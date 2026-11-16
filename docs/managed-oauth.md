# Host-managed OAuth

Enable `managed-oauth` for the native, Tokio-based helper. The default SDK has no OAuth dependency. `auth::managed::ManagedOAuth` implements the existing `AuthProvider`; custom providers remain supported. Use `AuthProviders` to combine explicit bearer references, an OAuth provider, and an independently selected unbound route. Configured Authorization always wins. Installing this helper does not silently replace other routes.

## Supply the security boundaries

The helper deliberately provides **no browser, callback listener, worker, HTTP client, or persistent store**. Supply:

- `OAuthNetwork`: check HTTPS destinations, resolve and pin allowed IP addresses at connection time, enforce TLS identity, disable redirects, cap streaming response reads at 1 MiB, and never log requests/responses. A preliminary DNS check alone does not prevent rebinding. `check` also authorizes URLs before the host displays them. Do not reuse an unrestricted general-purpose HTTP client.
- `OAuthPolicy`: select an exact trusted issuer and locally allowed scopes. Its mandatory `approve_endpoints` callback must approve authorization/token endpoints for that issuer, client ID and client-secret reference. A public HTTPS address is not permission to disclose a secret; cross-origin endpoints require explicit approval. Metadata and challenge scopes never grant consent.
- `CredentialStore`: acquire exclusive ownership per `SessionKey` across **all** processes sharing credentials. Hold ownership until the guard drops, including during network calls. Implement atomic versioned compare-and-swap. Acquisition, load and writes must be cancellation-safe and respect their enclosing deadline; uncertain writes must not overwrite newer versions. A process-local mutex is sufficient only for a genuinely single-process host. No SDK registry or global cache is created.

Records contain access/refresh tokens, PKCE verifiers and state. Encrypt/protect them as credentials; never serialize them into logs or protocol messages. Keys separate credential namespace, backend, full destination and event/upload purpose. Records additionally bind the exact issuer, resource, client and granted scopes. Reusing a key with incompatible identity fails closed rather than switching credentials. Use separate namespaces for independent host accounts/client registrations.

Discovery follows MCP 2025-11-25: a Bearer `resource_metadata` challenge first, otherwise endpoint-path-specific then root resource well-known URLs; authorization-server OAuth/OIDC locations follow the prescribed issuer-path order. The discovered RFC 9728 resource must cover the destination; explicit configured resources and issuers retain exact identity. PKCE uses S256, validated state/redirect and advertised issuer-response validation. Every exchange and refresh includes RFC 8707 `resource`. Dynamic registration is not performed: the host provides a pre-registered client.

## Prepare and complete a login

The following host function has no transport/UI side effects. Its dependencies must implement the contracts above. Run it inside an existing Tokio runtime; do not call a nested runtime from an async host.

```rust,no_run
use std::{sync::Arc, time::Instant};
use agenthooksprotocol::{
    adapters::registered::AuthContext,
    auth::{OAuthFlow, managed::{
        CredentialStore, ManagedOAuth, OAuthClientConfig, OAuthNetwork, OAuthPolicy,
        OperationBudget, Preparation,
    }},
    client::HookError,
};

async fn prepare_login(
    context: AuthContext,
    deadline: Instant,
    network: Arc<dyn OAuthNetwork>,
    policy: Arc<dyn OAuthPolicy>,
    store: Arc<dyn CredentialStore>,
) -> Result<(ManagedOAuth, Preparation), HookError> {
    let config = OAuthClientConfig::new("account-a", "registered-client", OAuthFlow::AuthorizationCodePkce)
        .redirect_uri("https://app.example/oauth/callback")
        .scopes(vec!["hooks".into()], vec!["hooks".into()]);
    let oauth = ManagedOAuth::new(config, network, policy, store)?;
    let prepared = oauth.prepare(context, OperationBudget::until(deadline)).await?;
    Ok((oauth, prepared))
}
```

For `Preparation::Ready`, use the credential only for the original target. For `InteractionRequired`, display `pending.authorization_url()` only when it returns `Some`. The host receives the callback URL and calls `oauth.complete(pending, callback, budget).await`. Do not log either URL. The callback must match the configured HTTPS redirect, contain unique valid state/code fields, and satisfy issuer checks. A completion operation gets its own explicit budget; preparation remains bounded by the original context deadline.

Clone a pending handle before completion when you need to cancel that generation. Dropping a future cancels work and releases its store guard; it never spawns detached work. If an exchange may already have consumed the code, the persisted marker prevents replay. A later `prepare` returns a cancellation-only pending handle (`exchange_is_uncertain()`, no authorization URL). Call `cancel_login` on that generation, then prepare a new login. An old callback/cancellation cannot remove a newer pending generation. Definitive code rejection retires that login.

## Client credentials

Use `OAuthFlow::ClientCredentials` and `.client_secret("local-secret-reference", secret, TokenAuthMethod::ClientSecretBasic)` (or explicitly supported `ClientSecretPost`). Resolve `secret` from host-controlled storage into `ClientSecret::new(...)`; never put its value into protocol configuration. The explicit target's `clientId` and optional `clientSecretRef` must match. The issuer must advertise client-credentials support and the selected token authentication method. No interaction or fallback to a different flow is attempted.

## Refresh and recovery

Tokens are refreshed before expiry with a 30-second safety margin. The host's exclusive guard provides single-flight refresh; waiters reload the latest generation. A delayed 401 for an older generation cannot reject or unnecessarily refresh a newer valid token. Definitive `invalid_grant` persists rejection and invokes the matching-generation rejection hook. Scope increases require a new locally approved grant, not reuse of a narrower token.

Credentials are retained on all refresh failures. Transport loss, cancellation, malformed responses and ambiguous server errors retain an uncertainty marker: the old refresh token is **not** automatically replayed. A 429/5xx status alone does not prove that rotation did not happen. A network adapter may implement `refresh_failure_is_safe` only where the trusted issuer's contract establishes that the specific response did not consume the grant. Such known-safe failures clear the marker, preserving credentials for a later host-controlled retry. Standard, definitive OAuth request errors are classified without exposing server error text.

For an uncertain refresh, use `SessionRecord::refresh_is_uncertain()` and its opaque `attempt_id()` to obtain the generation, then call `abandon_uncertain_refresh(context, generation, budget)`. This explicit host decision retires only that generation without replaying its refresh token or discarding its evidence; prepare again to authorize/reacquire. A stale repair cannot reject a newer token. Inspect only opaque IDs/flags; never log the record.

All public failures use sanitized classifications and recovery guidance. Recovery guidance never authorizes replaying an effectful hook delivery. Authentication failure never sends an explicitly bound request anonymously, changes its binding, or borrows event credentials for upload. Fix login/credentials for a **new** operation instead of replaying effects.

See [dependency review](managed-oauth-dependency-review.md) for the pinned primitive, provenance, optional dependency footprint and inherited audit findings.
