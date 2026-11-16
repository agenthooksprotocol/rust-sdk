# Host-managed OAuth

Enable `managed-oauth` to use `auth::managed::ManagedOAuth` with Tokio. The default SDK has no OAuth dependency. `ManagedOAuth` implements `AuthProvider`; custom providers remain supported. Use `AuthProviders` to select bearer, OAuth and unbound routes explicitly. An explicit `Authorization` header bypasses provider lookup and challenge handling.

## Supply network, policy and storage

The helper creates no browser, callback listener, HTTP client, worker or persistent store. Supply these host boundaries:

- `OAuthNetwork`: enforce destination policy against connection-time resolved addresses, pin approved addresses, verify TLS identity, disable redirects and bound streaming response reads to 1 MiB. A preliminary URL/DNS check alone does not prevent rebinding. `check` also approves authorization URLs before they are displayed. Never log OAuth requests or responses.
- `OAuthPolicy`: approve the exact issuer, resource, client, scopes and advertised authorization/token endpoints. A public HTTPS endpoint is not permission to disclose a client secret. Metadata and challenge scopes are untrusted requirements, not consent.
- `CredentialStore`: coordinate exclusive ownership and atomic versioned compare-and-swap across all processes sharing credentials. Use `SessionKey::as_str()` as the storage identity. Acquisition, reads and writes must be cancellation-safe and obey the operation budget. Dropping a guard must release ownership. A process-local mutex is sufficient only for a single-process host.

Records contain access/refresh tokens, PKCE verifiers and state. Encrypt/protect them as credentials; do not log or send them on the AHP wire. Discovery runs outside credential-store ownership; token acquisition/refresh remains serialized per grant. Hosts must not introduce a second lock order around network or policy callbacks.

## Choose scope and consent boundaries

Configure `OAuthClientConfig::new(namespace, client_id, flow)` and call `.scopes(requested, allowed)`. Requested scopes guide acquisition; allowed scopes are the local ceiling, defaulting to the requested set when no broader ceiling is supplied. A token may grant fewer requested scopes, or additional scopes within that ceiling. An explicit target or Bearer challenge can require a subset for an operation. Insufficient required scopes prevent dispatch without discarding a rotated refresh token.

Binding identity separates namespace, backend, exact destination and event/upload purpose. Grant identity additionally includes exact issuer/resource, client, flow and the canonical allowed-scope ceiling. Secrets, secret references, token-auth method, metadata capabilities and requested/granted scopes are not grant identity. Use separate namespaces for host accounts or registrations.

Default grants are isolated per binding, including upload targets. Set `.grant_partition("host-approved-account")` only to share consent deliberately. Each target and purpose must still pass independent policy approval; matching partitions do not authorize a new resource, issuer, client or scope ceiling. Do not automatically copy event authorization to uploads.

## Prepare and complete a login

```rust,no_run
use agenthooksprotocol::{
    adapters::registered::AuthContext,
    auth::{OAuthFlow, managed::{CredentialStore, ManagedOAuth, OAuthClientConfig,
        OAuthNetwork, OAuthPolicy, OperationBudget, Preparation}},
    client::HookError,
};
use std::{sync::Arc, time::Instant};

async fn prepare_login(
    context: AuthContext,
    deadline: Instant,
    network: Arc<dyn OAuthNetwork>,
    policy: Arc<dyn OAuthPolicy>,
    store: Arc<dyn CredentialStore>,
) -> Result<(ManagedOAuth, Preparation), HookError> {
    let config = OAuthClientConfig::new(
        "account-a", "registered-client", OAuthFlow::AuthorizationCodePkce,
    )
    .redirect_uri("https://app.example/oauth/callback")
    .scopes(vec!["hooks".into()], vec!["hooks".into()]);
    let oauth = ManagedOAuth::new(config, network, policy, store)?;
    let prepared = oauth.prepare(context, OperationBudget::until(deadline)).await?;
    Ok((oauth, prepared))
}
```

For `Preparation::Ready`, use the credential only for its approved target. For `InteractionRequired`, display `pending.authorization_url()` when present, receive the callback through host-owned transport and call `complete(pending, callback, budget)`. Do not log either URL. Clone a pending handle if the host needs to call `cancel_login` later. Completion and cancellation receive explicit host budgets. Completion cannot extend the original consent operation's deadline. Dropping a future cancels its work; it does not spawn a detached exchange.

Only host `prepare` creates pending consent. Dispatch and challenge handling return `interaction_required` without starting login or borrowing a short delivery deadline as a consent budget. Pending consent is reused only for the same grant, exact redirect, requested scope set and explicit requirements, while its original context remains active and covers the new prepare budget. An incompatible explicit prepare replaces the pending generation; its old callback cannot complete the replacement. Poll the same host operation with its original budget rather than extending its lifetime. Invalid callback redirect, state or issuer does not consume a valid pending operation. A valid callback is claimed once before code exchange; consent denial consumes it. Canceling a login does not delete a valid grant. Ambiguous code exchange cannot be safely replayed: cancel that pending generation and explicitly prepare another login.

Redirects must use HTTPS, except HTTP to literal IPv4 loopback addresses in `127.0.0.0/8` or IPv6 `::1` for desktop/CLI callbacks. HTTP DNS names, including `localhost`, and remote HTTP redirects are rejected. No implicit listener is installed.

## Use configured or discovered endpoints

An explicit OAuth binding fixes issuer, resource, client and flow. It skips protected-resource metadata discovery, but still validates issuer metadata and local constraints. Unbound endpoints use RFC 9728 protected-resource discovery, with strict retrieval-source/resource identity and local approval before credentials are issued. Resource identifiers retain exact trailing slash and query identity; they are not normalized into a different configured identifier.

Saved approved bindings allow valid cached credentials to be sent up front, including notifications and uploads that cannot be replayed, and after recreating a provider with the same durable host store. An unknown unbound target may start anonymously under local policy. Hosts can prepare an unknown target before its first unsafe call. Mutable capabilities and client-secret rotation do not permanently poison a compatible grant.

PKCE uses S256, state and redirect validation, and advertised issuer-response checks. Every token exchange and refresh includes RFC 8707 `resource`. Dynamic client registration is not performed.

## Use client credentials

Choose `OAuthFlow::ClientCredentials` and `.client_secret(reference, secret, TokenAuthMethod::ClientSecretBasic)` or explicitly supported `ClientSecretPost`. Construct the SDK-owned `ClientSecret::new(...)` from a host-resolved secret; never put its value in protocol configuration. The type has no `Debug` or serialization implementation; explicit secret access and serialized session records still require care. Secret memory is not automatically zeroized. The explicit target's client ID and optional secret reference must match. Issuer metadata must support the flow and token-auth method. Client credentials reacquire noninteractively and never request human login.

## Recover without replaying effects

Known-expiry tokens refresh with a 30-second margin. Tokens with no expiry remain usable until rejected or restricted by host policy. Refresh preserves omitted refresh tokens and persists rotations before reporting operation-level scope insufficiency. Refresh responses with omitted scope inherit the previous grant rather than broadening consent.

A delayed rejection of an older token generation cannot invalidate a newer token. Definitive interactive refresh `invalid_grant` requires new consent. Timeouts, non-OAuth responses, 5xx and other transient refresh failures preserve material and return retry guidance; uncertainty is not an irreversible login-only state. An ambiguous rotating refresh may later return `invalid_grant`: neither the SDK nor the host store can roll back an authorization server's external exchange.

`auth_code()` and `auth_recovery()` provide sanitized classifications. `AuthRecovery::as_str()` returns `configure`, `login`, `retry` or `none`. Guidance never permits replay of an effectful operation. A Bearer 403 with `error="insufficient_scope"` can record step-up only within the local ceiling; other 403 responses remain denied. PKCE asks the host to prepare consent; client credentials can reacquire approved scopes. Only the transport decides whether its existing single safe retry applies. Notifications, uploads and effectful deliveries are not replayed merely because authentication state changed.
