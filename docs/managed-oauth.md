# Host-managed OAuth

Enable `managed-oauth` to use `auth::managed::ManagedOAuth` with Tokio. The default SDK has no OAuth dependency. `ManagedOAuth` implements `AuthProvider`; custom providers remain supported. Use `AuthProviders` to select bearer, OAuth and unbound routes explicitly. An explicit `Authorization` header bypasses provider lookup and challenge handling.

## Supply network, policy and storage

The helper creates no browser, callback listener, HTTP client, worker or persistent store. Supply these host boundaries:

- `OAuthNetwork`: enforce destination policy against connection-time resolved addresses, pin approved addresses, verify TLS identity, disable redirects and bound streaming response reads to 1 MiB. A preliminary URL/DNS check alone does not prevent rebinding. `check` also approves authorization URLs before they are displayed. Never log OAuth requests or responses.
- `OAuthPolicy`: approve the exact issuer, resource, client, scopes and advertised authorization/token endpoints. A public HTTPS endpoint is not permission to disclose a client secret. Metadata and challenge scopes are untrusted requirements, not consent.
- `CredentialStore`: coordinate exclusive ownership and atomic versioned compare-and-swap across all processes sharing credentials. Use `SessionKey::as_str()` as the storage identity. Acquisition, reads and writes must be cancellation-safe and obey the operation budget. Dropping a guard must release ownership. A process-local mutex is sufficient only for a single-process host.

Records contain access/refresh tokens, PKCE verifiers and state. Encrypt/protect them as credentials; do not log or send them on the AHP wire. Discovery runs outside credential-store ownership; token acquisition/refresh remains serialized per grant. Hosts must not introduce a second lock order around network or policy callbacks.

## Choose scope and consent boundaries

Configure `OAuthClientConfig::new(namespace, client_id, flow)` and call `.scopes(requested, allowed)`. Requested scopes guide acquisition. Allowed scopes are the local ceiling, defaulting to the requested set. The ceiling governs what the SDK requests and records; it does not constrain what an issued token can do. Hosts that need enforcement validate tokens in their own policy.

The SDK records granted scopes only. An acquisition (PKCE consent or client credentials, including step-up for an existing grant) requests the previously granted scopes plus the requested and required scopes within the caller's ceiling. It records the response scopes (the requested set when `scope` is omitted) intersected with the previous grant plus the acquiring ceiling; for PKCE that is the ceiling stored with the pending login. Earlier scopes are never lost. A refresh records the response scopes intersected with the previous grant, so it never broadens consent and is not narrowed by the current ceiling. At use, the effective scopes are the grant intersected with the current caller's ceiling. Scopes outside it, such as `openid` or `offline_access`, are ignored, never an error. An operation fails `access_denied` only when an explicit host requirement (`scopes` on the binding or `prepare_with_required`) or a validated challenge requirement is missing from the effective scopes. The grant, including any rotated refresh token, is still saved.

Binding identity is namespace, backend, exact destination and event/upload purpose. Grant identity is namespace, exact issuer and resource, client, flow and grant partition. The ceiling, secrets, token-endpoint auth method, metadata capabilities and scope sets are not identity, so changing them never orphans a grant. Use separate namespaces for host accounts or registrations.

Default grants are isolated per binding, including upload targets. Set `.grant_partition("host-approved-account")` only to share consent deliberately. Each target and purpose must still pass independent policy approval. Do not automatically copy event authorization to uploads.

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

For `Preparation::Ready`, use the credential only for its approved target. For `InteractionRequired`, display `pending.authorization_url()`, receive the callback through host-owned transport and call `complete(context, callback, budget)`. Any process sharing the store can complete it; the creating call need not still be running. Do not log either URL. Keep the `PendingLogin` handle to call `cancel_login`. Dropping a future cancels its work; it does not spawn a detached exchange.

Only host `prepare` creates a pending login. Delivery, challenge handling and the unbound up-front lookup return `interaction_required` instead. A pending login is a stored record with a lifetime fixed at creation by `.login_lifetime(...)` (default and maximum 10 minutes), independent of the creating call's budget. A later `prepare` reuses it when the grant, exact redirect match and its requested plus required scopes are within the pending scopes, regardless of deadline; reuse never extends the lifetime. Otherwise `prepare` supersedes it. For the same grant and redirect, the new login requests the old pending scopes plus the new caller's requested and required scopes and stores the union of both ceilings; with a different redirect it uses only the new caller's scopes and ceiling. Both sets only grow, so alternating callers converge; each caller still filters effective scopes by its own ceiling. Because reuse requires the exact redirect, keep the redirect stable per grant key when processes share a store; with per-process ephemeral loopback ports, give each process its own grant partition. A pending login ends exactly once: completion (including consent denial), supersede, `cancel_login` or expiry. A callback for an ended login fails `interaction_required`. Invalid redirect, state or issuer never consumes a pending login. A valid callback is claimed once before the code exchange. A failed initial exchange persists nothing. Canceling never deletes a valid grant.

Redirects must use HTTPS, HTTP to a literal loopback IP (`127.0.0.0/8` or `::1`), or an RFC 8252 reverse-domain private-use scheme such as `com.example.app:/callback`. HTTP DNS names, including `localhost`, and remote HTTP redirects are rejected. No implicit listener is installed.

## Use configured or discovered endpoints

An explicit OAuth binding fixes issuer, resource, client and flow. It skips protected-resource metadata discovery, but still validates issuer metadata and local constraints. Unbound endpoints use RFC 9728 protected-resource discovery, with strict retrieval-source/resource identity and local approval before credentials are issued. Resource identifiers retain exact trailing slash and query identity; they are not normalized into a different configured identifier.

Once a validated, locally approved binding is stored for a destination, its token is sent on the first attempt, including for notifications and uploads that are never replayed, and after recreating a provider with the same store. That lookup never creates a login and never runs protected-resource discovery. It refreshes an expired token, or re-acquires a client-credentials grant, with the authorization-server metadata persisted on the binding; if that metadata is absent it fetches only the stored issuer's metadata (`discovery_failed` on failure). A known binding that cannot be renewed fails the operation, for example `interaction_required` when PKCE needs consent. Only a store miss or a host policy refusal sends anonymously. If a renewal fails where the token endpoint provably did not process it (a DNS, TCP connect or TLS handshake failure that `OAuthNetwork::send` marks with `HookError::request_not_sent`, or a 404/410), the stored issuer's metadata is refetched once and the renewal retried once. Ambiguous failures after sending (timeouts, resets, 5xx, non-OAuth bodies, redirects) return `provider_failed` with no immediate retry, so a rotated refresh token is never replayed; a changed issuer or failed refetch is `discovery_failed`. Challenge handling, and a `prepare` that needs an exchange or login, always run full protected-resource discovery (honouring a challenge's `resource_metadata`), so a resource moved to another authorization server is rebound even while the old one still answers; `prepare` also rebinds when policy no longer approves the stored issuer. A known binding for a different client or flow is `discovery_failed` at lookup. A host `prepare` serves a usable cached token without metadata calls; when an exchange or login is needed it re-runs discovery, which repairs stale binding metadata. A 401 or `insufficient_scope` on a notification or upload is not replayed, but challenge handling (discovery, client-credentials acquisition) prepares the next attempt. Hosts can prepare an unknown target before its first call. Mutable capabilities and client-secret rotation do not invalidate a compatible grant.

PKCE uses S256, state and redirect validation, and advertised issuer-response checks. Every token exchange and refresh includes RFC 8707 `resource`. Dynamic client registration is not performed.

## Use client credentials

Choose `OAuthFlow::ClientCredentials` and `.client_secret(reference, secret, TokenAuthMethod::ClientSecretBasic)` or explicitly supported `ClientSecretPost`. Construct the SDK-owned `ClientSecret::new(...)` from a host-resolved secret; never put its value in protocol configuration. The type has no `Debug` or serialization implementation; explicit secret access and serialized session records still require care. Secret memory is not automatically zeroized. The explicit target's client ID and optional secret reference must match. Issuer metadata must support the flow and token-auth method. Client credentials reacquire noninteractively and never request human login.

## Recover and replay

Known-expiry tokens refresh with a 30-second margin. Tokens without `expires_in` remain usable until rejected. `expires_in` must be a positive integer or a string of ASCII digits; other values, including `null`, fail `provider_failed`. Once a token response is received, its outcome (including a rotated refresh token from an undecodable 2xx) is persisted on a spawned Tokio task bounded by `.commit_timeout(...)` (default 30 seconds), so a slow store, an expired caller deadline or a dropped future never leaves a spent refresh token stored as current. A failed refresh response clears in-flight state and keeps a valid rotated refresh token, otherwise the presented one. Timeouts, non-OAuth responses and 5xx keep refresh material and return `provider_failed` (retry); the next acquisition retries the refresh token by default. A definitive refresh `invalid_grant` returns `refresh_rejected` and drops both tokens only if the store still holds the presented refresh token.

A 401 marks the rejected token stale even when its expiry is unknown or in the future; challenge handling renews it by refresh or client-credentials re-acquisition and never resends it, including after a notification or upload that is not replayed. A delayed rejection of an older token generation cannot invalidate a newer token. `auth_code()` and `auth_recovery()` provide sanitized classifications (`configure`, `login`, `retry` or `none`).

A Bearer 403 with `error="insufficient_scope"` requires its scopes for that operation only; they are never stored. Other 403 responses are denied. Client credentials can acquire the broader grant. PKCE fails `interaction_required` carrying `HookError::required_scopes()`; pass them to `prepare_with_required` to request step-up consent. Required scopes outside the ceiling fail `access_denied`.

After the provider handles a 401 or `insufficient_scope` challenge, the HTTP transport replays `hooks/intercept`, `hooks/configuration` and `hooks/capabilities` once, with the same JSON-RPC id and buffered body. A second rejection is an operational failure. Notifications and uploads are never replayed; uploads still run challenge handling for a 401 or Bearer 403 `insufficient_scope` and report the provider's classified error.
