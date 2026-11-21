//! Host-driven OAuth mechanics. No browser, listener, executor, file store or task is created.
//!
//! The embedding host supplies a policy-enforcing network client and a durable,
//! exclusive/CAS-capable store. Credentials and pending login records are secret.
use crate::{
    adapters::registered::{
        AuthChallenge, AuthContext, AuthProvider, AuthPurpose, BearerCredential,
    },
    auth::{AuthBinding, AuthErrorCode, AuthTarget, OAuthFlow},
    client::{HookError, LocalFuture},
};
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, RequestTokenError, Scope,
    TokenResponse, TokenUrl,
    basic::{
        BasicClient, BasicErrorResponse, BasicErrorResponseType, BasicTokenResponse, BasicTokenType,
    },
};
pub use oauth2::{HttpRequest as OAuthRequest, HttpResponse as OAuthResponse};
/// SDK-owned secret. Deliberately does not implement Debug or serialization.
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientSecret(String);
impl ClientSecret {
    pub fn new(secret: String) -> Self {
        Self(secret)
    }
    pub fn secret(&self) -> &String {
        &self.0
    }
}
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;
#[path = "managed/decide.rs"]
mod decide;
#[path = "managed/discovery.rs"]
mod discovery;
#[path = "managed/registration.rs"]
mod registration;
use registration::{ClientChoice, ClientSource};
pub use registration::{ClientSecretStorage, RegistrationPolicy};

/// Absolute operation budget. Dropping an operation drops all its work/guards.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct OperationBudget {
    deadline: Instant,
}
impl OperationBudget {
    pub fn until(deadline: Instant) -> Self {
        Self { deadline }
    }
    pub fn deadline(self) -> Instant {
        self.deadline
    }
    async fn run<T>(
        self,
        future: impl Future<Output = Result<T, HookError>>,
    ) -> Result<T, HookError> {
        let expired = || {
            HookError::new("OAuth operation deadline exceeded")
                .classified(crate::generated::DeliveryDiagnosticCode::DeadlineExceeded)
        };
        if Instant::now() >= self.deadline {
            return Err(expired());
        }
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(self.deadline), future)
            .await
            .map_err(|_| expired())?;
        if Instant::now() >= self.deadline {
            return Err(expired());
        }
        result.map_err(decide::classify)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndpointUse {
    ResourceMetadata,
    IssuerMetadata,
    Authorization,
    Token,
    /// RFC 7591 client registration; also local destination policy for it.
    Registration,
}
/// Required security boundary, not a generic HTTP client. Implementations MUST
/// enforce local destination policy against resolved IPs (including rebinding),
/// certificate/hostname verification, bounded reads, and NO redirects. `check`
/// validates the host-displayed authorization URL too; `send` must repeat/pin
/// that validation at actual connection time, not trust an earlier DNS lookup.
/// Adapter requests and responses MUST NOT be logged, even at DEBUG level.
/// Mark DNS, TCP connect and TLS handshake failures from `send` with
/// `HookError::request_not_sent`; only those (and 404/410) refetch metadata.
/// For token and registration requests, call the `RequestWritten` extension's
/// `mark` once the request bytes are written.
pub trait OAuthNetwork: Send + Sync {
    fn check(
        &self,
        endpoint: Url,
        usage: EndpointUse,
        budget: OperationBudget,
    ) -> LocalFuture<'_, Result<(), HookError>>;
    fn send(
        &self,
        request: oauth2::HttpRequest,
        usage: EndpointUse,
        budget: OperationBudget,
    ) -> LocalFuture<'_, Result<oauth2::HttpResponse, HookError>>;
}
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustedMetadata {
    pub resource: String,
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub authorization_response_iss_parameter_supported: bool,
    pub token_endpoint: String,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    /// True only when the metadata member is JSON `true`.
    #[serde(default)]
    pub client_id_metadata_document_supported: bool,
}
/// A host policy selection: the trusted issuer and this target's requested
/// scopes (empty: the configured requested scopes).
#[derive(Clone)]
#[non_exhaustive]
pub struct TrustDecision {
    pub issuer: String,
    pub scopes: Vec<String>,
}
impl ResourceMetadata {
    pub fn new(resource: String, authorization_servers: Vec<String>) -> Self {
        Self {
            resource,
            authorization_servers,
        }
    }
}
impl TrustDecision {
    pub fn new(issuer: String, scopes: Vec<String>) -> Self {
        Self { issuer, scopes }
    }
}
impl TrustedMetadata {
    pub fn new(resource: String, issuer: String, token_endpoint: String) -> Self {
        Self {
            resource,
            issuer,
            token_endpoint,
            authorization_endpoint: None,
            authorization_response_iss_parameter_supported: false,
            grant_types_supported: Vec::new(),
            token_endpoint_auth_methods_supported: Vec::new(),
            code_challenge_methods_supported: Vec::new(),
            registration_endpoint: None,
            client_id_metadata_document_supported: false,
        }
    }
}
/// Approval of the endpoints of a locally trusted issuer, for a client. Metadata
/// is untrusted input to evaluate, never trust or consent.
#[non_exhaustive]
pub struct EndpointTrust<'a> {
    pub target: &'a AuthTarget,
    /// The pre-registered client; empty when CIMD or DCR selects it after approval.
    pub client_id: &'a str,
    pub client_secret_ref: Option<&'a str>,
    pub metadata: &'a TrustedMetadata,
}
impl<'a> EndpointTrust<'a> {
    pub fn new(target: &'a AuthTarget, client_id: &'a str, metadata: &'a TrustedMetadata) -> Self {
        Self {
            target,
            client_id,
            client_secret_ref: None,
            metadata,
        }
    }
}
pub trait OAuthPolicy: Send + Sync {
    /// Mandatory issuer/client-bound approval of every advertised endpoint.
    /// SSRF checks alone do not authorize disclosing a client secret to a public URL.
    fn approve_endpoints(&self, context: EndpointTrust<'_>) -> Result<(), HookError>;
    /// Select a trusted issuer for the resource and, optionally, this target's
    /// requested scopes (S); empty scopes mean the configured requested scopes.
    /// `required` is the operation's required set (host-required, explicit and
    /// 403 challenge scopes), for information: acquisitions request S and the
    /// required set, within the ceiling. S beyond the ceiling, or a preset's
    /// `scopes` other than S, fails `invalid_configuration`. An error keeps
    /// its code and never carries scopes.
    fn select(
        &self,
        target: &AuthTarget,
        resource: &ResourceMetadata,
        required: &[String],
    ) -> Result<TrustDecision, HookError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
}
const MAX_LOGIN_LIFETIME: Duration = Duration::from_secs(600);
/// `complete` phases, for `HookError::login_ended`.
const LOOKUP: u8 = 0;
const PENDING: u8 = 1;
const CLAIMING: u8 = 2;
const CLAIMED: u8 = 3;
/// Host registration, never inferred from untrusted metadata. Secret Debug is not exposed.
#[non_exhaustive]
pub struct OAuthClientConfig {
    namespace: String,
    pub(super) client_id: Option<String>,
    pub(super) flow: OAuthFlow,
    pub(super) requested_scopes: Vec<String>,
    pub(super) allowed_scopes: Vec<String>,
    pub(super) required_scopes: Vec<String>,
    redirect_uri: Option<String>,
    grant_partition: Option<String>,
    secret: Option<(String, ClientSecret)>,
    method: TokenAuthMethod,
    login_lifetime: Duration,
    commit_timeout: Duration,
    cimd: Option<registration::Cimd>,
    registrations: Vec<RegistrationPolicy>,
    secret_storage: Option<Arc<dyn ClientSecretStorage>>,
    registration_backoff: (Duration, Duration),
    max_pending_logins: usize,
    persist_pending_logins: bool,
}
impl OAuthClientConfig {
    /// A pre-registered client. It always wins: CIMD and DCR are never attempted.
    pub fn new(
        namespace: impl Into<String>,
        client_id: impl Into<String>,
        flow: OAuthFlow,
    ) -> Self {
        Self {
            client_id: Some(client_id.into()),
            ..Self::unregistered(namespace, flow)
        }
    }
    /// No pre-registered client: an explicit preset's `clientId`, else a configured
    /// Client ID Metadata Document, else permitted Dynamic Client Registration.
    pub fn unregistered(namespace: impl Into<String>, flow: OAuthFlow) -> Self {
        Self {
            namespace: namespace.into(),
            client_id: None,
            flow,
            requested_scopes: Vec::new(),
            allowed_scopes: Vec::new(),
            required_scopes: Vec::new(),
            redirect_uri: None,
            grant_partition: None,
            secret: None,
            method: TokenAuthMethod::None,
            login_lifetime: MAX_LOGIN_LIFETIME,
            commit_timeout: Duration::from_secs(30),
            cimd: None,
            registrations: Vec::new(),
            secret_storage: None,
            registration_backoff: (Duration::from_secs(60), Duration::from_secs(3600)),
            max_pending_logins: 5,
            persist_pending_logins: false,
        }
    }
    /// PKCE only, used when issuer metadata has `client_id_metadata_document_supported`
    /// `true`. `url` is the `client_id` verbatim; `redirect_uris` are the document's.
    /// Each login's redirect must be one of them, a loopback redirect compared
    /// without its port (RFC 8252 section 7.3). The SDK never fetches `url`.
    pub fn client_id_metadata_document(
        mut self,
        url: impl Into<String>,
        redirect_uris: Vec<String>,
    ) -> Self {
        self.cimd = Some(registration::Cimd {
            url: url.into(),
            redirect_uris,
        });
        self
    }
    /// Permit RFC 7591 registration at the policy's exact issuer. Repeat per issuer.
    pub fn dynamic_registration(mut self, policy: RegistrationPolicy) -> Self {
        self.registrations.push(policy);
        self
    }
    /// Host storage for issued client secrets; required for client-credentials DCR.
    /// A PKCE client is registered per login and never has a secret.
    pub fn client_secret_storage(mut self, storage: Arc<dyn ClientSecretStorage>) -> Self {
        self.secret_storage = Some(storage);
        self
    }
    /// Client-credentials failed-registration backoff: `initial` doubling per
    /// failure, capped at `max` (defaults 1 minute and 1 hour). `max` also caps a
    /// later `Retry-After` (delta-seconds or HTTP-date).
    pub fn registration_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.registration_backoff = (initial, max);
        self
    }
    /// Concurrent pending logins per grant key (default 5, at least 1). Creating
    /// one beyond the cap cancels the oldest.
    pub fn max_pending_logins(mut self, cap: usize) -> Self {
        self.max_pending_logins = cap.max(1);
        self
    }
    /// Store pending logins (with their PKCE verifier) in the grant record so
    /// any process sharing the store can complete one by `state`, for example
    /// from a pasted callback URL. By default a pending login lives only in the
    /// `ManagedOAuth` that created it, as in MCP clients.
    pub fn persist_pending_logins(mut self) -> Self {
        self.persist_pending_logins = true;
        self
    }
    /// Bound for persisting a received token response (default 30 seconds). The
    /// write outlives the caller's deadline and cancellation so a spent refresh
    /// token is never left current; it requires a Tokio runtime to run detached.
    pub fn commit_timeout(mut self, timeout: Duration) -> Self {
        self.commit_timeout = timeout;
        self
    }
    /// Fixed lifetime of each pending login, from its creation; at most 10 minutes.
    /// It is independent of the creating `prepare` call's budget or cancellation.
    /// Expired pending logins are deleted.
    pub fn login_lifetime(mut self, lifetime: Duration) -> Self {
        self.login_lifetime = lifetime.min(MAX_LOGIN_LIFETIME);
        self
    }
    /// `requested` scopes are asked for in every acquisition but are never
    /// mandatory; a binding preset's `scopes`, when present, must equal them.
    /// `allowed` is the local ceiling, defaulting to `requested`. A requested
    /// scope outside it, or an invalid scope token, fails every operation
    /// `invalid_configuration`.
    pub fn scopes(mut self, requested: Vec<String>, allowed: Vec<String>) -> Self {
        self.requested_scopes = requested;
        self.allowed_scopes = allowed;
        self
    }
    /// Host-required scopes: mandatory for every operation of this client, with
    /// explicit `prepare` and challenge requirements. One outside the ceiling
    /// fails each operation `access_denied`, before any network request.
    pub fn required_scopes(mut self, required: Vec<String>) -> Self {
        self.required_scopes = required;
        self
    }
    /// Explicit opt-in to grant sharing, never destination authorization.
    pub fn grant_partition(mut self, partition: impl Into<String>) -> Self {
        self.grant_partition = Some(partition.into());
        self
    }
    /// The default PKCE redirect. A host binding a new loopback port per login
    /// passes each login's redirect with `PrepareOptions::redirect_uri` instead.
    /// HTTP is allowed only to a literal loopback IP, never `localhost`.
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }
    pub fn client_secret(
        mut self,
        reference: impl Into<String>,
        secret: ClientSecret,
        method: TokenAuthMethod,
    ) -> Self {
        self.secret = Some((reference.into(), secret));
        self.method = method;
        self
    }
}
/// Canonical binding or grant storage identity; use `as_str()` for durable keys.
/// Context accessors (backend, destination, purpose) describe binding keys only;
/// they return empty strings for grant keys, whose principal is encoded in `as_str()`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct SessionKey {
    storage_key: String,
    namespace: String,
    backend_id: String,
    destination: String,
    purpose: String,
}
impl SessionKey {
    /// Canonical length-prefixed UTF-8 storage identity.
    pub fn as_str(&self) -> &str {
        &self.storage_key
    }
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }
    pub fn destination(&self) -> &str {
        &self.destination
    }
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}
/// Host-persisted secret record. Serialization is for host storage,
/// not diagnostics or protocol messages. There is intentionally no Debug.
///
/// Binding records hold validated discovery provenance and the selected client
/// source; grant records hold the token and the client it was issued to, plus
/// pending logins when the host persists them. Only granted scopes are
/// recorded: the local ceiling and operation requirements are re-applied at use.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionRecord {
    version: String,
    metadata: TrustedMetadata,
    /// Bindings: the pre-registered client or CIMD URL (empty for DCR).
    /// Grants: the client the token was issued to, committed with it.
    client_id: String,
    flow: String,
    configured_binding: bool,
    resource_metadata_hint: Option<discovery::ResourceMetadataHint>,
    token: Option<SavedToken>,
    /// Oldest first; only with `OAuthClientConfig::persist_pending_logins`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_logins: Vec<SavedLogin>,
    #[serde(default)]
    client_source: ClientSource,
    /// Client-credentials registration records: the DCR client and its backoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registration: Option<registration::SavedRegistration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backoff: Option<registration::Backoff>,
}
#[derive(Clone, Serialize, Deserialize)]
struct SavedToken {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
    /// Granted: response ∩ acquiring ceiling, or ∩ previous grant on refresh.
    /// The current ceiling is applied at use, never when recording.
    scopes: Vec<String>,
    generation: String,
    access_rejected: bool,
    refresh_in_flight: bool,
}
/// One pending login: its exact redirect, client, PKCE verifier and ceiling.
#[derive(Clone, Serialize, Deserialize)]
struct SavedLogin {
    id: String,
    metadata: TrustedMetadata,
    scopes: Vec<String>,
    /// The creating caller's ceiling; it bounds what completion records.
    ceiling: Vec<String>,
    /// The operation's required set at creation (host-required ∪ explicit);
    /// completion fails `access_denied` unless the grant covers it. `None` in
    /// a record written by an older release: the current host-required set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    required: Option<Vec<String>>,
    state: String,
    verifier: String,
    redirect_uri: String,
    expires_at_ms: u64,
    client_id: String,
}
impl SessionRecord {
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn attempt_id(&self) -> Option<&str> {
        self.token.as_ref().map(|token| token.generation.as_str())
    }
    /// A refresh request was sent but no response was observed (cancelled or
    /// transport failure). The refresh token is still retried by default.
    pub fn refresh_is_uncertain(&self) -> bool {
        self.token
            .as_ref()
            .is_some_and(|token| token.refresh_in_flight)
    }
    fn empty(metadata: TrustedMetadata, flow: &str) -> Self {
        Self {
            version: String::new(),
            metadata,
            client_id: String::new(),
            flow: flow.into(),
            configured_binding: false,
            resource_metadata_hint: None,
            token: None,
            pending_logins: Vec::new(),
            client_source: ClientSource::default(),
            registration: None,
            backoff: None,
        }
    }
    fn same_binding(&self, other: &Self) -> bool {
        self.metadata == other.metadata
            && self.resource_metadata_hint == other.resource_metadata_hint
            && self.client_id == other.client_id
            && self.flow == other.flow
            && self.configured_binding == other.configured_binding
            && self.client_source == other.client_source
    }
}
/// Acquire MUST serialize all writers for this key across the host's processes.
/// Cancellation/drop releases ownership. CAS additionally protects against stale
/// callbacks/writers; returning false is a classified failure, never overwritten.
pub trait CredentialStore: Send + Sync {
    fn acquire(
        &self,
        key: SessionKey,
        budget: OperationBudget,
    ) -> LocalFuture<'_, Result<Box<dyn CredentialGuard>, HookError>>;
}
// Native AuthProvider futures are Send; the guard crosses their await points.
pub trait CredentialGuard: Send {
    fn load(&mut self) -> LocalFuture<'_, Result<Option<SessionRecord>, HookError>>;
    fn compare_and_swap(
        &mut self,
        expected: Option<String>,
        replacement: SessionRecord,
    ) -> LocalFuture<'_, Result<bool, HookError>>;
    /// Called only after a matching generation's definitive invalid_grant is persisted.
    /// Transient and uncertain failures never invoke this hook or erase secrets.
    fn on_refresh_rejected(
        &mut self,
        _generation: String,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}
/// A pending login. The creating `ManagedOAuth` completes it by `state` with
/// `ManagedOAuth::complete` (with `persist_pending_logins`, any process sharing
/// the store can); this handle is only needed to display or cancel it.
#[derive(Clone)]
#[non_exhaustive]
pub struct PendingLogin {
    key: Box<SessionKey>,
    id: String,
    url: Url,
    redirect_uri: String,
    expires_at: SystemTime,
}
impl PendingLogin {
    pub fn authorization_url(&self) -> &Url {
        &self.url
    }
    /// The login's exact redirect, where its callback arrives.
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
    /// Fixed at creation.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}
#[non_exhaustive]
pub enum Preparation {
    Ready(BearerCredential),
    InteractionRequired(PendingLogin),
}
/// Options for an explicit host `prepare`.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct PrepareOptions {
    required: Vec<String>,
    redirect_uri: Option<String>,
    force_registration: bool,
}
impl PrepareOptions {
    pub fn new() -> Self {
        Self::default()
    }
    /// Operation requirements, such as the `HookError::required_scopes` of a step-up.
    pub fn required(mut self, scopes: Vec<String>) -> Self {
        self.required = scopes;
        self
    }
    /// The redirect of a login this `prepare` creates, such as a loopback
    /// listener on a new ephemeral port (`http://127.0.0.1:<port>/callback`).
    /// Authorization, registration and token requests use it exactly. Defaults
    /// to `OAuthClientConfig::redirect_uri`.
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }
    /// Replace a usable client-credentials registration, for example so changed
    /// `RegistrationPolicy` settings take effect; otherwise it is never replaced
    /// while usable. Once per `prepare`; a failed replacement returns its error,
    /// keeps the current record and counts toward the registration backoff,
    /// which a host `prepare` bypasses. PKCE registers per login anyway.
    pub fn force_registration(mut self) -> Self {
        self.force_registration = true;
        self
    }
}
#[non_exhaustive]
pub struct ManagedOAuth {
    pub(super) config: Arc<OAuthClientConfig>,
    pub(super) network: Arc<dyn OAuthNetwork>,
    pub(super) policy: Arc<dyn OAuthPolicy>,
    store: Arc<dyn CredentialStore>,
    /// Successful host preparations by backend, purpose and destination.
    prepared: Arc<std::sync::Mutex<std::collections::BTreeMap<String, u64>>>,
    /// Pending logins owned by this provider, by grant key, oldest first.
    pending: Arc<std::sync::Mutex<std::collections::BTreeMap<String, Vec<SavedLogin>>>>,
}
/// An operation's host policy selection and the authorization servers it was
/// made for. It is reused for the rest of the operation, and made again only
/// when discovery finds other authorization servers.
/// `decide::grant` for one operation: (S, the grant's token, can refresh).
type GrantDecision<'a> = dyn Fn(&[String], Option<&SavedToken>, bool) -> decide::Step + 'a;
/// The operation's selection, shared by its re-attempts.
pub(super) type Selections = std::sync::Mutex<Option<Selection>>;
#[derive(Clone)]
pub(super) struct Selection {
    servers: Vec<String>,
    result: Result<TrustDecision, HookError>,
}
impl Selection {
    pub(super) fn reuse(&self, servers: &[String]) -> Option<Result<TrustDecision, HookError>> {
        match &self.result {
            Ok(decision) if servers.contains(&decision.issuer) => Some(Ok(decision.clone())),
            Err(error) if self.servers == servers => Some(Err(error.clone())),
            _ => None,
        }
    }
}
/// Which caller drives acquisition. Only `Prepare` may create a pending login.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Explicit host preparation.
    Prepare,
    /// Bound delivery credential or challenge recovery.
    Deliver,
    /// Up-front lookup for an unbound endpoint: stored usable token only.
    Lookup,
}
struct TokenHttp {
    network: Arc<dyn OAuthNetwork>,
    budget: OperationBudget,
    written: RequestWritten,
    status: AtomicU16,
    /// The raw received body; oauth2 does not keep it for every failure.
    body: std::sync::Mutex<Option<Vec<u8>>>,
}
/// Inserted into every token and registration request's extensions. `OAuthNetwork::send` must call
/// `mark` once the request bytes are written: until then caller cancellation
/// aborts the exchange; afterwards it receives the response and commits the
/// outcome itself, so a rotated refresh token is never lost.
#[derive(Clone, Default)]
pub struct RequestWritten(Arc<std::sync::atomic::AtomicBool>);
impl RequestWritten {
    /// Call once the request bytes are written to the token endpoint. From then
    /// on the exchange, and the grant lock, outlive caller cancellation until
    /// its outcome is committed. Clients that cannot observe write completion
    /// (such as reqwest) should mark once the connection is established, or when
    /// the send future is first polled after connecting, as an approximation.
    pub fn mark(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn is_marked(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}
struct AbortUnlessWritten {
    task: tokio::task::AbortHandle,
    written: RequestWritten,
}
impl Drop for AbortUnlessWritten {
    fn drop(&mut self) {
        if !self.written.is_marked() {
            self.task.abort();
        }
    }
}
impl TokenHttp {
    async fn send(&self, request: oauth2::HttpRequest) -> Result<OAuthResponse, HookError> {
        let url = Url::parse(&request.uri().to_string())
            .map_err(|_| fail(AuthErrorCode::UntrustedDestination))?;
        if !valid_https(&url) {
            return Err(fail(AuthErrorCode::UntrustedDestination));
        }
        let budget = self.budget;
        budget
            .run(async {
                (self.network.check(url, EndpointUse::Token, budget).await)
                    .map_err(destination_refused)
            })
            .await?;
        let mut request = request;
        request.extensions_mut().insert(self.written.clone());
        budget
            .run(self.network.send(request, EndpointUse::Token, budget))
            .await
    }
}
/// What a refresh presented, for compare-and-delete on a definitive rejection.
struct Presented {
    client_id: String,
    refresh: RefreshToken,
    generation: String,
    drop_on_invalid_client: bool,
}
/// The caller's login inputs for `prepare`: the login's redirect (PKCE) and
/// explicit operation requirements.
#[derive(Clone, Copy, Default)]
struct Login<'a> {
    redirect: Option<&'a str>,
    required: &'a [String],
    /// `PrepareOptions::force_registration`, consumed by the first registration.
    force: Option<&'a AtomicBool>,
    /// Set once per operation: a client-credentials prepare forcing
    /// re-registration, so a DCR client's existing token is not usable in
    /// any of its attempts, whatever the consumed `force` flag says.
    forced: bool,
}
impl Login<'_> {
    fn forcing(&self) -> bool {
        self.force.is_some_and(|force| force.load(Ordering::SeqCst))
    }
}
/// The owned state a detached exchange needs after its response, so it can
/// commit the outcome after the caller is gone.
#[derive(Clone)]
struct Committer {
    allowed: Vec<String>,
    timeout: Duration,
}
type Exchange<T> = LocalFuture<'static, (T, Box<dyn CredentialGuard>, SessionRecord)>;
impl TokenHttp {
    /// Only failures where the token endpoint provably did not process the
    /// request suggest stale metadata: a request the network reports as not
    /// sent (DNS, connect, TLS handshake) or a 404/410. Ambiguous post-send
    /// failures are never retried, so a rotated refresh token is not replayed.
    fn failure(&self, error: &TokenError, classified: HookError) -> Renewal {
        let unsent = matches!(error, RequestTokenError::Request(e) if e.is_request_not_sent());
        if unsent || matches!(self.status.load(Ordering::Relaxed), 404 | 410) {
            Renewal::Stale(classified)
        } else if invalid_client(error) {
            Renewal::InvalidClient(classified)
        } else {
            Renewal::Failed(classified)
        }
    }
}
/// Acquisition failure; `Stale` means persisted metadata may be outdated.
enum Renewal {
    Stale(HookError),
    Failed(HookError),
    /// The token endpoint answered `invalid_client` (an OAuth error).
    InvalidClient(HookError),
    /// A DCR client-credentials registration at this issuer was deleted after
    /// `invalid_client`; register once more and re-acquire once.
    Reregister(String),
}
impl From<HookError> for Renewal {
    fn from(error: HookError) -> Self {
        Self::Failed(error)
    }
}
impl From<Renewal> for HookError {
    fn from(error: Renewal) -> Self {
        match error {
            Renewal::Stale(error) | Renewal::Failed(error) | Renewal::InvalidClient(error) => error,
            Renewal::Reregister(_) => fail(AuthErrorCode::CredentialUnavailable),
        }
    }
}
impl<'c> oauth2::AsyncHttpClient<'c> for TokenHttp {
    type Error = HookError;
    type Future = LocalFuture<'c, Result<oauth2::HttpResponse, HookError>>;
    fn call(&'c self, request: oauth2::HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self.send(request).await?;
            if response.status().is_redirection() || response.body().len() > 1024 * 1024 {
                // Never followed; the request may have been processed.
                return Err(fail(AuthErrorCode::ProviderFailed));
            }
            self.status
                .store(response.status().as_u16(), Ordering::Relaxed);
            *self.body.lock().unwrap() = Some(response.body().clone());
            Ok(if response.status().is_success() {
                response.map(|body| normalize_token_body(&body).unwrap_or(body))
            } else {
                response
            })
        })
    }
}
async fn checked_network_send(
    network: &dyn OAuthNetwork,
    request: oauth2::HttpRequest,
    usage: EndpointUse,
    budget: OperationBudget,
) -> Result<oauth2::HttpResponse, HookError> {
    let url = Url::parse(&request.uri().to_string())
        .map_err(|_| fail(AuthErrorCode::UntrustedDestination))?;
    if !valid_https(&url) {
        return Err(fail(AuthErrorCode::UntrustedDestination));
    }
    budget
        .run(async { (network.check(url, usage, budget).await).map_err(destination_refused) })
        .await?;
    let response = budget
        .run(network.send(request, usage, budget))
        .await
        .map_err(|error| error.transient_if(true))?;
    if response.status().is_redirection() || response.body().len() > 1024 * 1024 {
        return Err(fail(AuthErrorCode::UntrustedDestination));
    }
    Ok(response)
}
/// A host destination refusal (`OAuthNetwork::check`), for any URL: it keeps
/// the host's code, `untrusted_destination` when it has none, and never
/// carries scopes.
pub(super) fn destination_refused(error: HookError) -> HookError {
    HookError::authentication(
        error
            .auth_code()
            .unwrap_or(AuthErrorCode::UntrustedDestination),
    )
    .classified(error.code())
    .refused_destination()
}
type Client =
    BasicClient<EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;
type TokenError = RequestTokenError<HookError, BasicErrorResponse>;
fn invalid_client(error: &TokenError) -> bool {
    matches!(error, RequestTokenError::ServerResponse(r) if *r.error() == BasicErrorResponseType::InvalidClient)
}
fn fail(code: AuthErrorCode) -> HookError {
    HookError::authentication(code)
}
fn random_id() -> String {
    CsrfToken::new_random().secret().clone()
}
fn now() -> u64 {
    now_ms() / 1000
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |v| v.as_millis().min(u64::MAX as u128) as u64)
}
fn union(a: &[String], b: &[String]) -> Vec<String> {
    let mut all = [a, b].concat();
    all.sort();
    all.dedup();
    all
}
/// `scopes` ∩ `ceiling`, in `scopes` order.
fn within(ceiling: &[String], scopes: &[String]) -> Vec<String> {
    scopes
        .iter()
        .filter(|scope| ceiling.contains(scope))
        .cloned()
        .collect()
}
fn subset(scopes: &[String], of: &[String]) -> bool {
    scopes.iter().all(|scope| of.contains(scope))
}
impl ManagedOAuth {
    pub fn new(
        mut config: OAuthClientConfig,
        network: Arc<dyn OAuthNetwork>,
        policy: Arc<dyn OAuthPolicy>,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, HookError> {
        let invalid = || fail(AuthErrorCode::InvalidConfiguration);
        if config.allowed_scopes.is_empty() {
            config.allowed_scopes = config.requested_scopes.clone();
        }
        config.allowed_scopes = union(&config.allowed_scopes, &[]);
        config.required_scopes = union(&config.required_scopes, &[]);
        // Scope sets are checked by every operation's decision (step 1), after
        // a 401 retires its token, never here.
        if config
            .grant_partition
            .as_ref()
            .is_some_and(|p| p.is_empty())
            || config.namespace.is_empty()
            || config.client_id.as_ref().is_some_and(|id| id.is_empty())
            || config.client_id.is_none() && config.secret.is_some()
            || !config.registrations.iter().all(RegistrationPolicy::valid)
            || config.registrations.iter().enumerate().any(|(i, policy)| {
                config.registrations[..i]
                    .iter()
                    .any(|other| other.issuer() == policy.issuer())
            })
        {
            return Err(invalid());
        }
        if config.secret.as_ref().is_some_and(|(reference, secret)| {
            reference.is_empty()
                || secret.secret().is_empty()
                || config.method == TokenAuthMethod::None
        }) || (config.method != TokenAuthMethod::None && config.secret.is_none())
        {
            return Err(invalid());
        }
        if config.flow == OAuthFlow::ClientCredentials
            && config.client_id.is_some()
            && config.secret.is_none()
        {
            return Err(fail(AuthErrorCode::UnsupportedBinding));
        }
        if config
            .redirect_uri
            .as_deref()
            .is_some_and(|uri| !Url::parse(uri).is_ok_and(|uri| valid_redirect(&uri)))
        {
            return Err(invalid());
        }
        Ok(Self {
            config: Arc::new(config),
            network,
            policy,
            store,
            prepared: Arc::default(),
            pending: Arc::default(),
        })
    }
    fn prepared_key(context: &AuthContext) -> Option<String> {
        let target = context.target().ok()?;
        let purpose = match target.purpose() {
            AuthPurpose::Event => "event",
            AuthPurpose::Upload => "upload",
        };
        Some(frame(
            "ahp.oauth.prepared:",
            &[target.backend_id(), purpose, target.destination().as_str()],
        ))
    }
    fn mark_prepared(&self, context: &AuthContext) {
        if let Some(key) = Self::prepared_key(context) {
            let mut prepared = self.prepared.lock().unwrap();
            let count = prepared.entry(key).or_default();
            *count = count.saturating_add(1);
        }
    }
    fn flow_id(&self) -> &'static str {
        match self.config.flow {
            OAuthFlow::AuthorizationCodePkce => "authorization_code_pkce",
            OAuthFlow::ClientCredentials => "client_credentials",
        }
    }
    fn key(&self, target: &AuthTarget) -> SessionKey {
        self.binding_key(target.backend_id(), target.purpose(), target.destination())
    }
    fn binding_key(&self, backend_id: &str, purpose: AuthPurpose, destination: &Url) -> SessionKey {
        let purpose = match purpose {
            AuthPurpose::Event => "event",
            AuthPurpose::Upload => "upload",
        };
        SessionKey {
            storage_key: frame(
                "ahp.oauth.binding:",
                &[
                    &self.config.namespace,
                    backend_id,
                    purpose,
                    destination.as_str(),
                ],
            ),
            namespace: self.config.namespace.clone(),
            backend_id: backend_id.into(),
            destination: destination.as_str().into(),
            purpose: purpose.into(),
        }
    }
    /// No ceiling, auth method, secret or issued DCR `client_id`: changing those
    /// never orphans a grant. A different client identity (`preregistered:<id>`,
    /// `cimd:<url>` or `dcr`) is a different grant.
    fn grant_key(
        &self,
        target: &AuthTarget,
        metadata: &TrustedMetadata,
        client_identity: &str,
    ) -> SessionKey {
        self.grant_key_for(&self.key(target), metadata, client_identity)
    }
    fn grant_key_for(
        &self,
        binding_key: &SessionKey,
        metadata: &TrustedMetadata,
        client_identity: &str,
    ) -> SessionKey {
        let partition = match &self.config.grant_partition {
            Some(partition) => format!("shared:{partition}"),
            None => format!("binding:{}", binding_key.as_str()),
        };
        SessionKey {
            storage_key: frame(
                "ahp.oauth.grant:",
                &[
                    &self.config.namespace,
                    &metadata.issuer,
                    &metadata.resource,
                    client_identity,
                    self.flow_id(),
                    &partition,
                ],
            ),
            namespace: self.config.namespace.clone(),
            backend_id: String::new(),
            destination: String::new(),
            purpose: String::new(),
        }
    }
    /// The decision against a grant record before any authorization-server
    /// request: its outcome when that is use or a refusal (including step 9's
    /// interaction_required), `None` when a refresh, acquisition or login is
    /// needed. A token rejected by this 401 is unusable; its refresh token is.
    fn early(
        &self,
        record: Option<SessionRecord>,
        rejected: Option<&str>,
        decide: &GrantDecision<'_>,
        cc: bool,
    ) -> Option<Result<Option<Preparation>, Renewal>> {
        let token = record.and_then(|r| r.token).map(|mut token| {
            token.access_rejected |= rejected == Some(token.generation.as_str());
            token
        });
        match decide(&self.config.requested_scopes, token.as_ref(), !cc) {
            decide::Step::Use(credential) => Some(Ok(Some(Preparation::Ready(credential)))),
            decide::Step::Fail(error) => Some(Err(error.into())),
            _ => None,
        }
    }
    /// A pre-registered preset's grant key, known without any stored binding.
    fn preset_grant_key(&self, target: &AuthTarget) -> Option<SessionKey> {
        let (AuthBinding::OAuth { resource, .. }, Some(issuer), Some(client_id)) = (
            target.binding(),
            target.issuer(),
            self.preregistered(target),
        ) else {
            return None;
        };
        let metadata = TrustedMetadata::new(resource.clone(), issuer.to_owned(), String::new());
        Some(self.grant_key(target, &metadata, &format!("preregistered:{client_id}")))
    }
    fn binding_grant_key(&self, target: &AuthTarget, binding: &SessionRecord) -> SessionKey {
        self.grant_key(target, &binding.metadata, &Self::client_identity(binding))
    }
    /// The caller's ceiling.
    fn ceiling(&self) -> Vec<String> {
        self.config.allowed_scopes.clone()
    }
    fn validate_target(&self, target: &AuthTarget) -> Result<(), HookError> {
        match target.binding() {
            AuthBinding::Unbound => Ok(()),
            AuthBinding::OAuth { flow, .. }
                if *flow == self.config.flow
                    && self
                        .config
                        .client_id
                        .as_deref()
                        .is_none_or(|id| target.client_id() == Some(id)) =>
            {
                if let Some(reference) = target.client_secret_ref()
                    && self.config.secret.as_ref().map(|(r, _)| r.as_str()) != Some(reference)
                {
                    return Err(fail(AuthErrorCode::InvalidConfiguration));
                }
                // A preset client-credentials client needs the host's secret.
                if *flow == OAuthFlow::ClientCredentials && self.config.client_id.is_none() {
                    return Err(fail(AuthErrorCode::UnsupportedBinding));
                }
                Ok(())
            }
            _ => Err(fail(AuthErrorCode::UnsupportedBinding)),
        }
    }
    /// A saved binding is only reused for the same principal as the current target
    /// and while host policy still selects its recorded client.
    fn compatible(&self, target: &AuthTarget, record: &SessionRecord) -> bool {
        self.selection_current(target, record) && self.same_principal(target, record)
    }
    /// The saved binding is for this target's flow, issuer and resource.
    fn same_principal(&self, target: &AuthTarget, record: &SessionRecord) -> bool {
        record.flow == self.flow_id()
            && target
                .issuer()
                .is_none_or(|issuer| issuer == record.metadata.issuer)
            && !matches!(target.binding(), AuthBinding::OAuth { resource, .. } if resource != &record.metadata.resource)
    }
    pub(super) fn approve_metadata(
        &self,
        target: &AuthTarget,
        metadata: &TrustedMetadata,
    ) -> Result<(), HookError> {
        self.policy
            .approve_endpoints(EndpointTrust {
                target,
                client_id: self.preregistered(target).unwrap_or_default(),
                client_secret_ref: self
                    .config
                    .secret
                    .as_ref()
                    .map(|(reference, _)| reference.as_str()),
                metadata,
            })
            .map_err(decide::classify)
    }
    /// Apply host issuer policy; returns the decision with S, this target's
    /// requested scopes: the policy's selection, else the configured requested
    /// scopes. Its errors keep their code and carry no scopes; an untrusted
    /// issuer is `access_denied`; S beyond the ceiling, or a present preset
    /// `scopes` other than S, is `invalid_configuration`.
    pub(super) fn select(
        &self,
        target: &AuthTarget,
        resource: &ResourceMetadata,
        required: &[String],
    ) -> Result<TrustDecision, HookError> {
        let mut decision = self
            .policy
            .select(target, resource, required)
            .map_err(decide::classify)?;
        decision.scopes = if decision.scopes.is_empty() {
            self.config.requested_scopes.clone()
        } else {
            union(&decision.scopes, &[])
        };
        if !resource.authorization_servers.contains(&decision.issuer)
            || target
                .issuer()
                .is_some_and(|issuer| issuer != decision.issuer)
        {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        if !subset(&decision.scopes, &self.ceiling())
            || target
                .preset_scopes()
                .is_some_and(|preset| union(preset, &[]) != decision.scopes)
        {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
        Ok(decision)
    }
    /// The operation's single host policy selection, before the scope
    /// decision, for a known binding (a compatible stored one, else an
    /// explicit preset) without any network request. Nothing for an unbound
    /// target without a stored binding: discovery selects once it knows the
    /// authorization servers.
    fn preselect(
        &self,
        selections: &Selections,
        target: &AuthTarget,
        saved: Option<&SessionRecord>,
        required: &[String],
    ) {
        let (resource, issuer) = match saved.filter(|r| self.compatible(target, r)) {
            Some(binding) => (
                binding.metadata.resource.clone(),
                binding.metadata.issuer.clone(),
            ),
            None => match (target.binding(), target.issuer()) {
                (AuthBinding::OAuth { resource, .. }, Some(issuer)) => {
                    (resource.clone(), issuer.to_owned())
                }
                _ => return,
            },
        };
        let resource = ResourceMetadata::new(resource, vec![issuer]);
        let _ = self.selected(selections, target, &resource, required);
    }
    /// The operation's selection for these authorization servers: the one it
    /// already made (or its refusal) when it covers them, else a new one, kept
    /// for the rest of the operation, including every re-attempt.
    pub(super) fn selected(
        &self,
        selections: &Selections,
        target: &AuthTarget,
        resource: &ResourceMetadata,
        required: &[String],
    ) -> Result<TrustDecision, HookError> {
        let mut held = selections.lock().unwrap();
        if let Some(reused) = held
            .as_ref()
            .and_then(|selection| selection.reuse(&resource.authorization_servers))
        {
            return reused;
        }
        let result = self.select(target, resource, required);
        *held = Some(Selection {
            servers: resource.authorization_servers.clone(),
            result: result.clone(),
        });
        result
    }
    /// Revalidate a saved binding against current local policy, without network.
    fn validate_saved(
        &self,
        target: &AuthTarget,
        record: &SessionRecord,
        required: &[String],
    ) -> Result<Vec<String>, HookError> {
        self.check_saved(target, record)?;
        let resource = ResourceMetadata::new(
            record.metadata.resource.clone(),
            vec![record.metadata.issuer.clone()],
        );
        Ok(self.select(target, &resource, required)?.scopes)
    }
    /// The local (non-policy) checks of a saved binding's provenance.
    fn check_saved(&self, target: &AuthTarget, record: &SessionRecord) -> Result<(), HookError> {
        if matches!(target.binding(), AuthBinding::Unbound) && !record.configured_binding {
            discovery::validate_saved_source(
                target.destination(),
                &record.metadata.resource,
                record.resource_metadata_hint.as_ref(),
            )?;
        } else {
            discovery::validate_resource(
                &record.metadata.resource,
                target.destination(),
                Some(&record.metadata.resource),
            )?;
        }
        Ok(())
    }
    pub(super) async fn check_url(
        &self,
        url: &Url,
        usage: EndpointUse,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        if !valid_https(url) {
            return Err(fail(AuthErrorCode::UntrustedDestination));
        }
        budget
            .run(async {
                (self.network.check(url.clone(), usage, budget).await).map_err(destination_refused)
            })
            .await
    }
    pub(super) async fn checked_send(
        &self,
        request: oauth2::HttpRequest,
        usage: EndpointUse,
        budget: OperationBudget,
    ) -> Result<oauth2::HttpResponse, HookError> {
        checked_network_send(&*self.network, request, usage, budget).await
    }
    async fn load(
        &self,
        key: &SessionKey,
        budget: OperationBudget,
    ) -> Result<Option<SessionRecord>, HookError> {
        let mut guard = budget.run(self.store.acquire(key.clone(), budget)).await?;
        budget.run(guard.load()).await
    }
    async fn persist(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        persist(guard, record, budget).await
    }
    /// Host-initiated preparation; bounded by both the supplied budget and context.
    /// The only operation that creates a pending login. To request step-up consent
    /// after `interaction_required`, pass its `HookError::required_scopes` to
    /// `prepare_with_required`; challenge requirements are not stored.
    pub async fn prepare(
        &self,
        context: AuthContext,
        budget: OperationBudget,
    ) -> Result<Preparation, HookError> {
        self.prepare_with_required(context, &[], budget).await
    }
    /// `prepare` with explicit operation requirements, such as the
    /// `HookError::required_scopes` of an `interaction_required` step-up.
    pub async fn prepare_with_required(
        &self,
        context: AuthContext,
        required: &[String],
        budget: OperationBudget,
    ) -> Result<Preparation, HookError> {
        let options = PrepareOptions::new().required(required.to_vec());
        self.prepare_with(context, options, budget).await
    }
    /// `prepare` with explicit options; the only path that creates a pending login
    /// and, with DCR, registers a PKCE client for that login's redirect.
    pub async fn prepare_with(
        &self,
        context: AuthContext,
        options: PrepareOptions,
        budget: OperationBudget,
    ) -> Result<Preparation, HookError> {
        if !options.required.iter().all(|scope| valid_scope(scope)) {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
        let redirect = self.login_redirect(&options)?;
        let budget = OperationBudget::until(budget.deadline.min(context.deadline));
        let prepared = budget
            .run(async {
                let target = context.target()?;
                self.validate_target(&target)?;
                let required = &options.required;
                let force = AtomicBool::new(options.force_registration);
                let login = Login {
                    redirect,
                    required,
                    force: Some(&force),
                    forced: false,
                };
                let pending = self
                    .acquire(context.clone(), None, login, None, budget, Mode::Prepare)
                    .await?;
                pending.ok_or_else(|| fail(AuthErrorCode::ProviderFailed))
            })
            .await?;
        if matches!(prepared, Preparation::Ready(_)) {
            self.mark_prepared(&context);
        }
        Ok(prepared)
    }
    /// A PKCE login's redirect, checked before client selection or any request:
    /// HTTPS, a literal loopback IP (never `localhost`) or a private-use scheme.
    fn login_redirect<'a>(
        &'a self,
        options: &'a PrepareOptions,
    ) -> Result<Option<&'a str>, HookError> {
        if self.config.flow != OAuthFlow::AuthorizationCodePkce {
            return Ok(None);
        }
        options
            .redirect_uri
            .as_deref()
            .or(self.config.redirect_uri.as_deref())
            .filter(|uri| Url::parse(uri).is_ok_and(|uri| valid_redirect(&uri)))
            .map(Some)
            .ok_or_else(|| fail(AuthErrorCode::InvalidConfiguration))
    }
    /// Every credential and challenge entry point: the scope decision
    /// (`decide`) before any network request, then binding, grant and token
    /// I/O. A 403 challenge's scopes apply to this operation only and are
    /// never stored; `sent` is the generation the rejected request carried.
    async fn acquire(
        &self,
        context: AuthContext,
        rejection: Option<decide::Rejection<'_>>,
        login: Login<'_>,
        sent: Option<&str>,
        budget: OperationBudget,
        mode: Mode,
    ) -> Result<Option<Preparation>, HookError> {
        let target = context.target()?;
        self.validate_target(&target)?;
        decide::configuration(&self.config, target.preset_scopes(), login.required)?;
        let saved = self.load(&self.key(&target), budget).await?;
        // A lookup's store miss is anonymous delivery, before any scope decision.
        if mode == Mode::Lookup && saved.is_none() {
            return Ok(None);
        }
        // Select once, before the decision, so step 1 (S within the ceiling,
        // a preset equal to S) precedes the rest; the selection is told R.
        let operation = decide::operation(&self.config, login.required, rejection);
        let required = match &operation {
            Ok(operation) => operation.required.clone(),
            Err(error) if !error.required_scopes().is_empty() => error.required_scopes().to_vec(),
            Err(_) => union(&self.config.required_scopes, login.required),
        };
        let selections = Selections::default();
        self.preselect(&selections, &target, saved.as_ref(), &required);
        if let Some(Selection {
            result: Err(error), ..
        }) = &*selections.lock().unwrap()
            && error.auth_code() == Some(AuthErrorCode::InvalidConfiguration)
        {
            return Err(error.clone());
        }
        let operation = operation?;
        let challenged = operation.challenge.is_some();
        // Every re-attempt of this operation shares its selection.
        let selection = &selections;
        let login = Login {
            forced: mode == Mode::Prepare
                && self.config.flow == OAuthFlow::ClientCredentials
                && login.forcing(),
            ..login
        };
        let attempt = |rediscover| {
            self.acquire_inner(
                &target, &operation, selection, login, sent, budget, mode, rediscover,
            )
        };
        let result = match attempt(false).await {
            // The token endpoint provably did not process the renewal: refetch the
            // stored issuer's metadata once (never protected-resource) and retry once.
            Err(Renewal::Stale(_)) => match self.refetch_issuer(&target, budget).await {
                Ok(()) => attempt(false).await,
                Err(error) => Err(Renewal::Stale(error)),
            },
            result => result,
        };
        // Challenge handling and `prepare` may repair the binding with full
        // protected-resource discovery (honouring a challenge's resource_metadata).
        let result = match result {
            Err(Renewal::Stale(_)) if challenged || mode == Mode::Prepare => attempt(true).await,
            result => result,
        };
        // A deleted DCR client-credentials registration: register once more and
        // re-acquire once; a repeated invalid_client is credential_unavailable
        // and counts as a failed registration for the backoff.
        let result = match result {
            Err(Renewal::Reregister(_)) => match attempt(false).await {
                Err(Renewal::Reregister(issuer)) => {
                    self.mark_failed(&issuer, budget).await;
                    Err(fail(AuthErrorCode::CredentialUnavailable).into())
                }
                result => result,
            },
            result => result,
        };
        result.map_err(Into::into)
    }
    async fn refetch_issuer(
        &self,
        target: &AuthTarget,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        let discovery = || fail(AuthErrorCode::DiscoveryFailed);
        let key = self.key(target);
        let binding = self.load(&key, budget).await?.ok_or_else(discovery)?;
        let metadata = discovery::issuer_metadata(
            self,
            target,
            binding.metadata.resource.clone(),
            binding.metadata.issuer.clone(),
            budget,
        )
        .await
        // A host destination refusal keeps its code; any other failure to
        // fetch or validate the metadata is discovery_failed.
        .map_err(|error| {
            if error.is_refused_destination() {
                error
            } else {
                discovery()
            }
        })?;
        let mut guard = budget.run(self.store.acquire(key, budget)).await?;
        let mut current = budget.run(guard.load()).await?.ok_or_else(discovery)?;
        if current.metadata.issuer != metadata.issuer {
            return Err(discovery());
        }
        current.metadata = metadata;
        self.persist(&mut *guard, &mut current, budget).await
    }
    /// Step 0: a 401 retires the rejected generation before every decision
    /// step and every target or configuration check, whenever the stored
    /// binding identifies its grant, so neither a refusal nor a failed
    /// discovery or renewal leaves it servable. Only an unparseable target
    /// (no binding key) or an exhausted budget stops it.
    async fn retire_rejected(
        &self,
        context: &AuthContext,
        attempt: &str,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        // The binding key needs only the backend, purpose and destination, so
        // a target that fails validation still identifies it.
        let Ok(destination) = Url::parse(&context.destination) else {
            return Ok(());
        };
        let key = self.binding_key(&context.backend_id, context.purpose, &destination);
        // The stored binding names the rejected grant, even when it is no
        // longer compatible with this target or configuration.
        let Some(binding) = self.load(&key, budget).await? else {
            return Ok(());
        };
        let grant = self.grant_key_for(&key, &binding.metadata, &Self::client_identity(&binding));
        self.retire_generation(grant, attempt, budget).await
    }
    /// Mark this exact token generation as rejected in the store.
    async fn retire_generation(
        &self,
        key: SessionKey,
        attempt: &str,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        let mut guard = budget.run(self.store.acquire(key, budget)).await?;
        if let Some(mut record) = budget.run(guard.load()).await?
            && let Some(token) = record.token.as_mut()
            && token.generation == attempt
            && !token.access_rejected
        {
            token.access_rejected = true;
            self.persist(&mut *guard, &mut record, budget).await?;
        }
        Ok(())
    }
    /// Full discovery (outside any store guard) and a write-on-change binding update.
    #[allow(clippy::too_many_arguments)]
    async fn rebind(
        &self,
        target: &AuthTarget,
        resource: discovery::Resource,
        cached_issuer: Option<&str>,
        binding_key: SessionKey,
        budget: OperationBudget,
    ) -> Result<(SessionRecord, Vec<String>), HookError> {
        let (metadata, hint, scopes) =
            discovery::discover(self, target, resource, cached_issuer, budget).await?;
        self.store_binding(target, metadata, hint, binding_key, budget)
            .await
            .map(|binding| (binding, scopes))
    }
    /// A write-on-change binding update; a recorded client selection survives
    /// metadata changes until host policy changes it.
    async fn store_binding(
        &self,
        target: &AuthTarget,
        metadata: TrustedMetadata,
        hint: Option<discovery::ResourceMetadataHint>,
        binding_key: SessionKey,
        budget: OperationBudget,
    ) -> Result<SessionRecord, HookError> {
        let mut binding = SessionRecord {
            configured_binding: !matches!(target.binding(), AuthBinding::Unbound),
            resource_metadata_hint: hint,
            ..SessionRecord::empty(metadata, self.flow_id())
        };
        let mut guard = budget.run(self.store.acquire(binding_key, budget)).await?;
        let current = budget.run(guard.load()).await?;
        // A recorded selection survives metadata changes until host policy changes it.
        match current.as_ref().filter(|current| {
            current.metadata.issuer == binding.metadata.issuer
                && current.flow == binding.flow
                && self.selection_current(target, current)
        }) {
            Some(current) => {
                binding.client_source = current.client_source;
                binding.client_id = current.client_id.clone();
            }
            None => {
                binding.client_source = self.select_source(target, &binding.metadata)?;
                binding.client_id = match binding.client_source {
                    ClientSource::Preregistered => {
                        self.preregistered(target).unwrap_or_default().into()
                    }
                    ClientSource::Cimd => self.config.cimd.as_ref().unwrap().url.clone(),
                    ClientSource::Dcr => String::new(),
                };
            }
        }
        match current {
            Some(current) if current.same_binding(&binding) => {}
            current => {
                binding.version = current.map(|r| r.version).unwrap_or_default();
                self.persist(&mut *guard, &mut binding, budget).await?;
            }
        }
        Ok(binding)
    }
    #[allow(clippy::too_many_arguments)]
    async fn acquire_inner(
        &self,
        target: &AuthTarget,
        operation: &decide::Operation,
        selection: &Selections,
        login: Login<'_>,
        sent: Option<&str>,
        budget: OperationBudget,
        mode: Mode,
        rediscover: bool,
    ) -> Result<Option<Preparation>, Renewal> {
        let redirect = login.redirect;
        let target = target.clone();
        let required = operation.required.clone();
        let challenge = operation.challenge.as_ref();
        // Only a 401 retires the generation it rejected.
        let rejected = sent.filter(|_| operation.unauthorized);
        let cc = self.config.flow == OAuthFlow::ClientCredentials;
        // Before a selection, S defaults to the configured requested scopes;
        // only acquisitions and logins (after one) request it.
        let decide = |requested: &[String], token: Option<&SavedToken>, can_refresh: bool| {
            decide::grant(
                &self.config,
                operation,
                mode,
                requested,
                token,
                sent,
                can_refresh,
            )
        };
        let configured = &self.config.requested_scopes;
        let binding_key = self.key(&target);
        let saved = self.load(&binding_key, budget).await?;
        // Local authorization of a saved binding needs no network; policy runs off-lock.
        let mut usable = None;
        // The known binding passed validation and selection, with this S.
        let mut validated = None;
        // A known binding for another client or flow needs `prepare`, not anonymity.
        if mode == Mode::Lookup && saved.as_ref().is_some_and(|r| !self.compatible(&target, r)) {
            return Err(fail(AuthErrorCode::DiscoveryFailed).into());
        }
        // Challenge handling always rebinds through full discovery, so a resource
        // that moved to another authorization server is found even if the old one
        // still answers. The stored issuer's metadata is not refetched first.
        let force = rediscover || challenge.is_some();
        let known = saved.as_ref().filter(|r| self.compatible(&target, r));
        if let Some(binding) = known {
            // The operation's selection, again only for another issuer.
            let selected = self.check_saved(&target, binding).and_then(|()| {
                let resource = ResourceMetadata::new(
                    binding.metadata.resource.clone(),
                    vec![binding.metadata.issuer.clone()],
                );
                self.selected(selection, &target, &resource, &required)
                    .map(|decision| decision.scopes)
            });
            match selected {
                Ok(scopes) => validated = Some(scopes),
                // A selection beyond the ceiling is a configuration error in every mode.
                Err(error) if error.auth_code() == Some(AuthErrorCode::InvalidConfiguration) => {
                    return Err(error.into());
                }
                Err(_) if mode == Mode::Lookup => return Ok(None),
                // Policy no longer approves the stored binding: rebind by discovery.
                Err(_) if mode == Mode::Prepare || force => {}
                Err(error) => return Err(error.into()),
            }
        }
        // Outcomes that need no authorization-server request (use, a step 1
        // to 5 refusal, step 9's interaction_required) are returned before
        // any discovery or metadata fetch, for any challenge or delivery
        // against the known grant: a validated stored binding's (even without
        // persisted metadata), or a pre-registered preset's when none is
        // stored. A refresh, an acquisition or a login continues below.
        // A forced re-registration of a client-credentials DCR client never
        // serves its existing token, in any attempt of the operation.
        let forced = |source: ClientSource| login.forced && source == ClientSource::Dcr;
        if !known.is_some_and(|binding| forced(binding.client_source)) {
            // A stored binding host policy refuses is never decided on: its
            // refusal surfaces (after rediscovery for a challenge).
            let early = match known {
                Some(binding) if validated.is_some() => {
                    Some(self.binding_grant_key(&target, binding))
                }
                None if selection
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|s| s.result.is_ok()) =>
                {
                    self.preset_grant_key(&target)
                }
                _ => None,
            };
            if let Some(key) = early {
                // Every host `prepare` deletes the grant key's expired pending logins.
                if mode == Mode::Prepare {
                    self.end_login(&key, None, budget).await?;
                }
                let record = self.load(&key, budget).await?;
                if let Some(step) = self.early(record, rejected, &decide, cc) {
                    return step;
                }
            }
        }
        // A validated known binding is usable once it has authorization-server
        // metadata: absent, fetch only the stored issuer's (never
        // protected-resource metadata), now that a request is needed.
        if let (Some(binding), Some(scopes)) = (known, validated) {
            let mut binding = binding.clone();
            if binding.metadata.token_endpoint.is_empty() && mode != Mode::Prepare && !force {
                binding.metadata = discovery::issuer_metadata(
                    self,
                    &target,
                    binding.metadata.resource.clone(),
                    binding.metadata.issuer.clone(),
                    budget,
                )
                .await
                .map_err(Renewal::Stale)?;
                let mut guard = budget
                    .run(self.store.acquire(binding_key.clone(), budget))
                    .await?;
                self.persist(&mut *guard, &mut binding, budget).await?;
            }
            if !binding.metadata.token_endpoint.is_empty()
                && self.approve_metadata(&target, &binding.metadata).is_ok()
            {
                usable = Some((binding, scopes));
            }
        }
        // `prepare` serves a usable cached token, otherwise rebuilds binding metadata
        // so stale persisted metadata always has a repair path.
        let mut discover_now = force || usable.is_none();
        if mode == Mode::Prepare
            && let Some((binding, _)) = &usable
        {
            let key = self.binding_grant_key(&target, binding);
            // Every host `prepare` deletes the grant key's expired pending logins.
            self.end_login(&key, None, budget).await?;
            let record = self.load(&key, budget).await?;
            if !forced(binding.client_source)
                && let decide::Step::Use(credential) = decide(
                    configured,
                    record.as_ref().and_then(|r| r.token.as_ref()),
                    !cc,
                )
            {
                return Ok(Some(Preparation::Ready(credential)));
            }
            discover_now = true;
        }
        let (binding, selected) = match usable {
            Some(found) if !discover_now => found,
            None if mode == Mode::Lookup => return Ok(None),
            cached => {
                let hint = saved
                    .as_ref()
                    .and_then(|r| r.resource_metadata_hint.as_ref());
                let cached_issuer = cached.as_ref().map(|(b, _)| b.metadata.issuer.as_str());
                let rebound = async {
                    let resource = discovery::discover_resource(
                        self, &target, challenge, hint, &required, selection, budget,
                    )
                    .await?;
                    // A pre-registered client's grant is known once the issuer
                    // is: decide before any authorization-server request, and
                    // store a binding without authorization-server metadata.
                    if saved.is_none()
                        && let Some(client_id) = self.preregistered(&target)
                    {
                        let metadata = TrustedMetadata::new(
                            resource.resource.clone(),
                            resource.decision.issuer.clone(),
                            String::new(),
                        );
                        let key = self.grant_key(
                            &target,
                            &metadata,
                            &format!("preregistered:{client_id}"),
                        );
                        // Every host `prepare` deletes the grant key's expired
                        // pending logins.
                        if mode == Mode::Prepare {
                            self.end_login(&key, None, budget).await?;
                        }
                        let record = self.load(&key, budget).await?;
                        if let Some(step) = self.early(record, rejected, &decide, cc) {
                            self.store_binding(
                                &target,
                                metadata,
                                resource.hint.clone(),
                                binding_key.clone(),
                                budget,
                            )
                            .await?;
                            return Ok(Err(step));
                        }
                    }
                    self.rebind(&target, resource, cached_issuer, binding_key, budget)
                        .await
                        .map(Ok)
                };
                match rebound.await {
                    Ok(Err(step)) => return step,
                    Ok(Ok(found)) => found,
                    // A transient discovery outage (transport failure or 5xx) during
                    // challenge handling renews through the still-valid cached binding.
                    // Definitive failures, or metadata naming another issuer, never do.
                    Err(error)
                        if challenge.is_some() && cached.is_some() && error.is_transient() =>
                    {
                        cached.unwrap()
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        };
        // The grant is keyed by the configured client source, so a still-valid
        // token is served before any client-credentials registration.
        let key = self.binding_grant_key(&target, &binding);
        if mode == Mode::Prepare {
            self.end_login(&key, None, budget).await?;
        }
        let stored = self.load(&key, budget).await?;
        let token = stored
            .as_ref()
            .and_then(|r| r.token.as_ref())
            .filter(|token| rejected != Some(token.generation.as_str()));
        match decide(&selected, token, !cc) {
            decide::Step::Fail(error) if operation.step_up => return Err(error.into()),
            decide::Step::Use(credential) if !forced(binding.client_source) => {
                return Ok(Some(Preparation::Ready(credential)));
            }
            _ => {}
        }
        let mut choice = match binding.client_source {
            ClientSource::Dcr if cc => {
                let force = mode == Mode::Prepare
                    && login.force.is_some_and(|f| f.swap(false, Ordering::SeqCst));
                self.registered(&binding.metadata, mode, force, budget)
                    .await?
            }
            _ => self.configured_choice(&target, &binding),
        };
        let mut guard = budget.run(self.store.acquire(key.clone(), budget)).await?;
        let loaded = budget.run(guard.load()).await?;
        let mut record = loaded.unwrap_or_else(|| SessionRecord {
            version: String::new(),
            ..binding.clone()
        });
        let mut dirty = record.metadata != binding.metadata;
        record.metadata = binding.metadata.clone();
        // A 401 for this exact generation retires it; a stale 401 cannot reject a newer token.
        if let Some(token) = record.token.as_mut()
            && rejected == Some(token.generation.as_str())
            && !token.access_rejected
        {
            token.access_rejected = true;
            dirty = true;
        }
        // Persist a rejection before any renewal that can fail, so the revoked
        // token is never served again from the store.
        if dirty {
            self.persist(&mut *guard, &mut record, budget).await?;
        }
        // A PKCE DCR grant refreshes with the client stored alongside its tokens.
        if !cc && choice.source == ClientSource::Dcr {
            choice.id = record.client_id.clone();
        }
        // An acquisition for an existing grant keeps what was previously granted.
        let previous = record
            .token
            .as_ref()
            .map_or(Vec::new(), |t| t.scopes.clone());
        let ceiling = self.ceiling();
        // After a client-credentials DCR client's forced re-registration the
        // existing token is not usable: acquire with the new client.
        let token = record.token.clone().map(|mut token| {
            if forced(binding.client_source) {
                token.access_rejected = true;
                token.refresh_token = None;
            }
            token
        });
        let scopes = match decide(&selected, token.as_ref(), !cc && !choice.id.is_empty()) {
            decide::Step::Use(credential) => return Ok(Some(Preparation::Ready(credential))),
            decide::Step::Fail(error) => return Err(error.into()),
            decide::Step::Refresh => {
                let result = self
                    .refresh(
                        &mut guard,
                        &mut record,
                        &choice,
                        &required,
                        &ceiling,
                        budget,
                    )
                    .await;
                drop(guard);
                return self
                    .client_failure(result, &choice, &binding, budget)
                    .await
                    .map(|c| Some(Preparation::Ready(c)));
            }
            decide::Step::Acquire(scopes) => {
                let result = self
                    .client_credentials(
                        &mut guard,
                        &mut record,
                        &choice,
                        &scopes,
                        &previous,
                        &required,
                        &ceiling,
                    )
                    .await;
                drop(guard);
                if result.is_ok()
                    && let Some(generation) = &choice.generation
                {
                    // Best effort: the token is already committed.
                    let _ = self
                        .registration_worked(&binding.metadata.issuer, generation, budget)
                        .await;
                }
                return self
                    .client_failure(result, &choice, &binding, budget)
                    .await
                    .map(|c| Some(Preparation::Ready(c)));
            }
            decide::Step::Login(scopes) => scopes,
        };
        drop(guard);
        let redirect = redirect.ok_or_else(|| fail(AuthErrorCode::InvalidConfiguration))?;
        self.check_login_redirect(binding.client_source, redirect)?;
        // As in MCP clients, DCR runs inside each login with its exact redirect.
        if choice.source == ClientSource::Dcr {
            choice = self
                .register_login(&record.metadata, redirect, budget)
                .await?;
        }
        let authorization = record
            .metadata
            .authorization_endpoint
            .clone()
            .ok_or_else(|| fail(AuthErrorCode::DiscoveryFailed))?;
        let client = self
            .client(&record.metadata, &choice, Some(redirect))?
            .set_auth_uri(
                AuthUrl::new(authorization).map_err(|_| fail(AuthErrorCode::DiscoveryFailed))?,
            );
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(challenge)
            .add_extra_param("resource", &record.metadata.resource);
        for scope in &scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let (url, state) = request.url();
        self.check_url(&url, EndpointUse::Authorization, budget)
            .await?;
        let login = SavedLogin {
            id: random_id(),
            metadata: record.metadata.clone(),
            scopes,
            ceiling,
            required: Some(required),
            state: state.secret().clone(),
            verifier: verifier.secret().clone(),
            redirect_uri: redirect.into(),
            expires_at_ms: now_ms().saturating_add(self.config.login_lifetime.as_millis() as u64),
            client_id: choice.id,
        };
        let pending = PendingLogin {
            key: Box::new(key.clone()),
            id: login.id.clone(),
            url,
            redirect_uri: login.redirect_uri.clone(),
            expires_at: UNIX_EPOCH + Duration::from_millis(login.expires_at_ms),
        };
        self.add_login(&key, record, login, budget).await?;
        Ok(Some(Preparation::InteractionRequired(pending)))
    }
    /// Admit a pending login for a grant key, deleting expired ones and
    /// cancelling the oldest beyond the cap; atomic under the grant lock when
    /// persisted.
    async fn add_login(
        &self,
        key: &SessionKey,
        template: SessionRecord,
        login: SavedLogin,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        let cap = self.config.max_pending_logins;
        let admit = |logins: &mut Vec<SavedLogin>| {
            logins.retain(|l| l.expires_at_ms > now_ms());
            logins.push(login);
            let excess = logins.len().saturating_sub(cap);
            logins.drain(..excess);
        };
        if !self.config.persist_pending_logins {
            admit(
                self.pending
                    .lock()
                    .unwrap()
                    .entry(key.as_str().into())
                    .or_default(),
            );
            return Ok(());
        }
        let mut guard = budget.run(self.store.acquire(key.clone(), budget)).await?;
        let mut record = budget.run(guard.load()).await?.unwrap_or(SessionRecord {
            version: String::new(),
            token: None,
            pending_logins: Vec::new(),
            ..template
        });
        admit(&mut record.pending_logins);
        self.persist(&mut *guard, &mut record, budget).await
    }
    /// A live pending login of a grant key by `state`, without ending it.
    async fn find_login(
        &self,
        key: &SessionKey,
        state: &CsrfToken,
        budget: OperationBudget,
    ) -> Result<Option<SavedLogin>, HookError> {
        let live = |logins: &[SavedLogin]| {
            logins
                .iter()
                .find(|l| l.expires_at_ms > now_ms() && *state == CsrfToken::new(l.state.clone()))
                .cloned()
        };
        if !self.config.persist_pending_logins {
            let pending = self.pending.lock().unwrap();
            return Ok(pending.get(key.as_str()).and_then(|logins| live(logins)));
        }
        Ok(self
            .load(key, budget)
            .await?
            .and_then(|record| live(&record.pending_logins)))
    }
    /// End the pending login `id` (if any) and delete expired ones; returns the
    /// login if it was still live, so only one callback can claim it.
    async fn end_login(
        &self,
        key: &SessionKey,
        id: Option<&str>,
        budget: OperationBudget,
    ) -> Result<Option<SavedLogin>, HookError> {
        let end = |logins: &mut Vec<SavedLogin>| {
            logins.retain(|l| l.expires_at_ms > now_ms());
            let at = logins.iter().position(|l| Some(l.id.as_str()) == id)?;
            Some(logins.remove(at))
        };
        if !self.config.persist_pending_logins {
            let mut pending = self.pending.lock().unwrap();
            let Some(logins) = pending.get_mut(key.as_str()) else {
                return Ok(None);
            };
            let ended = end(logins);
            if logins.is_empty() {
                pending.remove(key.as_str());
            }
            return Ok(ended);
        }
        let mut guard = budget.run(self.store.acquire(key.clone(), budget)).await?;
        let Some(mut record) = budget.run(guard.load()).await? else {
            return Ok(None);
        };
        let before = record.pending_logins.len();
        let ended = end(&mut record.pending_logins);
        if record.pending_logins.len() != before {
            self.persist(&mut *guard, &mut record, budget).await?;
        }
        Ok(ended)
    }
    /// `invalid_client`: a CIMD client is misconfigured; a PKCE DCR client needs
    /// a new login (a refresh already compare-and-deleted its grant); a client-
    /// credentials registration generation is compare-and-deleted, then
    /// registered once more.
    async fn client_failure(
        &self,
        result: Result<BearerCredential, Renewal>,
        choice: &ClientChoice,
        binding: &SessionRecord,
        budget: OperationBudget,
    ) -> Result<BearerCredential, Renewal> {
        let Err(Renewal::InvalidClient(error)) = result else {
            return result;
        };
        match choice.source {
            ClientSource::Preregistered => Err(Renewal::Failed(error)),
            ClientSource::Cimd => Err(fail(AuthErrorCode::InvalidConfiguration).into()),
            ClientSource::Dcr if self.config.flow == OAuthFlow::AuthorizationCodePkce => {
                Err(fail(AuthErrorCode::InteractionRequired).into())
            }
            ClientSource::Dcr => {
                if let Some(generation) = &choice.generation {
                    self.forget(&binding.metadata.issuer, generation, budget)
                        .await?;
                }
                Err(Renewal::Reregister(binding.metadata.issuer.clone()))
            }
        }
    }
    /// `redirect` is the login's exact redirect, sent with authorization and code
    /// exchange requests only.
    fn client(
        &self,
        metadata: &TrustedMetadata,
        choice: &ClientChoice,
        redirect: Option<&str>,
    ) -> Result<Client, HookError> {
        let method = match choice.method {
            TokenAuthMethod::None => "none",
            TokenAuthMethod::ClientSecretBasic => "client_secret_basic",
            TokenAuthMethod::ClientSecretPost => "client_secret_post",
        };
        let supported = if metadata.token_endpoint_auth_methods_supported.is_empty() {
            method == "client_secret_basic"
        } else {
            metadata
                .token_endpoint_auth_methods_supported
                .iter()
                .any(|s| s == method)
        };
        if !supported {
            return Err(fail(AuthErrorCode::UnsupportedBinding));
        }
        let mut client = BasicClient::new(ClientId::new(choice.id.clone()))
            .set_token_uri(
                TokenUrl::new(metadata.token_endpoint.clone())
                    .map_err(|_| fail(AuthErrorCode::DiscoveryFailed))?,
            )
            .set_auth_type(if choice.method == TokenAuthMethod::ClientSecretBasic {
                AuthType::BasicAuth
            } else {
                AuthType::RequestBody
            });
        if let Some(secret) = &choice.secret {
            client = client.set_client_secret(oauth2::ClientSecret::new(secret.secret().clone()));
        }
        if let Some(redirect) = redirect {
            client = client.set_redirect_uri(
                RedirectUrl::new(redirect.into())
                    .map_err(|_| fail(AuthErrorCode::InvalidConfiguration))?,
            );
        }
        Ok(client)
    }
    fn committer(&self, ceiling: &[String]) -> Committer {
        Committer {
            allowed: ceiling.to_vec(),
            timeout: self.config.commit_timeout,
        }
    }
    /// Run a token exchange that owns the grant guard and record. Before its
    /// request is written, dropping the caller aborts it and releases the lock;
    /// afterwards it receives the response and commits the outcome itself under
    /// a fresh commit budget, holding the lock, and only then reports back.
    async fn detached<T: Send + 'static>(
        &self,
        guard: &mut Box<dyn CredentialGuard>,
        record: &mut SessionRecord,
        ceiling: &[String],
        exchange: impl FnOnce(
            Box<dyn CredentialGuard>,
            SessionRecord,
            TokenHttp,
            Committer,
        ) -> Exchange<T>,
    ) -> Result<T, HookError> {
        let committer = self.committer(ceiling);
        let http = TokenHttp {
            network: self.network.clone(),
            budget: commit_budget(committer.timeout),
            written: RequestWritten::default(),
            status: AtomicU16::new(0),
            body: std::sync::Mutex::new(None),
        };
        let written = http.written.clone();
        let owned = std::mem::replace(guard, Box::new(Committing));
        let future = exchange(owned, record.clone(), http, committer);
        let (outcome, owned, updated) = if tokio::runtime::Handle::try_current().is_ok() {
            let task = tokio::spawn(future);
            let _abort = AbortUnlessWritten {
                task: task.abort_handle(),
                written,
            };
            task.await
                .map_err(|_| fail(AuthErrorCode::ProviderFailed))?
        } else {
            future.await
        };
        *guard = owned;
        *record = updated;
        Ok(outcome)
    }
    #[allow(clippy::too_many_arguments)]
    async fn client_credentials(
        &self,
        guard: &mut Box<dyn CredentialGuard>,
        record: &mut SessionRecord,
        choice: &ClientChoice,
        scopes: &[String],
        previous: &[String],
        required: &[String],
        ceiling: &[String],
    ) -> Result<BearerCredential, Renewal> {
        if !record
            .metadata
            .grant_types_supported
            .iter()
            .any(|g| g == "client_credentials")
        {
            return Err(fail(AuthErrorCode::UnsupportedBinding).into());
        }
        let client = self.client(&record.metadata, choice, None)?;
        let resource = record.metadata.resource.clone();
        let (scopes, required) = (scopes.to_vec(), required.to_vec());
        let bound = union(previous, ceiling);
        let client_id = choice.id.clone();
        self.detached(
            guard,
            record,
            ceiling,
            move |mut guard, mut record, http, committer| {
                Box::pin(async move {
                    let mut request = client
                        .exchange_client_credentials()
                        .add_extra_param("resource", resource);
                    for scope in &scopes {
                        request = request.add_scope(Scope::new(scope.clone()));
                    }
                    let outcome = match request.request_async(&http).await {
                        Ok(response) => committer
                            .save_token(
                                &mut *guard,
                                &mut record,
                                response,
                                &scopes,
                                &bound,
                                None,
                                &required,
                                &client_id,
                            )
                            .await
                            .map_err(Renewal::from),
                        Err(error) => Err(http.failure(&error, renewal_error(&error, false))),
                    };
                    (outcome, guard, record)
                })
            },
        )
        .await?
    }
    async fn refresh(
        &self,
        guard: &mut Box<dyn CredentialGuard>,
        record: &mut SessionRecord,
        choice: &ClientChoice,
        required: &[String],
        ceiling: &[String],
        budget: OperationBudget,
    ) -> Result<BearerCredential, Renewal> {
        let token = record
            .token
            .as_mut()
            .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))?;
        let generation = token.generation.clone();
        let previous = token.scopes.clone();
        let refresh = RefreshToken::new(
            token
                .refresh_token
                .clone()
                .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))?,
        );
        token.refresh_in_flight = true;
        let client = self.client(&record.metadata, choice, None)?;
        self.persist(&mut **guard, record, budget).await?;
        let resource = record.metadata.resource.clone();
        let required = required.to_vec();
        let presented = Presented {
            client_id: choice.id.clone(),
            refresh,
            generation,
            // A PKCE DCR client was registered for one login and is not reissued.
            drop_on_invalid_client: choice.source == ClientSource::Dcr,
        };
        self.detached(
            guard,
            record,
            ceiling,
            move |mut guard, mut record, http, committer| {
                Box::pin(async move {
                    let outcome = committer
                        .refresh(
                            &mut *guard,
                            &mut record,
                            &http,
                            client,
                            presented,
                            previous,
                            resource,
                            &required,
                        )
                        .await;
                    (outcome, guard, record)
                })
            },
        )
        .await?
    }
    /// Complete a pending login of this target by its callback's `state`: one this
    /// `ManagedOAuth` created or, with `persist_pending_logins`, any in the store.
    /// Callback transport/UI remain host-owned.
    ///
    /// In order: the login is looked up by `state` before any host callback
    /// (none: `interaction_required`); the callback is validated (`access_denied`)
    /// and host policy applied, both leaving the login pending; the login is
    /// claimed; then consent denial, the code exchange and the grant. The grant
    /// must cover, within the current ceiling, the required set the login was
    /// prepared with, else `access_denied` carrying that set, with the grant
    /// saved and the login consumed. Every error reports
    /// `HookError::login_ended`.
    pub async fn complete(
        &self,
        context: AuthContext,
        callback: Url,
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
        let budget = OperationBudget::until(budget.deadline.min(context.deadline));
        let phase = std::sync::atomic::AtomicU8::new(LOOKUP);
        let result = budget
            .run(self.complete_inner(context.clone(), callback.clone(), &phase, budget))
            .await;
        match result {
            Ok(credential) => {
                self.mark_prepared(&context);
                Ok(credential)
            }
            Err(error) => {
                let ended = match phase.load(Ordering::SeqCst) {
                    PENDING => false,
                    CLAIMED => true,
                    // An unknown login, or an uncertain claim: re-read the store
                    // on a fresh short budget; undetermined means still pending.
                    _ => self.login_pending(&context, &callback).await == Some(false),
                };
                Err(error.with_login_ended(ended))
            }
        }
    }
    /// Whether the pending login named by the callback's (first) `state` is
    /// still live, on a fresh short budget; `None` when undetermined.
    async fn login_pending(&self, context: &AuthContext, callback: &Url) -> Option<bool> {
        let Some(state) = callback
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| CsrfToken::new(value.into_owned()))
        else {
            return Some(false);
        };
        let Ok(target) = context.target() else {
            return Some(false);
        };
        let budget = commit_budget(self.config.commit_timeout.min(Duration::from_secs(5)));
        let lookup = async {
            let Some(binding) = self.load(&self.key(&target), budget).await? else {
                return Ok(false);
            };
            if !self.same_principal(&target, &binding) {
                return Ok(false);
            }
            let key = self.binding_grant_key(&target, &binding);
            Ok::<_, HookError>(self.find_login(&key, &state, budget).await?.is_some())
        };
        budget.run(lookup).await.ok()
    }
    async fn complete_inner(
        &self,
        context: AuthContext,
        callback: Url,
        phase: &std::sync::atomic::AtomicU8,
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
        let denied = || fail(AuthErrorCode::AccessDenied);
        let gone = || fail(AuthErrorCode::InteractionRequired);
        let target = context.target()?;
        self.validate_target(&target)?;
        decide::configuration(&self.config, target.preset_scopes(), &[])?;
        if self.config.flow != OAuthFlow::AuthorizationCodePkce {
            return Err(fail(AuthErrorCode::UnsupportedBinding));
        }
        let (mut state, mut code, mut error, mut issuer) = (None, None, None, None);
        for (key, value) in callback.query_pairs() {
            let field = match key.as_ref() {
                "state" => &mut state,
                "code" => &mut code,
                "error" => &mut error,
                "iss" => &mut issuer,
                _ => continue,
            };
            if field.is_none() {
                *field = Some(value.into_owned());
            }
        }
        // 1. Find the login the `state` names, before any host callback: no
        // state, like an unknown, expired or ended one, matches none.
        let state = CsrfToken::new(state.ok_or_else(gone)?);
        let binding = self
            .load(&self.key(&target), budget)
            .await?
            .ok_or_else(gone)?;
        if !self.same_principal(&target, &binding) {
            return Err(gone());
        }
        let key = self.binding_grant_key(&target, &binding);
        let Some(saved) = self.find_login(&key, &state, budget).await? else {
            self.end_login(&key, None, budget).await?;
            return Err(gone());
        };
        phase.store(PENDING, Ordering::SeqCst);
        // 2. Validate the callback; an invalid one never consumes the login.
        let redirect = Url::parse(&saved.redirect_uri).map_err(|_| denied())?;
        // The redirect's own query parameters must be present exactly; ones the
        // authorization server adds (such as `session_state`) are allowed, but
        // no parameter may be duplicated.
        let pairs: Vec<(String, String)> = callback.query_pairs().into_owned().collect();
        let duplicated = pairs
            .iter()
            .enumerate()
            .any(|(i, (key, _))| pairs[..i].iter().any(|(k, _)| k == key));
        let own_query = redirect
            .query_pairs()
            .into_owned()
            .all(|pair| pairs.contains(&pair));
        // The login's exact redirect, including its loopback port.
        if duplicated
            || !callback.query().is_none_or(decodable_query)
            || code.is_some() == error.is_some()
            || code.as_ref().is_some_and(|code| code.is_empty())
            || callback.scheme() != redirect.scheme()
            || callback.host_str() != redirect.host_str()
            || callback.port_or_known_default() != redirect.port_or_known_default()
            || callback.path() != redirect.path()
            || callback.fragment().is_some()
            || !callback.username().is_empty()
            || callback.password().is_some()
            || !own_query
            || (saved
                .metadata
                .authorization_response_iss_parameter_supported
                && issuer.is_none())
            || issuer.is_some_and(|i| i != saved.metadata.issuer)
        {
            return Err(denied());
        }
        // 3. Host policy; its failures keep their code and leave the login pending.
        if !self.selection_current(&target, &binding) {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
        // The login's required set is enforced on its grant, after the exchange.
        self.validate_saved(&target, &binding, &[])?;
        self.approve_metadata(&target, &binding.metadata)?;
        self.approve_metadata(&target, &saved.metadata)?;
        // The token endpoint's destination check, before the claim; the
        // exchange checks it again at connection time.
        let token_endpoint = Url::parse(&saved.metadata.token_endpoint)
            .map_err(|_| fail(AuthErrorCode::UntrustedDestination))?;
        self.check_url(&token_endpoint, EndpointUse::Token, budget)
            .await?;
        // 4. Claim once before the exchange; a valid denial also ends the login.
        phase.store(CLAIMING, Ordering::SeqCst);
        let saved = self
            .end_login(&key, Some(&saved.id), budget)
            .await?
            .ok_or_else(gone)?;
        phase.store(CLAIMED, Ordering::SeqCst);
        // 5. Consent denied.
        if let Some(error) = error {
            // An authorization-endpoint invalid_client for a CIMD client is a
            // misconfiguration, never a DCR fallback.
            if error == "invalid_client" && binding.client_source == ClientSource::Cimd {
                return Err(fail(AuthErrorCode::InvalidConfiguration));
            }
            return Err(denied());
        }
        let code = code.ok_or_else(denied)?;
        let choice = ClientChoice {
            id: saved.client_id.clone(),
            ..self.configured_choice(&target, &binding)
        };
        let client = self.client(&saved.metadata, &choice, Some(&saved.redirect_uri))?;
        let mut guard = budget.run(self.store.acquire(key, budget)).await?;
        let mut record = budget
            .run(guard.load())
            .await?
            .unwrap_or_else(|| SessionRecord {
                version: String::new(),
                ..binding.clone()
            });
        let previous = record
            .token
            .as_ref()
            .map_or(Vec::new(), |t| t.scopes.clone());
        let bound = union(&saved.ceiling, &previous);
        // 7. A login written by an older release stored no required set (nor
        // a prepare-time host-required set): the current host-required scopes.
        let required = saved
            .required
            .clone()
            .unwrap_or_else(|| self.config.required_scopes.clone());
        // Enforced on the grant within the current ceiling.
        let ceiling = self.ceiling();
        let outcome = self
            .detached(
                &mut guard,
                &mut record,
                &ceiling,
                move |mut guard, mut record, http, committer| {
                    Box::pin(async move {
                        // 6. Exchange the code.
                        let response = client
                            .exchange_code(AuthorizationCode::new(code))
                            .set_pkce_verifier(PkceCodeVerifier::new(saved.verifier))
                            .add_extra_param("resource", saved.metadata.resource.clone())
                            .request_async(&http)
                            .await;
                        // Success replaces the grant's client and tokens: the newest
                        // completed login wins. A failure persists nothing.
                        let outcome = match response {
                            Ok(response) => committer
                                .save_token(
                                    &mut *guard,
                                    &mut record,
                                    response,
                                    &saved.scopes,
                                    &bound,
                                    None,
                                    &required,
                                    &saved.client_id,
                                )
                                .await
                                .map_err(Renewal::from),
                            Err(RequestTokenError::ServerResponse(response))
                                if *response.error() == BasicErrorResponseType::InvalidGrant =>
                            {
                                Err(fail(AuthErrorCode::InteractionRequired).into())
                            }
                            Err(error) if invalid_client(&error) => {
                                Err(Renewal::InvalidClient(renewal_error(&error, false)))
                            }
                            // Every other token-endpoint failure, including
                            // unauthorized_client, an unreachable endpoint and
                            // an invalid token response.
                            Err(_) => Err(fail(AuthErrorCode::ProviderFailed).into()),
                        };
                        (outcome, guard, record)
                    })
                },
            )
            .await?;
        drop(guard);
        // invalid_client ends only this login; the stored grant is kept.
        self.client_failure(outcome, &choice, &binding, budget)
            .await
            .map_err(Into::into)
    }
    /// Cancel only this login. A stale cancellation cannot remove another login,
    /// and cancellation never deletes a valid stored grant.
    pub async fn cancel_login(
        &self,
        login: PendingLogin,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        budget
            .run(async {
                self.end_login(&login.key, Some(&login.id), budget).await?;
                Ok(())
            })
            .await
    }
}
use crate::auth::valid_scope;
impl Committer {
    async fn persist(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
    ) -> Result<(), HookError> {
        persist(guard, record, commit_budget(self.timeout)).await
    }
    /// The refresh exchange proper; runs detached once the request is written.
    #[allow(clippy::too_many_arguments)]
    async fn refresh(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        http: &TokenHttp,
        client: Client,
        presented: Presented,
        previous: Vec<String>,
        resource: String,
        required: &[String],
    ) -> Result<BearerCredential, Renewal> {
        let Presented {
            client_id,
            refresh,
            generation,
            drop_on_invalid_client,
        } = presented;
        // No scope parameter: the refresh keeps the full previous grant even when
        // the current ceiling is narrower (RFC 6749 section 6).
        let request = client
            .exchange_refresh_token(&refresh)
            .add_extra_param("resource", resource);
        let error = match request.request_async(http).await {
            Ok(response) => {
                let presented = Some(refresh.secret().clone());
                return Ok(self
                    .save_token(
                        guard, record, response, &previous, &previous, presented, required,
                        &client_id,
                    )
                    .await?);
            }
            Err(error) => error,
        };
        let rejected = matches!(&error, RequestTokenError::ServerResponse(response)
            if *response.error() == BasicErrorResponseType::InvalidGrant
                && http.status.load(Ordering::Relaxed) == 400);
        let unknown_client = drop_on_invalid_client && invalid_client(&error);
        if rejected || unknown_client {
            // Definitive: drop both tokens, but only if the store still holds the
            // presented refresh token (and, for invalid_client, the presented
            // client): compare-and-delete, so a newer record is kept.
            let budget = commit_budget(self.timeout);
            if let Some(mut current) = budget.run(guard.load()).await?
                && current
                    .token
                    .as_ref()
                    .and_then(|t| t.refresh_token.as_ref())
                    == Some(refresh.secret())
                && (rejected || current.client_id == client_id)
            {
                current.token = None;
                self.persist(guard, &mut current).await?;
                *record = current;
                if rejected {
                    budget.run(guard.on_refresh_rejected(generation)).await?;
                }
            }
            return Err(fail(if rejected {
                AuthErrorCode::RefreshRejected
            } else {
                AuthErrorCode::InteractionRequired
            })
            .into());
        }
        // An observed failure response clears the marker and keeps a valid rotated
        // refresh token (else the presented one). Without a response the outcome is
        // unknown: the marker remains and the token is retried.
        let body = http.body.lock().unwrap().take();
        if let Some(body) = body {
            keep_refresh(record, rotated_refresh(&body));
            self.persist(guard, record).await?;
        }
        Err(http.failure(&error, renewal_error(&error, true)))
    }
    /// `requested` is the response scope set when `scope` is omitted: the
    /// requested set initially, the previous grant on refresh. `bound` is the
    /// acquiring ceiling initially, the previous grant on refresh.
    #[allow(clippy::too_many_arguments)]
    async fn save_token(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        response: BasicTokenResponse,
        requested: &[String],
        bound: &[String],
        old_refresh: Option<String>,
        required: &[String],
        client_id: &str,
    ) -> Result<BearerCredential, HookError> {
        let response_scopes = response_scopes(
            response
                .scopes()
                .map(|s| s.iter().map(|s| s.as_str()).collect::<Vec<_>>()),
            requested,
        );
        let refreshed = old_refresh.is_some();
        let rotated = response.refresh_token().map(|s| s.secret().clone());
        let expires = response.expires_in();
        let Some(response_scopes) = response_scopes else {
            return self
                .reject_response(guard, record, refreshed, rotated)
                .await;
        };
        let granted = union(&response_scopes, &[])
            .into_iter()
            .filter(|scope| bound.contains(scope))
            .collect::<Vec<_>>();
        if *response.token_type() != BasicTokenType::Bearer
            || !valid_token(response.access_token().secret())
            || expires.is_some_and(|v| v.is_zero())
        {
            return self
                .reject_response(guard, record, refreshed, rotated)
                .await;
        }
        let refresh_token = rotated.filter(|token| valid_token(token)).or(old_refresh);
        // The client is committed with its tokens, replacing any previous pair.
        record.client_id = client_id.into();
        let token = SavedToken {
            access_token: response.access_token().secret().clone(),
            refresh_token,
            expires_at: expires.map(|expiry| now().saturating_add(expiry.as_secs())),
            scopes: granted,
            generation: random_id(),
            access_rejected: false,
            refresh_in_flight: false,
        };
        let credential = BearerCredential {
            token: token.access_token.clone(),
            attempt_id: token.generation.clone(),
        };
        let covered = decide::covered(&token.scopes, &self.allowed, required);
        record.token = Some(token);
        self.persist(guard, record).await?;
        covered?;
        Ok(credential)
    }
    /// A token response failing basic validity. A failed initial exchange
    /// persists nothing.
    async fn reject_response(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        refreshed: bool,
        rotated: Option<String>,
    ) -> Result<BearerCredential, HookError> {
        if refreshed {
            keep_refresh(record, rotated);
            self.persist(guard, record).await?;
        }
        Err(fail(AuthErrorCode::ProviderFailed))
    }
}
/// The response scope set, or `None` when `scope` is malformed. `oauth2` splits
/// the string on single SP, so rejoining recovers it exactly. Absent, null
/// (`None`) and blank (only SP, HTAB, CR, LF) mean omitted and inherit
/// `inherited`; anything else must be RFC 6749 scope tokens separated by
/// exactly one SP.
fn response_scopes(split: Option<Vec<&str>>, inherited: &[String]) -> Option<Vec<String>> {
    let Some(split) = split else {
        return Some(inherited.to_vec());
    };
    let raw = split.join(" ");
    if raw
        .bytes()
        .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
    {
        return Some(inherited.to_vec());
    }
    split
        .iter()
        .all(|scope| valid_scope(scope))
        .then(|| split.iter().map(|scope| (*scope).to_owned()).collect())
}
/// The access token of a failed refresh is retired; the refresh token is kept.
fn keep_refresh(record: &mut SessionRecord, rotated: Option<String>) {
    if let Some(token) = record.token.as_mut() {
        if let Some(rotated) = rotated.filter(|token| valid_token(token)) {
            token.refresh_token = Some(rotated);
        }
        token.access_rejected = true;
        token.refresh_in_flight = false;
    }
}
fn commit_budget(timeout: Duration) -> OperationBudget {
    let now = Instant::now();
    OperationBudget::until(
        now.checked_add(timeout)
            .unwrap_or_else(|| now + Duration::from_secs(86_400)),
    )
}
/// A refresh token from a JSON or form-encoded body, if valid.
fn rotated_refresh(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value["refresh_token"].as_str().map(str::to_owned))
        .or_else(|| {
            url::form_urlencoded::parse(body)
                .find(|(key, _)| key == "refresh_token")
                .map(|(_, value)| value.into_owned())
        })
        .filter(|token| valid_token(token))
}
async fn persist(
    guard: &mut dyn CredentialGuard,
    record: &mut SessionRecord,
    budget: OperationBudget,
) -> Result<(), HookError> {
    if !cas(guard, record, budget).await? {
        return Err(fail(AuthErrorCode::ProviderFailed));
    }
    Ok(())
}
/// Compare-and-set on the record version; false when another writer won.
async fn cas(
    guard: &mut dyn CredentialGuard,
    record: &mut SessionRecord,
    budget: OperationBudget,
) -> Result<bool, HookError> {
    let expected = Some(record.version.clone()).filter(|v| !v.is_empty());
    let mut replacement = record.clone();
    replacement.version = random_id();
    let version = replacement.version.clone();
    let swapped = budget
        .run(guard.compare_and_swap(expected, replacement))
        .await?;
    if swapped {
        record.version = version;
    }
    Ok(swapped)
}
/// Stands in for a guard while its commit task owns it.
struct Committing;
impl CredentialGuard for Committing {
    fn load(&mut self) -> LocalFuture<'_, Result<Option<SessionRecord>, HookError>> {
        Box::pin(async { Err(fail(AuthErrorCode::ProviderFailed)) })
    }
    fn compare_and_swap(
        &mut self,
        _: Option<String>,
        _: SessionRecord,
    ) -> LocalFuture<'_, Result<bool, HookError>> {
        Box::pin(async { Err(fail(AuthErrorCode::ProviderFailed)) })
    }
}
/// Every query component percent-decodes to UTF-8: an unparseable callback
/// is an invalid one.
fn decodable_query(query: &str) -> bool {
    query.split('&').all(|component| {
        let bytes = component.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let Some(byte) = bytes
                    .get(i + 1..i + 3)
                    .filter(|hex| hex.iter().all(u8::is_ascii_hexdigit))
                    .and_then(|hex| std::str::from_utf8(hex).ok())
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                else {
                    return false;
                };
                decoded.push(byte);
                i += 3;
            } else {
                decoded.push(bytes[i]);
                i += 1;
            }
        }
        std::str::from_utf8(&decoded).is_ok()
    })
}
fn valid_token(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic())
}
fn frame(prefix: &str, fields: &[&str]) -> String {
    let mut key = prefix.to_owned();
    for field in fields {
        key.push_str(&format!("{}:{}", field.len(), field));
    }
    key
}
fn valid_https(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}
/// HTTPS; HTTP only to a literal loopback IP (never `localhost`, RFC 8252
/// section 8.3); or an RFC 8252 section 7.1 reverse-domain private-use scheme
/// (one containing a period).
fn valid_redirect(uri: &Url) -> bool {
    uri.username().is_empty()
        && uri.password().is_none()
        && uri.fragment().is_none()
        && match uri.scheme() {
            "https" => uri.host_str().is_some(),
            "http" => registration::loopback(uri),
            scheme => scheme.contains('.'),
        }
}
/// RFC 6749 permits `expires_in` as a positive integer; also accept a string of
/// ASCII digits. Anything else, including null, fails token parsing.
fn normalize_token_body(body: &[u8]) -> Option<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(body).ok()?;
    if value.get("expires_in")?.is_null() {
        // Present but null is malformed, not absent.
        value["expires_in"] = "invalid".into();
        return serde_json::to_vec(&value).ok();
    }
    let digits = value.get("expires_in")?.as_str()?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value["expires_in"] = digits.parse::<u64>().ok()?.into();
    serde_json::to_vec(&value).ok()
}
/// Renewal errors: a token-endpoint error from a refresh (`refresh`) or a
/// client-credentials grant, outside `complete`. `invalid_grant` is
/// `refresh_rejected` for a refresh and `credential_unavailable` for client
/// credentials; `unauthorized_client` and `invalid_client` are
/// `credential_unavailable` (`client_failure` then applies the client source);
/// every other error, an unreachable endpoint and an invalid response are
/// `provider_failed`. None carries scopes.
fn renewal_error(error: &TokenError, refresh: bool) -> HookError {
    match error {
        // The diagnostic (such as a deadline) and the not-sent mark are kept.
        RequestTokenError::Request(error) => fail(AuthErrorCode::ProviderFailed)
            .classified(error.code())
            .request_not_sent_if(error.is_request_not_sent()),
        RequestTokenError::ServerResponse(response) => fail(match response.error() {
            BasicErrorResponseType::InvalidGrant if refresh => AuthErrorCode::RefreshRejected,
            BasicErrorResponseType::InvalidGrant
            | BasicErrorResponseType::InvalidClient
            | BasicErrorResponseType::UnauthorizedClient => AuthErrorCode::CredentialUnavailable,
            _ => AuthErrorCode::ProviderFailed,
        }),
        _ => fail(AuthErrorCode::ProviderFailed),
    }
}
impl AuthProvider for ManagedOAuth {
    /// Bound targets acquire without ever creating a login. Unbound targets only
    /// look up a stored usable token (no discovery); otherwise they go anonymous.
    fn credential(
        &self,
        context: AuthContext,
    ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
        Box::pin(async move {
            let budget = OperationBudget::until(context.deadline);
            let mode = if context.authentication.is_none() {
                Mode::Lookup
            } else {
                Mode::Deliver
            };
            match budget
                .run(self.acquire(context, None, Login::default(), None, budget, mode))
                .await?
            {
                Some(Preparation::Ready(credential)) => Ok(Some(credential)),
                // `decide` creates a login only for `prepare`.
                Some(Preparation::InteractionRequired(_)) => {
                    unreachable!("delivery never creates a login")
                }
                None => Ok(None),
            }
        })
    }
    /// A 401 retires the rejected generation first; its `scope` (within the
    /// ceiling) is requested only by this operation's client-credentials
    /// acquisition. A Bearer 403 `insufficient_scope` requirement applies to
    /// this operation only; one the grant that was sent already covers fails
    /// `access_denied`. Malformed or ambiguous challenges and other 403s fail
    /// `access_denied` with no scopes.
    fn challenge(
        &self,
        context: AuthContext,
        challenge: AuthChallenge,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async move {
            let budget = OperationBudget::until(context.deadline);
            let sent = challenge.attempt_id.as_deref();
            // Step 0: a 401 retires the generation it rejected before every
            // other step, so no later refusal leaves that token servable.
            if challenge.status == 401
                && let Some(attempt) = sent
            {
                budget
                    .run(self.retire_rejected(&context, attempt, budget))
                    .await?;
            }
            let header = challenge
                .headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case("www-authenticate"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let rejection = decide::Rejection {
                status: challenge.status,
                header: &header,
            };
            match budget
                .run(self.acquire(
                    context,
                    Some(rejection),
                    Login::default(),
                    sent,
                    budget,
                    Mode::Deliver,
                ))
                .await?
            {
                Some(Preparation::Ready(_)) => Ok(()),
                // Only `prepare` creates a login, and only a lookup has no outcome.
                _ => unreachable!("challenge handling ends in a credential or an error"),
            }
        })
    }
    /// Counts `prepare` calls that returned a credential and completed logins.
    fn preparations(&self, context: &AuthContext) -> u64 {
        Self::prepared_key(context)
            .and_then(|key| self.prepared.lock().unwrap().get(&key).copied())
            .unwrap_or(0)
    }
}

#[cfg(test)]
#[path = "managed/tests/mod.rs"]
mod tests;
