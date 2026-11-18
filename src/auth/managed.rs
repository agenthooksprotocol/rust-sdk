//! Host-driven OAuth mechanics. No browser, listener, executor, file store or task is created.
//!
//! The embedding host supplies a policy-enforcing network client and a durable,
//! exclusive/CAS-capable store. Credentials and pending login records are secret.
use crate::{
    adapters::registered::{
        AuthChallenge, AuthContext, AuthProvider, AuthPurpose, BearerCredential,
    },
    auth::{
        AuthBinding, AuthErrorCode, AuthTarget, OAuthFlow, challenge::Challenge,
        sanitize_provider_error,
    },
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
        atomic::{AtomicU16, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use url::Url;
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
        result.map_err(sanitize_provider_error)
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
/// Select only locally trusted issuers and locally permitted scopes. Metadata and
/// challenge scopes are requirements to evaluate, never trust/consent grants.
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
    fn select(
        &self,
        target: &AuthTarget,
        resource: &ResourceMetadata,
        challenge_scopes: &[String],
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
/// Host registration, never inferred from untrusted metadata. Secret Debug is not exposed.
#[non_exhaustive]
pub struct OAuthClientConfig {
    namespace: String,
    pub(super) client_id: Option<String>,
    pub(super) flow: OAuthFlow,
    pub(super) requested_scopes: Vec<String>,
    pub(super) allowed_scopes: Vec<String>,
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
    renewal_margin: Duration,
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
            renewal_margin: Duration::from_secs(3600),
        }
    }
    /// PKCE only, used when issuer metadata has `client_id_metadata_document_supported`
    /// `true`. `url` is the `client_id` verbatim; `redirect_uris` are the document's,
    /// and the configured redirect must be one of them. The SDK never fetches `url`.
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
    pub fn client_secret_storage(mut self, storage: Arc<dyn ClientSecretStorage>) -> Self {
        self.secret_storage = Some(storage);
        self
    }
    /// Failed-registration backoff: `initial` doubling per attempt, capped at `max`
    /// (defaults 1 minute and 1 hour). `max` also caps a later `Retry-After`
    /// (delta-seconds or HTTP-date).
    pub fn registration_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.registration_backoff = (initial, max);
        self
    }
    /// Cap of the proactive re-registration margin before a client secret expires:
    /// `min(0.1 x secret lifetime, cap)`, default 1 hour.
    pub fn registration_renewal_margin(mut self, cap: Duration) -> Self {
        self.renewal_margin = cap;
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
    pub fn login_lifetime(mut self, lifetime: Duration) -> Self {
        self.login_lifetime = lifetime.min(MAX_LOGIN_LIFETIME);
        self
    }
    pub fn scopes(mut self, requested: Vec<String>, allowed: Vec<String>) -> Self {
        self.requested_scopes = requested;
        self.allowed_scopes = allowed;
        self
    }
    /// Explicit opt-in to grant sharing, never destination authorization.
    pub fn grant_partition(mut self, partition: impl Into<String>) -> Self {
        self.grant_partition = Some(partition.into());
        self
    }
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
/// Binding records hold validated discovery provenance; grant records also hold
/// the token and any pending login. Only granted scopes are recorded: the local
/// ceiling and operation requirements are re-applied at use.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionRecord {
    version: String,
    metadata: TrustedMetadata,
    client_id: String,
    flow: String,
    configured_binding: bool,
    resource_metadata_hint: Option<discovery::ResourceMetadataHint>,
    token: Option<SavedToken>,
    pending: Option<SavedLogin>,
    /// Binding records: the selected client's source and, for DCR, its registration key.
    #[serde(default)]
    client_source: ClientSource,
    #[serde(default)]
    registration_key: Option<String>,
    /// Registration records: the DCR client and its failed-registration marker.
    #[serde(default)]
    registration: Option<registration::SavedRegistration>,
    #[serde(default)]
    marker: Option<registration::FailedMarker>,
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
#[derive(Clone, Serialize, Deserialize)]
struct SavedLogin {
    id: String,
    metadata: TrustedMetadata,
    scopes: Vec<String>,
    /// The creating caller's ceiling; it bounds what completion records.
    ceiling: Vec<String>,
    state: String,
    verifier: String,
    redirect_uri: String,
    url: String,
    expires_at_ms: u64,
    in_flight: bool,
    /// The client and DCR registration generation the login was created under.
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    registration_generation: Option<String>,
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
            pending: None,
            client_source: ClientSource::default(),
            registration_key: None,
            registration: None,
            marker: None,
        }
    }
    fn same_binding(&self, other: &Self) -> bool {
        self.metadata == other.metadata
            && self.resource_metadata_hint == other.resource_metadata_hint
            && self.client_id == other.client_id
            && self.flow == other.flow
            && self.configured_binding == other.configured_binding
            && self.client_source == other.client_source
            && self.registration_key == other.registration_key
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
/// A stored pending login. Any process sharing the store can complete it with
/// `ManagedOAuth::complete`; this handle is only needed to display or cancel it.
#[derive(Clone)]
#[non_exhaustive]
pub struct PendingLogin {
    key: SessionKey,
    id: String,
    url: Url,
    expires_at: SystemTime,
}
impl PendingLogin {
    pub fn authorization_url(&self) -> &Url {
        &self.url
    }
    /// Fixed at creation; reuse by a later `prepare` never extends it.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    fn new(key: SessionKey, login: &SavedLogin) -> Result<Self, HookError> {
        Ok(Self {
            key,
            id: login.id.clone(),
            url: Url::parse(&login.url).map_err(|_| fail(AuthErrorCode::InvalidConfiguration))?,
            expires_at: UNIX_EPOCH + Duration::from_millis(login.expires_at_ms),
        })
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
    /// Delete the current DCR registration (and its secret) and any failed
    /// marker, then register anew. Use when the server deleted the client: it
    /// sends no callback, so the SDK never infers this from an expired login.
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
            .run(self.network.check(url, EndpointUse::Token, budget))
            .await?;
        let mut request = request;
        request.extensions_mut().insert(self.written.clone());
        budget
            .run(self.network.send(request, EndpointUse::Token, budget))
            .await
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
    budget.run(network.check(url, usage, budget)).await?;
    let response = budget
        .run(network.send(request, usage, budget))
        .await
        .map_err(|error| error.transient_if(true))?;
    if response.status().is_redirection() || response.body().len() > 1024 * 1024 {
        return Err(fail(AuthErrorCode::UntrustedDestination));
    }
    Ok(response)
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
        if config
            .allowed_scopes
            .iter()
            .any(|scope| !valid_scope(scope))
            || config
                .grant_partition
                .as_ref()
                .is_some_and(|p| p.is_empty())
            || config.namespace.is_empty()
            || config.client_id.as_ref().is_some_and(|id| id.is_empty())
            || !subset(&config.requested_scopes, &config.allowed_scopes)
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
        if config.flow == OAuthFlow::AuthorizationCodePkce {
            let uri = Url::parse(config.redirect_uri.as_deref().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            if !valid_redirect(&uri) {
                return Err(invalid());
            }
        }
        Ok(Self {
            config: Arc::new(config),
            network,
            policy,
            store,
            prepared: Arc::default(),
        })
    }
    /// A second handle on the same configuration, network, policy and store,
    /// for work that outlives the caller.
    fn handle(&self) -> Self {
        Self {
            config: self.config.clone(),
            network: self.network.clone(),
            policy: self.policy.clone(),
            store: self.store.clone(),
            prepared: self.prepared.clone(),
        }
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
        let purpose = match target.purpose() {
            AuthPurpose::Event => "event",
            AuthPurpose::Upload => "upload",
        };
        SessionKey {
            storage_key: frame(
                "ahp.oauth.binding:",
                &[
                    &self.config.namespace,
                    target.backend_id(),
                    purpose,
                    target.destination().as_str(),
                ],
            ),
            namespace: self.config.namespace.clone(),
            backend_id: target.backend_id().into(),
            destination: target.destination().as_str().into(),
            purpose: purpose.into(),
        }
    }
    /// No ceiling, auth method, secret or registration source: changing those
    /// never orphans a grant. A different `client_id` is a different grant.
    fn grant_key(
        &self,
        target: &AuthTarget,
        metadata: &TrustedMetadata,
        client_id: &str,
    ) -> SessionKey {
        let partition = match &self.config.grant_partition {
            Some(partition) => format!("shared:{partition}"),
            None => format!("binding:{}", self.key(target).as_str()),
        };
        SessionKey {
            storage_key: frame(
                "ahp.oauth.grant:",
                &[
                    &self.config.namespace,
                    &metadata.issuer,
                    &metadata.resource,
                    client_id,
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
    /// Requirements are judged on effective scopes (granted ∩ current ceiling).
    fn cached(&self, record: &SessionRecord, required: &[String]) -> Option<BearerCredential> {
        record
            .token
            .as_ref()
            .filter(|token| {
                !token.access_rejected
                    && token
                        .expires_at
                        .is_none_or(|expiry| expiry > now().saturating_add(30))
                    && subset(required, &self.effective(&token.scopes))
            })
            .map(|token| BearerCredential {
                token: token.access_token.clone(),
                attempt_id: token.generation.clone(),
            })
    }
    /// An acquisition requests previously granted ∪ (wanted ∩ ceiling).
    fn request_scopes(&self, previous: &[String], wanted: &[String]) -> Vec<String> {
        union(previous, &self.effective(wanted))
    }
    fn effective(&self, scopes: &[String]) -> Vec<String> {
        scopes
            .iter()
            .filter(|scope| self.config.allowed_scopes.contains(scope))
            .cloned()
            .collect()
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
        self.selection_current(target, record)
            && record.flow == self.flow_id()
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
            .map_err(sanitize_provider_error)
    }
    /// Apply local policy; returns the scopes to request. Configured requested
    /// and operation-required scopes must be selected, all within the ceiling.
    pub(super) fn select(
        &self,
        target: &AuthTarget,
        resource: &ResourceMetadata,
        required: &[String],
    ) -> Result<TrustDecision, HookError> {
        let mut decision = self
            .policy
            .select(target, resource, required)
            .map_err(sanitize_provider_error)?;
        decision.scopes = union(&decision.scopes, &[]);
        if !resource.authorization_servers.contains(&decision.issuer)
            || target
                .issuer()
                .is_some_and(|issuer| issuer != decision.issuer)
            || !subset(&decision.scopes, &self.config.allowed_scopes)
            || !subset(
                &union(&self.config.requested_scopes, required),
                &decision.scopes,
            )
        {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        Ok(decision)
    }
    /// Revalidate a saved binding against current local policy, without network.
    fn validate_saved(
        &self,
        target: &AuthTarget,
        record: &SessionRecord,
        required: &[String],
    ) -> Result<Vec<String>, HookError> {
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
        let resource = ResourceMetadata::new(
            record.metadata.resource.clone(),
            vec![record.metadata.issuer.clone()],
        );
        Ok(self.select(target, &resource, required)?.scopes)
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
            .run(self.network.check(url.clone(), usage, budget))
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
    /// after `interaction_required`, include the broader scopes in host policy or
    /// the target's configured requirements; challenge requirements are not stored.
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
    /// `prepare` with explicit options; the only path that registers a PKCE client.
    pub async fn prepare_with(
        &self,
        context: AuthContext,
        options: PrepareOptions,
        budget: OperationBudget,
    ) -> Result<Preparation, HookError> {
        if !options.required.iter().all(|scope| valid_scope(scope)) {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
        let budget = OperationBudget::until(budget.deadline.min(context.deadline));
        let prepared = budget
            .run(async {
                let target = context.target()?;
                self.validate_target(&target)?;
                self.prepare_registration(&target, options.force_registration, budget)
                    .await?;
                let required = &options.required;
                let pending = self
                    .acquire(context.clone(), None, required, None, budget, Mode::Prepare)
                    .await?;
                pending.ok_or_else(|| fail(AuthErrorCode::ProviderFailed))
            })
            .await?;
        if matches!(prepared, Preparation::Ready(_)) {
            self.mark_prepared(&context);
        }
        Ok(prepared)
    }
    /// `challenge` is present only for challenge recovery; its requirements, like
    /// `extra`, apply to this operation only and are never stored.
    async fn acquire(
        &self,
        context: AuthContext,
        challenge: Option<&Challenge>,
        extra: &[String],
        rejected_attempt: Option<&str>,
        budget: OperationBudget,
        mode: Mode,
    ) -> Result<Option<Preparation>, HookError> {
        let target = context.target()?;
        self.validate_target(&target)?;
        let mut required = union(target.scopes(), extra);
        if let Some(challenge) = challenge {
            required = union(&required, &challenge.scopes);
        }
        let attach = |error: HookError| error.with_required_scopes(&required);
        if !subset(&required, &self.config.allowed_scopes) {
            return Err(attach(fail(AuthErrorCode::AccessDenied)));
        }
        let attempt = |rediscover| {
            self.acquire_inner(
                &target,
                challenge,
                &required,
                rejected_attempt,
                budget,
                mode,
                rediscover,
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
            Err(Renewal::Stale(_)) if challenge.is_some() || mode == Mode::Prepare => {
                attempt(true).await
            }
            result => result,
        };
        // A deleted DCR client-credentials registration: register once more and
        // re-acquire once; a repeated invalid_client is a failed registration.
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
        result.map_err(|error| attach(error.into()))
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
        .map_err(|_| discovery())?;
        let mut guard = budget.run(self.store.acquire(key, budget)).await?;
        let mut current = budget.run(guard.load()).await?.ok_or_else(discovery)?;
        if current.metadata.issuer != metadata.issuer {
            return Err(discovery());
        }
        current.metadata = metadata;
        self.persist(&mut *guard, &mut current, budget).await
    }
    /// Mark this exact token generation as rejected in the store.
    async fn retire(
        &self,
        target: &AuthTarget,
        binding: &SessionRecord,
        attempt: &str,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        let key = self.grant_key(target, &binding.metadata, &binding.client_id);
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
        challenge: Option<&Challenge>,
        hint: Option<&discovery::ResourceMetadataHint>,
        cached_issuer: Option<&str>,
        required: &[String],
        binding_key: SessionKey,
        budget: OperationBudget,
    ) -> Result<(SessionRecord, Vec<String>), HookError> {
        let (metadata, hint, scopes) = discovery::discover(
            self,
            target,
            challenge,
            hint,
            cached_issuer,
            required,
            budget,
        )
        .await?;
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
                binding.registration_key = current.registration_key.clone();
            }
            None => {
                binding.client_source = self.select_source(target, &binding.metadata)?;
                match binding.client_source {
                    ClientSource::Preregistered => {
                        binding.client_id = self.preregistered(target).unwrap_or_default().into()
                    }
                    ClientSource::Cimd => {
                        binding.client_id = self.config.cimd.as_ref().unwrap().url.clone()
                    }
                    ClientSource::Dcr => {
                        let key = self.registration_key(&binding.metadata.issuer);
                        binding.registration_key = Some(key.as_str().into());
                    }
                }
            }
        }
        match current {
            Some(current) if current.same_binding(&binding) => {}
            current => {
                binding.version = current.map(|r| r.version).unwrap_or_default();
                self.persist(&mut *guard, &mut binding, budget).await?;
            }
        }
        Ok((binding, scopes))
    }
    #[allow(clippy::too_many_arguments)]
    async fn acquire_inner(
        &self,
        target: &AuthTarget,
        challenge: Option<&Challenge>,
        required: &[String],
        rejected_attempt: Option<&str>,
        budget: OperationBudget,
        mode: Mode,
        rediscover: bool,
    ) -> Result<Option<Preparation>, Renewal> {
        let target = target.clone();
        let required = required.to_vec();
        let binding_key = self.key(&target);
        let saved = self.load(&binding_key, budget).await?;
        // Local authorization of a saved binding needs no network; policy runs off-lock.
        let mut usable = None;
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
            match self.validate_saved(&target, binding, &required) {
                Ok(scopes) => {
                    let mut binding = binding.clone();
                    // Absent persisted authorization-server metadata: fetch only the
                    // stored issuer's metadata, never protected-resource metadata.
                    if binding.metadata.token_endpoint.is_empty() && mode != Mode::Prepare && !force
                    {
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
                Err(_) if mode == Mode::Lookup => return Ok(None),
                // Policy no longer approves the stored binding: rebind by discovery.
                Err(_) if mode == Mode::Prepare || force => {}
                Err(error) => return Err(error.into()),
            }
        }
        // Retire a rejected generation before any network, so a failed discovery
        // or renewal never leaves the revoked token servable.
        if let (Some(attempt), Some(binding)) = (rejected_attempt, known) {
            self.retire(&target, binding, attempt, budget).await?;
        }
        // `prepare` serves a usable cached token, otherwise rebuilds binding metadata
        // so stale persisted metadata always has a repair path.
        let mut discover_now = force || usable.is_none();
        if mode == Mode::Prepare
            && let Some((binding, _)) = &usable
        {
            // The binding records its selected client; a usable token needs no registration.
            let key = self.grant_key(&target, &binding.metadata, &binding.client_id);
            if let Some(credential) = self
                .load(&key, budget)
                .await?
                .and_then(|record| self.cached(&record, &required))
            {
                return Ok(Some(Preparation::Ready(credential)));
            }
            discover_now = true;
        }
        let (binding, scopes) = match usable {
            Some(found) if !discover_now => found,
            None if mode == Mode::Lookup => return Ok(None),
            cached => {
                let hint = saved
                    .as_ref()
                    .and_then(|r| r.resource_metadata_hint.as_ref());
                let cached_issuer = cached.as_ref().map(|(b, _)| b.metadata.issuer.as_str());
                match self
                    .rebind(
                        &target,
                        challenge,
                        hint,
                        cached_issuer,
                        &required,
                        binding_key,
                        budget,
                    )
                    .await
                {
                    Ok(found) => found,
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
        // A still-valid token for the recorded DCR client keeps working even
        // while its registration is unusable or a failed marker blocks renewal.
        if binding.client_source == ClientSource::Dcr
            && rejected_attempt.is_none()
            && !binding.client_id.is_empty()
            && let Some(credential) = self
                .load(
                    &self.grant_key(&target, &binding.metadata, &binding.client_id),
                    budget,
                )
                .await?
                .and_then(|record| self.cached(&record, &required))
        {
            return Ok(Some(Preparation::Ready(credential)));
        }
        let choice = self.choose(&target, &binding, mode, budget).await?;
        let binding = self
            .record_client(&target, binding, &choice, budget)
            .await?;
        let key = self.grant_key(&target, &binding.metadata, &choice.id);
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
            && rejected_attempt == Some(token.generation.as_str())
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
        if let Some(credential) = self.cached(&record, &required) {
            return Ok(Some(Preparation::Ready(credential)));
        }
        // A refresh cannot broaden a grant, so it only helps when the grant suffices.
        if self.config.flow == OAuthFlow::AuthorizationCodePkce
            && let Some(token) = &record.token
            && token.refresh_token.is_some()
            && subset(&required, &self.effective(&token.scopes))
        {
            let result = self
                .refresh(&mut guard, &mut record, &choice, &required, budget)
                .await;
            drop(guard);
            return self
                .client_failure(result, &choice, &binding, budget)
                .await
                .map(|c| Some(Preparation::Ready(c)));
        }
        // An acquisition for an existing grant keeps what was previously granted.
        let previous = record
            .token
            .as_ref()
            .map_or(Vec::new(), |t| t.scopes.clone());
        let scopes = self.request_scopes(&previous, &scopes);
        if self.config.flow == OAuthFlow::ClientCredentials {
            let result = self
                .client_credentials(
                    &mut guard,
                    &mut record,
                    &choice,
                    &scopes,
                    &previous,
                    &required,
                )
                .await;
            drop(guard);
            if result.is_ok()
                && choice.renew
                && let Some(generation) = choice.generation.clone()
            {
                // The token is committed: renewal never delays or fails this
                // operation. It runs on its own commit budget, fire-and-forget.
                let owner = self.handle();
                let metadata = binding.metadata.clone();
                let renewal = async move {
                    let budget = commit_budget(owner.config.commit_timeout);
                    owner.renew(&metadata, &generation, budget).await;
                };
                if tokio::runtime::Handle::try_current().is_ok() {
                    tokio::spawn(renewal);
                } else {
                    renewal.await;
                }
            }
            return self
                .client_failure(result, &choice, &binding, budget)
                .await
                .map(|c| Some(Preparation::Ready(c)));
        }
        if mode != Mode::Prepare {
            return Err(fail(AuthErrorCode::InteractionRequired).into());
        }
        // Only a live login for the same grant key and redirect is reused or merged.
        let live = record.pending.as_ref().filter(|login| {
            login.expires_at_ms > now_ms()
                && !login.in_flight
                && self.config.redirect_uri.as_deref() == Some(login.redirect_uri.as_str())
                && login.registration_generation == choice.generation
        });
        if let Some(login) = live
            && subset(&scopes, &login.scopes)
        {
            let pending = PendingLogin::new(key, login)?;
            self.check_url(&pending.url, EndpointUse::Authorization, budget)
                .await?;
            return Ok(Some(Preparation::InteractionRequired(pending)));
        }
        // Supersede with growing scope and ceiling unions so alternating callers converge.
        let ceiling = union(
            &self.config.allowed_scopes,
            live.map_or(&[], |l| l.ceiling.as_slice()),
        );
        let scopes = union(&scopes, live.map_or(&[], |l| l.scopes.as_slice()));
        let authorization = record
            .metadata
            .authorization_endpoint
            .clone()
            .ok_or_else(|| fail(AuthErrorCode::DiscoveryFailed))?;
        let client = self.client(&record.metadata, &choice)?.set_auth_uri(
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
            state: state.secret().clone(),
            verifier: verifier.secret().clone(),
            redirect_uri: self
                .config
                .redirect_uri
                .clone()
                .ok_or_else(|| fail(AuthErrorCode::InvalidConfiguration))?,
            url: url.to_string(),
            expires_at_ms: now_ms().saturating_add(self.config.login_lifetime.as_millis() as u64),
            in_flight: false,
            client_id: choice.id.clone(),
            registration_generation: choice.generation.clone(),
        };
        let pending = PendingLogin::new(key, &login)?;
        // Atomically supersedes any previous pending login; its callback then fails.
        record.pending = Some(login);
        self.persist(&mut *guard, &mut record, budget).await?;
        Ok(Some(Preparation::InteractionRequired(pending)))
    }
    /// Record the chosen client on the binding (write-on-change).
    async fn record_client(
        &self,
        target: &AuthTarget,
        mut binding: SessionRecord,
        choice: &ClientChoice,
        budget: OperationBudget,
    ) -> Result<SessionRecord, HookError> {
        if binding.client_id == choice.id {
            return Ok(binding);
        }
        let mut guard = budget
            .run(self.store.acquire(self.key(target), budget))
            .await?;
        if let Some(mut current) = budget.run(guard.load()).await?
            && current.same_binding(&binding)
        {
            current.client_id = choice.id.clone();
            self.persist(&mut *guard, &mut current, budget).await?;
            binding.version = current.version;
        }
        drop(guard);
        // A replaced DCR client (after invalid_client or expiry): the old client's
        // binding-scoped grant is unreachable, and served no usable token.
        let old = std::mem::replace(&mut binding.client_id, choice.id.clone());
        if choice.source == ClientSource::Dcr {
            self.clear_grant(target, &binding.metadata, &old, budget)
                .await?;
        }
        Ok(binding)
    }
    /// `invalid_client`: a CIMD client is misconfigured; a DCR registration
    /// generation is compare-and-deleted, then PKCE needs consent and client
    /// credentials register once more.
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
            ClientSource::Dcr => {
                if let Some(generation) = &choice.generation {
                    self.forget(&binding.metadata.issuer, generation, budget)
                        .await?;
                }
                if self.config.flow == OAuthFlow::AuthorizationCodePkce {
                    return Err(fail(AuthErrorCode::InteractionRequired).into());
                }
                Err(Renewal::Reregister(binding.metadata.issuer.clone()))
            }
        }
    }
    fn client(
        &self,
        metadata: &TrustedMetadata,
        choice: &ClientChoice,
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
        if let Some(redirect) = &self.config.redirect_uri {
            client = client.set_redirect_uri(
                RedirectUrl::new(redirect.clone())
                    .map_err(|_| fail(AuthErrorCode::InvalidConfiguration))?,
            );
        }
        Ok(client)
    }
    fn committer(&self) -> Committer {
        Committer {
            allowed: self.config.allowed_scopes.clone(),
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
        exchange: impl FnOnce(
            Box<dyn CredentialGuard>,
            SessionRecord,
            TokenHttp,
            Committer,
        ) -> Exchange<T>,
    ) -> Result<T, HookError> {
        let committer = self.committer();
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
    ) -> Result<BearerCredential, Renewal> {
        if !record
            .metadata
            .grant_types_supported
            .iter()
            .any(|g| g == "client_credentials")
        {
            return Err(fail(AuthErrorCode::UnsupportedBinding).into());
        }
        let client = self.client(&record.metadata, choice)?;
        let resource = record.metadata.resource.clone();
        let (scopes, required) = (scopes.to_vec(), required.to_vec());
        let bound = union(previous, &self.config.allowed_scopes);
        self.detached(
            guard,
            record,
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
                            )
                            .await
                            .map_err(Renewal::from),
                        Err(error) => Err(http.failure(&error, token_error(&error))),
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
        let client = self.client(&record.metadata, choice)?;
        self.persist(&mut **guard, record, budget).await?;
        let resource = record.metadata.resource.clone();
        let required = required.to_vec();
        self.detached(
            guard,
            record,
            move |mut guard, mut record, http, committer| {
                Box::pin(async move {
                    let outcome = committer
                        .refresh(
                            &mut *guard,
                            &mut record,
                            &http,
                            client,
                            refresh,
                            generation,
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
    /// Complete the stored pending login for this target from any process sharing
    /// the store. Callback transport/UI remain host-owned. Redirect, state and issuer
    /// are validated before the login is claimed, so stray callbacks cannot consume it.
    pub async fn complete(
        &self,
        context: AuthContext,
        callback: Url,
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
        let budget = OperationBudget::until(budget.deadline.min(context.deadline));
        let credential = budget
            .run(self.complete_inner(context.clone(), callback, budget))
            .await?;
        self.mark_prepared(&context);
        Ok(credential)
    }
    async fn complete_inner(
        &self,
        context: AuthContext,
        callback: Url,
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
        let denied = || fail(AuthErrorCode::AccessDenied);
        let gone = || fail(AuthErrorCode::InteractionRequired);
        let target = context.target()?;
        self.validate_target(&target)?;
        let redirect = Url::parse(
            self.config
                .redirect_uri
                .as_deref()
                .ok_or_else(|| fail(AuthErrorCode::UnsupportedBinding))?,
        )
        .map_err(|_| fail(AuthErrorCode::InvalidConfiguration))?;
        let fixed_query = |url: &Url| {
            let mut pairs = url
                .query_pairs()
                .filter(|(key, _)| {
                    !matches!(
                        key.as_ref(),
                        "state" | "code" | "error" | "iss" | "error_description" | "error_uri"
                    )
                })
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect::<Vec<_>>();
            pairs.sort();
            pairs
        };
        if callback.scheme() != redirect.scheme()
            || callback.host_str() != redirect.host_str()
            || callback.port_or_known_default() != redirect.port_or_known_default()
            || callback.path() != redirect.path()
            || callback.fragment().is_some()
            || !callback.username().is_empty()
            || callback.password().is_some()
            || fixed_query(&callback) != fixed_query(&redirect)
        {
            return Err(denied());
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
            if field.replace(value.into_owned()).is_some() {
                return Err(denied());
            }
        }
        let state = CsrfToken::new(state.ok_or_else(denied)?);
        if code.is_some() == error.is_some() {
            return Err(denied());
        }
        let binding = self
            .load(&self.key(&target), budget)
            .await?
            .ok_or_else(gone)?;
        if !self.compatible(&target, &binding) {
            return Err(gone());
        }
        self.validate_saved(&target, &binding, target.scopes())?;
        self.approve_metadata(&target, &binding.metadata)?;
        // Never registers: a missing PKCE registration needs a new `prepare`.
        let choice = self
            .choose(&target, &binding, Mode::Deliver, budget)
            .await?;
        let key = self.grant_key(&target, &binding.metadata, &choice.id);
        let record = self.load(&key, budget).await?.ok_or_else(gone)?;
        // Superseded, expired, claimed or foreign-state callbacks never consume a login.
        let saved = record
            .pending
            .filter(|login| {
                login.expires_at_ms > now_ms()
                    && !login.in_flight
                    && self.config.redirect_uri.as_deref() == Some(login.redirect_uri.as_str())
                    && (login.client_id.is_empty() || login.client_id == choice.id)
                    && state == CsrfToken::new(login.state.clone())
            })
            .ok_or_else(gone)?;
        if (saved
            .metadata
            .authorization_response_iss_parameter_supported
            && issuer.is_none())
            || issuer.is_some_and(|i| i != saved.metadata.issuer)
        {
            return Err(denied());
        }
        self.approve_metadata(&target, &saved.metadata)?;
        let mut guard = budget.run(self.store.acquire(key, budget)).await?;
        let mut record = budget.run(guard.load()).await?.ok_or_else(gone)?;
        if !record.pending.as_ref().is_some_and(|login| {
            login.id == saved.id && !login.in_flight && login.expires_at_ms > now_ms()
        }) {
            return Err(gone());
        }
        if error.is_some() {
            record.pending = None;
            self.persist(&mut *guard, &mut record, budget).await?;
            return Err(denied());
        }
        let code = code.filter(|s| !s.is_empty()).ok_or_else(denied)?;
        // Claim once before the exchange; a cancelled exchange is superseded by `prepare`.
        record.pending.as_mut().unwrap().in_flight = true;
        self.persist(&mut *guard, &mut record, budget).await?;
        let client = self.client(&saved.metadata, &choice)?;
        let generation = saved.registration_generation.clone();
        let previous = record
            .token
            .as_ref()
            .map_or(Vec::new(), |t| t.scopes.clone());
        let bound = union(&saved.ceiling, &previous);
        let required = target.scopes().to_vec();
        let outcome = self.detached(&mut guard, &mut record, move |mut guard, mut record, http, committer| {
            Box::pin(async move {
                let response = client
                    .exchange_code(AuthorizationCode::new(code))
                    .set_pkce_verifier(PkceCodeVerifier::new(saved.verifier))
                    .add_extra_param("resource", saved.metadata.resource.clone())
                    .request_async(&http)
                    .await;
                let outcome = match response {
                    Ok(response) => {
                        committer
                            .save_token(&mut *guard, &mut record, response, &saved.scopes, &bound, None, &required)
                            .await
                            .map_err(Renewal::from)
                    }
                    Err(error) => {
                        // The claimed login has ended; nothing else is persisted.
                        record.pending = None;
                        match committer.persist(&mut *guard, &mut record).await {
                            Err(failure) => Err(failure.into()),
                            Ok(()) if matches!(&error, RequestTokenError::ServerResponse(response) if *response.error() == BasicErrorResponseType::InvalidGrant) => {
                                Err(fail(AuthErrorCode::InteractionRequired).into())
                            }
                            Ok(()) if invalid_client(&error) => Err(Renewal::InvalidClient(token_error(&error))),
                            Ok(()) => Err(token_error(&error).into()),
                        }
                    }
                };
                (outcome, guard, record)
            })
        })
        .await?;
        drop(guard);
        // invalid_client deletes only the registration generation this login used.
        let choice = ClientChoice {
            generation,
            ..choice
        };
        self.client_failure(outcome, &choice, &binding, budget)
            .await
            .map_err(Into::into)
    }
    /// Cancel only this login generation. A stale cancellation cannot remove a newer
    /// login, and cancellation never deletes a valid stored grant.
    pub async fn cancel_login(
        &self,
        login: PendingLogin,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        budget
            .run(async {
                let mut guard = budget.run(self.store.acquire(login.key, budget)).await?;
                if let Some(mut record) = budget.run(guard.load()).await?
                    && record.pending.as_ref().is_some_and(|s| s.id == login.id)
                {
                    record.pending = None;
                    self.persist(&mut *guard, &mut record, budget).await?;
                }
                Ok(())
            })
            .await
    }
}
use crate::auth::valid_scope;
impl Committer {
    fn effective(&self, scopes: &[String]) -> Vec<String> {
        scopes
            .iter()
            .filter(|scope| self.allowed.contains(scope))
            .cloned()
            .collect()
    }
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
        refresh: RefreshToken,
        generation: String,
        previous: Vec<String>,
        resource: String,
        required: &[String],
    ) -> Result<BearerCredential, Renewal> {
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
                    )
                    .await?);
            }
            Err(error) => error,
        };
        if let RequestTokenError::ServerResponse(response) = &error
            && *response.error() == BasicErrorResponseType::InvalidGrant
            && http.status.load(Ordering::Relaxed) == 400
        {
            // Definitive: drop both tokens, but only if the store still holds the
            // presented refresh token (compare-and-delete); a newer record is kept.
            let budget = commit_budget(self.timeout);
            if let Some(mut current) = budget.run(guard.load()).await?
                && current
                    .token
                    .as_ref()
                    .and_then(|t| t.refresh_token.as_ref())
                    == Some(refresh.secret())
            {
                current.token = None;
                self.persist(guard, &mut current).await?;
                *record = current;
                budget.run(guard.on_refresh_rejected(generation)).await?;
            }
            return Err(fail(AuthErrorCode::RefreshRejected).into());
        }
        // An observed failure response clears the marker and keeps a valid rotated
        // refresh token (else the presented one). Without a response the outcome is
        // unknown: the marker remains and the token is retried.
        let body = http.body.lock().unwrap().take();
        if let Some(body) = body {
            keep_refresh(record, rotated_refresh(&body));
            self.persist(guard, record).await?;
        }
        Err(http.failure(&error, token_error(&error)))
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
        record.pending = None;
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
        let sufficient = subset(required, &self.effective(&token.scopes));
        record.token = Some(token);
        self.persist(guard, record).await?;
        if !sufficient {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        Ok(credential)
    }
    /// A token response failing basic validity. A failed initial exchange
    /// persists nothing beyond releasing its login claim.
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
        } else if record.pending.take().is_some() {
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
/// HTTPS; HTTP only to a literal loopback IP; or an RFC 8252 section 7.1
/// reverse-domain private-use scheme (one containing a period).
fn valid_redirect(uri: &Url) -> bool {
    let loopback = || {
        uri.host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback())
    };
    uri.username().is_empty()
        && uri.password().is_none()
        && uri.fragment().is_none()
        && match uri.scheme() {
            "https" => uri.host_str().is_some(),
            "http" => loopback(),
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
fn token_error(error: &TokenError) -> HookError {
    match error {
        RequestTokenError::Request(error) => sanitize_provider_error(error.clone()),
        RequestTokenError::ServerResponse(response)
            if matches!(
                response.error(),
                BasicErrorResponseType::InvalidClient | BasicErrorResponseType::UnauthorizedClient
            ) =>
        {
            fail(AuthErrorCode::CredentialUnavailable)
        }
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
                .run(self.acquire(context, None, &[], None, budget, mode))
                .await?
            {
                Some(Preparation::Ready(credential)) => Ok(Some(credential)),
                Some(Preparation::InteractionRequired(_)) => {
                    Err(fail(AuthErrorCode::InteractionRequired))
                }
                None => Ok(None),
            }
        })
    }
    /// A 401 retires the rejected generation. A Bearer 403 `insufficient_scope`
    /// requirement applies to this operation's acquisition only.
    fn challenge(
        &self,
        context: AuthContext,
        challenge: AuthChallenge,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async move {
            if challenge.status != 401 && challenge.status != 403 {
                return Err(fail(AuthErrorCode::AccessDenied));
            }
            let budget = OperationBudget::until(context.deadline);
            let headers = challenge
                .headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case("www-authenticate"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let parsed = crate::auth::challenge::parse(&headers)
                .map_err(|_| fail(AuthErrorCode::DiscoveryFailed))?;
            let rejected = if challenge.status == 401 {
                challenge.attempt_id.as_deref()
            } else if !parsed.insufficient_scope
                || (parsed.scopes.is_empty() && context.target()?.scopes().is_empty())
            {
                return Err(fail(AuthErrorCode::AccessDenied));
            } else {
                None
            };
            match budget
                .run(self.acquire(context, Some(&parsed), &[], rejected, budget, Mode::Deliver))
                .await?
            {
                Some(Preparation::Ready(_)) => Ok(()),
                _ => Err(fail(AuthErrorCode::InteractionRequired)),
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
