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
}
/// Required security boundary, not a generic HTTP client. Implementations MUST
/// enforce local destination policy against resolved IPs (including rebinding),
/// certificate/hostname verification, bounded reads, and NO redirects. `check`
/// validates the host-displayed authorization URL too; `send` must repeat/pin
/// that validation at actual connection time, not trust an earlier DNS lookup.
/// Adapter requests and responses MUST NOT be logged, even at DEBUG level.
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
        }
    }
}
/// Select only locally trusted issuers and locally permitted scopes. Metadata and
/// challenge scopes are requirements to evaluate, never trust/consent grants.
#[non_exhaustive]
pub struct EndpointTrust<'a> {
    pub target: &'a AuthTarget,
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
    pub(super) client_id: String,
    pub(super) flow: OAuthFlow,
    pub(super) requested_scopes: Vec<String>,
    pub(super) allowed_scopes: Vec<String>,
    redirect_uri: Option<String>,
    grant_partition: Option<String>,
    secret: Option<(String, ClientSecret)>,
    method: TokenAuthMethod,
    login_lifetime: Duration,
}
impl OAuthClientConfig {
    pub fn new(
        namespace: impl Into<String>,
        client_id: impl Into<String>,
        flow: OAuthFlow,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            client_id: client_id.into(),
            flow,
            requested_scopes: Vec::new(),
            allowed_scopes: Vec::new(),
            redirect_uri: None,
            grant_partition: None,
            secret: None,
            method: TokenAuthMethod::None,
            login_lifetime: MAX_LOGIN_LIFETIME,
        }
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
    fn same_binding(&self, other: &Self) -> bool {
        self.metadata == other.metadata
            && self.resource_metadata_hint == other.resource_metadata_hint
            && self.client_id == other.client_id
            && self.flow == other.flow
            && self.configured_binding == other.configured_binding
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
#[non_exhaustive]
pub struct ManagedOAuth {
    pub(super) config: OAuthClientConfig,
    pub(super) network: Arc<dyn OAuthNetwork>,
    pub(super) policy: Arc<dyn OAuthPolicy>,
    store: Arc<dyn CredentialStore>,
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
    status: AtomicU16,
}
impl TokenHttp {
    fn new(owner: &ManagedOAuth, budget: OperationBudget) -> Self {
        Self {
            network: owner.network.clone(),
            budget,
            status: AtomicU16::new(0),
        }
    }
}
impl<'c> oauth2::AsyncHttpClient<'c> for TokenHttp {
    type Error = HookError;
    type Future = LocalFuture<'c, Result<oauth2::HttpResponse, HookError>>;
    fn call(&'c self, request: oauth2::HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response =
                checked_network_send(&*self.network, request, EndpointUse::Token, self.budget)
                    .await?;
            self.status
                .store(response.status().as_u16(), Ordering::Relaxed);
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
    let response = budget.run(network.send(request, usage, budget)).await?;
    if response.status().is_redirection() || response.body().len() > 1024 * 1024 {
        return Err(fail(AuthErrorCode::UntrustedDestination));
    }
    Ok(response)
}
type Client =
    BasicClient<EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;
type TokenError = RequestTokenError<HookError, BasicErrorResponse>;
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
            || config.client_id.is_empty()
            || !subset(&config.requested_scopes, &config.allowed_scopes)
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
        if config.flow == OAuthFlow::ClientCredentials && config.secret.is_none() {
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
            config,
            network,
            policy,
            store,
        })
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
    /// No ceiling, auth method or secret: changing those never orphans a grant.
    fn grant_key(&self, target: &AuthTarget, metadata: &TrustedMetadata) -> SessionKey {
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
                    &self.config.client_id,
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
                    && target.client_id() == Some(self.config.client_id.as_str()) =>
            {
                if let Some(reference) = target.client_secret_ref()
                    && self.config.secret.as_ref().map(|(r, _)| r.as_str()) != Some(reference)
                {
                    return Err(fail(AuthErrorCode::InvalidConfiguration));
                }
                Ok(())
            }
            _ => Err(fail(AuthErrorCode::UnsupportedBinding)),
        }
    }
    /// A saved binding is only reused for the same principal as the current target.
    fn compatible(&self, target: &AuthTarget, record: &SessionRecord) -> bool {
        record.client_id == self.config.client_id
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
                client_id: &self.config.client_id,
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
        let expected = Some(record.version.clone()).filter(|v| !v.is_empty());
        let mut replacement = record.clone();
        replacement.version = random_id();
        let version = replacement.version.clone();
        if !budget
            .run(guard.compare_and_swap(expected, replacement))
            .await?
        {
            return Err(fail(AuthErrorCode::ProviderFailed));
        }
        record.version = version;
        Ok(())
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
        if !required.iter().all(|scope| valid_scope(scope)) {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
        let budget = OperationBudget::until(budget.deadline.min(context.deadline));
        let pending = budget
            .run(self.acquire(context, None, required, None, budget, Mode::Prepare))
            .await?;
        pending.ok_or_else(|| fail(AuthErrorCode::ProviderFailed))
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
        self.acquire_inner(target, challenge, &required, rejected_attempt, budget, mode)
            .await
            .map_err(attach)
    }
    async fn acquire_inner(
        &self,
        target: AuthTarget,
        challenge: Option<&Challenge>,
        required: &[String],
        rejected_attempt: Option<&str>,
        budget: OperationBudget,
        mode: Mode,
    ) -> Result<Option<Preparation>, HookError> {
        let required = required.to_vec();
        let binding_key = self.key(&target);
        let saved = self.load(&binding_key, budget).await?;
        // Local authorization of a saved binding needs no network; policy runs off-lock.
        let mut usable = None;
        if let Some(binding) = saved.as_ref().filter(|r| self.compatible(&target, r)) {
            match self.validate_saved(&target, binding, &required) {
                Ok(scopes) => {
                    let mut binding = binding.clone();
                    // Absent persisted authorization-server metadata: fetch only the
                    // stored issuer's metadata, never protected-resource metadata.
                    if binding.metadata.token_endpoint.is_empty() && mode != Mode::Prepare {
                        binding.metadata = discovery::issuer_metadata(
                            self,
                            &target,
                            binding.metadata.resource.clone(),
                            binding.metadata.issuer.clone(),
                            budget,
                        )
                        .await?;
                        let mut guard = budget
                            .run(self.store.acquire(binding_key.clone(), budget))
                            .await?;
                        self.persist(&mut *guard, &mut binding, budget).await?;
                    }
                    if self.approve_metadata(&target, &binding.metadata).is_ok() {
                        usable = Some((binding, scopes));
                    }
                }
                Err(_) if mode == Mode::Lookup => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        // `prepare` serves a usable cached token, otherwise rebuilds binding metadata
        // so stale persisted metadata always has a repair path.
        if mode == Mode::Prepare
            && let Some((binding, _)) = &usable
        {
            let key = self.grant_key(&target, &binding.metadata);
            if let Some(credential) = self
                .load(&key, budget)
                .await?
                .and_then(|record| self.cached(&record, &required))
            {
                return Ok(Some(Preparation::Ready(credential)));
            }
            usable = None;
        }
        let (binding, scopes) = match usable {
            Some(found) => found,
            None if mode == Mode::Lookup => return Ok(None),
            None => {
                // Discovery never holds a credential-store guard.
                let hint = saved
                    .as_ref()
                    .and_then(|r| r.resource_metadata_hint.as_ref());
                let (metadata, hint, scopes) =
                    discovery::discover(self, &target, challenge, hint, &required, budget).await?;
                let mut binding = SessionRecord {
                    version: String::new(),
                    metadata,
                    client_id: self.config.client_id.clone(),
                    flow: self.flow_id().into(),
                    configured_binding: !matches!(target.binding(), AuthBinding::Unbound),
                    resource_metadata_hint: hint,
                    token: None,
                    pending: None,
                };
                let mut guard = budget.run(self.store.acquire(binding_key, budget)).await?;
                match budget.run(guard.load()).await? {
                    Some(current) if current.same_binding(&binding) => {}
                    current => {
                        binding.version = current.map(|r| r.version).unwrap_or_default();
                        self.persist(&mut *guard, &mut binding, budget).await?;
                    }
                }
                (binding, scopes)
            }
        };
        let key = self.grant_key(&target, &binding.metadata);
        let mut guard = budget.run(self.store.acquire(key.clone(), budget)).await?;
        let loaded = budget.run(guard.load()).await?;
        let mut record = loaded.unwrap_or_else(|| SessionRecord {
            version: String::new(),
            ..binding.clone()
        });
        let mut dirty = record.metadata != binding.metadata;
        record.metadata = binding.metadata;
        // A 401 for this exact generation retires it; a stale 401 cannot reject a newer token.
        if let Some(token) = record.token.as_mut()
            && rejected_attempt == Some(token.generation.as_str())
            && !token.access_rejected
        {
            token.access_rejected = true;
            dirty = true;
        }
        if let Some(credential) = self.cached(&record, &required) {
            if dirty {
                self.persist(&mut *guard, &mut record, budget).await?;
            }
            return Ok(Some(Preparation::Ready(credential)));
        }
        // A refresh cannot broaden a grant, so it only helps when the grant suffices.
        if self.config.flow == OAuthFlow::AuthorizationCodePkce
            && let Some(token) = &record.token
            && token.refresh_token.is_some()
            && subset(&required, &self.effective(&token.scopes))
        {
            return self
                .refresh(&mut *guard, &mut record, &required, budget)
                .await
                .map(|c| Some(Preparation::Ready(c)));
        }
        // An acquisition for an existing grant keeps what was previously granted.
        let previous = record
            .token
            .as_ref()
            .map_or(Vec::new(), |t| t.scopes.clone());
        let scopes = union(&previous, &scopes);
        if self.config.flow == OAuthFlow::ClientCredentials {
            return self
                .client_credentials(
                    &mut *guard,
                    &mut record,
                    &scopes,
                    &previous,
                    &required,
                    budget,
                )
                .await
                .map(|c| Some(Preparation::Ready(c)));
        }
        if mode != Mode::Prepare {
            if dirty {
                self.persist(&mut *guard, &mut record, budget).await?;
            }
            return Err(fail(AuthErrorCode::InteractionRequired));
        }
        let live = record
            .pending
            .as_ref()
            .filter(|login| login.expires_at_ms > now_ms() && !login.in_flight);
        if let Some(login) = live
            && self.config.redirect_uri.as_deref() == Some(login.redirect_uri.as_str())
            && subset(&scopes, &login.scopes)
        {
            let pending = PendingLogin::new(key, login)?;
            if dirty {
                self.persist(&mut *guard, &mut record, budget).await?;
            }
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
        let client = self.client(&record.metadata)?.set_auth_uri(
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
        };
        let pending = PendingLogin::new(key, &login)?;
        // Atomically supersedes any previous pending login; its callback then fails.
        record.pending = Some(login);
        self.persist(&mut *guard, &mut record, budget).await?;
        Ok(Some(Preparation::InteractionRequired(pending)))
    }
    fn client(&self, metadata: &TrustedMetadata) -> Result<Client, HookError> {
        let method = match self.config.method {
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
        let mut client = BasicClient::new(ClientId::new(self.config.client_id.clone()))
            .set_token_uri(
                TokenUrl::new(metadata.token_endpoint.clone())
                    .map_err(|_| fail(AuthErrorCode::DiscoveryFailed))?,
            )
            .set_auth_type(
                if self.config.method == TokenAuthMethod::ClientSecretBasic {
                    AuthType::BasicAuth
                } else {
                    AuthType::RequestBody
                },
            );
        if let Some((_, secret)) = &self.config.secret {
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
    async fn client_credentials(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        scopes: &[String],
        previous: &[String],
        required: &[String],
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
        if !record
            .metadata
            .grant_types_supported
            .iter()
            .any(|g| g == "client_credentials")
        {
            return Err(fail(AuthErrorCode::UnsupportedBinding));
        }
        let client = self.client(&record.metadata)?;
        let mut request = client
            .exchange_client_credentials()
            .add_extra_param("resource", &record.metadata.resource);
        for scope in scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let http = TokenHttp::new(self, budget);
        match request.request_async(&http).await {
            Ok(response) => {
                let bound = union(previous, &self.config.allowed_scopes);
                self.save_token(
                    guard, record, response, scopes, &bound, None, required, budget,
                )
                .await
            }
            Err(error) => Err(token_error(error)),
        }
    }
    async fn refresh(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        required: &[String],
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
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
        let client = self.client(&record.metadata)?;
        self.persist(guard, record, budget).await?;
        // No scope parameter: the refresh keeps the full previous grant even when
        // the current ceiling is narrower (RFC 6749 section 6).
        let request = client
            .exchange_refresh_token(&refresh)
            .add_extra_param("resource", &record.metadata.resource);
        let http = TokenHttp::new(self, budget);
        let error = match request.request_async(&http).await {
            Ok(response) => {
                return self
                    .save_token(
                        guard,
                        record,
                        response,
                        &previous,
                        &previous,
                        Some(refresh.secret().clone()),
                        required,
                        budget,
                    )
                    .await;
            }
            Err(error) => error,
        };
        if let RequestTokenError::ServerResponse(response) = &error
            && *response.error() == BasicErrorResponseType::InvalidGrant
            && http.status.load(Ordering::Relaxed) == 400
        {
            // Definitive: drop both tokens, but only if the store still holds the
            // presented refresh token (compare-and-delete); a newer record is kept.
            if let Some(mut current) = budget.run(guard.load()).await?
                && current
                    .token
                    .as_ref()
                    .and_then(|t| t.refresh_token.as_ref())
                    == Some(refresh.secret())
            {
                current.token = None;
                self.persist(guard, &mut current, budget).await?;
                *record = current;
                budget.run(guard.on_refresh_rejected(generation)).await?;
            }
            return Err(fail(AuthErrorCode::RefreshRejected));
        }
        self.failed_refresh(guard, record, &error, budget).await?;
        Err(token_error(error))
    }
    /// After a spent refresh token, an observed failure response clears the marker
    /// and keeps a valid rotated refresh token (else the presented one). Without a
    /// response the outcome is unknown: the marker remains and the token is retried.
    async fn failed_refresh(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        error: &TokenError,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        let body = match error {
            RequestTokenError::ServerResponse(_) => None,
            RequestTokenError::Parse(_, body) => Some(body.as_slice()),
            _ => return Ok(()),
        };
        let rotated = body
            .and_then(|body| serde_json::from_slice::<serde_json::Value>(body).ok())
            .and_then(|value| value["refresh_token"].as_str().map(str::to_owned));
        self.keep_refresh(record, rotated);
        self.persist(guard, record, budget).await
    }
    /// The access token of a failed refresh is retired; the refresh token is kept.
    fn keep_refresh(&self, record: &mut SessionRecord, rotated: Option<String>) {
        if let Some(token) = record.token.as_mut() {
            if let Some(rotated) = rotated.filter(|token| valid_token(token)) {
                token.refresh_token = Some(rotated);
            }
            token.access_rejected = true;
            token.refresh_in_flight = false;
        }
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
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
        let response_scopes = response
            .scopes()
            .map(|s| s.iter().map(|s| s.as_str().to_owned()).collect::<Vec<_>>())
            .unwrap_or_else(|| requested.to_vec());
        let refreshed = old_refresh.is_some();
        let granted = union(&response_scopes, &[])
            .into_iter()
            .filter(|scope| bound.contains(scope))
            .collect::<Vec<_>>();
        let rotated = response.refresh_token().map(|s| s.secret().clone());
        let expires = response.expires_in();
        if *response.token_type() != BasicTokenType::Bearer
            || !valid_token(response.access_token().secret())
            || expires.is_some_and(|v| v.is_zero())
        {
            // A failed initial exchange persists nothing beyond releasing its login claim.
            if refreshed {
                self.keep_refresh(record, rotated);
                self.persist(guard, record, budget).await?;
            } else if record.pending.take().is_some() {
                self.persist(guard, record, budget).await?;
            }
            return Err(fail(AuthErrorCode::ProviderFailed));
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
        self.persist(guard, record, budget).await?;
        if !sufficient {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        Ok(credential)
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
        budget
            .run(self.complete_inner(context, callback, budget))
            .await
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
        let key = self.grant_key(&target, &binding.metadata);
        let record = self.load(&key, budget).await?.ok_or_else(gone)?;
        // Superseded, expired, claimed or foreign-state callbacks never consume a login.
        let saved = record
            .pending
            .filter(|login| {
                login.expires_at_ms > now_ms()
                    && !login.in_flight
                    && self.config.redirect_uri.as_deref() == Some(login.redirect_uri.as_str())
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
        let http = TokenHttp::new(self, budget);
        let response = self
            .client(&saved.metadata)?
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(saved.verifier))
            .add_extra_param("resource", &saved.metadata.resource)
            .request_async(&http)
            .await;
        let previous = record
            .token
            .as_ref()
            .map_or(Vec::new(), |t| t.scopes.clone());
        let bound = union(&saved.ceiling, &previous);
        match response {
            Ok(response) => {
                self.save_token(
                    &mut *guard,
                    &mut record,
                    response,
                    &saved.scopes,
                    &bound,
                    None,
                    target.scopes(),
                    budget,
                )
                .await
            }
            Err(error) => {
                // The claimed login has ended; nothing else is persisted.
                record.pending = None;
                self.persist(&mut *guard, &mut record, budget).await?;
                if matches!(&error, RequestTokenError::ServerResponse(response) if *response.error() == BasicErrorResponseType::InvalidGrant)
                {
                    return Err(gone());
                }
                Err(token_error(error))
            }
        }
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
/// ASCII digits. Anything else (zero aside) is left to fail token parsing.
fn normalize_token_body(body: &[u8]) -> Option<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let digits = value.get("expires_in")?.as_str()?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value["expires_in"] = digits.parse::<u64>().ok()?.into();
    serde_json::to_vec(&value).ok()
}
fn token_error(error: TokenError) -> HookError {
    match error {
        RequestTokenError::Request(error) => sanitize_provider_error(error),
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
}

#[cfg(test)]
#[path = "managed/tests/mod.rs"]
mod tests;
