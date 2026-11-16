//! Host-driven OAuth mechanics. No browser, listener, executor, file store or task is created.
//!
//! The embedding host supplies a policy-enforcing network client and a durable,
//! exclusive/CAS-capable store. Credentials and pending login records are secret.
use crate::{
    adapters::registered::{AuthChallenge, AuthContext, AuthProvider, BearerCredential},
    auth::{AuthBinding, AuthErrorCode, AuthTarget, OAuthFlow, sanitize_provider_error},
    client::{HookError, LocalFuture},
};
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, RequestTokenError, Scope,
    TokenResponse, TokenUrl,
    basic::{BasicClient, BasicErrorResponseType, BasicTokenResponse, BasicTokenType},
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
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
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
    /// Opt in only when this trusted issuer guarantees this response did not
    /// consume/rotate the refresh grant. Status 429/5xx alone is NOT proof.
    fn refresh_failure_is_safe(&self, _response: &OAuthResponse) -> bool {
        false
    }
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
    pub scopes: Vec<String>,
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
            scopes: Vec::new(),
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
        }
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
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionRecord {
    version: String,
    metadata: TrustedMetadata,
    client_id: String,
    flow: String,
    configured_binding: bool,
    allowed_scopes: Vec<String>,
    resource_metadata_hint: Option<discovery::ResourceMetadataHint>,
    challenge_scopes: Vec<String>,
    token: Option<SavedToken>,
    pending: Option<SavedLogin>,
}
#[derive(Clone, Serialize, Deserialize)]
struct SavedToken {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
    scopes: Vec<String>,
    authorized_scopes: Vec<String>,
    generation: String,
    rejected: bool,
    access_rejected: bool,
    refresh_in_flight: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct SavedLogin {
    id: String,
    binding_key: SessionKey,
    metadata: TrustedMetadata,
    required_scopes: Vec<String>,
    host_deadline_ms: u64,
    state: String,
    verifier: String,
    redirect_uri: String,
    url: String,
    expires_at: u64,
    in_flight: bool,
}
impl SessionRecord {
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn attempt_id(&self) -> Option<&str> {
        self.token.as_ref().map(|token| token.generation.as_str())
    }
    pub fn refresh_is_uncertain(&self) -> bool {
        self.token
            .as_ref()
            .is_some_and(|token| token.refresh_in_flight)
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
#[derive(Clone)]
#[non_exhaustive]
pub struct PendingLogin {
    key: Box<SessionKey>,
    id: String,
    url: Url,
    expires_at: u64,
    exchange_in_flight: bool,
    deadline: Instant,
    context: Box<AuthContext>,
}
impl PendingLogin {
    /// Never reopen this URL after an uncertain exchange; cancel this generation first.
    pub fn authorization_url(&self) -> Option<&Url> {
        if self.exchange_in_flight {
            None
        } else {
            Some(&self.url)
        }
    }
    pub fn exchange_is_uncertain(&self) -> bool {
        self.exchange_in_flight
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
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
struct TokenHttp {
    network: Arc<dyn OAuthNetwork>,
    budget: OperationBudget,
    status: Option<Arc<std::sync::atomic::AtomicU16>>,
    safe_failure: Option<Arc<std::sync::atomic::AtomicBool>>,
}
impl<'c> oauth2::AsyncHttpClient<'c> for TokenHttp {
    type Error = HookError;
    type Future = LocalFuture<'c, Result<oauth2::HttpResponse, HookError>>;
    fn call(&'c self, request: oauth2::HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response =
                checked_network_send(&*self.network, request, EndpointUse::Token, self.budget)
                    .await?;
            if let Some(safe) = &self.safe_failure {
                safe.store(
                    self.network.refresh_failure_is_safe(&response),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            if let Some(status) = &self.status {
                status.store(
                    response.status().as_u16(),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            Ok(response)
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
type Client = BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;
fn fail(code: AuthErrorCode) -> HookError {
    HookError::authentication(code)
}
fn random_id() -> String {
    CsrfToken::new_random().secret().clone()
}
fn now() -> Result<u64, HookError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| fail(AuthErrorCode::ProviderFailed))
}
impl ManagedOAuth {
    pub fn new(
        mut config: OAuthClientConfig,
        network: Arc<dyn OAuthNetwork>,
        policy: Arc<dyn OAuthPolicy>,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, HookError> {
        if config.allowed_scopes.is_empty() {
            config.allowed_scopes = config.requested_scopes.clone();
        }
        config.allowed_scopes.sort();
        config.allowed_scopes.dedup();
        if config
            .allowed_scopes
            .iter()
            .any(|scope| !valid_scope(scope))
        {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
        if config
            .grant_partition
            .as_ref()
            .is_some_and(|p| p.is_empty())
            || config.namespace.is_empty()
            || config.client_id.is_empty()
            || config
                .requested_scopes
                .iter()
                .any(|s| !config.allowed_scopes.contains(s) || !valid_scope(s))
        {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
        if config.secret.as_ref().is_some_and(|(reference, secret)| {
            reference.is_empty()
                || secret.secret().is_empty()
                || config.method == TokenAuthMethod::None
        }) {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
        if config.method != TokenAuthMethod::None && config.secret.is_none() {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
        if config.flow == OAuthFlow::ClientCredentials && config.secret.is_none() {
            return Err(fail(AuthErrorCode::UnsupportedBinding));
        }
        if config.flow == OAuthFlow::AuthorizationCodePkce {
            let uri = Url::parse(
                config
                    .redirect_uri
                    .as_deref()
                    .ok_or_else(|| fail(AuthErrorCode::InvalidConfiguration))?,
            )
            .map_err(|_| fail(AuthErrorCode::InvalidConfiguration))?;
            if !(valid_https(&uri)
                || (uri.scheme() == "http"
                    && uri
                        .host_str()
                        .and_then(|host| {
                            host.trim_matches(['[', ']'])
                                .parse::<std::net::IpAddr>()
                                .ok()
                        })
                        .is_some_and(|ip| ip.is_loopback())
                    && uri.username().is_empty()
                    && uri.password().is_none()
                    && uri.fragment().is_none()))
            {
                return Err(fail(AuthErrorCode::InvalidConfiguration));
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
            crate::adapters::registered::AuthPurpose::Event => "event",
            crate::adapters::registered::AuthPurpose::Upload => "upload",
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
            purpose: match target.purpose() {
                crate::adapters::registered::AuthPurpose::Event => "event",
                crate::adapters::registered::AuthPurpose::Upload => "upload",
            }
            .into(),
        }
    }
    fn grant_key(&self, target: &AuthTarget, metadata: &TrustedMetadata) -> SessionKey {
        let partition = self
            .config
            .grant_partition
            .as_ref()
            .map(|p| format!("shared:{p}"))
            .unwrap_or_else(|| format!("binding:{}", self.key(target).as_str()));
        let allowed = self.config.allowed_scopes.join(" ");
        SessionKey {
            storage_key: frame(
                "ahp.oauth.grant:",
                &[
                    &self.config.namespace,
                    &metadata.issuer,
                    &metadata.resource,
                    &self.config.client_id,
                    self.flow_id(),
                    &allowed,
                    &partition,
                ],
            ),
            namespace: self.config.namespace.clone(),
            backend_id: String::new(),
            destination: String::new(),
            purpose: String::new(),
        }
    }
    fn satisfies_requirements(&self, record: &SessionRecord) -> bool {
        record.token.as_ref().is_some_and(|token| {
            record
                .challenge_scopes
                .iter()
                .all(|scope| token.authorized_scopes.contains(scope))
        })
    }
    fn cached(&self, record: &SessionRecord) -> Option<BearerCredential> {
        record
            .token
            .as_ref()
            .filter(|token| {
                !token.rejected
                    && !token.access_rejected
                    && token
                        .expires_at
                        .is_none_or(|expiry| expiry > now().unwrap_or(u64::MAX).saturating_add(30))
                    && self.satisfies_requirements(record)
            })
            .map(|token| BearerCredential {
                token: token.access_token.clone(),
                attempt_id: token.generation.clone(),
            })
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
    fn validate_saved(&self, target: &AuthTarget, record: &SessionRecord) -> Result<(), HookError> {
        if record.client_id != self.config.client_id
            || record.flow != self.flow_id()
            || record.allowed_scopes != self.config.allowed_scopes
        {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
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
        if target
            .issuer()
            .is_some_and(|issuer| issuer != record.metadata.issuer)
            || matches!(target.binding(), AuthBinding::OAuth { resource, .. } if resource != &record.metadata.resource)
        {
            return Err(fail(AuthErrorCode::UntrustedDestination));
        }
        let resource = ResourceMetadata {
            resource: record.metadata.resource.clone(),
            authorization_servers: vec![record.metadata.issuer.clone()],
        };
        let mut decision = self
            .policy
            .select(target, &resource, &record.challenge_scopes)
            .map_err(sanitize_provider_error)?;
        decision.scopes.sort();
        decision.scopes.dedup();
        if decision.issuer != record.metadata.issuer
            || decision
                .scopes
                .iter()
                .any(|scope| !self.config.allowed_scopes.contains(scope))
            || target
                .scopes()
                .iter()
                .chain(&record.challenge_scopes)
                .any(|scope| !decision.scopes.contains(scope))
        {
            return Err(fail(AuthErrorCode::UntrustedDestination));
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
    /// Host-initiated preparation; bounded by both the supplied budget and context.
    pub async fn prepare(
        &self,
        context: AuthContext,
        budget: OperationBudget,
    ) -> Result<Preparation, HookError> {
        let budget = OperationBudget::until(budget.deadline.min(context.deadline));
        budget
            .run(self.prepare_inner(context, None, None, budget, true))
            .await
    }
    async fn persist(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        let expected = if record.version.is_empty() {
            None
        } else {
            Some(record.version.clone())
        };
        let next = random_id();
        let mut replacement = record.clone();
        replacement.version = next.clone();
        if !budget
            .run(guard.compare_and_swap(expected, replacement))
            .await?
        {
            return Err(fail(AuthErrorCode::ProviderFailed));
        }
        record.version = next;
        Ok(())
    }
    async fn prepare_inner(
        &self,
        context: AuthContext,
        challenge: Option<&str>,
        rejected_attempt: Option<&str>,
        budget: OperationBudget,
        interactive: bool,
    ) -> Result<Preparation, HookError> {
        let target = context.target()?;
        self.validate_target(&target)?;
        let binding_key = self.key(&target);
        let mut binding_guard = budget
            .run(self.store.acquire(binding_key.clone(), budget))
            .await?;
        let mut saved_binding = budget.run(binding_guard.load()).await?;
        drop(binding_guard);
        if saved_binding.as_ref().is_some_and(|record| record.client_id != self.config.client_id || record.flow != self.flow_id() || record.allowed_scopes != self.config.allowed_scopes
            || target.issuer().is_some_and(|issuer| issuer != record.metadata.issuer)
            || matches!(target.binding(), AuthBinding::OAuth {resource, ..} if resource != &record.metadata.resource)) {
            saved_binding = None;
        }
        let mut required = discovery::challenge_scopes(challenge)?;
        required.extend_from_slice(target.scopes());
        if let Some(binding) = &saved_binding {
            required.extend_from_slice(&binding.challenge_scopes);
        }
        required.sort();
        required.dedup();
        if required
            .iter()
            .any(|scope| !self.config.allowed_scopes.contains(scope))
        {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        // Validate local authorization before touching the grant; no network is needed on a cache hit.
        if let Some(binding) = &saved_binding {
            let mut current_binding = binding.clone();
            current_binding.challenge_scopes = required.clone();
            self.validate_saved(&target, &current_binding)?;
            let endpoints_current = self.approve_metadata(&target, &binding.metadata).is_ok();
            let key = self.grant_key(&target, &binding.metadata);
            let mut guard = budget.run(self.store.acquire(key, budget)).await?;
            if let Some(mut record) = budget.run(guard.load()).await?
                && endpoints_current
            {
                record.metadata = binding.metadata.clone();
                record.challenge_scopes = required.clone();
                if let Some(token) = record.token.as_mut()
                    && rejected_attempt == Some(token.generation.as_str())
                {
                    token.access_rejected = true;
                    self.persist(&mut *guard, &mut record, budget).await?;
                }
                if challenge.is_none()
                    || rejected_attempt.is_some_and(|attempt| {
                        record
                            .token
                            .as_ref()
                            .is_some_and(|token| token.generation != attempt)
                    })
                {
                    if let Some(credential) = self.cached(&record) {
                        return Ok(Preparation::Ready(credential));
                    }
                }
                if self.config.flow == OAuthFlow::AuthorizationCodePkce
                    && record
                        .token
                        .as_ref()
                        .is_some_and(|token| token.refresh_token.is_some() && !token.rejected)
                    && self.satisfies_requirements(&record)
                {
                    return self
                        .refresh(&mut *guard, &mut record, budget)
                        .await
                        .map(Preparation::Ready);
                }
            }
        }
        // Discovery must never hold a credential-store guard (including a binding guard).
        let (mut metadata, hint) = discovery::discover(
            self,
            &target,
            challenge,
            saved_binding
                .as_ref()
                .and_then(|record| record.resource_metadata_hint.as_ref()),
            &required,
            budget,
        )
        .await?;
        let mut binding = SessionRecord {
            version: String::new(),
            metadata: metadata.clone(),
            client_id: self.config.client_id.clone(),
            flow: self.flow_id().into(),
            configured_binding: !matches!(target.binding(), AuthBinding::Unbound),
            allowed_scopes: self.config.allowed_scopes.clone(),
            resource_metadata_hint: hint.clone(),
            challenge_scopes: required.clone(),
            token: None,
            pending: None,
        };
        loop {
            let mut binding_guard = budget
                .run(self.store.acquire(binding_key.clone(), budget))
                .await?;
            let current = budget.run(binding_guard.load()).await?;
            drop(binding_guard);
            let expected = current.as_ref().map(|record| record.version.clone());
            if let Some(current) = current
                && current.client_id == self.config.client_id
                && current.flow == self.flow_id()
                && current.allowed_scopes == self.config.allowed_scopes
                && current.metadata.issuer == metadata.issuer
                && current.metadata.resource == metadata.resource
            {
                required.extend(current.challenge_scopes);
            }
            required.sort();
            required.dedup();
            let decision = self
                .policy
                .select(
                    &target,
                    &ResourceMetadata::new(
                        metadata.resource.clone(),
                        vec![metadata.issuer.clone()],
                    ),
                    &required,
                )
                .map_err(sanitize_provider_error)?;
            if decision.issuer != metadata.issuer
                || decision
                    .scopes
                    .iter()
                    .any(|scope| !self.config.allowed_scopes.contains(scope))
                || required
                    .iter()
                    .any(|scope| !decision.scopes.contains(scope))
            {
                return Err(fail(AuthErrorCode::AccessDenied));
            }
            metadata.scopes = decision.scopes;
            binding.metadata = metadata.clone();
            binding.challenge_scopes = required.clone();
            binding.version = expected.clone().unwrap_or_default();
            let mut binding_guard = budget
                .run(self.store.acquire(binding_key.clone(), budget))
                .await?;
            if budget
                .run(binding_guard.load())
                .await?
                .as_ref()
                .map(|record| record.version.clone())
                != expected
            {
                drop(binding_guard);
                continue;
            }
            self.persist(&mut *binding_guard, &mut binding, budget)
                .await?;
            break;
        }
        let key = self.grant_key(&target, &metadata);
        let mut guard = budget.run(self.store.acquire(key.clone(), budget)).await?;
        let mut record = match budget.run(guard.load()).await? {
            Some(record) => record,
            None => {
                let mut record = binding.clone();
                record.version.clear();
                record
            }
        };
        record.metadata = metadata;
        record.resource_metadata_hint = hint;
        record.challenge_scopes = required;
        if let Some(token) = record.token.as_mut()
            && rejected_attempt == Some(token.generation.as_str())
        {
            token.access_rejected = true;
        }
        if let Some(credential) = self.cached(&record) {
            return Ok(Preparation::Ready(credential));
        }
        if let Some(token) = &record.token {
            // Explicit step-up needs new consent, not refresh with a widened scope request.
            if self.config.flow == OAuthFlow::AuthorizationCodePkce
                && token.refresh_token.is_some()
                && !token.rejected
                && self.satisfies_requirements(&record)
            {
                return self
                    .refresh(&mut *guard, &mut record, budget)
                    .await
                    .map(Preparation::Ready);
            }
        }
        match self.config.flow {
            OAuthFlow::ClientCredentials => self
                .client_credentials(&mut *guard, &mut record, budget)
                .await
                .map(Preparation::Ready),
            OAuthFlow::AuthorizationCodePkce => {
                if !interactive {
                    return Err(fail(AuthErrorCode::InteractionRequired));
                }
                if let Some(login) = &record.pending
                    && login.expires_at > now()?
                    && login.host_deadline_ms.saturating_add(1) >= wall_deadline_ms(budget)?
                    && login.host_deadline_ms > now_ms()?
                    && login.binding_key == self.key(&target)
                    && login.metadata.scopes == record.metadata.scopes
                    && login.required_scopes == record.challenge_scopes
                    && self.config.redirect_uri.as_deref() == Some(login.redirect_uri.as_str())
                {
                    let pending = pending(key, context, login)?;
                    self.check_url(&pending.url, EndpointUse::Authorization, budget)
                        .await?;
                    return Ok(Preparation::InteractionRequired(pending));
                }
                let client = self.client(&record.metadata)?;
                let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
                let mut request = client
                    .authorize_url(CsrfToken::new_random)
                    .set_pkce_challenge(challenge)
                    .add_extra_param("resource", &record.metadata.resource);
                for scope in &record.metadata.scopes {
                    request = request.add_scope(Scope::new(scope.clone()));
                }
                let (url, state) = request.url();
                self.check_url(&url, EndpointUse::Authorization, budget)
                    .await?;
                let login = SavedLogin {
                    id: random_id(),
                    binding_key: self.key(&target),
                    metadata: record.metadata.clone(),
                    required_scopes: record.challenge_scopes.clone(),
                    host_deadline_ms: wall_deadline_ms(budget)?,
                    state: state.secret().clone(),
                    verifier: verifier.secret().clone(),
                    redirect_uri: self
                        .config
                        .redirect_uri
                        .clone()
                        .ok_or_else(|| fail(AuthErrorCode::InvalidConfiguration))?,
                    url: url.to_string(),
                    expires_at: now()?.saturating_add(
                        600.min(
                            budget
                                .deadline
                                .saturating_duration_since(Instant::now())
                                .as_secs()
                                .max(1),
                        ),
                    ),
                    in_flight: false,
                };
                record.pending = Some(login.clone());
                self.persist(&mut *guard, &mut record, budget).await?;
                pending(key, context, &login).map(Preparation::InteractionRequired)
            }
        }
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
        let auth = metadata
            .authorization_endpoint
            .as_deref()
            .unwrap_or(&metadata.token_endpoint);
        let mut client = BasicClient::new(ClientId::new(self.config.client_id.clone()))
            .set_auth_uri(
                AuthUrl::new(auth.into()).map_err(|_| fail(AuthErrorCode::DiscoveryFailed))?,
            )
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
        for scope in &record.metadata.scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let http = TokenHttp {
            network: self.network.clone(),
            budget,
            status: None,
            safe_failure: None,
        };
        let response = request.request_async(&http).await.map_err(token_error)?;
        self.save_token(guard, record, response, None, budget).await
    }
    async fn refresh(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
        let token = record
            .token
            .as_ref()
            .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))?;
        let generation = token.generation.clone();
        let refresh = RefreshToken::new(
            token
                .refresh_token
                .clone()
                .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))?,
        );
        let client = self.client(&record.metadata)?;
        record.token.as_mut().unwrap().refresh_in_flight = true;
        self.persist(guard, record, budget).await?;
        let mut request = client
            .exchange_refresh_token(&refresh)
            .add_extra_param("resource", &record.metadata.resource);
        for scope in &record.token.as_ref().unwrap().authorized_scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let status = Arc::new(std::sync::atomic::AtomicU16::new(0));
        let safe_failure = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let http = TokenHttp {
            network: self.network.clone(),
            budget,
            status: Some(status.clone()),
            safe_failure: Some(safe_failure.clone()),
        };
        match request.request_async(&http).await {
            Ok(response) => {
                self.save_token(
                    guard,
                    record,
                    response,
                    Some(refresh.secret().clone()),
                    budget,
                )
                .await
            }
            Err(RequestTokenError::ServerResponse(response)) => {
                let status = status.load(std::sync::atomic::Ordering::Relaxed);
                let known_oauth_error = status == 400
                    && !matches!(response.error(), BasicErrorResponseType::Extension(_));
                if !known_oauth_error && !safe_failure.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(fail(AuthErrorCode::ProviderFailed));
                }
                let rejected = *response.error() == BasicErrorResponseType::InvalidGrant;
                let token = record.token.as_mut().unwrap();
                token.refresh_in_flight = false;
                token.rejected = rejected;
                self.persist(guard, record, budget).await?;
                if rejected {
                    budget.run(guard.on_refresh_rejected(generation)).await?;
                    return Err(fail(AuthErrorCode::RefreshRejected));
                }
                Err(fail(AuthErrorCode::ProviderFailed))
            }
            Err(error) => {
                if safe_failure.load(std::sync::atomic::Ordering::Relaxed) {
                    record.token.as_mut().unwrap().refresh_in_flight = false;
                    self.persist(guard, record, budget).await?;
                }
                Err(token_error(error)) // uncertain transport/parse failure retains marker and secrets
            }
        }
    }
    async fn save_token(
        &self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        response: BasicTokenResponse,
        old_refresh: Option<String>,
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
        let invalid_access = *response.token_type() != BasicTokenType::Bearer
            || response.access_token().secret().is_empty()
            || !response
                .access_token()
                .secret()
                .bytes()
                .all(|b| b.is_ascii_graphic());
        let expires = response.expires_in();
        let invalid_expiry = expires.is_some_and(|v| v.as_secs() == 0);
        let previous_scopes = if old_refresh.is_some() {
            record
                .token
                .as_ref()
                .map(|token| token.authorized_scopes.clone())
                .unwrap_or_else(|| record.metadata.scopes.clone())
        } else {
            record.metadata.scopes.clone()
        };
        let mut scopes = response
            .scopes()
            .map(|s| s.iter().map(|s| s.as_str().to_owned()).collect::<Vec<_>>())
            .unwrap_or_else(|| previous_scopes.clone());
        scopes.sort();
        scopes.dedup();
        let invalid_scopes = scopes.iter().any(|scope| {
            !valid_scope(scope)
                || !self.config.allowed_scopes.contains(scope)
                || (old_refresh.is_some() && !previous_scopes.contains(scope))
        });
        let token = SavedToken {
            access_token: response.access_token().secret().clone(),
            refresh_token: response
                .refresh_token()
                .map(|s| s.secret().clone())
                .or(old_refresh.clone()),
            expires_at: expires
                .map(|expiry| now().unwrap_or(u64::MAX).saturating_add(expiry.as_secs())),
            authorized_scopes: if invalid_scopes && old_refresh.is_some() {
                previous_scopes
            } else {
                scopes
                    .iter()
                    .filter(|scope| self.config.allowed_scopes.contains(scope))
                    .cloned()
                    .collect()
            },
            scopes,
            generation: random_id(),
            rejected: false,
            access_rejected: invalid_access || invalid_expiry || invalid_scopes,
            refresh_in_flight: false,
        };
        let credential = BearerCredential {
            token: token.access_token.clone(),
            attempt_id: token.generation.clone(),
        };
        record.token = Some(token);
        record.pending = None;
        self.persist(guard, record, budget).await?;
        if invalid_access || invalid_expiry {
            return Err(fail(AuthErrorCode::CredentialUnavailable));
        }
        if invalid_scopes || !self.satisfies_requirements(record) {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        Ok(credential)
    }
    /// Complete only this pending generation. Callback transport/UI remain host-owned.
    /// Clone the handle before calling if the host needs generation-specific cancellation.
    /// An uncertain exchange is never replayed; prepare returns a cancellation-only handle.
    pub async fn complete(
        &self,
        login: PendingLogin,
        callback: Url,
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
        let budget = OperationBudget::until(budget.deadline.min(login.deadline));
        budget
            .run(self.complete_inner(login, callback, budget))
            .await
    }
    async fn complete_inner(
        &self,
        login: PendingLogin,
        callback: Url,
        budget: OperationBudget,
    ) -> Result<BearerCredential, HookError> {
        let target = login.context.target()?;
        self.validate_target(&target)?;
        let redirect = Url::parse(
            self.config
                .redirect_uri
                .as_deref()
                .ok_or_else(|| fail(AuthErrorCode::UnsupportedBinding))?,
        )
        .map_err(|_| fail(AuthErrorCode::InvalidConfiguration))?;
        if callback.origin() != redirect.origin()
            || callback.path() != redirect.path()
            || callback.fragment().is_some()
            || !callback.username().is_empty()
            || callback.password().is_some()
        {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        let mut expected_query = redirect
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>();
        let mut fixed_query = callback
            .query_pairs()
            .filter(|(key, _)| {
                !matches!(
                    key.as_ref(),
                    "state" | "code" | "error" | "iss" | "error_description" | "error_uri"
                )
            })
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<Vec<_>>();
        expected_query.sort();
        fixed_query.sort();
        if expected_query != fixed_query {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        let mut binding_guard = budget
            .run(self.store.acquire(self.key(&target), budget))
            .await?;
        let binding = budget
            .run(binding_guard.load())
            .await?
            .ok_or_else(|| fail(AuthErrorCode::InteractionRequired))?;
        drop(binding_guard);
        self.validate_saved(&target, &binding)?;
        self.approve_metadata(&target, &binding.metadata)?;
        let mut guard = budget
            .run(self.store.acquire((*login.key).clone(), budget))
            .await?;
        let mut record = budget
            .run(guard.load())
            .await?
            .ok_or_else(|| fail(AuthErrorCode::InteractionRequired))?;
        drop(guard);
        if *login.key != self.grant_key(&target, &record.metadata) {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }

        let saved = record
            .pending
            .as_ref()
            .filter(|s| {
                s.id == login.id
                    && s.expires_at > now().unwrap_or(u64::MAX)
                    && s.host_deadline_ms > now_ms().unwrap_or(u64::MAX)
                    && !s.in_flight
                    && self.config.redirect_uri.as_deref() == Some(s.redirect_uri.as_str())
            })
            .ok_or_else(|| fail(AuthErrorCode::InteractionRequired))?
            .clone();
        let mut state = None;
        let mut code = None;
        let mut error = None;
        let mut issuer = None;
        for (key, value) in callback.query_pairs() {
            let field = match key.as_ref() {
                "state" => &mut state,
                "code" => &mut code,
                "error" => &mut error,
                "iss" => &mut issuer,
                _ => continue,
            };
            if field.replace(value.into_owned()).is_some() {
                return Err(fail(AuthErrorCode::AccessDenied));
            }
        }
        if CsrfToken::new(state.ok_or_else(|| fail(AuthErrorCode::AccessDenied))?)
            != CsrfToken::new(saved.state.clone())
            || (saved
                .metadata
                .authorization_response_iss_parameter_supported
                && issuer.is_none())
            || issuer.as_ref().is_some_and(|i| i != &saved.metadata.issuer)
            || (code.is_some() && error.is_some())
        {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        if saved.binding_key != self.key(&target) {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        self.approve_metadata(&target, &saved.metadata)?;
        let mut guard = budget
            .run(self.store.acquire((*login.key).clone(), budget))
            .await?;
        record = budget
            .run(guard.load())
            .await?
            .ok_or_else(|| fail(AuthErrorCode::InteractionRequired))?;
        if !record.pending.as_ref().is_some_and(|pending| {
            pending.id == saved.id
                && !pending.in_flight
                && pending.host_deadline_ms > now_ms().unwrap_or(u64::MAX)
        }) {
            return Err(fail(AuthErrorCode::InteractionRequired));
        }
        if error.is_some() {
            record.pending = None;
            self.persist(&mut *guard, &mut record, budget).await?;
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        let code = code
            .filter(|s| !s.is_empty())
            .ok_or_else(|| fail(AuthErrorCode::AccessDenied))?;
        record.metadata = saved.metadata.clone();
        record.challenge_scopes = saved.required_scopes.clone();
        record.pending.as_mut().unwrap().in_flight = true;
        self.persist(&mut *guard, &mut record, budget).await?;
        let client = self.client(&record.metadata)?;
        let http = TokenHttp {
            network: self.network.clone(),
            budget,
            status: None,
            safe_failure: None,
        };
        let response = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(saved.verifier))
            .add_extra_param("resource", &record.metadata.resource)
            .request_async(&http)
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                // A rejected code is not reusable. Transport/parse ambiguity retains
                // the marker; hosts can cancel only this generation and start anew.
                if matches!(&error, RequestTokenError::ServerResponse(_)) {
                    record.pending = None;
                    self.persist(&mut *guard, &mut record, budget).await?;
                }
                if matches!(&error, RequestTokenError::ServerResponse(response) if *response.error() == BasicErrorResponseType::InvalidGrant)
                {
                    return Err(fail(AuthErrorCode::InteractionRequired));
                }
                return Err(token_error(error));
            }
        };
        self.save_token(&mut *guard, &mut record, response, None, budget)
            .await
    }
    /// Host-approved recovery after an uncertain rotation. This never retries the
    /// old refresh token or deletes its evidence. Only the matching generation is
    /// retired; a stale repair cannot reject a newer credential. Prepare again
    /// afterward to restart PKCE or reacquire a client-credentials grant.
    pub async fn abandon_uncertain_refresh(
        &self,
        context: AuthContext,
        attempt_id: &str,
        budget: OperationBudget,
    ) -> Result<bool, HookError> {
        budget
            .run(async {
                let target = context.target()?;
                self.validate_target(&target)?;
                let mut binding_guard = budget
                    .run(self.store.acquire(self.key(&target), budget))
                    .await?;
                let Some(binding) = budget.run(binding_guard.load()).await? else {
                    return Ok(false);
                };
                drop(binding_guard);
                self.validate_saved(&target, &binding)?;
                let mut guard = budget
                    .run(
                        self.store
                            .acquire(self.grant_key(&target, &binding.metadata), budget),
                    )
                    .await?;
                let Some(mut record) = budget.run(guard.load()).await? else {
                    return Ok(false);
                };
                if self.grant_key(&target, &binding.metadata)
                    != self.grant_key(&target, &record.metadata)
                {
                    return Err(fail(AuthErrorCode::InvalidConfiguration));
                }
                if let Some(token) = &mut record.token
                    && token.generation == attempt_id
                    && token.refresh_in_flight
                {
                    token.refresh_in_flight = false;
                    token.rejected = true;
                    self.persist(&mut *guard, &mut record, budget).await?;
                    return Ok(true);
                }
                Ok(false)
            })
            .await
    }
    /// Cancel only this login generation. A stale cancellation cannot remove a newer login.
    pub async fn cancel_login(
        &self,
        login: PendingLogin,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        budget
            .run(async {
                let target = login.context.target()?;
                self.validate_target(&target)?;
                let mut guard = budget
                    .run(self.store.acquire((*login.key).clone(), budget))
                    .await?;
                if let Some(mut record) = budget.run(guard.load()).await?
                    && record.pending.as_ref().is_some_and(|s| s.id == login.id)
                {
                    if record
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending.binding_key != self.key(&target))
                    {
                        return Err(fail(AuthErrorCode::AccessDenied));
                    }
                    if *login.key != self.grant_key(&target, &record.metadata) {
                        return Err(fail(AuthErrorCode::InvalidConfiguration));
                    }
                    record.pending = None;
                    self.persist(&mut *guard, &mut record, budget).await?;
                }
                Ok(())
            })
            .await
    }
}
fn pending(
    key: SessionKey,
    mut context: AuthContext,
    login: &SavedLogin,
) -> Result<PendingLogin, HookError> {
    let remaining = login.host_deadline_ms.saturating_sub(now_ms()?);
    let deadline = Instant::now() + std::time::Duration::from_millis(remaining);
    context.deadline = deadline;
    Ok(PendingLogin {
        key: Box::new(key),
        id: login.id.clone(),
        url: Url::parse(&login.url).map_err(|_| fail(AuthErrorCode::InvalidConfiguration))?,
        expires_at: login.expires_at,
        exchange_in_flight: login.in_flight,
        deadline,
        context: Box::new(context),
    })
}
fn now_ms() -> Result<u64, HookError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_millis().min(u64::MAX as u128) as u64)
        .map_err(|_| fail(AuthErrorCode::ProviderFailed))
}
fn wall_deadline_ms(budget: OperationBudget) -> Result<u64, HookError> {
    Ok(now_ms()?.saturating_add(
        budget
            .deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u64::MAX as u128) as u64,
    ))
}
fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
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
fn token_error(
    error: RequestTokenError<HookError, oauth2::basic::BasicErrorResponse>,
) -> HookError {
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
    fn credential(
        &self,
        context: AuthContext,
    ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
        Box::pin(async move {
            let budget = OperationBudget::until(context.deadline);
            if context.authentication.is_none() {
                let target = context.target()?;
                let mut guard = budget
                    .run(self.store.acquire(self.key(&target), budget))
                    .await?;
                if budget.run(guard.load()).await?.is_none() {
                    return Ok(None);
                }
            }
            match budget
                .run(self.prepare_inner(context, None, None, budget, false))
                .await?
            {
                Preparation::Ready(credential) => Ok(Some(credential)),
                Preparation::InteractionRequired(_) => {
                    Err(fail(AuthErrorCode::InteractionRequired))
                }
            }
        })
    }
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
            if challenge.status == 403
                && (!discovery::insufficient_scope(&headers)?
                    || (discovery::challenge_scopes(Some(&headers))?.is_empty()
                        && context.target()?.scopes().is_empty()))
            {
                return Err(fail(AuthErrorCode::AccessDenied));
            }
            let header = if headers.is_empty() {
                None
            } else {
                Some(headers.as_str())
            };
            match budget
                .run(self.prepare_inner(
                    context,
                    header,
                    challenge.attempt_id.as_deref(),
                    budget,
                    false,
                ))
                .await?
            {
                Preparation::Ready(_) => Ok(()),
                Preparation::InteractionRequired(_) => {
                    Err(fail(AuthErrorCode::InteractionRequired))
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "managed/tests.rs"]
mod tests;
