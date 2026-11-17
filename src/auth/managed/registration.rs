//! Client selection: a pre-registered client, then a Client ID Metadata
//! Document, then RFC 7591 Dynamic Client Registration when host policy permits.
use super::{
    ClientSecret, CredentialGuard, EndpointUse, ManagedOAuth, Mode, OperationBudget, SessionKey,
    SessionRecord, TokenAuthMethod, TrustedMetadata, cas, fail, frame, now, persist, random_id,
    valid_https,
};
use crate::{
    auth::{AuthErrorCode, AuthTarget, OAuthFlow, valid_scope},
    client::{HookError, LocalFuture},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use url::Url;

/// Host permission to register a client at exactly one issuer. It is never
/// inferred from metadata; the request metadata comes only from here.
#[non_exhaustive]
pub struct RegistrationPolicy {
    issuer: String,
    client_name: String,
    software_id: Option<String>,
    software_version: Option<String>,
    scope: Option<Vec<String>>,
    initial_access_token: Option<(String, ClientSecret)>,
}
impl RegistrationPolicy {
    /// `issuer` is matched exactly; `client_name` is sent as RFC 7591 `client_name`.
    pub fn new(issuer: impl Into<String>, client_name: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            client_name: client_name.into(),
            software_id: None,
            software_version: None,
            scope: None,
            initial_access_token: None,
        }
    }
    pub fn software_id(mut self, id: impl Into<String>) -> Self {
        self.software_id = Some(id.into());
        self
    }
    pub fn software_version(mut self, version: impl Into<String>) -> Self {
        self.software_version = Some(version.into());
        self
    }
    /// Registration `scope`; never derived from an operation's requested scopes.
    pub fn scope(mut self, scopes: Vec<String>) -> Self {
        self.scope = Some(scopes);
        self
    }
    /// Sent as a Bearer credential only to this issuer's registration endpoint
    /// and never persisted. The reference, not the token, enters the request digest.
    pub fn initial_access_token(
        mut self,
        reference: impl Into<String>,
        token: ClientSecret,
    ) -> Self {
        self.initial_access_token = Some((reference.into(), token));
        self
    }
    pub(super) fn valid(&self) -> bool {
        !self.issuer.is_empty()
            && !self.client_name.is_empty()
            && self.software_id.as_ref().is_none_or(|s| !s.is_empty())
            && self.software_version.as_ref().is_none_or(|s| !s.is_empty())
            && self
                .scope
                .as_ref()
                .is_none_or(|s| !s.is_empty() && s.iter().all(|s| valid_scope(s)))
            && self
                .initial_access_token
                .as_ref()
                .is_none_or(|(r, t)| !r.is_empty() && !t.secret().is_empty())
    }
    pub(super) fn issuer(&self) -> &str {
        &self.issuer
    }
    fn scope_value(&self) -> Option<String> {
        self.scope.as_ref().map(|scopes| {
            let mut scopes = scopes.clone();
            scopes.sort();
            scopes.dedup();
            scopes.join(" ")
        })
    }
    /// Lowercase hex SHA-256 of the framed policy; a record with another digest is unusable.
    pub(super) fn request_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let field = |value: &Option<String>| value.clone().unwrap_or_default();
        let framed = frame(
            "ahp.oauth.registration-request:",
            &[
                &self.client_name,
                &field(&self.software_id),
                &field(&self.software_version),
                &self.scope_value().unwrap_or_default(),
                &self
                    .initial_access_token
                    .as_ref()
                    .map(|(r, _)| r.clone())
                    .unwrap_or_default(),
            ],
        );
        Sha256::digest(framed.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Host secret storage for issued client secrets. The SDK has no implicit store:
/// without this hook confidential (client-credentials) registration is unavailable.
/// The SDK chooses fresh opaque references; records hold only the reference.
pub trait ClientSecretStorage: Send + Sync {
    fn store(
        &self,
        reference: String,
        secret: ClientSecret,
        budget: OperationBudget,
    ) -> LocalFuture<'_, Result<(), HookError>>;
    /// `None` when the reference cannot be resolved; the registration is then unusable.
    fn resolve(
        &self,
        reference: String,
        budget: OperationBudget,
    ) -> LocalFuture<'_, Result<Option<ClientSecret>, HookError>>;
    fn delete(
        &self,
        reference: String,
        budget: OperationBudget,
    ) -> LocalFuture<'_, Result<(), HookError>>;
}

/// Host CIMD configuration: the published document URL (the `client_id`) and the
/// `redirect_uris` that document declares. The SDK never fetches the URL.
pub(super) struct Cimd {
    pub(super) url: String,
    pub(super) redirect_uris: Vec<String>,
}

#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum ClientSource {
    #[default]
    Preregistered,
    Cimd,
    Dcr,
}

/// A stored DCR registration. The client secret is only a host reference.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct SavedRegistration {
    pub(super) client_id: String,
    pub(super) client_secret_expires_at: Option<u64>,
    pub(super) registered_at: u64,
    pub(super) issued: Value,
    pub(super) request_digest: String,
    pub(super) method: String,
    pub(super) generation: String,
    pub(super) secret_ref: Option<String>,
}
/// Persisted backoff for failed registrations; blocks only registration requests.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct FailedMarker {
    pub(super) request_digest: String,
    pub(super) failed_at: u64,
    pub(super) attempts: u32,
    pub(super) next_attempt_at: u64,
    pub(super) generation: String,
}
impl SavedRegistration {
    fn expires(&self) -> Option<u64> {
        self.client_secret_expires_at.filter(|at| *at != 0)
    }
    fn expired(&self) -> bool {
        self.expires().is_some_and(|at| at <= now())
    }
    fn renewal_due(&self, cap: Duration) -> bool {
        self.expires().is_some_and(|at| {
            let margin = (at.saturating_sub(self.registered_at) / 10).min(cap.as_secs());
            now() >= at.saturating_sub(margin)
        })
    }
}

/// The client for one operation. No Debug: it may carry a secret.
pub(super) struct ClientChoice {
    pub(super) id: String,
    pub(super) source: ClientSource,
    pub(super) method: TokenAuthMethod,
    pub(super) secret: Option<ClientSecret>,
    /// DCR registration generation, and whether proactive renewal is due.
    pub(super) generation: Option<String>,
    pub(super) renew: bool,
}

const SECRET_METHODS: [(&str, TokenAuthMethod); 2] = [
    ("client_secret_basic", TokenAuthMethod::ClientSecretBasic),
    ("client_secret_post", TokenAuthMethod::ClientSecretPost),
];

/// `https`, a path, no userinfo, fragment or dot segments, checked on the
/// verbatim string because URL parsing would normalize them away.
pub(super) fn valid_cimd_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let path = match rest.find('/') {
        Some(start) if !rest[..start].contains(['?', '#']) => &rest[start..],
        _ => return false,
    };
    let path = path.split(['?', '#']).next().unwrap_or_default();
    url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && !value.contains('#')
        && !path.split('/').any(|segment| {
            let segment = segment.to_ascii_lowercase().replace("%2e", ".");
            segment == "." || segment == ".."
        })
}

pub(super) fn secret_method(metadata: &TrustedMetadata) -> Option<(&'static str, TokenAuthMethod)> {
    let supported = &metadata.token_endpoint_auth_methods_supported;
    SECRET_METHODS.into_iter().find(|(name, _)| {
        if supported.is_empty() {
            *name == "client_secret_basic"
        } else {
            supported.iter().any(|s| s == name)
        }
    })
}

fn method_of(name: &str) -> TokenAuthMethod {
    SECRET_METHODS
        .into_iter()
        .find(|(n, _)| *n == name)
        .map_or(TokenAuthMethod::None, |(_, method)| method)
}

/// An accepted registration response, before persistence.
pub(super) struct Issued {
    pub(super) client_id: String,
    pub(super) secret: Option<String>,
    pub(super) expires_at: Option<u64>,
    pub(super) metadata: Value,
}

/// Validate a registration response, mapping outcomes in the contract's table order.
pub(super) fn accept_registration(
    flow: OAuthFlow,
    request: &Value,
    status: u16,
    body: &[u8],
    now: u64,
) -> Result<Issued, AuthErrorCode> {
    use AuthErrorCode::*;
    let object = serde_json::from_slice::<Value>(body)
        .ok()
        .filter(Value::is_object);
    match status {
        300..=399 => return Err(UntrustedDestination),
        200 | 201 if object.is_some() => {}
        200..=299 => return Err(ProviderFailed),
        401 | 403 => return Err(CredentialUnavailable),
        408 | 429 => return Err(ProviderFailed),
        400..=499 => return Err(InvalidConfiguration),
        _ => return Err(ProviderFailed),
    }
    let mut body = object.unwrap();
    let present = |key: &str| body.get(key).filter(|v| !v.is_null());
    let pkce = flow == OAuthFlow::AuthorizationCodePkce;
    let grant = if pkce {
        "authorization_code"
    } else {
        "client_credentials"
    };
    let client_id = present("client_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or(InvalidConfiguration)?;
    let secret = present("client_secret").map(|s| s.as_str().filter(|s| !s.is_empty()));
    let expires_at = match present("client_secret_expires_at") {
        None => None,
        Some(value) => Some(
            value
                .as_u64()
                .filter(|at| *at == 0 || *at > now)
                .ok_or(InvalidConfiguration)?,
        ),
    };
    if present("redirect_uris").is_some_and(|v| Some(v) != request.get("redirect_uris"))
        || present("grant_types").is_some_and(|v| {
            !v.as_array()
                .is_some_and(|grants| grants.iter().any(|g| g == grant))
        })
        || present("token_endpoint_auth_method")
            .is_some_and(|v| Some(v) != request.get("token_endpoint_auth_method"))
        || pkce != secret.is_none()
        || secret.is_some_and(|s| s.is_none())
    {
        return Err(InvalidConfiguration);
    }
    let secret = secret.flatten().map(str::to_owned);
    let issued = body.as_object_mut().unwrap();
    for key in [
        "client_secret",
        "registration_access_token",
        "registration_client_uri",
    ] {
        issued.remove(key);
    }
    Ok(Issued {
        client_id,
        secret,
        expires_at,
        metadata: body,
    })
}

/// `Retry-After` as delta-seconds or an HTTP-date (a past date is no wait).
fn retry_after(response: &oauth2::HttpResponse) -> Option<u64> {
    let value = response.headers().get("retry-after")?.to_str().ok()?.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return value.parse().ok();
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(
        at.duration_since(std::time::SystemTime::now())
            .map_or(0, |wait| wait.as_secs()),
    )
}

impl ManagedOAuth {
    /// An explicit preset's client, else the host's configured client.
    pub(super) fn preregistered<'a>(&'a self, target: &'a AuthTarget) -> Option<&'a str> {
        self.config.client_id.as_deref().or(target.client_id())
    }
    fn registration_policy(&self, issuer: &str) -> Option<&RegistrationPolicy> {
        self.config
            .registrations
            .iter()
            .find(|policy| policy.issuer == issuer)
    }
    fn redirect(&self) -> &str {
        match self.config.flow {
            OAuthFlow::AuthorizationCodePkce => self.config.redirect_uri.as_deref().unwrap_or(""),
            _ => "",
        }
    }
    pub(super) fn registration_key(&self, issuer: &str) -> SessionKey {
        SessionKey {
            storage_key: frame(
                "ahp.oauth.registration:",
                &[
                    &self.config.namespace,
                    issuer,
                    self.flow_id(),
                    self.redirect(),
                ],
            ),
            namespace: self.config.namespace.clone(),
            backend_id: String::new(),
            destination: String::new(),
            purpose: String::new(),
        }
    }
    /// Select a client source for new binding metadata, without network access.
    pub(super) fn select_source(
        &self,
        target: &AuthTarget,
        metadata: &TrustedMetadata,
    ) -> Result<ClientSource, HookError> {
        if self.preregistered(target).is_some() {
            return Ok(ClientSource::Preregistered);
        }
        let pkce = self.config.flow == OAuthFlow::AuthorizationCodePkce;
        if let Some(cimd) = self.config.cimd.as_ref().filter(|_| pkce)
            && metadata.client_id_metadata_document_supported
        {
            if !valid_cimd_url(&cimd.url)
                || !cimd.redirect_uris.iter().any(|r| r == self.redirect())
            {
                return Err(fail(AuthErrorCode::InvalidConfiguration));
            }
            return Ok(ClientSource::Cimd);
        }
        let endpoint = metadata
            .registration_endpoint
            .as_deref()
            .filter(|_| self.registration_policy(&metadata.issuer).is_some())
            .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))?;
        if !pkce && (self.config.secret_storage.is_none() || secret_method(metadata).is_none()) {
            return Err(fail(AuthErrorCode::CredentialUnavailable));
        }
        if !Url::parse(endpoint).is_ok_and(|url| valid_https(&url)) {
            return Err(fail(AuthErrorCode::UntrustedDestination));
        }
        Ok(ClientSource::Dcr)
    }
    /// A recorded selection is obsolete only when current host policy changes it.
    pub(super) fn selection_current(&self, target: &AuthTarget, record: &SessionRecord) -> bool {
        let preregistered = self.preregistered(target);
        match record.client_source {
            ClientSource::Preregistered => preregistered == Some(record.client_id.as_str()),
            ClientSource::Cimd => {
                preregistered.is_none()
                    && self.config.flow == OAuthFlow::AuthorizationCodePkce
                    && self.config.cimd.as_ref().is_some_and(|cimd| {
                        cimd.url == record.client_id
                            && cimd.redirect_uris.iter().any(|r| r == self.redirect())
                    })
            }
            ClientSource::Dcr => {
                preregistered.is_none()
                    && self.registration_policy(&record.metadata.issuer).is_some()
                    && record.registration_key.as_deref()
                        == Some(self.registration_key(&record.metadata.issuer).as_str())
            }
        }
    }
    /// The client for an operation on this binding. Only DCR touches the store;
    /// it registers only in `prepare` or, for client credentials, non-interactively.
    pub(super) async fn choose(
        &self,
        target: &AuthTarget,
        binding: &SessionRecord,
        mode: Mode,
        budget: OperationBudget,
    ) -> Result<ClientChoice, HookError> {
        let choice = |id: &str, method, secret| ClientChoice {
            id: id.to_owned(),
            source: binding.client_source,
            method,
            secret,
            generation: None,
            renew: false,
        };
        match binding.client_source {
            ClientSource::Preregistered => Ok(choice(
                self.preregistered(target).unwrap_or(&binding.client_id),
                self.config.method,
                self.config.secret.as_ref().map(|(_, s)| s.clone()),
            )),
            ClientSource::Cimd => Ok(choice(&binding.client_id, TokenAuthMethod::None, None)),
            ClientSource::Dcr => self.registered(&binding.metadata, mode, budget).await,
        }
    }
    fn secret_store(&self) -> Result<&dyn ClientSecretStorage, HookError> {
        self.config
            .secret_storage
            .as_deref()
            .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))
    }
    async fn delete_secret(&self, reference: Option<String>, budget: OperationBudget) {
        delete_secret(self.config.secret_storage.as_deref(), reference, budget).await
    }
    async fn usable(
        &self,
        record: &SessionRecord,
        digest: &str,
        budget: OperationBudget,
    ) -> Result<Option<ClientChoice>, HookError> {
        usable(
            self.config.secret_storage.as_deref(),
            self.config.renewal_margin,
            record,
            digest,
            budget,
        )
        .await
    }
    fn blocked(&self, record: &SessionRecord, mode: Mode) -> bool {
        mode != Mode::Prepare
            && record
                .marker
                .as_ref()
                .is_some_and(|marker| marker.next_attempt_at > now())
    }
    async fn locked(
        &self,
        issuer: &str,
        budget: OperationBudget,
    ) -> Result<(Box<dyn CredentialGuard>, SessionRecord), HookError> {
        let key = self.registration_key(issuer);
        let mut guard = budget.run(self.store.acquire(key, budget)).await?;
        let record = budget.run(guard.load()).await?.unwrap_or_else(|| {
            SessionRecord::empty(
                TrustedMetadata::new(String::new(), issuer.into(), String::new()),
                self.flow_id(),
            )
        });
        Ok((guard, record))
    }
    /// Under the registration-key lock: drop records and markers for a changed
    /// policy (and any marker for a host `prepare`), reuse a usable record, else
    /// register when this path may.
    async fn registered(
        &self,
        metadata: &TrustedMetadata,
        mode: Mode,
        budget: OperationBudget,
    ) -> Result<ClientChoice, HookError> {
        let policy = self
            .registration_policy(&metadata.issuer)
            .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))?;
        let digest = policy.request_digest();
        let (mut guard, mut record) = self.locked(&metadata.issuer, budget).await?;
        let stale = record
            .registration
            .as_ref()
            .is_some_and(|r| r.request_digest != digest);
        let old_secret = stale
            .then(|| record.registration.take().and_then(|r| r.secret_ref))
            .flatten();
        let unmark = record
            .marker
            .as_ref()
            .is_some_and(|m| mode == Mode::Prepare || m.request_digest != digest);
        if unmark {
            record.marker = None;
        }
        if stale || unmark {
            if !cas(&mut *guard, &mut record, budget).await? {
                return Err(fail(AuthErrorCode::ProviderFailed));
            }
            self.delete_secret(old_secret, budget).await;
        }
        if let Some(choice) = self.usable(&record, &digest, budget).await? {
            return Ok(choice);
        }
        if self.config.flow == OAuthFlow::AuthorizationCodePkce && mode != Mode::Prepare {
            return Err(fail(AuthErrorCode::InteractionRequired));
        }
        if self.blocked(&record, mode) {
            return Err(fail(AuthErrorCode::CredentialUnavailable));
        }
        self.register(&mut guard, &mut record, metadata, policy, &digest, budget)
            .await
    }
    /// Send one registration request. Eligibility is re-checked here, for a
    /// recorded selection too. Like a token exchange, once the request is written
    /// the response is received and committed under the held lock even if the
    /// caller is dropped, so an issued client is never lost.
    async fn register(
        &self,
        guard: &mut Box<dyn CredentialGuard>,
        record: &mut SessionRecord,
        metadata: &TrustedMetadata,
        policy: &RegistrationPolicy,
        digest: &str,
        budget: OperationBudget,
    ) -> Result<ClientChoice, HookError> {
        let unavailable = || fail(AuthErrorCode::CredentialUnavailable);
        let untrusted = || fail(AuthErrorCode::UntrustedDestination);
        let pkce = self.config.flow == OAuthFlow::AuthorizationCodePkce;
        let endpoint = metadata
            .registration_endpoint
            .as_deref()
            .ok_or_else(unavailable)?;
        let method = if pkce {
            "none"
        } else {
            self.secret_store()?;
            secret_method(metadata).ok_or_else(unavailable)?.0
        };
        let url = Url::parse(endpoint)
            .ok()
            .filter(valid_https)
            .ok_or_else(untrusted)?;
        budget
            .run(
                self.network
                    .check(url.clone(), EndpointUse::Registration, budget),
            )
            .await
            .map_err(|_| untrusted())?;
        let mut body = if pkce {
            json!({
                "redirect_uris": [self.redirect()],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            })
        } else {
            json!({"grant_types": ["client_credentials"]})
        };
        body["token_endpoint_auth_method"] = method.into();
        body["client_name"] = policy.client_name.clone().into();
        for (key, value) in [
            ("software_id", policy.software_id.clone()),
            ("software_version", policy.software_version.clone()),
            ("scope", policy.scope_value()),
        ] {
            if let Some(value) = value {
                body[key] = value.into();
            }
        }
        let mut request = oauth2::http::Request::builder()
            .method("POST")
            .uri(url.as_str())
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");
        if let Some((_, token)) = &policy.initial_access_token {
            request = request.header("Authorization", format!("Bearer {}", token.secret()));
        }
        let request = request
            .body(serde_json::to_vec(&body).map_err(|_| unavailable())?)
            .map_err(|_| fail(AuthErrorCode::InvalidConfiguration))?;
        let registrar = Registrar {
            flow: self.config.flow,
            body,
            digest: digest.into(),
            method,
            storage: self.config.secret_storage.clone(),
            backoff: self.config.registration_backoff,
            margin: self.config.renewal_margin,
        };
        self.detached(guard, record, move |mut guard, mut record, http, _| {
            Box::pin(async move {
                let outcome = registrar
                    .exchange(&mut *guard, &mut record, request, &http)
                    .await;
                (outcome, guard, record)
            })
        })
        .await?
    }
    /// After a successful client-credentials acquisition inside the renewal margin:
    /// re-check under the lock so one process renews; failure only updates the marker.
    pub(super) async fn renew(
        &self,
        metadata: &TrustedMetadata,
        generation: &str,
        budget: OperationBudget,
    ) {
        let renew = async {
            let policy = self
                .registration_policy(&metadata.issuer)
                .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))?;
            let digest = policy.request_digest();
            let (mut guard, mut record) = self.locked(&metadata.issuer, budget).await?;
            let due = record.registration.as_ref().is_some_and(|r| {
                r.generation == generation && r.renewal_due(self.config.renewal_margin)
            });
            if due && !self.blocked(&record, Mode::Deliver) {
                self.register(&mut guard, &mut record, metadata, policy, &digest, budget)
                    .await?;
            }
            Ok::<_, HookError>(())
        };
        let _ = renew.await;
    }
    /// Compare-and-delete one registration generation (and its secret reference).
    pub(super) async fn forget(
        &self,
        issuer: &str,
        generation: &str,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        let (mut guard, mut record) = self.locked(issuer, budget).await?;
        if record
            .registration
            .as_ref()
            .is_none_or(|r| r.generation != generation)
        {
            return Ok(());
        }
        let secret = record.registration.take().and_then(|r| r.secret_ref);
        if cas(&mut *guard, &mut record, budget).await? {
            self.delete_secret(secret, budget).await;
        }
        Ok(())
    }
    /// A repeated `invalid_client` for a replacement client is a failed registration.
    pub(super) async fn mark_failed(&self, issuer: &str, budget: OperationBudget) {
        let mark = async {
            let digest = self
                .registration_policy(issuer)
                .map(RegistrationPolicy::request_digest)
                .unwrap_or_default();
            let (mut guard, mut record) = self.locked(issuer, budget).await?;
            mark(&mut record, &digest, None, self.config.registration_backoff);
            cas(&mut *guard, &mut record, budget).await
        };
        let _ = mark.await;
    }
    /// Every host `prepare` clears a failed marker. With `force` (for a client the
    /// server deleted silently) it also deletes the current registration and its
    /// secret, and the binding-scoped grant of the old client, so `prepare`
    /// registers anew.
    pub(super) async fn prepare_registration(
        &self,
        target: &AuthTarget,
        force: bool,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        let key = self.key(target);
        let Some(mut binding) = self
            .load(&key, budget)
            .await?
            .filter(|b| b.client_source == ClientSource::Dcr && self.compatible(target, b))
        else {
            return Ok(());
        };
        let (mut guard, mut record) = self.locked(&binding.metadata.issuer, budget).await?;
        if !force && record.marker.is_none() {
            return Ok(());
        }
        let secret = force
            .then(|| record.registration.take().and_then(|r| r.secret_ref))
            .flatten();
        record.marker = None;
        if !cas(&mut *guard, &mut record, budget).await? {
            return Err(fail(AuthErrorCode::ProviderFailed));
        }
        drop(guard);
        if !force {
            return Ok(());
        }
        self.delete_secret(secret, budget).await;
        let old = std::mem::take(&mut binding.client_id);
        self.clear_grant(target, &binding.metadata, &old, budget)
            .await?;
        let mut guard = budget.run(self.store.acquire(key, budget)).await?;
        if let Some(mut current) = budget.run(guard.load()).await?
            && current.client_id == old
            && current.client_source == ClientSource::Dcr
        {
            current.client_id.clear();
            persist(&mut *guard, &mut current, budget).await?;
        }
        Ok(())
    }
    /// Compare-and-clear a binding-scoped grant of a replaced client: its tokens
    /// and login are never presented under another client. Shared grant
    /// partitions are left alone; other bindings may still use them.
    pub(super) async fn clear_grant(
        &self,
        target: &AuthTarget,
        metadata: &TrustedMetadata,
        client_id: &str,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        if client_id.is_empty() || self.config.grant_partition.is_some() {
            return Ok(());
        }
        let key = self.grant_key(target, metadata, client_id);
        let mut guard = budget.run(self.store.acquire(key, budget)).await?;
        if let Some(mut record) = budget.run(guard.load()).await?
            && (record.token.is_some() || record.pending.is_some())
        {
            record.token = None;
            record.pending = None;
            persist(&mut *guard, &mut record, budget).await?;
        }
        Ok(())
    }
}

async fn delete_secret(
    storage: Option<&dyn ClientSecretStorage>,
    reference: Option<String>,
    budget: OperationBudget,
) {
    if let (Some(reference), Some(storage)) = (reference, storage) {
        // Best effort once the record no longer names it.
        let _ = budget.run(storage.delete(reference, budget)).await;
    }
}
async fn usable(
    storage: Option<&dyn ClientSecretStorage>,
    margin: Duration,
    record: &SessionRecord,
    digest: &str,
    budget: OperationBudget,
) -> Result<Option<ClientChoice>, HookError> {
    let Some(saved) = record
        .registration
        .as_ref()
        .filter(|r| r.request_digest == digest && !r.expired())
    else {
        return Ok(None);
    };
    let secret = match &saved.secret_ref {
        Some(reference) => {
            let storage = storage.ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))?;
            match budget
                .run(storage.resolve(reference.clone(), budget))
                .await?
            {
                Some(secret) => Some(secret),
                None => return Ok(None),
            }
        }
        None => None,
    };
    Ok(Some(ClientChoice {
        id: saved.client_id.clone(),
        source: ClientSource::Dcr,
        method: method_of(&saved.method),
        secret,
        generation: Some(saved.generation.clone()),
        renew: saved.renewal_due(margin),
    }))
}
/// Exponential backoff (or a later Retry-After), capped at the host maximum.
fn mark(
    record: &mut SessionRecord,
    digest: &str,
    retry_after: Option<u64>,
    (base, max): (Duration, Duration),
) {
    let attempts = record
        .marker
        .as_ref()
        .filter(|m| m.request_digest == digest)
        .map_or(0, |m| m.attempts)
        .saturating_add(1);
    let backoff = base
        .as_secs()
        .saturating_mul(1u64 << (attempts - 1).min(32))
        .min(max.as_secs());
    let wait = retry_after.unwrap_or(0).max(backoff).min(max.as_secs());
    record.marker = Some(FailedMarker {
        request_digest: digest.into(),
        failed_at: now(),
        attempts,
        next_attempt_at: now().saturating_add(wait),
        generation: random_id(),
    });
}

/// The owned state a detached registration needs to commit its outcome.
struct Registrar {
    flow: OAuthFlow,
    body: Value,
    digest: String,
    method: &'static str,
    storage: Option<Arc<dyn ClientSecretStorage>>,
    backoff: (Duration, Duration),
    margin: Duration,
}
impl Registrar {
    async fn exchange(
        self,
        guard: &mut dyn CredentialGuard,
        record: &mut SessionRecord,
        mut request: oauth2::HttpRequest,
        http: &super::TokenHttp,
    ) -> Result<ClientChoice, HookError> {
        let budget = http.budget;
        let storage = self.storage.as_deref();
        request.extensions_mut().insert(http.written.clone());
        let outcome = match budget
            .run(
                http.network
                    .send(request, EndpointUse::Registration, budget),
            )
            .await
        {
            Err(_) => Err((AuthErrorCode::ProviderFailed, None)),
            Ok(response) if response.body().len() > 1024 * 1024 => {
                Err((AuthErrorCode::ProviderFailed, retry_after(&response)))
            }
            Ok(response) => accept_registration(
                self.flow,
                &self.body,
                response.status().as_u16(),
                response.body(),
                now(),
            )
            .map_err(|code| (code, retry_after(&response))),
        };
        let issued = match outcome {
            Ok(issued) => issued,
            Err((code, retry_after)) => {
                mark(record, &self.digest, retry_after, self.backoff);
                cas(guard, record, budget).await?;
                return Err(fail(code));
            }
        };
        // Store the secret under a fresh reference before the record's CAS.
        let secret = issued.secret.map(ClientSecret::new);
        let secret_ref = match (&secret, storage) {
            (Some(secret), Some(storage)) => {
                let reference = format!("ahp.oauth.client-secret:{}", random_id());
                budget
                    .run(storage.store(reference.clone(), secret.clone(), budget))
                    .await?;
                Some(reference)
            }
            (Some(_), None) => return Err(fail(AuthErrorCode::CredentialUnavailable)),
            (None, _) => None,
        };
        let generation = random_id();
        let replaced = record.registration.take().and_then(|r| r.secret_ref);
        record.marker = None;
        record.registration = Some(SavedRegistration {
            client_id: issued.client_id.clone(),
            client_secret_expires_at: issued.expires_at,
            registered_at: now(),
            issued: issued.metadata,
            request_digest: self.digest.clone(),
            method: self.method.into(),
            generation: generation.clone(),
            secret_ref: secret_ref.clone(),
        });
        if !cas(guard, record, budget).await? {
            // A concurrent writer won: discard ours and use the winner's record.
            delete_secret(storage, secret_ref, budget).await;
            let current = budget.run(guard.load()).await?;
            if let Some(current) = current {
                *record = current;
            }
            return usable(storage, self.margin, record, &self.digest, budget)
                .await?
                .ok_or_else(|| fail(AuthErrorCode::ProviderFailed));
        }
        delete_secret(storage, replaced, budget).await;
        Ok(ClientChoice {
            id: issued.client_id,
            source: ClientSource::Dcr,
            method: method_of(self.method),
            secret,
            generation: Some(generation),
            renew: false,
        })
    }
}
