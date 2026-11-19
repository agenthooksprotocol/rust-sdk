//! Client selection: a pre-registered client, then a Client ID Metadata
//! Document, then RFC 7591 Dynamic Client Registration when host policy permits.
//!
//! As in MCP clients, a PKCE client is registered inside each login with that
//! login's redirect and stored with the tokens. Only client credentials keep a
//! persisted registration record.
use super::{
    ClientSecret, CredentialGuard, EndpointUse, ManagedOAuth, Mode, OperationBudget, SessionKey,
    SessionRecord, TokenAuthMethod, TrustedMetadata, cas, fail, frame, now, random_id, valid_https,
    valid_redirect,
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
    /// and never persisted.
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
    /// Digest of the settings a client-credentials record was registered with,
    /// so a host `prepare` replaces a record made under other settings.
    fn digest(&self) -> String {
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

/// A client-credentials DCR registration. The client secret is only a host reference.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct SavedRegistration {
    pub(super) client_id: String,
    pub(super) method: String,
    pub(super) client_secret_expires_at: Option<u64>,
    pub(super) generation: String,
    pub(super) secret_ref: Option<String>,
    /// The registration settings' digest; only a host `prepare` acts on a change.
    pub(super) digest: String,
}
/// Shared backoff after a failed client-credentials registration.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Backoff {
    pub(super) attempts: u32,
    pub(super) next_attempt_at: u64,
    /// The last failure's code, returned while the backoff lasts.
    pub(super) code: String,
}
impl SavedRegistration {
    fn expired(&self) -> bool {
        self.client_secret_expires_at
            .is_some_and(|at| at != 0 && at <= now())
    }
}

/// The client for one operation. No Debug: it may carry a secret.
pub(super) struct ClientChoice {
    pub(super) id: String,
    pub(super) source: ClientSource,
    pub(super) method: TokenAuthMethod,
    pub(super) secret: Option<ClientSecret>,
    /// The client-credentials registration generation.
    pub(super) generation: Option<String>,
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

/// A literal loopback IP `http` redirect without userinfo (RFC 8252 section 7.3).
pub(super) fn loopback(uri: &Url) -> bool {
    uri.scheme() == "http"
        && uri.username().is_empty()
        && uri.password().is_none()
        && uri
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback())
}

/// A redirect equals a declared CIMD redirect; a loopback redirect is compared
/// without its port, as authorization servers do (RFC 8252 section 7.3).
pub(super) fn cimd_redirect_matches(declared: &[String], redirect: &str) -> bool {
    let portless = |uri: &str| {
        let mut url = Url::parse(uri).ok().filter(loopback)?;
        url.set_port(None).ok()?;
        Some(url)
    };
    let wanted = portless(redirect);
    declared.iter().any(|entry| {
        entry == redirect || wanted.is_some() && portless(entry).as_ref() == wanted.as_ref()
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

fn code_of(name: &str) -> AuthErrorCode {
    use AuthErrorCode::*;
    [
        UntrustedDestination,
        InvalidConfiguration,
        CredentialUnavailable,
    ]
    .into_iter()
    .find(|code| code.as_str() == name)
    .unwrap_or(ProviderFailed)
}

/// An accepted registration response, before persistence.
pub(super) struct Issued {
    pub(super) client_id: String,
    pub(super) secret: Option<String>,
    pub(super) expires_at: Option<u64>,
}

/// Validate a registration response, mapping outcomes in the contract's table order.
/// For PKCE (method `none`) any `client_secret` and its expiry are ignored.
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
    let body = object.unwrap();
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
    let requested = request["redirect_uris"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if present("redirect_uris").is_some_and(|v| {
        !v.as_array()
            .is_some_and(|echoed| requested.iter().all(|r| echoed.contains(r)))
    }) || present("grant_types").is_some_and(|v| {
        !v.as_array()
            .is_some_and(|grants| grants.iter().any(|g| g == grant))
    }) || present("token_endpoint_auth_method")
        .is_some_and(|v| Some(v) != request.get("token_endpoint_auth_method"))
    {
        return Err(InvalidConfiguration);
    }
    if pkce {
        return Ok(Issued {
            client_id,
            secret: None,
            expires_at: None,
        });
    }
    let secret = present("client_secret")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(InvalidConfiguration)?;
    let expires_at = match present("client_secret_expires_at") {
        None => None,
        Some(value) => Some(
            value
                .as_u64()
                .filter(|at| *at == 0 || *at > now)
                .ok_or(InvalidConfiguration)?,
        ),
    };
    Ok(Issued {
        client_id,
        secret: Some(secret.into()),
        expires_at,
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

/// An outcome from the registration endpoint, or a send failure (`None`).
fn registration_outcome(
    flow: OAuthFlow,
    body: &Value,
    response: Result<oauth2::HttpResponse, HookError>,
) -> Result<Issued, (AuthErrorCode, Option<u64>)> {
    match response {
        Err(_) => Err((AuthErrorCode::ProviderFailed, None)),
        Ok(response) if response.body().len() > 1024 * 1024 => {
            Err((AuthErrorCode::ProviderFailed, retry_after(&response)))
        }
        Ok(response) => accept_registration(
            flow,
            body,
            response.status().as_u16(),
            response.body(),
            now(),
        )
        .map_err(|code| (code, retry_after(&response))),
    }
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
    /// Client-credentials registrations only; PKCE registers per login.
    pub(super) fn registration_key(&self, issuer: &str) -> SessionKey {
        SessionKey {
            storage_key: frame("ahp.oauth.registration:", &[&self.config.namespace, issuer]),
            namespace: self.config.namespace.clone(),
            backend_id: String::new(),
            destination: String::new(),
            purpose: String::new(),
        }
    }
    fn cimd_redirect_ok(&self, redirect: &str) -> bool {
        self.config
            .cimd
            .as_ref()
            .is_some_and(|cimd| cimd_redirect_matches(&cimd.redirect_uris, redirect))
    }
    /// Before a PKCE login: the redirect is valid (never `localhost`) and, for a
    /// CIMD client, declared by its document.
    pub(super) fn check_login_redirect(
        &self,
        source: ClientSource,
        redirect: &str,
    ) -> Result<(), HookError> {
        if !Url::parse(redirect).is_ok_and(|uri| valid_redirect(&uri))
            || source == ClientSource::Cimd && !self.cimd_redirect_ok(redirect)
        {
            return Err(fail(AuthErrorCode::InvalidConfiguration));
        }
        Ok(())
    }
    /// Select a client source for new binding metadata, without network access.
    /// A login's redirect is checked when a host `prepare` creates the login.
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
            if !valid_cimd_url(&cimd.url) {
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
    /// The grant key's client identity: the configured source, never an issued id.
    pub(super) fn client_identity(record: &SessionRecord) -> String {
        match record.client_source {
            ClientSource::Preregistered => format!("preregistered:{}", record.client_id),
            ClientSource::Cimd => format!("cimd:{}", record.client_id),
            ClientSource::Dcr => "dcr".into(),
        }
    }
    /// A recorded selection is obsolete only when current host policy changes it.
    pub(super) fn selection_current(&self, target: &AuthTarget, record: &SessionRecord) -> bool {
        let preregistered = self.preregistered(target);
        match record.client_source {
            ClientSource::Preregistered => preregistered == Some(record.client_id.as_str()),
            ClientSource::Cimd => {
                preregistered.is_none()
                    && self.config.flow == OAuthFlow::AuthorizationCodePkce
                    && self
                        .config
                        .cimd
                        .as_ref()
                        .is_some_and(|cimd| cimd.url == record.client_id)
            }
            ClientSource::Dcr => {
                preregistered.is_none()
                    && self.registration_policy(&record.metadata.issuer).is_some()
            }
        }
    }
    /// The configured client of a binding. A PKCE DCR client lives in the grant
    /// record (or the pending login), so its id is empty here.
    pub(super) fn configured_choice(
        &self,
        target: &AuthTarget,
        binding: &SessionRecord,
    ) -> ClientChoice {
        let (id, method, secret) = match binding.client_source {
            ClientSource::Preregistered => (
                self.preregistered(target).unwrap_or(&binding.client_id),
                self.config.method,
                self.config.secret.as_ref().map(|(_, s)| s.clone()),
            ),
            ClientSource::Cimd => (binding.client_id.as_str(), TokenAuthMethod::None, None),
            ClientSource::Dcr => ("", TokenAuthMethod::None, None),
        };
        ClientChoice {
            id: id.into(),
            source: binding.client_source,
            method,
            secret,
            generation: None,
        }
    }
    fn secret_store(&self) -> Result<&dyn ClientSecretStorage, HookError> {
        self.config
            .secret_storage
            .as_deref()
            .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))
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
    /// The registration request for a login's redirect (PKCE) or for client
    /// credentials. Eligibility is re-checked here, for a recorded selection too.
    async fn registration_request(
        &self,
        metadata: &TrustedMetadata,
        policy: &RegistrationPolicy,
        redirect: Option<&str>,
        budget: OperationBudget,
    ) -> Result<(Value, oauth2::HttpRequest, &'static str), HookError> {
        let unavailable = || fail(AuthErrorCode::CredentialUnavailable);
        let untrusted = || fail(AuthErrorCode::UntrustedDestination);
        let endpoint = metadata
            .registration_endpoint
            .as_deref()
            .ok_or_else(unavailable)?;
        let method = match redirect {
            Some(_) => "none",
            None => {
                self.secret_store()?;
                secret_method(metadata).ok_or_else(unavailable)?.0
            }
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
        let mut body = match redirect {
            Some(redirect) => {
                let mut body = json!({
                    "redirect_uris": [redirect],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                });
                if Url::parse(redirect).is_ok_and(|uri| loopback(&uri)) {
                    body["application_type"] = "native".into();
                }
                body
            }
            None => json!({"grant_types": ["client_credentials"]}),
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
        Ok((body, request, method))
    }
    /// Register a public client for one PKCE login with its exact redirect, as MCP
    /// clients do. Nothing is persisted: the pending login holds the client.
    pub(super) async fn register_login(
        &self,
        metadata: &TrustedMetadata,
        redirect: &str,
        budget: OperationBudget,
    ) -> Result<ClientChoice, HookError> {
        let policy = self
            .registration_policy(&metadata.issuer)
            .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))?;
        let (body, mut request, _) = self
            .registration_request(metadata, policy, Some(redirect), budget)
            .await?;
        request
            .extensions_mut()
            .insert(super::RequestWritten::default());
        let response = budget
            .run(
                self.network
                    .send(request, EndpointUse::Registration, budget),
            )
            .await;
        let issued = registration_outcome(self.config.flow, &body, response)
            .map_err(|(code, _)| fail(code))?;
        Ok(ClientChoice {
            id: issued.client_id,
            source: ClientSource::Dcr,
            method: TokenAuthMethod::None,
            secret: None,
            generation: None,
        })
    }
    /// The client-credentials registration, under its key's lock: reuse a usable
    /// record (for a host `prepare`, one made with the current settings), else
    /// register unless a backoff from a failed registration still applies.
    pub(super) async fn registered(
        &self,
        metadata: &TrustedMetadata,
        mode: Mode,
        budget: OperationBudget,
    ) -> Result<ClientChoice, HookError> {
        let policy = self
            .registration_policy(&metadata.issuer)
            .ok_or_else(|| fail(AuthErrorCode::CredentialUnavailable))?;
        let digest = policy.digest();
        let current = (mode == Mode::Prepare).then_some(digest.as_str());
        let (mut guard, mut record) = self.locked(&metadata.issuer, budget).await?;
        let storage = self.config.secret_storage.as_deref();
        if let Some(choice) = usable(storage, &record, current, budget).await? {
            return Ok(choice);
        }
        if mode != Mode::Prepare
            && let Some(backoff) = record
                .backoff
                .as_ref()
                .filter(|b| b.next_attempt_at > now())
        {
            return Err(fail(code_of(&backoff.code)));
        }
        let (body, request, method) = self
            .registration_request(metadata, policy, None, budget)
            .await?;
        let registrar = Registrar {
            body,
            digest,
            method,
            storage: self.config.secret_storage.clone(),
            backoff: self.config.registration_backoff,
        };
        // Like a token exchange: once the request is written its outcome is
        // committed under the held lock even if the caller is dropped.
        self.detached(
            &mut guard,
            &mut record,
            move |mut guard, mut record, http, _| {
                Box::pin(async move {
                    let outcome = registrar
                        .exchange(&mut *guard, &mut record, request, &http)
                        .await;
                    (outcome, guard, record)
                })
            },
        )
        .await?
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
            delete_secret(self.config.secret_storage.as_deref(), secret, budget).await;
        }
        Ok(())
    }
    /// A token request with this registration succeeded: reset the failure count.
    pub(super) async fn registration_worked(
        &self,
        issuer: &str,
        generation: &str,
        budget: OperationBudget,
    ) -> Result<(), HookError> {
        let (mut guard, mut record) = self.locked(issuer, budget).await?;
        if record.backoff.is_some()
            && record
                .registration
                .as_ref()
                .is_some_and(|r| r.generation == generation)
        {
            record.backoff = None;
            cas(&mut *guard, &mut record, budget).await?;
        }
        Ok(())
    }
    /// A repeated `invalid_client` for a fresh registration counts as a failed
    /// registration, so it is not re-registered on every operation.
    pub(super) async fn mark_failed(&self, issuer: &str, budget: OperationBudget) {
        let mark = async {
            let (mut guard, mut record) = self.locked(issuer, budget).await?;
            back_off(
                &mut record,
                AuthErrorCode::CredentialUnavailable,
                None,
                self.config.registration_backoff,
            );
            cas(&mut *guard, &mut record, budget).await
        };
        let _ = mark.await;
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
/// A record is usable while its secret is unexpired and resolvable; `digest`,
/// when given, must also match the current settings.
async fn usable(
    storage: Option<&dyn ClientSecretStorage>,
    record: &SessionRecord,
    digest: Option<&str>,
    budget: OperationBudget,
) -> Result<Option<ClientChoice>, HookError> {
    let Some(saved) = record
        .registration
        .as_ref()
        .filter(|r| !r.expired() && digest.is_none_or(|d| r.digest == d))
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
    }))
}
/// Exponential backoff (or a later Retry-After), capped at the host maximum.
fn back_off(
    record: &mut SessionRecord,
    code: AuthErrorCode,
    retry_after: Option<u64>,
    (base, max): (Duration, Duration),
) {
    let attempts = record
        .backoff
        .as_ref()
        .map_or(0, |b| b.attempts)
        .saturating_add(1);
    let backoff = base
        .as_secs()
        .saturating_mul(1u64 << (attempts - 1).min(32))
        .min(max.as_secs());
    let wait = retry_after.unwrap_or(0).max(backoff).min(max.as_secs());
    record.backoff = Some(Backoff {
        attempts,
        next_attempt_at: now().saturating_add(wait),
        code: code.as_str().into(),
    });
}

/// The owned state a detached registration needs to commit its outcome.
struct Registrar {
    body: Value,
    digest: String,
    method: &'static str,
    storage: Option<Arc<dyn ClientSecretStorage>>,
    backoff: (Duration, Duration),
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
        let response = budget
            .run(
                http.network
                    .send(request, EndpointUse::Registration, budget),
            )
            .await;
        let issued = match registration_outcome(OAuthFlow::ClientCredentials, &self.body, response)
        {
            Ok(issued) => issued,
            Err((code, retry_after)) => {
                back_off(record, code, retry_after, self.backoff);
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
        // Registering lifts the block but keeps the failure count, so a server
        // that registers clients and then rejects them still backs off longer;
        // only a successful token request with the client resets it.
        if let Some(backoff) = record.backoff.as_mut() {
            backoff.next_attempt_at = 0;
        }
        record.registration = Some(SavedRegistration {
            client_id: issued.client_id.clone(),
            method: self.method.into(),
            client_secret_expires_at: issued.expires_at,
            generation: generation.clone(),
            secret_ref: secret_ref.clone(),
            digest: self.digest.clone(),
        });
        if !cas(guard, record, budget).await? {
            // A concurrent writer won: discard ours and use the winner's record.
            delete_secret(storage, secret_ref, budget).await;
            if let Some(current) = budget.run(guard.load()).await? {
                *record = current;
            }
            return usable(storage, record, None, budget)
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
        })
    }
}
