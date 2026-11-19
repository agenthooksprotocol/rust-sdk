//! Managed OAuth lifecycle tests at host store, network and transport boundaries.
//! The store, network and policy are in-memory host fakes; the transport tests
//! run the real HTTP backend against a loopback listener.
use super::*;
use crate::auth::AuthRecovery;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize},
    },
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

mod client_registration;
#[cfg(feature = "reqwest")]
mod transport;

const FIXTURE: &str = include_str!("sdk-auth-lifecycle.json");

fn budget() -> OperationBudget {
    OperationBudget::until(Instant::now() + Duration::from_secs(10))
}
fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect()
}
fn scopes(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// Exclusive per key (like a cross-process lock) with CAS writes; another
/// "process" may still write through `records` directly.
#[derive(Default)]
struct Store {
    records: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
    locks: Mutex<BTreeMap<String, Arc<AsyncMutex<()>>>>,
    held: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
    /// Milliseconds each write takes, simulating a slow host store.
    write_delay: Arc<AtomicUsize>,
}
struct Guard {
    records: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
    key: String,
    held: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
    write_delay: Arc<AtomicUsize>,
    _lock: OwnedMutexGuard<()>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.held.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Store {
    fn grant(&self) -> Option<SessionRecord> {
        self.find("ahp.oauth.grant:")
    }
    fn binding(&self) -> Option<SessionRecord> {
        self.find("ahp.oauth.binding:")
    }
    fn find(&self, prefix: &str) -> Option<SessionRecord> {
        let records = self.records.lock().unwrap();
        let mut found = records.iter().filter(|(k, _)| k.starts_with(prefix));
        let record = found.next().map(|(_, r)| r.clone());
        assert!(found.next().is_none(), "one {prefix} record expected");
        record
    }
    fn token(&self) -> SavedToken {
        self.grant().unwrap().token.unwrap()
    }
    fn expire(&self) {
        for record in self.records.lock().unwrap().values_mut() {
            if let Some(token) = record.token.as_mut() {
                token.expires_at = Some(0);
            }
        }
    }
    fn registration_record(&self) -> Option<SessionRecord> {
        self.find("ahp.oauth.registration:")
    }
    fn registration(&self) -> Option<registration::SavedRegistration> {
        self.registration_record().and_then(|r| r.registration)
    }
    fn backoff(&self) -> Option<registration::Backoff> {
        self.registration_record().and_then(|r| r.backoff)
    }
    /// Another process's write, bypassing the lock (and CAS) of this one.
    fn edit_registration(&self, edit: impl FnOnce(&mut SessionRecord)) {
        let mut records = self.records.lock().unwrap();
        let record = records
            .iter_mut()
            .find(|(k, _)| k.starts_with("ahp.oauth.registration:"))
            .unwrap()
            .1;
        edit(record);
        record.version = random_id();
    }
    /// Every persisted record, serialized as the host would store it.
    fn dump(&self) -> String {
        serde_json::to_string(&*self.records.lock().unwrap()).unwrap()
    }
}
impl CredentialStore for Store {
    fn acquire(
        &self,
        key: SessionKey,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<Box<dyn CredentialGuard>, HookError>> {
        Box::pin(async move {
            let lock = self
                .locks
                .lock()
                .unwrap()
                .entry(key.as_str().into())
                .or_default()
                .clone();
            let lock = lock.lock_owned().await;
            self.held.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Guard {
                records: self.records.clone(),
                key: key.as_str().into(),
                held: self.held.clone(),
                rejected: self.rejected.clone(),
                writes: self.writes.clone(),
                write_delay: self.write_delay.clone(),
                _lock: lock,
            }) as Box<dyn CredentialGuard>)
        })
    }
}
impl CredentialGuard for Guard {
    fn load(&mut self) -> LocalFuture<'_, Result<Option<SessionRecord>, HookError>> {
        Box::pin(async { Ok(self.records.lock().unwrap().get(&self.key).cloned()) })
    }
    fn compare_and_swap(
        &mut self,
        expected: Option<String>,
        replacement: SessionRecord,
    ) -> LocalFuture<'_, Result<bool, HookError>> {
        Box::pin(async move {
            let delay = self.write_delay.load(Ordering::SeqCst) as u64;
            tokio::time::sleep(Duration::from_millis(delay)).await;
            let mut records = self.records.lock().unwrap();
            if records.get(&self.key).map(|r| r.version.clone()) != expected {
                return Ok(false);
            }
            self.writes.fetch_add(1, Ordering::SeqCst);
            records.insert(self.key.clone(), replacement);
            Ok(true)
        })
    }
    fn on_refresh_rejected(&mut self, _: String) -> LocalFuture<'_, Result<(), HookError>> {
        self.rejected.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

/// Selects `read` (configurable) plus requirements. Asserts it is never called under a store guard.
struct Policy {
    held: Arc<AtomicUsize>,
    deny: AtomicBool,
    select: Mutex<Vec<String>>,
    /// When set, only this issuer is approved.
    only: Mutex<Option<String>>,
    /// Another holder (a detached exchange) may legitimately own a guard.
    shared_lock: AtomicBool,
}
impl Policy {
    fn off_lock(&self) {
        if !self.shared_lock.load(Ordering::SeqCst) {
            assert_eq!(self.held.load(Ordering::SeqCst), 0, "policy under lock");
        }
    }
}
impl Policy {
    fn new(store: &Store) -> Arc<Self> {
        Arc::new(Self {
            held: store.held.clone(),
            deny: AtomicBool::new(false),
            select: Mutex::new(scopes(&["read"])),
            only: Mutex::new(None),
            shared_lock: AtomicBool::new(false),
        })
    }
}
impl OAuthPolicy for Policy {
    fn approve_endpoints(&self, _: EndpointTrust<'_>) -> Result<(), HookError> {
        self.off_lock();
        Ok(())
    }
    fn select(
        &self,
        _: &AuthTarget,
        resource: &ResourceMetadata,
        required: &[String],
    ) -> Result<TrustDecision, HookError> {
        self.off_lock();
        if self.deny.load(Ordering::SeqCst) {
            return Err(fail(AuthErrorCode::UntrustedDestination));
        }
        let issuer = match self.only.lock().unwrap().clone() {
            Some(only) if !resource.authorization_servers.contains(&only) => {
                return Err(fail(AuthErrorCode::UntrustedDestination));
            }
            Some(only) => only,
            None => resource.authorization_servers[0].clone(),
        };
        Ok(TrustDecision::new(
            issuer,
            union(&self.select.lock().unwrap(), required),
        ))
    }
}

#[derive(Clone)]
struct Seen {
    usage: EndpointUse,
    uri: String,
    body: String,
    authorization: String,
}
type Hook = Box<dyn FnOnce() + Send>;
#[derive(Default)]
struct Network {
    seen: Mutex<Vec<Seen>>,
    replies: Mutex<VecDeque<(u16, Value)>>,
    issuer_patch: Mutex<Value>,
    /// Authorization server advertised by protected-resource metadata.
    prm_issuer: Mutex<Option<String>>,
    prm_outage: AtomicBool,
    /// Issuer host whose authorization-server metadata answers 503.
    issuer_outage: Mutex<Option<String>>,
    /// One-shot delay (ms) between writing a token request and its response.
    token_delay: AtomicUsize,
    offline: AtomicBool,
    transport_failures: AtomicUsize,
    unsent_failures: AtomicUsize,
    on_token: Mutex<Option<Hook>>,
    /// Issuer metadata advertises `{issuer}/register`.
    dcr: AtomicBool,
    /// Queued registration replies `(status, body, Retry-After)`; status 0 is a
    /// network failure. When empty, registration succeeds with a fresh client.
    registration_replies: Mutex<VecDeque<(u16, Value, Option<&'static str>)>>,
    registered: AtomicUsize,
    registration_delay: AtomicUsize,
    refuse_registration: AtomicBool,
    /// Mark the registration request written only after the delay.
    registration_written_late: AtomicBool,
    on_registration: Mutex<Option<Hook>>,
}
impl Network {
    fn reply(&self, status: u16, body: Value) {
        self.replies.lock().unwrap().push_back((status, body));
    }
    fn tokens(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.usage == EndpointUse::Token)
            .cloned()
            .collect()
    }
    fn registrations(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.usage == EndpointUse::Registration)
            .cloned()
            .collect()
    }
    fn register_reply(&self, status: u16, body: Value, retry_after: Option<&'static str>) {
        self.registration_replies
            .lock()
            .unwrap()
            .push_back((status, body, retry_after));
    }
    fn metadata_requests(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| !matches!(s.usage, EndpointUse::Token | EndpointUse::Registration))
            .map(|s| s.uri.clone())
            .collect()
    }
    fn last_form(&self) -> BTreeMap<String, String> {
        url::form_urlencoded::parse(self.tokens().last().unwrap().body.as_bytes())
            .into_owned()
            .collect()
    }
}
impl OAuthNetwork for Network {
    fn check(
        &self,
        _: Url,
        usage: EndpointUse,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        let refused =
            usage == EndpointUse::Registration && self.refuse_registration.load(Ordering::SeqCst);
        Box::pin(async move {
            if refused {
                return Err(fail(AuthErrorCode::UntrustedDestination));
            }
            Ok(())
        })
    }
    fn send(
        &self,
        request: OAuthRequest,
        usage: EndpointUse,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<OAuthResponse, HookError>> {
        Box::pin(async move {
            self.seen.lock().unwrap().push(Seen {
                usage,
                uri: request.uri().to_string(),
                body: String::from_utf8_lossy(request.body()).into_owned(),
                authorization: request
                    .headers()
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_owned())
                    .unwrap_or_default(),
            });
            let (status, body) = match usage {
                EndpointUse::Registration => return self.registration(&request).await,
                EndpointUse::Token => {
                    if let Some(written) = request.extensions().get::<RequestWritten>() {
                        written.mark();
                    }
                    let delay = self.token_delay.swap(0, Ordering::SeqCst) as u64;
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    if let Some(hook) = self.on_token.lock().unwrap().take() {
                        hook();
                    }
                    for (failures, unsent) in [
                        (&self.transport_failures, false),
                        (&self.unsent_failures, true),
                    ] {
                        if failures.load(Ordering::SeqCst) > 0 {
                            failures.fetch_sub(1, Ordering::SeqCst);
                            let error = fail(AuthErrorCode::ProviderFailed);
                            return Err(if unsent {
                                error.request_not_sent()
                            } else {
                                error
                            });
                        }
                    }
                    // A moved token endpoint answers 404 at its old address.
                    let current = self.issuer_patch.lock().unwrap()["token_endpoint"].clone();
                    if current.as_str().is_some_and(|uri| request.uri() != uri) {
                        return Ok(http::Response::builder()
                            .status(404)
                            .body(b"gone".to_vec())
                            .unwrap());
                    }
                    self.replies
                        .lock()
                        .unwrap()
                        .pop_front()
                        .expect("queued token response")
                }
                _ if self.offline.load(Ordering::SeqCst) => {
                    panic!("metadata HTTP while offline: {}", request.uri())
                }
                EndpointUse::ResourceMetadata if self.prm_outage.load(Ordering::SeqCst) => {
                    (503, json!({}))
                }
                EndpointUse::ResourceMetadata if request.uri().path().contains("missing") => {
                    (404, json!({}))
                }
                EndpointUse::IssuerMetadata
                    if self.issuer_outage.lock().unwrap().as_deref() == request.uri().host() =>
                {
                    (503, json!({}))
                }
                EndpointUse::ResourceMetadata => {
                    let issuer = self.prm_issuer.lock().unwrap().clone();
                    let issuer = issuer.unwrap_or_else(|| "https://issuer.example".into());
                    (
                        200,
                        json!({"resource":"https://api.example/hooks","authorization_servers":[issuer]}),
                    )
                }
                _ => {
                    let origin = format!("https://{}", request.uri().host().unwrap());
                    let mut body = json!({"issuer":origin,"authorization_endpoint":format!("{origin}/authorize"),"token_endpoint":format!("{origin}/token"),"grant_types_supported":["authorization_code","refresh_token","client_credentials"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],"code_challenge_methods_supported":["S256"]});
                    if self.dcr.load(Ordering::SeqCst) {
                        body["registration_endpoint"] = format!("{origin}/register").into();
                    }
                    if let Value::Object(patch) = &*self.issuer_patch.lock().unwrap() {
                        for (k, v) in patch {
                            body[k] = v.clone();
                        }
                    }
                    (200, body)
                }
            };
            // Raw string replies are served as text/plain.
            let (media, body) = match body {
                Value::String(raw) => ("text/plain", raw.into_bytes()),
                body => ("application/json", serde_json::to_vec(&body).unwrap()),
            };
            Ok(http::Response::builder()
                .status(status)
                .header("content-type", media)
                .body(body)
                .unwrap())
        })
    }
}

impl Network {
    async fn registration(&self, request: &OAuthRequest) -> Result<OAuthResponse, HookError> {
        let written = request.extensions().get::<RequestWritten>().unwrap();
        let late = self.registration_written_late.load(Ordering::SeqCst);
        if !late {
            written.mark();
        }
        let delay = self.registration_delay.load(Ordering::SeqCst) as u64;
        tokio::time::sleep(Duration::from_millis(delay)).await;
        if late {
            written.mark();
        }
        if let Some(hook) = self.on_registration.lock().unwrap().take() {
            hook();
        }
        let queued = self.registration_replies.lock().unwrap().pop_front();
        let (status, body, retry_after) = queued.unwrap_or_else(|| {
            let n = self.registered.fetch_add(1, Ordering::SeqCst) + 1;
            let sent: Value = serde_json::from_slice(request.body()).unwrap();
            let mut body = json!({"client_id": format!("dcr-client-{n}")});
            if sent["token_endpoint_auth_method"] != "none" {
                body["client_secret"] = format!("issued-secret-{n}").into();
            }
            (201, body, None)
        });
        if status == 0 {
            return Err(fail(AuthErrorCode::ProviderFailed));
        }
        let mut response = http::Response::builder()
            .status(status)
            .header("content-type", "application/json");
        if let Some(retry_after) = retry_after {
            response = response.header("retry-after", retry_after);
        }
        Ok(response.body(serde_json::to_vec(&body).unwrap()).unwrap())
    }
}

/// Host secret storage; records deletions.
#[derive(Default)]
struct Secrets {
    values: Mutex<BTreeMap<String, String>>,
    deleted: Mutex<Vec<String>>,
}
impl ClientSecretStorage for Secrets {
    fn store(
        &self,
        reference: String,
        secret: ClientSecret,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        self.values
            .lock()
            .unwrap()
            .insert(reference, secret.secret().clone());
        Box::pin(async { Ok(()) })
    }
    fn resolve(
        &self,
        reference: String,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<Option<ClientSecret>, HookError>> {
        let value = self.values.lock().unwrap().get(&reference).cloned();
        Box::pin(async { Ok(value.map(ClientSecret::new)) })
    }
    fn delete(
        &self,
        reference: String,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        self.values.lock().unwrap().remove(&reference);
        self.deleted.lock().unwrap().push(reference);
        Box::pin(async { Ok(()) })
    }
}

type Logins = Arc<Mutex<BTreeMap<String, Vec<SavedLogin>>>>;
/// One host process: its providers share process-owned pending logins.
struct Host {
    store: Arc<Store>,
    network: Arc<Network>,
    policy: Arc<Policy>,
    secrets: Arc<Secrets>,
    logins: Logins,
}
impl Host {
    fn new() -> Self {
        let store = Arc::new(Store::default());
        Self {
            policy: Policy::new(&store),
            store,
            network: Arc::new(Network::default()),
            secrets: Arc::new(Secrets::default()),
            logins: Logins::default(),
        }
    }
    /// Another process sharing this one's store, with its own network client.
    fn other_process(&self) -> Self {
        Self {
            store: self.store.clone(),
            network: Arc::new(Network::default()),
            policy: self.policy.clone(),
            secrets: self.secrets.clone(),
            logins: Logins::default(),
        }
    }
    /// Pending logins of this process and of the store.
    fn pending(&self) -> Vec<SavedLogin> {
        let mut all: Vec<SavedLogin> = self
            .logins
            .lock()
            .unwrap()
            .values()
            .flatten()
            .cloned()
            .collect();
        all.extend(
            self.store
                .records
                .lock()
                .unwrap()
                .values()
                .flat_map(|r| r.pending_logins.clone()),
        );
        all
    }
    fn pkce(&self, config: impl FnOnce(OAuthClientConfig) -> OAuthClientConfig) -> ManagedOAuth {
        let base = OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .redirect_uri("http://127.0.0.1/callback");
        self.owner(config(base))
    }
    fn cc(&self, method: TokenAuthMethod, secret: &str) -> ManagedOAuth {
        self.owner(
            OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
                .scopes(scopes(&["read"]), scopes(&["read", "write"]))
                .client_secret("secret-ref", ClientSecret::new(secret.into()), method),
        )
    }
    fn owner(&self, config: OAuthClientConfig) -> ManagedOAuth {
        let mut oauth = ManagedOAuth::new(
            config,
            self.network.clone(),
            self.policy.clone(),
            self.store.clone(),
        )
        .unwrap();
        oauth.pending = self.logins.clone();
        oauth
    }
    /// PKCE login completed with a known-expiry token, then expired.
    async fn seed(&self, oauth: &ManagedOAuth, ctx: AuthContext) -> BearerCredential {
        let pending = login(oauth.prepare(ctx.clone(), budget()).await.unwrap());
        self.network.reply(
            200,
            json!({"access_token":"seed","refresh_token":"seed-refresh","token_type":"Bearer","expires_in":3600}),
        );
        oauth
            .complete(ctx, callback(&pending), budget())
            .await
            .unwrap()
    }
}
fn context() -> AuthContext {
    AuthContext {
        backend_id: "backend".into(),
        authentication: Some(
            json!({"type":"oauth","flow":"authorization_code_pkce","issuer":"https://issuer.example","resource":"https://api.example/hooks","clientId":"client"}),
        ),
        destination: "https://api.example/hooks".into(),
        purpose: AuthPurpose::Event,
        deadline: budget().deadline(),
    }
}
fn unbound() -> AuthContext {
    AuthContext {
        authentication: None,
        ..context()
    }
}
fn cc_context() -> AuthContext {
    let mut ctx = context();
    ctx.authentication.as_mut().unwrap()["flow"] = "client_credentials".into();
    ctx
}
fn login(value: Preparation) -> PendingLogin {
    match value {
        Preparation::InteractionRequired(login) => login,
        _ => panic!("expected login"),
    }
}
fn ready(value: Preparation) -> BearerCredential {
    match value {
        Preparation::Ready(credential) => credential,
        _ => panic!("expected credential"),
    }
}
fn query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}
fn callback(login: &PendingLogin) -> Url {
    let mut url = Url::parse(login.redirect_uri()).unwrap();
    url.set_query(None);
    url.query_pairs_mut()
        .append_pair("state", &query(login.authorization_url(), "state").unwrap())
        .append_pair("code", "fake-code");
    url
}
fn code<T>(result: Result<T, HookError>) -> AuthErrorCode {
    result.err().expect("expected error").auth_code().unwrap()
}
fn challenge(status: u16, header: &str, attempt: Option<&str>) -> AuthChallenge {
    AuthChallenge {
        status,
        headers: BTreeMap::from([("WWW-Authenticate".into(), header.into())]),
        attempt_id: attempt.map(Into::into),
    }
}

// ---- Fixture vectors ----

#[test]
fn canonical_key_vectors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for vector in fixture["keys"].as_array().unwrap() {
        let v = &vector["input"];
        let flow = if v["flow"] == "client_credentials" {
            OAuthFlow::ClientCredentials
        } else {
            OAuthFlow::AuthorizationCodePkce
        };
        let mut config = OAuthClientConfig::new(v["namespace"].as_str().unwrap(), "client", flow)
            .scopes(vec![], strings(&v["allowed_scopes"]))
            .redirect_uri("https://host.example/callback");
        if let Some(secret) = v["client_secret"].as_str() {
            let method = if v["token_endpoint_auth_method"] == "client_secret_post" {
                TokenAuthMethod::ClientSecretPost
            } else {
                TokenAuthMethod::ClientSecretBasic
            };
            config = config.client_secret("reference", ClientSecret::new(secret.into()), method);
        }
        if let Some(partition) = v["grant_partition"].as_str() {
            config = config.grant_partition(partition);
        }
        let oauth = Host::new().owner(config);
        let target = AuthContext {
            backend_id: v["backend_id"].as_str().unwrap().into(),
            destination: v["destination"].as_str().unwrap().into(),
            purpose: if v["purpose"] == "upload" {
                AuthPurpose::Upload
            } else {
                AuthPurpose::Event
            },
            ..unbound()
        }
        .target()
        .unwrap();
        let mut metadata = TrustedMetadata::new(
            v["resource"].as_str().unwrap().into(),
            v["issuer"].as_str().unwrap().into(),
            "https://issuer.example/token".into(),
        );
        if v["metadata"]["grant_types_supported"].is_array() {
            metadata.grant_types_supported = strings(&v["metadata"]["grant_types_supported"]);
        }
        let id = &vector["id"];
        assert_eq!(oauth.key(&target).as_str(), vector["binding_key"], "{id}");
        // The grant key holds the configured client source, never an issued id.
        let identity = v["client_identity"].as_str().unwrap();
        let (client_source, client_id) = match identity.split_once(':') {
            Some(("preregistered", id)) => (ClientSource::Preregistered, id.to_owned()),
            Some(("cimd", url)) => (ClientSource::Cimd, url.to_owned()),
            _ => (
                ClientSource::Dcr,
                v["issued_client_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            ),
        };
        let record = SessionRecord {
            client_source,
            client_id,
            ..SessionRecord::empty(metadata, oauth.flow_id())
        };
        assert_eq!(ManagedOAuth::client_identity(&record), identity, "{id}");
        assert_eq!(
            oauth.binding_grant_key(&target, &record).as_str(),
            vector["grant_key"],
            "{id}"
        );
    }
}

#[tokio::test]
async fn canonical_token_vectors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for vector in fixture["token_responses"].as_array().unwrap() {
        let id = &vector["id"];
        let host = Host::new();
        let mut oauth = host.pkce(|c| c);
        let config = Arc::get_mut(&mut oauth.config).unwrap();
        config.requested_scopes = strings(&vector["requested"]);
        config.allowed_scopes = strings(&vector["allowed"]);
        let required = strings(&vector["required"]);
        let mut record = SessionRecord {
            client_id: "client".into(),
            configured_binding: true,
            ..SessionRecord::empty(
                TrustedMetadata::new(
                    "https://api.example/hooks".into(),
                    "https://issuer.example".into(),
                    "https://issuer.example/token".into(),
                ),
                "authorization_code_pkce",
            )
        };
        let refresh = vector["exchange"] == "refresh";
        let previous = if vector["previous_granted"].is_array() {
            strings(&vector["previous_granted"])
        } else {
            Vec::new()
        };
        // Initial and re-acquisition responses are bounded by previous ∪ ceiling.
        let bound = if refresh {
            previous.clone()
        } else {
            union(&previous, &oauth.config.allowed_scopes)
        };
        if !previous.is_empty() {
            record.token = Some(SavedToken {
                access_token: "old".into(),
                refresh_token: Some("old-refresh".into()),
                expires_at: Some(0),
                scopes: strings(&vector["previous_granted"]),
                generation: "old".into(),
                access_rejected: false,
                refresh_in_flight: refresh,
            });
        }
        let requested = if refresh {
            previous.clone()
        } else if vector["wire_request"].is_array() {
            let wanted = union(&strings(&vector["requested"]), &required);
            let wire = oauth.request_scopes(&previous, &wanted);
            assert_eq!(wire, union(&strings(&vector["wire_request"]), &[]), "{id}");
            wire
        } else {
            strings(&vector["requested"])
        };
        let body = serde_json::to_vec(&vector["response"]).unwrap();
        let body = normalize_token_body(&body).unwrap_or(body);
        let mut guard = host
            .store
            .acquire(oauth.key(&context().target().unwrap()), budget())
            .await
            .unwrap();
        let result = match serde_json::from_slice::<BasicTokenResponse>(&body) {
            Ok(response) => {
                oauth
                    .committer()
                    .save_token(
                        &mut *guard,
                        &mut record,
                        response,
                        &requested,
                        &bound,
                        refresh.then(|| "old-refresh".into()),
                        &required,
                        "client",
                    )
                    .await
            }
            // Unparseable responses are never accepted; as in `refresh`, an
            // observed refresh response keeps a valid rotated refresh token.
            Err(_) => {
                if refresh {
                    super::keep_refresh(&mut record, super::rotated_refresh(&body));
                }
                Err(fail(AuthErrorCode::ProviderFailed))
            }
        };
        assert_eq!(result.is_ok(), vector["usable"] == true, "{id}");
        if let Some(error) = vector["error"].as_str() {
            assert_eq!(
                result.err().unwrap().auth_code().unwrap().as_str(),
                error,
                "{id}"
            );
        }
        let token = record.token.as_ref();
        let accepted = vector["accepted"] == true;
        if accepted {
            let token = token.unwrap();
            assert_eq!(
                token.scopes,
                union(&strings(&vector["granted"]), &[]),
                "{id}"
            );
            assert_eq!(
                token.expires_at.is_none(),
                vector["expiry"] == "unknown",
                "{id}"
            );
            if vector["effective"].is_array() {
                assert_eq!(
                    oauth.effective(&token.scopes),
                    strings(&vector["effective"]),
                    "{id}"
                );
            }
        }
        assert!(token.is_none_or(|t| !t.refresh_in_flight), "{id}");
        assert_eq!(
            token.is_some_and(|t| t.refresh_token.is_some()),
            vector["refresh_preserved"] == true,
            "{id}"
        );
        if refresh && !accepted {
            assert_eq!(
                token.unwrap().refresh_token.as_deref(),
                vector["response"]["refresh_token"].as_str(),
                "{id}: valid rotated refresh token is kept"
            );
        }
        assert_eq!(
            oauth.cached(&record, &required).is_some(),
            vector["usable"] == true,
            "{id}"
        );
    }
}

/// Every lifecycle id maps to a native test; the function pointers must exist.
#[cfg(feature = "reqwest")]
#[test]
fn lifecycle_manifest_maps_to_native_tests() {
    let mapping: &[(&str, fn())] = &[
        ("cached-token-metadata-outage", cached_token_metadata_outage),
        (
            "unbound-preemptive-unsafe-delivery",
            transport::unbound_preemptive_unsafe_delivery,
        ),
        (
            "unreplayed-challenge-prepares-next-attempt",
            transport::unreplayed_challenge_prepares_next_attempt,
        ),
        (
            "unbound-lookup-anonymous-fallback",
            unbound_lookup_anonymous_fallback,
        ),
        (
            "unbound-lookup-refreshes-expired-token",
            unbound_lookup_refreshes_expired_token,
        ),
        (
            "up-front-refresh-failure-no-anonymous-fallback",
            up_front_refresh_failure_no_anonymous_fallback,
        ),
        (
            "refresh-unknown-expiry-rotation",
            refresh_unknown_expiry_rotation,
        ),
        ("transient-refresh-failure", transient_refresh_failure),
        (
            "refresh-invalid-grant-drops-tokens",
            refresh_invalid_grant_drops_tokens,
        ),
        (
            "refresh-invalid-grant-stale-does-not-wipe",
            refresh_invalid_grant_stale_does_not_wipe,
        ),
        (
            "token-validation-failure-clears-in-flight",
            token_validation_failure_clears_in_flight,
        ),
        (
            "client-credentials-transient-reissue",
            client_credentials_transient_reissue,
        ),
        (
            "delivery-never-creates-pending-login",
            delivery_never_creates_pending_login,
        ),
        ("pending-login-fixed-lifetime", pending_login_fixed_lifetime),
        (
            "pending-login-owned-by-creating-process",
            pending_login_owned_by_creating_process,
        ),
        (
            "pending-login-persisted-cross-process-completion",
            pending_login_persisted_cross_process_completion,
        ),
        (
            "pending-logins-concurrent-per-state",
            client_registration::pending_logins_concurrent_per_state,
        ),
        (
            "pending-logins-capped-per-grant-key",
            pending_logins_capped_per_grant_key,
        ),
        (
            "pending-completion-newest-grant-wins",
            client_registration::pending_completion_newest_grant_wins,
        ),
        ("pending-login-end-states", pending_login_end_states),
        ("metadata-and-secret-rotation", metadata_and_secret_rotation),
        (
            "scope-ceiling-widening-keeps-grant",
            scope_ceiling_widening_keeps_grant,
        ),
        (
            "scope-ceiling-narrowing-keeps-grant",
            scope_ceiling_narrowing_keeps_grant,
        ),
        ("insufficient-scope-step-up", insufficient_scope_step_up),
        (
            "step-up-requirement-operation-scoped",
            step_up_requirement_operation_scoped,
        ),
        (
            "step-up-required-scopes-round-trip",
            step_up_required_scopes_round_trip,
        ),
        (
            "prepare-required-outside-ceiling-denied",
            prepare_required_outside_ceiling_denied,
        ),
        ("challenged-replay-once", transport::challenged_replay_once),
        (
            "configured-preset-no-protected-resource-metadata",
            configured_preset_no_protected_resource_metadata,
        ),
        ("explicit-shared-grant", explicit_shared_grant),
        (
            "invalid-callback-does-not-consume",
            invalid_callback_does_not_consume,
        ),
        ("loopback-redirect", loopback_redirect),
        (
            "loopback-redirect-ephemeral-port-per-login",
            loopback_redirect_ephemeral_port_per_login,
        ),
        (
            "cimd-portless-loopback-redirect-matches",
            client_registration::cimd_portless_loopback_redirect_matches,
        ),
        (
            "narrowed-refresh-scope-inheritance",
            narrowed_refresh_scope_inheritance,
        ),
        (
            "scope-challenge-without-required-scope",
            scope_challenge_without_required_scope,
        ),
        (
            "refresh-broadening-scope-ignored",
            refresh_broadening_scope_ignored,
        ),
        ("extra-granted-scope-ignored", extra_granted_scope_ignored),
        (
            "challenge-renews-rejected-unexpired-token",
            challenge_renews_rejected_unexpired_token,
        ),
        (
            "up-front-client-credentials-reacquire",
            up_front_client_credentials_reacquire,
        ),
        (
            "up-front-lookup-issuer-metadata-only",
            up_front_lookup_issuer_metadata_only,
        ),
        (
            "known-binding-without-token-requires-login",
            known_binding_without_token_requires_login,
        ),
        ("step-up-keeps-previous-grant", step_up_keeps_previous_grant),
        ("stale-metadata-refetch-once", stale_metadata_refetch_once),
        (
            "ambiguous-renewal-failure-no-refetch",
            ambiguous_renewal_failure_no_refetch,
        ),
        (
            "registration-order-preregistered-cimd-dcr",
            client_registration::registration_order_preregistered_cimd_dcr,
        ),
        (
            "dcr-preregistered-wins",
            client_registration::dcr_preregistered_wins,
        ),
        (
            "cimd-used-when-supported",
            client_registration::cimd_used_when_supported,
        ),
        (
            "cimd-not-supported-falls-back-to-dcr",
            client_registration::cimd_not_supported_falls_back_to_dcr,
        ),
        (
            "cimd-redirect-mismatch-invalid-configuration",
            client_registration::cimd_redirect_mismatch_invalid_configuration,
        ),
        (
            "cimd-never-fetched-by-sdk",
            client_registration::cimd_never_fetched_by_sdk,
        ),
        (
            "cimd-client-credentials-not-used",
            client_registration::cimd_client_credentials_not_used,
        ),
        (
            "cimd-invalid-client-no-dcr-fallback",
            client_registration::cimd_invalid_client_no_dcr_fallback,
        ),
        (
            "dcr-policy-disallows-registration",
            client_registration::dcr_policy_disallows_registration,
        ),
        (
            "dcr-registration-endpoint-destination-policy",
            client_registration::dcr_registration_endpoint_destination_policy,
        ),
        (
            "dcr-pkce-registers-per-login",
            client_registration::dcr_pkce_registers_per_login,
        ),
        (
            "dcr-issued-client-stored-with-grant",
            client_registration::dcr_issued_client_stored_with_grant,
        ),
        (
            "dcr-pkce-invalid-client-drops-grant",
            client_registration::dcr_pkce_invalid_client_drops_grant,
        ),
        (
            "dcr-registers-once-across-processes",
            client_registration::dcr_registers_once_across_processes,
        ),
        (
            "dcr-registration-reused-across-grants",
            client_registration::dcr_registration_reused_across_grants,
        ),
        (
            "dcr-expired-secret-reregisters",
            client_registration::dcr_expired_secret_reregisters,
        ),
        (
            "dcr-invalid-client-reregisters-once",
            client_registration::dcr_invalid_client_reregisters_once,
        ),
        (
            "dcr-secret-not-in-token-record",
            client_registration::dcr_secret_not_in_token_record,
        ),
        (
            "dcr-no-secret-hook-no-confidential-registration",
            client_registration::dcr_no_secret_hook_no_confidential_registration,
        ),
        (
            "dcr-metadata-change-keeps-selection",
            client_registration::dcr_metadata_change_keeps_selection,
        ),
        (
            "dcr-management-fields-not-persisted",
            client_registration::dcr_management_fields_not_persisted,
        ),
        (
            "dcr-initial-access-token-scoped",
            client_registration::dcr_initial_access_token_scoped,
        ),
        (
            "lookup-never-registers-pkce",
            client_registration::lookup_never_registers_pkce,
        ),
        (
            "dcr-response-validation-invalid-configuration",
            client_registration::dcr_response_validation_invalid_configuration,
        ),
        (
            "dcr-replaced-secret-deleted",
            client_registration::dcr_replaced_secret_deleted,
        ),
        (
            "registration-transient-failure-backs-off",
            client_registration::registration_transient_failure_backs_off,
        ),
        (
            "registration-retry-after-honoured",
            client_registration::registration_retry_after_honoured,
        ),
        (
            "configuration-401-diagnostic-carries-auth-code",
            transport::configuration_401_diagnostic_carries_auth_code,
        ),
        (
            "configuration-unavailable-retried-after-prepare",
            transport::configuration_unavailable_retried_after_prepare,
        ),
        (
            "configuration-unavailable-backoff",
            crate::hooks::configuration_tests::configuration_unavailable_backoff,
        ),
        (
            "configuration-auth-failure-not-retried-on-backoff",
            crate::hooks::configuration_tests::configuration_auth_failure_not_retried_on_backoff,
        ),
        (
            "configuration-invalid-not-retried",
            crate::hooks::configuration_tests::configuration_invalid_not_retried,
        ),
        (
            "configuration-retry-atomic-routes",
            crate::hooks::configuration_tests::configuration_retry_atomic_routes,
        ),
    ];
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let ids: Vec<&str> = fixture["lifecycle"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap())
        .collect();
    let mut ids = ids;
    let mut mapped: Vec<&str> = mapping.iter().map(|(id, _)| *id).collect();
    ids.sort();
    mapped.sort();
    assert_eq!(ids, mapped);
}

// ---- Lifecycle ----

#[tokio::test]
async fn cached_token_metadata_outage() {
    let host = Host::new();
    let credential = host.seed(&host.pkce(|c| c), context()).await;
    host.network.offline.store(true, Ordering::SeqCst);
    let writes = host.store.writes.load(Ordering::SeqCst);
    let recreated = host.pkce(|c| c);
    for ctx in [context(), unbound(), context()] {
        let served = recreated.credential(ctx).await.unwrap().unwrap();
        assert_eq!(served.token, credential.token);
    }
    // A host prepare with a usable cached token makes no metadata calls either.
    let prepared = ready(recreated.prepare(context(), budget()).await.unwrap());
    assert_eq!(prepared.token, credential.token);
    assert_eq!(
        host.store.writes.load(Ordering::SeqCst),
        writes,
        "no per-call writes"
    );
    assert_eq!(host.network.tokens().len(), 1);
}

#[tokio::test]
async fn unbound_lookup_anonymous_fallback() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    assert!(oauth.credential(unbound()).await.unwrap().is_none());
    assert!(host.network.seen.lock().unwrap().is_empty(), "no discovery");
    host.seed(&oauth, context()).await;
    host.policy.deny.store(true, Ordering::SeqCst);
    assert!(oauth.credential(unbound()).await.unwrap().is_none());
    host.policy.deny.store(false, Ordering::SeqCst);
    assert!(host.pending().is_empty());
    assert_eq!(
        host.network.metadata_requests().len(),
        1,
        "only the seed discovery"
    );
}

#[tokio::test]
async fn unbound_lookup_refreshes_expired_token() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    // Learn the binding through standard discovery after a 401.
    assert_eq!(
        code(
            oauth
                .challenge(unbound(), challenge(401, "Bearer", None))
                .await
        ),
        AuthErrorCode::InteractionRequired
    );
    assert!(host.pending().is_empty());
    let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
    host.network.reply(
        200,
        json!({"access_token":"first","refresh_token":"r1","token_type":"Bearer","expires_in":60}),
    );
    oauth
        .complete(unbound(), callback(&pending), budget())
        .await
        .unwrap();
    host.store.expire();
    host.network.offline.store(true, Ordering::SeqCst);
    host.network.reply(
        200,
        json!({"access_token":"refreshed","token_type":"Bearer","expires_in":60}),
    );
    let credential = host
        .pkce(|c| c)
        .credential(unbound())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(credential.token, "refreshed");
    assert_eq!(host.network.last_form()["grant_type"], "refresh_token");
    assert_eq!(host.network.last_form()["refresh_token"], "r1");
}

#[tokio::test]
async fn refresh_unknown_expiry_rotation() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.store.expire();
    host.network.reply(
        200,
        json!({"access_token":"second","refresh_token":"rotated","token_type":"Bearer"}),
    );
    assert_eq!(
        ready(oauth.prepare(context(), budget()).await.unwrap()).token,
        "second"
    );
    let token = host.store.token();
    assert_eq!(token.refresh_token.as_deref(), Some("rotated"));
    assert!(
        token.expires_at.is_none(),
        "absent expires_in is unknown, not expired"
    );
    assert!(!token.refresh_in_flight);
    // Unknown expiry stays usable without refreshing on every call.
    assert_eq!(
        ready(oauth.prepare(context(), budget()).await.unwrap()).token,
        "second"
    );
    assert_eq!(host.network.tokens().len(), 2);
    assert_eq!(
        host.network.last_form()["resource"],
        "https://api.example/hooks"
    );
}

#[tokio::test]
async fn transient_refresh_failure() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.store.expire();
    host.network
        .reply(503, Value::String("<html>busy</html>".into()));
    assert_eq!(
        code(oauth.prepare(context(), budget()).await),
        AuthErrorCode::ProviderFailed
    );
    let token = host.store.token();
    assert_eq!(token.refresh_token.as_deref(), Some("seed-refresh"));
    assert!(
        !token.refresh_in_flight,
        "an observed response clears the marker"
    );
    // An ambiguous transport failure is neither refetched nor retried.
    host.network.transport_failures.store(1, Ordering::SeqCst);
    assert_eq!(
        code(oauth.prepare(context(), budget()).await),
        AuthErrorCode::ProviderFailed
    );
    assert!(host.store.grant().unwrap().refresh_is_uncertain());
    // Uncertainty is not a login-only state: the default retries the refresh.
    host.network
        .reply(200, json!({"access_token":"back","token_type":"Bearer"}));
    assert_eq!(
        ready(oauth.prepare(context(), budget()).await.unwrap()).token,
        "back"
    );
    assert!(!host.store.grant().unwrap().refresh_is_uncertain());
    assert_eq!(host.network.last_form()["refresh_token"], "seed-refresh");
}

#[tokio::test]
async fn refresh_invalid_grant_drops_tokens() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.store.expire();
    host.network.reply(400, json!({"error":"invalid_grant"}));
    assert_eq!(
        code(oauth.prepare(context(), budget()).await),
        AuthErrorCode::RefreshRejected
    );
    assert!(host.store.grant().unwrap().token.is_none());
    assert_eq!(host.store.rejected.load(Ordering::SeqCst), 1);
    assert!(matches!(
        oauth.prepare(context(), budget()).await.unwrap(),
        Preparation::InteractionRequired(_)
    ));
}

#[tokio::test]
async fn refresh_invalid_grant_stale_does_not_wipe() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.store.expire();
    // Another process rotates the grant while this refresh is in flight.
    let records = host.store.records.clone();
    *host.network.on_token.lock().unwrap() = Some(Box::new(move || {
        for record in records.lock().unwrap().values_mut() {
            if let Some(token) = record.token.as_mut() {
                token.access_token = "newer".into();
                token.refresh_token = Some("newer-refresh".into());
                token.expires_at = None;
                token.refresh_in_flight = false;
                record.version = "other-process".into();
            }
        }
    }));
    host.network.reply(400, json!({"error":"invalid_grant"}));
    assert_eq!(
        code(oauth.prepare(context(), budget()).await),
        AuthErrorCode::RefreshRejected
    );
    let token = host.store.token();
    assert_eq!(token.refresh_token.as_deref(), Some("newer-refresh"));
    assert_eq!(host.store.rejected.load(Ordering::SeqCst), 0);
    assert_eq!(
        ready(oauth.prepare(context(), budget()).await.unwrap()).token,
        "newer"
    );
}

#[tokio::test]
async fn token_validation_failure_clears_in_flight() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    // Invalid initial exchange: nothing is persisted and the login has ended.
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    host.network.reply(
        200,
        json!({"access_token":"a","refresh_token":"r","token_type":"mac"}),
    );
    assert_eq!(
        code(
            oauth
                .complete(context(), callback(&pending), budget())
                .await
        ),
        AuthErrorCode::ProviderFailed
    );
    assert!(host.store.grant().is_none() && host.pending().is_empty());
    // Invalid refresh: only the valid rotated refresh token is kept.
    host.seed(&oauth, context()).await;
    host.store.expire();
    for (body, kept) in [
        (
            json!({"access_token":"a","refresh_token":"rotated","token_type":"Bearer","expires_in":0}),
            "rotated",
        ),
        (
            json!({"access_token":"a","refresh_token":"bad token","token_type":"Bearer","expires_in":"x"}),
            "rotated",
        ),
        (
            json!({"access_token":"a","refresh_token":"frac","token_type":"Bearer","expires_in":1.5}),
            "frac",
        ),
    ] {
        host.network.reply(200, body);
        assert_eq!(
            code(oauth.prepare(context(), budget()).await),
            AuthErrorCode::ProviderFailed
        );
        let token = host.store.token();
        assert_eq!(token.refresh_token.as_deref(), Some(kept));
        assert!(!token.refresh_in_flight && token.access_rejected);
    }
    // A positive string expires_in is accepted.
    host.network.reply(
        200,
        json!({"access_token":"ok","token_type":"Bearer","expires_in":"120"}),
    );
    assert_eq!(
        ready(oauth.prepare(context(), budget()).await.unwrap()).token,
        "ok"
    );
    assert!(host.store.token().expires_at.is_some());
}

#[tokio::test]
async fn client_credentials_transient_reissue() {
    let host = Host::new();
    let oauth = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    host.network
        .reply(503, json!({"error":"temporarily_unavailable"}));
    host.network.reply(
        200,
        json!({"access_token":"machine","token_type":"Bearer","expires_in":60}),
    );
    assert_eq!(
        code(oauth.credential(cc_context()).await),
        AuthErrorCode::ProviderFailed
    );
    assert_eq!(
        oauth.credential(cc_context()).await.unwrap().unwrap().token,
        "machine"
    );
    host.store.expire();
    for (status, body, expected) in [
        (
            400,
            json!({"error":"invalid_grant"}),
            AuthErrorCode::ProviderFailed,
        ),
        (
            401,
            json!({"error":"invalid_client"}),
            AuthErrorCode::CredentialUnavailable,
        ),
    ] {
        host.network.reply(status, body);
        let error = oauth.credential(cc_context()).await.err().unwrap();
        assert_eq!(error.auth_code(), Some(expected));
        assert_ne!(error.auth_recovery(), Some(AuthRecovery::Login));
    }
    assert!(host.pending().is_empty());
    let form = host.network.last_form();
    assert_eq!(form["grant_type"], "client_credentials");
    assert_eq!(form["resource"], "https://api.example/hooks");
}

#[tokio::test]
async fn delivery_never_creates_pending_login() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    assert_eq!(
        code(oauth.credential(context()).await),
        AuthErrorCode::InteractionRequired
    );
    let step_up = challenge(
        403,
        r#"Bearer error="insufficient_scope", scope="write""#,
        None,
    );
    assert_eq!(
        code(oauth.challenge(context(), step_up).await),
        AuthErrorCode::InteractionRequired
    );
    assert_eq!(
        code(
            oauth
                .challenge(context(), challenge(401, "Bearer", None))
                .await
        ),
        AuthErrorCode::InteractionRequired
    );
    assert!(host.pending().is_empty());
    assert!(host.network.tokens().is_empty());
    assert!(matches!(
        oauth.prepare(context(), budget()).await.unwrap(),
        Preparation::InteractionRequired(_)
    ));
    assert_eq!(host.pending().len(), 1);
}

#[tokio::test]
async fn pending_login_fixed_lifetime() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let mut short = context();
    short.deadline = Instant::now() + Duration::from_millis(100);
    let pending = login(oauth.prepare(short.clone(), budget()).await.unwrap());
    let lifetime = pending
        .expires_at()
        .duration_since(SystemTime::now())
        .unwrap();
    assert!(lifetime > Duration::from_secs(590) && lifetime <= Duration::from_secs(600));
    tokio::time::sleep(Duration::from_millis(150)).await;
    host.network
        .reply(200, json!({"access_token":"late","token_type":"Bearer"}));
    let ctx = context();
    assert_eq!(
        oauth
            .complete(ctx, callback(&pending), budget())
            .await
            .unwrap()
            .token,
        "late"
    );
    // The host-configured lifetime is bounded by 10 minutes and expiry ends the login.
    let capped = host.pkce(|c| {
        c.login_lifetime(Duration::from_secs(3600))
            .grant_partition("capped")
    });
    let pending = login(capped.prepare(context(), budget()).await.unwrap());
    assert!(pending.expires_at() <= SystemTime::now() + Duration::from_secs(600));
    let brief = host.pkce(|c| {
        c.login_lifetime(Duration::from_millis(30))
            .grant_partition("brief")
    });
    let pending = login(brief.prepare(context(), budget()).await.unwrap());
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        code(
            brief
                .complete(context(), callback(&pending), budget())
                .await
        ),
        AuthErrorCode::InteractionRequired
    );
}

#[tokio::test]
async fn pending_login_owned_by_creating_process() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    let verifier = host.pending()[0].verifier.clone();
    // Nothing about the login reaches the store; it lives in the creating process.
    assert!(
        host.store
            .records
            .lock()
            .unwrap()
            .values()
            .all(|r| r.pending_logins.is_empty())
    );
    assert!(!host.store.dump().contains(&verifier));
    let other = host.other_process();
    assert_eq!(
        code(
            other
                .pkce(|c| c)
                .complete(context(), callback(&pending), budget())
                .await
        ),
        AuthErrorCode::InteractionRequired
    );
    assert!(other.network.tokens().is_empty());
    // The creating process receives the callback and completes it by state.
    host.network
        .reply(200, json!({"access_token":"mine","token_type":"Bearer"}));
    let credential = oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(credential.token, "mine");
    assert!(host.pending().is_empty());
}

#[tokio::test]
async fn pending_login_persisted_cross_process_completion() {
    let host = Host::new();
    let pending = login(
        host.pkce(|c| c.persist_pending_logins())
            .prepare(context(), budget())
            .await
            .unwrap(),
    );
    // The verifier is only in the pending record, never in binding metadata.
    let stored = host.pending();
    assert_eq!(stored.len(), 1);
    assert!(host.logins.lock().unwrap().is_empty());
    let binding = serde_json::to_string(&host.store.binding().unwrap()).unwrap();
    assert!(!binding.contains(&stored[0].verifier));
    // A different process: new provider and network client, the same store.
    let other = host.other_process();
    other.network.reply(
        200,
        json!({"access_token":"elsewhere","token_type":"Bearer"}),
    );
    let credential = other
        .pkce(|c| c.persist_pending_logins())
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(credential.token, "elsewhere");
    assert!(other.network.metadata_requests().is_empty());
    assert!(
        other.network.tokens()[0]
            .body
            .contains(&format!("code_verifier={}", stored[0].verifier))
    );
    assert!(host.pending().is_empty());
    assert!(!host.store.dump().contains(&stored[0].verifier));
}

// A persisted grant key's expired pending logins, with their verifiers, are
// swept by any host `prepare` for it, even one served from the cached token.
#[tokio::test]
async fn persisted_expired_logins_swept_on_prepare() {
    let host = Host::new();
    let oauth = host.pkce(|c| {
        c.persist_pending_logins()
            .login_lifetime(Duration::from_millis(30))
    });
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    host.network
        .reply(200, json!({"access_token":"t","token_type":"Bearer"}));
    oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    login(
        oauth
            .prepare_with_required(context(), &scopes(&["write"]), budget())
            .await
            .unwrap(),
    );
    let verifier = host.pending()[0].verifier.clone();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        ready(oauth.prepare(context(), budget()).await.unwrap()).token,
        "t"
    );
    assert!(host.pending().is_empty());
    assert!(!host.store.dump().contains(&verifier));
}

#[tokio::test]
async fn pending_logins_capped_per_grant_key() {
    for persisted in [false, true] {
        let host = Host::new();
        let oauth = host.pkce(|c| {
            let c = c.max_pending_logins(2);
            if persisted {
                c.persist_pending_logins()
            } else {
                c
            }
        });
        let first = login(oauth.prepare(context(), budget()).await.unwrap());
        let second = login(oauth.prepare(context(), budget()).await.unwrap());
        let third = login(oauth.prepare(context(), budget()).await.unwrap());
        // The oldest is cancelled; the others stay valid.
        let ids: Vec<String> = host.pending().into_iter().map(|l| l.id).collect();
        assert_eq!(ids, [second.id.clone(), third.id.clone()], "{persisted}");
        assert_eq!(
            code(oauth.complete(context(), callback(&first), budget()).await),
            AuthErrorCode::InteractionRequired
        );
        host.network
            .reply(200, json!({"access_token":"second","token_type":"Bearer"}));
        oauth
            .complete(context(), callback(&second), budget())
            .await
            .unwrap();
        assert_eq!(host.pending().len(), 1, "{persisted}");
        // The cap is per grant key: another partition has its own logins.
        let other = host.pkce(|c| {
            let c = c.max_pending_logins(2).grant_partition("other");
            if persisted {
                c.persist_pending_logins()
            } else {
                c
            }
        });
        login(other.prepare(context(), budget()).await.unwrap());
        assert_eq!(host.pending().len(), 2, "{persisted}");
        // Expired pending logins are deleted.
        let brief = host.pkce(|c| {
            let c = c
                .login_lifetime(Duration::from_millis(20))
                .grant_partition("brief");
            if persisted {
                c.persist_pending_logins()
            } else {
                c
            }
        });
        let stale = login(brief.prepare(context(), budget()).await.unwrap());
        tokio::time::sleep(Duration::from_millis(40)).await;
        let fresh = login(brief.prepare(context(), budget()).await.unwrap());
        let ids: Vec<String> = host.pending().into_iter().map(|l| l.id).collect();
        assert!(
            !ids.contains(&stale.id) && ids.contains(&fresh.id),
            "{persisted}"
        );
        brief.cancel_login(fresh, budget()).await.unwrap();
        assert_eq!(host.pending().len(), 2, "{persisted}");
    }
}

#[tokio::test]
async fn pending_login_end_states() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    // Completion.
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    host.network.reply(
        200,
        json!({"access_token":"done","token_type":"Bearer","expires_in":1}),
    );
    oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(
        code(
            oauth
                .complete(context(), callback(&pending), budget())
                .await
        ),
        AuthErrorCode::InteractionRequired
    );
    // Consent denial is a completion.
    host.store.expire();
    host.store
        .records
        .lock()
        .unwrap()
        .values_mut()
        .for_each(|r| r.token = None);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    let mut denied = Url::parse("http://127.0.0.1/callback").unwrap();
    denied
        .query_pairs_mut()
        .append_pair(
            "state",
            &query(pending.authorization_url(), "state").unwrap(),
        )
        .append_pair("error", "access_denied");
    assert_eq!(
        code(oauth.complete(context(), denied, budget()).await),
        AuthErrorCode::AccessDenied
    );
    assert_eq!(
        code(
            oauth
                .complete(context(), callback(&pending), budget())
                .await
        ),
        AuthErrorCode::InteractionRequired
    );
    // Cancel, which never deletes a valid grant; a stale cancel cannot end another login.
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    oauth.cancel_login(pending.clone(), budget()).await.unwrap();
    assert_eq!(
        code(
            oauth
                .complete(context(), callback(&pending), budget())
                .await
        ),
        AuthErrorCode::InteractionRequired
    );
    let newer = login(oauth.prepare(context(), budget()).await.unwrap());
    oauth.cancel_login(pending, budget()).await.unwrap();
    assert_eq!(host.pending()[0].id, newer.id);
    assert!(host.network.tokens().len() == 1);
}

#[tokio::test]
async fn metadata_and_secret_rotation() {
    let host = Host::new();
    let first = host.cc(TokenAuthMethod::ClientSecretBasic, "old-secret");
    host.network.reply(
        200,
        json!({"access_token":"machine","token_type":"Bearer","expires_in":60}),
    );
    first.credential(cc_context()).await.unwrap().unwrap();
    let grant = serde_json::to_string(&host.store.grant().unwrap()).unwrap();
    assert!(!grant.contains("old-secret") && !grant.contains("secret-ref"));
    host.store.expire();
    // Different auth method, new runtime secret and changed capabilities: same grant.
    *host.network.issuer_patch.lock().unwrap() =
        json!({"grant_types_supported":["client_credentials"]});
    let rotated = host.cc(TokenAuthMethod::ClientSecretPost, "new-secret");
    host.network
        .reply(200, json!({"access_token":"rotated","token_type":"Bearer"}));
    assert_eq!(
        rotated
            .credential(cc_context())
            .await
            .unwrap()
            .unwrap()
            .token,
        "rotated"
    );
    let form = host.network.last_form();
    assert_eq!(form["client_secret"], "new-secret");
    assert!(
        host.network
            .tokens()
            .last()
            .unwrap()
            .authorization
            .is_empty()
    );
    assert!(host.store.grant().is_some(), "single grant record");
    assert!(
        !serde_json::to_string(&host.store.grant().unwrap())
            .unwrap()
            .contains("new-secret")
    );
}

#[tokio::test]
async fn scope_ceiling_widening_keeps_grant() {
    let host = Host::new();
    let narrow = host.pkce(|c| c.scopes(scopes(&["read"]), scopes(&["read"])));
    let credential = host.seed(&narrow, context()).await;
    host.network.offline.store(true, Ordering::SeqCst);
    let wide = host.pkce(|c| c.scopes(scopes(&["read"]), scopes(&["read", "write", "admin"])));
    assert_eq!(
        wide.credential(context()).await.unwrap().unwrap().token,
        credential.token
    );
    assert_eq!(host.network.tokens().len(), 1);
}

#[tokio::test]
async fn insufficient_scope_step_up() {
    let host = Host::new();
    let oauth = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    host.network.reply(
        200,
        json!({"access_token":"read","token_type":"Bearer","scope":"read"}),
    );
    let read = oauth.credential(cc_context()).await.unwrap().unwrap();
    for header in [
        "Bearer error=\"invalid_token\"",
        "Basic realm=\"insufficient_scope\"",
    ] {
        let error = oauth
            .challenge(cc_context(), challenge(403, header, Some(&read.attempt_id)))
            .await;
        assert_eq!(code(error), AuthErrorCode::AccessDenied);
    }
    assert_eq!(host.network.tokens().len(), 1);
    host.network.reply(
        200,
        json!({"access_token":"write","token_type":"Bearer","scope":"read write"}),
    );
    let step_up = challenge(
        403,
        r#"Bearer error="insufficient_scope", scope="write""#,
        None,
    );
    oauth.challenge(cc_context(), step_up).await.unwrap();
    assert_eq!(host.network.last_form()["scope"], "read write");
    assert_eq!(
        oauth.credential(cc_context()).await.unwrap().unwrap().token,
        "write"
    );
    let outside = challenge(
        403,
        r#"Bearer error="insufficient_scope", scope="admin""#,
        None,
    );
    let error = oauth.challenge(cc_context(), outside).await.err().unwrap();
    assert_eq!(error.auth_code(), Some(AuthErrorCode::AccessDenied));
    assert_eq!(error.required_scopes(), ["admin"]);
}

#[tokio::test]
async fn step_up_requirement_operation_scoped() {
    let host = Host::new();
    let oauth = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    host.network.reply(
        200,
        json!({"access_token":"wide","token_type":"Bearer","scope":"read write","expires_in":60}),
    );
    let step_up = challenge(
        403,
        r#"Bearer error="insufficient_scope", scope="write""#,
        None,
    );
    oauth.challenge(cc_context(), step_up).await.unwrap();
    let binding = serde_json::to_string(&host.store.binding().unwrap()).unwrap();
    assert!(
        !binding.contains("write"),
        "requirement not persisted on the binding"
    );
    assert_eq!(
        oauth.credential(cc_context()).await.unwrap().unwrap().token,
        "wide"
    );
    assert_eq!(host.store.token().scopes, scopes(&["read", "write"]));
    host.store.expire();
    host.network
        .reply(200, json!({"access_token":"later","token_type":"Bearer"}));
    oauth.credential(cc_context()).await.unwrap().unwrap();
    assert_eq!(
        host.network.last_form()["scope"],
        "read write",
        "re-acquisition keeps the stored grant, not a binding requirement"
    );
}

#[tokio::test]
async fn step_up_required_scopes_round_trip() {
    let host = Host::new();
    let oauth = Arc::new(host.pkce(|c| c));
    host.seed(&oauth, context()).await;
    let providers = crate::auth::AuthProviders::builder()
        .oauth(oauth.clone())
        .build();
    let step_up = challenge(
        403,
        r#"Bearer error="insufficient_scope", scope="write""#,
        None,
    );
    let error = providers.challenge(context(), step_up).await.err().unwrap();
    assert_eq!(error.auth_code(), Some(AuthErrorCode::InteractionRequired));
    assert_eq!(error.required_scopes(), ["write"]);
    assert!(host.pending().is_empty());
    let pending = login(
        oauth
            .prepare_with_required(context(), error.required_scopes(), budget())
            .await
            .unwrap(),
    );
    assert_eq!(
        query(pending.authorization_url(), "scope").unwrap(),
        "read write"
    );
    host.network.reply(
        200,
        json!({"access_token":"stepped","token_type":"Bearer","scope":"read write"}),
    );
    oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(
        ready(
            oauth
                .prepare_with_required(context(), &scopes(&["write"]), budget())
                .await
                .unwrap()
        )
        .token,
        "stepped"
    );
    assert_eq!(
        code(
            oauth
                .prepare_with_required(context(), &scopes(&["bad\\scope"]), budget())
                .await
        ),
        AuthErrorCode::InvalidConfiguration
    );
}

#[tokio::test]
async fn configured_preset_no_protected_resource_metadata() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    let requests = host.network.metadata_requests();
    assert_eq!(
        requests,
        ["https://issuer.example/.well-known/oauth-authorization-server"]
    );
    let url = pending.authorization_url();
    assert_eq!(query(url, "resource").unwrap(), "https://api.example/hooks");
    assert_eq!(query(url, "code_challenge_method").unwrap(), "S256");
    assert!(
        url.as_str()
            .starts_with("https://issuer.example/authorize?")
    );
}

#[tokio::test]
async fn explicit_shared_grant() {
    let host = Host::new();
    let shared = host.pkce(|c| c.grant_partition("consent"));
    let credential = host.seed(&shared, context()).await;
    let upload = AuthContext {
        purpose: AuthPurpose::Upload,
        destination: "https://api.example/hooks/upload".into(),
        ..context()
    };
    assert_eq!(
        ready(shared.prepare(upload.clone(), budget()).await.unwrap()).token,
        credential.token
    );
    // The default partition isolates the upload binding.
    assert!(matches!(
        host.pkce(|c| c)
            .prepare(upload.clone(), budget())
            .await
            .unwrap(),
        Preparation::InteractionRequired(_)
    ));
    // Sharing never overrides independent upload policy.
    host.policy.deny.store(true, Ordering::SeqCst);
    let other = AuthContext {
        destination: "https://api.example/hooks/other".into(),
        ..upload
    };
    assert!(shared.prepare(other, budget()).await.is_err());
}

#[tokio::test]
async fn invalid_callback_does_not_consume() {
    let host = Host::new();
    let oauth = host.pkce(|c| c.redirect_uri("http://127.0.0.1/callback?tenant=one"));
    *host.network.issuer_patch.lock().unwrap() =
        json!({"authorization_response_iss_parameter_supported": true});
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    let valid = || {
        let mut url = callback(&pending);
        url.query_pairs_mut()
            .append_pair("tenant", "one")
            .append_pair("iss", "https://issuer.example");
        url
    };
    let mut wrong_state = valid();
    wrong_state.set_query(Some(
        "tenant=one&state=bad&code=x&iss=https%3A%2F%2Fissuer.example",
    ));
    let mut wrong_redirect = valid();
    wrong_redirect.set_path("/elsewhere");
    let mut wrong_query = valid();
    wrong_query.query_pairs_mut().append_pair("tenant", "two");
    let mut wrong_issuer = callback(&pending);
    wrong_issuer
        .query_pairs_mut()
        .append_pair("tenant", "one")
        .append_pair("iss", "https://evil.example");
    let mut missing_issuer = callback(&pending);
    missing_issuer
        .query_pairs_mut()
        .append_pair("tenant", "one");
    let mut duplicate = valid();
    duplicate.query_pairs_mut().append_pair("code", "again");
    for bad in [
        wrong_state,
        wrong_redirect,
        wrong_query,
        wrong_issuer,
        missing_issuer,
        duplicate,
    ] {
        assert!(oauth.complete(context(), bad, budget()).await.is_err());
    }
    assert!(host.network.tokens().is_empty());
    host.network
        .reply(200, json!({"access_token":"once","token_type":"Bearer"}));
    assert_eq!(
        oauth
            .complete(context(), valid(), budget())
            .await
            .unwrap()
            .token,
        "once"
    );
    assert!(oauth.complete(context(), valid(), budget()).await.is_err());
    assert_eq!(host.network.tokens().len(), 1);
}

#[test]
fn loopback_redirect() {
    for (redirect, accepted) in [
        ("https://host.example/callback", true),
        ("http://127.0.0.1/callback", true),
        ("http://127.254.3.2/callback", true),
        ("http://[::1]/callback", true),
        ("com.example.app:/oauth2redirect", true),
        ("http://localhost/callback", false),
        ("http://127.0.0.1.example.com/callback", false),
        ("http://192.168.1.1/callback", false),
        ("http://host.example/callback", false),
        ("http://[::2]/callback", false),
        ("myapp:/callback", false),
        ("com.example.app:/callback#fragment", false),
    ] {
        let host = Host::new();
        let config = OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
            .redirect_uri(redirect);
        assert_eq!(
            ManagedOAuth::new(config, host.network, host.policy, host.store).is_ok(),
            accepted,
            "{redirect}"
        );
    }
}

#[tokio::test]
async fn private_use_redirect_completes() {
    let host = Host::new();
    let oauth = host.pkce(|c| c.redirect_uri("com.example.app:/oauth2redirect"));
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    let mut url = Url::parse("com.example.app:/oauth2redirect").unwrap();
    url.query_pairs_mut()
        .append_pair(
            "state",
            &query(pending.authorization_url(), "state").unwrap(),
        )
        .append_pair("code", "c");
    host.network
        .reply(200, json!({"access_token":"app","token_type":"Bearer"}));
    assert_eq!(
        oauth
            .complete(context(), url, budget())
            .await
            .unwrap()
            .token,
        "app"
    );
}

#[tokio::test]
async fn loopback_redirect_ephemeral_port_per_login() {
    let host = Host::new();
    // No configured redirect: each login brings its own loopback port.
    let oauth = host.owner(
        OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
            .scopes(scopes(&["read"]), scopes(&["read", "write"])),
    );
    assert_eq!(
        code(oauth.prepare(context(), budget()).await),
        AuthErrorCode::InvalidConfiguration
    );
    // localhost and non-loopback http fail before any request or pending login.
    for redirect in [
        "http://localhost:51001/callback",
        "http://192.168.1.2:51001/callback",
    ] {
        let options = PrepareOptions::new().redirect_uri(redirect);
        assert_eq!(
            code(oauth.prepare_with(context(), options, budget()).await),
            AuthErrorCode::InvalidConfiguration
        );
    }
    assert!(host.network.seen.lock().unwrap().is_empty() && host.pending().is_empty());
    let mut logins = Vec::new();
    for port in [51001, 51002] {
        let redirect = format!("http://127.0.0.1:{port}/callback");
        let options = PrepareOptions::new().redirect_uri(&redirect);
        let pending = login(
            oauth
                .prepare_with(context(), options, budget())
                .await
                .unwrap(),
        );
        assert_eq!(pending.redirect_uri(), redirect);
        assert_eq!(
            query(pending.authorization_url(), "redirect_uri").unwrap(),
            redirect
        );
        logins.push(pending);
    }
    // A callback on another port never consumes the login.
    let mut wrong_port = callback(&logins[0]);
    wrong_port.set_port(Some(51002)).unwrap();
    assert_eq!(
        code(oauth.complete(context(), wrong_port, budget()).await),
        AuthErrorCode::AccessDenied
    );
    for (pending, port) in logins.iter().zip([51001, 51002]) {
        host.network.reply(
            200,
            json!({"access_token":format!("t{port}"),"token_type":"Bearer"}),
        );
        oauth
            .complete(context(), callback(pending), budget())
            .await
            .unwrap();
        assert_eq!(
            host.network.last_form()["redirect_uri"],
            format!("http://127.0.0.1:{port}/callback")
        );
    }
}

#[tokio::test]
async fn narrowed_refresh_scope_inheritance() {
    let host = Host::new();
    *host.policy.select.lock().unwrap() = scopes(&["read", "write"]);
    let oauth = host.pkce(|c| c.scopes(scopes(&["read", "write"]), scopes(&["read", "write"])));
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    assert_eq!(
        query(pending.authorization_url(), "scope").unwrap(),
        "read write"
    );
    host.network.reply(200, json!({"access_token":"a","refresh_token":"r","token_type":"Bearer","scope":"read","expires_in":1}));
    oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    host.store.expire();
    host.network
        .reply(200, json!({"access_token":"b","token_type":"Bearer"}));
    ready(oauth.prepare(context(), budget()).await.unwrap());
    assert!(
        !host.network.last_form().contains_key("scope"),
        "refresh never re-scopes"
    );
    assert_eq!(host.store.token().scopes, scopes(&["read"]));
}

#[tokio::test]
async fn scope_challenge_without_required_scope() {
    let host = Host::new();
    let oauth = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    let bare = || challenge(403, "Bearer error=\"insufficient_scope\"", None);
    assert_eq!(
        code(oauth.challenge(cc_context(), bare()).await),
        AuthErrorCode::AccessDenied
    );
    assert!(host.network.seen.lock().unwrap().is_empty());
    let mut required = cc_context();
    required.authentication.as_mut().unwrap()["scopes"] = json!(["write"]);
    host.network.reply(
        200,
        json!({"access_token":"w","token_type":"Bearer","scope":"read write"}),
    );
    oauth.challenge(required, bare()).await.unwrap();
    assert_eq!(host.network.last_form()["scope"], "read write");
}

#[tokio::test]
async fn refresh_broadening_scope_ignored() {
    let host = Host::new();
    *host.policy.select.lock().unwrap() = scopes(&["read", "write"]);
    let oauth = host.pkce(|c| c.scopes(scopes(&["read", "write"]), scopes(&["read", "write"])));
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    host.network.reply(200, json!({"access_token":"a","refresh_token":"r","token_type":"Bearer","scope":"read","expires_in":1}));
    oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    host.store.expire();
    host.network.reply(200, json!({"access_token":"b","refresh_token":"rotated","token_type":"Bearer","scope":"read write"}));
    let recreated = host.pkce(|c| c.scopes(scopes(&["read", "write"]), scopes(&["read", "write"])));
    assert_eq!(
        ready(recreated.prepare(context(), budget()).await.unwrap()).token,
        "b"
    );
    let token = host.store.token();
    assert_eq!(token.scopes, scopes(&["read"]));
    assert_eq!(token.refresh_token.as_deref(), Some("rotated"));
    let mut write = context();
    write.authentication.as_mut().unwrap()["scopes"] = json!(["write"]);
    let error = recreated.credential(write).await.err().unwrap();
    assert_eq!(error.auth_code(), Some(AuthErrorCode::InteractionRequired));
    assert_eq!(error.required_scopes(), ["write"]);
}

#[tokio::test]
async fn extra_granted_scope_ignored() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    host.network.reply(200, json!({"access_token":"a","token_type":"Bearer","scope":"read openid offline_access admin"}));
    oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(host.store.token().scopes, scopes(&["read"]));
}

#[tokio::test]
async fn challenge_renews_rejected_unexpired_token() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let first = host.seed(&oauth, context()).await;
    host.network.reply(
        200,
        json!({"access_token":"second","refresh_token":"r2","token_type":"Bearer"}),
    );
    oauth
        .challenge(context(), challenge(401, "Bearer", Some(&first.attempt_id)))
        .await
        .unwrap();
    let second = oauth.credential(context()).await.unwrap().unwrap();
    assert_eq!(second.token, "second");
    // A delayed 401 for the old generation does not reject the newer token.
    oauth
        .challenge(context(), challenge(401, "Bearer", Some(&first.attempt_id)))
        .await
        .unwrap();
    assert_eq!(
        oauth.credential(context()).await.unwrap().unwrap().token,
        "second"
    );
    assert_eq!(host.network.tokens().len(), 2);
}

#[tokio::test]
async fn up_front_refresh_failure_no_anonymous_fallback() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.network.offline.store(true, Ordering::SeqCst);
    for (status, body, expected) in [
        (
            503,
            json!({"error":"temporarily_unavailable"}),
            AuthErrorCode::ProviderFailed,
        ),
        (
            400,
            json!({"error":"invalid_grant"}),
            AuthErrorCode::RefreshRejected,
        ),
    ] {
        host.store.expire();
        host.network.reply(status, body);
        assert_eq!(code(oauth.credential(unbound()).await), expected);
    }
    assert!(host.pending().is_empty());
}

#[tokio::test]
async fn scope_ceiling_narrowing_keeps_grant() {
    let host = Host::new();
    *host.policy.select.lock().unwrap() = scopes(&["read", "write"]);
    let wide = || host.pkce(|c| c.scopes(scopes(&["read"]), scopes(&["read", "write"])));
    let narrow = host.pkce(|c| c.scopes(scopes(&["read"]), scopes(&["read"])));
    let pending = login(wide().prepare(context(), budget()).await.unwrap());
    host.network.reply(200, json!({"access_token":"a","refresh_token":"r","token_type":"Bearer","scope":"read write","expires_in":1}));
    wide()
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    // The narrow caller sees only `read` but refreshes without losing `write`.
    *host.policy.select.lock().unwrap() = scopes(&["read"]);
    host.network.reply(
        200,
        json!({"access_token":"b","refresh_token":"r2","token_type":"Bearer"}),
    );
    assert_eq!(
        ready(narrow.prepare(context(), budget()).await.unwrap()).token,
        "b"
    );
    assert_eq!(host.store.token().scopes, scopes(&["read", "write"]));
    let write = scopes(&["write"]);
    assert_eq!(
        code(
            narrow
                .prepare_with_required(context(), &write, budget())
                .await
        ),
        AuthErrorCode::AccessDenied
    );
    *host.policy.select.lock().unwrap() = scopes(&["read", "write"]);
    let again = wide()
        .prepare_with_required(context(), &write, budget())
        .await;
    assert_eq!(ready(again.unwrap()).token, "b");
}

#[tokio::test]
async fn prepare_required_outside_ceiling_denied() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let error = oauth
        .prepare_with_required(context(), &scopes(&["admin"]), budget())
        .await
        .err()
        .unwrap();
    assert_eq!(error.auth_code(), Some(AuthErrorCode::AccessDenied));
    assert_eq!(error.required_scopes(), ["admin"], "diagnostics only");
    assert!(host.network.seen.lock().unwrap().is_empty());
    assert!(host.pending().is_empty());
}

#[tokio::test]
async fn challenge_renews_rejected_unexpired_token_without_expiry() {
    // Unknown expiry: a 401 still marks the token stale, and client credentials re-acquire.
    let host = Host::new();
    let oauth = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    host.network
        .reply(200, json!({"access_token":"revoked","token_type":"Bearer"}));
    let revoked = oauth.credential(cc_context()).await.unwrap().unwrap();
    host.network
        .reply(200, json!({"access_token":"renewed","token_type":"Bearer"}));
    oauth
        .challenge(
            cc_context(),
            challenge(401, "Bearer", Some(&revoked.attempt_id)),
        )
        .await
        .unwrap();
    assert_eq!(
        oauth.credential(cc_context()).await.unwrap().unwrap().token,
        "renewed"
    );
}

/// Client-credentials binding learned for an unbound endpoint.
async fn learned_cc(host: &Host) -> ManagedOAuth {
    let oauth = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    host.network.reply(
        200,
        json!({"access_token":"first","token_type":"Bearer","expires_in":60}),
    );
    oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .unwrap();
    oauth
}

#[tokio::test]
async fn up_front_client_credentials_reacquire() {
    let host = Host::new();
    let oauth = learned_cc(&host).await;
    host.store.expire();
    host.network.offline.store(true, Ordering::SeqCst);
    host.network
        .reply(200, json!({"access_token":"again","token_type":"Bearer"}));
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "again"
    );
    assert_eq!(host.network.last_form()["grant_type"], "client_credentials");
    assert!(host.pending().is_empty());
}

#[tokio::test]
async fn up_front_lookup_issuer_metadata_only() {
    let host = Host::new();
    let oauth = learned_cc(&host).await;
    let strip = || {
        for (key, record) in host.store.records.lock().unwrap().iter_mut() {
            if key.starts_with("ahp.oauth.binding:") {
                record.metadata = TrustedMetadata::new(
                    record.metadata.resource.clone(),
                    record.metadata.issuer.clone(),
                    String::new(),
                );
            }
        }
    };
    strip();
    host.store.expire();
    let before = host.network.metadata_requests().len();
    host.network
        .reply(200, json!({"access_token":"rebuilt","token_type":"Bearer"}));
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "rebuilt"
    );
    let fetched = host.network.metadata_requests()[before..].to_vec();
    assert_eq!(
        fetched,
        ["https://issuer.example/.well-known/oauth-authorization-server"]
    );
    assert!(
        !host
            .store
            .binding()
            .unwrap()
            .metadata
            .token_endpoint
            .is_empty()
    );
    // A failed issuer fetch is discovery_failed, not an anonymous attempt.
    strip();
    host.store.expire();
    *host.network.issuer_patch.lock().unwrap() = json!({"issuer":"https://other.example"});
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::DiscoveryFailed
    );
    let after = host.network.metadata_requests();
    assert!(
        after[before..]
            .iter()
            .all(|uri| !uri.contains("oauth-protected-resource"))
    );
}

#[tokio::test]
async fn known_binding_without_token_requires_login() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.store
        .records
        .lock()
        .unwrap()
        .values_mut()
        .for_each(|r| r.token = None);
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InteractionRequired
    );
    assert!(host.pending().is_empty());
    let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
    host.network.reply(
        200,
        json!({"access_token":"restored","token_type":"Bearer"}),
    );
    oauth
        .complete(unbound(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "restored"
    );
}

#[tokio::test]
async fn step_up_keeps_previous_grant() {
    let host = Host::new();
    *host.policy.select.lock().unwrap() = scopes(&["files", "read"]);
    let files = host.pkce(|c| c.scopes(scopes(&["read"]), scopes(&["files", "read"])));
    let pending = login(files.prepare(context(), budget()).await.unwrap());
    host.network.reply(
        200,
        json!({"access_token":"a","token_type":"Bearer","scope":"files read"}),
    );
    files
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    // A caller with a different ceiling steps up; earlier scopes are requested and kept.
    *host.policy.select.lock().unwrap() = scopes(&["read"]);
    let writer = host.pkce(|c| c);
    let write = scopes(&["write"]);
    let pending = login(
        writer
            .prepare_with_required(context(), &write, budget())
            .await
            .unwrap(),
    );
    assert_eq!(
        query(pending.authorization_url(), "scope").unwrap(),
        "files read write"
    );
    host.network.reply(
        200,
        json!({"access_token":"b","token_type":"Bearer","scope":"files read write openid"}),
    );
    writer
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(
        host.store.token().scopes,
        scopes(&["files", "read", "write"])
    );
    assert_eq!(
        writer.effective(&host.store.token().scopes),
        scopes(&["read", "write"])
    );
    let ready_files = files.credential(context()).await.unwrap().unwrap();
    assert_eq!(ready_files.token, "b");
}

#[tokio::test]
async fn stale_metadata_refetch_once() {
    let host = Host::new();
    let oauth = learned_cc(&host).await;
    let old = host.network.tokens()[0].uri.clone();
    let prm = |host: &Host| {
        let requests = host.network.metadata_requests();
        requests
            .iter()
            .filter(|uri| uri.contains("oauth-protected-resource"))
            .count()
    };
    let learned = prm(&host);
    // The issuer moves its token endpoint; the persisted one now answers 404.
    *host.network.issuer_patch.lock().unwrap() =
        json!({"token_endpoint":"https://issuer.example/token2"});
    host.store.expire();
    let before = host.network.metadata_requests().len();
    host.network
        .reply(200, json!({"access_token":"moved","token_type":"Bearer"}));
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "moved"
    );
    let tokens: Vec<_> = host
        .network
        .tokens()
        .iter()
        .map(|t| t.uri.clone())
        .collect();
    assert_eq!(tokens[1..], [old, "https://issuer.example/token2".into()]);
    assert_eq!(
        host.network.metadata_requests()[before..],
        ["https://issuer.example/.well-known/oauth-authorization-server"]
    );
    assert!(
        host.store
            .binding()
            .unwrap()
            .metadata
            .token_endpoint
            .ends_with("/token2")
    );
    // A connect/DNS/TLS failure (request provably not sent) also refetches once.
    host.store.expire();
    let before = host.network.metadata_requests().len();
    host.network.unsent_failures.store(1, Ordering::SeqCst);
    host.network.reply(
        200,
        json!({"access_token":"reconnected","token_type":"Bearer"}),
    );
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "reconnected"
    );
    assert_eq!(host.network.metadata_requests().len(), before + 1);
    // An OAuth error response never refetches.
    host.store.expire();
    let before = host.network.metadata_requests().len();
    host.network.reply(401, json!({"error":"invalid_client"}));
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::CredentialUnavailable
    );
    assert_eq!(host.network.metadata_requests().len(), before);
    // A changed issuer is discovery_failed, repaired by the host with prepare.
    host.store.expire();
    *host.network.issuer_patch.lock().unwrap() =
        json!({"issuer":"https://other.example","token_endpoint":"https://issuer.example/token3"});
    let error = oauth.credential(unbound()).await.err().unwrap();
    assert_eq!(error.auth_code(), Some(AuthErrorCode::DiscoveryFailed));
    assert_eq!(error.auth_recovery(), Some(AuthRecovery::Retry));
    assert_eq!(prm(&host), learned, "never protected-resource discovery");
}

#[tokio::test]
async fn ambiguous_renewal_failure_no_refetch() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.network.offline.store(true, Ordering::SeqCst);
    // Read timeout/reset after send, 5xx, non-OAuth body and redirects are ambiguous.
    for (status, body) in [
        (None, Value::Null),
        (Some(503), json!({"error":"temporarily_unavailable"})),
        (Some(500), Value::String("<html>oops</html>".into())),
        (Some(302), Value::String(String::new())),
    ] {
        host.store.expire();
        let presented = host.network.tokens().len();
        match status {
            None => host.network.transport_failures.store(1, Ordering::SeqCst),
            Some(status) => host.network.reply(status, body),
        }
        let error = oauth.credential(unbound()).await.err().unwrap();
        assert_eq!(error.auth_code(), Some(AuthErrorCode::ProviderFailed));
        assert_eq!(error.auth_recovery(), Some(AuthRecovery::Retry));
        assert_eq!(
            host.network.tokens().len(),
            presented + 1,
            "no immediate retry"
        );
    }
    // Offline metadata would have panicked on any refetch; the token is retained.
    assert_eq!(
        host.store.token().refresh_token.as_deref(),
        Some("seed-refresh")
    );
}

#[tokio::test]
async fn rejected_token_is_persisted_before_failed_renewal() {
    let host = Host::new();
    let oauth = learned_cc(&host).await;
    let revoked = oauth.credential(unbound()).await.unwrap().unwrap();
    host.network
        .reply(503, json!({"error":"temporarily_unavailable"}));
    let rejected = challenge(401, "Bearer", Some(&revoked.attempt_id));
    assert_eq!(
        code(oauth.challenge(unbound(), rejected).await),
        AuthErrorCode::ProviderFailed
    );
    assert!(
        host.store.token().access_rejected,
        "rejection survives the failed renewal"
    );
    host.network
        .reply(200, json!({"access_token":"renewed","token_type":"Bearer"}));
    let next = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    assert_eq!(
        next.credential(unbound()).await.unwrap().unwrap().token,
        "renewed"
    );
}

#[tokio::test]
async fn challenge_rediscovers_moved_issuer() {
    let host = Host::new();
    let oauth = learned_cc(&host).await;
    let revoked = oauth.credential(unbound()).await.unwrap().unwrap();
    // The resource moves to a new issuer; the old token endpoint is gone.
    *host.network.prm_issuer.lock().unwrap() = Some("https://issuer2.example".into());
    *host.network.issuer_patch.lock().unwrap() = json!({
        "issuer":"https://issuer2.example",
        "token_endpoint":"https://issuer2.example/token"
    });
    host.network
        .reply(200, json!({"access_token":"moved","token_type":"Bearer"}));
    let header = r#"Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource/hooks""#;
    oauth
        .challenge(unbound(), challenge(401, header, Some(&revoked.attempt_id)))
        .await
        .unwrap();
    assert_eq!(
        host.store.binding().unwrap().metadata.issuer,
        "https://issuer2.example"
    );
    assert_eq!(
        host.network.tokens().last().unwrap().uri,
        "https://issuer2.example/token"
    );
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "moved"
    );
}

#[tokio::test]
async fn lookup_with_changed_client_or_flow_is_discovery_failed() {
    let host = Host::new();
    host.seed(&host.pkce(|c| c), context()).await;
    let other = host.owner(
        OAuthClientConfig::new("account", "other-client", OAuthFlow::AuthorizationCodePkce)
            .scopes(scopes(&["read"]), scopes(&["read"]))
            .redirect_uri("http://127.0.0.1/callback"),
    );
    assert_eq!(
        code(other.credential(unbound()).await),
        AuthErrorCode::DiscoveryFailed
    );
    let flow = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    assert_eq!(
        code(flow.credential(unbound()).await),
        AuthErrorCode::DiscoveryFailed
    );
}

/// Seeded PKCE grant whose refresh is in flight when the store becomes slow.
async fn slow_refresh(host: &Host, oauth: &ManagedOAuth, reply: Value) {
    host.seed(oauth, context()).await;
    host.store.expire();
    host.network.reply(200, reply);
    let delay = host.store.write_delay.clone();
    *host.network.on_token.lock().unwrap() =
        Some(Box::new(move || delay.store(300, Ordering::SeqCst)));
}

#[tokio::test]
async fn token_commit_outlives_caller_deadline() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    slow_refresh(
        &host,
        &oauth,
        json!({"access_token":"b","refresh_token":"rotated","token_type":"Bearer"}),
    )
    .await;
    let mut short = context();
    short.deadline = Instant::now() + Duration::from_millis(150);
    assert!(oauth.credential(short).await.is_err());
    tokio::time::sleep(Duration::from_millis(400)).await;
    let token = host.store.token();
    assert_eq!(token.refresh_token.as_deref(), Some("rotated"));
    assert!(!token.refresh_in_flight);
}

#[tokio::test]
async fn token_commit_survives_dropped_future() {
    // Both a valid response and an undecodable 2xx keep the rotated refresh token.
    for (reply, access) in [
        (
            json!({"access_token":"b","refresh_token":"rotated","token_type":"Bearer"}),
            false,
        ),
        (
            json!({"access_token":"b","refresh_token":"rotated","token_type":"Bearer","expires_in":null}),
            true,
        ),
    ] {
        let host = Host::new();
        let oauth = host.pkce(|c| c);
        slow_refresh(&host, &oauth, reply).await;
        let dropped = tokio::time::timeout(Duration::from_millis(50), oauth.credential(context()));
        assert!(dropped.await.is_err(), "future dropped mid-commit");
        tokio::time::sleep(Duration::from_millis(400)).await;
        let token = host.store.token();
        assert_eq!(token.refresh_token.as_deref(), Some("rotated"));
        assert!(!token.refresh_in_flight);
        assert_eq!(token.access_rejected, access);
    }
}

#[tokio::test]
async fn expires_in_null_is_malformed() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.store.expire();
    host.network.reply(
        200,
        json!({"access_token":"b","token_type":"Bearer","expires_in":null}),
    );
    assert_eq!(
        code(oauth.credential(context()).await),
        AuthErrorCode::ProviderFailed
    );
}

#[tokio::test]
async fn non_json_2xx_refresh_keeps_rotated_token() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.store.expire();
    // oauth2 reports a 2xx without a JSON content type as `Other`.
    host.network.reply(
        200,
        Value::String(
            r#"{"access_token":"b","refresh_token":"rotated","token_type":"Bearer"}"#.into(),
        ),
    );
    assert_eq!(
        code(oauth.credential(context()).await),
        AuthErrorCode::ProviderFailed
    );
    let token = host.store.token();
    assert_eq!(token.refresh_token.as_deref(), Some("rotated"));
    assert!(!token.refresh_in_flight && token.access_rejected);
}

/// Strip the binding's persisted token endpoint and move the resource to issuer2.
fn move_issuer_with_empty_metadata(host: &Host) {
    for (key, record) in host.store.records.lock().unwrap().iter_mut() {
        if key.starts_with("ahp.oauth.binding:") {
            record.metadata.token_endpoint.clear();
        }
    }
    *host.network.prm_issuer.lock().unwrap() = Some("https://issuer2.example".into());
    *host.network.issuer_patch.lock().unwrap() = json!({"issuer":"https://issuer2.example"});
}

#[tokio::test]
async fn challenge_with_empty_metadata_rediscovers_moved_issuer() {
    // Client credentials.
    let host = Host::new();
    let oauth = learned_cc(&host).await;
    move_issuer_with_empty_metadata(&host);
    host.network
        .reply(200, json!({"access_token":"moved","token_type":"Bearer"}));
    oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .unwrap();
    assert_eq!(
        host.store.binding().unwrap().metadata.issuer,
        "https://issuer2.example"
    );
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "moved"
    );
    // PKCE: the binding is repaired and consent is requested from the new issuer.
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    assert_eq!(
        code(
            oauth
                .challenge(unbound(), challenge(401, "Bearer", None))
                .await
        ),
        AuthErrorCode::InteractionRequired
    );
    move_issuer_with_empty_metadata(&host);
    assert_eq!(
        code(
            oauth
                .challenge(unbound(), challenge(401, "Bearer", None))
                .await
        ),
        AuthErrorCode::InteractionRequired
    );
    assert_eq!(
        host.store.binding().unwrap().metadata.issuer,
        "https://issuer2.example"
    );
    assert!(
        !host
            .store
            .binding()
            .unwrap()
            .metadata
            .token_endpoint
            .is_empty()
    );
}

#[tokio::test]
async fn challenge_rebinds_when_old_issuer_still_answers() {
    let host = Host::new();
    let oauth = learned_cc(&host).await;
    // The old authorization server is still up; only PRM points elsewhere.
    *host.network.prm_issuer.lock().unwrap() = Some("https://issuer2.example".into());
    host.network
        .reply(200, json!({"access_token":"rebound","token_type":"Bearer"}));
    oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .unwrap();
    assert_eq!(
        host.store.binding().unwrap().metadata.issuer,
        "https://issuer2.example"
    );
    assert_eq!(
        host.network.tokens().last().unwrap().uri,
        "https://issuer2.example/token"
    );
}

#[tokio::test]
async fn prepare_rebinds_when_policy_rejects_stored_issuer() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    assert!(
        oauth
            .challenge(unbound(), challenge(401, "Bearer", None))
            .await
            .is_err()
    );
    *host.network.prm_issuer.lock().unwrap() = Some("https://issuer2.example".into());
    *host.policy.only.lock().unwrap() = Some("https://issuer2.example".into());
    // Lookup keeps treating a refusal as anonymous.
    assert!(oauth.credential(unbound()).await.unwrap().is_none());
    let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
    assert!(
        pending
            .authorization_url()
            .as_str()
            .starts_with("https://issuer2.example/authorize?")
    );
    assert_eq!(
        host.store.binding().unwrap().metadata.issuer,
        "https://issuer2.example"
    );
}

#[tokio::test]
async fn failed_challenge_discovery_still_retires_rejected_token() {
    let host = Host::new();
    let oauth = learned_cc(&host).await;
    let revoked = oauth.credential(unbound()).await.unwrap().unwrap();
    // No cached fallback either: the binding lacks persisted token-endpoint metadata.
    for (key, record) in host.store.records.lock().unwrap().iter_mut() {
        if key.starts_with("ahp.oauth.binding:") {
            record.metadata.token_endpoint.clear();
        }
    }
    host.network.prm_outage.store(true, Ordering::SeqCst);
    let rejected = challenge(401, "Bearer", Some(&revoked.attempt_id));
    assert_eq!(
        code(oauth.challenge(unbound(), rejected).await),
        AuthErrorCode::DiscoveryFailed
    );
    assert!(host.store.token().access_rejected);
    host.network
        .reply(200, json!({"access_token":"fresh","token_type":"Bearer"}));
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "fresh"
    );
}

#[tokio::test]
async fn challenge_renews_through_cached_binding_during_discovery_outage() {
    let host = Host::new();
    let oauth = learned_cc(&host).await;
    let revoked = oauth.credential(unbound()).await.unwrap().unwrap();
    host.network.prm_outage.store(true, Ordering::SeqCst);
    host.network
        .reply(200, json!({"access_token":"renewed","token_type":"Bearer"}));
    let rejected = challenge(401, "Bearer", Some(&revoked.attempt_id));
    oauth.challenge(unbound(), rejected).await.unwrap();
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "renewed"
    );
}

#[tokio::test]
async fn form_encoded_refresh_failure_keeps_valid_rotated_token() {
    let host = Host::new();
    let oauth = host.pkce(|c| c.commit_timeout(Duration::MAX));
    host.seed(&oauth, context()).await;
    for (body, kept) in [
        (
            "access_token=a&refresh_token=bad%20token&token_type=Bearer",
            "seed-refresh",
        ),
        (
            "access_token=a&refresh_token=rotated&token_type=Bearer",
            "rotated",
        ),
    ] {
        host.store.expire();
        host.network.reply(200, Value::String(body.into()));
        assert_eq!(
            code(oauth.credential(context()).await),
            AuthErrorCode::ProviderFailed
        );
        assert_eq!(host.store.token().refresh_token.as_deref(), Some(kept));
    }
}

#[tokio::test]
async fn detached_refresh_keeps_grant_lock_from_concurrent_caller() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.store.expire();
    host.network.reply(
        200,
        json!({"access_token":"a","refresh_token":"rotated","token_type":"Bearer"}),
    );
    host.network.token_delay.store(300, Ordering::SeqCst);
    host.policy.shared_lock.store(true, Ordering::SeqCst);
    // Caller A gives up after the request was written.
    let a = tokio::time::timeout(Duration::from_millis(100), oauth.credential(context()));
    assert!(a.await.is_err());
    // Caller B retries at once: it waits for the lock, then uses the committed
    // outcome of A's exchange instead of re-presenting the spent token.
    assert_eq!(
        oauth.credential(context()).await.unwrap().unwrap().token,
        "a"
    );
    let presented: Vec<String> = host
        .network
        .tokens()
        .iter()
        .skip(1)
        .map(|seen| {
            url::form_urlencoded::parse(seen.body.as_bytes())
                .find(|(k, _)| k == "refresh_token")
                .unwrap()
                .1
                .into_owned()
        })
        .collect();
    assert_eq!(presented, ["seed-refresh"]);
    assert_eq!(host.store.token().refresh_token.as_deref(), Some("rotated"));
}

#[tokio::test]
async fn definitive_discovery_failure_never_falls_back_to_cached_binding() {
    // A hinted protected-resource metadata URL that is gone.
    let host = Host::new();
    let oauth = learned_cc(&host).await;
    let tokens = host.network.tokens().len();
    let header = r#"Bearer resource_metadata="https://api.example/missing""#;
    assert!(
        oauth
            .challenge(unbound(), challenge(401, header, None))
            .await
            .is_err()
    );
    // Metadata naming another issuer whose metadata is temporarily unavailable.
    *host.network.prm_issuer.lock().unwrap() = Some("https://issuer2.example".into());
    *host.network.issuer_outage.lock().unwrap() = Some("issuer2.example".into());
    assert!(
        oauth
            .challenge(unbound(), challenge(401, "Bearer", None))
            .await
            .is_err()
    );
    assert_eq!(
        host.network.tokens().len(),
        tokens,
        "no renewal against the old issuer"
    );
    assert_eq!(
        host.store.binding().unwrap().metadata.issuer,
        "https://issuer.example"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn caller_dropped_after_response_before_polling_still_commits() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.store.expire();
    host.network.reply(
        200,
        json!({"access_token":"a","refresh_token":"rotated","token_type":"Bearer"}),
    );
    let mut caller = Box::pin(oauth.credential(context()));
    // Poll the caller only until its exchange has been spawned.
    // (Yield between polls so the runtime drives timers in the fake store.)
    loop {
        assert!(futures::poll!(&mut caller).is_pending());
        if host.store.token().refresh_in_flight {
            break;
        }
        tokio::task::yield_now().await;
    }
    // The exchange runs to completion while the caller is not polled.
    tokio::time::timeout(Duration::from_secs(2), async {
        while host.store.token().refresh_in_flight {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached exchange committed");
    drop(caller);
    let token = host.store.token();
    assert_eq!(token.refresh_token.as_deref(), Some("rotated"));
    assert_eq!(token.access_token, "a");
    assert!(!token.access_rejected);
}

#[tokio::test]
async fn slow_issuer_then_slow_store_commit_within_fresh_budget_after_drop() {
    let host = Host::new();
    // Each phase fits the commit timeout; together they exceed it.
    let oauth = host.pkce(|c| c.commit_timeout(Duration::from_millis(300)));
    host.seed(&oauth, context()).await;
    host.store.expire();
    host.network.reply(
        200,
        json!({"access_token":"a","refresh_token":"rotated","token_type":"Bearer"}),
    );
    host.network.token_delay.store(200, Ordering::SeqCst);
    let delay = host.store.write_delay.clone();
    *host.network.on_token.lock().unwrap() =
        Some(Box::new(move || delay.store(200, Ordering::SeqCst)));
    let caller = tokio::time::timeout(Duration::from_millis(50), oauth.credential(context()));
    assert!(caller.await.is_err());
    tokio::time::sleep(Duration::from_millis(700)).await;
    let token = host.store.token();
    assert_eq!(token.refresh_token.as_deref(), Some("rotated"));
    assert!(!token.refresh_in_flight);
}

/// Blank or null `scope` inherits on every token path (PKCE initial, refresh,
/// client credentials); malformed grammar or a non-string fails basic validity.
#[tokio::test]
async fn response_scope_blank_inherits_and_malformed_fails_every_path() {
    let blank = [json!(""), json!(" \t\r\n"), Value::Null];
    let malformed = [
        json!("read  write"),
        json!(" read"),
        json!("read "),
        json!("read\twrite"),
        json!("read\nwrite"),
        json!(123),
        json!(true),
        json!(["read"]),
        json!({"read": true}),
    ];
    let body = |scope: &Value| json!({"access_token":"a","refresh_token":"r","token_type":"Bearer","scope":scope});
    // PKCE initial: requested is ["read"].
    for (scope, ok) in blank
        .iter()
        .map(|s| (s, true))
        .chain(malformed.iter().map(|s| (s, false)))
    {
        let host = Host::new();
        let oauth = host.pkce(|c| c);
        let pending = login(oauth.prepare(context(), budget()).await.unwrap());
        host.network.reply(200, body(scope));
        let result = oauth
            .complete(context(), callback(&pending), budget())
            .await;
        if ok {
            result.unwrap();
            assert_eq!(host.store.token().scopes, scopes(&["read"]), "{scope}");
        } else {
            assert_eq!(code(result), AuthErrorCode::ProviderFailed, "{scope}");
            assert!(
                host.store.grant().and_then(|g| g.token).is_none(),
                "{scope}"
            );
        }
    }
    // Refresh inherits the previous grant.
    for (scope, ok) in blank
        .iter()
        .map(|s| (s, true))
        .chain(malformed.iter().map(|s| (s, false)))
    {
        let host = Host::new();
        let oauth = host.pkce(|c| c);
        host.seed(&oauth, context()).await;
        host.store.expire();
        host.network.reply(200, body(scope));
        let result = oauth.credential(context()).await;
        let token = host.store.token();
        if ok {
            assert_eq!(result.unwrap().unwrap().token, "a", "{scope}");
            assert_eq!(token.scopes, scopes(&["read"]), "{scope}");
        } else {
            assert_eq!(code(result), AuthErrorCode::ProviderFailed, "{scope}");
            assert_eq!(token.refresh_token.as_deref(), Some("r"), "{scope}");
            assert!(token.access_rejected && !token.refresh_in_flight, "{scope}");
        }
    }
    // Client credentials: requested ["read"] within ceiling ["read", "write"].
    for (scope, ok) in blank
        .iter()
        .map(|s| (s, true))
        .chain(malformed.iter().map(|s| (s, false)))
    {
        let host = Host::new();
        let oauth = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
        host.network.reply(200, body(scope));
        let result = oauth.credential(cc_context()).await;
        if ok {
            assert_eq!(result.unwrap().unwrap().token, "a", "{scope}");
            assert_eq!(host.store.token().scopes, scopes(&["read"]), "{scope}");
        } else {
            assert_eq!(code(result), AuthErrorCode::ProviderFailed, "{scope}");
            assert!(
                host.store.grant().and_then(|g| g.token).is_none(),
                "{scope}"
            );
        }
    }
}

#[test]
fn response_scope_grammar() {
    let inherited = scopes(&["read"]);
    let parse = |raw: &str| super::response_scopes(Some(raw.split(' ').collect()), &inherited);
    assert_eq!(
        super::response_scopes(None, &inherited),
        Some(inherited.clone())
    );
    for blank in ["", " ", "\t", "\r\n", " \t\r\n "] {
        assert_eq!(parse(blank), Some(inherited.clone()), "{blank:?}");
    }
    assert_eq!(parse("write"), Some(scopes(&["write"])));
    assert_eq!(parse("a b"), Some(scopes(&["a", "b"])));
    for bad in [
        "a  b", " a", "a ", "a\tb", "a\rb", "a\nb", "\ta", "a\"b", "a\\b",
    ] {
        assert_eq!(parse(bad), None, "{bad:?}");
    }
}

/// Successful prepares are counted per backend, purpose and normalized
/// destination; a prepare that only creates a login is not counted.
#[tokio::test]
async fn preparations_match_normalized_endpoint() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    assert_eq!(oauth.preparations(&context()), 0);
    host.network.reply(
        200,
        json!({"access_token":"a","refresh_token":"r","token_type":"Bearer","expires_in":3600}),
    );
    oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    ready(oauth.prepare(context(), budget()).await.unwrap());
    let variant = AuthContext {
        destination: "HTTPS://API.Example:443/hooks".into(),
        authentication: None,
        ..context()
    };
    assert_eq!(oauth.preparations(&variant), 2);
    let other = AuthContext {
        destination: "https://api.example/other".into(),
        ..context()
    };
    assert_eq!(oauth.preparations(&other), 0);
    let upload = AuthContext {
        purpose: AuthPurpose::Upload,
        ..context()
    };
    assert_eq!(oauth.preparations(&upload), 0);
}
