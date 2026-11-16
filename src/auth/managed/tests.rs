//! All listeners, TLS policy, storage and workers in these tests belong to the host.
use super::*;
use crate::adapters::registered::AuthPurpose;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

fn budget() -> OperationBudget {
    OperationBudget::until(Instant::now() + Duration::from_secs(5))
}
#[derive(Default)]
struct Store {
    records: Arc<AsyncMutex<BTreeMap<SessionKey, SessionRecord>>>,
    rejected: Arc<AtomicUsize>,
}
struct Guard {
    records: OwnedMutexGuard<BTreeMap<SessionKey, SessionRecord>>,
    key: SessionKey,
    rejected: Arc<AtomicUsize>,
}
impl CredentialStore for Store {
    fn acquire(
        &self,
        key: SessionKey,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<Box<dyn CredentialGuard>, HookError>> {
        Box::pin(async move {
            Ok(Box::new(Guard {
                records: self.records.clone().lock_owned().await,
                key,
                rejected: self.rejected.clone(),
            }) as Box<dyn CredentialGuard>)
        })
    }
}
impl CredentialGuard for Guard {
    fn load(&mut self) -> LocalFuture<'_, Result<Option<SessionRecord>, HookError>> {
        Box::pin(async { Ok(self.records.get(&self.key).cloned()) })
    }
    fn compare_and_swap(
        &mut self,
        expected: Option<String>,
        replacement: SessionRecord,
    ) -> LocalFuture<'_, Result<bool, HookError>> {
        Box::pin(async move {
            if self.records.get(&self.key).map(|r| r.version().to_owned()) != expected {
                return Ok(false);
            }
            self.records.insert(self.key.clone(), replacement);
            Ok(true)
        })
    }
    fn on_refresh_rejected(&mut self, _: String) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async {
            self.rejected.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}
struct Policy;
impl OAuthPolicy for Policy {
    fn approve_endpoints(&self, context: EndpointTrust<'_>) -> Result<(), HookError> {
        let issuer = Url::parse(&context.metadata.issuer).unwrap();
        for endpoint in std::iter::once(&context.metadata.token_endpoint)
            .chain(context.metadata.authorization_endpoint.iter())
        {
            if Url::parse(endpoint).unwrap().origin() != issuer.origin() {
                return Err(fail(AuthErrorCode::UntrustedDestination));
            }
        }
        Ok(())
    }
    fn select(
        &self,
        _: &AuthTarget,
        resource: &ResourceMetadata,
        _: &[String],
    ) -> Result<TrustDecision, HookError> {
        Ok(TrustDecision {
            issuer: resource.authorization_servers[0].clone(),
            scopes: vec!["read".into()],
        })
    }
}
#[derive(Clone)]
struct Seen {
    path: String,
    body: String,
    authorization: bool,
}
struct Fixture {
    base: String,
    network: Arc<Network>,
    seen: Arc<Mutex<Vec<Seen>>>,
    reply: Arc<Mutex<(u16, Value)>>,
    metadata_replies: Arc<Mutex<BTreeMap<String, (u16, String)>>>,
    denied_token: Arc<AtomicBool>,
    delay: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
struct Network {
    client: reqwest::Client,
    port: u16,
    sends: AtomicUsize,
}
impl Network {
    fn allowed(&self, url: &Url) -> Result<(), HookError> {
        if url.scheme() != "https"
            || url.host_str() != Some("oauth.test")
            || url.port_or_known_default() != Some(self.port)
        {
            return Err(fail(AuthErrorCode::UntrustedDestination));
        }
        Ok(())
    }
}
impl OAuthNetwork for Network {
    fn refresh_failure_is_safe(&self, response: &OAuthResponse) -> bool {
        // Fixture issuer contract: this exact response occurs before processing grants.
        response.status().as_u16() == 503
            && serde_json::from_slice::<Value>(response.body()).ok()
                == Some(json!({"error":"temporarily_unavailable"}))
    }
    fn check(
        &self,
        endpoint: Url,
        _: EndpointUse,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async move { self.allowed(&endpoint) })
    }
    fn send(
        &self,
        request: oauth2::HttpRequest,
        _: EndpointUse,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<oauth2::HttpResponse, HookError>> {
        Box::pin(async move {
            let url = Url::parse(&request.uri().to_string()).unwrap();
            self.allowed(&url)?;
            self.sends.fetch_add(1, Ordering::SeqCst);
            let (parts, body) = request.into_parts();
            let mut response = self
                .client
                .request(parts.method, url)
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|_| fail(AuthErrorCode::ProviderFailed))?;
            let mut builder = oauth2::http::Response::builder().status(response.status());
            *builder.headers_mut().unwrap() = response.headers().clone();
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| fail(AuthErrorCode::ProviderFailed))?
            {
                if bytes.len() + chunk.len() > 1024 * 1024 {
                    return Err(fail(AuthErrorCode::ProviderFailed));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(builder.body(bytes).unwrap())
        })
    }
}
impl Fixture {
    fn new() -> Self {
        let server = tiny_http::Server::https(
            "127.0.0.1:0",
            tiny_http::SslConfig {
                certificate: include_bytes!("testdata/cert.pem").to_vec(),
                private_key: include_bytes!("testdata/key.pem").to_vec(),
            },
        )
        .unwrap();
        let addr: SocketAddr = server.server_addr().to_ip().unwrap();
        let base = format!("https://oauth.test:{}", addr.port());
        let mut roots = rustls::RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut &include_bytes!("testdata/ca.pem")[..]) {
            roots.add(certificate.unwrap()).unwrap();
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve("oauth.test", addr)
            .build()
            .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let reply = Arc::new(Mutex::new((200, token("first", true))));
        let metadata_replies = Arc::new(Mutex::new(BTreeMap::<String, (u16, String)>::new()));
        let metadata = metadata_replies.clone();
        let denied_token = Arc::new(AtomicBool::new(false));
        let delay = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (s, r, d, wait, done, origin) = (
            seen.clone(),
            reply.clone(),
            denied_token.clone(),
            delay.clone(),
            stop.clone(),
            base.clone(),
        );
        let worker = thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let Some(mut request) = server.recv_timeout(Duration::from_millis(20)).unwrap()
                else {
                    continue;
                };
                let path = request.url().to_owned();
                let authorization = request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("Authorization"));
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body).unwrap();
                s.lock().unwrap().push(Seen {
                    path: path.clone(),
                    body,
                    authorization,
                });
                let (status, value) = if path == "/token" {
                    if wait.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_millis(300));
                    }
                    r.lock().unwrap().clone()
                } else if path == "/meta"
                    || path.starts_with("/.well-known/oauth-protected-resource")
                {
                    let default_resource = if path == "/.well-known/oauth-protected-resource" {
                        origin.clone()
                    } else if path == "/meta" {
                        format!("{origin}/resource")
                    } else {
                        format!(
                            "{origin}{}",
                            path.strip_prefix("/.well-known/oauth-protected-resource")
                                .unwrap()
                        )
                    };
                    let (status, resource) = metadata
                        .lock()
                        .unwrap()
                        .get(&path)
                        .cloned()
                        .unwrap_or((200, default_resource));
                    (
                        status,
                        json!({"resource":resource,"authorization_servers":[format!("{origin}/tenant")]}),
                    )
                } else if path == "/tenant/.well-known/openid-configuration" {
                    (
                        200,
                        json!({"issuer":format!("{origin}/tenant"),"authorization_endpoint":format!("{origin}/authorize"),
                        "token_endpoint":if d.load(Ordering::SeqCst) { "https://denied.invalid/token".into() } else { format!("{origin}/token") },
                        "grant_types_supported":["authorization_code","refresh_token","client_credentials"],
                        "token_endpoint_auth_methods_supported":["none","client_secret_basic"],"code_challenge_methods_supported":["S256"],"authorization_response_iss_parameter_supported":true}),
                    )
                } else {
                    (404, json!({}))
                };
                let response = tiny_http::Response::from_string(value.to_string())
                    .with_status_code(status)
                    .with_header(
                        tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                    );
                let _ = request.respond(response);
            }
        });
        Self {
            base,
            network: Arc::new(Network {
                client,
                port: addr.port(),
                sends: AtomicUsize::new(0),
            }),
            seen,
            reply,
            metadata_replies,
            denied_token,
            delay,
            stop,
            worker: Some(worker),
        }
    }
    fn owner(&self, store: Arc<Store>, namespace: &str, flow: OAuthFlow) -> ManagedOAuth {
        let mut config = OAuthClientConfig::new(namespace, "client", flow)
            .scopes(vec!["read".into()], vec!["read".into()]);
        if flow == OAuthFlow::AuthorizationCodePkce {
            config = config.redirect_uri("https://localhost/callback");
        } else {
            config = config.client_secret(
                "secret-ref",
                ClientSecret::new("fixture-secret".into()),
                TokenAuthMethod::ClientSecretBasic,
            );
        }
        ManagedOAuth::new(config, self.network.clone(), Arc::new(Policy), store).unwrap()
    }
    fn context(&self) -> AuthContext {
        AuthContext {
            backend_id: "backend".into(),
            authentication: None,
            destination: format!("{}/resource", self.base),
            purpose: AuthPurpose::Event,
            deadline: budget().deadline(),
        }
    }
    fn token_requests(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == "/token")
            .cloned()
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn token(access: &str, refresh: bool) -> Value {
    let mut v =
        json!({"access_token":access,"token_type":"Bearer","expires_in":3600,"scope":"read"});
    if refresh {
        v["refresh_token"] = "original-refresh".into();
    }
    v
}
fn login(preparation: Preparation) -> PendingLogin {
    match preparation {
        Preparation::InteractionRequired(p) => p,
        _ => panic!("expected login"),
    }
}
fn ready(preparation: Preparation) -> BearerCredential {
    match preparation {
        Preparation::Ready(p) => p,
        _ => panic!("expected credential"),
    }
}
fn callback(pending: &PendingLogin) -> Url {
    let state = pending
        .url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    let mut url = Url::parse("https://localhost/callback").unwrap();
    url.query_pairs_mut()
        .append_pair("state", &state)
        .append_pair("code", "test-code")
        .append_pair(
            "iss",
            &format!("{}/tenant", pending.url.origin().ascii_serialization()),
        );
    url
}
async fn seed(f: &Fixture, owner: &ManagedOAuth) -> BearerCredential {
    let p = login(owner.prepare(f.context(), budget()).await.unwrap());
    let url = callback(&p);
    owner.complete(p, url, budget()).await.unwrap()
}
async fn expire(store: &Store) {
    for record in store.records.lock().await.values_mut() {
        record.token.as_mut().unwrap().expires_at = 0;
    }
}
fn form(request: &Seen) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(request.body.as_bytes())
        .into_owned()
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn pkce_deduplicates_validates_callback_and_exchanges_resource_bound_verifier() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    let p = login(owner.prepare(f.context(), budget()).await.unwrap());
    let q = login(owner.prepare(f.context(), budget()).await.unwrap());
    assert_eq!(p.url, q.url);
    assert_eq!(p.id, q.id);
    let params: BTreeMap<_, _> = p.url.query_pairs().into_owned().collect();
    assert_eq!(params["code_challenge_method"], "S256");
    assert_eq!(params["resource"], f.context().destination);
    let saved = store
        .records
        .lock()
        .await
        .values()
        .next()
        .unwrap()
        .pending
        .clone()
        .unwrap();
    assert_eq!(
        params["code_challenge"],
        PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(
            saved.verifier.clone()
        ))
        .as_str()
    );
    for query in [
        "state=wrong&code=x",
        "state=wrong&state=other&code=x",
        "code=x",
    ] {
        let p = login(owner.prepare(f.context(), budget()).await.unwrap());
        assert!(
            owner
                .complete(
                    p,
                    Url::parse(&format!("https://localhost/callback?{query}")).unwrap(),
                    budget()
                )
                .await
                .is_err()
        );
    }
    let p = login(owner.prepare(f.context(), budget()).await.unwrap());
    let mut wrong_path = callback(&p);
    wrong_path.set_path("/other");
    assert!(owner.complete(p, wrong_path, budget()).await.is_err());
    let p = login(owner.prepare(f.context(), budget()).await.unwrap());
    let mut wrong_issuer = callback(&p);
    let state = saved.state.clone();
    wrong_issuer.set_query(None);
    wrong_issuer
        .query_pairs_mut()
        .append_pair("state", &state)
        .append_pair("code", "x")
        .append_pair("iss", "https://wrong.invalid");
    assert!(owner.complete(p, wrong_issuer, budget()).await.is_err());
    assert!(f.token_requests().is_empty());
    let missing_issuer = login(owner.prepare(f.context(), budget()).await.unwrap());
    let mut missing = callback(&missing_issuer);
    let pairs: Vec<_> = missing
        .query_pairs()
        .filter(|(key, _)| key != "iss")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    missing.set_query(None);
    missing.query_pairs_mut().extend_pairs(pairs);
    assert!(
        owner
            .complete(missing_issuer, missing, budget())
            .await
            .is_err()
    );
    let url = callback(&q);
    assert_eq!(
        owner.complete(q, url, budget()).await.unwrap().token,
        "first"
    );
    let requests = f.token_requests();
    let fields = form(&requests[0]);
    assert_eq!(fields["code_verifier"], saved.verifier);
    assert_eq!(fields["resource"], f.context().destination);
    assert_eq!(fields["grant_type"], "authorization_code");
    assert!(
        store
            .records
            .lock()
            .await
            .values()
            .next()
            .unwrap()
            .pending
            .is_none()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn client_credentials_expiry_and_cache() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "one", OAuthFlow::ClientCredentials);
    *f.reply.lock().unwrap() = (200, token("cc", false));
    let first = ready(owner.prepare(f.context(), budget()).await.unwrap());
    assert_eq!(first.token, "cc");
    assert_eq!(
        ready(owner.prepare(f.context(), budget()).await.unwrap()).attempt_id,
        first.attempt_id
    );
    assert_eq!(f.token_requests().len(), 1);
    expire(&store).await;
    *f.reply.lock().unwrap() = (200, token("renewed", false));
    assert_eq!(
        ready(owner.prepare(f.context(), budget()).await.unwrap()).token,
        "renewed"
    );
    let requests = f.token_requests();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|r| r.authorization));
    let fields = form(&requests[0]);
    assert_eq!(fields["grant_type"], "client_credentials");
    assert_eq!(fields["resource"], f.context().destination);
    expire(&store).await;
    let mut short = token("too-short", false);
    short["expires_in"] = 30.into();
    *f.reply.lock().unwrap() = (200, short);
    assert!(owner.prepare(f.context(), budget()).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn serialized_refresh_preserves_resource_and_ignores_stale_401() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    let first = seed(&f, &owner).await;
    expire(&store).await;
    *f.reply.lock().unwrap() = (200, token("refreshed", false));
    let (a, b) = futures::join!(
        owner.prepare(f.context(), budget()),
        owner.prepare(f.context(), budget())
    );
    let a = ready(a.unwrap());
    let b = ready(b.unwrap());
    assert_eq!(a.attempt_id, b.attempt_id);
    assert_ne!(a.attempt_id, first.attempt_id);
    let requests = f.token_requests();
    assert_eq!(requests.len(), 2);
    let fields = form(&requests[1]);
    assert_eq!(fields["grant_type"], "refresh_token");
    assert_eq!(fields["resource"], f.context().destination);
    assert_eq!(fields["refresh_token"], "original-refresh");
    owner
        .challenge(
            f.context(),
            AuthChallenge {
                status: 401,
                headers: BTreeMap::new(),
                attempt_id: Some(first.attempt_id),
            },
        )
        .await
        .unwrap();
    assert_eq!(f.token_requests().len(), 2);
    assert_eq!(
        store
            .records
            .lock()
            .await
            .values()
            .next()
            .unwrap()
            .token
            .as_ref()
            .unwrap()
            .refresh_token
            .as_deref(),
        Some("original-refresh")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn refresh_transient_retains_secret_and_definitive_rejection_calls_hook_once() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    seed(&f, &owner).await;
    expire(&store).await;
    *f.reply.lock().unwrap() = (503, json!({"error":"temporarily_unavailable"}));
    assert!(owner.prepare(f.context(), budget()).await.is_err());
    {
        let records = store.records.lock().await;
        let t = records.values().next().unwrap().token.as_ref().unwrap();
        assert_eq!(t.refresh_token.as_deref(), Some("original-refresh"));
        assert!(!t.refresh_in_flight);
        assert!(!t.rejected);
    }
    assert_eq!(store.rejected.load(Ordering::SeqCst), 0);
    *f.reply.lock().unwrap() = (400, json!({"error":"invalid_grant"}));
    assert!(owner.prepare(f.context(), budget()).await.is_err());
    assert_eq!(store.rejected.load(Ordering::SeqCst), 1);
    assert!(
        store
            .records
            .lock()
            .await
            .values()
            .next()
            .unwrap()
            .token
            .as_ref()
            .unwrap()
            .rejected
    );
    let _ = owner.prepare(f.context(), budget()).await;
    assert_eq!(store.rejected.load(Ordering::SeqCst), 1);
    assert_eq!(f.token_requests().len(), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_refresh_releases_guard_and_keeps_uncertainty_marker() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    seed(&f, &owner).await;
    expire(&store).await;
    f.delay.store(true, Ordering::SeqCst);
    {
        let operation = owner.prepare(f.context(), budget());
        tokio::pin!(operation);
        // Cancel only after the actual TLS server has received the refresh request.
        let observed = async {
            loop {
                if f.token_requests().len() == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };
        tokio::select! { _ = &mut operation => panic!("refresh unexpectedly completed"), _ = observed => {} }
    }
    let records = tokio::time::timeout(Duration::from_millis(100), store.records.lock())
        .await
        .expect("cancelled refresh must release store ownership");
    let token = records.values().next().unwrap().token.as_ref().unwrap();
    assert!(token.refresh_in_flight);
    assert_eq!(token.refresh_token.as_deref(), Some("original-refresh"));
    drop(records);
    assert_eq!(store.rejected.load(Ordering::SeqCst), 0);
    assert!(owner.prepare(f.context(), budget()).await.is_err());
    assert_eq!(f.token_requests().len(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn namespace_destination_upload_isolation_and_login_cancellation() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let a = f.owner(store.clone(), "a", OAuthFlow::AuthorizationCodePkce);
    let b = f.owner(store.clone(), "b", OAuthFlow::AuthorizationCodePkce);
    let p = login(a.prepare(f.context(), budget()).await.unwrap());
    let q = login(b.prepare(f.context(), budget()).await.unwrap());
    assert_ne!(p.id, q.id);
    let mut upload = f.context();
    upload.purpose = AuthPurpose::Upload;
    let u = login(a.prepare(upload, budget()).await.unwrap());
    assert_ne!(p.id, u.id);
    let mut destination = f.context();
    destination.destination.push_str("?separate=1");
    // The explicit resource must also match the query-bearing retrieval identity.
    destination.authentication = Some(
        json!({"type":"oauth","flow":"authorization_code_pkce","issuer":format!("{}/tenant", f.base),"clientId":"client","resource":destination.destination,"scopes":["read"]}),
    );
    let d = login(a.prepare(destination, budget()).await.unwrap());
    assert_ne!(p.id, d.id);
    assert_eq!(store.records.lock().await.len(), 4);
    let old_id = p.id.clone();
    let stale = login(a.prepare(f.context(), budget()).await.unwrap());
    a.cancel_login(p, budget()).await.unwrap();
    let replacement = login(a.prepare(f.context(), budget()).await.unwrap());
    assert_ne!(replacement.id, old_id);
    a.cancel_login(stale, budget()).await.unwrap();
    let unchanged = login(a.prepare(f.context(), budget()).await.unwrap());
    assert_eq!(replacement.id, unchanged.id);
    assert!(
        store
            .records
            .lock()
            .await
            .values()
            .filter(|r| r.pending.is_some())
            .count()
            == 4
    );
}

#[tokio::test(flavor = "current_thread")]
async fn denied_advertised_endpoint_never_receives_secrets_or_network() {
    let f = Fixture::new();
    f.denied_token.store(true, Ordering::SeqCst);
    let store = Arc::new(Store::default());
    let owner = f.owner(store, "one", OAuthFlow::ClientCredentials);
    assert!(owner.prepare(f.context(), budget()).await.is_err());
    assert!(f.token_requests().is_empty());
    {
        let seen = f.seen.lock().unwrap();
        assert!(seen.iter().all(|s| s.body.is_empty() && !s.authorization));
        assert_eq!(f.network.sends.load(Ordering::SeqCst), seen.len());
    }
    assert!(
        f.network
            .check(
                Url::parse("https://oauth.test:1/token").unwrap(),
                EndpointUse::Token,
                budget()
            )
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn unbound_initial_none_then_challenge_hint_and_well_known_order() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store, "one", OAuthFlow::AuthorizationCodePkce);
    assert!(owner.credential(f.context()).await.unwrap().is_none());
    assert!(f.seen.lock().unwrap().is_empty());
    let headers = BTreeMap::from([(
        "WWW-Authenticate".into(),
        format!(
            "Bearer resource_metadata=\"{}/meta\", scope=\"read\"",
            f.base
        ),
    )]);
    assert!(
        owner
            .challenge(
                f.context(),
                AuthChallenge {
                    status: 401,
                    headers,
                    attempt_id: None
                }
            )
            .await
            .is_err()
    );
    let paths: Vec<_> = f
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(
        paths,
        [
            "/meta",
            "/.well-known/oauth-authorization-server/tenant",
            "/.well-known/openid-configuration/tenant",
            "/tenant/.well-known/openid-configuration"
        ]
    );
    f.seen.lock().unwrap().clear();
    let fresh = f.owner(
        Arc::new(Store::default()),
        "fresh",
        OAuthFlow::AuthorizationCodePkce,
    );
    let _ = fresh.prepare(f.context(), budget()).await.unwrap();
    let paths: Vec<_> = f
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(
        &paths[..2],
        [
            "/.well-known/oauth-protected-resource/resource",
            "/.well-known/oauth-authorization-server/tenant"
        ]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_pkce_exchange_requires_matching_generation_cancellation() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    let p = login(owner.prepare(f.context(), budget()).await.unwrap());
    let stale = p.clone();
    let url = callback(&p);
    f.delay.store(true, Ordering::SeqCst);
    {
        let operation = owner.complete(p, url, budget());
        tokio::pin!(operation);
        let observed = async {
            loop {
                if f.token_requests().len() == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };
        tokio::select! {
            _ = &mut operation => panic!("exchange unexpectedly completed"),
            _ = tokio::time::sleep(Duration::from_secs(2)) => panic!("exchange never reached fixture"),
            _ = observed => {}
        }
    }
    let records = tokio::time::timeout(Duration::from_millis(100), store.records.lock())
        .await
        .expect("dropped exchange must release store ownership");
    assert!(
        records
            .values()
            .next()
            .unwrap()
            .pending
            .as_ref()
            .unwrap()
            .in_flight
    );
    drop(records);
    let uncertain = login(owner.prepare(f.context(), budget()).await.unwrap());
    assert!(uncertain.exchange_is_uncertain());
    assert!(uncertain.authorization_url().is_none());
    assert_eq!(uncertain.id, stale.id);
    assert!(
        owner
            .complete(uncertain.clone(), callback(&uncertain), budget())
            .await
            .is_err()
    );
    assert_eq!(f.token_requests().len(), 1);
    owner.cancel_login(uncertain, budget()).await.unwrap();
    let fresh = login(owner.prepare(f.context(), budget()).await.unwrap());
    assert_ne!(fresh.id, stale.id);
    assert!(!fresh.exchange_is_uncertain());
    assert!(fresh.authorization_url().is_some());
    owner.cancel_login(stale, budget()).await.unwrap();
    assert_eq!(
        login(owner.prepare(f.context(), budget()).await.unwrap()).id,
        fresh.id
    );
    assert_eq!(f.token_requests().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_503_refresh_is_uncertain_and_never_retransmitted() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    seed(&f, &owner).await;
    expire(&store).await;
    // Valid JSON, but not an OAuth error or the issuer's safe-retry contract.
    *f.reply.lock().unwrap() = (503, json!({"upstream":"original-refresh"}));
    let error = owner.prepare(f.context(), budget()).await.err().unwrap();
    assert!(!format!("{error:?}").contains("original-refresh"));
    {
        let records = store.records.lock().await;
        let record = records.values().next().unwrap();
        assert!(record.refresh_is_uncertain());
        let token = record.token.as_ref().unwrap();
        assert_eq!(token.refresh_token.as_deref(), Some("original-refresh"));
        assert!(!token.rejected);
    }
    *f.reply.lock().unwrap() = (200, token("must-not-be-requested", true));
    for _ in 0..2 {
        assert!(owner.prepare(f.context(), budget()).await.is_err());
    }
    assert_eq!(f.token_requests().len(), 2);
    assert_eq!(store.rejected.load(Ordering::SeqCst), 0);
}

struct RequirementPolicy;
impl OAuthPolicy for RequirementPolicy {
    fn approve_endpoints(&self, context: EndpointTrust<'_>) -> Result<(), HookError> {
        Policy.approve_endpoints(context)
    }
    fn select(
        &self,
        _: &AuthTarget,
        resource: &ResourceMetadata,
        requirements: &[String],
    ) -> Result<TrustDecision, HookError> {
        let mut scopes = vec!["read".to_owned()];
        scopes.extend_from_slice(requirements);
        scopes.sort();
        scopes.dedup();
        Ok(TrustDecision {
            issuer: resource.authorization_servers[0].clone(),
            scopes,
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn case_variant_challenges_preserve_policy_scopes_through_completion_and_increase() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = ManagedOAuth::new(
        OAuthClientConfig::new("one", "client", OAuthFlow::AuthorizationCodePkce)
            .redirect_uri("https://localhost/callback")
            .scopes(vec!["read".into()], vec!["read".into(), "write".into()]),
        f.network.clone(),
        Arc::new(RequirementPolicy),
        store.clone(),
    )
    .unwrap();
    let initial = seed(&f, &owner).await;
    let headers = BTreeMap::from([
        (
            "WWW-Authenticate".into(),
            format!("Bearer resource_metadata=\"{}/meta\"", f.base),
        ),
        ("www-authenticate".into(), "Bearer scope=\"write\"".into()),
    ]);
    assert!(
        owner
            .challenge(
                f.context(),
                AuthChallenge {
                    status: 401,
                    headers,
                    attempt_id: Some(initial.attempt_id.clone()),
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        f.token_requests().len(),
        1,
        "scope increase requires consent, not refresh"
    );
    let pending = login(owner.prepare(f.context(), budget()).await.unwrap());
    let scopes = pending
        .url
        .query_pairs()
        .find(|(k, _)| k == "scope")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(scopes, "read write");
    {
        let records = store.records.lock().await;
        let record = records.values().next().unwrap();
        assert_eq!(record.challenge_scopes, ["write"]);
        assert!(
            record.token.is_none(),
            "old narrower token must not survive scope increase"
        );
    }
    let mut response = token("expanded", true);
    response["scope"] = "read write".into();
    *f.reply.lock().unwrap() = (200, response);
    let url = callback(&pending);
    let credential = owner.complete(pending, url, budget()).await.unwrap();
    assert_eq!(credential.token, "expanded");
    assert_ne!(credential.attempt_id, initial.attempt_id);
    assert_eq!(
        ready(owner.prepare(f.context(), budget()).await.unwrap()).token,
        "expanded"
    );
    let requests = f.token_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(form(&requests[1])["grant_type"], "authorization_code");
    assert!(f.seen.lock().unwrap().iter().any(|s| s.path == "/meta"));
}

#[tokio::test(flavor = "current_thread")]
async fn expired_budget_and_store_wait_are_redacted_and_release_waiter() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    let held = store.records.lock().await;
    let expired = OperationBudget::until(Instant::now() - Duration::from_millis(1));
    let error = owner.prepare(f.context(), expired).await.err().unwrap();
    assert_eq!(
        error.code(),
        crate::generated::DeliveryDiagnosticCode::DeadlineExceeded
    );
    let short = OperationBudget::until(Instant::now() + Duration::from_millis(20));
    let error = owner.prepare(f.context(), short).await.err().unwrap();
    assert_eq!(
        error.code(),
        crate::generated::DeliveryDiagnosticCode::DeadlineExceeded
    );
    assert!(!format!("{error:?}").contains("fixture-secret"));
    assert_eq!(f.network.sends.load(Ordering::SeqCst), 0);
    drop(held);
    let p = login(owner.prepare(f.context(), budget()).await.unwrap());
    owner.cancel_login(p, budget()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), store.records.lock())
            .await
            .is_ok()
    );

    let error = budget()
        .run(async {
            Err::<(), _>(HookError::new(
                "fixture-secret original-refresh https://oauth.test/private",
            ))
        })
        .await
        .unwrap_err();
    let diagnostic = format!("{error:?} {error}");
    for secret in ["fixture-secret", "original-refresh", "oauth.test/private"] {
        assert!(!diagnostic.contains(secret));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn saved_pkce_grant_cannot_be_reopened_as_client_credentials() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let pkce = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    seed(&f, &pkce).await;
    let machine = f.owner(store.clone(), "one", OAuthFlow::ClientCredentials);
    let sends = f.network.sends.load(Ordering::SeqCst);
    for expired in [false, true] {
        if expired {
            expire(&store).await;
        }
        let error = machine.prepare(f.context(), budget()).await.err().unwrap();
        assert_eq!(error.auth_code(), Some(AuthErrorCode::InvalidConfiguration));
        let error = machine.credential(f.context()).await.err().unwrap();
        assert_eq!(error.auth_code(), Some(AuthErrorCode::InvalidConfiguration));
        assert_eq!(f.network.sends.load(Ordering::SeqCst), sends);
        assert_eq!(f.token_requests().len(), 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn redirect_change_replaces_pending_generation_and_rejects_stale_callbacks() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let old_owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    let old = login(old_owner.prepare(f.context(), budget()).await.unwrap());
    let changed = ManagedOAuth::new(
        OAuthClientConfig::new("one", "client", OAuthFlow::AuthorizationCodePkce)
            .scopes(vec!["read".into()], vec!["read".into()])
            .redirect_uri("https://localhost/new-callback"),
        f.network.clone(),
        Arc::new(Policy),
        store.clone(),
    )
    .unwrap();
    let mut moved_callback = callback(&old);
    moved_callback.set_path("/new-callback");
    assert!(
        changed
            .complete(old.clone(), moved_callback.clone(), budget())
            .await
            .is_err()
    );
    let fresh = login(changed.prepare(f.context(), budget()).await.unwrap());
    assert_ne!(fresh.id, old.id);
    assert_eq!(
        fresh
            .url
            .query_pairs()
            .find(|(key, _)| key == "redirect_uri")
            .unwrap()
            .1,
        "https://localhost/new-callback"
    );
    assert!(
        changed
            .complete(old.clone(), callback(&old), budget())
            .await
            .is_err()
    );
    assert!(
        changed
            .complete(old.clone(), moved_callback, budget())
            .await
            .is_err()
    );
    assert!(
        old_owner
            .complete(old.clone(), callback(&old), budget())
            .await
            .is_err()
    );
    assert!(f.token_requests().is_empty());
    assert_eq!(
        login(changed.prepare(f.context(), budget()).await.unwrap()).id,
        fresh.id
    );
    let mut url = callback(&fresh);
    url.set_path("/new-callback");
    changed.complete(fresh, url, budget()).await.unwrap();
    assert_eq!(
        form(&f.token_requests()[0])["redirect_uri"],
        "https://localhost/new-callback"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_access_without_refresh_stays_rejected_while_login_pending() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    *f.reply.lock().unwrap() = (200, token("rejected-access", false));
    let first = seed(&f, &owner).await;
    assert!(
        owner
            .challenge(
                f.context(),
                AuthChallenge {
                    status: 401,
                    headers: BTreeMap::new(),
                    attempt_id: Some(first.attempt_id),
                }
            )
            .await
            .is_err()
    );
    {
        let records = store.records.lock().await;
        let record = records.values().next().unwrap();
        let token = record.token.as_ref().unwrap();
        assert!(token.access_rejected);
        assert!(!token.rejected);
        assert!(token.refresh_token.is_none());
        assert!(record.pending.is_some());
    }
    let pending = login(owner.prepare(f.context(), budget()).await.unwrap());
    let error = owner.credential(f.context()).await.err().unwrap();
    assert_eq!(error.auth_code(), Some(AuthErrorCode::InteractionRequired));
    assert_eq!(
        login(owner.prepare(f.context(), budget()).await.unwrap()).id,
        pending.id
    );
    assert_eq!(f.token_requests().len(), 1);
    *f.reply.lock().unwrap() = (200, token("replacement", false));
    let url = callback(&pending);
    owner.complete(pending, url, budget()).await.unwrap();
    assert_eq!(
        owner.credential(f.context()).await.unwrap().unwrap().token,
        "replacement"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn safe_refresh_failure_does_not_resurrect_rejected_access() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
    let first = seed(&f, &owner).await;
    *f.reply.lock().unwrap() = (503, json!({"error":"temporarily_unavailable"}));
    assert!(
        owner
            .challenge(
                f.context(),
                AuthChallenge {
                    status: 401,
                    headers: BTreeMap::new(),
                    attempt_id: Some(first.attempt_id),
                }
            )
            .await
            .is_err()
    );
    {
        let records = store.records.lock().await;
        let token = records.values().next().unwrap().token.as_ref().unwrap();
        assert!(token.access_rejected);
        assert!(!token.rejected);
        assert!(!token.refresh_in_flight);
        assert_eq!(token.refresh_token.as_deref(), Some("original-refresh"));
    }
    assert!(owner.credential(f.context()).await.is_err());
    assert_eq!(
        f.token_requests().len(),
        3,
        "must refresh again, not reuse rejected access"
    );
    *f.reply.lock().unwrap() = (200, token("replacement", true));
    assert_eq!(
        owner.credential(f.context()).await.unwrap().unwrap().token,
        "replacement"
    );
    assert!(
        !store
            .records
            .lock()
            .await
            .values()
            .next()
            .unwrap()
            .token
            .as_ref()
            .unwrap()
            .access_rejected
    );
}

fn metadata_challenge(f: &Fixture) -> AuthChallenge {
    AuthChallenge {
        status: 401,
        headers: BTreeMap::from([(
            "WWW-Authenticate".into(),
            format!("Bearer resource_metadata=\"{}/meta\"", f.base),
        )]),
        attempt_id: None,
    }
}

fn seen_paths(f: &Fixture) -> Vec<String> {
    f.seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.path.clone())
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn metadata_source_identity_rejects_covering_resources_without_fallback() {
    for source in ["challenge", "path", "root"] {
        let f = Fixture::new();
        let owner = f.owner(
            Arc::new(Store::default()),
            source,
            OAuthFlow::AuthorizationCodePkce,
        );
        let path = "/.well-known/oauth-protected-resource/resource";
        let root = "/.well-known/oauth-protected-resource";
        let (metadata_path, wrong_resource, expected_paths) = match source {
            "challenge" => ("/meta", f.base.clone(), vec!["/meta"]),
            "path" => (path, f.base.clone(), vec![path]),
            // A trailing slash covers the same origin but is not its exact identity.
            _ => {
                f.metadata_replies
                    .lock()
                    .unwrap()
                    .insert(path.into(), (404, String::new()));
                (root, format!("{}/", f.base), vec![path, root])
            }
        };
        f.metadata_replies
            .lock()
            .unwrap()
            .insert(metadata_path.into(), (200, wrong_resource));
        if source == "challenge" {
            assert!(
                owner
                    .challenge(f.context(), metadata_challenge(&f))
                    .await
                    .is_err()
            );
        } else {
            assert!(owner.prepare(f.context(), budget()).await.is_err());
        }
        assert_eq!(
            seen_paths(&f),
            expected_paths,
            "source {source} must fail before AS discovery or alternate fallback"
        );
        assert!(f.token_requests().is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn root_metadata_hint_survives_completion_and_repeated_prepare() {
    let f = Fixture::new();
    f.metadata_replies.lock().unwrap().insert(
        "/.well-known/oauth-protected-resource/resource".into(),
        (404, String::new()),
    );
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "root", OAuthFlow::AuthorizationCodePkce);
    let pending = login(owner.prepare(f.context(), budget()).await.unwrap());
    {
        let records = store.records.lock().await;
        let record = records.values().next().unwrap();
        assert_eq!(record.schema_version, 2);
        let hint = record.resource_metadata_hint.as_ref().unwrap();
        assert_eq!(hint.expected_resource, f.base);
        assert_eq!(
            hint.url,
            format!("{}/.well-known/oauth-protected-resource", f.base)
        );
        assert!(matches!(
            hint.source,
            discovery::ResourceMetadataSource::WellKnown
        ));
    }
    f.seen.lock().unwrap().clear();
    let url = callback(&pending);
    owner.complete(pending, url, budget()).await.unwrap();
    assert_eq!(seen_paths(&f)[0], "/.well-known/oauth-protected-resource");
    assert_eq!(form(&f.token_requests()[0])["resource"], f.base);
    f.seen.lock().unwrap().clear();
    let _ = ready(owner.prepare(f.context(), budget()).await.unwrap());
    assert_eq!(seen_paths(&f)[0], "/.well-known/oauth-protected-resource");
    assert!(!seen_paths(&f).iter().any(|p| p.ends_with("/resource")));
}

#[tokio::test(flavor = "current_thread")]
async fn challenge_hint_provenance_survives_completion_and_repeated_prepare() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "challenge", OAuthFlow::AuthorizationCodePkce);
    assert!(
        owner
            .challenge(f.context(), metadata_challenge(&f))
            .await
            .is_err()
    );
    {
        let records = store.records.lock().await;
        let hint = records
            .values()
            .next()
            .unwrap()
            .resource_metadata_hint
            .as_ref()
            .unwrap();
        assert_eq!(hint.expected_resource, f.context().destination);
        assert!(matches!(
            hint.source,
            discovery::ResourceMetadataSource::Challenge
        ));
    }
    f.seen.lock().unwrap().clear();
    let pending = login(owner.prepare(f.context(), budget()).await.unwrap());
    assert_eq!(seen_paths(&f)[0], "/meta");
    f.seen.lock().unwrap().clear();
    let url = callback(&pending);
    owner.complete(pending, url, budget()).await.unwrap();
    assert_eq!(seen_paths(&f)[0], "/meta");
    f.seen.lock().unwrap().clear();
    let _ = ready(owner.prepare(f.context(), budget()).await.unwrap());
    assert_eq!(seen_paths(&f)[0], "/meta");
}

#[tokio::test(flavor = "current_thread")]
async fn mismatched_saved_metadata_provenance_fails_closed_before_network() {
    for corruption in ["source", "resource", "url"] {
        let f = Fixture::new();
        let store = Arc::new(Store::default());
        let owner = f.owner(store.clone(), corruption, OAuthFlow::AuthorizationCodePkce);
        assert!(
            owner
                .challenge(f.context(), metadata_challenge(&f))
                .await
                .is_err()
        );
        {
            let mut records = store.records.lock().await;
            let hint = records
                .values_mut()
                .next()
                .unwrap()
                .resource_metadata_hint
                .as_mut()
                .unwrap();
            match corruption {
                "source" => hint.source = discovery::ResourceMetadataSource::WellKnown,
                "resource" => hint.expected_resource = f.base.clone(),
                _ => hint.url = "http://oauth.test/meta".into(),
            }
        }
        f.seen.lock().unwrap().clear();
        assert!(
            owner.prepare(f.context(), budget()).await.is_err(),
            "corruption {corruption}"
        );
        assert!(
            seen_paths(&f).is_empty(),
            "corruption {corruption} must fail before network"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn challenge_metadata_identity_includes_destination_query() {
    for exact in [false, true] {
        let f = Fixture::new();
        let store = Arc::new(Store::default());
        let owner = f.owner(store, "query", OAuthFlow::AuthorizationCodePkce);
        let mut context = f.context();
        context.destination.push_str("?tenant=one");
        let resource = if exact {
            context.destination.clone()
        } else {
            f.context().destination
        };
        f.metadata_replies
            .lock()
            .unwrap()
            .insert("/meta".into(), (200, resource));
        // challenge() reports interaction-required as an error even on valid discovery.
        assert!(
            owner
                .challenge(context.clone(), metadata_challenge(&f))
                .await
                .is_err()
        );
        if exact {
            let pending = login(owner.prepare(context, budget()).await.unwrap());
            let resource = pending
                .url
                .query_pairs()
                .find(|(k, _)| k == "resource")
                .unwrap()
                .1
                .into_owned();
            assert_eq!(resource, format!("{}/resource?tenant=one", f.base));
        } else {
            assert_eq!(seen_paths(&f), ["/meta"]);
        }
        assert!(f.token_requests().is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_resource_preset_does_not_accept_root_fallback_identity() {
    let f = Fixture::new();
    f.metadata_replies.lock().unwrap().insert(
        "/.well-known/oauth-protected-resource/resource".into(),
        (404, String::new()),
    );
    let owner = f.owner(
        Arc::new(Store::default()),
        "preset",
        OAuthFlow::AuthorizationCodePkce,
    );
    let mut context = f.context();
    context.authentication = Some(json!({
        "type": "oauth", "flow": "authorization_code_pkce",
        "issuer": format!("{}/tenant", f.base), "clientId": "client",
        "resource": context.destination,
    }));
    assert!(owner.prepare(context, budget()).await.is_err());
    assert_eq!(
        seen_paths(&f),
        [
            "/.well-known/oauth-protected-resource/resource",
            "/.well-known/oauth-protected-resource",
        ]
    );
    assert!(f.token_requests().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_session_schema_and_unattributed_string_hints_are_not_trusted() {
    let f = Fixture::new();
    let store = Arc::new(Store::default());
    let owner = f.owner(store.clone(), "legacy", OAuthFlow::AuthorizationCodePkce);
    let _ = login(owner.prepare(f.context(), budget()).await.unwrap());
    {
        let mut records = store.records.lock().await;
        let record = records.values_mut().next().unwrap();
        let mut serialized = serde_json::to_value(&*record).unwrap();
        serialized["resource_metadata_hint"] = format!("{}/meta", f.base).into();
        assert!(serde_json::from_value::<SessionRecord>(serialized).is_err());
        record.schema_version = 1;
    }
    f.seen.lock().unwrap().clear();
    assert!(owner.prepare(f.context(), budget()).await.is_err());
    assert!(seen_paths(&f).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn saved_root_hint_cannot_claim_path_identity() {
    let f = Fixture::new();
    f.metadata_replies.lock().unwrap().insert(
        "/.well-known/oauth-protected-resource/resource".into(),
        (404, String::new()),
    );
    let store = Arc::new(Store::default());
    let owner = f.owner(
        store.clone(),
        "root-provenance",
        OAuthFlow::AuthorizationCodePkce,
    );
    let _ = login(owner.prepare(f.context(), budget()).await.unwrap());
    store
        .records
        .lock()
        .await
        .values_mut()
        .next()
        .unwrap()
        .resource_metadata_hint
        .as_mut()
        .unwrap()
        .expected_resource = f.context().destination;
    f.seen.lock().unwrap().clear();
    assert!(owner.prepare(f.context(), budget()).await.is_err());
    assert!(seen_paths(&f).is_empty());
}
