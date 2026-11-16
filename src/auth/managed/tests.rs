#[cfg(feature = "interop")]
mod interop_tests {
    // All listeners, TLS policy, storage and workers in these tests belong to the host.
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
                            tiny_http::Header::from_bytes("Content-Type", "application/json")
                                .unwrap(),
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
        for record in store
            .records
            .lock()
            .await
            .values_mut()
            .filter(|record| record.token.is_some())
        {
            record.token.as_mut().unwrap().expires_at = Some(0);
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
        let context = f.context();
        let operation = OperationBudget::until(context.deadline);
        let store = Arc::new(Store::default());
        let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
        let p = login(owner.prepare(context.clone(), operation).await.unwrap());
        let q = login(owner.prepare(context.clone(), operation).await.unwrap());
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
            .find(|record| record.token.is_some() || record.pending.is_some())
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
            let p = login(owner.prepare(context.clone(), operation).await.unwrap());
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
        let p = login(owner.prepare(context.clone(), operation).await.unwrap());
        let mut wrong_path = callback(&p);
        wrong_path.set_path("/other");
        assert!(owner.complete(p, wrong_path, budget()).await.is_err());
        let p = login(owner.prepare(context.clone(), operation).await.unwrap());
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
        let missing_issuer = login(owner.prepare(context.clone(), operation).await.unwrap());
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
                .find(|record| record.token.is_some() || record.pending.is_some())
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
        short["expires_in"] = 0.into();
        *f.reply.lock().unwrap() = (200, short);
        assert!(owner.prepare(f.context(), budget()).await.is_err());
    }

    struct RefreshScopePolicy;
    impl OAuthPolicy for RefreshScopePolicy {
        fn approve_endpoints(&self, trust: EndpointTrust<'_>) -> Result<(), HookError> {
            Policy.approve_endpoints(trust)
        }
        fn select(
            &self,
            _: &AuthTarget,
            resource: &ResourceMetadata,
            required: &[String],
        ) -> Result<TrustDecision, HookError> {
            let mut scopes = vec!["read".into(), "write".into()];
            scopes.extend_from_slice(required);
            scopes.sort();
            scopes.dedup();
            Ok(TrustDecision::new(
                resource.authorization_servers[0].clone(),
                scopes,
            ))
        }
    }
    fn refresh_scope_owner(f: &Fixture, store: Arc<Store>) -> ManagedOAuth {
        let config =
            OAuthClientConfig::new("refresh-scopes", "client", OAuthFlow::AuthorizationCodePkce)
                .scopes(
                    vec!["read".into(), "write".into()],
                    vec!["read".into(), "write".into()],
                )
                .redirect_uri("https://localhost/callback");
        ManagedOAuth::new(
            config,
            f.network.clone(),
            Arc::new(RefreshScopePolicy),
            store,
        )
        .unwrap()
    }
    async fn reload_scope_grant(
        oauth: &ManagedOAuth,
        store: &Store,
        context: &AuthContext,
    ) -> SessionRecord {
        let target = context.target().unwrap();
        let mut guard = store.acquire(oauth.key(&target), budget()).await.unwrap();
        let binding = guard.load().await.unwrap().unwrap();
        drop(guard);
        let mut guard = store
            .acquire(oauth.grant_key(&target, &binding.metadata), budget())
            .await
            .unwrap();
        guard.load().await.unwrap().unwrap()
    }
    async fn tls_refresh_scope_lifecycle(broaden: bool) {
        let f = Fixture::new();
        let store = Arc::new(Store::default());
        let owner = refresh_scope_owner(&f, store.clone());
        let pending = login(owner.prepare(f.context(), budget()).await.unwrap());
        assert!(
            pending
                .url
                .query_pairs()
                .any(|(key, value)| key == "scope" && value == "read write")
        );
        *f.reply.lock().unwrap() = (
            200,
            json!({"access_token":"initial-read", "refresh_token":"initial-refresh", "token_type":"Bearer", "scope":"read", "expires_in":3600}),
        );
        owner
            .complete(pending.clone(), callback(&pending), budget())
            .await
            .unwrap();
        let initial = reload_scope_grant(&owner, &store, &f.context()).await;
        assert_eq!(initial.token.as_ref().unwrap().scopes, vec!["read"]);
        assert_eq!(
            initial.token.as_ref().unwrap().authorized_scopes,
            vec!["read"]
        );
        drop(owner);
        expire(&store).await;
        let recreated = refresh_scope_owner(&f, store.clone());
        let mut response = json!({"access_token":"refreshed-access", "refresh_token":"rotated-refresh", "token_type":"Bearer", "expires_in":3600});
        if broaden {
            response["scope"] = json!("read write");
        }
        *f.reply.lock().unwrap() = (200, response);
        let refreshed = recreated.credential(f.context()).await;
        if broaden {
            assert_eq!(
                refreshed.err().unwrap().auth_code(),
                Some(AuthErrorCode::AccessDenied)
            );
        } else {
            assert_eq!(refreshed.unwrap().unwrap().token, "refreshed-access");
        }
        let requests = f.token_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(form(&requests[0])["grant_type"], "authorization_code");
        let refresh = form(&requests[1]);
        assert_eq!(refresh["grant_type"], "refresh_token");
        assert_eq!(refresh["scope"], "read");
        assert_eq!(refresh["refresh_token"], "initial-refresh");
        assert_eq!(refresh["resource"], f.context().destination);
        drop(recreated);
        let recreated = refresh_scope_owner(&f, store.clone());
        let saved = reload_scope_grant(&recreated, &store, &f.context()).await;
        let token = saved.token.as_ref().unwrap();
        assert_eq!(token.refresh_token.as_deref(), Some("rotated-refresh"));
        assert_eq!(token.authorized_scopes, vec!["read"]);
        assert_eq!(token.access_rejected, broaden);
        if broaden {
            assert!(recreated.cached(&saved).is_none());
        } else {
            assert_eq!(token.scopes, vec!["read"]);
        }
        let mut required = f.context();
        required.authentication = Some(
            json!({"type":"oauth", "flow":"authorization_code_pkce", "issuer":format!("{}/tenant", f.base), "resource":required.destination, "clientId":"client", "scopes":["write"]}),
        );
        assert_eq!(
            recreated
                .credential(required.clone())
                .await
                .err()
                .unwrap()
                .auth_code(),
            Some(AuthErrorCode::InteractionRequired)
        );
        let fresh = login(recreated.prepare(required, budget()).await.unwrap());
        assert!(
            fresh
                .url
                .query_pairs()
                .any(|(key, value)| key == "scope" && value == "read write")
        );
        assert_eq!(
            f.token_requests().len(),
            2,
            "fresh write consent must not be replaced with a widening refresh"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn tls_narrowed_grant_refresh_after_provider_recreation() {
        tls_refresh_scope_lifecycle(false).await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn tls_broadened_refresh_quarantines_access_after_provider_recreation() {
        tls_refresh_scope_lifecycle(true).await;
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
                .find(|record| record.token.is_some() || record.pending.is_some())
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
            let t = records
                .values()
                .find(|record| record.token.is_some() || record.pending.is_some())
                .unwrap()
                .token
                .as_ref()
                .unwrap();
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
                .find(|record| record.token.is_some() || record.pending.is_some())
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
        let token = records
            .values()
            .find(|record| record.token.is_some() || record.pending.is_some())
            .unwrap()
            .token
            .as_ref()
            .unwrap();
        assert!(token.refresh_in_flight);
        assert_eq!(token.refresh_token.as_deref(), Some("original-refresh"));
        drop(records);
        assert_eq!(store.rejected.load(Ordering::SeqCst), 0);
        f.delay.store(false, Ordering::SeqCst);
        assert!(owner.prepare(f.context(), budget()).await.is_ok());
        assert_eq!(f.token_requests().len(), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn namespace_destination_upload_isolation_and_login_cancellation() {
        let f = Fixture::new();
        let context = f.context();
        let operation = OperationBudget::until(context.deadline);
        let store = Arc::new(Store::default());
        let a = f.owner(store.clone(), "a", OAuthFlow::AuthorizationCodePkce);
        let b = f.owner(store.clone(), "b", OAuthFlow::AuthorizationCodePkce);
        let p = login(a.prepare(context.clone(), operation).await.unwrap());
        let q = login(b.prepare(context.clone(), operation).await.unwrap());
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
        assert_eq!(store.records.lock().await.len(), 8);
        let old_id = p.id.clone();
        let stale = login(a.prepare(context.clone(), operation).await.unwrap());
        a.cancel_login(p, budget()).await.unwrap();
        let replacement = login(a.prepare(context.clone(), operation).await.unwrap());
        assert_ne!(replacement.id, old_id);
        a.cancel_login(stale, budget()).await.unwrap();
        let unchanged = login(a.prepare(context.clone(), operation).await.unwrap());
        assert_eq!(replacement.id, unchanged.id);
        assert!(
            store
                .records
                .lock()
                .await
                .values()
                .filter(|record| record.token.is_some() || record.pending.is_some())
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
        let context = f.context();
        let operation = OperationBudget::until(context.deadline);
        let store = Arc::new(Store::default());
        let owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
        let p = login(owner.prepare(context.clone(), operation).await.unwrap());
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
                .find(|record| record.token.is_some() || record.pending.is_some())
                .unwrap()
                .pending
                .as_ref()
                .unwrap()
                .in_flight
        );
        drop(records);
        let uncertain = login(owner.prepare(context.clone(), operation).await.unwrap());
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
        let fresh = login(owner.prepare(context.clone(), operation).await.unwrap());
        assert_ne!(fresh.id, stale.id);
        assert!(!fresh.exchange_is_uncertain());
        assert!(fresh.authorization_url().is_some());
        owner.cancel_login(stale, budget()).await.unwrap();
        assert_eq!(
            login(owner.prepare(context.clone(), operation).await.unwrap()).id,
            fresh.id
        );
        assert_eq!(f.token_requests().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_503_refresh_retains_material_and_allows_host_retry() {
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
            let record = records
                .values()
                .find(|record| record.token.is_some() || record.pending.is_some())
                .unwrap();
            assert!(record.refresh_is_uncertain());
            let token = record.token.as_ref().unwrap();
            assert_eq!(token.refresh_token.as_deref(), Some("original-refresh"));
            assert!(!token.rejected);
        }
        *f.reply.lock().unwrap() = (200, token("retried", true));
        assert_eq!(
            ready(owner.prepare(f.context(), budget()).await.unwrap()).token,
            "retried"
        );
        assert_eq!(f.token_requests().len(), 3);
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
            let record = records
                .values()
                .find(|record| record.token.is_some() || record.pending.is_some())
                .unwrap();
            assert_eq!(record.challenge_scopes, ["write"]);
            assert!(
                owner.cached(record).is_none(),
                "narrower token must not be dispatched after step-up"
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
    async fn changed_flow_uses_a_distinct_grant_after_rebuilding_binding() {
        let f = Fixture::new();
        let store = Arc::new(Store::default());
        let pkce = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
        seed(&f, &pkce).await;
        let machine = f.owner(store.clone(), "one", OAuthFlow::ClientCredentials);
        let grant = ready(machine.prepare(f.context(), budget()).await.unwrap());
        assert!(!grant.token.is_empty());
        assert_eq!(f.token_requests().len(), 2);
        assert_eq!(
            form(&f.token_requests()[1])["grant_type"],
            "client_credentials"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_change_replaces_pending_generation_and_rejects_stale_callbacks() {
        let f = Fixture::new();
        let context = f.context();
        let operation = OperationBudget::until(context.deadline);
        let store = Arc::new(Store::default());
        let old_owner = f.owner(store.clone(), "one", OAuthFlow::AuthorizationCodePkce);
        let old = login(old_owner.prepare(context.clone(), operation).await.unwrap());
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
        let fresh = login(changed.prepare(context.clone(), operation).await.unwrap());
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
            login(changed.prepare(context.clone(), operation).await.unwrap()).id,
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
        let context = f.context();
        let operation = OperationBudget::until(context.deadline);
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
            let record = records
                .values()
                .find(|record| record.token.is_some() || record.pending.is_some())
                .unwrap();
            let token = record.token.as_ref().unwrap();
            assert!(token.access_rejected);
            assert!(!token.rejected);
            assert!(token.refresh_token.is_none());
            assert!(
                record.pending.is_none(),
                "dispatch must never create a host login"
            );
        }
        let pending = login(owner.prepare(context.clone(), operation).await.unwrap());
        let error = owner.credential(f.context()).await.err().unwrap();
        assert_eq!(error.auth_code(), Some(AuthErrorCode::InteractionRequired));
        assert_eq!(
            login(owner.prepare(context.clone(), operation).await.unwrap()).id,
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
            let token = records
                .values()
                .find(|record| record.token.is_some() || record.pending.is_some())
                .unwrap()
                .token
                .as_ref()
                .unwrap();
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
                .find(|record| record.token.is_some() || record.pending.is_some())
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
            assert!(
                serde_json::to_value(record)
                    .unwrap()
                    .get("schema_version")
                    .is_none()
            );
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
        assert_eq!(seen_paths(&f), ["/token"]);
        assert_eq!(form(&f.token_requests()[0])["resource"], f.base);
        f.seen.lock().unwrap().clear();
        let _ = ready(owner.prepare(f.context(), budget()).await.unwrap());
        assert!(seen_paths(&f).is_empty());
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
        assert_eq!(seen_paths(&f), ["/token"]);
        f.seen.lock().unwrap().clear();
        let _ = ready(owner.prepare(f.context(), budget()).await.unwrap());
        assert!(seen_paths(&f).is_empty());
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
        assert!(matches!(
            owner.prepare(context, budget()).await.unwrap(),
            Preparation::InteractionRequired(_)
        ));
        assert!(
            !seen_paths(&f)
                .iter()
                .any(|path| path.contains("oauth-protected-resource"))
        );
        assert!(f.token_requests().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unattributed_metadata_hints_are_not_trusted() {
        let f = Fixture::new();
        let store = Arc::new(Store::default());
        let owner = f.owner(store.clone(), "hints", OAuthFlow::AuthorizationCodePkce);
        let _ = login(owner.prepare(f.context(), budget()).await.unwrap());
        {
            let mut records = store.records.lock().await;
            let record = records.values_mut().next().unwrap();
            let mut serialized = serde_json::to_value(&*record).unwrap();
            serialized["resource_metadata_hint"] = format!("{}/meta", f.base).into();
            assert!(serde_json::from_value::<SessionRecord>(serialized).is_err());
            record.resource_metadata_hint = None;
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
}

use super::*;
use crate::adapters::registered::AuthPurpose;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
fn budget() -> OperationBudget {
    OperationBudget::until(Instant::now() + Duration::from_secs(10))
}
#[derive(Default)]
struct Store {
    records: Arc<AsyncMutex<BTreeMap<SessionKey, SessionRecord>>>,
}
struct Guard {
    records: OwnedMutexGuard<BTreeMap<SessionKey, SessionRecord>>,
    key: SessionKey,
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
            if self.records.get(&self.key).map(|r| r.version.clone()) != expected {
                return Ok(false);
            }
            self.records.insert(self.key.clone(), replacement);
            Ok(true)
        })
    }
}
struct Policy;
impl OAuthPolicy for Policy {
    fn approve_endpoints(&self, _: EndpointTrust<'_>) -> Result<(), HookError> {
        Ok(())
    }
    fn select(
        &self,
        _: &AuthTarget,
        resource: &ResourceMetadata,
        required: &[String],
    ) -> Result<TrustDecision, HookError> {
        let mut scopes = vec!["read".into()];
        scopes.extend_from_slice(required);
        scopes.sort();
        scopes.dedup();
        Ok(TrustDecision::new(
            resource.authorization_servers[0].clone(),
            scopes,
        ))
    }
}
#[derive(Default)]
struct Network {
    requests: Mutex<Vec<String>>,
    authentications: Mutex<Vec<String>>,
    token_endpoint: Mutex<Option<String>>,
    replies: Mutex<VecDeque<(u16, Value)>>,
    metadata: AtomicUsize,
    tokens: AtomicUsize,
    offline: std::sync::atomic::AtomicBool,
}
impl OAuthNetwork for Network {
    fn check(
        &self,
        _: Url,
        _: EndpointUse,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
    fn send(
        &self,
        request: OAuthRequest,
        usage: EndpointUse,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<OAuthResponse, HookError>> {
        Box::pin(async move {
            let (status, mut body) = if usage == EndpointUse::Token {
                self.authentications.lock().unwrap().push(
                    request
                        .headers()
                        .get("authorization")
                        .map(|value| value.to_str().unwrap().to_owned())
                        .unwrap_or_default(),
                );
                self.requests
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(request.body()).into_owned());
                self.tokens.fetch_add(1, Ordering::SeqCst);
                self.replies
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("queued token response")
            } else {
                self.metadata.fetch_add(1, Ordering::SeqCst);
                assert!(
                    !self.offline.load(Ordering::SeqCst),
                    "cached acquisition performed metadata HTTP"
                );
                if usage == EndpointUse::ResourceMetadata {
                    (
                        200,
                        json!({"resource":"https://api.example/hooks", "authorization_servers":["https://issuer.example"]}),
                    )
                } else {
                    assert!(request.uri().path().contains(".well-known"));
                    (
                        200,
                        json!({"issuer":"https://issuer.example", "authorization_endpoint":"https://issuer.example/authorize", "token_endpoint":"https://issuer.example/token", "grant_types_supported":["authorization_code","refresh_token","client_credentials"], "token_endpoint_auth_methods_supported":["none", "client_secret_basic"], "code_challenge_methods_supported":["S256"]}),
                    )
                }
            };
            if usage == EndpointUse::IssuerMetadata {
                if let Some(endpoint) = self.token_endpoint.lock().unwrap().as_ref() {
                    body["token_endpoint"] = endpoint.clone().into();
                }
            }
            Ok(http::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(serde_json::to_vec(&body).unwrap())
                .unwrap())
        })
    }
}
fn context() -> AuthContext {
    AuthContext {
        backend_id: "backend".into(),
        authentication: Some(
            json!({"type":"oauth", "flow":"authorization_code_pkce", "issuer":"https://issuer.example", "resource":"https://api.example/hooks", "clientId":"client"}),
        ),
        destination: "https://api.example/hooks".into(),
        purpose: AuthPurpose::Event,
        deadline: budget().deadline(),
    }
}
fn owner(store: Arc<Store>, network: Arc<Network>, partition: Option<&str>) -> ManagedOAuth {
    let mut config = OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
        .scopes(vec!["read".into()], vec!["read".into(), "write".into()])
        .redirect_uri("http://127.0.0.1/callback");
    if let Some(partition) = partition {
        config = config.grant_partition(partition);
    }
    ManagedOAuth::new(config, network, Arc::new(Policy), store).unwrap()
}
fn login(value: Preparation) -> PendingLogin {
    match value {
        Preparation::InteractionRequired(login) => login,
        _ => panic!("expected login"),
    }
}
fn callback(login: &PendingLogin) -> Url {
    let state = login
        .url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let mut url = Url::parse("http://127.0.0.1/callback").unwrap();
    url.query_pairs_mut()
        .append_pair("state", &state)
        .append_pair("code", "fake-code");
    url
}
fn record(scopes: Vec<String>, required: Vec<String>) -> SessionRecord {
    let mut metadata = TrustedMetadata::new(
        "https://api.example/hooks".into(),
        "https://issuer.example".into(),
        "https://issuer.example/token".into(),
    );
    metadata.scopes = scopes;
    SessionRecord {
        version: String::new(),
        metadata,
        client_id: "client".into(),
        flow: "authorization_code_pkce".into(),
        configured_binding: true,
        allowed_scopes: vec!["read".into()],
        resource_metadata_hint: None,
        challenge_scopes: required,
        token: None,
        pending: None,
    }
}
fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect()
}
#[test]
fn canonical_key_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("testdata/sdk-auth-lifecycle.json")).unwrap();
    for vector in fixture["keys"].as_array().unwrap() {
        let v = &vector["input"];
        let mut config = OAuthClientConfig::new(
            v["namespace"].as_str().unwrap(),
            v["client_id"].as_str().unwrap(),
            if v["flow"] == "client_credentials" {
                OAuthFlow::ClientCredentials
            } else {
                OAuthFlow::AuthorizationCodePkce
            },
        )
        .scopes(vec![], strings(&v["allowed_scopes"]))
        .redirect_uri("https://host.example/callback");
        if let Some(secret) = v["client_secret"].as_str() {
            config = config.client_secret(
                "fixture-reference",
                ClientSecret::new(secret.into()),
                TokenAuthMethod::ClientSecretBasic,
            );
        }
        if let Some(partition) = v["grant_partition"].as_str() {
            config = config.grant_partition(partition);
        }
        let oauth = ManagedOAuth::new(
            config,
            Arc::new(Network::default()),
            Arc::new(Policy),
            Arc::new(Store::default()),
        )
        .unwrap();
        let mut ctx = context();
        ctx.backend_id = v["backend_id"].as_str().unwrap().into();
        ctx.destination = v["destination"].as_str().unwrap().into();
        ctx.authentication = None;
        ctx.purpose = if v["purpose"] == "upload" {
            AuthPurpose::Upload
        } else {
            AuthPurpose::Event
        };
        let target = ctx.target().unwrap();
        let mut metadata = TrustedMetadata::new(
            v["resource"].as_str().unwrap().into(),
            v["issuer"].as_str().unwrap().into(),
            "https://issuer.example/token".into(),
        );
        if v["metadata"]["grant_types_supported"].is_array() {
            metadata.grant_types_supported = strings(&v["metadata"]["grant_types_supported"]);
        }
        assert_eq!(
            oauth.key(&target).as_str(),
            vector["binding_key"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
        assert_eq!(
            oauth.grant_key(&target, &metadata).as_str(),
            vector["grant_key"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
    }
}
#[tokio::test]
async fn canonical_token_vectors_persist_rotations() {
    let fixture: Value =
        serde_json::from_str(include_str!("testdata/sdk-auth-lifecycle.json")).unwrap();
    for vector in fixture["token_responses"].as_array().unwrap() {
        let store = Arc::new(Store::default());
        let mut oauth = owner(store.clone(), Arc::new(Network::default()), None);
        oauth.config.requested_scopes = strings(&vector["requested"]);
        oauth.config.allowed_scopes = strings(&vector["allowed"]);
        let mut record = record(strings(&vector["requested"]), strings(&vector["required"]));
        let response = serde_json::from_value(vector["response"].clone()).unwrap();
        let old_refresh = if vector["previous_granted"].is_array() {
            record.token = Some(SavedToken {
                access_token: "old".into(),
                refresh_token: Some("old-refresh".into()),
                expires_at: Some(0),
                scopes: strings(&vector["previous_granted"]),
                authorized_scopes: strings(&vector["previous_granted"]),
                generation: "generation".into(),
                rejected: false,
                access_rejected: false,
                refresh_in_flight: false,
            });
            Some("old-refresh".into())
        } else {
            None
        };
        let mut guard = store
            .acquire(oauth.key(&context().target().unwrap()), budget())
            .await
            .unwrap();
        let result = oauth
            .save_token(&mut *guard, &mut record, response, old_refresh, budget())
            .await;
        assert_eq!(
            result.is_ok(),
            vector["usable"].as_bool().unwrap(),
            "{}",
            vector["id"]
        );
        let token = record.token.as_ref().unwrap();
        if vector["granted"].is_array() {
            let mut expected = strings(&vector["granted"]);
            expected.sort();
            expected.dedup();
            assert_eq!(token.scopes, expected);
        }
        assert_eq!(
            token.refresh_token.is_some(),
            vector["refresh_preserved"].as_bool().unwrap()
        );
        if vector["expiry"].is_string() {
            assert_eq!(token.expires_at.is_none(), vector["expiry"] == "unknown");
        }
        assert_eq!(
            oauth.cached(&record).is_some(),
            vector["usable"].as_bool().unwrap()
        );
    }
}
#[tokio::test]
async fn dispatch_never_creates_login_and_cached_recreated_provider_is_offline() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = owner(store.clone(), network.clone(), None);
    assert!(oauth.credential(context()).await.is_err());
    assert!(
        store
            .records
            .lock()
            .await
            .values()
            .all(|r| r.pending.is_none())
    );
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    let mut bad = callback(&pending);
    bad.query_pairs_mut()
        .clear()
        .append_pair("state", "bad")
        .append_pair("code", "fake");
    assert!(
        oauth
            .complete(pending.clone(), bad, budget())
            .await
            .is_err()
    );
    network.replies.lock().unwrap().push_back((
        200,
        json!({"access_token":"first","refresh_token":"refresh","token_type":"Bearer"}),
    ));
    let credential = oauth
        .complete(pending.clone(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(credential.token, "first");
    network.offline.store(true, Ordering::SeqCst);
    let recreated = owner(store.clone(), network.clone(), None);
    assert_eq!(
        recreated
            .credential(context())
            .await
            .unwrap()
            .unwrap()
            .token,
        "first"
    );
    let mut unbound = context();
    unbound.authentication = None;
    // The explicitly approved exact resource is also a trusted same-destination unbound binding.
    assert_eq!(
        recreated.credential(unbound).await.unwrap().unwrap().token,
        "first"
    );
    assert!(
        oauth
            .complete(pending.clone(), callback(&pending), budget())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn shared_partition_reuses_consent_only_after_independent_binding_approval() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = owner(store.clone(), network.clone(), Some("consent"));
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    network
        .replies
        .lock()
        .unwrap()
        .push_back((200, json!({"access_token":"shared","token_type":"Bearer"})));
    oauth
        .complete(pending.clone(), callback(&pending), budget())
        .await
        .unwrap();
    let mut upload = context();
    upload.purpose = AuthPurpose::Upload;
    upload.destination = "https://api.example/hooks/upload".into();
    match oauth.prepare(upload.clone(), budget()).await.unwrap() {
        Preparation::Ready(c) => assert_eq!(c.token, "shared"),
        _ => panic!("shared grant should not need consent"),
    }
    let isolated = owner(store, network, None);
    assert!(matches!(
        isolated.prepare(upload, budget()).await.unwrap(),
        Preparation::InteractionRequired(_)
    ));
}

async fn seed(store: Arc<Store>, network: Arc<Network>, oauth: &ManagedOAuth) -> BearerCredential {
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    network.replies.lock().unwrap().push_back((
        200,
        json!({"access_token":"seed","refresh_token":"original-refresh","token_type":"Bearer"}),
    ));
    let credential = oauth
        .complete(pending.clone(), callback(&pending), budget())
        .await
        .unwrap();
    for record in store.records.lock().await.values_mut() {
        if let Some(token) = record.token.as_mut() {
            token.expires_at = Some(0);
        }
    }
    credential
}
#[tokio::test]
async fn refresh_rotation_unknown_expiry_and_transient_retry_preserve_authorized_ceiling() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = owner(store.clone(), network.clone(), None);
    seed(store.clone(), network.clone(), &oauth).await;
    network.offline.store(true, Ordering::SeqCst);
    network.replies.lock().unwrap().extend([
        (503,json!({"unavailable":true})),
        (200,json!({"access_token":"bad","refresh_token":"rotated-one","token_type":"Bearer","scope":"read write"})),
        (200,json!({"access_token":"repaired","refresh_token":"rotated-two","token_type":"Bearer"})),
    ]);
    assert_eq!(
        oauth
            .prepare(context(), budget())
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::ProviderFailed)
    );
    assert_eq!(
        oauth
            .prepare(context(), budget())
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::AccessDenied)
    );
    {
        let records = store.records.lock().await;
        let token = records
            .values()
            .find_map(|record| record.token.as_ref())
            .unwrap();
        assert_eq!(token.refresh_token.as_deref(), Some("rotated-one"));
        assert!(token.access_rejected);
        assert_eq!(token.authorized_scopes, ["read"]);
    }
    match oauth.prepare(context(), budget()).await.unwrap() {
        Preparation::Ready(c) => assert_eq!(c.token, "repaired"),
        _ => panic!("refresh must not fabricate login"),
    }
    let records = store.records.lock().await;
    let token = records
        .values()
        .find_map(|record| record.token.as_ref())
        .unwrap();
    assert_eq!(token.scopes, ["read"]);
    assert_eq!(token.refresh_token.as_deref(), Some("rotated-two"));
    assert!(token.expires_at.is_none());
    let requests = network.requests.lock().unwrap();
    for request in &requests[1..] {
        assert!(request.contains("scope=read"));
        assert!(!request.contains("write"));
    }
    assert!(
        requests
            .last()
            .unwrap()
            .contains("refresh_token=rotated-one")
    );
}
#[tokio::test]
async fn invalid_access_shape_quarantines_rotated_refresh_before_error() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = owner(store.clone(), network, None);
    let mut record = record(vec!["read".into()], vec![]);
    let mut guard = store
        .acquire(oauth.key(&context().target().unwrap()), budget())
        .await
        .unwrap();
    let response = serde_json::from_value(
        json!({"access_token":"not a bearer","refresh_token":"rotation","token_type":"Bearer"}),
    )
    .unwrap();
    assert!(
        oauth
            .save_token(&mut *guard, &mut record, response, None, budget())
            .await
            .is_err()
    );
    let persisted = guard.load().await.unwrap().unwrap();
    let token = persisted.token.unwrap();
    assert_eq!(token.refresh_token.as_deref(), Some("rotation"));
    assert!(token.access_rejected);
}
#[tokio::test]
async fn pending_scope_budget_eligibility_and_missing_403_scope() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = owner(store.clone(), network, None);
    let mut ctx = context();
    ctx.deadline = Instant::now() + Duration::from_secs(3);
    let original = OperationBudget::until(ctx.deadline);
    let first = login(oauth.prepare(ctx.clone(), original).await.unwrap());
    let shorter = OperationBudget::until(Instant::now() + Duration::from_secs(1));
    assert_eq!(
        login(oauth.prepare(ctx.clone(), shorter).await.unwrap()).id,
        first.id
    );
    let missing = AuthChallenge {
        status: 403,
        headers: BTreeMap::from([(
            "WWW-Authenticate".into(),
            "Bearer error=\"insufficient_scope\"".into(),
        )]),
        attempt_id: None,
    };
    assert_eq!(
        oauth
            .challenge(ctx.clone(), missing)
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::AccessDenied)
    );
    let stepup = AuthChallenge {
        status: 403,
        headers: BTreeMap::from([(
            "WWW-Authenticate".into(),
            "Bearer error=\"insufficient_scope\", scope=\"write\"".into(),
        )]),
        attempt_id: None,
    };
    assert_eq!(
        oauth
            .challenge(ctx.clone(), stepup)
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::InteractionRequired)
    );
    {
        let records = store.records.lock().await;
        assert_eq!(
            records
                .values()
                .find_map(|r| r.pending.as_ref())
                .unwrap()
                .id,
            first.id,
            "dispatch must not replace host pending"
        );
    }
    let expanded = login(oauth.prepare(ctx.clone(), original).await.unwrap());
    assert_ne!(expanded.id, first.id);
    assert!(
        expanded
            .url
            .query_pairs()
            .any(|(key, value)| key == "scope" && value == "read write")
    );
    assert!(
        oauth
            .complete(first.clone(), callback(&first), budget())
            .await
            .is_err()
    );
    let mut later = ctx;
    later.deadline = Instant::now() + Duration::from_secs(5);
    let replaced = login(
        oauth
            .prepare(later.clone(), OperationBudget::until(later.deadline))
            .await
            .unwrap(),
    );
    assert_ne!(replaced.id, expanded.id);
    oauth.cancel_login(replaced, budget()).await.unwrap();
    assert!(
        matches!(
            oauth
                .prepare(later.clone(), OperationBudget::until(later.deadline))
                .await
                .unwrap(),
            Preparation::InteractionRequired(_)
        ),
        "cancelled empty grant must keep its CAS version"
    );
}
#[tokio::test]
async fn callback_original_subsecond_deadline_fixed_query_and_pending_issuer_snapshot() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let mut oauth = owner(store.clone(), network.clone(), None);
    oauth.config.redirect_uri = Some("http://127.0.0.1/callback?tenant=one".into());
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    let mut wrong = callback(&pending);
    wrong.query_pairs_mut().append_pair("tenant", "two");
    assert!(
        oauth
            .complete(pending.clone(), wrong, budget())
            .await
            .is_err()
    );
    // A different binding's shared metadata must not rewrite this pending exchange's issuer contract.
    for record in store.records.lock().await.values_mut() {
        if record.pending.is_some() {
            record
                .metadata
                .authorization_response_iss_parameter_supported = true;
        }
    }
    let mut correct = callback(&pending);
    correct.query_pairs_mut().append_pair("tenant", "one");
    network.replies.lock().unwrap().push_back((
        200,
        json!({"access_token":"query-bound","token_type":"Bearer"}),
    ));
    oauth.complete(pending, correct, budget()).await.unwrap();
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = owner(store, network.clone(), None);
    let mut ctx = context();
    ctx.deadline = Instant::now() + Duration::from_millis(40);
    let pending = login(oauth.prepare(ctx, budget()).await.unwrap());
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        oauth
            .complete(pending.clone(), callback(&pending), budget())
            .await
            .is_err()
    );
    assert_eq!(network.tokens.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn client_credentials_transient_reissue_never_requests_human_login() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let config = OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
        .scopes(vec!["read".into()], vec!["read".into()])
        .client_secret(
            "reference",
            ClientSecret::new("secret".into()),
            TokenAuthMethod::ClientSecretBasic,
        );
    let oauth =
        ManagedOAuth::new(config, network.clone(), Arc::new(Policy), store.clone()).unwrap();
    let mut ctx = context();
    ctx.authentication.as_mut().unwrap()["flow"] = "client_credentials".into();
    network.replies.lock().unwrap().extend([
        (503, json!({"error":"temporarily_unavailable"})),
        (200, json!({"access_token":"machine","token_type":"Bearer"})),
    ]);
    assert_eq!(
        oauth
            .credential(ctx.clone())
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::ProviderFailed)
    );
    assert_eq!(
        oauth.credential(ctx).await.unwrap().unwrap().token,
        "machine"
    );
    assert!(
        store
            .records
            .lock()
            .await
            .values()
            .all(|r| r.pending.is_none())
    );
}

#[path = "consent.rs"]
mod consent;

struct GuardedPolicy {
    store: Arc<Store>,
    deny_original_endpoint: bool,
}
impl OAuthPolicy for GuardedPolicy {
    fn approve_endpoints(&self, trust: EndpointTrust<'_>) -> Result<(), HookError> {
        assert!(
            self.store.records.try_lock().is_ok(),
            "endpoint approval called under store guard"
        );
        if self.deny_original_endpoint && trust.metadata.token_endpoint.ends_with("/token") {
            return Err(fail(AuthErrorCode::UntrustedDestination));
        }
        Ok(())
    }
    fn select(
        &self,
        target: &AuthTarget,
        resource: &ResourceMetadata,
        required: &[String],
    ) -> Result<TrustDecision, HookError> {
        assert!(
            self.store.records.try_lock().is_ok(),
            "principal policy called under store guard"
        );
        Policy.select(target, resource, required)
    }
}
#[tokio::test]
async fn policy_reentry_is_off_lock_and_obsolete_endpoint_metadata_is_rebuilt() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let mut oauth = owner(store.clone(), network.clone(), None);
    oauth.policy = Arc::new(GuardedPolicy {
        store: store.clone(),
        deny_original_endpoint: false,
    });
    let credential = seed(store.clone(), network.clone(), &oauth).await;
    assert!(
        !oauth
            .abandon_uncertain_refresh(context(), &credential.attempt_id, budget())
            .await
            .unwrap()
    );
    network.replies.lock().unwrap().push_back((
        200,
        json!({"access_token":"refreshed","refresh_token":"refresh","token_type":"Bearer"}),
    ));
    assert!(matches!(
        oauth.prepare(context(), budget()).await.unwrap(),
        Preparation::Ready(_)
    ));
    *network.token_endpoint.lock().unwrap() = Some("https://issuer.example/rotated-token".into());
    oauth.policy = Arc::new(GuardedPolicy {
        store: store.clone(),
        deny_original_endpoint: true,
    });
    assert!(matches!(
        oauth.prepare(context(), budget()).await.unwrap(),
        Preparation::Ready(_)
    ));
    let records = store.records.lock().await;
    assert!(records.iter().any(
        |(key, record)| key.as_str().starts_with("ahp.oauth.binding:")
            && record.metadata.token_endpoint.ends_with("/rotated-token")
    ));
}
#[tokio::test]
async fn explicit_required_scope_change_replaces_cached_token_with_host_consent() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = owner(store.clone(), network.clone(), None);
    seed(store, network.clone(), &oauth).await;
    network.replies.lock().unwrap().push_back((
        200,
        json!({"access_token":"fresh","refresh_token":"refresh","token_type":"Bearer"}),
    ));
    assert!(matches!(
        oauth.prepare(context(), budget()).await.unwrap(),
        Preparation::Ready(_)
    ));
    let mut ctx = context();
    ctx.authentication.as_mut().unwrap()["scopes"] = json!(["write"]);
    let pending = login(oauth.prepare(ctx, budget()).await.unwrap());
    assert!(
        pending
            .url
            .query_pairs()
            .any(|(key, value)| key == "scope" && value == "read write")
    );
}
#[tokio::test]
async fn client_credentials_invalid_grant_and_client_errors_never_advise_login() {
    let network = Arc::new(Network::default());
    let store = Arc::new(Store::default());
    let config = OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
        .scopes(vec!["read".into()], vec!["read".into()])
        .client_secret(
            "reference",
            ClientSecret::new("fake".into()),
            TokenAuthMethod::ClientSecretBasic,
        );
    let oauth = ManagedOAuth::new(config, network.clone(), Arc::new(Policy), store).unwrap();
    let mut ctx = context();
    ctx.authentication.as_mut().unwrap()["flow"] = "client_credentials".into();
    for code in ["invalid_grant", "invalid_client"] {
        network
            .replies
            .lock()
            .unwrap()
            .push_back((400, json!({"error":code})));
        let error = oauth.credential(ctx.clone()).await.err().unwrap();
        assert_ne!(error.auth_code(), Some(AuthErrorCode::RefreshRejected));
        assert_ne!(error.auth_code(), Some(AuthErrorCode::InteractionRequired));
    }
}

#[tokio::test]
async fn client_secret_and_capability_rotation_preserve_grant_and_use_current_secret() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let create = |secret: &str| {
        ManagedOAuth::new(
            OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
                .scopes(vec!["read".into()], vec!["read".into()])
                .client_secret(
                    "reference",
                    ClientSecret::new(secret.into()),
                    TokenAuthMethod::ClientSecretBasic,
                ),
            network.clone(),
            Arc::new(Policy),
            store.clone(),
        )
        .unwrap()
    };
    let mut ctx = context();
    ctx.authentication.as_mut().unwrap()["flow"] = "client_credentials".into();
    network.replies.lock().unwrap().push_back((
        200,
        json!({"access_token":"before-rotation","token_type":"Bearer"}),
    ));
    assert_eq!(
        create("first-secret")
            .credential(ctx.clone())
            .await
            .unwrap()
            .unwrap()
            .token,
        "before-rotation"
    );
    for record in store.records.lock().await.values_mut() {
        record
            .metadata
            .grant_types_supported
            .push("extension_grant".into());
    }
    network.offline.store(true, Ordering::SeqCst);
    let rotated = create("second-secret");
    assert_eq!(
        rotated
            .credential(ctx.clone())
            .await
            .unwrap()
            .unwrap()
            .token,
        "before-rotation"
    );
    for record in store.records.lock().await.values_mut() {
        if let Some(token) = record.token.as_mut() {
            token.expires_at = Some(0);
        }
    }
    network.offline.store(false, Ordering::SeqCst);
    network.replies.lock().unwrap().push_back((
        200,
        json!({"access_token":"after-rotation","token_type":"Bearer"}),
    ));
    assert_eq!(
        rotated.credential(ctx).await.unwrap().unwrap().token,
        "after-rotation"
    );
    {
        let auth = network.authentications.lock().unwrap();
        assert_eq!(auth.len(), 2);
        assert_ne!(auth[0], auth[1]);
    }
    let persisted =
        serde_json::to_string(&*store.records.lock().await.values().collect::<Vec<_>>()).unwrap();
    assert!(!persisted.contains("first-secret"));
    assert!(!persisted.contains("second-secret"));
    assert!(!persisted.contains("reference"));
}

struct NarrowedPolicy;
impl OAuthPolicy for NarrowedPolicy {
    fn approve_endpoints(&self, _: EndpointTrust<'_>) -> Result<(), HookError> {
        Ok(())
    }
    fn select(
        &self,
        _: &AuthTarget,
        resource: &ResourceMetadata,
        _: &[String],
    ) -> Result<TrustDecision, HookError> {
        Ok(TrustDecision::new(
            resource.authorization_servers[0].clone(),
            vec!["read".into()],
        ))
    }
}
#[tokio::test]
async fn cached_scope_requirement_cannot_override_current_local_policy() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let mut oauth = owner(store.clone(), network.clone(), None);
    let mut ctx = context();
    ctx.authentication.as_mut().unwrap()["scopes"] = json!(["write"]);
    let pending = login(oauth.prepare(ctx.clone(), budget()).await.unwrap());
    network.replies.lock().unwrap().push_back((
        200,
        json!({"access_token":"read-and-write","token_type":"Bearer","scope":"read write"}),
    ));
    oauth
        .complete(pending.clone(), callback(&pending), budget())
        .await
        .unwrap();
    oauth.policy = Arc::new(NarrowedPolicy);
    network.offline.store(true, Ordering::SeqCst);
    let mut unbound = context();
    unbound.authentication = None;
    assert!(
        oauth.credential(unbound).await.is_err(),
        "a cached token cannot override locally denied challenge requirements"
    );
}

#[tokio::test]
async fn quarantined_broadened_refresh_requires_new_consent_for_broader_requirement() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = owner(store.clone(), network.clone(), None);
    seed(store, network.clone(), &oauth).await;
    network.replies.lock().unwrap().push_back((200,json!({"access_token":"bad","refresh_token":"rotation","token_type":"Bearer","scope":"read write"})));
    assert!(oauth.prepare(context(), budget()).await.is_err());
    let mut ctx = context();
    ctx.authentication.as_mut().unwrap()["scopes"] = json!(["write"]);
    assert_eq!(
        oauth
            .credential(ctx.clone())
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::InteractionRequired)
    );
    assert!(matches!(
        oauth.prepare(ctx, budget()).await.unwrap(),
        Preparation::InteractionRequired(_)
    ));
    assert_eq!(
        network.tokens.load(Ordering::SeqCst),
        2,
        "unconsented reported scopes must not make another refresh eligible"
    );
}
#[tokio::test]
async fn principal_replacement_discards_old_binding_scope_requirements() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let mut oauth = owner(store.clone(), network.clone(), None);
    let mut old = context();
    old.authentication.as_mut().unwrap()["scopes"] = json!(["write"]);
    assert!(matches!(
        oauth.prepare(old, budget()).await.unwrap(),
        Preparation::InteractionRequired(_)
    ));
    oauth.config.client_id = "replacement-client".into();
    oauth.config.allowed_scopes = vec!["read".into()];
    let mut new = context();
    new.authentication.as_mut().unwrap()["clientId"] = "replacement-client".into();
    let pending = login(oauth.prepare(new, budget()).await.unwrap());
    assert!(
        pending
            .url
            .query_pairs()
            .any(|(key, value)| key == "scope" && value == "read")
    );
}
