//! Consent regressions complementing the parent module's scope-step-up and expiry tests.
use super::*;

async fn stored_grant(oauth: &ManagedOAuth, store: &Store, ctx: &AuthContext) -> SessionRecord {
    let target = ctx.target().unwrap();
    let mut binding_guard = store.acquire(oauth.key(&target), budget()).await.unwrap();
    let binding = binding_guard.load().await.unwrap().unwrap();
    drop(binding_guard);
    let mut grant_guard = store
        .acquire(oauth.grant_key(&target, &binding.metadata), budget())
        .await
        .unwrap();
    grant_guard.load().await.unwrap().unwrap()
}

fn last_refresh_scopes(network: &Network) -> Vec<String> {
    let requests = network.requests.lock().unwrap();
    let params =
        url::form_urlencoded::parse(requests.last().unwrap().as_bytes()).collect::<Vec<_>>();
    assert!(
        params
            .iter()
            .any(|(key, value)| key == "grant_type" && value == "refresh_token")
    );
    params
        .iter()
        .find(|(key, _)| key == "scope")
        .unwrap()
        .1
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

async fn exchange_narrowed_grant(store: Arc<Store>, network: Arc<Network>) {
    let oauth = consent_owner(store.clone(), network.clone(), &["read", "write"]);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    assert!(
        pending
            .url
            .query_pairs()
            .any(|(key, value)| key == "scope" && value == "read write")
    );
    network.replies.lock().unwrap().push_back((
        200,
        json!({
            "access_token":"initial-read", "refresh_token":"initial-refresh",
            "token_type":"Bearer", "scope":"read", "expires_in":1
        }),
    ));
    assert_eq!(
        oauth
            .complete(pending.clone(), consent_callback(&pending), budget())
            .await
            .unwrap()
            .token,
        "initial-read"
    );
    let saved = stored_grant(&oauth, &store, &context()).await;
    let token = saved.token.unwrap();
    assert_eq!(token.scopes, vec!["read"]);
    assert_eq!(token.authorized_scopes, vec!["read"]);
    // The one-second lifetime is inside the normal refresh safety margin.
    assert!(token.expires_at.unwrap() <= now().unwrap() + 30);
}

#[tokio::test]
async fn narrowed_grant_survives_provider_recreation_and_scope_omitting_refresh() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    exchange_narrowed_grant(store.clone(), network.clone()).await;
    let metadata_requests = network.metadata.load(Ordering::SeqCst);
    network.offline.store(true, Ordering::SeqCst);
    network.replies.lock().unwrap().push_back((
        200,
        json!({
            "access_token":"refreshed-read", "refresh_token":"rotated-read",
            "token_type":"Bearer", "expires_in":3600
        }),
    ));
    let recreated = consent_owner(store.clone(), network.clone(), &["read", "write"]);
    assert_eq!(
        recreated
            .credential(context())
            .await
            .unwrap()
            .unwrap()
            .token,
        "refreshed-read"
    );
    assert_eq!(last_refresh_scopes(&network), vec!["read"]);
    assert_eq!(network.metadata.load(Ordering::SeqCst), metadata_requests);
    let saved = stored_grant(&recreated, &store, &context()).await;
    let token = saved.token.unwrap();
    assert_eq!(token.scopes, vec!["read"]);
    assert_eq!(token.authorized_scopes, vec!["read"]);
    assert_eq!(token.refresh_token.as_deref(), Some("rotated-read"));
    drop(recreated);
    let recreated = consent_owner(store, network.clone(), &["read", "write"]);
    let mut required = context();
    required.authentication.as_mut().unwrap()["scopes"] = json!(["write"]);
    network.offline.store(false, Ordering::SeqCst);
    assert_eq!(
        recreated
            .credential(required.clone())
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::InteractionRequired)
    );
    let pending = login(recreated.prepare(required, budget()).await.unwrap());
    assert!(
        pending
            .url
            .query_pairs()
            .any(|(key, value)| key == "scope" && value == "read write")
    );
    assert_eq!(
        network.tokens.load(Ordering::SeqCst),
        2,
        "write requires fresh consent, not a widening refresh"
    );
}

#[tokio::test]
async fn recreated_provider_quarantines_broadened_refresh_and_retains_rotation() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    exchange_narrowed_grant(store.clone(), network.clone()).await;
    network.replies.lock().unwrap().push_back((
        200,
        json!({
            "access_token":"unconsented-write", "refresh_token":"rotated-quarantined",
            "token_type":"Bearer", "scope":"read write", "expires_in":3600
        }),
    ));
    let recreated = consent_owner(store.clone(), network.clone(), &["read", "write"]);
    assert_eq!(
        recreated
            .credential(context())
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::AccessDenied)
    );
    assert_eq!(last_refresh_scopes(&network), vec!["read"]);
    drop(recreated);
    let recreated = consent_owner(store.clone(), network.clone(), &["read", "write"]);
    let saved = stored_grant(&recreated, &store, &context()).await;
    assert!(recreated.cached(&saved).is_none());
    let token = saved.token.unwrap();
    assert_eq!(token.refresh_token.as_deref(), Some("rotated-quarantined"));
    assert_eq!(token.authorized_scopes, vec!["read"]);
    assert!(token.access_rejected);
    let mut required = context();
    required.authentication.as_mut().unwrap()["scopes"] = json!(["write"]);
    assert_eq!(
        recreated
            .credential(required.clone())
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::InteractionRequired)
    );
    assert!(matches!(
        recreated.prepare(required, budget()).await.unwrap(),
        Preparation::InteractionRequired(_)
    ));
    assert_eq!(
        network.tokens.load(Ordering::SeqCst),
        2,
        "quarantine must not become consent after provider recreation"
    );
}

struct ConsentPolicy(Vec<String>);
impl OAuthPolicy for ConsentPolicy {
    fn approve_endpoints(&self, context: EndpointTrust<'_>) -> Result<(), HookError> {
        Policy.approve_endpoints(context)
    }

    fn select(
        &self,
        _: &AuthTarget,
        resource: &ResourceMetadata,
        required: &[String],
    ) -> Result<TrustDecision, HookError> {
        let mut scopes = self.0.clone();
        scopes.extend_from_slice(required);
        scopes.sort();
        scopes.dedup();
        Ok(TrustDecision::new(
            resource.authorization_servers[0].clone(),
            scopes,
        ))
    }
}

fn consent_owner(store: Arc<Store>, network: Arc<Network>, requested: &[&str]) -> ManagedOAuth {
    let requested: Vec<String> = requested.iter().map(|scope| (*scope).into()).collect();
    let config = OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
        .scopes(requested.clone(), vec!["read".into(), "write".into()])
        .redirect_uri("http://127.0.0.1/callback?tenant=one");
    ManagedOAuth::new(config, network, Arc::new(ConsentPolicy(requested)), store).unwrap()
}

fn consent_callback(pending: &PendingLogin) -> Url {
    let mut url = callback(pending);
    url.query_pairs_mut().append_pair("tenant", "one");
    url
}

// pending-scope-context-replacement: requested and required sets are separate reuse constraints.
#[tokio::test]
async fn pending_scope_context_replacement_invalidates_old_callback() {
    for change_requested in [true, false] {
        let store = Arc::new(Store::default());
        let network = Arc::new(Network::default());
        let requested = if change_requested {
            vec!["read"]
        } else {
            vec!["read", "write"]
        };
        let first_owner = consent_owner(store.clone(), network.clone(), &requested);
        let mut ctx = context();
        let host_budget = OperationBudget::until(ctx.deadline);
        ctx.authentication.as_mut().unwrap()["scopes"] = json!(["read"]);
        let first = login(first_owner.prepare(ctx.clone(), host_budget).await.unwrap());
        let next_owner = consent_owner(store, network.clone(), &["read", "write"]);
        if !change_requested {
            ctx.authentication.as_mut().unwrap()["scopes"] = json!(["write"]);
        }
        let replacement = login(next_owner.prepare(ctx, host_budget).await.unwrap());
        assert_ne!(first.id, replacement.id);
        assert!(
            first_owner
                .complete(first.clone(), consent_callback(&first), budget())
                .await
                .is_err()
        );
        assert_eq!(network.tokens.load(Ordering::SeqCst), 0);
        network.replies.lock().unwrap().push_back((
            200,
            json!({
                "access_token":"replacement", "token_type":"Bearer", "scope":"read write"
            }),
        ));
        next_owner
            .complete(
                replacement.clone(),
                consent_callback(&replacement),
                budget(),
            )
            .await
            .unwrap();
        assert_eq!(network.tokens.load(Ordering::SeqCst), 1);
    }
}

// pending-budget-replacement: equal-budget polling preserves ownership; later consent replaces it.
#[tokio::test]
async fn pending_budget_replacement_rejects_old_handle_without_exchange() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = owner(store.clone(), network.clone(), None);
    let mut ctx = context();
    ctx.deadline = Instant::now() + Duration::from_secs(3);
    let short = OperationBudget::until(ctx.deadline);
    let first = login(oauth.prepare(ctx.clone(), short).await.unwrap());
    let original_deadline = store
        .records
        .lock()
        .await
        .values()
        .find_map(|record| {
            record
                .pending
                .as_ref()
                .map(|pending| pending.host_deadline_ms)
        })
        .unwrap();
    let same = login(oauth.prepare(ctx.clone(), short).await.unwrap());
    assert_eq!(first.id, same.id);
    assert_eq!(
        store
            .records
            .lock()
            .await
            .values()
            .find_map(|record| record
                .pending
                .as_ref()
                .map(|pending| pending.host_deadline_ms))
            .unwrap(),
        original_deadline
    );
    ctx.deadline += Duration::from_secs(1);
    let replacement = login(
        oauth
            .prepare(ctx.clone(), OperationBudget::until(ctx.deadline))
            .await
            .unwrap(),
    );
    assert_ne!(first.id, replacement.id);
    assert!(
        oauth
            .complete(first.clone(), callback(&first), budget())
            .await
            .is_err()
    );
    assert_eq!(network.tokens.load(Ordering::SeqCst), 0);
    network
        .replies
        .lock()
        .unwrap()
        .push_back((200, json!({"access_token":"later", "token_type":"Bearer"})));
    oauth
        .complete(replacement.clone(), callback(&replacement), budget())
        .await
        .unwrap();
}

// invalid-callback-not-consumed: state and issuer checks precede claiming fixed-query consent.
#[tokio::test]
async fn invalid_state_and_issuer_leave_fixed_query_consent_completable_once() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = consent_owner(store, network.clone(), &["read"]);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    let mut wrong_state =
        Url::parse("http://127.0.0.1/callback?tenant=one&state=wrong&code=fake-code").unwrap();
    assert!(
        oauth
            .complete(pending.clone(), wrong_state.clone(), budget())
            .await
            .is_err()
    );
    wrong_state = consent_callback(&pending);
    wrong_state
        .query_pairs_mut()
        .append_pair("iss", "https://other.example");
    assert!(
        oauth
            .complete(pending.clone(), wrong_state, budget())
            .await
            .is_err()
    );
    assert_eq!(network.tokens.load(Ordering::SeqCst), 0);
    network
        .replies
        .lock()
        .unwrap()
        .push_back((200, json!({"access_token":"valid", "token_type":"Bearer"})));
    oauth
        .complete(pending.clone(), consent_callback(&pending), budget())
        .await
        .unwrap();
    assert!(
        oauth
            .complete(pending.clone(), consent_callback(&pending), budget())
            .await
            .is_err()
    );
    assert_eq!(network.tokens.load(Ordering::SeqCst), 1);
}

// missing403scope: a host's explicit requirement supplies scope, never the challenge's error alone.
#[tokio::test]
async fn missing_403_scope_accepts_explicit_host_requirement_without_starting_consent() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let oauth = owner(store.clone(), network.clone(), None);
    let mut ctx = context();
    ctx.authentication.as_mut().unwrap()["scopes"] = json!(["write"]);
    let challenge = AuthChallenge {
        status: 403,
        headers: BTreeMap::from([(
            "WWW-Authenticate".into(),
            "Bearer error=\"insufficient_scope\"".into(),
        )]),
        attempt_id: None,
    };
    assert_eq!(
        oauth
            .challenge(ctx.clone(), challenge)
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::InteractionRequired)
    );
    assert!(
        store
            .records
            .lock()
            .await
            .values()
            .all(|record| record.pending.is_none())
    );
    assert_eq!(network.tokens.load(Ordering::SeqCst), 0);
    let pending = login(oauth.prepare(ctx, budget()).await.unwrap());
    assert!(
        pending
            .url
            .query_pairs()
            .any(|(key, value)| key == "scope" && value == "read write")
    );
}

#[test]
fn redirects_allow_only_https_or_literal_loopback_http() {
    for (redirect, accepted) in [
        ("https://host.example/callback", true),
        ("http://127.0.0.1/callback", true),
        ("http://127.254.3.2/callback", true),
        ("http://[::1]/callback", true),
        ("http://localhost/callback", false),
        ("http://127.0.0.1.example.com/callback", false),
        ("http://192.168.1.1/callback", false),
        ("http://host.example/callback", false),
        ("http://[::2]/callback", false),
    ] {
        let config = OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
            .redirect_uri(redirect);
        assert_eq!(
            ManagedOAuth::new(
                config,
                Arc::new(Network::default()),
                Arc::new(Policy),
                Arc::new(Store::default())
            )
            .is_ok(),
            accepted,
            "{redirect}"
        );
    }
}

struct PurposePolicy;
impl OAuthPolicy for PurposePolicy {
    fn approve_endpoints(&self, trust: EndpointTrust<'_>) -> Result<(), HookError> {
        if trust.target.purpose() == AuthPurpose::Upload {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        Policy.approve_endpoints(trust)
    }
    fn select(
        &self,
        target: &AuthTarget,
        resource: &ResourceMetadata,
        required: &[String],
    ) -> Result<TrustDecision, HookError> {
        if target.purpose() == AuthPurpose::Upload {
            return Err(fail(AuthErrorCode::AccessDenied));
        }
        Policy.select(target, resource, required)
    }
}

#[tokio::test]
async fn shared_consent_never_overrides_independent_upload_policy() {
    let store = Arc::new(Store::default());
    let network = Arc::new(Network::default());
    let config = OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
        .scopes(vec!["read".into()], vec!["read".into(), "write".into()])
        .redirect_uri("http://127.0.0.1/callback")
        .grant_partition("consent");
    let oauth = ManagedOAuth::new(
        config,
        network.clone(),
        Arc::new(PurposePolicy),
        store.clone(),
    )
    .unwrap();
    seed(store, network.clone(), &oauth).await;
    let before = network.tokens.load(Ordering::SeqCst);
    let mut upload = context();
    upload.purpose = AuthPurpose::Upload;
    upload.destination = "https://api.example/hooks/upload".into();
    assert_eq!(
        oauth
            .prepare(upload, budget())
            .await
            .err()
            .unwrap()
            .auth_code(),
        Some(AuthErrorCode::AccessDenied)
    );
    assert_eq!(network.tokens.load(Ordering::SeqCst), before);
}
