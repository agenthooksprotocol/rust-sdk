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
}
struct Guard {
    records: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
    key: String,
    held: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
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
    fn pending(&self) -> Vec<SavedLogin> {
        self.records
            .lock()
            .unwrap()
            .values()
            .filter_map(|r| r.pending.clone())
            .collect()
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
}
impl Policy {
    fn new(store: &Store) -> Arc<Self> {
        Arc::new(Self {
            held: store.held.clone(),
            deny: AtomicBool::new(false),
            select: Mutex::new(scopes(&["read"])),
        })
    }
}
impl OAuthPolicy for Policy {
    fn approve_endpoints(&self, _: EndpointTrust<'_>) -> Result<(), HookError> {
        assert_eq!(self.held.load(Ordering::SeqCst), 0, "policy under lock");
        Ok(())
    }
    fn select(
        &self,
        _: &AuthTarget,
        resource: &ResourceMetadata,
        required: &[String],
    ) -> Result<TrustDecision, HookError> {
        assert_eq!(self.held.load(Ordering::SeqCst), 0, "policy under lock");
        if self.deny.load(Ordering::SeqCst) {
            return Err(fail(AuthErrorCode::UntrustedDestination));
        }
        Ok(TrustDecision::new(
            resource.authorization_servers[0].clone(),
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
    offline: AtomicBool,
    transport_failure: AtomicBool,
    on_token: Mutex<Option<Hook>>,
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
    fn metadata_requests(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.usage != EndpointUse::Token)
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
                EndpointUse::Token => {
                    if let Some(hook) = self.on_token.lock().unwrap().take() {
                        hook();
                    }
                    if self.transport_failure.swap(false, Ordering::SeqCst) {
                        return Err(fail(AuthErrorCode::ProviderFailed));
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
                EndpointUse::ResourceMetadata => (
                    200,
                    json!({"resource":"https://api.example/hooks","authorization_servers":["https://issuer.example"]}),
                ),
                _ => {
                    let mut body = json!({"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","grant_types_supported":["authorization_code","refresh_token","client_credentials"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],"code_challenge_methods_supported":["S256"]});
                    if let Value::Object(patch) = &*self.issuer_patch.lock().unwrap() {
                        for (k, v) in patch {
                            body[k] = v.clone();
                        }
                    }
                    (200, body)
                }
            };
            let body = match body {
                Value::String(raw) => raw.into_bytes(),
                body => serde_json::to_vec(&body).unwrap(),
            };
            Ok(http::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(body)
                .unwrap())
        })
    }
}

struct Host {
    store: Arc<Store>,
    network: Arc<Network>,
    policy: Arc<Policy>,
}
impl Host {
    fn new() -> Self {
        let store = Arc::new(Store::default());
        Self {
            policy: Policy::new(&store),
            store,
            network: Arc::new(Network::default()),
        }
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
        ManagedOAuth::new(
            config,
            self.network.clone(),
            self.policy.clone(),
            self.store.clone(),
        )
        .unwrap()
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
    let mut url = Url::parse("http://127.0.0.1/callback").unwrap();
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
        let mut config = OAuthClientConfig::new(
            v["namespace"].as_str().unwrap(),
            v["client_id"].as_str().unwrap(),
            flow,
        )
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
        assert_eq!(
            oauth.grant_key(&target, &metadata).as_str(),
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
        oauth.config.requested_scopes = strings(&vector["requested"]);
        oauth.config.allowed_scopes = strings(&vector["allowed"]);
        let required = strings(&vector["required"]);
        let mut record = SessionRecord {
            version: String::new(),
            metadata: TrustedMetadata::new(
                "https://api.example/hooks".into(),
                "https://issuer.example".into(),
                "https://issuer.example/token".into(),
            ),
            client_id: "client".into(),
            flow: "authorization_code_pkce".into(),
            configured_binding: true,
            resource_metadata_hint: None,
            token: None,
            pending: None,
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
                    .save_token(
                        &mut *guard,
                        &mut record,
                        response,
                        &requested,
                        &bound,
                        refresh.then(|| "old-refresh".into()),
                        &required,
                        budget(),
                    )
                    .await
            }
            // Unparseable responses are never accepted.
            Err(_) => Err(fail(AuthErrorCode::ProviderFailed)),
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
            "pending-login-cross-process-completion",
            pending_login_cross_process_completion,
        ),
        ("pending-login-reuse", pending_login_reuse),
        ("pending-login-supersede", pending_login_supersede),
        (
            "pending-login-supersede-scope-union",
            pending_login_supersede_scope_union,
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
    assert!(host.store.pending().is_empty());
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
    assert!(host.store.pending().is_empty());
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
    host.network.transport_failure.store(true, Ordering::SeqCst);
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
    let grant = host.store.grant().unwrap();
    assert!(grant.token.is_none() && grant.pending.is_none());
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
    assert!(host.store.pending().is_empty());
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
    assert!(host.store.pending().is_empty());
    assert!(host.network.tokens().is_empty());
    assert!(matches!(
        oauth.prepare(context(), budget()).await.unwrap(),
        Preparation::InteractionRequired(_)
    ));
    assert_eq!(host.store.pending().len(), 1);
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
async fn pending_login_cross_process_completion() {
    let host = Host::new();
    let pending = login(host.pkce(|c| c).prepare(context(), budget()).await.unwrap());
    // A different process: new provider and network client, the same store.
    let other = Host {
        store: host.store.clone(),
        network: Arc::new(Network::default()),
        policy: host.policy.clone(),
    };
    other.network.reply(
        200,
        json!({"access_token":"elsewhere","token_type":"Bearer"}),
    );
    let credential = other
        .pkce(|c| c)
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(credential.token, "elsewhere");
    assert!(other.network.metadata_requests().is_empty());
    assert!(other.network.tokens()[0].body.contains("code_verifier="));
}

#[tokio::test]
async fn pending_login_reuse() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let first = login(oauth.prepare(context(), budget()).await.unwrap());
    let mut short = context();
    short.deadline = Instant::now() + Duration::from_millis(500);
    let again = login(oauth.prepare(short, budget()).await.unwrap());
    assert_eq!(again.id, first.id);
    assert_eq!(
        again.expires_at(),
        first.expires_at(),
        "reuse never extends"
    );
    // A requirement already within the pending scopes reuses too.
    let mut read = context();
    read.authentication.as_mut().unwrap()["scopes"] = json!(["read"]);
    assert_eq!(
        login(oauth.prepare(read, budget()).await.unwrap()).id,
        first.id
    );
    // A different ceiling reuses too; completion is bounded by the creating ceiling.
    let narrow = host.pkce(|c| c.scopes(scopes(&["read"]), scopes(&["read"])));
    assert_eq!(
        login(narrow.prepare(context(), budget()).await.unwrap()).id,
        first.id
    );
    host.network.reply(
        200,
        json!({"access_token":"t","token_type":"Bearer","scope":"read write admin"}),
    );
    narrow
        .complete(context(), callback(&first), budget())
        .await
        .unwrap();
    assert_eq!(host.store.token().scopes, scopes(&["read", "write"]));
}

#[tokio::test]
async fn pending_login_supersede() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let first = login(oauth.prepare(context(), budget()).await.unwrap());
    let redirected = host.pkce(|c| c.redirect_uri("http://127.0.0.1/other"));
    let second = login(redirected.prepare(context(), budget()).await.unwrap());
    assert_ne!(second.id, first.id);
    // Scopes outside the pending scopes supersede; the old callback then fails.
    let wide = login(
        oauth
            .prepare_with_required(context(), &scopes(&["write"]), budget())
            .await
            .unwrap(),
    );
    assert_ne!(wide.id, second.id);
    for old in [&first, &second] {
        assert_eq!(
            code(oauth.complete(context(), callback(old), budget()).await),
            AuthErrorCode::InteractionRequired
        );
    }
    assert!(host.network.tokens().is_empty());
}

#[tokio::test]
async fn pending_login_supersede_scope_union() {
    let host = Host::new();
    let reader = host.pkce(|c| c.scopes(scopes(&["read"]), scopes(&["read"])));
    let writer = host.pkce(|c| c.scopes(scopes(&["read"]), scopes(&["read", "write"])));
    let first = login(reader.prepare(context(), budget()).await.unwrap());
    assert_eq!(query(first.authorization_url(), "scope").unwrap(), "read");
    let write = scopes(&["write"]);
    let union = login(
        writer
            .prepare_with_required(context(), &write, budget())
            .await
            .unwrap(),
    );
    assert_ne!(union.id, first.id);
    assert_eq!(
        query(union.authorization_url(), "scope").unwrap(),
        "read write"
    );
    assert_eq!(host.store.pending()[0].ceiling, scopes(&["read", "write"]));
    // Alternating callers with different ceilings converge instead of looping.
    for _ in 0..2 {
        assert_eq!(
            login(reader.prepare(context(), budget()).await.unwrap()).id,
            union.id
        );
        let again = writer.prepare_with_required(context(), &write, budget());
        assert_eq!(login(again.await.unwrap()).id, union.id);
    }
    // Completion is bounded by the stored union ceiling; each caller filters at use.
    host.network.reply(
        200,
        json!({"access_token":"t","token_type":"Bearer","scope":"read write"}),
    );
    reader
        .complete(context(), callback(&union), budget())
        .await
        .unwrap();
    assert_eq!(host.store.token().scopes, scopes(&["read", "write"]));
    assert_eq!(
        reader.effective(&host.store.token().scopes),
        scopes(&["read"])
    );
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
    // Cancel, which never deletes a valid grant; a stale cancel cannot end a newer login.
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
    assert_eq!(host.store.pending()[0].id, newer.id);
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
    assert!(host.store.pending().is_empty());
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
    assert!(host.store.pending().is_empty());
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
    assert!(host.store.pending().is_empty());
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
    assert!(host.store.pending().is_empty());
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
    assert!(host.store.pending().is_empty());
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
