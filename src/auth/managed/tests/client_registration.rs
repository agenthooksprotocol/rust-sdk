//! Client registration lifecycle at the host store, network and secret-storage boundaries.
use super::*;

const ISSUER: &str = "https://issuer.example";
const CIMD: &str = "https://adapter.example/oauth/client.json";
const REDIRECT: &str = "http://127.0.0.1/callback";

fn policy() -> RegistrationPolicy {
    RegistrationPolicy::new(ISSUER, "Example Adapter")
}
fn token(name: &str) -> Value {
    json!({"access_token": name, "token_type": "Bearer", "expires_in": 3600})
}
fn invalid_client() -> Value {
    json!({"error": "invalid_client"})
}
fn dcr_host() -> Host {
    let host = Host::new();
    host.network.dcr.store(true, Ordering::SeqCst);
    host
}
fn patch(host: &Host, value: Value) {
    *host.network.issuer_patch.lock().unwrap() = value;
}
fn pkce_config() -> OAuthClientConfig {
    OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
        .scopes(scopes(&["read"]), scopes(&["read", "write"]))
        .redirect_uri(REDIRECT)
}
fn dcr_pkce(host: &Host) -> ManagedOAuth {
    host.owner(pkce_config().dynamic_registration(policy()))
}
fn cc_with(host: &Host, policy: RegistrationPolicy) -> ManagedOAuth {
    host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .dynamic_registration(policy)
            .client_secret_storage(host.secrets.clone()),
    )
}
fn dcr_cc(host: &Host) -> ManagedOAuth {
    cc_with(host, policy())
}
fn backend(id: &str) -> AuthContext {
    AuthContext {
        backend_id: id.into(),
        ..unbound()
    }
}
fn client_id(login: &PendingLogin) -> String {
    query(login.authorization_url(), "client_id").unwrap()
}
fn sent(seen: &Seen) -> Value {
    serde_json::from_str(&seen.body).unwrap()
}
async fn cc_ready(host: &Host, oauth: &ManagedOAuth, ctx: AuthContext) -> BearerCredential {
    host.network.reply(200, token("cc"));
    ready(oauth.prepare(ctx, budget()).await.unwrap())
}
fn unauthorized() -> AuthChallenge {
    challenge(401, "Bearer", None)
}
/// RFC 6749 section 2.3.1 Basic credentials for URL-safe ids and secrets.
fn basic(id: &str, secret: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = format!("{id}:{secret}").into_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| n << 8 | *b as u32) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    format!("Basic {out}")
}
fn grant_keys(host: &Host) -> Vec<String> {
    host.store
        .records
        .lock()
        .unwrap()
        .keys()
        .filter(|k| k.starts_with("ahp.oauth.grant:"))
        .cloned()
        .collect()
}
fn expire_registration(host: &Host) {
    host.store.edit_registration(|r| {
        r.registration.as_mut().unwrap().client_secret_expires_at = Some(1);
    });
}
fn renewal_due(host: &Host, registered_ago: u64, expires_in: u64) {
    host.store.edit_registration(|r| {
        let registration = r.registration.as_mut().unwrap();
        registration.registered_at = now() - registered_ago;
        registration.client_secret_expires_at = Some(now() + expires_in);
    });
}
/// Proactive renewal runs in the background: let it start, then wait until it
/// releases every store lock.
async fn renewed(host: &Host) {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while host.store.held.load(Ordering::SeqCst) != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "renewal never settled"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
fn elapse_marker(host: &Host) {
    host.store
        .edit_registration(|r| r.marker.as_mut().unwrap().next_attempt_at = 0);
}

// ---- Fixture vectors ----

#[test]
fn client_selection_vectors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for vector in fixture["client_selection"].as_array().unwrap() {
        let (id, v) = (&vector["id"], &vector["input"]);
        let pkce = v["flow"] == "authorization_code_pkce";
        let flow = if pkce {
            OAuthFlow::AuthorizationCodePkce
        } else {
            OAuthFlow::ClientCredentials
        };
        let host = Host::new();
        let mut config = match v["preregistered_client_id"].as_str() {
            Some(client) => OAuthClientConfig::new("account", client, flow),
            None => OAuthClientConfig::unregistered("account", flow),
        };
        if let Some(redirect) = v["redirect"].as_str() {
            config = config.redirect_uri(redirect);
        }
        if v["cimd"].is_object() {
            config = config.client_id_metadata_document(
                v["cimd"]["url"].as_str().unwrap(),
                strings(&v["cimd"]["redirect_uris"]),
            );
        }
        if v["dcr_permitted"] == true {
            config = config.dynamic_registration(policy());
        }
        if v["secret_hook"] == true {
            config = config.client_secret_storage(host.secrets.clone());
        }
        let oauth = host.owner(config);
        let as_metadata = &v["as_metadata"];
        let mut metadata = TrustedMetadata::new(
            "https://api.example/hooks".into(),
            ISSUER.into(),
            "https://issuer.example/token".into(),
        );
        metadata.registration_endpoint = as_metadata["registration_endpoint"]
            .as_str()
            .map(Into::into);
        metadata.client_id_metadata_document_supported =
            as_metadata["client_id_metadata_document_supported"] == true;
        if as_metadata["token_endpoint_auth_methods_supported"].is_array() {
            metadata.token_endpoint_auth_methods_supported =
                strings(&as_metadata["token_endpoint_auth_methods_supported"]);
        }
        let target = unbound().target().unwrap();
        let expect = &vector["expect"];
        match oauth.select_source(&target, &metadata) {
            Ok(source) => {
                let (name, client, method) = match source {
                    ClientSource::Preregistered => {
                        ("preregistered", oauth.preregistered(&target), None)
                    }
                    ClientSource::Cimd => ("cimd", Some(CIMD), Some("none")),
                    ClientSource::Dcr => (
                        "dcr",
                        None,
                        Some(if pkce {
                            "none"
                        } else {
                            registration::secret_method(&metadata).unwrap().0
                        }),
                    ),
                };
                assert_eq!(expect["source"], name, "{id}");
                assert_eq!(expect["client_id"].as_str(), client, "{id}");
                assert_eq!(
                    expect["token_endpoint_auth_method"].as_str(),
                    method,
                    "{id}"
                );
            }
            Err(error) => assert_eq!(expect["error"], error.auth_code().unwrap().as_str(), "{id}"),
        }
    }
}

#[test]
fn registration_response_vectors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for vector in fixture["registration_responses"].as_array().unwrap() {
        let id = &vector["id"];
        let flow = if vector["flow"] == "client_credentials" {
            OAuthFlow::ClientCredentials
        } else {
            OAuthFlow::AuthorizationCodePkce
        };
        let body = match &vector["response"] {
            Value::Null => Vec::new(),
            body => serde_json::to_vec(body).unwrap(),
        };
        let result = registration::accept_registration(
            flow,
            &vector["request"],
            vector["status"].as_u64().unwrap() as u16,
            &body,
            vector["now"].as_u64().unwrap(),
        );
        let expect = &vector["expect"];
        match result {
            Ok(issued) => {
                assert_eq!(expect["accepted"], true, "{id}");
                let record = &expect["record"];
                assert_eq!(record["client_id"], issued.client_id.as_str(), "{id}");
                assert_eq!(
                    record["client_secret_expires_at"].as_u64(),
                    issued.expires_at,
                    "{id}"
                );
                assert_eq!(record["secret_ref"], issued.secret.is_some(), "{id}");
                let known = issued.expires_at.is_some_and(|at| at != 0);
                assert_eq!(
                    expect["expiry"],
                    if known { "known" } else { "none" },
                    "{id}"
                );
                let issued = issued.metadata.to_string();
                for forbidden in [
                    "not-a-real-secret",
                    "registration_access_token",
                    "registration_client_uri",
                ] {
                    assert!(!issued.contains(forbidden), "{id}");
                }
            }
            Err(code) => {
                assert_eq!(expect["accepted"], false, "{id}");
                assert_eq!(expect["error"], code.as_str(), "{id}");
            }
        }
    }
}

#[test]
fn registration_key_and_digest_vectors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for vector in fixture["registration_keys"].as_array().unwrap() {
        let v = &vector["input"];
        let config = if v["flow"] == "client_credentials" {
            OAuthClientConfig::unregistered(
                v["namespace"].as_str().unwrap(),
                OAuthFlow::ClientCredentials,
            )
        } else {
            OAuthClientConfig::unregistered(
                v["namespace"].as_str().unwrap(),
                OAuthFlow::AuthorizationCodePkce,
            )
            .redirect_uri(v["redirect"].as_str().unwrap())
        };
        let oauth = Host::new().owner(config);
        assert_eq!(
            oauth
                .registration_key(v["issuer"].as_str().unwrap())
                .as_str(),
            vector["registration_key"],
            "{}",
            vector["id"]
        );
    }
    for vector in fixture["registration_request_digests"].as_array().unwrap() {
        let v = &vector["input"];
        let mut policy = RegistrationPolicy::new(ISSUER, v["client_name"].as_str().unwrap());
        if let Some(id) = v["software_id"].as_str() {
            policy = policy.software_id(id);
        }
        if let Some(version) = v["software_version"].as_str() {
            policy = policy.software_version(version);
        }
        if v["registration_scope"].is_array() {
            policy = policy.scope(strings(&v["registration_scope"]));
        }
        if let Some(reference) = v["initial_access_token_ref"].as_str() {
            policy = policy.initial_access_token(reference, ClientSecret::new("iat".into()));
        }
        assert_eq!(
            policy.request_digest(),
            vector["request_digest"],
            "{}",
            vector["id"]
        );
    }
}

// ---- Selection ----

#[tokio::test]
pub(super) async fn registration_order_preregistered_cimd_dcr() {
    for (preregistered, cimd, dcr, expected) in [
        (true, true, true, Some("client")),
        (false, true, true, Some(CIMD)),
        (false, false, true, Some("dcr-client-1")),
        (false, false, false, None),
    ] {
        let host = dcr_host();
        patch(
            &host,
            json!({"client_id_metadata_document_supported": true}),
        );
        let mut config = if preregistered {
            OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
                .scopes(scopes(&["read"]), scopes(&["read", "write"]))
                .redirect_uri(REDIRECT)
        } else {
            pkce_config()
        };
        if cimd {
            config = config.client_id_metadata_document(CIMD, vec![REDIRECT.into()]);
        }
        if dcr {
            config = config.dynamic_registration(policy());
        }
        let result = host.owner(config).prepare(unbound(), budget()).await;
        match expected {
            Some(expected) => {
                assert_eq!(client_id(&login(result.unwrap())), expected);
                let registered = expected.starts_with("dcr-");
                assert_eq!(host.network.registrations().len(), registered as usize);
            }
            None => {
                assert_eq!(code(result), AuthErrorCode::CredentialUnavailable);
                assert!(host.network.registrations().is_empty());
            }
        }
    }
}

#[tokio::test]
pub(super) async fn dcr_preregistered_wins() {
    let host = dcr_host();
    let ctx = unbound();
    let dcr = dcr_pkce(&host);
    host.seed(&dcr, ctx.clone()).await;
    assert_eq!(host.network.registrations().len(), 1);
    // A pre-registered client added later makes the recorded DCR selection
    // obsolete: a new grant key, and the DCR grant's token is never presented.
    let pre = host.pkce(|c| c.dynamic_registration(policy()));
    let pending = login(pre.prepare(ctx.clone(), budget()).await.unwrap());
    assert_eq!(client_id(&pending), "client");
    assert_eq!(host.network.registrations().len(), 1);
    assert_eq!(
        code(pre.credential(ctx.clone()).await),
        AuthErrorCode::InteractionRequired
    );
    let keys = grant_keys(&host);
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().any(|k| k.contains("dcr-client-1")));
    assert!(keys.iter().any(|k| k.contains("6:client23:")));
    assert_eq!(host.store.binding().unwrap().client_id, "client");
}

#[tokio::test]
pub(super) async fn cimd_used_when_supported() {
    let host = Host::new();
    patch(
        &host,
        json!({"client_id_metadata_document_supported": true}),
    );
    let oauth = host.owner(pkce_config().client_id_metadata_document(CIMD, vec![REDIRECT.into()]));
    let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
    assert_eq!(client_id(&pending), CIMD);
    host.network.reply(200, token("cimd"));
    oauth
        .complete(unbound(), callback(&pending), budget())
        .await
        .unwrap();
    let form = host.network.last_form();
    assert_eq!(form["client_id"], CIMD);
    assert!(!form.contains_key("client_secret"));
    assert!(host.network.tokens()[0].authorization.is_empty());
    assert!(host.store.registration_record().is_none());
    assert!(host.store.binding().unwrap().client_source == ClientSource::Cimd);
}

#[tokio::test]
pub(super) async fn cimd_not_supported_falls_back_to_dcr() {
    for advertised in [
        json!({}),
        json!({"client_id_metadata_document_supported": "true"}),
    ] {
        let host = dcr_host();
        patch(&host, advertised);
        let oauth = host.owner(
            pkce_config()
                .client_id_metadata_document(CIMD, vec![REDIRECT.into()])
                .dynamic_registration(policy()),
        );
        let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
        assert_eq!(client_id(&pending), "dcr-client-1");
        assert_eq!(host.network.registrations().len(), 1);
    }
}

#[tokio::test]
pub(super) async fn cimd_redirect_mismatch_invalid_configuration() {
    let host = dcr_host();
    patch(
        &host,
        json!({"client_id_metadata_document_supported": true}),
    );
    let oauth = host.owner(
        pkce_config()
            .client_id_metadata_document(CIMD, vec!["http://127.0.0.1:9999/callback".into()])
            .dynamic_registration(policy()),
    );
    assert_eq!(
        code(oauth.prepare(unbound(), budget()).await),
        AuthErrorCode::InvalidConfiguration
    );
    assert!(host.store.pending().is_empty());
    assert!(host.network.registrations().is_empty());
}

#[tokio::test]
pub(super) async fn cimd_never_fetched_by_sdk() {
    let host = Host::new();
    patch(
        &host,
        json!({"client_id_metadata_document_supported": true}),
    );
    let oauth = host.owner(pkce_config().client_id_metadata_document(CIMD, vec![REDIRECT.into()]));
    host.seed(&oauth, unbound()).await;
    host.store.expire();
    host.network.reply(200, token("refreshed"));
    assert!(oauth.credential(unbound()).await.unwrap().is_some());
    let seen = host.network.seen.lock().unwrap();
    assert!(seen.len() > 3);
    assert!(seen.iter().all(|s| !s.uri.contains("adapter.example")));
}

#[tokio::test]
pub(super) async fn cimd_client_credentials_not_used() {
    let host = dcr_host();
    patch(
        &host,
        json!({"client_id_metadata_document_supported": true}),
    );
    let oauth = host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), scopes(&["read"]))
            .client_id_metadata_document(CIMD, vec![REDIRECT.into()])
            .dynamic_registration(policy())
            .client_secret_storage(host.secrets.clone()),
    );
    cc_ready(&host, &oauth, unbound()).await;
    let registrations = host.network.registrations();
    assert_eq!(registrations.len(), 1);
    assert_eq!(
        sent(&registrations[0])["token_endpoint_auth_method"],
        "client_secret_basic"
    );
    assert_eq!(
        host.network.tokens()[0].authorization,
        basic("dcr-client-1", "issued-secret-1")
    );
}

#[tokio::test]
pub(super) async fn cimd_invalid_client_no_dcr_fallback() {
    let host = dcr_host();
    patch(
        &host,
        json!({"client_id_metadata_document_supported": true}),
    );
    let oauth = host.owner(
        pkce_config()
            .client_id_metadata_document(CIMD, vec![REDIRECT.into()])
            .dynamic_registration(policy()),
    );
    // At completion.
    let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
    host.network.reply(401, invalid_client());
    assert_eq!(
        code(
            oauth
                .complete(unbound(), callback(&pending), budget())
                .await
        ),
        AuthErrorCode::InvalidConfiguration
    );
    // At refresh.
    host.seed(&oauth, unbound()).await;
    host.store.expire();
    host.network.reply(401, invalid_client());
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InvalidConfiguration
    );
    assert!(host.network.registrations().is_empty());
    assert!(host.store.registration_record().is_none());
}

// ---- Eligibility and registration requests ----

#[tokio::test]
pub(super) async fn dcr_policy_disallows_registration() {
    let host = dcr_host();
    let oauth = host.owner(pkce_config().dynamic_registration(RegistrationPolicy::new(
        "https://other.example",
        "Example Adapter",
    )));
    assert_eq!(
        code(oauth.prepare(unbound(), budget()).await),
        AuthErrorCode::CredentialUnavailable
    );
    assert!(host.network.registrations().is_empty());
}

#[tokio::test]
pub(super) async fn dcr_registration_endpoint_destination_policy() {
    let insecure = dcr_host();
    patch(
        &insecure,
        json!({"registration_endpoint": "http://issuer.example/register"}),
    );
    let refused = dcr_host();
    refused
        .network
        .refuse_registration
        .store(true, Ordering::SeqCst);
    let redirected = dcr_host();
    redirected
        .network
        .register_reply(302, json!({"client_id": "moved"}), None);
    for (host, sent) in [(insecure, 0), (refused, 0), (redirected, 1)] {
        assert_eq!(
            code(dcr_pkce(&host).prepare(unbound(), budget()).await),
            AuthErrorCode::UntrustedDestination
        );
        assert_eq!(host.network.registrations().len(), sent);
        assert!(host.store.registration().is_none());
    }
}

#[tokio::test]
pub(super) async fn dcr_pkce_registers_only_in_prepare() {
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    assert_eq!(
        code(oauth.challenge(unbound(), unauthorized()).await),
        AuthErrorCode::InteractionRequired
    );
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InteractionRequired
    );
    assert!(host.network.registrations().is_empty());
    login(oauth.prepare(unbound(), budget()).await.unwrap());
    assert_eq!(host.network.registrations().len(), 1);
    // Client-credentials challenge handling registers without `prepare`.
    let host = dcr_host();
    host.network.reply(200, token("cc"));
    dcr_cc(&host)
        .challenge(unbound(), unauthorized())
        .await
        .unwrap();
    assert_eq!(host.network.registrations().len(), 1);
    assert_eq!(host.store.token().access_token, "cc");
}

#[tokio::test]
pub(super) async fn dcr_registers_once_across_processes() {
    let host = dcr_host();
    host.policy.shared_lock.store(true, Ordering::SeqCst);
    host.network.registration_delay.store(50, Ordering::SeqCst);
    let (a, b) = (dcr_cc(&host), dcr_cc(&host));
    host.network.reply(200, token("cc"));
    let (x, y) = tokio::join!(
        a.prepare(unbound(), budget()),
        b.prepare(unbound(), budget())
    );
    assert_eq!(ready(x.unwrap()).token, "cc");
    assert_eq!(ready(y.unwrap()).token, "cc");
    assert_eq!(host.network.registrations().len(), 1);
    assert_eq!(host.secrets.values.lock().unwrap().len(), 1);

    // A writer that bypasses this process's lock wins the compare-and-set: the
    // loser deletes only its own fresh reference and uses the winner's record.
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    let key = oauth.registration_key(ISSUER).as_str().to_owned();
    host.secrets
        .values
        .lock()
        .unwrap()
        .insert("winner-ref".into(), "winner-secret".into());
    let winner = SessionRecord {
        version: "winner".into(),
        registration: Some(registration::SavedRegistration {
            client_id: "winner".into(),
            client_secret_expires_at: None,
            registered_at: now(),
            issued: json!({}),
            request_digest: policy().request_digest(),
            method: "client_secret_basic".into(),
            generation: "winner-generation".into(),
            secret_ref: Some("winner-ref".into()),
        }),
        ..SessionRecord::empty(
            TrustedMetadata::new(String::new(), ISSUER.into(), String::new()),
            "client_credentials",
        )
    };
    let records = host.store.records.clone();
    *host.network.on_registration.lock().unwrap() = Some(Box::new(move || {
        records.lock().unwrap().insert(key, winner);
    }));
    cc_ready(&host, &oauth, unbound()).await;
    let deleted = host.secrets.deleted.lock().unwrap().clone();
    assert_eq!(deleted.len(), 1);
    assert_ne!(deleted[0], "winner-ref");
    assert_eq!(
        host.secrets
            .values
            .lock()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["winner-ref"]
    );
    assert_eq!(host.store.registration().unwrap().client_id, "winner");
    assert_eq!(
        host.network.tokens()[0].authorization,
        basic("winner", "winner-secret")
    );
}

#[tokio::test]
pub(super) async fn dcr_registration_reused_across_grants() {
    let host = dcr_host();
    let shared = host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), scopes(&["read"]))
            .grant_partition("shared")
            .dynamic_registration(policy())
            .client_secret_storage(host.secrets.clone()),
    );
    cc_ready(&host, &dcr_cc(&host), backend("backend")).await;
    cc_ready(&host, &dcr_cc(&host), backend("backend2")).await;
    cc_ready(&host, &shared, backend("backend3")).await;
    assert_eq!(host.network.registrations().len(), 1);
    let keys = grant_keys(&host);
    assert_eq!(keys.len(), 3);
    assert!(keys.iter().all(|k| k.contains("dcr-client-1")));
}

#[tokio::test]
pub(super) async fn dcr_expired_secret_reregisters() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    for (unusable, client) in [
        (expire_registration as fn(&Host), "dcr-client-2"),
        (
            |host: &Host| host.secrets.values.lock().unwrap().clear(),
            "dcr-client-3",
        ),
    ] {
        unusable(&host);
        host.store.expire();
        host.network.reply(200, token(client));
        // The up-front lookup re-registers before any token-endpoint request.
        assert!(oauth.credential(unbound()).await.unwrap().is_some());
        let seen = host.network.seen.lock().unwrap().clone();
        let n = seen.len();
        assert_eq!(seen[n - 2].usage, EndpointUse::Registration);
        assert_eq!(seen[n - 1].usage, EndpointUse::Token);
        assert_eq!(host.store.registration().unwrap().client_id, client);
        let secret = format!("issued-secret-{}", &client[11..]);
        assert_eq!(seen[n - 1].authorization, basic(client, &secret));
    }
}

#[tokio::test]
pub(super) async fn dcr_invalid_client_reregisters_once() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    let discovery = host.network.metadata_requests().len();
    host.store.expire();
    host.network.reply(401, invalid_client());
    host.network.reply(200, token("replacement"));
    let credential = oauth.credential(unbound()).await.unwrap().unwrap();
    assert_eq!(credential.token, "replacement");
    assert_eq!(host.network.registrations().len(), 2);
    let tokens = host.network.tokens();
    assert_eq!(
        tokens[1].authorization,
        basic("dcr-client-1", "issued-secret-1")
    );
    assert_eq!(
        tokens[2].authorization,
        basic("dcr-client-2", "issued-secret-2")
    );
    assert_eq!(host.network.metadata_requests().len(), discovery);
    // A repeated invalid_client for the replacement: at most one re-registration
    // per operation, then a failed marker and credential_unavailable.
    host.store.expire();
    host.network.reply(401, invalid_client());
    host.network.reply(401, invalid_client());
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::CredentialUnavailable
    );
    assert_eq!(host.network.registrations().len(), 3);
    assert_eq!(host.network.tokens().len(), 5);
    assert_eq!(host.store.marker().unwrap().attempts, 1);
    assert!(host.store.registration().is_none());

    // PKCE: the old client's refresh token is never reused.
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    host.seed(&oauth, unbound()).await;
    host.store.expire();
    host.network.reply(401, invalid_client());
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InteractionRequired
    );
    assert!(host.store.registration().is_none());
    assert_eq!(host.network.registrations().len(), 1);
    let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
    assert_eq!(client_id(&pending), "dcr-client-2");
}

#[tokio::test]
pub(super) async fn dcr_new_client_id_new_grant() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    host.store.expire();
    host.network.reply(401, invalid_client());
    host.network.reply(200, token("new"));
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "new"
    );
    let keys = grant_keys(&host);
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().any(|k| k.contains("dcr-client-1")));
    assert!(keys.iter().any(|k| k.contains("dcr-client-2")));
    // The old binding-scoped grant is compare-and-cleared, never migrated.
    let old = |host: &Host| {
        let records = host.store.records.lock().unwrap();
        let (_, record) = records
            .iter()
            .find(|(k, _)| k.contains("dcr-client-1"))
            .unwrap();
        record.token.is_some()
    };
    assert!(!old(&host));
    // A shared grant partition is left alone: other bindings may use it.
    let host = dcr_host();
    let shared = host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), scopes(&["read"]))
            .grant_partition("shared")
            .dynamic_registration(policy())
            .client_secret_storage(host.secrets.clone()),
    );
    cc_ready(&host, &shared, unbound()).await;
    host.store.edit_registration(|r| r.registration = None);
    host.store.expire();
    host.network.reply(200, token("replacement"));
    assert!(shared.credential(unbound()).await.unwrap().is_some());
    assert_eq!(grant_keys(&host).len(), 2);
    assert!(old(&host));

    // PKCE: the replacement client's login is stored under a new grant key.
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    host.seed(&oauth, unbound()).await;
    host.store.expire();
    host.network.reply(401, invalid_client());
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InteractionRequired
    );
    login(oauth.prepare(unbound(), budget()).await.unwrap());
    let records = host.store.records.lock().unwrap();
    let pending = records.iter().find(|(_, r)| r.pending.is_some()).unwrap();
    assert!(pending.0.contains("dcr-client-2"));
}

// ---- Secrets ----

#[tokio::test]
pub(super) async fn dcr_secret_not_in_token_record() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    let reference = host.store.registration().unwrap().secret_ref.unwrap();
    assert_eq!(
        host.secrets.values.lock().unwrap()[&reference],
        "issued-secret-1"
    );
    host.store.expire();
    host.network.reply(401, invalid_client());
    host.network.reply(401, invalid_client());
    let error = oauth.credential(unbound()).await.err().unwrap();
    for text in [host.store.dump(), format!("{error:?}"), error.to_string()] {
        assert!(!text.contains("issued-secret"));
    }
    // Pending logins hold no client secret either.
    let host = dcr_host();
    login(dcr_pkce(&host).prepare(unbound(), budget()).await.unwrap());
    assert!(!host.store.dump().contains("secret\":\""));
}

#[tokio::test]
pub(super) async fn dcr_no_secret_hook_no_confidential_registration() {
    let host = dcr_host();
    let oauth = host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), scopes(&["read"]))
            .dynamic_registration(policy()),
    );
    assert_eq!(
        code(oauth.prepare(unbound(), budget()).await),
        AuthErrorCode::CredentialUnavailable
    );
    assert!(host.network.registrations().is_empty());
    let host = dcr_host();
    login(dcr_pkce(&host).prepare(unbound(), budget()).await.unwrap());
    assert_eq!(host.network.registrations().len(), 1);
}

#[tokio::test]
pub(super) async fn dcr_metadata_change_keeps_selection() {
    let host = dcr_host();
    let oauth = host.owner(
        pkce_config()
            .client_id_metadata_document(CIMD, vec![REDIRECT.into()])
            .dynamic_registration(policy()),
    );
    host.seed(&oauth, unbound()).await;
    patch(
        &host,
        json!({"client_id_metadata_document_supported": true, "registration_endpoint": null}),
    );
    // A step-up needs a new login and rediscovers metadata; the client stays.
    let discovery = host.network.metadata_requests().len();
    let pending = login(
        oauth
            .prepare_with_required(unbound(), &scopes(&["write"]), budget())
            .await
            .unwrap(),
    );
    assert!(host.network.metadata_requests().len() > discovery);
    assert_eq!(client_id(&pending), "dcr-client-1");
    assert_eq!(host.network.registrations().len(), 1);
    assert!(host.store.binding().unwrap().client_source == ClientSource::Dcr);
}

#[tokio::test]
pub(super) async fn dcr_management_fields_not_persisted() {
    let host = dcr_host();
    host.network.register_reply(
        201,
        json!({"client_id": "dcr-client", "registration_access_token": "management-token",
            "registration_client_uri": "https://issuer.example/register/dcr-client"}),
        None,
    );
    let oauth = dcr_pkce(&host);
    let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
    host.network.reply(200, token("pkce"));
    oauth
        .complete(unbound(), callback(&pending), budget())
        .await
        .unwrap();
    let dump = host.store.dump();
    assert!(!dump.contains("management-token"));
    assert!(!dump.contains("register/dcr-client"));
    let seen = host.network.seen.lock().unwrap();
    assert!(
        seen.iter().all(|s| !s.uri.contains("register/dcr-client")
            && !s.authorization.contains("management-token"))
    );
}

#[tokio::test]
pub(super) async fn dcr_initial_access_token_scoped() {
    let host = dcr_host();
    let oauth = host.owner(
        pkce_config()
            .dynamic_registration(
                policy().initial_access_token("vault:iat", ClientSecret::new("iat-value".into())),
            )
            .dynamic_registration(RegistrationPolicy::new(
                "https://other.example",
                "Example Adapter",
            )),
    );
    login(oauth.prepare(unbound(), budget()).await.unwrap());
    *host.network.prm_issuer.lock().unwrap() = Some("https://other.example".into());
    login(oauth.prepare(backend("backend2"), budget()).await.unwrap());
    let registrations = host.network.registrations();
    assert_eq!(registrations.len(), 2);
    assert_eq!(registrations[0].uri, "https://issuer.example/register");
    assert_eq!(registrations[0].authorization, "Bearer iat-value");
    assert_eq!(registrations[1].uri, "https://other.example/register");
    assert!(registrations[1].authorization.is_empty());
    let seen = host.network.seen.lock().unwrap();
    assert_eq!(
        seen.iter()
            .filter(|s| s.authorization.contains("iat-value"))
            .count(),
        1
    );
    assert!(!host.store.dump().contains("iat-value"));
}

// ---- Lookup, backoff and repair ----

#[tokio::test]
pub(super) async fn lookup_never_registers_pkce() {
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    login(oauth.prepare(unbound(), budget()).await.unwrap());
    host.store.edit_registration(|r| r.registration = None);
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InteractionRequired
    );
    assert_eq!(host.network.registrations().len(), 1);
    // Client credentials re-register at the lookup's mandatory re-acquisition.
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    host.store.edit_registration(|r| r.registration = None);
    host.store.expire();
    host.network.reply(200, token("again"));
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "again"
    );
    assert_eq!(host.network.registrations().len(), 2);
}

#[tokio::test]
pub(super) async fn dcr_failed_marker_bounds_registration() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    host.network.register_reply(503, json!({}), None);
    assert_eq!(
        code(oauth.challenge(unbound(), unauthorized()).await),
        AuthErrorCode::ProviderFailed
    );
    let marker = host.store.marker().unwrap();
    assert_eq!(marker.attempts, 1);
    assert_eq!(marker.next_attempt_at - marker.failed_at, 60);
    // No path but prepare registers during the backoff, in any process.
    let other = dcr_cc(&host);
    for result in [
        oauth.credential(unbound()).await.map(|_| ()),
        other.credential(unbound()).await.map(|_| ()),
        other.challenge(unbound(), unauthorized()).await,
    ] {
        assert_eq!(code(result), AuthErrorCode::CredentialUnavailable);
    }
    assert_eq!(host.network.registrations().len(), 1);
    elapse_marker(&host);
    host.network.register_reply(503, json!({}), None);
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::ProviderFailed
    );
    let marker = host.store.marker().unwrap();
    assert_eq!(marker.attempts, 2);
    assert_eq!(marker.next_attempt_at - marker.failed_at, 120);
    // prepare clears it and registers immediately.
    cc_ready(&host, &oauth, unbound()).await;
    assert_eq!(host.network.registrations().len(), 3);
    assert!(host.store.marker().is_none());
    // A changed request digest clears an active marker.
    host.store.edit_registration(|r| {
        r.registration = None;
        r.marker = Some(registration::FailedMarker {
            request_digest: policy().request_digest(),
            failed_at: now(),
            attempts: 4,
            next_attempt_at: now() + 3600,
            generation: "g".into(),
        });
    });
    host.store.expire();
    host.network.reply(200, token("renamed"));
    let renamed = cc_with(&host, RegistrationPolicy::new(ISSUER, "Renamed Adapter"));
    assert_eq!(
        renamed.credential(unbound()).await.unwrap().unwrap().token,
        "renamed"
    );
    assert_eq!(host.network.registrations().len(), 4);
    assert!(host.store.marker().is_none());
}

#[tokio::test]
pub(super) async fn dcr_response_validation_invalid_configuration() {
    for response in [
        json!({"client_id": "dcr-client", "client_secret": "not-a-real-secret"}),
        json!({"client_id": "dcr-client", "redirect_uris": ["https://evil.example/cb"]}),
        json!({"client_id": "dcr-client", "token_endpoint_auth_method": "client_secret_basic"}),
    ] {
        let host = dcr_host();
        host.network.register_reply(201, response, None);
        assert_eq!(
            code(dcr_pkce(&host).prepare(unbound(), budget()).await),
            AuthErrorCode::InvalidConfiguration
        );
        assert_eq!(host.network.registrations().len(), 1);
        assert!(host.store.registration().is_none());
        assert!(host.store.pending().is_empty());
        assert!(!host.store.dump().contains("not-a-real-secret"));
    }
}

#[tokio::test]
pub(super) async fn prepare_force_reregistration() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    let old = host.store.registration().unwrap();
    host.store.edit_registration(|r| {
        r.marker = Some(registration::FailedMarker {
            request_digest: policy().request_digest(),
            failed_at: now(),
            attempts: 1,
            next_attempt_at: now() + 60,
            generation: "g".into(),
        });
    });
    host.network.reply(200, token("forced"));
    let forced = oauth
        .prepare_with(
            unbound(),
            PrepareOptions::new().force_registration(),
            budget(),
        )
        .await
        .unwrap();
    assert_eq!(ready(forced).token, "forced");
    assert_eq!(host.network.registrations().len(), 2);
    let new = host.store.registration().unwrap();
    assert_ne!(new.generation, old.generation);
    assert_eq!(new.client_id, "dcr-client-2");
    assert!(host.store.marker().is_none());
    assert_eq!(
        *host.secrets.deleted.lock().unwrap(),
        [old.secret_ref.unwrap()]
    );
    // An expired pending login alone never re-registers.
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    login(oauth.prepare(unbound(), budget()).await.unwrap());
    for record in host.store.records.lock().unwrap().values_mut() {
        if let Some(pending) = record.pending.as_mut() {
            pending.expires_at_ms = 0;
        }
    }
    let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
    assert_eq!(client_id(&pending), "dcr-client-1");
    assert_eq!(host.network.registrations().len(), 1);
}

#[tokio::test]
pub(super) async fn dcr_policy_change_reregisters() {
    let host = dcr_host();
    cc_ready(&host, &dcr_cc(&host), unbound()).await;
    let old = host.store.registration().unwrap();
    let changed = policy()
        .software_id("example-adapter")
        .scope(scopes(&["read"]));
    let digest = changed.request_digest();
    let oauth = cc_with(&host, changed);
    host.store.expire();
    host.network.reply(200, token("changed"));
    assert!(oauth.credential(unbound()).await.unwrap().is_some());
    let registrations = host.network.registrations();
    assert_eq!(registrations.len(), 2);
    let body = sent(&registrations[1]);
    assert_eq!(body["software_id"], "example-adapter");
    assert_eq!(body["scope"], "read");
    let new = host.store.registration().unwrap();
    assert_eq!(new.request_digest, digest);
    assert_ne!(new.request_digest, old.request_digest);
    assert_eq!(
        *host.secrets.deleted.lock().unwrap(),
        [old.secret_ref.unwrap()]
    );
}

#[tokio::test]
pub(super) async fn dcr_replaced_secret_deleted() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    let old = host.store.registration().unwrap().secret_ref.unwrap();
    expire_registration(&host);
    host.store.expire();
    host.network.reply(200, token("replaced"));
    assert!(oauth.credential(unbound()).await.unwrap().is_some());
    let new = host.store.registration().unwrap().secret_ref.unwrap();
    assert_eq!(*host.secrets.deleted.lock().unwrap(), [old.clone()]);
    let values = host.secrets.values.lock().unwrap().clone();
    assert!(values.contains_key(&new) && !values.contains_key(&old));
    // A compare-and-delete after invalid_client deletes that record's secret too.
    host.store.expire();
    host.network.reply(401, invalid_client());
    host.network.reply(200, token("after"));
    assert!(oauth.credential(unbound()).await.unwrap().is_some());
    assert_eq!(*host.secrets.deleted.lock().unwrap(), [old, new]);
}

#[tokio::test]
pub(super) async fn cc_registration_auto_repairs_after_backoff() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    host.network.register_reply(503, json!({}), None);
    assert_eq!(
        code(oauth.challenge(unbound(), unauthorized()).await),
        AuthErrorCode::ProviderFailed
    );
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::CredentialUnavailable
    );
    assert_eq!(host.network.registrations().len(), 1);
    elapse_marker(&host);
    host.network.reply(200, token("repaired"));
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "repaired"
    );
    assert_eq!(host.network.registrations().len(), 2);
    assert!(host.store.marker().is_none());
}

#[tokio::test]
pub(super) async fn cc_proactive_reregistration_before_expiry() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    // 1000 s lifetime: margin min(100 s, 1 hour); outside it nothing happens.
    renewal_due(&host, 900, 150);
    host.store.expire();
    host.network.reply(200, token("outside"));
    assert!(oauth.credential(unbound()).await.unwrap().is_some());
    assert_eq!(host.network.registrations().len(), 1);
    // Inside it the acquisition uses the current client, then re-registers.
    renewal_due(&host, 950, 50);
    host.store.expire();
    host.network.reply(200, token("inside"));
    let credential = oauth.credential(unbound()).await.unwrap().unwrap();
    assert_eq!(credential.token, "inside");
    renewed(&host).await;
    let seen = host.network.seen.lock().unwrap().clone();
    let n = seen.len();
    assert_eq!(
        seen[n - 2].authorization,
        basic("dcr-client-1", "issued-secret-1")
    );
    assert_eq!(seen[n - 1].usage, EndpointUse::Registration);
    assert_eq!(host.store.registration().unwrap().client_id, "dcr-client-2");
    // The margin is capped (default 1 hour, host-configurable).
    renewal_due(&host, 96_000, 4_000);
    host.store.expire();
    host.network.reply(200, token("capped"));
    assert!(oauth.credential(unbound()).await.unwrap().is_some());
    renewed(&host).await;
    assert_eq!(host.network.registrations().len(), 2);
    let wider = host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .dynamic_registration(policy())
            .client_secret_storage(host.secrets.clone())
            .registration_renewal_margin(Duration::from_secs(5_000)),
    );
    host.store.expire();
    host.network.reply(200, token("wider"));
    assert!(wider.credential(unbound()).await.unwrap().is_some());
    renewed(&host).await;
    assert_eq!(host.network.registrations().len(), 3);
}

#[tokio::test]
pub(super) async fn marker_blocks_only_registration() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    let tokens = host.network.tokens().len();
    expire_registration(&host);
    host.store.edit_registration(|r| {
        r.marker = Some(registration::FailedMarker {
            request_digest: policy().request_digest(),
            failed_at: now(),
            attempts: 3,
            next_attempt_at: now() + 600,
            generation: "g".into(),
        });
    });
    let credential = oauth.credential(unbound()).await.unwrap().unwrap();
    assert_eq!(credential.token, "cc");
    assert_eq!(host.network.tokens().len(), tokens);
    host.store.expire();
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::CredentialUnavailable
    );
    assert_eq!(host.network.registrations().len(), 1);
    // PKCE recovery stays interaction_required.
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    login(oauth.prepare(unbound(), budget()).await.unwrap());
    host.store.edit_registration(|r| {
        r.registration = None;
        r.marker = Some(registration::FailedMarker {
            request_digest: policy().request_digest(),
            failed_at: now(),
            attempts: 1,
            next_attempt_at: now() + 600,
            generation: "g".into(),
        });
    });
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InteractionRequired
    );
}

#[tokio::test]
pub(super) async fn stale_callback_does_not_delete_new_registration() {
    for reissued in [true, false] {
        let host = dcr_host();
        let oauth = dcr_pkce(&host);
        let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
        let created = host.store.registration().unwrap().generation;
        assert_eq!(
            host.store.pending()[0].registration_generation.as_deref(),
            Some(created.as_str())
        );
        if reissued {
            // Another process force-registered and got the same client_id back.
            host.store.edit_registration(|r| {
                r.registration.as_mut().unwrap().generation = "newer".into();
            });
        }
        host.network.reply(401, invalid_client());
        assert_eq!(
            code(
                oauth
                    .complete(unbound(), callback(&pending), budget())
                    .await
            ),
            AuthErrorCode::InteractionRequired
        );
        let current = host.store.registration();
        if reissued {
            assert_eq!(current.unwrap().generation, "newer");
        } else {
            assert!(current.is_none());
        }
    }
}

#[tokio::test]
pub(super) async fn registration_transient_failure_backs_off() {
    for (status, expected) in [
        (500, AuthErrorCode::ProviderFailed),
        (503, AuthErrorCode::ProviderFailed),
        (408, AuthErrorCode::ProviderFailed),
        (429, AuthErrorCode::ProviderFailed),
        (0, AuthErrorCode::ProviderFailed),
        (401, AuthErrorCode::CredentialUnavailable),
        (403, AuthErrorCode::CredentialUnavailable),
    ] {
        let host = dcr_host();
        let (a, b) = (dcr_cc(&host), dcr_cc(&host));
        host.network.register_reply(status, json!({}), None);
        assert_eq!(code(a.challenge(unbound(), unauthorized()).await), expected);
        for result in [
            a.credential(unbound()).await.map(|_| ()),
            b.credential(unbound()).await.map(|_| ()),
            b.challenge(unbound(), unauthorized()).await,
        ] {
            assert_eq!(code(result), AuthErrorCode::CredentialUnavailable);
        }
        assert_eq!(host.network.registrations().len(), 1, "{status}");
        assert_eq!(host.store.marker().unwrap().attempts, 1);
    }
}

#[tokio::test]
pub(super) async fn registration_retry_after_honoured() {
    for (retry_after, backoff, wait) in [
        ("600", None, 600),
        ("10", None, 60),
        ("99999", None, 3600),
        (
            "99999",
            Some((Duration::from_secs(30), Duration::from_secs(300))),
            300,
        ),
        ("soon", None, 60),
    ] {
        let host = dcr_host();
        let mut config = OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), scopes(&["read"]))
            .dynamic_registration(policy())
            .client_secret_storage(host.secrets.clone());
        if let Some((initial, max)) = backoff {
            config = config.registration_backoff(initial, max);
        }
        let oauth = host.owner(config);
        host.network
            .register_reply(429, json!({}), Some(retry_after));
        assert_eq!(
            code(oauth.challenge(unbound(), unauthorized()).await),
            AuthErrorCode::ProviderFailed
        );
        let marker = host.store.marker().unwrap();
        assert_eq!(
            marker.next_attempt_at - marker.failed_at,
            wait,
            "{retry_after}"
        );
    }
}

#[tokio::test]
pub(super) async fn marker_update_atomic_across_processes() {
    let host = dcr_host();
    host.policy.shared_lock.store(true, Ordering::SeqCst);
    host.network.registration_delay.store(50, Ordering::SeqCst);
    let (a, b) = (dcr_cc(&host), dcr_cc(&host));
    for attempt in 1..=2 {
        host.network.register_reply(503, json!({}), None);
        let (x, y) = tokio::join!(
            a.challenge(unbound(), unauthorized()),
            b.challenge(unbound(), unauthorized())
        );
        let mut codes = [code(x), code(y)];
        codes.sort_by_key(|c| c.as_str());
        assert_eq!(
            codes,
            [
                AuthErrorCode::CredentialUnavailable,
                AuthErrorCode::ProviderFailed
            ]
        );
        assert_eq!(host.network.registrations().len(), attempt);
        assert_eq!(host.store.marker().unwrap().attempts, attempt as u32);
        elapse_marker(&host);
    }
}

#[tokio::test]
pub(super) async fn proactive_reregistration_once_across_processes() {
    let host = dcr_host();
    host.policy.shared_lock.store(true, Ordering::SeqCst);
    let (a, b) = (dcr_cc(&host), dcr_cc(&host));
    cc_ready(&host, &a, backend("backend")).await;
    cc_ready(&host, &b, backend("backend2")).await;
    renewal_due(&host, 950, 50);
    host.store.expire();
    host.network.registration_delay.store(50, Ordering::SeqCst);
    host.network.reply(200, token("a"));
    host.network.reply(200, token("b"));
    let (x, y) = tokio::join!(
        a.credential(backend("backend")),
        b.credential(backend("backend2"))
    );
    assert!(x.unwrap().is_some() && y.unwrap().is_some());
    renewed(&host).await;
    assert_eq!(host.network.registrations().len(), 2);
    assert_eq!(host.store.registration().unwrap().client_id, "dcr-client-2");
}

#[tokio::test]
pub(super) async fn proactive_renewal_failure_keeps_current_registration() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    renewal_due(&host, 950, 50);
    let generation = host.store.registration().unwrap().generation;
    host.store.expire();
    host.network.register_reply(503, json!({}), None);
    host.network.reply(200, token("kept"));
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "kept"
    );
    renewed(&host).await;
    assert_eq!(host.network.registrations().len(), 2);
    let current = host.store.registration().unwrap();
    assert_eq!(current.generation, generation);
    assert_eq!(current.client_id, "dcr-client-1");
    assert_eq!(host.store.marker().unwrap().attempts, 1);
    // During the backoff the next acquisition still uses the current client.
    host.store.expire();
    host.network.reply(200, token("still"));
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "still"
    );
    renewed(&host).await;
    assert_eq!(host.network.registrations().len(), 2);
    assert_eq!(
        host.network.tokens().last().unwrap().authorization,
        basic("dcr-client-1", "issued-secret-1")
    );
}

// ---- Coordinator review: detached commit, eligibility, prepare, reuse ----

#[tokio::test]
async fn registration_commits_after_write_even_if_caller_dropped() {
    for late in [false, true] {
        let host = dcr_host();
        host.network.registration_delay.store(100, Ordering::SeqCst);
        host.network
            .registration_written_late
            .store(late, Ordering::SeqCst);
        let oauth = dcr_cc(&host);
        let dropped = tokio::time::timeout(
            Duration::from_millis(30),
            oauth.challenge(unbound(), unauthorized()),
        )
        .await;
        assert!(dropped.is_err());
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(host.network.registrations().len(), 1);
        if late {
            // Cancelled before the request was written: nothing is committed.
            assert!(host.store.registration().is_none());
            assert!(host.secrets.values.lock().unwrap().is_empty());
        } else {
            let saved = host.store.registration().unwrap();
            assert_eq!(saved.client_id, "dcr-client-1");
            let reference = saved.secret_ref.unwrap();
            assert_eq!(
                host.secrets.values.lock().unwrap()[&reference],
                "issued-secret-1"
            );
        }
    }
}

#[tokio::test]
async fn recorded_dcr_selection_rechecks_eligibility_at_registration() {
    // No secret hook any more.
    let host = dcr_host();
    cc_ready(&host, &dcr_cc(&host), unbound()).await;
    expire_registration(&host);
    host.store.expire();
    let without = host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .dynamic_registration(policy()),
    );
    assert_eq!(
        code(without.credential(unbound()).await),
        AuthErrorCode::CredentialUnavailable
    );
    // No usable secret-based token-endpoint method in the recorded metadata.
    let oauth = dcr_cc(&host);
    {
        let mut records = host.store.records.lock().unwrap();
        let binding = records
            .iter_mut()
            .find(|(k, _)| k.starts_with("ahp.oauth.binding:"))
            .unwrap()
            .1;
        binding.metadata.token_endpoint_auth_methods_supported = scopes(&["private_key_jwt"]);
    }
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::CredentialUnavailable
    );
    assert_eq!(host.network.registrations().len(), 1);
}

#[tokio::test]
async fn prepare_clears_failed_marker_with_usable_registration() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, unbound()).await;
    renewal_due(&host, 950, 50);
    host.store.expire();
    host.network.register_reply(503, json!({}), None);
    host.network.reply(200, token("kept"));
    oauth.credential(unbound()).await.unwrap();
    renewed(&host).await;
    assert!(host.store.marker().is_some());
    // The cached token is served, and the marker is still cleared.
    assert_eq!(
        ready(oauth.prepare(unbound(), budget()).await.unwrap()).token,
        "kept"
    );
    assert!(host.store.marker().is_none());
    assert_eq!(host.network.registrations().len(), 2);
}

#[tokio::test]
async fn forced_reregistration_never_reuses_older_generation_login() {
    let host = dcr_host();
    for _ in 0..2 {
        host.network
            .register_reply(201, json!({"client_id": "same"}), None);
    }
    let oauth = dcr_pkce(&host);
    let first = login(oauth.prepare(unbound(), budget()).await.unwrap());
    let old = host.store.registration().unwrap().generation;
    let second = login(
        oauth
            .prepare_with(
                unbound(),
                PrepareOptions::new().force_registration(),
                budget(),
            )
            .await
            .unwrap(),
    );
    let new = host.store.registration().unwrap().generation;
    assert_ne!(old, new);
    assert_eq!(client_id(&second), "same");
    assert_ne!(first.id, second.id);
    let pending = host.store.pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].registration_generation.as_deref(),
        Some(new.as_str())
    );
}

#[tokio::test]
async fn forced_reregistration_clears_binding_scoped_old_grant() {
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    host.seed(&oauth, unbound()).await;
    let pending = login(
        oauth
            .prepare_with(
                unbound(),
                PrepareOptions::new().force_registration(),
                budget(),
            )
            .await
            .unwrap(),
    );
    assert_eq!(client_id(&pending), "dcr-client-2");
    let records = host.store.records.lock().unwrap();
    let (_, old) = records
        .iter()
        .find(|(k, _)| k.contains("dcr-client-1"))
        .unwrap();
    assert!(old.token.is_none() && old.pending.is_none());
}

// A shared grant partition is never cleared, so only the registration
// generation guard stops a login started under the old client being reused.
#[tokio::test]
async fn shared_partition_stale_login_not_reused() {
    let host = dcr_host();
    for _ in 0..2 {
        host.network
            .register_reply(201, json!({"client_id": "same"}), None);
    }
    let oauth = host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .redirect_uri(REDIRECT)
            .grant_partition("shared")
            .dynamic_registration(RegistrationPolicy::new(
                "https://issuer.example",
                "Example Adapter",
            )),
    );
    let first = login(oauth.prepare(unbound(), budget()).await.unwrap());
    let second = login(
        oauth
            .prepare_with(
                unbound(),
                PrepareOptions::new().force_registration(),
                budget(),
            )
            .await
            .unwrap(),
    );
    assert_ne!(first.id, second.id, "stale-generation login reused");
}

// The failed marker is shared per registration key: a prepare for a binding
// that has not resolved yet still clears it.
#[tokio::test]
async fn prepare_for_new_binding_clears_marker() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, backend("backend")).await;
    renewal_due(&host, 950, 50);
    host.store.expire();
    host.network.register_reply(503, json!({}), None);
    host.network.reply(200, token("kept"));
    oauth.credential(backend("backend")).await.unwrap();
    renewed(&host).await;
    assert!(host.store.marker().is_some());
    host.network.reply(200, token("other"));
    ready(oauth.prepare(backend("backend2"), budget()).await.unwrap());
    assert!(
        host.store.marker().is_none(),
        "prepare left the failed marker"
    );
}

// The token is committed before proactive renewal: a renewal slower than the
// caller's deadline neither fails the operation nor is cut short by it.
#[tokio::test]
async fn slow_proactive_renewal_does_not_fail_operation() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    cc_ready(&host, &oauth, backend("backend")).await;
    renewal_due(&host, 950, 50);
    host.store.expire();
    host.network.registration_delay.store(800, Ordering::SeqCst);
    host.network.reply(200, token("kept"));
    let ctx = AuthContext {
        deadline: std::time::Instant::now() + Duration::from_millis(300),
        ..backend("backend")
    };
    let credential = oauth.credential(ctx).await.unwrap().unwrap();
    assert_eq!(credential.token, "kept");
    renewed(&host).await;
    assert_eq!(host.network.registrations().len(), 2);
    assert_eq!(host.store.registration().unwrap().client_id, "dcr-client-2");
}

// Retry-After as an HTTP-date sets the wait, capped at the maximum backoff; a
// past date leaves the normal backoff.
#[tokio::test]
async fn retry_after_http_date() {
    async fn wait(retry_after: &str) -> u64 {
        // The mock network keeps header values for the test's lifetime.
        let retry_after: &'static str = Box::leak(retry_after.to_owned().into_boxed_str());
        let host = dcr_host();
        let oauth = dcr_cc(&host);
        host.network
            .register_reply(429, json!({}), Some(retry_after));
        let _ = oauth
            .challenge(unbound(), challenge(401, "Bearer", None))
            .await;
        let m = host.store.marker().unwrap();
        m.next_attempt_at - m.failed_at
    }
    let at = |offset: i64| {
        let now = std::time::SystemTime::now();
        let when = if offset >= 0 {
            now + Duration::from_secs(offset as u64)
        } else {
            now - Duration::from_secs(offset.unsigned_abs())
        };
        httpdate::fmt_http_date(when)
    };
    let near = wait(&at(300)).await;
    assert!((299..=300).contains(&near), "{near}");
    assert_eq!(wait("Wed, 21 Oct 2099 07:28:00 GMT").await, 3600);
    assert_eq!(wait(&at(-300)).await, 60);
    assert_eq!(wait("120").await, 120);
    assert_eq!(wait("not a date").await, 60);
}
