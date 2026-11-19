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
fn pkce_token(name: &str) -> Value {
    json!({"access_token": name, "refresh_token": format!("{name}-refresh"), "token_type": "Bearer", "expires_in": 3600})
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
fn at_port(port: u16) -> PrepareOptions {
    PrepareOptions::new().redirect_uri(format!("http://127.0.0.1:{port}/callback"))
}
async fn login_at(oauth: &ManagedOAuth, port: u16) -> PendingLogin {
    login(
        oauth
            .prepare_with(unbound(), at_port(port), budget())
            .await
            .unwrap(),
    )
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
fn elapse_backoff(host: &Host) {
    host.store
        .edit_registration(|r| r.backoff.as_mut().unwrap().next_attempt_at = 0);
}
/// Seconds until the next registration attempt is permitted.
fn backoff_wait(host: &Host) -> u64 {
    host.store.backoff().unwrap().next_attempt_at - now()
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
        // The login's redirect, when there is one, is checked with selection.
        let redirect = v["redirect"].as_str().filter(|_| pkce);
        match oauth.select_source(&target, &metadata, redirect) {
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
                let binding = SessionRecord {
                    client_source: source,
                    client_id: client.unwrap_or_default().into(),
                    ..SessionRecord::empty(metadata, oauth.flow_id())
                };
                assert_eq!(
                    expect["client_identity"],
                    ManagedOAuth::client_identity(&binding),
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
            }
            Err(code) => {
                assert_eq!(expect["accepted"], false, "{id}");
                assert_eq!(expect["error"], code.as_str(), "{id}");
            }
        }
    }
}

#[test]
fn registration_key_vectors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for vector in fixture["registration_keys"].as_array().unwrap() {
        let v = &vector["input"];
        let config = OAuthClientConfig::unregistered(
            v["namespace"].as_str().unwrap(),
            OAuthFlow::ClientCredentials,
        );
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
    assert_eq!(
        keys.len(),
        1,
        "the new grant has no record until completion"
    );
    assert!(keys[0].contains("3:dcr23:"));
    assert_eq!(host.store.binding().unwrap().client_id, "client");
    assert!(host.store.binding().unwrap().client_source == ClientSource::Preregistered);
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
    assert!(grant_keys(&host)[0].contains(&format!("46:cimd:{CIMD}")));
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
    let declared = vec![
        "http://127.0.0.1:9999/other".into(),
        "https://adapter.example/callback".into(),
    ];
    let oauth = host.owner(
        pkce_config()
            .client_id_metadata_document(CIMD, declared)
            .dynamic_registration(policy()),
    );
    assert_eq!(
        code(oauth.prepare(unbound(), budget()).await),
        AuthErrorCode::InvalidConfiguration
    );
    // A recorded CIMD selection checks each login's redirect too.
    let ok = PrepareOptions::new().redirect_uri("https://adapter.example/callback");
    login(oauth.prepare_with(unbound(), ok, budget()).await.unwrap());
    let other = PrepareOptions::new().redirect_uri("https://adapter.example/other");
    assert_eq!(
        code(oauth.prepare_with(unbound(), other, budget()).await),
        AuthErrorCode::InvalidConfiguration
    );
    assert_eq!(host.pending().len(), 1);
    assert!(host.network.registrations().is_empty());
}

#[tokio::test]
pub(super) async fn cimd_portless_loopback_redirect_matches() {
    let host = Host::new();
    patch(
        &host,
        json!({"client_id_metadata_document_supported": true}),
    );
    let oauth = host.owner(pkce_config().client_id_metadata_document(
        CIMD,
        vec![
            "http://127.0.0.1/callback".into(),
            "http://[::1]:8765/callback".into(),
            "http://localhost:51004/callback".into(),
        ],
    ));
    // Any port matches a declared loopback redirect; the exact one is used.
    for redirect in [
        "http://127.0.0.1:51004/callback",
        "http://[::1]:51005/callback",
    ] {
        let options = PrepareOptions::new().redirect_uri(redirect);
        let pending = login(
            oauth
                .prepare_with(unbound(), options, budget())
                .await
                .unwrap(),
        );
        assert_eq!(client_id(&pending), CIMD);
        assert_eq!(
            query(pending.authorization_url(), "redirect_uri").unwrap(),
            redirect
        );
        host.network.reply(200, token("cimd"));
        oauth
            .complete(unbound(), callback(&pending), budget())
            .await
            .unwrap();
        assert_eq!(host.network.last_form()["redirect_uri"], redirect);
        host.store
            .records
            .lock()
            .unwrap()
            .values_mut()
            .for_each(|r| r.token = None);
    }
    // The path still has to match, and localhost is never accepted.
    for redirect in [
        "http://127.0.0.1:51004/other",
        "http://localhost:51004/callback",
        "http://user@127.0.0.1:51004/callback",
    ] {
        let options = PrepareOptions::new().redirect_uri(redirect);
        assert_eq!(
            code(oauth.prepare_with(unbound(), options, budget()).await),
            AuthErrorCode::InvalidConfiguration,
            "{redirect}"
        );
    }
    assert!(host.pending().is_empty());
}

// With redirects given only per login, the declared-redirect check runs only
// when a host prepare creates a login: lookups and refreshes keep working.
#[tokio::test]
async fn cimd_per_login_redirect_only_lookup_and_refresh_work() {
    let host = Host::new();
    patch(
        &host,
        json!({"client_id_metadata_document_supported": true}),
    );
    let oauth = host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .client_id_metadata_document(CIMD, vec!["http://127.0.0.1/callback".into()]),
    );
    let pending = login_at(&oauth, 51007).await;
    host.network.reply(200, pkce_token("cimd"));
    oauth
        .complete(unbound(), callback(&pending), budget())
        .await
        .unwrap();
    let recreated = host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .client_id_metadata_document(CIMD, vec!["http://127.0.0.1/callback".into()]),
    );
    assert_eq!(
        recreated
            .credential(unbound())
            .await
            .unwrap()
            .unwrap()
            .token,
        "cimd"
    );
    host.store.expire();
    host.network.reply(200, pkce_token("refreshed"));
    assert_eq!(
        recreated
            .credential(unbound())
            .await
            .unwrap()
            .unwrap()
            .token,
        "refreshed"
    );
    assert_eq!(host.network.last_form()["client_id"], CIMD);
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
        assert!(host.pending().is_empty());
    }
}

#[tokio::test]
pub(super) async fn dcr_pkce_registers_per_login() {
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    // Delivery paths never register.
    assert_eq!(
        code(oauth.challenge(unbound(), unauthorized()).await),
        AuthErrorCode::InteractionRequired
    );
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InteractionRequired
    );
    assert!(host.network.registrations().is_empty());
    // Each prepare registers anew with its login's exact loopback redirect.
    let first = login_at(&oauth, 51001).await;
    let second = login_at(&oauth, 51002).await;
    let registrations = host.network.registrations();
    assert_eq!(registrations.len(), 2);
    for (seen, port) in registrations.iter().zip([51001, 51002]) {
        let body = sent(seen);
        assert_eq!(
            body["redirect_uris"],
            json!([format!("http://127.0.0.1:{port}/callback")])
        );
        assert_eq!(body["application_type"], "native");
        assert_eq!(body["token_endpoint_auth_method"], "none");
        assert_eq!(
            body["grant_types"],
            json!(["authorization_code", "refresh_token"])
        );
    }
    assert_eq!(client_id(&first), "dcr-client-1");
    assert_eq!(client_id(&second), "dcr-client-2");
    // No registration record: each login holds its client.
    assert!(host.store.registration_record().is_none());
    assert_eq!(
        host.pending()
            .iter()
            .map(|l| l.client_id.clone())
            .collect::<Vec<_>>(),
        ["dcr-client-1", "dcr-client-2"]
    );
    // A non-loopback redirect is not a native application.
    let remote = PrepareOptions::new().redirect_uri("https://app.example/callback");
    login(
        oauth
            .prepare_with(unbound(), remote, budget())
            .await
            .unwrap(),
    );
    let body = sent(host.network.registrations().last().unwrap());
    assert!(body.get("application_type").is_none());
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
pub(super) async fn dcr_issued_client_stored_with_grant() {
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    host.seed(&oauth, unbound()).await;
    // The grant is keyed by the `dcr` identity and holds the issued client.
    let keys = grant_keys(&host);
    assert_eq!(keys.len(), 1);
    assert!(keys[0].contains("3:dcr23:") && !keys[0].contains("dcr-client"));
    assert_eq!(host.store.grant().unwrap().client_id, "dcr-client-1");
    assert!(host.store.binding().unwrap().client_id.is_empty());
    // Refresh uses the stored client.
    host.store.expire();
    host.network.reply(200, pkce_token("refreshed"));
    oauth.credential(unbound()).await.unwrap().unwrap();
    assert_eq!(host.network.last_form()["client_id"], "dcr-client-1");
    // A re-registered client replaces it under the same grant key.
    let pending = login(
        oauth
            .prepare_with_required(unbound(), &scopes(&["write"]), budget())
            .await
            .unwrap(),
    );
    assert_eq!(client_id(&pending), "dcr-client-2");
    host.network.reply(200, pkce_token("stepped-up"));
    oauth
        .complete(unbound(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(grant_keys(&host), keys);
    let grant = host.store.grant().unwrap();
    assert_eq!(grant.client_id, "dcr-client-2");
    assert_eq!(grant.token.unwrap().access_token, "stepped-up");
    host.store.expire();
    host.network.reply(200, pkce_token("again"));
    oauth.credential(unbound()).await.unwrap().unwrap();
    let form = host.network.last_form();
    assert_eq!(form["client_id"], "dcr-client-2");
    assert_eq!(form["refresh_token"], "stepped-up-refresh");
}

#[tokio::test]
pub(super) async fn dcr_pkce_invalid_client_drops_grant() {
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    host.seed(&oauth, unbound()).await;
    // invalid_client at completion ends only that login; the grant is kept.
    let write = scopes(&["write"]);
    let step_up = || oauth.prepare_with_required(unbound(), &write, budget());
    let other = login(step_up().await.unwrap());
    let kept = login(step_up().await.unwrap());
    host.network.reply(401, invalid_client());
    assert_eq!(
        code(oauth.complete(unbound(), callback(&other), budget()).await),
        AuthErrorCode::InteractionRequired
    );
    let grant = host.store.grant().unwrap();
    assert_eq!(grant.client_id, "dcr-client-1");
    assert_eq!(grant.token.as_ref().unwrap().access_token, "seed");
    assert_eq!(
        code(oauth.complete(unbound(), callback(&other), budget()).await),
        AuthErrorCode::InteractionRequired
    );
    assert_eq!(host.pending().len(), 1);
    assert_eq!(host.pending()[0].id, kept.id);
    // At refresh, a grant another writer replaced meanwhile is kept.
    host.store.expire();
    let records = host.store.records.clone();
    *host.network.on_token.lock().unwrap() = Some(Box::new(move || {
        for (key, record) in records.lock().unwrap().iter_mut() {
            if key.starts_with("ahp.oauth.grant:") {
                record.token.as_mut().unwrap().refresh_token = Some("newer-refresh".into());
                record.version = "newer".into();
            }
        }
    }));
    host.network.reply(401, invalid_client());
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InteractionRequired
    );
    let token = host.store.token();
    assert_eq!(token.refresh_token.as_deref(), Some("newer-refresh"));
    // So is one whose client another login replaced, even with the same token.
    let records = host.store.records.clone();
    *host.network.on_token.lock().unwrap() = Some(Box::new(move || {
        for (key, record) in records.lock().unwrap().iter_mut() {
            if key.starts_with("ahp.oauth.grant:") {
                record.client_id = "dcr-client-9".into();
                record.version = "replaced".into();
            }
        }
    }));
    host.network.reply(401, invalid_client());
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InteractionRequired
    );
    assert!(host.store.grant().unwrap().token.is_some());
    host.store
        .records
        .lock()
        .unwrap()
        .values_mut()
        .for_each(|r| {
            if r.client_id == "dcr-client-9" {
                r.client_id = "dcr-client-1".into();
            }
        });
    // When the record still holds the presented client and refresh token, the
    // grant is compare-and-deleted.
    host.network.reply(401, invalid_client());
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::InteractionRequired
    );
    assert!(host.store.grant().unwrap().token.is_none());
    assert_eq!(host.network.registrations().len(), 3);
    // The next prepare registers again.
    let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
    assert_eq!(client_id(&pending), "dcr-client-4");
}

#[tokio::test]
pub(super) async fn pending_logins_concurrent_per_state() {
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    let a = login_at(&oauth, 51001).await;
    let b = login_at(&oauth, 51002).await;
    assert_ne!(
        query(a.authorization_url(), "state"),
        query(b.authorization_url(), "state")
    );
    assert_eq!(
        (client_id(&a), client_id(&b)),
        ("dcr-client-1".into(), "dcr-client-2".into())
    );
    // A callback carrying one login's state on the other's redirect is refused
    // without consuming either.
    let mut crossed = callback(&a);
    crossed.set_port(Some(51002)).unwrap();
    assert_eq!(
        code(oauth.complete(unbound(), crossed, budget()).await),
        AuthErrorCode::AccessDenied
    );
    // Each callback completes only its own login, with its own client and redirect.
    for (pending, client, port) in [(&b, "dcr-client-2", 51002), (&a, "dcr-client-1", 51001)] {
        host.network.reply(200, pkce_token(client));
        let credential = oauth
            .complete(unbound(), callback(pending), budget())
            .await
            .unwrap();
        assert_eq!(credential.token, client);
        let form = host.network.last_form();
        assert_eq!(form["client_id"], client);
        assert_eq!(
            form["redirect_uri"],
            format!("http://127.0.0.1:{port}/callback")
        );
    }
    assert!(host.pending().is_empty());
}

#[tokio::test]
pub(super) async fn pending_completion_newest_grant_wins() {
    for persisted in [false, true] {
        let host = dcr_host();
        let oauth = host.owner({
            let c = pkce_config().dynamic_registration(policy());
            if persisted {
                c.persist_pending_logins()
            } else {
                c
            }
        });
        let older = login_at(&oauth, 51001).await;
        let newer = login_at(&oauth, 51002).await;
        host.network.reply(200, pkce_token("newer"));
        oauth
            .complete(unbound(), callback(&newer), budget())
            .await
            .unwrap();
        // Completing one leaves the other valid; its completion replaces the grant.
        assert_eq!(host.pending().len(), 1, "{persisted}");
        host.network.reply(200, pkce_token("older"));
        oauth
            .complete(unbound(), callback(&older), budget())
            .await
            .unwrap();
        let grant = host.store.grant().unwrap();
        assert_eq!(grant.client_id, "dcr-client-1", "{persisted}");
        assert_eq!(grant.token.unwrap().access_token, "older", "{persisted}");
        // The pair is consistent: refresh presents that client's refresh token.
        host.store.expire();
        host.network.reply(200, pkce_token("refreshed"));
        oauth.credential(unbound()).await.unwrap().unwrap();
        let form = host.network.last_form();
        assert_eq!(form["client_id"], "dcr-client-1", "{persisted}");
        assert_eq!(form["refresh_token"], "older-refresh", "{persisted}");
    }
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
            method: "client_secret_basic".into(),
            client_secret_expires_at: None,
            generation: "winner-generation".into(),
            secret_ref: Some("winner-ref".into()),
            digest: String::new(),
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
    assert_eq!(grant_keys(&host).len(), 3);
    for seen in host.network.tokens() {
        assert_eq!(seen.authorization, basic("dcr-client-1", "issued-secret-1"));
    }
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
    assert_eq!(grant_keys(&host).len(), 1);
    // A repeated invalid_client for the replacement: at most one re-registration
    // per operation, then credential_unavailable, counted as a failed registration.
    host.store.expire();
    host.network.reply(401, invalid_client());
    host.network.reply(401, invalid_client());
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::CredentialUnavailable
    );
    assert_eq!(host.network.registrations().len(), 3);
    assert_eq!(host.network.tokens().len(), 5);
    assert!(host.store.registration().is_none());
    let backoff = host.store.backoff().unwrap();
    assert_eq!(
        (backoff.attempts, backoff.code.as_str()),
        (1, "credential_unavailable")
    );
    // So the next operation sends no registration request until the backoff passes.
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::CredentialUnavailable
    );
    assert_eq!(host.network.registrations().len(), 3);
    assert_eq!(host.network.tokens().len(), 5);
}

// The failure count survives the re-registration after invalid_client, so a
// server that keeps rejecting fresh clients backs off longer each time; a
// successful token request with the client resets it.
#[tokio::test]
async fn cc_failure_count_resets_only_on_token_success() {
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    for (attempts, wait) in [(1, 60), (2, 120), (3, 240)] {
        for _ in 0..2 {
            host.network.reply(401, invalid_client());
        }
        assert_eq!(
            code(oauth.challenge(unbound(), unauthorized()).await),
            AuthErrorCode::CredentialUnavailable
        );
        assert_eq!(host.store.backoff().unwrap().attempts, attempts);
        assert!(
            (wait - 1..=wait).contains(&backoff_wait(&host)),
            "{attempts}"
        );
        elapse_backoff(&host);
    }
    // The next registration's client works: the count resets.
    host.network.reply(200, token("works"));
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "works"
    );
    assert!(host.store.backoff().is_none());
}

#[test]
fn cc_echoed_redirect_uris_any_list() {
    let request = json!({"grant_types": ["client_credentials"], "token_endpoint_auth_method": "client_secret_basic"});
    let accept = |redirects: Value| {
        let body = json!({"client_id": "c", "client_secret": "s", "redirect_uris": redirects});
        registration::accept_registration(
            OAuthFlow::ClientCredentials,
            &request,
            201,
            &serde_json::to_vec(&body).unwrap(),
            now(),
        )
        .map(|issued| issued.client_id)
    };
    assert_eq!(accept(json!([])).unwrap(), "c");
    assert_eq!(
        accept(json!(["https://elsewhere.example/cb"])).unwrap(),
        "c"
    );
    for invalid in [json!("https://elsewhere.example/cb"), json!({}), json!(1)] {
        assert_eq!(
            accept(invalid).err(),
            Some(AuthErrorCode::InvalidConfiguration)
        );
    }
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
    // A secret in a PKCE registration response is ignored, never persisted.
    let host = dcr_host();
    host.network.register_reply(
        201,
        json!({"client_id": "dcr-client", "client_secret": "pkce-secret", "client_secret_expires_at": 0}),
        None,
    );
    let oauth = host.owner(
        pkce_config()
            .dynamic_registration(policy())
            .persist_pending_logins(),
    );
    let pending = login(oauth.prepare(unbound(), budget()).await.unwrap());
    host.network.reply(200, token("pkce"));
    oauth
        .complete(unbound(), callback(&pending), budget())
        .await
        .unwrap();
    assert!(!host.store.dump().contains("pkce-secret"));
    assert!(!host.network.last_form().contains_key("client_secret"));
    assert!(host.network.tokens()[0].authorization.is_empty());
    assert!(host.secrets.values.lock().unwrap().is_empty());
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
        json!({"client_id_metadata_document_supported": true}),
    );
    // A step-up needs a new login and rediscovers metadata; DCR stays selected.
    let discovery = host.network.metadata_requests().len();
    let pending = login(
        oauth
            .prepare_with_required(unbound(), &scopes(&["write"]), budget())
            .await
            .unwrap(),
    );
    assert!(host.network.metadata_requests().len() > discovery);
    assert_eq!(client_id(&pending), "dcr-client-2");
    assert!(host.store.binding().unwrap().client_source == ClientSource::Dcr);
    // A removed registration endpoint does not move the working grant.
    patch(&host, json!({"registration_endpoint": null}));
    host.store.expire();
    host.network.reply(200, pkce_token("refreshed"));
    assert!(oauth.challenge(unbound(), unauthorized()).await.is_ok());
    assert_eq!(host.network.last_form()["client_id"], "dcr-client-1");
    assert!(host.store.binding().unwrap().client_source == ClientSource::Dcr);
    assert_eq!(host.network.registrations().len(), 2);
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

// ---- Lookup and backoff ----

#[tokio::test]
pub(super) async fn lookup_never_registers_pkce() {
    let host = dcr_host();
    let oauth = dcr_pkce(&host);
    login(oauth.prepare(unbound(), budget()).await.unwrap());
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
    // ... subject to the backoff.
    host.store.edit_registration(|r| {
        r.registration = None;
        r.backoff = Some(registration::Backoff {
            attempts: 1,
            next_attempt_at: now() + 60,
            code: "provider_failed".into(),
        });
    });
    host.store.expire();
    assert_eq!(
        code(oauth.credential(unbound()).await),
        AuthErrorCode::ProviderFailed
    );
    assert_eq!(host.network.registrations().len(), 2);
}

#[tokio::test]
pub(super) async fn dcr_response_validation_invalid_configuration() {
    for (cc, response) in [
        (
            false,
            json!({"client_id": "dcr-client", "redirect_uris": ["https://evil.example/cb"]}),
        ),
        (
            false,
            json!({"client_id": "dcr-client", "redirect_uris": ["http://127.0.0.1:9999/callback"]}),
        ),
        (
            false,
            json!({"client_id": "dcr-client", "token_endpoint_auth_method": "client_secret_basic"}),
        ),
        (true, json!({"client_id": "dcr-client"})),
        (
            true,
            json!({"client_id": "dcr-client", "client_secret": "not-a-real-secret", "token_endpoint_auth_method": "none"}),
        ),
    ] {
        let host = dcr_host();
        host.network.register_reply(201, response, None);
        let oauth = if cc { dcr_cc(&host) } else { dcr_pkce(&host) };
        assert_eq!(
            code(oauth.prepare(unbound(), budget()).await),
            AuthErrorCode::InvalidConfiguration
        );
        assert_eq!(host.network.registrations().len(), 1);
        assert!(host.store.registration().is_none());
        assert!(host.pending().is_empty());
        assert!(!host.store.dump().contains("not-a-real-secret"));
        assert!(host.secrets.values.lock().unwrap().is_empty());
    }
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
    let after = host.store.registration().unwrap().secret_ref.unwrap();
    assert_eq!(
        *host.secrets.deleted.lock().unwrap(),
        [old.clone(), new.clone()]
    );
    // Changed registration settings: delivery keeps the usable record, and a host
    // `prepare` replaces it, deleting the old secret.
    let changed = cc_with(&host, policy().software_id("example-adapter"));
    host.store.expire();
    host.network.reply(200, token("delivered"));
    assert!(changed.credential(unbound()).await.unwrap().is_some());
    assert_eq!(host.network.registrations().len(), 3);
    host.store.expire();
    host.network.reply(200, token("prepared"));
    ready(changed.prepare(unbound(), budget()).await.unwrap());
    let registrations = host.network.registrations();
    assert_eq!(registrations.len(), 4);
    assert_eq!(sent(&registrations[3])["software_id"], "example-adapter");
    assert_eq!(*host.secrets.deleted.lock().unwrap(), [old, new, after]);
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
        (400, AuthErrorCode::InvalidConfiguration),
    ] {
        let host = dcr_host();
        let (a, b) = (dcr_cc(&host), dcr_cc(&host));
        host.network.register_reply(status, json!({}), None);
        assert_eq!(code(a.challenge(unbound(), unauthorized()).await), expected);
        assert!((59..=60).contains(&backoff_wait(&host)), "{status}");
        // Meanwhile every path and process returns the last failure's code, with
        // no registration request.
        for result in [
            a.credential(unbound()).await.map(|_| ()),
            b.credential(unbound()).await.map(|_| ()),
            b.challenge(unbound(), unauthorized()).await,
        ] {
            assert_eq!(code(result), expected, "{status}");
        }
        assert_eq!(host.network.registrations().len(), 1, "{status}");
        assert_eq!(host.store.backoff().unwrap().attempts, 1);
        // After it passes, the next failure doubles it.
        elapse_backoff(&host);
        host.network.register_reply(status, json!({}), None);
        assert_eq!(code(b.credential(unbound()).await), expected);
        assert!((119..=120).contains(&backoff_wait(&host)), "{status}");
        // An unattended host recovers automatically once the backoff passes.
        elapse_backoff(&host);
        host.network.reply(200, token("repaired"));
        assert_eq!(
            a.credential(unbound()).await.unwrap().unwrap().token,
            "repaired"
        );
        assert!(host.store.backoff().is_none());
        assert_eq!(host.network.registrations().len(), 3);
    }
    // A host `prepare` bypasses the backoff.
    let host = dcr_host();
    let oauth = dcr_cc(&host);
    host.network.register_reply(503, json!({}), None);
    assert_eq!(
        code(oauth.challenge(unbound(), unauthorized()).await),
        AuthErrorCode::ProviderFailed
    );
    cc_ready(&host, &oauth, unbound()).await;
    assert_eq!(host.network.registrations().len(), 2);
    assert!(host.store.backoff().is_none());
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
        let waited = backoff_wait(&host);
        assert!(
            (wait - 1..=wait).contains(&waited),
            "{retry_after}: {waited}"
        );
    }
}

// ---- Detached commit, eligibility and shared backoff ----

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

// Concurrent processes sharing the store: one registers and fails, the other
// waits on the registration-key lock, then sees the shared backoff.
#[tokio::test]
async fn backoff_shared_across_concurrent_processes() {
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
        assert_eq!(
            [code(x), code(y)],
            [AuthErrorCode::ProviderFailed, AuthErrorCode::ProviderFailed]
        );
        assert_eq!(host.network.registrations().len(), attempt);
        assert_eq!(host.store.backoff().unwrap().attempts, attempt as u32);
        elapse_backoff(&host);
    }
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
        backoff_wait(&host)
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
    assert!((298..=300).contains(&near), "{near}");
    assert!((3599..=3600).contains(&wait("Wed, 21 Oct 2099 07:28:00 GMT").await));
    assert!((59..=60).contains(&wait(&at(-300)).await));
    assert!((119..=120).contains(&wait("120").await));
    assert!((59..=60).contains(&wait("not a date").await));
}
