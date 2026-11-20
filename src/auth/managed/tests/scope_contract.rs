//! The cross-SDK scope and step-up contract, one test per rule. Scope sets on
//! errors are the operation's required set R = host-required ∪ explicit ∪
//! challenged, deduplicated and sorted.
use super::*;

fn cc_client(host: &Host, required: &[&str]) -> ManagedOAuth {
    host.owner(
        OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .required_scopes(scopes(required))
            .client_secret(
                "secret-ref",
                ClientSecret::new("secret".into()),
                TokenAuthMethod::ClientSecretBasic,
            ),
    )
}
fn requests(host: &Host) -> usize {
    host.network.seen.lock().unwrap().len()
}
#[track_caller]
fn assert_error(error: HookError, expected: AuthErrorCode, required: &[&str]) {
    assert_eq!(error.auth_code(), Some(expected));
    assert_eq!(error.required_scopes(), scopes(required));
}
fn with_preset(mut ctx: AuthContext, preset: &[&str]) -> AuthContext {
    ctx.authentication.as_mut().unwrap()["scopes"] = json!(preset);
    ctx
}
fn step_up(scope: &str) -> AuthChallenge {
    challenge(
        403,
        &format!(r#"Bearer error="insufficient_scope", scope="{scope}""#),
        None,
    )
}

/// Rule 1: preset scopes are the client's requested scopes: requested, never
/// required or reported; a preset whose scopes differ is a configuration error.
#[tokio::test]
pub(super) async fn rule1_preset_scopes_are_requested_not_required() {
    let host = Host::new();
    let oauth = host.owner(
        OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
            .scopes(
                scopes(&["files", "read"]),
                scopes(&["files", "read", "write"]),
            )
            .client_secret(
                "secret-ref",
                ClientSecret::new("secret".into()),
                TokenAuthMethod::ClientSecretBasic,
            ),
    );
    let mismatched = with_preset(cc_context(), &["files"]);
    assert_error(
        oauth.credential(mismatched).await.err().unwrap(),
        AuthErrorCode::InvalidConfiguration,
        &[],
    );
    assert_eq!(requests(&host), 0);
    let preset = with_preset(cc_context(), &["read", "files"]);
    host.network.reply(
        200,
        json!({"access_token":"narrow","token_type":"Bearer","scope":"read"}),
    );
    let credential = oauth.credential(preset.clone()).await.unwrap().unwrap();
    assert_eq!(credential.token, "narrow");
    assert_eq!(host.network.last_form()["scope"], "files read");
    assert_eq!(host.store.token().scopes, scopes(&["read"]));
    let error = oauth
        .challenge(preset, step_up("admin"))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["admin"]);

    // PKCE: consent requests the preset scopes; a grant lacking one completes.
    let host = Host::new();
    let oauth = host.pkce(|c| c.scopes(scopes(&["files", "read"]), Vec::new()));
    let preset = with_preset(context(), &["files", "read"]);
    let pending = login(oauth.prepare(preset.clone(), budget()).await.unwrap());
    assert_eq!(
        query(pending.authorization_url(), "scope").unwrap(),
        "files read"
    );
    host.network.reply(
        200,
        json!({"access_token":"a","token_type":"Bearer","scope":"read"}),
    );
    oauth
        .complete(preset.clone(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(oauth.credential(preset).await.unwrap().unwrap().token, "a");
}

/// Rule 2: every scoped error carries the full required set.
#[tokio::test]
pub(super) async fn rule2_one_scope_set() {
    let host = Host::new();
    let oauth = host.pkce(|c| c.required_scopes(scopes(&["read"])));
    let seeded = host.seed(&oauth, context()).await;
    assert_eq!(host.store.token().scopes, scopes(&["read"]));
    // Step-up.
    let error = oauth
        .challenge(context(), step_up("write"))
        .await
        .err()
        .unwrap();
    assert_error(
        error,
        AuthErrorCode::InteractionRequired,
        &["read", "write"],
    );
    // Ceiling refusal.
    let error = oauth
        .challenge(context(), step_up("admin"))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["admin", "read"]);
    let error = oauth
        .prepare_with_required(context(), &scopes(&["admin", "admin"]), budget())
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["admin", "read"]);
    // A narrower grant from complete().
    let pending = login(
        oauth
            .prepare_with_required(context(), &scopes(&["write"]), budget())
            .await
            .unwrap(),
    );
    host.network.reply(
        200,
        json!({"access_token":"narrow","token_type":"Bearer","scope":"read"}),
    );
    let error = oauth
        .complete(context(), callback(&pending), budget())
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["read", "write"]);
    assert_ne!(host.store.token().generation, seeded.attempt_id);
}

/// Rule 3: a required scope outside the ceiling fails locally on every path,
/// with zero network requests; a 401's token is retired first.
#[tokio::test]
pub(super) async fn rule3_ceiling_refusal_before_network() {
    let host = Host::new();
    let seeded = host.seed(&host.pkce(|c| c), context()).await;
    let before = requests(&host);
    let bad = host.pkce(|c| c.required_scopes(scopes(&["admin"])));
    // Cached binding, delivery.
    assert_error(
        bad.credential(context()).await.err().unwrap(),
        AuthErrorCode::AccessDenied,
        &["admin"],
    );
    // Preemptive lookup for an unbound endpoint.
    assert_error(
        bad.credential(unbound()).await.err().unwrap(),
        AuthErrorCode::AccessDenied,
        &["admin"],
    );
    // prepare, with an explicit requirement too.
    assert_error(
        bad.prepare(context(), budget()).await.err().unwrap(),
        AuthErrorCode::AccessDenied,
        &["admin"],
    );
    assert_error(
        bad.prepare_with_required(context(), &scopes(&["write"]), budget())
            .await
            .err()
            .unwrap(),
        AuthErrorCode::AccessDenied,
        &["admin", "write"],
    );
    // Challenge.
    assert_error(
        bad.challenge(context(), step_up("write"))
            .await
            .err()
            .unwrap(),
        AuthErrorCode::AccessDenied,
        &["admin", "write"],
    );
    assert!(!host.store.token().access_rejected);
    // A 401 retires the rejected token before refusing.
    let rejected = challenge(401, "Bearer", Some(&seeded.attempt_id));
    assert_error(
        bad.challenge(context(), rejected).await.err().unwrap(),
        AuthErrorCode::AccessDenied,
        &["admin"],
    );
    assert!(host.store.token().access_rejected);
    assert_eq!(requests(&host), before);
    assert!(host.pending().is_empty());

    // Fresh client credentials: nothing is fetched.
    let host = Host::new();
    let bad = cc_client(&host, &["admin"]);
    assert_error(
        bad.credential(cc_context()).await.err().unwrap(),
        AuthErrorCode::AccessDenied,
        &["admin"],
    );
    assert_eq!(requests(&host), 0);
}

/// Rule 4: requested scopes outside the ceiling are a configuration error.
#[tokio::test]
pub(super) async fn rule4_requested_outside_ceiling_invalid_configuration() {
    let host = Host::new();
    let config = OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
        .scopes(scopes(&["read", "admin"]), scopes(&["read"]))
        .client_secret(
            "secret-ref",
            ClientSecret::new("secret".into()),
            TokenAuthMethod::ClientSecretBasic,
        );
    let error = ManagedOAuth::new(
        config,
        host.network.clone(),
        host.policy.clone(),
        host.store.clone(),
    )
    .err()
    .unwrap();
    assert_error(error, AuthErrorCode::InvalidConfiguration, &[]);
    // An invalid host-required scope token is a configuration error too.
    let config = OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
        .redirect_uri("http://127.0.0.1/callback")
        .required_scopes(scopes(&["bad\\scope"]));
    let error = ManagedOAuth::new(
        config,
        host.network.clone(),
        host.policy.clone(),
        host.store.clone(),
    )
    .err()
    .unwrap();
    assert_error(error, AuthErrorCode::InvalidConfiguration, &[]);
    // A preset's requested scope outside the ceiling.
    let oauth = host.pkce(|c| c);
    let preset = with_preset(context(), &["admin"]);
    let error = oauth.prepare(preset.clone(), budget()).await.err().unwrap();
    assert_eq!(error.auth_recovery(), Some(AuthRecovery::Configure));
    assert_error(error, AuthErrorCode::InvalidConfiguration, &[]);
    assert_error(
        oauth.credential(preset).await.err().unwrap(),
        AuthErrorCode::InvalidConfiguration,
        &[],
    );
    assert_eq!(requests(&host), 0);
}

/// Rule 5: a 401 retires the token; its `scope` (within the ceiling) is
/// requested by the next acquisition or sign-in, never required.
#[tokio::test]
pub(super) async fn rule5_unauthorized_scope_is_requested_not_required() {
    let host = Host::new();
    let oauth = cc_client(&host, &[]);
    host.network.reply(
        200,
        json!({"access_token":"first","token_type":"Bearer","scope":"read"}),
    );
    let first = oauth.credential(cc_context()).await.unwrap().unwrap();
    host.network.reply(
        200,
        json!({"access_token":"second","token_type":"Bearer","scope":"read"}),
    );
    let rejected = challenge(
        401,
        r#"Bearer scope="write admin""#,
        Some(&first.attempt_id),
    );
    oauth.challenge(cc_context(), rejected).await.unwrap();
    // `admin` is outside the ceiling: not requested, and no access_denied.
    assert_eq!(host.network.last_form()["scope"], "read write");
    let second = oauth.credential(cc_context()).await.unwrap().unwrap();
    assert_eq!(second.token, "second");
    host.network.reply(
        200,
        json!({"access_token":"third","token_type":"Bearer","scope":"read"}),
    );
    let rejected = challenge(401, r#"Bearer scope="admin""#, Some(&second.attempt_id));
    oauth.challenge(cc_context(), rejected).await.unwrap();
    assert_eq!(host.network.last_form()["scope"], "read");
    assert_eq!(host.network.tokens().len(), 3);

    // PKCE: the next sign-in requests the 401 scope, once.
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    host.network
        .reply(200, json!({"access_token":"only","token_type":"Bearer"}));
    let only = oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    let rejected = challenge(401, r#"Bearer scope="write""#, Some(&only.attempt_id));
    let error = oauth.challenge(context(), rejected).await.err().unwrap();
    assert_error(error, AuthErrorCode::InteractionRequired, &[]);
    assert!(host.store.token().access_rejected);
    let next = login(oauth.prepare(context(), budget()).await.unwrap());
    assert_eq!(
        query(next.authorization_url(), "scope").unwrap(),
        "read write"
    );
    let later = login(oauth.prepare(context(), budget()).await.unwrap());
    assert_eq!(query(later.authorization_url(), "scope").unwrap(), "read");
}

/// Rule 6: a scope-less 403 `insufficient_scope` uses host-required scopes,
/// otherwise fails access_denied with no scopes.
#[tokio::test]
pub(super) async fn rule6_insufficient_scope_without_scope() {
    let bare = || challenge(403, r#"Bearer error="insufficient_scope""#, None);
    let host = Host::new();
    let error = cc_client(&host, &[])
        .challenge(cc_context(), bare())
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &[]);
    assert_eq!(requests(&host), 0);
    let oauth = cc_client(&host, &["write"]);
    host.network.reply(
        200,
        json!({"access_token":"w","token_type":"Bearer","scope":"read write"}),
    );
    oauth.challenge(cc_context(), bare()).await.unwrap();
    assert_eq!(host.network.last_form()["scope"], "read write");
}

/// Rule 7: a malformed challenge fails closed: access_denied, no scopes,
/// recovery none, and it is no transport auth retry.
#[tokio::test]
pub(super) async fn rule7_malformed_challenge_scope() {
    let host = Host::new();
    let oauth = cc_client(&host, &["write"]);
    for (status, header) in [
        (403, r#"Bearer error="insufficient_scope", scope="""#),
        (
            403,
            r#"Bearer error="insufficient_scope", scope="read  write""#,
        ),
        (403, r#"Bearer error="insufficient_scope", scope=" write""#),
        (403, r#"Bearer error="insufficient_scope", scope="write ""#),
        (403, r#"Bearer error="insufficient_scope", scope="wr\\ite""#),
        (
            403,
            "Bearer error=\"insufficient_scope\", scope=\"read\twrite\"",
        ),
        (
            403,
            r#"Bearer error="insufficient_scope", scope="write", scope="read""#,
        ),
        (401, r#"Bearer scope="read  write""#),
    ] {
        let error = oauth
            .challenge(cc_context(), challenge(status, header, None))
            .await
            .err()
            .unwrap();
        assert_eq!(error.auth_recovery(), Some(AuthRecovery::None), "{header}");
        assert_error(error, AuthErrorCode::AccessDenied, &[]);
        if status == 403 {
            assert!(
                !crate::auth::challenge::insufficient_scope(header),
                "{header}"
            );
        }
    }
    assert_eq!(requests(&host), 0);
}

/// Rule 8: insufficient_scope for scopes the grant records as granted fails
/// access_denied with R: no replay, no loop, no login.
#[tokio::test]
pub(super) async fn rule8_insufficient_scope_for_granted_scopes() {
    let host = Host::new();
    let oauth = cc_client(&host, &[]);
    host.network.reply(
        200,
        json!({"access_token":"wide","token_type":"Bearer","scope":"read write"}),
    );
    oauth.credential(cc_context()).await.unwrap().unwrap();
    let error = oauth
        .challenge(cc_context(), step_up("write"))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["write"]);
    assert_eq!(host.network.tokens().len(), 1);

    let host = Host::new();
    let oauth = host.pkce(|c| c.required_scopes(scopes(&["read"])));
    host.seed(&oauth, context()).await;
    let error = oauth
        .challenge(context(), step_up("read"))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["read"]);
    assert_eq!(host.network.tokens().len(), 1);
    assert!(host.pending().is_empty());
}

/// Rule 9: complete() enforces the required set the login was prepared with.
#[tokio::test]
pub(super) async fn rule9_complete_enforces_login_required_set() {
    let host = Host::new();
    let oauth = host.pkce(|c| c.required_scopes(scopes(&["read"])));
    let pending = login(
        oauth
            .prepare_with_required(context(), &scopes(&["write"]), budget())
            .await
            .unwrap(),
    );
    assert_eq!(host.pending()[0].required, scopes(&["read", "write"]));
    host.network.reply(
        200,
        json!({"access_token":"narrow","refresh_token":"kept","token_type":"Bearer","scope":"read"}),
    );
    let error = oauth
        .complete(context(), callback(&pending), budget())
        .await
        .err()
        .unwrap();
    assert!(error.login_ended());
    assert_error(error, AuthErrorCode::AccessDenied, &["read", "write"]);
    let token = host.store.token();
    assert_eq!(token.scopes, scopes(&["read"]));
    assert_eq!(token.refresh_token.as_deref(), Some("kept"));
    assert!(host.pending().is_empty(), "login consumed");
    let error = oauth
        .complete(context(), callback(&pending), budget())
        .await
        .err()
        .unwrap();
    assert!(error.login_ended());
    assert_error(error, AuthErrorCode::InteractionRequired, &[]);
}

/// Rule 10: refresh and client-credentials grants narrower than R fail
/// access_denied with R; the grant is persisted.
#[tokio::test]
pub(super) async fn rule10_narrower_grants() {
    let host = Host::new();
    let oauth = cc_client(&host, &["read"]);
    host.network.reply(
        200,
        json!({"access_token":"narrow","token_type":"Bearer","scope":"read"}),
    );
    let error = oauth
        .challenge(cc_context(), step_up("write"))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["read", "write"]);
    assert_eq!(host.store.token().access_token, "narrow");

    let host = Host::new();
    *host.policy.select.lock().unwrap() = scopes(&["read", "write"]);
    let oauth = host.pkce(|c| c.scopes(scopes(&["read", "write"]), scopes(&["read", "write"])));
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    host.network.reply(200, json!({"access_token":"a","refresh_token":"r","token_type":"Bearer","scope":"read write","expires_in":1}));
    oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    host.store.expire();
    host.network.reply(
        200,
        json!({"access_token":"b","refresh_token":"r2","token_type":"Bearer","scope":"read"}),
    );
    let error = oauth
        .prepare_with_required(context(), &scopes(&["write"]), budget())
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["write"]);
    let token = host.store.token();
    assert_eq!(token.scopes, scopes(&["read"]));
    assert_eq!(token.refresh_token.as_deref(), Some("r2"));
}

/// Rule 11: host-policy errors never carry scopes; the SDK's own scope
/// refusals of a policy selection do.
#[tokio::test]
pub(super) async fn rule11_host_policy_errors_carry_no_scopes() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let write = scopes(&["write"]);
    for code in [
        AuthErrorCode::AccessDenied,
        AuthErrorCode::InteractionRequired,
    ] {
        *host.policy.refuse.lock().unwrap() = Some(fail(code).with_required_scopes(&write));
        let error = oauth
            .prepare_with_required(context(), &write, budget())
            .await
            .err()
            .unwrap();
        assert_error(error, code, &[]);
        let error = oauth
            .challenge(context(), step_up("write"))
            .await
            .err()
            .unwrap();
        assert_error(error, code, &[]);
    }
    *host.policy.refuse.lock().unwrap() = None;
    *host.policy.refuse_endpoints.lock().unwrap() =
        Some(fail(AuthErrorCode::AccessDenied).with_required_scopes(&write));
    let error = oauth
        .prepare_with_required(context(), &write, budget())
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &[]);
    *host.policy.refuse_endpoints.lock().unwrap() = None;
    // The policy omits a required scope: the SDK's scope refusal names R.
    host.policy.omit_required.store(true, Ordering::SeqCst);
    let error = oauth
        .prepare_with_required(context(), &write, budget())
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["write"]);
    assert!(host.pending().is_empty());
}

/// Rule 12: every complete() error reports whether its login has ended.
#[tokio::test]
pub(super) async fn rule12_complete_errors_report_login_ended() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    let ended = |result: Result<BearerCredential, HookError>| {
        let error = result.err().unwrap();
        (error.auth_code().unwrap(), error.login_ended())
    };
    // Rejected before the claim: still pending.
    let mut wrong_redirect = callback(&pending);
    wrong_redirect.set_path("/elsewhere");
    assert_eq!(
        ended(oauth.complete(context(), wrong_redirect, budget()).await),
        (AuthErrorCode::AccessDenied, false)
    );
    let mut duplicate = callback(&pending);
    duplicate.query_pairs_mut().append_pair("code", "again");
    assert_eq!(
        ended(oauth.complete(context(), duplicate, budget()).await),
        (AuthErrorCode::AccessDenied, false)
    );
    // Unknown or missing state: no such login.
    let mut unknown = callback(&pending);
    unknown.set_query(Some("state=unknown&code=x"));
    assert_eq!(
        ended(oauth.complete(context(), unknown, budget()).await),
        (AuthErrorCode::InteractionRequired, true)
    );
    let mut stateless = callback(&pending);
    stateless.set_query(Some("code=x"));
    assert_eq!(
        ended(oauth.complete(context(), stateless, budget()).await),
        (AuthErrorCode::InteractionRequired, true)
    );
    assert_eq!(host.pending().len(), 1);
    // A consent denial consumes it.
    let mut denied = callback(&pending);
    denied.set_query(Some(&format!(
        "state={}&error=access_denied",
        query(pending.authorization_url(), "state").unwrap()
    )));
    assert_eq!(
        ended(oauth.complete(context(), denied, budget()).await),
        (AuthErrorCode::AccessDenied, true)
    );
    assert_eq!(
        ended(
            oauth
                .complete(context(), callback(&pending), budget())
                .await
        ),
        (AuthErrorCode::InteractionRequired, true)
    );
    // Expired.
    let short = host.pkce(|c| c.login_lifetime(Duration::from_millis(20)));
    let expiring = login(short.prepare(context(), budget()).await.unwrap());
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        ended(
            short
                .complete(context(), callback(&expiring), budget())
                .await
        ),
        (AuthErrorCode::InteractionRequired, true)
    );
    assert!(host.network.tokens().is_empty());
}

// ---- Conformance vectors: `scope_decisions` and `completions` ----

fn list(value: &Value) -> Vec<String> {
    if value.is_array() {
        strings(value)
    } else {
        Vec::new()
    }
}
fn config_for(flow: &str, requested: Vec<String>, ceiling: Vec<String>) -> OAuthClientConfig {
    if flow == "client_credentials" {
        OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
            .scopes(requested, ceiling)
            .client_secret(
                "secret-ref",
                ClientSecret::new("secret".into()),
                TokenAuthMethod::ClientSecretBasic,
            )
    } else {
        OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
            .scopes(requested, ceiling)
            .redirect_uri("http://127.0.0.1/callback")
    }
}
/// Store a grant of exactly `granted` with a permissive client; a PKCE grant
/// has no refresh token. Returns its attempt id.
async fn seed_grant(host: &Host, flow: &str, ctx: &AuthContext, granted: &[String]) -> String {
    let preset = ctx.target().unwrap().scopes().to_vec();
    let all = union(
        &union(granted, &host.policy.select.lock().unwrap()),
        &preset,
    );
    let seeder = host.owner(config_for(flow, preset, all));
    let reply = json!({"access_token":"seeded","token_type":"Bearer","expires_in":3600,"scope":granted.join(" ")});
    let credential = if flow == "client_credentials" {
        host.network.reply(200, reply);
        seeder.credential(ctx.clone()).await.unwrap().unwrap()
    } else {
        let pending = login(seeder.prepare(ctx.clone(), budget()).await.unwrap());
        host.network.reply(200, reply);
        seeder
            .complete(ctx.clone(), callback(&pending), budget())
            .await
            .unwrap()
    };
    assert_eq!(host.store.token().scopes, union(granted, &[]));
    credential.attempt_id
}
fn authorization_server_requests(host: &Host) -> usize {
    host.network
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|seen| seen.usage != EndpointUse::ResourceMetadata)
        .count()
}

#[tokio::test]
async fn canonical_scope_decision_vectors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let mut not_applicable = Vec::new();
    for vector in fixture["scope_decisions"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let (input, expect) = (&vector["input"], &vector["expect"]);
        // Rust has no host token-validation callback.
        if input["host_error"]["callback"] == "token_validation" {
            not_applicable.push(id);
            continue;
        }
        let destination = input["host_error"]["callback"] == "destination";
        let flow = input["flow"].as_str().unwrap();
        let path = input["path"].as_str().unwrap();
        let requested = list(&input["requested"]);
        let host = Host::new();
        *host.policy.select.lock().unwrap() = requested.clone();
        let mut ctx = if flow == "client_credentials" {
            cc_context()
        } else {
            context()
        };
        let preset = list(&input["preset_scopes"]);
        if !preset.is_empty() {
            ctx.authentication.as_mut().unwrap()["scopes"] = json!(preset);
        }
        let mut config = config_for(flow, requested.clone(), list(&input["ceiling"]));
        if destination {
            // A dynamically registered client-credentials client whose
            // registration endpoint host destination policy refuses.
            assert_eq!(
                input["host_error"]["target"], "registration_endpoint",
                "{id}"
            );
            host.network.dcr.store(true, Ordering::SeqCst);
            host.network
                .refuse_registration
                .store(true, Ordering::SeqCst);
            config = OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
                .scopes(requested.clone(), list(&input["ceiling"]))
                .dynamic_registration(RegistrationPolicy::new(
                    "https://issuer.example",
                    "Example Adapter",
                ))
                .client_secret_storage(host.secrets.clone());
            ctx.authentication = None;
        }
        let config = config.required_scopes(list(&input["host_required"]));
        let oauth = match ManagedOAuth::new(
            config,
            host.network.clone(),
            host.policy.clone(),
            host.store.clone(),
        ) {
            Ok(mut oauth) => {
                oauth.pending = host.logins.clone();
                oauth
            }
            Err(error) => {
                assert_eq!(error.auth_code().unwrap().as_str(), expect["code"], "{id}");
                continue;
            }
        };
        let seeded = match input["granted"].as_array() {
            Some(_) => Some(seed_grant(&host, flow, &ctx, &list(&input["granted"])).await),
            None => None,
        };
        if input["binding"] == "unbound" {
            ctx.authentication = None;
        }
        if let Some(error) = input["host_error"].as_object().filter(|_| !destination) {
            let code = [
                AuthErrorCode::AccessDenied,
                AuthErrorCode::InteractionRequired,
            ]
            .into_iter()
            .find(|code| code.as_str() == error["code"])
            .unwrap();
            *host.policy.refuse.lock().unwrap() =
                Some(fail(code).with_required_scopes(&list(&error["scopes"])));
        }
        let acquisition = list(&expect["acquisition_scopes"]).join(" ");
        if expect["code"].is_null() && expect["action"] == "acquire" {
            host.network.reply(
                200,
                json!({"access_token":"next","token_type":"Bearer","scope":acquisition}),
            );
        }
        let (before, before_as) = (requests(&host), authorization_server_requests(&host));
        let explicit = list(&input["explicit"]);
        let result: Result<Option<Preparation>, HookError> = match path {
            "cached" | "credential" | "fresh" => oauth
                .credential(ctx.clone())
                .await
                .map(|c| c.map(Preparation::Ready)),
            "preemptive" => oauth
                .credential(unbound())
                .await
                .map(|c| c.map(Preparation::Ready)),
            "prepare" => oauth
                .prepare_with_required(ctx.clone(), &explicit, budget())
                .await
                .map(Some),
            "challenge" => {
                let status = input["challenge"]["status"].as_u64().unwrap() as u16;
                let header = input["challenge"]["www_authenticate"].as_str().unwrap();
                let attempt = seeded.as_deref().filter(|_| status == 401);
                oauth
                    .challenge(ctx.clone(), challenge(status, header, attempt))
                    .await
                    .map(|()| None)
            }
            other => panic!("{id}: unknown path {other}"),
        };
        if let Some(expected) = expect["authorization_server_requests"].as_u64() {
            let made = (authorization_server_requests(&host) - before_as) as u64;
            assert_eq!(made, expected, "{id}: authorization-server requests");
        }
        if let Some(expected) = expect["network_calls"].as_u64() {
            let made = (requests(&host) - before) as u64;
            // An unbound target's allowance is protected-resource discovery;
            // host-required scopes here are static, so it is decided before.
            if input["binding"] == "unbound" {
                assert!(made <= expected, "{id}: network calls {made}");
            } else {
                assert_eq!(made, expected, "{id}: network calls");
            }
        }
        if expect["retired"] == true {
            let token = host.store.token();
            assert!(
                token.access_rejected || Some(&token.generation) != seeded.as_ref(),
                "{id}: retired"
            );
        }
        match result {
            Ok(outcome) => {
                assert!(
                    expect["code"].is_null(),
                    "{id}: expected {}",
                    expect["code"]
                );
                match expect["action"].as_str().unwrap() {
                    "use" => assert!(matches!(outcome, Some(Preparation::Ready(_))), "{id}"),
                    "acquire" => {
                        assert_eq!(host.network.last_form()["scope"], acquisition, "{id}")
                    }
                    "login" => {
                        let pending = login(outcome.unwrap());
                        assert_eq!(
                            query(pending.authorization_url(), "scope").unwrap(),
                            acquisition,
                            "{id}"
                        );
                        assert_eq!(
                            host.pending()[0].required,
                            list(&expect["required"]),
                            "{id}"
                        );
                    }
                    other => panic!("{id}: unknown action {other}"),
                }
            }
            Err(error) => {
                assert_eq!(error.auth_code().unwrap().as_str(), expect["code"], "{id}");
                assert_eq!(error.required_scopes(), list(&expect["scopes"]), "{id}");
                // The next sign-in requests the acquisition scopes.
                if !acquisition.is_empty()
                    && error.auth_code() == Some(AuthErrorCode::InteractionRequired)
                {
                    *host.policy.refuse.lock().unwrap() = None;
                    let pending = login(
                        oauth
                            .prepare_with_required(ctx.clone(), error.required_scopes(), budget())
                            .await
                            .unwrap(),
                    );
                    assert_eq!(
                        query(pending.authorization_url(), "scope").unwrap(),
                        acquisition,
                        "{id}"
                    );
                }
            }
        }
    }
    assert_eq!(
        not_applicable,
        ["host-policy-access-denied-scopes-stripped"]
    );
}

#[tokio::test]
async fn canonical_completion_vectors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for vector in fixture["completions"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let (input, expect) = (&vector["input"], &vector["expect"]);
        let source = input["client_source"].as_str().unwrap_or("preregistered");
        let stored = list(&input["stored_required"]);
        let granted = list(&input["granted"]);
        let host = Host::new();
        host.policy.select.lock().unwrap().clear();
        *host.network.issuer_patch.lock().unwrap() = json!({
            "authorization_response_iss_parameter_supported": true,
            "client_id_metadata_document_supported": source == "cimd",
        });
        host.network.dcr.store(source == "dcr", Ordering::SeqCst);
        const CIMD: &str = "https://adapter.example/oauth/client.json";
        let client = |ceiling: Vec<String>| {
            let config = match source {
                "preregistered" => {
                    OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
                }
                "cimd" => {
                    OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
                        .client_id_metadata_document(CIMD, vec!["http://127.0.0.1/callback".into()])
                }
                "dcr" => {
                    OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
                        .dynamic_registration(RegistrationPolicy::new(
                            "https://issuer.example",
                            "Example Adapter",
                        ))
                }
                other => panic!("{id}: unknown client source {other}"),
            };
            config
                .scopes(Vec::new(), ceiling)
                .redirect_uri("http://127.0.0.1/callback")
        };
        // A pre-registered client uses its preset; CIMD and DCR learn the binding.
        let ctx = if source == "preregistered" {
            context()
        } else {
            unbound()
        };
        let wide = union(&union(&stored, &granted), &list(&input["ceiling"]));
        let lifetime = if input["pending"] == "expired" {
            Duration::from_millis(1)
        } else {
            MAX_LOGIN_LIFETIME
        };
        let preparer = host.owner(client(wide).login_lifetime(lifetime));
        let pending = login(
            preparer
                .prepare_with_required(ctx.clone(), &stored, budget())
                .await
                .unwrap(),
        );
        // Another pending login, named by a mismatched callback state.
        let other = if input["callback"] == "state_mismatch" {
            let other = preparer
                .prepare_with_required(ctx.clone(), &stored, budget())
                .await
                .unwrap();
            Some(query(login(other).authorization_url(), "state").unwrap())
        } else {
            None
        };
        match input["pending"].as_str().unwrap() {
            "expired" => tokio::time::sleep(Duration::from_millis(10)).await,
            "ended" => preparer
                .cancel_login(pending.clone(), budget())
                .await
                .unwrap(),
            _ => {}
        }
        let state = query(pending.authorization_url(), "state").unwrap();
        let state = if input["pending"] == "unknown" {
            "unknown".to_owned()
        } else {
            other.unwrap_or(state)
        };
        let mut url = Url::parse(pending.redirect_uri()).unwrap();
        let mut pairs = vec![
            ("state", state),
            ("code", "fake-code".into()),
            ("iss", "https://issuer.example".into()),
        ];
        match input["callback"].as_str().unwrap() {
            "valid" => {}
            "denied" => pairs[1] = ("error", "access_denied".into()),
            "redirect_mismatch" => url.set_path("/elsewhere"),
            "iss_mismatch" => pairs[2].1 = "https://evil.example".into(),
            "fragment" => url.set_fragment(Some("x")),
            "userinfo" => url.set_username("user").unwrap(),
            "missing_code" => {
                pairs.remove(1);
            }
            "duplicate_param" => pairs.push(("code", "again".into())),
            "missing_state" => {
                pairs.remove(0);
            }
            "state_mismatch" => {}
            other => panic!("{id}: unknown callback {other}"),
        }
        url.query_pairs_mut().extend_pairs(pairs);
        match input["exchange"].as_str().unwrap() {
            "ok" => host.network.reply(
                200,
                json!({"access_token":"done","refresh_token":"rotated","token_type":"Bearer","scope":granted.join(" ")}),
            ),
            "invalid_grant" => host.network.reply(400, json!({"error":"invalid_grant"})),
            "invalid_client" => host.network.reply(401, json!({"error":"invalid_client"})),
            "token_endpoint_failure" => host.network.reply(500, json!({"error":"server_error"})),
            _ => host
                .network
                .reply(200, json!({"access_token":"done","token_type":"mac"})),
        }
        let completer = host.owner(client(list(&input["ceiling"])));
        let result = match input["handle"].as_str() {
            Some("matching") => completer.complete_login(ctx, &pending, url, budget()).await,
            _ => completer.complete(ctx, url, budget()).await,
        };
        let persisted = host.store.grant().and_then(|r| r.token).is_some();
        assert_eq!(persisted, expect["grant_persisted"] == true, "{id}: grant");
        match result {
            Ok(_) => assert!(expect["code"].is_null() && expect["failed"] != true, "{id}"),
            Err(error) => {
                assert!(
                    expect["failed"] == true || expect["code"].is_string(),
                    "{id}"
                );
                if let Some(code) = expect["code"].as_str() {
                    assert_eq!(error.auth_code().unwrap().as_str(), code, "{id}");
                }
                if expect["scopes"].is_array() {
                    assert_eq!(error.required_scopes(), list(&expect["scopes"]), "{id}");
                }
                assert_eq!(
                    error.login_ended(),
                    expect["login_ended"] == true,
                    "{id}: ended"
                );
            }
        }
    }
}
