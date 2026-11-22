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
    // No policy selection: S is the configured requested scopes.
    host.policy.select.lock().unwrap().clear();
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
    host.policy.select.lock().unwrap().clear();
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
    // Requested scopes outside the ceiling, or an invalid host-required scope
    // token: every operation fails `invalid_configuration`, before any request.
    let host = Host::new();
    let outside = host.owner(
        OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read", "admin"]), scopes(&["read"]))
            .client_secret(
                "secret-ref",
                ClientSecret::new("secret".into()),
                TokenAuthMethod::ClientSecretBasic,
            ),
    );
    let invalid = host.pkce(|c| c.required_scopes(scopes(&["bad\\scope"])));
    for error in [
        outside.credential(cc_context()).await.err().unwrap(),
        invalid.prepare(context(), budget()).await.err().unwrap(),
        invalid.credential(context()).await.err().unwrap(),
    ] {
        assert_eq!(error.auth_recovery(), Some(AuthRecovery::Configure));
        assert_error(error, AuthErrorCode::InvalidConfiguration, &[]);
    }
    // A preset's scopes that differ from the requested ones.
    let oauth = host.pkce(|c| c);
    let preset = with_preset(context(), &["admin"]);
    let error = oauth.prepare(preset.clone(), budget()).await.err().unwrap();
    assert_error(error, AuthErrorCode::InvalidConfiguration, &[]);
    assert_error(
        oauth.credential(preset).await.err().unwrap(),
        AuthErrorCode::InvalidConfiguration,
        &[],
    );
    // An empty preset `scopes` is present, so it must equal them too; an
    // omitted one is no constraint.
    let empty = with_preset(context(), &[]);
    assert_error(
        oauth.prepare(empty, budget()).await.err().unwrap(),
        AuthErrorCode::InvalidConfiguration,
        &[],
    );
    assert_eq!(requests(&host), 0);
    assert!(oauth.prepare(context(), budget()).await.is_ok());
}

/// Rule 5: a 401 retires the token; its `scope` (within the ceiling) is
/// requested only by the same operation's client-credentials acquisition,
/// never stored for a later acquisition or sign-in, and never required.
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

    // PKCE: the hint is for this operation's client-credentials acquisition
    // only; it is never stored, so the next sign-in does not request it.
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
    assert_eq!(query(next.authorization_url(), "scope").unwrap(), "read");
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
        // The transport hands a malformed `scope` to the provider (it validates
        // it); a duplicated parameter is no single Bearer challenge.
        if status == 403 {
            assert_eq!(
                crate::auth::challenge::insufficient_scope(header),
                !header.contains(", scope=\"read\""),
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
    assert_eq!(host.pending()[0].required, Some(scopes(&["read", "write"])));
    host.network.reply(
        200,
        json!({"access_token":"narrow","refresh_token":"kept","token_type":"Bearer","scope":"read"}),
    );
    let error = oauth
        .complete(context(), callback(&pending), budget())
        .await
        .err()
        .unwrap();
    assert_eq!(error.login_ended(), Some(true));
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
    assert_eq!(error.login_ended(), Some(true));
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
    // A selection without a required scope is not a refusal: acquisitions
    // request the selected scopes and R.
    let pending = login(
        oauth
            .prepare_with_required(context(), &write, budget())
            .await
            .unwrap(),
    );
    assert_eq!(
        query(pending.authorization_url(), "scope").unwrap(),
        "read write"
    );
    // A selection beyond the ceiling is a configuration error, without scopes.
    *host.policy.select.lock().unwrap() = scopes(&["read", "admin"]);
    for error in [
        oauth
            .prepare_with_required(context(), &write, budget())
            .await
            .err()
            .unwrap(),
        oauth.credential(unbound()).await.err().unwrap(),
    ] {
        assert_error(error, AuthErrorCode::InvalidConfiguration, &[]);
    }
}

/// Rule 12: every complete() error reports whether its login has ended.
#[tokio::test]
pub(super) async fn rule12_complete_errors_report_login_ended() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    let ended = |result: Result<BearerCredential, HookError>| {
        let error = result.err().unwrap();
        (error.auth_code().unwrap(), error.login_ended().unwrap())
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

// ---- Contract v2 section 7 ----

fn decisions() -> usize {
    decide::DECISIONS.with(|count| count.replace(0))
}

/// Every credential and challenge entry point produces `decide`'s outcome,
/// through exactly one decision; `complete` makes none.
#[tokio::test]
pub(super) async fn entry_points_route_through_decide() {
    let host = Host::new();
    let seeded = host.seed(&host.pkce(|c| c), context()).await;
    let oauth = host.pkce(|c| c.required_scopes(scopes(&["admin"])));
    let pure = |rejection| {
        decide::operation(&oauth.config, &[], rejection)
            .err()
            .unwrap()
    };
    let header = r#"Bearer error="insufficient_scope", scope="write""#;
    let expected = pure(None);
    let expected_step_up = pure(Some(decide::Rejection {
        status: 403,
        header,
    }));
    assert_error(expected.clone(), AuthErrorCode::AccessDenied, &["admin"]);
    decisions();
    let options = || PrepareOptions::new().required(Vec::new());
    let results: Vec<(&str, HookError)> = vec![
        (
            "credential",
            oauth.credential(context()).await.err().unwrap(),
        ),
        (
            "preemptive",
            oauth.credential(unbound()).await.err().unwrap(),
        ),
        (
            "prepare",
            oauth.prepare(context(), budget()).await.err().unwrap(),
        ),
        (
            "prepare_with_required",
            oauth
                .prepare_with_required(context(), &[], budget())
                .await
                .err()
                .unwrap(),
        ),
        (
            "prepare_with",
            oauth
                .prepare_with(context(), options(), budget())
                .await
                .err()
                .unwrap(),
        ),
        (
            "challenge 401",
            oauth
                .challenge(
                    context(),
                    challenge(401, "Bearer", Some(&seeded.attempt_id)),
                )
                .await
                .err()
                .unwrap(),
        ),
    ];
    for (entry, error) in results {
        assert_eq!(error, expected, "{entry}");
    }
    let error = oauth
        .challenge(context(), challenge(403, header, None))
        .await
        .err()
        .unwrap();
    assert_eq!(error, expected_step_up, "challenge 403");
    assert_eq!(decisions(), 7, "one decision per entry point call");
    let host = Host::new();
    let pending = login(host.pkce(|c| c).prepare(context(), budget()).await.unwrap());
    decisions();
    host.network
        .reply(200, json!({"access_token":"done","token_type":"Bearer"}));
    host.pkce(|c| c)
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(decisions(), 0, "complete follows its own procedure");
}

/// Step 5: a newer stored generation than the one sent is used; the one sent
/// is refused with R.
#[tokio::test]
async fn race_newer_generation_than_sent() {
    let host = Host::new();
    let oauth = cc_client(&host, &[]);
    host.network.reply(
        200,
        json!({"access_token":"first","token_type":"Bearer","scope":"read write","expires_in":3600}),
    );
    let first = oauth.credential(cc_context()).await.unwrap().unwrap();
    // Another writer stores a newer generation.
    host.store.expire();
    host.network.reply(
        200,
        json!({"access_token":"second","token_type":"Bearer","scope":"read write","expires_in":3600}),
    );
    let second = oauth.credential(cc_context()).await.unwrap().unwrap();
    assert_ne!(first.attempt_id, second.attempt_id);
    let before = requests(&host);
    let header = r#"Bearer error="insufficient_scope", scope="write""#;
    oauth
        .challenge(
            cc_context(),
            challenge(403, header, Some(&first.attempt_id)),
        )
        .await
        .unwrap();
    assert_eq!(requests(&host), before, "the current token is used as is");
    let error = oauth
        .challenge(
            cc_context(),
            challenge(403, header, Some(&second.attempt_id)),
        )
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["write"]);
    assert_eq!(requests(&host), before);
}

/// Completion step 7: a pending login written by an older release has no
/// stored R; the current host-required scopes apply.
#[tokio::test]
async fn upgrade_pending_login_without_required() {
    for (host_required, expected) in [(&[][..], None), (&["write"][..], Some(&["write"][..]))] {
        let host = Host::new();
        let pending = login(host.pkce(|c| c).prepare(context(), budget()).await.unwrap());
        for logins in host.logins.lock().unwrap().values_mut() {
            for login in logins {
                login.required = None;
            }
        }
        // The serialized form of such a record has no `required`.
        let saved = host.pending()[0].clone();
        let json = serde_json::to_value(&saved).unwrap();
        assert!(json.get("required").is_none());
        let old: SavedLogin = serde_json::from_value(json).unwrap();
        assert!(old.required.is_none());
        host.network.reply(
            200,
            json!({"access_token":"done","token_type":"Bearer","scope":"read"}),
        );
        let completer = host.pkce(|c| c.required_scopes(scopes(host_required)));
        let result = completer
            .complete(context(), callback(&pending), budget())
            .await;
        match expected {
            None => assert_eq!(result.unwrap().token, "done"),
            Some(required) => {
                let error = result.err().unwrap();
                assert_eq!(error.login_ended(), Some(true));
                assert_error(error, AuthErrorCode::AccessDenied, required);
            }
        }
    }
}

/// Host store, network, callback and client-source failures carry no scopes,
/// whatever scopes the host attached.
#[tokio::test]
async fn host_failures_carry_no_scopes() {
    let with_scopes = |code| fail(code).with_required_scopes(&scopes(&["write"]));
    // Store.
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    *host.store.failure.lock().unwrap() = Some(with_scopes(AuthErrorCode::AccessDenied));
    let error = oauth.credential(context()).await.err().unwrap();
    assert_error(error.clone(), AuthErrorCode::AccessDenied, &[]);
    assert_eq!(error.login_ended(), None);
    // Network, on a token request: an unreachable token endpoint is
    // provider_failed, whatever the host network reported.
    let host = Host::new();
    let oauth = cc_client(&host, &[]);
    *host.network.token_failure.lock().unwrap() =
        Some(with_scopes(AuthErrorCode::InteractionRequired));
    let error = oauth.credential(cc_context()).await.err().unwrap();
    assert_error(error, AuthErrorCode::ProviderFailed, &[]);
    // Callback policy (client selection) and a client source no longer
    // permitted, before the claim: the login stays pending.
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    *host.policy.refuse.lock().unwrap() = Some(with_scopes(AuthErrorCode::InteractionRequired));
    let error = oauth
        .complete(context(), callback(&pending), budget())
        .await
        .err()
        .unwrap();
    assert_eq!(error.login_ended(), Some(false));
    assert_error(error, AuthErrorCode::InteractionRequired, &[]);
    *host.policy.refuse.lock().unwrap() = None;
    let other_client = host.owner(
        OAuthClientConfig::new("account", "other", OAuthFlow::AuthorizationCodePkce)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .redirect_uri("http://127.0.0.1/callback"),
    );
    let mut other = context();
    other.authentication.as_mut().unwrap()["clientId"] = "other".into();
    let error = other_client
        .complete(other, callback(&pending), budget())
        .await
        .err()
        .unwrap();
    assert_eq!(error.login_ended(), Some(false));
    assert_error(error, AuthErrorCode::InvalidConfiguration, &[]);
    assert_eq!(host.pending().len(), 1);
    // The login still completes once policy allows it.
    host.network
        .reply(200, json!({"access_token":"done","token_type":"Bearer"}));
    oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
}

/// A claim whose outcome is uncertain is re-read on a fresh budget.
#[tokio::test]
async fn uncertain_claim_rereads_store_on_fresh_budget() {
    let host = Host::new();
    let oauth = host.pkce(|c| c.persist_pending_logins());
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    // The claim's write outlives the caller's deadline.
    host.store.write_delay.store(300, Ordering::SeqCst);
    let short = OperationBudget::until(Instant::now() + Duration::from_millis(100));
    let error = oauth
        .complete(context(), callback(&pending), short)
        .await
        .err()
        .unwrap();
    host.store.write_delay.store(0, Ordering::SeqCst);
    // The claim did not land before the deadline: the login is still pending.
    assert_eq!(error.login_ended(), Some(false));
    assert_eq!(host.pending().len(), 1);
}

/// S is the host policy's per-target selection when it makes one: it is what
/// the authorization URL and the client-credentials request ask for (with R),
/// must lie within the ceiling, and a present preset `scopes` must equal it.
#[tokio::test]
async fn policy_selected_scopes_are_requested() {
    // PKCE: the policy selects `write` for this target; S = [write].
    let host = Host::new();
    *host.policy.select.lock().unwrap() = scopes(&["write"]);
    let oauth = host.pkce(|c| c.required_scopes(scopes(&["read"])));
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    assert_eq!(
        query(pending.authorization_url(), "scope").unwrap(),
        "read write",
        "S ∪ R, not the configured requested scopes alone"
    );
    // Client credentials: the policy's selection is the request.
    let host = Host::new();
    *host.policy.select.lock().unwrap() = scopes(&["write"]);
    let oauth = cc_client(&host, &[]);
    host.network.reply(
        200,
        json!({"access_token":"w","token_type":"Bearer","scope":"write"}),
    );
    oauth.credential(cc_context()).await.unwrap().unwrap();
    assert_eq!(host.network.last_form()["scope"], "write");
    // No selection: the configured requested scopes.
    let host = Host::new();
    host.policy.select.lock().unwrap().clear();
    let oauth = cc_client(&host, &[]);
    host.network
        .reply(200, json!({"access_token":"r","token_type":"Bearer"}));
    oauth.credential(cc_context()).await.unwrap().unwrap();
    assert_eq!(host.network.last_form()["scope"], "read");
    // A present preset `scopes` must equal the selection, before any request.
    let host = Host::new();
    *host.policy.select.lock().unwrap() = scopes(&["write"]);
    let oauth = cc_client(&host, &[]);
    for (preset, ok) in [(&["read"][..], false), (&["write"][..], true)] {
        if ok {
            host.network.reply(
                200,
                json!({"access_token":"w","token_type":"Bearer","scope":"write"}),
            );
        }
        let result = oauth.credential(with_preset(cc_context(), preset)).await;
        match ok {
            true => assert!(result.is_ok()),
            false => {
                assert_error(
                    result.err().unwrap(),
                    AuthErrorCode::InvalidConfiguration,
                    &[],
                );
                assert_eq!(requests(&host), 0);
            }
        }
    }
}

/// Step 1 precedes step 4: a preset `scopes` other than the policy-selected S
/// is invalid_configuration even when R is also outside the ceiling, with no
/// scopes and no authorization-server request.
#[tokio::test]
async fn preset_mismatch_precedes_ceiling_refusal() {
    let host = Host::new();
    *host.policy.select.lock().unwrap() = scopes(&["write"]);
    let pkce = host.pkce(|c| c.required_scopes(scopes(&["admin"])));
    let cc = host.owner(
        OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .required_scopes(scopes(&["admin"]))
            .client_secret(
                "secret-ref",
                ClientSecret::new("secret".into()),
                TokenAuthMethod::ClientSecretBasic,
            ),
    );
    let pkce_preset = with_preset(context(), &["read"]);
    let cc_preset = with_preset(cc_context(), &["read"]);
    let step_up = || step_up("write");
    for error in [
        pkce.credential(pkce_preset.clone()).await.err().unwrap(),
        pkce.prepare(pkce_preset.clone(), budget())
            .await
            .err()
            .unwrap(),
        pkce.challenge(pkce_preset, step_up()).await.err().unwrap(),
        cc.credential(cc_preset.clone()).await.err().unwrap(),
        cc.challenge(cc_preset, step_up()).await.err().unwrap(),
    ] {
        assert_error(error, AuthErrorCode::InvalidConfiguration, &[]);
    }
    assert_eq!(
        requests(&host),
        0,
        "no authorization-server or other request"
    );
    // A policy-selected S beyond the ceiling is step 1 too, for a preset.
    *host.policy.select.lock().unwrap() = scopes(&["read", "admin"]);
    let error = pkce.credential(context()).await.err().unwrap();
    assert_error(error, AuthErrorCode::InvalidConfiguration, &[]);
    assert_eq!(requests(&host), 0);
    *host.policy.select.lock().unwrap() = scopes(&["write"]);
    // With the preset matching S, the ceiling refusal applies.
    let error = pkce
        .credential(with_preset(context(), &["write"]))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["admin"]);
}

fn selects(host: &Host) -> usize {
    host.policy.selects.swap(0, Ordering::SeqCst)
}

/// Host policy selects once per operation, before the decision, on every
/// path: a stored or preset binding, challenge rediscovery and a refusal.
#[tokio::test]
async fn policy_selects_once_per_operation() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    // A preset without a stored binding: prepare creates a login.
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    assert_eq!(selects(&host), 1, "prepare");
    host.network.reply(
        200,
        json!({"access_token":"t","refresh_token":"r","token_type":"Bearer","expires_in":3600}),
    );
    let token = oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    assert_eq!(selects(&host), 1, "complete");
    // A stored binding: lookup and delivery.
    oauth.credential(context()).await.unwrap().unwrap();
    assert_eq!(selects(&host), 1, "credential");
    oauth.credential(unbound()).await.unwrap().unwrap();
    assert_eq!(selects(&host), 1, "preemptive");
    // Challenges rediscover through the same selection.
    let header = r#"Bearer error="insufficient_scope", scope="write""#;
    let _ = oauth
        .challenge(context(), challenge(403, header, Some(&token.attempt_id)))
        .await;
    assert_eq!(selects(&host), 1, "403");
    host.network.reply(
        200,
        json!({"access_token":"t2","refresh_token":"r2","token_type":"Bearer","expires_in":3600}),
    );
    oauth
        .challenge(context(), challenge(401, "Bearer", Some(&token.attempt_id)))
        .await
        .unwrap();
    assert_eq!(selects(&host), 1, "401");
    // A refusing policy is asked once, and its error is the outcome.
    *host.policy.refuse.lock().unwrap() = Some(fail(AuthErrorCode::CredentialUnavailable));
    let error = oauth.prepare(context(), budget()).await.err().unwrap();
    assert_error(error, AuthErrorCode::CredentialUnavailable, &[]);
    assert_eq!(selects(&host), 1, "refused prepare");
    let error = oauth
        .challenge(context(), challenge(401, "Bearer", None))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::CredentialUnavailable, &[]);
    assert_eq!(selects(&host), 1, "refused challenge");
    *host.policy.refuse.lock().unwrap() = None;
    // An unbound, learned client-credentials binding rediscovered on a 401.
    let host = Host::new();
    let oauth = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    host.network
        .reply(200, json!({"access_token":"first","token_type":"Bearer"}));
    oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .unwrap();
    assert_eq!(selects(&host), 1, "first discovery");
    host.network
        .reply(200, json!({"access_token":"second","token_type":"Bearer"}));
    oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .unwrap();
    assert_eq!(selects(&host), 1, "rediscovery");
}

/// A learned binding's policy-selected S beyond the ceiling is step 1, before
/// a host-required scope outside the ceiling: invalid_configuration.
#[tokio::test]
async fn learned_binding_selection_beyond_ceiling_is_configuration() {
    let host = Host::new();
    let learner = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    host.network
        .reply(200, json!({"access_token":"first","token_type":"Bearer"}));
    learner
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .unwrap();
    let before = requests(&host);
    *host.policy.select.lock().unwrap() = scopes(&["read", "admin"]);
    let oauth = cc_client(&host, &["admin"]);
    for error in [
        oauth.credential(unbound()).await.err().unwrap(),
        oauth
            .challenge(unbound(), challenge(401, "Bearer", None))
            .await
            .err()
            .unwrap(),
    ] {
        assert_error(error, AuthErrorCode::InvalidConfiguration, &[]);
    }
    assert_eq!(requests(&host), before);
}

/// Renewal errors outside `complete`: refresh and client-credentials grants.
#[tokio::test]
async fn renewal_errors_are_classified() {
    let cases: &[(&str, u16, Value, AuthErrorCode)] = &[
        (
            "refresh",
            400,
            json!({"error":"invalid_grant"}),
            AuthErrorCode::RefreshRejected,
        ),
        (
            "refresh",
            400,
            json!({"error":"unauthorized_client"}),
            AuthErrorCode::CredentialUnavailable,
        ),
        (
            "refresh",
            401,
            json!({"error":"invalid_client"}),
            AuthErrorCode::CredentialUnavailable,
        ),
        (
            "refresh",
            400,
            json!({"error":"access_denied"}),
            AuthErrorCode::ProviderFailed,
        ),
        (
            "refresh",
            400,
            json!({"error":"invalid_scope"}),
            AuthErrorCode::ProviderFailed,
        ),
        (
            "refresh",
            500,
            json!({"error":"server_error"}),
            AuthErrorCode::ProviderFailed,
        ),
        (
            "refresh",
            200,
            json!({"access_token":"x","token_type":"mac"}),
            AuthErrorCode::ProviderFailed,
        ),
        (
            "cc",
            400,
            json!({"error":"invalid_grant"}),
            AuthErrorCode::CredentialUnavailable,
        ),
        (
            "cc",
            400,
            json!({"error":"unauthorized_client"}),
            AuthErrorCode::CredentialUnavailable,
        ),
        (
            "cc",
            401,
            json!({"error":"invalid_client"}),
            AuthErrorCode::CredentialUnavailable,
        ),
        (
            "cc",
            400,
            json!({"error":"access_denied"}),
            AuthErrorCode::ProviderFailed,
        ),
        (
            "cc",
            400,
            json!({"error":"invalid_scope"}),
            AuthErrorCode::ProviderFailed,
        ),
        (
            "cc",
            500,
            json!({"error":"server_error"}),
            AuthErrorCode::ProviderFailed,
        ),
        (
            "cc",
            200,
            json!({"access_token":"x","token_type":"mac"}),
            AuthErrorCode::ProviderFailed,
        ),
    ];
    for (grant, status, body, expected) in cases {
        let host = Host::new();
        let (oauth, ctx) = if *grant == "refresh" {
            let oauth = host.pkce(|c| c);
            host.seed(&oauth, context()).await;
            (oauth, context())
        } else {
            (cc_client(&host, &[]), cc_context())
        };
        host.store.expire();
        host.network.reply(*status, body.clone());
        let error = oauth.credential(ctx).await.err().unwrap();
        assert_error(error, *expected, &[]);
    }
    // An unreachable token endpoint.
    for grant in ["refresh", "cc"] {
        let host = Host::new();
        let (oauth, ctx) = if grant == "refresh" {
            let oauth = host.pkce(|c| c);
            host.seed(&oauth, context()).await;
            (oauth, context())
        } else {
            (cc_client(&host, &[]), cc_context())
        };
        host.store.expire();
        *host.network.token_failure.lock().unwrap() =
            Some(fail(AuthErrorCode::UntrustedDestination));
        let error = oauth.credential(ctx).await.err().unwrap();
        assert_error(error, AuthErrorCode::ProviderFailed, &[]);
    }
}

/// Re-attempts of an operation share its selection: a stale renewal that
/// refetches metadata, a client-credentials DCR re-registration, and a
/// first-use unbound target's discovery each select once.
#[tokio::test]
async fn policy_selects_once_across_reattempts() {
    // Stale: the refresh is provably unsent, the issuer metadata is
    // refetched and the refresh retried.
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    host.store.expire();
    selects(&host);
    host.network.unsent_failures.store(1, Ordering::SeqCst);
    host.network
        .reply(200, json!({"access_token":"renewed","token_type":"Bearer"}));
    assert_eq!(
        oauth.credential(context()).await.unwrap().unwrap().token,
        "renewed"
    );
    assert_eq!(selects(&host), 1, "stale renewal");
    // A client-credentials DCR client, first use of an unbound target: the
    // token endpoint's invalid_client re-registers once and re-acquires.
    let host = Host::new();
    host.network.dcr.store(true, Ordering::SeqCst);
    let oauth = host.owner(
        OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
            .scopes(scopes(&["read"]), Vec::new())
            .dynamic_registration(RegistrationPolicy::new(
                "https://issuer.example",
                "Example Adapter",
            ))
            .client_secret_storage(host.secrets.clone()),
    );
    host.network.reply(401, json!({"error":"invalid_client"}));
    host.network.reply(
        200,
        json!({"access_token":"reissued","token_type":"Bearer"}),
    );
    oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .unwrap();
    assert_eq!(host.network.registrations().len(), 2);
    assert_eq!(selects(&host), 1, "first use and re-registration");
}

/// Step 0 precedes every target and configuration check: a 401 retires the
/// generation it rejected even when the target no longer validates or the
/// stored binding no longer matches this configuration.
#[tokio::test]
async fn unauthorized_retires_before_target_checks() {
    // A binding stored for another client.
    let host = Host::new();
    let seeded = host.seed(&host.pkce(|c| c), context()).await;
    let other = host.owner(
        OAuthClientConfig::new("account", "other", OAuthFlow::AuthorizationCodePkce)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .redirect_uri("http://127.0.0.1/callback"),
    );
    let mut ctx = context();
    ctx.authentication.as_mut().unwrap()["clientId"] = "other".into();
    let _ = other
        .challenge(ctx, challenge(401, "Bearer", Some(&seeded.attempt_id)))
        .await;
    assert!(host.store.token().access_rejected, "incompatible binding");
    // A target that fails validation.
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let seeded = host.seed(&oauth, context()).await;
    let mut ctx = context();
    ctx.authentication.as_mut().unwrap()["flow"] = "bogus".into();
    let error = oauth
        .challenge(ctx, challenge(401, "Bearer", Some(&seeded.attempt_id)))
        .await
        .err()
        .unwrap();
    assert_eq!(error.auth_code(), Some(AuthErrorCode::UnsupportedBinding));
    assert!(host.store.token().access_rejected, "invalid target");
}

/// A PKCE step-up needing consent on a known binding is decided without any
/// authorization-server request, even when metadata would be refused.
#[tokio::test]
async fn step_up_needing_consent_makes_no_request() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let seeded = host.seed(&oauth, context()).await;
    host.network.refusals.lock().unwrap().push((
        EndpointUse::IssuerMetadata,
        fail(AuthErrorCode::UntrustedDestination),
    ));
    let before = requests(&host);
    let error = oauth
        .challenge(
            context(),
            challenge(
                403,
                r#"Bearer error="insufficient_scope", scope="write""#,
                Some(&seeded.attempt_id),
            ),
        )
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::InteractionRequired, &["write"]);
    assert_eq!(requests(&host), before);
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

/// A client-credentials 401 whose current generation already covers R
/// (another request re-acquired meanwhile) is answered with that token,
/// without rediscovery or any request.
#[tokio::test]
async fn client_credentials_401_with_newer_generation_uses_it() {
    let host = Host::new();
    let oauth = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    host.network.reply(
        200,
        json!({"access_token":"first","token_type":"Bearer","expires_in":3600}),
    );
    let first = oauth.credential(cc_context()).await.unwrap().unwrap();
    host.store.expire();
    host.network.reply(
        200,
        json!({"access_token":"second","token_type":"Bearer","expires_in":3600}),
    );
    let second = oauth.credential(cc_context()).await.unwrap().unwrap();
    let before = requests(&host);
    oauth
        .challenge(
            cc_context(),
            challenge(401, "Bearer", Some(&first.attempt_id)),
        )
        .await
        .unwrap();
    assert_eq!(requests(&host), before, "no rediscovery or token request");
    let token = host.store.token();
    assert_eq!(token.generation, second.attempt_id);
    assert!(!token.access_rejected);
}

/// An unbound pre-registered PKCE target's first anonymous 401 ending at step
/// 9: protected-resource discovery only, then interaction_required, with a
/// binding stored without authorization-server metadata.
#[tokio::test]
async fn unbound_preregistered_pkce_401_needs_no_authorization_server() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let error = oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::InteractionRequired, &[]);
    assert_eq!(authorization_server_requests(&host), 0);
    assert!(requests(&host) >= 1, "protected-resource metadata");
    let binding = host.store.binding().unwrap();
    assert!(binding.metadata.token_endpoint.is_empty());
    assert!(binding.client_source == ClientSource::Preregistered);
    // The host's prepare fetches the issuer's metadata for the login.
    login(oauth.prepare(unbound(), budget()).await.unwrap());
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

/// A stale renewal's issuer-metadata refetch keeps a host destination
/// refusal's code, without scopes; other failures are discovery_failed.
#[tokio::test]
async fn stale_refetch_keeps_destination_refusal_code() {
    for (refusal, expected) in [
        (
            Some(fail(AuthErrorCode::CredentialUnavailable)),
            AuthErrorCode::CredentialUnavailable,
        ),
        (
            Some(HookError::new("refused")),
            AuthErrorCode::UntrustedDestination,
        ),
        (None, AuthErrorCode::DiscoveryFailed),
    ] {
        let host = Host::new();
        let oauth = host.pkce(|c| c);
        host.seed(&oauth, context()).await;
        host.store.expire();
        host.network.unsent_failures.store(1, Ordering::SeqCst);
        match refusal {
            Some(error) => host.network.refusals.lock().unwrap().push((
                EndpointUse::IssuerMetadata,
                error.with_required_scopes(&scopes(&["read"])),
            )),
            None => *host.network.issuer_outage.lock().unwrap() = Some("issuer.example".into()),
        }
        let error = oauth.credential(context()).await.err().unwrap();
        assert_error(error, expected, &[]);
    }
}

/// A stored binding without persisted authorization-server metadata decides
/// use and step 9's interaction_required without fetching it.
#[tokio::test]
async fn stored_binding_without_metadata_decides_without_fetch() {
    let clear = |host: &Host| {
        for (key, record) in host.store.records.lock().unwrap().iter_mut() {
            if key.starts_with("ahp.oauth.binding:") {
                record.metadata.token_endpoint.clear();
                record.metadata.authorization_endpoint = None;
            }
        }
    };
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let seeded = host.seed(&oauth, context()).await;
    clear(&host);
    let before = requests(&host);
    // Use: the stored token is valid.
    assert_eq!(
        oauth
            .credential(unbound())
            .await
            .unwrap()
            .unwrap()
            .attempt_id,
        seeded.attempt_id
    );
    // interaction_required: the grant lacks a host-required scope.
    let needs_write = host.pkce(|c| c.required_scopes(scopes(&["write"])));
    for error in [
        needs_write.credential(context()).await.err().unwrap(),
        needs_write.credential(unbound()).await.err().unwrap(),
    ] {
        assert_error(error, AuthErrorCode::InteractionRequired, &["write"]);
    }
    assert_eq!(requests(&host), before, "no issuer-metadata fetch");
}

/// A host `prepare` on a stored binding without persisted metadata serves a
/// usable cached token with no network request at all.
#[tokio::test]
async fn prepare_serves_cached_token_without_metadata_or_request() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let seeded = host.seed(&oauth, context()).await;
    for (key, record) in host.store.records.lock().unwrap().iter_mut() {
        if key.starts_with("ahp.oauth.binding:") {
            record.metadata.token_endpoint.clear();
            record.metadata.authorization_endpoint = None;
        }
    }
    let before = requests(&host);
    for ctx in [context(), unbound()] {
        assert_eq!(
            ready(oauth.prepare(ctx, budget()).await.unwrap()).attempt_id,
            seeded.attempt_id
        );
    }
    assert_eq!(requests(&host), before);
    // A prepare that must create a login still proceeds.
    let needs_write = host.pkce(|c| c.required_scopes(scopes(&["write"])));
    login(needs_write.prepare(context(), budget()).await.unwrap());
}

/// An unbound target with a stored binding and a usable grant is served with
/// no authorization-server request.
#[tokio::test]
async fn unbound_usable_grant_is_used_without_request() {
    let host = Host::new();
    let oauth = host.cc(TokenAuthMethod::ClientSecretBasic, "secret");
    host.network.reply(
        200,
        json!({"access_token":"stored","token_type":"Bearer","expires_in":3600}),
    );
    oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .unwrap();
    let before = requests(&host);
    assert_eq!(
        oauth.credential(unbound()).await.unwrap().unwrap().token,
        "stored"
    );
    assert_eq!(requests(&host), before);
}

/// A host prepare on an unbound target whose grant is usable but whose
/// binding is not stored: protected-resource discovery only, then use, with
/// a binding stored without authorization-server metadata.
#[tokio::test]
async fn unbound_prepare_with_usable_grant_needs_no_authorization_server() {
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    let seeded = host.seed(&oauth, unbound()).await;
    host.store
        .records
        .lock()
        .unwrap()
        .retain(|key, _| !key.starts_with("ahp.oauth.binding:"));
    let before = authorization_server_requests(&host);
    let served = ready(oauth.prepare(unbound(), budget()).await.unwrap());
    assert_eq!(served.attempt_id, seeded.attempt_id);
    assert_eq!(authorization_server_requests(&host), before);
    assert!(
        host.store
            .binding()
            .unwrap()
            .metadata
            .token_endpoint
            .is_empty()
    );
}

/// A 403 step-up on a stored binding host policy now refuses is not decided
/// on that binding: the host's refusal surfaces, never step 5 or a token.
#[tokio::test]
async fn step_up_on_refused_binding_surfaces_the_refusal() {
    let host = Host::new();
    *host.policy.select.lock().unwrap() = scopes(&["read", "write"]);
    let oauth = host.pkce(|c| c.scopes(scopes(&["read", "write"]), Vec::new()));
    let pending = login(oauth.prepare(context(), budget()).await.unwrap());
    host.network.reply(
        200,
        json!({"access_token":"wide","token_type":"Bearer","scope":"read write","expires_in":3600}),
    );
    let token = oauth
        .complete(context(), callback(&pending), budget())
        .await
        .unwrap();
    *host.policy.refuse.lock().unwrap() = Some(fail(AuthErrorCode::CredentialUnavailable));
    let error = oauth
        .challenge(context(), step_up_with("write", &token.attempt_id))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::CredentialUnavailable, &[]);
}

fn step_up_with(scope: &str, sent: &str) -> AuthChallenge {
    challenge(
        403,
        &format!(r#"Bearer error="insufficient_scope", scope="{scope}""#),
        Some(sent),
    )
}

/// Host policy runs after step 0 and before step 1: on a stored binding (a
/// preset's or a learned one) that client selection now refuses, the host's
/// code is the outcome, without scopes, instead of an out-of-ceiling,
/// malformed-challenge, scopeless step-up or configuration refusal.
#[tokio::test]
async fn host_refusal_precedes_local_refusals() {
    for learned in [false, true] {
        let ctx = || if learned { unbound() } else { context() };
        let host = Host::new();
        let oauth = host.pkce(|c| c);
        host.seed(&oauth, ctx()).await;
        let seeded = authorization_server_requests(&host);
        *host.policy.refuse.lock().unwrap() = Some(
            fail(AuthErrorCode::CredentialUnavailable).with_required_scopes(&scopes(&["read"])),
        );
        let misconfigured = host.pkce(|c| c.scopes(scopes(&["read", "admin"]), scopes(&["read"])));
        for (oauth, rejection) in [
            (&oauth, step_up("admin")),
            (
                &oauth,
                challenge(
                    403,
                    r#"Bearer error="insufficient_scope", scope="read  write""#,
                    None,
                ),
            ),
            (
                &oauth,
                challenge(403, r#"Bearer error="insufficient_scope""#, None),
            ),
            (&misconfigured, step_up("read")),
        ] {
            let error = oauth.challenge(ctx(), rejection).await.err().unwrap();
            assert_error(error, AuthErrorCode::CredentialUnavailable, &[]);
        }
        if learned {
            // An unbound lookup refused by host policy is anonymous delivery.
            assert!(misconfigured.credential(ctx()).await.unwrap().is_none());
        } else {
            let error = misconfigured.credential(ctx()).await.err().unwrap();
            assert_error(error, AuthErrorCode::CredentialUnavailable, &[]);
        }
        assert_eq!(
            authorization_server_requests(&host),
            seeded,
            "no authorization-server request"
        );
    }
    // A non-refused known binding still refuses out-of-ceiling locally, with
    // no request.
    let host = Host::new();
    let oauth = host.pkce(|c| c);
    host.seed(&oauth, context()).await;
    let before = requests(&host);
    let error = oauth
        .challenge(context(), step_up("admin"))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["admin"]);
    assert_eq!(requests(&host), before);
}

/// An unbound target without a stored binding runs protected-resource
/// discovery and selection first: a refusing host's code is the outcome,
/// with no authorization-server request, even with R outside the ceiling.
#[tokio::test]
async fn unbound_host_refusal_precedes_ceiling_refusal() {
    let host = Host::new();
    let oauth = cc_client(&host, &["admin"]);
    *host.policy.refuse.lock().unwrap() = Some(fail(AuthErrorCode::UntrustedDestination));
    let error = oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::UntrustedDestination, &[]);
    assert_eq!(authorization_server_requests(&host), 0);
    // Accepted by host policy, the ceiling refusal applies.
    *host.policy.refuse.lock().unwrap() = None;
    let error = oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .err()
        .unwrap();
    assert_error(error, AuthErrorCode::AccessDenied, &["admin"]);
    assert_eq!(authorization_server_requests(&host), 0);
}
