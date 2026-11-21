//! The decision table: every `scope_decisions` and `completions` conformance
//! vector, run against the pure `decide` steps and end to end through the
//! entry points. Every field a vector defines is asserted; an unknown field,
//! value or required feature fails the run.
use super::*;

fn list(value: &Value) -> Vec<String> {
    if value.is_array() {
        strings(value)
    } else {
        Vec::new()
    }
}
/// Fail on any field outside `known`.
#[track_caller]
fn only(id: &str, value: &Value, known: &[&str]) {
    if let Some(object) = value.as_object() {
        for key in object.keys() {
            assert!(known.contains(&key.as_str()), "{id}: unknown field {key}");
        }
    }
}
fn requests(host: &Host) -> usize {
    host.network.seen.lock().unwrap().len()
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
fn config_for(flow: &str, requested: Vec<String>, ceiling: Vec<String>) -> OAuthClientConfig {
    match flow {
        "client_credentials" => {
            OAuthClientConfig::new("account", "client", OAuthFlow::ClientCredentials)
                .scopes(requested, ceiling)
                .client_secret(
                    "secret-ref",
                    ClientSecret::new("secret".into()),
                    TokenAuthMethod::ClientSecretBasic,
                )
        }
        "authorization_code_pkce" => {
            OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
                .scopes(requested, ceiling)
                .redirect_uri("http://127.0.0.1/callback")
        }
        other => panic!("unknown flow {other}"),
    }
}
/// Optional SDK features a vector may `require`, and which of them Rust has.
const KNOWN_FEATURES: &[&str] = &[
    "token_validation_callback",
    "complete_handle",
    "legacy_prepare_time_host_required",
];
/// No host token-validation callback, `complete()` takes no handle, and no
/// release's pending record held a prepare-time host-required set.
const RUST_FEATURES: &[&str] = &[];
/// Whether a vector applies to Rust; an unknown required feature fails.
pub(super) fn applies(vector: &Value) -> bool {
    let requires = vector["requires"].as_array().map_or(&[][..], |v| &v[..]);
    requires.iter().all(|feature| {
        let feature = feature.as_str().unwrap();
        assert!(
            KNOWN_FEATURES.contains(&feature),
            "{}: unknown feature {feature}",
            vector["id"]
        );
        RUST_FEATURES.contains(&feature)
    })
}
fn auth_code(name: &str) -> AuthErrorCode {
    [
        AuthErrorCode::InvalidConfiguration,
        AuthErrorCode::UnsupportedBinding,
        AuthErrorCode::CredentialUnavailable,
        AuthErrorCode::InteractionRequired,
        AuthErrorCode::AccessDenied,
        AuthErrorCode::RefreshRejected,
        AuthErrorCode::DiscoveryFailed,
        AuthErrorCode::UntrustedDestination,
        AuthErrorCode::ProviderFailed,
    ]
    .into_iter()
    .find(|code| code.as_str() == name)
    .unwrap_or_else(|| panic!("unknown code {name}"))
}

#[test]
fn vector_features_are_known() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for section in [
        "scope_decisions",
        "completions",
        "token_responses",
        "lifecycle",
    ] {
        for vector in fixture[section].as_array().unwrap() {
            applies(vector);
        }
    }
}

fn generation(value: &Value) -> String {
    format!("gen-{}", value.as_u64().expect("an integer generation"))
}

/// The inputs' binding and grant: a permissive client stores the binding
/// (and a grant), which is then replaced by the vector's grant.
async fn store_grant(host: &Host, flow: &str, ctx: &AuthContext, all: &[String], grant: &Value) {
    let preset = ctx.target().unwrap().preset_scopes().map(<[_]>::to_vec);
    let seeder = host.owner(config_for(flow, preset.unwrap_or_default(), all.to_vec()));
    let reply = json!({"access_token":"seeded","token_type":"Bearer","expires_in":3600});
    if flow == "client_credentials" {
        host.network.reply(200, reply);
        seeder.credential(ctx.clone()).await.unwrap().unwrap();
    } else {
        let pending = login(seeder.prepare(ctx.clone(), budget()).await.unwrap());
        host.network.reply(200, reply);
        seeder
            .complete(ctx.clone(), callback(&pending), budget())
            .await
            .unwrap();
    }
    set_grant(host, grant);
}
fn set_grant(host: &Host, grant: &Value) {
    let token = grant.as_object().map(|_| {
        only(
            "grant",
            grant,
            &["generation", "granted", "token", "refresh"],
        );
        let id = generation(&grant["generation"]);
        SavedToken {
            access_token: format!("token-{id}"),
            refresh_token: grant["refresh"]
                .as_bool()
                .unwrap()
                .then(|| format!("refresh-{id}")),
            expires_at: match grant["token"].as_str().unwrap() {
                "valid" => Some(now() + 3600),
                "expired" => Some(0),
                other => panic!("unknown token {other}"),
            },
            scopes: union(&list(&grant["granted"]), &[]),
            generation: id,
            access_rejected: false,
            refresh_in_flight: false,
        }
    });
    let mut records = host.store.records.lock().unwrap();
    let (_, record) = records
        .iter_mut()
        .find(|(key, _)| key.starts_with("ahp.oauth.grant:"))
        .unwrap();
    record.token = token;
    record.version = random_id();
}

#[tokio::test]
async fn canonical_scope_decision_vectors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let mut ran = 0;
    for vector in fixture["scope_decisions"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        only(id, vector, &["id", "input", "expect", "requires"]);
        if !applies(vector) {
            continue;
        }
        ran += 1;
        let (input, expect) = (&vector["input"], &vector["expect"]);
        only(
            id,
            input,
            &[
                "flow",
                "path",
                "binding",
                "requested",
                "ceiling",
                "preset_scopes",
                "host_required",
                "explicit",
                "grant",
                "sent",
                "challenge",
                "prior_401_hint",
                "host_error",
                "target_error",
                "client_source",
                "force_registration",
            ],
        );
        // The client host client selection yields: for an unbound target,
        // pre-registered; with a forced re-registration, a client-credentials
        // DCR client (learned for an unbound endpoint, its stored binding).
        let forced = input["force_registration"] == true;
        let dcr = match input["client_source"].as_str() {
            Some("preregistered") => {
                assert_eq!(input["binding"], "unbound", "{id}");
                false
            }
            Some("dcr") => {
                assert!(forced, "{id}");
                true
            }
            None => false,
            Some(other) => panic!("{id}: unsupported client source {other}"),
        };
        only(id, &input["target_error"], &["check", "code"]);
        only(
            id,
            expect,
            &[
                "code",
                "scopes",
                "required",
                "action",
                "acquisition_scopes",
                "retired",
                "authorization_server_requests",
                "authorization_server_requests_min",
                "network_calls",
                "network_calls_max",
            ],
        );
        only(id, &input["challenge"], &["status", "www_authenticate"]);
        only(
            id,
            &input["host_error"],
            &["callback", "target", "code", "scopes"],
        );
        let flow = input["flow"].as_str().unwrap();
        let path = input["path"].as_str().unwrap();
        let binding = input["binding"].as_str().unwrap();
        assert!(
            matches!(
                binding,
                "stored" | "stored_without_metadata" | "preset" | "unbound"
            ),
            "{id}: unknown binding {binding}"
        );
        // A stored binding whose record lacks the authorization-server
        // metadata, so a token request fetches the issuer's first.
        let without_metadata = binding == "stored_without_metadata";
        let binding = if without_metadata { "stored" } else { binding };
        let requested = list(&input["requested"]);
        let explicit = list(&input["explicit"]);
        let ceiling = list(&input["ceiling"]);
        let host_required = list(&input["host_required"]);
        let preset = input["preset_scopes"]
            .as_array()
            .map(|_| list(&input["preset_scopes"]));
        let grant = &input["grant"];
        let current = grant.as_object().map(|_| generation(&grant["generation"]));
        let sent = input["sent"].as_u64().map(|n| format!("gen-{n}"));
        let host_error = input["host_error"].as_object();
        // A destination refusal: of a client-credentials DCR registration, or
        // of a metadata request.
        let refused = host_error
            .filter(|e| e["callback"] == "destination")
            .map(|e| {
                let usage = match e["target"].as_str().unwrap() {
                    "registration_endpoint" => EndpointUse::Registration,
                    "issuer_metadata" => EndpointUse::IssuerMetadata,
                    "protected_resource_metadata" => EndpointUse::ResourceMetadata,
                    other => panic!("{id}: unknown destination {other}"),
                };
                let error = fail(auth_code(e["code"].as_str().unwrap()))
                    .with_required_scopes(&list(&e["scopes"]));
                (usage, error)
            });
        let destination = refused
            .as_ref()
            .is_some_and(|(usage, _)| *usage == EndpointUse::Registration);
        let rejection = input["challenge"].as_object().map(|c| decide::Rejection {
            status: c["status"].as_u64().unwrap() as u16,
            header: c["www_authenticate"].as_str().unwrap(),
        });

        // The pure decision, steps 1 to 4 (`ManagedOAuth::new` defaults an
        // empty ceiling to the requested scopes).
        let mut normalized = config_for(flow, requested.clone(), ceiling.clone())
            .required_scopes(host_required.clone());
        if normalized.allowed_scopes.is_empty() {
            normalized.allowed_scopes = normalized.requested_scopes.clone();
        }
        normalized.allowed_scopes = union(&normalized.allowed_scopes, &[]);
        normalized.required_scopes = union(&normalized.required_scopes, &[]);
        let pure = decide::configuration(&normalized, preset.as_deref(), &explicit)
            .and_then(|()| decide::operation(&normalized, &explicit, rejection));
        if expect["required"].is_array() {
            let required = match &pure {
                Ok(operation) => operation.required.clone(),
                Err(error) => error.required_scopes().to_vec(),
            };
            assert_eq!(required, list(&expect["required"]), "{id}: decide R");
        }
        if let Err(error) = &pure {
            assert_eq!(
                error.auth_code().unwrap().as_str(),
                expect["code"],
                "{id}: decide"
            );
            assert_eq!(
                error.required_scopes(),
                list(&expect["scopes"]),
                "{id}: decide"
            );
        }

        // End to end through the entry point.
        let host = Host::new();
        *host.policy.select.lock().unwrap() = requested.clone();
        let mut ctx = if flow == "client_credentials" {
            cc_context()
        } else {
            context()
        };
        if let Some(preset) = &preset {
            assert_eq!(binding, "preset", "{id}");
            ctx.authentication.as_mut().unwrap()["scopes"] = json!(preset);
        }
        let mut config = config_for(flow, requested.clone(), ceiling.clone());
        if destination || dcr {
            // A dynamically registered client-credentials client, learned for
            // an unbound endpoint (its stored binding), whose registration
            // endpoint host destination policy refuses, or that is forced to
            // re-register.
            assert_eq!(binding, "stored", "{id}");
            assert!(grant.is_null() || dcr, "{id}");
            host.network.dcr.store(true, Ordering::SeqCst);
            config = OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
                .scopes(requested.clone(), ceiling.clone())
                .dynamic_registration(RegistrationPolicy::new(
                    "https://issuer.example",
                    "Example Adapter",
                ))
                .client_secret_storage(host.secrets.clone());
            ctx.authentication = None;
        }
        let mut oauth = ManagedOAuth::new(
            config.required_scopes(host_required.clone()),
            host.network.clone(),
            host.policy.clone(),
            host.store.clone(),
        )
        .unwrap();
        oauth.pending = host.logins.clone();
        let all = [
            &requested[..],
            &ceiling,
            &list(&grant["granted"]),
            preset.as_deref().unwrap_or_default(),
            &list(&input["prior_401_hint"]),
        ]
        .concat();
        let all = union(&all, &[]);
        if destination || dcr {
            // Store the binding (and a registration) through a first
            // operation and set the vector's grant. For a refused destination,
            // also drop the registration, so this operation registers again.
            host.network
                .reply(200, json!({"access_token":"seeded","token_type":"Bearer"}));
            oauth
                .challenge(ctx.clone(), challenge(401, "Bearer", None))
                .await
                .unwrap();
            assert!(host.store.binding().is_some(), "{id}: stored binding");
            set_grant(&host, grant);
            if destination {
                host.store
                    .records
                    .lock()
                    .unwrap()
                    .retain(|key, _| !key.starts_with("ahp.oauth.registration:"));
            }
        }
        // An unbound target's grant is learned through its binding.
        if binding == "unbound" {
            ctx.authentication = None;
        }
        let seeded = !destination && !dcr && (binding == "stored" || grant.is_object());
        if seeded {
            store_grant(&host, flow, &ctx, &all, grant).await;
            if without_metadata {
                let mut records = host.store.records.lock().unwrap();
                let (_, record) = records
                    .iter_mut()
                    .find(|(key, _)| key.starts_with("ahp.oauth.binding:"))
                    .unwrap();
                record.metadata.token_endpoint.clear();
                record.metadata.authorization_endpoint = None;
                record.version = random_id();
            }
        } else {
            assert!(grant.is_null() || dcr, "{id}");
        }
        if let Some(hint) = input["prior_401_hint"].as_array() {
            // An earlier operation's 401 named these scopes.
            let hint = list(&Value::Array(hint.clone())).join(" ");
            host.network
                .reply(200, json!({"access_token":"earlier","token_type":"Bearer"}));
            let earlier = challenge(401, &format!("Bearer scope=\"{hint}\""), None);
            let _ = oauth.challenge(ctx.clone(), earlier).await;
            set_grant(&host, grant);
        }
        if binding == "unbound" {
            ctx.authentication = None;
        }
        if let Some(target_error) = input["target_error"].as_object() {
            // A target check failing before any decide step: a binding whose
            // flow this client does not support.
            assert_eq!(target_error["check"], "unsupported_binding", "{id}");
            assert_eq!(target_error["code"], expect["code"], "{id}");
            let other = match flow {
                "client_credentials" => "authorization_code_pkce",
                _ => "client_credentials",
            };
            ctx.authentication.as_mut().unwrap()["flow"] = other.into();
        }
        // The host's refusal, with the scopes it carries, which are stripped.
        if let Some(refusal) = refused.clone() {
            host.network.refusals.lock().unwrap().push(refusal);
        }
        if let Some(error) = host_error.filter(|e| e["callback"] != "destination") {
            assert_eq!(error["callback"], "client_selection", "{id}");
            *host.policy.refuse.lock().unwrap() = Some(
                fail(auth_code(error["code"].as_str().unwrap()))
                    .with_required_scopes(&list(&error["scopes"])),
            );
        }
        let acquisition = list(&expect["acquisition_scopes"]).join(" ");
        match expect["action"].as_str() {
            Some("acquire") => host.network.reply(
                200,
                json!({"access_token":"acquired","token_type":"Bearer","scope":acquisition}),
            ),
            Some("refresh") => host.network.reply(
                200,
                json!({"access_token":"refreshed","token_type":"Bearer"}),
            ),
            Some("use" | "login") | None => {}
            Some(other) => panic!("{id}: unknown action {other}"),
        }
        let (before, before_as) = (requests(&host), authorization_server_requests(&host));
        let tokens = host.network.tokens().len();
        assert!(
            input["sent"].is_null() || input["challenge"].is_object(),
            "{id}"
        );
        let result: Result<Option<Preparation>, HookError> = match path {
            "cached" | "credential" | "fresh" => match oauth.credential(ctx.clone()).await {
                // An unbound target: an anonymous request (no token sent)
                // receives the vector's 401, handled by challenge.
                Ok(None) if binding == "unbound" => {
                    let (status, header) =
                        rejection.map_or((401, "Bearer"), |r| (r.status, r.header));
                    assert_eq!(status, 401, "{id}");
                    assert!(sent.is_none(), "{id}: no token was sent");
                    oauth
                        .challenge(ctx.clone(), challenge(status, header, None))
                        .await
                        .map(|()| None)
                }
                result => result.map(|c| c.map(Preparation::Ready)),
            },
            "preemptive" => oauth
                .credential(unbound())
                .await
                .map(|c| c.map(Preparation::Ready)),
            "prepare" => {
                let mut options = PrepareOptions::new().required(explicit.clone());
                if forced {
                    options = options.force_registration();
                }
                oauth
                    .prepare_with(ctx.clone(), options, budget())
                    .await
                    .map(Some)
            }
            "challenge" => {
                let rejection = rejection.unwrap();
                oauth
                    .challenge(
                        ctx.clone(),
                        challenge(rejection.status, rejection.header, sent.as_deref()),
                    )
                    .await
                    .map(|()| None)
            }
            other => panic!("{id}: unknown path {other}"),
        };
        if let Some(min) = expect["authorization_server_requests_min"].as_u64() {
            let made = (authorization_server_requests(&host) - before_as) as u64;
            assert!(
                made >= min,
                "{id}: authorization-server requests {made} < {min}"
            );
        }
        if let Some(expected) = expect["authorization_server_requests"].as_u64() {
            let made = (authorization_server_requests(&host) - before_as) as u64;
            assert_eq!(made, expected, "{id}: authorization-server requests");
        }
        if let Some(expected) = expect["network_calls"].as_u64() {
            assert_eq!(
                (requests(&host) - before) as u64,
                expected,
                "{id}: network calls"
            );
        }
        if let Some(max) = expect["network_calls_max"].as_u64() {
            let made = (requests(&host) - before) as u64;
            assert!(made <= max, "{id}: network calls {made} > {max}");
        }
        if let Some(retired) = expect["retired"].as_bool() {
            // Generation `sent` was retired iff it was current and is now
            // rejected or replaced.
            let token = host.store.grant().and_then(|r| r.token);
            let was_current = sent.is_some() && sent == current;
            let gone =
                token.is_none_or(|t| t.access_rejected || Some(&t.generation) != sent.as_ref());
            assert_eq!(was_current && gone, retired, "{id}: retired");
        }
        match result {
            Ok(outcome) => {
                assert!(
                    expect["code"].is_null(),
                    "{id}: expected {}",
                    expect["code"]
                );
                let required = pure.as_ref().expect("decide passes").required.clone();
                let form = || host.network.last_form();
                match expect["action"].as_str().unwrap() {
                    "use" => {
                        assert_eq!(host.network.tokens().len(), tokens, "{id}: no exchange");
                        if let Some(Preparation::Ready(used)) = outcome {
                            assert_eq!(Some(used.attempt_id), current, "{id}: the stored token");
                        }
                        assert_eq!(host.store.token().generation, current.unwrap(), "{id}");
                    }
                    "refresh" => {
                        assert_eq!(form()["grant_type"], "refresh_token", "{id}");
                        assert_eq!(host.store.token().access_token, "refreshed", "{id}");
                    }
                    "acquire" => {
                        assert_eq!(form()["grant_type"], "client_credentials", "{id}");
                        assert_eq!(form()["scope"], acquisition, "{id}");
                    }
                    "login" => {
                        let pending = login(outcome.unwrap());
                        assert_eq!(
                            query(pending.authorization_url(), "scope").unwrap(),
                            acquisition,
                            "{id}"
                        );
                        assert_eq!(host.pending()[0].required.as_ref(), Some(&required), "{id}");
                    }
                    other => panic!("{id}: unknown action {other}"),
                }
            }
            Err(error) => {
                assert_eq!(error.auth_code().unwrap().as_str(), expect["code"], "{id}");
                assert_eq!(error.required_scopes(), list(&expect["scopes"]), "{id}");
                assert_eq!(
                    error.login_ended(),
                    None,
                    "{id}: only complete() reports it"
                );
                assert!(expect["action"].is_null(), "{id}");
            }
        }
    }
    assert!(ran > 0);
}

#[tokio::test]
pub(super) async fn canonical_completion_vectors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let mut ran = 0;
    for vector in fixture["completions"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        only(id, vector, &["id", "input", "expect", "requires"]);
        // Without `complete_handle`, `handle: matching` means none is passed.
        if !applies(vector) {
            continue;
        }
        ran += 1;
        let (input, expect) = (&vector["input"], &vector["expect"]);
        only(
            id,
            input,
            &[
                "pending",
                "handle",
                "client_source",
                "source_permitted",
                "callback",
                "host_error",
                "claim",
                "exchange",
                "stored_required",
                "prepare_time_host_required",
                "current_host_required",
                "granted",
                "ceiling",
            ],
        );
        only(
            id,
            expect,
            &["code", "scopes", "login_ended", "grant_persisted"],
        );
        only(
            id,
            &input["host_error"],
            &["callback", "target", "code", "scopes"],
        );
        only(id, &input["claim"], &["outcome", "error_code", "reread"]);
        assert!(
            matches!(input["handle"].as_str(), Some("matching" | "none")),
            "{id}: handle"
        );
        let source = input["client_source"].as_str().unwrap();
        let permitted = input["source_permitted"].as_bool().unwrap();
        let stored = input["stored_required"]
            .as_array()
            .map(|_| list(&input["stored_required"]));
        let granted = list(&input["granted"]);
        let current_host = list(&input["current_host_required"]);
        // Only `legacy_prepare_time_host_required` vectors hold one.
        assert!(input["prepare_time_host_required"].is_null(), "{id}");
        let prepare_time: Option<Vec<String>> = None;
        let host = Host::new();
        host.policy.select.lock().unwrap().clear();
        *host.network.issuer_patch.lock().unwrap() = json!({
            "authorization_response_iss_parameter_supported": true,
            "client_id_metadata_document_supported": source == "cimd",
        });
        host.network.dcr.store(source == "dcr", Ordering::SeqCst);
        const CIMD: &str = "https://adapter.example/oauth/client.json";
        const REDIRECT: &str = "http://127.0.0.1/callback?tenant=one";
        let client = |ceiling: Vec<String>, permitted: bool| {
            let config = match (source, permitted) {
                ("preregistered", true) => {
                    OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
                }
                ("preregistered", false) => {
                    OAuthClientConfig::new("account", "other", OAuthFlow::AuthorizationCodePkce)
                }
                ("cimd", true) => {
                    OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
                        .client_id_metadata_document(CIMD, vec![REDIRECT.into()])
                }
                ("dcr", true) => {
                    OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
                        .dynamic_registration(RegistrationPolicy::new(
                            "https://issuer.example",
                            "Example Adapter",
                        ))
                }
                // The source is no longer configured.
                ("cimd" | "dcr", false) => {
                    OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
                }
                (other, _) => panic!("{id}: unknown client source {other}"),
            };
            config
                .scopes(Vec::new(), ceiling)
                .redirect_uri(REDIRECT)
                .persist_pending_logins()
        };
        // A pre-registered client uses its preset; CIMD and DCR learn the binding.
        let ctx = |permitted: bool| match (source, permitted) {
            ("preregistered", true) => context(),
            ("preregistered", false) => {
                let mut ctx = context();
                ctx.authentication.as_mut().unwrap()["clientId"] = "other".into();
                ctx
            }
            _ => unbound(),
        };
        let wide = union(
            &union(&stored.clone().unwrap_or_default(), &granted),
            &union(
                &list(&input["ceiling"]),
                &union(prepare_time.as_deref().unwrap_or_default(), &current_host),
            ),
        );
        let lifetime = match input["pending"].as_str().unwrap() {
            "expired" => Duration::from_millis(1),
            "pending" | "ended" | "unknown" | "absent" => MAX_LOGIN_LIFETIME,
            other => panic!("{id}: unknown pending {other}"),
        };
        let preparer = host.owner(client(wide, true).login_lifetime(lifetime));
        let pending = login(
            preparer
                .prepare_with_required(ctx(true), &stored.clone().unwrap_or_default(), budget())
                .await
                .unwrap(),
        );
        match &stored {
            Some(stored) => {
                assert_eq!(host.pending()[0].required, Some(union(stored, &[])), "{id}");
            }
            // A record written by an older release: no required set.
            None => {
                let mut records = host.store.records.lock().unwrap();
                for record in records.values_mut() {
                    for login in &mut record.pending_logins {
                        login.required = None;
                    }
                }
            }
        }
        match input["pending"].as_str().unwrap() {
            "expired" => tokio::time::sleep(Duration::from_millis(10)).await,
            "ended" => preparer
                .cancel_login(pending.clone(), budget())
                .await
                .unwrap(),
            _ => {}
        }
        let state = query(pending.authorization_url(), "state").unwrap();
        let mut pairs = vec![
            ("tenant", "one".to_owned()),
            (
                "state",
                if input["pending"] == "unknown" {
                    "unknown".into()
                } else {
                    state.clone()
                },
            ),
            ("code", "fake-code".into()),
            ("iss", "https://issuer.example".into()),
        ];
        if input["pending"] == "absent" {
            pairs.remove(1);
        }
        let mut url = Url::parse("http://127.0.0.1/callback").unwrap();
        let mut raw = None;
        match input["callback"].as_str().unwrap() {
            "valid" => {}
            "valid_with_server_params" => pairs.push(("session_state", "opaque".into())),
            "denied" => pairs[2] = ("error", "access_denied".into()),
            "denied_invalid_client" => pairs[2] = ("error", "invalid_client".into()),
            "redirect_mismatch" => url.set_path("/elsewhere"),
            "redirect_query_mismatch" => pairs[0].1 = "two".into(),
            "state_duplicated" => pairs.push(("state", state.clone())),
            "iss_mismatch" => pairs[3].1 = "https://evil.example".into(),
            "fragment" => url.set_fragment(Some("x")),
            "userinfo" => url.set_username("user").unwrap(),
            "missing_code" => {
                pairs.remove(2);
            }
            "code_and_error" => pairs.push(("error", "access_denied".into())),
            "duplicate_param" => pairs.push(("code", "again".into())),
            "unparseable" => raw = Some("bad=%FF%FE"),
            other => panic!("{id}: unknown callback {other}"),
        }
        url.query_pairs_mut().extend_pairs(pairs);
        if let Some(raw) = raw {
            let query = format!("{}&{raw}", url.query().unwrap());
            url.set_query(Some(&query));
        }
        match input["exchange"].as_str().unwrap() {
            "ok" => host.network.reply(
                200,
                json!({"access_token":"done","refresh_token":"rotated","token_type":"Bearer","scope":granted.join(" ")}),
            ),
            error @ ("invalid_grant" | "unauthorized_client" | "access_denied" | "invalid_scope") => {
                host.network.reply(400, json!({ "error": error }))
            }
            "invalid_client" => host.network.reply(401, json!({"error":"invalid_client"})),
            "server_error" => host.network.reply(500, json!({"error":"server_error"})),
            "not_found" => host.network.reply(404, json!({})),
            "unreachable" => {
                *host.network.token_failure.lock().unwrap() =
                    Some(fail(AuthErrorCode::ProviderFailed).request_not_sent());
            }
            "invalid_response" => host
                .network
                .reply(200, json!({"access_token":"done","token_type":"mac"})),
            other => panic!("{id}: unknown exchange {other}"),
        }
        match &input["claim"] {
            Value::String(ok) if ok == "ok" => {}
            claim @ Value::Object(_) => {
                assert_eq!(claim["outcome"], "uncertain", "{id}");
                *host.store.claim_fault.lock().unwrap() = Some((
                    fail(auth_code(claim["error_code"].as_str().unwrap())),
                    claim["reread"].as_str().unwrap().to_owned(),
                ));
            }
            other => panic!("{id}: unknown claim {other}"),
        }
        let completer = host.owner(
            client(list(&input["ceiling"]), permitted).required_scopes(current_host.clone()),
        );
        let host_error = input["host_error"].as_object();
        let host_failure = |error: &serde_json::Map<String, Value>| {
            fail(auth_code(error["code"].as_str().unwrap()))
                .with_required_scopes(&list(&error["scopes"]))
        };
        let refuse = |on: bool| match host_error {
            Some(error) if error["callback"] == "client_selection" => {
                assert!(error.get("target").is_none(), "{id}");
                *host.policy.refuse.lock().unwrap() = on.then(|| host_failure(error));
            }
            Some(error) if error["callback"] == "destination" => {
                assert_eq!(error["target"], "token_endpoint", "{id}");
                let mut refusals = host.network.refusals.lock().unwrap();
                refusals.clear();
                if on {
                    refusals.push((EndpointUse::Token, host_failure(error)));
                }
            }
            Some(error) => panic!("{id}: unknown host error {error:?}"),
            None => {}
        };
        refuse(true);
        let result = completer
            .complete(ctx(permitted), url.clone(), budget())
            .await;
        host.store.unavailable.store(false, Ordering::SeqCst);
        let persisted = host.store.grant().and_then(|r| r.token).is_some();
        assert_eq!(
            persisted,
            expect["grant_persisted"].as_bool().unwrap(),
            "{id}: grant"
        );
        match result {
            Ok(_) => {
                assert!(
                    expect["code"].is_null(),
                    "{id}: expected {}",
                    expect["code"]
                );
                assert!(expect["login_ended"].is_null(), "{id}");
            }
            Err(error) => {
                assert_eq!(
                    error.auth_code().unwrap().as_str(),
                    expect["code"].as_str().unwrap(),
                    "{id}"
                );
                // Scopes only on a grant narrower than the stored R.
                assert_eq!(
                    error.required_scopes(),
                    list(&expect["scopes"]),
                    "{id}: scopes"
                );
                assert_eq!(
                    error.login_ended(),
                    Some(expect["login_ended"].as_bool().unwrap()),
                    "{id}: ended"
                );
                if host_error.is_some() && input["pending"] == "pending" {
                    // The login stayed pending: the same callback now reaches
                    // the claim (a valid code completes; a denial ends it).
                    refuse(false);
                    let again = completer.complete(ctx(permitted), url, budget()).await;
                    match input["callback"].as_str().unwrap() {
                        "valid" => {
                            again.unwrap();
                            assert!(host.store.grant().and_then(|r| r.token).is_some(), "{id}");
                        }
                        _ => {
                            let error = again.err().unwrap();
                            assert_eq!(error.login_ended(), Some(true), "{id}: claimed");
                        }
                    }
                }
            }
        }
    }
    assert!(ran > 0);
}

/// `token_errors`: token-endpoint errors from a refresh or a
/// client-credentials grant, outside `complete`.
#[tokio::test]
pub(super) async fn canonical_token_error_vectors() {
    const CIMD: &str = "https://adapter.example/oauth/client.json";
    const REDIRECT: &str = "http://127.0.0.1/callback";
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let mut ran = 0;
    for vector in fixture["token_errors"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        only(id, vector, &["id", "input", "expect", "requires"]);
        if !applies(vector) {
            continue;
        }
        ran += 1;
        let (input, expect) = (&vector["input"], &vector["expect"]);
        only(
            id,
            input,
            &["grant_type", "client_source", "error", "refetch"],
        );
        only(id, expect, &["code", "reregistrations"]);
        let grant = input["grant_type"].as_str().unwrap();
        let source = input["client_source"].as_str().unwrap();
        let host = Host::new();
        host.network.dcr.store(source == "dcr", Ordering::SeqCst);
        *host.network.issuer_patch.lock().unwrap() =
            json!({"client_id_metadata_document_supported": source == "cimd"});
        let (oauth, ctx) = match (grant, source) {
            ("refresh", "preregistered") => (host.pkce(|c| c), context()),
            ("refresh", "cimd") => (
                host.owner(
                    OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
                        .scopes(scopes(&["read"]), Vec::new())
                        .redirect_uri(REDIRECT)
                        .client_id_metadata_document(CIMD, vec![REDIRECT.into()]),
                ),
                unbound(),
            ),
            ("refresh", "dcr") => (
                host.owner(
                    OAuthClientConfig::unregistered("account", OAuthFlow::AuthorizationCodePkce)
                        .scopes(scopes(&["read"]), Vec::new())
                        .redirect_uri(REDIRECT)
                        .dynamic_registration(RegistrationPolicy::new(
                            "https://issuer.example",
                            "Example Adapter",
                        )),
                ),
                unbound(),
            ),
            ("client_credentials", "preregistered") => (
                host.cc(TokenAuthMethod::ClientSecretBasic, "secret"),
                cc_context(),
            ),
            ("client_credentials", "dcr") => (
                host.owner(
                    OAuthClientConfig::unregistered("account", OAuthFlow::ClientCredentials)
                        .scopes(scopes(&["read"]), Vec::new())
                        .dynamic_registration(RegistrationPolicy::new(
                            "https://issuer.example",
                            "Example Adapter",
                        ))
                        .client_secret_storage(host.secrets.clone()),
                ),
                unbound(),
            ),
            other => panic!("{id}: unknown grant {other:?}"),
        };
        if grant == "refresh" {
            // A PKCE grant with a refresh token, then expired.
            host.seed(&oauth, ctx.clone()).await;
            host.store.expire();
        }
        // A failure that refetches the issuer's metadata is answered twice.
        let reply = |host: &Host| match input["error"].as_str().unwrap() {
            error @ ("invalid_grant"
            | "unauthorized_client"
            | "access_denied"
            | "invalid_scope") => host.network.reply(400, json!({ "error": error })),
            "invalid_client" => host.network.reply(401, json!({"error":"invalid_client"})),
            "server_error" => host.network.reply(500, json!({"error":"server_error"})),
            "not_found" => host.network.reply(404, json!({})),
            "unreachable" => {
                host.network.unsent_failures.fetch_add(1, Ordering::SeqCst);
            }
            "invalid_response" => host
                .network
                .reply(200, json!({"access_token":"x","token_type":"mac"})),
            other => panic!("{id}: unknown error {other}"),
        };
        reply(&host);
        reply(&host);
        // The stale-metadata refetch of the stored issuer's metadata fails, or
        // host destination policy refuses it (with scopes, stripped).
        match &input["refetch"] {
            Value::Null => {}
            Value::String(failed) if failed == "failed" => {
                *host.network.issuer_outage.lock().unwrap() = Some("issuer.example".into());
            }
            refused @ Value::Object(_) => {
                only(id, refused, &["callback", "target", "code", "scopes"]);
                assert_eq!(refused["callback"], "destination", "{id}");
                assert_eq!(refused["target"], "issuer_metadata", "{id}");
                host.network.refusals.lock().unwrap().push((
                    EndpointUse::IssuerMetadata,
                    fail(auth_code(refused["code"].as_str().unwrap()))
                        .with_required_scopes(&list(&refused["scopes"])),
                ));
            }
            other => panic!("{id}: unknown refetch {other}"),
        }
        let registered = host.network.registrations().len();
        let error = if ctx.authentication.is_none() && grant == "client_credentials" {
            // An unbound client-credentials endpoint acquires on its 401.
            oauth
                .challenge(ctx, challenge(401, "Bearer", None))
                .await
                .err()
                .unwrap()
        } else {
            oauth.credential(ctx).await.err().unwrap()
        };
        assert_eq!(error.auth_code().unwrap().as_str(), expect["code"], "{id}");
        assert!(error.required_scopes().is_empty(), "{id}: no scopes");
        assert_eq!(error.login_ended(), None, "{id}");
        let registrations = host.network.registrations().len() - registered;
        match expect["reregistrations"].as_u64() {
            // Registrations after the first, before the repeated invalid_client.
            Some(expected) => {
                assert_eq!(registrations.saturating_sub(1) as u64, expected, "{id}")
            }
            None => assert!(registrations <= 1, "{id}: no re-registration"),
        }
    }
    assert!(ran > 0);
}
