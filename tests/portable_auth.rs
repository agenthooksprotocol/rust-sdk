use agenthooksprotocol::{generated, interop::Schemas};
use serde_json::{Value, json};

fn registration() -> Value {
    json!({
        "protocolVersion": "draft",
        "hooks": [{
            "id": "com.example.policy",
            "transport": {"type": "http", "url": "https://policy.example.com/hooks"},
            "subscriptions": [{
                "events": ["tool.before"], "mode": "intercept", "timeoutMs": 750,
                "failurePolicy": "fail-closed", "content": {"default": "metadata"}
            }]
        }]
    })
}

#[test]
fn portable_registration_accepts_omission_bearer_and_oauth() {
    let schemas = Schemas::bundled().unwrap();
    let mut value = registration();
    schemas.validate("registration", &value).unwrap();
    for auth in [
        json!({"type": "bearer", "tokenEnv": "AHP_TOKEN"}),
        json!({"type": "bearer", "tokenRef": "secret-reference"}),
        json!({"type": "oauth", "resource": "https://policy.example.com/hooks",
            "issuer": "https://issuer.example.com", "clientId": "test-client",
            "flow": "client_credentials", "clientSecretRef": "secret-reference"}),
    ] {
        value["hooks"][0]["authentication"] = auth;
        assert!(generated::parse_registration_value(value.clone()).is_ok());
        schemas.validate("registration", &value).unwrap();
    }
}

#[test]
fn registration_unknown_authentication_follows_schema_but_rejects_admission() {
    let schemas = Schemas::bundled().unwrap();
    let mut value = registration();
    value["hooks"][0]["authentication"] =
        json!({"type": "com.example.identity", "tokenEnv": "AHP_TOKEN"});
    // The pinned schema uses an inferred open oneOf discriminator. Main's
    // auth-discovery contract intentionally uses a closed anyOf instead.
    // Neither structural contract authorizes an unknown runtime identity.
    let bundle: Vec<Value> = serde_json::from_str(include_str!("../src/schemas.json")).unwrap();
    let schema = bundle
        .iter()
        .find(|schema| {
            schema["$id"]
                .as_str()
                .unwrap()
                .ends_with("/registration.schema.json")
        })
        .unwrap();
    let authentication = &schema["$defs"]["authentication"];
    let parsed = generated::parse_registration_value(value.clone());
    if authentication.get("oneOf").is_some() {
        assert!(parsed.is_ok(), "{:?}", parsed.diagnostics());
        assert!(parsed.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == generated::DiagnosticCode::UnknownVariant
                && diagnostic.severity == generated::DiagnosticSeverity::Warning
        }));
        assert_eq!(
            serde_json::to_value(parsed.value().unwrap()).unwrap(),
            value
        );
    } else {
        assert!(authentication.get("anyOf").is_some());
        assert!(!parsed.is_ok());
        assert!(
            parsed
                .diagnostics()
                .iter()
                .any(|diagnostic| { diagnostic.code == generated::DiagnosticCode::NoUnionMatch })
        );
    }
    assert!(
        agenthooksprotocol::registration::validate(
            &value,
            &json!({}),
            &json!({}),
            &json!({}),
            &schemas,
        )
        .is_err()
    );
    assert!(schemas.validate("registration", &value).is_err());
}

#[test]
fn registration_rejects_structurally_malformed_known_authentication() {
    let schemas = Schemas::bundled().unwrap();
    for auth in [
        json!({"type": "bearer", "tokenEnv": 42}),
        json!({"type": "bearer"}),
        json!({"type": "oauth", "resource": "https://policy.example.com/hooks"}),
        json!({"type": 42, "tokenEnv": "AHP_TOKEN"}),
    ] {
        let mut value = registration();
        value["hooks"][0]["authentication"] = auth;
        let parsed = generated::parse_registration_value(value.clone());
        assert!(!parsed.is_ok(), "malformed authentication parsed: {value}");
        assert!(
            !parsed
                .diagnostics()
                .iter()
                .any(|diagnostic| { diagnostic.code == generated::DiagnosticCode::UnknownVariant })
        );
        assert!(schemas.validate("registration", &value).is_err());
        assert!(
            agenthooksprotocol::registration::validate(
                &value,
                &json!({}),
                &json!({}),
                &json!({}),
                &schemas,
            )
            .is_err()
        );
    }
}

#[cfg(feature = "reqwest")]
#[test]
fn provider_does_not_admit_unknown_mechanisms_or_oauth_flows() {
    use agenthooksprotocol::{
        adapters::registered::*,
        client::{HookError, LocalFuture},
    };
    use std::sync::Arc;
    struct Host;
    impl AuthProvider for Host {
        fn credential(
            &self,
            _: AuthContext,
        ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
            Box::pin(async { panic!("admission must not invoke provider") })
        }
        fn challenge(
            &self,
            _: AuthContext,
            _: AuthChallenge,
        ) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { panic!("admission must not invoke provider") })
        }
    }
    let options = BackendOptions {
        auth_provider: Some(Arc::new(Host)),
        ..Default::default()
    };
    for authentication in [
        json!({"type":"unknown"}),
        json!({"type":"oauth","flow":"password"}),
    ] {
        assert!(from_registration(&json!({"id":"example","transport":{"type":"http","url":"https://example.com"},"authentication":authentication}), &options).is_err());
    }
}
