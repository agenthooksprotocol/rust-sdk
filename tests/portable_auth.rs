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
fn registration_preserves_unknown_authentication_but_rejects_admission() {
    let schemas = Schemas::bundled().unwrap();
    let mut value = registration();
    value["hooks"][0]["authentication"] =
        json!({"type": "com.example.identity", "tokenEnv": "AHP_TOKEN"});
    // Generated structural models preserve unknown discriminator variants. This
    // is not authority to use that authentication binding at runtime.
    let parsed = generated::parse_registration_value(value.clone());
    assert!(parsed.is_ok());
    assert!(parsed.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == generated::DiagnosticCode::UnknownVariant
            && diagnostic.severity == generated::DiagnosticSeverity::Warning
    }));
    assert_eq!(
        serde_json::to_value(parsed.value().unwrap()).unwrap(),
        value
    );
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
