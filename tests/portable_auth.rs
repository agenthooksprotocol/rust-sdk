use agent_hooks_protocol::{generated, interop::Schemas};
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
fn registration_rejects_unknown_authentication() {
    let schemas = Schemas::bundled().unwrap();
    let mut value = registration();
    value["hooks"][0]["authentication"] =
        json!({"type": "com.example.identity", "tokenEnv": "AHP_TOKEN"});
    assert!(!generated::parse_registration_value(value.clone()).is_ok());
    assert!(schemas.validate("registration", &value).is_err());
}
