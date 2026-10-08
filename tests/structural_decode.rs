use agenthooksprotocol::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn check<T: DeserializeOwned + Serialize>(case: &Value, parsed: ParseResult<T>) {
    let raw = case["value"].clone();
    let accepted = case["accepted"].as_bool().unwrap();
    let direct = serde_json::from_value::<T>(raw.clone());
    assert_eq!(
        direct.is_ok(),
        accepted,
        "direct {}: {:?}",
        case["id"],
        direct.err()
    );
    match parsed {
        ParseResult::Success {
            value,
            raw: preserved,
            diagnostics,
        } => {
            assert!(accepted, "parse {}", case["id"]);
            assert_eq!(preserved, raw, "raw {}", case["id"]);
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                raw,
                "roundtrip {}",
                case["id"]
            );
            assert_eq!(
                diagnostics
                    .iter()
                    .any(|d| d.severity == DiagnosticSeverity::Warning),
                case["warning"].as_bool().unwrap(),
                "warnings {}",
                case["id"]
            );
        }
        ParseResult::Failure {
            raw: preserved,
            diagnostics,
        } => {
            assert!(!accepted, "parse {}: {diagnostics:?}", case["id"]);
            assert_eq!(preserved, Some(raw));
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.severity == DiagnosticSeverity::Error)
            );
        }
    }
}

#[test]
fn shared_structural_acceptance_matrix() {
    let matrix: Value = serde_json::from_str(include_str!("structural-acceptance.json")).unwrap();
    for case in matrix["cases"].as_array().unwrap() {
        let wire = case["value"].to_string();
        match case["root"].as_str().unwrap() {
            "intercept_request" => check::<InterceptRequest>(case, parse_intercept_request(&wire)),
            "content_reference" => check::<ContentReference>(case, parse_content_reference(&wire)),
            "content_upload_receipt" => {
                check::<ContentUploadReceipt>(case, parse_content_upload_receipt(&wire))
            }
            other => panic!("unknown matrix root {other}"),
        }
    }
}

#[test]
fn serde_state_requires_candidate_and_candidate_value_and_resets_after_failure() {
    assert!(serde_json::from_value::<state::Candidate>(serde_json::json!({})).is_err());
    assert!(serde_json::from_value::<state::Candidate>(serde_json::json!({"value":null})).is_ok());
    assert!(
        serde_json::from_value::<state::Candidate>(
            serde_json::json!({"value":null,"provenance":null})
        )
        .is_err()
    );
    let extended = serde_json::json!({"value":null,"vendor":7});
    let candidate: state::Candidate = serde_json::from_value(extended.clone()).unwrap();
    assert_eq!(serde_json::to_value(candidate).unwrap(), extended);
    for candidate in [
        serde_json::json!(null),
        serde_json::json!({"value":null}),
        serde_json::json!({"value":0}),
    ] {
        let raw = serde_json::json!({"permission":"allow", "candidate":candidate});
        let state: state::InitialState = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(serde_json::to_value(state).unwrap(), raw);
    }
    for raw in [
        serde_json::json!({"permission":"allow"}),
        serde_json::json!({"permission":"allow","candidate":{}}),
    ] {
        assert!(serde_json::from_value::<state::InitialState>(raw).is_err());
    }
    assert!(
        serde_json::from_value::<state::InitialState>(
            serde_json::json!({"permission":"allow","candidate":null})
        )
        .is_ok()
    );
}

#[test]
fn incoming_capabilities_support_schema_effect_ids_and_custom_families() {
    let value = serde_json::json!({"effects":["deny","vendor.effect"], "modify":{"input":{"replace":true,"merge":false}}});
    let capabilities: Capabilities = serde_json::from_value(value.clone()).unwrap();
    assert!(capabilities.supports(EffectId::Deny));
    assert!(capabilities.supports(capability::EffectType::Deny));
    assert_eq!(
        capability::EffectType::Unknown("vendor.effect".into()).as_str(),
        "vendor.effect"
    );
    let native = Capabilities::new(vec![
        CapabilitiesEffectsItem::Custom("deny".into()),
        CapabilitiesEffectsItem::Known(EffectId::Unknown("vendor.effect".into())),
    ]);
    assert!(native.supports(EffectId::Deny));
    assert!(native.supports(EffectId::Unknown("vendor.effect".into())));
    let scoped: ToolBeforeCapabilities =
        serde_json::from_value(serde_json::json!({"effects":["deny"]})).unwrap();
    assert!(scoped.supports(capability::EffectType::Deny));
    assert!(!scoped.supports(capability::EffectType::Modify));
    assert!(capabilities.supports(EffectId::Unknown("vendor.effect".into())));
    assert!(!capabilities.supports(EffectId::Modify));
    assert!(!capabilities.supports(EffectId::Unknown("absent.effect".into())));
    assert_eq!(serde_json::to_value(capabilities).unwrap(), value);
}
