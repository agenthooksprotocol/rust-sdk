//! Compile-time coverage for the crate-root model API and legacy paths.
use agenthooksprotocol::{
    Registration, StaticCapabilityManifest, encode_registration, generated, parse_registration,
};

#[test]
fn root_models_and_codecs_are_the_generated_api() {
    // Assignments enforce identical types, not merely matching wire formats.
    let _: fn(Registration) -> generated::Registration = |value| value;
    let _: fn(StaticCapabilityManifest) -> generated::StaticCapabilityManifest = |value| value;
    let _: fn(&str) -> generated::ParseResult<Registration> = parse_registration;
    let _: fn(&Registration) -> Result<String, serde_json::Error> = encode_registration;
    assert_eq!(
        agenthooksprotocol::boundary::ALL_BOUNDARIES.len(),
        generated::boundary::ALL_BOUNDARIES.len(),
    );
}

#[test]
fn handwritten_modules_and_semantic_helpers_remain_accessible() {
    use agenthooksprotocol::{client, content, effect, registration, transport};

    let _: Option<client::Client> = None;
    let _: Option<content::MemoryContentStore> = None;
    let _: Option<transport::Request> = None;
    let _ = registration::validate;
    let _: agenthooksprotocol::Effect = effect::deny("denied".into());
    let _: agenthooksprotocol::Effect = effect::DenyEffect::new("denied").into();
    let _: Option<agenthooksprotocol::capability::Event> = None;
    let _: Option<agenthooksprotocol::state::Candidate> = None;
}

#[test]
fn intercept_and_observe_expose_the_same_shared_event() {
    use agenthooksprotocol::{
        Event, ParseResult, parse_intercept_request_value, parse_observe_notification_value,
    };
    use serde_json::{Value, json};

    fn consume(event: &Event) -> Value {
        serde_json::to_value(event).unwrap()
    }
    let event = json!({
        "id":"shared", "source":"urn:test", "time":"2026-09-01T00:00:00Z",
        "type":"tool.before", "path":"native", "call":{"id":"call"},
        "tool":{"name":"read", "origin":"native", "input":{}},
        "items":[{"id":"body", "kind":"attachment", "mediaType":"application/octet-stream",
                  "selection":"body", "body":{"ref":"stored"}}]
    });
    let intercept = json!({"jsonrpc":"2.0", "id":"rpc", "method":"hooks/intercept",
        "params":{"protocolVersion":"draft", "event":event, "capabilities":{"effects":[]}}});
    let observe = json!({"jsonrpc":"2.0", "method":"hooks/observe",
        "params":{"protocolVersion":"draft", "event":event}});
    let parsed_intercept = parse_intercept_request_value(intercept);
    let ParseResult::Success {
        value: intercept, ..
    } = parsed_intercept
    else {
        panic!("valid intercept request: {parsed_intercept:?}");
    };
    let ParseResult::Success { value: observe, .. } = parse_observe_notification_value(observe)
    else {
        panic!("valid observation");
    };
    // These assignments require the actual request fields to have one identical type.
    let intercept_event: Box<Event> = intercept.params.event;
    let observe_event: Box<Event> = observe.params.event;
    assert_eq!(consume(&intercept_event), event);
    assert_eq!(consume(&observe_event), event);
}

#[test]
fn shared_event_does_not_widen_the_intercept_event_subset() {
    use agenthooksprotocol::{
        ParseResult, parse_intercept_request_value, parse_observe_notification_value,
    };
    use serde_json::json;
    let event = json!({"id":"settled", "source":"urn:test", "time":"2026-09-01T00:00:00Z",
        "type":"session.end", "session":{"id":"session"}, "outcome":"completed", "reason":"done"});
    let observe = json!({"jsonrpc":"2.0", "method":"hooks/observe", "params":{"protocolVersion":"draft", "event":event}});
    let observed = parse_observe_notification_value(observe);
    assert!(
        matches!(observed, ParseResult::Success { .. }),
        "{observed:?}"
    );
    let intercept = json!({"jsonrpc":"2.0", "id":"rpc", "method":"hooks/intercept", "params":{"protocolVersion":"draft", "event":event, "capabilities":{"effects":[]}}});
    assert!(!matches!(
        parse_intercept_request_value(intercept),
        ParseResult::Success { .. }
    ));
}
