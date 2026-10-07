//! Generated semantic constructors, optional builders, and native union conversion.
use agenthooksprotocol::{
    client::{InterceptResponse, InterceptResponseResult},
    common::{JsonRpcId, JsonRpcResponseId},
    effect::{DenyEffect, Effect},
    encode_intercept_response, parse_intercept_response_value,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let effect: Effect = DenyEffect::new("Application policy denied this operation")
        .with_code("policy_denied")
        .into();
    assert!(matches!(effect, Effect::Deny(_)));
    let response = InterceptResponse::new(
        JsonRpcResponseId::from(JsonRpcId::from("evt_example".to_owned())),
        InterceptResponseResult::new(vec![Box::new(effect)]),
    );
    // Constructors supply jsonrpc, effect type, and protocolVersion literals.
    let encoded = encode_intercept_response(&response)?;
    let mut wire: serde_json::Value = serde_json::from_str(&encoded)?;
    assert_eq!(wire["jsonrpc"], "2.0");
    assert_eq!(wire["result"]["protocolVersion"], "draft");
    assert_eq!(wire["result"]["effects"][0]["type"], "deny");
    // Open envelope properties remain unchanged when decoding and re-encoding.
    wire["com.example.trace"] = serde_json::json!({"retained": true});
    let parsed = parse_intercept_response_value(wire.clone())
        .into_value()
        .unwrap();
    assert_eq!(serde_json::to_value(parsed)?, wire);
    println!("{encoded}");
    Ok(())
}
