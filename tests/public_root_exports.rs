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
