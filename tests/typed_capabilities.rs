use agenthooksprotocol::{
    Hooks,
    capability::{self, HostCapabilities, InjectContext, Modify, Observe},
    hooks::HooksOptions,
};
use agenthooksprotocol::{
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
struct UnusedBackend;
impl ManagedBackend for UnusedBackend {
    fn call(&self, _: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        panic!("construction must not perform I/O")
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn typed_capabilities_render_exact_grants_and_explicit_observation() {
    let capabilities = HostCapabilities {
        tool_before: Some(
            capability::tool_before()
                .allow()
                .deny()
                .return_result()
                .modify_input(Modify::ReplaceAndMerge)
                .observe(),
        ),
        tool_after: Some(capability::tool_after().inject_context(InjectContext::NowAndNextTurn)),
        session_end: Some(Observe),
        ..Default::default()
    };
    let wire = serde_json::to_value(capabilities.to_wire()).unwrap();
    assert_eq!(
        wire["tool.before"]["modes"],
        json!(["intercept", "observe"])
    );
    assert_eq!(
        wire["tool.before"]["capabilities"]["effects"],
        json!(["allow", "deny", "modify", "return"])
    );
    assert_eq!(
        wire["tool.before"]["capabilities"]["modify"]["input"],
        json!({"replace":true,"merge":true})
    );
    assert_eq!(wire["tool.after"]["modes"], json!(["intercept"]));
    assert_eq!(
        wire["tool.after"]["capabilities"]["inject"]["context"],
        json!({"append":true,"deliverAt":["now","next_turn"]})
    );
    assert_eq!(wire["session.end"], json!({"modes":["observe"]}));
    assert!(wire.get("session.start").is_none());
    assert_eq!(
        serde_json::to_value(HostCapabilities::default().to_wire()).unwrap(),
        json!({})
    );
}

#[test]
fn facility_only_interception_and_observation_render_without_artificial_effects() {
    for declaration in [
        capability::user_elicitation_request().elicitation_form(),
        capability::user_elicitation_request()
            .observe()
            .elicitation_form(),
    ] {
        let caps = HostCapabilities {
            user_elicitation_request: Some(declaration),
            ..Default::default()
        };
        let hooks = Hooks::new(
            json!({"protocolVersion":"draft","hooks":[{"id":"org.example.facilities",
                "transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},
                "subscriptions":[{"events":["user.elicitation.request"],"mode":"intercept",
                    "failurePolicy":"fail-closed","timeoutMs":1000,"content":{"default":"metadata"}}]}]}),
            HooksOptions::new("urn:test:typed-facilities", caps).with_backend("org.example.facilities", Arc::new(UnusedBackend)),
        )
        .unwrap();
        let event = hooks.manifest()["events"][0].clone();
        assert_eq!(event["event"], json!("user.elicitation.request"));
        assert_eq!(
            event["capabilities"],
            json!({"effects":[],"elicitation":{"form":{}}})
        );
        assert!(
            event["modes"]
                .as_array()
                .unwrap()
                .contains(&json!("intercept"))
        );
        assert!(hooks.subscribes("user.elicitation.request"));
    }
    let observe = serde_json::to_value(capability::user_elicitation_request().observe()).unwrap();
    assert_eq!(observe, json!({"modes":["observe"]}));
    assert!(observe.get("capabilities").is_none());
}
