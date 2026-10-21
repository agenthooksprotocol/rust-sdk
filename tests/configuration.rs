use agenthooksprotocol::{Configuration, content, event, subscription};
use std::time::Duration;

#[test]
fn public_configuration_uses_typed_selectors_and_native_duration() {
    let configuration = Configuration::new()
        .subscribe(
            subscription::intercept(event::ToolBefore)
                .timeout(Duration::from_millis(750))
                .fail_open()
                .content(content::Selection::metadata()),
        )
        .subscribe(subscription::observe(event::ToolAfter).content(content::Selection::metadata()));
    let wire = serde_json::to_value(&configuration).unwrap();
    assert_eq!(
        wire["subscriptions"][0]["events"],
        serde_json::json!(["tool.before"])
    );
    assert_eq!(wire["subscriptions"][0]["mode"], "intercept");
    assert_eq!(wire["subscriptions"][0]["timeoutMs"], 750);
    assert_eq!(wire["subscriptions"][0]["failurePolicy"], "fail-open");
    assert_eq!(wire["subscriptions"][1]["mode"], "observe");
    assert!(wire["subscriptions"][1].get("timeoutMs").is_none());
    assert!(wire["subscriptions"][1].get("failurePolicy").is_none());
    let from_file: Configuration = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(from_file).unwrap(), wire);
    let handlers = agenthooksprotocol::server::HandlerSet {
        configuration: Some(configuration),
        ..Default::default()
    };
    assert!(handlers.configuration.is_some());
}
