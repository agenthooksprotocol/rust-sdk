use agenthooksprotocol::{
    Attachment, Hooks, ToolBeforeInputOrigin,
    ergonomic_inputs::{PartInput, ToolBeforeInput},
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use agenthooksprotocol::{
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
};
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
struct Unreachable;
impl ManagedBackend for Unreachable {
    fn call(
        &self,
        _: serde_json::Value,
        _: Duration,
    ) -> LocalFuture<'_, Result<serde_json::Value, HookError>> {
        panic!("unmatched route called")
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Arguments {
    count: u64,
}

#[test]
fn primary_typed_tool_hook_owns_direct_binary_parts() {
    block_on(async {
        let hooks = Hooks::new(
            json!({"protocolVersion":"draft","hooks":[{"id":"org.example.direct", "transport":{"type":"stdio","command":"unused","lifecycle":"persistent"}, "subscriptions":[{"events":["tool.before"],"mode":"intercept","failurePolicy":"fail-closed","timeoutMs":1000,"filters":{"paths":["unmatched/**"]},"content":{"default":"metadata"}}]}]}),
            HooksOptions::new(
                "urn:test:direct-tool",
                BTreeMap::from([(
                    "tool.before".into(),
                    EventGrant::intercept(Capabilities::none()),
                )]),
            ).with_backend("org.example.direct", Arc::new(Unreachable)),
        )
        .unwrap();
        let input = ToolBeforeInput::new(
            "call".into(),
            "files/read".into(),
            Arguments { count: 7 },
            "read".into(),
            ToolBeforeInputOrigin::Native,
        )
        .with_sources()
        .with_items(vec![
            PartInput::inline_text("Read the binary file"),
            PartInput::owned(Attachment::bytes(vec![0, 255]), "application/octet-stream"),
        ]);
        let result = hooks.tool_before(input).await.unwrap();
        assert_eq!(result.input.unwrap(), Arguments { count: 7 });
        hooks.shutdown().await.unwrap();
        assert_eq!(&*result.content.read("/items/1").await.unwrap(), &[0, 255]);
    });
}
