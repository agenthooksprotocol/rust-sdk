//! Run with: cargo run --no-default-features --example tool_contracts
use agenthooksprotocol::{
    Hooks,
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
    contracts::Contract,
    generated::ToolBeforeInputOrigin,
    hooks::{Capabilities, EventGrant, HooksOptions},
    inputs::ToolBeforeInput,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolResult {
    total: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    source: String,
}

struct Policy;
impl ManagedBackend for Policy {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            Ok(json!({
                "jsonrpc": "2.0", "id": request["id"],
                "result": {"protocolVersion": "draft", "effects": [
                    {"type": "modify", "target": "input", "operation": "merge",
                     "value": {"count": 2}},
                    {"type": "return", "value": {"total": 20}}
                ]}
            }))
        })
    }

    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    futures::executor::block_on(async {
        // JSON registration is an advanced configuration path. The backend
        // override implements delivery without starting the declared process.
        let registration = json!({"protocolVersion": "draft", "hooks": [{
            "id": "org.example.contracts",
            "transport": {"type": "stdio", "command": "unused", "lifecycle": "persistent"},
            "subscriptions": [{"events": ["tool.before"], "mode": "intercept",
                "timeoutMs": 1000, "failurePolicy": "fail-closed",
                "content": {"default": "metadata"}}]
        }]});
        let options = HooksOptions::new(
            "urn:example:contracts",
            BTreeMap::from([(
                "tool.before".into(),
                EventGrant::intercept(Capabilities::none().modify_input().return_value()),
            )]),
        )
        .with_backend("org.example.contracts", Arc::new(Policy));
        let hooks = Hooks::new(registration, options)?;
        let input = ToolBeforeInput::new(
            "call-1".into(),
            "native".into(),
            Arguments { count: 1 },
            "counter".into(),
            ToolBeforeInputOrigin::Native,
        );
        let operation = hooks
            .tool_before(input)
            .arguments_contract(Contract::<Arguments>::validated(|args| {
                if args.count <= 100 {
                    Ok(())
                } else {
                    Err("count exceeds limit".into())
                }
            }))
            .result_type::<ToolResult>()
            .provenance_type::<Provenance>()
            .await;
        // Always shut down owned backend resources, even after a boundary error.
        hooks.shutdown().await?;
        let outcome = operation?;
        println!("permission: {:?}", outcome.permission());
        let arguments = outcome.input;
        assert_eq!(arguments.count, 2);
        if let Some(candidate) = outcome.outcome.settled_candidate {
            assert_eq!(candidate.value.total, 20);
            println!("candidate: {:?}", candidate.value);
        }
        // Host approval and execution policy are separate; this example does
        // not execute the tool. Release returned content owners when finished.
        drop(outcome.content);
        Ok(())
    })
}
