//! `cargo run --example typed_boundary --no-default-features`
//! A real lazy typed SDK boundary on a non-Tokio executor. Execution is userland.
use agenthooksprotocol::client::{
    Client, Decision, FailurePolicy, Hook, HookError, LocalFuture, Subscription, ToolContext,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Serialize, Deserialize)]
struct Input {
    command: String,
}

struct Policy;
impl Hook for Policy {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":[
                    {"type":"modify","target":"input","operation":"replace","value":{"command":"echo reviewed"}},
                    {"type":"allow"}
                ]}}),
            )
        })
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(ToolContext::new(json!({
        "id":"evt_example_1", "source":"urn:example:rust", "type":"tool.before",
        "time":"2026-09-01T00:00:00Z", "session":{"id":"session_example"},
        "call":{"id":"call_example_1"}, "path":"native",
        "tool":{"origin":"native","name":"shell","kind":"shell","input":{}}
    })))
    .with_subscription(Subscription::intercept(
        "policy",
        FailurePolicy::Closed,
        Policy,
    ));

    let result = futures::executor::block_on(async {
        client
            .tool_before(Input {
                command: "echo original".into(),
            })
            .initial_state(Decision::Allow)
            .capabilities(
                json!({"effects":["modify","allow"], "modify":{"input":{"replace":true,"merge":false}}}),
            )
            .await
    })?;
    // Protocol outcome is already settled. A decoding or host-policy rejection
    // must not turn it into a rejected protocol response or undo effects.
    println!("effective input: {}", result.effective_input);
    if result.outcome.can_execute() {
        match result.input {
            Ok(input) if input.command.starts_with("echo ") => {
                println!(
                    "Host accepted {:?}; execution deliberately omitted",
                    input.command
                );
            }
            Ok(_) => println!("SDK accepted; host refused its own execution policy"),
            Err(error) => println!("SDK accepted; host cannot decode: {error}"),
        }
    } else {
        println!("Not executable: {:?}", result.outcome.decision);
    }
    Ok(())
}
