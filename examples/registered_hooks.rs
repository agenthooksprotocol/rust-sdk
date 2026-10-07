//! Run a real registered HTTP or stdio hook without a transport callback.
//!
//! ```text
//! cargo run --example registered_hooks --features reqwest,tokio-process -- registration.json
//! ```
//!
//! The file is an ordinary protocol Registration JSON document. For a backend
//! using bearer `tokenRef: "policy-token"`, supply `REGISTERED_HOOK_TOKEN` through
//! your environment. Add `--allow-loopback-http` after the path only for an
//! explicitly trusted local HTTP fixture. HTTPS remains the default.
//!
//! This example intentionally never executes the proposed shell command. The
//! application, not the hook SDK, owns execution and approval policy.

use agenthooksprotocol::{
    EventType, Registration, ToolBeforeInputOrigin,
    capability::{self, ModifyOperation},
    client::Decision,
    ergonomic_inputs::ToolBeforeInput,
    hooks::{Hooks, HooksOptions},
    state,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct ShellInput {
    command: String,
    #[serde(rename = "timeoutMs")]
    timeout_ms: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: registered_hooks <registration.json> [--allow-loopback-http]")?;
    let allow_loopback_http = match args.next().as_deref() {
        None => false,
        Some("--allow-loopback-http") => true,
        Some(_) => return Err("unknown option".into()),
    };
    if args.next().is_some() {
        return Err("too many arguments".into());
    }

    // Normal filesystem I/O and serde: there is no custom registration loader.
    let configuration = std::fs::read_to_string(path)?;
    let registration = serde_json::from_str::<Registration>(&configuration)?;
    // Authority is separate from configuration and limited to one named event.
    // No wildcard grants or implicit elicitation modes are enabled.
    let mut options = HooksOptions::from_declarations(
        "https://example.test/registered-hooks-demo",
        [(
            EventType::ToolBefore,
            capability::intercept()
                .allow()
                .deny()
                .r#return()
                .modify_input([ModifyOperation::Replace, ModifyOperation::Merge])?,
        )],
    )?;
    options.backend.allow_loopback_http = allow_loopback_http;
    if let Ok(token) = std::env::var("REGISTERED_HOOK_TOKEN") {
        options
            .backend
            .credentials
            .insert("policy-token".into(), token);
    }
    // Registration selects the actual built-in HTTP or process transport.
    // Construction performs validation but does not start I/O.
    let hooks = Hooks::new(registration, options)?;
    let pending = hooks
        .tool_before(
            ToolBeforeInput::new(
                "demo-call".into(),
                "native".into(),
                ShellInput {
                    command: "echo hello".into(),
                    timeout_ms: 1000,
                },
                "shell".into(),
                ToolBeforeInputOrigin::Native,
            )
            .with_tool_kind("shell".into()),
        )
        // Native policy already decided for this exact occurrence; not execution.
        .initial_snapshot(state::initial(Decision::Allow))?;
    // Dispatch is lazy. Event identity/time are generated and source is bound
    // to the explicit host authority when this boundary is awaited.
    let result = pending.await;
    // This awaited operation has completed its owned observation deliveries.
    // Idle waiting only reports; shutdown cancels outstanding work and reaps children.
    let report = hooks.wait_until_idle().await;
    hooks.shutdown().await?;
    eprintln!(
        "observations: {} delivered, {} failed",
        report.delivered,
        report.failures.len()
    );
    let result = result?;
    if result.outcome.is_denied() {
        println!("Denied: do not execute the tool or consume a supplied result.");
    } else if let Some(value) = result.outcome.supplied_result() {
        println!("Hook supplied a result; do not execute the tool: {value}");
    } else if result.outcome.can_execute() {
        // Re-deserialization occurs after the effective protocol input settles.
        // A typed decode failure must not fall back to the original input.
        let effective = result.input?;
        println!("Authorized effective input: {effective:?}");
        println!("The host would execute this input here; this example does not.");
    } else {
        println!("Not executable: approval or another local policy step is required.");
    }
    Ok(())
}
