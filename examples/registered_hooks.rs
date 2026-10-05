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
    client::{Decision, ToolContext},
    generated::Registration,
    hooks::{Capabilities, EventGrant, Hooks, HooksOptions, TokioObservationScheduler},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
struct ShellInput {
    command: String,
    #[serde(rename = "timeoutMs")]
    timeout_ms: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::task::LocalSet::new().run_until(run()).await
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
    let grants = [(
        "tool.before".into(),
        EventGrant::intercept(
            Capabilities::none()
                .allow()
                .deny()
                .return_value()
                .modify_input(),
        )
        .with_observe(),
    )]
    .into();
    let mut options = HooksOptions::new("https://example.test/registered-hooks-demo", grants);
    options.backend.allow_loopback_http = allow_loopback_http;
    if let Ok(token) = std::env::var("REGISTERED_HOOK_TOKEN") {
        options
            .backend
            .credentials
            .insert("policy-token".into(), token);
    }
    // Registration selects the actual built-in HTTP or process transport.
    // Construction performs validation but does not start I/O.
    options.observation_scheduler = Some(std::rc::Rc::new(TokioObservationScheduler));
    let hooks = Hooks::new(registration, options)?;
    let pending = hooks
        .tool_before(ShellInput {
            command: "echo hello".into(),
            timeout_ms: 1000,
        })
        .context(ToolContext::new(json!({
            "path":"native",
            "call":{"id":"demo-call"},
            "tool":{"name":"shell","kind":"shell","origin":"native"}
        })))
        // Explicit local policy for this harmless proposal; real hosts must decide.
        .initial_state(Decision::Allow);
    // Dispatch is lazy. Event identity/time are generated and source is bound
    // to the explicit host authority when this boundary is awaited.
    let result = pending.await;
    // Observations are scheduled automatically on the host LocalSet. Waiting
    // only joins delivery; shutdown cancels outstanding work and reaps children.
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
