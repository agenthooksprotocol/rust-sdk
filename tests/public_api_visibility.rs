//! Compile consumers outside the crate to check its actual public boundary.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
struct Consumer {
    dir: PathBuf,
    deps: PathBuf,
    library: PathBuf,
}
impl Consumer {
    fn new() -> Self {
        let deps = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let library = library(&deps, "agenthooksprotocol");
        let dir = std::env::temp_dir().join(format!(
            "ahp-consumer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        Self { dir, deps, library }
    }
    fn compile(&self, name: &str, source: &str) -> std::process::Output {
        let input = self.dir.join(format!("{name}.rs"));
        fs::write(&input, source).unwrap();
        let mut command = Command::new("rustc");
        command.args([
            "--edition=2024",
            "--crate-type=lib",
            "--emit=metadata",
            "--crate-name",
            name,
        ]);
        command
            .arg(&input)
            .arg("--out-dir")
            .arg(&self.dir)
            .arg("-L")
            .arg(format!("dependency={}", self.deps.display()))
            .arg("--extern")
            .arg(format!("agenthooksprotocol={}", self.library.display()));
        #[cfg(feature = "typed-form")]
        {
            command.arg("--cfg").arg("feature=\"typed-form\"");
            for name in ["serde", "schemars"] {
                command
                    .arg("--extern")
                    .arg(format!("{name}={}", library(&self.deps, name).display()));
            }
        }
        command.output().unwrap()
    }
}
impl Drop for Consumer {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn library(deps: &Path, name: &str) -> PathBuf {
    fs::read_dir(deps)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&format!("lib{name}-"))
                && path.extension().is_some_and(|ext| ext == "rlib")
        })
        .filter(|path| {
            if name != "agenthooksprotocol" {
                return true;
            }
            // Other feature gates and examples can leave newer libraries here.
            // Select this test's feature set, not the most recent arbitrary build.
            let stem = path.file_stem().unwrap().to_string_lossy();
            let fingerprint = deps
                .parent()
                .unwrap()
                .join(".fingerprint")
                .join(stem.trim_start_matches("lib"))
                .join("lib-agenthooksprotocol.json");
            let Ok(bytes) = fs::read(fingerprint) else {
                return false;
            };
            let metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let features: Vec<String> =
                serde_json::from_str(metadata["features"].as_str().unwrap()).unwrap();
            [
                ("default", cfg!(feature = "default")),
                ("typed-form", cfg!(feature = "typed-form")),
                ("reqwest", cfg!(feature = "reqwest")),
                ("axum", cfg!(feature = "axum")),
                ("tokio-process", cfg!(feature = "tokio-process")),
                ("interop", cfg!(feature = "interop")),
            ]
            .into_iter()
            .all(|(feature, enabled)| features.iter().any(|actual| actual == feature) == enabled)
        })
        .max_by_key(|path| fs::metadata(path).unwrap().modified().unwrap())
        .unwrap_or_else(|| panic!("missing external consumer library {name}"))
}
#[test]
fn domain_facade_compiles_from_an_external_consumer() {
    let consumer = Consumer::new();
    let output=consumer.compile("public_consumer",r#"
use agenthooksprotocol::{Hooks, inputs::ToolBeforeInput, generated::{Candidate,JsonValue}, hooks::{ToolBoundary,ToolOutcome}, contracts::Contract};
pub fn boundary<'a>(hooks:&'a Hooks,input:ToolBeforeInput<JsonValue>)->ToolBoundary<'a,JsonValue,String> {
    hooks.tool_before(input).result_type::<String>()
}
pub fn candidate(outcome:ToolOutcome<JsonValue,String>)->Option<Candidate<String,JsonValue>> { outcome.outcome.settled_candidate }
pub fn input(outcome:ToolOutcome<JsonValue,String>)->JsonValue { outcome.input }
pub fn subscribes(hooks:&Hooks,event:agenthooksprotocol::generated::EventType)->bool { hooks.subscribes(event) }
pub fn typed_options()->agenthooksprotocol::hooks::HooksOptions {
    use agenthooksprotocol::capability::{self, HostCapabilities, Modify};
    agenthooksprotocol::hooks::HooksOptions::new("urn:test:typed", HostCapabilities {
        tool_before: Some(capability::tool_before().allow().deny().return_result().modify_input(Modify::ReplaceAndMerge)),
        user_elicitation_request: Some(capability::user_elicitation_request().elicitation_form()),
        ..Default::default()
    })
}
pub fn typed_handlers()->agenthooksprotocol::server::HandlerSet {
    let mut handlers = agenthooksprotocol::server::HandlerSet::default();
    handlers.intercept.tool_before = Some(std::sync::Arc::new(|ctx, _event| Box::pin(async move {Ok(ctx.reply())})));
    handlers.observe.tool_before = Some(std::sync::Arc::new(|_ctx, _event| Box::pin(async move {Ok(())})));
    handlers
}

pub fn contract()->Contract<JsonValue> {Contract::new()}
#[cfg(feature="typed-form")]
pub fn form() {
    #[derive(serde::Serialize,serde::Deserialize,schemars::JsonSchema)] struct Answer {count:u64}
    let form=agenthooksprotocol::form::Form::<Answer>::new().unwrap();
    let result:agenthooksprotocol::generated::ElicitResult<Answer>=form.accept(&Answer {count:1}).unwrap();
    let _=form.decode(&result).unwrap();
    let _=form.result_contract();
}
"#);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn assembly_and_provisional_helpers_are_not_public_consumer_apis() {
    let consumer = Consumer::new();
    for (name, source, diagnostic) in [
        (
            "stringly_subscription_interest",
            "fn interest(hooks: &agenthooksprotocol::Hooks, event: String) { let _ = hooks.subscribes(event); }",
            "EventType",
        ),
        (
            "borrowed_string_subscription_interest",
            "fn interest(hooks: &agenthooksprotocol::Hooks, event: &str) { let _ = hooks.subscribes(event); }",
            "EventType",
        ),
        (
            "metadata_has_no_events",
            "fn wrong() {let _ = agenthooksprotocol::hooks::ManifestMetadata {events: vec![], ..Default::default()};}",
            "events",
        ),
        (
            "observe_only_intercept_slot",
            "fn wrong(handlers: &mut agenthooksprotocol::server::HandlerSet) { handlers.intercept.file_changed = None; }",
            "file_changed",
        ),
        (
            "broad_server_handler",
            "use agenthooksprotocol::server::Handler;",
            "Handler",
        ),
        (
            "broad_server_incoming",
            "use agenthooksprotocol::server::Incoming;",
            "Incoming",
        ),
        (
            "broad_server_outgoing",
            "use agenthooksprotocol::server::Outgoing;",
            "Outgoing",
        ),
        (
            "broad_server_future",
            "use agenthooksprotocol::server::HandlerFuture;",
            "HandlerFuture",
        ),
        (
            "observe_control",
            "fn wrong(ctx: agenthooksprotocol::server::ToolBeforeObserveContext) {let _ = ctx.reply();}",
            "reply",
        ),
        (
            "wrong_reply_event",
            "fn wrong(ctx: agenthooksprotocol::server::ToolAfterContext)->agenthooksprotocol::server::ToolBeforeReply {ctx.reply()}",
            "ToolAfterEffect",
        ),
        (
            "wrong_effect_event",
            "fn wrong(ctx: agenthooksprotocol::server::ToolBeforeContext, effect: agenthooksprotocol::generated::ToolAfterEffect) {let _ = ctx.reply().effect(effect);}",
            "ToolAfterEffect",
        ),
        (
            "forge_reply",
            "fn wrong() {let _ = agenthooksprotocol::server::ToolBeforeReply {scope: std::sync::Arc::new(()), effects: vec![]};}",
            "private",
        ),
        (
            "generic_host_caps",
            "use agenthooksprotocol::hooks::Capabilities;",
            "Capabilities",
        ),
        (
            "generic_event_grant",
            "use agenthooksprotocol::hooks::EventGrant;",
            "EventGrant",
        ),
        (
            "generic_host_map",
            "use agenthooksprotocol::hooks::EventCapabilities;",
            "EventCapabilities",
        ),
        (
            "empty_declaration",
            "fn empty() { let _ = agenthooksprotocol::capability::HostCapabilities {tool_before: Some(agenthooksprotocol::capability::tool_before()), ..Default::default()}; }",
            "ToolBeforeInitial",
        ),
        (
            "wrong_event_declaration",
            "fn wrong() { let _ = agenthooksprotocol::capability::HostCapabilities {tool_before: Some(agenthooksprotocol::capability::tool_after().message()), ..Default::default()}; }",
            "ToolAfter",
        ),
        (
            "unsupported_target",
            "fn wrong() { let _ = agenthooksprotocol::capability::tool_before().modify_output(agenthooksprotocol::capability::Modify::Replace); }",
            "modify_output",
        ),
        (
            "unsupported_flow",
            "fn wrong() { let _ = agenthooksprotocol::capability::tool_before().flow(agenthooksprotocol::capability::Flow::Continue {remaining_continuations: 1, continuation_count: 0, max_continuations: None}); }",
            "ToolBeforeFlow",
        ),
        (
            "capability_build",
            "fn old() { let _ = agenthooksprotocol::capability::tool_before().allow().build(); }",
            "build",
        ),
        (
            "capability_intercept",
            "fn old() { let _ = agenthooksprotocol::capability::tool_before().intercept(); }",
            "intercept",
        ),
        (
            "raw_manifest_options",
            r#"fn old() { let _ = agenthooksprotocol::hooks::HooksOptions::from_manifest("urn:test", ()); }"#,
            "from_manifest",
        ),
        (
            "raw_declaration_options",
            r#"fn old() { let _ = agenthooksprotocol::hooks::HooksOptions::from_declarations("urn:test", ()); }"#,
            "from_declarations",
        ),
        (
            "decision_alias",
            "use agenthooksprotocol::client::Decision;",
            "Decision",
        ),
        (
            "consumer_wrapper",
            "use agenthooksprotocol::client::ConsumerProtocolOutcome;",
            "ConsumerProtocolOutcome",
        ),
        (
            "error_function",
            "fn old_error() { let _ = agenthooksprotocol::client::HookError(String::new()); }",
            "HookError",
        ),
        (
            "raw_outcome",
            "fn raw(o: agenthooksprotocol::client::ProtocolOutcome) { let _ = o.raw(); }",
            "raw",
        ),
        (
            "duplicate_event",
            "fn duplicate(o: agenthooksprotocol::hooks::EventOutcome) { let _ = o.effective_event; }",
            "effective_event",
        ),
        (
            "duplicate_settled_event",
            "fn duplicate(o: agenthooksprotocol::hooks::EventOutcome) { let _ = o.settled_event; }",
            "settled_event",
        ),
        (
            "runtime_raw_event",
            "fn duplicate(o: agenthooksprotocol::runtime::EventResult<'_, serde_json::Value>) { let _ = o.effective_event; }",
            "effective_event",
        ),
        (
            "client_raw_input",
            "fn duplicate(o: agenthooksprotocol::client::BoundaryResult<'_, serde_json::Value>) { let _ = o.effective_input; }",
            "effective_input",
        ),
        (
            "consumer_typed_wrapper",
            "fn wrapper(o: agenthooksprotocol::runtime::EventResult<'_, serde_json::Value>) { let _ = o.typed_outcome(); }",
            "typed_outcome",
        ),
        (
            "duplicate_candidate",
            "fn duplicate(o: agenthooksprotocol::hooks::ToolOutcome<serde_json::Value>) { let _ = o.candidate; }",
            "candidate",
        ),
        (
            "legacy_compaction",
            "use agenthooksprotocol::compaction::run_compaction;",
            "run_compaction",
        ),
        (
            "assembly_macro",
            "agenthooksprotocol::ahp_hooks_boundary_methods!(inventory);",
            "ahp_hooks_boundary_methods",
        ),
        (
            "projection_helper",
            "use agenthooksprotocol::inputs::ProjectHostInput;",
            "ProjectHostInput",
        ),
        (
            "source_binding",
            "use agenthooksprotocol::inputs::ContentSourceBinding;",
            "ContentSourceBinding",
        ),
        (
            "implementation_namespace",
            "use agenthooksprotocol::ergonomic_inputs;",
            "ergonomic_inputs",
        ),
        (
            "provisional_result",
            "use agenthooksprotocol::hooks::DeclaredToolOutcome;",
            "DeclaredToolOutcome",
        ),
        (
            "internal_dispatch",
            r#"fn dispatch(hooks:&agenthooksprotocol::Hooks,input:agenthooksprotocol::inputs::ToolBeforeInput<agenthooksprotocol::generated::JsonValue>) { let _=hooks.host_input_for("tool.before",input); }"#,
            "host_input_for",
        ),
    ] {
        let output = consumer.compile(name, source);
        let errors = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "unexpected public helper {name}");
        assert!(
            errors.contains(diagnostic),
            "unexpected failure for {name}: {errors}"
        );
    }
}
