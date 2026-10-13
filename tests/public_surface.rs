use agenthooksprotocol::{hooks::HooksOptions, inputs::*};
use serde::Serialize;
use serde_json::json;

#[test]
fn handwritten_consumer_surface_has_no_compatibility_layers() {
    let client = include_str!("../src/client.rs");
    let hooks = include_str!("../src/hooks.rs");
    let runtime = include_str!("../src/runtime.rs");
    for source in [client, hooks, runtime] {
        for forbidden in [
            "pub effective_event:",
            "pub effective_input:",
            "pub settled_event:",
            "pub candidate_descriptor:",
            "ConsumerProtocolOutcome",
            "pub fn typed_outcome(",
            "pub fn settled_event(",
            "pub fn raw(",
            "pub use crate::generated::Permission as Decision",
        ] {
            assert!(
                !source.contains(forbidden),
                "compatibility surface: {forbidden}"
            );
        }
    }
    assert!(!include_str!("../src/adapters/registered.rs").contains("allow_anonymous_http"));
    for forbidden in [
        "pub fn run_compaction",
        "pub struct CompactionHook",
        "pub struct DeferredCompaction",
        "pub struct CompactionSnapshot",
    ] {
        assert!(!include_str!("../src/compaction.rs").contains(forbidden));
    }
}

#[test]
fn every_canonical_event_has_a_handwritten_typed_hooks_method() {
    // Verify the implementation, not just the generated inventory (which previously
    // claimed coverage even when Hooks had four missing tool methods).
    let schemas: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../src/schemas.json")).unwrap();
    let catalogue = schemas
        .iter()
        .find(|schema| {
            schema["$id"]
                .as_str()
                .unwrap()
                .ends_with("/catalogue-event.schema.json")
        })
        .unwrap();
    let canonical: std::collections::BTreeSet<&str> = catalogue["$defs"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .chain(["tool.before", "tool.after", "session.start", "session.end"])
        .collect();
    let actual: std::collections::BTreeSet<&str> = agenthooksprotocol::hooks::NAMED_BOUNDARIES
        .iter()
        .map(|event| event.as_str())
        .collect();
    assert_eq!(actual, canonical);
    let source = include_str!("../src/hooks.rs");
    for event in agenthooksprotocol::hooks::NAMED_BOUNDARIES {
        let name = event.as_str();
        if name == "tool.before" {
            assert!(source.contains("pub fn tool_before<T:"));
        } else {
            let method = name.replace('.', "_");
            assert!(
                source.contains(&format!("({method}, ")),
                "missing typed Hooks::{method}"
            );
            assert!(source.contains(&format!("generated::EventType::{event:?}")));
        }
    }
}

#[derive(Serialize)]
struct Arguments {
    count: u64,
}

#[test]
fn missing_tool_methods_settle_typed_generic_host_facts() {
    use agenthooksprotocol::*;
    futures::executor::block_on(async {
        let names = [
            "tool.after",
            "tool.permission.request",
            "tool.permission.resolved",
            "tool.progress",
        ];
        let hooks = Hooks::new(
            json!({"protocolVersion":"draft","hooks":[{"id":"org.example.coverage","transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},"subscriptions":[{"events":["tool.*"],"mode":"observe","filters":{"paths":["unmatched/**"]},"content":{"default":"metadata"}}]}]}),
            HooksOptions::new("urn:test:coverage", agenthooksprotocol::hooks::Harness::new("test", "1"), capability::HostCapabilities { tool_after: Some(capability::tool_after().observe()), tool_permission_request: Some(capability::tool_permission_request().observe()), tool_permission_resolved: Some(capability::tool_permission_resolved().observe()), tool_progress: Some(capability::tool_progress().observe()), ..Default::default() }).with_backend("org.example.coverage", std::sync::Arc::new(Noop)),
        ).unwrap();
        let after = ToolAfterInput::new(
            "call".into(),
            serde_json::from_value(json!({"status":"executed"})).unwrap(),
            vec![],
            ToolAfterInputOutcome::Ok,
            "native".into(),
            Arguments { count: 1 },
            "read".into(),
            ToolAfterInputOrigin::Native,
        );
        let request = ToolPermissionRequestInput::new(
            "call".into(),
            "native".into(),
            false,
            vec![],
            Arguments { count: 2 },
            "read".into(),
            ToolPermissionRequestInputOrigin::Native,
        );
        let resolved = ToolPermissionResolvedInput::new(
            "call".into(),
            ToolPermissionResolvedInputDecidedBy::Policy,
            ToolPermissionResolvedInputDecision::Allow,
            "native".into(),
            Arguments { count: 3 },
            "read".into(),
            ToolPermissionResolvedInputOrigin::Native,
        );
        let progress = ToolProgressInput::new(false, "call".into(), serde_json::from_value(json!({"id":"partial","role":"tool","parts":[{"id":"text","kind":"text","mediaType":"text/plain","selection":"body","text":"progress"}]})).unwrap(), "native".into(), Arguments { count: 4 }, "read".into(), ToolProgressInputOrigin::Native);
        let results = [
            hooks.tool_after(after).await.unwrap(),
            hooks.tool_permission_request(request).await.unwrap(),
            hooks.tool_permission_resolved(resolved).await.unwrap(),
            hooks.tool_progress(progress).await.unwrap(),
        ];
        for (index, result) in results.into_iter().enumerate() {
            let event: Event = result.event;
            let wire = serde_json::to_value(event).unwrap();
            assert_eq!(wire["type"], names[index]);
            assert_eq!(wire["tool"]["input"]["count"], index + 1);
            assert!(result.outcome.failures.is_empty());
        }
        hooks.shutdown().await.unwrap();
    });
}

struct Noop;
impl agenthooksprotocol::adapters::registered::ManagedBackend for Noop {
    fn call(
        &self,
        _: serde_json::Value,
        _: std::time::Duration,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        Result<serde_json::Value, agenthooksprotocol::client::HookError>,
    > {
        panic!("unmatched backend was called")
    }
    fn shutdown(
        &self,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        Result<(), agenthooksprotocol::client::HookError>,
    > {
        Box::pin(async { Ok(()) })
    }
}
