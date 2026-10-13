use agenthooksprotocol::generated::EventType;
use agenthooksprotocol::{
    Hooks,
    adapters::registered::ManagedBackend,
    capability::{self, HostCapabilities},
    client::{HookError, LocalFuture},
    hooks::HooksOptions,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Default)]
struct Backend {
    calls: AtomicUsize,
    shutdowns: AtomicUsize,
}
impl ManagedBackend for Backend {
    fn call(&self, _: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("static interest contacted a backend")
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}
fn hooks(
    selector: &str,
    mode: &str,
    grants: HostCapabilities,
    filters: Value,
) -> (Hooks, Arc<Backend>) {
    let backend = Arc::new(Backend::default());
    let mut subscription =
        json!({"events":[selector],"mode":mode,"content":{"default":"metadata"}});
    if mode == "intercept" {
        subscription["failurePolicy"] = json!("fail-closed");
        subscription["timeoutMs"] = json!(1000);
    }
    if !filters.is_null() {
        subscription["filters"] = filters;
    }
    let hooks = Hooks::new(
        json!({"protocolVersion":"draft","hooks":[{"id":"org.example.interest","transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},"subscriptions":[subscription]}]}),
        HooksOptions::new("urn:test:interest", agenthooksprotocol::hooks::Harness::new("test", "1"), grants).with_backend("org.example.interest", backend.clone()),
    ).unwrap();
    (hooks, backend)
}
fn grants() -> HostCapabilities {
    HostCapabilities {
        tool_before: Some(capability::tool_before().allow().observe()),
        tool_after: Some(capability::tool_after().observe()),
        session_end: Some(capability::session_end().observe()),
        tool_permission_resolved: Some(capability::tool_permission_resolved().observe()),
        ..HostCapabilities::default()
    }
}
fn finish(hooks: Hooks, backend: &Backend) {
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.shutdowns.load(Ordering::SeqCst), 0);
    futures::executor::block_on(hooks.shutdown()).unwrap();
    assert_eq!(backend.shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn unrelated_and_unconfigured_events_skip_expensive_preparation() {
    let (hooks, backend) = hooks("session.end", "observe", grants(), Value::Null);
    let preparations = AtomicUsize::new(0);
    for _ in 0..3 {
        if hooks.subscribes(EventType::ToolBefore) {
            preparations.fetch_add(1, Ordering::SeqCst);
        }
        assert!(!hooks.subscribes(EventType::ToolAfter));
        assert!(!hooks.subscribes(EventType::SessionStart));
    }
    assert_eq!(preparations.load(Ordering::SeqCst), 0);
    assert!(hooks.subscribes(EventType::SessionEnd));
    finish(hooks, &backend);
}

#[test]
fn exact_interception_and_observe_only_interest_are_both_visible() {
    for (event, mode) in [
        (EventType::ToolBefore, "intercept"),
        (EventType::ToolAfter, "observe"),
    ] {
        let (hooks, backend) = hooks(event.as_str(), mode, grants(), Value::Null);
        assert!(hooks.subscribes(event));
        assert!(!hooks.subscribes(EventType::SessionEnd));
        finish(hooks, &backend);
    }
}

#[test]
fn wildcard_prefixes_follow_validated_selector_and_host_mode_eligibility() {
    for selector in ["tool.*", "*"] {
        let (hooks, backend) = hooks(selector, "observe", grants(), Value::Null);
        assert!(hooks.subscribes(EventType::ToolBefore));
        assert!(hooks.subscribes(EventType::ToolAfter));
        assert!(hooks.subscribes(EventType::ToolPermissionResolved));
        assert_eq!(hooks.subscribes(EventType::SessionEnd), selector == "*");

        finish(hooks, &backend);
    }
    // An intercept selector maps only to intercept-eligible host entries;
    // observation authority alone does not add a route for that event.
    let (hooks, backend) = hooks("*", "intercept", grants(), Value::Null);
    assert!(hooks.subscribes(EventType::ToolBefore));
    assert!(!hooks.subscribes(EventType::ToolAfter));
    assert!(!hooks.subscribes(EventType::SessionEnd));
    finish(hooks, &backend);
}

#[test]
fn payload_filters_do_not_turn_potential_interest_into_a_false_negative() {
    for mode in ["intercept", "observe"] {
        let (hooks, backend) = hooks(
            "tool.*",
            mode,
            grants(),
            json!({"paths":["restricted/**"],"toolKinds":["shell"]}),
        );
        assert!(hooks.subscribes(EventType::ToolBefore));
        finish(hooks, &backend);
    }
}

#[test]
fn observation_selector_does_not_claim_intercept_only_host_entries() {
    let grants = HostCapabilities {
        tool_before: Some(capability::tool_before().allow()),
        session_end: Some(capability::session_end().observe()),
        tool_permission_resolved: Some(capability::tool_permission_resolved().observe()),
        ..HostCapabilities::default()
    };
    let (hooks, backend) = hooks("*", "observe", grants, Value::Null);
    assert!(!hooks.subscribes(EventType::ToolBefore));
    assert!(hooks.subscribes(EventType::SessionEnd));
    finish(hooks, &backend);
}

#[test]
fn every_canonical_event_accepts_typed_interest_without_preparation() {
    let events = [
        EventType::ConfigChangeAfter,
        EventType::ConfigChangeBefore,
        EventType::ContextCompactAfter,
        EventType::ContextCompactBefore,
        EventType::FileChanged,
        EventType::HookFailure,
        EventType::ModelError,
        EventType::ModelRequestBefore,
        EventType::ModelResponseAfter,
        EventType::ModelSwitchAfter,
        EventType::ModelSwitchBefore,
        EventType::SessionEnd,
        EventType::SessionStart,
        EventType::TaskChangeAfter,
        EventType::TaskChangeBefore,
        EventType::ToolAfter,
        EventType::ToolBatchAfter,
        EventType::ToolBefore,
        EventType::ToolPermissionRequest,
        EventType::ToolPermissionResolved,
        EventType::ToolProgress,
        EventType::TurnEnd,
        EventType::TurnFinishBefore,
        EventType::TurnProgress,
        EventType::TurnStart,
        EventType::UserAttention,
        EventType::UserElicitationRequest,
        EventType::UserElicitationResult,
        EventType::UserMessageInbound,
        EventType::UserMessageOutbound,
        EventType::WorkspaceChangeAfter,
        EventType::WorkspaceChangeBefore,
    ];
    let capabilities = HostCapabilities {
        config_change_after: Some(capability::config_change_after().observe()),
        config_change_before: Some(capability::config_change_before().observe()),
        context_compact_after: Some(capability::context_compact_after().observe()),
        context_compact_before: Some(capability::context_compact_before().observe()),
        file_changed: Some(capability::file_changed().observe()),
        hook_failure: Some(capability::hook_failure().observe()),
        model_error: Some(capability::model_error().observe()),
        model_request_before: Some(capability::model_request_before().observe()),
        model_response_after: Some(capability::model_response_after().observe()),
        model_switch_after: Some(capability::model_switch_after().observe()),
        model_switch_before: Some(capability::model_switch_before().observe()),
        session_end: Some(capability::session_end().observe()),
        session_start: Some(capability::session_start().observe()),
        task_change_after: Some(capability::task_change_after().observe()),
        task_change_before: Some(capability::task_change_before().observe()),
        tool_after: Some(capability::tool_after().observe()),
        tool_batch_after: Some(capability::tool_batch_after().observe()),
        tool_before: Some(capability::tool_before().observe()),
        tool_permission_request: Some(capability::tool_permission_request().observe()),
        tool_permission_resolved: Some(capability::tool_permission_resolved().observe()),
        tool_progress: Some(capability::tool_progress().observe()),
        turn_end: Some(capability::turn_end().observe()),
        turn_finish_before: Some(capability::turn_finish_before().observe()),
        turn_progress: Some(capability::turn_progress().observe()),
        turn_start: Some(capability::turn_start().observe()),
        user_attention: Some(capability::user_attention().observe()),
        user_elicitation_request: Some(capability::user_elicitation_request().observe()),
        user_elicitation_result: Some(capability::user_elicitation_result().observe()),
        user_message_inbound: Some(capability::user_message_inbound().observe()),
        user_message_outbound: Some(capability::user_message_outbound().observe()),
        workspace_change_after: Some(capability::workspace_change_after().observe()),
        workspace_change_before: Some(capability::workspace_change_before().observe()),
    };
    assert_eq!(
        events.len(),
        agenthooksprotocol::generated::boundary::ALL_BOUNDARIES.len()
    );
    for boundary in agenthooksprotocol::generated::boundary::ALL_BOUNDARIES {
        assert!(events.iter().any(|event| event.as_str() == boundary.name));
    }
    let (hooks, backend) = hooks("*", "observe", capabilities, Value::Null);
    let client = agenthooksprotocol::client::Client::new(
        agenthooksprotocol::client::ToolContext::new(json!({})),
    );
    for event in events {
        let _ = hooks.event_for(event, json!({}));
        let _ = client.event_for(event, json!({}));
        assert!(hooks.subscribes(event), "{}", event.as_str());
    }
    finish(hooks, &backend);
}
