use agenthooksprotocol::{
    Hooks,
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
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
    grants: BTreeMap<String, EventGrant>,
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
        HooksOptions::new("urn:test:interest", grants).with_backend("org.example.interest", backend.clone()),
    ).unwrap();
    (hooks, backend)
}
fn grants() -> BTreeMap<String, EventGrant> {
    BTreeMap::from([
        (
            "tool.before".into(),
            EventGrant::intercept(Capabilities::none()),
        ),
        ("tool.after".into(), EventGrant::observe()),
        ("session.end".into(), EventGrant::observe()),
        ("tool.permission.resolved".into(), EventGrant::observe()),
    ])
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
        if hooks.subscribes("tool.before") {
            preparations.fetch_add(1, Ordering::SeqCst);
        }
        assert!(!hooks.subscribes("tool.after"));
        assert!(!hooks.subscribes("session.start"));
        assert!(!hooks.subscribes("tool.unknown"));
        assert!(!hooks.subscribes("unknown"));
        assert!(!hooks.subscribes(""));
    }
    assert_eq!(preparations.load(Ordering::SeqCst), 0);
    assert!(hooks.subscribes("session.end"));
    finish(hooks, &backend);
}

#[test]
fn exact_interception_and_observe_only_interest_are_both_visible() {
    for (event, mode) in [("tool.before", "intercept"), ("tool.after", "observe")] {
        let (hooks, backend) = hooks(event, mode, grants(), Value::Null);
        assert!(hooks.subscribes(event));
        assert!(!hooks.subscribes("session.end"));
        finish(hooks, &backend);
    }
}

#[test]
fn wildcard_prefixes_follow_validated_selector_and_host_mode_eligibility() {
    for selector in ["tool.*", "*"] {
        let (hooks, backend) = hooks(selector, "observe", grants(), Value::Null);
        assert!(hooks.subscribes("tool.before"));
        assert!(hooks.subscribes("tool.after"));
        assert!(hooks.subscribes("tool.permission.resolved"));
        assert_eq!(hooks.subscribes("session.end"), selector == "*");
        assert!(!hooks.subscribes("tool.unknown"));
        assert!(!hooks.subscribes("tools.before"));
        finish(hooks, &backend);
    }
    // An intercept selector maps only to intercept-eligible host entries;
    // observation authority alone does not add a route for that event.
    let (hooks, backend) = hooks("*", "intercept", grants(), Value::Null);
    assert!(hooks.subscribes("tool.before"));
    assert!(!hooks.subscribes("tool.after"));
    assert!(!hooks.subscribes("session.end"));
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
        assert!(hooks.subscribes("tool.before"));
        finish(hooks, &backend);
    }
}

#[test]
fn observation_selector_does_not_claim_intercept_only_host_entries() {
    let grants = BTreeMap::from([
        (
            "tool.before".into(),
            EventGrant::from_declaration(
                json!({"modes":["intercept"],"capabilities":{"effects":[]}}),
            )
            .unwrap(),
        ),
        ("session.end".into(), EventGrant::observe()),
        ("tool.permission.resolved".into(), EventGrant::observe()),
    ]);
    let (hooks, backend) = hooks("*", "observe", grants, Value::Null);
    assert!(!hooks.subscribes("tool.before"));
    assert!(hooks.subscribes("session.end"));
    finish(hooks, &backend);
}
