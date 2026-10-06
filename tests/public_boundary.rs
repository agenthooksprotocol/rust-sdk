use agenthooksprotocol::client::*;
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Input {
    count: u64,
}
struct Fake {
    effects: Value,
    calls: Arc<Mutex<Vec<Value>>>,
}
impl Hook for Fake {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(request.clone());
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":self.effects}}),
            )
        })
    }
}
fn context() -> ToolContext {
    ToolContext::new(
        json!({"id":"evt_public_1","source":"https://example.test/runtime","type":"tool.before","time":"2026-08-24T08:51:14Z","path":"native","session":{"id":"session_1"},"call":{"id":"call_1"},"tool":{"name":"counter","kind":"file_read","origin":"native","input":{}}}),
    )
}
fn hook(
    id: &str,
    effects: Value,
    policy: FailurePolicy,
    calls: &Arc<Mutex<Vec<Value>>>,
) -> Subscription {
    Subscription::intercept(
        id,
        policy,
        Fake {
            effects,
            calls: calls.clone(),
        },
    )
}
fn replace(value: Value) -> Value {
    json!({"type":"modify","target":"input","operation":"replace","value":value})
}

#[test]
fn protocol_commit_precedes_fresh_typed_decode_and_observation() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context())
        .with_subscription(hook("mutator", json!([replace(json!({"count":"not a u64"})),{"type":"message","text":"accepted"},{"type":"allow"}]), FailurePolicy::Closed, &calls))
        .with_subscription(Subscription::observe("audit", Fake { effects: json!([]), calls: calls.clone() }));
    let result = block_on(async { client.tool_before(Input { count: 1 }).await.unwrap() });
    assert!(result.input.is_err());
    assert_eq!(result.effective_input, json!({"count":"not a u64"}));
    assert_eq!(result.outcome.decision, Decision::Allow);
    assert_eq!(result.outcome.messages.len(), 1);
    assert!(result.outcome.failures.is_empty());
    assert_eq!(calls.lock().unwrap().len(), 1); // observers never delay settlement
    block_on(result.observations.into_iter().next().unwrap().deliver()).unwrap();
    assert_eq!(
        calls.lock().unwrap()[1]["params"]["event"]["tool"]["input"]["count"],
        "not a u64"
    );
    assert!(calls.lock().unwrap()[1].get("id").is_none());
    assert_eq!(
        calls.lock().unwrap()[1]["params"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
}
#[test]
fn serial_candidates_and_approval_are_invalidated_only_on_change() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context())
        .with_subscription(hook(
            "first",
            json!([{"type":"return","value":7}]),
            FailurePolicy::Closed,
            &calls,
        ))
        .with_subscription(hook(
            "same",
            json!([replace(json!({"count":1}))]),
            FailurePolicy::Closed,
            &calls,
        ))
        .with_subscription(hook(
            "changed",
            json!([replace(json!({"count":2}))]),
            FailurePolicy::Closed,
            &calls,
        ))
        .with_subscription(hook("last", json!([]), FailurePolicy::Closed, &calls));
    let result = block_on(async {
        client
            .tool_before(Input { count: 1 })
            .initial_state(Decision::Allow)
            .await
            .unwrap()
    });
    assert_eq!(result.input.unwrap().count, 2);
    assert_eq!(
        calls.lock().unwrap()[2]["params"]["state"]["candidate"]["value"],
        7
    );
    assert_eq!(
        calls.lock().unwrap()[3]["params"]["state"]["candidate"],
        Value::Null
    );
    assert_eq!(result.outcome.decision, Decision::None);
    assert!(result.outcome.approval_invalidated);
    assert!(!result.outcome.can_execute());
}
#[test]
fn atomic_invalid_compound_does_not_salvage_deny_or_mutation() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context())
        .with_subscription(hook("accepted", json!([replace(json!({"count":2}))]), FailurePolicy::Closed, &calls))
        .with_subscription(hook("bad", json!([replace(json!({"count":3})),{"type":"deny","reason":"no"},{"type":"flow","operation":"continue"}]), FailurePolicy::Open, &calls))
        .with_subscription(hook("allow", json!([{"type":"allow"}]), FailurePolicy::Closed, &calls));
    let result = block_on(async { client.tool_before(json!({"count":1})).await.unwrap() });
    assert_eq!(result.input.unwrap(), json!({"count":2}));
    assert_eq!(result.outcome.failures.len(), 1);
    assert_eq!(result.outcome.decision, Decision::Allow);
    assert_eq!(calls.lock().unwrap().len(), 3);
}
#[test]
fn deny_wins_and_only_uncalled_or_explicit_observers_get_notifications() {
    let calls = Arc::new(Mutex::new(vec![]));
    let mut unmatched = hook("other", json!([]), FailurePolicy::Open, &calls);
    unmatched.events = vec!["tool.after".into()];
    let client = Client::new(context())
        .with_subscription(hook(
            "called",
            json!([{"type":"allow"},{"type":"ask"},{"type":"deny","reason":"policy"}]),
            FailurePolicy::Closed,
            &calls,
        ))
        .with_subscription(hook("uncalled", json!([]), FailurePolicy::Closed, &calls))
        .with_subscription(Subscription::observe(
            "explicit",
            Fake {
                effects: json!([]),
                calls: calls.clone(),
            },
        ))
        .with_subscription(unmatched);
    let result = block_on(async { client.tool_before(Input { count: 1 }).await.unwrap() });
    assert_eq!(result.outcome.decision, Decision::Deny);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(
        result
            .observations
            .iter()
            .map(|o| o.subscription_id)
            .collect::<Vec<_>>(),
        ["uncalled", "explicit"]
    );
}
#[test]
fn ask_persists_and_mandatory_gates_block_supplied_results() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context()).with_subscription(hook(
        "policy",
        json!([{"type":"allow"},{"type":"return","value":42}]),
        FailurePolicy::Closed,
        &calls,
    ));
    let result = block_on(async {
        client
            .tool_before(Input { count: 1 })
            .initial_state(Decision::Ask)
            .await
            .unwrap()
    });
    assert_eq!(result.outcome.decision, Decision::Ask);
    assert!(result.outcome.supplied_result().is_none());
    let result = block_on(async {
        client
            .tool_before(Input { count: 1 })
            .mandatory_gates_passed(false)
            .await
            .unwrap()
    });
    assert_eq!(result.outcome.decision, Decision::Deny);
    assert!(result.outcome.supplied_result().is_none());
}
#[test]
fn fail_closed_is_distinct_and_capability_narrowing_is_enforced() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context())
        .with_subscription(hook(
            "bad",
            json!([{"type":"allow"}]),
            FailurePolicy::Closed,
            &calls,
        ))
        .with_subscription(hook("remaining", json!([]), FailurePolicy::Open, &calls));
    let result = block_on(async {
        client
            .tool_before(Input { count: 1 })
            .capabilities(json!({"effects":["deny"]}))
            .await
            .unwrap()
    });
    assert_eq!(result.outcome.decision, Decision::Deny);
    assert_eq!(result.outcome.failures.len(), 1);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(result.observations.len(), 1);
}
#[test]
fn strict_invalid_effects_are_atomic_and_fail_open() {
    for invalid in [
        json!({"type":"flow","operation":"stop","reason":""}),
        json!({"type":"allow","unexpected":true}),
        json!({"type":"mystery"}),
        json!({"type":"modify","target":"input","operation":"replace","value":null}),
    ] {
        let calls = Arc::new(Mutex::new(vec![]));
        let client = Client::new(context()).with_subscription(hook("invalid", json!([replace(json!({"count":99})), {"type":"message","text":"must not leak"}, invalid]), FailurePolicy::Open, &calls));
        let result = block_on(async {
            client
                .tool_before(Input { count: 1 })
                .initial_state(Decision::Allow)
                .await
                .unwrap()
        });
        assert_eq!(result.input.unwrap().count, 1);
        assert_eq!(result.outcome.decision, Decision::Allow);
        assert!(result.outcome.messages.is_empty());
        assert_eq!(result.outcome.failures.len(), 1);
    }
}
#[test]
fn return_binds_after_modifications_and_stop_discards_candidate() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context()).with_subscription(hook(
        "compound",
        json!([
            {"type":"return","value":42}, replace(json!({"count":2})), {"type":"allow"}
        ]),
        FailurePolicy::Closed,
        &calls,
    ));
    let result = block_on(async {
        client
            .tool_before(Input { count: 1 })
            .initial_state(Decision::Allow)
            .await
            .unwrap()
    });
    assert_eq!(result.outcome.supplied_result(), Some(&json!(42)));
    assert_eq!(result.input.unwrap().count, 2);
    assert!(!result.outcome.can_execute());
    let stopped = Client::new(context()).with_subscription(hook("stop", json!([
        {"type":"return","value":42}, {"type":"flow","operation":"stop","reason":"settled"}, {"type":"allow"}
    ]), FailurePolicy::Closed, &calls));
    let result = block_on(async { stopped.tool_before(Input { count: 1 }).await.unwrap() });
    assert!(result.outcome.stopped);
    assert!(result.outcome.candidate.is_none());
    assert!(!result.outcome.can_execute());
}
#[test]
fn changed_approval_without_reauthorization_refuses_path() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context())
        .with_subscription(hook(
            "modify",
            json!([replace(json!({"count":2}))]),
            FailurePolicy::Closed,
            &calls,
        ))
        .with_subscription(hook(
            "must_not_run",
            json!([{"type":"allow"}]),
            FailurePolicy::Closed,
            &calls,
        ));
    let result = block_on(async {
        client
            .tool_before(Input { count: 1 })
            .initial_state(Decision::Allow)
            .reauthorization_available(false)
            .await
            .unwrap()
    });
    assert_eq!(result.input.unwrap().count, 2);
    assert!(result.outcome.is_denied());
    assert_eq!(calls.lock().unwrap().len(), 1);
}
#[test]
fn builder_is_lazy_and_initial_permission_is_per_occurrence() {
    #[derive(Deserialize)]
    struct Lazy {
        #[serde(skip)]
        count: Arc<AtomicUsize>,
    }
    impl Serialize for Lazy {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            self.count.fetch_add(1, Ordering::Relaxed);
            json!({}).serialize(s)
        }
    }
    let count = Arc::new(AtomicUsize::new(0));
    let client = Client::new(context());
    drop(client.tool_before(Lazy {
        count: count.clone(),
    }));
    assert_eq!(count.load(Ordering::Relaxed), 0);
    let first = block_on(async {
        client
            .tool_before(Input { count: 1 })
            .initial_state(Decision::Allow)
            .await
            .unwrap()
    });
    assert!(first.outcome.can_execute());
    let second = block_on(async { client.tool_before(Input { count: 1 }).await.unwrap() });
    assert_eq!(second.outcome.decision, Decision::None);
    assert!(!second.outcome.can_execute());
}

struct PendingHook {
    calls: Arc<AtomicUsize>,
}
impl Hook for PendingHook {
    fn call(&self, _: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(std::future::pending())
    }
}

#[test]
fn dropping_pending_boundary_retains_nonexecutable_accepted_evidence() {
    use std::{
        future::IntoFuture,
        task::{Context, Poll},
    };
    let calls = Arc::new(Mutex::new(vec![]));
    let pending_calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(context())
        .with_subscription(hook("accepted", json!([replace(json!({"count":2})), {"type":"message","text":"accepted"}, {"type":"allow"}]), FailurePolicy::Closed, &calls))
        .with_subscription(Subscription::intercept("pending", FailurePolicy::Open, PendingHook { calls: pending_calls.clone() }))
        .with_subscription(hook("never", json!([{"type":"allow"}]), FailurePolicy::Open, &calls));
    let builder = client
        .tool_before(Input { count: 1 })
        .initial_state(Decision::Allow);
    let progress = builder.progress();
    assert_eq!(progress.snapshot().status, BoundaryStatus::NotStarted);
    assert!(progress.snapshot().partial.is_none());
    let mut future = builder.into_future();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    assert_eq!(progress.snapshot().status, BoundaryStatus::Running);
    drop(future);
    let snapshot = progress.snapshot();
    assert_eq!(snapshot.status, BoundaryStatus::Interrupted);
    let partial = snapshot.partial.unwrap();
    assert_eq!(partial.effective_input, json!({"count":2}));
    assert_eq!(partial.outcome.decision, Decision::Allow);
    assert_eq!(partial.outcome.messages.len(), 1);
    assert!(!partial.outcome.authorized);
    assert!(!partial.outcome.can_execute());
    assert!(partial.outcome.supplied_result().is_none());
    assert_eq!(pending_calls.load(Ordering::Relaxed), 1);
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn explicit_interruption_overrides_fail_open_and_preserves_prior_commit() {
    use std::{
        future::IntoFuture,
        task::{Context, Poll},
    };
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context())
        .with_subscription(hook(
            "accepted",
            json!([replace(json!({"count":2})), {"type":"allow"}]),
            FailurePolicy::Closed,
            &calls,
        ))
        .with_subscription(Subscription::intercept(
            "pending",
            FailurePolicy::Open,
            PendingHook {
                calls: Arc::new(AtomicUsize::new(0)),
            },
        ))
        .with_subscription(hook("never", json!([]), FailurePolicy::Open, &calls));
    let builder = client.tool_before(Input { count: 1 });
    let progress = builder.progress();
    let mut future = builder.into_future();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    assert!(progress.interrupt());
    let error = match future.as_mut().poll(&mut cx) {
        Poll::Ready(Err(error)) => error,
        _ => panic!("interruption must finish with a typed outer error"),
    };
    assert_eq!(error.kind, BoundaryErrorKind::Interrupted);
    let partial = error.partial.unwrap();
    assert_eq!(partial.effective_input, json!({"count":2}));
    assert!(!partial.outcome.authorized);
    assert!(partial.outcome.failures.is_empty()); // not a fail-open operational failure
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(progress.snapshot().status, BoundaryStatus::Interrupted);
}

#[test]
fn preflight_error_is_classified_without_fabricated_partial_acceptance() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(ToolContext::new(json!({}))).with_subscription(hook(
        "never",
        json!([]),
        FailurePolicy::Closed,
        &calls,
    ));
    let builder = client.tool_before(Input { count: 1 });
    let progress = builder.progress();
    let error = match block_on(async { builder.await }) {
        Err(error) => error,
        Ok(_) => panic!("invalid context must fail preflight"),
    };
    assert_eq!(error.kind, BoundaryErrorKind::Preflight);
    assert!(error.partial.is_none());
    assert_eq!(progress.snapshot().status, BoundaryStatus::Failed);
    assert!(progress.snapshot().partial.is_none());
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn original_deadline_rejects_whole_late_response_once() {
    use std::time::Duration;
    struct Late;
    impl Hook for Late {
        fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                std::thread::sleep(Duration::from_millis(15));
                Ok(
                    json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":[replace(json!({"count":99})),{"type":"deny","reason":"late"},{"type":"message","text":"discard"}]}}),
                )
            })
        }
    }
    for policy in [FailurePolicy::Open, FailurePolicy::Closed] {
        let calls = Arc::new(Mutex::new(vec![]));
        let client = Client::new(context())
            .with_subscription(hook(
                "accepted",
                json!([replace(json!({"count":2})),{"type":"allow"}]),
                FailurePolicy::Closed,
                &calls,
            ))
            .with_subscription(
                Subscription::intercept("late", policy, Late).timeout(Duration::from_millis(1)),
            )
            .with_subscription(hook("tail", json!([]), FailurePolicy::Open, &calls));
        let result = block_on(async { client.tool_before(Input { count: 1 }).await.unwrap() });
        assert_eq!(result.input.unwrap().count, 2);
        assert!(result.outcome.messages.is_empty());
        assert_eq!(result.outcome.failures.len(), 1);
        assert_eq!(result.outcome.failures[0].policy, policy);
        assert_eq!(
            result.outcome.decision,
            if policy == FailurePolicy::Open {
                Decision::Allow
            } else {
                Decision::Deny
            }
        );
        assert_eq!(
            calls.lock().unwrap().len(),
            if policy == FailurePolicy::Open { 2 } else { 1 }
        );
    }
}

#[test]
fn native_candidate_preserves_provenance_without_advertising_return() {
    let calls = Arc::new(Mutex::new(vec![]));
    let descriptor =
        json!({"value":null,"provenance":{"native":"cache","trace":{"id":"original"}}});
    let client = Client::new(context())
        .with_subscription(hook("first", json!([]), FailurePolicy::Closed, &calls))
        .with_subscription(hook("second", json!([]), FailurePolicy::Closed, &calls));
    let result = block_on(async {
        client
            .tool_before(Input { count: 1 })
            .initial_state(Decision::Allow)
            .initial_candidate(descriptor.clone())
            .capabilities(json!({"effects":["message"]}))
            .await
            .unwrap()
    });
    assert!(result.outcome.failures.is_empty());
    assert_eq!(result.outcome.supplied_result(), Some(&Value::Null));
    assert_eq!(calls.lock().unwrap().len(), 2);
    for request in calls.lock().unwrap().iter() {
        assert_eq!(request["params"]["state"]["candidate"], descriptor);
        assert_eq!(request["params"]["state"].as_object().unwrap().len(), 2);
        assert!(request["params"]["state"].get("flow").is_none());
        assert!(request["params"]["state"].get("injections").is_none());
    }
}

#[test]
fn native_candidate_is_invalidated_by_changed_effective_input() {
    let calls = Arc::new(Mutex::new(vec![]));
    let descriptor = json!({"value":7,"provenance":{"source":"native"}});
    let client = Client::new(context())
        .with_subscription(hook(
            "change",
            json!([replace(json!({"count":2}))]),
            FailurePolicy::Closed,
            &calls,
        ))
        .with_subscription(hook("next", json!([]), FailurePolicy::Closed, &calls));
    let result = block_on(async {
        client
            .tool_before(Input { count: 1 })
            .initial_state(Decision::Allow)
            .initial_candidate(descriptor.clone())
            .await
            .unwrap()
    });
    assert_eq!(
        calls.lock().unwrap()[0]["params"]["state"]["candidate"],
        descriptor
    );
    assert_eq!(
        calls.lock().unwrap()[1]["params"]["state"]["candidate"],
        Value::Null
    );
    assert!(result.outcome.candidate.is_none());
    assert_eq!(result.input.unwrap().count, 2);
}

#[test]
fn accepted_equal_return_replaces_native_provenance() {
    let calls = Arc::new(Mutex::new(vec![]));
    let descriptor = json!({"value":7,"provenance":{"source":"native"}});
    let client = Client::new(context())
        .with_subscription(hook(
            "same_input",
            json!([replace(json!({"count":1}))]),
            FailurePolicy::Closed,
            &calls,
        ))
        .with_subscription(hook(
            "same_return",
            json!([{"type":"return","value":7}]),
            FailurePolicy::Closed,
            &calls,
        ))
        .with_subscription(hook("next", json!([]), FailurePolicy::Closed, &calls));
    let result = block_on(async {
        client
            .tool_before(Input { count: 1 })
            .initial_state(Decision::Allow)
            .initial_candidate(descriptor.clone())
            .await
            .unwrap()
    });
    assert_eq!(
        calls.lock().unwrap()[1]["params"]["state"]["candidate"],
        descriptor
    );
    assert_eq!(
        calls.lock().unwrap()[2]["params"]["state"]["candidate"],
        json!({"value":7})
    );
    assert_eq!(result.outcome.supplied_result(), Some(&json!(7)));
}

#[test]
fn malformed_native_candidate_fails_preflight_even_on_initial_denial() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context()).with_subscription(hook(
        "never",
        json!([]),
        FailurePolicy::Closed,
        &calls,
    ));
    for descriptor in [
        json!({"provenance":{}}),
        json!({"value":7,"provenance":null}),
    ] {
        let error = match block_on(async {
            client
                .tool_before(Input { count: 1 })
                .initial_state(Decision::Deny)
                .initial_candidate(descriptor)
                .await
        }) {
            Err(error) => error,
            Ok(_) => panic!("malformed descriptor must fail before settlement"),
        };
        assert_eq!(error.kind, BoundaryErrorKind::Preflight);
        assert!(error.partial.is_none());
    }
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn omitted_native_state_differs_from_explicit_none_until_first_acceptance() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context())
        .with_subscription(hook("first", json!([]), FailurePolicy::Closed, &calls))
        .with_subscription(hook("second", json!([]), FailurePolicy::Closed, &calls));
    block_on(async { client.tool_before(Input { count: 1 }).await.unwrap() });
    assert!(calls.lock().unwrap()[0]["params"].get("state").is_none());
    assert_eq!(
        calls.lock().unwrap()[1]["params"]["state"],
        json!({"permission":"none","candidate":null})
    );
    calls.lock().unwrap().clear();
    block_on(async {
        client
            .tool_before(Input { count: 1 })
            .initial_state(Decision::None)
            .await
            .unwrap()
    });
    for request in calls.lock().unwrap().iter() {
        assert_eq!(
            request["params"]["state"],
            json!({"permission":"none","candidate":null})
        );
    }
}
