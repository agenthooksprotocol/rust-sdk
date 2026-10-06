use agenthooksprotocol::{
    Hooks,
    adapters::registered::ManagedBackend,
    client::{Decision, HookError, LocalFuture, ToolContext},
    hooks::{Capabilities, EventGrant, HooksOptions, NAMED_BOUNDARIES},
};
use std::future::IntoFuture;
fn block_on<F: IntoFuture>(future: F) -> F::Output {
    futures::executor::block_on(future.into_future())
}
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Default)]
struct Backend {
    messages: Mutex<Vec<Value>>,
    effects: Mutex<Value>,
    closed: Cell<usize>,
}
impl ManagedBackend for Backend {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            self.messages.lock().unwrap().push(request.clone());
            if request["method"] == "hooks/observe" {
                return Ok(Value::Null);
            }
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":self.effects.lock().unwrap().clone()}}),
            )
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async move {
            self.closed.set(self.closed.get() + 1);
            Ok(())
        })
    }
}
fn registration(observe: bool) -> Value {
    let mut subscriptions = vec![
        json!({"events":["tool.before"],"mode":"intercept","timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":"metadata"}}),
    ];
    if observe {
        subscriptions.push(
            json!({"events":["tool.before"],"mode":"observe","content":{"default":"metadata"}}),
        );
    }
    json!({"protocolVersion":"draft","hooks":[{"id":"org.example.hook","transport":{"type":"stdio","command":"never-started","lifecycle":"persistent"},"subscriptions":subscriptions}]})
}
fn context() -> ToolContext {
    ToolContext::new(
        json!({"tool":{"name":"shell","kind":"shell","origin":"native"},"call":{"id":"call-1"},"path":"native","native":{"secret":"private"}}),
    )
}

#[test]
fn generated_tool_input_preserves_application_type_and_host_facts() {
    use agenthooksprotocol::{
        ergonomic_inputs::ToolBeforeInput, generated::ToolBeforeInputOrigin, state,
    };
    let backend = Arc::new(Backend::default());
    *backend.effects.lock().unwrap() = json!([]);
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    let proposal = ToolBeforeInput::new(
        "typed-call".into(),
        "adapter".into(),
        input(),
        "shell".into(),
        ToolBeforeInputOrigin::Native,
    )
    .with_tool_kind("shell".into());
    let result = block_on(
        hooks
            .tool_before(proposal)
            .initial_snapshot(state::initial(Decision::Allow))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result.permission(), Decision::Allow);
    assert_eq!(result.input.unwrap(), input());
    let messages = backend.messages.lock().unwrap();
    let event = &messages[0]["params"]["event"];
    assert_eq!(event["path"], "adapter");
    assert_eq!(event["tool"]["origin"], "native");
    assert_eq!(event["call"]["id"], "typed-call");
    assert_eq!(event["source"], "urn:example:host");
    assert!(event["id"].is_string());
}

struct UnusedSource {
    reads: Arc<std::sync::atomic::AtomicUsize>,
    drops: Arc<std::sync::atomic::AtomicUsize>,
}
impl agenthooksprotocol::body::BodyStream for UnusedSource {
    fn next_chunk(&mut self) -> agenthooksprotocol::body::BodyChunkFuture<'_> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Ok(None) })
    }
}
impl Drop for UnusedSource {
    fn drop(&mut self) {
        self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
#[test]
fn generated_named_source_is_closed_unused_without_reads_and_capacity_is_reusable() {
    use agenthooksprotocol::{
        body::Body,
        ergonomic_inputs::{ToolBeforeInput, tool_before_sources},
        generated::ToolBeforeInputOrigin,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    let backend = Arc::new(Backend::default());
    let mut options = options(backend.clone(), false);
    options.max_stored_entries = 1;
    let hooks = Hooks::new(registration(false), options).unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    for _ in 0..2 {
        let item = serde_json::from_value(json!({"id":"owned-text","kind":"text","mediaType":"text/plain","selection":"metadata"})).unwrap();
        let proposal = ToolBeforeInput::new(
            "typed-call".into(),
            "native".into(),
            input(),
            "shell".into(),
            ToolBeforeInputOrigin::Native,
        )
        .with_items(vec![Box::new(item)]);
        let pending = hooks
            .tool_before(proposal)
            .body_source(tool_before_sources::items(
                0,
                Body::stream(UnusedSource {
                    reads: reads.clone(),
                    drops: drops.clone(),
                }),
            ));
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        block_on(pending).unwrap();
    }
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert!(!format!("{:?}", backend.messages.lock().unwrap()).contains("ahp-deferred:"));
}

fn options(backend: Arc<dyn ManagedBackend>, observe: bool) -> HooksOptions {
    let grant = EventGrant::intercept(
        Capabilities::none()
            .allow()
            .deny()
            .return_value()
            .modify_input(),
    );
    HooksOptions::new(
        "urn:example:host",
        BTreeMap::from([(
            "tool.before".into(),
            if observe { grant.with_observe() } else { grant },
        )]),
    )
    .with_backend("org.example.hook", backend)
}
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Args {
    command: String,
    timeout_ms: u64,
}
fn input() -> Args {
    Args {
        command: "old".into(),
        timeout_ms: 10,
    }
}
#[test]
fn ordinary_json_registration_typed_modification_return_deny_and_shutdown() {
    let backend = Arc::new(Backend::default());
    *backend.effects.lock().unwrap() = json!([{"type":"modify","target":"input","operation":"merge","value":{"command":"new"}},{"type":"return","value":{"cached":true}}]);
    let config: agenthooksprotocol::generated::Registration =
        serde_json::from_str(&registration(true).to_string()).unwrap();
    let hooks = Hooks::new(config, options(backend.clone(), true)).unwrap();
    let lazy = hooks
        .tool_input(input())
        .context(context())
        .initial_state(Decision::Allow);
    assert!(backend.messages.lock().unwrap().is_empty());
    let result = block_on(lazy).unwrap();
    assert_eq!(result.input.unwrap().command, "new");
    assert_eq!(result.outcome.candidate(), Some(&json!({"cached":true})));
    assert_eq!(backend.messages.lock().unwrap().len(), 2);
    let first = backend.messages.lock().unwrap()[0].clone();
    assert_eq!(first["params"]["event"]["source"], "urn:example:host");
    assert!(first["params"]["event"].get("native").is_none());
    assert!(first["params"]["capabilities"].get("elicitation").is_none());
    assert_eq!(block_on(hooks.wait_until_idle()).delivered, 1);
    let notification = backend.messages.lock().unwrap()[1].clone();
    assert_eq!(notification["method"], "hooks/observe");
    assert!(notification.get("id").is_none());
    assert!(notification["params"].get("capabilities").is_none());
    assert_eq!(
        notification["params"]["event"]["tool"]["input"]["command"],
        "new"
    );
    *backend.effects.lock().unwrap() = json!([{"type":"deny","reason":"host policy"}]);
    let denied = block_on(
        hooks
            .tool_input(input())
            .context(context())
            .initial_state(Decision::Allow),
    )
    .unwrap();
    assert!(denied.outcome.is_denied());
    assert!(!denied.outcome.can_execute());
    assert_eq!(block_on(hooks.wait_until_idle()).delivered, 2);
    assert_eq!(block_on(hooks.shutdown()).unwrap().delivered, 2);
    block_on(hooks.shutdown()).unwrap();
    assert_eq!(backend.closed.get(), 1);
    assert!(block_on(hooks.tool_input(input()).context(context())).is_err());
}
#[test]
fn no_implicit_observation_routes_or_capability_expansion() {
    let backend = Arc::new(Backend::default());
    *backend.effects.lock().unwrap() = json!([]);
    assert!(Hooks::new(registration(true), options(backend.clone(), false)).is_ok());
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    assert!(
        block_on(
            hooks
                .tool_input(input())
                .context(context())
                .capabilities(Capabilities::none().flow_stop())
        )
        .is_err()
    );
    assert!(backend.messages.lock().unwrap().is_empty());
    block_on(hooks.tool_input(input()).context(context())).unwrap();
    assert_eq!(block_on(hooks.wait_until_idle()).delivered, 0);
    assert_eq!(backend.messages.lock().unwrap().len(), 1);
}
#[test]
fn unknown_events_duplicate_ids_and_mode_grants_fail_closed() {
    let backend = Arc::new(Backend::default());
    let mut opts = options(backend.clone(), false);
    opts.capabilities
        .insert("not.a.boundary".into(), EventGrant::observe());
    assert!(Hooks::new(registration(false), opts).is_err());
    let mut config = registration(false);
    let duplicate = config["hooks"][0].clone();
    config["hooks"].as_array_mut().unwrap().push(duplicate);
    assert!(Hooks::new(config, options(backend.clone(), false)).is_err());
    let mut opts = options(backend, false);
    opts.capabilities.insert(
        "file.changed".into(),
        EventGrant::intercept(Capabilities::none().deny()),
    );
    assert!(Hooks::new(registration(false), opts).is_err());
    let caps = Capabilities::none().return_value();
    assert!(caps.as_value().get("elicitation").is_none());
    assert_eq!(
        caps.elicitation_form().as_value()["elicitation"],
        json!({"form":{}})
    );
}
#[test]
fn named_facade_inventory_matches_the_generated_canonical_inventory() {
    let mut actual = NAMED_BOUNDARIES.to_vec();
    actual.sort();
    let mut expected = agenthooksprotocol::generated::boundary::ALL_BOUNDARIES
        .iter()
        .map(|b| b.name)
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected);
}
#[test]
fn decoding_failure_does_not_undo_settled_effects() {
    let backend = Arc::new(Backend::default());
    *backend.effects.lock().unwrap() = json!([{"type":"modify","target":"input","operation":"merge","value":{"timeout_ms":"not an integer"}}]);
    let hooks = Hooks::new(registration(false), options(backend, false)).unwrap();
    let result = block_on(
        hooks
            .tool_input(input())
            .context(context())
            .initial_state(Decision::Allow),
    )
    .unwrap();
    assert!(result.input.is_err());
    assert_eq!(result.effective_input["timeout_ms"], "not an integer");
    assert!(!result.outcome.is_denied());
}
#[test]
fn registration_filters_and_configured_source_are_enforced() {
    let backend = Arc::new(Backend::default());
    *backend.effects.lock().unwrap() = json!([]);
    let mut config = registration(false);
    config["hooks"][0]["subscriptions"][0]["filters"] = json!({"toolKinds":["different"]});
    let hooks = Hooks::new(config, options(backend.clone(), false)).unwrap();
    block_on(hooks.tool_input(input()).context(context())).unwrap();
    assert!(backend.messages.lock().unwrap().is_empty());
    let mut context = context();
    context.event["source"] = json!("urn:other");
    assert!(block_on(hooks.tool_input(input()).context(context)).is_err());
}

// Controlled futures need no runtime or timers.
#[derive(Default)]
struct ControlledBackend {
    inner: Backend,
    attempts: Cell<usize>,
    shutdowns: Mutex<
        std::collections::VecDeque<futures::channel::oneshot::Receiver<Result<(), HookError>>>,
    >,
}
impl ControlledBackend {
    fn next_shutdown(&self) -> futures::channel::oneshot::Sender<Result<(), HookError>> {
        let (send, receive) = futures::channel::oneshot::channel();
        self.shutdowns.lock().unwrap().push_back(receive);
        send
    }
}
impl ManagedBackend for ControlledBackend {
    fn call(&self, request: Value, timeout: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        self.inner.call(request, timeout)
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async move {
            self.attempts.set(self.attempts.get() + 1);
            let receive = self
                .shutdowns
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected shutdown attempt");
            receive.await.expect("shutdown controller dropped")
        })
    }
}
fn poll_once<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
    let mut context = std::task::Context::from_waker(futures::task::noop_waker_ref());
    future.poll(&mut context)
}

#[test]
fn cancelled_shutdown_can_be_retried() {
    let backend = Arc::new(ControlledBackend::default());
    let cancelled = backend.next_shutdown();
    let retry = backend.next_shutdown();
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    let mut first = Box::pin(hooks.shutdown());
    assert!(poll_once(first.as_mut()).is_pending());
    assert_eq!(backend.attempts.get(), 1);
    drop(first);
    assert!(cancelled.send(Ok(())).is_err());
    assert!(block_on(hooks.tool_input(input()).context(context())).is_err());
    let mut second = Box::pin(hooks.shutdown());
    assert!(poll_once(second.as_mut()).is_pending());
    assert_eq!(backend.attempts.get(), 2);
    retry.send(Ok(())).unwrap();
    assert!(matches!(
        poll_once(second.as_mut()),
        std::task::Poll::Ready(Ok(_))
    ));
    block_on(hooks.shutdown()).unwrap();
    assert_eq!(backend.attempts.get(), 2);
}

#[test]
fn concurrent_shutdown_callers_wait_for_backend_completion() {
    let backend = Arc::new(ControlledBackend::default());
    let complete = backend.next_shutdown();
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    let mut first = Box::pin(hooks.shutdown());
    let mut second = Box::pin(hooks.shutdown());
    assert!(poll_once(first.as_mut()).is_pending());
    assert!(poll_once(second.as_mut()).is_pending());
    assert!(poll_once(second.as_mut()).is_pending());
    assert_eq!(backend.attempts.get(), 1);
    complete.send(Ok(())).unwrap();
    assert!(matches!(
        poll_once(first.as_mut()),
        std::task::Poll::Ready(Ok(_))
    ));
    assert!(matches!(
        poll_once(second.as_mut()),
        std::task::Poll::Ready(Ok(_))
    ));
    assert_eq!(backend.attempts.get(), 1);
}

#[test]
fn concurrent_shutdown_waiter_retries_failed_backend() {
    let backend = Arc::new(ControlledBackend::default());
    let failure = backend.next_shutdown();
    let retry = backend.next_shutdown();
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    let mut first = Box::pin(hooks.shutdown());
    let mut second = Box::pin(hooks.shutdown());
    assert!(poll_once(first.as_mut()).is_pending());
    assert!(poll_once(second.as_mut()).is_pending());
    assert_eq!(backend.attempts.get(), 1);
    failure
        .send(Err(HookError("controlled failure".into())))
        .unwrap();
    assert!(matches!(
        poll_once(first.as_mut()),
        std::task::Poll::Ready(Err(_))
    ));
    assert!(poll_once(second.as_mut()).is_pending());
    assert_eq!(backend.attempts.get(), 2);
    retry.send(Ok(())).unwrap();
    assert!(matches!(
        poll_once(second.as_mut()),
        std::task::Poll::Ready(Ok(_))
    ));
}

#[test]
fn failed_backend_shutdown_can_be_retried() {
    let backend = Arc::new(ControlledBackend::default());
    backend
        .next_shutdown()
        .send(Err(HookError("controlled failure".into())))
        .unwrap();
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    let error = block_on(hooks.shutdown()).unwrap_err();
    assert!(error.to_string().contains("controlled failure"));
    assert_eq!(backend.attempts.get(), 1);
    backend.next_shutdown().send(Ok(())).unwrap();
    block_on(hooks.shutdown()).unwrap();
    block_on(hooks.shutdown()).unwrap();
    assert_eq!(backend.attempts.get(), 2);
}

#[test]
fn nonobject_tool_context_returns_error_without_panicking() {
    let backend = Arc::new(Backend::default());
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    for event in [
        Value::Null,
        json!(false),
        json!(42),
        json!("invalid"),
        json!([]),
    ] {
        let result = block_on(hooks.tool_input(input()).context(ToolContext::new(event)));
        assert!(result.is_err());
    }
    assert!(backend.messages.lock().unwrap().is_empty());
    block_on(hooks.shutdown()).unwrap();
    assert_eq!(backend.closed.get(), 1);
}

#[test]
fn observation_diagnostics_are_bounded_and_count_omissions() {
    let backend = Arc::new(Backend::default());
    *backend.effects.lock().unwrap() = json!([]);
    let mut opts = options(backend.clone(), true);
    opts.max_observations = 1;
    let mut config = registration(true);
    let subscriptions = config["hooks"][0]["subscriptions"].as_array_mut().unwrap();
    subscriptions.push(subscriptions.last().unwrap().clone());
    let hooks = Hooks::new(config, opts).unwrap();
    // One delivered observation and one bounded-limit failure per operation.
    for _ in 0..1028 {
        block_on(hooks.tool_input(input()).context(context())).unwrap();
    }
    let report = block_on(hooks.wait_until_idle());
    assert_eq!(report.delivered, 1028);
    assert_eq!(report.failures.len(), 1024);
    assert_eq!(report.omitted_failures, 4);
    assert!(
        report
            .failures
            .iter()
            .all(|failure| failure.error == "observation operation limit reached")
    );
    let closed = block_on(hooks.shutdown()).unwrap();
    assert_eq!(closed.delivered, 1028);
    assert_eq!(closed.failures, report.failures);
    assert_eq!(closed.omitted_failures, 4);
}

#[test]
fn shutdown_drops_suspended_backend_before_cleanup_without_caller_poll() {
    struct PendingBackend {
        active: Arc<Cell<bool>>,
        closed: Cell<bool>,
    }
    struct ActiveCall(Arc<Cell<bool>>);
    impl Drop for ActiveCall {
        fn drop(&mut self) {
            self.0.set(false);
        }
    }
    impl ManagedBackend for PendingBackend {
        fn call(&self, _: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                self.active.set(true);
                let _guard = ActiveCall(self.active.clone());
                std::future::pending().await
            })
        }
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async move {
                assert!(
                    !self.active.get(),
                    "transport call must be destroyed before reap"
                );
                self.closed.set(true);
                Ok(())
            })
        }
    }
    let backend = Arc::new(PendingBackend {
        active: Arc::new(Cell::new(false)),
        closed: Cell::new(false),
    });
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    let mut boundary = hooks.tool_input(input()).context(context()).into_future();
    let waker = futures::task::noop_waker();
    assert!(
        boundary
            .as_mut()
            .poll(&mut std::task::Context::from_waker(&waker))
            .is_pending()
    );
    assert!(backend.active.get());
    block_on(hooks.shutdown()).unwrap();
    assert!(backend.closed.get());
    assert!(!backend.active.get());
    assert!(block_on(boundary).is_err());
}

#[derive(Default)]
struct Cell<T>(Mutex<T>);
impl<T: Copy> Cell<T> {
    fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }
    fn get(&self) -> T {
        *self.0.lock().unwrap()
    }
    fn set(&self, value: T) {
        *self.0.lock().unwrap() = value;
    }
}

#[test]
fn full_native_snapshot_and_permission_are_preserved_by_primary_harness() {
    let backend = Arc::new(Backend::default());
    *backend.effects.lock().unwrap() = json!([]);
    let hooks = Hooks::new(registration(true), options(backend.clone(), true)).unwrap();
    let snapshot = json!({"permission":"allow","candidate":{"value":null,"provenance":{"native":"cache"}},"flow":"none","instructions":["native context"],"injections":[],"com.example.state":true});
    let result = block_on(
        hooks
            .tool_input(input())
            .context(context())
            .initial_snapshot(snapshot.clone())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result.permission(), Decision::Allow);
    assert_eq!(result.outcome.instructions, ["native context"]);
    assert_eq!(
        backend.messages.lock().unwrap()[0]["params"]["state"],
        snapshot
    );
    assert_eq!(block_on(hooks.wait_until_idle()).delivered, 1);
    block_on(hooks.shutdown()).unwrap();
}

#[test]
fn diagnostics_attribute_backend_without_exposing_transport_details() {
    struct Failing;
    impl ManagedBackend for Failing {
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { Ok(()) })
        }
        fn call(&self, _: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async {
                Err(HookError("secret transport response".into())
                    .classified(agenthooksprotocol::generated::DeliveryDiagnosticCode::Transport))
            })
        }
    }
    let hooks = Hooks::new(registration(true), options(Arc::new(Failing), true)).unwrap();
    let result = block_on(
        hooks
            .tool_input(input())
            .context(context())
            .initial_state(Decision::Allow),
    )
    .unwrap();
    assert!(!result.outcome.can_execute());
    assert_eq!(result.diagnostics.len(), 2);
    for diagnostic in &result.diagnostics {
        assert_eq!(diagnostic.backend_id.as_deref(), Some("org.example.hook"));
        assert!(!format!("{diagnostic:?}").contains("secret"));
    }
    assert!(result.diagnostics[0].synthetic_denial);
    assert!(!result.diagnostics[1].synthetic_denial);
    assert!(!format!("{:?}", block_on(hooks.wait_until_idle())).contains("secret"));
    block_on(hooks.shutdown()).unwrap();
}

#[test]
fn signals_raised_during_final_delivery_poll_never_return_permission() {
    use agenthooksprotocol::DeliveryDiagnosticCode;
    struct Signals(Mutex<Option<futures::channel::oneshot::Sender<()>>>);
    impl ManagedBackend for Signals {
        fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                self.0.lock().unwrap().take().unwrap().send(()).unwrap();
                Ok(
                    json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":[]}}),
                )
            })
        }
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { Ok(()) })
        }
    }
    for budget in [false, true] {
        let (send, receive) = futures::channel::oneshot::channel();
        let hooks = Hooks::new(
            registration(false),
            options(Arc::new(Signals(Mutex::new(Some(send)))), false),
        )
        .unwrap();
        let signal = async move {
            receive.await.unwrap();
        };
        let boundary = hooks
            .tool_input(input())
            .context(context())
            .initial_state(Decision::Allow);
        let boundary = if budget {
            boundary.budget(signal)
        } else {
            boundary.cancel_when(signal)
        };
        let error = block_on(boundary).err().unwrap();
        assert_eq!(
            error.code(),
            if budget {
                DeliveryDiagnosticCode::DeadlineExceeded
            } else {
                DeliveryDiagnosticCode::Cancelled
            }
        );
        block_on(hooks.shutdown()).unwrap();
    }
}

#[test]
fn route_response_rejections_and_remote_errors_have_distinct_sanitized_codes() {
    use agenthooksprotocol::DeliveryDiagnosticCode;
    struct Reply(Value);
    impl ManagedBackend for Reply {
        fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                let mut reply = self.0.clone();
                reply["id"] = request["id"].clone();
                Ok(reply)
            })
        }
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { Ok(()) })
        }
    }
    for (reply, expected) in [
        (
            json!({"jsonrpc":"2.0","result":{"protocolVersion":"draft","effects":[{"type":"ask","reason":"secret"}]}}),
            DeliveryDiagnosticCode::ProtocolRejection,
        ),
        (
            json!({"jsonrpc":"2.0","error":{"code":-32603,"message":"secret","data":{"token":"secret"}}}),
            DeliveryDiagnosticCode::RemoteRpc,
        ),
        (
            json!({"jsonrpc":"2.0","error":{"code":"wrong","message":"secret"}}),
            DeliveryDiagnosticCode::ProtocolRejection,
        ),
    ] {
        let hooks =
            Hooks::new(registration(false), options(Arc::new(Reply(reply)), false)).unwrap();
        let result = block_on(
            hooks
                .tool_input(input())
                .context(context())
                .initial_state(Decision::Allow),
        )
        .unwrap();
        assert_eq!(result.permission(), Decision::Deny);
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(result.diagnostics[0].code, expected);
        assert!(result.diagnostics[0].synthetic_denial);
        assert_eq!(
            result.diagnostics[0].backend_id.as_deref(),
            Some("org.example.hook")
        );
        assert!(!format!("{:?}", result.diagnostics).contains("secret"));
        assert!(result.outcome.responses.is_empty());
        block_on(hooks.shutdown()).unwrap();
    }
}
