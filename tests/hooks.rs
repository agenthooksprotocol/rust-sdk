use agenthooksprotocol::{
    Hooks,
    adapters::registered::ManagedBackend,
    client::{Decision, HookError, LocalFuture, ToolContext},
    hooks::{
        Capabilities, EventGrant, HooksOptions, NAMED_BOUNDARIES, ObservationScheduler,
        ObservationTask,
    },
};
use std::future::IntoFuture;
thread_local! { static POOL: RefCell<futures::executor::LocalPool> = RefCell::new(futures::executor::LocalPool::new()); }
fn block_on<F: IntoFuture>(future: F) -> F::Output {
    POOL.with(|pool| pool.borrow_mut().run_until(future.into_future()))
}
struct Scheduler(futures::executor::LocalSpawner);
struct Task {
    abort: futures::future::AbortHandle,
    done: futures::future::Shared<futures::future::LocalBoxFuture<'static, ()>>,
}
impl Drop for Task {
    fn drop(&mut self) {
        self.abort.abort();
    }
}
impl ObservationTask for Task {
    fn cancel(&self) {
        self.abort.abort();
    }
    fn completion(&self) -> LocalFuture<'_, ()> {
        Box::pin(self.done.clone())
    }
}
impl ObservationScheduler for Scheduler {
    fn schedule(&self, work: LocalFuture<'static, ()>) -> Rc<dyn ObservationTask> {
        use futures::{FutureExt, task::LocalSpawnExt};
        let (abort, registration) = futures::future::AbortHandle::new_pair();
        let (send, receive) = futures::channel::oneshot::channel();
        self.0
            .spawn_local(async move {
                let _ = futures::future::Abortable::new(work, registration).await;
                let _ = send.send(());
            })
            .unwrap();
        Rc::new(Task {
            abort,
            done: async move {
                let _ = receive.await;
            }
            .boxed_local()
            .shared(),
        })
    }
}
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    time::Duration,
};

#[derive(Default)]
struct Backend {
    messages: RefCell<Vec<Value>>,
    effects: RefCell<Value>,
    closed: Cell<usize>,
}
impl ManagedBackend for Backend {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            self.messages.borrow_mut().push(request.clone());
            if request["method"] == "hooks/observe" {
                return Ok(Value::Null);
            }
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":self.effects.borrow().clone()}}),
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
fn options(backend: Rc<dyn ManagedBackend>, observe: bool) -> HooksOptions {
    let grant = EventGrant::intercept(
        Capabilities::none()
            .allow()
            .deny()
            .return_value()
            .modify_input(),
    );
    let mut options = HooksOptions::new(
        "urn:example:host",
        BTreeMap::from([(
            "tool.before".into(),
            if observe { grant.with_observe() } else { grant },
        )]),
    )
    .with_backend("org.example.hook", backend);
    if observe {
        options.observation_scheduler = Some(Rc::new(Scheduler(
            POOL.with(|pool| pool.borrow().spawner()),
        )));
    }
    options
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
    let backend = Rc::new(Backend::default());
    *backend.effects.borrow_mut() = json!([{"type":"modify","target":"input","operation":"merge","value":{"command":"new"}},{"type":"return","value":{"cached":true}}]);
    let config: agenthooksprotocol::generated::Registration =
        serde_json::from_str(&registration(true).to_string()).unwrap();
    let hooks = Hooks::new(config, options(backend.clone(), true)).unwrap();
    let lazy = hooks
        .tool_before(input())
        .context(context())
        .initial_state(Decision::Allow);
    assert!(backend.messages.borrow().is_empty());
    let result = block_on(lazy).unwrap();
    assert_eq!(result.input.unwrap().command, "new");
    assert_eq!(result.outcome.candidate(), Some(&json!({"cached":true})));
    assert_eq!(backend.messages.borrow().len(), 1);
    let first = backend.messages.borrow()[0].clone();
    assert_eq!(first["params"]["event"]["source"], "urn:example:host");
    assert!(first["params"]["event"].get("native").is_none());
    assert!(first["params"]["capabilities"].get("elicitation").is_none());
    assert_eq!(block_on(hooks.wait_until_idle()).delivered, 1);
    let notification = backend.messages.borrow()[1].clone();
    assert_eq!(notification["method"], "hooks/observe");
    assert!(notification.get("id").is_none());
    assert!(notification["params"].get("capabilities").is_none());
    assert_eq!(
        notification["params"]["event"]["tool"]["input"]["command"],
        "new"
    );
    *backend.effects.borrow_mut() = json!([{"type":"deny","reason":"host policy"}]);
    let denied = block_on(
        hooks
            .tool_before(input())
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
    assert!(block_on(hooks.tool_before(input()).context(context())).is_err());
}
#[test]
fn no_implicit_observation_or_capability_expansion() {
    let backend = Rc::new(Backend::default());
    *backend.effects.borrow_mut() = json!([]);
    assert!(Hooks::new(registration(true), options(backend.clone(), false)).is_err());
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    assert!(
        block_on(
            hooks
                .tool_before(input())
                .context(context())
                .capabilities(Capabilities::none().flow_stop())
        )
        .is_err()
    );
    assert!(backend.messages.borrow().is_empty());
    block_on(hooks.tool_before(input()).context(context())).unwrap();
    assert_eq!(block_on(hooks.wait_until_idle()).delivered, 0);
    assert_eq!(backend.messages.borrow().len(), 1);
}
#[test]
fn unknown_events_duplicate_ids_and_mode_grants_fail_closed() {
    let backend = Rc::new(Backend::default());
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
    let backend = Rc::new(Backend::default());
    *backend.effects.borrow_mut() = json!([{"type":"modify","target":"input","operation":"merge","value":{"timeout_ms":"not an integer"}}]);
    let hooks = Hooks::new(registration(false), options(backend, false)).unwrap();
    let result = block_on(
        hooks
            .tool_before(input())
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
    let backend = Rc::new(Backend::default());
    *backend.effects.borrow_mut() = json!([]);
    let mut config = registration(false);
    config["hooks"][0]["subscriptions"][0]["filters"] = json!({"toolKinds":["different"]});
    let hooks = Hooks::new(config, options(backend.clone(), false)).unwrap();
    block_on(hooks.tool_before(input()).context(context())).unwrap();
    assert!(backend.messages.borrow().is_empty());
    let mut context = context();
    context.event["source"] = json!("urn:other");
    assert!(block_on(hooks.tool_before(input()).context(context)).is_err());
}

// Controlled futures need no runtime or timers.
#[derive(Default)]
struct ControlledBackend {
    inner: Backend,
    attempts: Cell<usize>,
    shutdowns: RefCell<
        std::collections::VecDeque<futures::channel::oneshot::Receiver<Result<(), HookError>>>,
    >,
}
impl ControlledBackend {
    fn next_shutdown(&self) -> futures::channel::oneshot::Sender<Result<(), HookError>> {
        let (send, receive) = futures::channel::oneshot::channel();
        self.shutdowns.borrow_mut().push_back(receive);
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
                .borrow_mut()
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
    let backend = Rc::new(ControlledBackend::default());
    let cancelled = backend.next_shutdown();
    let retry = backend.next_shutdown();
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    let mut first = Box::pin(hooks.shutdown());
    assert!(poll_once(first.as_mut()).is_pending());
    assert_eq!(backend.attempts.get(), 1);
    drop(first);
    assert!(cancelled.send(Ok(())).is_err());
    assert!(block_on(hooks.tool_before(input()).context(context())).is_err());
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
    let backend = Rc::new(ControlledBackend::default());
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
    let backend = Rc::new(ControlledBackend::default());
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
    let backend = Rc::new(ControlledBackend::default());
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
    let backend = Rc::new(Backend::default());
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    for event in [
        Value::Null,
        json!(false),
        json!(42),
        json!("invalid"),
        json!([]),
    ] {
        let result = block_on(hooks.tool_before(input()).context(ToolContext::new(event)));
        assert!(result.is_err());
    }
    assert!(backend.messages.borrow().is_empty());
    block_on(hooks.shutdown()).unwrap();
    assert_eq!(backend.closed.get(), 1);
}

#[test]
fn observation_diagnostics_are_bounded_and_count_omissions() {
    let backend = Rc::new(Backend::default());
    *backend.effects.borrow_mut() = json!([]);
    let mut opts = options(backend.clone(), true);
    opts.max_observations = 1;
    let hooks = Hooks::new(registration(true), opts).unwrap();
    // One queued observation, then 1027 queue-limit failures.
    for _ in 0..1028 {
        block_on(hooks.tool_before(input()).context(context())).unwrap();
    }
    let report = block_on(hooks.wait_until_idle());
    assert_eq!(report.delivered, 1);
    assert_eq!(report.failures.len(), 1024);
    assert_eq!(report.omitted_failures, 3);
    assert!(
        report
            .failures
            .iter()
            .all(|failure| failure.error == "observation queue limit reached")
    );
    let closed = block_on(hooks.shutdown()).unwrap();
    assert_eq!(closed.delivered, 1);
    assert_eq!(closed.failures, report.failures);
    assert_eq!(closed.omitted_failures, 3);
}

#[test]
fn shutdown_drops_suspended_backend_before_cleanup_without_caller_poll() {
    struct PendingBackend {
        active: Rc<Cell<bool>>,
        closed: Cell<bool>,
    }
    struct ActiveCall(Rc<Cell<bool>>);
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
    let backend = Rc::new(PendingBackend {
        active: Rc::new(Cell::new(false)),
        closed: Cell::new(false),
    });
    let hooks = Hooks::new(registration(false), options(backend.clone(), false)).unwrap();
    let mut boundary = hooks.tool_before(input()).context(context()).into_future();
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
