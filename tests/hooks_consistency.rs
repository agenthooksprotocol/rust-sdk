use agenthooksprotocol::{
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
    hooks::{Capabilities, EventGrant, Hooks, HooksOptions, ObservationScheduler, ObservationTask},
};
use futures::{
    executor::LocalPool,
    future::{AbortHandle, Abortable, FutureExt, LocalBoxFuture, Shared},
    task::LocalSpawnExt,
};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    future::IntoFuture,
    rc::Rc,
    time::Duration,
};

#[derive(Default)]
struct Backend {
    calls: RefCell<Vec<Value>>,
    closed: Cell<bool>,
    gate: RefCell<Option<futures::channel::oneshot::Receiver<()>>>,
}
impl ManagedBackend for Backend {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            let gate = self.gate.borrow_mut().take();
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            assert!(!self.closed.get());
            self.calls.borrow_mut().push(request);
            Ok(Value::Null)
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async move {
            self.closed.set(true);
            Ok(())
        })
    }
}
fn registration() -> Value {
    json!({"protocolVersion":"draft","hooks":[{"id":"org.example.test",
        "transport":{"type":"stdio","command":"never-run","lifecycle":"persistent"},
        "subscriptions":[{"events":["session.start"],"mode":"observe","content":{"default":"metadata"}}]}]})
}
fn options(backend: Rc<Backend>) -> HooksOptions {
    HooksOptions::new(
        "urn:test:host",
        BTreeMap::from([(
            "session.start".into(),
            EventGrant::intercept(Capabilities::none()).with_observe(),
        )]),
    )
    .with_backend("org.example.test", backend)
}
fn facts() -> Value {
    json!({"session":{"id":"session_1"},"trigger":"startup",
        "harness":{"name":"test","version":"1"},"permissionMode":"ask","items":[]})
}
#[test]
fn named_event_supplies_type_and_manifest_and_rejects_conflicts() {
    let mut pool = LocalPool::new();
    let backend = Rc::new(Backend::default());
    let mut opts = options(backend.clone());
    opts.observation_scheduler = Some(Rc::new(Scheduler(pool.spawner())));
    let hooks = Hooks::new(registration(), opts).unwrap();
    let result = pool
        .run_until(hooks.session_start(facts()).into_future())
        .unwrap();
    assert_eq!(result.effective_event["type"], "session.start");
    assert_eq!(result.effective_event["manifest"], hooks.manifest());
    assert!(
        backend.calls.borrow().is_empty(),
        "executor has not polled scheduled work yet"
    );
    let report = pool.run_until(hooks.wait_until_idle());
    assert_eq!(report.delivered, 1, "{:?}", report.failures);
    let mut same = facts();
    same["type"] = json!("session.start");
    same["manifest"] = hooks.manifest();
    assert!(
        pool.run_until(hooks.session_start(same).into_future())
            .is_ok()
    );
    for (field, wrong) in [
        ("type", json!("session.end")),
        ("type", Value::Null),
        ("manifest", json!({})),
    ] {
        let mut event = facts();
        event[field] = wrong;
        assert!(
            pool.run_until(hooks.session_start(event).into_future())
                .is_err()
        );
    }
    pool.run_until(hooks.shutdown()).unwrap();
}
#[test]
fn full_manifest_is_preserved_in_session_start() {
    let mut pool = LocalPool::new();
    let backend = Rc::new(Backend::default());
    let mut opts = options(backend.clone());
    opts.observation_scheduler = Some(Rc::new(Scheduler(pool.spawner())));
    let original = Hooks::new(registration(), opts).unwrap();
    let mut manifest = original.manifest();
    manifest["toolPaths"] = json!(["native"]);
    manifest["limits"] = json!({"maxUploadBytes":1234});
    manifest["vendor.example"] = json!({"preserved":true});
    let mut options = HooksOptions::from_manifest(
        "urn:test:host",
        serde_json::from_value(manifest.clone()).unwrap(),
    )
    .unwrap()
    .with_backend("org.example.test", backend);
    options.observation_scheduler = Some(Rc::new(Scheduler(pool.spawner())));
    let hooks = Hooks::new(registration(), options).unwrap();
    let result = pool
        .run_until(hooks.session_start(facts()).into_future())
        .unwrap();
    assert_eq!(result.effective_event["manifest"], manifest);
    pool.run_until(hooks.shutdown()).unwrap();
}
struct Scheduler(futures::executor::LocalSpawner);
struct Task {
    abort: AbortHandle,
    done: Shared<LocalBoxFuture<'static, ()>>,
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
        let (abort, registration) = AbortHandle::new_pair();
        let (send, receive) = futures::channel::oneshot::channel();
        self.0
            .spawn_local(async move {
                let _ = Abortable::new(work, registration).await;
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
#[test]
fn injected_scheduler_delivers_without_idle_and_shutdown_cancels_owned_work() {
    let mut pool = LocalPool::new();
    let backend = Rc::new(Backend::default());
    let mut options = options(backend.clone());
    options.observation_scheduler = Some(Rc::new(Scheduler(pool.spawner())));
    let hooks = Hooks::new(registration(), options).unwrap();
    pool.run_until(hooks.session_start(facts()).into_future())
        .unwrap();
    pool.run_until_stalled();
    assert_eq!(
        backend.calls.borrow().len(),
        1,
        "automatic delivery before idle waiter"
    );
    let (send, receive) = futures::channel::oneshot::channel();
    *backend.gate.borrow_mut() = Some(receive);
    pool.run_until(hooks.session_start(facts()).into_future())
        .unwrap();
    pool.run_until_stalled();
    // Cancelling a waiter must leave the owned worker alive.
    assert!(hooks.wait_until_idle().now_or_never().is_none());
    assert!(hooks.shutdown().now_or_never().is_none());
    assert!(!backend.closed.get());
    assert!(
        send.send(()).is_err(),
        "shutdown dropped the suspended backend future"
    );
    let report = pool.run_until(hooks.shutdown()).unwrap();
    assert_eq!(report.delivered, 1);
    assert_eq!(report.failures.len(), 1);
    assert!(backend.closed.get());
    assert!(
        pool.run_until(hooks.session_start(facts()).into_future())
            .is_err()
    );
}

#[cfg(feature = "tokio-process")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_adapter_delivers_automatically_on_explicit_local_set() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let backend = Rc::new(Backend::default());
            let mut options = options(backend.clone());
            options.observation_scheduler = Some(Rc::new(
                agenthooksprotocol::hooks::TokioObservationScheduler,
            ));
            let hooks = Hooks::new(registration(), options).unwrap();
            hooks.session_start(facts()).await.unwrap();
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert_eq!(backend.calls.borrow().len(), 1);
            assert_eq!(hooks.shutdown().await.unwrap().delivered, 1);
        })
        .await;
}

#[test]
fn observation_registration_requires_explicit_scheduler() {
    let backend = Rc::new(Backend::default());
    let result = Hooks::new(registration(), options(backend));
    assert!(matches!(result, Err(error) if error.to_string().contains("ObservationScheduler")));
}

#[test]
fn idle_waiter_does_not_poll_observation_work() {
    let mut pool = LocalPool::new();
    let backend = Rc::new(Backend::default());
    let mut opts = options(backend.clone());
    opts.observation_scheduler = Some(Rc::new(Scheduler(pool.spawner())));
    let hooks = Hooks::new(registration(), opts).unwrap();
    futures::executor::block_on(hooks.session_start(facts()).into_future()).unwrap();
    assert!(hooks.wait_until_idle().now_or_never().is_none());
    assert!(backend.calls.borrow().is_empty());
    pool.run_until_stalled();
    assert_eq!(backend.calls.borrow().len(), 1);
    assert_eq!(pool.run_until(hooks.wait_until_idle()).delivered, 1);
    pool.run_until(hooks.shutdown()).unwrap();
}

#[test]
fn shutdown_cancels_queued_worker_before_first_poll() {
    let mut pool = LocalPool::new();
    let backend = Rc::new(Backend::default());
    let mut opts = options(backend.clone());
    opts.observation_scheduler = Some(Rc::new(Scheduler(pool.spawner())));
    let hooks = Hooks::new(registration(), opts).unwrap();
    futures::executor::block_on(hooks.session_start(facts()).into_future()).unwrap();
    let report = pool.run_until(hooks.shutdown()).unwrap();
    assert_eq!(report.delivered, 0);
    assert_eq!(report.failures.len(), 1);
    assert!(backend.calls.borrow().is_empty());
    assert!(backend.closed.get());
    assert_eq!(pool.run_until(hooks.wait_until_idle()).delivered, 0);
}
