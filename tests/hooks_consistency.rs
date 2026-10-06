use agenthooksprotocol::{
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
    hooks::{Capabilities, EventGrant, Hooks, HooksOptions},
};
use futures::{FutureExt, executor::LocalPool};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::IntoFuture,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Default)]
struct Backend {
    calls: Mutex<Vec<Value>>,
    closed: Cell<bool>,
    gate: Mutex<Option<futures::channel::oneshot::Receiver<()>>>,
}
impl ManagedBackend for Backend {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            let gate = self.gate.lock().unwrap().take();
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            assert!(!self.closed.get());
            self.calls.lock().unwrap().push(request);
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
fn options(backend: Arc<Backend>) -> HooksOptions {
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
    let backend = Arc::new(Backend::default());
    let opts = options(backend.clone());
    let hooks = Hooks::new(registration(), opts).unwrap();
    let result = pool
        .run_until(hooks.session_start(facts()).into_future())
        .unwrap();
    assert_eq!(result.effective_event["type"], "session.start");
    assert_eq!(result.effective_event["manifest"], hooks.manifest());
    assert!(
        backend.calls.lock().unwrap().len() == 1,
        "the operation delivered its observation before completion"
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
    let backend = Arc::new(Backend::default());
    let opts = options(backend.clone());
    let original = Hooks::new(registration(), opts).unwrap();
    let mut manifest = original.manifest();
    manifest["toolPaths"] = json!(["native"]);
    manifest["limits"] = json!({"maxUploadBytes":1234});
    manifest["vendor.example"] = json!({"preserved":true});
    let options = HooksOptions::from_manifest(
        "urn:test:host",
        serde_json::from_value(manifest.clone()).unwrap(),
    )
    .unwrap()
    .with_backend("org.example.test", backend);
    let hooks = Hooks::new(registration(), options).unwrap();
    let result = pool
        .run_until(hooks.session_start(facts()).into_future())
        .unwrap();
    assert_eq!(result.effective_event["manifest"], manifest);
    pool.run_until(hooks.shutdown()).unwrap();
}

#[derive(Default)]
struct Cell<T>(Mutex<T>);
impl<T: Copy> Cell<T> {
    fn get(&self) -> T {
        *self.0.lock().unwrap()
    }
    fn set(&self, value: T) {
        *self.0.lock().unwrap() = value;
    }
}

#[test]
fn dropping_operation_cancels_observation_without_detached_work() {
    let backend = Arc::new(Backend::default());
    let (send, receive) = futures::channel::oneshot::channel();
    *backend.gate.lock().unwrap() = Some(receive);
    let hooks = Hooks::new(registration(), options(backend.clone())).unwrap();
    assert!(
        hooks
            .session_start(facts())
            .into_future()
            .now_or_never()
            .is_none()
    );
    assert!(send.send(()).is_err());
    assert!(backend.calls.lock().unwrap().is_empty());
    let report = futures::executor::block_on(hooks.wait_until_idle());
    assert_eq!(report.delivered, 0);
    assert_eq!(report.failures.len(), 1);
    futures::executor::block_on(hooks.shutdown()).unwrap();
}

#[test]
fn shutdown_cancels_suspended_observation_without_polling_operation() {
    let backend = Arc::new(Backend::default());
    let (send, receive) = futures::channel::oneshot::channel();
    *backend.gate.lock().unwrap() = Some(receive);
    let hooks = Hooks::new(registration(), options(backend.clone())).unwrap();
    let mut operation = hooks.session_start(facts()).into_future();
    assert!(operation.as_mut().now_or_never().is_none());
    futures::executor::block_on(hooks.shutdown()).unwrap();
    assert!(send.send(()).is_err());
    assert!(futures::executor::block_on(operation).is_err());
    assert!(backend.closed.get());
}

#[test]
fn budget_and_caller_cancellation_cover_owned_observations() {
    for budget in [true, false] {
        let backend = Arc::new(Backend::default());
        let (send, receive) = futures::channel::oneshot::channel();
        *backend.gate.lock().unwrap() = Some(receive);
        let hooks = Hooks::new(registration(), options(backend.clone())).unwrap();
        let (cancel, cancelled) = futures::channel::oneshot::channel();
        let signal = async move {
            let _ = cancelled.await;
        };
        let boundary = hooks.session_start(facts());
        let mut operation = if budget {
            boundary.budget(signal)
        } else {
            boundary.cancel_when(signal)
        }
        .into_future();
        assert!(operation.as_mut().now_or_never().is_none());
        cancel.send(()).unwrap();
        let error = futures::executor::block_on(operation).err().unwrap();
        assert!(error.to_string().contains(if budget {
            "budget exceeded"
        } else {
            "cancelled by caller"
        }));
        assert!(send.send(()).is_err());
        assert_eq!(
            futures::executor::block_on(hooks.wait_until_idle()).delivered,
            0
        );
        futures::executor::block_on(hooks.shutdown()).unwrap();
    }
}

#[test]
fn hooks_and_operation_futures_are_send_without_runtime() {
    fn send<T: Send>(_: T) {}
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Hooks>();
    let hooks = Hooks::new(registration(), options(Arc::new(Backend::default()))).unwrap();
    send(hooks.session_start(facts()).into_future());
    send(hooks.tool_input(json!({})).into_future());
    send(hooks.wait_until_idle());
    send(hooks.shutdown());
}

#[test]
fn expired_deadline_never_dispatches_or_returns_permission() {
    let backend = Arc::new(Backend::default());
    let hooks = Hooks::new(registration(), options(backend.clone())).unwrap();
    let error = futures::executor::block_on(
        hooks
            .session_start(facts())
            .deadline_with(std::time::Instant::now(), std::future::pending())
            .into_future(),
    )
    .err()
    .unwrap();
    assert_eq!(
        error.code(),
        agenthooksprotocol::generated::DeliveryDiagnosticCode::DeadlineExceeded
    );
    assert!(backend.calls.lock().unwrap().is_empty());
    futures::executor::block_on(hooks.shutdown()).unwrap();
}

#[cfg(feature = "tokio-process")]
#[tokio::test(flavor = "current_thread")]
async fn runtime_native_timeout_cancels_observation_and_allows_shutdown() {
    let backend = Arc::new(Backend::default());
    let (send, receive) = futures::channel::oneshot::channel();
    *backend.gate.lock().unwrap() = Some(receive);
    let hooks = Hooks::new(registration(), options(backend.clone())).unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            hooks.session_start(facts()).into_future()
        )
        .await
        .is_err()
    );
    assert!(send.send(()).is_err());
    assert!(backend.calls.lock().unwrap().is_empty());
    assert_eq!(hooks.shutdown().await.unwrap().delivered, 0);
    assert!(backend.closed.get());
}
