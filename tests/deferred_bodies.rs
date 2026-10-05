//! Deferred staging must remain lazy through route selection and fail closed.
use agenthooksprotocol::{
    Hooks,
    adapters::registered::ManagedBackend,
    body::{Body, BodyChunkFuture, BodyError, BodyStream},
    client::{HookError, LocalFuture, ToolContext},
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use futures::{executor::block_on, task::noop_waker};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    future::IntoFuture,
    rc::Rc,
    task::Context,
    time::Duration,
};

#[derive(Default)]
struct Backend(RefCell<Vec<Value>>);
impl ManagedBackend for Backend {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            self.0.borrow_mut().push(request.clone());
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":[]}}),
            )
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}
struct Source {
    reads: Rc<Cell<usize>>,
    pending: bool,
}
impl BodyStream for Source {
    fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
        self.reads.set(self.reads.get() + 1);
        Box::pin(async move {
            if self.pending {
                std::future::pending().await
            } else {
                Err(BodyError::Read("unavailable".into()))
            }
        })
    }
}
fn hooks(mode: &str, filtered: bool) -> (Hooks, Rc<Backend>) {
    let backend = Rc::new(Backend::default());
    let mut subscription = json!({"events":["tool.before"],"mode":"intercept","timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":mode}});
    if filtered {
        subscription["filters"] = json!({"toolKinds":["other"]});
    }
    if mode == "body" {
        subscription["upload"] = json!({"endpoint":"https://upload.example.test/content","maxBytes":16,"timeoutMs":1000,"auth":{"type":"bearer","tokenRef":"upload"}});
    }
    let registration = json!({"protocolVersion":"draft","hooks":[{"id":"org.example.deferred","transport":{"type":"stdio","command":"never-started","lifecycle":"persistent"},"subscriptions":[subscription]}]});
    let mut options = HooksOptions::new(
        "urn:example:host",
        [(
            "tool.before".into(),
            EventGrant::intercept(Capabilities::none().allow().deny()),
        )]
        .into(),
    )
    .with_backend("org.example.deferred", backend.clone());
    options
        .backend
        .credentials
        .insert("upload".into(), "test-upload-token".into());
    (Hooks::new(registration, options).unwrap(), backend)
}
fn context(body: Value) -> ToolContext {
    ToolContext::new(
        json!({"tool":{"name":"shell","kind":"shell","origin":"native"},"call":{"id":"call-1"},"path":"native","items":[{"id":"body-1","kind":"text","mediaType":"text/plain","selection":"body","body":body}]}),
    )
}

#[test]
fn awaiting_staging_and_metadata_omit_or_unmatched_routes_never_read() {
    for (mode, filtered) in [("metadata", false), ("omit", false), ("body", true)] {
        let (hooks, backend) = hooks(mode, filtered);
        let reads = Rc::new(Cell::new(0));
        let body = block_on(hooks.stage_body(Body::stream(Source {
            reads: reads.clone(),
            pending: false,
        })))
        .unwrap();
        assert_eq!(reads.get(), 0);
        for _ in 0..2 {
            block_on(
                hooks
                    .tool_before(json!({}))
                    .context(context(body.clone()))
                    .into_future(),
            )
            .unwrap();
        }
        assert_eq!(reads.get(), 0);
        for request in backend.0.borrow().iter() {
            assert!(!request.to_string().contains("ahp-deferred:"));
            assert!(request["params"]["event"]["items"][0].get("body").is_none());
        }
        assert_eq!(backend.0.borrow().len(), if filtered { 0 } else { 2 });
    }
}

#[test]
fn cancelled_body_route_consumes_source_once_and_never_delivers_partial_request() {
    let (hooks, backend) = hooks("body", false);
    let reads = Rc::new(Cell::new(0));
    let body = block_on(hooks.stage_body(Body::stream(Source {
        reads: reads.clone(),
        pending: true,
    })))
    .unwrap();
    let mut future = hooks
        .tool_before(json!({}))
        .context(context(body.clone()))
        .into_future();
    let waker = noop_waker();
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(reads.get(), 1);
    drop(future);
    let outcome = block_on(
        hooks
            .tool_before(json!({}))
            .context(context(body))
            .into_future(),
    )
    .unwrap();
    assert!(outcome.outcome.is_denied());
    assert_eq!(reads.get(), 1);
    assert!(backend.0.borrow().is_empty());
}

#[test]
fn failed_body_route_is_terminal_and_never_delivers() {
    let (hooks, backend) = hooks("body", false);
    let reads = Rc::new(Cell::new(0));
    let body = block_on(hooks.stage_body(Body::stream(Source {
        reads: reads.clone(),
        pending: false,
    })))
    .unwrap();
    for _ in 0..2 {
        let outcome = block_on(
            hooks
                .tool_before(json!({}))
                .context(context(body.clone()))
                .into_future(),
        )
        .unwrap();
        assert!(outcome.outcome.is_denied());
    }
    assert_eq!(reads.get(), 1);
    assert!(backend.0.borrow().is_empty());
}

#[test]
fn shutdown_cancels_body_read_without_repolling_boundary() {
    let (hooks, backend) = hooks("body", false);
    let reads = Rc::new(Cell::new(0));
    let body = block_on(hooks.stage_body(Body::stream(Source {
        reads: reads.clone(),
        pending: true,
    })))
    .unwrap();
    let mut boundary = hooks
        .tool_before(json!({}))
        .context(context(body))
        .into_future();
    let waker = noop_waker();
    assert!(
        boundary
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(reads.get(), 1);
    block_on(hooks.shutdown()).unwrap();
    assert!(block_on(boundary).is_err());
    assert!(backend.0.borrow().is_empty());
    assert!(block_on(hooks.stage_body(Body::bytes(vec![]))).is_err());
}

#[test]
fn shutdown_drops_unselected_body_without_reading() {
    struct Untouched {
        dropped: Rc<Cell<bool>>,
    }
    impl BodyStream for Untouched {
        fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
            panic!("unselected body must not be read")
        }
    }
    impl Drop for Untouched {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }
    let (hooks, _) = hooks("metadata", false);
    let dropped = Rc::new(Cell::new(false));
    let body = block_on(hooks.stage_body(Body::stream(Untouched {
        dropped: dropped.clone(),
    })))
    .unwrap();
    block_on(
        hooks
            .tool_before(json!({}))
            .context(context(body))
            .into_future(),
    )
    .unwrap();
    assert!(!dropped.get());
    block_on(hooks.shutdown()).unwrap();
    assert!(dropped.get());
}
