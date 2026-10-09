//! Owned attachments remain lazy through route selection and fail closed.
use agenthooksprotocol::{
    Attachment, Hooks,
    adapters::registered::ManagedBackend,
    body::{BodyChunkFuture, BodyError, BodyStream},
    client::{HookError, LocalFuture, ToolContext},
    ergonomic_inputs::tool_before_sources::items,
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use futures::{executor::block_on, task::noop_waker};
use serde_json::{Value, json};
use std::{future::IntoFuture, sync::Arc, sync::Mutex, task::Context, time::Duration};

#[derive(Default)]
struct Backend(Mutex<Vec<Value>>);
impl ManagedBackend for Backend {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(request.clone());
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
    reads: Arc<Mutex<usize>>,
    pending: bool,
}
impl BodyStream for Source {
    fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
        *self.reads.lock().unwrap() += 1;
        Box::pin(async move {
            if self.pending {
                std::future::pending().await
            } else {
                Err(BodyError::Read("unavailable".into()))
            }
        })
    }
}
fn hooks(mode: &str, filtered: bool) -> (Hooks, Arc<Backend>) {
    hooks_with_upload_timeout(mode, filtered, 1000)
}
fn hooks_with_upload_timeout(
    mode: &str,
    filtered: bool,
    upload_timeout: u64,
) -> (Hooks, Arc<Backend>) {
    let backend = Arc::new(Backend::default());
    let mut subscription = json!({"events":["tool.before"],"mode":"intercept","timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":mode}});
    if filtered {
        subscription["filters"] = json!({"toolKinds":["other"]});
    }
    if mode == "body" {
        subscription["upload"] = json!({"endpoint":"https://upload.example.test/content","maxBytes":16,"timeoutMs":upload_timeout,"auth":{"type":"bearer","tokenRef":"upload"}});
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

#[tokio::test]
async fn metadata_omit_or_unmatched_routes_never_read() {
    for (mode, filtered) in [("metadata", false), ("omit", false), ("body", true)] {
        let (hooks, backend) = hooks(mode, filtered);
        let reads = Arc::new(Mutex::new(0));
        let outcome = hooks
            .tool_input(json!({}))
            .context(context(Value::Null))
            .attachment(items(
                0,
                Attachment::lazy(Source {
                    reads: reads.clone(),
                    pending: false,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(*reads.lock().unwrap(), 0);
        for request in backend.0.lock().unwrap().iter() {
            assert!(!request.to_string().contains("ahp-attachment:"));
            assert!(request["params"]["event"]["items"][0].get("body").is_none());
        }
        assert_eq!(
            backend.0.lock().unwrap().len(),
            if filtered { 0 } else { 1 }
        );
        drop(outcome);
        assert_eq!(*reads.lock().unwrap(), 0);
    }
}

#[tokio::test]
async fn cancelled_body_route_never_delivers_partial_request() {
    let (hooks, backend) = hooks("body", false);
    let reads = Arc::new(Mutex::new(0));
    let mut future = hooks
        .tool_input(json!({}))
        .context(context(Value::Null))
        .attachment(items(
            0,
            Attachment::lazy(Source {
                reads: reads.clone(),
                pending: true,
            }),
        ))
        .into_future();
    let waker = noop_waker();
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(*reads.lock().unwrap(), 1);
    drop(future);
    assert_eq!(*reads.lock().unwrap(), 1);
    assert!(backend.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_body_route_is_terminal_and_never_delivers() {
    let (hooks, backend) = hooks("body", false);
    let reads = Arc::new(Mutex::new(0));
    let outcome = hooks
        .tool_input(json!({}))
        .context(context(Value::Null))
        .attachment(items(
            0,
            Attachment::lazy(Source {
                reads: reads.clone(),
                pending: false,
            }),
        ))
        .await
        .unwrap();
    assert!(outcome.outcome.is_denied());
    for _ in 0..2 {
        assert!(outcome.content.read("/items/0").await.is_err());
    }
    assert_eq!(*reads.lock().unwrap(), 1);
    assert!(backend.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn shutdown_cancels_body_read_without_repolling_boundary() {
    let (hooks, backend) = hooks("body", false);
    let reads = Arc::new(Mutex::new(0));
    let mut boundary = hooks
        .tool_input(json!({}))
        .context(context(Value::Null))
        .attachment(items(
            0,
            Attachment::lazy(Source {
                reads: reads.clone(),
                pending: true,
            }),
        ))
        .into_future();
    let waker = noop_waker();
    assert!(
        boundary
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(*reads.lock().unwrap(), 1);
    block_on(hooks.shutdown()).unwrap();
    assert!(block_on(boundary).is_err());
    assert!(backend.0.lock().unwrap().is_empty());
    assert!(
        hooks
            .tool_input(json!({}))
            .context(context(Value::Null))
            .attachment(items(0, Attachment::bytes(vec![])))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dropping_result_drops_unselected_body_without_reading() {
    struct Untouched {
        dropped: Arc<Mutex<bool>>,
    }
    impl BodyStream for Untouched {
        fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
            panic!("unselected body must not be read")
        }
    }
    impl Drop for Untouched {
        fn drop(&mut self) {
            *self.dropped.lock().unwrap() = true;
        }
    }
    let (hooks, _) = hooks("metadata", false);
    let dropped = Arc::new(Mutex::new(false));
    let outcome = hooks
        .tool_input(json!({}))
        .context(context(Value::Null))
        .attachment(items(
            0,
            Attachment::lazy(Untouched {
                dropped: dropped.clone(),
            }),
        ))
        .await
        .unwrap();
    assert!(!*dropped.lock().unwrap());
    drop(outcome);
    assert!(*dropped.lock().unwrap());
    hooks.shutdown().await.unwrap();
    assert!(*dropped.lock().unwrap());
}

#[cfg(feature = "reqwest")]
#[tokio::test]
async fn upload_phase_timeout_cancels_pending_source_without_outer_budget() {
    let (hooks, backend) = hooks_with_upload_timeout("body", false, 5);
    let reads = Arc::new(Mutex::new(0));
    let outcome = hooks
        .tool_input(json!({}))
        .context(context(Value::Null))
        .attachment(items(
            0,
            Attachment::lazy(Source {
                reads: reads.clone(),
                pending: true,
            }),
        ))
        .await
        .unwrap();
    assert!(outcome.outcome.is_denied());
    assert_eq!(*reads.lock().unwrap(), 1);
    assert!(outcome.content.read("/items/0").await.is_err());
    assert_eq!(*reads.lock().unwrap(), 1);
    assert!(backend.0.lock().unwrap().is_empty());
}
