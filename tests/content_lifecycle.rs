//! Public ownership and capacity regressions for Hooks-managed content.
use agenthooksprotocol::{
    Hooks,
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
    content::UploadError,
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::IntoFuture,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

fn options() -> HooksOptions {
    HooksOptions::new(
        "urn:test:content-lifecycle",
        BTreeMap::from([(
            "user.message.outbound".into(),
            EventGrant::intercept(Capabilities::none()),
        )]),
    )
}

fn registration() -> Value {
    json!({"protocolVersion":"draft", "hooks":[{
        "id":"org.example.lifecycle",
        "transport":{"type":"stdio","command":"never-run","lifecycle":"persistent"},
        "subscriptions":[{"events":["user.message.outbound"], "mode":"intercept",
            "timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":"metadata"}}]
    }]})
}

struct Noop;
impl ManagedBackend for Noop {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            Ok(json!({"jsonrpc":"2.0", "id":request["id"],
            "result":{"protocolVersion":"draft","effects":[]}}))
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}

fn hooks_with_limits(bytes: usize, entries: usize) -> Hooks {
    let mut options = options();
    options.max_stored_bytes = bytes;
    options.max_stored_entries = entries;
    Hooks::new(
        registration(),
        options.with_backend("org.example.lifecycle", Arc::new(Noop)),
    )
    .unwrap()
}

fn event(reference: Value) -> Value {
    json!({"id":"outbound", "source":"urn:test:content-lifecycle",
    "type":"user.message.outbound", "time":"2026-09-15T12:00:00Z",
    "message":{"channel":"chat","payload":[{
        "id":"body", "kind":"content", "category":"content", "role":"assistant",
        "mediaType":"text/plain", "selection":"body", "body":reference
    }]}})
}

#[test]
fn default_capacity_is_reused_across_more_than_4096_invocations() {
    let hooks = Hooks::new(
        registration(),
        options().with_backend("org.example.lifecycle", Arc::new(Noop)),
    )
    .unwrap();
    for invocation in 0..4100 {
        let scope = hooks.content_scope();
        let reference = scope.context().put(b"original").unwrap_or_else(|error| {
            panic!("invocation {invocation} could not stage content: {error}")
        });
        let result = futures::executor::block_on(
            hooks
                .event(event(reference.clone()))
                .content_scope(scope)
                .into_future(),
        )
        .unwrap();
        assert_eq!(
            result.content.resolve(&reference).unwrap().as_ref(),
            b"original"
        );
    }
}

#[test]
fn returned_content_outlives_hooks_and_does_not_charge_active_capacity() {
    let hooks = hooks_with_limits(8, 1);
    let scope = hooks.content_scope();
    let reference = scope.context().put(b"original").unwrap();
    let result = futures::executor::block_on(
        hooks
            .event(event(reference.clone()))
            .content_scope(scope)
            .into_future(),
    )
    .unwrap();
    let next = hooks.content_scope();
    next.context()
        .put(b"next")
        .expect("completed invocation must release active capacity even while its outcome lives");
    drop(next);
    drop(hooks);
    let returned = &result.effective_event["message"]["payload"][0]["body"];
    assert_eq!(
        result.content.resolve(returned).unwrap().as_ref(),
        b"original"
    );
    assert_eq!(
        result
            .content
            .context()
            .resolve(&reference)
            .unwrap()
            .as_ref(),
        b"original"
    );
}

#[test]
fn explicit_scopes_share_entry_and_byte_budgets_and_release_on_drop() {
    for (bytes, entries, first_body) in [(32, 1, b"a".as_slice()), (4, 8, b"full".as_slice())] {
        let hooks = hooks_with_limits(bytes, entries);
        let first = hooks.content_scope();
        let second = hooks.content_scope();
        let reference = first.context().put(first_body).unwrap();
        assert!(
            second.context().resolve(&reference).is_err(),
            "a sibling scope must not gain authority from a reference"
        );
        assert_eq!(
            second.context().put(b"x").unwrap_err(),
            UploadError::Capacity
        );
        drop(first);
        let replacement = second.context().put(b"x").unwrap();
        assert_eq!(
            second.context().resolve(&replacement).unwrap().as_ref(),
            b"x"
        );
        assert!(second.context().resolve(&reference).is_err());
    }
}

#[test]
fn concurrent_staging_cannot_multiply_configured_capacity() {
    let hooks = hooks_with_limits(4, 4);
    let scopes: Vec<_> = (0..12).map(|_| hooks.content_scope()).collect();
    let start = Arc::new(Barrier::new(scopes.len()));
    let staged = Arc::new(Barrier::new(scopes.len()));
    let successes = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|threads| {
        for scope in scopes {
            let start = start.clone();
            let staged = staged.clone();
            let successes = successes.clone();
            threads.spawn(move || {
                start.wait();
                match scope.context().put(b"x") {
                    Ok(_) => {
                        successes.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(error) => assert_eq!(error, UploadError::Capacity),
                }
                // Keep every successful scope live until all writes were attempted.
                staged.wait();
            });
        }
    });
    assert_eq!(successes.load(Ordering::SeqCst), 4);
    hooks.content_scope().context().put(b"full").unwrap();
}

#[test]
fn preflight_failure_and_unpolled_boundary_drop_release_staged_content() {
    let hooks = hooks_with_limits(8, 1);
    let scope = hooks.content_scope();
    scope.context().put(b"original").unwrap();
    let result = futures::executor::block_on(
        hooks
            .event(json!({"type":"not-an-event"}))
            .content_scope(scope)
            .into_future(),
    );
    assert!(result.is_err());
    let scope = hooks.content_scope();
    let reference = scope.context().put(b"original").unwrap();
    drop(hooks.event(event(reference)).content_scope(scope));
    hooks.content_scope().context().put(b"reused").unwrap();
}

struct Backend {
    pending: bool,
    calls: AtomicUsize,
}
impl ManagedBackend for Backend {
    fn call(&self, _: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.pending {
                std::future::pending::<()>().await;
            }
            Err(HookError("intentional backend failure".into()))
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}

fn backend_hooks(pending: bool) -> (Hooks, Arc<Backend>) {
    let backend = Arc::new(Backend {
        pending,
        calls: AtomicUsize::new(0),
    });
    let mut options = options().with_backend("org.example.lifecycle", backend.clone());
    options.max_stored_bytes = 8;
    options.max_stored_entries = 1;
    let hooks = Hooks::new(
        json!({"protocolVersion":"draft", "hooks":[{
            "id":"org.example.lifecycle",
            "transport":{"type":"stdio","command":"never-run","lifecycle":"persistent"},
            "subscriptions":[{"events":["user.message.outbound"], "mode":"intercept",
                "timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":"metadata"}}]
        }]}),
        options,
    )
    .unwrap();
    (hooks, backend)
}

#[test]
fn backend_failure_releases_active_capacity_while_outcome_is_retained() {
    let (hooks, backend) = backend_hooks(false);
    let scope = hooks.content_scope();
    let reference = scope.context().put(b"original").unwrap();
    let result = futures::executor::block_on(
        hooks
            .event(event(reference.clone()))
            .content_scope(scope)
            .into_future(),
    )
    .unwrap();
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert!(!result.outcome.failures.is_empty());
    hooks.content_scope().context().put(b"reused").unwrap();
    assert_eq!(
        result.content.resolve(&reference).unwrap().as_ref(),
        b"original"
    );
}

#[test]
fn dropping_an_in_flight_invocation_releases_its_content() {
    let (hooks, backend) = backend_hooks(true);
    let scope = hooks.content_scope();
    let reference = scope.context().put(b"original").unwrap();
    let mut future = hooks
        .event(event(reference))
        .content_scope(scope)
        .into_future();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        hooks.content_scope().context().put(b"x").unwrap_err(),
        UploadError::Capacity
    );
    drop(future);
    hooks.content_scope().context().put(b"reused").unwrap();
}

#[test]
fn cancellation_and_expired_budget_release_content() {
    let (hooks, _) = backend_hooks(true);
    for cancellation in [true, false] {
        let scope = hooks.content_scope();
        let reference = scope.context().put(b"original").unwrap();
        let boundary = hooks.event(event(reference)).content_scope(scope);
        let (signal, receiver) = futures::channel::oneshot::channel();
        let expiry = async move {
            let _ = receiver.await;
        };
        let boundary = if cancellation {
            boundary.cancel_when(expiry)
        } else {
            boundary.budget(expiry)
        };
        let mut future = boundary.into_future();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
        signal.send(()).unwrap();
        assert!(futures::executor::block_on(future).is_err());
        hooks.content_scope().context().put(b"reused").unwrap();
    }
}

struct CountedSource {
    reads: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    bytes: Option<Vec<u8>>,
}
impl agenthooksprotocol::body::BodyStream for CountedSource {
    fn next_chunk(&mut self) -> agenthooksprotocol::body::BodyChunkFuture<'_> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let bytes = self.bytes.take();
        Box::pin(async move { Ok(bytes) })
    }
}
impl Drop for CountedSource {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
fn counted_body(
    reads: &Arc<AtomicUsize>,
    drops: &Arc<AtomicUsize>,
) -> agenthooksprotocol::body::Body {
    agenthooksprotocol::body::Body::stream(CountedSource {
        reads: reads.clone(),
        drops: drops.clone(),
        bytes: Some(b"original".to_vec()),
    })
}

#[test]
fn scoped_lazy_sources_drop_unread_and_release_registry_capacity() {
    futures::executor::block_on(async {
        let hooks = hooks_with_limits(8, 1);
        let reads = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut first = hooks.content_scope();
        first
            .stage_body(counted_body(&reads, &drops))
            .await
            .unwrap();
        let mut second = hooks.content_scope();
        assert!(matches!(
            second
                .stage_body(agenthooksprotocol::body::Body::text("blocked"))
                .await,
            Err(agenthooksprotocol::body::BodyError::Capacity)
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(first);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let reference = second
            .stage_body(counted_body(&reads, &drops))
            .await
            .unwrap();
        // The configured metadata-only route must never read this source. Keep its
        // outcome alive while checking that the invocation releases the registry.
        let outcome = hooks
            .event(event(reference))
            .content_scope(second)
            .await
            .unwrap();
        assert!(outcome.outcome.failures.is_empty());
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        let mut third = hooks.content_scope();
        third
            .stage_body(counted_body(&reads, &drops))
            .await
            .unwrap();
        drop(third);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    });
}

// Selected body projection performs a real upload even with a host-owned backend.
// Keep this transport fixture feature-gated; ownership tests above need no runtime.
#[cfg(feature = "reqwest")]
mod chained_replacements {
    use super::*;
    use agenthooksprotocol::{
        content::{AuthorizedScope, UploadReceiver},
        transport::Request,
    };
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        thread,
        time::Instant,
    };

    struct Replace(&'static str);
    impl ManagedBackend for Replace {
        fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                assert_eq!(
                    request["params"]["capabilities"]["modify"]["content"]["replace"],
                    true
                );
                Ok(json!({"jsonrpc":"2.0", "id":request["id"], "result":{
                    "protocolVersion":"draft", "effects":[{
                        "type":"modify", "target":"content", "operation":"replace", "value":self.0
                    }]
                }}))
            })
        }
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn upload_server(count: usize) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/upload", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let mut receiver = UploadReceiver::new(
                |_: &Request| Ok(AuthorizedScope::new("test-receiver")),
                "/upload",
                64,
                1024,
                16,
            );
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut uploaded = Vec::new();
            for _ in 0..count {
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "upload fixture timed out");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = BufReader::new(&socket);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line, "POST /upload HTTP/1.1\r\n");
                let mut headers = BTreeMap::new();
                loop {
                    line.clear();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap();
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                }
                let size: usize = headers["content-length"].parse().unwrap();
                assert!(size <= 64);
                let mut body = vec![0; size];
                reader.read_exact(&mut body).unwrap();
                uploaded.push(body.clone());
                let response = receiver.handle(Request {
                    method: "POST".into(),
                    uri: "/upload".into(),
                    headers,
                    body,
                });
                assert_eq!(response.status, 201);
                write!(socket, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.body.len()).unwrap();
                socket.write_all(&response.body).unwrap();
            }
            uploaded
        });
        (endpoint, server)
    }

    fn chain_hooks(endpoint: &str, observer: Option<Arc<dyn ManagedBackend>>) -> Hooks {
        let mut registrations: Vec<_> = ["org.example.first", "org.example.second"].into_iter().map(|id| json!({
            "id":id, "transport":{"type":"stdio","command":"never-run","lifecycle":"persistent"},
            "subscriptions":[{"events":["user.message.outbound"],"mode":"intercept","timeoutMs":5000,
                "failurePolicy":"fail-closed","content":{"default":"body"},
                "upload":{"endpoint":endpoint,"maxBytes":64,"timeoutMs":5000}}]
        })).collect();
        let mut options = HooksOptions::new(
            "urn:test:content-lifecycle",
            BTreeMap::from([(
                "user.message.outbound".into(),
                EventGrant::intercept(Capabilities::none().modify("content", true, false))
                    .with_observe(),
            )]),
        )
        .with_backend("org.example.first", Arc::new(Replace("middle")))
        .with_backend("org.example.second", Arc::new(Replace("final")));
        if let Some(observer) = observer {
            registrations.push(json!({
                "id":"org.example.observer",
                "transport":{"type":"stdio","command":"never-run","lifecycle":"persistent"},
                "subscriptions":[{"events":["user.message.outbound"],"mode":"observe",
                    "content":{"default":"body"},
                    "upload":{"endpoint":endpoint,"maxBytes":64,"timeoutMs":5000}}]
            }));
            options = options.with_backend("org.example.observer", observer);
        }
        options.backend.allow_loopback_http = true;
        options.max_stored_entries = 3;
        options.max_stored_bytes = 19; // original + middle + final
        Hooks::new(
            json!({"protocolVersion":"draft","hooks":registrations}),
            options,
        )
        .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inline_replacements_chain_and_only_outcome_bytes_survive() {
        let (endpoint, server) = upload_server(8);
        let hooks = chain_hooks(&endpoint, None);
        let mut outcomes = Vec::new();
        for _ in 0..4 {
            let scope = hooks.content_scope();
            let original = scope.put(b"original").unwrap();
            let bytes = scope.resolve(&original).unwrap();
            let original_bytes = Arc::downgrade(&bytes);
            drop(bytes);
            let result = hooks
                .event(event(original))
                .content_scope(scope)
                .content_target("content", "/message/payload/0")
                .await
                .unwrap();
            assert!(
                result.outcome.failures.is_empty(),
                "{:?}",
                result.outcome.failures
            );
            let reference = &result.effective_event["message"]["payload"][0]["body"];
            assert_eq!(
                result.content.resolve(reference).unwrap().as_ref(),
                b"final"
            );
            assert!(
                original_bytes.upgrade().is_none(),
                "result must not retain overwritten originals"
            );
            outcomes.push(result);
        }
        drop(hooks);
        for result in outcomes {
            let reference = &result.effective_event["message"]["payload"][0]["body"];
            assert_eq!(
                result.content.resolve(reference).unwrap().as_ref(),
                b"final"
            );
        }
        assert_eq!(
            server.join().unwrap(),
            (0..4)
                .flat_map(|_| [b"original".to_vec(), b"middle".to_vec()])
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn selected_lazy_scope_roundtrip_retains_alias_and_ignores_foreign_reference_copy() {
        let (endpoint, server) = upload_server(1);
        let mut registration = registration();
        let subscription = &mut registration["hooks"][0]["subscriptions"][0];
        subscription["content"] = json!({"default":"body"});
        subscription["upload"] = json!({"endpoint":endpoint,"maxBytes":64,"timeoutMs":5000});
        let mut options = options().with_backend("org.example.lifecycle", Arc::new(Noop));
        options.backend.allow_loopback_http = true;
        options.max_stored_entries = 1;
        options.max_stored_bytes = 8;
        let hooks = Hooks::new(registration, options).unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut scope = hooks.content_scope();
        let alias = scope
            .stage_body(counted_body(&reads, &drops))
            .await
            .unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        let invalid = hooks
            .event(json!({"type":"not-an-event", "native":{"copied":alias}}))
            .await;
        assert!(invalid.is_err());
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "foreign reference discovery must not retire the owning scope's source"
        );

        // No mapped edit target: selected projection, not runtime capability
        // negotiation, is responsible for materializing the lazy body.
        let outcome = hooks
            .event(event(alias.clone()))
            .content_scope(scope)
            .await
            .unwrap();
        assert!(
            outcome.outcome.failures.is_empty(),
            "{:?}",
            outcome.outcome.failures
        );
        assert!(outcome.diagnostics.is_empty());
        assert_eq!(reads.load(Ordering::SeqCst), 2); // one chunk, then EOF
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        hooks.content_scope().put(b"reused").unwrap();
        let mut unused = hooks.content_scope();
        unused
            .stage_body(agenthooksprotocol::body::Body::text("next"))
            .await
            .unwrap();
        drop(unused);
        drop(hooks);
        assert_eq!(
            outcome.content.resolve(&alias).unwrap().as_ref(),
            b"original"
        );
        let returned = &outcome.effective_event["message"]["payload"][0]["body"];
        assert_eq!(
            outcome.content.resolve(returned).unwrap().as_ref(),
            b"original"
        );
        assert_eq!(server.join().unwrap(), vec![b"original".to_vec()]);
    }

    struct PendingObserver {
        entered: std::sync::Mutex<Option<futures::channel::oneshot::Sender<Value>>>,
        release: std::sync::Mutex<Option<futures::channel::oneshot::Receiver<()>>>,
    }
    impl ManagedBackend for PendingObserver {
        fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                assert_eq!(request["method"], "hooks/observe");
                assert!(request.get("id").is_none());
                self.entered
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(request)
                    .unwrap();
                let release = self.release.lock().unwrap().take().unwrap();
                let _ = release.await;
                Ok(Value::Null)
            })
        }
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_observer_frees_invocation_capacity_without_retiring_unrelated_scopes() {
        for finish in ["complete", "drop", "cancel"] {
            let (endpoint, server) = upload_server(3);
            let (entered_tx, entered_rx) = futures::channel::oneshot::channel();
            let (release_tx, release_rx) = futures::channel::oneshot::channel();
            let observer = Arc::new(PendingObserver {
                entered: std::sync::Mutex::new(Some(entered_tx)),
                release: std::sync::Mutex::new(Some(release_rx)),
            });
            let hooks = chain_hooks(&endpoint, Some(observer));
            let scope = hooks.content_scope();
            let original = scope.put(b"original").unwrap();
            let (cancel_tx, cancel_rx) = futures::channel::oneshot::channel();
            let future = hooks
                .event(event(original))
                .content_scope(scope)
                .content_target("content", "/message/payload/0")
                .cancel_when(async move {
                    let _ = cancel_rx.await;
                })
                .into_future();
            // Poll the invocation until the fully projected observation reaches its
            // backend, not merely until an interceptor or upload is pending.
            let (notification, future) = match futures::future::select(future, entered_rx).await {
                futures::future::Either::Right((notification, future)) => {
                    (notification.unwrap(), future)
                }
                futures::future::Either::Left(_) => {
                    panic!("invocation completed before observer blocked")
                }
            };
            let body = &notification["params"]["event"]["message"]["payload"][0]["body"];
            assert!(
                body["ref"]
                    .as_str()
                    .is_some_and(|value| !value.starts_with("ahp-deferred:"))
            );
            assert_eq!(
                server.join().unwrap(),
                vec![b"original".to_vec(), b"middle".to_vec(), b"final".to_vec()]
            );

            // All originals and both replacements must already have left the active
            // store, despite the invocation future still waiting for observation I/O.
            let unrelated = hooks.content_scope();
            let payloads: [&[u8]; 3] = [b"1234567", b"abcdef", b"UVWXYZ"];
            let references: Vec<_> = payloads
                .iter()
                .map(|bytes| {
                    unrelated
                        .context()
                        .put(bytes)
                        .expect("pending observer must not retain invocation capacity")
                })
                .collect();
            assert_eq!(
                unrelated.context().put(b"x").unwrap_err(),
                UploadError::Capacity
            );
            match finish {
                "complete" => {
                    release_tx.send(()).unwrap();
                    let outcome = future.await.unwrap();
                    assert!(outcome.outcome.failures.is_empty());
                    assert!(outcome.diagnostics.is_empty());
                    let reference = &outcome.effective_event["message"]["payload"][0]["body"];
                    assert_eq!(
                        outcome.content.resolve(reference).unwrap().as_ref(),
                        b"final"
                    );
                }
                "drop" => {
                    drop(future);
                    drop(release_tx);
                }
                "cancel" => {
                    cancel_tx.send(()).unwrap();
                    assert!(future.await.is_err());
                    drop(release_tx);
                }
                _ => unreachable!(),
            }
            // Completion and either cancellation path may release only their own
            // allocations, not those created while the observer was blocked.
            for (reference, bytes) in references.iter().zip(payloads) {
                assert_eq!(
                    unrelated.context().resolve(reference).unwrap().as_ref(),
                    bytes
                );
            }
            assert_eq!(
                hooks.content_scope().context().put(b"x").unwrap_err(),
                UploadError::Capacity
            );
            drop(unrelated);
            hooks.content_scope().context().put(&[0; 19]).unwrap();
        }
    }
}

#[test]
fn shutdown_releases_staged_bytes_without_repolling_suspended_caller() {
    let (hooks, backend) = backend_hooks(true);
    let scope = hooks.content_scope();
    let reference = scope.put(b"original").unwrap();
    let bytes = scope.resolve(&reference).unwrap();
    let weak = Arc::downgrade(&bytes);
    drop(bytes);
    let mut future = hooks
        .event(event(reference))
        .content_scope(scope)
        .into_future();
    let waker = futures::task::noop_waker();
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert!(weak.upgrade().is_some());
    futures::executor::block_on(hooks.shutdown()).unwrap();
    assert!(
        weak.upgrade().is_none(),
        "shutdown must free backing before caller repolls"
    );
    assert_eq!(
        hooks.content_scope().put(b"x").unwrap_err(),
        UploadError::Unavailable
    );
    assert!(futures::executor::block_on(future).is_err());
    drop(backend);
}

#[test]
fn abandoned_staged_body_owners_do_not_fill_host_registry() {
    let hooks = hooks_with_limits(8, 1);
    for _ in 0..4100 {
        let staged = futures::executor::block_on(
            hooks.stage_body(agenthooksprotocol::body::Body::text("unread")),
        )
        .unwrap();
        assert!(
            futures::executor::block_on(
                hooks.stage_body(agenthooksprotocol::body::Body::text("blocked")),
            )
            .is_err()
        );
        drop(staged);
    }
}

#[test]
fn foreign_hooks_scope_is_rejected_without_releasing_sibling_allocations() {
    let first = hooks_with_limits(8, 1);
    let second = hooks_with_limits(8, 1);
    let foreign = first.content_scope();
    let reference = foreign.put(b"original").unwrap();
    let sibling = second.content_scope();
    let sibling_ref = sibling.put(b"retained").unwrap();
    assert!(
        futures::executor::block_on(
            second
                .event(event(reference))
                .content_scope(foreign)
                .into_future(),
        )
        .is_err()
    );
    assert_eq!(sibling.resolve(&sibling_ref).unwrap().as_ref(), b"retained");
    first.content_scope().put(b"reused").unwrap();
}

#[test]
fn observation_route_budgets_exclude_other_routes_delivery_time() {
    struct TimedObserver {
        delay: Duration,
        budgets: std::sync::Mutex<Vec<Duration>>,
    }
    impl ManagedBackend for TimedObserver {
        fn call(&self, _: Value, remaining: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                self.budgets.lock().unwrap().push(remaining);
                std::thread::sleep(self.delay);
                Ok(Value::Null)
            })
        }
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { Ok(()) })
        }
    }
    let first = Arc::new(TimedObserver {
        delay: Duration::from_millis(200),
        budgets: Default::default(),
    });
    let second = Arc::new(TimedObserver {
        delay: Duration::ZERO,
        budgets: Default::default(),
    });
    let mut options = options();
    options.observation_timeout = Duration::from_secs(1);
    options.capabilities.insert(
        "user.message.outbound".into(),
        EventGrant::intercept(Capabilities::none()).with_observe(),
    );
    let registrations: Vec<_> = ["org.example.first", "org.example.second"].iter().map(|id| json!({
        "id": id,
        "transport":{"type":"stdio","command":"never-run","lifecycle":"persistent"},
        "subscriptions":[{"events":["user.message.outbound"],"mode":"observe","content":{"default":"metadata"}}]
    })).collect();
    let hooks = Hooks::new(
        json!({"protocolVersion":"draft","hooks":registrations}),
        options
            .with_backend("org.example.first", first)
            .with_backend("org.example.second", second.clone()),
    )
    .unwrap();
    let scope = hooks.content_scope();
    let reference = scope.put(b"original").unwrap();
    futures::executor::block_on(
        hooks
            .event(event(reference))
            .content_scope(scope)
            .into_future(),
    )
    .unwrap();
    let budgets = second.budgets.lock().unwrap();
    assert_eq!(budgets.len(), 1);
    assert!(
        budgets[0] > Duration::from_millis(950),
        "another route consumed the subscription budget: {:?}",
        budgets[0]
    );
}

#[test]
fn typed_decode_failure_preserves_result_bytes_but_releases_staging() {
    struct CannotDecode(Value);
    impl serde::Serialize for CannotDecode {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.serialize(serializer)
        }
    }
    impl<'de> serde::Deserialize<'de> for CannotDecode {
        fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
            Err(serde::de::Error::custom("host decode failed"))
        }
    }
    let hooks = hooks_with_limits(8, 1);
    let scope = hooks.content_scope();
    let reference = scope.put(b"original").unwrap();
    let result = futures::executor::block_on(
        hooks
            .event(CannotDecode(event(reference.clone())))
            .content_scope(scope)
            .into_future(),
    )
    .unwrap();
    assert!(result.event.is_err());
    assert_eq!(
        result.content.resolve(&reference).unwrap().as_ref(),
        b"original"
    );
    hooks.content_scope().put(b"reusable").unwrap();
}
