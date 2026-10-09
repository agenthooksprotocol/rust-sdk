//! Public ownership and capacity regressions for Hooks-managed content.
use agenthooksprotocol::{
    Attachment, Hooks,
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
    ergonomic_inputs::user_message_outbound_sources::message_payload,
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::IntoFuture,
    sync::{
        Arc,
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
    let hooks = hooks_with_limits(8, 1);
    for invocation in 0..4100 {
        let result = futures::executor::block_on(
            hooks
                .event(event(json!({"ref":"unused"})))
                .attachment(message_payload(0, Attachment::bytes(b"original".to_vec())))
                .into_future(),
        )
        .unwrap_or_else(|error| panic!("invocation {invocation}: {error}"));
        assert_eq!(
            &*futures::executor::block_on(result.content.read("/message/payload/0")).unwrap(),
            b"original"
        );
    }
}

#[test]
fn returned_content_outlives_hooks_and_does_not_charge_active_capacity() {
    let hooks = hooks_with_limits(8, 1);
    let result = futures::executor::block_on(
        hooks
            .event(event(json!({"ref":"unused"})))
            .attachment(message_payload(0, Attachment::bytes(b"original".to_vec())))
            .into_future(),
    )
    .unwrap();
    let next = futures::executor::block_on(
        hooks
            .event(event(json!({"ref":"unused"})))
            .attachment(message_payload(0, Attachment::bytes(b"next".to_vec())))
            .into_future(),
    )
    .unwrap();
    drop(hooks);
    assert_eq!(
        &*futures::executor::block_on(result.content.read("/message/payload/0")).unwrap(),
        b"original"
    );
    assert_eq!(
        &*futures::executor::block_on(next.content.read("/message/payload/0")).unwrap(),
        b"next"
    );
}

#[test]
fn boundary_attachments_enforce_eager_byte_limits() {
    let mut options = options().with_backend("org.example.lifecycle", Arc::new(Noop));
    options.max_body_bytes = 4;
    let hooks = Hooks::new(registration(), options).unwrap();
    for bytes in [b"full".to_vec(), b"large".to_vec(), b"x".to_vec()] {
        let result = futures::executor::block_on(
            hooks
                .event(event(json!({"ref":"unused"})))
                .attachment(message_payload(0, Attachment::bytes(bytes.clone())))
                .into_future(),
        );
        if bytes.len() > 4 {
            assert!(
                result.is_err(),
                "oversized eager attachment escaped binding limits"
            );
        } else {
            let result = result.unwrap();
            let read = futures::executor::block_on(result.content.read("/message/payload/0"));
            assert_eq!(&*read.unwrap(), bytes.as_slice());
        }
    }
}

#[test]
fn active_boundaries_share_entry_and_byte_budgets_and_release_on_drop() {
    for (bytes, entries, first_body) in [(32, 1, b"a".as_slice()), (4, 8, b"full".as_slice())] {
        let backend = Arc::new(Backend {
            pending: true,
            calls: AtomicUsize::new(0),
        });
        let mut options = options().with_backend("org.example.lifecycle", backend);
        options.max_stored_bytes = bytes;
        options.max_stored_entries = entries;
        let hooks = Hooks::new(registration(), options).unwrap();
        let mut first = hooks
            .event(event(json!({"ref":"unused"})))
            .attachment(message_payload(0, Attachment::bytes(first_body.to_vec())))
            .into_future();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(first.as_mut().poll(&mut cx).is_pending());
        let blocked = hooks
            .event(event(json!({"ref":"unused"})))
            .attachment(message_payload(0, Attachment::bytes(vec![0])))
            .into_future();
        assert!(futures::executor::block_on(blocked).is_err());
        drop(first);
        let mut replacement = hooks
            .event(event(json!({"ref":"unused"})))
            .attachment(message_payload(0, Attachment::bytes(vec![0])))
            .into_future();
        assert!(
            replacement.as_mut().poll(&mut cx).is_pending(),
            "dropping the first boundary must release its budget"
        );
        drop(replacement);
    }
}

#[test]
fn concurrent_attachment_binding_cannot_multiply_capacity() {
    let backend = Arc::new(Backend {
        pending: true,
        calls: AtomicUsize::new(0),
    });
    let mut options = options().with_backend("org.example.lifecycle", backend);
    options.max_stored_bytes = 4;
    options.max_stored_entries = 4;
    let hooks = Hooks::new(registration(), options).unwrap();
    let start = std::sync::Barrier::new(12);
    let bound = std::sync::Barrier::new(12);
    let successes = AtomicUsize::new(0);
    std::thread::scope(|threads| {
        for _ in 0..12 {
            threads.spawn(|| {
                let mut future = hooks
                    .event(event(json!({"ref":"unused"})))
                    .attachment(message_payload(0, Attachment::bytes(vec![0])))
                    .into_future();
                let mut cx = Context::from_waker(futures::task::noop_waker_ref());
                start.wait();
                match future.as_mut().poll(&mut cx) {
                    Poll::Pending => {
                        successes.fetch_add(1, Ordering::SeqCst);
                    }
                    Poll::Ready(result) => assert!(result.is_err()),
                }
                // Successful invocations keep every reservation until all attempts finish.
                bound.wait();
            });
        }
    });
    assert_eq!(successes.load(Ordering::SeqCst), 4);
    let mut future = hooks
        .event(event(json!({"ref":"unused"})))
        .attachment(message_payload(0, Attachment::bytes(b"full".to_vec())))
        .into_future();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(future.as_mut().poll(&mut cx).is_pending());
}

#[test]
fn concurrent_attachment_results_keep_independent_owners() {
    let hooks = hooks_with_limits(8, 1);
    futures::executor::block_on(async {
        let results = futures::future::join_all((0..12).map(|index| {
            hooks
                .event(event(json!({"ref":"same-literal"})))
                .attachment(message_payload(0, Attachment::bytes(vec![index])))
                .into_future()
        }))
        .await;
        drop(hooks);
        for (index, result) in results.into_iter().enumerate() {
            assert_eq!(
                &*result
                    .unwrap()
                    .content
                    .read("/message/payload/0")
                    .await
                    .unwrap(),
                &[index as u8]
            );
        }
    });
}

#[test]
fn preflight_failure_and_unpolled_boundary_drop_release_attachments() {
    let hooks = hooks_with_limits(8, 1);
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let result = futures::executor::block_on(
        hooks
            .event(json!({"type":"not-an-event"}))
            .attachment(message_payload(0, counted_attachment(&reads, &drops)))
            .into_future(),
    );
    assert!(result.is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    drop(
        hooks
            .event(event(json!({"ref":"unused"})))
            .attachment(message_payload(0, counted_attachment(&reads, &drops))),
    );
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
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
    let reference = json!({"ref":"unused"});
    let result = futures::executor::block_on(
        hooks
            .event(event(reference.clone()))
            .attachment(message_payload(0, Attachment::bytes(b"original".to_vec())))
            .into_future(),
    )
    .unwrap();
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert!(!result.outcome.failures.is_empty());
    drop(
        hooks
            .event(event(json!({"ref":"unused"})))
            .attachment(message_payload(0, Attachment::bytes(b"reused".to_vec()))),
    );
    assert_eq!(
        futures::executor::block_on(result.content.read("/message/payload/0"))
            .unwrap()
            .as_ref(),
        b"original"
    );
}

#[test]
fn dropping_an_in_flight_invocation_releases_its_content() {
    let (hooks, backend) = backend_hooks(true);
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut future = hooks
        .event(event(json!({"ref":"unused"})))
        .attachment(message_payload(0, counted_attachment(&reads, &drops)))
        .into_future();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(future);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
}

#[test]
fn cancellation_and_expired_budget_release_content() {
    let (hooks, _) = backend_hooks(true);
    for cancellation in [true, false] {
        let reads = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let boundary = hooks
            .event(event(json!({"ref":"unused"})))
            .attachment(message_payload(0, counted_attachment(&reads, &drops)));
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
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
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
fn counted_attachment(reads: &Arc<AtomicUsize>, drops: &Arc<AtomicUsize>) -> Attachment {
    Attachment::lazy(CountedSource {
        reads: reads.clone(),
        drops: drops.clone(),
        bytes: Some(b"original".to_vec()),
    })
}

#[test]
fn lazy_attachment_result_owns_unread_source_until_drop() {
    futures::executor::block_on(async {
        let hooks = hooks_with_limits(8, 1);
        let reads = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let outcome = hooks
            .event(event(json!({"ref":"unused"})))
            .attachment(message_payload(0, counted_attachment(&reads, &drops)))
            .await
            .unwrap();
        assert!(outcome.outcome.failures.is_empty());
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(
            hooks
                .event(event(json!({"ref":"unused"})))
                .attachment(message_payload(0, counted_attachment(&reads, &drops))),
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(hooks);
        drop(outcome);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
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
    async fn owned_attachment_reused_by_selected_consumers() {
        use agenthooksprotocol::{
            Attachment, ergonomic_inputs::user_message_outbound_sources::message_payload,
        };
        let (endpoint, server) = upload_server(2);
        let mut registrations = Vec::new();
        let mut options = options();
        options.backend.allow_loopback_http = true;
        for id in ["org.example.first", "org.example.second"] {
            registrations.push(json!({"id":id,
                "transport":{"type":"stdio","command":"never-run","lifecycle":"persistent"},
                "subscriptions":[{"events":["user.message.outbound"],"mode":"intercept","timeoutMs":5000,
                "failurePolicy":"fail-closed","content":{"default":"body"},
                "upload":{"endpoint":endpoint,"maxBytes":64,"timeoutMs":5000}}]}));
            options = options.with_backend(id, Arc::new(Noop));
        }
        let hooks = Hooks::new(
            json!({"protocolVersion":"draft","hooks":registrations}),
            options,
        )
        .unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        struct Binary {
            reads: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
            done: bool,
        }
        impl Drop for Binary {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        impl agenthooksprotocol::body::BodyStream for Binary {
            fn next_chunk(&mut self) -> agenthooksprotocol::body::BodyChunkFuture<'_> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    if self.done {
                        Ok(None)
                    } else {
                        self.done = true;
                        Ok(Some(vec![0, 255, 42]))
                    }
                })
            }
        }
        let mut input = event(json!({"ref":"unused"}));
        input["message"]["payload"][0]["mediaType"] = json!("application/octet-stream");
        let result = hooks
            .event(input)
            .attachment(message_payload(
                0,
                Attachment::lazy(Binary {
                    reads: reads.clone(),
                    drops: drops.clone(),
                    done: false,
                }),
            ))
            .await
            .unwrap();
        assert!(
            result.outcome.failures.is_empty(),
            "{:?}",
            result.outcome.failures
        );
        hooks.shutdown().await.unwrap();
        drop(hooks);
        assert_eq!(
            &*result.content.read("/message/payload/0").await.unwrap(),
            &[0, 255, 42]
        );
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            server.join().unwrap(),
            vec![vec![0, 255, 42], vec![0, 255, 42]]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_generic_edit_transaction_preserves_original_attachment() {
        struct Effects;
        impl ManagedBackend for Effects {
            fn call(
                &self,
                request: Value,
                _: Duration,
            ) -> LocalFuture<'_, Result<Value, HookError>> {
                Box::pin(async move {
                    assert_eq!(
                        request["params"]["capabilities"]["modify"]["content"]["replace"],
                        true
                    );
                    Ok(
                        json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":[
                            {"type":"modify","target":"content","operation":"replace","value":"middle"},
                            {"type":"modify","target":"content","operation":"replace","value":"x".repeat(65)}
                        ]}}),
                    )
                })
            }
            fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
                Box::pin(async { Ok(()) })
            }
        }
        let (endpoint, server) = upload_server(1);
        let mut config = registration();
        config["hooks"][0]["subscriptions"][0]["content"] = json!({"default":"body"});
        config["hooks"][0]["subscriptions"][0]["upload"] =
            json!({"endpoint":endpoint,"maxBytes":64,"timeoutMs":5000});
        let mut options = HooksOptions::new(
            "urn:test:content-lifecycle",
            BTreeMap::from([(
                "user.message.outbound".into(),
                EventGrant::intercept(Capabilities::none().modify("content", true, false)),
            )]),
        )
        .with_backend("org.example.lifecycle", Arc::new(Effects));
        options.backend.allow_loopback_http = true;
        options.max_body_bytes = 64;
        let hooks = Hooks::new(config, options).unwrap();
        let result = hooks
            .event(event(Value::Null))
            .attachment(message_payload(0, Attachment::bytes(b"original".to_vec())))
            .content_target("content", "/message/payload/0")
            .await
            .unwrap();
        assert!(!result.outcome.failures.is_empty());
        assert!(result.outcome.is_denied());
        drop(hooks);
        assert_eq!(
            result
                .content
                .read("/message/payload/0")
                .await
                .unwrap()
                .as_ref(),
            b"original"
        );
        assert_eq!(server.join().unwrap(), vec![b"original".to_vec()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inline_replacements_chain_and_only_outcome_bytes_survive() {
        let (endpoint, server) = upload_server(8);
        let hooks = chain_hooks(&endpoint, None);
        let mut outcomes = Vec::new();
        for _ in 0..4 {
            let original = json!({"ref":"opaque-original"});
            let mut input = event(original.clone());
            input["native"] = json!({"opaque": original, "nested": event(original.clone())});
            let result = hooks
                .event(input)
                .attachment(message_payload(0, Attachment::bytes(b"original".to_vec())))
                .content_target("content", "/message/payload/0")
                .await
                .unwrap();
            assert!(
                result.outcome.failures.is_empty(),
                "{:?}",
                result.outcome.failures
            );
            assert_eq!(
                &*result.content.read("/message/payload/0").await.unwrap(),
                b"final"
            );
            assert!(result.content.read("/native/opaque").await.is_err());
            assert!(
                result
                    .content
                    .read("/native/nested/message/payload/0")
                    .await
                    .is_err()
            );
            assert_eq!(result.effective_event["native"]["opaque"], original);
            outcomes.push(result);
        }
        drop(hooks);
        for result in outcomes {
            assert_eq!(
                &*result.content.read("/message/payload/0").await.unwrap(),
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
    async fn selected_lazy_attachment_roundtrip_ignores_foreign_reference_copy() {
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
        let alias = json!({"ref":"opaque-copy"});
        let boundary = hooks
            .event(event(alias.clone()))
            .attachment(message_payload(0, counted_attachment(&reads, &drops)));
        let invalid = hooks
            .event(json!({"type":"not-an-event", "native":{"copied":alias}}))
            .await;
        assert!(invalid.is_err());
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        // Selected projection must materialize without any mapped edit target.
        let outcome = boundary.await.unwrap();
        assert!(
            outcome.outcome.failures.is_empty(),
            "{:?}",
            outcome.outcome.failures
        );
        assert!(outcome.diagnostics.is_empty());
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(hooks);
        let first = outcome.content.read("/message/payload/0").await.unwrap();
        let again = outcome.content.read("/message/payload/0").await.unwrap();
        assert_eq!(&*first, b"original");
        assert!(
            Arc::ptr_eq(&first, &again),
            "upload and result reads must share the same owner"
        );
        assert_eq!(reads.load(Ordering::SeqCst), 2);
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
    async fn pending_observer_completion_does_not_retire_unrelated_attachments() {
        for finish in ["complete", "drop", "cancel"] {
            let (endpoint, server) = upload_server(3);
            let (entered_tx, entered_rx) = futures::channel::oneshot::channel();
            let (release_tx, release_rx) = futures::channel::oneshot::channel();
            let observer = Arc::new(PendingObserver {
                entered: std::sync::Mutex::new(Some(entered_tx)),
                release: std::sync::Mutex::new(Some(release_rx)),
            });
            let hooks = chain_hooks(&endpoint, Some(observer));
            let original = json!({"ref":"unused"});
            let (cancel_tx, cancel_rx) = futures::channel::oneshot::channel();
            let future = hooks
                .event(event(original))
                .attachment(message_payload(0, Attachment::bytes(b"original".to_vec())))
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

            // A separate unpolled boundary owns its source independently of the
            // invocation waiting for observation I/O.
            let reads = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let unrelated = hooks
                .event(event(json!({"ref":"unused"})))
                .attachment(message_payload(0, counted_attachment(&reads, &drops)));
            match finish {
                "complete" => {
                    release_tx.send(()).unwrap();
                    let outcome = future.await.unwrap();
                    assert!(outcome.outcome.failures.is_empty());
                    assert!(outcome.diagnostics.is_empty());
                    assert_eq!(
                        outcome
                            .content
                            .read("/message/payload/0")
                            .await
                            .unwrap()
                            .as_ref(),
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
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert_eq!(reads.load(Ordering::SeqCst), 0);
            drop(unrelated);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn shutdown_cancels_suspended_attachment_invocation() {
    let (hooks, backend) = backend_hooks(true);
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut future = hooks
        .event(event(json!({"ref":"unused"})))
        .attachment(message_payload(0, counted_attachment(&reads, &drops)))
        .into_future();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    futures::executor::block_on(hooks.shutdown()).unwrap();
    assert!(futures::executor::block_on(future).is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert!(
        futures::executor::block_on(
            hooks
                .event(event(json!({"ref":"unused"})))
                .attachment(message_payload(0, Attachment::bytes(vec![0])))
                .into_future()
        )
        .is_err()
    );
}

#[test]
fn abandoned_attachment_owners_do_not_fill_host_registry() {
    let hooks = hooks_with_limits(8, 1);
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    for _ in 0..4100 {
        drop(
            hooks
                .event(event(json!({"ref":"unused"})))
                .attachment(message_payload(0, counted_attachment(&reads, &drops))),
        );
    }
    assert_eq!(drops.load(Ordering::SeqCst), 4100);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
}

#[test]
fn foreign_reference_does_not_grant_attachment_read_authority() {
    let first = hooks_with_limits(8, 1);
    let second = hooks_with_limits(8, 1);
    let owner = futures::executor::block_on(
        first
            .event(event(json!({"ref":"unused"})))
            .attachment(message_payload(0, Attachment::bytes(b"original".to_vec())))
            .into_future(),
    )
    .unwrap();
    let copied = owner.effective_event["message"]["payload"][0]["body"].clone();
    let foreign = futures::executor::block_on(second.event(event(copied)).into_future()).unwrap();
    assert!(futures::executor::block_on(foreign.content.read("/message/payload/0")).is_err());
    drop(first);
    drop(second);
    assert_eq!(
        &*futures::executor::block_on(owner.content.read("/message/payload/0")).unwrap(),
        b"original"
    );
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
    let reference = json!({"ref":"unused"});
    futures::executor::block_on(
        hooks
            .event(event(reference))
            .attachment(message_payload(0, Attachment::bytes(b"original".to_vec())))
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
fn typed_decode_failure_preserves_result_bytes_but_releases_active_capacity() {
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
    let reference = json!({"ref":"unused"});
    let result = futures::executor::block_on(
        hooks
            .event(CannotDecode(event(reference.clone())))
            .attachment(message_payload(0, Attachment::bytes(b"original".to_vec())))
            .into_future(),
    )
    .unwrap();
    assert!(result.event.is_err());
    assert_eq!(
        futures::executor::block_on(result.content.read("/message/payload/0"))
            .unwrap()
            .as_ref(),
        b"original"
    );
}

#[test]
fn native_reference_collisions_do_not_grant_reads_but_message_slots_survive() {
    let hooks = hooks_with_limits(64, 2);
    let reference = json!({"ref":"content-1"});
    let mut input = event(reference.clone());
    input["native"] = json!({"opaque":reference,"fake_event":event(reference.clone()),
        "literal":reference["ref"],"candidate":{"value":reference}});
    let result = futures::executor::block_on(
        hooks
            .event(input.clone())
            .attachment(message_payload(0, Attachment::bytes(b"effective".to_vec())))
            .into_future(),
    )
    .unwrap();
    assert_eq!(result.effective_event["native"], input["native"]);
    for path in [
        "/native/opaque",
        "/native/fake_event/message/payload/0",
        "/native/candidate/value",
    ] {
        assert!(futures::executor::block_on(result.content.read(path)).is_err());
    }
    drop(hooks);
    assert_eq!(
        &*futures::executor::block_on(result.content.read("/message/payload/0")).unwrap(),
        b"effective"
    );
}

#[test]
fn opaque_tool_input_candidates_and_accepted_effects_do_not_root_content() {
    struct Effects(Value);
    impl ManagedBackend for Effects {
        fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                Ok(json!({"jsonrpc":"2.0", "id":request["id"],
                "result":{"protocolVersion":"draft","effects":self.0}}))
            })
        }
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { Ok(()) })
        }
    }
    // An arbitrary descriptor in opaque values must never grant content authority.
    let reference = json!({"ref":"content-1"});
    let opaque = event(reference.clone());
    let message = json!({"type":"message","text":"literal {\"ref\":\"content-1\"}"});
    let injection = json!({"type":"inject","target":"context","operation":"append",
        "deliverAt":"now","value":{"text":"keep this instruction", "opaque":opaque}});
    let effects = json!([message, injection, {"type":"return","value":opaque}]);
    let caps = Capabilities::from_value(json!({"effects":["message","inject","return"],
        "inject":{"context":{"append":true,"deliverAt":["now"]}}}))
    .unwrap();
    let mut options = HooksOptions::new(
        "urn:test:content-lifecycle",
        BTreeMap::from([("tool.before".into(), EventGrant::intercept(caps))]),
    );
    options.max_stored_entries = 1;
    let mut registration = registration();
    registration["hooks"][0]["subscriptions"][0]["events"] = json!(["tool.before"]);
    let hooks = Hooks::new(
        registration,
        options.with_backend("org.example.lifecycle", Arc::new(Effects(effects))),
    )
    .unwrap();
    let context = agenthooksprotocol::client::ToolContext::new(json!({
        "tool":{"name":"shell","kind":"shell","origin":"native"},
        "call":{"id":"call-1"},"path":"native","native":{"copied":reference}
    }));
    let result = futures::executor::block_on(
        hooks
            .tool_input(opaque.clone())
            .context(context)
            .into_future(),
    )
    .unwrap();
    assert!(
        result.outcome.failures.is_empty(),
        "{:?}",
        result.outcome.failures
    );
    assert_eq!(result.effective_input, opaque);
    assert_eq!(result.outcome.candidate, Some(opaque));
    assert_eq!(result.outcome.messages, vec![message]);
    assert_eq!(result.outcome.injections, vec![injection]);
    assert!(!result.outcome.responses.is_empty());
    for path in [
        "/message/payload/0",
        "/native/copied",
        "/candidate/message/payload/0",
    ] {
        assert!(futures::executor::block_on(result.content.read(path)).is_err());
    }
}
