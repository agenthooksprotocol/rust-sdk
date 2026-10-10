#![cfg(feature = "reqwest")]

use agenthooksprotocol::{
    Attachment, Hooks, Permission,
    adapters::registered::ManagedBackend,
    body::{BodyChunkFuture, BodyStream},
    client::{HookError, LocalFuture},
    content::{AuthorizedScope, UploadReceiver},
    ergonomic_inputs::{HostInput, MessageInput, PartInput, UserMessageOutboundInput},
    generated::CanonicalMessageRole,
    hooks::{Capabilities, EventGrant, HooksOptions},
    transport::Request,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
struct Transfer {
    token: String,
    bytes: Vec<u8>,
    receipt: Value,
}
#[derive(Default)]
struct Monitor {
    active: AtomicUsize,
    peak: AtomicUsize,
    completed: AtomicUsize,
    transfers: Mutex<Vec<Transfer>>,
}
struct Fixture {
    endpoint: String,
    monitor: Arc<Monitor>,
    thread: std::thread::JoinHandle<()>,
}
impl Fixture {
    // The first wave must overlap before any response is released. A bounded
    // wait makes a serial implementation fail rather than hang the test suite.
    fn new(expected: usize, wave: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/upload", listener.local_addr().unwrap());
        let monitor = Arc::new(Monitor::default());
        let recorded = monitor.clone();
        let url = endpoint.clone();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let receiver = Arc::new(Mutex::new(UploadReceiver::new(
            |request: &Request| {
                Ok(AuthorizedScope::new(
                    request.headers["authorization"].clone(),
                ))
            },
            endpoint.clone(),
            1024,
            32 * 1024,
            32,
        )));
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut workers = Vec::new();
            for _ in 0..expected {
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "missing planned upload");
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(e) => panic!("accept: {e}"),
                    }
                };
                let monitor = recorded.clone();
                let url = url.clone();
                let gate = gate.clone();
                let receiver = receiver.clone();
                workers.push(std::thread::spawn(move || {
                    socket.set_nonblocking(false).unwrap();
                    socket.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
                    let mut reader = BufReader::new(socket);
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    assert!(line.starts_with("POST /upload "));
                    let mut headers = BTreeMap::new();
                    loop {
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" { break; }
                        let (name, value) = line.trim_end().split_once(':').unwrap();
                        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                    }
                    let mut bytes = vec![0; headers["content-length"].parse().unwrap()];
                    reader.read_exact(&mut bytes).unwrap();
                    let token = headers["authorization"].clone();
                    let active = monitor.active.fetch_add(1, Ordering::SeqCst) + 1;
                    monitor.peak.fetch_max(active, Ordering::SeqCst);
                    let (lock, cond) = &*gate;
                    let mut open = lock.lock().unwrap();
                    if active >= wave { *open = true; cond.notify_all(); }
                    if !*open {
                        let (next, timeout) = cond.wait_timeout_while(open, Duration::from_secs(2), |v| !*v).unwrap();
                        open = next;
                        assert!(!timeout.timed_out(), "uploads did not overlap");
                    }
                    drop(open);
                    std::thread::sleep(Duration::from_millis(60));
                    let failed = token == "Bearer broken";
                    let response = receiver.lock().unwrap().handle(Request {
                        method: "POST".into(), uri: url, headers, body: bytes.clone(),
                    });
                    assert_eq!(response.status, 201);
                    let receipt: Value = serde_json::from_slice(&response.body).unwrap();
                    monitor.transfers.lock().unwrap().push(Transfer { token, bytes, receipt });
                    monitor.active.fetch_sub(1, Ordering::SeqCst);
                    monitor.completed.fetch_add(1, Ordering::SeqCst);
                    let mut socket = reader.into_inner();
                    let (status, body) = if failed { ("500 Internal Server Error", b"{}".as_slice()) } else { ("201 Created", response.body.as_slice()) };
                    write!(socket, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    socket.write_all(body).unwrap();
                    socket.flush().unwrap();
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            endpoint,
            monitor,
            thread,
        }
    }
    fn finish(self) {
        self.thread.join().unwrap();
    }
}

type Effects = dyn Fn(&Value) -> Value + Send + Sync;
struct Backend {
    monitor: Arc<Monitor>,
    expected_uploads: Option<usize>,
    requests: Mutex<Vec<Value>>,
    effects: Box<Effects>,
}
impl Backend {
    fn new(
        monitor: Arc<Monitor>,
        expected_uploads: usize,
        effects: impl Fn(&Value) -> Value + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            monitor,
            expected_uploads: Some(expected_uploads),
            requests: Mutex::new(Vec::new()),
            effects: Box::new(effects),
        })
    }
}
impl ManagedBackend for Backend {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            if let Some(expected) = self.expected_uploads {
                assert_eq!(
                    self.monitor.completed.load(Ordering::SeqCst),
                    expected,
                    "interception began before upfront uploads settled"
                );
            }
            self.requests.lock().unwrap().push(request.clone());
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":(self.effects)(&request)}}),
            )
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}
struct Source {
    bytes: Option<Vec<u8>>,
    reads: Arc<AtomicUsize>,
}
impl BodyStream for Source {
    fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let bytes = self.bytes.take();
        Box::pin(async move { Ok(bytes) })
    }
}
fn source(bytes: Vec<u8>) -> (Attachment, Arc<AtomicUsize>) {
    let reads = Arc::new(AtomicUsize::new(0));
    (
        Attachment::lazy(Source {
            bytes: Some(bytes),
            reads: reads.clone(),
        }),
        reads,
    )
}
fn input(parts: Vec<PartInput<Attachment>>) -> HostInput<UserMessageOutboundInput, Attachment> {
    UserMessageOutboundInput::new(
        serde_json::from_value(json!({"channel":"chat","messages":[]})).unwrap(),
    )
    .with_sources()
    .with_message_messages(vec![MessageInput::new(
        "message",
        CanonicalMessageRole::Assistant,
        parts,
    )])
}
fn subscription(endpoint: &str, token: &str) -> Value {
    json!({"events":["user.message.outbound"],"mode":"intercept","timeoutMs":5000,"failurePolicy":"fail-closed","content":{"default":"body"},"upload":{"endpoint":endpoint,"maxBytes":1024,"timeoutMs":4000,"auth":{"type":"bearer","tokenRef":token}}})
}
fn options() -> HooksOptions {
    HooksOptions::new(
        "urn:coordinated-uploads",
        [(
            "user.message.outbound".into(),
            EventGrant::intercept(Capabilities::none().deny().modify("content", true, true)),
        )]
        .into(),
    )
}
fn registration(routes: Vec<(&str, Vec<Value>)>) -> Value {
    json!({"protocolVersion":"draft","hooks":routes.into_iter().map(|(id, subscriptions)| json!({"id":id,"transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},"subscriptions":subscriptions})).collect::<Vec<_>>()})
}
fn configure(routes: Vec<(&str, Vec<Value>, Arc<Backend>)>, cap: usize) -> Hooks {
    let mut opts = options();
    opts.max_concurrent_uploads = cap;
    opts.backend.allow_loopback_http = true;
    for token in ["first", "second", "third", "broken"] {
        opts.backend.credentials.insert(token.into(), token.into());
    }
    let config = registration(
        routes
            .iter()
            .map(|(id, subs, _)| (*id, subs.clone()))
            .collect(),
    );
    for (id, _, backend) in routes {
        opts = opts.with_backend(id, backend);
    }
    Hooks::new(config, opts).unwrap()
}
fn parts(request: &Value) -> &Value {
    &request["params"]["event"]["message"]["messages"][0]["parts"]
}
fn assert_receipt(part: &Value, transfer: &Transfer) {
    assert_eq!(part["body"], json!({"ref":transfer.receipt["ref"]}));
    assert_eq!(transfer.receipt["size"], transfer.bytes.len());
}

#[test]
fn concurrency_option_defaults_to_eight_and_rejects_zero() {
    let mut opts = options();
    assert_eq!(opts.max_concurrent_uploads, 8);
    opts.max_concurrent_uploads = 0;
    let backend = Backend::new(Arc::new(Monitor::default()), 0, |_| json!([]));
    let mut route = subscription("https://upload.example.test/upload", "first");
    route["content"]["default"] = json!("metadata");
    opts = opts.with_backend("org.example.option", backend);
    let error = Hooks::new(
        registration(vec![("org.example.option", vec![route])]),
        opts,
    )
    .err()
    .expect("zero concurrency must be rejected");
    assert!(error.to_string().contains("positive"), "{error}");
}

#[tokio::test]
async fn upfront_fanout_overlaps_within_configured_cap_and_captures_once() {
    for cap in [1, 2, 3] {
        let fixture = Fixture::new(3, cap);
        let backend = Backend::new(fixture.monitor.clone(), 3, |_| json!([]));
        let hooks = configure(
            vec![(
                "org.example.fanout",
                ["first", "second", "third"]
                    .iter()
                    .map(|token| subscription(&fixture.endpoint, token))
                    .collect(),
                backend.clone(),
            )],
            cap,
        );
        let bytes = vec![0, 255, 13, 10, 128];
        let (attachment, reads) = source(bytes.clone());
        let boundary = hooks.user_message_outbound(input(vec![
            PartInput::inline_text("caption"),
            PartInput::owned_attachment("binary", "application/octet-stream", attachment),
        ]));
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        fn assert_send<T: Send>(_: &T) {}
        let future = std::future::IntoFuture::into_future(boundary);
        assert_send(&future);
        let result = future.await.unwrap();
        assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "one chunk and EOF across all subscribers"
        );
        assert_eq!(fixture.monitor.peak.load(Ordering::SeqCst), cap);
        {
            let requests = backend.requests.lock().unwrap();
            let transfers = fixture.monitor.transfers.lock().unwrap();
            assert_eq!(requests.len(), 3);
            for (request, token) in requests.iter().zip(["first", "second", "third"]) {
                let transfer = transfers
                    .iter()
                    .find(|t| t.token == format!("Bearer {token}"))
                    .unwrap();
                assert_eq!(transfer.bytes, bytes);
                assert_eq!(parts(request)[0]["text"], "caption");
                assert_receipt(&parts(request)[1], transfer);
            }
        }
        hooks.shutdown().await.unwrap();
        fixture.finish();
    }
}

#[tokio::test]
async fn equal_endpoint_different_backends_keep_credentials_and_receipts_scoped() {
    let fixture = Fixture::new(2, 2);
    let first = Backend::new(fixture.monitor.clone(), 2, |_| json!([]));
    let second = Backend::new(fixture.monitor.clone(), 2, |_| json!([]));
    let hooks = configure(
        vec![
            (
                "org.example.first",
                vec![subscription(&fixture.endpoint, "first")],
                first.clone(),
            ),
            (
                "org.example.second",
                vec![subscription(&fixture.endpoint, "second")],
                second.clone(),
            ),
        ],
        2,
    );
    let (attachment, reads) = source(vec![7, 0, 255]);
    let result = hooks
        .user_message_outbound(input(vec![PartInput::owned(
            attachment,
            "application/octet-stream",
        )]))
        .await
        .unwrap();
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    {
        let transfers = fixture.monitor.transfers.lock().unwrap();
        let a = transfers
            .iter()
            .find(|t| t.token == "Bearer first")
            .unwrap();
        let b = transfers
            .iter()
            .find(|t| t.token == "Bearer second")
            .unwrap();
        assert_ne!(a.receipt["ref"], b.receipt["ref"]);
        assert_receipt(&parts(&first.requests.lock().unwrap()[0])[0], a);
        assert_receipt(&parts(&second.requests.lock().unwrap()[0])[0], b);
    }
    hooks.shutdown().await.unwrap();
    fixture.finish();
}

#[tokio::test]
async fn failed_open_upload_does_not_poison_healthy_subscription() {
    let fixture = Fixture::new(2, 2);
    let backend = Backend::new(fixture.monitor.clone(), 2, |_| json!([]));
    let mut failed = subscription(&fixture.endpoint, "broken");
    failed["failurePolicy"] = json!("fail-open");
    let hooks = configure(
        vec![(
            "org.example.failure",
            vec![failed, subscription(&fixture.endpoint, "second")],
            backend.clone(),
        )],
        2,
    );
    let (attachment, reads) = source(vec![1, 2, 3]);
    let result = hooks
        .user_message_outbound(input(vec![PartInput::owned(
            attachment,
            "application/octet-stream",
        )]))
        .initial_state(Permission::Allow)
        .await
        .unwrap();
    assert_eq!(result.permission(), Permission::Allow);
    assert!(!result.diagnostics.is_empty());
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    {
        let requests = backend.requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "failed route must not invoke its backend"
        );
        let transfers = fixture.monitor.transfers.lock().unwrap();
        assert_receipt(
            &parts(&requests[0])[0],
            transfers
                .iter()
                .find(|t| t.token == "Bearer second")
                .unwrap(),
        );
    }
    hooks.shutdown().await.unwrap();
    fixture.finish();
}

#[tokio::test]
async fn denial_reuses_upfront_receipt_for_later_interceptor_observation() {
    let fixture = Fixture::new(2, 2);
    let deny = Backend::new(
        fixture.monitor.clone(),
        2,
        |_| json!([{"type":"deny","reason":"policy"}]),
    );
    let later = Backend::new(fixture.monitor.clone(), 2, |_| json!([]));
    let hooks = configure(
        vec![
            (
                "org.example.deny",
                vec![subscription(&fixture.endpoint, "first")],
                deny.clone(),
            ),
            (
                "org.example.later",
                vec![subscription(&fixture.endpoint, "second")],
                later.clone(),
            ),
        ],
        2,
    );
    let result = hooks
        .user_message_outbound(input(vec![PartInput::owned(
            Attachment::bytes(vec![42]),
            "application/octet-stream",
        )]))
        .await
        .unwrap();
    assert_eq!(result.permission(), Permission::Deny);
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    {
        let requests = later.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "hooks/observe");
        let transfers = fixture.monitor.transfers.lock().unwrap();
        assert_eq!(transfers.len(), 2, "observation must not upload again");
        assert_receipt(
            &parts(&requests[0])[0],
            transfers
                .iter()
                .find(|t| t.token == "Bearer second")
                .unwrap(),
        );
    }
    hooks.shutdown().await.unwrap();
    fixture.finish();
}

#[tokio::test]
async fn metadata_omit_unmatched_and_no_routes_leave_lazy_sources_unread() {
    for mode in ["metadata", "omit", "unmatched", "no-routes"] {
        let backend = Backend::new(Arc::new(Monitor::default()), 0, |_| json!([]));
        let mut route = subscription("http://127.0.0.1:9/upload", "first");
        if mode == "metadata" || mode == "omit" {
            route["content"]["default"] = json!(mode);
        }
        if mode == "unmatched" {
            route["filters"] = json!({"paths":["/never/**"]});
        }
        let mut opts = options().with_backend("org.example.unread", backend.clone());
        opts.backend.allow_loopback_http = true;
        opts.backend
            .credentials
            .insert("first".into(), "first".into());
        if mode == "no-routes" {
            route["events"] = json!(["tool.before"]);
            opts.capabilities.insert(
                "tool.before".into(),
                EventGrant::intercept(Capabilities::none()),
            );
        }
        let routes = vec![("org.example.unread", vec![route])];
        let hooks = Hooks::new(registration(routes), opts).unwrap();
        let (attachment, reads) = source(vec![99]);
        let result = hooks
            .user_message_outbound(input(vec![PartInput::owned(
                attachment,
                "application/octet-stream",
            )]))
            .await
            .unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0, "{mode}");
        assert!(
            result.diagnostics.is_empty(),
            "{mode}: {:?}",
            result.diagnostics
        );
        drop(result);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        hooks.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn removing_attachment_after_upfront_upload_is_tolerated() {
    let fixture = Fixture::new(2, 2);
    let remove = Backend::new(fixture.monitor.clone(), 2, |request| {
        let mut messages = request["params"]["event"]["message"]["messages"].clone();
        messages[0]["parts"] = json!([parts(request)[0].clone()]);
        json!([{"type":"modify","target":"content","operation":"replace","value":messages}])
    });
    let later = Backend::new(fixture.monitor.clone(), 2, |_| json!([]));
    let hooks = configure(
        vec![
            (
                "org.example.remove",
                vec![subscription(&fixture.endpoint, "first")],
                remove,
            ),
            (
                "org.example.later",
                vec![subscription(&fixture.endpoint, "second")],
                later.clone(),
            ),
        ],
        2,
    );
    let result = hooks
        .user_message_outbound(input(vec![
            PartInput::inline_text("keep"),
            PartInput::owned_attachment(
                "removed",
                "application/octet-stream",
                Attachment::bytes(vec![5]),
            ),
        ]))
        .await
        .unwrap();
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    {
        let requests = later.requests.lock().unwrap();
        assert_eq!(parts(&requests[0]).as_array().unwrap().len(), 1);
        assert_eq!(parts(&requests[0])[0]["text"], "keep");
    }
    hooks.shutdown().await.unwrap();
    fixture.finish();
}

#[tokio::test]
async fn reordering_parts_keeps_owner_receipts_bound_to_attachment_identity() {
    let fixture = Fixture::new(4, 2);
    let reorder = Backend::new(fixture.monitor.clone(), 4, |request| {
        let mut messages = request["params"]["event"]["message"]["messages"].clone();
        messages[0]["parts"].as_array_mut().unwrap().reverse();
        json!([{"type":"modify","target":"content","operation":"replace","value":messages}])
    });
    let later = Backend::new(fixture.monitor.clone(), 4, |_| json!([]));
    let hooks = configure(
        vec![
            (
                "org.example.reorder",
                vec![subscription(&fixture.endpoint, "first")],
                reorder,
            ),
            (
                "org.example.later",
                vec![subscription(&fixture.endpoint, "second")],
                later.clone(),
            ),
        ],
        2,
    );
    let result = hooks
        .user_message_outbound(input(vec![
            PartInput::owned_attachment(
                "a",
                "application/octet-stream",
                Attachment::bytes(vec![1]),
            ),
            PartInput::owned_attachment(
                "b",
                "application/octet-stream",
                Attachment::bytes(vec![2]),
            ),
        ]))
        .await
        .unwrap();
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    {
        let requests = later.requests.lock().unwrap();
        let transfers = fixture.monitor.transfers.lock().unwrap();
        for (index, id, bytes) in [(0, "b", vec![2]), (1, "a", vec![1])] {
            assert_eq!(parts(&requests[0])[index]["id"], id);
            assert_receipt(
                &parts(&requests[0])[index],
                transfers
                    .iter()
                    .find(|t| t.token == "Bearer second" && t.bytes == bytes)
                    .unwrap(),
            );
        }
    }
    assert_eq!(
        result
            .content
            .read("/message/messages/0/parts/0")
            .await
            .unwrap()
            .as_ref(),
        &[2]
    );
    assert_eq!(
        result
            .content
            .read("/message/messages/0/parts/1")
            .await
            .unwrap()
            .as_ref(),
        &[1]
    );
    hooks.shutdown().await.unwrap();
    fixture.finish();
}

#[tokio::test]
async fn simultaneous_boundaries_share_the_hooks_transfer_cap() {
    let fixture = Fixture::new(4, 2);
    let mut backend = Backend::new(fixture.monitor.clone(), 4, |_| json!([]));
    // Each boundary waits for its own routes, not the other operation's uploads.
    Arc::get_mut(&mut backend).unwrap().expected_uploads = None;
    let hooks = configure(
        vec![(
            "org.example.shared",
            vec![
                subscription(&fixture.endpoint, "first"),
                subscription(&fixture.endpoint, "second"),
            ],
            backend.clone(),
        )],
        2,
    );
    let first = hooks.user_message_outbound(input(vec![PartInput::owned(
        Attachment::bytes(vec![1]),
        "application/octet-stream",
    )]));
    let second = hooks.user_message_outbound(input(vec![PartInput::owned(
        Attachment::bytes(vec![2]),
        "application/octet-stream",
    )]));
    let (a, b) = futures::join!(
        std::future::IntoFuture::into_future(first),
        std::future::IntoFuture::into_future(second)
    );
    assert!(a.unwrap().diagnostics.is_empty());
    assert!(b.unwrap().diagnostics.is_empty());
    assert_eq!(fixture.monitor.peak.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.monitor.completed.load(Ordering::SeqCst), 4);
    assert_eq!(backend.requests.lock().unwrap().len(), 4);
    hooks.shutdown().await.unwrap();
    fixture.finish();
}

#[tokio::test]
async fn fail_closed_upload_is_applied_at_its_route_after_earlier_interception() {
    let fixture = Fixture::new(2, 2);
    let earlier = Backend::new(fixture.monitor.clone(), 2, |request| {
        let mut messages = request["params"]["event"]["message"]["messages"].clone();
        messages[0]["parts"][0]["text"] = json!("earlier interceptor ran");
        json!([{"type":"modify","target":"content","operation":"replace","value":messages}])
    });
    let failing = Backend::new(fixture.monitor.clone(), 2, |_| json!([]));
    let hooks = configure(
        vec![
            (
                "org.example.earlier",
                vec![subscription(&fixture.endpoint, "first")],
                earlier.clone(),
            ),
            (
                "org.example.failing",
                vec![subscription(&fixture.endpoint, "broken")],
                failing.clone(),
            ),
        ],
        2,
    );
    let result = hooks
        .user_message_outbound(input(vec![
            PartInput::inline_text("original"),
            PartInput::owned(Attachment::bytes(vec![9]), "application/octet-stream"),
        ]))
        .await
        .unwrap();
    assert_eq!(result.permission(), Permission::Deny);
    assert_eq!(earlier.requests.lock().unwrap().len(), 1);
    assert!(failing.requests.lock().unwrap().is_empty());
    assert_eq!(
        result.effective_event["message"]["messages"][0]["parts"][0]["text"],
        "earlier interceptor ran"
    );
    assert_eq!(result.diagnostics.len(), 1);
    assert!(result.diagnostics[0].synthetic_denial);
    hooks.shutdown().await.unwrap();
    fixture.finish();
}
