#![cfg(feature = "reqwest")]
use agenthooksprotocol::{
    Attachment, Hooks, Permission,
    adapters::registered::ManagedBackend,
    body::{BodyChunkFuture, BodyStream},
    client::{HookError, LocalFuture},
    content::{AuthorizedScope, UploadError, UploadReceiver},
    ergonomic_inputs::{PartInput, ToolBeforeInput},
    generated::ToolBeforeInputOrigin,
    hooks::{Capabilities, EventGrant, HooksOptions},
    transport::Request,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

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
    bytes: Option<Vec<u8>>,
    reads: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}
impl BodyStream for Source {
    fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let bytes = self.bytes.take();
        Box::pin(async move { Ok(bytes) })
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
fn authorize(request: &Request) -> Result<AuthorizedScope, UploadError> {
    match request.headers.get("authorization").map(String::as_str) {
        Some("Bearer first-upload") if request.uri.ends_with("/first") => {
            Ok(AuthorizedScope::new("first"))
        }
        Some("Bearer second-upload") if request.uri.ends_with("/second") => {
            Ok(AuthorizedScope::new("second"))
        }
        _ => Err(UploadError::Unauthorized),
    }
}

#[tokio::test]
async fn named_source_snapshots_once_and_uploads_to_each_independently_authorized_destination() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server_base = base.clone();
    let expected = vec![0, 255, 13, 10, 128];
    let server_bytes = expected.clone();
    let allocated = Arc::new(Mutex::new(Vec::<Value>::new()));
    let recorded = allocated.clone();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        for path in ["/first", "/second"] {
            let mut receiver =
                UploadReceiver::new(authorize, format!("{server_base}{path}"), 64, 128, 4);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "upload fixture timed out");
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => panic!("accept failed: {e}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(&socket);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, format!("POST {path} HTTP/1.1\r\n"));
            let mut headers = BTreeMap::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.split_once(':').unwrap();
                headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
            }
            let size: usize = headers["content-length"].parse().unwrap();
            assert!(size <= 64);
            let mut bytes = vec![0; size];
            reader.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, server_bytes);
            let response = receiver.handle(Request {
                method: "POST".into(),
                uri: format!("{server_base}{path}"),
                headers,
                body: bytes,
            });
            assert_eq!(response.status, 201);
            recorded
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&response.body).unwrap());
            write!(socket, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.body.len()).unwrap();
            socket.write_all(&response.body).unwrap();
            socket.flush().unwrap();
        }
    });
    let backend = Arc::new(Backend::default());
    let subscriptions: Vec<_> = ["first", "second"].into_iter().map(|name| json!({
        "events":["tool.before"],"mode":"intercept","timeoutMs":3000,"failurePolicy":"fail-closed","content":{"default":"body"},
        "upload":{"endpoint":format!("{base}/{name}"),"maxBytes":64,"timeoutMs":2000,"auth":{"type":"bearer","tokenRef":name}}
    })).collect();
    let registration = json!({"protocolVersion":"draft","hooks":[{"id":"org.example.upload","transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},"subscriptions":subscriptions}]});
    let mut options = HooksOptions::new(
        "urn:source-test",
        [(
            "tool.before".into(),
            EventGrant::intercept(Capabilities::none().allow().deny()),
        )]
        .into(),
    )
    .with_backend("org.example.upload", backend.clone());
    options.backend.allow_loopback_http = true;
    options
        .backend
        .credentials
        .insert("first".into(), "first-upload".into());
    options
        .backend
        .credentials
        .insert("second".into(), "second-upload".into());
    let hooks = Hooks::new(registration, options).unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let input = ToolBeforeInput::new(
        "call".into(),
        "native".into(),
        json!({"x":1}),
        "read".into(),
        ToolBeforeInputOrigin::Native,
    )
    .with_sources()
    .with_items(vec![PartInput::owned_attachment(
        "binary",
        "application/octet-stream",
        Attachment::lazy(Source {
            bytes: Some(expected.clone()),
            reads: reads.clone(),
            drops: drops.clone(),
        }),
    )]);
    let call = hooks.tool_before(input).initial_state(Permission::Allow);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    let result = call.await.unwrap();
    assert_eq!(
        result.permission(),
        Permission::Allow,
        "{:?}",
        result.diagnostics
    );
    assert!(result.diagnostics.is_empty());
    assert_eq!(reads.load(Ordering::SeqCst), 2); // one chunk and EOF, not twice per destination
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    server.join().unwrap();
    {
        let messages = backend.0.lock().unwrap();
        let references = allocated.lock().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(references.len(), 2);
        for (message, reference) in messages.iter().zip(references.iter()) {
            assert_eq!(
                message["params"]["event"]["items"][0]["body"],
                json!({"ref": reference["ref"]})
            );
            assert_eq!(reference["size"], expected.len());
            assert!(!reference["ref"].as_str().unwrap().contains("ahp-deferred:"));
        }
    }
    hooks.shutdown().await.unwrap();
}
