#![cfg(feature = "reqwest")]
use agenthooksprotocol::capability;

use agenthooksprotocol::{
    Attachment,
    adapters::registered::{AuthChallenge, AuthContext, AuthProvider, BearerCredential},
    client::{HookError, LocalFuture, Permission, ToolContext},
    content::{AuthorizedScope, UploadReceiver},
    generated::{Registration, ToolBeforeInputOrigin},
    hooks::{Hooks, HooksOptions},
    inputs::{PartInput, ToolBeforeInput},
    transport::Request,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Serialize, Deserialize)]
struct Input {
    command: String,
    #[serde(rename = "timeoutMs")]
    timeout_ms: u64,
}
fn context() -> ToolContext {
    ToolContext::new(
        json!({"path":"native","call":{"id":"http-call"},"tool":{"name":"shell","kind":"shell","origin":"native"}}),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_registration_http_dispatch_and_owned_observations() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/hooks", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
    let recorded = requests.clone();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        for _ in 0..6 {
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "HTTP fixture timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept: {e}"),
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
            assert_eq!(line, "POST /hooks HTTP/1.1\r\n");
            let mut headers = std::collections::BTreeMap::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (key, value) = line.split_once(':').unwrap();
                headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
            }
            assert_eq!(headers["authorization"], "Bearer test-http-token");
            assert_eq!(headers["content-type"], "application/json");
            let size: usize = headers["content-length"].parse().unwrap();
            assert!(size <= 65536);
            let mut bytes = vec![0; size];
            reader.read_exact(&mut bytes).unwrap();
            let request: Value = serde_json::from_slice(&bytes).unwrap();
            recorded.lock().unwrap().push(request.clone());
            let command = request["params"]["event"]["tool"]["input"]["command"]
                .as_str()
                .unwrap();
            let effects = match command {
                "modify" => json!([
                    {"type":"modify","target":"input","operation":"replace","value":{"command":"safe","timeoutMs":25}},
                    {"type":"allow"}
                ]),
                "cached" => json!([{"type":"allow"},{"type":"return","value":{"cached":true}}]),
                _ => {
                    json!([{"type":"return","value":{"ignored":true}},{"type":"deny","reason":"test policy"}])
                }
            };
            // A hostile observer reply is rejected as a delivery diagnostic;
            // it cannot change the already-settled execution decision.
            let hostile = request.get("id").is_none() && command == "safe";
            let (status, body) = if request.get("id").is_some() || hostile {
                ("200 OK", serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":effects}})).unwrap())
            } else {
                ("204 No Content", vec![])
            };
            write!(socket, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            socket.write_all(&body).unwrap();
        }
    });
    let config = json!({"protocolVersion":"draft","hooks":[{
        "id":"com.example.http","transport":{"type":"http","url":url},
        "authentication":{"type":"bearer","tokenRef":"policy-token"},
        "subscriptions":[
            {"events":["tool.before"],"mode":"intercept","timeoutMs":2000,"failurePolicy":"fail-closed","content":{"default":"metadata"}},
            {"events":["tool.before"],"mode":"observe","content":{"default":"metadata"}}
        ]
    }]}).to_string();
    let registration = serde_json::from_str::<Registration>(&config).unwrap();
    let grants = capability::HostCapabilities {
        tool_before: Some(
            capability::tool_before()
                .allow()
                .deny()
                .return_result()
                .modify_input(capability::Modify::ReplaceAndMerge)
                .observe(),
        ),
        ..Default::default()
    };
    let mut options = HooksOptions::new(
        "https://host.test/http",
        agenthooksprotocol::hooks::Harness::new("test", "1"),
        grants,
    );
    options.backend.allow_loopback_http = true;
    options
        .backend
        .credentials
        .insert("policy-token".into(), "test-http-token".into());
    options.observation_timeout = Duration::from_secs(2);
    let hooks = Hooks::new(registration, options).unwrap();
    let lazy = hooks
        .tool_input(Input {
            command: "modify".into(),
            timeout_ms: 100,
        })
        .context(context())
        .initial_state(Permission::Allow);
    assert!(requests.lock().unwrap().is_empty());
    let modified = lazy.await.unwrap();
    assert!(
        modified.outcome.failures.is_empty(),
        "{:?}",
        modified.outcome.failures
    );
    assert!(modified.outcome.can_execute());
    let effective = modified.input;
    assert_eq!(effective.command, "safe");
    assert_eq!(effective.timeout_ms, 25);
    let cached = hooks
        .tool_input(Input {
            command: "cached".into(),
            timeout_ms: 100,
        })
        .capabilities(capability::tool_before().allow().return_result())
        .context(context())
        .initial_state(Permission::Allow)
        .await
        .unwrap();
    let Some(value) = cached.outcome.supplied_result() else {
        panic!("missing caller-owned tool result")
    };
    assert_eq!(value, &json!({"cached":true}));
    assert!(!cached.outcome.can_execute());
    let denied = hooks
        .tool_input(Input {
            command: "denied".into(),
            timeout_ms: 100,
        })
        .context(context())
        .initial_state(Permission::Allow)
        .await
        .unwrap();
    assert!(denied.outcome.is_denied());
    assert!(!denied.outcome.can_execute());
    assert!(denied.outcome.supplied_result().is_none());
    // Occurrence-level authority can narrow, never add an ungranted effect.
    assert!(
        hooks
            .tool_input(Input {
                command: "never-sent".into(),
                timeout_ms: 1
            })
            .context(context())
            .capabilities(capability::tool_before().ask())
            .await
            .is_err()
    );
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.get("id").is_some())
            .count(),
        3
    );
    let report = hooks.wait_until_idle().await;
    assert_eq!(report.delivered, 2);
    assert_eq!(report.failures.len(), 1);
    assert!(modified.outcome.can_execute());
    let report = tokio::time::timeout(Duration::from_secs(3), hooks.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.delivered, 2);
    assert_eq!(report.failures.len(), 1);
    server.join().unwrap();
    let requests = requests.lock().unwrap();
    let mut ids = std::collections::BTreeSet::new();
    for request in requests.iter() {
        let event = &request["params"]["event"];
        assert_eq!(event["source"], "https://host.test/http");
        assert!(event["id"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(event["time"].as_str().is_some_and(|s| !s.is_empty()));
        if request.get("id").is_some() {
            assert!(ids.insert(event["id"].as_str().unwrap()));
            if event["tool"]["input"]["command"] == "cached" {
                assert_eq!(
                    request["params"]["capabilities"]["effects"],
                    json!(["allow", "return"])
                );
            }
            assert!(
                request["params"]["capabilities"]
                    .get("elicitation")
                    .is_none()
            );
        } else {
            assert!(request["params"].get("capabilities").is_none());
            assert!(request["params"].get("state").is_none());
        }
    }
}

struct Received {
    /// `hooks/*` method, or `upload` for the advertised upload destination.
    method: String,
    headers: std::collections::BTreeMap<String, String>,
}

/// Answers `count` requests: event requests on `/hooks`, uploads on `/upload`.
fn fixture(
    listener: TcpListener,
    count: usize,
    subscription: Value,
) -> thread::JoinHandle<Vec<Received>> {
    let base = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut receiver = UploadReceiver::new(
            |_: &Request| Ok(AuthorizedScope::new("upload")),
            format!("{base}/upload"),
            64,
            128,
            4,
        );
        let mut received = Vec::new();
        for _ in 0..count {
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "discovery fixture timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("{e}"),
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
            let path = line
                .strip_prefix("POST ")
                .and_then(|rest| rest.strip_suffix(" HTTP/1.1\r\n"))
                .unwrap()
                .to_owned();
            let mut headers = std::collections::BTreeMap::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (key, value) = line.split_once(':').unwrap();
                headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
            }
            let mut bytes = vec![0; headers["content-length"].parse::<usize>().unwrap()];
            reader.read_exact(&mut bytes).unwrap();
            let (status, method, body) = if path == "/upload" {
                let response = receiver.handle(Request {
                    method: "POST".into(),
                    uri: format!("{base}{path}"),
                    headers: headers.clone(),
                    body: bytes,
                });
                assert_eq!(response.status, 201);
                ("201 Created", "upload".to_owned(), response.body)
            } else {
                assert_eq!(path, "/hooks");
                let request: Value = serde_json::from_slice(&bytes).unwrap();
                let result = if request["method"] == "hooks/configuration" {
                    json!({"protocolVersion":"draft","configuration":{"subscriptions":[subscription]}})
                } else {
                    json!({"protocolVersion":"draft","effects":[]})
                };
                let body = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
                )
                .unwrap();
                (
                    "200 OK",
                    request["method"].as_str().unwrap().to_owned(),
                    body,
                )
            };
            write!(socket, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            socket.write_all(&body).unwrap();
            received.push(Received { method, headers });
        }
        received
    })
}

fn body_subscription(upload: Value) -> Value {
    json!({"events":["tool.before"],"mode":"intercept","timeoutMs":3000,"failurePolicy":"fail-closed","content":{"default":"body"},"upload":upload})
}

fn upload_settings(base: &str, auth: Option<Value>) -> Value {
    let mut upload = json!({"endpoint":format!("{base}/upload"),"timeoutMs":2000,"maxBytes":64});
    if let Some(auth) = auth {
        upload["auth"] = auth;
    }
    upload
}

fn upload_options() -> HooksOptions {
    let mut options = HooksOptions::new(
        "https://host.test/http",
        agenthooksprotocol::Harness::new("test", "1"),
        capability::HostCapabilities {
            tool_before: Some(capability::tool_before().allow().deny()),
            ..Default::default()
        },
    );
    options.backend.allow_loopback_http = true;
    options.observation_timeout = Duration::from_secs(3);
    options
}

/// Dispatches one selected binary body; every case here leaves execution allowed.
async fn dispatch_body(hooks: &Hooks) {
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
        Attachment::bytes(vec![0, 255, 13, 10, 128]),
    )]);
    let result = hooks
        .tool_before(input)
        .initial_state(Permission::Allow)
        .await
        .unwrap();
    assert_eq!(
        result.permission(),
        Permission::Allow,
        "{:?}",
        result.diagnostics
    );
    assert!(result.diagnostics.is_empty());
}

fn configured_transport(url: String) -> Value {
    json!({"type":"http","url":url,"headers":{"Authorization":"Bearer configured-token","X-Backend":"configuration-test"}})
}

#[tokio::test(flavor = "current_thread")]
async fn discovery_uses_event_endpoint_authentication_and_configured_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/hooks", listener.local_addr().unwrap());
    let server = fixture(
        listener,
        2,
        json!({"events":["tool.before"],"mode":"intercept","timeoutMs":3000,"failurePolicy":"fail-closed","content":{"default":"metadata"}}),
    );
    let registration = json!({"protocolVersion":"draft","hooks":[{
        "id":"com.example.configuration","transport":configured_transport(url)
    }]});
    let hooks = Hooks::new(registration, upload_options()).unwrap();
    hooks
        .tool_input(Input {
            command: "safe".into(),
            timeout_ms: 100,
        })
        .context(context())
        .await
        .unwrap();
    hooks.shutdown().await.unwrap();
    assert!(hooks.intercepts(agenthooksprotocol::EventType::ToolBefore));
    let received = server.join().unwrap();
    assert_eq!(received[0].method, "hooks/configuration");
    assert_eq!(received[1].method, "hooks/intercept");
    for request in &received {
        assert_eq!(request.headers["authorization"], "Bearer configured-token");
        assert_eq!(request.headers["x-backend"], "configuration-test");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn discovered_upload_uses_advertised_destination_with_configured_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = fixture(listener, 3, body_subscription(upload_settings(&base, None)));
    let registration = json!({"protocolVersion":"draft","hooks":[{
        "id":"com.example.configuration","transport":configured_transport(format!("{base}/hooks"))
    }]});
    let hooks = Hooks::new(registration, upload_options()).unwrap();
    dispatch_body(&hooks).await;
    hooks.shutdown().await.unwrap();
    let received = server.join().unwrap();
    let methods: Vec<_> = received.iter().map(|r| r.method.as_str()).collect();
    assert_eq!(
        methods,
        ["hooks/configuration", "upload", "hooks/intercept"]
    );
    assert_eq!(
        received[1].headers["authorization"],
        "Bearer configured-token"
    );
    assert_eq!(received[1].headers["x-backend"], "configuration-test");
}

struct NoSecretResolution;
impl AuthProvider for NoSecretResolution {
    fn credential(
        &self,
        _: AuthContext,
    ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
        panic!("a skipped backend must not reach the auth provider")
    }
    fn challenge(
        &self,
        _: AuthContext,
        _: AuthChallenge,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        panic!("a skipped backend must not reach the auth provider")
    }
}

#[tokio::test(flavor = "current_thread")]
async fn discovered_local_secret_reference_skips_backend_before_resolution_or_upload() {
    for auth in [
        json!({"type":"bearer","tokenEnv":"CARGO_PKG_NAME"}),
        json!({"type":"bearer","tokenRef":"available"}),
        json!({"type":"oauth","issuer":"https://issuer.example","resource":"https://uploads.example","clientId":"client","flow":"client_credentials","clientSecretRef":"available"}),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let unexpected = listener.try_clone().unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = fixture(
            listener,
            1,
            body_subscription(upload_settings(&base, Some(auth))),
        );
        let registration = json!({"protocolVersion":"draft","hooks":[{
            "id":"com.example.configuration","transport":configured_transport(format!("{base}/hooks"))
        }]});
        let mut options = upload_options();
        options.backend.auth_provider = Some(Arc::new(NoSecretResolution));
        options
            .backend
            .credentials
            .insert("available".into(), "resolved-secret".into());
        let hooks = Hooks::new(registration, options).unwrap();
        dispatch_body(&hooks).await;
        hooks.shutdown().await.unwrap();
        assert!(!hooks.intercepts(agenthooksprotocol::EventType::ToolBefore));
        let received = server.join().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].method, "hooks/configuration");
        assert_eq!(
            unexpected.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_upload_resolves_token_env() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    // A read-only environment variable avoids process-global mutation in concurrent tests.
    let upload = upload_settings(
        &base,
        Some(json!({"type":"bearer","tokenEnv":"CARGO_PKG_NAME"})),
    );
    let server = fixture(listener, 2, Value::Null);
    let registration = json!({"protocolVersion":"draft","hooks":[{
        "id":"com.example.configuration",
        "transport":{"type":"http","url":format!("{base}/hooks")},
        "subscriptions":[body_subscription(upload)]
    }]});
    let hooks = Hooks::new(registration, upload_options()).unwrap();
    dispatch_body(&hooks).await;
    hooks.shutdown().await.unwrap();
    let received = server.join().unwrap();
    let methods: Vec<_> = received.iter().map(|r| r.method.as_str()).collect();
    assert_eq!(methods, ["upload", "hooks/intercept"]);
    assert_eq!(
        received[0].headers["authorization"],
        concat!("Bearer ", env!("CARGO_PKG_NAME"))
    );
    assert!(!received[1].headers.contains_key("authorization"));
}
