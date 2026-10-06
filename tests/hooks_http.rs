#![cfg(feature = "reqwest")]

use agenthooksprotocol::{
    client::{Decision, ToolContext},
    generated::Registration,
    hooks::{Capabilities, EventGrant, Hooks, HooksOptions},
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
    let grants = [(
        "tool.before".into(),
        EventGrant::intercept(
            Capabilities::none()
                .allow()
                .deny()
                .return_value()
                .modify_input(),
        )
        .with_observe(),
    )]
    .into();
    let mut options = HooksOptions::new("https://host.test/http", grants);
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
        .initial_state(Decision::Allow);
    assert!(requests.lock().unwrap().is_empty());
    let modified = lazy.await.unwrap();
    assert!(
        modified.outcome.failures.is_empty(),
        "{:?}",
        modified.outcome.failures
    );
    assert!(modified.outcome.can_execute());
    let effective = modified.input.unwrap();
    assert_eq!(effective.command, "safe");
    assert_eq!(effective.timeout_ms, 25);
    let cached = hooks
        .tool_input(Input {
            command: "cached".into(),
            timeout_ms: 100,
        })
        .capabilities(Capabilities::none().allow().return_value())
        .context(context())
        .initial_state(Decision::Allow)
        .await
        .unwrap();
    assert_eq!(
        cached.outcome.supplied_result(),
        Some(&json!({"cached":true}))
    );
    assert!(!cached.outcome.can_execute());
    let denied = hooks
        .tool_input(Input {
            command: "denied".into(),
            timeout_ms: 100,
        })
        .context(context())
        .initial_state(Decision::Allow)
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
            .capabilities(Capabilities::none().ask())
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
