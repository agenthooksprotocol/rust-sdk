use agenthooksprotocol::adapters::registered::{BackendOptions, from_registration};
use serde_json::json;
#[cfg(any(feature = "reqwest", feature = "tokio-process"))]
use std::time::Duration;

#[test]
fn authentication_and_network_policy_fail_closed() {
    let options = BackendOptions::default();
    for authentication in [
        json!({"type":"oauth"}),
        json!({"type":"mtls"}),
        json!({"type":"workload"}),
        json!({"type":"bearer","tokenRef":"missing"}),
        json!({"type":"bearer","tokenRef":"a","tokenEnv":"B"}),
    ] {
        let backend = json!({"transport":{"type":"http","url":"https://example.com/hook"},"authentication":authentication});
        assert!(from_registration(&backend, &options).is_err());
    }
    assert!(
        from_registration(
            &json!({"transport":{"type":"http","url":"https://example.com"}}),
            &options
        )
        .is_err()
    );
    let anonymous = BackendOptions {
        allow_anonymous_http: true,
        ..options
    };
    for url in [
        "http://example.com",
        "http://127.0.0.1",
        "https://secret@example.com",
        "https://example.com/#fragment",
    ] {
        assert!(
            from_registration(&json!({"transport":{"type":"http","url":url}}), &anonymous).is_err()
        );
    }
    assert!(from_registration(&json!({"transport":{"type":"unknown"}}), &anonymous).is_err());
}
#[cfg(not(feature = "reqwest"))]
#[test]
fn http_feature_is_explicit() {
    let err = from_registration(
        &json!({"transport":{"type":"http","url":"https://example.com"}}),
        &BackendOptions {
            allow_anonymous_http: true,
            ..Default::default()
        },
    )
    .err()
    .unwrap();
    assert!(err.0.contains("reqwest"));
}
#[cfg(not(feature = "tokio-process"))]
#[test]
fn stdio_feature_is_explicit() {
    let err = from_registration(
        &json!({"transport":{"type":"stdio","command":"absent","lifecycle":"persistent"}}),
        &BackendOptions::default(),
    )
    .err()
    .unwrap();
    assert!(err.0.contains("tokio-process"));
}
#[cfg(any(feature = "reqwest", feature = "tokio-process"))]
fn request() -> serde_json::Value {
    json!({"jsonrpc":"2.0","id":"evt_demo","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"evt_demo","source":"urn:example:demo","type":"tool.before","time":"2026-08-24T08:51:14Z","session":{"id":"sess_demo","cwd":"/repo","workspaceRoots":["/repo"]},"tool":{"name":"Bash","kind":"shell","input":{"command":"echo hello"},"origin":"native"},"call":{"id":"call_demo"},"path":"example"},"capabilities":{"effects":["deny"]}}})
}
#[cfg(any(feature = "reqwest", feature = "tokio-process"))]
fn notification() -> serde_json::Value {
    let mut request = request();
    request.as_object_mut().unwrap().remove("id");
    request["method"] = json!("hooks/observe");
    request["params"]
        .as_object_mut()
        .unwrap()
        .remove("capabilities");
    request
}
#[cfg(feature = "reqwest")]
mod http {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };
    fn fixture(
        status: u16,
        media: &str,
        body: &str,
        delay: Duration,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/hooks", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let task = thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut stream = loop {
                if let Ok((stream, _)) = listener.accept() {
                    break stream;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "no HTTP request arrived"
                );
                thread::sleep(Duration::from_millis(5));
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let n = stream.read(&mut chunk).unwrap();
                assert_ne!(n, 0);
                bytes.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&bytes);
                if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                    let len: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .and_then(|v| v.parse().ok())
                        })
                        .unwrap();
                    if body.len() >= len {
                        break;
                    }
                }
            }
            thread::sleep(delay);
            let _ = stream.write_all(response.as_bytes());
            String::from_utf8(bytes).unwrap()
        });
        (url, task)
    }
    fn options() -> BackendOptions {
        BackendOptions {
            credentials: [("fixture".into(), "private-token".into())].into(),
            allow_loopback_http: true,
            ..Default::default()
        }
    }
    fn backend(
        url: String,
    ) -> std::rc::Rc<dyn agenthooksprotocol::adapters::registered::ManagedBackend> {
        from_registration(&json!({"transport":{"type":"http","url":url},"authentication":{"type":"bearer","tokenRef":"fixture"}}), &options()).unwrap()
    }
    #[tokio::test]
    async fn real_http_and_terminal_shutdown() {
        let body = json!({"jsonrpc":"2.0","id":"evt_demo","result":{"protocolVersion":"draft","effects":[]}}).to_string();
        let (url, task) = fixture(
            200,
            "application/json; charset=utf-8",
            &body,
            Duration::ZERO,
        );
        let backend = backend(url);
        assert_eq!(
            backend
                .call(request(), Duration::from_secs(3))
                .await
                .unwrap()["id"],
            "evt_demo"
        );
        let received = task.join().unwrap();
        assert!(
            received
                .to_ascii_lowercase()
                .contains("authorization: bearer private-token")
        );
        backend.shutdown().await.unwrap();
        backend.shutdown().await.unwrap();
        assert!(
            backend
                .call(request(), Duration::from_secs(1))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn strict_http_acknowledgments_media_correlation_and_deadline() {
        let good = json!({"jsonrpc":"2.0","id":"evt_demo","result":{"protocolVersion":"draft","effects":[]}}).to_string();
        for (status, media, body, notify, success) in [
            (202, "text/plain", "", true, true),
            (204, "text/plain", "", true, true),
            (200, "application/json", "{}", true, false),
            (202, "application/json", "{}", true, false),
            (200, "text/plain", good.as_str(), false, false),
            (
                200,
                "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":\"wrong\",\"result\":{}}",
                false,
                false,
            ),
        ] {
            let (url, task) = fixture(status, media, body, Duration::ZERO);
            let backend = backend(url);
            assert_eq!(
                backend
                    .call(
                        if notify { notification() } else { request() },
                        Duration::from_secs(3)
                    )
                    .await
                    .is_ok(),
                success
            );
            task.join().unwrap();
            backend.shutdown().await.unwrap();
        }
        let (url, task) = fixture(200, "application/json", &good, Duration::from_millis(300));
        let backend = backend(url);
        let start = std::time::Instant::now();
        let err = backend
            .call(request(), Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(!err.0.contains("private-token"));
        task.join().unwrap();
    }
    #[test]
    fn construction_is_runtime_free_and_lazy() {
        let backend = backend("http://127.0.0.1:1/no-listener".into());
        futures::executor::block_on(backend.shutdown()).unwrap();
    }
}
#[cfg(feature = "tokio-process")]
mod stdio {
    use super::*;
    fn backend(
        script: &str,
        lifecycle: &str,
    ) -> std::rc::Rc<dyn agenthooksprotocol::adapters::registered::ManagedBackend> {
        from_registration(&json!({"transport":{"type":"stdio","command":"python3","args":["-u","-c",script],"lifecycle":lifecycle}}), &BackendOptions::default()).unwrap()
    }
    #[test]
    fn construction_and_unstarted_shutdown_need_no_runtime() {
        let backend = from_registration(&json!({"transport":{"type":"stdio","command":"/no/such/program","lifecycle":"persistent"}}), &BackendOptions::default()).unwrap();
        futures::executor::block_on(backend.shutdown()).unwrap();
    }
    #[tokio::test]
    async fn persistent_and_per_event_calls_and_notifications() {
        let script = "import sys,json\nfor line in sys.stdin:\n r=json.loads(line)\n if 'id' in r: print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':{'protocolVersion':'draft','effects':[]}}),flush=True)\n";
        for lifecycle in ["persistent", "per_event"] {
            let backend = backend(script, lifecycle);
            for _ in 0..2 {
                assert_eq!(
                    backend
                        .call(request(), Duration::from_secs(3))
                        .await
                        .unwrap()["id"],
                    "evt_demo"
                );
                assert!(
                    backend
                        .call(notification(), Duration::from_secs(3))
                        .await
                        .unwrap()
                        .is_null()
                );
            }
            backend.shutdown().await.unwrap();
            backend.shutdown().await.unwrap();
            assert!(
                backend
                    .call(request(), Duration::from_secs(3))
                    .await
                    .is_err()
            );
        }
    }
    #[tokio::test]
    async fn queued_calls_have_their_own_deadline_and_shutdown_reaps() {
        let backend = backend(
            "import sys,time\nfor line in sys.stdin: time.sleep(10)\n",
            "persistent",
        );
        let start = std::time::Instant::now();
        let (first, queued) = futures::join!(
            backend.call(request(), Duration::from_millis(250)),
            backend.call(request(), Duration::from_millis(50))
        );
        assert!(first.is_err() && queued.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        tokio::time::timeout(Duration::from_secs(2), backend.shutdown())
            .await
            .unwrap()
            .unwrap();
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_exchange_is_killed_and_shutdown_reaps() {
        let path = std::env::temp_dir().join(format!("ahp-registered-{}.pid", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let script = format!(
            "import os,sys,time\nopen({},'w').write(str(os.getpid()))\nsys.stdin.readline()\ntime.sleep(60)\n",
            serde_json::to_string(path.to_str().unwrap()).unwrap()
        );
        let backend = backend(&script, "persistent");
        assert!(!path.exists(), "factory must not spawn");
        backend
            .call(notification(), Duration::from_secs(3))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(300),
                backend.call(request(), Duration::from_secs(30))
            )
            .await
            .is_err()
        );
        let pid = std::fs::read_to_string(&path).unwrap();
        backend.shutdown().await.unwrap();
        assert!(
            !tokio::process::Command::new("kill")
                .args(["-0", &pid])
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .unwrap()
                .success()
        );
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn bounded_frames_and_bad_correlation_are_rejected() {
        for output in [
            "x".repeat(1024 * 1024 + 1),
            "{\"jsonrpc\":\"2.0\",\"id\":\"wrong\",\"result\":{}}".into(),
        ] {
            // Generate oversized output in the child, not its command arguments.
            let script = if output.len() > 1024 {
                "import sys\nsys.stdin.readline()\nprint('x'*(1024*1024+1),flush=True)".into()
            } else {
                format!(
                    "import sys\nsys.stdin.readline()\nprint({},flush=True)",
                    serde_json::to_string(&output).unwrap()
                )
            };
            let backend = backend(&script, "persistent");
            assert!(
                backend
                    .call(request(), Duration::from_secs(3))
                    .await
                    .is_err()
            );
            backend.shutdown().await.unwrap();
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn per_event_notification_closes_stdin_and_bounds_uncooperative_exit() {
        for stubborn in [false, true] {
            let path = std::env::temp_dir().join(format!(
                "ahp-notification-{}-{}.json",
                std::process::id(),
                stubborn
            ));
            let _ = std::fs::remove_file(&path);
            let script = format!(
                "import os,sys,time,json\nrequest=json.loads(sys.stdin.readline())\nassert 'id' not in request\nassert sys.stdin.read()==''\nopen({},'w').write(str(os.getpid()))\ntime.sleep({})\n",
                serde_json::to_string(path.to_str().unwrap()).unwrap(),
                if stubborn { "60" } else { "0.1" },
            );
            let backend = backend(&script, "per_event");
            let result = tokio::time::timeout(
                Duration::from_secs(4),
                backend.call(notification(), Duration::from_secs(3)),
            )
            .await
            .unwrap();
            assert_eq!(result.is_err(), stubborn);
            // Reading this immediately after call completion proves EOF was consumed,
            // not merely that the SDK successfully wrote to a pipe.
            let pid = std::fs::read_to_string(&path).unwrap();
            assert!(
                !tokio::process::Command::new("kill")
                    .args(["-0", &pid])
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await
                    .unwrap()
                    .success(),
                "call completion must reap both graceful and forcibly terminated children"
            );
            backend.shutdown().await.unwrap();
            std::fs::remove_file(path).unwrap();
        }
    }
}
