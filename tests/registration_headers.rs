use agenthooksprotocol::adapters::registered::{BackendOptions, from_registration};
use serde_json::{Value, json};

fn config(url: &str, headers: Value) -> Value {
    json!({"id":"policy", "transport":{"type":"http","url":url,"headers":headers}})
}
#[test]
fn invalid_static_headers_fail_before_io() {
    let invalid = [
        json!(null),
        json!([]),
        json!({"X":1}),
        json!({"X":"\r\n"}),
        json!({"X":"\u{7f}"}),
        json!({"X":"\0"}),
        json!({"bad name":"x"}),
        json!({"é":"x"}),
        json!({"X":{"valueRef":""}}),
        json!({"X":{"valueEnv":"1BAD"}}),
        json!({"X":{"valueEnv":"A","valueRef":"b"}}),
        json!({"X":{"unknown":"b"}}),
    ];
    for headers in invalid {
        assert!(
            from_registration(
                &config("https://example.test", headers),
                &BackendOptions::default()
            )
            .is_err()
        );
    }
}

#[cfg(feature = "reqwest")]
mod http {
    use super::*;
    use agenthooksprotocol::{
        adapters::registered::{AuthPurpose, HeaderContext, HeaderResolver, HeaderSource},
        client::{HookError, LocalFuture},
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };
    fn notification() -> Value {
        json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":{"id":"evt_demo","harness":{"name":"test","version":"1"},"source":"urn:example:demo","type":"tool.before","time":"2026-08-24T08:51:14Z","session":{"id":"sess_demo","cwd":"/repo","workspaceRoots":["/repo"]},"tool":{"name":"Bash","kind":"shell","input":{"command":"echo hello"},"origin":"native"},"call":{"id":"call_demo"},"path":"example"}}})
    }
    fn options() -> BackendOptions {
        BackendOptions {
            allow_loopback_http: true,
            ..Default::default()
        }
    }
    fn server(count: usize, extra: String) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/hooks", listener.local_addr().unwrap());
        let task = thread::spawn(move || {
            let mut received = vec![];
            let start = std::time::Instant::now();
            while received.len() < count {
                let Ok((mut stream, _)) = listener.accept() else {
                    assert!(start.elapsed() < Duration::from_secs(5));
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut bytes = vec![];
                loop {
                    let mut chunk = [0; 4096];
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&bytes);
                    if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                        let size: usize = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|v| v.parse().ok())
                            })
                            .unwrap();
                        if body.len() >= size {
                            break;
                        }
                    }
                }
                received.push(String::from_utf8(bytes).unwrap());
                let status = if extra.is_empty() {
                    "204 No Content"
                } else if extra.starts_with("WWW-Authenticate:") {
                    "401 Unauthorized"
                } else {
                    "307 Temporary Redirect"
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n{extra}\r\n"
                )
                .unwrap();
            }
            received
        });
        (url, task)
    }
    struct Resolver {
        value: Mutex<String>,
        calls: Mutex<Vec<HeaderContext>>,
    }
    impl HeaderResolver for Resolver {
        fn resolve(&self, context: HeaderContext) -> LocalFuture<'_, Result<String, HookError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(context);
                Ok(self.value.lock().unwrap().clone())
            })
        }
    }
    struct NoOAuth;
    impl agenthooksprotocol::adapters::registered::AuthProvider for NoOAuth {
        fn credential(
            &self,
            _: agenthooksprotocol::adapters::registered::AuthContext,
        ) -> LocalFuture<
            '_,
            Result<Option<agenthooksprotocol::adapters::registered::BearerCredential>, HookError>,
        > {
            panic!("explicit Authorization must suppress acquisition")
        }
        fn challenge(
            &self,
            _: agenthooksprotocol::adapters::registered::AuthContext,
            _: agenthooksprotocol::adapters::registered::AuthChallenge,
        ) -> LocalFuture<'_, Result<(), HookError>> {
            panic!("explicit Authorization must suppress challenge")
        }
    }
    #[tokio::test]
    async fn configured_headers_override_defaults_and_auth_without_oauth() {
        for auth in [json!("Bearer abc123"), json!({"valueRef":"explicit"})] {
            let (url, task) = server(1, String::new());
            let opts = BackendOptions {
                auth_provider: Some(Arc::new(NoOAuth)),
                credentials: [("explicit".into(), "Bearer abc123".into())].into(),
                ..options()
            };
            let mut registration = config(
                &url,
                json!({"AUTHORIZATION":"discarded","authorization":auth,"Content-Type":"application/custom","Cookie":"session=literal-secret","X-Api-Key":"literal-key","Origin":"https://origin.example","AHP-Example":"allowed","X-Text":"café\tvalue","X-Duplicate":"first","x-duplicate":"last"}),
            );
            registration["authentication"] = json!({"type":"oauth","flow":"client_credentials"});
            let backend = from_registration(&registration, &opts).unwrap();
            backend
                .call(notification(), Duration::from_secs(2))
                .await
                .unwrap();
            let wire = task.join().unwrap().remove(0);
            for header in [
                "authorization: Bearer abc123",
                "content-type: application/custom",
                "cookie: session=literal-secret",
                "x-api-key: literal-key",
                "origin: https://origin.example",
                "ahp-example: allowed",
                "x-text: café\tvalue",
                "x-duplicate: last",
            ] {
                assert!(wire.contains(header), "missing {header}");
            }
            assert_eq!(wire.matches("authorization:").count(), 1);
            assert_eq!(wire.matches("x-duplicate:").count(), 1);
        }
    }
    #[tokio::test]
    async fn explicit_authorization_suppresses_challenge_and_retry() {
        let (url, task) = server(1, "WWW-Authenticate: Bearer\r\n".into());
        let opts = BackendOptions {
            auth_provider: Some(Arc::new(NoOAuth)),
            ..options()
        };
        let backend = from_registration(
            &config(&url, json!({"Authorization":"Bearer abc123"})),
            &opts,
        )
        .unwrap();
        assert!(
            backend
                .call(notification(), Duration::from_secs(2))
                .await
                .is_err()
        );
        assert!(task.join().unwrap()[0].contains("authorization: Bearer abc123"));
    }
    #[tokio::test]
    async fn explicit_auth_failure_does_not_fall_back_to_oauth() {
        let opts = BackendOptions {
            auth_provider: Some(Arc::new(NoOAuth)),
            ..options()
        };
        let backend = from_registration(
            &config(
                "http://127.0.0.1:1",
                json!({"Authorization":{"valueRef":"missing"}}),
            ),
            &opts,
        )
        .unwrap();
        assert!(
            backend
                .call(notification(), Duration::from_secs(1))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn parsed_header_duplicates_follow_input_order_without_resolving_overridden_sources() {
        for input in [
            r#"{"x-key":"first","X-Key":"last"}"#,
            r#"{"X-Key":"first","x-key":"last"}"#,
            r#"{"x-key":{"valueEnv":"AHP_NEVER_RESOLVE_OVERRIDDEN"},"X-Key":"last"}"#,
            r#"{"X-Key":{"valueEnv":"AHP_NEVER_RESOLVE_OVERRIDDEN"},"x-key":"last"}"#,
        ] {
            let (url, task) = server(1, String::new());
            let opts = BackendOptions {
                header_resolver: Some(Arc::new(Pending)),
                ..options()
            };
            let backend =
                from_registration(&config(&url, serde_json::from_str(input).unwrap()), &opts)
                    .unwrap();
            backend
                .call(notification(), Duration::from_secs(2))
                .await
                .unwrap();
            let wire = task.join().unwrap().remove(0);
            assert!(wire.contains("x-key: last\r\n"));
            assert_eq!(wire.matches("x-key:").count(), 1);
        }
    }
    #[tokio::test]
    async fn header_sources_accept_inert_extension_properties() {
        let (url, task) = server(1, String::new());
        let opts = BackendOptions {
            credentials: [("key".into(), "resolved".into())].into(),
            ..options()
        };
        let backend = from_registration(
            &config(
                &url,
                json!({
                    "X-Env":{"valueEnv":"CARGO_MANIFEST_DIR","description":"metadata"},
                    "X-Ref":{"valueRef":"key","description":"metadata","extension":{"nested":true}}
                }),
            ),
            &opts,
        )
        .unwrap();
        backend
            .call(notification(), Duration::from_secs(2))
            .await
            .unwrap();
        let wire = task.join().unwrap().remove(0);
        assert!(wire.contains("x-ref: resolved\r\n"));
        assert!(wire.contains(&format!(
            "x-env: {}\r\n",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        )));
        assert!(!wire.contains("description"));
    }
    #[tokio::test]
    async fn emitted_headers_rotate_per_dispatch_and_remain_backend_local() {
        let (url, task) = server(3, String::new());
        let resolver = Arc::new(Resolver {
            value: Mutex::new("first-secret".into()),
            calls: Mutex::new(vec![]),
        });
        let opts = BackendOptions {
            header_resolver: Some(resolver.clone()),
            credentials: [("auth".into(), "bearer-secret".into())].into(),
            ..options()
        };
        let mut registration = config(
            &url,
            json!({"X-Metadata":"${UNCHANGED}", "X-Secret":{"valueRef":"opaque"}, "X-Empty":""}),
        );
        registration["authentication"] = json!({"type":"bearer","tokenRef":"auth"});
        let backend = from_registration(&registration, &opts).unwrap();
        backend
            .call(notification(), Duration::from_secs(2))
            .await
            .unwrap();
        *resolver.value.lock().unwrap() = "rotated-secret".into();
        backend
            .call(notification(), Duration::from_secs(2))
            .await
            .unwrap();
        let other = from_registration(&config(&url, json!({})), &options()).unwrap();
        other
            .call(notification(), Duration::from_secs(2))
            .await
            .unwrap();
        let requests = task.join().unwrap();
        assert!(requests[0].contains("x-secret: first-secret\r\n"));
        assert!(requests[1].contains("x-secret: rotated-secret\r\n"));
        assert!(requests[0].contains("x-metadata: ${UNCHANGED}\r\n"));
        assert!(requests[0].contains("authorization: Bearer bearer-secret\r\n"));
        assert!(!requests[2].contains("x-secret"));
        assert!(!requests[2].contains("authorization"));
        let calls = resolver.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for call in calls.iter() {
            assert_eq!(call.backend_id, "policy");
            assert_eq!(call.destination, url);
            assert_eq!(call.purpose, AuthPurpose::Event);
            assert!(matches!(&call.source, HeaderSource::Reference(s) if s == "opaque"));
        }
    }
    #[tokio::test]
    async fn environment_and_reference_defaults_emit_complete_values() {
        let (url, task) = server(1, String::new());
        // A read-only environment variable avoids process-global mutation in concurrent tests.
        let key = "CARGO_MANIFEST_DIR";
        let expected = std::env::var(key).unwrap();
        let opts = BackendOptions {
            credentials: [("key".into(), "complete-value".into())].into(),
            ..options()
        };
        let backend = from_registration(
            &config(
                &url,
                json!({"X-Env":{"valueEnv":key},"X-Ref":{"valueRef":"key"}}),
            ),
            &opts,
        )
        .unwrap();
        backend
            .call(notification(), Duration::from_secs(2))
            .await
            .unwrap();
        let received = task.join().unwrap();
        assert!(received[0].contains(&format!("x-env: {expected}\r\n")));
        assert!(received[0].contains("x-ref: complete-value\r\n"));
    }
    #[tokio::test]
    async fn missing_and_invalid_values_send_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/hooks", listener.local_addr().unwrap());
        for value in ["private-secret\n", "private-secret\0"] {
            let opts = BackendOptions {
                credentials: [("key".into(), value.into())].into(),
                ..options()
            };
            let backend =
                from_registration(&config(&url, json!({"X":{"valueRef":"key"}})), &opts).unwrap();
            let err = backend
                .call(notification(), Duration::from_secs(1))
                .await
                .unwrap_err();
            assert!(!err.to_string().contains("private-secret"));
            assert!(listener.accept().is_err());
        }
        for source in [
            json!({"valueRef":"absent"}),
            json!({"valueEnv":"AHP_MISSING_HEADERS_TEST_294858"}),
        ] {
            let backend =
                from_registration(&config(&url, json!({"X":source})), &options()).unwrap();
            assert!(
                backend
                    .call(notification(), Duration::from_secs(1))
                    .await
                    .is_err()
            );
            assert!(listener.accept().is_err());
        }
    }
    struct Pending;
    impl HeaderResolver for Pending {
        fn resolve(&self, _: HeaderContext) -> LocalFuture<'_, Result<String, HookError>> {
            Box::pin(std::future::pending())
        }
    }
    #[tokio::test]
    async fn resolution_obeys_dispatch_deadline() {
        let opts = BackendOptions {
            header_resolver: Some(Arc::new(Pending)),
            ..options()
        };
        let backend = from_registration(
            &config("http://127.0.0.1:1", json!({"X":{"valueRef":"secret"}})),
            &opts,
        )
        .unwrap();
        let err = backend
            .call(notification(), Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("deadline"));
    }
    #[tokio::test]
    async fn capability_discovery_neither_resolves_nor_emits_headers() {
        let (url, task) = server(1, String::new());
        // A pending resolver would time out if discovery incorrectly consulted it.
        let opts = BackendOptions {
            header_resolver: Some(Arc::new(Pending)),
            ..options()
        };
        let backend = from_registration(
            &config(&url, json!({"X-Secret":{"valueRef":"opaque"}})),
            &opts,
        )
        .unwrap();
        let request = json!({"jsonrpc":"2.0","id":"caps","method":"hooks/capabilities","params":{"protocolVersion":"draft"}});
        // The test server intentionally returns no capability response body.
        assert!(backend.call(request, Duration::from_secs(2)).await.is_err());
        assert!(!task.join().unwrap()[0].contains("x-secret"));
    }
    #[tokio::test]
    async fn existing_no_redirect_transport_behavior_is_unchanged() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let (url, task) = server(
            1,
            format!(
                "Location: http://{}/other\r\n",
                target.local_addr().unwrap()
            ),
        );
        let backend =
            from_registration(&config(&url, json!({"X":"metadata"})), &options()).unwrap();
        assert!(
            backend
                .call(notification(), Duration::from_secs(2))
                .await
                .is_err()
        );
        assert!(task.join().unwrap()[0].contains("x: metadata\r\n"));
        assert!(target.accept().is_err());
    }
}

#[test]
fn generated_transport_preserves_header_sources() {
    let input = json!({"type":"http","url":"https://example.test/hooks","headers":{"X-Literal":"meta","X-Env":{"valueEnv":"KEY"},"X-Ref":{"valueRef":"opaque"}}});
    let transport: agenthooksprotocol::generated::HttpTransport =
        serde_json::from_value(input.clone()).unwrap();
    assert_eq!(serde_json::to_value(transport).unwrap(), input);
}
