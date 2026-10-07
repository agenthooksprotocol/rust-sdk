use agenthooksprotocol::{
    Hooks,
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

struct Unused;
impl ManagedBackend for Unused {
    fn call(&self, _: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async { panic!("constructor must not perform I/O") })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}
fn registration() -> Value {
    json!({"protocolVersion":"draft","hooks":[{
        "id":"org.example.review",
        "transport":{"type":"http","url":"https://hooks.example/intercept"},
        "authentication":{"type":"bearer","tokenRef":"event"},
        "subscriptions":[{"events":["tool.before"],"mode":"intercept",
            "timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":"body"},
            "upload":{"endpoint":"https://uploads.example/content","maxBytes":128,
                "timeoutMs":1000,"auth":{"type":"bearer","tokenRef":"upload"}}}]
    }]})
}
fn options() -> HooksOptions {
    let mut options = HooksOptions::new(
        "urn:example:comparison",
        [(
            "tool.before".into(),
            EventGrant::intercept(Capabilities::none()),
        )]
        .into(),
    )
    .with_backend("org.example.review", Arc::new(Unused));
    options
        .backend
        .credentials
        .insert("event".into(), "event-only".into());
    options
        .backend
        .credentials
        .insert("upload".into(), "upload-only".into());
    options
}
#[test]
fn canonical_token_ref_upload_is_admitted_by_actual_hooks_constructor() {
    let hooks = Hooks::new(registration(), options()).expect("canonical tokenRef upload binding");
    futures::executor::block_on(hooks.shutdown()).unwrap();
}
#[test]
fn removed_and_unknown_authentication_mechanisms_remain_rejected() {
    for mechanism in ["mtls", "workload", "com.example.identity"] {
        let mut value = registration();
        value["hooks"][0]["authentication"] = json!({"type":mechanism});
        assert!(
            Hooks::new(value, options()).is_err(),
            "admitted {mechanism}"
        );
    }
}

#[cfg(feature = "reqwest")]
mod runtime {
    use super::*;
    use agenthooksprotocol::{
        body::Body,
        client::{Decision, ToolContext},
    };
    use std::sync::Mutex;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    #[derive(Default)]
    struct Recorded(Mutex<Vec<Value>>);
    impl ManagedBackend for Recorded {
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
    async fn dispatch(hooks: &Hooks) -> agenthooksprotocol::hooks::ToolOutcome<Value> {
        let body = hooks
            .stage_body(Body::bytes(b"upload payload".to_vec()))
            .await
            .unwrap();
        hooks.tool_input(json!({})).context(ToolContext::new(json!({
            "tool":{"name":"shell","kind":"shell","origin":"native"},
            "call":{"id":"call-upload"},"path":"native",
            "items":[{"id":"body-1","kind":"text","mediaType":"text/plain","selection":"body","body":body}]
        }))).initial_state(Decision::Allow).await.unwrap()
    }
    fn configured(endpoint: String, missing_upload_token: bool) -> (Hooks, Arc<Recorded>) {
        let backend = Arc::new(Recorded::default());
        let mut options = options().with_backend("org.example.review", backend.clone());
        options.backend.allow_loopback_http = true;
        if missing_upload_token {
            options.backend.credentials.remove("upload");
        }
        let mut registration = registration();
        registration["hooks"][0]["subscriptions"][0]["upload"]["endpoint"] = json!(endpoint);
        (Hooks::new(registration, options).unwrap(), backend)
    }
    #[tokio::test]
    async fn actual_upload_uses_only_upload_token_ref() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (hooks, backend) = configured(
            format!("http://{}/content", listener.local_addr().unwrap()),
            false,
        );
        let server = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, "POST /content HTTP/1.1\r\n");
            let mut headers = std::collections::BTreeMap::new();
            loop {
                line.clear();
                assert!(reader.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                let (key, value) = line.split_once(':').unwrap();
                headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
            }
            assert_eq!(headers["authorization"], "Bearer upload-only");
            assert!(!headers.values().any(|value| value.contains("event-only")));
            let size: usize = headers["content-length"].parse().unwrap();
            assert!(size <= 128);
            let mut body = vec![0; size];
            reader.read_exact(&mut body).await.unwrap();
            assert_eq!(body, b"upload payload");
            let descriptor = json!({"ref":"https://uploads.example/content/verified","size":size,"sha256":headers["ahp-content-sha256"]});
            let body = descriptor.to_string();
            reader.get_mut().write_all(format!("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
            descriptor
        };
        let (result, descriptor) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(dispatch(&hooks), server)
        })
        .await
        .unwrap();
        assert!(
            result.outcome.failures.is_empty(),
            "{:?}",
            result.outcome.failures
        );
        assert!(result.outcome.can_execute());
        assert_eq!(backend.0.lock().unwrap().len(), 1);
        assert_eq!(
            backend.0.lock().unwrap()[0]["params"]["event"]["items"][0]["body"],
            descriptor
        );
        hooks.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn missing_upload_token_never_falls_back_to_event_credential() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let (hooks, backend) = configured(
            format!("http://{}/content", listener.local_addr().unwrap()),
            true,
        );
        let result = dispatch(&hooks).await;
        assert!(!result.outcome.failures.is_empty());
        assert!(!result.outcome.can_execute());
        assert!(
            backend.0.lock().unwrap().is_empty(),
            "failed upload must prevent event delivery"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "missing upload token must prevent network I/O despite available event token"
        );
        hooks.shutdown().await.unwrap();
    }
}

#[cfg(feature = "reqwest")]
mod provider_auth {
    use super::*;
    use agenthooksprotocol::adapters::registered::{
        AuthChallenge, AuthContext, AuthProvider, AuthPurpose, BackendOptions, BearerCredential,
        from_registration,
    };
    use std::sync::Mutex;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    #[derive(Default)]
    struct Provider {
        contexts: Mutex<Vec<AuthContext>>,
        challenges: Mutex<Vec<AuthChallenge>>,
    }
    impl AuthProvider for Provider {
        fn credential(
            &self,
            context: AuthContext,
        ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
            Box::pin(async move {
                self.contexts.lock().unwrap().push(context);
                Ok(Some(BearerCredential {
                    token: "host-token".into(),
                    attempt_id: "generation-7".into(),
                }))
            })
        }
        fn challenge(
            &self,
            _: AuthContext,
            challenge: AuthChallenge,
        ) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async move {
                self.challenges.lock().unwrap().push(challenge);
                Ok(())
            })
        }
    }
    async fn exercise(request: Value, expected_calls: usize, binding: Option<Value>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/hooks", listener.local_addr().unwrap());
        let provider = Arc::new(Provider::default());
        let mut registration =
            json!({"id":"org.example.auth", "transport":{"type":"http", "url":endpoint}});
        if let Some(binding) = &binding {
            registration["authentication"] = binding.clone();
        }
        let backend = from_registration(
            &registration,
            &BackendOptions {
                auth_provider: Some(provider.clone()),
                allow_loopback_http: true,
                ..Default::default()
            },
        )
        .unwrap();
        let server = async {
            let mut bodies = Vec::new();
            for _ in 0..expected_calls {
                let (socket, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(socket);
                let mut headers = String::new();
                let mut size = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).await.unwrap();
                    assert!(!line.is_empty());
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length: ")
                    {
                        size = value.trim().parse::<usize>().unwrap();
                    }
                    headers.push_str(&line);
                }
                assert!(
                    headers
                        .to_ascii_lowercase()
                        .contains("authorization: bearer host-token")
                );
                let mut body = vec![0; size];
                reader.read_exact(&mut body).await.unwrap();
                bodies.push(body);
                reader.get_mut().write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer error=\"invalid_token\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            }
            bodies
        };
        let (result, bodies) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                backend.call(request.clone(), Duration::from_secs(4)),
                server
            )
        })
        .await
        .unwrap();
        assert!(result.is_err());
        assert_eq!(bodies.len(), expected_calls);
        for body in &bodies {
            assert_eq!(serde_json::from_slice::<Value>(body).unwrap(), request);
        }
        if expected_calls == 2 {
            assert_eq!(bodies[0], bodies[1]);
        }
        let contexts = provider.contexts.lock().unwrap();
        assert_eq!(contexts.len(), expected_calls);
        assert_eq!(contexts[0].authentication, binding);
        assert_eq!(contexts[0].backend_id, "org.example.auth");
        assert_eq!(contexts[0].destination, endpoint);
        assert_eq!(contexts[0].purpose, AuthPurpose::Event);
        let challenges = provider.challenges.lock().unwrap();
        assert_eq!(challenges.len(), expected_calls);
        assert_eq!(challenges[0].attempt_id.as_deref(), Some("generation-7"));
        assert_eq!(challenges[0].status, 401);
        assert!(challenges[0].headers["www-authenticate"].contains("invalid_token"));
    }
    #[tokio::test]
    async fn capabilities_retries_once_with_stable_body_and_full_oauth_binding() {
        exercise(json!({"jsonrpc":"2.0","id":"caps","method":"hooks/capabilities","params":{"protocolVersion":"draft"}}), 2,
            Some(json!({"type":"oauth","flow":"client_credentials","resource":"https://resource.example", "issuer":"https://issuer.example", "clientId":"client", "clientSecretRef":"host-secret"}))).await;
    }
    #[tokio::test]
    async fn absent_binding_challenge_is_given_to_host() {
        exercise(json!({"jsonrpc":"2.0","id":"caps","method":"hooks/capabilities","params":{"protocolVersion":"draft"}}), 2, None).await;
    }
    #[tokio::test]
    async fn intercept_challenge_does_not_authorize_replay() {
        exercise(json!({"jsonrpc":"2.0","id":"evt_demo","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"evt_demo","source":"urn:example:demo","type":"tool.before","time":"2026-08-24T08:51:14Z","session":{"id":"sess_demo","cwd":"/repo","workspaceRoots":["/repo"]},"tool":{"name":"Bash","kind":"shell","input":{"command":"echo hello"},"origin":"native"},"call":{"id":"call_demo"},"path":"example"},"capabilities":{"effects":["deny"]}}}), 1,
            Some(json!({"type":"bearer","tokenRef":"host-reference"}))).await;
    }
    #[tokio::test]
    async fn pending_provider_is_dropped_at_backend_deadline() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Pending(Arc<AtomicBool>);
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        impl AuthProvider for Pending {
            fn credential(
                &self,
                _: AuthContext,
            ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
                Box::pin(async move {
                    let _guard = Dropped(self.0.clone());
                    std::future::pending().await
                })
            }
            fn challenge(
                &self,
                _: AuthContext,
                _: AuthChallenge,
            ) -> LocalFuture<'_, Result<(), HookError>> {
                Box::pin(async { Ok(()) })
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let backend = from_registration(&json!({"id":"pending", "transport":{"type":"http","url":"https://example.invalid"}, "authentication":{"type":"bearer","tokenRef":"pending"}}), &BackendOptions {
            auth_provider: Some(Arc::new(Pending(dropped.clone()))), ..Default::default()
        }).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), backend.call(
            json!({"jsonrpc":"2.0","id":"caps","method":"hooks/capabilities","params":{"protocolVersion":"draft"}}), Duration::from_millis(30)
        )).await.expect("backend must enforce its own deadline").unwrap_err();
        assert_eq!(
            result.code(),
            agenthooksprotocol::generated::DeliveryDiagnosticCode::DeadlineExceeded
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "provider future must be dropped, not detached"
        );
    }
}
