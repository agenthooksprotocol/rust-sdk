use agenthooksprotocol::{
    Hooks,
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use serde_json::{Value, json};
use std::{rc::Rc, time::Duration};

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
    .with_backend("org.example.review", Rc::new(Unused));
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
    use std::cell::RefCell;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    #[derive(Default)]
    struct Recorded(RefCell<Vec<Value>>);
    impl ManagedBackend for Recorded {
        fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                self.0.borrow_mut().push(request.clone());
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
        hooks.tool_before(json!({})).context(ToolContext::new(json!({
            "tool":{"name":"shell","kind":"shell","origin":"native"},
            "call":{"id":"call-upload"},"path":"native",
            "items":[{"id":"body-1","kind":"text","mediaType":"text/plain","selection":"body","body":body}]
        }))).initial_state(Decision::Allow).await.unwrap()
    }
    fn configured(endpoint: String, missing_upload_token: bool) -> (Hooks, Rc<Recorded>) {
        let backend = Rc::new(Recorded::default());
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
        assert_eq!(backend.0.borrow().len(), 1);
        assert_eq!(
            backend.0.borrow()[0]["params"]["event"]["items"][0]["body"],
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
            backend.0.borrow().is_empty(),
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
