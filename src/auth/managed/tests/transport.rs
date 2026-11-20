//! The real HTTP backend with `ManagedOAuth` against a loopback listener.
use super::*;
use crate::adapters::registered::{BackendOptions, ManagedBackend, from_registration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

/// Loopback stands in for the approved HTTPS destination the binding was learned for.
struct Mapped(Arc<ManagedOAuth>);
fn mapped(mut context: AuthContext) -> AuthContext {
    context.destination = "https://api.example/hooks".into();
    context
}
impl AuthProvider for Mapped {
    fn credential(
        &self,
        context: AuthContext,
    ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
        self.0.credential(mapped(context))
    }
    fn challenge(
        &self,
        context: AuthContext,
        challenge: AuthChallenge,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        self.0.challenge(mapped(context), challenge)
    }
    fn preparations(&self, context: &AuthContext) -> u64 {
        self.0.preparations(&mapped(context.clone()))
    }
}

const RESPONSE: &str =
    r#"{"jsonrpc":"2.0","id":"evt_demo","result":{"protocolVersion":"draft","effects":[]}}"#;
fn intercept() -> Value {
    json!({"jsonrpc":"2.0","id":"evt_demo","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"evt_demo","harness":{"name":"test","version":"1"},"source":"urn:example:demo","type":"tool.before","time":"2026-08-24T08:51:14Z","session":{"id":"sess_demo","cwd":"/repo","workspaceRoots":["/repo"]},"tool":{"name":"Bash","kind":"shell","input":{"command":"echo hello"},"origin":"native"},"call":{"id":"call_demo"},"path":"example"},"capabilities":{"effects":["deny"]}}})
}
fn observe() -> Value {
    let mut request = intercept();
    request.as_object_mut().unwrap().remove("id");
    request["method"] = "hooks/observe".into();
    request["params"]
        .as_object_mut()
        .unwrap()
        .remove("capabilities");
    request
}

/// Serve `replies` in order; returns each request's (lowercased headers, body).
async fn serve(listener: &TcpListener, replies: Vec<(u16, &'static str)>) -> Vec<(String, String)> {
    let mut seen = Vec::new();
    for (status, body) in replies {
        let Ok(Ok((socket, _))) =
            tokio::time::timeout(Duration::from_millis(300), listener.accept()).await
        else {
            break;
        };
        let mut reader = BufReader::new(socket);
        let (mut headers, mut size) = (String::new(), 0);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
            let line = line.to_ascii_lowercase();
            if let Some(value) = line.strip_prefix("content-length:") {
                size = value.trim().parse().unwrap();
            }
            headers.push_str(&line);
        }
        let mut request = vec![0; size];
        reader.read_exact(&mut request).await.unwrap();
        seen.push((headers, String::from_utf8(request).unwrap()));
        let response = format!(
            "HTTP/1.1 {status} X\r\nWWW-Authenticate: Bearer error=\"invalid_token\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        reader
            .get_mut()
            .write_all(response.as_bytes())
            .await
            .unwrap();
    }
    seen
}

/// Unbound endpoint with a learned client-credentials binding and stored token.
async fn learned(host: &Host) -> (Arc<ManagedOAuth>, TcpListener, Arc<dyn ManagedBackend>) {
    let oauth = Arc::new(host.cc(TokenAuthMethod::ClientSecretBasic, "secret"));
    host.network
        .reply(200, json!({"access_token":"stored","token_type":"Bearer"}));
    oauth
        .challenge(unbound(), challenge(401, "Bearer", None))
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let registration = json!({"id":"backend","transport":{"type":"http","url":format!("http://{}/hooks", listener.local_addr().unwrap())}});
    let backend = from_registration(
        &registration,
        &BackendOptions {
            auth_provider: Some(Arc::new(Mapped(oauth.clone()))),
            allow_loopback_http: true,
            ..Default::default()
        },
    )
    .unwrap();
    (oauth, listener, backend)
}

#[tokio::test]
pub(super) async fn unbound_preemptive_unsafe_delivery() {
    let host = Host::new();
    let (_, listener, backend) = learned(&host).await;
    host.network.offline.store(true, Ordering::SeqCst);
    let (result, seen) = tokio::join!(
        backend.call(observe(), Duration::from_secs(3)),
        serve(&listener, vec![(202, ""), (202, "")])
    );
    result.unwrap();
    assert_eq!(seen.len(), 1, "no 401 round trip or replay");
    assert!(seen[0].0.contains("authorization: bearer stored\r\n"));
    assert_eq!(host.network.tokens().len(), 1);
}

#[tokio::test]
pub(super) async fn challenged_replay_once() {
    let host = Host::new();
    let (_, listener, backend) = learned(&host).await;
    // 401 retires the stored token; the provider acquires a new one; one replay.
    host.network
        .reply(200, json!({"access_token":"fresh","token_type":"Bearer"}));
    let (result, seen) = tokio::join!(
        backend.call(intercept(), Duration::from_secs(3)),
        serve(&listener, vec![(401, ""), (200, RESPONSE), (200, RESPONSE)])
    );
    assert_eq!(result.unwrap()["id"], "evt_demo");
    assert_eq!(seen.len(), 2);
    assert!(seen[0].0.contains("authorization: bearer stored\r\n"));
    assert!(seen[1].0.contains("authorization: bearer fresh\r\n"));
    assert_eq!(seen[0].1, seen[1].1, "same JSON-RPC id and buffered body");
    // A second rejection is an operational failure.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let registration = json!({"id":"backend","transport":{"type":"http","url":format!("http://{}/hooks", listener.local_addr().unwrap())}});
    let backend = from_registration(
        &registration,
        &BackendOptions {
            auth_provider: Some(Arc::new(Mapped(Arc::new(
                host.cc(TokenAuthMethod::ClientSecretBasic, "secret"),
            )))),
            allow_loopback_http: true,
            ..Default::default()
        },
    )
    .unwrap();
    host.network
        .reply(200, json!({"access_token":"third","token_type":"Bearer"}));
    host.network
        .reply(200, json!({"access_token":"fourth","token_type":"Bearer"}));
    let (result, seen) = tokio::join!(
        backend.call(intercept(), Duration::from_secs(3)),
        serve(&listener, vec![(401, ""), (401, ""), (401, "")])
    );
    assert!(result.is_err());
    assert_eq!(seen.len(), 2, "one replay per operation");
    assert!(seen[1].0.contains("authorization: bearer third\r\n"));
    // The token rejected on the replay is retired, never sent again.
    assert_eq!(host.network.tokens().len(), 4);
    assert_eq!(host.store.token().access_token, "fourth");
}

#[tokio::test]
pub(super) async fn unreplayed_challenge_prepares_next_attempt() {
    let host = Host::new();
    let oauth = Arc::new(host.cc(TokenAuthMethod::ClientSecretBasic, "secret"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let registration = json!({"id":"backend","transport":{"type":"http","url":format!("http://{}/hooks", listener.local_addr().unwrap())}});
    let backend = from_registration(
        &registration,
        &BackendOptions {
            auth_provider: Some(Arc::new(Mapped(oauth))),
            allow_loopback_http: true,
            ..Default::default()
        },
    )
    .unwrap();
    // The unknown endpoint is first attempted anonymously; its 401 is not replayed
    // but discovery and client-credentials acquisition prepare the next operation.
    host.network
        .reply(200, json!({"access_token":"learned","token_type":"Bearer"}));
    let (result, seen) = tokio::join!(
        backend.call(observe(), Duration::from_secs(3)),
        serve(&listener, vec![(401, ""), (202, "")])
    );
    assert!(result.is_err());
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].0.contains("authorization:"));
    assert!(!host.network.metadata_requests().is_empty());
    assert!(host.pending().is_empty());
    let (result, seen) = tokio::join!(
        backend.call(observe(), Duration::from_secs(3)),
        serve(&listener, vec![(202, "")])
    );
    result.unwrap();
    assert!(seen[0].0.contains("authorization: bearer learned\r\n"));
}

/// Forwards token requests over real HTTP to a loopback listener; metadata uses the fake.
struct Loopback {
    inner: Arc<Network>,
    token: String,
}
impl OAuthNetwork for Loopback {
    fn check(
        &self,
        _: Url,
        _: EndpointUse,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
    fn send(
        &self,
        request: OAuthRequest,
        usage: EndpointUse,
        budget: OperationBudget,
    ) -> LocalFuture<'_, Result<OAuthResponse, HookError>> {
        if usage != EndpointUse::Token {
            return self.inner.send(request, usage, budget);
        }
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            // reqwest cannot report write completion; as documented, mark when the
            // send is first polled (connect to loopback is immediate).
            if let Some(written) = parts.extensions.get::<RequestWritten>() {
                written.mark();
            }
            let response = reqwest::Client::new()
                .post(&self.token)
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|_| fail(AuthErrorCode::ProviderFailed))?;
            let status = response.status();
            let body = response
                .bytes()
                .await
                .map_err(|_| fail(AuthErrorCode::ProviderFailed))?;
            Ok(http::Response::builder()
                .status(status.as_u16())
                .header("content-type", "application/json")
                .body(body.to_vec())
                .unwrap())
        })
    }
}

#[tokio::test]
async fn token_response_body_is_received_after_caller_drop() {
    let host = Host::new();
    host.seed(&host.pkce(|c| c), context()).await;
    host.store.expire();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let network = Arc::new(Loopback {
        inner: host.network.clone(),
        token: format!("http://{}/token", listener.local_addr().unwrap()),
    });
    let oauth = ManagedOAuth::new(
        OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .redirect_uri("http://127.0.0.1/callback"),
        network,
        host.policy.clone(),
        host.store.clone(),
    )
    .unwrap();
    // Headers arrive at once; the body only after the caller's future is dropped.
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(socket);
        let mut size = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                size = value.trim().parse().unwrap();
            }
        }
        let mut request = vec![0; size];
        reader.read_exact(&mut request).await.unwrap();
        let body = r#"{"access_token":"b","refresh_token":"rotated","token_type":"Bearer"}"#;
        let socket = reader.get_mut();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        socket.write_all(head.as_bytes()).await.unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        socket.write_all(body.as_bytes()).await.unwrap();
    });
    let dropped = tokio::time::timeout(Duration::from_millis(100), oauth.credential(context()));
    assert!(
        dropped.await.is_err(),
        "caller future dropped before the body"
    );
    server.await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let token = host.store.token();
    assert_eq!(token.refresh_token.as_deref(), Some("rotated"));
    // The detached exchange committed the whole response, not just the rotation.
    assert!(!token.refresh_in_flight && !token.access_rejected);
    assert_eq!(token.access_token, "b");
}

/// A token connect that never completes; records when its future is dropped.
struct Stalled {
    inner: Arc<Network>,
    dropped: Arc<std::sync::atomic::AtomicBool>,
}
struct OnDrop(Arc<std::sync::atomic::AtomicBool>);
impl Drop for OnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl OAuthNetwork for Stalled {
    fn check(
        &self,
        _: Url,
        _: EndpointUse,
        _: OperationBudget,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
    fn send(
        &self,
        request: OAuthRequest,
        usage: EndpointUse,
        budget: OperationBudget,
    ) -> LocalFuture<'_, Result<OAuthResponse, HookError>> {
        if usage != EndpointUse::Token {
            return self.inner.send(request, usage, budget);
        }
        let guard = OnDrop(self.dropped.clone());
        Box::pin(async move {
            let _guard = guard;
            std::future::pending().await
        })
    }
}

#[tokio::test]
async fn stalled_connect_releases_promptly_on_caller_drop() {
    let host = Host::new();
    host.seed(&host.pkce(|c| c), context()).await;
    host.store.expire();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let oauth = ManagedOAuth::new(
        OAuthClientConfig::new("account", "client", OAuthFlow::AuthorizationCodePkce)
            .scopes(scopes(&["read"]), scopes(&["read", "write"]))
            .redirect_uri("http://127.0.0.1/callback"),
        Arc::new(Stalled {
            inner: host.network.clone(),
            dropped: dropped.clone(),
        }),
        host.policy.clone(),
        host.store.clone(),
    )
    .unwrap();
    let caller = tokio::time::timeout(Duration::from_millis(50), oauth.credential(context()));
    assert!(caller.await.is_err());
    tokio::task::yield_now().await;
    assert!(
        dropped.load(Ordering::SeqCst),
        "unsent request is aborted with the caller"
    );
    assert_eq!(
        host.store.held.load(Ordering::SeqCst),
        0,
        "grant lock released"
    );
}

// ---- Server-driven configuration over the real HTTP backend ----

const BACKEND: &str = "org.example.backend";
/// Answers each request from `reply`, echoing its JSON-RPC id; returns
/// (lowercased headers, method) per request.
async fn serve_rpc(
    listener: &TcpListener,
    replies: usize,
    reply: impl Fn(&Value) -> (u16, String),
) -> Vec<(String, String)> {
    let mut seen = Vec::new();
    for _ in 0..replies {
        let Ok(Ok((socket, _))) =
            tokio::time::timeout(Duration::from_millis(300), listener.accept()).await
        else {
            break;
        };
        let mut reader = BufReader::new(socket);
        let (mut headers, mut size) = (String::new(), 0);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
            let line = line.to_ascii_lowercase();
            if let Some(value) = line.strip_prefix("content-length:") {
                size = value.trim().parse().unwrap();
            }
            headers.push_str(&line);
        }
        let mut body = vec![0; size];
        reader.read_exact(&mut body).await.unwrap();
        let request: Value = serde_json::from_slice(&body).unwrap();
        let (status, body) = reply(&request);
        seen.push((headers, request["method"].as_str().unwrap().to_owned()));
        let response = format!(
            "HTTP/1.1 {status} X\r\nWWW-Authenticate: Bearer error=\"invalid_token\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        reader
            .get_mut()
            .write_all(response.as_bytes())
            .await
            .unwrap();
    }
    seen
}
fn configuration_reply(request: &Value) -> (u16, String) {
    if request["method"] == "hooks/configuration" {
        let subscriptions =
            json!([{"events":["tool.before"],"mode":"observe","content":{"default":"metadata"}}]);
        (
            200,
            json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft",
                "configuration":{"subscriptions":subscriptions}}})
            .to_string(),
        )
    } else {
        (202, String::new())
    }
}
type Diagnostics = Arc<Mutex<Vec<Value>>>;
/// An unbound discovered HTTP backend whose OAuth is a PKCE `ManagedOAuth`.
async fn configured(host: &Host) -> (Arc<ManagedOAuth>, TcpListener, crate::Hooks, Diagnostics) {
    let oauth = Arc::new(host.pkce(|c| c));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hooks", listener.local_addr().unwrap());
    let registration = json!({"protocolVersion":"draft","hooks":[{"id":BACKEND,"transport":{"type":"http","url":url}}]});
    let diagnostics: Diagnostics = Arc::default();
    let sink = diagnostics.clone();
    let mut options = crate::hooks::HooksOptions::new(
        "urn:example:host",
        crate::hooks::Harness::new("test", "1"),
        crate::generated::capability::HostCapabilities {
            tool_before: Some(
                crate::generated::capability::tool_before()
                    .allow()
                    .deny()
                    .observe(),
            ),
            ..Default::default()
        },
    )
    .on_configuration_skipped(move |d| sink.lock().unwrap().push(serde_json::to_value(d).unwrap()));
    options.backend = BackendOptions {
        auth_provider: Some(Arc::new(Mapped(oauth.clone()))),
        allow_loopback_http: true,
        ..Default::default()
    };
    let hooks = crate::Hooks::new(registration, options).unwrap();
    (oauth, listener, hooks, diagnostics)
}
fn endpoint() -> AuthContext {
    AuthContext {
        backend_id: BACKEND.into(),
        ..unbound()
    }
}
async fn admit(hooks: &crate::Hooks) {
    hooks
        .tool_input(json!({"command":"x"}))
        .context(crate::client::ToolContext::new(json!({"tool":{"name":"shell","kind":"shell","origin":"native"},"call":{"id":"call-1"},"path":"native"})))
        .await
        .unwrap();
}

#[tokio::test]
pub(super) async fn configuration_401_diagnostic_carries_auth_code() {
    let host = Host::new();
    let (_, listener, hooks, diagnostics) = configured(&host).await;
    // Anonymous discovery is answered 401; with no usable grant the provider's
    // challenge handling cannot create a login, so the backend is skipped.
    let (result, seen) = tokio::join!(
        hooks.initialize(),
        serve_rpc(&listener, 2, |_| (401, String::new()))
    );
    result.unwrap();
    assert_eq!(seen.len(), 1, "a 401 is not replayed without a credential");
    assert!(!seen[0].0.contains("authorization:"));
    assert_eq!(
        *diagnostics.lock().unwrap(),
        [
            json!({"backendId":BACKEND,"code":"configuration_unavailable",
            "authError":"interaction_required","recovery":"login"})
        ]
    );
    assert!(host.pending().is_empty(), "discovery never creates a login");
    assert!(!hooks.subscribes(crate::generated::EventType::ToolBefore));
    // Cancellation emits no diagnostic and propagates.
    let host = Host::new();
    let (_, _listener, hooks, diagnostics) = configured(&host).await;
    let mut initialization = Box::pin(hooks.initialize());
    let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
    assert!(initialization.as_mut().poll(&mut cx).is_pending());
    hooks.shutdown().await.unwrap();
    assert_eq!(
        initialization.await.unwrap_err().code(),
        crate::generated::DeliveryDiagnosticCode::Cancelled
    );
    assert!(diagnostics.lock().unwrap().is_empty());
}

#[tokio::test]
pub(super) async fn configuration_unavailable_retried_after_prepare() {
    let host = Host::new();
    let (oauth, listener, hooks, diagnostics) = configured(&host).await;
    let (result, _) = tokio::join!(
        hooks.initialize(),
        serve_rpc(&listener, 1, |_| (401, String::new()))
    );
    result.unwrap();
    // Recovery `login`: no backoff retry, so admissions do not contact it.
    let (_, seen) = tokio::join!(admit(&hooks), serve_rpc(&listener, 1, configuration_reply));
    assert!(seen.is_empty());
    // A prepare that only creates a login is not yet a successful prepare.
    let login = super::login(oauth.prepare(endpoint(), budget()).await.unwrap());
    let (_, seen) = tokio::join!(admit(&hooks), serve_rpc(&listener, 1, configuration_reply));
    assert!(seen.is_empty());
    host.network.reply(
        200,
        json!({"access_token":"prepared","refresh_token":"r","token_type":"Bearer","expires_in":3600}),
    );
    oauth
        .complete(endpoint(), super::callback(&login), budget())
        .await
        .unwrap();
    // The next admission starts the re-attempt at once, with the prepared
    // credential, on its own task: that event does not wait and uses the
    // routes current at admission.
    let (_, seen) = tokio::join!(admit(&hooks), serve_rpc(&listener, 2, configuration_reply));
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].1, "hooks/configuration");
    assert!(seen[0].0.contains("authorization: bearer prepared\r\n"));
    hooks.initialize().await.unwrap();
    assert!(hooks.subscribes(crate::generated::EventType::ToolBefore));
    assert_eq!(diagnostics.lock().unwrap().len(), 1);
    // Admitted: no further discovery.
    let (_, seen) = tokio::join!(admit(&hooks), serve_rpc(&listener, 1, configuration_reply));
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].1, "hooks/observe");
}
