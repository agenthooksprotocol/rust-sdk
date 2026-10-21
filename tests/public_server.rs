#[path = "../examples/neutral_server.rs"]
mod demo;
use agenthooksprotocol::{adapters::stdio, server::*, transport::Request};
use futures::executor::block_on;
use std::{collections::BTreeMap, io::Cursor};
fn server() -> Server<demo::Credentials> {
    Server {
        handlers: demo::handlers(),
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    }
}
fn request() -> Request {
    Request {
        method: "POST".into(),
        uri: "/hooks".into(),
        headers: BTreeMap::from([
            ("content-type".into(), "application/json".into()),
            ("authorization".into(), "Bearer local-demo".into()),
        ]),
        body: demo::request_body(),
    }
}
#[test]
fn neutral_roundtrip_and_same_stdio_dispatch() {
    let server = server();
    let http = block_on(server.handle(request()));
    assert_eq!(http.status, 200);
    let framed = block_on(stdio::dispatch(
        &server,
        demo::request_body(),
        Some("Bearer local-demo".into()),
    ));
    assert_eq!(http, framed);
    let mut output = Vec::new();
    stdio::write_frame(&mut output, &framed, 65536).unwrap();
    let mut reader = Cursor::new(output);
    assert_eq!(
        stdio::read_frame(&mut reader, 65536).unwrap().unwrap(),
        http.body
    );
    assert!(stdio::read_frame(&mut reader, 65536).unwrap().is_none());
}
#[test]
fn rejects_http_and_message_errors() {
    let server = server();
    let mut bad = request();
    bad.method = "GET".into();
    assert_eq!(block_on(server.handle(bad)).status, 405);
    let mut bad = request();
    bad.headers.remove("content-type");
    assert_eq!(block_on(server.handle(bad)).status, 415);
    for (bytes, code) in [
        (b"{".to_vec(), -32700),
        (b"[]".to_vec(), -32600),
        (b"{}".to_vec(), -32600),
    ] {
        let mut bad = request();
        bad.body = bytes;
        let response = block_on(server.handle(bad));
        assert_eq!(response.status, 400);
        assert_rpc_error(&response, &serde_json::Value::Null, code);
    }
    let mut bad = request();
    bad.body.resize(65537, b' ');
    let response = block_on(server.handle(bad));
    assert_eq!(response.status, 413);
    assert!(response.body.is_empty());
    let mut bad = request();
    let mut value: serde_json::Value = serde_json::from_slice(&bad.body).unwrap();
    value["id"] = "wrong".into();
    bad.body = serde_json::to_vec(&value).unwrap();
    let response = block_on(server.handle(bad));
    assert_eq!(response.status, 400);
    assert_rpc_error(&response, &"wrong".into(), -32602);
}
fn assert_rpc_error(
    response: &agenthooksprotocol::transport::Response,
    id: &serde_json::Value,
    code: i64,
) -> serde_json::Value {
    let wire: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(wire["jsonrpc"], "2.0");
    assert_eq!(&wire["id"], id);
    assert_eq!(wire["error"]["code"], code, "{wire}");
    assert!(wire["error"]["message"].is_string());
    assert!(wire.get("result").is_none());
    wire["error"].clone()
}
fn with_body(edit: impl FnOnce(&mut serde_json::Value)) -> Request {
    let mut request = request();
    let mut value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    edit(&mut value);
    request.body = serde_json::to_vec(&value).unwrap();
    request
}
fn as_notification(value: &mut serde_json::Value) {
    value.as_object_mut().unwrap().remove("id");
    value["method"] = "hooks/observe".into();
    value["params"]
        .as_object_mut()
        .unwrap()
        .remove("capabilities");
}
#[test]
fn request_failures_use_distinct_json_rpc_codes() {
    let response = block_on(server().handle(with_body(|v| v["method"] = "hooks/other".into())));
    assert_rpc_error(&response, &"evt_demo".into(), -32601);
    let response = block_on(server().handle(with_body(|v| {
        v["params"]["protocolVersion"] = "1999-01-01".into();
    })));
    let error = assert_rpc_error(&response, &"evt_demo".into(), -32001);
    assert_eq!(error["data"], serde_json::json!({"supported": ["draft"]}));
    let response = block_on(server().handle(with_body(|v| {
        v["params"]["event"]["type"] = "session.end".into();
    })));
    assert_rpc_error(&response, &"evt_demo".into(), -32002);
    let response = block_on(server().handle(with_body(|v| {
        v["params"]["event"]["type"] = "vendor.future".into();
    })));
    assert_rpc_error(&response, &"evt_demo".into(), -32002);
    // A known interceptable event without a registered intercept handler.
    let unconfigured = Server {
        handlers: HandlerSet::default(),
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let response = block_on(unconfigured.handle(request()));
    assert_rpc_error(&response, &"evt_demo".into(), -32002);
    let mut discovery = request();
    discovery.body = br#"{"jsonrpc":"2.0","id":7,"method":"hooks/capabilities","params":{"protocolVersion":"draft"}}"#.to_vec();
    let response = block_on(unconfigured.handle(discovery));
    assert_rpc_error(&response, &7.into(), -32601);
    let mut handlers = HandlerSet::default();
    handlers.intercept.tool_before = Some(std::sync::Arc::new(|_ctx, _event| {
        Box::pin(async { Err("SECRET handler diagnostic".to_owned()) })
    }));
    let failing = Server {
        handlers,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let response = block_on(failing.handle(request()));
    assert_eq!(response.status, 500);
    assert_rpc_error(&response, &"evt_demo".into(), -32004);
    assert!(!String::from_utf8_lossy(&response.body).contains("SECRET"));
}
#[test]
fn rejected_notifications_never_produce_a_response_or_frame() {
    let mut handlers = HandlerSet::default();
    handlers.observe.tool_before = Some(std::sync::Arc::new(|_ctx, _event| {
        Box::pin(async { Err("SECRET observer failure".to_owned()) })
    }));
    let failing = Server {
        handlers,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let cases: [fn(&mut serde_json::Value); 6] = [
        |_| {},
        |v| v["params"]["event"]["time"] = "not-a-timestamp".into(),
        |v| v["params"]["event"]["type"] = "vendor.future".into(),
        |v| v["params"]["protocolVersion"] = "1999-01-01".into(),
        |v| v["method"] = "hooks/other".into(),
        |v| v["jsonrpc"] = "1.0".into(),
    ];
    for edit in cases {
        let notification = with_body(|v| {
            as_notification(v);
            edit(v);
        });
        let http = block_on(failing.handle(notification.clone()));
        assert!(
            http.body.is_empty(),
            "{:?}",
            String::from_utf8_lossy(&http.body)
        );
        assert!(matches!(http.status, 204 | 500));
        let framed = block_on(stdio::dispatch(
            &failing,
            notification.body,
            Some("Bearer local-demo".into()),
        ));
        let mut stdout = Vec::new();
        stdio::write_frame(&mut stdout, &framed, 65536).unwrap();
        assert!(stdout.is_empty(), "{}", String::from_utf8_lossy(&stdout));
    }
    // Rejected credentials on stdio still produce no frame for a notification.
    let framed = block_on(stdio::dispatch(
        &failing,
        with_body(as_notification).body,
        None,
    ));
    let mut stdout = Vec::new();
    stdio::write_frame(&mut stdout, &framed, 65536).unwrap();
    assert!(stdout.is_empty());
    // A missing observer is silent success.
    let silent = Server {
        handlers: HandlerSet::default(),
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let response = block_on(silent.handle(with_body(as_notification)));
    assert_eq!(response.status, 204);
    assert!(response.body.is_empty());
}
#[test]
fn stdio_request_rejected_by_transport_gets_a_correlated_error_frame() {
    let response = block_on(stdio::dispatch(&server(), demo::request_body(), None));
    assert_rpc_error(&response, &"evt_demo".into(), -32600);
    let mut stdout = Vec::new();
    stdio::write_frame(&mut stdout, &response, 65536).unwrap();
    assert!(stdout.ends_with(b"\n"));
}
#[test]
fn write_frame_refuses_non_json_rpc_objects() {
    let response = agenthooksprotocol::transport::Response {
        status: 400,
        body: br#"{"error":"invalid JSON"}"#.to_vec(),
        ..Default::default()
    };
    let mut stdout = Vec::new();
    assert!(stdio::write_frame(&mut stdout, &response, 65536).is_err());
    assert!(stdout.is_empty());
}
#[test]
fn payload_refs_do_not_authenticate() {
    let mut bad = request();
    bad.headers.remove("authorization");
    let mut value: serde_json::Value = serde_json::from_slice(&bad.body).unwrap();
    value["params"]["event"]["principalRef"] = "local-demo-user".into();
    bad.body = serde_json::to_vec(&value).unwrap();
    assert_eq!(block_on(server().handle(bad)).status, 401);
    let mut bad = request();
    bad.headers
        .insert("Authorization".into(), "Bearer other".into());
    assert_eq!(block_on(server().handle(bad)).status, 401);
}
#[test]
fn frame_bounds_and_eof() {
    assert!(stdio::read_frame(&mut Cursor::new(b"{}"), 2).is_err());
    assert!(stdio::read_frame(&mut Cursor::new(b"123\n"), 2).is_err());
    assert_eq!(
        stdio::read_frame(&mut Cursor::new(b"{}\n"), 2).unwrap(),
        Some(b"{}".to_vec())
    );
    let mut out = Vec::new();
    assert!(
        stdio::write_frame(
            &mut out,
            &agenthooksprotocol::transport::Response {
                status: 500,
                ..Default::default()
            },
            10
        )
        .is_err()
    );
    assert!(out.is_empty());
}
#[test]
fn rejects_callback_reply_scope_mismatch() {
    let cached = std::sync::Arc::new(std::sync::Mutex::new(None));
    let mut handlers = HandlerSet::default();
    handlers.intercept.tool_before = Some(std::sync::Arc::new(move |ctx, _event| {
        let cached = cached.clone();
        Box::pin(async move {
            let mut slot = cached.lock().unwrap();
            if let Some(reply) = slot.take() {
                return Ok(reply);
            }
            *slot = Some(ctx.reply());
            Ok(ctx.reply())
        })
    }));
    let server = Server {
        handlers,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    assert_eq!(block_on(server.handle(request())).status, 200);
    assert_eq!(block_on(server.handle(request())).status, 500);
}

#[cfg(all(feature = "reqwest", feature = "axum"))]
#[tokio::test(flavor = "current_thread")]
async fn real_http_preserves_errors_rejects_redirects_and_bounds_bodies() {
    use agenthooksprotocol::{adapters::reqwest::ReqwestHttp, transport::Http};
    let app = axum::Router::new()
        .route(
            "/error",
            axum::routing::post(|| async { (axum::http::StatusCode::BAD_REQUEST, "diagnostic") }),
        )
        .route(
            "/redirect",
            axum::routing::post(|| async { axum::response::Redirect::temporary("/error") }),
        )
        .route("/large", axum::routing::post(|| async { "too large" }));
    let app = app.route(
        "/chunked",
        axum::routing::post(|| async {
            axum::body::Body::from_stream(futures::stream::iter([
                Ok::<_, std::io::Error>("1234"),
                Ok("5678"),
            ]))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = ReqwestHttp::with_options(65536, true).unwrap();
    let mut error = request();
    error.uri = format!("{base}/error");
    let result = client.send(error.clone()).await.unwrap();
    assert_eq!(result.status, 400);
    assert_eq!(result.body, b"diagnostic");
    assert!(
        ReqwestHttp::new()
            .unwrap()
            .send(error.clone())
            .await
            .is_err()
    );
    let mut redirect = error.clone();
    redirect.uri = format!("{base}/redirect");
    assert_eq!(client.send(redirect).await.unwrap().status, 307);
    let mut large = error.clone();
    large.uri = format!("{base}/large");
    assert!(
        ReqwestHttp::with_options(2, true)
            .unwrap()
            .send(large)
            .await
            .is_err()
    );
    let mut chunked = error.clone();
    chunked.uri = format!("{base}/chunked");
    assert!(
        ReqwestHttp::with_options(6, true)
            .unwrap()
            .send(chunked)
            .await
            .is_err()
    );
    let mut fragment = error.clone();
    fragment.uri.push_str("#secret");
    assert!(client.send(fragment).await.is_err());
    let mut userinfo = error;
    userinfo.uri = userinfo.uri.replace("http://", "http://user:secret@");
    assert!(client.send(userinfo).await.is_err());
    task.abort();
}

#[test]
fn observe_is_one_way_and_rejects_request_ids() {
    let mut notification = request();
    let mut value: serde_json::Value = serde_json::from_slice(&notification.body).unwrap();
    value.as_object_mut().unwrap().remove("id");
    value["method"] = "hooks/observe".into();
    value["params"]
        .as_object_mut()
        .unwrap()
        .remove("capabilities");
    notification.body = serde_json::to_vec(&value).unwrap();
    let response = block_on(server().handle(notification.clone()));
    assert_eq!(response.status, 204);
    assert!(response.body.is_empty());
    let mut output = Vec::new();
    stdio::write_frame(&mut output, &response, 100).unwrap();
    assert!(output.is_empty());
    value["id"] = "forbidden".into();
    notification.body = serde_json::to_vec(&value).unwrap();
    assert_eq!(block_on(server().handle(notification)).status, 400);
}

#[test]
fn server_rejects_invalid_canonical_timestamp() {
    let mut bad = request();
    let mut value: serde_json::Value = serde_json::from_slice(&bad.body).unwrap();
    value["params"]["event"]["time"] = "not-a-timestamp".into();
    bad.body = serde_json::to_vec(&value).unwrap();
    assert_eq!(block_on(server().handle(bad)).status, 400);
}

#[test]
fn http_hook_bridge_checks_status_correlation_and_credentials() {
    use agenthooksprotocol::{
        adapters::http_hook::HttpHook,
        client::Hook,
        transport::{Http, Response, TransportError},
    };
    struct Fake(Response);
    impl Http for Fake {
        fn send(
            &self,
            request: Request,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Response, TransportError>> + Send + '_>,
        > {
            assert_eq!(request.headers["authorization"], "Bearer scoped");
            Box::pin(async { Ok(self.0.clone()) })
        }
    }
    let message: serde_json::Value = serde_json::from_slice(&demo::request_body()).unwrap();
    let good = block_on(server().handle(request()));
    let mut hook = HttpHook {
        http: Fake(good.clone()),
        endpoint: "https://example.test/hooks".into(),
        authorization: "Bearer scoped".into(),
    };
    assert_eq!(
        block_on(hook.call(message.clone())).unwrap()["id"],
        "evt_demo"
    );
    hook.authorization.clear();
    assert!(block_on(hook.call(message.clone())).is_err());
    hook.authorization = "Bearer scoped".into();
    hook.http.0.status = 503;
    hook.http.0.body = b"upstream diagnostic".to_vec();
    let error = block_on(hook.call(message.clone())).unwrap_err();
    assert!(error.to_string().contains("503"));
    assert!(!error.to_string().contains("upstream diagnostic"));
    hook.http.0 = good;
    let mut body: serde_json::Value = serde_json::from_slice(&hook.http.0.body).unwrap();
    body["id"] = "wrong".into();
    hook.http.0.body = serde_json::to_vec(&body).unwrap();
    assert!(
        block_on(hook.call(message))
            .unwrap_err()
            .to_string()
            .contains("correlation")
    );
}

#[test]
fn stdio_preserves_json_error_body_on_non_success_status() {
    let body =
        br#"{"jsonrpc":"2.0","id":"evt_demo","error":{"code":-32603,"message":"failed"}}"#.to_vec();
    let response = agenthooksprotocol::transport::Response {
        status: 500,
        body: body.clone(),
        ..Default::default()
    };
    let mut out = Vec::new();
    stdio::write_frame(&mut out, &response, 65536).unwrap();
    assert_eq!(
        stdio::read_frame(&mut Cursor::new(out), 65536).unwrap(),
        Some(body)
    );
}

fn unadvertised_allow() -> HandlerSet {
    let mut handlers = HandlerSet::default();
    handlers.intercept.tool_before = Some(std::sync::Arc::new(|ctx, _event| {
        Box::pin(async move {
            let effect = serde_json::from_value::<agenthooksprotocol::generated::ToolBeforeEffect>(
                serde_json::json!({"type":"allow"}),
            )
            .unwrap();
            Ok(ctx.reply().effect(effect))
        })
    }));
    handlers
}
#[test]
fn server_never_publishes_unadvertised_allow() {
    let server = Server {
        handlers: unadvertised_allow(),
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    assert_eq!(block_on(server.handle(request())).status, 500);
}
#[test]
fn generic_effect_grants_cover_operations_and_elicitation() {
    use agenthooksprotocol::server::validate_effect_capabilities;
    use serde_json::json;
    let cases = [
        (
            json!({"effects":["modify"],"modify":{"input":{"replace":true}}}),
            json!({"type":"modify","target":"input","operation":"merge","value":{}}),
        ),
        (
            json!({"effects":["flow"],"flow":{"operations":["stop"]}}),
            json!({"type":"flow","operation":"continue"}),
        ),
        (
            json!({"effects":["flow"],"flow":{"operations":["continue"],"remainingContinuations":0,"maxContinuations":1,"continuationCount":1}}),
            json!({"type":"flow","operation":"continue"}),
        ),
        (
            json!({"effects":["inject"],"inject":{"context":{"append":true,"deliverAt":["now"]}}}),
            json!({"type":"inject","target":"context","operation":"append","deliverAt":"next_turn","value":[]}),
        ),
    ];
    for (caps, effect) in cases {
        let request = json!({"params":{"event":{"type":"tool.after"},"capabilities":caps}});
        let response = json!({"jsonrpc":"2.0","id":"grant","result":{"protocolVersion":"draft","effects":[effect]}});
        assert!(validate_effect_capabilities(&request, &response).is_err());
    }
    let response = json!({"jsonrpc":"2.0","id":"grant","result":{"protocolVersion":"draft","effects":[{"type":"return","value":{"action":"decline"}}]}});
    let mut request = json!({"params":{"event":{"type":"user.elicitation.request","elicitation":{"mode":"form"}},"capabilities":{"effects":["return"],"elicitation":{"url":{}}}}});
    assert!(validate_effect_capabilities(&request, &response).is_err());
    request["params"]["capabilities"]["elicitation"]["form"] = json!({});
    assert!(validate_effect_capabilities(&request, &response).is_ok());
    let request = json!({"params":{"event":{"type":"tool.after"},"capabilities":{"effects":["modify"],"modify":{"output":{"replace":true}}}}});
    let response = json!({"jsonrpc":"2.0","id":"grant","result":{"protocolVersion":"draft","effects":[{"type":"modify","target":"output","operation":"replace","value":[]}]}});
    assert!(validate_effect_capabilities(&request, &response).is_ok());
}

#[test]
fn continuation_instructions_coalesce_without_mutating_effects() {
    use agenthooksprotocol::server::validate_effect_capabilities;
    use serde_json::json;
    let response = json!({"jsonrpc":"2.0","id":"grant","result":{"protocolVersion":"draft","effects":[
        {"type":"flow","operation":"continue","instruction":"first"},
        {"type":"flow","operation":"continue","instruction":"second"}
    ]}});
    let original = response.clone();
    let mut request = json!({"params":{"event":{"type":"turn.finish.before"},"capabilities":{"effects":["flow"],"flow":{
        "operations":["continue"],"remainingContinuations":1,"continuationCount":0,"maxContinuations":1
    }}}});
    assert!(validate_effect_capabilities(&request, &response).is_ok());
    request["params"]["capabilities"]["flow"]
        .as_object_mut()
        .unwrap()
        .remove("maxContinuations");
    assert!(validate_effect_capabilities(&request, &response).is_ok());
    request["params"]["capabilities"]["flow"]["remainingContinuations"] = json!(0);
    assert!(validate_effect_capabilities(&request, &response).is_err());
    request["params"]["state"] = json!({"flow":"continue"});
    request["params"]["capabilities"]["flow"]["continuationCount"] = json!(1);
    request["params"]["capabilities"]["flow"]["maxContinuations"] = json!(1);
    assert!(validate_effect_capabilities(&request, &response).is_ok());
    assert_eq!(response, original);
}

#[test]
fn continuation_budgets_accept_integral_decimal_and_exponent_numbers() {
    use agenthooksprotocol::server::validate_effect_capabilities;
    use serde_json::{Value, json};
    let response = json!({"jsonrpc":"2.0","id":"grant","result":{"protocolVersion":"draft","effects":[{"type":"flow","operation":"continue"}]}});
    let mut request: Value = serde_json::from_str(r#"{"params":{"event":{"type":"turn.finish.before"},"capabilities":{"effects":["flow"],"flow":{"operations":["continue"],"remainingContinuations":1.0,"continuationCount":0e0,"maxContinuations":1e0}}}}"#).unwrap();
    assert!(validate_effect_capabilities(&request, &response).is_ok());
    request["params"]["capabilities"]["flow"]["remainingContinuations"] = json!(0.0);
    assert!(validate_effect_capabilities(&request, &response).is_err());
    request["params"]["capabilities"]["flow"]["remainingContinuations"] = json!(1.0);
    request["params"]["capabilities"]["flow"]["continuationCount"] = json!(1.0);
    assert!(validate_effect_capabilities(&request, &response).is_err());
}

fn verified_handlers(
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    expected: Option<&'static [u8]>,
) -> HandlerSet {
    fn verify(principal: &Principal, content: &ResolvedContent, expected: Option<&[u8]>) {
        assert_eq!(principal.subject, "local-demo-user");
        match expected {
            Some(bytes) => {
                assert_eq!(content.len(), 1);
                assert_eq!(&**content.get("/params/event/items/0").unwrap(), bytes);
            }
            None => assert!(content.is_empty()),
        }
    }
    let mut handlers = HandlerSet::default();
    let intercept_calls = calls.clone();
    handlers.intercept.tool_before = Some(std::sync::Arc::new(move |ctx, _event| {
        verify(&ctx.principal, &ctx.verified_content, expected);
        intercept_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move { Ok(ctx.reply()) })
    }));
    handlers.observe.tool_before = Some(std::sync::Arc::new(move |ctx, _event| {
        verify(&ctx.principal, &ctx.verified_content, expected);
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }));
    handlers
}
fn content_request(items: serde_json::Value) -> Request {
    let mut request = request();
    let mut value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    value["params"]["event"]["items"] = items;
    request.body = serde_json::to_vec(&value).unwrap();
    request
}
fn selected_item(reference: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"id":"message", "kind":"attachment", "mediaType":"application/octet-stream", "selection":"body", "body":reference})
}
struct CountingContentStore {
    store: agenthooksprotocol::content::MemoryContentStore,
    reads: std::sync::atomic::AtomicUsize,
}
impl agenthooksprotocol::content::ContentStore for CountingContentStore {
    fn resolve(
        &self,
        scope: &agenthooksprotocol::content::AuthorizedScope,
        reference: &agenthooksprotocol::generated::ContentReference,
    ) -> Result<std::sync::Arc<[u8]>, agenthooksprotocol::content::UploadError> {
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.store.resolve(scope, reference)
    }
    fn put(
        &self,
        scope: &agenthooksprotocol::content::AuthorizedScope,
        bytes: std::sync::Arc<[u8]>,
    ) -> Result<
        agenthooksprotocol::generated::ContentReference,
        agenthooksprotocol::content::UploadError,
    > {
        self.store.put(scope, bytes)
    }
}
#[test]
fn authenticated_automatic_resolution_reaches_verified_callback() {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    let store = CountingContentStore {
        store: MemoryContentStore::new(128, 512, 8),
        reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("local-demo-user"),
    };
    let reference = context.put(b"verified bytes").unwrap();
    store.reads.store(0, std::sync::atomic::Ordering::Relaxed);
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = Server {
        handlers: verified_handlers(calls.clone(), Some(b"verified bytes")),
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let request = content_request(serde_json::json!([selected_item(reference)]));
    let future = server.handle_with_content(request, &store);
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&future);
    assert_eq!(block_on(future).status, 200);
    assert_eq!(store.reads.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}
#[test]
fn content_resolution_never_uses_payload_scope_and_never_partially_dispatches() {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    let store = MemoryContentStore::new(128, 512, 8);
    let other = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("attacker-chosen"),
    };
    let unavailable = other.put(b"secret").unwrap();
    let own = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("local-demo-user"),
    };
    let good = own.put(b"good").unwrap();
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = Server {
        handlers: verified_handlers(calls.clone(), None),
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let mut request = content_request(serde_json::json!([
        selected_item(good.clone()),
        selected_item(unavailable)
    ]));
    let mut value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    value["params"]["event"]["principalRef"] = serde_json::json!("attacker-chosen");
    request.body = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        block_on(server.handle_with_content(request, &store)).status,
        400
    );
    let mut tampered = good;
    tampered["sha256"] = serde_json::json!("0".repeat(64));
    assert_eq!(
        block_on(server.handle_with_content(
            content_request(serde_json::json!([selected_item(tampered)])),
            &store
        ))
        .status,
        400
    );
    let gap = serde_json::json!({"id":"gap", "kind":"attachment", "mediaType":"application/octet-stream", "selection":"body", "gap":{"reason":"unavailable"}});
    assert_eq!(
        block_on(server.handle_with_content(content_request(serde_json::json!([gap])), &store))
            .status,
        400
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}
#[test]
fn metadata_omit_and_open_tool_input_never_trigger_content_reads() {
    use agenthooksprotocol::content::MemoryContentStore;
    let store = CountingContentStore {
        store: MemoryContentStore::new(128, 512, 8),
        reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = Server {
        handlers: verified_handlers(calls.clone(), None),
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let items = serde_json::json!([
        {"id":"meta", "kind":"attachment", "mediaType":"application/octet-stream", "selection":"metadata"},
        {"id":"omitted", "kind":"attachment", "mediaType":"application/octet-stream", "selection":"omit"},
        {"id":"inline", "kind":"text", "mediaType":"text/plain", "selection":"body", "text":"inline text needs no storage"}
    ]);
    let mut request = content_request(items);
    let mut value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    value["params"]["event"]["tool"]["input"] = serde_json::json!({
        "items":[selected_item(serde_json::json!({"ref":"missing", "size":0, "sha256":"0".repeat(64)}))],
        "selection":"body", "gap":{"reason":"unavailable"}
    });
    request.body = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        block_on(server.handle_with_content(request, &store)).status,
        200
    );
    assert_eq!(store.reads.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}
#[test]
fn authentication_failure_happens_before_resolution() {
    use agenthooksprotocol::content::MemoryContentStore;
    let store = CountingContentStore {
        store: MemoryContentStore::new(128, 512, 8),
        reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let mut request = content_request(serde_json::json!([selected_item(
        serde_json::json!({"ref":"missing", "size":0, "sha256":"0".repeat(64)})
    )]));
    request.headers.remove("authorization");
    assert_eq!(
        block_on(server().handle_with_content(request, &store)).status,
        401
    );
    assert_eq!(store.reads.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn observe_and_intercept_share_the_resolution_gate() {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    let store = MemoryContentStore::new(128, 512, 8);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("local-demo-user"),
    };
    let reference = context.put(b"verified bytes").unwrap();
    let request = content_request(serde_json::json!([selected_item(reference)]));
    let existing = server();
    assert_eq!(
        block_on(existing.handle_with_content(request.clone(), &store)).status,
        200
    );
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = Server {
        handlers: verified_handlers(calls.clone(), Some(b"verified bytes")),
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let mut value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    value.as_object_mut().unwrap().remove("id");
    value["method"] = serde_json::json!("hooks/observe");
    value["params"]
        .as_object_mut()
        .unwrap()
        .remove("capabilities");
    let mut observe = request;
    observe.body = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        block_on(server.handle_with_content(observe, &store)).status,
        204
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn typed_effect_retains_metadata_and_opaque_members() {
    use agenthooksprotocol::generated as g;
    let expected = serde_json::json!({
        "type":"deny", "reason":"policy", "code":"example.policy",
        "extensions":{"example.audit":{"id":"eff-1", "order":2, "explicitNull":null}}
    });
    let effect: g::ToolBeforeEffect = serde_json::from_value(expected.clone()).unwrap();
    let mut handlers = HandlerSet::default();
    handlers.intercept.tool_before = Some(std::sync::Arc::new(move |ctx, _event| {
        let effect = effect.clone();
        Box::pin(async move { Ok(ctx.reply().effect(effect)) })
    }));
    let server = Server {
        handlers,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let response = block_on(server.handle(request()));
    assert_eq!(response.status, 200);
    let wire: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(wire["result"]["effects"][0], expected);
}

#[test]
fn caller_data_contract_decodes_in_both_phases_without_erasure() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Input {
        command: String,
    }
    let mut handlers = HandlerSet::default();
    handlers.intercept.tool_before = Some(std::sync::Arc::new(|ctx, event| {
        Box::pin(async move {
            let input = ctx.decode(
                "/params/event/tool/input",
                &agenthooksprotocol::contracts::Contract::<Input>::new(),
            )?;
            assert_eq!(input.command, "echo hello");
            assert_eq!(serde_json::to_value(event).unwrap()["path"], "example");
            Ok(ctx.reply())
        })
    }));
    handlers.observe.tool_before = Some(std::sync::Arc::new(|ctx, _event| {
        Box::pin(async move {
            let input = ctx.decode(
                "/params/event/tool/input",
                &agenthooksprotocol::contracts::Contract::<Input>::new(),
            )?;
            assert_eq!(input.command, "echo hello");
            Ok(())
        })
    }));
    let server = Server {
        handlers,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    assert_eq!(block_on(server.handle(request())).status, 200);
    let mut notification = request();
    let mut wire: serde_json::Value = serde_json::from_slice(&notification.body).unwrap();
    wire.as_object_mut().unwrap().remove("id");
    wire["method"] = "hooks/observe".into();
    wire["params"]
        .as_object_mut()
        .unwrap()
        .remove("capabilities");
    notification.body = serde_json::to_vec(&wire).unwrap();
    assert_eq!(block_on(server.handle(notification)).status, 204);
    let mut invalid = request();
    let mut wire: serde_json::Value = serde_json::from_slice(&invalid.body).unwrap();
    wire["params"]["event"]["tool"]["input"]["opaque"] = true.into();
    invalid.body = serde_json::to_vec(&wire).unwrap();
    // The caller's codec does not preserve the opaque field: reject, never erase it.
    assert_eq!(block_on(server.handle(invalid)).status, 500);
}

#[test]
fn typed_discovery_owns_correlation_and_headers() {
    use agenthooksprotocol::generated as g;
    let handlers = HandlerSet {
        discovery: Some(std::sync::Arc::new(|ctx, request| {
            Box::pin(async move {
                assert_eq!(ctx.principal.subject, "local-demo-user");
                assert_eq!(serde_json::to_value(request).unwrap()["id"], "discover-1");
                let manifest = g::CapabilitiesResponseResultManifest::new(
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    g::CapabilitiesResponseResultManifestLimits::new(),
                    g::CapabilitiesResponseResultManifestManagedPolicy::new(false, vec![]),
                    vec![],
                    vec![],
                );
                Ok(ctx.reply(manifest))
            })
        })),
        ..Default::default()
    };
    let server = Server {
        handlers,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let mut request = request();
    request.body = serde_json::to_vec(&serde_json::json!({
        "jsonrpc":"2.0", "id":"discover-1", "method":"hooks/capabilities", "params":{"protocolVersion":"draft"}
    })).unwrap();
    let response = block_on(server.handle(request));
    assert_eq!(response.status, 200);
    let wire: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(wire["id"], "discover-1");
    assert_eq!(wire["jsonrpc"], "2.0");
    assert!(wire["result"]["manifest"].is_object());
}

#[test]
fn typed_reply_retains_effect_order_delivery_and_literal_nulls() {
    use agenthooksprotocol::generated as g;
    let expected = serde_json::json!([
        {"type":"inject", "target":"context", "operation":"append", "deliverAt":"next_turn",
         "value":[{"id":"deferred", "role":"system", "parts":[]}]},
        {"type":"return", "value":null},
        {"type":"inject", "target":"context", "operation":"append", "deliverAt":"now",
         "value":[{"id":"immediate", "role":"system", "parts":[], "synthesized":false}]},
        {"type":"modify", "target":"input", "operation":"merge",
         "value":{"explicitNull":null, "nested":{"opaque":[null,{"payload":true}]}}}
    ]);
    let effects: Vec<g::ToolBeforeEffect> = serde_json::from_value(expected.clone()).unwrap();
    let mut handlers = HandlerSet::default();
    handlers.intercept.tool_before = Some(std::sync::Arc::new(move |ctx, _event| {
        let effects = effects.clone();
        Box::pin(async move {
            assert_eq!(ctx.grants()["inject"]["context"]["append"], true);
            assert_eq!(ctx.grants(), &ctx.request()["params"]["capabilities"]);
            let mut reply = ctx.reply();
            for effect in effects {
                reply = reply.effect(effect);
            }
            Ok(reply)
        })
    }));
    let server = Server {
        handlers,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let mut request = request();
    let mut raw: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    raw["params"]["capabilities"] = serde_json::json!({
        "effects":["inject", "return", "modify"],
        "inject":{"context":{"append":true, "deliverAt":["now", "next_turn"]}},
        "modify":{"input":{"replace":false, "merge":true}}
    });
    request.body = serde_json::to_vec(&raw).unwrap();
    let response = block_on(server.handle(request.clone()));
    assert_eq!(response.status, 200);
    let wire: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(wire["result"]["effects"], expected);
    assert!(
        wire["result"]["effects"][0]["value"][0]
            .get("synthesized")
            .is_none()
    );
    assert_eq!(
        wire["result"]["effects"][2]["value"][0]["synthesized"],
        false
    );
    assert!(wire["result"]["effects"][1].get("value").unwrap().is_null());
    raw["params"]["capabilities"]["inject"]["context"]["deliverAt"] = serde_json::json!(["now"]);
    request.body = serde_json::to_vec(&raw).unwrap();
    let rejected = block_on(server.handle(request));
    assert_eq!(rejected.status, 500);
    let rejected_wire: serde_json::Value = serde_json::from_slice(&rejected.body).unwrap();
    assert!(rejected_wire.get("result").is_none());
}

#[test]
fn invalid_effect_anywhere_rejects_the_entire_reply() {
    use agenthooksprotocol::generated as g;
    for invalid in [
        // Canonically valid but not dynamically granted.
        serde_json::json!({"type":"allow"}),
        // Generated models must not bypass the canonical nonempty constraint.
        serde_json::json!({"type":"deny", "reason":""}),
    ] {
        let mut handlers = HandlerSet::default();
        handlers.intercept.tool_before = Some(std::sync::Arc::new(move |ctx, _event| {
            let invalid = invalid.clone();
            Box::pin(async move {
                let valid: g::ToolBeforeEffect = serde_json::from_value(
                    serde_json::json!({"type":"deny", "reason":"valid-first"}),
                )
                .unwrap();
                Ok(ctx
                    .reply()
                    .effect(valid)
                    .effect(g::ToolBeforeEffect::Unknown(invalid)))
            })
        }));
        let server = Server {
            handlers,
            authenticator: demo::Credentials,
            max_body_bytes: 65536,
        };
        let response = block_on(server.handle(request()));
        assert_eq!(response.status, 500);
        let wire: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(wire.get("result").is_none());
        assert!(wire.get("effects").is_none());
        assert!(
            !String::from_utf8(response.body)
                .unwrap()
                .contains("valid-first")
        );
    }
}

#[test]
fn empty_reply_is_correlated_noop_even_with_empty_dynamic_grants() {
    let mut request = request();
    let mut raw: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    raw["params"]["capabilities"]["effects"] = serde_json::json!([]);
    request.body = serde_json::to_vec(&raw).unwrap();
    let response = block_on(server().handle(request));
    assert_eq!(response.status, 200);
    let wire: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(wire["id"], raw["id"]);
    assert_eq!(wire["result"]["effects"], serde_json::json!([]));
}

fn serve_input() -> Vec<u8> {
    let mut input = demo::request_body();
    input.push(b'\n');
    input.extend_from_slice(&with_body(as_notification).body);
    input.extend_from_slice(b"\n{\n");
    input.extend_from_slice(&vec![b' '; 70000]);
    input.extend_from_slice(b"{}\n");
    input.extend_from_slice(&demo::request_body());
    input.push(b'\n');
    input
}
fn assert_served(output: &[u8]) {
    let lines: Vec<serde_json::Value> = output
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert_eq!(lines[0]["id"], "evt_demo");
    assert!(lines[0]["result"].is_object());
    assert_eq!(lines[1]["error"]["code"], -32700);
    assert!(lines[1]["id"].is_null());
    assert_eq!(lines[2]["error"]["code"], -32600);
    assert!(lines[2]["id"].is_null());
    assert_eq!(lines[3]["id"], "evt_demo");
}
#[test]
fn stdio_serve_loop_answers_requests_and_survives_malformed_frames() {
    let mut output = Vec::new();
    block_on(stdio::serve(
        &server(),
        Cursor::new(serve_input()),
        &mut output,
        Some("Bearer local-demo".into()),
        65536,
    ))
    .unwrap();
    assert_served(&output);
    // An unterminated final line is reported, not dispatched.
    let mut output = Vec::new();
    assert!(
        block_on(stdio::serve(
            &server(),
            Cursor::new(demo::request_body()),
            &mut output,
            Some("Bearer local-demo".into()),
            65536,
        ))
        .is_err()
    );
    assert!(output.is_empty());
}
#[cfg(feature = "tokio-process")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_stdio_serve_loop_matches_blocking_loop() {
    let mut output = Vec::new();
    stdio::serve_tokio(
        &server(),
        tokio::io::BufReader::new(std::io::Cursor::new(serve_input())),
        &mut output,
        Some("Bearer local-demo".into()),
        65536,
    )
    .await
    .unwrap();
    assert_served(&output);
}
#[test]
fn catch_all_observer_sees_only_events_without_a_specific_observer() {
    use std::sync::{Arc, Mutex};
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut handlers = HandlerSet::default();
    handlers.observe.any = Some(with_state(
        seen.clone(),
        |seen, ctx: AnyObserveContext, notification| async move {
            assert_eq!(ctx.principal.subject, "local-demo-user");
            assert_eq!(serde_json::to_value(&notification).unwrap(), *ctx.request());
            seen.lock().unwrap().push(ctx.event_type());
            Ok(())
        },
    ));
    let server = Server {
        handlers,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let response = block_on(server.handle(with_body(as_notification)));
    assert_eq!(response.status, 204);
    assert_eq!(
        *seen.lock().unwrap(),
        [Some(agenthooksprotocol::generated::EventType::ToolBefore)]
    );
    // A per-event observer takes precedence over the catch-all.
    let mut server = server;
    let specific = Arc::new(Mutex::new(0));
    server.handlers.observe.tool_before = Some(with_state(
        specific.clone(),
        |specific, _ctx, _event| async move {
            *specific.lock().unwrap() += 1;
            Ok(())
        },
    ));
    block_on(server.handle(with_body(as_notification)));
    assert_eq!(*specific.lock().unwrap(), 1);
    assert_eq!(seen.lock().unwrap().len(), 1);
}
#[test]
fn callback_helpers_build_handlers_without_boilerplate() {
    let mut handlers = HandlerSet::default();
    handlers.intercept.tool_before = Some(callback(|ctx: ToolBeforeContext, _event| async move {
        Ok(ctx.reply())
    }));
    let server = Server {
        handlers,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    assert_eq!(block_on(server.handle(request())).status, 200);
}

#[test]
fn static_configuration_discovery_is_authenticated_and_shared_with_stdio() {
    let mut server = server();
    let configuration = serde_json::json!({"subscriptions":[{"events":["tool.before"],"mode":"intercept","timeoutMs":750,"failurePolicy":"fail-open","content":{"default":"metadata"}}]});
    server.handlers.configuration = Some(serde_json::from_value(configuration.clone()).unwrap());
    let message = serde_json::json!({"jsonrpc":"2.0","id":"config-1","method":"hooks/configuration","params":{"protocolVersion":"draft"}});
    let mut req = request();
    req.body = serde_json::to_vec(&message).unwrap();
    let response = block_on(server.handle(req.clone()));
    assert_eq!(response.status, 200);
    let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(value["id"], "config-1");
    assert_eq!(value["result"]["configuration"], configuration);
    assert!(value["result"].get("manifest").is_none());
    let framed = block_on(stdio::dispatch(
        &server,
        req.body.clone(),
        Some("Bearer local-demo".into()),
    ));
    assert_eq!(framed, response);
    req.headers.remove("authorization");
    assert_eq!(block_on(server.handle(req)).status, 401);
}

#[test]
fn absent_configuration_returns_method_not_found_without_inference() {
    let server = server();
    let mut req = request();
    req.body = serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":"config-2","method":"hooks/configuration","params":{"protocolVersion":"draft"}})).unwrap();
    let response = block_on(server.handle(req));
    assert_rpc_error(&response, &"config-2".into(), -32601);
}
