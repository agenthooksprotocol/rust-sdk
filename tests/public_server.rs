#[path = "../examples/neutral_server.rs"]
mod demo;
use agenthooksprotocol::{adapters::stdio, server::*, transport::Request};
use futures::executor::block_on;
use std::{collections::BTreeMap, io::Cursor};
fn server() -> Server<demo::Policy, demo::Credentials> {
    Server {
        handler: demo::Policy,
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
    for bytes in [b"{".to_vec(), b"[]".to_vec(), b"{}".to_vec()] {
        let mut bad = request();
        bad.body = bytes;
        assert_eq!(block_on(server.handle(bad)).status, 400);
    }
    let mut bad = request();
    bad.body.resize(65537, b' ');
    assert_eq!(block_on(server.handle(bad)).status, 413);
    let mut bad = request();
    let mut value: serde_json::Value = serde_json::from_slice(&bad.body).unwrap();
    value["id"] = "wrong".into();
    bad.body = serde_json::to_vec(&value).unwrap();
    assert_eq!(block_on(server.handle(bad)).status, 400);
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
struct WrongId;
impl Handler for WrongId {
    fn handle(&self, _: Principal, _: Incoming) -> HandlerFuture<'_> {
        Box::pin(async {
            Ok(Outgoing::Intercept(Box::new(agenthooksprotocol::generated::parse_intercept_response_value(serde_json::json!({"jsonrpc":"2.0","id":"wrong","result":{"protocolVersion":"draft","effects":[]}})).into_value().unwrap())))
        })
    }
}
#[test]
fn rejects_callback_correlation_mismatch() {
    let server = Server {
        handler: WrongId,
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
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

struct UnadvertisedAllow;
impl Handler for UnadvertisedAllow {
    fn handle(&self, _: Principal, message: Incoming) -> HandlerFuture<'_> {
        Box::pin(async move {
            let Incoming::Intercept(request) = message else {
                return Err("expected intercept".into());
            };
            Ok(Outgoing::Intercept(Box::new(agenthooksprotocol::generated::parse_intercept_response_value(
                serde_json::json!({"jsonrpc":"2.0","id":request.id,"result":{"protocolVersion":"draft","effects":[{"type":"allow"}]}})
            ).into_value().unwrap())))
        })
    }
}
#[test]
fn server_never_publishes_unadvertised_allow() {
    let server = Server {
        handler: UnadvertisedAllow,
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
            json!({"type":"inject","target":"context","operation":"append","deliverAt":"next_turn","value":"context"}),
        ),
    ];
    for (caps, effect) in cases {
        let request = json!({"params":{"capabilities":caps}});
        let response = json!({"result":{"effects":[effect]}});
        assert!(validate_effect_capabilities(&request, &response).is_err());
    }
    let response = json!({"result":{"effects":[{"type":"return","value":{"action":"decline"}}]}});
    let mut request = json!({"params":{"event":{"type":"user.elicitation.request","elicitation":{"mode":"form"}},"capabilities":{"effects":["return"],"elicitation":{"url":{}}}}});
    assert!(validate_effect_capabilities(&request, &response).is_err());
    request["params"]["capabilities"]["elicitation"]["form"] = json!({});
    assert!(validate_effect_capabilities(&request, &response).is_ok());
    let request = json!({"params":{"capabilities":{"effects":["modify"],"modify":{"output":{"replace":true}}}}});
    let response = json!({"result":{"effects":[{"type":"modify","target":"output","operation":"replace","value":{"ok":true}}]}});
    assert!(validate_effect_capabilities(&request, &response).is_ok());
}

#[test]
fn continuation_instructions_coalesce_without_mutating_effects() {
    use agenthooksprotocol::server::validate_effect_capabilities;
    use serde_json::json;
    let response = json!({"result":{"effects":[
        {"type":"flow","operation":"continue","instruction":"first"},
        {"type":"flow","operation":"continue","instruction":"second"}
    ]}});
    let original = response.clone();
    let mut request = json!({"params":{"capabilities":{"effects":["flow"],"flow":{
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
    let response = json!({"result":{"effects":[{"type":"flow","operation":"continue"}]}});
    let mut request: Value = serde_json::from_str(r#"{"params":{"capabilities":{"effects":["flow"],"flow":{"operations":["continue"],"remainingContinuations":1.0,"continuationCount":0e0,"maxContinuations":1e0}}}}"#).unwrap();
    assert!(validate_effect_capabilities(&request, &response).is_ok());
    request["params"]["capabilities"]["flow"]["remainingContinuations"] = json!(0.0);
    assert!(validate_effect_capabilities(&request, &response).is_err());
    request["params"]["capabilities"]["flow"]["remainingContinuations"] = json!(1.0);
    request["params"]["capabilities"]["flow"]["continuationCount"] = json!(1.0);
    assert!(validate_effect_capabilities(&request, &response).is_err());
}

struct VerifiedPolicy {
    calls: std::sync::atomic::AtomicUsize,
    expected: Option<&'static [u8]>,
}
impl Handler for VerifiedPolicy {
    fn handle(&self, _: Principal, _: Incoming) -> HandlerFuture<'_> {
        panic!("content-enabled dispatch must use the verified callback")
    }
    fn handle_verified(
        &self,
        principal: Principal,
        message: Incoming,
        content: ResolvedContent,
    ) -> HandlerFuture<'_> {
        assert_eq!(principal.subject, "local-demo-user");
        match self.expected {
            Some(bytes) => {
                assert_eq!(content.len(), 1);
                assert_eq!(&**content.get("/params/event/items/0").unwrap(), bytes);
            }
            None => assert!(content.is_empty()),
        }
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            match message {
                Incoming::Intercept(request) => Ok(Outgoing::Intercept(Box::new(
                    agenthooksprotocol::generated::parse_intercept_response_value(
                        serde_json::json!({
                            "jsonrpc":"2.0", "id":request.id,
                            "result":{"protocolVersion":"draft", "effects":[]}
                        }),
                    )
                    .into_value()
                    .unwrap(),
                ))),
                Incoming::Observe(_) => Ok(Outgoing::Observed),
                _ => Err("unexpected capabilities request".into()),
            }
        })
    }
}
fn content_request(items: serde_json::Value) -> Request {
    let mut request = request();
    let mut value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    value["params"]["event"]["items"] = items;
    request.body = serde_json::to_vec(&value).unwrap();
    request
}
fn selected_item(reference: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"id":"message", "kind":"message", "mediaType":"text/plain", "role":"user", "selection":"body", "body":reference})
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
    let server = Server {
        handler: VerifiedPolicy {
            calls: 0.into(),
            expected: Some(b"verified bytes"),
        },
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let request = content_request(serde_json::json!([selected_item(reference)]));
    let future = server.handle_with_content(request, &store);
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&future);
    assert_eq!(block_on(future).status, 200);
    assert_eq!(store.reads.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(
        server
            .handler
            .calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
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
    let server = Server {
        handler: VerifiedPolicy {
            calls: 0.into(),
            expected: None,
        },
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
    let gap = serde_json::json!({"id":"gap", "kind":"message", "mediaType":"text/plain", "selection":"body", "gap":{"reason":"unavailable"}});
    assert_eq!(
        block_on(server.handle_with_content(content_request(serde_json::json!([gap])), &store))
            .status,
        400
    );
    assert_eq!(
        server
            .handler
            .calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}
#[test]
fn metadata_omit_and_open_tool_input_never_trigger_content_reads() {
    use agenthooksprotocol::content::MemoryContentStore;
    let store = CountingContentStore {
        store: MemoryContentStore::new(128, 512, 8),
        reads: std::sync::atomic::AtomicUsize::new(0),
    };
    let server = Server {
        handler: VerifiedPolicy {
            calls: 0.into(),
            expected: None,
        },
        authenticator: demo::Credentials,
        max_body_bytes: 65536,
    };
    let items = serde_json::json!([
        {"id":"meta", "kind":"message", "mediaType":"text/plain", "selection":"metadata"},
        {"id":"omitted", "kind":"message", "mediaType":"text/plain", "selection":"omit"}
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
    assert_eq!(
        server
            .handler
            .calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
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
fn observe_and_existing_handlers_share_the_resolution_gate() {
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
    let server = Server {
        handler: VerifiedPolicy {
            calls: 0.into(),
            expected: Some(b"verified bytes"),
        },
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
    assert_eq!(
        server
            .handler
            .calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}
