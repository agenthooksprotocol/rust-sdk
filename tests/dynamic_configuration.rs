use agenthooksprotocol::server::*;
use agenthooksprotocol::{Configuration, ConfigurationRequest, content, event, subscription};
use agenthooksprotocol::{adapters::stdio, transport::Request};
use futures::executor::block_on;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct Credentials;
impl Authenticator for Credentials {
    fn authenticate(&self, authorization: Option<&str>) -> Result<Principal, String> {
        match authorization {
            Some("Bearer tenant-a") => Ok(Principal {
                subject: "tenant-a".into(),
            }),
            Some("Bearer tenant-b") => Ok(Principal {
                subject: "tenant-b".into(),
            }),
            _ => Err("credential details must remain private".into()),
        }
    }
}
fn declaration(timeout: u64) -> Configuration {
    Configuration::new().subscribe(
        subscription::intercept(event::ToolBefore)
            .timeout(Duration::from_millis(timeout))
            .fail_open()
            .content(content::Selection::metadata()),
    )
}
fn request(tenant: &str, id: &str) -> Request {
    Request { method: "POST".into(), uri: "/hooks".into(), headers: BTreeMap::from([
        ("content-type".into(), "application/json".into()), ("authorization".into(), format!("Bearer {tenant}")),
    ]), body: serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":id,"method":"hooks/configuration","params":{"protocolVersion":"draft"}})).unwrap() }
}
fn body(response: agenthooksprotocol::transport::Response) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}

#[test]
fn dynamic_configuration_is_per_authenticated_request_and_shared_by_transports() {
    let calls = Arc::new(AtomicUsize::new(0));
    let handlers = HandlerSet::new()
        .configuration(with_state(
            calls.clone(),
            |calls, ctx: ConfigurationContext, request: ConfigurationRequest| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                assert!(ctx.verified_content.is_empty());
                assert_eq!(
                    serde_json::to_value(request).unwrap()["params"]["protocolVersion"],
                    "draft"
                );
                Ok(
                    ctx.reply(declaration(if ctx.principal.subject == "tenant-a" {
                        750
                    } else {
                        900
                    })),
                )
            },
        ))
        .intercept(InterceptHandlers::new().tool_before(callback(
            |ctx: ToolBeforeContext, _| async move { Ok(ctx.reply()) },
        )))
        .observe(ObserveHandlers::new().tool_after(callback(|_, _| async { Ok(()) })));
    let server = ConfiguredServer::new(handlers, Credentials, 65536);
    let first = body(block_on(server.handle(request("tenant-a", "one"))));
    let second = body(block_on(server.handle(request("tenant-b", "two"))));
    assert_eq!(first["id"], "one");
    assert_eq!(second["id"], "two");
    assert_eq!(
        first["result"]["configuration"]["subscriptions"][0]["timeoutMs"],
        750
    );
    assert_eq!(
        second["result"]["configuration"]["subscriptions"][0]["timeoutMs"],
        900
    );
    assert!(first["result"].get("effects").is_none());
    let framed = body(block_on(stdio::dispatch(
        &server,
        request("tenant-b", "two").body,
        Some("Bearer tenant-b".into()),
    )));
    assert_eq!(framed, second);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn authentication_and_request_validation_precede_configuration_callback() {
    let calls = Arc::new(AtomicUsize::new(0));
    let server = HandlerSet::new()
        .configuration(with_state(
            calls.clone(),
            |calls, ctx: ConfigurationContext, _| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(ctx.reply(declaration(750)))
            },
        ))
        .build(Credentials, 65536);
    assert_eq!(
        block_on(server.handle(request("untrusted", "one"))).status,
        401
    );
    for change in ["version", "params", "id", "json"] {
        let mut req = request("tenant-a", "one");
        let mut value: Value = serde_json::from_slice(&req.body).unwrap();
        match change {
            "version" => value["params"]["protocolVersion"] = json!("invalid"),
            "params" => {
                value.as_object_mut().unwrap().remove("params");
            }
            "id" => {
                value.as_object_mut().unwrap().remove("id");
            }
            _ => {}
        }
        req.body = if change == "json" {
            b"{".to_vec()
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        let response = block_on(server.handle(req));
        assert_ne!(response.status, 200);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn callback_errors_and_invalid_results_are_sanitized() {
    let callback_error = HandlerSet::new()
        .configuration(callback(|_: ConfigurationContext, _| async move {
            Err::<ConfigurationReply, _>("sensitive callback failure".into())
        }))
        .build(Credentials, 65536);
    let invalid = HandlerSet::new()
        .configuration(callback(|ctx: ConfigurationContext, _| async move {
            Ok(ctx.reply(Configuration::new()))
        }))
        .build(Credentials, 65536);
    for response in [
        block_on(callback_error.handle(request("tenant-a", "one"))),
        block_on(invalid.handle(request("tenant-a", "one"))),
    ] {
        let wire = body(response);
        assert_eq!(wire["error"]["code"], -32004);
        assert!(!wire.to_string().contains("sensitive"));
        assert!(wire.get("result").is_none());
    }
}

#[test]
fn cross_request_replies_are_rejected() {
    let saved = Arc::new(Mutex::new(None));
    let server = HandlerSet::new()
        .configuration(with_state(
            saved,
            |saved, ctx: ConfigurationContext, _| async move {
                let mut saved = saved.lock().unwrap();
                if let Some(reply) = saved.take() {
                    return Ok(reply);
                }
                *saved = Some(ctx.reply(declaration(750)));
                Ok(ctx.reply(declaration(750)))
            },
        ))
        .build(Credentials, 65536);
    assert!(
        body(block_on(server.handle(request("tenant-a", "one"))))
            .get("result")
            .is_some()
    );
    let response = body(block_on(server.handle(request("tenant-b", "two"))));
    assert_eq!(response["error"]["code"], -32603);
    assert!(response.get("result").is_none());
}

#[test]
fn dropping_request_cancels_owned_configuration_callback() {
    struct Owned(Arc<AtomicUsize>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let server = HandlerSet::new()
        .configuration(with_state(
            dropped.clone(),
            |dropped, _: ConfigurationContext, _| async move {
                let _owned = Owned(dropped);
                futures::future::pending::<Result<ConfigurationReply, String>>().await
            },
        ))
        .build(Credentials, 65536);
    let mut request = Box::pin(server.handle(request("tenant-a", "one")));
    let mut context = std::task::Context::from_waker(futures::task::noop_waker_ref());
    assert!(std::future::Future::poll(request.as_mut(), &mut context).is_pending());
    drop(request);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn static_builders_and_legacy_literals_preserve_owned_snapshots_and_inference() {
    let mut source = declaration(750);
    let built = HandlerSet::new()
        .configuration(source.clone())
        .build(Credentials, 65536);
    let handlers = HandlerSet {
        configuration: Some(source.clone()),
        ..Default::default()
    };
    let legacy: Server<Credentials> = Server {
        handlers,
        authenticator: Credentials,
        max_body_bytes: 65536,
    };
    source.subscriptions.clear();
    let expected = body(block_on(legacy.handle(request("tenant-a", "one"))));
    assert_eq!(
        body(block_on(built.handle(request("tenant-a", "one")))),
        expected
    );
    let mut changed = expected;
    changed["result"]["configuration"]["subscriptions"] = json!([]);
    assert_eq!(body(block_on(built.handle(request("tenant-a", "two"))))["result"]["configuration"]["subscriptions"].as_array().unwrap().len(), 1);
    // This unannotated literal must remain inferable in a patch release.
    let handlers = HandlerSet {
        observe: ObserveHandlers::new(),
        ..Default::default()
    };
    let server = Server::new(handlers, Credentials, 65536);
    assert_eq!(
        body(block_on(server.handle(request("tenant-a", "none"))))["error"]["code"],
        -32601
    );
}
