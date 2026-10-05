use agenthooksprotocol::client::*;
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{cell::RefCell, rc::Rc};

struct HookFn {
    effects: Value,
    calls: Rc<RefCell<Vec<Value>>>,
}
impl Hook for HookFn {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            self.calls.borrow_mut().push(request.clone());
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":self.effects}}),
            )
        })
    }
}
fn event() -> Value {
    json!({"id":"evt_1","source":"https://example.test/runtime","type":"tool.before","time":"2026-08-24T08:51:14Z","path":"native","call":{"id":"call_1"},"tool":{"name":"counter","kind":"file_read","origin":"native","input":{"count":1}}})
}
fn client() -> Client {
    Client::new(ToolContext::new(json!({})))
}
fn subscription(id: &str, effects: Value, calls: &Rc<RefCell<Vec<Value>>>) -> Subscription {
    let mut sub = Subscription::intercept(
        id,
        FailurePolicy::Open,
        HookFn {
            effects,
            calls: calls.clone(),
        },
    );
    sub.events = vec!["*".into()];
    sub
}
#[test]
fn full_event_is_lazy_and_requires_no_client_tool_context() {
    let calls = Rc::new(RefCell::new(vec![]));
    let c = client().with_subscription(subscription("allow", json!([{"type":"allow"}]), &calls));
    let boundary = c.tool_before_event(event());
    assert_eq!(
        boundary.progress().snapshot().status,
        BoundaryStatus::NotStarted
    );
    drop(boundary);
    assert!(calls.borrow().is_empty());
    let result = block_on(async { c.event(event()).await.unwrap() });
    assert_eq!(result.outcome.decision, Decision::Allow);
    assert_eq!(result.event.unwrap(), event());
}
#[test]
fn invalid_initial_event_and_name_fail_without_hooks() {
    let c = client();
    assert!(block_on(async { c.event(json!({"type":"tool.before"})).await }).is_err());
    assert!(block_on(async { c.event_for("session.end", event()).await }).is_err());
    assert!(
        block_on(async {
            c.event(event())
                .capabilities(json!({"effects":["return"],"other":true}))
                .await
        })
        .is_err()
    );
}
#[test]
fn serial_full_event_modification_is_atomic() {
    let calls = Rc::new(RefCell::new(vec![]));
    let c = client()
        .with_subscription(subscription("first", json!([{"type":"modify","target":"input","operation":"merge","value":{"count":2}},{"type":"return","value":null}]), &calls))
        .with_subscription(subscription("bad", json!([{"type":"deny","reason":"no"},{"type":"modify","target":"workspace","operation":"replace","value":{}}]), &calls))
        .with_subscription(subscription("last", json!([{"type":"allow"}]), &calls));
    let result = block_on(async { c.event(event()).await.unwrap() });
    assert_eq!(result.effective_event["tool"]["input"]["count"], 2);
    assert_eq!(result.outcome.decision, Decision::Allow);
    assert_eq!(result.outcome.candidate, Some(Value::Null));
    assert_eq!(result.outcome.failures.len(), 1);
    assert_eq!(
        calls.borrow()[2]["params"]["state"]["candidate"],
        json!({"value":null})
    );
}
#[test]
fn observe_only_event_is_deferred_and_one_way() {
    let calls = Rc::new(RefCell::new(vec![]));
    let c = client().with_subscription(subscription(
        "observe",
        json!([{"type":"deny","reason":"ignored"}]),
        &calls,
    ));
    let e = json!({"id":"end","source":"https://example.test/runtime","type":"session.end","time":"2026-08-24T08:51:14Z","session":{"id":"s"},"outcome":"completed","reason":"done"});
    let result = block_on(async { c.session_end_event(e).await.unwrap() });
    assert!(calls.borrow().is_empty());
    assert_eq!(result.observations.len(), 1);
    block_on(result.observations.into_iter().next().unwrap().deliver()).unwrap();
    assert_eq!(calls.borrow()[0]["method"], "hooks/observe");
    assert!(calls.borrow()[0].get("id").is_none());
}
#[derive(Serialize, Deserialize)]
struct TypedEvent {
    tool: TypedTool,
    #[serde(flatten)]
    rest: serde_json::Map<String, Value>,
}
#[derive(Serialize, Deserialize)]
struct TypedTool {
    input: Input,
    #[serde(flatten)]
    rest: serde_json::Map<String, Value>,
}
#[derive(Serialize, Deserialize)]
struct Input {
    count: u64,
}
#[test]
fn full_event_decode_failure_does_not_rollback_protocol_commit() {
    let calls = Rc::new(RefCell::new(vec![]));
    let c = client().with_subscription(subscription("mutate", json!([{"type":"modify","target":"input","operation":"replace","value":{"count":"changed"}},{"type":"allow"}]), &calls));
    let typed: TypedEvent = serde_json::from_value(event()).unwrap();
    let result = block_on(async { c.event(typed).await.unwrap() });
    assert!(result.event.is_err());
    assert_eq!(result.effective_event["tool"]["input"]["count"], "changed");
    assert_eq!(result.outcome.decision, Decision::Allow);
}
#[test]
fn cancellation_keeps_accepted_evidence_without_authorization() {
    struct Pending;
    impl Hook for Pending {
        fn call(&self, _: Value) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(std::future::pending())
        }
    }
    use std::{
        future::IntoFuture,
        task::{Context, Poll},
    };
    let calls = Rc::new(RefCell::new(vec![]));
    let c = client()
        .with_subscription(subscription("allow", json!([{"type":"allow"}]), &calls))
        .with_subscription(Subscription::intercept(
            "pending",
            FailurePolicy::Open,
            Pending,
        ));
    let boundary = c.event(event());
    let progress = boundary.progress();
    let mut future = boundary.into_future();
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
    assert!(!progress.snapshot().partial.unwrap().outcome.authorized);
    drop(future);
    assert_eq!(progress.snapshot().status, BoundaryStatus::Interrupted);
}

#[test]
fn missing_content_resolver_rejects_whole_body_response() {
    let calls = Rc::new(RefCell::new(vec![]));
    let c = client().with_subscription(subscription(
        "body",
        json!([
            {"type":"deny","reason":"must not leak"},
            {"type":"modify","target":"prompt","operation":"replace","value":"new"}
        ]),
        &calls,
    ));
    let e = json!({"id":"turn","source":"https://example.test/runtime","type":"turn.start","time":"2026-08-24T08:51:14Z","turn":{"id":"t"},"trigger":"user","items":[]});
    let result = block_on(async { c.turn_start_event(e.clone()).await.unwrap() });
    assert_eq!(result.effective_event, e);
    assert_eq!(result.outcome.decision, Decision::None);
    assert_eq!(result.outcome.failures.len(), 1);
}

#[test]
fn continuation_is_one_requested_step_with_ordered_instructions() {
    let calls = Rc::new(RefCell::new(vec![]));
    let c = client().with_subscription(subscription(
        "continue",
        json!([
            {"type":"flow","operation":"continue","instruction":"first"},
            {"type":"flow","operation":"continue","instruction":"second"}
        ]),
        &calls,
    ));
    let e = json!({"id":"finish","source":"https://example.test/runtime","type":"turn.finish.before","time":"2026-08-24T08:51:14Z","turn":{"id":"t"},"outcome":"completed","continuationCount":0,"items":[]});
    let result = block_on(async {
        c.turn_finish_before_event(e)
            .continuation_budget(1, 0, 1)
            .await
            .unwrap()
    });
    assert!(
        result.outcome.failures.is_empty(),
        "{:?}",
        result.outcome.failures
    );
    assert!(result.outcome.continuation_requested);
    assert_eq!(result.outcome.instructions, ["first", "second"]);
    assert!(!result.outcome.stopped);
}

fn specialized_event(name: &str) -> Value {
    let mut event = json!({"id":"specialized","source":"urn:test:runtime","type":name,"time":"2026-09-15T12:00:00Z","session":{"id":"session"}});
    match name {
        "context.compact.before" => {
            event["trigger"] = json!("manual");
            event["items"] = json!([]);
        }
        "context.compact.after" => {
            event["summary"] = json!({"id":"summary","kind":"summary","role":"assistant","mediaType":"text/plain","selection":"metadata"});
            event["removed"] = json!([]);
            event["execution"] = json!({"status":"executed"});
        }
        "user.elicitation.request" => {
            event["elicitation"] = json!({"server":"mcp-server","mode":"form"});
        }
        "user.elicitation.result" => {
            event["parentEventId"] = json!("request");
            event["elicitation"] = json!({"server":"mcp-server","mode":"form","action":"decline"});
        }
        _ => unreachable!(),
    }
    event
}

#[test]
fn specialized_preflight_requires_resolver_without_subscriptions_or_effects() {
    let c = client();
    for name in [
        "context.compact.before",
        "context.compact.after",
        "user.elicitation.request",
        "user.elicitation.result",
    ] {
        let result = block_on(async {
            c.event(specialized_event(name))
                .initial_state(Decision::Allow)
                .await
        });
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("unverified boundary settled: {name}"),
        };
        assert_eq!(error.kind, BoundaryErrorKind::Preflight);
        assert!(error.partial.is_none());
        assert!(
            error.to_string().contains("content resolver"),
            "{name}: {error}"
        );
    }
}

#[test]
fn elicitation_result_requires_exchange_even_without_selected_body() {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    let store = MemoryContentStore::new(1024, 4096, 8);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    let c = client();
    let result = block_on(async {
        c.event(specialized_event("user.elicitation.result"))
            .content(content)
            .initial_state(Decision::Allow)
            .await
    });
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("uncorrelated result settled"),
    };
    assert_eq!(error.kind, BoundaryErrorKind::Preflight);
    assert!(error.to_string().contains("original exchange"));
}

#[test]
fn elicitation_modes_can_be_narrowed_independently() {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    let store = MemoryContentStore::new(1024, 4096, 8);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    let c = client();
    let result = block_on(async {
        c.event(specialized_event("user.elicitation.request"))
            .content(content)
            .capabilities(json!({"effects":[],"elicitation":{"form":{}}}))
            .await
    });
    assert!(result.is_ok());
}

fn outbound(items: Value) -> Value {
    json!({"id":"outbound","source":"urn:test:runtime","type":"user.message.outbound","time":"2026-09-15T12:00:00Z","message":{"channel":"chat","payload":items}})
}
fn selected_item(
    content: &agenthooksprotocol::content::ContentContext<'_>,
    media: &str,
    bytes: &[u8],
) -> Value {
    json!({"id":"item","kind":"content","category":"content","role":"assistant","mediaType":media,"selection":"body","body":content.put(bytes).unwrap()})
}
#[test]
fn generic_body_grants_require_mapping_resolver_selection_and_supported_encoding() {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    let store = MemoryContentStore::new(1024, 16384, 64);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    for (media, bytes, view, resolver, mapping, expected) in [
        (
            "text/plain",
            b"text".as_slice(),
            "body",
            true,
            true,
            Some(false),
        ),
        (
            "application/json",
            b"{}".as_slice(),
            "body",
            true,
            true,
            Some(true),
        ),
        (
            "application/json",
            b"[]".as_slice(),
            "body",
            true,
            true,
            Some(false),
        ),
        (
            "application/octet-stream",
            b"binary".as_slice(),
            "body",
            true,
            true,
            None,
        ),
        (
            "text/plain",
            b"text".as_slice(),
            "metadata",
            true,
            true,
            None,
        ),
        ("text/plain", b"text".as_slice(), "omit", true, true, None),
        ("text/plain", b"text".as_slice(), "gap", true, true, None),
        ("text/plain", b"text".as_slice(), "body", false, true, None),
        ("text/plain", b"text".as_slice(), "body", true, false, None),
    ] {
        let calls = Rc::new(RefCell::new(vec![]));
        let c = client().with_subscription(subscription("inspect", json!([]), &calls));
        let mut item = selected_item(&content, media, bytes);
        if view != "body" {
            item.as_object_mut().unwrap().remove("body");
            if view == "gap" {
                item["gap"] = json!({"reason":"unavailable"});
            } else {
                item["selection"] = json!(view);
            }
        }
        let mut boundary = c.event(outbound(json!([item])));
        if resolver {
            boundary = boundary.content(content.clone());
        }
        if mapping {
            boundary = boundary.content_target("content", "/message/payload/0");
        }
        let result = block_on(async { boundary.await });
        assert!(result.is_ok(), "case {media}/{view}/{resolver}/{mapping}");
        let calls = calls.borrow();
        let caps = &calls[0]["params"]["capabilities"];
        match expected {
            Some(merge) => assert_eq!(
                caps["modify"]["content"],
                json!({"replace":true,"merge":merge})
            ),
            None => {
                assert!(caps.get("modify").is_none());
                assert!(
                    !caps["effects"]
                        .as_array()
                        .unwrap()
                        .contains(&json!("modify"))
                );
            }
        }
    }
}
#[test]
fn explicit_content_mapping_ignores_misleading_metadata_and_preserves_siblings() {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    let store = MemoryContentStore::new(1024, 16384, 64);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    let sibling = selected_item(&content, "text/plain", b"attachment");
    let mut primary = selected_item(&content, "text/plain", b"primary");
    primary["id"] = json!("host-primary");
    primary["kind"] = json!("attachment");
    primary["category"] = json!("unrelated");
    primary["role"] = json!("system");
    let calls = Rc::new(RefCell::new(vec![]));
    let c = client().with_subscription(subscription(
        "modify",
        json!([{"type":"modify","target":"content","operation":"replace","value":"changed"}]),
        &calls,
    ));
    let result = block_on(async {
        c.event(outbound(json!([sibling, primary])))
            .content(content.clone())
            .content_target("content", "/message/payload/1")
            .await
            .unwrap()
    });
    assert!(result.outcome.failures.is_empty());
    assert_eq!(result.effective_event["message"]["payload"][0], sibling);
    let item = &result.effective_event["message"]["payload"][1];
    assert_eq!(item["id"], "host-primary");
    assert_eq!(
        content.resolve_selected(item).unwrap().unwrap().as_ref(),
        b"changed"
    );
}
#[test]
fn restored_generic_body_keeps_original_reference_approval_and_candidate() {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    let store = MemoryContentStore::new(1024, 16384, 64);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    let original = outbound(json!([selected_item(&content, "text/plain", b"original")]));
    let calls = Rc::new(RefCell::new(vec![]));
    let c = client().with_subscription(subscription(
        "restore",
        json!([
            {"type":"modify","target":"content","operation":"replace","value":"temporary"},
            {"type":"modify","target":"content","operation":"replace","value":"original"}
        ]),
        &calls,
    ));
    let result = block_on(async {
        c.event(original.clone())
            .content(content)
            .content_target("content", "/message/payload/0")
            .initial_state(Decision::Allow)
            .initial_candidate(json!({"value":"candidate","provenance":{"source":"native"}}))
            .await
            .unwrap()
    });
    assert!(result.outcome.failures.is_empty());
    assert_eq!(result.effective_event, original);
    assert_eq!(result.outcome.decision, Decision::Allow);
    assert_eq!(result.outcome.candidate, Some(json!("candidate")));
    assert!(!result.outcome.approval_invalidated);
}
#[test]
fn content_mapping_rejects_noncanonical_or_nested_locations_before_dispatch() {
    let calls = Rc::new(RefCell::new(vec![]));
    let c = client().with_subscription(subscription("inspect", json!([]), &calls));
    for pointer in [
        "/tool/input",
        "/message/payload/0/body",
        "/message/payload/99",
        "/message/payload/00",
    ] {
        let item =
            json!({"id":"item","kind":"content","mediaType":"text/plain","selection":"metadata"});
        assert!(
            block_on(async {
                c.event(outbound(json!([item])))
                    .content_target("content", pointer)
                    .await
            })
            .is_err()
        );
    }
    assert!(calls.borrow().is_empty());
}

#[test]
fn compaction_unselected_targets_do_not_advertise_modify() {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    let store = MemoryContentStore::new(1024, 16384, 64);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    for (name, target) in [
        ("context.compact.before", "instructions"),
        ("context.compact.after", "summary"),
    ] {
        for selection in ["metadata", "omit", "absent"] {
            if target == "summary" && selection == "absent" {
                continue;
            }
            let mut event = specialized_event(name);
            if selection == "absent" {
                event.as_object_mut().unwrap().remove(target);
            } else {
                event[target] = json!({"id":"target","kind":target,"role":"assistant","mediaType":"text/plain","selection":selection});
            }
            let calls = Rc::new(RefCell::new(vec![]));
            let c = client().with_subscription(subscription("inspect", json!([]), &calls));
            let result = block_on(async { c.event(event).content(content.clone()).await });
            assert!(result.is_ok(), "{name}/{selection}");
            let calls = calls.borrow();
            let caps = &calls[0]["params"]["capabilities"];
            assert!(caps.get("modify").is_none());
            let effects = caps["effects"].as_array().unwrap();
            assert!(!effects.contains(&json!("modify")));
            assert!(effects.contains(&json!("message")));
            assert!(effects.contains(&json!("inject")));
        }
    }
}

#[test]
fn elicitation_unselected_request_advertises_only_independent_messages() {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    let store = MemoryContentStore::new(1024, 16384, 64);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    for selection in ["metadata", "omit", "absent"] {
        let mut event = specialized_event("user.elicitation.request");
        if selection != "absent" {
            event["elicitation"]["request"] = json!({"id":"request-item","kind":"elicitation.request","mediaType":"application/json","selection":selection});
        }
        let calls = Rc::new(RefCell::new(vec![]));
        let c = client().with_subscription(subscription("inspect", json!([]), &calls));
        let result = block_on(async { c.event(event).content(content.clone()).await });
        assert!(result.is_ok(), "{selection}");
        assert_eq!(
            calls.borrow()[0]["params"]["capabilities"]["effects"],
            json!(["message"])
        );
    }
}

#[test]
fn elicitation_result_modify_requires_both_original_request_and_current_result_bodies() {
    use agenthooksprotocol::{
        content::{AuthorizedScope, ContentContext, MemoryContentStore},
        elicitation::Exchange,
    };
    let store = MemoryContentStore::new(2048, 32768, 64);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    for (original_selected, result_selected) in
        [(false, true), (true, false), (false, false), (true, true)]
    {
        let mut request_event = specialized_event("user.elicitation.request");
        request_event["id"] = json!("request");
        request_event["elicitation"]["request"] = if original_selected {
            selected_item(&content, "application/json", br#"{"message":"Name?","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}}}}"#)
        } else {
            json!({"id":"original","kind":"elicitation.request","mediaType":"application/json","selection":"metadata"})
        };
        let envelope = json!({"jsonrpc":"2.0","id":"request","method":"hooks/intercept","params":{"protocolVersion":"draft","event":request_event,"capabilities":{"effects":[],"elicitation":{"form":{}}}}});
        let exchange = Exchange::new(&envelope, &content).unwrap();
        let mut event = specialized_event("user.elicitation.result");
        event["elicitation"]["action"] = json!("accept");
        event["elicitation"]["result"] = if result_selected {
            selected_item(
                &content,
                "application/json",
                br#"{"action":"accept","content":{"name":"Ada"}}"#,
            )
        } else {
            json!({"id":"result","kind":"elicitation.result","mediaType":"application/json","selection":"metadata"})
        };
        let calls = Rc::new(RefCell::new(vec![]));
        let c = client().with_subscription(subscription("inspect", json!([]), &calls));
        let result = block_on(async {
            c.event(event)
                .content(content.clone())
                .elicitation_exchange(&exchange)
                .await
        });
        assert!(result.is_ok(), "{original_selected}/{result_selected}");
        let calls = calls.borrow();
        let caps = &calls[0]["params"]["capabilities"];
        assert_eq!(
            caps.get("modify").is_some(),
            original_selected && result_selected
        );
        assert!(
            caps["effects"]
                .as_array()
                .unwrap()
                .contains(&json!("message"))
        );
    }
}
