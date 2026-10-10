use agenthooksprotocol::{
    client::*,
    content::{AuthorizedScope, ContentContext, MemoryContentStore},
};
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

struct Effects {
    effects: Value,
    calls: Arc<Mutex<Vec<Value>>>,
}
impl Hook for Effects {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(request.clone());
            Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":{
                "protocolVersion":"draft","effects":self.effects
            }}))
        })
    }
}
fn subscription(id: &str, effects: Value, calls: &Arc<Mutex<Vec<Value>>>) -> Subscription {
    let mut sub = Subscription::intercept(
        id,
        FailurePolicy::Open,
        Effects {
            effects,
            calls: calls.clone(),
        },
    );
    sub.events = vec!["*".into()];
    sub
}
fn client(effects: Value, calls: &Arc<Mutex<Vec<Value>>>) -> Client {
    Client::new(ToolContext::new(json!({})))
        .with_subscription(subscription("family", effects, calls))
}
// Fixtures follow the canonical draft schemas, with an open-envelope host field.
fn event(name: &str, fields: Value) -> Value {
    let mut event = json!({"id":"evt_family","source":"https://example.test/runtime",
        "type":name,"time":"2026-08-24T08:51:14Z","hostMetadata":{"trace":"retained"}});
    event
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    event
}
fn tool() -> Value {
    json!({"name":"read_file","origin":"native","input":{"path":"README.md"}})
}
fn model() -> Value {
    json!({"id":"small","provider":"example"})
}

#[test]
fn session_start_collects_injection_and_message_without_rewriting_event() {
    let input = event(
        "session.start",
        json!({
            "session":{"id":"session_1"},"trigger":"startup",
            "harness":{"name":"test","version":"1"},"permissionMode":"ask","items":[],
            "manifest":{"events":[],"gaps":[],"transports":["in_process"],"authentication":[],
                "toolPaths":["native"],"contentCategories":[],"limits":{},
                "managedPolicy":{"scopes":[],"disableable":true},"correlationIdentityFields":[]}
        }),
    );
    let inject = json!({"type":"inject","target":"context","operation":"append",
        "deliverAt":"now","value":[{"id":"injection","role":"system","parts":[{"id":"text","kind":"text","mediaType":"text/plain","selection":"body","text":"Read the project instructions before editing."}]}]});
    let message = json!({"type":"message","text":"Project instructions queued."});
    let calls = Arc::new(Mutex::new(vec![]));
    let c = client(json!([inject, message]), &calls);
    let result = block_on(async { c.event(input.clone()).await.unwrap() });
    assert!(result.outcome.failures.is_empty());
    assert_eq!(result.outcome.injections, vec![inject]);
    assert_eq!(result.outcome.messages, vec![message]);
    assert_eq!(result.event.unwrap(), input);
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn config_and_task_changes_can_be_denied_without_applying_changes() {
    for input in [
        event(
            "config.change.before",
            json!({"change":{"source":"project","scope":"project",
            "settings":["permissions"],"summary":"Relax tool permissions"}}),
        ),
        event(
            "task.change.before",
            json!({"task":{"id":"task_1","operation":"update",
            "change":{"status":"done"},"prior":{"status":"active"}}}),
        ),
    ] {
        let calls = Arc::new(Mutex::new(vec![]));
        let c = client(json!([{"type":"deny","reason":"Review required"}]), &calls);
        let result = block_on(async { c.event(input.clone()).await.unwrap() });
        assert!(result.outcome.failures.is_empty());
        assert!(result.outcome.is_denied());
        assert!(!result.outcome.can_execute());
        assert_eq!(result.event.unwrap(), input);
    }
}

#[test]
fn model_switch_stop_prevents_later_interception() {
    let input = event(
        "model.switch.before",
        json!({"current":model(),
        "proposed":{"id":"large","provider":"example"},"reason":"Need more context"}),
    );
    let calls = Arc::new(Mutex::new(vec![]));
    let c = client(
        json!([{"type":"flow","operation":"stop","reason":"Budget exhausted"}]),
        &calls,
    )
    .with_subscription(subscription(
        "unreached",
        json!([{"type":"message","text":"late"}]),
        &calls,
    ));
    let result = block_on(async { c.event(input.clone()).await.unwrap() });
    assert!(result.outcome.failures.is_empty());
    assert!(result.outcome.stopped);
    assert!(!result.outcome.can_execute());
    assert_eq!(result.event.unwrap(), input);
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[derive(Debug, Serialize, Deserialize)]
struct ModelRequest {
    params: BTreeMap<String, Value>,
    #[serde(flatten)]
    envelope: BTreeMap<String, Value>,
}
#[test]
fn model_request_appends_messages_preserves_params_and_settles_typed_event() {
    let input = event(
        "model.request.before",
        json!({"model":model(),"attempt":{"id":"attempt_1","number":1},
        "params":{"temperature":1,"hostOption":"preserved"},"items":[]}),
    );
    let typed: ModelRequest = serde_json::from_value(input).unwrap();
    let calls = Arc::new(Mutex::new(vec![]));
    let candidate = json!([{"id":"cached","role":"assistant","parts":[{"id":"cached-text","kind":"text","mediaType":"text/plain","selection":"body","text":"Cached answer"}]}]);
    let c = client(
        json!([
            {"type":"modify","target":"request","operation":"merge","value":[{"id":"request","role":"user","parts":[{"id":"request-text","kind":"text","mediaType":"text/plain","selection":"body","text":"revised request"}]}]},
            {"type":"return","value":candidate}
        ]),
        &calls,
    );
    let result = block_on(async { c.event(typed).await.unwrap() });
    assert!(result.outcome.failures.is_empty());
    assert_eq!(result.outcome.candidate, Some(candidate));
    let typed = result.event.unwrap();
    assert_eq!(typed.params["temperature"], 1);
    assert_eq!(
        typed.envelope["items"][0]["parts"][0]["text"],
        "revised request"
    );
    assert_eq!(typed.params["hostOption"], "preserved");
    assert_eq!(typed.envelope["hostMetadata"]["trace"], "retained");
    assert_eq!(serde_json::to_value(typed).unwrap(), result.effective_event);
}

#[test]
fn permission_input_and_workspace_change_modify_only_their_protocol_targets() {
    for (input, target, patch, pointer, expected) in [
        (
            event(
                "tool.permission.request",
                json!({"call":{"id":"call_1"},"tool":tool(),
            "path":"native","suggestions":[],"sandboxBypass":false}),
            ),
            "input",
            json!({"path":"docs/README.md"}),
            "/tool/input/path",
            json!("docs/README.md"),
        ),
        (
            event(
                "workspace.change.before",
                json!({"workspace":{"kind":"cwd",
            "change":{"cwd":"/project"},"prior":{"cwd":"/home"}}}),
            ),
            "workspace",
            json!({"cwd":"/safe/project"}),
            "/workspace/change/cwd",
            json!("/safe/project"),
        ),
    ] {
        let calls = Arc::new(Mutex::new(vec![]));
        let c = client(
            json!([{"type":"modify","target":target,"operation":"merge","value":patch}]),
            &calls,
        );
        let result = block_on(async { c.event(input.clone()).await.unwrap() });
        assert!(result.outcome.failures.is_empty(), "{target}");
        let mut expected_event = input;
        *expected_event.pointer_mut(pointer).unwrap() = expected;
        assert_eq!(result.effective_event, expected_event);
        assert_eq!(result.event.unwrap(), expected_event);
    }
}

#[test]
fn unknown_effect_rolls_back_entire_model_request_response_before_next_hook() {
    let input = event(
        "model.request.before",
        json!({"model":model(),"attempt":{"id":"attempt_1","number":1},
        "params":{"temperature":1},"items":[]}),
    );
    let calls = Arc::new(Mutex::new(vec![]));
    let c = client(
        json!([
            {"type":"modify","target":"request","operation":"merge","value":[{"id":"request","role":"user","parts":[{"id":"request-text","kind":"text","mediaType":"text/plain","selection":"body","text":"revised request"}]}]},
            {"type":"return","value":"must not survive"},
            {"type":"message","text":"must not survive"},
            {"type":"future_effect"}
        ]),
        &calls,
    )
    .with_subscription(subscription("next", json!([]), &calls));
    let result = block_on(async { c.event(input.clone()).await.unwrap() });
    assert_eq!(result.outcome.failures.len(), 1);
    assert!(result.outcome.candidate.is_none());
    assert!(result.outcome.messages.is_empty());
    assert_eq!(result.effective_event, input);
    assert_eq!(calls.lock().unwrap().len(), 2);
    assert_eq!(calls.lock().unwrap()[1]["params"]["event"], input);
}

#[test]
fn remaining_content_families_replace_inline_lists_preserving_siblings() {
    for (name, target, array, fields) in [
        (
            "turn.start",
            "prompt",
            "/items",
            json!({"turn":{"id":"turn_1"},"trigger":"user"}),
        ),
        (
            "model.response.after",
            "response",
            "/items",
            json!({"model":model(),
            "attempt":{"id":"attempt_1","number":1},"execution":{"status":"executed"},"finishReason":"stop"}),
        ),
        (
            "tool.after",
            "output",
            "/items",
            json!({"call":{"id":"call_1"},"tool":tool(),
            "path":"native","outcome":"ok","execution":{"status":"executed"}}),
        ),
        (
            "user.message.inbound",
            "prompt",
            "/message/messages",
            json!({"message":{"channel":"chat","sender":"user"}}),
        ),
    ] {
        let store = MemoryContentStore::new(1024, 16384, 64);
        let content = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("family"),
        };
        let first = json!({"id":"first","kind":"text","mediaType":"text/plain","selection":"body","text":"leave me alone"});
        let selected = json!({"id":"selected","kind":"text","mediaType":"text/plain","selection":"body","text":"original"});
        let mut input = event(name, fields);
        let parts = json!([first, selected]);
        let messages = json!([{"id":"message","role":match name { "model.response.after" => "assistant", "tool.after" => "tool", _ => "user" },"parts":parts}]);
        let pointer = if array == "/items" {
            input["items"] = messages;
            "/items/0/parts/1"
        } else {
            input["message"]["messages"] = messages;
            "/message/messages/0/parts/1"
        };
        let calls = Arc::new(Mutex::new(vec![]));
        let mut replacement = input.pointer(array).unwrap().clone();
        replacement[0]["parts"][1]["text"] = json!("revised");
        let c = client(
            json!([{"type":"modify","target":target,"operation":"replace","value":replacement}]),
            &calls,
        );
        let result = block_on(async {
            c.event(input.clone())
                .content(content.clone())
                .content_target(target, pointer)
                .await
                .unwrap()
        });
        assert!(result.outcome.failures.is_empty(), "{name}");
        let effective = result.event.unwrap();
        assert_eq!(
            effective.pointer(&pointer.replace("/1", "/0")).unwrap(),
            &first,
            "{name}"
        );
        let mapped = effective.pointer(pointer).unwrap();
        assert_eq!(mapped["text"], "revised", "{name}");
        let mut expected = input;
        expected.pointer_mut(pointer).unwrap()["text"] = mapped["text"].clone();
        assert_eq!(effective, expected, "only mapped body changes: {name}");
        assert_eq!(
            calls.lock().unwrap()[0]["params"]["capabilities"]["modify"][target]["replace"],
            true
        );
    }
}

#[test]
fn tool_output_replacement_substitutes_and_merge_appends_canonical_messages() {
    fn message(id: &str) -> Value {
        json!({"id":id,"role":"tool","parts":[{"id":format!("{id}-text"),"kind":"text","mediaType":"text/plain","selection":"body","text":id}]})
    }
    let original = event(
        "tool.after",
        json!({"call":{"id":"call"},"tool":tool(),"path":"native",
        "outcome":"ok","execution":{"status":"executed"},"items":[message("original")]}),
    );
    let calls = Arc::new(Mutex::new(vec![]));
    let c = client(
        json!([
            {"type":"modify","target":"output","operation":"replace","value":[message("replacement")]},
            {"type":"modify","target":"output","operation":"merge","value":[message("appended"),message("appended")]}
        ]),
        &calls,
    );
    let result = block_on(async { c.event(original.clone()).await.unwrap() });
    assert!(result.outcome.failures.is_empty());
    assert_eq!(
        result.effective_event["items"],
        json!([
            message("replacement"),
            message("appended"),
            message("appended")
        ])
    );
    assert_eq!(original["items"], json!([message("original")]));
    assert!(result.effective_event["tool"].get("output").is_none());
}
