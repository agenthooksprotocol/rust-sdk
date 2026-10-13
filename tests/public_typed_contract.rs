//! Regressions exercise the registered public facade, including receipt restoration.
use agenthooksprotocol::{
    Hooks,
    adapters::registered::ManagedBackend,
    capability,
    client::{HookError, LocalFuture},
    hooks::HooksOptions,
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

struct Reply(Value);
impl ManagedBackend for Reply {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move { Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":self.0})) })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}
fn hooks(name: &str, caps: capability::HostCapabilities, result: Value) -> Hooks {
    Hooks::new(
        json!({"protocolVersion":"draft","hooks":[{"id":"org.example.typed",
        "transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},
        "subscriptions":[{"events":[name],"mode":"intercept","failurePolicy":"fail-open",
        "timeoutMs":1000,"content":{"default":"body"}}]}]}),
        HooksOptions::new(
            "urn:test:typed",
            agenthooksprotocol::hooks::Harness::new("test", "1"),
            caps,
        )
        .with_backend("org.example.typed", Arc::new(Reply(result))),
    )
    .unwrap()
}
fn event(name: &str, fields: Value) -> Value {
    let mut event = json!({"id":"evt","session":{"id":"session"},"harness":{"name":"test","version":"1"},"source":"urn:test:typed","time":"2026-09-15T12:00:00Z",
        "type":name,"unknown":{"parts":[{"kind":"attachment","body":{"ref":"opaque"}}]}});
    event
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    event
}
fn text(value: &str) -> Value {
    json!({"id":"text","kind":"text","mediaType":"text/plain","selection":"body","text":value})
}
fn messages(value: &str) -> Value {
    json!([{"id":"message","role":"assistant","parts":[text(value)]}])
}
fn result(effects: Value) -> Value {
    json!({"protocolVersion":"draft","effects":effects})
}
fn edit(target: &str, value: Value) -> Value {
    json!({"type":"modify","target":target,"operation":"replace","value":value})
}

#[test]
fn omitted_and_empty_effects_are_neutral_through_registered_backend() {
    use agenthooksprotocol::{ToolBeforeInputOrigin, inputs::ToolBeforeInput};
    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
    struct Arguments {
        count: u64,
    }
    futures::executor::block_on(async {
        for reply in [json!({"protocolVersion":"draft"}), result(json!([]))] {
            let hooks = hooks(
                "tool.before",
                capability::HostCapabilities {
                    tool_before: Some(capability::tool_before().message()),
                    ..Default::default()
                },
                reply,
            );
            let outcome = hooks
                .tool_before(ToolBeforeInput::new(
                    "call".into(),
                    "native".into(),
                    Arguments { count: u64::MAX },
                    "counter".into(),
                    ToolBeforeInputOrigin::Native,
                ))
                .await
                .unwrap();
            assert!(
                outcome.outcome.failures.is_empty(),
                "{:?}",
                outcome.outcome.failures
            );
            assert_eq!(outcome.input, Arguments { count: u64::MAX });
            assert!(outcome.outcome.settled_candidate.is_none());
            assert!(outcome.outcome.messages.is_empty());
            assert!(outcome.outcome.injections.is_empty());
            hooks.shutdown().await.unwrap();
        }
    });
}

#[test]
fn compaction_inline_instructions_and_summary_edits_do_not_insert_parts() {
    futures::executor::block_on(async {
        for after in [false, true] {
            let name = if after {
                "context.compact.after"
            } else {
                "context.compact.before"
            };
            let target = if after { "summary" } else { "instructions" };
            let mut fields = if after {
                json!({"removed":[],"execution":{"status":"executed"}})
            } else {
                json!({"trigger":"manual","items":[]})
            };
            fields[target] = json!([text("original")]);
            let original = event(name, fields);
            let replacement = json!([text(" revised\r\nλ ")]);
            let hooks = hooks(
                name,
                if after {
                    capability::HostCapabilities {
                        context_compact_after: Some(
                            capability::context_compact_after()
                                .modify_summary(capability::Modify::ReplaceAndMerge),
                        ),
                        ..Default::default()
                    }
                } else {
                    capability::HostCapabilities {
                        context_compact_before: Some(
                            capability::context_compact_before()
                                .modify_instructions(capability::Modify::ReplaceAndMerge),
                        ),
                        ..Default::default()
                    }
                },
                result(json!([edit(target, replacement.clone())])),
            );
            let outcome = hooks.event(original.clone()).await.unwrap();
            assert!(
                outcome.outcome.failures.is_empty(),
                "{:?}",
                outcome.outcome.failures
            );
            assert_eq!(
                serde_json::to_value(&outcome.event).unwrap()[target],
                replacement
            );
            assert!(
                serde_json::to_value(&outcome.event).unwrap()[target][0]
                    .get("parts")
                    .is_none()
            );
            assert_eq!(
                serde_json::to_value(&outcome.event).unwrap()["unknown"],
                original["unknown"]
            );
            assert_eq!(original[target][0]["text"], "original");
            hooks.shutdown().await.unwrap();
        }
    });
}

#[test]
fn known_messages_model_return_and_opaque_workspace_forward_unknown_bags() {
    futures::executor::block_on(async {
        for (name, fields, caps, effects, pointer, expected) in [
            (
                "model.request.before",
                json!({"model":{"id":"small","provider":"example"},"attempt":{"id":"attempt","number":1},"params":{},"items":[]}),
                capability::HostCapabilities {
                    model_request_before: Some(
                        capability::model_request_before()
                            .modify_request(capability::Modify::Replace)
                            .return_result(),
                    ),
                    ..Default::default()
                },
                json!([edit("request",messages("request")),{"type":"return","value":messages("candidate")}]),
                "/items",
                messages("request"),
            ),
            (
                "user.message.outbound",
                json!({"message":{"channel":"test","messages":messages("old")}}),
                capability::HostCapabilities {
                    user_message_outbound: Some(
                        capability::user_message_outbound()
                            .modify_content(capability::Modify::Replace),
                    ),
                    ..Default::default()
                },
                json!([edit("content", messages("new"))]),
                "/message/messages",
                messages("new"),
            ),
            (
                "workspace.change.before",
                json!({"workspace":{"kind":"cwd","change":{"cwd":"/old"},"prior":{"cwd":"/prior"}}}),
                capability::HostCapabilities {
                    workspace_change_before: Some(
                        capability::workspace_change_before()
                            .modify_workspace(capability::Modify::Replace),
                    ),
                    ..Default::default()
                },
                json!([edit("workspace", json!({"cwd":"/new"}))]),
                "/workspace/change",
                json!({"cwd":"/new"}),
            ),
        ] {
            let original = event(name, fields);
            let hooks = hooks(name, caps, result(effects));
            let outcome = hooks.event(original.clone()).await.unwrap();
            assert!(
                outcome.outcome.failures.is_empty(),
                "{name}: {:?}",
                outcome.outcome.failures
            );
            assert_eq!(
                serde_json::to_value(&outcome.event)
                    .unwrap()
                    .pointer(pointer)
                    .unwrap(),
                &expected
            );
            assert_eq!(
                serde_json::to_value(&outcome.event).unwrap()["unknown"],
                original["unknown"]
            );
            if name == "model.request.before" {
                assert_eq!(
                    outcome
                        .outcome
                        .candidate_as::<Value, Value>()
                        .unwrap()
                        .map(|c| c.value),
                    Some(messages("candidate"))
                );
            }
            hooks.shutdown().await.unwrap();
        }
    });
}

#[test]
fn invalid_response_rolls_back_all_edits() {
    futures::executor::block_on(async {
        let original = event(
            "user.message.outbound",
            json!({"message":{"channel":"test","messages":messages("old")}}),
        );
        let hooks = hooks(
            "user.message.outbound",
            capability::HostCapabilities {
                user_message_outbound: Some(
                    capability::user_message_outbound().modify_content(capability::Modify::Replace),
                ),
                ..Default::default()
            },
            result(json!([
                edit("content", messages("leak")),
                edit("content", json!([{"id":"invalid"}]))
            ])),
        );
        let outcome = hooks.event(original.clone()).await.unwrap();
        assert_eq!(outcome.outcome.failures.len(), 1);
        assert_eq!(serde_json::to_value(&outcome.event).unwrap(), original);
        hooks.shutdown().await.unwrap();
    });
}

#[test]
fn elicitation_result_candidate_preserves_opaque_metadata() {
    futures::executor::block_on(async {
        let body = json!({"message":"Answer?","requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}});
        let original = event(
            "user.elicitation.request",
            json!({"elicitation":{"server":"mcp-server","mode":"form",
            "request":{"id":"request","kind":"text","mediaType":"text/plain","selection":"body","text":body.to_string()}}}),
        );
        let candidate = json!({"action":"decline","_meta":{"parts":[{"kind":"attachment","body":{"ref":"opaque"}}]}});
        let hooks = hooks(
            "user.elicitation.request",
            capability::HostCapabilities {
                user_elicitation_request: Some(
                    capability::user_elicitation_request()
                        .return_result()
                        .elicitation_form(),
                ),
                ..Default::default()
            },
            result(json!([{"type":"return","value":candidate}])),
        );
        let outcome = hooks.event(original.clone()).await.unwrap();
        assert!(
            outcome.outcome.failures.is_empty(),
            "{:?}",
            outcome.outcome.failures
        );
        assert_eq!(
            outcome
                .outcome
                .candidate_as::<Value, Value>()
                .unwrap()
                .map(|c| c.value),
            Some(candidate)
        );
        assert_eq!(serde_json::to_value(&outcome.event).unwrap(), original);
        hooks.shutdown().await.unwrap();
    });
}

#[test]
fn session_counters_are_lossless_unbounded_and_nonnegative_in_full_sdk_decoding() {
    use agenthooksprotocol::generated::{Presence, SessionCounters};
    let huge = "123456789012345678901234567890123456789012345678901234567890";
    let raw: Value = serde_json::from_str(&format!(
        r#"{{"turns":{huge},"inputTokens":{huge},"hostCounter":{huge}}}"#
    ))
    .unwrap();
    let counters: SessionCounters = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(serde_json::to_value(&counters).unwrap(), raw);
    let Presence::Present(turns) = counters.turns else {
        panic!("missing typed counter")
    };
    assert_eq!(turns.as_number().to_string(), huge);
    for invalid in [
        json!({"turns":-1}),
        json!({"hostCounter":-1}),
        json!({"turns":1.5}),
        json!({"hostCounter":true}),
    ] {
        assert!(serde_json::from_value::<SessionCounters>(invalid).is_err());
    }
    futures::executor::block_on(async {
        let name = "model.request.before";
        let mut original = event(
            name,
            json!({"model":{"id":"small","provider":"example"},"attempt":{"id":"attempt","number":1},"params":{},"items":[]}),
        );
        original["session"]["counters"] = raw.clone();
        let hooks = hooks(
            name,
            capability::HostCapabilities {
                model_request_before: Some(capability::model_request_before().message()),
                ..Default::default()
            },
            result(json!([])),
        );
        let outcome = hooks.event(original.clone()).await.unwrap();
        assert!(outcome.outcome.failures.is_empty());
        assert_eq!(
            serde_json::to_value(&outcome.event).unwrap()["session"]["counters"],
            raw
        );
        assert_eq!(serde_json::to_value(&outcome.event).unwrap(), original);
        hooks.shutdown().await.unwrap();
    });
}
