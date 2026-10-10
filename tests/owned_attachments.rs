use agenthooksprotocol::{
    Attachment, Hooks,
    body::{BodyChunkFuture, BodyStream},
    ergonomic_inputs::{HostInput, MessageInput, PartInput, UserMessageOutboundInput},
    generated::CanonicalMessageRole,
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use futures::executor::block_on;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::IntoFuture,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Source {
    reads: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    done: bool,
}
impl Drop for Source {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl BodyStream for Source {
    fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.done {
                Ok(None)
            } else {
                self.done = true;
                Ok(Some(vec![0, 255, 42]))
            }
        })
    }
}
fn source() -> (Attachment, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    (
        Attachment::lazy(Source {
            reads: reads.clone(),
            drops: drops.clone(),
            done: false,
        }),
        reads,
        drops,
    )
}
fn hooks(limit: usize) -> Hooks {
    let mut options = HooksOptions::new(
        "urn:test:attachments",
        BTreeMap::from([(
            "user.message.outbound".into(),
            EventGrant::intercept(Capabilities::none()),
        )]),
    );
    options.max_body_bytes = limit;
    Hooks::new(
        registration(),
        options.with_backend("org.example.attachments", Arc::new(Noop)),
    )
    .unwrap()
}
fn event() -> Value {
    json!({"type":"user.message.outbound", "message":{"channel":"chat", "messages":[{
        "id":"message", "role":"assistant", "parts":[{"id":"body", "kind":"attachment", "mediaType":"application/octet-stream", "selection":"body", "body":{"ref":"ahp:host-pending"}}]
    }]}})
}
fn attachment_input(
    event: Value,
    attachment: Attachment,
) -> HostInput<UserMessageOutboundInput, Attachment> {
    let metadata =
        serde_json::from_value(event["message"]["messages"][0]["parts"][0].clone()).unwrap();
    let input: UserMessageOutboundInput = serde_json::from_value(event).unwrap();
    input
        .with_sources()
        .with_message_messages(vec![MessageInput::from_parts(
            CanonicalMessageRole::Assistant,
            vec![PartInput::attachment(metadata, attachment)],
        )])
}
#[test]
fn mixed_inline_text_and_binary_parts_keep_distinct_ownership() {
    block_on(async {
        let hooks = hooks(10);
        let (attachment, reads, drops) = source();
        let input = UserMessageOutboundInput::new(
            serde_json::from_value(event()["message"].clone()).unwrap(),
        )
        .with_sources()
        .with_message_messages(vec![MessageInput::from_parts(
            CanonicalMessageRole::Assistant,
            vec![
                PartInput::text(agenthooksprotocol::generated::TextBodyPart::new(
                    "caption",
                    "Binary caption",
                )),
                PartInput::owned_attachment("binary", "application/octet-stream", attachment),
            ],
        )]);
        let result = hooks.user_message_outbound(input).await.unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        let parts = &result.effective_event["message"]["messages"][0]["parts"];
        assert_eq!(parts[0]["kind"], "text");
        assert_eq!(parts[0]["text"], "Binary caption");
        assert!(parts[0].get("body").is_none());
        assert_eq!(parts[1]["kind"], "attachment");
        assert_eq!(parts[1]["mediaType"], "application/octet-stream");
        assert!(parts[1].get("text").is_none());
        hooks.shutdown().await.unwrap();
        drop(hooks);
        assert!(
            result
                .content
                .read("/message/messages/0/parts/0")
                .await
                .is_err()
        );
        let bytes = result
            .content
            .read("/message/messages/0/parts/1")
            .await
            .unwrap();
        let again = result
            .content
            .read("/message/messages/0/parts/1")
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), &[0, 255, 42]);
        assert!(Arc::ptr_eq(&bytes, &again));
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn metadata_retains_unread_source_after_shutdown_and_returns_immutable_bytes() {
    block_on(async {
        let hooks = hooks(10);
        let (source, reads, drops) = source();
        let result = hooks
            .user_message_outbound(attachment_input(event(), source))
            .await
            .unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        hooks.shutdown().await.unwrap();
        drop(hooks);
        let bytes = result
            .content
            .read("/message/messages/0/parts/0")
            .await
            .unwrap();
        assert_eq!(&*bytes, &[0, 255, 42]);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let again = result
            .content
            .read("/message/messages/0/parts/0")
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&bytes, &again));
        let mut owned = bytes;
        Arc::make_mut(&mut owned)[0] = 100;
        assert_eq!(again[0], 0);
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    });
}
#[test]
fn unopened_result_and_unpolled_invocation_drop_sources() {
    let hooks = hooks(10);
    let (source, reads, drops) = source();
    let result = block_on(
        hooks
            .user_message_outbound(attachment_input(event(), source))
            .into_future(),
    )
    .unwrap();
    drop(result);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let (source, reads, drops) = self::source();
    drop(
        hooks
            .user_message_outbound(attachment_input(event(), source))
            .into_future(),
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
#[test]
fn eager_and_lazy_limits_are_terminal_and_release_sources() {
    block_on(async {
        let hooks = hooks(2);
        let (source, reads, drops) = source();
        let result = hooks
            .user_message_outbound(attachment_input(event(), source))
            .await
            .unwrap();
        assert!(
            result
                .content
                .read("/message/messages/0/parts/0")
                .await
                .is_err()
        );
        assert!(
            result
                .content
                .read("/message/messages/0/parts/0")
                .await
                .is_err()
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(
            hooks
                .user_message_outbound(attachment_input(event(), Attachment::bytes(vec![1, 2, 3])))
                .await
                .is_err()
        );
        let result = hooks
            .user_message_outbound(attachment_input(event(), Attachment::bytes(vec![1, 2])))
            .await
            .unwrap();
        hooks.shutdown().await.unwrap();
        assert_eq!(
            &*result
                .content
                .read("/message/messages/0/parts/0")
                .await
                .unwrap(),
            &[1, 2]
        );
    });
}

fn registration() -> Value {
    json!({"protocolVersion":"draft", "hooks":[{
        "id":"org.example.attachments", "transport":{"type":"stdio","command":"never-run","lifecycle":"persistent"},
        "subscriptions":[{"events":["user.message.outbound"],"mode":"intercept","timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":"metadata"}}]
    }]})
}
struct Noop;
impl agenthooksprotocol::adapters::registered::ManagedBackend for Noop {
    fn call(
        &self,
        request: Value,
        _: std::time::Duration,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        Result<Value, agenthooksprotocol::client::HookError>,
    > {
        Box::pin(async move {
            Ok(
                json!({"jsonrpc":"2.0", "id":request["id"],"result":{"protocolVersion":"draft","effects":[]}}),
            )
        })
    }
    fn shutdown(
        &self,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        Result<(), agenthooksprotocol::client::HookError>,
    > {
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn no_match_typed_input_is_not_mutated_and_sources_remain_unread() {
    block_on(async {
        let mut config = registration();
        config["hooks"][0]["subscriptions"][0]["filters"] = json!({"paths":["/unrelated/**"]});
        let options = HooksOptions::new(
            "urn:test:attachments",
            BTreeMap::from([(
                "user.message.outbound".into(),
                EventGrant::intercept(Capabilities::none()),
            )]),
        )
        .with_backend("org.example.attachments", Arc::new(UnreachableBackend));
        let hooks = Hooks::new(config, options).unwrap();
        let input: agenthooksprotocol::ergonomic_inputs::UserMessageOutboundInput =
            serde_json::from_value(event()).unwrap();
        let original = serde_json::to_value(&input).unwrap();
        let (attachment, reads, drops) = source();
        let result = hooks
            .user_message_outbound(input.clone().with_sources().with_message_messages(vec![
                MessageInput::from_parts(
                    CanonicalMessageRole::Assistant,
                    vec![PartInput::owned_attachment(
                        "body",
                        "application/octet-stream",
                        attachment,
                    )],
                ),
            ]))
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(input).unwrap(), original);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        drop(hooks);
        assert_eq!(
            &*result
                .content
                .read("/message/messages/0/parts/0")
                .await
                .unwrap(),
            &[0, 255, 42]
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn cancelled_result_read_drops_source_and_cannot_restart() {
    use std::{
        future::Future,
        task::{Context, Poll},
    };
    struct Pending(Arc<AtomicUsize>);
    impl Drop for Pending {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl BodyStream for Pending {
        fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
            Box::pin(std::future::pending())
        }
    }
    let hooks = hooks(10);
    let drops = Arc::new(AtomicUsize::new(0));
    let result = block_on(
        hooks
            .user_message_outbound(attachment_input(
                event(),
                Attachment::lazy(Pending(drops.clone())),
            ))
            .into_future(),
    )
    .unwrap();
    let mut read = Box::pin(result.content.read("/message/messages/0/parts/0"));
    assert!(matches!(
        read.as_mut()
            .poll(&mut Context::from_waker(futures::task::noop_waker_ref())),
        Poll::Pending
    ));
    drop(read);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(block_on(result.content.read("/message/messages/0/parts/0")).is_err());
}

#[test]
fn invalid_binding_and_chunk_limit_drop_owned_sources() {
    let hooks = hooks(10);
    let (attachment, reads, drops) = source();
    assert!(
        block_on(
            hooks
                .user_message_outbound(
                    UserMessageOutboundInput::new(
                        serde_json::from_value(event()["message"].clone()).unwrap()
                    )
                    .with_sources()
                    .with_message_messages(vec![MessageInput::from_parts(
                        CanonicalMessageRole::Assistant,
                        vec![PartInput::owned_attachment(
                            "invalid",
                            "text/plain",
                            attachment
                        )]
                    )])
                )
                .into_future()
        )
        .is_err()
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let (attachment, _, drops) = source();
    let result = block_on(
        hooks
            .user_message_outbound(attachment_input(event(), attachment.with_max_chunks(0)))
            .into_future(),
    )
    .unwrap();
    assert!(block_on(result.content.read("/message/messages/0/parts/0")).is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn invocation_cancellation_and_timeout_drop_unopened_sources() {
    let hooks = hooks(10);
    for cancelled in [true, false] {
        let (attachment, reads, drops) = source();
        let boundary = hooks.user_message_outbound(attachment_input(event(), attachment));
        let boundary = if cancelled {
            boundary.cancel_when(std::future::ready(()))
        } else {
            boundary.budget(std::future::ready(()))
        };
        assert!(block_on(boundary.into_future()).is_err());
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

struct UnreachableBackend;
impl agenthooksprotocol::adapters::registered::ManagedBackend for UnreachableBackend {
    fn call(
        &self,
        _: Value,
        _: std::time::Duration,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        Result<Value, agenthooksprotocol::client::HookError>,
    > {
        panic!("unmatched subscription must not run")
    }
    fn shutdown(
        &self,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        Result<(), agenthooksprotocol::client::HookError>,
    > {
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn forbidden_integrity_metadata_rejects_unopened_owned_sources() {
    block_on(async {
        for metadata in [json!({"size":999}), json!({"sha256":"0".repeat(64)})] {
            let hooks = hooks(10);
            let (attachment, reads, drops) = source();
            let mut part = agenthooksprotocol::generated::AttachmentBodyPart::new(
                agenthooksprotocol::generated::ContentReference::new("ahp:host-pending"),
                "body",
                "application/octet-stream",
            );
            part.additional_properties
                .extend(metadata.as_object().unwrap().clone());
            let input: UserMessageOutboundInput = serde_json::from_value(event()).unwrap();
            let input = input
                .with_sources()
                .with_message_messages(vec![MessageInput::from_parts(
                    CanonicalMessageRole::Assistant,
                    vec![PartInput::attachment(part, attachment)],
                )]);
            assert!(hooks.user_message_outbound(input).await.is_err());
            assert_eq!(reads.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
        let hooks = hooks(10);
        let (attachment, reads, drops) = source();
        let result = hooks
            .user_message_outbound(attachment_input(event(), attachment))
            .await
            .unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        let part = &result.effective_event["message"]["messages"][0]["parts"][0];
        assert!(part.get("size").is_none());
        assert!(part.get("sha256").is_none());
        let first = result
            .content
            .read("/message/messages/0/parts/0")
            .await
            .unwrap();
        let again = result
            .content
            .read("/message/messages/0/parts/0")
            .await
            .unwrap();
        assert_eq!(first.as_ref(), &[0, 255, 42]);
        assert!(Arc::ptr_eq(&first, &again));
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn inline_instructions_and_elicitation_exchange_outlive_hooks() {
    block_on(async {
        let payload = json!({"message":"Your answer", "requestedSchema":{"type":"object", "properties":{"answer":{"type":"string"}}, "required":["answer"]}});
        let cases = [
            (
                "context.compact.before",
                "/instructions/0",
                json!({"type":"context.compact.before", "trigger":"manual", "items":[], "instructions":[{"id":"instructions", "kind":"text", "mediaType":"text/plain", "selection":"body", "text":"compact these items"}]}),
                "compact these items".to_owned(),
            ),
            (
                "user.elicitation.request",
                "/elicitation/request",
                json!({"type":"user.elicitation.request", "elicitation":{"server":"mcp-server", "mode":"form", "request":{"id":"request", "kind":"text", "mediaType":"text/plain", "selection":"body", "text":payload.to_string()}}}),
                payload.to_string(),
            ),
        ];
        for (name, path, event, text) in cases {
            let mut config = registration();
            config["hooks"][0]["subscriptions"][0]["events"] = json!([name]);
            config["hooks"][0]["subscriptions"][0]["content"] = json!({"default":"body"});
            let caps = if name == "user.elicitation.request" {
                Capabilities::none().elicitation_form()
            } else {
                Capabilities::none()
            };
            let options = HooksOptions::new(
                "urn:test:inline",
                BTreeMap::from([(name.into(), EventGrant::intercept(caps))]),
            )
            .with_backend("org.example.attachments", Arc::new(Noop));
            let hooks = Hooks::new(config, options).unwrap();
            let result = hooks.event(event).await.unwrap();
            assert!(
                result.outcome.failures.is_empty(),
                "{:?}",
                result.outcome.failures
            );
            hooks.shutdown().await.unwrap();
            drop(hooks);
            assert_eq!(
                result.effective_event.pointer(path).unwrap()["text"]
                    .as_str()
                    .unwrap()
                    .as_bytes(),
                text.as_bytes()
            );
            if name == "user.elicitation.request" {
                let envelope = json!({"jsonrpc":"2.0", "id":result.effective_event["id"], "method":"hooks/intercept", "params":{"protocolVersion":"draft", "event":result.effective_event, "capabilities":{"effects":["return","deny","message"], "elicitation":{"form":{}}}}});
                let exchange =
                    agenthooksprotocol::elicitation::Exchange::new(&envelope, &result.content)
                        .unwrap();
                drop(result);
                assert_eq!(
                    exchange.original_request().unwrap()["message"],
                    "Your answer"
                );
            }
        }
    });
}
