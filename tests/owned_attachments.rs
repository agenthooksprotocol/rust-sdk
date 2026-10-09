use agenthooksprotocol::{
    Attachment, Hooks,
    body::{BodyChunkFuture, BodyStream},
    ergonomic_inputs::user_message_outbound_sources::message_payload,
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
    json!({"type":"user.message.outbound", "message":{"channel":"chat", "payload":[{
        "id":"file", "kind":"content", "category":"content", "role":"assistant", "mediaType":"application/octet-stream", "selection":"metadata"
    }]}})
}
#[test]
fn metadata_retains_unread_source_after_shutdown_and_returns_immutable_bytes() {
    block_on(async {
        let hooks = hooks(10);
        let (source, reads, drops) = source();
        let result = hooks
            .event(event())
            .attachment(message_payload(0, source))
            .await
            .unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        hooks.shutdown().await.unwrap();
        drop(hooks);
        let bytes = result.content.read("/message/payload/0").await.unwrap();
        assert_eq!(&*bytes, &[0, 255, 42]);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let again = result.content.read("/message/payload/0").await.unwrap();
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
            .event(event())
            .attachment(message_payload(0, source))
            .into_future(),
    )
    .unwrap();
    drop(result);
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let (source, reads, drops) = self::source();
    drop(
        hooks
            .event(event())
            .attachment(message_payload(0, source))
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
            .event(event())
            .attachment(message_payload(0, source))
            .await
            .unwrap();
        assert!(result.content.read("/message/payload/0").await.is_err());
        assert!(result.content.read("/message/payload/0").await.is_err());
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(
            hooks
                .event(event())
                .attachment(message_payload(0, Attachment::bytes(vec![1, 2, 3])))
                .await
                .is_err()
        );
        let result = hooks
            .event(event())
            .attachment(message_payload(0, Attachment::bytes(vec![1, 2])))
            .await
            .unwrap();
        hooks.shutdown().await.unwrap();
        assert_eq!(
            &*result.content.read("/message/payload/0").await.unwrap(),
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
            .user_message_outbound(input.clone())
            .attachment(message_payload(0, attachment))
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(input).unwrap(), original);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        drop(hooks);
        assert_eq!(
            &*result.content.read("/message/payload/0").await.unwrap(),
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
            .event(event())
            .attachment(message_payload(0, Attachment::lazy(Pending(drops.clone()))))
            .into_future(),
    )
    .unwrap();
    let mut read = Box::pin(result.content.read("/message/payload/0"));
    assert!(matches!(
        read.as_mut()
            .poll(&mut Context::from_waker(futures::task::noop_waker_ref())),
        Poll::Pending
    ));
    drop(read);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(block_on(result.content.read("/message/payload/0")).is_err());
}

#[test]
fn invalid_binding_and_chunk_limit_drop_owned_sources() {
    let hooks = hooks(10);
    let (attachment, reads, drops) = source();
    assert!(
        block_on(
            hooks
                .event(event())
                .attachment(message_payload(99, attachment))
                .into_future()
        )
        .is_err()
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let (attachment, _, drops) = source();
    let result = block_on(
        hooks
            .event(event())
            .attachment(message_payload(0, attachment.with_max_chunks(0)))
            .into_future(),
    )
    .unwrap();
    assert!(block_on(result.content.read("/message/payload/0")).is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn invocation_cancellation_and_timeout_drop_unopened_sources() {
    let hooks = hooks(10);
    for cancelled in [true, false] {
        let (attachment, reads, drops) = source();
        let boundary = hooks
            .event(event())
            .attachment(message_payload(0, attachment));
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
fn attachment_integrity_metadata_is_checked_on_demand_not_sent_on_wire() {
    block_on(async {
        for metadata in [json!({"size":999}), json!({"sha256":"0".repeat(64)})] {
            let hooks = hooks(10);
            let (attachment, reads, drops) = source();
            let mut input = event();
            input["message"]["payload"][0]
                .as_object_mut()
                .unwrap()
                .extend(metadata.as_object().unwrap().clone());
            let result = hooks
                .event(input)
                .attachment(message_payload(0, attachment))
                .await
                .unwrap();
            assert_eq!(reads.load(Ordering::SeqCst), 0);
            let item = &result.effective_event["message"]["payload"][0];
            assert!(item.get("size").is_none());
            assert!(item.get("sha256").is_none());
            assert!(result.content.read("/message/payload/0").await.is_err());
            let attempted = reads.load(Ordering::SeqCst);
            assert!(attempted > 0);
            assert!(result.content.read("/message/payload/0").await.is_err());
            assert_eq!(reads.load(Ordering::SeqCst), attempted);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
        let hooks = hooks(10);
        let (attachment, reads, drops) = source();
        let mut input = event();
        input["message"]["payload"][0]["size"] = json!(3);
        let result = hooks
            .event(input)
            .attachment(message_payload(0, attachment))
            .await
            .unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(
            result
                .content
                .read("/message/payload/0")
                .await
                .unwrap()
                .as_ref(),
            &[0, 255, 42]
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn specialized_attachment_slots_and_elicitation_exchange_outlive_hooks() {
    use agenthooksprotocol::ergonomic_inputs::{
        context_compact_before_sources::instructions,
        user_elicitation_request_sources::elicitation_request,
    };
    block_on(async {
        let cases = [
            ("context.compact.before", "/instructions", json!({
                "type":"context.compact.before", "trigger":"manual", "items":[],
                "instructions":{"id":"instructions","kind":"instructions","mediaType":"text/plain","selection":"metadata"}
            }), b"compact these items".to_vec()),
            ("user.elicitation.request", "/elicitation/request", json!({
                "type":"user.elicitation.request", "elicitation":{"server":"mcp-server","mode":"form",
                "request":{"id":"request","kind":"elicitation.request","mediaType":"application/json","selection":"metadata"}}
            }), serde_json::to_vec(&json!({"message":"Your answer", "requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}})).unwrap()),
        ];
        for (name, path, event, bytes) in cases {
            let mut config = registration();
            config["hooks"][0]["subscriptions"][0]["events"] = json!([name]);
            let options = HooksOptions::new(
                "urn:test:specialized",
                BTreeMap::from([(
                    name.into(),
                    EventGrant::intercept(if name == "user.elicitation.request" {
                        Capabilities::none().elicitation_form()
                    } else {
                        Capabilities::none()
                    }),
                )]),
            )
            .with_backend("org.example.attachments", Arc::new(Noop));
            let hooks = Hooks::new(config, options).unwrap();
            let boundary = hooks.event(event);
            let result = if name == "context.compact.before" {
                boundary
                    .attachment(instructions(Attachment::bytes(bytes.clone())))
                    .await
                    .unwrap()
            } else {
                boundary
                    .attachment(elicitation_request(Attachment::bytes(bytes.clone())))
                    .await
                    .unwrap()
            };
            assert!(
                result.outcome.failures.is_empty(),
                "{:?}",
                result.outcome.failures
            );
            hooks.shutdown().await.unwrap();
            drop(hooks);
            assert_eq!(result.content.read(path).await.unwrap().as_ref(), bytes);
            if name == "user.elicitation.request" {
                let envelope = json!({"jsonrpc":"2.0","id":result.effective_event["id"],"method":"hooks/intercept","params":{"protocolVersion":"draft","event":result.effective_event,
                    "capabilities":{"effects":["return","deny","message"],"elicitation":{"form":{}}}}});
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
