use agenthooksprotocol::{
    content::{AuthorizedScope, ContentContext, MemoryContentStore},
    elicitation::{Exchange, stage_boundary},
};
use serde_json::{Value, json};

fn envelope(context: &ContentContext<'_>, stage: &str, body: &Value) -> Value {
    let reference = context.put(&serde_json::to_vec(body).unwrap()).unwrap();
    let mut meta = json!({"server":"mcp-server","mode":"form"});
    meta[stage] = json!({"id":format!("{stage}-item"),"kind":format!("elicitation.{stage}"),"mediaType":"application/json","selection":"body","body":reference});
    if stage == "result" {
        meta["action"] = body["action"].clone();
    }
    let mut event = json!({"id":stage,"source":"urn:test:host","time":"2026-09-15T12:00:00Z","type":format!("user.elicitation.{stage}"),"session":{"id":"session"},"elicitation":meta});
    if stage == "result" {
        event["parentEventId"] = json!("request");
    }
    let capabilities = if stage == "request" {
        json!({"effects":["return","deny","message"],"elicitation":{"form":{}}})
    } else {
        json!({"effects":["modify","message"],"elicitation":{"form":{}},"modify":{"content":{"replace":true,"merge":true}}})
    };
    json!({"jsonrpc":"2.0","id":stage,"method":"hooks/intercept","params":{"protocolVersion":"draft","event":event,"capabilities":capabilities}})
}
fn form() -> Value {
    json!({"message":"Your answer","requestedSchema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]},"_meta":{"preserved":true}})
}

#[test]
fn original_schema_and_envelope_are_owned_and_result_requires_snapshot() {
    let store = MemoryContentStore::new(100000, 1000000, 100);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("authorized"),
    };
    let mut request = envelope(&context, "request", &form());
    let exchange = Exchange::new(&request, &context).unwrap();
    request["params"]["event"]["elicitation"]["request"]["body"] = context.put(b"{}").unwrap();
    assert_eq!(
        exchange.original_request().unwrap()["_meta"]["preserved"],
        true
    );
    let result = envelope(
        &context,
        "result",
        &json!({"action":"accept","content":{"answer":"yes"},"_meta":{"kept":7}}),
    );
    assert!(stage_boundary(&result, &[], &context, None).is_err());
    let staged = stage_boundary(&result, &[], &context, Some(&exchange)).unwrap();
    assert_eq!(staged["candidate"]["_meta"]["kept"], 7);
    let invalid =
        json!({"type":"modify","target":"content","operation":"replace","value":{"answer":42}});
    assert!(stage_boundary(&result, &[invalid], &context, Some(&exchange)).is_err());
    for field in ["source", "parentEventId"] {
        let mut wrong = result.clone();
        wrong["params"]["event"][field] = json!("wrong");
        assert!(stage_boundary(&wrong, &[], &context, Some(&exchange)).is_err());
    }
}

#[test]
fn stages_publish_complete_immutable_answers_and_fail_atomically() {
    let store = MemoryContentStore::new(100000, 1000000, 100);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("authorized"),
    };
    let request = envelope(&context, "request", &form());
    let exchange = Exchange::new(&request, &context).unwrap();
    let untouched = stage_boundary(&request, &[], &context, None).unwrap();
    assert!(untouched.get("candidate").is_none());
    let deny = stage_boundary(
        &request,
        &[json!({"type":"deny","reason":"policy"})],
        &context,
        None,
    )
    .unwrap();
    assert_eq!(deny["candidate"], json!({"action":"decline"}));
    assert_eq!(deny["denied"], true);
    let result = envelope(
        &context,
        "result",
        &json!({"action":"accept","content":{"answer":"before"},"_meta":{"retained":true}}),
    );
    let modify = json!({"type":"modify","target":"content","operation":"replace","value":{"answer":"after"}});
    let staged = stage_boundary(
        &result,
        std::slice::from_ref(&modify),
        &context,
        Some(&exchange),
    )
    .unwrap();
    let bytes = context
        .resolve(&staged["event"]["elicitation"]["result"]["body"])
        .unwrap();
    let published: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(published["content"]["answer"], "after");
    assert_eq!(published["_meta"]["retained"], true);
    assert_ne!(
        staged["event"]["elicitation"]["result"]["body"],
        result["params"]["event"]["elicitation"]["result"]["body"]
    );
    assert!(
        stage_boundary(
            &result,
            &[
                modify,
                json!({"type":"return","value":{"action":"decline"}})
            ],
            &context,
            Some(&exchange)
        )
        .is_err()
    );
}

#[test]
fn metadata_and_missing_mode_grants_do_not_authorize_effects() {
    let store = MemoryContentStore::new(100000, 1000000, 100);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("authorized"),
    };
    let mut request = envelope(&context, "request", &form());
    request["params"]["capabilities"]["elicitation"] = json!({"url":{}});
    assert!(
        stage_boundary(
            &request,
            &[json!({"type":"return","value":{"action":"decline"}})],
            &context,
            None
        )
        .is_err()
    );
    request["params"]["capabilities"]
        .as_object_mut()
        .unwrap()
        .remove("elicitation");
    let item = &mut request["params"]["event"]["elicitation"]["request"];
    item["selection"] = json!("metadata");
    item.as_object_mut().unwrap().remove("body");
    assert!(
        stage_boundary(&request, &[], &context, None)
            .unwrap()
            .get("candidate")
            .is_none()
    );
    assert!(
        stage_boundary(
            &request,
            &[json!({"type":"deny","reason":"policy"})],
            &context,
            None
        )
        .is_err()
    );
}

#[test]
fn consuming_effects_require_explicit_mode_but_messages_do_not_require_bodies() {
    let store = MemoryContentStore::new(100000, 1000000, 100);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("authorized"),
    };
    let mut request = envelope(&context, "request", &form());
    request["params"]["capabilities"]
        .as_object_mut()
        .unwrap()
        .remove("elicitation");
    let returned = json!({"type":"return","value":{"action":"decline"}});
    assert!(stage_boundary(&request, &[returned], &context, None).is_err());
    let exchange = Exchange::new(&request, &context).unwrap();
    let mut result = envelope(
        &context,
        "result",
        &json!({"action":"accept","content":{"answer":"yes"}}),
    );
    result["params"]["capabilities"]
        .as_object_mut()
        .unwrap()
        .remove("elicitation");
    let modify = json!({"type":"modify","target":"content","operation":"replace","value":{"answer":"after"}});
    assert!(stage_boundary(&result, &[modify], &context, Some(&exchange)).is_err());
    let item = &mut request["params"]["event"]["elicitation"]["request"];
    item["selection"] = json!("metadata");
    item.as_object_mut().unwrap().remove("body");
    request["params"]["capabilities"]["elicitation"] = json!({});
    let message = json!({"type":"message","text":"No body needed"});
    let staged = stage_boundary(&request, std::slice::from_ref(&message), &context, None).unwrap();
    assert_eq!(staged["messages"], json!([message]));
    assert!(staged.get("candidate").is_none());
}

#[test]
fn outer_integrity_hints_are_verified_and_renewed_after_modify() {
    let store = MemoryContentStore::new(100000, 1000000, 100);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("authorized"),
    };
    let mut request = envelope(&context, "request", &form());
    request["params"]["event"]["elicitation"]["request"]["size"] = json!(1);
    assert!(Exchange::new(&request, &context).is_err());
    request["params"]["event"]["elicitation"]["request"]
        .as_object_mut()
        .unwrap()
        .remove("size");
    let exchange = Exchange::new(&request, &context).unwrap();
    let mut result = envelope(
        &context,
        "result",
        &json!({"action":"accept","content":{"answer":"yes"}}),
    );
    let item = &mut result["params"]["event"]["elicitation"]["result"];
    item["size"] = item["body"]["size"].clone();
    item["sha256"] = item["body"]["sha256"].clone();
    let modify = json!({"type":"modify","target":"content","operation":"replace","value":{"answer":"a much longer replacement"}});
    let staged = stage_boundary(&result, &[modify], &context, Some(&exchange)).unwrap();
    let item = &staged["event"]["elicitation"]["result"];
    assert_eq!(item["size"], item["body"]["size"]);
    assert_eq!(item["sha256"], item["body"]["sha256"]);
    assert!(context.resolve_selected(item).unwrap().is_some());
    result["params"]["event"]["elicitation"]["result"]["sha256"] = json!("0".repeat(64));
    assert!(stage_boundary(&result, &[], &context, Some(&exchange)).is_err());
}

#[test]
fn noop_modifications_preserve_exact_descriptor_without_puts_or_reauthorization() {
    use agenthooksprotocol::{
        client::{
            Client, Decision, FailurePolicy, Hook, HookError, LocalFuture, Subscription,
            ToolContext,
        },
        content::{ContentReference, ContentStore, UploadError},
    };
    use std::{cell::Cell, sync::Arc};

    struct CountedStore {
        inner: MemoryContentStore,
        puts: Cell<usize>,
    }
    impl ContentStore for CountedStore {
        fn resolve(
            &self,
            scope: &AuthorizedScope,
            reference: &ContentReference,
        ) -> Result<Arc<[u8]>, UploadError> {
            self.inner.resolve(scope, reference)
        }
        fn put(
            &self,
            scope: &AuthorizedScope,
            bytes: Arc<[u8]>,
        ) -> Result<ContentReference, UploadError> {
            self.puts.set(self.puts.get() + 1);
            self.inner.put(scope, bytes)
        }
    }
    struct Effects(Vec<Value>);
    impl Hook for Effects {
        fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                Ok(
                    json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":self.0}}),
                )
            })
        }
    }
    let store = CountedStore {
        inner: MemoryContentStore::new(100000, 1000000, 100),
        puts: Cell::new(0),
    };
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("authorized"),
    };
    let request = envelope(&context, "request", &form());
    let exchange = Exchange::new(&request, &context).unwrap();
    let mut result = envelope(
        &context,
        "result",
        &json!({"action":"accept","content":{"answer":"yes"},"_meta":{"keep":true}}),
    );
    // Deliberately noncanonical formatting must survive semantic no-ops exactly.
    let bytes = b"{\n \"_meta\": {\"keep\":true}, \"content\": {\"answer\":\"yes\"}, \"action\":\"accept\"\n}";
    let reference = context.put(bytes).unwrap();
    let item = &mut result["params"]["event"]["elicitation"]["result"];
    item["body"] = reference.clone();
    item["size"] = reference["size"].clone();
    item["sha256"] = reference["sha256"].clone();
    let before = store.puts.get();
    let replace =
        json!({"type":"modify","target":"content","operation":"replace","value":{"answer":"yes"}});
    for effects in [
        vec![replace.clone()],
        vec![json!({"type":"modify","target":"content","operation":"merge","value":{}})],
        vec![
            json!({"type":"modify","target":"content","operation":"replace","value":{"answer":"temporary"}}),
            replace,
        ],
    ] {
        let staged = stage_boundary(&result, &effects, &context, Some(&exchange)).unwrap();
        assert_eq!(staged["event"], result["params"]["event"]);
        assert_eq!(store.puts.get(), before);
        assert_eq!(
            context
                .resolve_selected(&staged["event"]["elicitation"]["result"])
                .unwrap()
                .unwrap()
                .as_ref(),
            bytes
        );

        let mut subscription =
            Subscription::intercept("noop", FailurePolicy::Closed, Effects(effects));
        subscription.events = vec!["user.elicitation.result".into()];
        let client = Client::new(ToolContext::new(json!({}))).with_subscription(subscription);
        let settled = futures::executor::block_on(async {
            client
                .event(result["params"]["event"].clone())
                .capabilities(result["params"]["capabilities"].clone())
                .content(context.clone())
                .elicitation_exchange(&exchange)
                .initial_state(Decision::Allow)
                .await
                .unwrap()
        });
        assert!(settled.outcome.failures.is_empty());
        assert_eq!(settled.effective_event, result["params"]["event"]);
        assert_eq!(settled.outcome.decision, Decision::Allow);
        assert!(settled.outcome.authorized);
        assert!(!settled.outcome.approval_invalidated);
        assert_eq!(store.puts.get(), before);
    }
}
