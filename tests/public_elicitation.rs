use agenthooksprotocol::{
    content::{AuthorizedScope, ContentContext, MemoryContentStore},
    elicitation::{Exchange, stage_boundary},
};
use serde_json::{Value, json};

fn envelope(_context: &ContentContext<'_>, stage: &str, body: &Value) -> Value {
    let mut meta = json!({"server":"mcp-server","mode":"form"});
    meta[stage] = json!({"id":format!("{stage}-item"),"kind":"text","mediaType":"text/plain","selection":"body","text":serde_json::to_string(body).unwrap()});
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
    request["params"]["event"]["elicitation"]["request"]["text"] = json!("{}");
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
    let published: Value = serde_json::from_str(
        staged["event"]["elicitation"]["result"]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(published["content"]["answer"], "after");
    assert_eq!(published["_meta"]["retained"], true);
    assert_ne!(
        staged["event"]["elicitation"]["result"]["text"],
        result["params"]["event"]["elicitation"]["result"]["text"]
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
    item.as_object_mut().unwrap().remove("text");
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
    item.as_object_mut().unwrap().remove("text");
    request["params"]["capabilities"]["elicitation"] = json!({});
    let message = json!({"type":"message","text":"No body needed"});
    let staged = stage_boundary(&request, std::slice::from_ref(&message), &context, None).unwrap();
    assert_eq!(staged["messages"], json!([message]));
    assert!(staged.get("candidate").is_none());
}

#[test]
fn inline_payloads_are_validated_and_rewritten_after_modify() {
    let store = MemoryContentStore::new(100000, 1000000, 100);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("authorized"),
    };
    let mut request = envelope(&context, "request", &form());
    request["params"]["event"]["elicitation"]["request"]["text"] = json!("not JSON");
    assert!(Exchange::new(&request, &context).is_err());
    request["params"]["event"]["elicitation"]["request"]["text"] =
        json!(serde_json::to_string(&form()).unwrap());
    let exchange = Exchange::new(&request, &context).unwrap();
    let mut result = envelope(
        &context,
        "result",
        &json!({"action":"accept","content":{"answer":"yes"}}),
    );
    let modify = json!({"type":"modify","target":"content","operation":"replace","value":{"answer":"a much longer replacement"}});
    let staged = stage_boundary(&result, &[modify], &context, Some(&exchange)).unwrap();
    let item = &staged["event"]["elicitation"]["result"];
    assert!(item.get("size").is_none());
    assert!(item.get("sha256").is_none());
    assert!(item.get("body").is_none());
    let published: Value = serde_json::from_str(item["text"].as_str().unwrap()).unwrap();
    assert_eq!(published["content"]["answer"], "a much longer replacement");
    result["params"]["event"]["elicitation"]["result"]["text"] = json!("not JSON");
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct CountedStore {
        inner: MemoryContentStore,
        puts: AtomicUsize,
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
            self.puts.fetch_add(1, Ordering::Relaxed);
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
        puts: AtomicUsize::new(0),
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
    let text = std::str::from_utf8(bytes).unwrap();
    let item = &mut result["params"]["event"]["elicitation"]["result"];
    item["text"] = json!(text);
    let before = store.puts.load(Ordering::Relaxed);
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
        assert_eq!(store.puts.load(Ordering::Relaxed), before);
        assert_eq!(staged["event"]["elicitation"]["result"]["text"], text);

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
        assert_eq!(store.puts.load(Ordering::Relaxed), before);
    }
}

#[test]
fn elicitation_content_requires_objects_even_when_a_later_effect_repairs_it() {
    let store = MemoryContentStore::new(100000, 1000000, 100);
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("authorized"),
    };
    let request = envelope(&context, "request", &form());
    let exchange = Exchange::new(&request, &context).unwrap();
    let result = envelope(
        &context,
        "result",
        &json!({"action":"accept","content":{"answer":"original"}}),
    );
    let effects = [
        json!({"type":"modify","target":"content","operation":"replace","value":[]}),
        json!({"type":"modify","target":"content","operation":"replace","value":{"answer":"repaired"}}),
    ];
    assert!(stage_boundary(&result, &effects, &context, Some(&exchange)).is_err());
    let declined = envelope(&context, "result", &json!({"action":"decline"}));
    assert!(stage_boundary(&declined, &effects[1..], &context, Some(&exchange)).is_err());
    let mut ungranted_request = request.clone();
    ungranted_request["params"]["capabilities"]["effects"] = json!(["modify"]);
    ungranted_request["params"]["capabilities"]["modify"] = json!({"request":{"replace":true}});
    assert!(
        stage_boundary(
            &ungranted_request,
            &[json!({"type":"modify","target":"request","operation":"replace","value":[]})],
            &context,
            None
        )
        .is_err()
    );
}
