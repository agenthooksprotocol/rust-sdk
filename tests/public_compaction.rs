use agenthooksprotocol::{
    compaction::{capabilities, selected_text, stage_boundary},
    content::{
        AuthorizedScope, ContentContext, ContentReference, ContentStore, MemoryContentStore,
        UploadError,
    },
};
use serde_json::{Value, json};
use std::sync::Arc;

fn request(content: &ContentContext<'_>, after: bool) -> Value {
    let boundary = if after { "after" } else { "before" };
    let target = if after { "summary" } else { "instructions" };
    let descriptor = content.put("original\r\nλ".as_bytes()).unwrap();
    let mut event = json!({"id":boundary,"source":"urn:test:compaction","time":"2026-09-15T12:00:00Z","type":format!("context.compact.{boundary}"),"session":{"id":"session"},"parentEventId":"original-exchange","native":{"host":"test"}});
    event[target] = json!({"id":"logical-item","kind":target,"role":"assistant","category":"test","parentItemId":"parent-item","mediaType":"text/plain","selection":"body","body":descriptor});
    if after {
        event["removed"] = json!([{"id":"context-item"}]);
        event["execution"] = json!({"status":"executed"});
    } else {
        event["trigger"] = json!("manual");
        event["items"] = json!([]);
    }
    json!({"jsonrpc":"2.0","id":boundary,"method":"hooks/intercept","params":{"protocolVersion":"draft","event":event,"capabilities":capabilities(boundary,false).unwrap()}})
}
fn modify(target: &str, text: &str) -> Value {
    json!({"type":"modify","target":target,"operation":"replace","value":text})
}
fn store() -> MemoryContentStore {
    MemoryContentStore::new(4096, 65536, 100)
}

#[test]
fn immutable_rewrites_preserve_identity_correlations_and_exact_utf8() {
    let store = store();
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    for after in [false, true] {
        let request = request(&content, after);
        let target = if after { "summary" } else { "instructions" };
        let original = request["params"]["event"].clone();
        let result =
            stage_boundary(&request, &[modify(target, " redacted\r\nλ ")], &content).unwrap();
        assert_eq!(
            selected_text(&result["event"][target], &content).unwrap(),
            " redacted\r\nλ "
        );
        assert_eq!(
            selected_text(&original[target], &content).unwrap(),
            "original\r\nλ"
        );
        assert_ne!(result["event"][target]["body"], original[target]["body"]);
        for key in [
            "id",
            "role",
            "category",
            "parentItemId",
            "selection",
            "mediaType",
        ] {
            assert_eq!(result["event"][target][key], original[target][key]);
        }
        for key in ["parentEventId", "session", "native", "removed", "execution"] {
            assert_eq!(result["event"].get(key), original.get(key));
        }
        assert!(result["event"][target].get("size").is_none());
        assert!(result["event"][target].get("sha256").is_none());
        assert_eq!(
            result["event"][target]["body"].as_object().unwrap().len(),
            1
        );
    }
}

#[test]
fn no_effects_preserve_optional_presence_and_absent_candidate() {
    let store = store();
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    let mut request = request(&content, false);
    request["params"]["event"]
        .as_object_mut()
        .unwrap()
        .remove("instructions");
    let result = stage_boundary(&request, &[], &content).unwrap();
    assert_eq!(result["event"], request["params"]["event"]);
    assert!(result.get("candidate").is_none());
    assert_eq!(result["messages"], json!([]));
    assert_eq!(result["denied"], false);
    let returned = stage_boundary(
        &request,
        &[json!({"type":"return","value":"supplied"})],
        &content,
    )
    .unwrap();
    assert_eq!(returned["candidate"], "supplied");
    assert!(stage_boundary(&request, &[json!({"type":"return","value":null})], &content).is_err());
}

#[test]
fn malformed_effects_reject_whole_response_and_leave_original_unchanged() {
    let store = store();
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    for after in [false, true] {
        let request = request(&content, after);
        let saved = request.clone();
        let target = if after { "summary" } else { "instructions" };
        for bad in [
            json!({"type":"future"}),
            json!({"type":"modify","target":target,"operation":"future","value":"bad"}),
            modify(if after { "instructions" } else { "summary" }, "bad"),
        ] {
            assert!(
                stage_boundary(
                    &request,
                    &[
                        modify(target, "leak"),
                        json!({"type":"message","text":"leak"}),
                        bad
                    ],
                    &content
                )
                .is_err()
            );
            assert_eq!(request, saved);
        }
    }
}

#[test]
fn original_integrity_missing_bodies_and_scope_cannot_be_hidden_by_replacement() {
    let store = store();
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    let request = request(&content, false);
    for field in ["size", "sha256"] {
        let mut corrupt = request.clone();
        corrupt["params"]["event"]["instructions"][field] = if field == "size" {
            json!(999)
        } else {
            json!("0".repeat(64))
        };
        assert!(
            stage_boundary(&corrupt, &[modify("instructions", "replacement")], &content).is_err()
        );
    }
    let mut missing = request.clone();
    missing["params"]["event"]["instructions"]
        .as_object_mut()
        .unwrap()
        .remove("body");
    assert!(stage_boundary(&missing, &[], &content).is_err());
    missing["params"]["event"]["instructions"]["gap"] = json!({"reason":"unavailable"});
    assert!(stage_boundary(&missing, &[], &content).is_err());
    let wrong_scope = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("other"),
    };
    assert!(stage_boundary(&request, &[], &wrong_scope).is_err());
}

struct LyingStore;
impl ContentStore for LyingStore {
    fn resolve(&self, _: &AuthorizedScope, _: &ContentReference) -> Result<Arc<[u8]>, UploadError> {
        Ok(Arc::from(&b"wrong"[..]))
    }
    fn put(&self, _: &AuthorizedScope, _: Arc<[u8]>) -> Result<ContentReference, UploadError> {
        Err(UploadError::Unavailable)
    }
}
#[test]
fn scoped_store_bytes_are_authoritative_and_metadata_never_resolves() {
    let store = store();
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    let mut request = request(&content, false);
    let lying = ContentContext {
        store: &LyingStore,
        scope: AuthorizedScope::new("scope"),
    };
    let staged = stage_boundary(&request, &[], &lying).unwrap();
    assert_eq!(
        selected_text(&staged["event"]["instructions"], &lying).unwrap(),
        "wrong"
    );
    let item = &mut request["params"]["event"]["instructions"];
    item.as_object_mut().unwrap().remove("body");
    item["selection"] = json!("metadata");
    assert_eq!(
        stage_boundary(&request, &[], &lying).unwrap()["event"],
        request["params"]["event"]
    );
    assert!(stage_boundary(&request, &[modify("instructions", "forbidden")], &lying).is_err());
}

#[test]
fn denial_and_messages_are_staged_but_not_allowed_after() {
    let store = store();
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("scope"),
    };
    let effects = [
        json!({"type":"return","value":"cached"}),
        json!({"type":"message","text":"notice"}),
        json!({"type":"deny","reason":"policy"}),
    ];
    let before = request(&content, false);
    let result = stage_boundary(&before, &effects, &content).unwrap();
    assert_eq!(result["denied"], true);
    assert_eq!(result["candidate"], "cached");
    assert_eq!(result["messages"], json!(["notice"]));
    assert_eq!(result["event"], before["params"]["event"]);
    assert!(stage_boundary(&request(&content, true), &effects, &content).is_err());
}

#[test]
fn deferred_observers_do_not_start_until_the_caller_schedules_them() {
    use agenthooksprotocol::compaction::{CompactionObserver, run_compaction_observed};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let capture = calls.clone();
    let deferred = run_compaction_observed(
        "text",
        "summary",
        &[],
        vec![CompactionObserver {
            supplier: "observer".into(),
            run: Arc::new(move |_| {
                capture.fetch_add(1, Ordering::SeqCst);
                Ok(vec![modify("summary", "ignored")])
            }),
        }],
        None,
    )
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(deferred.result["applied"], true);
    for observation in deferred.observations {
        observation.deliver();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let reference = deferred.result["summary"]["ref"].as_str().unwrap();
    assert_eq!(deferred.result["bodies"][reference], "summary:text");
}

struct CountingStore {
    inner: MemoryContentStore,
    writes: std::sync::atomic::AtomicUsize,
}
impl CountingStore {
    fn new() -> Self {
        Self {
            inner: store(),
            writes: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn writes(&self) -> usize {
        self.writes.load(std::sync::atomic::Ordering::SeqCst)
    }
}
impl ContentStore for CountingStore {
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
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.put(scope, bytes)
    }
}

#[test]
fn no_op_and_restoring_replacements_preserve_descriptor_without_allocating() {
    for after in [false, true] {
        let store = CountingStore::new();
        let content = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("scope"),
        };
        let request = request(&content, after);
        let target = if after { "summary" } else { "instructions" };
        let original = selected_text(&request["params"]["event"][target], &content).unwrap();
        let writes = store.writes();
        for effects in [
            vec![modify(target, &original)],
            vec![modify(target, "temporary"), modify(target, &original)],
        ] {
            let result = stage_boundary(&request, &effects, &content).unwrap();
            assert_eq!(result["event"], request["params"]["event"]);
            assert_eq!(store.writes(), writes, "semantic no-op must not allocate");
        }
        let result = stage_boundary(
            &request,
            &[modify(target, "temporary"), modify(target, "final")],
            &content,
        )
        .unwrap();
        assert_eq!(
            store.writes(),
            writes + 1,
            "only final changed bytes are stored"
        );
        assert_eq!(
            selected_text(&result["event"][target], &content).unwrap(),
            "final"
        );
        assert_eq!(
            selected_text(&request["params"]["event"][target], &content).unwrap(),
            original
        );
    }
}

struct PublicEffects(Vec<Value>);
impl agenthooksprotocol::client::Hook for PublicEffects {
    fn call(
        &self,
        request: Value,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        Result<Value, agenthooksprotocol::client::HookError>,
    > {
        Box::pin(async move {
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":self.0}}),
            )
        })
    }
}
#[test]
fn public_runtime_no_op_preserves_approval_and_candidate_at_both_boundaries() {
    use agenthooksprotocol::client::{Client, Decision, FailurePolicy, Subscription, ToolContext};
    for after in [false, true] {
        for restore in [false, true] {
            let store = CountingStore::new();
            let content = ContentContext {
                store: &store,
                scope: AuthorizedScope::new("scope"),
            };
            let request = request(&content, after);
            let original = request["params"]["event"].clone();
            let target = if after { "summary" } else { "instructions" };
            let text = selected_text(&original[target], &content).unwrap();
            let mut effects = vec![];
            if restore {
                effects.push(modify(target, "temporary"));
            }
            effects.push(modify(target, &text));
            let mut subscription =
                Subscription::intercept("same", FailurePolicy::Closed, PublicEffects(effects));
            subscription.events = vec![original["type"].as_str().unwrap().to_owned()];
            let client = Client::new(ToolContext::new(json!({}))).with_subscription(subscription);
            let writes = store.writes();
            let result = futures::executor::block_on(async {
                client
                    .event(original.clone())
                    .content(content.clone())
                    .capabilities(request["params"]["capabilities"].clone())
                    .initial_state(Decision::Allow)
                    .initial_candidate(json!({"value":"cached"}))
                    .await
            })
            .unwrap();
            assert_eq!(result.effective_event, original);
            assert_eq!(result.outcome.candidate, Some(json!("cached")));
            assert_eq!(result.outcome.decision, Decision::Allow);
            assert!(result.outcome.authorized);
            assert!(!result.outcome.approval_invalidated);
            assert!(result.outcome.failures.is_empty());
            assert_eq!(store.writes(), writes);
        }
    }
}

fn inject(value: Value, deliver_at: &str) -> Value {
    json!({"type":"inject","target":"context","operation":"append","deliverAt":deliver_at,"value":value})
}

#[test]
fn compaction_injections_stage_in_order_without_mutating_original_context() {
    for after in [false, true] {
        for modified in [false, true] {
            let store = CountingStore::new();
            let content = ContentContext {
                store: &store,
                scope: AuthorizedScope::new("scope"),
            };
            let request = request(&content, after);
            let saved = request.clone();
            let target = if after { "summary" } else { "instructions" };
            // Injection payload is protocol JSON, not an SDK application schema.
            let first = inject(json!({"text":"one","applicationField":7}), "now");
            let second = inject(Value::Null, "next_turn");
            let mut effects = vec![first.clone()];
            if modified {
                effects.push(modify(target, "modified"));
            }
            effects.push(second.clone());
            let writes = store.writes();
            let staged = stage_boundary(&request, &effects, &content).unwrap();
            assert_eq!(staged["injections"], json!([first, second]));
            assert_eq!(request, saved);
            assert_eq!(
                staged["event"].get("items"),
                saved["params"]["event"].get("items")
            );
            if modified {
                assert_eq!(
                    selected_text(&staged["event"][target], &content).unwrap(),
                    "modified"
                );
                assert_eq!(store.writes(), writes + 1);
            } else {
                assert_eq!(staged["event"], saved["params"]["event"]);
                assert_eq!(store.writes(), writes);
            }
            assert_eq!(
                stage_boundary(&request, &[], &content).unwrap()["injections"],
                json!([])
            );
        }
    }
}

#[test]
fn malformed_or_unadvertised_injections_reject_all_effects_before_allocation() {
    for after in [false, true] {
        let store = CountingStore::new();
        let content = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("scope"),
        };
        let request = request(&content, after);
        let saved = request.clone();
        let target = if after { "summary" } else { "instructions" };
        let valid = inject(json!("accepted only on full success"), "now");
        let mut invalid = vec![];
        for (field, value) in [
            ("target", json!("summary")),
            ("operation", json!("replace")),
            ("deliverAt", json!("later")),
            ("extra", json!(true)),
        ] {
            let mut effect = valid.clone();
            effect[field] = value;
            invalid.push(effect);
        }
        for field in ["value", "deliverAt"] {
            let mut effect = valid.clone();
            effect.as_object_mut().unwrap().remove(field);
            invalid.push(effect);
        }
        let writes = store.writes();
        for bad in invalid {
            assert!(
                stage_boundary(
                    &request,
                    &[
                        modify(target, "must not publish"),
                        valid.clone(),
                        json!({"type":"message","text":"must not publish"}),
                        bad
                    ],
                    &content
                )
                .is_err()
            );
            assert_eq!(store.writes(), writes);
            assert_eq!(request, saved);
        }
        let mut limited = request.clone();
        limited["params"]["capabilities"]["inject"]["context"]["deliverAt"] = json!(["now"]);
        assert!(
            stage_boundary(
                &limited,
                &[
                    modify(target, "must not publish"),
                    inject(json!("not granted"), "next_turn")
                ],
                &content
            )
            .is_err()
        );
        assert_eq!(store.writes(), writes);
        let mut unadvertised = request.clone();
        unadvertised["params"]["capabilities"]["effects"]
            .as_array_mut()
            .unwrap()
            .retain(|effect| effect != "inject");
        unadvertised["params"]["capabilities"]
            .as_object_mut()
            .unwrap()
            .remove("inject");
        assert!(stage_boundary(&unadvertised, &[valid], &content).is_err());
        assert_eq!(store.writes(), writes);
    }
}

#[test]
fn public_runtime_accumulates_compaction_injections_once_across_subscriptions() {
    use agenthooksprotocol::client::{Client, Decision, FailurePolicy, Subscription, ToolContext};
    for after in [false, true] {
        let store = store();
        let content = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("scope"),
        };
        let request = request(&content, after);
        let target = if after { "summary" } else { "instructions" };
        let first = inject(json!({"text":"one"}), "now");
        let second = inject(json!(["two"]), "next_turn");
        let mut client = Client::new(ToolContext::new(json!({})));
        for (id, effects) in [
            ("one", vec![first.clone()]),
            ("two", vec![modify(target, "changed"), second.clone()]),
        ] {
            let mut subscription =
                Subscription::intercept(id, FailurePolicy::Closed, PublicEffects(effects));
            subscription.events = vec![
                request["params"]["event"]["type"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ];
            client = client.with_subscription(subscription);
        }
        let result = futures::executor::block_on(async {
            client
                .event(request["params"]["event"].clone())
                .content(content.clone())
                .capabilities(request["params"]["capabilities"].clone())
                .initial_state(Decision::Allow)
                .await
        })
        .unwrap();
        assert!(result.outcome.failures.is_empty());
        assert_eq!(result.outcome.injections, vec![first, second]);
        assert_eq!(
            selected_text(&result.effective_event[target], &content).unwrap(),
            "changed"
        );
        assert_eq!(
            result.effective_event.get("items"),
            request["params"]["event"].get("items")
        );
    }
}
