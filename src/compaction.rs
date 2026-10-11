//! Canonical compaction staging over authorized immutable content.
//! Responses commit atomically; the application owns generation, scheduling and
//! downstream context installation. Legacy text fixtures project through the same
//! public protocol reducer and do not establish model consumption or replay.
use serde_json::{Value, json};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

/// Borrowed summary generation preserves the caller's capture lifetime.
pub type SummaryGenerator<'a> = dyn Fn(&str) -> Result<String, String> + 'a;
/// Owned observer work may outlive compaction settlement.
pub type ObserverCallback = dyn Fn(&Value) -> Result<Vec<Value>, String> + Send + Sync + 'static;

pub struct CompactionHook<'a> {
    pub supplier: &'a str,
    pub failure_policy: &'a str,
    pub run: &'a dyn Fn(&Value) -> Result<Vec<Value>, String>,
}
/// Deferred observers own their callback captures. A borrowed intercept callback
/// cannot outlive compaction. Observer return values have no authority.
pub struct CompactionObserver {
    pub supplier: String,
    pub run: Arc<ObserverCallback>,
}

/// Settled compatibility result plus explicitly deferred best-effort work.
/// The caller owns scheduling; this SDK never creates an executor or thread.
pub struct DeferredCompaction {
    pub result: Value,
    pub observations: Vec<CompactionObservation>,
}
pub struct CompactionObservation {
    snapshot: Value,
    observer: CompactionObserver,
}
impl CompactionObservation {
    /// Run once on a caller-selected executor. Effects and failures cannot reopen
    /// the settled result. Panics are isolated as best-effort delivery failures.
    pub fn deliver(self) {
        let _ = catch_unwind(AssertUnwindSafe(|| (self.observer.run)(&self.snapshot)));
    }
}
/// Settle first and return owned observation work without starting it.
pub fn run_compaction_observed(
    instructions: &str,
    item_id: &str,
    before: &[CompactionHook<'_>],
    observers: Vec<CompactionObserver>,
    generate: Option<&SummaryGenerator<'_>>,
) -> Result<DeferredCompaction, String> {
    if observers.iter().any(|o| o.supplier.is_empty()) {
        return Err("invalid observer".into());
    }
    let mut result = run_compaction(instructions, item_id, before, &[], generate, true)?;
    let mut observations = Vec::new();
    if result["applied"] == true {
        for observer in observers {
            let mut snapshot = result.clone();
            snapshot.as_object_mut().unwrap().remove("seen");
            snapshot.as_object_mut().unwrap().remove("failures");
            snapshot["boundary"] = json!("after");
            snapshot["capabilities"] = capabilities("after", true)?;
            result["seen"]
                .as_array_mut()
                .unwrap()
                .push(snapshot.clone());
            observations.push(CompactionObservation { snapshot, observer });
        }
    }
    Ok(DeferredCompaction {
        result,
        observations,
    })
}

pub fn capabilities(boundary: &str, observe_only: bool) -> Result<Value, String> {
    if boundary != "before" && boundary != "after" {
        return Err("unknown boundary".into());
    }
    if observe_only {
        return Ok(json!({"effects":[],"modify":{}}));
    }
    let target = if boundary == "before" {
        "instructions"
    } else {
        "summary"
    };
    let effects = if boundary == "before" {
        vec!["modify", "message", "return", "deny", "inject"]
    } else {
        vec!["modify", "message", "inject"]
    };
    Ok(
        json!({"effects":effects,"modify":{target:{"replace":true,"merge":true}},"inject":{"context":{"append":true,"deliverAt":["now","next_turn"]}}}),
    )
}
// Legacy JSON exposes content-N identifiers. Preserve their sequence without
// retaining a backing store: these names index only the documented `bodies`
// result field and are never used by canonical content evaluation.
fn legacy_reference(next: &mut u64) -> Result<String, String> {
    *next = next
        .checked_add(1)
        .ok_or("legacy content identifier capacity")?;
    Ok(format!("content-{next}"))
}
fn summary(state: &mut Value, item_id: &str, body: &str, next: &mut u64) -> Result<Value, String> {
    let reference = legacy_reference(next)?;
    state["bodies"][&reference] = json!(body);
    Ok(json!({"id":item_id,"ref":reference}))
}
// Compatibility projection only: all protocol effect semantics run through the
// public canonical engine, never a second private reducer.
fn stage(
    state: &Value,
    effects: &[Value],
    boundary: &str,
    supplier: &str,
    item_id: &str,
    observe_only: bool,
    next: &mut u64,
) -> Result<Value, String> {
    let mut execute = || -> CompactionResult<Value> {
        let before = boundary == "before";
        let target = if before { "instructions" } else { "summary" };
        let body = if before {
            state["instructions"].as_str()
        } else {
            state["bodies"][state["summary"]["ref"]
                .as_str()
                .ok_or("summary reference")?]
            .as_str()
        }
        .ok_or("compaction text")?;
        let mut event = json!({"id":boundary,"source":"urn:ahp:compaction-host","time":"2026-09-15T12:00:00Z","type":format!("context.compact.{boundary}")});
        event[target] = json!([{"id":if before { "instructions" } else { item_id },"kind":"text","mediaType":"text/plain","selection":"body","text":body}]);
        if before {
            event["trigger"] = json!("manual");
            event["items"] = json!([]);
        } else {
            event["removed"] = json!([]);
            event["execution"] = json!({"status":"executed"});
        }
        // The original compatibility projection allocated one reference per
        // callback. Keep that visible numbering, but bind only this stage's slot.
        legacy_reference(next)?;
        let content = crate::attachment::InvocationAttachments::bind(
            &mut event,
            vec![],
            crate::attachment::Budget::new(usize::MAX, usize::MAX),
            usize::MAX,
        )?;
        let request = json!({"jsonrpc":"2.0","id":boundary,"method":"hooks/intercept","params":{"protocolVersion":"draft","event":event,"capabilities":capabilities(boundary,observe_only)?}});
        // This string convenience API projects its candidates to canonical parts.
        let canonical_effects: Vec<_> = effects
            .iter()
            .map(|effect| {
                let mut effect = effect.clone();
                if effect["type"] == "return"
                    && let Some(text) = effect["value"].as_str()
                {
                    effect["value"] = json!([{ "id":item_id, "kind":"text",
                    "mediaType":"text/plain", "selection":"body", "text":text }]);
                }
                effect
            })
            .collect();
        let result = stage_boundary(&request, &canonical_effects, &content)?;
        let mut staged = state.clone();
        let changed = selected_text_at(&format!("/{target}"), &result["event"][target], &content)?;
        let replacement_reference = if changed != body {
            Some(legacy_reference(next)?)
        } else {
            None
        };
        if before {
            if staged["instructions"] != changed {
                staged["candidate"] = Value::Null;
            }
            staged["instructions"] = json!(changed);
        } else if changed != body {
            let reference = replacement_reference.ok_or("reference")?;
            staged["bodies"][&reference] = json!(changed);
            staged["summary"] = json!({"id":item_id,"ref":reference});
        }
        if let Some(candidate) = result.get("candidate") {
            staged["candidate"] = json!({"body":inline_text(candidate)?,"supplier":supplier});
        }
        if result["denied"] == true {
            staged["denied"] = json!(true);
        }
        staged["messages"].as_array_mut().ok_or("messages")?.extend(
            result["messages"]
                .as_array()
                .ok_or("messages")?
                .iter()
                .cloned(),
        );
        staged["injections"]
            .as_array_mut()
            .ok_or("injections")?
            .extend(
                result["injections"]
                    .as_array()
                    .ok_or("injections")?
                    .iter()
                    .cloned(),
            );
        Ok(staged)
    };
    execute().map_err(|e| e.to_string())
}
#[derive(Default)]
struct PipelineLog {
    seen: Vec<Value>,
    failures: Vec<Value>,
}
fn pipeline(
    state: &mut Value,
    hooks: &[CompactionHook<'_>],
    boundary: &str,
    item_id: &str,
    observe_only: bool,
    log: &mut PipelineLog,
    next: &mut u64,
) -> bool {
    let caps = capabilities(boundary, observe_only && boundary == "after").unwrap();
    for hook in hooks {
        let mut snapshot = state.clone();
        snapshot["boundary"] = json!(boundary);
        snapshot["capabilities"] = caps.clone();
        log.seen.push(snapshot.clone());
        match (hook.run)(&snapshot).and_then(|effects| {
            stage(
                state,
                &effects,
                boundary,
                hook.supplier,
                item_id,
                observe_only,
                next,
            )
        }) {
            Ok(staged) => *state = staged,
            Err(_) => {
                log.failures
                    .push(json!({"boundary":boundary,"supplier":hook.supplier}));
                if hook.failure_policy == "fail-closed" && !(observe_only && boundary == "after") {
                    return false;
                }
            }
        }
        if state["denied"] == true {
            return false;
        }
    }
    true
}
/// Hooks run in order; changed inputs invalidate earlier supplied candidates.
/// The legacy JSON result retains `bodies` and `seen` (callback snapshots) for
/// compatibility. These explicit output fields are not a content store; canonical
/// evaluation uses temporary slot-bound attachment owners for each callback.
/// A supplied summary skips generation, never applicable after controls.
/// Observe-only after callbacks require the owned run_compaction_observed API;
/// borrowed after callbacks are rejected rather than joined or leaked.
pub fn run_compaction(
    instructions: &str,
    item_id: &str,
    before: &[CompactionHook<'_>],
    after: &[CompactionHook<'_>],
    generate: Option<&SummaryGenerator<'_>>,
    observe_only: bool,
) -> Result<Value, String> {
    if observe_only && !after.is_empty() {
        return Err("borrowed intercept callbacks cannot be detached; use run_compaction_observed with owned observers".into());
    }
    if item_id.is_empty() {
        return Err("empty item ID".into());
    }
    for hook in before.iter().chain(after) {
        if hook.supplier.is_empty() || !["fail-open", "fail-closed"].contains(&hook.failure_policy)
        {
            return Err("invalid hook".into());
        }
    }
    let mut next = 0;
    let mut state = json!({"instructions":instructions,"candidate":null,"summary":null,"bodies":{},"messages":[],"injections":[],"denied":false});
    let mut log = PipelineLog::default();
    let mut generated = false;
    let mut applied = false;
    let mut provenance = Value::Null;
    if pipeline(
        &mut state,
        before,
        "before",
        item_id,
        observe_only,
        &mut log,
        &mut next,
    ) {
        let body = if !state["candidate"].is_null() {
            provenance = json!({"kind":"supplied","supplier":state["candidate"]["supplier"]});
            state["candidate"]["body"].as_str().unwrap().to_owned()
        } else {
            let input = state["instructions"].as_str().unwrap();
            let body = match generate {
                Some(f) => f(input)?,
                None => format!("summary:{input}"),
            };
            generated = true;
            provenance = json!({"kind":"generated"});
            body
        };
        state["summary"] = summary(&mut state, item_id, &body, &mut next)?;
        applied = observe_only
            || pipeline(
                &mut state, after, "after", item_id, false, &mut log, &mut next,
            );
    }
    state["seen"] = json!(log.seen);
    state["failures"] = json!(log.failures);
    state["generated"] = json!(generated);
    state["applied"] = json!(applied);
    state["provenance"] = provenance;
    Ok(state)
}

/// Errors from canonical validation, content verification, or effect staging.
pub type CompactionResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Read selected compaction text without normalizing its immutable bytes.
pub fn selected_text(
    item: &Value,
    content: &crate::content::ContentContext<'_>,
) -> CompactionResult<String> {
    let _ = content;
    inline_text(item)
}

fn inline_text(parts: &Value) -> CompactionResult<String> {
    let mut text = String::new();
    for part in parts.as_array().ok_or("compaction text parts required")? {
        if part["selection"] != "body" || part.get("gap").is_some() {
            return Err("compaction text not selected".into());
        }
        text.push_str(part["text"].as_str().ok_or("inline text required")?);
    }
    Ok(text)
}

fn selected_text_at(
    _path: &str,
    item: &Value,
    _content: &dyn crate::content::ContentAccess,
) -> CompactionResult<String> {
    inline_text(item)
}

// Internal reducer commands, projected only from generated contextual variants.
enum CompactEdit {
    Modify(bool, Box<crate::generated::TextParts>),
    Return(Box<crate::generated::TextParts>),
    Deny,
    Message(String),
    Inject(Box<crate::generated::InjectEffect>),
}

/// Stage one canonical compaction response atomically. Publish the returned
/// event only on success. Inline edits do not allocate attachments; failed stages
/// cannot commit text parts, messages, injections, denial or a candidate.
/// `injections` contains full canonical inject effects in response order. They
/// request host delivery; they do not mutate the event or install context. This does not
/// install context or promise downstream model consumption or replay.
pub fn stage_boundary(
    request: &Value,
    effects: &[Value],
    _content: &dyn crate::content::ContentAccess,
) -> CompactionResult<Value> {
    stage_boundary_admitted(
        request,
        effects,
        _content,
        &crate::contracts::Admission::default(),
    )
}

pub(crate) fn stage_boundary_admitted(
    request: &Value,
    effects: &[Value],
    _content: &dyn crate::content::ContentAccess,
    admission: &crate::contracts::Admission,
) -> CompactionResult<Value> {
    use crate::generated::*;
    crate::canonical::validate("intercept-request", request)?;
    let mut typed: InterceptRequest = serde_json::from_value(request.clone())?;
    let (before, id) = match typed.params.event.as_ref() {
        Event::ContextCompactBefore(e) => (true, &e.0.id),
        Event::ContextCompactAfter(e) => (false, &e.0.id),
        _ => return Err("not a compaction boundary".into()),
    };
    if request["id"] != *id {
        return Err("compaction request/event correlation mismatch".into());
    }
    let event_type = if before {
        "context.compact.before"
    } else {
        "context.compact.after"
    };
    let response = json!({"jsonrpc":"2.0", "id":request["id"],
        "result":{"protocolVersion":"draft","effects":effects}});
    crate::canonical::validate("intercept-response", &response)?;
    let parsed = match response_for_request(event_type, &serde_json::to_string(&response)?) {
        ParseResult::Success { value, .. } => value,
        ParseResult::Failure { diagnostics, .. } => {
            return Err(format!("invalid compaction response: {diagnostics:?}").into());
        }
    };
    let mut edits = Vec::new();
    match parsed {
        ContextualResponse::ContextCompactBefore(r) => {
            if let Presence::Present(effects) = r.result.effects {
                for effect in effects {
                    edits.push(match *effect {
                        ContextCompactBeforeEffect::ModifyInstructions(e) => CompactEdit::Modify(
                            matches!(
                                e.operation,
                                ContextCompactBeforeModifyEffectOperation::Merge(_)
                            ),
                            e.value,
                        ),
                        ContextCompactBeforeEffect::Return(e) => CompactEdit::Return(e.value),
                        ContextCompactBeforeEffect::Deny(_) => CompactEdit::Deny,
                        ContextCompactBeforeEffect::Message(e) => CompactEdit::Message(e.text),
                        ContextCompactBeforeEffect::InjectAppendContext(e) => {
                            CompactEdit::Inject(e)
                        }
                        ContextCompactBeforeEffect::Unknown(_) => {
                            return Err("unsupported compaction effect".into());
                        }
                    });
                }
            }
        }
        ContextualResponse::ContextCompactAfter(r) => {
            if let Presence::Present(effects) = r.result.effects {
                for effect in effects {
                    edits.push(match *effect {
                        ContextCompactAfterEffect::ModifySummary(e) => CompactEdit::Modify(
                            matches!(
                                e.operation,
                                ContextCompactAfterModifyEffectOperation::Merge(_)
                            ),
                            e.value,
                        ),
                        ContextCompactAfterEffect::Message(e) => CompactEdit::Message(e.text),
                        ContextCompactAfterEffect::InjectAppendContext(e) => CompactEdit::Inject(e),
                        ContextCompactAfterEffect::Unknown(_) => {
                            return Err("unsupported compaction effect".into());
                        }
                    });
                }
            }
        }
        _ => return Err("not a compaction response".into()),
    }
    let caps = &typed.params.capabilities;
    // Validate every command before mutating the private snapshot.
    for edit in &edits {
        let kind = match &edit {
            CompactEdit::Modify(..) => InterceptRequestParamsCapabilitiesEffectsItemKnown::Modify,
            CompactEdit::Return(_) => InterceptRequestParamsCapabilitiesEffectsItemKnown::Return,
            CompactEdit::Deny => InterceptRequestParamsCapabilitiesEffectsItemKnown::Deny,
            CompactEdit::Message(_) => InterceptRequestParamsCapabilitiesEffectsItemKnown::Message,
            CompactEdit::Inject(_) => InterceptRequestParamsCapabilitiesEffectsItemKnown::Inject,
        };
        if !caps.effects.iter().any(|grant| matches!(grant, InterceptRequestParamsCapabilitiesEffectsItem::Known(known) if *known == kind)) {
            return Err("effect not advertised".into());
        }
        match edit {
            CompactEdit::Modify(merge, _) => {
                let granted = match &caps.modify {
                    Presence::Present(modify) if before => match &modify.instructions {
                        Presence::Present(grant) => {
                            if *merge {
                                grant.merge
                            } else {
                                grant.replace
                            }
                        }
                        Presence::Missing => false,
                    },
                    Presence::Present(modify) => match &modify.summary {
                        Presence::Present(grant) => {
                            if *merge {
                                grant.merge
                            } else {
                                grant.replace
                            }
                        }
                        Presence::Missing => false,
                    },
                    Presence::Missing => false,
                };
                if !granted {
                    return Err("unsupported compaction modification".into());
                }
                let selected = match typed.params.event.as_ref() {
                    Event::ContextCompactBefore(e) => match &e.0.instructions {
                        Presence::Present(parts) => parts,
                        Presence::Missing => return Err("missing compaction target".into()),
                    },
                    Event::ContextCompactAfter(e) => &e.0.summary,
                    _ => unreachable!(),
                };
                if selected
                    .0
                    .iter()
                    .any(|part| !matches!(part.as_ref(), TextPart::TextBodyPart(_)))
                {
                    return Err("compaction text not selected".into());
                }
            }
            CompactEdit::Return(parts) => {
                for part in &parts.0 {
                    if !matches!(part.as_ref(), TextPart::TextBodyPart(_)) {
                        return Err("compaction text not selected".into());
                    }
                }
            }
            CompactEdit::Inject(e) => {
                let granted = match &caps.inject {
                    Presence::Present(grant) => grant.context.deliver_at.iter().any(|delivery| matches!(
                        (&e.deliver_at, delivery),
                        (InjectEffectDeliverAt::Now, InterceptRequestParamsCapabilitiesInjectContextDeliverAtItem::Now)
                        | (InjectEffectDeliverAt::NextTurn, InterceptRequestParamsCapabilitiesInjectContextDeliverAtItem::NextTurn)
                    )),
                    Presence::Missing => false,
                };
                if !granted {
                    return Err("unsupported compaction injection".into());
                }
            }
            _ => {}
        }
    }
    let mut candidate = None;
    let mut denied = false;
    let mut messages = Vec::new();
    let mut injections = Vec::new();
    for edit in edits {
        match edit {
            CompactEdit::Modify(merge, parts) => {
                let destination = match typed.params.event.as_mut() {
                    Event::ContextCompactBefore(e) => match &mut e.0.instructions {
                        Presence::Present(parts) => parts,
                        Presence::Missing => return Err("missing compaction target".into()),
                    },
                    Event::ContextCompactAfter(e) => &mut e.0.summary,
                    _ => unreachable!(),
                };
                if merge {
                    destination.0.extend(parts.0);
                } else {
                    *destination = parts;
                }
            }
            CompactEdit::Return(parts) => candidate = Some(parts),
            CompactEdit::Deny => denied = true,
            CompactEdit::Message(text) => messages.push(text),
            CompactEdit::Inject(effect) => injections.push(effect),
        }
        // Validate each complete temporary value before another edit can repair it.
        crate::canonical::validate("intercept-request", &serde_json::to_value(&typed)?)?;
        admission.event(&serde_json::to_value(&typed.params.event)?)?;
        if let Some(candidate) = &candidate {
            admission.returned(&serde_json::to_value(candidate)?)?;
        }
    }
    let effective_request = serde_json::to_value(&typed)?;
    crate::canonical::validate("intercept-request", &effective_request)?;
    let mut result = json!({"event":typed.params.event,"denied":denied,"messages":messages,"injections":injections});
    if let Some(candidate) = candidate {
        result["candidate"] = serde_json::to_value(candidate)?;
    }
    Ok(result)
}

/// Owned original exchange. Each boundary has its own snapshot; after events
/// retain their original removed items, execution and correlation fields.
#[derive(Debug, Clone)]
pub struct CompactionSnapshot {
    request: Value,
}
impl CompactionSnapshot {
    pub fn new(
        request: Value,
        content: &crate::content::ContentContext<'_>,
    ) -> CompactionResult<Self> {
        stage_boundary(&request, &[], content)?;
        Ok(Self { request })
    }
    pub fn request(&self) -> &Value {
        &self.request
    }
    pub fn stage(
        &self,
        effects: &[Value],
        content: &crate::content::ContentContext<'_>,
    ) -> CompactionResult<Value> {
        stage_boundary(&self.request, effects, content)
    }
}

#[cfg(test)]
mod legacy_owned_tests {
    use super::*;

    #[test]
    fn temporary_owners_preserve_legacy_identifiers_and_callback_snapshots() {
        let before = |_: &Value| {
            Ok(vec![
                json!({"type":"modify","target":"instructions","operation":"replace","value":[{"id":"edit","kind":"text","mediaType":"text/plain","selection":"body","text":"edited"}]}),
            ])
        };
        let after = |snapshot: &Value| {
            assert_eq!(snapshot["summary"]["ref"], "content-3");
            assert_eq!(snapshot["bodies"]["content-3"], "summary:edited");
            Ok(vec![
                json!({"type":"modify","target":"summary","operation":"replace","value":[{"id":"edit","kind":"text","mediaType":"text/plain","selection":"body","text":"redacted"}]}),
            ])
        };
        let result = run_compaction(
            "original",
            "summary-id",
            &[CompactionHook {
                supplier: "before",
                failure_policy: "fail-closed",
                run: &before,
            }],
            &[CompactionHook {
                supplier: "after",
                failure_policy: "fail-closed",
                run: &after,
            }],
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            result["summary"],
            json!({"id":"summary-id","ref":"content-5"})
        );
        assert_eq!(
            result["bodies"],
            json!({"content-3":"summary:edited","content-5":"redacted"})
        );
        assert_eq!(result["seen"][1]["summary"]["ref"], "content-3");
        assert_eq!(result["seen"][0]["instructions"], "original");
    }
}

#[cfg(test)]
mod typed_boundary_tests {
    use super::*;
    use crate::content::{AuthorizedScope, ContentContext, MemoryContentStore};

    #[test]
    fn contextual_effect_failures_leave_original_snapshot_untouched() {
        let store = MemoryContentStore::new(4096, 65536, 100);
        let content = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("scope"),
        };
        let request = json!({"jsonrpc":"2.0","id":"before","method":"hooks/intercept",
            "params":{"protocolVersion":"draft","capabilities":capabilities("before", false).unwrap(),
                "event":{"id":"before","source":"urn:test:host","time":"2026-09-15T12:00:00Z",
                    "type":"context.compact.before","trigger":"manual","items":[],
                    "instructions":[{"id":"text","kind":"text","mediaType":"text/plain","selection":"body","text":"original"}]}}});
        let original = request.clone();
        let valid = json!({"type":"modify","target":"instructions","operation":"replace",
            "value":[{"id":"text","kind":"text","mediaType":"text/plain","selection":"body","text":"changed"}]});
        for invalid in [
            json!({"type":"modify","target":"instructions","operation":"replace","value":{"text":"not parts"}}),
            json!({"type":"return","value":{"action":"accept"}}),
            json!({"type":"future.effect"}),
        ] {
            assert!(stage_boundary(&request, &[valid.clone(), invalid], &content).is_err());
            assert_eq!(request, original);
        }
    }
}
