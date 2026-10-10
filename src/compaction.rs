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

/// Stage one canonical compaction response atomically. Publish the returned
/// event only on success. Inline edits do not allocate attachments; failed stages
/// cannot commit text parts, messages, injections, denial or a candidate.
/// `injections` contains full canonical inject effects in response order. They
/// request host delivery; they do not mutate the event or install context. This does not
/// install context or promise downstream model consumption or replay.
pub fn stage_boundary(
    request: &Value,
    effects: &[Value],
    content: &dyn crate::content::ContentAccess,
) -> CompactionResult<Value> {
    crate::canonical::validate("intercept-request", request)?;
    let original = &request["params"]["event"];
    if request["id"] != original["id"] {
        return Err("compaction request/event correlation mismatch".into());
    }
    let before = match original["type"].as_str() {
        Some("context.compact.before") => true,
        Some("context.compact.after") => false,
        _ => return Err("not a compaction boundary".into()),
    };
    let target = if before { "instructions" } else { "summary" };
    crate::canonical::validate(
        "intercept-response",
        &json!({
            "jsonrpc":"2.0", "id":request["id"],
            "result":{"protocolVersion":"draft","effects":effects}
        }),
    )?;
    let caps = &request["params"]["capabilities"];
    // Validate the entire response before allocating replacements.
    for effect in effects {
        let kind = effect["type"].as_str().ok_or("missing effect type")?;
        if !caps["effects"]
            .as_array()
            .is_some_and(|xs| xs.iter().any(|x| x == kind))
        {
            return Err("effect not advertised".into());
        }
        match kind {
            "modify" => {
                if effect["target"] != target
                    || !["replace", "merge"].contains(&effect["operation"].as_str().unwrap_or(""))
                    || caps["modify"][target][effect["operation"].as_str().unwrap_or("")] != true
                    || !effect["value"].is_array()
                {
                    return Err("unsupported compaction modification".into());
                }
                selected_text_at(
                    &format!("/{target}"),
                    original.get(target).ok_or("missing compaction target")?,
                    content,
                )?;
            }
            "return" if before => {
                let _: Vec<crate::generated::TextBodyPart> =
                    serde_json::from_value(effect["value"].clone())?;
                inline_text(&effect["value"])?;
            }
            "deny" if before => {}
            "message" => {}
            "inject" => {
                if effect["target"] != "context"
                    || effect["operation"] != "append"
                    || caps["inject"]["context"]["append"] != true
                    || !caps["inject"]["context"]["deliverAt"]
                        .as_array()
                        .is_some_and(|times| times.contains(&effect["deliverAt"]))
                {
                    return Err("unadvertised compaction injection".into());
                }
            }
            _ => return Err("unsupported compaction effect".into()),
        }
    }
    let mut event = original.clone();
    let mut messages = Vec::new();
    let mut injections = Vec::new();
    let mut denied = false;
    let mut candidate = None;
    for effect in effects {
        match effect["type"].as_str().unwrap() {
            "modify" if effect["operation"] == "merge" => {
                event[target]
                    .as_array_mut()
                    .ok_or("text parts required")?
                    .extend(
                        effect["value"]
                            .as_array()
                            .ok_or("text parts required")?
                            .clone(),
                    );
            }
            "modify" => event[target] = effect["value"].clone(),
            "return" => candidate = Some(effect["value"].clone()),
            "deny" => denied = true,
            "message" => messages.push(effect["text"].clone()),
            "inject" => injections.push(effect.clone()),
            _ => unreachable!(),
        }
    }
    let mut effective_request = request.clone();
    effective_request["params"]["event"] = event.clone();
    crate::canonical::validate("intercept-request", &effective_request)?;
    let mut result =
        json!({"event":event,"denied":denied,"messages":messages,"injections":injections});
    if let Some(candidate) = candidate {
        result["candidate"] = candidate;
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
