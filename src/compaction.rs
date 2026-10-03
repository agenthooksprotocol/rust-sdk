//! Serial host-side text compaction. Response effects commit atomically.
//! Only `applied` permits downstream use. Upload immutable UTF-8 bodies before
//! exposing their references on wire. The deterministic default needs no LLM.
use serde_json::{Value, json};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    thread,
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
/// Detached observers must own their callback captures: a borrowed intercept
/// callback cannot safely outlive run_compaction. Return values have no authority.
pub struct CompactionObserver {
    pub supplier: String,
    pub run: Arc<ObserverCallback>,
}

/// Settle first, then dispatch owned best-effort observers without joining them.
pub fn run_compaction_observed(
    instructions: &str,
    item_id: &str,
    before: &[CompactionHook<'_>],
    observers: Vec<CompactionObserver>,
    generate: Option<&SummaryGenerator<'_>>,
) -> Result<Value, String> {
    if observers.iter().any(|o| o.supplier.is_empty()) {
        return Err("invalid observer".into());
    }
    let mut result = run_compaction(instructions, item_id, before, &[], generate, true)?;
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
            // A failed spawn or callback cannot reopen the settled result. A
            // dropped JoinHandle never waits or extends borrowed stack lifetimes.
            let _ = thread::Builder::new()
                .name("compaction-observer".into())
                .spawn(move || {
                    let _ = catch_unwind(AssertUnwindSafe(|| (observer.run)(&snapshot)));
                });
        }
    }
    Ok(result)
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
        vec!["modify", "message", "return", "deny"]
    } else {
        vec!["modify", "message"]
    };
    Ok(json!({"effects":effects,"modify":{target:{"replace":true,"merge":false}}}))
}
fn summary(state: &mut Value, item_id: &str, body: &str) -> Value {
    let hex: String = body.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let reference = format!("urn:ahp:compaction:utf8:{hex}");
    state["bodies"][&reference] = json!(body);
    json!({"id":item_id,"ref":reference})
}
fn stage(
    state: &Value,
    effects: &[Value],
    boundary: &str,
    supplier: &str,
    item_id: &str,
    observe_only: bool,
) -> Result<Value, String> {
    let mut staged = state.clone();
    for effect in effects {
        if !crate::generated::parse_effect_value(effect.clone()).is_ok() {
            return Err("invalid effect".into());
        }
        let kind = effect["type"].as_str().ok_or("missing type")?;
        if (observe_only && boundary == "after")
            || !(kind == "modify"
                || kind == "message"
                || (boundary == "before" && (kind == "return" || kind == "deny")))
        {
            return Err("unsupported effect".into());
        }
        match kind {
            "modify" => {
                let target = if boundary == "before" {
                    "instructions"
                } else {
                    "summary"
                };
                if effect["target"] != target || effect["operation"] != "replace" {
                    return Err("invalid modification".into());
                }
                let body = effect["value"].as_str().ok_or("value must be text")?;
                if boundary == "before" {
                    staged["instructions"] = json!(body);
                } else {
                    staged["summary"] = summary(&mut staged, item_id, body);
                }
            }
            "deny" => {
                if effect["reason"].as_str().is_none_or(str::is_empty) {
                    return Err("denial requires reason".into());
                }
            }
            "return" => {
                effect["value"].as_str().ok_or("summary must be text")?;
            }
            "message" => {
                effect["text"].as_str().ok_or("message must be text")?;
            }
            _ => {}
        }
    }
    if staged["instructions"] != state["instructions"] {
        staged["candidate"] = Value::Null;
    }
    for effect in effects {
        match effect["type"].as_str().unwrap() {
            "return" => staged["candidate"] = json!({"body":effect["value"],"supplier":supplier}),
            "deny" => staged["denied"] = json!(true),
            "message" => staged["messages"]
                .as_array_mut()
                .unwrap()
                .push(effect["text"].clone()),
            _ => {}
        }
    }
    Ok(staged)
}
fn pipeline(
    state: &mut Value,
    hooks: &[CompactionHook<'_>],
    boundary: &str,
    item_id: &str,
    observe_only: bool,
    seen: &mut Vec<Value>,
    failures: &mut Vec<Value>,
) -> bool {
    let caps = capabilities(boundary, observe_only && boundary == "after").unwrap();
    for hook in hooks {
        let mut snapshot = state.clone();
        snapshot["boundary"] = json!(boundary);
        snapshot["capabilities"] = caps.clone();
        seen.push(snapshot.clone());
        match (hook.run)(&snapshot).and_then(|effects| {
            stage(
                state,
                &effects,
                boundary,
                hook.supplier,
                item_id,
                observe_only,
            )
        }) {
            Ok(staged) => *state = staged,
            Err(_) => {
                failures.push(json!({"boundary":boundary,"supplier":hook.supplier}));
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
    let mut state = json!({"instructions":instructions,"candidate":null,"summary":null,"bodies":{},"messages":[],"denied":false});
    let mut seen = vec![];
    let mut failures = vec![];
    let mut generated = false;
    let mut applied = false;
    let mut provenance = Value::Null;
    if pipeline(
        &mut state,
        before,
        "before",
        item_id,
        observe_only,
        &mut seen,
        &mut failures,
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
        state["summary"] = summary(&mut state, item_id, &body);
        applied = observe_only
            || pipeline(
                &mut state,
                after,
                "after",
                item_id,
                false,
                &mut seen,
                &mut failures,
            );
    }
    state["seen"] = json!(seen);
    state["failures"] = json!(failures);
    state["generated"] = json!(generated);
    state["applied"] = json!(applied);
    state["provenance"] = provenance;
    Ok(state)
}
