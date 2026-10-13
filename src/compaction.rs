//! Canonical compaction staging over authorized immutable content.
//! Responses commit atomically; the application owns generation, scheduling and
//! downstream context installation.
use serde_json::{Value, json};

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
        crate::generated::EventType::ContextCompactBefore
    } else {
        crate::generated::EventType::ContextCompactAfter
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
                "event":{"id":"before","harness":{"name":"test","version":"1"},"source":"urn:test:host","time":"2026-09-15T12:00:00Z",
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
