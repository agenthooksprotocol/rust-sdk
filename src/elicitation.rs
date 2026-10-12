//! Complete MCP payload binding. Resolver/validator and authenticated principal
//! are host-owned; requester metadata is not an authentication assertion.
use crate::interop::Result;
use serde_json::{Value, json};

pub fn validate_exchange(
    request: &Value,
    result: &Value,
    resolve: impl Fn(&Value) -> Result<Vec<u8>>,
    validate: impl Fn(&str, &Value) -> Result<()>,
    principal: &str,
    effect: Option<&Value>,
) -> Result<Value> {
    if principal.is_empty() {
        return Err("Authenticated principal required".into());
    }
    for e in [request, result] {
        validate("intercept-request", e)?;
        if e["id"] != e["params"]["event"]["id"] {
            return Err("Request/event ID mismatch".into());
        }
    }
    let re = &request["params"]["event"];
    let se = &result["params"]["event"];
    if re["type"] != "user.elicitation.request" || se["type"] != "user.elicitation.result" {
        return Err("Wrong elicitation boundary".into());
    }
    validate_correlation(request, result)?;
    let req = &re["elicitation"];
    let res = &se["elicitation"];
    let payload = read_selected(req, "request", &resolve, &validate)?;
    let answer = read_selected(res, "result", &resolve, &validate)?;
    if req["mode"] != res["mode"] || req["server"] != res["server"] {
        return Err("Normalized metadata mismatch".into());
    }
    if payload.is_none() || answer.is_none() {
        if effect.is_some() {
            return Err("Effects require selected bodies".into());
        }
        return Ok(
            json!({"selection":{"request":selection(req,"request"),"result":selection(res,"result")},"bodyValidation":"not-selected","provenance":{"kind":"mcp","authenticatedSource":principal},"externalCompletion":false}),
        );
    }
    let payload = payload.unwrap();
    let answer = answer.unwrap();
    validate_answer(&payload, &answer, &validate)?;
    let mode = payload
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("form");
    if req["mode"] != mode
        || res["mode"] != mode
        || req["server"] != res["server"]
        || res["action"] != answer["action"]
    {
        return Err("Normalized metadata mismatch".into());
    }
    if (mode == "url" || answer["action"] != "accept") && answer.get("content").is_some() {
        return Err("Content is only permitted for accepted forms".into());
    }
    let mut provenance = json!({"kind":"mcp","authenticatedSource":principal});
    if let Some(effect) = effect {
        validate("effect", effect)?;
        let kind = effect["type"].as_str().unwrap_or("");
        let boundary = if kind == "modify" { result } else { request };
        if !["return", "deny", "modify"].contains(&kind)
            || !boundary["params"]["capabilities"]["effects"]
                .as_array()
                .is_some_and(|a| a.contains(&json!(kind)))
        {
            return Err("Effect not granted at this boundary".into());
        }
        if kind == "modify"
            && (!["replace", "merge"].contains(&effect["operation"].as_str().unwrap_or(""))
                || effect["target"] != "content"
                || boundary["params"]["capabilities"]["modify"]["content"]
                    [effect["operation"].as_str().unwrap_or("")]
                    != true)
        {
            return Err("Modify target/operation not granted".into());
        }
        provenance = json!({"kind":"hook","authenticatedSource":principal,"effect":kind});
    }
    Ok(
        json!({"request":payload,"result":answer,"provenance":provenance,"externalCompletion":false}),
    )
}

/// Validate submitted data. Defaults are annotations, never type restrictions.
pub fn validate_answer(
    request: &Value,
    answer: &Value,
    validate: &impl Fn(&str, &Value) -> Result<()>,
) -> Result<()> {
    validate("mcp-elicitation#result", answer)?;
    let mode = request
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("form");
    if (mode == "url" || answer["action"] != "accept") && answer.get("content").is_some() {
        return Err("Content only permitted for accepted forms".into());
    }
    if mode == "form" && answer["action"] == "accept" {
        validate(
            "form-answer",
            &json!({"schema":request["requestedSchema"],"value":answer.get("content").cloned().unwrap_or(json!({}))}),
        )?;
    }
    Ok(())
}

pub fn validate_mode(mode: &str, capabilities: Option<&Value>, origin: &str) -> Result<Value> {
    if !["ahp", "mcp"].contains(&origin) || !["form", "url"].contains(&mode) {
        return Err("Unknown origin or mode".into());
    }
    let mut caps = capabilities.cloned().unwrap_or(json!({}));
    let object = caps.as_object().ok_or("Invalid capabilities")?;
    if object
        .iter()
        .any(|(k, v)| ["form", "url"].contains(&k.as_str()) && !v.is_object())
    {
        return Err("Invalid capabilities".into());
    }
    if origin == "mcp" && capabilities.is_some() && object.is_empty() {
        caps = json!({"form":{}});
    }
    if caps.get(mode).is_none() {
        return Err("Mode not registered".into());
    }
    Ok(caps)
}

/// Stage the entire list on a snapshot. Publish only the returned validated state;
/// callers must upload complete result JSON before delivering a result event.
pub fn apply_effects(
    request: &Value,
    result: Option<&Value>,
    resolve: impl Fn(&Value) -> Result<Vec<u8>>,
    validate: impl Fn(&str, &Value) -> Result<()>,
    principal: &str,
    effects: &[Value],
) -> Result<Value> {
    if principal.is_empty() || effects.is_empty() {
        return Err("Authenticated effects required".into());
    }
    validate("intercept-request", request)?;
    let event = &request["params"]["event"];
    if request["id"] != event["id"] || event["type"] != "user.elicitation.request" {
        return Err("Invalid request boundary".into());
    }
    if let Some(result) = result {
        validate_correlation(request, result)?;
    }
    let meta = &event["elicitation"];
    let payload = read_selected(meta, "request", &resolve, &validate)?
        .ok_or("Effects require selected request body")?;
    if meta["mode"]
        != payload
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("form")
    {
        return Err("Mode mismatch".into());
    }
    let boundary = result.unwrap_or(request);
    let caps = &boundary["params"]["capabilities"];
    let mut staged = match result {
        Some(r) => {
            validate_exchange(request, r, &resolve, &validate, principal, None)?["result"].clone()
        }
        None => Value::Null,
    };
    if result.is_some() && staged.is_null() {
        return Err("Effects require selected bodies".into());
    }
    let mut kinds: Vec<String> = vec![];
    for effect in effects {
        validate("effect", effect)?;
        let kind = effect["type"].as_str().ok_or("effect type")?;
        if !caps["effects"]
            .as_array()
            .is_some_and(|a| a.contains(&json!(kind)))
            || !(if result.is_none() {
                ["return", "deny"].contains(&kind)
            } else {
                kind == "modify"
            })
        {
            return Err("Effect not granted at boundary".into());
        }
        if kind == "return" || kind == "deny" {
            if !kinds.is_empty() {
                return Err("Conflicting terminal effects".into());
            }
            staged = if kind == "return" {
                effect["value"].clone()
            } else {
                json!({"action":"decline"})
            };
        } else {
            let op = effect["operation"].as_str().ok_or("operation")?;
            if !["replace", "merge"].contains(&op)
                || effect["target"] != "content"
                || caps["modify"]["content"][op] != true
            {
                return Err("Modify operation not granted".into());
            }
            if op == "replace" {
                staged["content"] = effect["value"].clone();
            } else {
                if staged.get("content").is_none() {
                    staged["content"] = json!({});
                }
                let map = staged["content"].as_object_mut().ok_or("content")?;
                for (k, v) in effect["value"].as_object().ok_or("merge value")? {
                    map.insert(k.clone(), v.clone());
                }
            }
        }
        kinds.push(kind.into());
    }
    validate_answer(&payload, &staged, &validate)?;
    Ok(
        json!({"request":payload,"result":staged,"provenance":{"kind":"hook","authenticatedSource":principal,"effects":kinds},"externalCompletion":false}),
    )
}

fn selection<'a>(meta: &'a Value, stage: &str) -> &'a str {
    meta[stage]["selection"].as_str().unwrap_or("omit")
}

/// Metadata/omit never resolve content. Selected gaps fail closed by default.
pub fn read_selected(
    meta: &Value,
    stage: &str,
    _resolve: &impl Fn(&Value) -> Result<Vec<u8>>,
    validate: &impl Fn(&str, &Value) -> Result<()>,
) -> Result<Option<Value>> {
    let Some(item) = meta.get(stage) else {
        return Ok(None);
    };
    validate("content-item", item)?;
    if item["mediaType"] != "text/plain" || item["kind"] != "text" {
        return Err("MCP payload must be an inline text part".into());
    }
    if item["selection"] != "body" {
        return Ok(None);
    }
    let text = item["text"]
        .as_str()
        .ok_or("Selected inline text unavailable (fail closed)")?;
    let payload: Value = serde_json::from_str(text)?;
    validate(&format!("mcp-elicitation#{stage}"), &payload)?;
    if stage == "request"
        && meta["mode"]
            != payload
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("form")
    {
        return Err("Mode mismatch".into());
    }
    if stage == "result" {
        if meta["action"] != payload["action"] {
            return Err("Action mismatch".into());
        }
        if (meta["mode"] == "url" || payload["action"] != "accept")
            && payload.get("content").is_some()
        {
            return Err("Forbidden content".into());
        }
    }
    Ok(Some(payload))
}

/// Bind the source-scoped parent and session before resolving any body.
pub fn validate_correlation(request: &Value, result: &Value) -> Result<()> {
    let req = &request["params"]["event"];
    let res = &result["params"]["event"];
    if !res["parentEventId"].is_string()
        || res["parentEventId"] != req["id"]
        || res["source"] != req["source"]
        || res["session"]["id"] != req["session"]["id"]
    {
        return Err("Elicitation parent/source/session mismatch".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_extensions_do_not_grant_modes_or_relax_known_fields() {
        let caps = json!({"form": {}, "future": 42});
        assert_eq!(validate_mode("form", Some(&caps), "ahp").unwrap(), caps);
        assert!(validate_mode("url", Some(&caps), "ahp").is_err());
        assert!(validate_mode("form", Some(&json!({"future": {}})), "ahp").is_err());
        assert!(validate_mode("form", Some(&json!({"form": false, "future": {}})), "ahp").is_err());
        assert!(validate_mode("form", Some(&json!({})), "ahp").is_err());
        assert_eq!(
            validate_mode("form", Some(&json!({})), "mcp").unwrap(),
            json!({"form": {}})
        );
    }

    #[test]
    fn unknown_operations_are_not_enabled_by_capability_extensions() {
        let request = json!({"id":"request","params":{"event":{
            "id":"request","source":"source","session":{"id":"session"},
            "type":"user.elicitation.request","elicitation":{"mode":"form","server":"server",
                "request":{"id":"request","kind":"text","mediaType":"text/plain","selection":"body","text":"{\"requestedSchema\":{}}"}}}}});
        let result = json!({"id":"result","params":{"capabilities":{"effects":["modify"],"modify":{"content":{"replace":true,"future":true}}},
            "event":{"id":"result","source":"source","session":{"id":"session"},"parentEventId":"request",
                "type":"user.elicitation.result","elicitation":{"mode":"form","server":"server","action":"accept",
                    "result":{"id":"result","kind":"text","mediaType":"text/plain","selection":"body","text":"{\"action\":\"accept\",\"content\":{\"original\":true}}"}}}}});
        // A permissive callback isolates semantic enforcement from schema checks.
        let resolve =
            |_: &Value| -> Result<Vec<u8>> { panic!("inline payload must not call resolver") };
        let validate = |_: &str, _: &Value| Ok(());
        let valid = json!({"type":"modify","target":"content","operation":"replace","value":{"changed":true}});
        let invalid =
            json!({"type":"modify","target":"content","operation":"future","value":{"leak":true}});
        assert!(
            apply_effects(
                &request,
                Some(&result),
                resolve,
                validate,
                "principal",
                std::slice::from_ref(&valid)
            )
            .is_ok()
        );
        assert!(
            apply_effects(
                &request,
                Some(&result),
                resolve,
                validate,
                "principal",
                &[valid, invalid.clone()]
            )
            .is_err()
        );
        assert!(
            validate_exchange(
                &request,
                &result,
                resolve,
                validate,
                "principal",
                Some(&invalid)
            )
            .is_err()
        );
        assert_eq!(
            serde_json::from_str::<Value>(
                result["params"]["event"]["elicitation"]["result"]["text"]
                    .as_str()
                    .unwrap()
            )
            .unwrap()["content"],
            json!({"original":true})
        );
    }
}

/// Immutable original envelope and complete resolved MCP request snapshot.
#[derive(Clone, Debug)]
pub struct Exchange {
    envelope: Value,
    request: Option<Value>,
}
impl Exchange {
    pub fn new(envelope: &Value, content: &dyn crate::content::ContentAccess) -> Result<Self> {
        public_validate("intercept-request", envelope)?;
        let event = &envelope["params"]["event"];
        if event["type"] != "user.elicitation.request" || envelope["id"] != event["id"] {
            return Err("Invalid elicitation request boundary".into());
        }
        let request = read_public_selected(&event["elicitation"], "request", content)?;
        Ok(Self {
            envelope: envelope.clone(),
            request,
        })
    }
    pub fn original_envelope(&self) -> &Value {
        &self.envelope
    }
    pub fn original_event(&self) -> &Value {
        &self.envelope["params"]["event"]
    }
    pub fn original_request(&self) -> Option<&Value> {
        self.request.as_ref()
    }
}

fn read_public_selected(
    meta: &Value,
    stage: &str,
    _content: &dyn crate::content::ContentAccess,
) -> Result<Option<Value>> {
    read_selected(
        meta,
        stage,
        &|_| Err("inline payloads do not resolve attachments".into()),
        &public_validate,
    )
}

// Public stages use bundled pinned validators, never application policy.
fn public_validate(name: &str, value: &Value) -> Result<()> {
    if name == "form-answer" {
        jsonschema::options()
            .should_validate_formats(true)
            .build(&value["schema"])?
            .validate(&value["value"])
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    crate::canonical::validate(name, value)?;
    Ok(())
}

// Reducer commands are constructed exclusively from contextual generated effects.
enum ElicitationEdit {
    Return(Box<crate::generated::McpElicitationElicitResult>),
    Deny,
    Modify(bool, Box<crate::generated::FormAnswers>),
    Message(Box<crate::generated::MessageEffect>),
}

/// Atomically stage a boundary. `candidate` is absent, not null, when no answer
/// is selected. Changed complete JSON is serialized into the inline result text.
pub fn stage_boundary(
    request: &Value,
    effects: &[Value],
    content: &dyn crate::content::ContentAccess,
    original: Option<&Exchange>,
) -> Result<Value> {
    stage_boundary_admitted(
        request,
        effects,
        content,
        original,
        &crate::contracts::Admission::default(),
    )
}

pub(crate) fn stage_boundary_admitted(
    request: &Value,
    effects: &[Value],
    content: &dyn crate::content::ContentAccess,
    original: Option<&Exchange>,
    admission: &crate::contracts::Admission,
) -> Result<Value> {
    use crate::generated::*;
    public_validate("intercept-request", request)?;
    let mut typed: InterceptRequest = serde_json::from_value(request.clone())?;
    let event_type = match typed.params.event.as_ref() {
        Event::UserElicitationRequest(_) => EventType::UserElicitationRequest,
        Event::UserElicitationResult(_) => EventType::UserElicitationResult,
        _ => return Err("Invalid request boundary".into()),
    };
    let response = json!({"jsonrpc":"2.0","id":request["id"],
        "result":{"protocolVersion":"draft","effects":effects}});
    public_validate("intercept-response", &response)?;
    let parsed = match response_for_request(event_type, &serde_json::to_string(&response)?) {
        ParseResult::Success { value, .. } => value,
        ParseResult::Failure { diagnostics, .. } => {
            return Err(format!("Invalid elicitation response: {diagnostics:?}").into());
        }
    };
    let mut edits = Vec::new();
    match parsed {
        ContextualResponse::UserElicitationRequest(r) => {
            if let Presence::Present(effects) = r.result.effects {
                for effect in effects {
                    edits.push(match *effect {
                        UserElicitationRequestEffect::Return(e) => ElicitationEdit::Return(e.value),
                        UserElicitationRequestEffect::Deny(_) => ElicitationEdit::Deny,
                        UserElicitationRequestEffect::Message(e) => ElicitationEdit::Message(e),
                        UserElicitationRequestEffect::Unknown(_) => {
                            return Err("Effect not permitted at elicitation boundary".into());
                        }
                    });
                }
            }
        }
        ContextualResponse::UserElicitationResult(r) => {
            if let Presence::Present(effects) = r.result.effects {
                for effect in effects {
                    edits.push(match *effect {
                        UserElicitationResultEffect::ModifyContent(e) => ElicitationEdit::Modify(
                            matches!(
                                e.operation,
                                UserElicitationResultModifyEffectOperation::Merge(_)
                            ),
                            e.value,
                        ),
                        UserElicitationResultEffect::Message(e) => ElicitationEdit::Message(e),
                        UserElicitationResultEffect::Unknown(_) => {
                            return Err("Effect not permitted at elicitation boundary".into());
                        }
                    });
                }
            }
        }
        _ => return Err("Invalid elicitation response".into()),
    }
    let event = request["params"]["event"].clone();
    if request["id"] != event["id"] {
        return Err("Request/event ID mismatch".into());
    }
    let result_stage = event["type"] == "user.elicitation.result";
    let owned;
    let exchange = if result_stage {
        let exchange = original.ok_or("Result requires original elicitation exchange")?;
        validate_correlation(&exchange.envelope, request)?;
        let first = exchange.original_event();
        if event.get("call") != first.get("call")
            || event["elicitation"]["mode"] != first["elicitation"]["mode"]
            || event["elicitation"]["server"] != first["elicitation"]["server"]
        {
            return Err("Elicitation correlation metadata mismatch".into());
        }
        exchange
    } else {
        owned = Exchange::new(request, content)?;
        &owned
    };
    let payload = exchange.request.as_ref();
    let selected_answer = if result_stage {
        read_public_selected(&event["elicitation"], "result", content)?
    } else {
        None
    };
    if let (Some(payload), Some(answer)) = (payload, selected_answer.as_ref()) {
        validate_answer(payload, answer, &public_validate)?;
    }
    let mut answer: Option<McpElicitationElicitResult> =
        selected_answer.map(serde_json::from_value).transpose()?;
    let caps = &typed.params.capabilities;
    let mut denied = false;
    let mut terminal = false;
    let mut messages = Vec::new();
    // Compare final semantic state, not the occurrence of modify effects. This
    // preserves the original exact bytes, hints and reference for no-op batches.
    let original_answer = answer.clone();
    for edit in edits {
        let kind = match &edit {
            ElicitationEdit::Modify(..) => {
                InterceptRequestParamsCapabilitiesEffectsItemKnown::Modify
            }
            ElicitationEdit::Return(_) => {
                InterceptRequestParamsCapabilitiesEffectsItemKnown::Return
            }
            ElicitationEdit::Deny => InterceptRequestParamsCapabilitiesEffectsItemKnown::Deny,
            ElicitationEdit::Message(_) => {
                InterceptRequestParamsCapabilitiesEffectsItemKnown::Message
            }
        };
        if !caps.effects.iter().any(|grant| matches!(grant, InterceptRequestParamsCapabilitiesEffectsItem::Known(known) if *known == kind)) {
            return Err("Effect not granted".into());
        }
        if let ElicitationEdit::Message(message) = edit {
            messages.push(message);
            continue;
        }
        let form_mode = match typed.params.event.as_ref() {
            Event::UserElicitationRequest(event) => matches!(
                event.elicitation.mode,
                UserElicitationRequestEventElicitationMode::Form
            ),
            Event::UserElicitationResult(event) => matches!(
                event.elicitation.mode,
                UserElicitationResultEventElicitationMode::Form
            ),
            _ => unreachable!(),
        };
        let registered = match &caps.elicitation {
            Presence::Present(grant) => {
                if form_mode {
                    matches!(grant.form, Presence::Present(_))
                } else {
                    matches!(grant.url, Presence::Present(_))
                }
            }
            Presence::Missing => false,
        };
        if !registered {
            return Err("Mode not registered".into());
        }
        payload.ok_or("Effects require original selected request")?;
        match edit {
            ElicitationEdit::Return(value) => {
                if terminal {
                    return Err("Conflicting terminal effects".into());
                }
                terminal = true;
                answer = Some(*value);
            }
            ElicitationEdit::Deny => {
                if terminal {
                    return Err("Conflicting terminal effects".into());
                }
                terminal = true;
                denied = true;
                answer = Some(McpElicitationElicitResult::new(
                    McpElicitationElicitResultAction::Decline,
                ));
            }
            ElicitationEdit::Modify(merge, patch) => {
                let granted = match &caps.modify {
                    Presence::Present(modify) => match &modify.content {
                        Presence::Present(grant) => {
                            if merge {
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
                    return Err("Modify not granted".into());
                }
                let answer = answer.as_mut().ok_or("Modify requires selected result")?;
                if !form_mode || answer.action != McpElicitationElicitResultAction::Accept {
                    return Err(
                        "Content modification requires an accepted form answer object".into(),
                    );
                }
                if !merge {
                    answer.content = Presence::Present(patch);
                } else if !patch.0.is_empty() {
                    if matches!(answer.content, Presence::Missing) {
                        answer.content = Presence::Present(Box::new(FormAnswers::new(
                            std::collections::BTreeMap::new(),
                        )));
                    }
                    if let Presence::Present(content) = &mut answer.content {
                        content.0.extend(patch.0);
                    }
                }
            }
            ElicitationEdit::Message(_) => unreachable!(),
        }
        // Keep publication atomic, but admit every intermediate complete answer.
        // Validate a temporary event so no-op batches retain original exact bytes.
        let mut intermediate = typed.clone();
        if let Some(answer) = answer.as_ref() {
            let value = serde_json::to_value(answer)?;
            if let Some(payload) = payload {
                validate_answer(payload, &value, &public_validate)?;
            }
            admission.returned(&value)?;
            if original_answer.as_ref() != Some(answer)
                && result_stage
                && let Event::UserElicitationResult(event) = intermediate.params.event.as_mut()
            {
                match &mut event.elicitation.result {
                    Presence::Present(part) => match part.as_mut() {
                        TextPart::TextBodyPart(body) => body.text = serde_json::to_string(answer)?,
                        _ => return Err("Modify requires selected result".into()),
                    },
                    Presence::Missing => return Err("Modify requires selected result".into()),
                }
            }
        }
        public_validate("intercept-request", &serde_json::to_value(&intermediate)?)?;
        admission.event(&serde_json::to_value(&intermediate.params.event)?)?;
    }
    if let Some(answer) = answer.as_ref() {
        if let Some(payload) = payload {
            validate_answer(payload, &serde_json::to_value(answer)?, &public_validate)?;
        }
        if original_answer.as_ref() != Some(answer)
            && result_stage
            && let Event::UserElicitationResult(event) = typed.params.event.as_mut()
        {
            match &mut event.elicitation.result {
                Presence::Present(part) => match part.as_mut() {
                    TextPart::TextBodyPart(body) => body.text = serde_json::to_string(answer)?,
                    _ => return Err("Modify requires selected result".into()),
                },
                Presence::Missing => return Err("Modify requires selected result".into()),
            }
        }
    }
    let event = serde_json::to_value(&typed.params.event)?;
    let mut staged =
        json!({"event":event,"denied":denied,"messages":messages,"externalCompletion":false});
    if let Some(answer) = answer {
        staged["candidate"] = serde_json::to_value(answer)?;
    }
    Ok(staged)
}

#[cfg(test)]
mod typed_boundary_tests {
    use super::*;
    use crate::content::{AuthorizedScope, ContentContext, MemoryContentStore};

    #[test]
    fn request_boundary_rejects_result_only_and_unknown_effects_atomically() {
        let store = MemoryContentStore::new(4096, 65536, 100);
        let content = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("scope"),
        };
        let request = json!({"jsonrpc":"2.0","id":"request","method":"hooks/intercept",
            "params":{"protocolVersion":"draft","capabilities":{"effects":["message","modify","future.effect"],"elicitation":{"form":{}}},
                "event":{"id":"request","source":"urn:test:host","time":"2026-09-15T12:00:00Z",
                    "type":"user.elicitation.request","elicitation":{"server":"mcp","mode":"form"}}}});
        let original = request.clone();
        for invalid in [
            json!({"type":"modify","target":"content","operation":"replace","value":{"answer":"wrong boundary"}}),
            json!({"type":"return","value":[{"kind":"text"}]}),
            json!({"type":"future.effect"}),
        ] {
            assert!(
                stage_boundary(
                    &request,
                    &[json!({"type":"message","text":"pending"}), invalid],
                    &content,
                    None
                )
                .is_err()
            );
            assert_eq!(request, original);
        }
    }
}
