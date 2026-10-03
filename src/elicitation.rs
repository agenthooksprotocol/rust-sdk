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
    resolve: &impl Fn(&Value) -> Result<Vec<u8>>,
    validate: &impl Fn(&str, &Value) -> Result<()>,
) -> Result<Option<Value>> {
    let Some(item) = meta.get(stage) else {
        return Ok(None);
    };
    validate("content-item", item)?;
    if item["mediaType"] != "application/json" {
        return Err("MCP body must be application/json".into());
    }
    if item["selection"] != "body" {
        return Ok(None);
    }
    let body = item
        .get("body")
        .ok_or("Selected body unavailable (fail closed)")?;
    let payload: Value = serde_json::from_slice(&resolve(body)?)?;
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
                "request":{"mediaType":"application/json","selection":"body","body":{"requestedSchema":{}}}}}}});
        let result = json!({"id":"result","params":{"capabilities":{"effects":["modify"],"modify":{"content":{"replace":true,"future":true}}},
            "event":{"id":"result","source":"source","session":{"id":"session"},"parentEventId":"request",
                "type":"user.elicitation.result","elicitation":{"mode":"form","server":"server","action":"accept",
                    "result":{"mediaType":"application/json","selection":"body","body":{"action":"accept","content":{"original":true}}}}}}});
        // A permissive callback isolates semantic enforcement from schema checks.
        let resolve = |body: &Value| Ok(serde_json::to_vec(body).unwrap());
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
                &[valid.clone()]
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
            result["params"]["event"]["elicitation"]["result"]["body"]["content"],
            json!({"original":true})
        );
    }
}
