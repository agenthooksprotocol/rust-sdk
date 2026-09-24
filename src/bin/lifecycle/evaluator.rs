//! Reuse the existing evaluator with a private synthetic-tool input projection.
//!
//! Core interop's `task > 0` check is a fixture-specific tool validator, not AHP.
//! Lifecycle fixtures use arbitrary object inputs. Box those objects under a
//! private key while keeping task=1 for the core synthetic tool. This preserves
//! equality/change detection and all SDK effect composition, capability checks,
//! candidate invalidation, approval invalidation, flow and injection behavior.
//! Neither projected request nor response is sent on the wire or published.
use super::*;
pub(super) fn apply(request: &Value, response: &Value, schemas: &Schemas) -> Result<Value> {
    schemas.validate("intercept-request", request)?;
    schemas.validate("intercept-response", response)?;
    if request["params"]["event"]["type"] != "tool.before" {
        return interop::apply(request, response, schemas);
    }
    let mut projected_request = request.clone();
    let mut projected_response = response.clone();
    let mut input = request["params"]["event"]["tool"]["input"].clone();
    projected_request["params"]["event"]["tool"]["input"] =
        json!({"task":1,"lifecycleInput":input});
    for effect in projected_response["result"]["effects"]
        .as_array_mut()
        .ok_or("missing effects")?
    {
        if effect["type"] != "modify" {
            continue;
        }
        let value = effect["value"]
            .as_object()
            .ok_or("lifecycle input must be an object")?
            .clone();
        match s(effect, "operation") {
            "replace" => input = Value::Object(value),
            "merge" => input
                .as_object_mut()
                .ok_or("lifecycle input must be an object")?
                .extend(value),
            _ => return Err("unsupported lifecycle modification".into()),
        }
        effect["value"] = json!({"task":1,"lifecycleInput":input});
    }
    let mut state = interop::apply(&projected_request, &projected_response, schemas)?;
    state["input"] = state["input"]["lifecycleInput"].clone();
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_preserves_merge_replace_and_invalidation() {
        let schemas = Schemas::bundled().unwrap();
        let request = json!({"jsonrpc":"2.0","id":"test","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"test","source":"urn:rust:test","type":"tool.before","time":"2026-09-01T00:00:00Z","session":{"id":"s"},"call":{"id":"c"},"path":"native","tool":{"origin":"native","name":"task","kind":"task","input":{"task":"lifecycle string","nested":{"a":1,"b":2}}}},"capabilities":interop::capabilities(),"state":{"permission":"allow","candidate":{"value":"stale","provenance":{}}}}});
        let response = json!({"jsonrpc":"2.0","id":"test","result":{"protocolVersion":"draft","effects":[{"type":"modify","target":"input","operation":"merge","value":{"nested":{"a":3}}}]}});
        let before = request.clone();
        let actual = apply(&request, &response, &schemas).unwrap();
        assert_eq!(
            actual["input"],
            json!({"task":"lifecycle string","nested":{"a":3}})
        );
        assert!(actual.get("result").is_none());
        assert_eq!(request, before);
        let mut response = response;
        response["result"]["effects"][0]["operation"] = json!("replace");
        response["result"]["effects"][0]["value"] = json!({"value":"settled"});
        assert_eq!(
            apply(&request, &response, &schemas).unwrap()["input"],
            json!({"value":"settled"})
        );
        response["id"] = json!("stale");
        assert!(apply(&request, &response, &schemas).is_err());
    }
}
