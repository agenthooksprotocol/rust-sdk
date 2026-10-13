//! Host-side reporting for boundaries evaluated by the public SDK.
//! Arbitrary lifecycle inputs are never projected through the synthetic `task` tool.
use super::*;
use agenthooksprotocol::client::{
    BoundaryResult, Client, FailurePolicy, Hook, HookError, LocalFuture, Permission, Subscription,
    ToolContext,
};

struct AcquiredResponse(Value);
impl Hook for AcquiredResponse {
    fn call(&self, _request: Value) -> LocalFuture<'_, std::result::Result<Value, HookError>> {
        Box::pin(async move { Ok(self.0.clone()) })
    }
}

pub(super) fn sdk_client(request: &Value, hook: impl Hook + 'static) -> Client {
    Client::new(ToolContext::new(request["params"]["event"].clone())).with_subscription(
        Subscription::intercept("lifecycle", FailurePolicy::Closed, hook),
    )
}

pub(super) struct Evaluated {
    pub state: Value,
    pub permission: Permission,
}

pub(super) async fn evaluate(client: &Client, request: &Value) -> Result<Evaluated> {
    let mut boundary = client
        .tool_before(request["params"]["event"]["tool"]["input"].clone())
        .capabilities(request["params"]["capabilities"].clone());
    if let Some(snapshot) = request["params"].get("state") {
        boundary = boundary.initial_snapshot(snapshot)?;
    }
    let result = boundary.await?;
    let permission = result.outcome.decision;
    Ok(Evaluated {
        state: report(result)?,
        permission,
    })
}

fn report(result: BoundaryResult<'_, Value>) -> Result<Value> {
    if let Some(failure) = result.outcome.failures.first() {
        return Err(failure.error.to_string().into());
    }
    let outcome = &result.outcome;
    let denied = matches!(outcome.decision, Permission::Deny | Permission::Ask);
    let candidate = outcome.candidate().filter(|_| !denied && !outcome.stopped);
    // Fixture host policy grants ordinary permission (and reauthorizes changed
    // input) when the SDK leaves permission undecided. This is not an SDK default.
    let decision = match outcome.decision {
        Permission::None | Permission::Allow => "allow",
        Permission::Ask => "ask",
        Permission::Deny => "deny",
    };
    let mut state = json!({"decision":decision,"executed":false,"input":serde_json::to_value(&result.event)?["tool"]["input"],"messages":outcome.messages.iter().map(|m| json!(m.text)).collect::<Vec<_>>()});
    if outcome.stopped {
        state["flow"] = json!("stop");
    }
    if !outcome.injections.is_empty() {
        state["injections"] = json!(outcome.injections);
    }
    if let Some(candidate) = candidate {
        state["result"] = serde_json::to_value(candidate)?;
    }
    // Decode and application validation are a separate host gate. A refusal must
    // not masquerade as protocol rollback or claim execution happened.
    let host_input = result.input.ok().filter(Value::is_object);
    if host_input.is_none() {
        state["hostAccepted"] = json!(false);
        state["sdkAccepted"] = json!(true);
        return Ok(state);
    }
    if !denied && !outcome.stopped && candidate.is_none() {
        let execute = |_input: Value| true;
        state["executed"] = json!(execute(host_input.unwrap()));
    }
    Ok(state)
}

pub(super) fn apply(request: &Value, response: &Value, schemas: &Schemas) -> Result<Value> {
    schemas.validate("intercept-request", request)?;
    schemas.validate("intercept-response", response)?;
    if request["params"]["event"]["type"] != "tool.before" {
        return Err("lifecycle evaluator requires tool.before".into());
    }
    if request["id"] != request["params"]["event"]["id"] || response["id"] != request["id"] {
        return Err("correlation mismatch".into());
    }
    let client = sdk_client(request, AcquiredResponse(response.clone()));
    futures::executor::block_on(evaluate(&client, request)).map(|evaluated| evaluated.state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_null_candidate_and_stop_never_authorize_execution() {
        let schemas = Schemas::bundled().unwrap();
        let request = json!({
            "jsonrpc":"2.0", "id":"native", "method":"hooks/intercept",
            "params": {
                "protocolVersion":"draft",
                "event": {
                    "id":"native", "harness":{"name":"test","version":"1"},"source":"urn:rust:test", "type":"tool.before",
                    "time":"2026-09-01T00:00:00Z", "path":"native",
                    "call":{"id":"call"},
                    "tool":{"origin":"native", "name":"task", "input":{}}
                },
                "capabilities":interop::capabilities(),
                "state": {
                    "permission":"allow",
                    "candidate":{"value":null,"provenance":{"cache":true}},
                    "flow":"stop"
                }
            }
        });
        let neutral = json!({"jsonrpc":"2.0","id":"native","result":{"protocolVersion":"draft","effects":[]}});
        let report = apply(&request, &neutral, &schemas).unwrap();
        assert_eq!(report["executed"], false);
        assert_eq!(report["flow"], "stop");
        assert!(report.get("result").is_none());

        // Without stop, a present null candidate is still a supplied result,
        // not an absent candidate authorizing ordinary host execution.
        let mut request = request;
        request["params"]["state"]
            .as_object_mut()
            .unwrap()
            .remove("flow");
        let report = apply(&request, &neutral, &schemas).unwrap();
        assert_eq!(report["executed"], false);
        assert_eq!(report.get("result"), Some(&Value::Null));
    }

    #[test]
    fn sdk_preserves_merge_replace_and_invalidation() {
        let schemas = Schemas::bundled().unwrap();
        let request = json!({
            "jsonrpc": "2.0",
            "id": "test",
            "method": "hooks/intercept",
            "params": {
                "protocolVersion": "draft",
                "event": {
                    "id": "test",
                    "harness":{"name":"test","version":"1"},"source": "urn:rust:test",
                    "type": "tool.before",
                    "time": "2026-09-01T00:00:00Z",
                    "session": {
                        "id": "s"
                    },
                    "call": {
                        "id": "c"
                    },
                    "path": "native",
                    "tool": {
                        "origin": "native",
                        "name": "task",
                        "kind": "task",
                        "input": {
                            "task": "lifecycle string",
                            "nested": {
                                "a": 1,
                                "b": 2
                            }
                        }
                    }
                },
                "capabilities": interop::capabilities(),
                "state": {
                    "permission": "allow",
                    "candidate": {
                        "value": "stale",
                        "provenance": {}
                    }
                }
            }
        });
        let response = json!({
            "jsonrpc": "2.0",
            "id": "test",
            "result": {
                "protocolVersion": "draft",
                "effects": [{
                    "type": "modify",
                    "target": "input",
                    "operation": "merge",
                    "value": {
                        "nested": {
                            "a": 3
                        }
                    }
                }]
            }
        });
        let before = request.clone();
        let actual = apply(&request, &response, &schemas).unwrap();
        let client = sdk_client(&request, AcquiredResponse(response.clone()));
        let evaluated = futures::executor::block_on(evaluate(&client, &request)).unwrap();
        assert_eq!(evaluated.permission, Permission::None);
        assert_eq!(evaluated.state["decision"], "allow");
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
