use agent_hooks_protocol::interop::{Schemas, apply, capabilities};
use serde_json::{Value, json};

fn schemas() -> Schemas {
    Schemas::bundled().unwrap()
}
fn request() -> Value {
    json!({"jsonrpc":"2.0","id":"test","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"test","source":"urn:rust:test","type":"tool.before","time":"2026-09-01T00:00:00Z","session":{"id":"s"},"call":{"id":"c"},"path":"native","tool":{"origin":"native","name":"task","kind":"task","input":{"task":1,"nested":{"a":1,"b":2}}}},"capabilities":capabilities()}})
}
fn response(effects: Value) -> Value {
    json!({"jsonrpc":"2.0","id":"test","result":{"protocolVersion":"draft","effects":effects}})
}
#[test]
fn stage_mutations_before_candidate_and_preserve_request() {
    let schemas = schemas();
    let request = request();
    let before = request.clone();
    let actual = apply(&request,&response(json!([{"type":"return","value":false},{"type":"modify","target":"input","operation":"merge","value":{"task":2,"nested":{"a":3}}}])),&schemas).unwrap();
    assert_eq!(actual["input"], json!({"task":2,"nested":{"a":3}}));
    assert_eq!(actual["result"], false);
    assert_eq!(actual["executed"], false);
    assert_eq!(request, before);
}
#[test]
fn unsupported_effect_rejects_whole_response_without_mutation() {
    let schemas = schemas();
    let request = request();
    let before = request.clone();
    assert!(apply(&request,&response(json!([{"type":"message","text":"not visible"},{"type":"modify","target":"input","operation":"merge","value":{"task":2}},{"type":"made.up"}])),&schemas).is_err());
    assert_eq!(request, before);
}
#[test]
fn ask_and_deny_win_over_allow_and_return() {
    let schemas = schemas();
    let req = request();
    for (effect, decision) in [
        (json!({"type":"ask"}), "ask"),
        (json!({"type":"deny","reason":"policy"}), "deny"),
    ] {
        let actual = apply(
            &req,
            &response(json!([effect,{"type":"allow"},{"type":"return","value":{"ok":true}}])),
            &schemas,
        )
        .unwrap();
        assert_eq!(actual["decision"], decision);
        assert_eq!(actual["executed"], false);
        assert!(actual.get("result").is_none());
    }
}
#[test]
fn stop_discards_candidate_and_injections_are_staged() {
    let schemas = schemas();
    let req = request();
    let injection = json!({"type":"inject","target":"context","operation":"append","deliverAt":"next_turn","value":"context"});
    let actual = apply(&req,&response(json!([injection,{"type":"return","value":1},{"type":"flow","operation":"stop","reason":"done"}])),&schemas).unwrap();
    assert_eq!(actual["flow"], "stop");
    assert_eq!(actual["executed"], false);
    assert!(actual.get("result").is_none());
    assert_eq!(actual["injections"], json!([injection]));
}
#[test]
fn canonical_validation_and_correlation_are_mandatory() {
    let schemas = schemas();
    let req = request();
    let mut res = response(json!([]));
    res["id"] = json!("wrong");
    assert!(apply(&req, &res, &schemas).is_err());
    res = response(json!([{"type":"flow","operation":"stop"}]));
    assert!(apply(&req, &res, &schemas).is_err());
    let mut req = req;
    req["params"]["event"]["time"] = json!("not a timestamp");
    assert!(apply(&req, &response(json!([])), &schemas).is_err());
}

#[test]
fn continuation_instructions_accumulate_but_consume_one_allowance() {
    let schemas = schemas();
    let mut req = request();
    req["params"]["event"]
        .as_object_mut()
        .unwrap()
        .remove("tool");
    req["params"]["event"]["type"] = json!("turn.finish.before");
    req["params"]["capabilities"] =
        agent_hooks_protocol::interop::capabilities_for("turn.finish.before").unwrap();
    req["params"]["event"]["turn"] = json!({"id":"turn"});
    req["params"]["event"]["continuationCount"] = json!(0);
    req["params"]["event"]["outcome"] = json!("completed");
    req["params"]["event"]["items"] = json!([]);
    let effects = json!([{"type":"flow","operation":"continue","instruction":"Check output"},{"type":"flow","operation":"continue","instruction":"Then check logs"}]);
    let actual = apply(&req, &response(effects.clone()), &schemas).unwrap();
    assert_eq!(
        actual["continuationInstructions"],
        json!(["Check output", "Then check logs"])
    );
    assert_eq!(actual["continuationRemaining"], 1);
    assert_eq!(
        req["params"]["capabilities"]["flow"]["remainingContinuations"],
        2
    );
    let mut stopped = effects.as_array().unwrap().clone();
    stopped.push(json!({"type":"flow","operation":"stop","reason":"Stop wins"}));
    let actual = apply(&req, &response(json!(stopped)), &schemas).unwrap();
    assert_eq!(actual["flow"], "stop");
    assert_eq!(
        actual["continuationInstructions"],
        json!(["Check output", "Then check logs"])
    );
    assert_eq!(actual["continuationRemaining"], 2);
}

#[test]
fn changed_input_invalidates_candidate_and_prior_allow_but_never_ask_or_deny() {
    let schemas = schemas();
    for prior in ["allow", "ask", "deny"] {
        let mut req = request();
        req["params"]["state"] =
            json!({"permission":prior,"candidate":{"value":"old","provenance":{"source":"cache"}}});
        let before = req.clone();
        let actual=apply(&req,&response(json!([{"type":"allow"},{"type":"modify","target":"input","operation":"replace","value":{"task":2}}])),&schemas).unwrap();
        assert_eq!(actual["input"], json!({"task":2}));
        assert!(actual.get("result").is_none());
        assert_eq!(actual["decision"], prior);
        assert_eq!(actual["executed"], prior == "allow");
        assert_eq!(req, before);
    }
}
#[test]
fn task_workspace_payloads_and_capabilities_are_enforced() {
    let schemas = schemas();
    for (kind, payload) in [
        (
            "task",
            json!({"id":"durable","operation":"update","change":{"status":"native-done"}}),
        ),
        ("workspace", json!({"kind":"cwd","change":{"cwd":"/next"}})),
    ] {
        let event = format!("{kind}.change.before");
        let mut req = request();
        req["params"]["event"] = json!({"id":"test","source":"urn:rust:test","time":"2026-09-01T00:00:00Z","type":event,kind:payload});
        req["params"]["capabilities"] =
            agent_hooks_protocol::interop::capabilities_for(&event).unwrap();
        let actual = apply(
            &req,
            &response(json!([{"type":"deny","reason":"policy"}])),
            &schemas,
        )
        .unwrap();
        assert_eq!(actual["decision"], "deny");
        assert_eq!(actual["executed"], false);
        assert!(apply(&req, &response(json!([{"type":"allow"}])), &schemas).is_err());
        req["params"]["event"].as_object_mut().unwrap().remove(kind);
        assert!(schemas.validate("intercept-request", &req).is_err());
    }
}

#[test]
fn prior_stop_injections_and_instructions_survive_later_serial_responses() {
    let schemas = schemas();
    let mut req = request();
    let injection = json!({"type":"inject","target":"context","operation":"append","deliverAt":"next_turn","value":"accepted earlier"});
    req["params"]["state"] = json!({"permission":"allow","candidate":{"value":"old candidate","provenance":{"source":"earlier"}},"flow":"stop","instructions":["old instruction"],"injections":[injection]});
    let original = req.clone();
    for effects in [
        json!([]),
        json!([{"type":"allow"},{"type":"return","value":"new candidate"}]),
    ] {
        let actual = apply(&req, &response(effects), &schemas).unwrap();
        assert_eq!(actual["flow"], "stop");
        assert_eq!(actual["executed"], false);
        assert!(actual.get("result").is_none());
        assert_eq!(
            actual["continuationInstructions"],
            json!(["old instruction"])
        );
        assert_eq!(actual["injections"], json!([injection]));
        assert_eq!(req, original);
    }
    let next_injection = json!({"type":"inject","target":"context","operation":"append","deliverAt":"next_turn","value":"accepted later"});
    let actual = apply(&req, &response(json!([next_injection])), &schemas).unwrap();
    assert_eq!(actual["injections"], json!([injection, next_injection]));
    assert_eq!(actual["flow"], "stop");
    assert_eq!(actual["executed"], false);
    let invalid = response(
        json!([{"type":"message","text":"not published"},{"type":"modify","target":"input","operation":"replace","value":{"task":0}}]),
    );
    assert!(apply(&req, &invalid, &schemas).is_err());
    assert_eq!(req, original);
}
#[test]
fn prior_continuation_consumes_no_second_allowance_and_stop_is_sticky() {
    let schemas = schemas();
    let mut req = request();
    req["params"]["event"] = json!({"id":"test","source":"urn:rust:test","type":"turn.finish.before","time":"2026-09-01T00:00:00Z","turn":{"id":"turn"},"outcome":"completed","items":[],"continuationCount":0});
    req["params"]["capabilities"] =
        agent_hooks_protocol::interop::capabilities_for("turn.finish.before").unwrap();
    let first = apply(
        &req,
        &response(json!([{"type":"flow","operation":"continue","instruction":"first"}])),
        &schemas,
    )
    .unwrap();
    req["params"]["state"] = json!({"permission":"allow","candidate":null,"flow":first["flow"],"instructions":first["continuationInstructions"],"injections":[]});
    req["params"]["capabilities"]["flow"]["remainingContinuations"] =
        first["continuationRemaining"].clone();
    let empty = apply(&req, &response(json!([])), &schemas).unwrap();
    assert_eq!(empty["continuationRemaining"], 1);
    assert_eq!(empty["continuationInstructions"], json!(["first"]));
    let continued = apply(
        &req,
        &response(json!([{"type":"flow","operation":"continue","instruction":"second"}])),
        &schemas,
    )
    .unwrap();
    assert_eq!(continued["continuationRemaining"], 1);
    assert_eq!(
        continued["continuationInstructions"],
        json!(["first", "second"])
    );
    req["params"]["capabilities"]["flow"]["remainingContinuations"] = json!(0);
    let exhausted = apply(&req, &response(json!([])), &schemas).unwrap();
    assert_eq!(exhausted["continuationRemaining"], 0);
    assert_eq!(exhausted["flow"], "continue");
    req["params"]["capabilities"]["flow"]["remainingContinuations"] = json!(1);
    req["params"]["state"]["flow"] = json!("stop");
    let stopped = apply(
        &req,
        &response(json!([{"type":"flow","operation":"continue","instruction":"cannot undo stop"}])),
        &schemas,
    )
    .unwrap();
    assert_eq!(stopped["flow"], "stop");
    assert_eq!(stopped["continuationRemaining"], 1);
    assert_eq!(stopped["executed"], false);
}
#[test]
fn prior_native_refusal_or_pending_permission_never_delivers_a_candidate() {
    let schemas = schemas();
    for permission in ["deny", "ask"] {
        let mut req = request();
        req["params"]["state"] = json!({"permission":permission,"candidate":null});
        let actual = apply(
            &req,
            &response(json!([{"type":"return","value":"sensitive result"},{"type":"allow"}])),
            &schemas,
        )
        .unwrap();
        assert_eq!(actual["decision"], permission);
        assert_eq!(actual["executed"], false);
        assert!(actual.get("result").is_none());
    }
}

#[test]
fn future_capability_and_state_fields_are_ignored_but_known_fields_validate() {
    let schemas = schemas();
    let mut req = request();
    req["params"]["capabilities"]["futureCapability"] = json!({"enabled":true});
    req["params"]["state"] =
        json!({"permission":"none","candidate":null,"futureState":{"value":1}});
    assert!(apply(&req, &response(json!([])), &schemas).is_ok());
    req["params"]["state"]["permission"] = json!(123);
    assert!(apply(&req, &response(json!([])), &schemas).is_err());
    req["params"]["state"]["permission"] = json!("none");
    req["params"]["capabilities"]["effects"] = json!("modify");
    assert!(apply(&req, &response(json!([])), &schemas).is_err());
}

#[test]
fn unsupported_operations_discard_the_entire_compound_response() {
    let schemas = schemas();
    let mut req = request();
    req["params"]["capabilities"]["flow"]["operations"] = json!(["stop", "future"]);
    let before = req.clone();
    for operation in [
        json!({"type":"modify","target":"input","operation":"future","value":{"task":2}}),
        json!({"type":"inject","target":"context","operation":"future","deliverAt":"now","value":"context"}),
        json!({"type":"flow","operation":"future"}),
    ] {
        let effects = json!([{"type":"message","text":"must not publish"},{"type":"return","value":"must not publish"},operation]);
        assert!(apply(&req, &response(effects), &schemas).is_err());
        assert_eq!(req, before);
    }
}

#[test]
fn unknown_effect_fields_reject_the_compound_response() {
    let schemas = schemas();
    let req = request();
    let original = req.clone();
    for invalid in [
        json!({"type":"deny","reason":"policy","future":true}),
        json!({"type":"message","text":"hello","future":true}),
        json!({"type":"flow","operation":"stop","reason":"done","future":true}),
    ] {
        assert!(apply(&req, &response(json!([{"type":"modify","target":"input","operation":"merge","value":{"task":2}},invalid])), &schemas).is_err());
        assert_eq!(req, original);
    }
}

#[test]
fn continuation_without_instruction_does_not_invent_one() {
    let schemas = schemas();
    let mut req = request();
    req["params"]["event"] = json!({"id":"test","source":"urn:rust:test","type":"turn.finish.before","time":"2026-09-01T00:00:00Z","turn":{"id":"turn"},"outcome":"completed","items":[],"continuationCount":0});
    req["params"]["capabilities"] =
        agent_hooks_protocol::interop::capabilities_for("turn.finish.before").unwrap();
    let actual = apply(
        &req,
        &response(json!([{"type":"flow","operation":"continue"}])),
        &schemas,
    )
    .unwrap();
    assert_eq!(actual["continuationInstructions"], json!([]));
    assert_eq!(actual["continuationRemaining"], 1);
}
