use super::*;

pub(super) fn run(
    scenario: &Value,
    transport: &mut Transport,
    validation: &Validation,
) -> Result<Value> {
    let original = &scenario["requests"]["a"];
    let id = s(original, "id");
    let mut event = original["params"]["event"].clone();
    let mut called = Vec::new();
    let mut failures = Vec::new();
    let mut remaining = Vec::new();
    let mut halted = false;
    let mut pending = None;
    for subscription in scenario["chain"]["subscriptions"]
        .as_array()
        .ok_or("missing subscriptions")?
    {
        if subscription["mode"] == "observe" || halted {
            remaining.push(subscription);
            continue;
        }
        let mut request = original.clone();
        request["params"]["event"] = event.clone();
        if subscription["content"] == "omit" {
            request["params"]["event"]["items"] = json!([]);
        }
        validation.core.validate("intercept-request", &request)?;
        called.push(subscription["id"].clone());
        let reply = transport.send(&request)?;
        transport.control("/wait", &json!({"id":id,"count":called.len()}))?;
        if scenario["chain"]["interrupt"] == true {
            transport.control(
                "/mark",
                &json!({"scenario":scenario["id"],"kind":"cancelled","id":id}),
            )?;
            pending = Some(reply);
            halted = true;
            continue;
        }
        transport.control("/release", &json!({"id":id}))?;
        let response = transport.receive(id, reply);
        let evaluated =
            response.and_then(|response| evaluator::apply(&request, &response, &validation.core));
        match evaluated {
            Ok(state) => {
                event["tool"]["input"] = state["input"].clone();
                halted = state["decision"] == "deny" || state["flow"] == "stop";
            }
            Err(_) => {
                failures.push(subscription["id"].clone());
                halted = subscription["failurePolicy"] == "fail-closed";
            }
        }
    }
    transport.control(
        "/mark",
        &json!({"scenario":scenario["id"],"kind":"chain-settled","id":id}),
    )?;
    let mut deliveries = Vec::new();
    for subscription in &remaining {
        let mut projected = event.clone();
        if subscription["content"] == "omit" {
            projected["items"] = json!([]);
        } else if let Some(items) = projected["items"].as_array_mut() {
            for item in items {
                let item = item.as_object_mut().ok_or("invalid item")?;
                item.remove("body");
                item.remove("gap");
                item.insert("selection".into(), json!("metadata"));
            }
        }
        let note = json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":projected}});
        validation.observe(&note)?;
        if transport.stdin.is_some() {
            transport.observe(&note)?;
        } else {
            let (client, token, endpoint) = (
                transport.event_http.clone(),
                transport.token.clone(),
                transport.endpoint.clone(),
            );
            deliveries.push(thread::spawn(move || -> std::result::Result<(), String> {
                client
                    .post(format!("{endpoint}/observe"))
                    .bearer_auth(token)
                    .json(&note)
                    .send()
                    .and_then(|r| r.error_for_status())
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            }));
        }
    }
    // Only test-controller draining follows settlement. No join gates interruption.
    if let Some(reply) = pending {
        transport.control("/release", &json!({"id":id}))?;
        let _ = transport.receive(id, reply)?;
    }
    if !remaining.is_empty() {
        transport.control(
            "/wait-observed",
            &json!({"eventId":id,"count":remaining.len()}),
        )?;
    }
    if scenario["chain"]["holdObservers"] == true {
        transport.control("/release", &json!({"id":format!("{id}:observers")}))?;
    }
    for delivery in deliveries {
        delivery
            .join()
            .map_err(|_| "observer worker panicked")?
            .map_err(|e| format!("observation test drain: {e}"))?;
    }
    Ok(
        json!({"called":called,"failures":failures,"observations":remaining.iter().map(|s|s["id"].clone()).collect::<Vec<_>>(),"input":event["tool"]["input"]}),
    )
}
