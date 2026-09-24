//! Catalogue delivery uses real transports and the local schema/lineage/registration engines.
use super::*;
pub(super) fn manifest() -> Value {
    let kinds = [
        "tool.before",
        "tool.after",
        "turn.start",
        "turn.finish.before",
        "turn.end",
        "turn.progress",
        "model.request.before",
        "model.response.after",
        "model.error",
        "model.switch.before",
        "model.switch.after",
        "tool.permission.request",
        "tool.permission.resolved",
        "tool.progress",
        "tool.batch.after",
        "context.compact.before",
        "context.compact.after",
        "task.change.before",
        "task.change.after",
        "workspace.change.before",
        "workspace.change.after",
        "file.changed",
    ];
    let events:Vec<_>=kinds.into_iter().map(|kind|if kind=="tool.before" {json!({"event":kind,"modes":["observe","intercept"],"capabilities":interop::capabilities()})} else {json!({"event":kind,"modes":["observe"]})}).collect();
    json!({"events":events,"gaps":[{"path":"events.other","reason":"Synthetic occurrence source does not implement other boundaries"}],"transports":["http","stdio"],"authentication":["bearer","oauth","workload","mtls"],"toolPaths":["native"],"contentCategories":["text","message","tool_result"],"limits":{"maxUploadBytes":1048576,"maxTimeoutMs":15000},"managedPolicy":{"scopes":["user","project"],"disableable":true},"correlationIdentityFields":["id","source","parentEventId","call.id","task.id"]})
}
pub(super) fn client(c: &Value) -> Result<()> {
    let validation = Validation::new(c)?;
    let fixtures = read(s(c, "scenarioFile"))?;
    let mut transport = Transport::new(c)?;
    let request = json!({"jsonrpc":"2.0","id":"rust-catalogue-discovery","method":"hooks/capabilities","params":{"protocolVersion":"draft"}});
    validation.core.validate("capabilities-request", &request)?;
    let discovery = if let Some(stdin) = &mut transport.stdin {
        let rx = transport.router.register(s(&request, "id"))?;
        writeln!(stdin, "{request}")?;
        stdin.flush()?;
        transport.receive(s(&request, "id"), rx)?
    } else {
        transport
            .event_http
            .post(format!("{}/capabilities", transport.endpoint))
            .bearer_auth(&transport.token)
            .json(&request)
            .send()?
            .error_for_status()?
            .json()?
    };
    validation
        .core
        .validate("capabilities-response", &discovery)?;
    if discovery["id"] != request["id"] {
        return Err("discovery correlation mismatch".into());
    }
    let mut lineage = agent_hooks_protocol::lineage::TaskLineage::default();
    let mut counts = BTreeMap::<String, u64>::new();
    let mut results = Vec::new();
    for scenario in fixtures["scenarios"]
        .as_array()
        .ok_or("missing scenarios")?
    {
        let mut sent = Vec::new();
        let mut registrations = Vec::new();
        for step in scenario["steps"].as_array().ok_or("missing steps")? {
            match s(step,"op") {
                "notify"|"rawNotify"=>{
                    let message=&step["message"];let raw=step["op"]=="rawNotify";
                    if !raw {validation.observe(message)?;lineage.accept(&message["params"]["event"])?;}
                    if let Some(stdin)=&mut transport.stdin {writeln!(stdin,"{message}")?;stdin.flush()?;}else{
                        let status=transport.event_http.post(format!("{}/observe",transport.endpoint)).bearer_auth(&transport.token).json(message).send()?.status().as_u16();
                        if status!=200 && !(raw && [400,409].contains(&status)){return Err(format!("observation HTTP failure: {status}").into());}
                    }
                    let id=s(&message["params"]["event"],"id");let count=counts.entry(id.into()).or_default();*count+=1;
                    transport.control("/wait-observed",&json!({"eventId":id,"count":count}))?;
                    sent.push(message.clone());
                }
                "register"=>registrations.push(json!({"accepted":agent_hooks_protocol::registration::validate(&step["registration"],&discovery["result"]["manifest"],&step["requirements"],&step["context"],&validation.core).is_ok()})),
                _=>return Err("unknown catalogue operation".into()),
            }
        }
        results.push(json!({"id":scenario["id"],"status":"passed","actual":{"sent":sent,"registrations":registrations}}));
    }
    let receipts: Value = transport
        .http
        .get(format!("{}/receipts", transport.control))
        .send()?
        .error_for_status()?
        .json()?;
    write(
        s(c, "reportFile"),
        &json!({"language":"rust","results":results,"receipts":receipts,"discovery":discovery}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn registration() -> Value {
        json!({"protocolVersion":"draft","hooks":[{"id":"org.example.policy","transport":{"type":"http","url":"https://policy.invalid/hooks"},"subscriptions":[{"events":["tool.before"],"mode":"intercept","timeoutMs":500,"failurePolicy":"fail-closed","content":{"default":"metadata"}}]}]})
    }
    #[test]
    fn registration_requires_effective_host_support_and_credentials() {
        let schemas = Schemas::bundled().unwrap();
        let host = manifest();
        let context = json!({"interactive":true,"environment":{"TOKEN":"local-test-only"}});
        let check = |r: &Value, q: &Value, c: &Value| {
            agent_hooks_protocol::registration::validate(r, &host, q, c, &schemas).is_ok()
        };
        let mut registration = registration();
        assert!(check(&registration, &json!([]), &context));
        registration["hooks"][0]["authentication"] = json!({"type":"bearer","tokenEnv":"TOKEN"});
        assert!(check(&registration, &json!([]), &context));
        assert!(!check(
            &registration,
            &json!([]),
            &json!({"interactive":true,"environment":{}})
        ));
        let requirement = json!([{"event":"tool.before","mode":"intercept","effects":["ask"]}]);
        assert!(check(&registration, &requirement, &context));
        assert!(!check(
            &registration,
            &requirement,
            &json!({"interactive":false,"environment":{"TOKEN":"present"}})
        ));
        let requirement = json!([{"event":"tool.before","mode":"intercept","effects":["modify"],"modify":{"input":{"merge":true}}}]);
        assert!(check(&registration, &requirement, &context));
        let mut unsupported = requirement;
        unsupported[0]["modify"] = json!({"destination":{"replace":true}});
        assert!(!check(&registration, &unsupported, &context));
        let duplicate = registration["hooks"][0].clone();
        registration["hooks"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(!check(&registration, &json!([]), &context));
    }
    #[test]
    fn canonical_registration_and_managed_policy_fail_closed() {
        let schemas = Schemas::bundled().unwrap();
        let context = json!({"interactive":true,"environment":{}});
        let check = |r: &Value| {
            agent_hooks_protocol::registration::validate(
                r,
                &manifest(),
                &json!([]),
                &context,
                &schemas,
            )
            .is_ok()
        };
        for field in ["content", "failurePolicy"] {
            let mut r = registration();
            r["hooks"][0]["subscriptions"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(!check(&r));
        }
        let mut r = registration();
        r["hooks"][0]["subscriptions"][0]["scope"] = json!("managed");
        r["hooks"][0]["subscriptions"][0]["disableable"] = json!(false);
        assert!(!check(&r));
        for event in ["model.error", "hook.failure"] {
            let mut r = registration();
            r["hooks"][0]["subscriptions"][0]["events"] = json!([event]);
            assert!(!check(&r));
        }
        let mut r = registration();
        r["hooks"][0]["subscriptions"][0] =
            json!({"events":["tool.after"],"mode":"observe","content":{"default":"metadata"}});
        assert!(check(&r));
        r["hooks"][0]["subscriptions"][0]["timeoutMs"] = json!(500);
        assert!(!check(&r));
    }
    #[test]
    fn wildcard_registration_expands_against_real_host_coverage() {
        let schemas = Schemas::bundled().unwrap();
        let context = json!({"interactive":true,"environment":{}});
        let mut registration = registration();
        registration["hooks"][0]["subscriptions"][0] =
            json!({"events":["model.*"],"mode":"observe","content":{"default":"metadata"}});
        assert!(
            agent_hooks_protocol::registration::validate(
                &registration,
                &manifest(),
                &json!([]),
                &context,
                &schemas
            )
            .is_ok()
        );
        registration["hooks"][0]["subscriptions"][0]["events"] = json!(["hook.*"]);
        assert!(
            agent_hooks_protocol::registration::validate(
                &registration,
                &manifest(),
                &json!([]),
                &context,
                &schemas
            )
            .is_err()
        );
    }
    #[test]
    fn canonical_model_visible_roles_and_hashes_are_not_shape_only() {
        let validation = Validation::new(&json!({})).unwrap();
        let mut notification = json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":{"id":"progress","source":"urn:catalogue-test","time":"2026-09-01T00:00:00Z","type":"turn.progress","turn":{"id":"turn"},"item":{"id":"item"},"final":false,"delta":{"id":"item","kind":"message","mediaType":"text/plain","selection":"metadata","role":"assistant"}}}});
        validation.observe(&notification).unwrap();
        notification["params"]["event"]["delta"]
            .as_object_mut()
            .unwrap()
            .remove("role");
        assert!(validation.observe(&notification).is_err());
        notification["params"]["event"]["delta"]["role"] = json!("assistant");
        notification["params"]["event"]["delta"]["selection"] = json!("body");
        notification["params"]["event"]["delta"]["body"] =
            json!({"ref":"ref","size":0,"sha256":sha256(b"")});
        validation.observe(&notification).unwrap();
        for hash in ["0".repeat(63), "A".repeat(64), "0".repeat(65)] {
            notification["params"]["event"]["delta"]["body"]["sha256"] = json!(hash);
            assert!(validation.observe(&notification).is_err());
        }
    }
    #[test]
    fn receiver_records_exact_rejections_and_recovers_atomically() {
        let receiver = ServerState {
            data: Mutex::new(Shared::default()),
            changed: Condvar::new(),
            validation: Validation::new(&json!({})).unwrap(),
            responses: BTreeMap::new(),
            sequences: BTreeMap::new(),
            stdio: false,
            stdout_order: Mutex::new(()),
            upload: json!({}),
            auth: json!({"auth":{"mode":"none"}}),
            catalogue: true,
        };
        let request = json!({"jsonrpc":"2.0","id":"discovery","method":"hooks/capabilities","params":{"protocolVersion":"draft"}});
        let response = receiver.protocol(&request).unwrap();
        receiver
            .validation
            .core
            .validate("capabilities-response", &response)
            .unwrap();
        let notification = |id: &str, parent: &str| json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":{"id":id,"source":"urn:catalogue-test","time":"2026-09-01T00:00:00Z","type":"task.change.after","parentEventId":parent,"task":{"id":"task","operation":"update","prior":{"status":"open"},"change":{"status":"closed"}}}}});
        let good = notification("child", "missing");
        receiver.protocol(&good).unwrap();
        let bad = notification("missing", "child");
        assert!(
            receiver
                .protocol(&bad)
                .unwrap_err()
                .to_string()
                .starts_with("lineage:")
        );
        let mut invalid = notification("invalid", "missing");
        invalid["params"]["event"]
            .as_object_mut()
            .unwrap()
            .remove("task");
        assert!(
            receiver
                .protocol(&invalid)
                .unwrap_err()
                .to_string()
                .starts_with("schema:")
        );
        let healthy = notification("missing", "filtered");
        receiver.protocol(&healthy).unwrap();
        let entries = &receiver.data.lock().unwrap().entries;
        assert_eq!(entries.len(), 5);
        assert_eq!(
            entries[2],
            json!({"kind":"rejected","eventId":"missing","message":bad,"errorKind":"lineage"})
        );
        assert_eq!(
            entries[3],
            json!({"kind":"rejected","eventId":"invalid","message":invalid,"errorKind":"schema"})
        );
        assert_eq!(entries[4]["message"], healthy);
    }
}
