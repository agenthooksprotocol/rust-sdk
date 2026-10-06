//! Complete-event SDK catalogue delivery over real fixture transports.
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
    let events: Vec<_> = kinds
        .into_iter()
        .map(|kind| {
            if kind == "tool.before" {
                json!({
                    "event": kind,
                    "modes": ["observe", "intercept"],
                    "capabilities": interop::capabilities()
                })
            } else {
                json!({
                    "event": kind,
                    "modes": ["observe"]
                })
            }
        })
        .collect();
    json!({
        "events": events,
        "gaps": [{
            "path": "events.other",
            "reason": "Synthetic occurrence source does not implement other boundaries"
        }],
        "transports": ["http", "stdio"],
        // Portable endpoint bindings only (AHP-AUTH-001). The fixture's
        // workload/mtls launch modes configure deployment HTTP/TLS identity;
        // they are not portable registration or discovery authentication types.
        "authentication": ["bearer", "oauth"],
        "toolPaths": ["native"],
        "contentCategories": ["text", "message", "tool_result"],
        "limits": {
            "maxUploadBytes": 1048576,
            "maxTimeoutMs": 15000
        },
        "managedPolicy": {
            "scopes": ["user", "project"],
            "disableable": true
        },
        "correlationIdentityFields": ["id", "source", "parentEventId", "call.id", "task.id"]
    })
}
// Only observation framing lives in this adapter. Canonical event settlement and
// deferred notification creation are owned by Client::event, not the fixture.
struct CatalogueObserver(EventWire);
impl agenthooksprotocol::client::Hook for CatalogueObserver {
    fn call(
        &self,
        notification: Value,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        std::result::Result<Value, agenthooksprotocol::client::HookError>,
    > {
        Box::pin(async move {
            let sent = (|| -> Result<()> {
                if notification["method"] != "hooks/observe" || notification.get("id").is_some() {
                    return Err("catalogue observer requires a one-way notification".into());
                }
                if let Some(stdin) = &self.0.stdin {
                    let mut stdin = stdin.lock().unwrap();
                    writeln!(stdin, "{notification}")?;
                    stdin.flush()?;
                } else {
                    self.0
                        .event_http
                        .post(format!("{}/observe", self.0.endpoint))
                        .bearer_auth(&self.0.token)
                        .json(&notification)
                        .send()?
                        .error_for_status()?;
                }
                Ok(())
            })();
            sent.map_err(|e| agenthooksprotocol::client::HookError(e.to_string()))?;
            // A notification cannot supply effects to the settled occurrence.
            Ok(Value::Null)
        })
    }
}

fn event_client(
    hook: impl agenthooksprotocol::client::Hook + 'static,
) -> agenthooksprotocol::client::Client {
    use agenthooksprotocol::client::{Client, Subscription, ToolContext};
    let mut subscription = Subscription::observe("catalogue", hook);
    subscription.events = vec!["*".into()];
    Client::new(ToolContext::new(json!({}))).with_subscription(subscription)
}

async fn deliver_event(client: &agenthooksprotocol::client::Client, event: Value) -> Result<Value> {
    use agenthooksprotocol::content::{AuthorizedScope, ContentContext, MemoryContentStore};
    // Catalogue fixtures authorize metadata/omit views, not body access. Even a
    // metadata-only compaction occurrence needs an explicit verification context.
    // This empty, zero-capacity store cannot resolve or publish any body; its
    // trusted scope is never derived from event identity or descriptor fields.
    let store = MemoryContentStore::new(0, 0, 0);
    let content = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("catalogue-metadata-only"),
    };
    let result = client.event(event).content(content).await?;
    // A fresh complete-event decode is part of the actual public boundary path.
    let _decoded: Value = result.event?;
    if !result.outcome.failures.is_empty() || result.observations.len() != 1 {
        return Err("catalogue event did not settle into one observation".into());
    }
    let observation = result.observations.into_iter().next().unwrap();
    let message = observation.notification.clone();
    observation.deliver().await?;
    Ok(message)
}

fn allow_raw_notification(scenario: &Value, step: &Value) -> bool {
    let message = &step["message"];
    step["op"] == "rawNotify"
        && message["method"] == "hooks/observe"
        && matches!(
            (
                s(scenario, "id"),
                s(&message["params"]["event"], "id"),
                s(&message["params"]["event"], "type")
            ),
            ("wrong-known-task-parent", "wrong:task", "task.change.after")
                | ("source-local-cycle", "cycle:self", "task.change.before")
                | ("no-op-actual-task", "noop:actual", "task.change.after")
                | (
                    "typed-model-error-required",
                    "invalid:model-error",
                    "model.error"
                )
                | ("typed-execution-enum", "invalid:execution", "tool.after")
        )
}

pub(super) fn client(c: &Value) -> Result<()> {
    let validation = Validation::new(c)?;
    let fixtures = read(s(c, "scenarioFile"))?;
    let mut transport = Transport::new(c)?;
    let request = json!({
        "jsonrpc": "2.0",
        "id": "rust-catalogue-discovery",
        "method": "hooks/capabilities",
        "params": {
            "protocolVersion": "draft"
        }
    });
    validation.core.validate("capabilities-request", &request)?;
    let discovery = if let Some(stdin) = &transport.stdin {
        let mut stdin = stdin.lock().unwrap();
        let rx = transport.router.register(s(&request, "id"))?;
        writeln!(stdin, "{request}")?;
        stdin.flush()?;
        drop(stdin);
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
    let sdk = event_client(CatalogueObserver(transport.event_wire()));
    let mut lineage = agenthooksprotocol::lineage::TaskLineage::default();
    let mut counts = BTreeMap::<String, u64>::new();
    let mut results = Vec::new();
    for scenario in fixtures["scenarios"]
        .as_array()
        .ok_or("missing scenarios")?
    {
        let mut sent = Vec::new();
        let mut registrations = Vec::new();
        for step in scenario["steps"].as_array().ok_or("missing steps")? {
            match s(step, "op") {
                "notify" | "rawNotify" => {
                    let fixture_message = &step["message"];
                    let message = if step["op"] == "notify" {
                        lineage.accept(&fixture_message["params"]["event"])?;
                        futures::executor::block_on(deliver_event(
                            &sdk,
                            fixture_message["params"]["event"].clone(),
                        ))?
                    } else {
                        // These exact negative receiver probes intentionally bypass
                        // client validation; they still hit the real SDK server.
                        if !allow_raw_notification(scenario, step) {
                            return Err("unsupported catalogue rawNotify operation".into());
                        }
                        if let Some(stdin) = &transport.stdin {
                            let mut stdin = stdin.lock().unwrap();
                            writeln!(stdin, "{fixture_message}")?;
                            stdin.flush()?;
                        } else {
                            let status = transport
                                .event_http
                                .post(format!("{}/observe", transport.endpoint))
                                .bearer_auth(&transport.token)
                                .json(fixture_message)
                                .send()?
                                .status()
                                .as_u16();
                            if ![200, 204, 400, 409].contains(&status) {
                                return Err(
                                    format!("raw observation HTTP failure: {status}").into()
                                );
                            }
                        }
                        fixture_message.clone()
                    };
                    let id = s(&message["params"]["event"], "id");
                    let count = counts.entry(id.into()).or_default();
                    *count += 1;
                    transport.control("/wait-observed", &json!({"eventId": id, "count": count}))?;
                    sent.push(message.clone());
                }
                "register" => registrations.push(json!({
                    "accepted": agenthooksprotocol::registration::validate(
                        &step["registration"],
                        &discovery["result"]["manifest"],
                        &step["requirements"],
                        &step["context"],
                        &validation.core
                    ).is_ok()
                })),
                _ => return Err("unknown catalogue operation".into()),
            }
        }
        results.push(json!({
            "id": scenario["id"],
            "status": "passed",
            "actual": {
                "sent": sent,
                "registrations": registrations
            }
        }));
    }
    let receipts: Value = transport
        .http
        .get(format!("{}/receipts", transport.control))
        .send()?
        .error_for_status()?
        .json()?;
    write(
        s(c, "reportFile"),
        &json!({
            "language": "rust",
            "results": results,
            "receipts": receipts,
            "discovery": discovery
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct RecordingObserver(Arc<Mutex<Vec<Value>>>);
    impl agenthooksprotocol::client::Hook for RecordingObserver {
        fn call(
            &self,
            message: Value,
        ) -> agenthooksprotocol::client::LocalFuture<
            '_,
            std::result::Result<Value, agenthooksprotocol::client::HookError>,
        > {
            Box::pin(async move {
                self.0.lock().unwrap().push(message);
                // Even a malicious observer return must never reopen settlement.
                Ok(json!({"effects":[{"type":"deny","reason":"ignored observer result"}]}))
            })
        }
    }
    fn progress_event() -> Value {
        json!({"id":"progress","source":"urn:catalogue-test","time":"2026-09-01T00:00:00Z",
            "type":"turn.progress","turn":{"id":"turn"},"item":{"id":"item"},"final":false,
            "delta":{"id":"item","kind":"message","mediaType":"text/plain","selection":"metadata","role":"assistant"}})
    }
    #[test]
    fn complete_event_boundary_is_lazy_and_observation_is_deferred() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let client = event_client(RecordingObserver(messages.clone()));
        let event = progress_event();
        let boundary = client.event(event.clone());
        assert!(messages.lock().unwrap().is_empty());
        let settled = futures::executor::block_on(async { boundary.await }).unwrap();
        assert!(
            messages.lock().unwrap().is_empty(),
            "settlement must not perform observer I/O"
        );
        assert_eq!(settled.event.unwrap(), event);
        assert_eq!(settled.observations.len(), 1);
        let observation = settled.observations.into_iter().next().unwrap();
        futures::executor::block_on(observation.deliver()).unwrap();
        assert_eq!(
            *messages.lock().unwrap(),
            vec![
                json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":event}})
            ]
        );
        assert_eq!(
            settled.outcome.decision,
            agenthooksprotocol::client::Decision::None
        );
    }
    #[test]
    fn invalid_complete_event_never_reaches_transport_and_next_event_recovers() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let client = event_client(RecordingObserver(messages.clone()));
        let mut invalid = progress_event();
        invalid["delta"].as_object_mut().unwrap().remove("role");
        assert!(futures::executor::block_on(deliver_event(&client, invalid)).is_err());
        assert!(messages.lock().unwrap().is_empty());
        let message =
            futures::executor::block_on(deliver_event(&client, progress_event())).unwrap();
        assert_eq!(*messages.lock().unwrap(), vec![message]);
    }
    #[test]
    fn metadata_only_compaction_uses_explicit_content_context() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let client = event_client(RecordingObserver(messages.clone()));
        let before = json!({"id":"compact-before","source":"urn:catalogue-test","time":"2026-09-15T12:00:00Z","type":"context.compact.before","trigger":"auto","items":[]});
        let after = json!({"id":"compact-after","source":"urn:catalogue-test","time":"2026-09-15T12:00:00Z","type":"context.compact.after","summary":{"id":"summary","kind":"message","mediaType":"text/plain","selection":"metadata","role":"system"},"removed":[],"execution":{"status":"executed"}});
        for event in [before, after] {
            let emitted =
                futures::executor::block_on(deliver_event(&client, event.clone())).unwrap();
            assert_eq!(emitted["params"]["event"], event);
        }
        assert_eq!(messages.lock().unwrap().len(), 2);
    }
    #[test]
    fn catalogue_content_context_does_not_grant_body_access() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let client = event_client(RecordingObserver(messages.clone()));
        let event = json!({"id":"compact-body","source":"urn:catalogue-test","time":"2026-09-15T12:00:00Z","type":"context.compact.after","summary":{"id":"summary","kind":"message","mediaType":"text/plain","selection":"body","role":"system","body":{"ref":"not-authorized","size":0,"sha256":sha256(b"")}},"removed":[],"execution":{"status":"executed"}});
        assert!(futures::executor::block_on(deliver_event(&client, event)).is_err());
        assert!(messages.lock().unwrap().is_empty());
    }
    #[test]
    fn manifest_advertises_portable_authentication_not_deployment_modes() {
        let manifest = manifest();
        // Keep this explicit: an older bundled schema may still accept the
        // superseded workload/mtls variants while the canonical runner does not.
        assert_eq!(manifest["authentication"], json!(["bearer", "oauth"]));
        let response = json!({"jsonrpc":"2.0","id":"discovery","result":{"protocolVersion":"draft","manifest":manifest}});
        Schemas::bundled()
            .unwrap()
            .validate("capabilities-response", &response)
            .unwrap();
    }
    #[test]
    fn raw_notification_bypass_is_exact_not_caller_controlled() {
        let scenario = json!({"id":"typed-model-error-required"});
        let mut step = json!({"op":"rawNotify","message":{"method":"hooks/observe","params":{"event":{"id":"invalid:model-error","type":"model.error"}}}});
        assert!(allow_raw_notification(&scenario, &step));
        assert!(!allow_raw_notification(&json!({"id":"ordinary"}), &step));
        step["message"]["params"]["event"]["id"] = json!("another-occurrence");
        assert!(!allow_raw_notification(&scenario, &step));
        step["message"]["params"]["event"]["id"] = json!("invalid:model-error");
        step["op"] = json!("notify");
        assert!(!allow_raw_notification(&scenario, &step));
    }
    fn registration() -> Value {
        json!({
            "protocolVersion": "draft",
            "hooks": [{
                "id": "org.example.policy",
                "transport": {
                    "type": "http",
                    "url": "https://policy.invalid/hooks"
                },
                "subscriptions": [{
                    "events": ["tool.before"],
                    "mode": "intercept",
                    "timeoutMs": 500,
                    "failurePolicy": "fail-closed",
                    "content": {
                        "default": "metadata"
                    }
                }]
            }]
        })
    }
    #[test]
    fn registration_requires_effective_host_support_and_credentials() {
        let schemas = Schemas::bundled().unwrap();
        let host = manifest();
        let context = json!({
            "interactive": true,
            "environment": {
                "TOKEN": "local-test-only"
            }
        });
        let check = |r: &Value, q: &Value, c: &Value| {
            agenthooksprotocol::registration::validate(r, &host, q, c, &schemas).is_ok()
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
        let requirement = json!([{
            "event": "tool.before",
            "mode": "intercept",
            "effects": ["ask"]
        }]);
        assert!(check(&registration, &requirement, &context));
        assert!(!check(
            &registration,
            &requirement,
            &json!({"interactive":false,"environment":{"TOKEN":"present"}})
        ));
        let requirement = json!([{
            "event": "tool.before",
            "mode": "intercept",
            "effects": ["modify"],
            "modify": {
                "input": {
                    "merge": true
                }
            }
        }]);
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
            agenthooksprotocol::registration::validate(
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
        r["hooks"][0]["subscriptions"][0] = json!({
            "events": ["tool.after"],
            "mode": "observe",
            "content": {
                "default": "metadata"
            }
        });
        assert!(check(&r));
        r["hooks"][0]["subscriptions"][0]["timeoutMs"] = json!(500);
        assert!(!check(&r));
    }
    #[test]
    fn wildcard_registration_expands_against_real_host_coverage() {
        let schemas = Schemas::bundled().unwrap();
        let context = json!({"interactive":true,"environment":{}});
        let mut registration = registration();
        registration["hooks"][0]["subscriptions"][0] = json!({
            "events": ["model.*"],
            "mode": "observe",
            "content": {
                "default": "metadata"
            }
        });
        assert!(
            agenthooksprotocol::registration::validate(
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
            agenthooksprotocol::registration::validate(
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
        let mut notification = json!({
            "jsonrpc": "2.0",
            "method": "hooks/observe",
            "params": {
                "protocolVersion": "draft",
                "event": {
                    "id": "progress",
                    "source": "urn:catalogue-test",
                    "time": "2026-09-01T00:00:00Z",
                    "type": "turn.progress",
                    "turn": {
                        "id": "turn"
                    },
                    "item": {
                        "id": "item"
                    },
                    "final": false,
                    "delta": {
                        "id": "item",
                        "kind": "message",
                        "mediaType": "text/plain",
                        "selection": "metadata",
                        "role": "assistant"
                    }
                }
            }
        });
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
        let request = json!({
            "jsonrpc": "2.0",
            "id": "discovery",
            "method": "hooks/capabilities",
            "params": {
                "protocolVersion": "draft"
            }
        });
        let response = receiver.protocol(&request).unwrap();
        receiver
            .validation
            .core
            .validate("capabilities-response", &response)
            .unwrap();
        let notification = |id: &str, parent: &str| {
            json!({
                "jsonrpc": "2.0",
                "method": "hooks/observe",
                "params": {
                    "protocolVersion": "draft",
                    "event": {
                        "id": id,
                        "source": "urn:catalogue-test",
                        "time": "2026-09-01T00:00:00Z",
                        "type": "task.change.after",
                        "parentEventId": parent,
                        "task": {
                            "id": "task",
                            "operation": "update",
                            "prior": {
                                "status": "open"
                            },
                            "change": {
                                "status": "closed"
                            }
                        }
                    }
                }
            })
        };
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
            json!({
                "kind": "rejected",
                "eventId": "missing",
                "message": bad,
                "errorKind": "lineage"
            })
        );
        assert_eq!(
            entries[3],
            json!({
                "kind": "rejected",
                "eventId": "invalid",
                "message": invalid,
                "errorKind": "schema"
            })
        );
        assert_eq!(entries[4]["message"], healthy);
    }
}
