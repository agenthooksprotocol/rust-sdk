//! Offline host fixture; no oracle or expected outcome is sent to this receiver.
use agenthooksprotocol::{
    client::{
        Client, Decision, FailurePolicy, Hook, HookError, LocalFuture, Mode, Subscription,
        ToolContext,
    },
    compaction::{capabilities, selected_text},
    content::{AuthorizedScope, ContentContext, MemoryContentStore},
};
use serde_json::{Value, json};
use std::io::{self, BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

pub fn fixture_content(store: &MemoryContentStore) -> ContentContext<'_> {
    ContentContext {
        store,
        scope: AuthorizedScope::new("compaction-fixture"),
    }
}
struct EffectsHook(Value);
impl Hook for EffectsHook {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            if self.0["throw"] == true {
                return Err(HookError("hook failed".into()));
            }
            let effects = self.0["effects"]
                .as_array()
                .ok_or_else(|| HookError("effects".into()))?;
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":effects}}),
            )
        })
    }
}
#[derive(Default)]
struct FixtureLog {
    seen: Vec<Value>,
    bodies: Value,
    instructions: String,
    returned: Vec<(String, Value)>,
}
struct RecordingHook {
    inner: Box<dyn Hook>,
    supplier: String,
    store: MemoryContentStore,
    log: Arc<Mutex<FixtureLog>>,
}
impl Hook for RecordingHook {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            let event = &request["params"]["event"];
            let before = event["type"] == "context.compact.before";
            let content = fixture_content(&self.store);
            {
                let mut log = self.log.lock().unwrap();
                let instructions = if before {
                    selected_text(&event["instructions"], &content)
                        .map_err(|e| HookError(e.to_string()))?
                } else {
                    log.instructions.clone()
                };
                let summary = if before {
                    Value::Null
                } else {
                    let item = &event["summary"];
                    let reference = item["body"]["ref"]
                        .as_str()
                        .ok_or_else(|| HookError("reference".into()))?;
                    log.bodies[reference] =
                        json!(selected_text(item, &content).map_err(|e| HookError(e.to_string()))?);
                    json!({"id":item["id"],"ref":reference})
                };
                let snapshot = json!({"boundary":if before {"before"} else {"after"},"instructions":instructions,"summary":summary,"bodies":log.bodies,"capabilities":request["params"].get("capabilities").cloned().unwrap_or(json!({"effects":[],"modify":{}}))});
                log.seen.push(snapshot);
            }
            let response = self.inner.call(request).await?;
            if let Some(effects) = response["result"]["effects"].as_array() {
                for effect in effects {
                    if effect["type"] == "return" {
                        self.log
                            .lock()
                            .unwrap()
                            .returned
                            .push((self.supplier.clone(), effect["value"].clone()));
                    }
                }
            }
            Ok(response)
        })
    }
}
pub fn fixture_subscription(
    row: &Value,
    boundary: &str,
    hook: Box<dyn Hook>,
    observe: bool,
) -> Result<Subscription, String> {
    let policy = match row["failurePolicy"].as_str().unwrap_or("fail-closed") {
        "fail-open" => FailurePolicy::Open,
        "fail-closed" => FailurePolicy::Closed,
        _ => return Err("policy".into()),
    };
    let id = row["supplier"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("supplier")?
        .to_owned();
    Ok(Subscription {
        id,
        events: vec![format!("context.compact.{boundary}")],
        mode: if observe {
            Mode::Observe
        } else {
            Mode::Intercept(policy)
        },
        hook,
        timeout: std::time::Duration::from_secs(30),
    })
}
fn content_item(
    content: &ContentContext<'_>,
    id: &str,
    kind: &str,
    role: &str,
    text: &str,
) -> Result<Value, String> {
    Ok(
        json!({"id":id,"kind":kind,"role":role,"mediaType":"text/plain","selection":"body","body":content.put(text.as_bytes()).map_err(|e|e.to_string())?}),
    )
}
/// Host fixture only: protocol settlement runs through Client::event. Generation,
/// permissive host policy and legacy report shaping are application responsibilities.
pub fn run_public_fixture(
    p: &Value,
    before: Vec<Subscription>,
    after: Vec<Subscription>,
    store: &MemoryContentStore,
) -> Result<Value, String> {
    let execute = || -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let instructions = p["instructions"].as_str().ok_or("instructions")?;
        let name = p["name"].as_str().unwrap_or("compaction");
        let summary_id = p["itemId"].as_str().unwrap_or("summary-1");
        let content = fixture_content(store);
        let log = Arc::new(Mutex::new(FixtureLog {
            bodies: json!({}),
            instructions: instructions.to_owned(),
            ..Default::default()
        }));
        let make_client = |subscriptions: Vec<Subscription>| {
            subscriptions.into_iter().fold(
                Client::new(ToolContext::new(json!({}))),
                |client, mut subscription| {
                    subscription.hook = Box::new(RecordingHook {
                        inner: subscription.hook,
                        supplier: subscription.id.clone(),
                        store: store.clone(),
                        log: log.clone(),
                    });
                    client.with_subscription(subscription)
                },
            )
        };
        let before_client = make_client(before);
        let before_event = json!({"id":format!("{name}:before"),"source":"urn:ahp:compaction-host","time":"2026-09-15T12:00:00Z","session":{"id":name},"type":"context.compact.before","trigger":"manual","items":[content_item(&content,&format!("{name}:context"),"user","user","conversation")?],"instructions":content_item(&content,&format!("{name}:instructions"),"instructions","system",instructions)?});
        let settled = futures::executor::block_on(async {
            before_client
                .event(before_event)
                .content(content.clone())
                .capabilities(capabilities("before", false)?)
                .initial_state(Decision::Allow)
                .await
                .map_err(|e| e.to_string())
        })?;
        let instructions = selected_text(&settled.effective_event["instructions"], &content)?;
        log.lock().unwrap().instructions = instructions.clone();
        let mut failures: Vec<Value> = settled
            .outcome
            .failures
            .iter()
            .map(|f| json!({"boundary":"before","supplier":f.subscription_id}))
            .collect();
        let mut messages: Vec<Value> = settled
            .outcome
            .messages
            .iter()
            .map(|message| message["text"].clone())
            .collect();
        let mut injections = settled.outcome.injections.clone();
        let mut denied = settled.outcome.is_denied();
        let mut generated = false;
        let mut applied = false;
        let mut summary = Value::Null;
        let mut candidate = Value::Null;
        let mut provenance = Value::Null;
        if !denied {
            // The fixture's host explicitly allows the effective input. This is
            // not evidence of model consumption or an SDK authorization default.
            let body = if let Some(value) = settled.outcome.candidate.as_ref() {
                let supplier = log
                    .lock()
                    .unwrap()
                    .returned
                    .iter()
                    .rev()
                    .find(|(id, v)| {
                        v == value
                            && !settled
                                .outcome
                                .failures
                                .iter()
                                .any(|f| &f.subscription_id == id)
                    })
                    .map(|(id, _)| id.clone())
                    .ok_or("candidate supplier")?;
                candidate = json!({"body":value,"supplier":supplier});
                provenance = json!({"kind":"supplied","supplier":supplier});
                value.as_str().ok_or("candidate text")?.to_owned()
            } else {
                generated = true;
                provenance = json!({"kind":"generated"});
                format!("summary:{instructions}")
            };
            let item = content_item(&content, summary_id, "summary", "assistant", &body)?;
            let reference = item["body"]["ref"].as_str().ok_or("reference")?;
            log.lock().unwrap().bodies[reference] = json!(body);
            let after_event = json!({"id":format!("{name}:after"),"source":settled.effective_event["source"],"time":settled.effective_event["time"],"session":settled.effective_event["session"],"parentEventId":settled.effective_event["id"],"type":"context.compact.after","summary":item,"removed":[{"id":format!("{name}:context")}],"execution":if generated {json!({"status":"executed"})} else {json!({"status":"skipped","reason":"supplied_result"})}});
            let after_client = make_client(after);
            let observe = p["observeOnly"] == true;
            let settled_after = futures::executor::block_on(async {
                after_client
                    .event(after_event)
                    .content(content.clone())
                    .capabilities(if observe {
                        // The legacy report includes an empty modify map, but a
                        // canonical request may advertise modify only when that
                        // effect is granted. Observers receive no capabilities.
                        json!({"effects":[]})
                    } else {
                        capabilities("after", false)?
                    })
                    .initial_state(Decision::Allow)
                    .await
                    .map_err(|e| e.to_string())
            })?;
            failures.extend(
                settled_after
                    .outcome
                    .failures
                    .iter()
                    .map(|f| json!({"boundary":"after","supplier":f.subscription_id})),
            );
            messages.extend(
                settled_after
                    .outcome
                    .messages
                    .iter()
                    .map(|message| message["text"].clone()),
            );
            injections.extend(settled_after.outcome.injections.clone());
            denied = settled_after.outcome.is_denied();
            applied = !denied;
            let item = &settled_after.effective_event["summary"];
            let reference = item["body"]["ref"].as_str().ok_or("reference")?;
            log.lock().unwrap().bodies[reference] = json!(selected_text(item, &content)?);
            summary = json!({"id":item["id"],"ref":reference});
            // The fixture explicitly schedules observations after settlement;
            // returned effects have no authority and delivery is best effort.
            if observe {
                for observation in settled_after.observations {
                    let _ = futures::executor::block_on(observation.deliver());
                }
            }
        }
        let log = log.lock().unwrap();
        Ok(
            json!({"instructions":instructions,"candidate":candidate,"summary":summary,"bodies":log.bodies,"messages":messages,"injections":injections,"denied":denied,"seen":log.seen,"failures":failures,"generated":generated,"applied":applied,"provenance":provenance}),
        )
    };
    execute().map_err(|e| e.to_string())
}
fn evaluate(p: &Value) -> Result<Value, String> {
    let subscriptions = |boundary: &str| -> Result<Vec<Subscription>, String> {
        p.get(boundary)
            .unwrap_or(&json!([]))
            .as_array()
            .ok_or("subscriptions")?
            .iter()
            .map(|row| {
                fixture_subscription(
                    row,
                    boundary,
                    Box::new(EffectsHook(row.clone())),
                    boundary == "after" && p["observeOnly"] == true,
                )
            })
            .collect()
    };
    run_public_fixture(
        p,
        subscriptions("before")?,
        subscriptions("after")?,
        &MemoryContentStore::new(usize::MAX, usize::MAX, usize::MAX),
    )
}
fn receive(request: Value) -> Value {
    let result = if request["jsonrpc"] != "2.0" || request["method"] != "compaction/run" {
        Err("invalid request".into())
    } else {
        evaluate(&request["params"])
    };
    match result {
        Ok(result) => json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
        Err(_) => {
            json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": {
                    "code": -32602,
                    "message": "invalid request"
                }
            })
        }
    }
}
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mode = std::env::args().nth(1).ok_or("mode")?;
    match mode.as_str() {
        "stdio" => {
            for line in io::stdin().lock().lines() {
                println!("{}", receive(serde_json::from_str(&line?)?));
            }
        }
        "server" => {
            let server = tiny_http::Server::http("127.0.0.1:0")?;
            println!(
                "{}",
                json!({"endpoint":format!("http://{}",server.server_addr())})
            );
            io::stdout().flush()?;
            let token = format!("Bearer {}", std::env::var("AHP_COMPACTION_TOKEN")?);
            for mut request in server.incoming_requests() {
                if !request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("Authorization") && h.value.as_str() == token)
                {
                    let _ = request.respond(tiny_http::Response::empty(401));
                    continue;
                }
                let mut body = String::new();
                if request
                    .as_reader()
                    .take(4 * 1024 * 1024 + 1)
                    .read_to_string(&mut body)
                    .is_err()
                {
                    let _ = request.respond(tiny_http::Response::empty(400));
                    continue;
                }
                if body.len() > 4 * 1024 * 1024 {
                    let _ = request.respond(tiny_http::Response::empty(413));
                    continue;
                }
                let Ok(value) = serde_json::from_str(&body) else {
                    let _ = request.respond(tiny_http::Response::empty(400));
                    continue;
                };
                let response = receive(value);
                let _ = request.respond(tiny_http::Response::from_string(response.to_string()));
            }
        }
        "client" => {
            let plan: Value = serde_json::from_reader(io::stdin())?;
            let requests = plan["requests"].as_array().ok_or("requests")?;
            let replies: Vec<Value> = if plan["transport"] == "stdio" {
                let cmd = plan["command"].as_array().ok_or("command")?;
                let mut child = Command::new(cmd[0].as_str().ok_or("command")?)
                    .args(cmd[1..].iter().map(|v| v.as_str().unwrap()))
                    .arg("stdio")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()?;
                let mut stdin = child.stdin.take().ok_or("stdin")?;
                let payload = requests
                    .iter()
                    .map(|r| format!("{r}\n"))
                    .collect::<String>();
                // Feed concurrently: large snapshots can fill stdout while stdin is read.
                let writer = std::thread::spawn(move || stdin.write_all(payload.as_bytes()));
                let output = child.wait_with_output()?;
                writer.join().map_err(|_| "writer panicked")??;
                if !output.status.success() {
                    return Err("receiver failed".into());
                }
                String::from_utf8(output.stdout)?
                    .lines()
                    .map(serde_json::from_str)
                    .collect::<Result<_, _>>()?
            } else {
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(20))
                    .build()?;
                let mut out = vec![];
                for request in requests {
                    let response = client
                        .post(plan["endpoint"].as_str().ok_or("endpoint")?)
                        .bearer_auth(plan["token"].as_str().ok_or("token")?)
                        .json(request)
                        .send()?
                        .error_for_status()?;
                    out.push(response.json()?);
                }
                out
            };
            println!("{}", json!(replies));
        }
        _ => return Err("unknown mode".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CanonicalObserver {
        effects: Value,
        delivered: Arc<Mutex<usize>>,
    }
    impl Hook for CanonicalObserver {
        fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
            Box::pin(async move {
                assert_eq!(request["method"], "hooks/observe");
                assert!(request.get("id").is_none());
                assert!(request["params"].get("capabilities").is_none());
                // Observation::deliver has already performed canonical validation.
                assert!(
                    agenthooksprotocol::generated::parse_observe_notification_value(
                        request.clone()
                    )
                    .is_ok()
                );
                *self.delivered.lock().unwrap() += 1;
                // Deliberately invalid notification response: never authority.
                Ok(json!({"jsonrpc":"2.0","id":"unsolicited","result":{
                    "protocolVersion":"draft","effects":self.effects
                }}))
            })
        }
    }

    #[test]
    fn observe_only_compaction_preserves_summary_and_ignores_effects() {
        let params = json!({"instructions":"base","itemId":"logical-summary","before":[],"after":[
            {"supplier":"invalid","effects":[{"type":"modify","target":"summary","operation":"replace","value":"leaked"}],"failurePolicy":"fail-closed","throw":false},
            {"supplier":"watch","effects":[],"failurePolicy":"fail-closed","throw":false}
        ],"observeOnly":true});
        let result = evaluate(&params).expect("observe-only public boundary must settle");
        let delivered = Arc::new(Mutex::new(0));
        let subscriptions = params["after"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                fixture_subscription(
                    row,
                    "after",
                    Box::new(CanonicalObserver {
                        effects: row["effects"].clone(),
                        delivered: delivered.clone(),
                    }),
                    true,
                )
                .unwrap()
            })
            .collect();
        let observed = run_public_fixture(
            &params,
            vec![],
            subscriptions,
            &MemoryContentStore::new(4096, 65536, 100),
        )
        .unwrap();
        assert_eq!(*delivered.lock().unwrap(), 2);
        assert_eq!(observed["applied"], true);
        assert_eq!(
            observed["bodies"][observed["summary"]["ref"].as_str().unwrap()],
            "summary:base"
        );
        assert_eq!(result["generated"], true);
        assert_eq!(result["applied"], true);
        assert_eq!(result["failures"], json!([]));
        assert_eq!(result["messages"], json!([]));
        let reference = result["summary"]["ref"].as_str().unwrap();
        assert_eq!(result["bodies"][reference], "summary:base");
        assert!(
            !result["bodies"]
                .as_object()
                .unwrap()
                .values()
                .any(|v| v == "leaked")
        );
        let seen = result["seen"].as_array().unwrap();
        assert_eq!(seen.len(), 2);
        for snapshot in seen {
            assert_eq!(snapshot["capabilities"], json!({"effects":[],"modify":{}}));
            assert_eq!(snapshot["summary"], result["summary"]);
        }
    }
}
