//! Offline actual HTTP wire sender/receiver; no expected-based behavior.
use agenthooksprotocol::{
    elicitation::{Exchange, stage_boundary, validate_mode},
    interop::Result,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
};
// The host owns uploaded bytes; the public content context verifies descriptors.
// Check-only explicit fixture import. Network uploads use UploadReceiver below.
struct HostStore {
    scope: agenthooksprotocol::content::AuthorizedScope,
    entries: std::sync::Mutex<BTreeMap<String, Vec<u8>>>,
}
impl agenthooksprotocol::content::ContentStore for HostStore {
    fn resolve(
        &self,
        scope: &agenthooksprotocol::content::AuthorizedScope,
        reference: &agenthooksprotocol::content::ContentReference,
    ) -> std::result::Result<std::sync::Arc<[u8]>, agenthooksprotocol::content::UploadError> {
        if scope != &self.scope {
            return Err(agenthooksprotocol::content::UploadError::Forbidden);
        }
        self.entries
            .lock()
            .unwrap()
            .get(&reference.ref_)
            .map(|b| std::sync::Arc::from(b.as_slice()))
            .ok_or(agenthooksprotocol::content::UploadError::Unavailable)
    }
    fn put(
        &self,
        scope: &agenthooksprotocol::content::AuthorizedScope,
        bytes: std::sync::Arc<[u8]>,
    ) -> std::result::Result<
        agenthooksprotocol::content::ContentReference,
        agenthooksprotocol::content::UploadError,
    > {
        if scope != &self.scope {
            return Err(agenthooksprotocol::content::UploadError::Forbidden);
        }
        let digest = sha256(&bytes);
        let name = format!("urn:ahp:staged:{digest}");
        let mut entries = self.entries.lock().unwrap();
        if bytes.len() > 4 * 1024 * 1024
            || entries.len() >= 4096
            || entries.values().map(Vec::len).sum::<usize>() + bytes.len() > 64 * 1024 * 1024
        {
            return Err(agenthooksprotocol::content::UploadError::Capacity);
        }
        entries.insert(name.clone(), bytes.to_vec());
        serde_json::from_value(json!({"ref":name}))
            .map_err(|_| agenthooksprotocol::content::UploadError::Descriptor)
    }
}
// A real public Client boundary drives ordinary fixture execution. Only the
// client wire driver below preserves deliberately malformed raw controls.
struct FixtureHook(Vec<Value>);
impl agenthooksprotocol::client::Hook for FixtureHook {
    fn call(
        &self,
        request: Value,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        std::result::Result<Value, agenthooksprotocol::client::HookError>,
    > {
        Box::pin(async move {
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":self.0}}),
            )
        })
    }
}
fn execute(
    request: &Value,
    effects: &[Value],
    content: &agenthooksprotocol::content::ContentContext<'_>,
    original: Option<&Exchange>,
) -> Result<Value> {
    use agenthooksprotocol::client::{Client, FailurePolicy, Subscription, ToolContext};
    // Validate the exact supplied envelope before Client constructs its own wire
    // envelope; this preserves negative ID/method/envelope controls.
    let mut staged = stage_boundary(request, &[], content, original)?;
    let mut subscription = Subscription::intercept(
        "fixture",
        FailurePolicy::Closed,
        FixtureHook(effects.to_vec()),
    );
    subscription.events = vec![
        request["params"]["event"]["type"]
            .as_str()
            .ok_or("event type")?
            .to_owned(),
    ];
    let client = Client::new(ToolContext::new(json!({}))).with_subscription(subscription);
    let mut boundary = client
        .event(request["params"]["event"].clone())
        .capabilities(request["params"]["capabilities"].clone())
        .content(content.clone());
    if let Some(exchange) = original {
        boundary = boundary.elicitation_exchange(exchange);
    }
    let result = futures::executor::block_on(async { boundary.await })?;
    if !result.outcome.failures.is_empty() {
        return Err("Public fixture boundary rejected effects".into());
    }
    // A result-stage modify changes the effective event body, not the runtime's
    // short-circuit candidate. Never reuse the preflight answer in its summary.
    if result.effective_event["type"] == "user.elicitation.result" {
        match result.effective_event["elicitation"].get("result") {
            Some(item) => match content.resolve_selected(item)? {
                Some(bytes) => staged["candidate"] = serde_json::from_slice(&bytes)?,
                None => {
                    staged
                        .as_object_mut()
                        .ok_or("staged object")?
                        .remove("candidate");
                }
            },
            None => {
                staged
                    .as_object_mut()
                    .ok_or("staged object")?
                    .remove("candidate");
            }
        }
    }
    staged["event"] = result.effective_event;
    staged["messages"] = json!(result.outcome.messages);
    staged["denied"] = json!(result.outcome.is_denied());
    if result.outcome.is_denied() {
        staged["candidate"] = json!({"action":"decline"});
    } else if let Some(candidate) = result.outcome.candidate {
        staged["candidate"] = candidate;
    }
    Ok(staged)
}
fn summary(exchange: &Exchange, staged: &Value, principal: &str, effects: &[Value]) -> Value {
    let event = &staged["event"];
    if let (Some(request), Some(answer)) = (exchange.original_request(), staged.get("candidate")) {
        let provenance = if effects.is_empty() {
            json!({"kind":"mcp","authenticatedSource":principal})
        } else {
            json!({"kind":"hook","authenticatedSource":principal,"effects":effects.iter().map(|e|e["type"].clone()).collect::<Vec<_>>()})
        };
        json!({"request":request,"result":answer,"provenance":provenance,"externalCompletion":false})
    } else {
        json!({"selection":{"request":exchange.original_event()["elicitation"]["request"]["selection"].as_str().unwrap_or("omit"),"result":event["elicitation"]["result"]["selection"].as_str().unwrap_or("omit")},"bodyValidation":"not-selected","provenance":{"kind":"mcp","authenticatedSource":principal},"externalCompletion":false})
    }
}
// The single-effect check adapter has a singular report field. Atomic checks
// retain the executor's plural provenance even when their batch has one effect.
fn check_summary(mut report: Value, case: &Value) -> Value {
    if case["op"] != "apply"
        && case.get("effect").is_some()
        && report["provenance"]["kind"] == "hook"
    {
        let provenance = report["provenance"]
            .as_object_mut()
            .expect("summary provenance");
        provenance.remove("effects");
        provenance.insert("effect".into(), case["effect"]["type"].clone());
    }
    report
}

fn sender_token<'a>(plan: &'a Value, step: &Value) -> Result<&'a str> {
    let field = if step["path"] == "/upload" {
        "uploadToken"
    } else {
        "token"
    };
    plan[field]
        .as_str()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| format!("missing {field}").into())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args[1] == "client" {
        let plan: Value = serde_json::from_reader(io::stdin())?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        // This is a raw transport driver: each plan selects a credential explicitly.
        // Separate upload plans/endpoints never reuse credentials through redirects.
        let mut results = vec![];
        for step in plan["steps"].as_array().ok_or("steps")? {
            let mut r = client
                .post(format!(
                    "{}{}",
                    plan["endpoint"].as_str().ok_or("endpoint")?,
                    step["path"].as_str().ok_or("path")?
                ))
                .body(STANDARD.decode(step["bytes"].as_str().ok_or("bytes")?)?);
            let explicit_auth = step["headers"].as_object().is_some_and(|headers| {
                headers
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case("Authorization"))
            });
            if !explicit_auth {
                r = r.bearer_auth(sender_token(&plan, step)?);
            }
            if let Some(headers) = step["headers"].as_object() {
                for (k, v) in headers {
                    r = r.header(k, v.as_str().ok_or("header")?);
                }
            }
            let response = r.send()?;
            let status = response.status().as_u16();
            results.push(json!({"status":status,"body":response.text()?}));
        }
        println!("{}", serde_json::to_string(&results)?);
        return Ok(());
    }
    let token = std::env::var("AHP_ELICITATION_TOKEN")?;
    // Upload authorization is independently configured; event credentials are
    // never an implicit fallback for this resource.
    let upload_token = std::env::var("AHP_ELICITATION_UPLOAD_TOKEN").unwrap_or_default();
    let principal = &args[3];
    if token.is_empty() || principal.is_empty() {
        return Err("Missing auth".into());
    }
    let mut store: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut pending: BTreeMap<(String, String), Exchange> = BTreeMap::new();
    let mut receipts = vec![];
    if args[1] == "check" {
        let cases: Value = serde_json::from_reader(io::stdin())?;
        let mut outputs = vec![];
        for c in cases.as_array().ok_or("cases")? {
            store.clear();
            for upload in c["uploads"].as_array().unwrap_or(&vec![]) {
                store.insert(
                    upload["ref"].as_str().ok_or("ref")?.to_string(),
                    STANDARD.decode(upload["bytes"].as_str().ok_or("bytes")?)?,
                );
            }
            let host = HostStore {
                scope: agenthooksprotocol::content::AuthorizedScope::new(principal),
                entries: std::sync::Mutex::new(store.clone()),
            };
            let context = agenthooksprotocol::content::ContentContext {
                store: &host,
                scope: agenthooksprotocol::content::AuthorizedScope::new(principal),
            };
            let before = c.clone();
            let checked = (|| -> Result<Value> {
                if c["op"] == "capability" {
                    return validate_mode(
                        c["mode"].as_str().unwrap_or(""),
                        c.get("capabilities"),
                        c["origin"].as_str().unwrap_or("ahp"),
                    );
                }
                let exchange = Exchange::new(&c["request"], &context)?;
                let effects = if c["op"] == "apply" {
                    c["effects"].as_array().ok_or("effects")?.clone()
                } else {
                    c.get("effect").cloned().into_iter().collect()
                };
                let result = c.get("result").filter(|r| !r.is_null());
                let request_effect = effects.first().is_some_and(|e| e["type"] != "modify");
                // A guard check reports the validated incoming result, not the
                // atomic executor's replacement/decline candidate. Atomic apply
                // continues to report the settled candidate instead.
                let incoming = if request_effect || c["op"] != "apply" {
                    result
                        .map(|result| execute(result, &[], &context, Some(&exchange)))
                        .transpose()?
                } else {
                    None
                };
                let boundary = if request_effect {
                    &c["request"]
                } else {
                    result.unwrap_or(&c["request"])
                };
                let staged = execute(boundary, &effects, &context, Some(&exchange))?;
                let reported = if c["op"] == "apply" {
                    &staged
                } else {
                    incoming.as_ref().unwrap_or(&staged)
                };
                Ok(check_summary(
                    summary(&exchange, reported, principal, &effects),
                    c,
                ))
            })();
            if *c != before {
                return Err("Input mutated".into());
            }
            outputs.push(match checked {
                Ok(summary) => json!({"accepted":true,"summary":summary}),
                Err(_) => json!({"accepted":false}),
            });
            if c["op"] == "apply" {
                outputs.last_mut().unwrap()["inputUnchanged"] = json!(*c == before);
            }
        }
        println!("{}", serde_json::to_string(&outputs)?);
        return Ok(());
    }
    // Both independently authenticated credentials are explicitly authorized by
    // host configuration for this same storage scope. No payload field grants it.
    let event_scope = agenthooksprotocol::content::AuthorizedScope::new(principal);
    let upload_scope = event_scope.clone();
    let upload_authorizer = move |request: &agenthooksprotocol::transport::Request| {
        if upload_token.is_empty()
            || request.headers.get("authorization") != Some(&format!("Bearer {upload_token}"))
        {
            return Err(agenthooksprotocol::content::UploadError::Unauthorized);
        }
        Ok(upload_scope.clone())
    };
    let mut upload_receiver = agenthooksprotocol::content::UploadReceiver::new(
        upload_authorizer,
        "/upload",
        4 * 1024 * 1024,
        64 * 1024 * 1024,
        4096,
    );
    let event_store = upload_receiver.store();
    let server = tiny_http::Server::http("127.0.0.1:0")?;
    println!(
        "{}",
        json!({"endpoint":format!("http://{}",server.server_addr())})
    );
    io::stdout().flush()?;
    for mut incoming in server.incoming_requests() {
        if incoming
            .headers()
            .iter()
            .filter(|h| {
                h.field
                    .as_str()
                    .as_str()
                    .eq_ignore_ascii_case("Authorization")
            })
            .count()
            != 1
        {
            incoming.respond(tiny_http::Response::empty(401))?;
            continue;
        }
        // Reject duplicate names before collection could collapse exact-case
        // duplicates. UploadReceiver additionally verifies normalized framing.
        let mut names = std::collections::BTreeSet::new();
        if incoming
            .headers()
            .iter()
            .any(|h| !names.insert(h.field.as_str().as_str().to_ascii_lowercase()))
        {
            incoming.respond(tiny_http::Response::empty(400))?;
            continue;
        }
        let headers: BTreeMap<String, String> = incoming
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_ascii_lowercase(),
                    h.value.as_str().to_owned(),
                )
            })
            .collect();
        let path = incoming.url().to_string();
        if path != "/upload" && headers.get("authorization") != Some(&format!("Bearer {token}")) {
            incoming.respond(tiny_http::Response::empty(401))?;
            continue;
        }
        let mut raw = vec![];
        incoming.as_reader().take(4194305).read_to_end(&mut raw)?;
        let operation = (|| -> Result<(u16, Value)> {
            if raw.len() > 4194304 {
                return Ok((413, json!({"error":"size limit"})));
            }
            if path == "/upload" {
                let response = upload_receiver.handle(agenthooksprotocol::transport::Request {
                    method: incoming.method().as_str().to_owned(),
                    uri: path.clone(),
                    headers,
                    body: raw,
                });
                return Ok((response.status, serde_json::from_slice(&response.body)?));
            }
            if path == "/receipts" {
                return Ok((200, json!(receipts)));
            }
            if path != "/hooks/intercept" {
                return Err("Unknown endpoint".into());
            }
            let context = agenthooksprotocol::content::ContentContext {
                store: &event_store,
                scope: event_scope.clone(),
            };
            let message: Value = serde_json::from_slice(&raw)?;
            let event = &message["params"]["event"];
            let meta = &event["elicitation"];
            let parent = if event["type"] == "user.elicitation.request" {
                &event["id"]
            } else {
                &event["parentEventId"]
            };
            let key = (
                event["source"].as_str().ok_or("source")?.to_string(),
                parent.as_str().ok_or("parent")?.to_string(),
            );
            let (body, summary) = match event["type"].as_str() {
                Some("user.elicitation.request") => {
                    if pending.contains_key(&key) {
                        return Err("Duplicate pending request identity".into());
                    }
                    validate_mode(
                        meta["mode"].as_str().ok_or("mode")?,
                        Some(&json!({"form":{},"url":{}})),
                        "ahp",
                    )?;
                    let exchange = Exchange::new(&message, &context)?;
                    execute(&message, &[], &context, None)?;
                    let payload = exchange.original_request().cloned();
                    let body = if payload.is_some() {
                        context.resolve(&meta["request"]["body"])?.to_vec()
                    } else {
                        vec![]
                    };
                    let summary = match payload {
                        Some(payload) => json!({"request":payload}),
                        None => {
                            json!({
                                "selection": meta["request"]["selection"].as_str().unwrap_or("omit")
                            })
                        }
                    };
                    pending.insert(key.clone(), exchange);
                    (body, summary)
                }
                Some("user.elicitation.result") => {
                    let request = pending.get(&key).ok_or("No pending elicitation")?;
                    let staged = execute(&message, &[], &context, Some(request))?;
                    let summary = summary(request, &staged, principal, &[]);
                    let body = if meta["result"].get("body").is_some() {
                        context.resolve(&meta["result"]["body"])?.to_vec()
                    } else {
                        vec![]
                    };
                    pending.remove(&key);
                    (body, summary)
                }
                _ => return Err("Not elicitation".into()),
            };
            receipts.push(json!({
                "message": message,
                "bytes": STANDARD.encode(body),
                "summary": summary
            }));
            Ok((
                200,
                json!({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "protocolVersion": "draft",
                        "effects": []
                    }
                }),
            ))
        })();
        let (status, value) = operation.unwrap_or((400, json!({"error":"rejected"})));
        let body = if status == 204 {
            String::new()
        } else {
            serde_json::to_string(&value)?
        };
        incoming.respond(
            tiny_http::Response::from_string(body)
                .with_status_code(status)
                .with_header(
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                ),
        )?;
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut b = bytes.to_vec();
    b.push(128);
    while b.len() % 64 != 56 {
        b.push(0);
    }
    b.extend_from_slice(&((bytes.len() as u64) * 8).to_be_bytes());
    for chunk in b.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let x = w[i - 15];
            let y = w[i - 2];
            w[i] = w[i - 16]
                .wrapping_add(x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3))
                .wrapping_add(w[i - 7])
                .wrapping_add(y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10));
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let t = hh
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let u = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t);
            d = c;
            c = b;
            b = a;
            a = t.wrapping_add(u);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[cfg(test)]
mod sender_tests {
    use super::*;

    #[test]
    fn upload_credentials_are_independent_of_event_credentials() {
        let plan = json!({"token":"event", "uploadToken":"upload"});
        assert_eq!(
            sender_token(&plan, &json!({"path":"/upload"})).unwrap(),
            "upload"
        );
        assert_eq!(
            sender_token(&plan, &json!({"path":"/hooks/intercept"})).unwrap(),
            "event"
        );
        for plan in [
            json!({"token":"event"}),
            json!({"token":"event","uploadToken":null}),
            json!({"token":"event","uploadToken":""}),
        ] {
            assert!(sender_token(&plan, &json!({"path":"/upload"})).is_err());
        }
    }
}

#[cfg(test)]
mod scoped_fixture_store_tests {
    use super::*;
    use agenthooksprotocol::content::{AuthorizedScope, ContentStore, UploadError};
    use std::sync::{Arc, Mutex};

    #[test]
    fn check_import_scope_is_not_inferred_from_a_reference() {
        let allowed = AuthorizedScope::new("configured-principal");
        let other = AuthorizedScope::new("payload-asserted-principal");
        let store = HostStore {
            scope: allowed.clone(),
            entries: Mutex::new(BTreeMap::new()),
        };
        let reference = store
            .put(&allowed, Arc::from(b"original".as_slice()))
            .unwrap();
        assert_eq!(
            store.resolve(&allowed, &reference).unwrap().as_ref(),
            b"original"
        );
        assert_eq!(
            store.resolve(&other, &reference).unwrap_err(),
            UploadError::Forbidden
        );
        assert_eq!(
            store
                .put(&other, Arc::from(b"other".as_slice()))
                .unwrap_err(),
            UploadError::Forbidden
        );
    }
}

#[cfg(test)]
mod check_report_tests {
    use super::*;

    #[test]
    fn single_effect_report_is_singular_without_changing_atomic_or_runtime_provenance() {
        let runtime = json!({"provenance":{"kind":"hook","authenticatedSource":"authenticated:hook","effects":["return"]},"result":{"action":"accept"},"externalCompletion":false});
        let single = check_summary(runtime.clone(), &json!({"effect":{"type":"return"}}));
        assert_eq!(
            single["provenance"],
            json!({"kind":"hook","authenticatedSource":"authenticated:hook","effect":"return"})
        );
        assert_eq!(single["result"], runtime["result"]);
        assert_eq!(single["externalCompletion"], false);
        assert_eq!(
            check_summary(
                runtime.clone(),
                &json!({"op":"apply","effects":[{"type":"return"}]})
            ),
            runtime
        );
        assert_eq!(runtime["provenance"]["effects"], json!(["return"]));
        let mcp = json!({"provenance":{"kind":"mcp","authenticatedSource":"authenticated:hook"}});
        assert_eq!(
            check_summary(mcp.clone(), &json!({"effect":{"type":"return"}})),
            mcp
        );
    }
}
