//! Canonical hooks/intercept with inline text; no scheduling wire method.
use agenthooksprotocol::{
    client::{Hook, HookError, LocalFuture},
    content::{
        AuthorizedScope, ContentContext, ContentReference, ContentStore, ContentUploadReceipt,
        MemoryContentStore, UploadAuthorizer, UploadError, UploadReceiver,
    },
    interop::Schemas,
    transport::{Request as HttpRequest, Response as HttpResponse},
};
#[cfg(test)]
use agenthooksprotocol::{
    content::{UploadCredential, Uploader},
    transport::{Http, TransportError},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};
#[allow(dead_code)]
#[path = "compaction.rs"]
mod fixture;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn location(store: &str, sub: &str, reference: &str) -> PathBuf {
    Path::new(store).join(sha256(format!("{sub}\0{reference}").as_bytes()))
}
// The fixture filesystem is a receiver-owned allocation domain, not a network
// retrieval API. Scope binding is explicit and descriptor verification belongs
// to the same public content layer used by protocol compaction staging.
struct FixtureContentStore<'a> {
    root: &'a str,
    subscription: &'a str,
}
impl ContentStore for FixtureContentStore<'_> {
    fn resolve(
        &self,
        scope: &AuthorizedScope,
        reference: &ContentReference,
    ) -> std::result::Result<Arc<[u8]>, UploadError> {
        if scope != &AuthorizedScope::new(self.subscription) {
            return Err(UploadError::Forbidden);
        }
        fs::read(location(self.root, self.subscription, &reference.ref_))
            .map(Arc::from)
            .map_err(|_| UploadError::Unavailable)
    }
    fn put(
        &self,
        _: &AuthorizedScope,
        _: Arc<[u8]>,
    ) -> std::result::Result<ContentReference, UploadError> {
        Err(UploadError::Unavailable)
    }
}
fn receive(request: &Value, sub: &str, config: &Value, store: &str, schemas: &Schemas) -> Value {
    let process = || -> Result<Value> {
        schemas.validate("intercept-request", request)?;
        let event = &request["params"]["event"];
        let storage = FixtureContentStore {
            root: store,
            subscription: sub,
        };
        let content = ContentContext {
            store: &storage,
            scope: AuthorizedScope::new(sub),
        };
        let mut bodies = json!({});
        let mut selected = event.clone();
        project_selected_items(&mut selected, |part| {
            if let Some(text) = part["text"].as_str() {
                bodies[part["id"].as_str().ok_or("part id")?] = json!(text);
            }
            Ok(())
        })?;
        let action = &config[sub];
        if action.is_null() {
            return Err("subscription".into());
        }
        let effects = if action["kind"] == "append" {
            let target = action["target"].as_str().ok_or("target")?;
            let body = agenthooksprotocol::compaction::selected_text(&event[target], &content)?;
            let text = format!("{}{}", body, action["suffix"].as_str().ok_or("suffix")?);
            json!([{
                "type":"modify", "target":target, "operation":"replace",
                "value":[{"id":event[target][0]["id"].as_str().unwrap_or(target),
                    "kind":"text","mediaType":"text/plain","selection":"body","text":text}]
            }])
        } else {
            action["effects"].clone()
        };
        let response = json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": "draft",
                "effects": effects
            }
        });
        schemas.validate("intercept-response", &response)?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(store).join("receipts.jsonl"))?;
        writeln!(
            file,
            "{}",
            json!({
                "subscription": sub,
                "request": request,
                "response": response,
                "bodies": bodies
            })
        )?;
        Ok(response)
    };
    process().unwrap_or_else(|_| {
        json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {
                "code": -32602,
                "message": "Invalid compaction request"
            }
        })
    })
}
const MAX_UPLOAD: usize = 4 * 1024 * 1024;
const MAX_STORED: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

// Reject duplicates before converting an HTTP multimap to the public transport
// map. Otherwise identical-name duplicates would be silently overwritten.
fn unique_headers<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> std::result::Result<BTreeMap<String, String>, UploadError> {
    let mut map = BTreeMap::new();
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        if map.insert(name, value.to_owned()).is_some() {
            return Err(UploadError::Framing);
        }
    }
    Ok(map)
}
#[cfg(test)]
struct BlockingUploadHttp<'a>(&'a reqwest::blocking::Client);
#[cfg(test)]
impl Http for BlockingUploadHttp<'_> {
    fn send(
        &self,
        request: HttpRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::result::Result<HttpResponse, TransportError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let execute = || -> Result<HttpResponse> {
                let mut outgoing = self.0.request(
                    reqwest::Method::from_bytes(request.method.as_bytes())?,
                    &request.uri,
                );
                for (name, value) in request.headers {
                    outgoing = outgoing.header(name, value);
                }
                let incoming = outgoing.body(request.body).send()?;
                let status = incoming.status().as_u16();
                let mut pairs = Vec::new();
                for (name, value) in incoming.headers() {
                    pairs.push((name.as_str(), value.to_str()?));
                }
                let headers = unique_headers(pairs)?;
                let mut body = Vec::new();
                incoming.take(8193).read_to_end(&mut body)?;
                Ok(HttpResponse {
                    status,
                    headers,
                    body,
                })
            };
            execute().map_err(|error| TransportError(error.to_string()))
        })
    }
}
#[derive(Clone)]
struct FixtureUploadAuthorizer {
    tokens: Value,
    subscriptions: BTreeSet<String>,
}
impl UploadAuthorizer for FixtureUploadAuthorizer {
    fn authorize(
        &self,
        request: &HttpRequest,
    ) -> std::result::Result<AuthorizedScope, UploadError> {
        let subscription = request
            .headers
            .get("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .and_then(|token| self.tokens[token].as_str())
            .filter(|subscription| !subscription.is_empty())
            .ok_or(UploadError::Unauthorized)?;
        if !self.subscriptions.contains(subscription) {
            return Err(UploadError::Forbidden);
        }
        Ok(AuthorizedScope::new(subscription))
    }
}
fn mirror_successful_upload<A: UploadAuthorizer>(
    uploads: &UploadReceiver<A>,
    scope: &AuthorizedScope,
    response: &HttpResponse,
    store: &str,
    subscription: &str,
) -> Result<()> {
    if response.status != 201 {
        return Ok(());
    }
    // Cross-process stdio readers need confirmed bytes, never another allocator.
    let reference = serde_json::from_slice::<ContentUploadReceipt>(&response.body)?.reference();
    let bytes = uploads.resolve(scope, &reference)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(location(store, subscription, &reference.ref_))?;
    file.write_all(&bytes)?;
    Ok(())
}
#[cfg(test)]
async fn item(
    client: &reqwest::blocking::Client,
    plan: &Value,
    sub: &str,
    id: &str,
    _kind: &str,
    text: &str,
    _role: &str,
) -> Result<Value> {
    // Only the harness base endpoint is shorthand. Explicit upload URLs remain exact.
    let endpoint = match plan["uploadEndpoint"].as_str() {
        Some(endpoint) => endpoint.to_owned(),
        None => format!("{}/upload", plan["endpoint"].as_str().ok_or("endpoint")?),
    };
    let credential = UploadCredential::bearer(
        plan["credentials"][sub]["uploadToken"]
            .as_str()
            .ok_or("upload token")?,
    )?;
    let http = BlockingUploadHttp(client);
    let uploader = Uploader::new(&http, endpoint, MAX_UPLOAD, Some(credential), true)?;
    let descriptor = uploader.upload(text.as_bytes()).await?.reference();
    Ok(json!({
        "id": id,
        "kind": "attachment",
        "mediaType": "application/octet-stream",
        "selection": "body",
        "body": descriptor
    }))
}
// Projection must preserve optional-field presence. In particular, indexing an
// absent `items` field mutably would synthesize `items: null` on after events and
// fail canonical validation before any hook exchange.
fn project_selected_items(
    event: &mut Value,
    mut project: impl FnMut(&mut Value) -> Result<()>,
) -> Result<()> {
    if let Some(items) = event.get_mut("items").and_then(Value::as_array_mut) {
        for message in items {
            for part in message["parts"].as_array_mut().ok_or("message parts")? {
                project(part)?;
            }
        }
    }
    for key in ["instructions", "summary"] {
        if let Some(parts) = event.get_mut(key).and_then(Value::as_array_mut) {
            for part in parts {
                project(part)?;
            }
        }
    }
    Ok(())
}
async fn exchange(
    client: &reqwest::blocking::Client,
    plan: &Value,
    sub: &str,
    request: Value,
    store: &MemoryContentStore,
    schemas: &Schemas,
    trace: &Mutex<Vec<Value>>,
) -> Result<Value> {
    // Text remains inline across both transports; compaction never uploads it.
    let _ = store;
    schemas.validate("intercept-request", &request)?;
    let response: Value = if plan["transport"] == "http" {
        client
            .post(format!(
                "{}/hooks/intercept",
                plan["endpoint"].as_str().ok_or("endpoint")?
            ))
            .bearer_auth(plan["credentials"][sub]["token"].as_str().ok_or("token")?)
            .json(&request)
            .send()?
            .error_for_status()?
            .json()?
    } else {
        let command = plan["receiverCommand"].as_array().ok_or("command")?;
        let mut child = Command::new(command[0].as_str().ok_or("command")?)
            .args(command[1..].iter().map(|v| v.as_str().unwrap()))
            .args(["stdio", sub])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        writeln!(child.stdin.take().ok_or("stdin")?, "{request}")?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err("receiver failed".into());
        }
        serde_json::from_slice(&output.stdout)?
    };
    trace
        .lock()
        .unwrap()
        .push(json!({"subscription":sub,"request":request,"response":response}));
    schemas.validate("intercept-response", &response)?;
    if request["id"] != response["id"] {
        return Err("correlation".into());
    }
    Ok(response)
}
struct WireHook {
    client: reqwest::blocking::Client,
    plan: Value,
    subscription: String,
    store: MemoryContentStore,
    schemas: Arc<Schemas>,
    trace: Arc<Mutex<Vec<Value>>>,
}
impl Hook for WireHook {
    fn call(&self, request: Value) -> LocalFuture<'_, std::result::Result<Value, HookError>> {
        Box::pin(async move {
            exchange(
                &self.client,
                &self.plan,
                &self.subscription,
                request,
                &self.store,
                &self.schemas,
                &self.trace,
            )
            .await
            .map_err(|e| HookError(e.to_string()))
        })
    }
}

fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if !["host", "server", "stdio"].contains(&args[0].as_str()) {
        let mode = args.remove(3);
        args.insert(0, mode);
    }
    if args[0] == "host" {
        let plan: Value = serde_json::from_reader(io::stdin())?;
        let schemas = Arc::new(Schemas::load(Path::new(
            plan["schema"].as_str().ok_or("schema")?,
        ))?);
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        let mut out = vec![];
        for row in plan["cases"].as_array().ok_or("cases")? {
            let name = row["name"].as_str().ok_or("name")?;
            let trace = Arc::new(Mutex::new(vec![]));
            let store = MemoryContentStore::new(usize::MAX, usize::MAX, usize::MAX);
            let subscriptions = |boundary: &str| -> Result<Vec<_>> {
                row[boundary]
                    .as_array()
                    .ok_or("subscriptions")?
                    .iter()
                    .map(|h| {
                        let hook = WireHook {
                            client: client.clone(),
                            plan: plan.clone(),
                            subscription: h["supplier"].as_str().ok_or("supplier")?.to_owned(),
                            store: store.clone(),
                            schemas: schemas.clone(),
                            trace: trace.clone(),
                        };
                        fixture::fixture_subscription(h, boundary, Box::new(hook), false)
                            .map_err(Into::into)
                    })
                    .collect()
            };
            let input =
                json!({"instructions":"base","name":name,"itemId":format!("{name}:summary")});
            let result = fixture::run_public_fixture(
                &input,
                subscriptions("before")?,
                subscriptions("after")?,
                &store,
            )?;
            let mut downstream = vec![];
            if result["applied"] == true {
                downstream
                    .push(result["bodies"][result["summary"]["ref"].as_str().unwrap()].clone());
            }
            out.push(json!({
                "name": name,
                "result": result,
                "trace": trace.lock().unwrap().clone(),
                "downstream": downstream
            }));
        }
        println!("{}", json!(out));
        return Ok(());
    }
    let (schema, store, config_path) = (&args[1], &args[2], &args[3]);
    let schemas = Schemas::load(Path::new(schema))?;
    let config: Value = serde_json::from_slice(&fs::read(config_path)?)?;
    if args[0] == "stdio" {
        for line in io::stdin().lock().lines() {
            let request = serde_json::from_str(&line?)?;
            println!("{}", receive(&request, &args[4], &config, store, &schemas));
        }
        return Ok(());
    }
    let server = tiny_http::Server::http("127.0.0.1:0")?;
    println!(
        "{}",
        json!({"endpoint":format!("http://{}",server.server_addr())})
    );
    io::stdout().flush()?;
    let upload_authorizer = FixtureUploadAuthorizer {
        tokens: serde_json::from_str(&std::env::var("AHP_COMPACTION_UPLOAD_TOKENS")?)?,
        subscriptions: config
            .as_object()
            .ok_or("subscriptions")?
            .keys()
            .cloned()
            .collect(),
    };
    let event_tokens: Value = serde_json::from_str(&std::env::var("AHP_COMPACTION_TOKENS")?)?;
    let mut uploads = UploadReceiver::new(
        upload_authorizer.clone(),
        "/upload",
        MAX_UPLOAD,
        MAX_STORED,
        MAX_ENTRIES,
    );
    for mut request in server.incoming_requests() {
        let upload = request.url() == "/upload";
        if request
            .headers()
            .iter()
            .filter(|header| header.field.equiv("Authorization"))
            .count()
            != 1
        {
            request.respond(tiny_http::Response::empty(401))?;
            continue;
        }
        let headers = match unique_headers(
            request
                .headers()
                .iter()
                .map(|header| (header.field.as_str().as_str(), header.value.as_str())),
        ) {
            Ok(headers) => headers,
            Err(_) => {
                request.respond(tiny_http::Response::empty(400))?;
                continue;
            }
        };
        let tokens = if upload {
            &upload_authorizer.tokens
        } else {
            &event_tokens
        };
        let sub = headers
            .get("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .and_then(|token| tokens[token].as_str())
            .filter(|sub| !sub.is_empty());
        let Some(sub) = sub else {
            request.respond(tiny_http::Response::empty(401))?;
            continue;
        };
        if config.get(sub).is_none() {
            request.respond(tiny_http::Response::empty(403))?;
            continue;
        }
        if request.method() != &tiny_http::Method::Post
            || (!upload && request.url() != "/hooks/intercept")
        {
            request.respond(tiny_http::Response::empty(404))?;
            continue;
        }
        let mut raw = Vec::new();
        request
            .as_reader()
            .take((MAX_UPLOAD + 1) as u64)
            .read_to_end(&mut raw)?;
        if raw.len() > MAX_UPLOAD {
            request.respond(tiny_http::Response::empty(413))?;
            continue;
        }
        if upload {
            let wire = HttpRequest {
                method: request.method().as_str().to_owned(),
                uri: request.url().to_owned(),
                headers,
                body: raw,
            };
            let scope = upload_authorizer.authorize(&wire)?;
            let response = uploads.handle(wire);
            if mirror_successful_upload(&uploads, &scope, &response, store, sub).is_err() {
                request.respond(tiny_http::Response::empty(503))?;
                continue;
            }
            let mut reply =
                tiny_http::Response::from_data(response.body).with_status_code(response.status);
            for (name, value) in response.headers {
                reply = reply.with_header(
                    tiny_http::Header::from_bytes(name, value).map_err(|_| "response header")?,
                );
            }
            request.respond(reply)?;
        } else {
            let value: Value = match serde_json::from_slice(&raw) {
                Ok(value) => value,
                Err(_) => {
                    request.respond(tiny_http::Response::empty(400))?;
                    continue;
                }
            };
            let response = receive(&value, sub, &config, store, &schemas);
            request.respond(interception_http_response(&response))?;
        }
    }
    Ok(())
}

// Both successful results and JSON-RPC errors are JSON protocol responses.
fn interception_http_response(response: &Value) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    tiny_http::Response::from_string(response.to_string()).with_header(
        tiny_http::Header::from_bytes("Content-Type", "application/json")
            .expect("static JSON content type"),
    )
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod projection_tests {
    use super::*;

    #[test]
    fn interception_http_replies_advertise_json_for_results_and_errors() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/hooks/intercept", server.server_addr());
        let replies = [
            json!({"jsonrpc":"2.0","id":"success","result":{"protocolVersion":"draft","effects":[]}}),
            json!({"jsonrpc":"2.0","id":"rejected","error":{"code":-32602,"message":"Invalid compaction request"}}),
        ];
        let expected = replies.clone();
        let worker = std::thread::spawn(move || {
            for reply in replies {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(3))
                    .unwrap()
                    .unwrap();
                request.respond(interception_http_response(&reply)).unwrap();
            }
        });
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap();
        for reply in expected {
            let response = client.post(&endpoint).json(&json!({})).send().unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert_eq!(
                response.headers().get("content-type").unwrap(),
                "application/json"
            );
            assert_eq!(response.json::<Value>().unwrap(), reply);
        }
        worker.join().unwrap();
    }

    #[test]
    fn after_projection_preserves_absent_items_and_original_correlations() {
        let mut event = json!({"id":"after","type":"context.compact.after","parentEventId":"before","summary":[{"id":"summary","kind":"text","mediaType":"text/plain","selection":"body","text":"local"}],"removed":[{"id":"context"}],"execution":{"status":"executed"}});
        let original = event.clone();
        let mut projected = Vec::new();
        project_selected_items(&mut event, |item| {
            projected.push(item["id"].clone());
            item["text"] = json!("inline-projection");
            Ok(())
        })
        .unwrap();
        assert_eq!(projected, vec![json!("summary")]);
        assert!(!event.as_object().unwrap().contains_key("items"));
        assert!(!event.as_object().unwrap().contains_key("instructions"));
        assert_eq!(event["summary"][0]["text"], "inline-projection");
        for key in ["id", "type", "parentEventId", "removed", "execution"] {
            assert_eq!(event[key], original[key]);
        }
    }

    #[test]
    fn projection_preserves_present_empty_items_and_projects_before_items() {
        let mut empty = json!({"items":[]});
        project_selected_items(&mut empty, |_| panic!("no selected items")).unwrap();
        assert_eq!(empty, json!({"items":[]}));
        let mut before = json!({"items":[{"id":"message","role":"user","parts":[{"id":"context","kind":"text","mediaType":"text/plain","selection":"body","text":"context"}]}],"instructions":[{"id":"instructions","kind":"text","mediaType":"text/plain","selection":"body","text":"instructions"}]});
        let original = before.clone();
        let mut projected = Vec::new();
        project_selected_items(&mut before, |item| {
            projected.push(item["id"].clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(projected, vec![json!("context"), json!("instructions")]);
        assert_eq!(before, original);
    }
}

#[cfg(test)]
mod upload_tests {
    use super::*;

    #[test]
    fn sender_uses_public_uploader_with_exact_endpoint_and_independent_credential() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let endpoint = format!(
            "http://{}/explicit-upload?case=compaction",
            server.server_addr()
        );
        let receiver = std::thread::spawn(move || {
            let authorizer = FixtureUploadAuthorizer {
                tokens: json!({"upload-token":"scope"}),
                subscriptions: BTreeSet::from(["scope".to_owned()]),
            };
            let mut uploads =
                UploadReceiver::new(authorizer, "/explicit-upload?case=compaction", 64, 128, 2);
            let mut references = Vec::new();
            for _ in 0..2 {
                let mut request = server.recv().unwrap();
                assert_eq!(request.url(), "/explicit-upload?case=compaction");
                let headers = unique_headers(
                    request
                        .headers()
                        .iter()
                        .map(|header| (header.field.as_str().as_str(), header.value.as_str())),
                )
                .unwrap();
                assert_eq!(headers["authorization"], "Bearer upload-token");
                let mut body = Vec::new();
                request.as_reader().read_to_end(&mut body).unwrap();
                assert_eq!(body, "exact ☃\r\n".as_bytes());
                let reply = uploads.handle(HttpRequest {
                    method: "POST".into(),
                    uri: request.url().into(),
                    headers,
                    body,
                });
                assert_eq!(reply.status, 201);
                references.push(serde_json::from_slice::<Value>(&reply.body).unwrap());
                request
                    .respond(
                        tiny_http::Response::from_data(reply.body)
                            .with_status_code(reply.status)
                            .with_header(
                                tiny_http::Header::from_bytes("Content-Type", "application/json")
                                    .unwrap(),
                            ),
                    )
                    .unwrap();
            }
            references
        });
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        // No base endpoint exists: the configured upload destination is exact.
        let plan = json!({"uploadEndpoint":endpoint,"credentials":{"scope":{"token":"event-token","uploadToken":"upload-token"}}});
        let items = futures::executor::block_on(async {
            let first = item(
                &client,
                &plan,
                "scope",
                "logical",
                "summary",
                "exact ☃\r\n",
                "assistant",
            )
            .await
            .unwrap();
            let second = item(
                &client,
                &plan,
                "scope",
                "logical",
                "summary",
                "exact ☃\r\n",
                "assistant",
            )
            .await
            .unwrap();
            [first, second]
        });
        let references = receiver.join().unwrap();
        assert_eq!(items[0]["body"], json!({"ref": references[0]["ref"]}));
        assert_eq!(items[1]["body"], json!({"ref": references[1]["ref"]}));
        assert_ne!(items[0]["body"]["ref"], items[1]["body"]["ref"]);
        assert_eq!(items[0]["id"], items[1]["id"]);
    }

    #[test]
    fn duplicate_headers_are_rejected_before_transport_map_conversion() {
        for names in [
            ("Content-Length", "Content-Length"),
            ("Content-Length", "content-length"),
            ("Authorization", "authorization"),
        ] {
            assert!(unique_headers([(names.0, "same"), (names.1, "same")]).is_err());
        }
        assert_eq!(
            unique_headers([("Content-Type", "application/octet-stream")]).unwrap()["content-type"],
            "application/octet-stream"
        );
    }

    #[test]
    fn public_receiver_mirrors_only_confirmed_scoped_uploads_and_keeps_bounds() {
        let authorizer = FixtureUploadAuthorizer {
            tokens: json!({"upload-token":"scope","ungranted":"other"}),
            subscriptions: BTreeSet::from(["scope".to_owned()]),
        };
        let mut receiver = UploadReceiver::new(authorizer, "/upload", 16, 16, 1);
        let make_request = |token: &str| HttpRequest {
            method: "POST".into(),
            uri: "/upload".into(),
            headers: BTreeMap::from([
                ("authorization".into(), format!("Bearer {token}")),
                ("content-type".into(), "application/octet-stream".into()),
                ("content-length".into(), "5".into()),
                ("ahp-content-sha256".into(), sha256(b"bytes")),
            ]),
            body: b"bytes".to_vec(),
        };
        let directory = std::env::temp_dir().join(format!(
            "ahp-compaction-mirror-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let root = directory.to_str().unwrap();
        let scope = AuthorizedScope::new("scope");
        for (token, status) in [("event-token", 401), ("ungranted", 403)] {
            let response = receiver.handle(make_request(token));
            assert_eq!(response.status, status);
            mirror_successful_upload(&receiver, &scope, &response, root, "scope").unwrap();
            assert_eq!(fs::read_dir(root).unwrap().count(), 0);
        }
        let mut invalid = make_request("upload-token");
        invalid
            .headers
            .insert("ahp-content-sha256".into(), "0".repeat(64));
        let rejected = receiver.handle(invalid);
        assert_eq!(rejected.status, 400);
        mirror_successful_upload(&receiver, &scope, &rejected, root, "scope").unwrap();
        assert_eq!(fs::read_dir(root).unwrap().count(), 0);
        let accepted = receiver.handle(make_request("upload-token"));
        assert_eq!(accepted.status, 201);
        let reference = serde_json::from_slice::<ContentUploadReceipt>(&accepted.body)
            .unwrap()
            .reference();
        mirror_successful_upload(&receiver, &scope, &accepted, root, "scope").unwrap();
        assert_eq!(
            fs::read(location(root, "scope", &reference.ref_)).unwrap(),
            b"bytes"
        );
        let storage = FixtureContentStore {
            root,
            subscription: "scope",
        };
        let content = ContentContext {
            store: &storage,
            scope: scope.clone(),
        };
        assert_eq!(
            content
                .resolve(&serde_json::to_value(&reference).unwrap())
                .unwrap()
                .as_ref(),
            b"bytes"
        );
        // Existing mirrors are immutable; no create/truncate overwrite path.
        assert!(mirror_successful_upload(&receiver, &scope, &accepted, root, "scope").is_err());
        let full = receiver.handle(make_request("upload-token"));
        assert_eq!(full.status, 413);
        mirror_successful_upload(&receiver, &scope, &full, root, "scope").unwrap();
        assert_eq!(fs::read_dir(root).unwrap().count(), 1);
        assert!(
            receiver
                .resolve(&AuthorizedScope::new("other"), &reference)
                .is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
