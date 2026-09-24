//! Test-controlled lifecycle runtime. No core adapter behavior is changed.
#![allow(dead_code)]
use base64::Engine;
mod auth;
mod catalogue;
mod evaluator;
mod observation_chain;
mod router;
use agent_hooks_protocol::{
    generated,
    interop::{self, Result, Schemas},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, Condvar, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
const TIMEOUT: Duration = Duration::from_secs(40);
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}
fn read(p: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn write(p: &str, v: &Value) -> Result<()> {
    let tmp = format!("{p}.{}.tmp", std::process::id());
    fs::write(&tmp, serde_json::to_vec(v)?)?;
    fs::rename(tmp, p)?;
    Ok(())
}
fn schema_path(c: &Value) -> &Path {
    Path::new(
        c["schemaDir"]
            .as_str()
            .unwrap_or("../agent-hooks-protocol/schema/draft"),
    )
}
fn load_schemas(c: &Value) -> Result<Schemas> {
    if c.get("schemaDir").is_some() {
        Schemas::load(schema_path(c))
    } else {
        Schemas::bundled()
    }
}
fn localize(v: &mut Value, file: &str) {
    match v {
        Value::Object(m) => {
            m.remove("$id");
            if let Some(Value::String(r)) = m.get_mut("$ref") {
                let old = r.clone();
                let (f, frag) = old.split_once('#').unwrap_or((&old, ""));
                *r = format!(
                    "#/$defs/files/{}{}",
                    if f.is_empty() { file } else { f },
                    frag
                );
            }
            for x in m.values_mut() {
                localize(x, file);
            }
        }
        Value::Array(a) => {
            for x in a {
                localize(x, file);
            }
        }
        _ => {}
    }
}
struct Validation {
    core: Schemas,
    observe: jsonschema::Validator,
}
impl Validation {
    fn new(c: &Value) -> Result<Self> {
        let path = schema_path(c);
        let mut files = serde_json::Map::new();
        if c.get("schemaDir").is_none() {
            for mut v in serde_json::from_str::<Vec<Value>>(include_str!("../../schemas.json"))? {
                let name = s(&v, "$id")
                    .rsplit('/')
                    .next()
                    .ok_or("missing schema filename")?
                    .to_owned();
                localize(&mut v, &name);
                files.insert(name, v);
            }
        } else {
            for e in fs::read_dir(path)? {
                let p = e?.path();
                if p.extension().and_then(|x| x.to_str()) != Some("json") {
                    continue;
                }
                let name = p.file_name().unwrap().to_str().unwrap();
                let mut v = read(p.to_str().unwrap())?;
                localize(&mut v, name);
                files.insert(name.into(), v);
            }
        }
        let schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"#/$defs/files/observe-notification.schema.json","$defs":{"files":files}});
        Ok(Self {
            core: load_schemas(c)?,
            observe: jsonschema::options()
                .should_validate_formats(true)
                .build(&schema)?,
        })
    }
    fn observe(&self, v: &Value) -> Result<()> {
        if !generated::parse_observe_notification_value(v.clone()).is_ok() {
            return Err("observe codec validation failed".into());
        }
        self.observe
            .validate(v)
            .map_err(|e| format!("observe schema: {e}"))?;
        Ok(())
    }
}
// SHA-256 over exact UTF-8 bytes, without an external command or new dependency.
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
    for chunk in b.chunks_exact(64) {
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
fn resolve_bodies(
    value: &Value,
    sub: &str,
    uploads: &BTreeMap<(String, String), Vec<u8>>,
) -> Result<()> {
    match value {
        Value::Object(m) => {
            if let Some(body) = m.get("body").filter(|b| b.get("ref").is_some()) {
                let bytes = uploads
                    .get(&(sub.into(), s(body, "ref").into()))
                    .ok_or("unconfirmed scoped content reference")?;
                if body["size"].as_u64() != Some(bytes.len() as u64)
                    || s(body, "sha256") != sha256(bytes)
                    || m.get("size").is_some_and(|size| size != &body["size"])
                    || m.get("sha256").is_some_and(|hash| hash != &body["sha256"])
                {
                    return Err("content metadata mismatch".into());
                }
            }
            for v in m.values() {
                resolve_bodies(v, sub, uploads)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                resolve_bodies(v, sub, uploads)?;
            }
        }
        _ => {}
    }
    Ok(())
}
#[derive(Default)]
struct Shared {
    entries: Vec<Value>,
    released: BTreeSet<String>,
    uploads: BTreeMap<(String, String), Vec<u8>>,
    lineage: agent_hooks_protocol::lineage::TaskLineage,
    shutdown: bool,
    attempts: BTreeMap<String, usize>,
}
struct ServerState {
    data: Mutex<Shared>,
    changed: Condvar,
    validation: Validation,
    responses: BTreeMap<String, Value>,
    sequences: BTreeMap<String, Vec<Value>>,
    stdio: bool,
    stdout_order: Mutex<()>,
    upload: Value,
    auth: Value,
    catalogue: bool,
}
impl ServerState {
    fn stdout(&self, response: &Value, emitted: bool) -> Result<()> {
        self.validation.core.validate(
            if response["result"].get("manifest").is_some() {
                "capabilities-response"
            } else {
                "intercept-response"
            },
            response,
        )?;
        let _order = self.stdout_order.lock().unwrap();
        if emitted {
            self.data
                .lock()
                .unwrap()
                .entries
                .push(json!({"kind":"emitted","id":response["id"]}));
        }
        let mut out = std::io::stdout().lock();
        writeln!(out, "{response}")?;
        out.flush()?;
        Ok(())
    }
    fn control(&self, path: &str, v: &Value) -> Result<(u16, Value)> {
        if path == "/emit" {
            if !self.stdio {
                return Ok((400, json!({"error":"emit requires stdio"})));
            }
            self.stdout(&v["response"], true)?;
            return Ok((200, json!({"ok":true})));
        }
        let mut d = self.data.lock().unwrap();
        match path {
            "/health" => return Ok((200, json!({"ready":true}))),
            "/receipts" => return Ok((200, json!({"entries":d.entries}))),
            "/shutdown" => {}
            "/release" => {
                d.released.insert(s(v, "id").into());
            }
            "/mark" => d
                .entries
                .push(json!({"kind":v["kind"],"id":v["id"],"scenario":v["scenario"]})),
            "/wait" | "/wait-observed" => {
                let observed = path == "/wait-observed";
                let field = if observed { "eventId" } else { "id" };
                let kind = if observed { "observed" } else { "received" };
                let count = v["count"].as_u64().unwrap_or(1) as usize;
                let (guard, timeout) = self
                    .changed
                    .wait_timeout_while(d, TIMEOUT, |d| {
                        !d.shutdown
                            && d.entries
                                .iter()
                                .filter(|e| {
                                    (e["kind"] == kind || (observed && e["kind"] == "rejected"))
                                        && e[field] == v[field]
                                })
                                .count()
                                < count
                    })
                    .unwrap();
                d = guard;
                if timeout.timed_out() || d.shutdown {
                    return Err("barrier interrupted or timed out".into());
                }
            }
            _ => return Ok((404, json!({"error":"unknown control"}))),
        }
        self.changed.notify_all();
        Ok((200, json!({"ok":true})))
    }
    fn upload_bytes(&self, req: &mut tiny_http::Request) -> Result<(u16, Value)> {
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|h| (h.field.to_string(), h.value.to_string()))
            .collect();
        let mut bytes = Vec::new();
        let _ = req.as_reader().take(1048577).read_to_end(&mut bytes);
        Ok(self.receive_upload(req.method().as_str(), &headers, &bytes))
    }
    fn receive_upload(
        &self,
        method: &str,
        headers: &[(String, String)],
        bytes: &[u8],
    ) -> (u16, Value) {
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
                .unwrap_or("")
        };
        // Each configured principal is bound to a receiver-defined scope, not RPC IDs.
        let sub = self.upload_scope();
        let mut descriptor = json!({});
        let hash = header("AHP-Content-SHA256");
        let length = header("Content-Length").parse::<usize>().ok();
        let status = (|| {
            for name in [
                "AHP-Content-SHA256",
                "Content-Length",
                "Content-Type",
                "Authorization",
            ] {
                if headers
                    .iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                    .count()
                    > 1
                {
                    return 400;
                }
            }
            let auth = &self.upload["auth"];
            let token = self.upload["token"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| {
                    if auth.is_null() {
                        None
                    } else {
                        Some(std::env::var(s(auth, "tokenEnv")).unwrap_or_default())
                    }
                });
            if let Some(token) = token {
                if token.is_empty() || header("Authorization") != format!("Bearer {token}") {
                    return 401;
                }
            } else if self.upload["anonymous"] != true {
                return 401;
            }
            if sub.is_empty() {
                return 403;
            }
            if length.is_some_and(|n| n > 1048576) || bytes.len() > 1048576 {
                return 413;
            }
            if method != "POST"
                || header("Content-Type") != "application/octet-stream"
                || headers.iter().any(|(key, _)| {
                    key.eq_ignore_ascii_case("Content-Encoding")
                        || key.eq_ignore_ascii_case("Transfer-Encoding")
                })
                || length != Some(bytes.len())
                || sha256(bytes) != hash
            {
                return 400;
            }
            let mut d = self.data.lock().unwrap();
            let reference = format!("urn:ahp:content:{}", d.uploads.len() + 1);
            d.uploads
                .insert((sub.to_owned(), reference.clone()), bytes.to_vec());
            descriptor = json!({"ref":reference,"size":bytes.len(),"sha256":hash});
            201
        })();
        self.data.lock().unwrap().entries.push(json!({"kind":"upload","scope":sub,"ref":descriptor["ref"],"descriptor":descriptor,"size":length,"sha256":hash,"status":status}));
        (status, descriptor)
    }
    fn upload_scope(&self) -> &str {
        self.upload["scope"]
            .as_str()
            .or_else(|| self.upload["subscriptions"][0].as_str())
            .unwrap_or("body")
    }
    fn event_scope(&self) -> &str {
        self.auth["auth"]["scope"]
            .as_str()
            .or_else(|| self.auth["scope"].as_str())
            .unwrap_or("body")
    }
    fn rejection(&self, v: &Value, kind: &str) -> Box<dyn std::error::Error + Send + Sync> {
        self.data.lock().unwrap().entries.push(json!({"kind":"rejected","eventId":v["params"]["event"]["id"],"message":v,"errorKind":kind}));
        self.changed.notify_all();
        format!("{kind}: rejected notification").into()
    }
    fn protocol(&self, v: &Value) -> Result<Value> {
        if self.catalogue && v["method"] == "hooks/capabilities" {
            self.validation.core.validate("capabilities-request", v)?;
            let response = json!({"jsonrpc":"2.0","id":v["id"],"result":{"protocolVersion":"draft","manifest":catalogue::manifest()}});
            self.validation
                .core
                .validate("capabilities-response", &response)?;
            self.data
                .lock()
                .unwrap()
                .entries
                .push(json!({"kind":"discovery","request":v,"response":response}));
            return Ok(response);
        }
        if v["method"] == "hooks/observe" {
            if let Err(error) = self.validation.observe(v) {
                return Err(if self.catalogue {
                    self.rejection(v, "schema")
                } else {
                    error
                });
            }
            let event = &v["params"]["event"];
            let sub = self.event_scope();
            let mut d = self.data.lock().unwrap();
            resolve_bodies(event, sub, &d.uploads)?;
            if let Some(items) = event["items"].as_array() {
                for item in items {
                    if !generated::parse_content_item_value(item.clone()).is_ok() {
                        return Err("content codec validation failed".into());
                    }
                    if let Some(body) = item.get("body") {
                        let bytes = d
                            .uploads
                            .get(&(sub.into(), s(body, "ref").into()))
                            .ok_or("unauthorized or missing body")?;
                        if body["size"].as_u64() != Some(bytes.len() as u64)
                            || s(body, "sha256") != sha256(bytes)
                        {
                            return Err("body metadata mismatch".into());
                        }
                    }
                }
            }
            if let Err(error) = d.lineage.accept(event) {
                drop(d);
                return Err(if self.catalogue {
                    self.rejection(v, "lineage")
                } else {
                    error
                });
            }
            let gate = format!("{}:observers", s(event, "id"));
            let held = self.sequences.contains_key(&gate);
            if held {
                d.entries
                    .push(json!({"kind":"observer-blocked","id":event["id"]}));
            }
            d.entries
                .push(json!({"kind":"observed","eventId":event["id"],"event":event,"message":v}));
            self.changed.notify_all();
            if held {
                let (guard, timeout) = self
                    .changed
                    .wait_timeout_while(d, TIMEOUT, |d| !d.shutdown && !d.released.contains(&gate))
                    .unwrap();
                d = guard;
                if timeout.timed_out() || d.shutdown {
                    return Err("observer gate timed out".into());
                }
            }
            return Ok(
                json!({"jsonrpc":"2.0","id":"unsolicited-observer","result":{"protocolVersion":"draft","effects":[{"type":"deny","reason":"observer must not decide"}]}}),
            );
        }
        self.validation.core.validate("intercept-request", v)?;
        resolve_bodies(
            &v["params"]["event"],
            self.event_scope(),
            &self.data.lock().unwrap().uploads,
        )?;
        let id = s(v, "id");
        let fallback = self.responses.get(id).ok_or("unknown interception ID")?;
        let mut d = self.data.lock().unwrap();
        d.lineage.accept(&v["params"]["event"])?;
        let occurrence = d.attempts.entry(id.into()).or_default();
        let response = self
            .sequences
            .get(id)
            .and_then(|sequence| sequence.get(*occurrence))
            .unwrap_or(fallback)
            .clone();
        *occurrence += 1;
        d.entries
            .push(json!({"kind":"received","id":id,"message":v}));
        self.changed.notify_all();
        let (mut d, t) = self
            .changed
            .wait_timeout_while(d, TIMEOUT, |d| !d.shutdown && !d.released.contains(id))
            .unwrap();
        if t.timed_out() || d.shutdown {
            return Err("interception interrupted or timed out".into());
        }
        self.validation
            .core
            .validate("intercept-response", &response)?;
        d.entries.push(json!({"kind":"replied","id":id}));
        Ok(response)
    }
}
fn listener(server: tiny_http::Server, state: Arc<ServerState>, control: bool) {
    thread::spawn(move || {
        loop {
            if state.data.lock().unwrap().shutdown {
                break;
            }
            match server.recv_timeout(Duration::from_millis(100)) {
                Ok(Some(mut req)) => {
                    let st = state.clone();
                    thread::spawn(move || {
                        let shutdown = control && req.url() == "/shutdown";
                        let result = (|| -> Result<(u16, Value)> {
                            if !control {
                                let token = req
                                    .headers()
                                    .iter()
                                    .find(|h| h.field.equiv("Authorization"))
                                    .map(|h| h.value.as_str())
                                    .unwrap_or("");
                                if !auth::authenticate(&st.auth, token) {
                                    return Ok((401, json!({"error":"unauthorized"})));
                                }
                            }
                            let mut b = String::new();
                            req.as_reader().read_to_string(&mut b)?;
                            let v = if b.is_empty() {
                                json!({})
                            } else {
                                serde_json::from_str(&b)?
                            };
                            if control {
                                st.control(req.url(), &v)
                            } else if ["/intercept", "/observe", "/capabilities"]
                                .contains(&req.url())
                            {
                                Ok((200, st.protocol(&v)?))
                            } else {
                                Ok((404, json!({})))
                            }
                        })();
                        let (status, v) = result.unwrap_or_else(|e| {
                            (
                                if e.to_string().starts_with("schema:") {
                                    400
                                } else {
                                    409
                                },
                                json!({"error":e.to_string()}),
                            )
                        });
                        let body = if status == 204 {
                            String::new()
                        } else {
                            v.to_string()
                        };
                        let _ = req.respond(
                            tiny_http::Response::from_string(body)
                                .with_status_code(status)
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        "Content-Type",
                                        "application/json",
                                    )
                                    .unwrap(),
                                ),
                        );
                        if shutdown {
                            st.data.lock().unwrap().shutdown = true;
                            st.changed.notify_all();
                        }
                    });
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
    });
}
fn raw_upload_listener(listener: std::net::TcpListener, state: Arc<ServerState>) {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let state = state.clone();
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(TIMEOUT));
                let _ = stream.set_write_timeout(Some(TIMEOUT));
                let result = (|| -> Result<(u16, Value)> {
                    let mut reader = BufReader::new(&mut stream);
                    let mut line = String::new();
                    reader.read_line(&mut line)?;
                    let parts: Vec<_> = line.split_whitespace().collect();
                    if parts.len() != 3 {
                        return Ok((400, json!({})));
                    }
                    let method = parts[0].to_owned();
                    let path = parts[1].to_owned();
                    let mut headers = Vec::new();
                    let mut total = 0;
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line)?;
                        total += line.len();
                        if total > 16384 {
                            return Ok((400, json!({})));
                        }
                        if line == "\r\n" {
                            break;
                        }
                        let (k, v) = line.split_once(':').ok_or("malformed header")?;
                        headers.push((k.to_owned(), v.trim().to_owned()));
                    }
                    if path != "/upload" {
                        return Ok((404, json!({})));
                    }
                    let length = headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
                        .and_then(|(_, v)| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    let mut bytes = vec![0; length.min(1048577)];
                    let mut used = 0;
                    while used < bytes.len() {
                        match reader.read(&mut bytes[used..]) {
                            Ok(0) => break,
                            Ok(n) => used += n,
                            Err(_) => break,
                        }
                    }
                    bytes.truncate(used);
                    Ok(state.receive_upload(&method, &headers, &bytes))
                })();
                let (status, descriptor) = result.unwrap_or((400, json!({})));
                let body = descriptor.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.flush();
            });
        }
    });
}
fn server(c: &Value) -> Result<()> {
    let fixtures = read(s(c, "scenarioFile"))?;
    let mut responses = BTreeMap::new();
    let mut sequences = BTreeMap::new();
    for scenario in fixtures["scenarios"]
        .as_array()
        .ok_or("missing scenarios")?
    {
        if scenario["chain"]["holdObservers"] == true {
            sequences.insert(
                format!("{}:observers", s(&scenario["requests"]["a"], "id")),
                Vec::new(),
            );
        }
        for (key, req) in scenario["requests"].as_object().ok_or("missing requests")? {
            responses.insert(s(req, "id").into(), scenario["responses"][key].clone());
            if let Some(sequence) = scenario["responseSequences"][key].as_array() {
                sequences.insert(s(req, "id").into(), sequence.clone());
            }
        }
    }
    let control = tiny_http::Server::http("127.0.0.1:0")?;
    let control_endpoint = format!("http://{}", control.server_addr());
    let upload_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let upload_endpoint = format!("http://{}/upload", upload_listener.local_addr()?);
    let mut internal_config = c.clone();
    let secret = format!(
        "lifecycle-internal-{}-{:?}",
        std::process::id(),
        Instant::now()
    );
    if s(&c["auth"], "mode") == "mtls" {
        internal_config["auth"] =
            json!({"mode":"bearer","token":secret,"scope":c["auth"]["scope"]});
    }
    let state = Arc::new(ServerState {
        data: Mutex::new(Shared::default()),
        changed: Condvar::new(),
        validation: Validation::new(c)?,
        responses,
        sequences,
        stdio: s(c, "transport") == "stdio",
        stdout_order: Mutex::new(()),
        upload: c["uploadAuth"].clone(),
        auth: internal_config,
        catalogue: s(c, "suite") == "catalogue",
    });
    raw_upload_listener(upload_listener, state.clone());
    listener(control, state.clone(), true);
    let endpoint = if s(c, "transport") == "http" {
        let http = tiny_http::Server::http("127.0.0.1:0")?;
        let url = format!("http://{}", http.server_addr());
        listener(http, state.clone(), false);
        if s(&c["auth"], "mode") == "mtls" {
            auth::tls_frontend(
                c,
                url,
                secret,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )?
        } else {
            url
        }
    } else {
        String::new()
    };
    write(
        s(c, "readinessFile"),
        &json!({"endpoint":endpoint,"controlEndpoint":control_endpoint,"uploadEndpoint":upload_endpoint,"pid":std::process::id()}),
    )?;
    if s(c, "transport") == "stdio" {
        let st = state.clone();
        thread::spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let line = match line {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let st = st.clone();
                thread::spawn(move || {
                    let r = (|| -> Result<()> {
                        let v: Value = serde_json::from_str(&line)?;
                        let result = st.protocol(&v);
                        if st.catalogue && v["method"] == "hooks/observe" {
                            match result {
                                Ok(_) => {}
                                Err(e)
                                    if e.to_string().starts_with("schema:")
                                        || e.to_string().starts_with("lineage:") => {}
                                Err(e) => return Err(e),
                            }
                        } else {
                            st.stdout(&result?, false)?;
                        }
                        Ok(())
                    })();
                    if let Err(e) = r {
                        eprintln!("lifecycle stdio: {e}");
                        std::process::exit(1);
                    }
                });
            }
            let mut d = st.data.lock().unwrap();
            d.shutdown = true;
            st.changed.notify_all();
        });
    }
    let d = state.data.lock().unwrap();
    drop(state.changed.wait_while(d, |d| !d.shutdown).unwrap());
    Ok(())
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            unsafe extern "C" {
                fn kill(pid: i32, signal: i32) -> i32;
            }
            // The child starts its own process group. Kill wrappers and descendants,
            // not only the cargo/go/node launcher. SIGKILL is 9 on POSIX targets.
            unsafe {
                kill(-(self.0.id() as i32), 9);
            }
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
type Reply = std::result::Result<Value, String>;
struct Transport {
    http: reqwest::blocking::Client,
    event_http: reqwest::blocking::Client,
    token: String,
    upload_endpoint: String,
    endpoint: String,
    control: String,
    stdin: Option<ChildStdin>,
    router: Arc<router::Router>,
    _child: Option<ChildGuard>,
}
impl Transport {
    fn new(c: &Value) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let (event_http, token) = auth::http_client(c)?;
        let mut t = Self {
            http,
            event_http,
            token,
            upload_endpoint: s(&c["upload"], "endpoint").into(),
            endpoint: s(c, "endpoint").into(),
            control: s(c, "controlEndpoint").into(),
            stdin: None,
            router: Arc::new(router::Router::default()),
            _child: None,
        };
        if s(c, "transport") == "stdio" {
            let args = c["serverCommand"]
                .as_array()
                .ok_or("missing serverCommand")?;
            let mut cmd = Command::new(
                args.first()
                    .and_then(Value::as_str)
                    .ok_or("empty serverCommand")?,
            );
            for a in &args[1..] {
                cmd.arg(a.as_str().ok_or("invalid command argument")?);
            }
            cmd.args(["--config", s(c, "serverConfig")]);
            if let Some(cwd) = c["serverCwd"].as_str() {
                cmd.current_dir(cwd);
            }
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                cmd.process_group(0);
            }
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            let mut child = ChildGuard(cmd.spawn()?);
            if let Some(path) = c["childPidFile"].as_str() {
                write(path, &json!({"pid":child.0.id()}))?;
            }
            t.stdin = child.0.stdin.take();
            let stdout = child.0.stdout.take().ok_or("missing stdout")?;
            let router = t.router.clone();
            let schemas = load_schemas(c)?;
            thread::spawn(move || {
                let result = (|| -> Result<()> {
                    for line in BufReader::new(stdout).lines() {
                        let v: Value = serde_json::from_str(&line?)?;
                        schemas.validate(
                            if v["result"].get("manifest").is_some() {
                                "capabilities-response"
                            } else {
                                "intercept-response"
                            },
                            &v,
                        )?;
                        router.route(v);
                    }
                    Err("stdio EOF".into())
                })();
                if let Err(e) = result {
                    router.fail(e.to_string());
                }
            });
            let server_config_path = Path::new(s(c, "serverConfig"));
            let server_config_path = if server_config_path.is_absolute() {
                server_config_path.to_path_buf()
            } else {
                Path::new(c["serverCwd"].as_str().unwrap_or(".")).join(server_config_path)
            };
            let sc = read(server_config_path.to_str().ok_or("invalid config path")?)?;
            let ready_path = Path::new(s(&sc, "readinessFile"));
            let ready_path = if ready_path.is_absolute() {
                ready_path.to_path_buf()
            } else {
                Path::new(c["serverCwd"].as_str().unwrap_or(".")).join(ready_path)
            };
            let start = Instant::now();
            loop {
                if child.0.try_wait()?.is_some() {
                    return Err("server exited before readiness".into());
                }
                if let Ok(r) = read(ready_path.to_str().ok_or("invalid readiness path")?) {
                    // Launchers such as `go run` have a different PID from the server.
                    if r["pid"].as_u64().is_some() && !s(&r, "controlEndpoint").is_empty() {
                        t.control = s(&r, "controlEndpoint").into();
                        // An explicit subscription endpoint is authoritative even on stdio.
                        // Readiness supplies a default only when configuration omits it.
                        if c["upload"].get("endpoint").is_none() {
                            t.upload_endpoint = s(&r, "uploadEndpoint").into();
                        }
                        break;
                    }
                }
                if start.elapsed() > TIMEOUT {
                    return Err("server readiness timeout".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            t._child = Some(child);
        }
        Ok(t)
    }
    fn control(&self, path: &str, v: &Value) -> Result<()> {
        self.http
            .post(format!("{}{path}", self.control))
            .json(v)
            .send()?
            .error_for_status()?;
        Ok(())
    }
    fn send(
        &mut self,
        request: &Value,
    ) -> Result<mpsc::Receiver<std::result::Result<Value, String>>> {
        if let Some(stdin) = &mut self.stdin {
            let rx = self.router.register(s(request, "id"))?;
            writeln!(stdin, "{request}")?;
            stdin.flush()?;
            return Ok(rx);
        }
        let (tx, rx) = mpsc::channel();
        {
            let http = self.event_http.clone();
            let token = self.token.clone();
            let endpoint = self.endpoint.clone();
            let req = request.clone();
            thread::spawn(move || {
                let result = (|| -> Result<Value> {
                    Ok(http
                        .post(format!("{endpoint}/intercept"))
                        .bearer_auth(token)
                        .json(&req)
                        .send()?
                        .error_for_status()?
                        .json()?)
                })();
                let _ = tx.send(result.map_err(|e| e.to_string()));
            });
        }
        Ok(rx)
    }
    fn receive(&mut self, _id: &str, rx: mpsc::Receiver<Reply>) -> Result<Value> {
        Ok(rx
            .recv_timeout(TIMEOUT)
            .map_err(|e| format!("receive: {e}"))?
            .map_err(|e| format!("transport: {e}"))?)
    }
    fn emit(&self, response: &Value) -> Result<()> {
        if self.stdin.is_none() {
            return Err("emit step requires stdio".into());
        }
        let id = s(response, "id");
        let before = self.router.discarded(id);
        self.control("/emit", &json!({"response":response}))?;
        self.router.wait_discarded(id, before)
    }
    fn observe(&mut self, notification: &Value) -> Result<()> {
        if let Some(stdin) = &mut self.stdin {
            writeln!(stdin, "{notification}")?;
            stdin.flush()?;
        } else {
            // Deliberately discard the response body: observers cannot decide.
            self.event_http
                .post(format!("{}/observe", self.endpoint))
                .bearer_auth(&self.token)
                .json(notification)
                .send()?
                .error_for_status()?;
        }
        Ok(())
    }
}
#[derive(Default)]
struct Boundary {
    terminal: Option<&'static str>,
    staged: Option<Value>,
}
impl Boundary {
    fn retain(&mut self, response: Value) -> bool {
        if self.terminal.is_some() || self.staged.is_some() {
            return false;
        }
        self.staged = Some(response);
        true
    }
    fn cancel(&mut self) -> bool {
        if self.terminal == Some("cancelled") {
            return false;
        }
        self.terminal = Some("cancelled");
        self.staged = None;
        true
    }
}
fn settled_view(
    request: &Value,
    boundary: &Boundary,
    accepted: Option<&Value>,
    subscription: &Value,
    items: Option<&Value>,
) -> Result<Value> {
    if boundary.terminal.is_none() {
        return Err("observe before settlement".into());
    }
    let mut event = request["params"]["event"].clone();
    if let Some(state) = accepted {
        if event.get("tool").is_some() {
            event["tool"]["input"] = state["input"].clone();
        }
    }
    if let Some(items) = items {
        event["items"] = items.clone();
    }
    let _ = subscription;
    Ok(event)
}
fn publish(id: &str, b: &mut Boundary, state: Value, actual: &mut Value) {
    if b.terminal.is_some() {
        return;
    }
    b.staged = None;
    b.terminal = Some("accepted");
    actual["published"].as_array_mut().unwrap().push(json!(id));
    actual["states"][id] = state;
}
// An explicit step policy replaces, rather than merges with, configured credentials.
fn upload_policy<'a>(config: &'a Value, step: &'a Value) -> &'a Value {
    step.get("upload").unwrap_or(&config["upload"])
}

fn send_upload(
    endpoint: &reqwest::Url,
    step: &Value,
    bytes: &[u8],
    token: Option<&str>,
    timeout: Duration,
) -> Result<(u16, Option<Value>)> {
    let declared = step["size"].as_u64().unwrap_or(bytes.len() as u64);
    let hash = step["sha256"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| sha256(bytes));
    if hash.contains(['\r', '\n']) || token.is_some_and(|token| token.contains(['\r', '\n'])) {
        return Err("upload header contains a line break".into());
    }
    // Negative framing fixtures use a half-closed raw HTTP body, not a local validation failure.
    if endpoint.scheme() == "http" && declared != bytes.len() as u64 {
        let mut stream = std::net::TcpStream::connect((
            endpoint.host_str().ok_or("missing host")?,
            endpoint.port_or_known_default().ok_or("missing port")?,
        ))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let path = match endpoint.query() {
            Some(q) => format!("{}?{q}", endpoint.path()),
            None => endpoint.path().to_owned(),
        };
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {declared}\r\nAHP-Content-SHA256: {hash}\r\nConnection: close\r\n",
            endpoint.host_str().unwrap()
        )?;
        if let Some(token) = token {
            write!(stream, "Authorization: Bearer {token}\r\n")?;
        }
        stream.write_all(b"\r\n")?;
        stream.write_all(bytes)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        return Ok((
            line.split_whitespace()
                .nth(1)
                .ok_or("missing HTTP upload status")?
                .parse()?,
            None,
        ));
    }
    let http = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()?;
    let mut post = http
        .post(endpoint.clone())
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", declared)
        .header("AHP-Content-SHA256", hash);
    if let Some(token) = token {
        post = post.bearer_auth(token);
    }
    let response = post.body(bytes.to_vec()).send()?;
    let status = response.status().as_u16();
    if status != 201 {
        return Ok((status, None));
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        != Some("application/json")
    {
        return Err("upload confirmation must be JSON".into());
    }
    let descriptor: Value = response.json()?;
    if descriptor.as_object().is_none_or(|o| o.len() != 3)
        || s(&descriptor, "ref").is_empty()
        || descriptor["size"].as_u64() != Some(bytes.len() as u64)
        || s(&descriptor, "sha256") != sha256(bytes)
    {
        return Err("invalid upload confirmation descriptor".into());
    }
    Ok((status, Some(descriptor)))
}
fn replace_references(value: &mut Value, descriptors: &BTreeMap<String, Value>) {
    match value {
        Value::Object(m) => {
            if let Some(body) = m.get_mut("body") {
                if let Some(descriptor) = descriptors.get(s(body, "ref")) {
                    body["ref"] = descriptor["ref"].clone();
                }
            }
            for child in m.values_mut() {
                replace_references(child, descriptors);
            }
        }
        Value::Array(a) => {
            for child in a {
                replace_references(child, descriptors);
            }
        }
        _ => {}
    }
}
fn client(c: &Value) -> Result<()> {
    let validation = Validation::new(c)?;
    let fixtures = read(s(c, "scenarioFile"))?;
    let mut transport = Transport::new(c)?;
    let mut results = Vec::new();
    let mut confirmed_uploads = BTreeMap::new();
    let mut descriptors = BTreeMap::new();
    let mut observed_counts: BTreeMap<String, u64> = BTreeMap::new();
    for scenario in fixtures["scenarios"]
        .as_array()
        .ok_or("missing scenarios")?
    {
        if scenario.get("chain").is_some() {
            let actual = observation_chain::run(scenario, &mut transport, &validation)?;
            results.push(json!({"id":scenario["id"],"actual":actual}));
            continue;
        }
        // Never read expected: reports are derived solely from acquired responses and local state.
        let mut actual = json!({"published":[],"cancelled":[],"ignored":[],"states":{},"observations":[],"uploadStatuses":[]});
        let mut boundaries: BTreeMap<String, Boundary> = BTreeMap::new();
        let mut slots = BTreeMap::new();
        for step in scenario["steps"].as_array().ok_or("missing steps")? {
            let mut request_value = scenario["requests"][s(step, "key")].clone();
            replace_references(&mut request_value, &descriptors);
            let request = &request_value;
            let id = s(request, "id");
            match s(step, "op") {
                "send" => {
                    validation.core.validate("intercept-request", request)?;
                    resolve_bodies(&request["params"]["event"], "body", &confirmed_uploads)?;
                    boundaries.entry(id.into()).or_default();
                    let slot = s(step, "slot").to_owned();
                    if slots.contains_key(&slot) {
                        return Err("duplicate transport slot".into());
                    }
                    slots.insert(slot, (request.clone(), transport.send(request)?));
                }
                "wait" => transport.control(
                    "/wait",
                    &json!({"id":id,"count":step["count"].as_u64().unwrap_or(1)}),
                )?,
                "release" => transport.control("/release", &json!({"id":id}))?,
                "receive" => {
                    let slot = s(step, "slot");
                    let (req, rx) = slots.remove(slot).ok_or("unknown receive slot")?;
                    let response = transport.receive(s(&req, "id"), rx)?;
                    validation.core.validate("intercept-response", &response)?;
                    let b = boundaries
                        .get_mut(s(&req, "id"))
                        .ok_or("missing boundary")?;
                    if response["id"] != req["id"] || !b.retain(response) {
                        actual["ignored"].as_array_mut().unwrap().push(json!(slot));
                    } else {
                        transport.control(
                            "/mark",
                            &json!({"scenario":scenario["id"],"kind":"acquired","id":req["id"]}),
                        )?;
                    }
                }
                "cancel" => {
                    let b = boundaries.entry(id.into()).or_default();
                    if b.cancel() {
                        actual["cancelled"].as_array_mut().unwrap().push(json!(id));
                        transport.control(
                            "/mark",
                            &json!({"scenario":scenario["id"],"kind":"cancelled","id":id}),
                        )?;
                    }
                }
                "accept" | "failOpen" => {
                    let b = boundaries.entry(id.into()).or_default();
                    if b.terminal.is_none() {
                        let state = if s(step, "op") == "failOpen" {
                            Some(evaluator::apply(
                                request,
                                &json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"draft","effects":[]}}),
                                &validation.core,
                            )?)
                        } else {
                            b.staged
                                .take()
                                .map(|response| {
                                    evaluator::apply(request, &response, &validation.core)
                                })
                                .transpose()?
                        };
                        if let Some(state) = state {
                            publish(id, b, state, &mut actual);
                            transport.control(
                                "/mark",
                                &json!({"scenario":scenario["id"],"kind":"accepted","id":id}),
                            )?;
                        }
                    }
                }
                "emit" => {
                    let response = &step["response"];
                    validation.core.validate("intercept-response", response)?;
                    transport.emit(response)?;
                    actual["ignored"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!(format!("unsolicited:{}", s(response, "id"))));
                    transport.control(
                        "/mark",
                        &json!({"scenario":scenario["id"],"kind":"discarded","id":response["id"]}),
                    )?;
                }
                "upload" => {
                    // Failed retries cannot revoke a previously confirmed immutable body.
                    // Only successful confirmations replace aliases; resolve_bodies still
                    // checks the referenced bytes against their exact size and hash.
                    let bytes =
                        base64::engine::general_purpose::STANDARD.decode(s(step, "bodyBase64"))?;
                    let upload = upload_policy(c, step);
                    let endpoint = reqwest::Url::parse(
                        upload["endpoint"]
                            .as_str()
                            .unwrap_or(&transport.upload_endpoint),
                    )?;
                    if endpoint.scheme() != "https"
                        && !(endpoint.scheme() == "http"
                            && ["127.0.0.1", "localhost", "[::1]"]
                                .contains(&endpoint.host_str().unwrap_or("")))
                    {
                        return Err("upload requires HTTPS".into());
                    }
                    if bytes.len() as u64 > upload["maxBytes"].as_u64().unwrap_or(1048576) {
                        return Err("upload exceeds subscription maxBytes".into());
                    }
                    let token = if upload["auth"].is_null() {
                        None
                    } else {
                        if upload["auth"]["type"] != "bearer" {
                            return Err("unsupported upload auth".into());
                        }
                        Some(std::env::var(s(&upload["auth"], "tokenEnv"))?)
                    };
                    let timeout =
                        Duration::from_millis(upload["timeoutMs"].as_u64().unwrap_or(5000));
                    let (status, descriptor) =
                        send_upload(&endpoint, step, &bytes, token.as_deref(), timeout)?;
                    if let Some(descriptor) = descriptor {
                        confirmed_uploads
                            .insert(("body".into(), s(&descriptor, "ref").into()), bytes);
                        descriptors.insert(s(step, "ref").to_owned(), descriptor);
                    }
                    actual["uploadStatuses"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!(status));
                }
                "observe" => {
                    let b = boundaries.get(id).ok_or("observe before send")?;
                    let mut event = settled_view(
                        request,
                        b,
                        actual["states"].get(id),
                        &step["subscription"],
                        step.get("items"),
                    )?;
                    replace_references(&mut event, &descriptors);
                    let notification = json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":event}});
                    validation.observe(&notification)?;
                    resolve_bodies(&event, "body", &confirmed_uploads)?;
                    transport.observe(&notification)?;
                    let count = observed_counts.entry(s(&event, "id").into()).or_default();
                    *count += 1;
                    transport.control(
                        "/wait-observed",
                        &json!({"eventId":event["id"],"count":count}),
                    )?;
                    actual["observations"].as_array_mut().unwrap().push(json!({"eventId":event["id"],"subscription":step["subscription"],"input":event["tool"]["input"]}));
                }
                _ => return Err(format!("unknown lifecycle operation: {}", s(step, "op")).into()),
            }
        }
        results.push(json!({"id":scenario["id"],"actual":actual}));
    }
    let mut report = json!({"language":"rust","results":results});
    {
        report["receipts"] = transport
            .http
            .get(format!("{}/receipts", transport.control))
            .send()?
            .error_for_status()?
            .json()?;
    }
    write(s(c, "reportFile"), &report)?;
    Ok(())
}
pub fn main_entry(is_server: bool) {
    let result = (|| -> Result<()> {
        let args: Vec<String> = std::env::args().collect();
        let i = args
            .iter()
            .position(|x| x == "--config")
            .ok_or("missing --config")?;
        let c = read(args.get(i + 1).ok_or("missing config path")?)?;
        if !["none", "bearer", "oauth", "workload", "mtls"].contains(&s(&c["auth"], "mode")) {
            return Err("unsupported event auth mode".into());
        }
        if s(&c, "transport") == "stdio" && s(&c["auth"], "mode") != "none" {
            return Err("stdio uses process trust only".into());
        }
        if !["http", "stdio"].contains(&s(&c, "transport")) {
            return Err("unsupported transport".into());
        }
        if !["", "lifecycle", "catalogue"].contains(&s(&c, "suite")) {
            return Err("unsupported suite".into());
        }
        if is_server {
            server(&c)
        } else if s(&c, "suite") == "catalogue" {
            catalogue::client(&c)
        } else {
            client(&c)
        }
    })();
    if let Err(e) = result {
        eprintln!("lifecycle: {e}");
        std::process::exit(1);
    }
}
#[cfg(test)]
fn test_upload(state: &ServerState, value: &Value) -> Result<(u16, Value)> {
    let server = tiny_http::Server::http("127.0.0.1:0")?;
    let url = format!("http://{}/raw", server.server_addr());
    let value = value.clone();
    let child = thread::spawn(move || {
        reqwest::blocking::Client::new()
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .header("AHP-Content-SHA256", s(&value, "sha256"))
            .body(
                value["bodyBase64"]
                    .as_str()
                    .map(|v| base64::engine::general_purpose::STANDARD.decode(v).unwrap())
                    .unwrap_or_else(|| s(&value, "text").as_bytes().to_vec()),
            )
            .send()
            .unwrap()
            .status()
            .as_u16()
    });
    let mut req = server.recv()?;
    let (status, descriptor) = state.upload_bytes(&mut req).unwrap_or((400, json!({})));
    req.respond(tiny_http::Response::empty(status))?;
    Ok((child.join().unwrap(), descriptor))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn step_upload_policy_replaces_configured_policy_without_credential_fallback() {
        let config = json!({"upload":{"endpoint":"https://configured.invalid/upload","auth":{"type":"bearer","tokenEnv":"AUTHORIZED"},"maxBytes":100}});
        assert_eq!(upload_policy(&config, &json!({})), &config["upload"]);
        let step = json!({"upload":{"endpoint":"https://override.invalid/upload","auth":{"type":"bearer","tokenEnv":"UNAUTHORIZED"},"maxBytes":1}});
        assert_eq!(upload_policy(&config, &step), &step["upload"]);
        let anonymous = json!({"upload":{"endpoint":"https://override.invalid/upload"}});
        assert!(upload_policy(&config, &anonymous)["auth"].is_null());
        assert!(upload_policy(&config, &json!({"upload":null})).is_null());
    }

    #[test]
    fn upload_header_injection_is_rejected_before_connecting() {
        let endpoint = reqwest::Url::parse("http://127.0.0.1:1/upload").unwrap();
        let step =
            json!({"size":99,"sha256":"bad\r\nInjected: value","ref":"r","subscription":"s"});
        assert_eq!(
            send_upload(&endpoint, &step, b"body", None, TIMEOUT)
                .unwrap_err()
                .to_string(),
            "upload header contains a line break"
        );
    }
    #[test]
    fn canonical_ask_has_no_reason_field() {
        let validation = Validation::new(&json!({})).unwrap();
        let mut response = json!({"jsonrpc":"2.0","id":"ask","result":{"protocolVersion":"draft","effects":[{"type":"ask"}]}});
        validation
            .core
            .validate("intercept-response", &response)
            .unwrap();
        response["result"]["effects"][0]["reason"] = json!("confirm");
        assert!(
            validation
                .core
                .validate("intercept-response", &response)
                .is_err()
        );
    }
    #[test]
    fn hash_vectors() {
        assert_eq!(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    fn state() -> ServerState {
        ServerState {
            data: Mutex::new(Shared::default()),
            changed: Condvar::new(),
            validation: Validation::new(&json!({})).unwrap(),
            responses: BTreeMap::new(),
            sequences: BTreeMap::new(),
            stdio: false,
            stdout_order: Mutex::new(()),
            upload: json!({"anonymous":true,"subscriptions":["body"]}),
            auth: json!({"auth":{"mode":"none"}}),
            catalogue: false,
        }
    }
    #[test]
    fn binary_upload_is_scoped_immutable_and_auth_is_independent() {
        let mut receiver = state();
        let bytes = [0, 255, 128, 13, 10];
        let upload = json!({"subscription":"body","ref":"urn:binary","bodyBase64":base64::engine::general_purpose::STANDARD.encode(bytes),"sha256":sha256(&bytes)});
        let (status, descriptor) = test_upload(&receiver, &upload).unwrap();
        assert_eq!(status, 201);
        let mut changed = upload.clone();
        changed["bodyBase64"] = json!("AA==");
        changed["sha256"] = json!(sha256(&[0]));
        let (status, second) = test_upload(&receiver, &changed).unwrap();
        assert_eq!(status, 201);
        assert_ne!(descriptor["ref"], second["ref"]);
        assert_eq!(
            receiver.data.lock().unwrap().uploads[&("body".into(), s(&descriptor, "ref").into())],
            bytes
        );
        receiver.upload["anonymous"] = json!(false);
        assert_eq!(test_upload(&receiver, &upload).unwrap().0, 401);
        assert_eq!(receiver.control("/upload", &upload).unwrap().0, 404);
    }
    #[test]
    fn observation_has_no_decision_summary() {
        let request = json!({"params":{"event":{"id":"same","tool":{"input":{}}}}});
        let mut boundary = Boundary {
            terminal: Some("accepted"),
            staged: None,
        };
        let state = json!({"decision":"deny","flow":"stop","input":{"effective":true}});
        let event = settled_view(&request, &boundary, Some(&state), &json!("s"), None).unwrap();
        assert_eq!(event["id"], "same");
        assert_eq!(event["tool"]["input"], state["input"]);
        boundary.cancel();
        assert_eq!(
            settled_view(&request, &boundary, Some(&state), &json!("s"), None).unwrap(),
            event
        );
    }
    #[test]
    fn typed_task_workspace_observations_capture_exact_wire_and_lineage() {
        let receiver = state();
        let notification = |id: &str, kind: &str, payload: Value, parent: Option<&str>| {
            let mut event = json!({"id":id,"source":"urn:tasks","time":"2026-09-01T00:00:00Z","type":format!("{kind}.change.after"),kind:payload});
            if let Some(parent) = parent {
                event["parentEventId"] = json!(parent);
            }
            json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":event}})
        };
        let task = notification(
            "task-after",
            "task",
            json!({"id":"stable-task","operation":"update","prior":{"status":"working"},"change":{"status":"native-finished"}}),
            Some("unknown-parent"),
        );
        receiver.protocol(&task).unwrap();
        assert_eq!(
            receiver.data.lock().unwrap().entries[0],
            json!({"kind":"observed","eventId":task["params"]["event"]["id"],"event":task["params"]["event"],"message":task})
        );
        let workspace = notification(
            "workspace-after",
            "workspace",
            json!({"kind":"cwd","prior":{"cwd":"/old"},"change":{"cwd":"/new"}}),
            None,
        );
        receiver.protocol(&workspace).unwrap();
        let mut bad = task.clone();
        bad["params"]["event"]["id"] = json!("noop");
        bad["params"]["event"]["task"]["change"] = json!({"status":"working"});
        assert!(receiver.protocol(&bad).is_err());
        bad = task.clone();
        bad["params"]["event"]["id"] = json!("unknown-parent");
        bad["params"]["event"]["parentEventId"] = json!("task-after");
        assert!(receiver.protocol(&bad).is_err());
        assert_eq!(receiver.data.lock().unwrap().entries.len(), 2);
    }
    #[test]
    fn terminal_boundaries_cannot_publish_again() {
        let mut actual = json!({"published":[],"states":{}});
        let mut b = Boundary {
            terminal: Some("cancelled"),
            staged: None,
        };
        publish("cancelled", &mut b, json!({"input":"wrong"}), &mut actual);
        assert_eq!(actual, json!({"published":[],"states":{}}));
        let mut b = Boundary::default();
        publish("accepted", &mut b, json!({"input":"first"}), &mut actual);
        publish("accepted", &mut b, json!({"input":"wrong"}), &mut actual);
        assert_eq!(actual["published"], json!(["accepted"]));
        assert_eq!(actual["states"]["accepted"]["input"], "first");
    }
    #[test]
    fn immutable_upload_and_receiver_authorization() {
        let mut state = state();
        let text = "é body";
        let upload = json!({"subscription":"body","ref":"urn:body:1","size":text.len(),"sha256":sha256(text.as_bytes()),"text":text});
        let (status, descriptor) = test_upload(&state, &upload).unwrap();
        assert_eq!(status, 201);
        let second = test_upload(&state, &upload).unwrap().1;
        assert_ne!(descriptor["ref"], second["ref"]);
        state.upload["scope"] = json!("");
        assert_eq!(test_upload(&state, &upload).unwrap().0, 403);
        state.upload["scope"] = json!("body");
        let mut notification = json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":{"id":"test","source":"urn:rust:test","type":"tool.before","time":"2026-09-01T00:00:00Z","session":{"id":"s"},"call":{"id":"c"},"path":"native","tool":{"origin":"native","name":"task","kind":"task","input":{"value":"settled"}},"items":[{"id":"item","kind":"text","mediaType":"text/plain","selection":"body","body":descriptor}]}}});
        let response = state.protocol(&notification).unwrap();
        state
            .validation
            .core
            .validate("intercept-response", &response)
            .unwrap();
        state.auth["auth"]["scope"] = json!("other-principal");
        assert!(state.protocol(&notification).is_err());
        state.auth["auth"]["scope"] = json!("body");
        notification["params"]["event"]["items"][0]["body"]["size"] = json!(1);
        assert!(state.protocol(&notification).is_err());
        assert_eq!(
            state
                .data
                .lock()
                .unwrap()
                .entries
                .iter()
                .filter(|e| e["kind"] == "observed")
                .count(),
            1
        );
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;
    fn request() -> Value {
        json!({"jsonrpc":"2.0","id":"hardening","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"hardening","source":"urn:rust:test","type":"tool.before","time":"2026-09-01T00:00:00Z","session":{"id":"s"},"call":{"id":"c"},"path":"native","tool":{"origin":"native","name":"task","kind":"task","input":{"value":"original"}}},"capabilities":interop::capabilities()}})
    }
    fn response(value: &str) -> Value {
        json!({"jsonrpc":"2.0","id":"hardening","result":{"protocolVersion":"draft","effects":[{"type":"modify","target":"input","operation":"replace","value":{"value":value}},{"type":"message","text":value}]}})
    }
    fn server() -> ServerState {
        ServerState {
            data: Mutex::new(Shared::default()),
            changed: Condvar::new(),
            validation: Validation::new(&json!({})).unwrap(),
            responses: BTreeMap::new(),
            sequences: BTreeMap::new(),
            stdio: false,
            stdout_order: Mutex::new(()),
            upload: json!({"anonymous":true,"subscriptions":["body"]}),
            auth: json!({"auth":{"mode":"none"}}),
            catalogue: false,
        }
    }
    #[test]
    fn cancellation_between_evaluation_and_publication_cannot_be_overwritten() {
        let shared = Arc::new(Mutex::new((
            Boundary::default(),
            json!({"published":[],"states":{}}),
        )));
        let staged = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let worker_state = shared.clone();
        let worker_staged = staged.clone();
        let worker_resume = resume.clone();
        let worker = thread::spawn(move || {
            let schemas = Schemas::bundled().unwrap();
            let evaluated =
                evaluator::apply(&request(), &response("must-not-publish"), &schemas).unwrap();
            worker_staged.wait();
            worker_resume.wait();
            let mut guard = worker_state.lock().unwrap();
            let (boundary, actual) = &mut *guard;
            publish("hardening", boundary, evaluated, actual);
        });
        staged.wait();
        assert!(shared.lock().unwrap().0.cancel());
        resume.wait();
        worker.join().unwrap();
        let guard = shared.lock().unwrap();
        assert_eq!(guard.0.terminal, Some("cancelled"));
        assert_eq!(guard.1, json!({"published":[],"states":{}}));
        let event = settled_view(&request(), &guard.0, None, &json!("metadata"), None).unwrap();
        assert_eq!(event, request()["params"]["event"]);
    }
    #[test]
    fn upload_sender_omitted_auth_never_inherits_event_credentials() {
        let receiver = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", receiver.server_addr());
        let capture = thread::spawn(move || {
            let mut captured = Vec::new();
            for _ in 0..3 {
                let mut req = receiver
                    .recv_timeout(TIMEOUT)
                    .unwrap()
                    .expect("sender never reached capture receiver");
                let path = req.url().to_owned();
                let authorization = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .map(|h| h.value.as_str().to_owned());
                let mut bytes = Vec::new();
                req.as_reader().read_to_end(&mut bytes).unwrap();
                captured.push((path.clone(), authorization, bytes));
                let response = if path.starts_with("/upload?") {
                    tiny_http::Response::from_string("").with_status_code(204)
                } else {
                    tiny_http::Response::from_string(if path == "/receipts" {
                        "{\"entries\":[]}"
                    } else {
                        "{}"
                    })
                    .with_status_code(200)
                };
                req.respond(response.with_header(
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                ))
                .unwrap();
            }
            captured
        });
        let directory =
            std::env::temp_dir().join(format!("rust-upload-isolation-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let fixture = directory.join("scenario.json");
        let report = directory.join("report.json");
        let bytes = vec![0, 255, 10];
        write(fixture.to_str().unwrap(),&json!({"scenarios":[{"id":"sender-isolation","requests":{},"responses":{},"steps":[{"op":"upload","subscription":"body","ref":"isolation","bodyBase64":base64::engine::general_purpose::STANDARD.encode(&bytes),"size":bytes.len(),"sha256":sha256(&bytes)}]}]})).unwrap();
        let config = json!({"transport":"http","auth":{"mode":"bearer","token":"TEST-EVENT-CREDENTIAL"},"endpoint":endpoint,"controlEndpoint":endpoint,"upload":{"endpoint":format!("{endpoint}/upload?separate=1"),"timeoutMs":5000,"maxBytes":128},"scenarioFile":fixture,"reportFile":report});
        let notification = json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":request()["params"]["event"]}});
        Validation::new(&config)
            .unwrap()
            .observe(&notification)
            .unwrap();
        Transport::new(&config)
            .unwrap()
            .observe(&notification)
            .unwrap();
        client(&config).unwrap();
        let captured = capture.join().unwrap();
        assert_eq!(captured[0].0, "/observe");
        assert_eq!(
            captured[0].1.as_deref(),
            Some("Bearer TEST-EVENT-CREDENTIAL")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&captured[0].2).unwrap(),
            notification
        );
        assert_eq!(captured[1].0, "/upload?separate=1");
        assert!(
            captured[1].1.is_none(),
            "event credential leaked to upload receiver"
        );
        assert_eq!(captured[1].2, bytes);
        assert_eq!(
            read(report.to_str().unwrap()).unwrap()["results"][0]["actual"]["uploadStatuses"],
            json!([204])
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn first_valid_retained_response_wins_before_acceptance() {
        let schemas = Schemas::bundled().unwrap();
        let mut boundary = Boundary::default();
        let first = response("first");
        let different = response("different");
        schemas.validate("intercept-response", &first).unwrap();
        schemas.validate("intercept-response", &different).unwrap();
        assert!(boundary.retain(first));
        assert!(!boundary.retain(different));
        let state =
            evaluator::apply(&request(), &boundary.staged.take().unwrap(), &schemas).unwrap();
        let mut actual = json!({"published":[],"states":{}});
        publish("hardening", &mut boundary, state, &mut actual);
        assert_eq!(
            actual["states"]["hardening"]["input"],
            json!({"value":"first"})
        );
        assert_eq!(actual["states"]["hardening"]["messages"], json!(["first"]));
    }
    #[test]
    fn cancel_after_accept_preserves_effective_input_and_control_decision() {
        let schemas = Schemas::bundled().unwrap();
        let mut boundary = Boundary::default();
        let state = evaluator::apply(&request(), &response("published"), &schemas).unwrap();
        let mut actual = json!({"published":[],"states":{}});
        publish("hardening", &mut boundary, state, &mut actual);
        assert!(boundary.cancel());
        assert!(!boundary.cancel());
        assert!(!boundary.retain(response("late")));
        let original = actual.clone();
        publish(
            "hardening",
            &mut boundary,
            json!({"input":"wrong"}),
            &mut actual,
        );
        assert_eq!(actual, original);
        let event = settled_view(
            &request(),
            &boundary,
            actual["states"].get("hardening"),
            &json!("metadata"),
            None,
        )
        .unwrap();
        assert_eq!(event["tool"]["input"], json!({"value":"published"}));
        assert!(event.get("decision").is_none());
        assert!(event.get("interrupted").is_none());
        let _event = settled_view(&request(), &boundary, None, &json!("metadata"), None).unwrap();
    }
    #[test]
    fn server_sequence_uses_attempt_occurrence_then_falls_back() {
        let mut server = server();
        server
            .responses
            .insert("hardening".into(), response("fallback"));
        server.sequences.insert(
            "hardening".into(),
            vec![response("first"), response("second")],
        );
        server
            .control("/release", &json!({"id":"hardening"}))
            .unwrap();
        for expected in ["first", "second", "fallback"] {
            assert_eq!(server.protocol(&request()).unwrap(), response(expected));
        }
        let data = server.data.lock().unwrap();
        assert_eq!(
            data.entries
                .iter()
                .filter(|e| e["kind"] == "received")
                .count(),
            3
        );
        assert_eq!(
            data.entries
                .iter()
                .filter(|e| e["kind"] == "replied")
                .count(),
            3
        );
        drop(data);
        assert_eq!(
            server
                .control("/emit", &json!({"response":response("not-stdio")}))
                .unwrap()
                .0,
            400
        );
    }
    #[test]
    fn receiver_allocates_references_and_rejects_same_size_wrong_hash() {
        let server = server();
        let upload = json!({"ref":"caller-ref","sha256":sha256(b"abc"),"text":"abc"});
        let (status, descriptor) = test_upload(&server, &upload).unwrap();
        assert_eq!(status, 201);
        assert_ne!(descriptor["ref"], upload["ref"]);
        let mut bad = upload.clone();
        bad["text"] = json!("def");
        assert_eq!(test_upload(&server, &bad).unwrap().0, 400);
        assert_eq!(test_upload(&server, &upload).unwrap().0, 201);
        assert_eq!(server.data.lock().unwrap().uploads.len(), 2);
        assert_eq!(
            server.data.lock().unwrap().uploads[&("body".into(), s(&descriptor, "ref").into())],
            b"abc"
        );
    }
    #[test]
    fn confirmation_requires_201_canonical_json_and_exact_bytes() {
        let bytes = b"abc";
        let descriptor = json!({"ref":"allocated", "size":3,"sha256":sha256(bytes)});
        let cases = [
            (201, "application/json", descriptor.to_string(), true),
            (201, "application/json", "{}".into(), false),
            (201, "application/json", "not json".into(), false),
            (201, "text/plain", descriptor.to_string(), false),
            (
                201,
                "application/json",
                json!({"ref":"", "size":3,"sha256":sha256(bytes)}).to_string(),
                false,
            ),
            (
                201,
                "application/json",
                json!({"ref":"allocated", "size":4,"sha256":sha256(bytes)}).to_string(),
                false,
            ),
            (
                201,
                "application/json",
                json!({"ref":"allocated", "size":3,"sha256":sha256(b"def")}).to_string(),
                false,
            ),
            (
                201,
                "application/json",
                json!({"ref":"allocated", "size":3,"sha256":sha256(bytes),"extra":true})
                    .to_string(),
                false,
            ),
            (202, "application/json", descriptor.to_string(), false),
            (204, "application/json", String::new(), false),
            (302, "application/json", descriptor.to_string(), false),
        ];
        for (status, media_type, body, confirmed) in cases {
            let receiver = tiny_http::Server::http("127.0.0.1:0").unwrap();
            let endpoint =
                reqwest::Url::parse(&format!("http://{}/upload", receiver.server_addr())).unwrap();
            let capture = thread::spawn(move || {
                let mut request = receiver.recv_timeout(TIMEOUT).unwrap().unwrap();
                assert!(
                    !request
                        .headers()
                        .iter()
                        .any(|h| h.field.equiv("AHP-Subscription")
                            || h.field.equiv("AHP-Content-Ref")
                            || h.field.equiv("Authorization"))
                );
                let mut sent = Vec::new();
                request.as_reader().read_to_end(&mut sent).unwrap();
                assert_eq!(sent, b"abc");
                request
                    .respond(
                        tiny_http::Response::from_string(body)
                            .with_status_code(status)
                            .with_header(
                                tiny_http::Header::from_bytes("Content-Type", media_type).unwrap(),
                            ),
                    )
                    .unwrap();
            });
            let result = send_upload(
                &endpoint,
                &json!({"subscription":"untrusted","ref":"caller-chosen"}),
                bytes,
                None,
                TIMEOUT,
            );
            let returned = result.ok().and_then(|(_, descriptor)| descriptor);
            assert_eq!(returned.is_some(), confirmed, "status {status}");
            if confirmed {
                assert_eq!(returned.unwrap(), descriptor);
            }
            capture.join().unwrap();
        }
    }
    #[test]
    fn descriptor_alias_replacement_preserves_negative_metadata() {
        let descriptor = json!({"ref":"receiver-ref", "size":3, "sha256":sha256(b"abc")});
        let aliases = BTreeMap::from([("fixture-alias".into(), descriptor.clone())]);
        let uploads = BTreeMap::from([(("body".into(), "receiver-ref".into()), b"abc".to_vec())]);
        let mut event = json!({"body":{"ref":"fixture-alias","size":3,"sha256":sha256(b"abc")}});
        replace_references(&mut event, &aliases);
        assert_eq!(event["body"], descriptor);
        assert!(resolve_bodies(&event, "body", &uploads).is_ok());
        event["body"]["ref"] = json!("fixture-alias");
        event["body"]["size"] = json!(0);
        replace_references(&mut event, &aliases);
        assert!(resolve_bodies(&event, "body", &uploads).is_err());
    }
    #[test]
    fn receiver_preserves_framing_and_authorization_negatives() {
        let mut receiver = server();
        let headers = vec![
            ("Content-Type".into(), "application/octet-stream".into()),
            ("Content-Length".into(), "3".into()),
            ("AHP-Content-SHA256".into(), sha256(b"abc")),
        ];
        assert_eq!(receiver.receive_upload("POST", &headers, b"abc").0, 201);
        assert_eq!(receiver.receive_upload("GET", &headers, b"abc").0, 400);
        assert_eq!(receiver.receive_upload("POST", &headers, b"ab").0, 400);
        assert_eq!(receiver.receive_upload("POST", &headers, b"def").0, 400);
        for (key, value) in [
            ("Content-Length", "3"),
            ("Content-Encoding", "gzip"),
            ("Transfer-Encoding", "chunked"),
        ] {
            let mut invalid = headers.clone();
            invalid.push((key.into(), value.into()));
            assert_eq!(receiver.receive_upload("POST", &invalid, b"abc").0, 400);
        }
        let mut oversized = headers.clone();
        oversized[1].1 = "1048577".into();
        assert_eq!(receiver.receive_upload("POST", &oversized, b"").0, 413);
        receiver.upload = json!({"token":"TEST-UPLOAD-ONLY"});
        assert_eq!(receiver.upload_scope(), receiver.event_scope());
        receiver.upload["scope"] = json!("tenant-a");
        assert_eq!(receiver.receive_upload("POST", &headers, b"abc").0, 401);
        let mut authorized = headers;
        authorized.push(("Authorization".into(), "Bearer TEST-UPLOAD-ONLY".into()));
        let (status, descriptor) = receiver.receive_upload("POST", &authorized, b"abc");
        assert_eq!(status, 201);
        let event = json!({"id":"caller-selected", "source":"urn:caller", "body":descriptor});
        let data = receiver.data.lock().unwrap();
        assert!(resolve_bodies(&event, "tenant-a", &data.uploads).is_ok());
        assert!(resolve_bodies(&event, "tenant-b", &data.uploads).is_err());
        let mut changed_id = event.clone();
        changed_id["id"] = json!("unrelated-correlation");
        assert!(resolve_bodies(&changed_id, "tenant-a", &data.uploads).is_ok());
        let mut metadata_mismatch = event.clone();
        metadata_mismatch["size"] = json!(0);
        assert!(resolve_bodies(&metadata_mismatch, "tenant-a", &data.uploads).is_err());
        assert!(
            !serde_json::to_string(&data.entries)
                .unwrap()
                .contains("TEST-UPLOAD-ONLY")
        );
        drop(data);
        receiver.upload["scope"] = json!("");
        assert_eq!(receiver.receive_upload("POST", &authorized, b"abc").0, 403);
    }
    #[cfg(unix)]
    #[test]
    fn child_pid_metadata_precedes_readiness_and_failure_reaps_child() {
        let directory =
            std::env::temp_dir().join(format!("rust-lifecycle-pid-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let pid_file = directory.join("child.json");
        // Force failure after spawn/metadata but before readiness. The spawned
        // process cannot exit naturally during this check; Drop must reap it.
        let config = json!({"transport":"stdio","serverCommand":["/bin/sh","-c","exec sleep 60"],"serverConfig":directory.join("unused.json"),"schemaDir":directory.join("missing-schema"),"childPidFile":pid_file});
        assert!(Transport::new(&config).is_err());
        let metadata = read(pid_file.to_str().unwrap()).unwrap();
        let pid = metadata["pid"].as_i64().unwrap() as i32;
        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        assert_eq!(unsafe { kill(pid, 0) }, -1, "spawned child still exists");
        fs::remove_dir_all(directory).unwrap();
    }
}
