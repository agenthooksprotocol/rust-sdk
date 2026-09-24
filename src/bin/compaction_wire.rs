//! Canonical hooks/intercept and preuploaded bodies; no scheduling wire method.
use agent_hooks_protocol::{
    compaction::{CompactionHook, run_compaction},
    interop::Schemas,
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    fs,
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn location(store: &str, sub: &str, reference: &str) -> PathBuf {
    Path::new(store).join(sha256(format!("{sub}\0{reference}").as_bytes()))
}
fn receive(request: &Value, sub: &str, config: &Value, store: &str, schemas: &Schemas) -> Value {
    let process = || -> Result<Value> {
        schemas.validate("intercept-request", request)?;
        let event = &request["params"]["event"];
        let mut items = event["items"].as_array().cloned().unwrap_or_default();
        for key in ["instructions", "summary"] {
            if let Some(item) = event.get(key) {
                items.push(item.clone());
            }
        }
        let mut bodies = json!({});
        for item in items {
            let reference = &item["body"];
            let raw = fs::read(location(
                store,
                sub,
                reference["ref"].as_str().ok_or("reference")?,
            ))?;
            if reference["size"].as_u64() != Some(raw.len() as u64)
                || reference["sha256"] != sha256(&raw)
            {
                return Err("integrity".into());
            }
            bodies[item["id"].as_str().ok_or("item id")?] = json!(String::from_utf8(raw)?);
        }
        let action = &config[sub];
        if action.is_null() {
            return Err("subscription".into());
        }
        let effects = if action["kind"] == "append" {
            let target = action["target"].as_str().ok_or("target")?;
            let body = bodies[event[target]["id"].as_str().ok_or("item")?]
                .as_str()
                .ok_or("body")?;
            json!([{"type":"modify","target":target,"operation":"replace","value":format!("{}{}",body,action["suffix"].as_str().ok_or("suffix")?)}])
        } else {
            action["effects"].clone()
        };
        let response = json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":effects}});
        schemas.validate("intercept-response", &response)?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(Path::new(store).join("receipts.jsonl"))?;
        writeln!(
            file,
            "{}",
            json!({"subscription":sub,"request":request,"response":response,"bodies":bodies})
        )?;
        Ok(response)
    };
    process().unwrap_or_else(|_|json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32602,"message":"Invalid compaction request"}}))
}
fn item(
    client: &reqwest::blocking::Client,
    plan: &Value,
    sub: &str,
    id: &str,
    kind: &str,
    text: &str,
    role: &str,
) -> Result<Value> {
    let raw = text.as_bytes();
    let hash = sha256(raw);

    // The harness base endpoint is shorthand only; an explicit upload endpoint is exact.
    let endpoint = plan["uploadEndpoint"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or(format!(
            "{}/upload",
            plan["endpoint"].as_str().ok_or("endpoint")?
        ));
    let r = client
        .post(endpoint)
        .bearer_auth(
            plan["credentials"][sub]["uploadToken"]
                .as_str()
                .ok_or("upload token")?,
        )
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", raw.len())
        .header("AHP-Content-SHA256", &hash)
        .body(raw.to_vec())
        .send()?;
    if r.status().as_u16() != 201
        || r.headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap().trim())
            != Some("application/json")
    {
        return Err("upload unavailable".into());
    }
    let descriptor: Value = r.json()?;
    if descriptor.as_object().is_none_or(|m| m.len() != 3)
        || descriptor["ref"].as_str().is_none_or(str::is_empty)
        || descriptor["size"].as_u64() != Some(raw.len() as u64)
        || descriptor["sha256"] != hash
    {
        return Err("upload confirmation integrity".into());
    }
    Ok(
        json!({"id":id,"kind":kind,"mediaType":"text/plain","role":role,"selection":"body","body":descriptor}),
    )
}
fn exchange(
    client: &reqwest::blocking::Client,
    plan: &Value,
    sub: &str,
    name: &str,
    snapshot: &Value,
    schemas: &Schemas,
    trace: &RefCell<Vec<Value>>,
) -> Result<Vec<Value>> {
    let boundary = snapshot["boundary"].as_str().ok_or("boundary")?;
    let mut event = json!({"id":format!("{name}:{boundary}"),"source":"urn:ahp:compaction-host","time":"2026-09-15T12:00:00Z","session":{"id":name},"type":format!("context.compact.{boundary}")});
    if boundary == "before" {
        event["trigger"] = json!("manual");
        event["items"] = json!([item(
            client,
            plan,
            sub,
            &format!("{name}:context"),
            "user",
            "conversation",
            "user"
        )?]);
        event["instructions"] = item(
            client,
            plan,
            sub,
            &format!("{name}:instructions"),
            "instructions",
            snapshot["instructions"].as_str().ok_or("instructions")?,
            "system",
        )?;
    } else {
        let handle = &snapshot["summary"];
        let body = snapshot["bodies"][handle["ref"].as_str().ok_or("reference")?]
            .as_str()
            .ok_or("body")?;
        event["summary"] = item(
            client,
            plan,
            sub,
            handle["id"].as_str().ok_or("id")?,
            "summary",
            body,
            "assistant",
        )?;
        event["parentEventId"] = json!(format!("{name}:before"));
        event["removed"] = json!([{"id":format!("{name}:context")}]);
        event["execution"] = if snapshot["candidate"].is_null() {
            json!({"status":"executed"})
        } else {
            json!({"status":"skipped","reason":"supplied_result"})
        };
    }
    let request = json!({"jsonrpc":"2.0","id":event["id"],"method":"hooks/intercept","params":{"protocolVersion":"draft","event":event,"capabilities":snapshot["capabilities"]}});
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
        .borrow_mut()
        .push(json!({"subscription":sub,"request":request,"response":response}));
    schemas.validate("intercept-response", &response)?;
    if request["id"] != response["id"] {
        return Err("correlation".into());
    }
    Ok(response["result"]["effects"]
        .as_array()
        .ok_or("effects")?
        .clone())
}
fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if !["host", "server", "stdio"].contains(&args[0].as_str()) {
        let mode = args.remove(3);
        args.insert(0, mode);
    }
    if args[0] == "host" {
        let plan: Value = serde_json::from_reader(io::stdin())?;
        let schemas = Schemas::load(Path::new(plan["schema"].as_str().ok_or("schema")?))?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(20))
            .build()?;
        let mut out = vec![];
        for row in plan["cases"].as_array().ok_or("cases")? {
            let name = row["name"].as_str().ok_or("name")?;
            let trace = RefCell::new(vec![]);
            let callbacks = |boundary: &str| {
                row[boundary]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|h| {
                        let sub = h["supplier"].as_str().unwrap();
                        let (client, plan, schemas, trace) = (&client, &plan, &schemas, &trace);
                        move |snapshot: &Value| {
                            exchange(client, plan, sub, name, snapshot, schemas, trace)
                                .map_err(|e| e.to_string())
                        }
                    })
                    .collect::<Vec<_>>()
            };
            let before_callbacks = callbacks("before");
            let after_callbacks = callbacks("after");
            let before: Vec<_> = row["before"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&before_callbacks)
                .map(|(h, run)| CompactionHook {
                    supplier: h["supplier"].as_str().unwrap(),
                    failure_policy: h["failurePolicy"].as_str().unwrap(),
                    run,
                })
                .collect();
            let after: Vec<_> = row["after"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&after_callbacks)
                .map(|(h, run)| CompactionHook {
                    supplier: h["supplier"].as_str().unwrap(),
                    failure_policy: h["failurePolicy"].as_str().unwrap(),
                    run,
                })
                .collect();
            let result = run_compaction(
                "base",
                &format!("{name}:summary"),
                &before,
                &after,
                None,
                false,
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let mut downstream = vec![];
            if result["applied"] == true {
                downstream
                    .push(result["bodies"][result["summary"]["ref"].as_str().unwrap()].clone());
            }
            out.push(json!({"name":name,"result":result,"trace":trace.into_inner(),"downstream":downstream}));
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
    for mut request in server.incoming_requests() {
        let upload = request.url() == "/upload";
        let tokens: Value = serde_json::from_str(&std::env::var(if upload {
            "AHP_COMPACTION_UPLOAD_TOKENS"
        } else {
            "AHP_COMPACTION_TOKENS"
        })?)?;
        if request
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
            request.respond(tiny_http::Response::empty(401))?;
            continue;
        }
        let header = |name: &str| {
            request
                .headers()
                .iter()
                .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
                .map(|h| h.value.as_str().to_owned())
                .unwrap_or_default()
        };
        let authorization = header("Authorization");
        let sub = authorization
            .strip_prefix("Bearer ")
            .and_then(|token| tokens[token].as_str());
        let Some(sub) = sub.filter(|s| !s.is_empty()) else {
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
        let hash = header("AHP-Content-SHA256");
        let content_type = header("Content-Type");
        let length = header("Content-Length").parse::<usize>().ok();
        let encoded =
            !header("Content-Encoding").is_empty() || !header("Transfer-Encoding").is_empty();
        let mut raw = vec![];
        request
            .as_reader()
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut raw)?;
        if raw.len() > 4 * 1024 * 1024 {
            request.respond(tiny_http::Response::empty(413))?;
            continue;
        }
        if upload {
            if content_type != "application/octet-stream"
                || encoded
                || length != Some(raw.len())
                || hash != sha256(&raw)
            {
                request.respond(tiny_http::Response::empty(400))?;
                continue;
            }
            let (reference, mut file) = loop {
                let reference = format!(
                    "urn:ahp:upload:{}:{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_nanos()
                );
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(location(store, sub, &reference))
                {
                    Ok(file) => break (reference, file),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e.into()),
                }
            };
            file.write_all(&raw)?;
            request.respond(
                tiny_http::Response::from_string(
                    json!({"ref":reference,"size":raw.len(),"sha256":hash}).to_string(),
                )
                .with_status_code(201)
                .with_header(
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                ),
            )?;
        } else {
            let value: Value = match serde_json::from_slice(&raw) {
                Ok(v) => v,
                Err(_) => {
                    request.respond(tiny_http::Response::empty(400))?;
                    continue;
                }
            };
            let response = receive(&value, sub, &config, store, &schemas);
            request.respond(tiny_http::Response::from_string(response.to_string()))?;
        }
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
