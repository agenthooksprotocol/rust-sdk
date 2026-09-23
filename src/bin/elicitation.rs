//! Offline actual HTTP wire sender/receiver; no expected-based behavior.
use agent_hooks_protocol::{
    elicitation::{apply_effects, read_selected, validate_exchange, validate_mode},
    interop::Result,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    path::Path,
};
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
                localize(x, file)
            }
        }
        Value::Array(a) => {
            for x in a {
                localize(x, file)
            }
        }
        _ => {}
    }
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
                r = r.bearer_auth(plan["token"].as_str().ok_or("token")?);
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
    let mut files = serde_json::Map::new();
    for entry in fs::read_dir(Path::new(&args[2]))? {
        let p = entry?.path();
        if !p.to_string_lossy().ends_with(".schema.json") {
            continue;
        }
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        let mut s: Value = serde_json::from_slice(&fs::read(&p)?)?;
        localize(&mut s, &name);
        files.insert(name, s);
    }
    let mut validators = BTreeMap::new();
    for name in [
        "intercept-request",
        "content-reference",
        "content-item",
        "effect",
        "mcp-elicitation#request",
        "mcp-elicitation#result",
    ] {
        let (file, def) = name.split_once('#').unwrap_or((name, ""));
        let reference = format!(
            "#/$defs/files/{file}.schema.json{}",
            if def.is_empty() {
                String::new()
            } else {
                format!("/$defs/{def}")
            }
        );
        let s = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":reference,"$defs":{"files":files}});
        validators.insert(
            name,
            jsonschema::options()
                .should_validate_formats(true)
                .build(&s)?,
        );
    }
    let validate = |name: &str, value: &Value| -> Result<()> {
        if name == "form-answer" {
            jsonschema::options()
                .should_validate_formats(true)
                .build(&value["schema"])?
                .validate(&value["value"])
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
        validators
            .get(name)
            .ok_or("schema")?
            .validate(value)
            .map_err(|e| e.to_string())?;
        Ok(())
    };
    let token = std::env::var("AHP_ELICITATION_TOKEN")?;
    // Upload authorization is independently configured; event credentials are
    // never an implicit fallback for this resource.
    let upload_token = std::env::var("AHP_ELICITATION_UPLOAD_TOKEN").unwrap_or_default();
    let principal = &args[3];
    if token.is_empty() || principal.is_empty() {
        return Err("Missing auth".into());
    }
    let mut store: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut pending: BTreeMap<(String, String), Value> = BTreeMap::new();
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
            let resolve = |reference: &Value| -> Result<Vec<u8>> {
                validate("content-reference", reference)?;
                let b = store
                    .get(reference["ref"].as_str().ok_or("ref")?)
                    .ok_or("missing")?;
                if reference["size"].as_u64() != Some(b.len() as u64)
                    || reference["sha256"] != sha256(b)
                {
                    return Err("integrity".into());
                }
                Ok(b.clone())
            };
            let before = c.clone();
            let checked = match c["op"].as_str() {
                Some("capability") => validate_mode(
                    c["mode"].as_str().unwrap_or(""),
                    c.get("capabilities"),
                    c["origin"].as_str().unwrap_or("ahp"),
                ),
                Some("apply") => apply_effects(
                    &c["request"],
                    c.get("result").filter(|x| !x.is_null()),
                    resolve,
                    validate,
                    principal,
                    c["effects"].as_array().ok_or("effects")?,
                ),
                _ => validate_exchange(
                    &c["request"],
                    &c["result"],
                    resolve,
                    validate,
                    principal,
                    c.get("effect"),
                ),
            };
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
        let header = |name: &str| {
            incoming
                .headers()
                .iter()
                .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
                .map(|h| h.value.as_str().to_string())
                .unwrap_or_default()
        };
        let expected_token = if incoming.url() == "/upload" {
            &upload_token
        } else {
            &token
        };
        if expected_token.is_empty()
            || header("Authorization") != format!("Bearer {expected_token}")
        {
            incoming.respond(tiny_http::Response::empty(401))?;
            continue;
        }
        let path = incoming.url().to_string();
        let length = header("Content-Length").parse::<usize>().ok();
        let content_type = header("Content-Type");
        let encoded =
            !header("Content-Encoding").is_empty() || !header("Transfer-Encoding").is_empty();
        let digest = header("AHP-Content-SHA256");
        let mut raw = vec![];
        incoming.as_reader().take(4194305).read_to_end(&mut raw)?;
        let operation = (|| -> Result<(u16, Value)> {
            if raw.len() > 4194304 {
                return Ok((413, json!({"error":"size limit"})));
            }
            if path == "/upload" {
                if incoming.method() != &tiny_http::Method::Post
                    || encoded
                    || content_type != "application/octet-stream"
                    || length != Some(raw.len())
                    || sha256(&raw) != digest
                {
                    return Err("Upload integrity".into());
                }
                let reference = format!("urn:ahp:upload:{}", store.len());
                let descriptor = json!({"ref":reference,"size":raw.len(),"sha256":digest});
                store.insert(reference, raw);
                return Ok((201, descriptor));
            }
            if path == "/receipts" {
                return Ok((200, json!(receipts)));
            }
            if path != "/hooks/intercept" {
                return Err("Unknown endpoint".into());
            }
            let resolve = |reference: &Value| -> Result<Vec<u8>> {
                validate("content-reference", reference)?;
                let b = store
                    .get(reference["ref"].as_str().ok_or("ref")?)
                    .ok_or("Missing upload")?;
                if reference["size"].as_u64() != Some(b.len() as u64)
                    || reference["sha256"] != sha256(b)
                {
                    return Err("Upload integrity".into());
                }
                Ok(b.clone())
            };
            let message: Value = serde_json::from_slice(&raw)?;
            validate("intercept-request", &message)?;
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
                    let payload = read_selected(meta, "request", &resolve, &validate)?;
                    let body = if payload.is_some() {
                        resolve(&meta["request"]["body"])?
                    } else {
                        vec![]
                    };
                    let summary = match payload {
                        Some(payload) => json!({"request":payload}),
                        None => {
                            json!({"selection":meta["request"]["selection"].as_str().unwrap_or("omit")})
                        }
                    };
                    pending.insert(key.clone(), message.clone());
                    (body, summary)
                }
                Some("user.elicitation.result") => {
                    let request = pending.get(&key).ok_or("No pending elicitation")?;
                    let summary =
                        validate_exchange(request, &message, resolve, validate, principal, None)?;
                    let body = if meta["result"].get("body").is_some() {
                        resolve(&meta["result"]["body"])?
                    } else {
                        vec![]
                    };
                    pending.remove(&key);
                    (body, summary)
                }
                _ => return Err("Not elicitation".into()),
            };
            receipts
                .push(json!({"message":message,"bytes":STANDARD.encode(body),"summary":summary}));
            Ok((
                200,
                json!({"jsonrpc":"2.0","id":message["id"],"result":{"protocolVersion":"draft","effects":[]}}),
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
