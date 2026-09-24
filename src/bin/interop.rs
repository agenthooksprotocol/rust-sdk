use agent_hooks_protocol::interop::{self, Result, Schemas};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
fn read(path: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn string<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}
fn atomic(path: &str, v: &Value) -> Result<()> {
    let temp = format!("{path}.{}.tmp", std::process::id());
    fs::write(&temp, serde_json::to_vec(v)?)?;
    fs::rename(temp, path)?;
    Ok(())
}
fn schema(c: &Value) -> Result<Schemas> {
    match c["schemaDir"].as_str() {
        Some(path) => Schemas::load(Path::new(path)),
        None => Schemas::bundled(),
    }
}
fn scenarios(c: &Value) -> Result<Vec<Value>> {
    read(string(c, "scenarioFile"))?["scenarios"]
        .as_array()
        .cloned()
        .ok_or_else(|| "missing scenarios".into())
}
fn authenticate(c: &Value, header: &str) -> bool {
    let a = &c["auth"];
    match string(a, "mode") {
        "" | "none" => true,
        "bearer" => {
            !string(a, "token").is_empty() && header == format!("Bearer {}", string(a, "token"))
        }
        "oauth" | "workload" => {
            if ["signingKey", "issuer", "audience", "purpose"]
                .iter()
                .any(|key| string(a, key).is_empty())
            {
                return false;
            }
            let Some(token) = header.strip_prefix("Bearer ") else {
                return false;
            };
            let mut val = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
            val.validate_exp = false;
            val.validate_nbf = false;
            val.set_issuer(&[string(a, "issuer")]);
            val.set_audience(&[string(a, "audience")]);
            match jsonwebtoken::decode::<Value>(
                token,
                &jsonwebtoken::DecodingKey::from_secret(string(a, "signingKey").as_bytes()),
                &val,
            ) {
                Ok(data) => {
                    let clock = a["clock"].as_i64().unwrap_or(1893456000);
                    data.claims["purpose"] == a["purpose"]
                        && data.claims["exp"].as_i64().is_some_and(|exp| exp > clock)
                        && data.claims["nbf"].as_i64().is_none_or(|nbf| nbf <= clock)
                        && data.claims["iat"].as_i64().is_none_or(|iat| iat <= clock)
                }
                Err(_) => false,
            }
        }
        _ => false,
    }
}
fn successful(response: reqwest::blocking::Response) -> Result<reqwest::blocking::Response> {
    if !response.status().is_success() {
        return Err("HTTP response status is not successful".into());
    }
    Ok(response)
}
fn http_client(c: &Value) -> Result<(reqwest::blocking::Client, String)> {
    let a = &c["auth"];
    let mut builder = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15));
    if string(a, "mode") == "mtls" {
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&fs::read(
            string(a, "caFile"),
        )?)?);
        let mut identity = fs::read(string(a, "certFile"))?;
        identity.extend(fs::read(string(a, "keyFile"))?);
        builder = builder.identity(reqwest::Identity::from_pem(&identity)?);
    }
    let client = builder.build()?;
    let token = match string(a, "mode") {
        "" | "none" | "mtls" => String::new(),
        "bearer" => string(a, "token").into(),
        "workload" => string(a, "assertion").into(),
        "oauth" => {
            let response: Value = successful(
                client
                    .post(string(a, "tokenEndpoint"))
                    .form(&[
                        ("grant_type", "client_credentials"),
                        ("client_id", string(a, "clientId")),
                        ("client_secret", string(a, "clientSecret")),
                        ("audience", string(a, "audience")),
                    ])
                    .send()?,
            )?
            .json()?;
            response["access_token"]
                .as_str()
                .ok_or("missing access token")?
                .to_string()
        }
        _ => return Err("unsupported auth mode".into()),
    };
    Ok((client, token))
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Peer {
    _child: Process,
    input: Option<std::process::ChildStdin>,
    lines: std::sync::mpsc::Receiver<std::io::Result<String>>,
}
impl Peer {
    fn start(c: &Value) -> Result<Self> {
        let args = c["serverCommand"]
            .as_array()
            .ok_or("serverCommand missing")?;
        let mut command = Command::new(
            args.first()
                .and_then(Value::as_str)
                .ok_or("empty command")?,
        );
        for arg in &args[1..] {
            command.arg(arg.as_str().ok_or("bad command argument")?);
        }
        command.args(["--config", string(c, "serverConfig")]);
        if let Some(cwd) = c["serverCwd"].as_str() {
            command.current_dir(cwd);
        }
        let mut child = Process(
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        let input = child.0.stdin.take().unwrap();
        let output = child.0.stdout.take().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            _child: child,
            input: Some(input),
            lines,
        })
    }
    fn call(&mut self, v: &Value) -> Result<Value> {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let result = (|| {
            let payload = serde_json::to_string(v)?;
            let mut input = self.input.take().ok_or("stdio peer unavailable")?;
            let (tx, written) = std::sync::mpsc::channel();
            // A peer may stop reading: never block the deadline owner on a pipe write.
            std::thread::spawn(move || {
                let result = writeln!(input, "{payload}").and_then(|_| input.flush());
                let _ = tx.send((input, result));
            });
            let (input, result) = written
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))?;
            result?;
            self.input = Some(input);
            let line = self
                .lines
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))??;
            let response = serde_json::from_str(&line)?;
            if std::time::Instant::now() >= deadline {
                return Err("stdio deadline exceeded".into());
            }
            Ok(response)
        })();
        if result.is_err() {
            // Unblock any writer and prevent late replies contaminating later calls.
            let _ = self._child.0.kill();
            let _ = self._child.0.wait();
            self.input = None;
        }
        result
    }
}
fn client(c: &Value) -> Result<bool> {
    let schemas = schema(c)?;
    let cases = scenarios(c)?;
    let stdio = string(c, "transport") == "stdio";
    if stdio && !["", "none"].contains(&string(&c["auth"], "mode")) {
        let results: Vec<_> = cases.iter().map(|s| json!({"id":s["id"],"status":"inapplicable","actual":null,"error":"stdio uses process trust"})).collect();
        atomic(
            string(c, "reportFile"),
            &json!({"language":"rust","results":results}),
        )?;
        return Ok(true);
    }
    let mut peer = if stdio { Some(Peer::start(c)?) } else { None };
    let (http, token) = http_client(c)?;
    let endpoint = string(c, "endpoint").trim_end_matches('/');
    let base = endpoint.strip_suffix("/intercept").unwrap_or(endpoint);
    let discovered = if let Some(peer) = &mut peer {
        let reply = peer.call(&json!({"jsonrpc":"2.0","id":"discovery","method":"hooks/capabilities","params":{"protocolVersion":"draft"}}))?;
        if reply["id"] != "discovery" || reply["jsonrpc"] != "2.0" {
            return Err("bad discovery envelope".into());
        }
        schemas.validate("capabilities-response", &reply)?;
        reply["result"]["manifest"]["events"]
            .as_array()
            .ok_or("missing discovery events")?
            .iter()
            .find(|event| event["event"] == "tool.before")
            .ok_or("tool.before not advertised")?["capabilities"]
            .clone()
    } else {
        successful(
            http.get(format!("{base}/capabilities"))
                .bearer_auth(&token)
                .send()?,
        )?
        .json()?
    };
    schemas.validate("capabilities", &discovered)?;
    let mut results = Vec::new();
    let mut passed = true;
    for s in cases {
        // Acquisition failures are never evidence of canonical response rejection.
        let outcome: Result<Result<Value>> = (|| {
            schemas.validate("intercept-request", &s["request"])?;
            let response = if let Some(peer) = &mut peer {
                peer.call(&s["request"])?
            } else {
                successful(
                    http.post(format!("{base}/intercept"))
                        .bearer_auth(&token)
                        .json(&s["request"])
                        .send()?,
                )?
                .json()?
            };
            Ok(interop::apply(&s["request"], &response, &schemas))
        })();
        let (ok, actual, error) = match outcome {
            Ok(Ok(actual)) => {
                let matches = s["expected"].as_object().is_some_and(|expected| {
                    expected
                        .iter()
                        .all(|(key, value)| actual.get(key) == Some(value))
                });
                (
                    matches && s["expectError"] != true,
                    actual,
                    if matches {
                        None
                    } else {
                        Some("expected application state mismatch")
                    },
                )
            }
            Ok(Err(_)) if s["expectError"] == true => (true, json!({"rejected":true}), None),
            Ok(Err(_)) | Err(_) => (
                false,
                Value::Null,
                Some("request, transport, or response validation failed"),
            ),
        };
        passed &= ok;
        let mut row =
            json!({"id":s["id"],"status":if ok {"passed"} else {"failed"},"actual":actual});
        if let Some(error) = error {
            row["error"] = json!(error);
        }
        results.push(row);
    }
    atomic(
        string(c, "reportFile"),
        &json!({"language":"rust","results":results}),
    )?;
    Ok(passed)
}
fn reply(
    request: &Value,
    cases: &[Value],
    schemas: &Schemas,
    receipts: &Mutex<Vec<Value>>,
    barriers: &(Mutex<Vec<String>>, Condvar),
) -> Result<Value> {
    if string(request, "method") == "hooks/capabilities" {
        schemas.validate("capabilities-request", request)?;
        let response = json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","manifest":{"transports":["http","stdio"],"authentication":["bearer","oauth","workload","mtls"],"toolPaths":["native"],"contentCategories":[],"limits":{"maxContinuations":2,"maxTimeoutMs":15000},"managedPolicy":{"scopes":["user"],"disableable":true},"correlationIdentityFields":["id","source","call.id"],"events":[{"event":"tool.before","modes":["intercept"],"capabilities":interop::capabilities()},{"event":"turn.finish.before","modes":["intercept"],"capabilities":{"effects":["flow","message"],"flow":{"operations":["stop","continue"],"remainingContinuations":2,"maxContinuations":2,"continuationCount":0}}},{"event":"task.change.before","modes":["intercept"],"capabilities":interop::capabilities_for("task.change.before")?},{"event":"workspace.change.before","modes":["intercept"],"capabilities":interop::capabilities_for("workspace.change.before")?}],"gaps":[{"path":"events.other","reason":"Synthetic adapter implements tool.before, turn.finish.before, task.change.before and workspace.change.before only"}]}}});
        schemas.validate("capabilities-response", &response)?;
        return Ok(response);
    }
    schemas.validate("intercept-request", request)?;
    if request["id"] != request["params"]["event"]["id"] {
        return Err("request id mismatch".into());
    }
    let case = cases
        .iter()
        .find(|s| s["id"] == request["params"]["event"]["id"])
        .ok_or("unknown scenario")?;
    // Test evidence preserves the exact canonical message, never transport credentials.
    receipts.lock().unwrap().push(json!({"id":request["id"],"method":request["method"],"eventId":request["params"]["event"]["id"],"message":request}));
    if let Some(barrier) = case["barrier"].as_str() {
        let (lock, cv) = barriers;
        let guard = lock.lock().unwrap();
        let (guard, _) = cv
            .wait_timeout_while(guard, Duration::from_secs(15), |released| {
                !released.iter().any(|s| s == barrier)
            })
            .unwrap();
        if !guard.iter().any(|s| s == barrier) {
            return Err("barrier deadline".into());
        }
    }
    // Negative fixtures intentionally bypass outgoing validation; clients must reject these.
    if case["expectError"] != true {
        schemas.validate("intercept-response", &case["response"])?;
    }
    Ok(case["response"].clone())
}
fn respond(request: tiny_http::Request, status: u16, body: Value) {
    let response = tiny_http::Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap());
    let _ = request.respond(response);
}
// Test-only TLS terminator: authenticates a client certificate before forwarding to the
// loopback HTTP implementation. The private bearer key protects that internal listener.
fn tls_frontend(
    c: &Value,
    upstream: String,
    secret: String,
    stop: Arc<AtomicBool>,
) -> Result<String> {
    use rustls::{
        RootCertStore, ServerConfig, ServerConnection, StreamOwned, server::WebPkiClientVerifier,
    };
    let a = &c["auth"];
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(fs::File::open(string(a, "caFile"))?)) {
        roots.add(cert?)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(fs::File::open(string(a, "certFile"))?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key =
        rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(string(a, "keyFile"))?))?
            .ok_or("missing private key")?;
    let config = Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?,
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("https://{}/intercept", listener.local_addr()?);
    listener.set_nonblocking(true)?;
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((socket, _)) => {
                    let config = config.clone();
                    let upstream = upstream.clone();
                    let secret = secret.clone();
                    std::thread::spawn(move || {
                        let result: Result<()> = (|| {
                            socket.set_nonblocking(false)?;
                            socket.set_read_timeout(Some(Duration::from_secs(15)))?;
                            socket.set_write_timeout(Some(Duration::from_secs(15)))?;
                            let mut stream = BufReader::new(StreamOwned::new(
                                ServerConnection::new(config)?,
                                socket,
                            ));
                            let mut first = String::new();
                            stream.read_line(&mut first)?;
                            let parts: Vec<_> = first.split_whitespace().collect();
                            if parts.len() != 3 {
                                return Err("bad HTTP request".into());
                            }
                            let method = reqwest::Method::from_bytes(parts[0].as_bytes())?;
                            let path = parts[1];
                            if !["/capabilities", "/intercept"].contains(&path) {
                                return Err("invalid path".into());
                            }
                            let mut length = 0;
                            let mut total = 0;
                            loop {
                                let mut line = String::new();
                                stream.read_line(&mut line)?;
                                total += line.len();
                                if total > 16384 {
                                    return Err("headers too large".into());
                                }
                                if line == "\r\n" {
                                    break;
                                }
                                if line.is_empty() {
                                    return Err("truncated HTTP".into());
                                }
                                if let Some((key, value)) = line.split_once(':') {
                                    if key.eq_ignore_ascii_case("content-length") {
                                        length = value.trim().parse::<usize>()?;
                                    }
                                    if key.eq_ignore_ascii_case("transfer-encoding") {
                                        return Err("chunked transfer unsupported".into());
                                    }
                                }
                            }
                            if length > 1048576 {
                                return Err("body too large".into());
                            }
                            let mut body = vec![0; length];
                            stream.read_exact(&mut body)?;
                            let response = reqwest::blocking::Client::builder()
                                .redirect(reqwest::redirect::Policy::none())
                                .timeout(Duration::from_secs(15))
                                .build()?
                                .request(method, format!("{upstream}{path}"))
                                .bearer_auth(secret)
                                .header("Content-Type", "application/json")
                                .body(body)
                                .send()?;
                            let status = response.status().as_u16();
                            let body = response.bytes()?;
                            write!(
                                stream.get_mut(),
                                "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )?;
                            stream.get_mut().write_all(&body)?;
                            stream.get_mut().flush()?;
                            Ok(())
                        })();
                        if let Err(error) = result {
                            eprintln!("interop: TLS connection rejected: {error}");
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::park_timeout(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    });
    Ok(endpoint)
}
fn server(c: &Value) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let schemas = Arc::new(schema(c)?);
    let cases = Arc::new(scenarios(c)?);
    let receipts = Arc::new(Mutex::new(Vec::new()));
    let barriers = Arc::new((Mutex::new(Vec::<String>::new()), Condvar::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let control = tiny_http::Server::http("127.0.0.1:0")?;
    let control_endpoint = format!("http://{}", control.server_addr());
    let control_receipts = receipts.clone();
    let control_barriers = barriers.clone();
    let control_stop = stop.clone();
    std::thread::spawn(move || {
        for mut r in control.incoming_requests() {
            match (r.method().as_str(), r.url()) {
                ("GET", "/health") => respond(
                    r,
                    200,
                    json!({"ready":true,"requests":*control_receipts.lock().unwrap()}),
                ),
                ("GET", "/receipts") => respond(
                    r,
                    200,
                    json!({"requests":*control_receipts.lock().unwrap()}),
                ),
                ("POST", "/release") => {
                    let mut body = String::new();
                    let _ = r.as_reader().take(1048576).read_to_string(&mut body);
                    match serde_json::from_str::<Value>(&body) {
                        Ok(v) if v["barrier"].is_string() => {
                            control_barriers
                                .0
                                .lock()
                                .unwrap()
                                .push(string(&v, "barrier").into());
                            control_barriers.1.notify_all();
                            respond(r, 200, json!({"released":true}));
                        }
                        _ => respond(r, 400, json!({"error":"bad barrier"})),
                    }
                }
                ("POST", "/shutdown") => {
                    control_stop.store(true, Ordering::SeqCst);
                    respond(r, 200, json!({"stopped":true}));
                    break;
                }
                _ => respond(r, 404, json!({"error":"not found"})),
            }
        }
    });
    if string(c, "transport") == "stdio" {
        atomic(
            string(c, "readinessFile"),
            &json!({"endpoint":"stdio","controlEndpoint":control_endpoint,"pid":std::process::id()}),
        )?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::stdin().lock().lines() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        while !stop.load(Ordering::SeqCst) {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(line) => {
                    let response = match serde_json::from_str::<Value>(&line?) { Ok(v) => reply(&v,&cases,&schemas,&receipts,&barriers).unwrap_or_else(|_| json!({"jsonrpc":"2.0","id":v["id"],"error":{"code":-32602,"message":"invalid request"}})), Err(_) => json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}) };
                    println!("{response}");
                    std::io::stdout().flush()?;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => break,
            }
        }
    } else {
        let server = tiny_http::Server::http("127.0.0.1:0")?;
        let mut internal_config = c.clone();
        let endpoint = if string(&c["auth"], "mode") == "mtls" {
            let mut entropy = [0u8; 32];
            fs::File::open("/dev/urandom")?.read_exact(&mut entropy)?;
            let secret: String = entropy.iter().map(|b| format!("{b:02x}")).collect();
            internal_config["auth"] = json!({"mode":"bearer","token":secret});
            tls_frontend(
                c,
                format!("http://{}", server.server_addr()),
                secret,
                stop.clone(),
            )?
        } else {
            format!("http://{}/intercept", server.server_addr())
        };
        atomic(
            string(c, "readinessFile"),
            &json!({"endpoint":endpoint,"controlEndpoint":control_endpoint,"pid":std::process::id()}),
        )?;
        while !stop.load(Ordering::SeqCst) {
            if let Some(mut r) = server.recv_timeout(Duration::from_millis(100))? {
                if r.headers()
                    .iter()
                    .filter(|h| h.field.equiv("Authorization"))
                    .count()
                    > 1
                {
                    respond(r, 401, json!({"error":"duplicate authorization"}));
                    continue;
                }
                let auth = r
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .map(|h| h.value.as_str())
                    .unwrap_or("");
                if !authenticate(&internal_config, auth) {
                    respond(r, 401, json!({"error":"unauthorized"}));
                    continue;
                }
                if r.method().as_str() == "GET" && r.url() == "/capabilities" {
                    respond(r, 200, interop::capabilities());
                    continue;
                }
                if r.method().as_str() != "POST" || r.url() != "/intercept" {
                    respond(r, 404, json!({"error":"not found"}));
                    continue;
                }
                let mut body = String::new();
                if r.as_reader()
                    .take(1048577)
                    .read_to_string(&mut body)
                    .is_err()
                {
                    respond(r, 400, json!({"error":"invalid request body"}));
                    continue;
                }
                if body.len() > 1048576 {
                    respond(r, 413, json!({"error":"too large"}));
                    continue;
                }
                let result = serde_json::from_str::<Value>(&body)
                    .map_err(Into::into)
                    .and_then(|v| reply(&v, &cases, &schemas, &receipts, &barriers));
                match result {
                    Ok(v) => respond(r, 200, v),
                    Err(_) => respond(r, 400, json!({"error":"invalid request"})),
                }
            }
        }
    }
    Ok(())
}
fn run() -> Result<bool> {
    let args: Vec<_> = std::env::args().collect();
    let index = args
        .iter()
        .position(|a| a == "--config")
        .ok_or("--config required")?;
    let c = read(args.get(index + 1).ok_or("config path required")?)?;
    match args.get(1).map(String::as_str) {
        Some("server") => {
            server(&c)?;
            Ok(true)
        }
        Some("client") => client(&c),
        _ => Err("expected client or server".into()),
    }
}
fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("interop: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepted_core_receipt_preserves_the_exact_canonical_message() {
        let schemas = schema(&json!({})).unwrap();
        let request = json!({"jsonrpc":"2.0","id":"receipt","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"receipt","source":"urn:rust:receipts","type":"tool.before","time":"2026-09-01T00:00:00Z","call":{"id":"call"},"path":"native","tool":{"name":"task","origin":"native","input":{"task":1}}},"capabilities":interop::capabilities()}});
        let cases = vec![
            json!({"id":"receipt","response":{"jsonrpc":"2.0","id":"receipt","result":{"protocolVersion":"draft","effects":[]}}}),
        ];
        let receipts = Mutex::new(Vec::new());
        let barriers = (Mutex::new(Vec::new()), Condvar::new());
        reply(&request, &cases, &schemas, &receipts, &barriers).unwrap();
        let receipts = receipts.lock().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0]["message"], request);
        schemas
            .validate("intercept-request", &receipts[0]["message"])
            .unwrap();
    }
    #[test]
    fn signed_auth_checks_signature_issuer_audience_purpose_and_time() {
        let c = json!({"auth":{"mode":"workload","signingKey":"TEST-ONLY-signature","issuer":"issuer","audience":"audience","purpose":"workload","clock":1893456000}});
        let claims = json!({"iss":"issuer","aud":"audience","purpose":"workload","exp":1893459600i64,"iat":1893456000i64});
        let sign = |v: &Value, key: &str| {
            format!(
                "Bearer {}",
                jsonwebtoken::encode(
                    &jsonwebtoken::Header::default(),
                    v,
                    &jsonwebtoken::EncodingKey::from_secret(key.as_bytes())
                )
                .unwrap()
            )
        };
        assert!(authenticate(&c, &sign(&claims, "TEST-ONLY-signature")));
        assert!(!authenticate(&c, &sign(&claims, "wrong-signature")));
        for (field, value) in [
            ("iss", json!("wrong")),
            ("aud", json!("wrong")),
            ("purpose", json!("oauth")),
            ("exp", json!(1893456000i64)),
            ("iat", json!(1893456001i64)),
            ("nbf", json!(1893456001i64)),
        ] {
            let mut invalid = claims.clone();
            invalid[field] = value;
            assert!(
                !authenticate(&c, &sign(&invalid, "TEST-ONLY-signature")),
                "accepted bad {field}"
            );
        }
        assert!(!authenticate(&c, "Bearer malformed"));
        assert!(!authenticate(&c, ""));
    }
    #[test]
    fn bearer_requires_exact_nonempty_token() {
        let c = json!({"auth":{"mode":"bearer","token":"TEST-ONLY-token"}});
        assert!(authenticate(&c, "Bearer TEST-ONLY-token"));
        assert!(!authenticate(&c, "Bearer wrong"));
        assert!(!authenticate(&c, ""));
        assert!(!authenticate(
            &json!({"auth":{"mode":"bearer","token":""}}),
            "Bearer "
        ));
    }
}
