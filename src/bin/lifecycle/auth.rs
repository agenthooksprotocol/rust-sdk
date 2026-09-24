//! Event authentication binding shared in behavior with the core interop adapter.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
fn string<'a>(v: &'a Value, k: &str) -> &'a str {
    s(v, k)
}
pub(super) fn authenticate(c: &Value, header: &str) -> bool {
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
pub(super) fn http_client(c: &Value) -> Result<(reqwest::blocking::Client, String)> {
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
pub(super) fn tls_frontend(
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
    let endpoint = format!("https://{}", listener.local_addr()?);
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
                            if !["/capabilities", "/intercept", "/observe"].contains(&path) {
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

#[cfg(test)]
mod tests {
    use super::*;
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
