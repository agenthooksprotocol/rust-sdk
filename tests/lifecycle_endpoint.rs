//! Real-process stdio sender regression: readiness must not replace subscription routing.
use base64::Engine;
use serde_json::{Value, json};
use std::{fs, path::PathBuf, process::Command, thread, time::Duration};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("rust-endpoint-{name}-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        Self(directory)
    }
    fn write(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }
    fn run(&self, upload: Value) -> Value {
        let body = [0, 255, 10];
        let scenarios = self.write("scenarios.json", &json!({"scenarios":[{"id":"route","requests":{},"responses":{},"steps":[{"op":"upload","subscription":"body","ref":"route","bodyBase64":base64::engine::general_purpose::STANDARD.encode(body)}]}]}));
        let server = self.write("server.json", &json!({"transport":"stdio","auth":{"mode":"none"},"scenarioFile":scenarios,"readinessFile":self.0.join("ready.json"),"uploadAuth":{"token":"TEST-READINESS-TOKEN","subscriptions":["body"]}}));
        let report = self.0.join("report.json");
        let config = self.write("client.json", &json!({"transport":"stdio","auth":{"mode":"none"},"scenarioFile":scenarios,"reportFile":report,"serverCommand":[env!("CARGO_BIN_EXE_lifecycle_server")],"serverConfig":server,"upload":upload}));
        let output = Command::new(env!("CARGO_BIN_EXE_lifecycle_client"))
            .args(["--config", config.to_str().unwrap()])
            .env("RUST_ENDPOINT_UPLOAD_TOKEN", "TEST-READINESS-TOKEN")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&fs::read(report).unwrap()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn stdio_explicit_endpoint_reaches_external_capture_unchanged() {
    let receiver = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let endpoint = format!(
        "http://{}/external/content?subscription=body&route=explicit",
        receiver.server_addr()
    );
    let capture = thread::spawn(move || {
        let mut request = receiver
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .expect("explicit upload endpoint was replaced or never contacted");
        let path = request.url().to_owned();
        let auth = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .map(|h| h.value.as_str().to_owned());
        let mut bytes = Vec::new();
        request.as_reader().read_to_end(&mut bytes).unwrap();
        assert!(
            !request
                .headers()
                .iter()
                .any(|h| h.field.equiv("AHP-Content-Ref") || h.field.equiv("AHP-Subscription"))
        );
        let hash = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("AHP-Content-SHA256"))
            .unwrap()
            .value
            .to_string();
        request
            .respond(
                tiny_http::Response::from_string(
                    json!({"ref":"receiver-allocated","size":bytes.len(),"sha256":hash})
                        .to_string(),
                )
                .with_status_code(201)
                .with_header(
                    tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                ),
            )
            .unwrap();
        (path, auth, bytes)
    });
    let fixture = Fixture::new("explicit");
    let report = fixture.run(json!({"endpoint":endpoint,"timeoutMs":5000,"maxBytes":1024}));
    let (path, auth, bytes) = capture.join().unwrap();
    assert_eq!(path, "/external/content?subscription=body&route=explicit");
    assert!(
        auth.is_none(),
        "upload acquired credentials from readiness/event setup"
    );
    assert_eq!(bytes, [0, 255, 10]);
    assert_eq!(
        report["results"][0]["actual"]["uploadStatuses"],
        json!([201])
    );
    assert_eq!(
        report["receipts"]["entries"],
        json!([]),
        "child's upload receiver was contacted instead"
    );
}

#[test]
fn stdio_missing_endpoint_uses_child_readiness_binding() {
    let fixture = Fixture::new("fallback");
    let report = fixture.run(json!({"timeoutMs":5000,"maxBytes":1024,"auth":{"type":"bearer","tokenEnv":"RUST_ENDPOINT_UPLOAD_TOKEN"}}));
    assert_eq!(
        report["results"][0]["actual"]["uploadStatuses"],
        json!([201])
    );
    let receipts = report["receipts"]["entries"].as_array().unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["kind"], "upload");
    assert_eq!(receipts[0]["scope"], "body");
    assert_ne!(receipts[0]["descriptor"]["ref"], "route");
    assert_eq!(receipts[0]["status"], 201);
    assert_eq!(receipts[0]["size"], 3);
}
