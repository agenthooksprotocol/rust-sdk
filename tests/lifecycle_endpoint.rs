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
        self.run_scenarios(&scenarios, upload)
    }
    fn run_scenarios(&self, scenarios: &std::path::Path, upload: Value) -> Value {
        let output = self.run_scenarios_output(scenarios, upload);
        assert!(
            output.status.success(),
            "client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&fs::read(self.0.join("report.json")).unwrap()).unwrap()
    }
    fn run_scenarios_output(
        &self,
        scenarios: &std::path::Path,
        upload: Value,
    ) -> std::process::Output {
        let server = self.write("server.json", &json!({"transport":"stdio","auth":{"mode":"none"},"scenarioFile":scenarios,"readinessFile":self.0.join("ready.json"),"uploadAuth":{"token":"TEST-READINESS-TOKEN","subscriptions":["body"]}}));
        let report = self.0.join("report.json");
        let config = self.write("client.json", &json!({"transport":"stdio","auth":{"mode":"none"},"scenarioFile":scenarios,"reportFile":report,"serverCommand":[env!("CARGO_BIN_EXE_lifecycle_server")],"serverConfig":server,"upload":upload}));
        Command::new(env!("CARGO_BIN_EXE_lifecycle_client"))
            .args(["--config", config.to_str().unwrap()])
            .env("RUST_ENDPOINT_UPLOAD_TOKEN", "TEST-READINESS-TOKEN")
            .output()
            .unwrap()
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

fn lifecycle_scenario(effects: Value) -> Value {
    json!({
        "id":"sdk-process",
        "requests":{"a":{
            "jsonrpc":"2.0","id":"sdk-process:a","method":"hooks/intercept",
            "params":{"protocolVersion":"draft","event":{
                "id":"sdk-process:a","source":"urn:rust:test","type":"tool.before",
                "time":"2026-09-01T00:00:00Z","session":{"id":"s"},"call":{"id":"c"},
                "path":"native","tool":{"origin":"native","name":"arbitrary","kind":"task","input":{"value":"original"}}
            },"capabilities":{"effects":["modify","message","deny"],"modify":{"input":{"replace":true,"merge":true}}}}
        }},
        "responses":{"a":{"jsonrpc":"2.0","id":"sdk-process:a","result":{"protocolVersion":"draft","effects":effects}}},
        "steps":[{"op":"send","key":"a","slot":"a"},{"op":"wait","key":"a"},{"op":"release","key":"a"},{"op":"receive","slot":"a"},{"op":"accept","key":"a"}]
    })
}

#[test]
fn ordinary_stdio_lifecycle_executes_arbitrary_object_input_after_sdk_modification() {
    let fixture = Fixture::new("sdk-modify");
    let scenario = lifecycle_scenario(json!([
        {"type":"modify","target":"input","operation":"replace","value":{"value":"settled"}},
        {"type":"message","text":"accepted"}
    ]));
    let scenarios = fixture.write("scenarios.json", &json!({"scenarios":[scenario]}));
    let report = fixture.run_scenarios(&scenarios, json!({}));
    let actual = &report["results"][0]["actual"];
    assert_eq!(actual["published"], json!(["sdk-process:a"]));
    assert_eq!(
        actual["states"]["sdk-process:a"]["input"],
        json!({"value":"settled"})
    );
    assert_eq!(actual["states"]["sdk-process:a"]["executed"], true);
    assert_eq!(
        actual["states"]["sdk-process:a"]["messages"],
        json!(["accepted"])
    );
    assert!(
        report["receipts"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["kind"] == "received")
    );
}

#[test]
fn ordinary_stdio_lifecycle_deny_prevents_execution() {
    let fixture = Fixture::new("sdk-deny");
    let scenario = lifecycle_scenario(json!([{"type":"deny","reason":"blocked"}]));
    let scenarios = fixture.write("scenarios.json", &json!({"scenarios":[scenario]}));
    let report = fixture.run_scenarios(&scenarios, json!({}));
    let state = &report["results"][0]["actual"]["states"]["sdk-process:a"];
    assert_eq!(state["decision"], "deny");
    assert_eq!(state["executed"], false);
    assert_eq!(state["input"], json!({"value":"original"}));
}

#[test]
fn ordinary_stdio_rejects_invalid_effect_batch_without_publication() {
    let fixture = Fixture::new("sdk-invalid-batch");
    let scenario = lifecycle_scenario(json!([
        {"type":"modify","target":"input","operation":"replace","value":{"value":"must-not-publish"}},
        {"type":"return","value":{"candidate":true}}
    ]));
    let scenarios = fixture.write("scenarios.json", &json!({"scenarios":[scenario]}));
    let output = fixture.run_scenarios_output(&scenarios, json!({}));
    assert!(
        !output.status.success(),
        "invalid effect batch was accepted"
    );
    assert!(
        !fixture.0.join("report.json").exists(),
        "a failed batch published a report"
    );
}

#[test]
fn arbitrary_scenario_cannot_opt_out_of_sdk_validation() {
    let fixture = Fixture::new("sdk-bypass");
    let mut scenario = lifecycle_scenario(json!([]));
    scenario["steps"][0]["bypassSDK"] = json!(true);
    let scenarios = fixture.write("scenarios.json", &json!({"scenarios":[scenario]}));
    let output = fixture.run_scenarios_output(&scenarios, json!({}));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported SDK bypass operation"));
    assert!(!fixture.0.join("report.json").exists());
}

#[test]
fn cancellation_after_acquisition_never_accepts_or_executes_staged_effects() {
    let fixture = Fixture::new("sdk-cancel-acquired");
    let mut scenario = lifecycle_scenario(json!([
        {"type":"modify","target":"input","operation":"replace","value":{"value":"must-not-publish"}},
        {"type":"return","value":{"candidate":true}}
    ]));
    // A conforming backend may supply a candidate, but cancellation must still
    // prevent its acceptance/publication after the bytes have been acquired.
    scenario["requests"]["a"]["params"]["capabilities"]["effects"]
        .as_array_mut()
        .unwrap()
        .push(json!("return"));
    scenario["steps"] = json!([
        {"op":"send","key":"a","slot":"a"}, {"op":"wait","key":"a"},
        {"op":"release","key":"a"}, {"op":"receive","slot":"a"},
        {"op":"cancel","key":"a"}, {"op":"accept","key":"a"}, {"op":"failOpen","key":"a"}
    ]);
    let scenarios = fixture.write("scenarios.json", &json!({"scenarios":[scenario]}));
    let report = fixture.run_scenarios(&scenarios, json!({}));
    let actual = &report["results"][0]["actual"];
    assert_eq!(actual["published"], json!([]));
    assert_eq!(actual["states"], json!({}));
    assert_eq!(actual["cancelled"], json!(["sdk-process:a"]));
    let receipts = report["receipts"]["entries"].as_array().unwrap();
    let acquired = receipts
        .iter()
        .position(|entry| entry["kind"] == "acquired")
        .unwrap();
    let cancelled = receipts
        .iter()
        .position(|entry| entry["kind"] == "cancelled")
        .unwrap();
    assert!(acquired < cancelled);
    assert!(!receipts.iter().any(|entry| entry["kind"] == "accepted"));
}
