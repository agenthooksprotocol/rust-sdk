#![cfg(feature = "interop")]
//! Real-process core endpoints: public SDK settlement precedes host validation.
use serde_json::{Value, json};
use std::{fs, path::PathBuf, process::Command};

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rust-core-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn write(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }
    fn run(&self, cases: Vec<Value>) -> (bool, Value) {
        let scenarios = self.write("scenarios.json", &json!({"scenarios":cases}));
        let server = self.write(
            "server.json",
            &json!({"transport":"stdio","auth":{"mode":"none"},
            "scenarioFile":scenarios,"readinessFile":self.0.join("ready.json")}),
        );
        let report = self.0.join("report.json");
        let client = self.write(
            "client.json",
            &json!({"transport":"stdio","auth":{"mode":"none"},
            "scenarioFile":scenarios,"reportFile":report,
            "serverCommand":[env!("CARGO_BIN_EXE_interop"),"server"],"serverConfig":server}),
        );
        let output = Command::new(env!("CARGO_BIN_EXE_interop"))
            .args(["client", "--config", client.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            report.exists(),
            "client produced no report: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        (
            output.status.success(),
            serde_json::from_slice(&fs::read(report).unwrap()).unwrap(),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn case(id: &str, effects: Value) -> Value {
    json!({"id":id,"request":{"jsonrpc":"2.0","id":id,"method":"hooks/intercept",
        "params":{"protocolVersion":"draft","event":{"id":id,"source":"urn:rust:core-test",
            "type":"tool.before","time":"2026-09-01T00:00:00Z","call":{"id":"call"},"path":"native",
            "tool":{"name":"task","origin":"native","input":{"task":1}}},
            "capabilities":{"effects":["message","modify","return"],"modify":{"input":{"merge":true,"replace":true}}},
            "state":{"permission":"allow","candidate":null}}},
        "response":{"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"draft","effects":effects}}})
}
#[test]
fn real_stdio_settles_protocol_before_host_refusal() {
    let mut valid = case(
        "ordinary-accepted",
        json!([{"type":"modify","target":"input","operation":"merge","value":{"task":2}}]),
    );
    valid["expected"] =
        json!({"decision":"allow","executed":true,"input":{"task":2},"messages":[]});
    let mut invalid = case(
        "invalid-task-zero-rejects-staged-message",
        json!([
            {"type":"message","text":"accepted message"},
            {"type":"modify","target":"input","operation":"merge","value":{"task":0}}
        ]),
    );
    invalid["request"]["params"]["state"]["candidate"] = json!({"value":{"cached":1}});
    invalid["expectError"] = json!(true);
    invalid["hostExpected"] = json!({"decision":"allow","executed":false,"input":{"task":0},"messages":["accepted message"]});
    let (passed, report) = Fixture::new("settlement").run(vec![valid, invalid]);
    assert!(passed, "{report}");
    let refused = &report["results"][1];
    assert_eq!(refused["sdkAccepted"], true);
    assert_eq!(refused["hostAccepted"], false);
    assert_eq!(refused["rejectionLayer"], "host-input-schema");
    assert_eq!(refused["actual"]["input"], json!({"task":0}));
    assert_eq!(refused["actual"]["messages"], json!(["accepted message"]));
    assert_eq!(refused["actual"]["executed"], false);
    assert!(refused["actual"].get("result").is_none());
}
#[test]
fn only_named_adversary_can_bypass_outgoing_sdk_validation() {
    let mut named = case("wrong-response-id", json!([]));
    named["response"]["id"] = json!("wrong");
    named["expectError"] = json!(true);
    let mut arbitrary = case("arbitrary-expect-error-is-not-a-raw-control", json!([]));
    arbitrary["response"]["id"] = json!("wrong");
    arbitrary["expectError"] = json!(true);
    let (passed, report) = Fixture::new("adversary").run(vec![named, arbitrary]);
    assert!(!passed, "{report}");
    assert_eq!(report["results"][0]["status"], "passed");
    assert_eq!(report["results"][0]["actual"], json!({"rejected":true}));
    assert_eq!(report["results"][1]["status"], "failed");
}

#[test]
fn prior_candidate_does_not_require_return_capability() {
    let mut prior = case("candidate-without-return-grant", json!([]));
    prior["request"]["params"]["capabilities"] = json!({"effects":["message"]});
    prior["request"]["params"]["state"]["candidate"] =
        json!({"value":{"cached":1},"provenance":{"requestId":"earlier"}});
    prior["expected"] = json!({"decision":"allow","executed":false,
        "input":{"task":1},"messages":[],"result":{"cached":1}});
    let (passed, report) = Fixture::new("native-candidate").run(vec![prior]);
    assert!(passed, "{report}");
}

#[test]
fn named_settled_probes_still_acquire_the_response() {
    // A missing fixture response must fail acquisition/reduction. A regular
    // SDK boundary would skip interception for deny and falsely pass this test.
    let mut denied = case("empty-preserves-incoming-deny", Value::Null);
    denied["request"]["params"]["state"]["permission"] = json!("deny");
    denied["expected"] = json!({"decision":"deny","executed":false,
        "input":{"task":1},"messages":[]});
    let (passed, report) = Fixture::new("settled-acquisition").run(vec![denied]);
    assert!(!passed, "settled probe skipped its transport: {report}");
    assert_eq!(report["results"][0]["status"], "failed");
}

#[test]
fn omitted_state_is_absent_on_the_actual_wire() {
    let fixture = Fixture::new("omitted-state");
    let mut scenario = case("omitted-state-wire", json!([]));
    scenario["request"]["params"]
        .as_object_mut()
        .unwrap()
        .remove("state");
    scenario["expected"] = json!({"decision":"allow","executed":true,
        "input":{"task":1},"messages":[]});
    let receiver = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/intercept", receiver.server_addr());
    let expected_request = scenario["request"].clone();
    let response = scenario["response"].clone();
    let capabilities = scenario["request"]["params"]["capabilities"].clone();
    let captured = std::thread::spawn(move || {
        let discovery = receiver
            .recv_timeout(std::time::Duration::from_secs(15))
            .unwrap()
            .unwrap();
        assert_eq!(discovery.url(), "/capabilities");
        discovery
            .respond(tiny_http::Response::from_string(capabilities.to_string()))
            .unwrap();
        let mut intercept = receiver
            .recv_timeout(std::time::Duration::from_secs(15))
            .unwrap()
            .unwrap();
        let request: Value = serde_json::from_reader(intercept.as_reader()).unwrap();
        intercept
            .respond(tiny_http::Response::from_string(response.to_string()))
            .unwrap();
        request
    });
    let scenarios = fixture.write("scenarios.json", &json!({"scenarios":[scenario]}));
    let config = fixture.write(
        "client.json",
        &json!({"transport":"http","auth":{"mode":"none"},
        "endpoint":endpoint,"scenarioFile":scenarios,"reportFile":fixture.0.join("report.json")}),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_interop"))
        .args(["client", "--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    let actual_request = captured.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(actual_request, expected_request);
    assert!(actual_request["params"].get("state").is_none());
}
