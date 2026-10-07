#![cfg(all(feature = "tokio-process", unix))]

use agenthooksprotocol::{
    client::{Decision, ToolContext},
    generated::Registration,
    hooks::{Capabilities, EventGrant, Hooks, HooksOptions},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const BACKEND: &str = r#"
import json, os, sys
log = sys.argv[1]
for line in sys.stdin:
    request = json.loads(line)
    assert request['jsonrpc'] == '2.0'
    params = request['params']
    event = params['event']
    assert params['protocolVersion'] == 'draft'
    assert event['type'] == 'tool.before'
    assert event['source'] == 'https://host.test/stdio'
    assert event['id'] and event['time']
    assert event['path'] == 'native' and event['call']['id'] == 'stdio-call'
    if 'id' in request:
        assert request['method'] == 'hooks/intercept'
        assert 'elicitation' not in params['capabilities']
        assert set(params['capabilities']['effects']) == {'allow', 'deny', 'modify'}
    else:
        assert request['method'] == 'hooks/observe'
        assert 'capabilities' not in params and 'state' not in params
    with open(log, 'a') as out:
        out.write(json.dumps({'pid': os.getpid(), 'request': request}) + '\n')
    if 'id' not in request:
        continue
    if event['tool']['input']['command'] == 'modify':
        effects = [
            {'type':'modify','target':'input','operation':'replace','value':{'command':'safe','timeoutMs':25}},
            {'type':'allow'}
        ]
    else:
        effects = [{'type':'deny','reason':'stdio policy'}]
    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'protocolVersion':'draft','effects':effects}}), flush=True)
"#;

struct Log(PathBuf);
impl Log {
    fn new() -> Self {
        static NEXT_LOG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
                "ahp-hooks-stdio-{}-{}-{}.jsonl",
                std::process::id(),
                NEXT_LOG.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )))
    }
    fn read(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.0)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}
impl Drop for Log {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
#[derive(Debug, Serialize, Deserialize)]
struct Input {
    command: String,
    #[serde(rename = "timeoutMs")]
    timeout_ms: u64,
}
fn context() -> ToolContext {
    ToolContext::new(
        json!({"path":"native","call":{"id":"stdio-call"},"tool":{"name":"shell","kind":"shell","origin":"native"}}),
    )
}
fn configured(log: &Log, lifecycle: &str, observe: bool) -> Hooks {
    let mut subscriptions = vec![
        json!({"events":["tool.before"],"mode":"intercept","timeoutMs":3000,"failurePolicy":"fail-closed","content":{"default":"metadata"}}),
    ];
    let grant = EventGrant::intercept(Capabilities::none().allow().deny().modify_input());
    let grant = if observe {
        subscriptions.push(
            json!({"events":["tool.before"],"mode":"observe","content":{"default":"metadata"}}),
        );
        grant.with_observe()
    } else {
        grant
    };
    let config = json!({"protocolVersion":"draft","hooks":[{
        "id":"com.example.stdio",
        "transport":{"type":"stdio","command":"python3","args":["-u","-c",BACKEND,log.0.to_str().unwrap()],"lifecycle":lifecycle},
        "subscriptions":subscriptions
    }]}).to_string();
    let registration = serde_json::from_str::<Registration>(&config).unwrap();
    let mut options = HooksOptions::new(
        "https://host.test/stdio",
        [("tool.before".into(), grant)].into(),
    );
    options.observation_timeout = Duration::from_secs(3);
    Hooks::new(registration, options).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_registration_persistent_stdio_drains_and_reaps_child() {
    let log = Log::new();
    let hooks = configured(&log, "persistent", true);
    let lazy = hooks
        .tool_input(Input {
            command: "modify".into(),
            timeout_ms: 100,
        })
        .context(context())
        .initial_state(Decision::Allow);
    assert!(!log.0.exists(), "construction must not spawn or dispatch");
    let modified = lazy.await.unwrap();
    assert!(
        modified.outcome.failures.is_empty(),
        "{:?}",
        modified.outcome.failures
    );
    assert!(modified.outcome.can_execute());
    let input = modified.input.unwrap();
    assert_eq!(input.command, "safe");
    assert_eq!(input.timeout_ms, 25);
    let denied = hooks
        .tool_input(Input {
            command: "denied".into(),
            timeout_ms: 100,
        })
        .context(context())
        .initial_state(Decision::Allow)
        .await
        .unwrap();
    assert!(denied.outcome.failures.is_empty());
    assert!(denied.outcome.is_denied());
    assert!(!denied.outcome.can_execute());
    assert!(denied.outcome.supplied_result().is_none());
    assert_eq!(
        log.read()
            .iter()
            .filter(|row| row["request"].get("id").is_some())
            .count(),
        2
    );
    let report = hooks.wait_until_idle().await;
    assert_eq!(report.delivered, 2);
    assert!(report.failures.is_empty());
    // Notification delivery means bytes were written, not a remote application
    // acknowledgment. Wait for the fixture's separate evidence before shutdown.
    let rows = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let rows = log.read();
            if rows.len() == 4 {
                break rows;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let pid = rows[0]["pid"].as_u64().unwrap();
    assert!(rows.iter().all(|row| row["pid"] == pid));
    let intercepts: Vec<_> = rows
        .iter()
        .filter(|row| row["request"].get("id").is_some())
        .collect();
    let observations: Vec<_> = rows
        .iter()
        .filter(|row| row["request"].get("id").is_none())
        .collect();
    let first = &intercepts[0]["request"]["params"]["event"];
    let second = &intercepts[1]["request"]["params"]["event"];
    assert_ne!(first["id"], second["id"]);
    assert_eq!(
        observations[0]["request"]["params"]["event"]["tool"]["input"]["command"],
        "safe"
    );
    for row in observations {
        assert!(row["request"].get("id").is_none());
        assert!(row["request"]["params"].get("capabilities").is_none());
    }
    let report = tokio::time::timeout(Duration::from_secs(3), hooks.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.delivered, 2);
    assert!(report.failures.is_empty());
    assert!(
        !Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "shutdown must reap its child"
    );
    assert_eq!(hooks.shutdown().await.unwrap().delivered, 2);
    assert!(
        hooks
            .tool_input(Input {
                command: "denied".into(),
                timeout_ms: 1
            })
            .context(context())
            .await
            .is_err()
    );
    assert_eq!(log.read().len(), 4);
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_registration_per_event_stdio_uses_fresh_children() {
    let log = Log::new();
    let hooks = configured(&log, "per_event", true);
    for _ in 0..2 {
        let result = hooks
            .tool_input(Input {
                command: "modify".into(),
                timeout_ms: 100,
            })
            .context(context())
            .initial_state(Decision::Allow)
            .await
            .unwrap();
        assert!(
            result.outcome.failures.is_empty(),
            "{:?}",
            result.outcome.failures
        );
        assert!(result.outcome.can_execute());
        assert_eq!(result.input.unwrap().command, "safe");
    }
    let report = hooks.wait_until_idle().await;
    assert_eq!(report.delivered, 2);
    assert!(report.failures.is_empty());
    let rows = log.read();
    assert_eq!(rows.len(), 4);
    assert_eq!(
        rows.iter()
            .map(|row| row["pid"].as_u64().unwrap())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
    assert_ne!(rows[0]["pid"], rows[1]["pid"]);
    for row in &rows {
        let pid = row["pid"].as_u64().unwrap().to_string();
        assert!(
            !Command::new("kill")
                .args(["-0", &pid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }
    let report = tokio::time::timeout(Duration::from_secs(3), hooks.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.delivered, 2);
    assert!(report.failures.is_empty());
}
