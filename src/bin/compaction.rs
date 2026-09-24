//! Offline host fixture; no oracle or expected outcome is sent to this receiver.
use agent_hooks_protocol::compaction::{
    CompactionHook, CompactionObserver, run_compaction, run_compaction_observed,
};
use serde_json::{Value, json};
use std::io::{self, BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
fn evaluate(p: &Value) -> Result<Value, String> {
    let input = p["instructions"].as_str().ok_or("instructions")?;
    let empty = vec![];
    let before = if p.get("before").is_none() {
        &empty
    } else {
        p["before"].as_array().ok_or("before")?
    };
    let after = if p.get("after").is_none() {
        &empty
    } else {
        p["after"].as_array().ok_or("after")?
    };
    let callback = |row: &Value| {
        let row = row.clone();
        move |_: &Value| -> Result<Vec<Value>, String> {
            if row["throw"] == true {
                return Err("hook failed".into());
            }
            row["effects"].as_array().cloned().ok_or("effects".into())
        }
    };
    let before_callbacks: Vec<_> = before.iter().map(callback).collect();
    let after_callbacks: Vec<_> = after.iter().map(callback).collect();
    let mut before_hooks = vec![];
    let mut after_hooks = vec![];
    for (row, run) in before.iter().zip(&before_callbacks) {
        before_hooks.push(CompactionHook {
            supplier: row["supplier"].as_str().ok_or("supplier")?,
            failure_policy: row
                .get("failurePolicy")
                .map(|v| v.as_str().ok_or("policy"))
                .transpose()?
                .unwrap_or("fail-closed"),
            run,
        });
    }
    for (row, run) in after.iter().zip(&after_callbacks) {
        after_hooks.push(CompactionHook {
            supplier: row["supplier"].as_str().ok_or("supplier")?,
            failure_policy: row
                .get("failurePolicy")
                .map(|v| v.as_str().ok_or("policy"))
                .transpose()?
                .unwrap_or("fail-closed"),
            run,
        });
    }
    let item_id = p
        .get("itemId")
        .map(|v| v.as_str().ok_or("itemId"))
        .transpose()?
        .unwrap_or("summary-1");
    if p["observeOnly"] == true {
        let observers = after
            .iter()
            .map(|row| {
                Ok(CompactionObserver {
                    supplier: row["supplier"].as_str().ok_or("supplier")?.to_owned(),
                    run: Arc::new(callback(row)),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        return run_compaction_observed(input, item_id, &before_hooks, observers, None);
    }
    run_compaction(
        input,
        item_id,
        &before_hooks,
        &after_hooks,
        None,
        p["observeOnly"] == true,
    )
}
fn receive(request: Value) -> Value {
    let result = if request["jsonrpc"] != "2.0" || request["method"] != "compaction/run" {
        Err("invalid request".into())
    } else {
        evaluate(&request["params"])
    };
    match result {
        Ok(result) => json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
        Err(_) => {
            json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32602,"message":"invalid request"}})
        }
    }
}
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mode = std::env::args().nth(1).ok_or("mode")?;
    match mode.as_str() {
        "stdio" => {
            for line in io::stdin().lock().lines() {
                println!("{}", receive(serde_json::from_str(&line?)?));
            }
        }
        "server" => {
            let server = tiny_http::Server::http("127.0.0.1:0")?;
            println!(
                "{}",
                json!({"endpoint":format!("http://{}",server.server_addr())})
            );
            io::stdout().flush()?;
            let token = format!("Bearer {}", std::env::var("AHP_COMPACTION_TOKEN")?);
            for mut request in server.incoming_requests() {
                if !request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("Authorization") && h.value.as_str() == token)
                {
                    let _ = request.respond(tiny_http::Response::empty(401));
                    continue;
                }
                let mut body = String::new();
                if request
                    .as_reader()
                    .take(4 * 1024 * 1024 + 1)
                    .read_to_string(&mut body)
                    .is_err()
                {
                    let _ = request.respond(tiny_http::Response::empty(400));
                    continue;
                }
                if body.len() > 4 * 1024 * 1024 {
                    let _ = request.respond(tiny_http::Response::empty(413));
                    continue;
                }
                let Ok(value) = serde_json::from_str(&body) else {
                    let _ = request.respond(tiny_http::Response::empty(400));
                    continue;
                };
                let response = receive(value);
                let _ = request.respond(tiny_http::Response::from_string(response.to_string()));
            }
        }
        "client" => {
            let plan: Value = serde_json::from_reader(io::stdin())?;
            let requests = plan["requests"].as_array().ok_or("requests")?;
            let replies: Vec<Value> = if plan["transport"] == "stdio" {
                let cmd = plan["command"].as_array().ok_or("command")?;
                let mut child = Command::new(cmd[0].as_str().ok_or("command")?)
                    .args(cmd[1..].iter().map(|v| v.as_str().unwrap()))
                    .arg("stdio")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()?;
                let mut stdin = child.stdin.take().ok_or("stdin")?;
                let payload = requests
                    .iter()
                    .map(|r| format!("{r}\n"))
                    .collect::<String>();
                // Feed concurrently: large snapshots can fill stdout while stdin is read.
                let writer = std::thread::spawn(move || stdin.write_all(payload.as_bytes()));
                let output = child.wait_with_output()?;
                writer.join().map_err(|_| "writer panicked")??;
                if !output.status.success() {
                    return Err("receiver failed".into());
                }
                String::from_utf8(output.stdout)?
                    .lines()
                    .map(serde_json::from_str)
                    .collect::<Result<_, _>>()?
            } else {
                let client = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(20))
                    .build()?;
                let mut out = vec![];
                for request in requests {
                    let response = client
                        .post(plan["endpoint"].as_str().ok_or("endpoint")?)
                        .bearer_auth(plan["token"].as_str().ok_or("token")?)
                        .json(request)
                        .send()?
                        .error_for_status()?;
                    out.push(response.json()?);
                }
                out
            };
            println!("{}", json!(replies));
        }
        _ => return Err("unknown mode".into()),
    }
    Ok(())
}
