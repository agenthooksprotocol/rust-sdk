use agent_hooks_protocol::compaction::{
    CompactionHook, CompactionObserver, capabilities, run_compaction, run_compaction_observed,
};
use serde_json::{Value, json};
use std::cell::RefCell;
fn modify(target: &str, value: &str) -> Value {
    json!({"type":"modify","target":target,"operation":"replace","value":value})
}
#[test]
fn callbacks_see_effective_inputs_and_results() {
    let generated = RefCell::new(vec![]);
    let edit = |_: &Value| Ok(vec![modify("instructions", "new")]);
    let redact = |s: &Value| {
        Ok(vec![modify(
            "summary",
            &format!(
                "{}:redacted",
                s["bodies"][s["summary"]["ref"].as_str().unwrap()]
                    .as_str()
                    .unwrap()
            ),
        )])
    };
    let watch = |s: &Value| {
        assert_eq!(
            s["bodies"][s["summary"]["ref"].as_str().unwrap()],
            "generated:new:redacted"
        );
        Ok(vec![])
    };
    let generate = |input: &str| {
        generated.borrow_mut().push(input.to_owned());
        Ok(format!("generated:{input}"))
    };
    let r = run_compaction(
        "old",
        "summary-1",
        &[CompactionHook {
            supplier: "edit",
            failure_policy: "fail-closed",
            run: &edit,
        }],
        &[
            CompactionHook {
                supplier: "redact",
                failure_policy: "fail-closed",
                run: &redact,
            },
            CompactionHook {
                supplier: "watch",
                failure_policy: "fail-closed",
                run: &watch,
            },
        ],
        Some(&generate),
        false,
    )
    .unwrap();
    assert_eq!(*generated.borrow(), vec!["new"]);
    assert_eq!(r["applied"], true);
    assert_eq!(r["failures"], json!([]));
    assert_eq!(r["bodies"].as_object().unwrap().len(), 2);
    assert_eq!(r["seen"][1]["summary"]["id"], r["summary"]["id"]);
    assert_ne!(r["seen"][1]["summary"]["ref"], r["summary"]["ref"]);
}
#[test]
fn atomic_candidate_and_after_redaction() {
    let cache = |_: &Value| Ok(vec![json!({"type":"return","value":"cached"})]);
    let bad = |_: &Value| {
        Ok(vec![
            modify("instructions", "leak"),
            json!({"type":"message","text":"leak"}),
            modify("summary", "wrong"),
        ])
    };
    let redact = |_: &Value| Ok(vec![modify("summary", "safe")]);
    let generate = |_: &str| Err("generator must not run".to_owned());
    let r = run_compaction(
        "old",
        "summary-1",
        &[
            CompactionHook {
                supplier: "cache",
                failure_policy: "fail-closed",
                run: &cache,
            },
            CompactionHook {
                supplier: "bad",
                failure_policy: "fail-open",
                run: &bad,
            },
        ],
        &[CompactionHook {
            supplier: "redact",
            failure_policy: "fail-closed",
            run: &redact,
        }],
        Some(&generate),
        false,
    )
    .unwrap();
    assert_eq!(r["instructions"], "old");
    assert_eq!(r["messages"], json!([]));
    assert_eq!(r["bodies"][r["summary"]["ref"].as_str().unwrap()], "safe");
    assert_eq!(
        r["provenance"],
        json!({"kind":"supplied","supplier":"cache"})
    );
    assert_eq!(r["applied"], true);
}
#[test]
fn unknown_effects_and_operations_roll_back_the_entire_response() {
    for invalid in [
        json!({"type":"future"}),
        json!({"type":"modify","target":"instructions","operation":"future","value":"leak"}),
    ] {
        let callback = |_: &Value| {
            Ok(vec![
                modify("instructions", "leak"),
                json!({"type":"message","text":"leak"}),
                json!({"type":"return","value":"leak"}),
                invalid.clone(),
            ])
        };
        let result = run_compaction(
            "base",
            "summary-1",
            &[CompactionHook {
                supplier: "invalid",
                failure_policy: "fail-open",
                run: &callback,
            }],
            &[],
            None,
            false,
        )
        .unwrap();
        assert_eq!(result["instructions"], "base");
        assert_eq!(result["messages"], json!([]));
        assert_eq!(result["candidate"], Value::Null);
        assert_eq!(result["generated"], true);
        assert_eq!(result["applied"], true);
        assert_eq!(result["failures"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn after_failure_prevents_delivery() {
    let bad = |_: &Value| {
        Ok(vec![
            modify("summary", "leak"),
            modify("instructions", "wrong"),
        ])
    };
    let r = run_compaction(
        "old",
        "summary-1",
        &[],
        &[CompactionHook {
            supplier: "bad",
            failure_policy: "fail-closed",
            run: &bad,
        }],
        None,
        false,
    )
    .unwrap();
    assert_eq!(r["applied"], false);
    assert_eq!(r["bodies"].as_object().unwrap().len(), 1);
    assert_eq!(
        capabilities("after", true).unwrap(),
        json!({"effects":[],"modify":{}})
    );
}

#[test]
fn blocked_observers_do_not_gate_settlement_or_downstream() {
    use std::{
        sync::{Arc, Mutex, mpsc},
        thread,
        time::Duration,
    };
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let (settled_tx, settled_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let observer = CompactionObserver {
        supplier: "slow".into(),
        run: Arc::new(move |snapshot| {
            entered_tx.send(snapshot.clone()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            finished_tx.send(()).unwrap();
            Ok(vec![modify("summary", "forbidden")])
        }),
    };
    let (error_tx, error_rx) = mpsc::channel();
    let throwing = CompactionObserver {
        supplier: "failure".into(),
        run: Arc::new(move |_| {
            error_tx.send(()).unwrap();
            Err("observer failure".into())
        }),
    };
    let host = thread::spawn(move || {
        let result =
            run_compaction_observed("base", "summary-1", &[], vec![observer, throwing], None)
                .unwrap();
        let downstream = if result["applied"] == true {
            vec![result["bodies"][result["summary"]["ref"].as_str().unwrap()].clone()]
        } else {
            vec![]
        };
        settled_tx.send((result, downstream)).unwrap();
    });
    let snapshot = entered_rx.recv_timeout(Duration::from_secs(5));
    let settled = settled_rx.recv_timeout(Duration::from_secs(5));
    let independently_notified = error_rx.recv_timeout(Duration::from_secs(5));
    let still_blocked = finished_rx.try_recv().is_err();
    // Always release before assertions so failures cannot strand a thread.
    release_tx.send(()).unwrap();
    let snapshot = snapshot.expect("observer not started");
    let (result, downstream) = settled.expect("blocked observer gated settlement");
    independently_notified.expect("notifications were serialized");
    assert!(still_blocked);
    assert_eq!(snapshot["applied"], true);
    assert_eq!(snapshot["capabilities"], json!({"effects":[],"modify":{}}));
    assert_eq!(downstream, vec![json!("summary:base")]);
    finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(result["failures"], json!([]));
    assert_eq!(
        result["bodies"][result["summary"]["ref"].as_str().unwrap()],
        "summary:base"
    );
    host.join().unwrap();
}

#[test]
fn borrowed_callbacks_cannot_escape_their_lifetime_as_observers() {
    let callback =
        |_: &Value| -> Result<Vec<Value>, String> { panic!("must not invoke borrowed observer") };
    let hook = CompactionHook {
        supplier: "borrowed",
        failure_policy: "fail-closed",
        run: &callback,
    };
    assert!(
        run_compaction("base", "summary-1", &[], &[hook], None, true)
            .unwrap_err()
            .contains("owned observers")
    );
}
