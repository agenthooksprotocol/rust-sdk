#![cfg(feature = "tokio-process")]
use agenthooksprotocol::{
    adapters::process::{DiscardedFrame, Process},
    transport::{Http, Request},
};
use std::time::Duration;
use tokio::process::Command;

async fn child(script: &str, limit: usize, deadline: Duration) -> Process {
    let mut command = Command::new("python3");
    command.args(["-u", "-c", script]);
    Process::spawn(command, limit, deadline).await.unwrap()
}
fn request() -> Request {
    Request {
        body: br#"{"id":"one"}"#.to_vec(),
        ..Request::default()
    }
}

#[tokio::test]
async fn persistent_exchange_preserves_error_bodies_and_notification_silence() {
    let process = child("import sys,json\nfor line in sys.stdin:\n if 'id' in json.loads(line):\n  print('{\"id\":\"one\",\"error\":\"denied\"}',flush=True)\n", 128, Duration::from_secs(2)).await;
    process
        .notify(Request {
            body: b"{}".to_vec(),
            ..Request::default()
        })
        .await
        .unwrap();
    for _ in 0..2 {
        let response = process.send(request()).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, br#"{"id":"one","error":"denied"}"#);
    }
    process.shutdown().await.unwrap();
    process.shutdown().await.unwrap();
    assert!(process.send(request()).await.is_err());
}

#[tokio::test]
async fn oversized_frame_and_eof_retire_the_child() {
    for (script, expected) in [
        (
            "import sys\nsys.stdin.readline()\nprint('x'*129,flush=True)\n",
            "too large",
        ),
        (
            "import sys\nsys.stdin.readline()\nsys.stdout.write('partial');sys.stdout.flush()\n",
            "unterminated",
        ),
        ("import sys\nsys.stdin.readline()\n", "EOF"),
    ] {
        let process = child(script, 128, Duration::from_secs(2)).await;
        assert!(
            process
                .send(request())
                .await
                .unwrap_err()
                .0
                .contains(expected)
        );
        assert!(
            process
                .send(request())
                .await
                .unwrap_err()
                .0
                .contains("retired")
        );
        process.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn real_deadline_and_dropped_inflight_future_prevent_reuse() {
    let script = "import sys,time\nsys.stdin.readline()\ntime.sleep(10)\nprint('{}',flush=True)\n";
    let process = child(script, 128, Duration::from_millis(100)).await;
    assert!(
        process
            .send(request())
            .await
            .unwrap_err()
            .0
            .contains("deadline")
    );
    assert!(process.send(request()).await.is_err());
    process.shutdown().await.unwrap();

    let process = child(script, 128, Duration::from_secs(2)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), process.send(request()))
            .await
            .is_err()
    );
    assert!(
        process
            .send(request())
            .await
            .unwrap_err()
            .0
            .contains("retired")
    );
    process.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn shutdown_and_drop_terminate_the_real_child() {
    async fn alive(pid: &str) -> bool {
        Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .unwrap()
            .success()
    }
    async fn child_pid(process: &Process) -> String {
        let body = process.send(request()).await.unwrap().body;
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["pid"].to_string()
    }
    let script = "import sys,os,json\nfor line in sys.stdin: print(json.dumps({'id':'one','pid':os.getpid()}),flush=True)\n";
    let process = child(script, 128, Duration::from_secs(2)).await;
    let pid = child_pid(&process).await;
    assert!(alive(&pid).await);
    process.shutdown().await.unwrap();
    assert!(!alive(&pid).await);

    let process = child(script, 128, Duration::from_secs(2)).await;
    let pid = child_pid(&process).await;
    drop(process);
    tokio::time::timeout(Duration::from_secs(2), async {
        while alive(&pid).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("dropped child must terminate and be reaped");
}

// Keep an exchange future alive but deliberately stop polling it. Its internal
// timer cannot release the gate unless polled; shutdown must enforce its own bound.
#[tokio::test]
async fn shutdown_deadline_bounds_queueing_and_cleanup_can_be_retried() {
    let process = child(
        "import sys,time\nfor line in sys.stdin: time.sleep(10)\n",
        128,
        Duration::from_millis(150),
    )
    .await;
    let mut exchange = process.send(request());
    assert!(futures::poll!(exchange.as_mut()).is_pending());

    let failure = tokio::time::timeout(Duration::from_secs(2), process.shutdown())
        .await
        .expect("shutdown must bound its own queue wait")
        .unwrap_err();
    assert!(failure.0.contains("shutdown deadline exceeded"));
    assert!(failure.0.contains("retried"));

    // Timing out while queued cannot steal the live exchange's lease. Dropping
    // it retires the process; shutdown must still own and reap that child.
    drop(exchange);
    process.shutdown().await.unwrap();
    process.shutdown().await.unwrap();
    assert!(
        process
            .send(request())
            .await
            .unwrap_err()
            .0
            .contains("shut down")
    );
}

#[tokio::test]
async fn cancelled_queued_shutdown_preserves_child_for_retry() {
    let process = child(
        "import sys,time\nfor line in sys.stdin: time.sleep(10)\n",
        128,
        Duration::from_secs(2),
    )
    .await;
    let mut exchange = process.send(request());
    assert!(futures::poll!(exchange.as_mut()).is_pending());
    let mut shutdown = Box::pin(process.shutdown());
    assert!(futures::poll!(shutdown.as_mut()).is_pending());
    drop(shutdown);
    drop(exchange);
    process.shutdown().await.unwrap();
    process.shutdown().await.unwrap();
    assert!(
        process
            .send(request())
            .await
            .unwrap_err()
            .0
            .contains("shut down")
    );
}

#[tokio::test]
async fn invalid_local_frames_do_not_retire_a_healthy_child() {
    let process = child(
        "import sys\nfor line in sys.stdin: print(line.strip(),flush=True)\n",
        32,
        Duration::from_secs(2),
    )
    .await;
    for body in [
        vec![b'x'; 33],
        b"{}\n{}".to_vec(),
        b"invalid".to_vec(),
        b"{}".to_vec(),
    ] {
        assert!(
            process
                .send(Request {
                    body,
                    ..Request::default()
                })
                .await
                .is_err()
        );
    }
    assert_eq!(process.send(request()).await.unwrap().body, request().body);
    process.shutdown().await.unwrap();
}

#[tokio::test]
async fn unsolicited_and_uncorrelated_frames_never_answer_the_next_request() {
    // Replies to a notification, then precedes each real reply with a stray
    // well-formed frame and one malformed line.
    let script = "import sys,json\nfor line in sys.stdin:\n r=json.loads(line)\n if 'id' not in r:\n  print('{\"jsonrpc\":\"2.0\",\"id\":\"unsolicited\"}',flush=True)\n else:\n  print('{\"id\":\"stray\"}',flush=True)\n  print('garbage',flush=True)\n  print(json.dumps({'id':r['id'],'ok':True}),flush=True)\n";
    let process = child(script, 128, Duration::from_secs(2)).await;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = seen.clone();
    process.on_discard(move |kind| sink.lock().unwrap().push(kind));
    for _ in 0..2 {
        process
            .notify(Request {
                body: br#"{"jsonrpc":"2.0","method":"hooks/observe"}"#.to_vec(),
                ..Request::default()
            })
            .await
            .unwrap();
        let response = process.send(request()).await.unwrap();
        assert_eq!(response.body, br#"{"id": "one", "ok": true}"#);
    }
    // Two rounds of: unsolicited (or uncorrelated, if the reply raced the next
    // request), uncorrelated stray, malformed line.
    assert_eq!(process.discarded_frames(), 6);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 6);
    assert_eq!(
        seen.iter()
            .filter(|kind| **kind == DiscardedFrame::Malformed)
            .count(),
        2
    );
    process.shutdown().await.unwrap();
}

#[tokio::test]
async fn repeated_malformed_output_retires_the_child() {
    let process = child(
        "import sys\nfor line in sys.stdin:\n for _ in range(3): print('garbage',flush=True)\n",
        128,
        Duration::from_secs(2),
    )
    .await;
    assert!(
        process
            .send(request())
            .await
            .unwrap_err()
            .0
            .contains("malformed")
    );
    assert!(
        process
            .send(request())
            .await
            .unwrap_err()
            .0
            .contains("retired")
    );
    process.shutdown().await.unwrap();
}
