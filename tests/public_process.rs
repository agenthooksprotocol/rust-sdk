#![cfg(feature = "tokio-process")]
use agenthooksprotocol::{
    adapters::process::Process,
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
    let process = child("import sys,json\nfor line in sys.stdin:\n if 'id' in json.loads(line):\n  print('{\"error\":\"denied\"}',flush=True)\n", 128, Duration::from_secs(2)).await;
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
        assert_eq!(response.body, br#"{"error":"denied"}"#);
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
    let script = "import sys,os\nfor line in sys.stdin: print(os.getpid(),flush=True)\n";
    let process = child(script, 128, Duration::from_secs(2)).await;
    let pid = String::from_utf8(process.send(request()).await.unwrap().body).unwrap();
    assert!(alive(&pid).await);
    process.shutdown().await.unwrap();
    assert!(!alive(&pid).await);

    let process = child(script, 128, Duration::from_secs(2)).await;
    let pid = String::from_utf8(process.send(request()).await.unwrap().body).unwrap();
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
    for body in [vec![b'x'; 33], b"{}\n{}".to_vec(), b"invalid".to_vec()] {
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
