//! Optional persistent JSON-lines subprocess transport, explicitly bound to Tokio.
//!
//! Call `spawn` inside a Tokio runtime with I/O and time enabled; no runtime is
//! created implicitly. Deadlines cover queueing, writes and reads. Cancellation,
//! timeout, EOF or framing failure permanently retires this process: a subsequent
//! call reaps it rather than reusing a possibly desynchronized stream. `shutdown`
//! deterministically kills and waits; dropping only initiates termination (Tokio
//! performs best-effort reaping while its runtime remains alive).
//!
//! Stdio has no HTTP status or headers. `Http::send` returns status 200 and the
//! unmodified response body, including protocol error bodies. Use `notify` for
//! notifications, which deliberately do not read a response. Child stdout must
//! contain only newline-delimited protocol messages; diagnostics belong on stderr.
use crate::transport::{Http, Request, Response, TransportError};
use std::{future::Future, pin::Pin, process::Stdio, sync::Mutex, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex as AsyncMutex,
};

struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}
enum State {
    Ready(Session),
    Retired(Session),
    Closed,
}

/// One persistent child, with serialized exchanges and bounded frames.
pub struct Process {
    state: Mutex<State>,
    gate: AsyncMutex<()>,
    max_frame_bytes: usize,
    deadline: Duration,
}

// Ownership follows the in-flight future. Dropping it cannot put an ambiguous
// stream back into the reusable state, including while shutdown is cancelled.
struct Lease<'a> {
    owner: &'a Process,
    session: Option<Session>,
}
impl Lease<'_> {
    fn restore(mut self) {
        *self.owner.state.lock().expect("process state lock") =
            State::Ready(self.session.take().expect("process lease"));
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Some(mut session) = self.session.take() {
            let _ = session.child.start_kill();
            *self.owner.state.lock().expect("process state lock") = State::Retired(session);
        }
    }
}
fn error(value: impl std::fmt::Display) -> TransportError {
    TransportError(value.to_string())
}

impl Process {
    /// Spawn in the caller's Tokio runtime. Stdin/stdout are piped and stderr is
    /// inherited. The supplied command is configured with `kill_on_drop(true)`.
    /// A zero frame limit or deadline is rejected before spawning.
    pub async fn spawn(
        mut command: Command,
        max_frame_bytes: usize,
        deadline: Duration,
    ) -> Result<Self, TransportError> {
        tokio::runtime::Handle::try_current().map_err(error)?;
        if max_frame_bytes == 0 || deadline.is_zero() {
            return Err(error("frame limit and deadline must be positive"));
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(error)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| error("missing child stdin"))?;
        let stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| error("missing child stdout"))?,
        );
        Ok(Self {
            state: Mutex::new(State::Ready(Session {
                child,
                stdin,
                stdout,
            })),
            gate: AsyncMutex::new(()),
            max_frame_bytes,
            deadline,
        })
    }

    /// Send a notification and return once the line is flushed, without waiting
    /// for stdout. Success is delivery to stdin, not acknowledgement by the child.
    pub async fn notify(&self, request: Request) -> Result<(), TransportError> {
        self.exchange(request.body, false).await.map(|_| ())
    }

    async fn exchange(
        &self,
        body: Vec<u8>,
        response_expected: bool,
    ) -> Result<Response, TransportError> {
        if body.len() > self.max_frame_bytes || body.contains(&b'\n') || body.contains(&b'\r') {
            return Err(error("invalid or oversized request frame"));
        }
        // Validate framing JSON only; protocol validation belongs to the shared
        // client/server dispatcher, not this adapter.
        serde_json::from_slice::<serde_json::Value>(&body).map_err(error)?;
        tokio::time::timeout(self.deadline, async {
            let _gate = self.gate.lock().await;
            let state = std::mem::replace(
                &mut *self.state.lock().expect("process state lock"),
                State::Closed,
            );
            let mut lease = match state {
                State::Ready(session) => Lease {
                    owner: self,
                    session: Some(session),
                },
                State::Retired(session) => {
                    let mut lease = Lease {
                        owner: self,
                        session: Some(session),
                    };
                    Self::terminate(&mut lease).await?;
                    return Err(error(
                        "process retired after an interrupted or failed exchange",
                    ));
                }
                State::Closed => return Err(error("process is shut down")),
            };
            let session = lease.session.as_mut().expect("process lease");
            session.stdin.write_all(&body).await.map_err(error)?;
            session.stdin.write_all(b"\n").await.map_err(error)?;
            session.stdin.flush().await.map_err(error)?;
            let body = if response_expected {
                read_frame(&mut session.stdout, self.max_frame_bytes).await?
            } else {
                Vec::new()
            };
            lease.restore();
            Ok(Response {
                status: if response_expected { 200 } else { 204 },
                body,
                ..Response::default()
            })
        })
        .await
        .map_err(|_| error("subprocess deadline exceeded; active exchange retired"))?
    }

    async fn terminate(lease: &mut Lease<'_>) -> Result<(), TransportError> {
        let session = lease.session.as_mut().expect("process lease");
        // start_kill can fail if the child already exited; wait is authoritative.
        let _ = session.child.start_kill();
        session.child.wait().await.map_err(error)?;
        lease.session.take();
        Ok(())
    }

    /// Serialize with active exchanges, terminate and reap the child. Idempotent.
    /// If this future is cancelled, termination is initiated and a later shutdown
    /// can finish waiting. An active exchange has its configured deadline.
    pub async fn shutdown(&self) -> Result<(), TransportError> {
        let _gate = self.gate.lock().await;
        let state = std::mem::replace(
            &mut *self.state.lock().expect("process state lock"),
            State::Closed,
        );
        match state {
            State::Ready(session) | State::Retired(session) => {
                Self::terminate(&mut Lease {
                    owner: self,
                    session: Some(session),
                })
                .await
            }
            State::Closed => Ok(()),
        }
    }
}
impl Http for Process {
    fn send(
        &self,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Response, TransportError>> + '_>> {
        Box::pin(self.exchange(request.body, true))
    }
}

async fn read_frame(
    reader: &mut BufReader<ChildStdout>,
    limit: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(error)?;
        if available.is_empty() {
            return Err(error(if frame.is_empty() {
                "child stdout EOF"
            } else {
                "unterminated child stdout frame"
            }));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.unwrap_or(available.len());
        if frame.len().saturating_add(count) > limit {
            return Err(error("child stdout frame too large"));
        }
        frame.extend_from_slice(&available[..count]);
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(frame);
        }
    }
}
