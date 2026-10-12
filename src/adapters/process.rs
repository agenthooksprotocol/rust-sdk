//! Optional persistent JSON-lines subprocess transport, explicitly bound to Tokio.
//!
//! Call `spawn` inside a Tokio runtime with I/O and time enabled; no runtime is
//! created implicitly. Deadlines cover queueing, writes and reads. Cancellation,
//! timeout, EOF or framing failure permanently retires this process: a subsequent
//! call reaps it rather than reusing a possibly desynchronized stream. `shutdown`
//! kills and waits within its configured deadline, including queueing. A cleanup
//! timeout retains the child for a later shutdown attempt, never reports it reaped.
//! Dropping only initiates termination (Tokio
//! performs best-effort reaping while its runtime remains alive).
//!
//! Stdio has no HTTP status or headers. `Http::send` requires a JSON-RPC request
//! object with an `id` and returns status 200 with the unmodified body of the
//! child frame carrying that same `id`, including protocol error bodies. Use
//! `notify` for notifications, which deliberately do not wait for a response.
//! Child stdout must contain only newline-delimited protocol messages;
//! diagnostics belong on stderr.
//!
//! One background reader task owns child stdout for the child's lifetime and
//! routes each frame to the in-flight request by JSON-RPC `id`. Frames that
//! match no in-flight request (for example, an unsolicited frame after a
//! notification) are discarded and reported through [`Process::on_discard`];
//! they never fail a later request and never retire the child on their own.
//! Repeated consecutive malformed frames, an oversized or unterminated frame,
//! or stdout EOF stop the reader and retire the child.
use crate::transport::{Http, Request, Response, TransportError};
use serde_json::Value;
use std::{
    future::Future,
    pin::Pin,
    process::Stdio,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{Mutex as AsyncMutex, oneshot},
    task::JoinHandle,
};

/// Consecutive malformed stdout frames tolerated before the child is retired.
const MAX_CONSECUTIVE_MALFORMED: usize = 3;

/// Why a child stdout frame was discarded rather than delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscardedFrame {
    /// A well-formed frame arrived while no request was awaiting a response.
    Unsolicited,
    /// A well-formed frame whose `id` does not match the in-flight request.
    Uncorrelated,
    /// A frame that is not a JSON object.
    Malformed,
}

type DiscardHook = Arc<dyn Fn(DiscardedFrame) + Send + Sync>;
type Delivery = oneshot::Sender<Result<Vec<u8>, String>>;

#[derive(Default)]
struct Inbox {
    pending: Option<(Value, Delivery)>,
    /// Set once the reader stops; the child can no longer answer.
    fatal: Option<String>,
}
#[derive(Default)]
struct Shared {
    inbox: Mutex<Inbox>,
    discarded: AtomicU64,
    hook: RwLock<Option<DiscardHook>>,
}
impl Shared {
    fn discard(&self, kind: DiscardedFrame) {
        self.discarded.fetch_add(1, Ordering::Relaxed);
        let hook = self.hook.read().expect("discard hook lock").clone();
        if let Some(hook) = hook {
            hook(kind);
        }
    }
    fn fail(&self, message: String) {
        let mut inbox = self.inbox.lock().expect("process inbox lock");
        if let Some((_, delivery)) = inbox.pending.take() {
            let _ = delivery.send(Err(message.clone()));
        }
        inbox.fatal = Some(message);
    }
    fn fatal(&self) -> Option<String> {
        self.inbox.lock().expect("process inbox lock").fatal.clone()
    }
    /// Register the in-flight request before its frame is written, so that a
    /// fast response cannot be classified as unsolicited.
    fn expect(&self, id: Value) -> Result<oneshot::Receiver<Result<Vec<u8>, String>>, String> {
        let mut inbox = self.inbox.lock().expect("process inbox lock");
        if let Some(fatal) = &inbox.fatal {
            return Err(fatal.clone());
        }
        let (sender, receiver) = oneshot::channel();
        inbox.pending = Some((id, sender));
        Ok(receiver)
    }
    fn route(&self, frame: Vec<u8>, message: &Value) {
        let mut inbox = self.inbox.lock().expect("process inbox lock");
        let kind = match inbox.pending.take() {
            Some((id, delivery)) if message.get("id") == Some(&id) => {
                let _ = delivery.send(Ok(frame));
                return;
            }
            Some(pending) => {
                inbox.pending = Some(pending);
                DiscardedFrame::Uncorrelated
            }
            None => DiscardedFrame::Unsolicited,
        };
        drop(inbox);
        self.discard(kind);
    }
}

async fn read_loop(mut stdout: BufReader<ChildStdout>, limit: usize, shared: Arc<Shared>) {
    let mut malformed = 0;
    loop {
        let frame = match read_frame(&mut stdout, limit).await {
            Ok(frame) => frame,
            Err(failure) => return shared.fail(failure.0),
        };
        match serde_json::from_slice::<Value>(&frame) {
            Ok(message) if message.is_object() => {
                malformed = 0;
                shared.route(frame, &message);
            }
            _ => {
                malformed += 1;
                shared.discard(DiscardedFrame::Malformed);
                if malformed >= MAX_CONSECUTIVE_MALFORMED {
                    return shared.fail("repeated malformed child stdout output".into());
                }
            }
        }
    }
}

struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    reader: JoinHandle<()>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.reader.abort();
    }
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
    shared: Arc<Shared>,
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
        let shared = Arc::new(Shared::default());
        let reader = tokio::spawn(read_loop(stdout, max_frame_bytes, shared.clone()));
        Ok(Self {
            state: Mutex::new(State::Ready(Session {
                child,
                stdin: Some(stdin),
                reader,
            })),
            gate: AsyncMutex::new(()),
            shared,
            max_frame_bytes,
            deadline,
        })
    }

    /// Send a notification and return once the line is flushed, without waiting
    /// for stdout. Success is delivery to stdin, not acknowledgement by the child.
    /// Any frame the child writes in reply is discarded as unsolicited.
    pub async fn notify(&self, request: Request) -> Result<(), TransportError> {
        self.exchange(request.body, false).await.map(|_| ())
    }

    /// Observe discarded stdout frames (unsolicited, uncorrelated or malformed).
    /// The hook runs on the reader task and must not block. Frame contents are
    /// never passed to it. Replaces any previously installed hook.
    pub fn on_discard(&self, hook: impl Fn(DiscardedFrame) + Send + Sync + 'static) {
        *self.shared.hook.write().expect("discard hook lock") = Some(Arc::new(hook));
    }

    /// Total stdout frames discarded since spawn.
    pub fn discarded_frames(&self) -> u64 {
        self.shared.discarded.load(Ordering::Relaxed)
    }

    async fn exchange(
        &self,
        body: Vec<u8>,
        response_expected: bool,
    ) -> Result<Response, TransportError> {
        if body.len() > self.max_frame_bytes || body.contains(&b'\n') || body.contains(&b'\r') {
            return Err(error("invalid or oversized request frame"));
        }
        // Validate framing JSON and extract the correlation id only; protocol
        // validation belongs to the shared client/server dispatcher.
        let message = serde_json::from_slice::<Value>(&body).map_err(error)?;
        let id = if response_expected {
            Some(
                message
                    .get("id")
                    .cloned()
                    .ok_or_else(|| error("request frame has no JSON-RPC id"))?,
            )
        } else {
            None
        };
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
            // A stopped reader means the child can no longer answer: retire it.
            let receiver = match id {
                Some(id) => Some(self.shared.expect(id).map_err(error)?),
                None => match self.shared.fatal() {
                    Some(fatal) => return Err(error(fatal)),
                    None => None,
                },
            };
            let session = lease.session.as_mut().expect("process lease");
            let stdin = session.stdin.as_mut().expect("open child stdin");
            stdin.write_all(&body).await.map_err(error)?;
            stdin.write_all(b"\n").await.map_err(error)?;
            stdin.flush().await.map_err(error)?;
            let body = match receiver {
                Some(receiver) => receiver
                    .await
                    .map_err(|_| error("child stdout reader stopped"))?
                    .map_err(error)?,
                None => Vec::new(),
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
        tokio::time::timeout(lease.owner.deadline, session.child.wait())
            .await
            .map_err(|_| {
                error("subprocess cleanup deadline exceeded; child retained for shutdown")
            })?
            .map_err(error)?;
        lease.session.take();
        Ok(())
    }

    /// Close stdin after a per-event notification and allow bounded graceful exit.
    /// A timeout or unsuccessful exit is a delivery failure, never an acknowledgment.
    /// Queueing and graceful exit share `grace`; kill/reap then has at most the
    /// configured process deadline. Cancellation while owning the child retains
    /// it retired for a subsequent `shutdown` to reap.
    pub(crate) async fn finish_notification(&self, grace: Duration) -> Result<(), TransportError> {
        let graceful_deadline = tokio::time::Instant::now() + grace;
        let _gate = tokio::time::timeout_at(graceful_deadline, self.gate.lock())
            .await
            .map_err(|_| {
                error("notification queue deadline exceeded; child retained for shutdown")
            })?;
        let state = std::mem::replace(
            &mut *self.state.lock().expect("process state lock"),
            State::Closed,
        );
        let session = match state {
            State::Ready(session) => session,
            State::Retired(session) => {
                Self::terminate(&mut Lease {
                    owner: self,
                    session: Some(session),
                })
                .await?;
                return Err(error("notification process was retired"));
            }
            State::Closed => return Err(error("process is shut down")),
        };
        let mut lease = Lease {
            owner: self,
            session: Some(session),
        };
        let session = lease.session.as_mut().expect("process lease");
        // Dropping the pipe, rather than merely flushing it, delivers EOF.
        session.stdin.take();
        match tokio::time::timeout_at(graceful_deadline, session.child.wait()).await {
            Ok(Ok(status)) => {
                lease.session.take();
                if status.success() {
                    Ok(())
                } else {
                    Err(error("notification child exited unsuccessfully"))
                }
            }
            outcome => {
                Self::terminate(&mut lease).await?;
                Err(error(if outcome.is_err() {
                    "notification child exceeded graceful exit deadline"
                } else {
                    "notification child wait failed"
                }))
            }
        }
    }

    /// Serialize with active exchanges, terminate and reap the child. Idempotent.
    /// The configured process deadline bounds queueing and kill/reap together.
    /// Success means the child was reaped. Timeout or cancellation while reaping
    /// retains a retired child for retry; while queued, the active exchange keeps
    /// ownership and is not cancelled. Drop that exchange before retrying cleanup.
    pub async fn shutdown(&self) -> Result<(), TransportError> {
        tokio::time::timeout(self.deadline, self.shutdown_inner())
            .await
            .map_err(|_| error("subprocess shutdown deadline exceeded; cleanup must be retried"))?
    }

    async fn shutdown_inner(&self) -> Result<(), TransportError> {
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
    ) -> Pin<Box<dyn Future<Output = Result<Response, TransportError>> + Send + '_>> {
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
