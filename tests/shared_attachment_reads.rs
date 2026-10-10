use agenthooksprotocol::{
    Attachment, Hooks,
    body::{BodyChunkFuture, BodyError, BodyStream},
    ergonomic_inputs::{HostInput, MessageInput, PartInput, UserMessageOutboundInput},
    generated::CanonicalMessageRole,
    hooks::{Capabilities, EventGrant, HooksOptions},
};
use futures::executor::block_on;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::{Future, poll_fn},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

fn hooks(limit: usize) -> Hooks {
    let mut options = HooksOptions::new(
        "urn:test:attachments",
        BTreeMap::from([(
            "user.message.outbound".into(),
            EventGrant::intercept(Capabilities::none()),
        )]),
    );
    options.max_body_bytes = limit;
    Hooks::new(
        registration(),
        options.with_backend("org.example.attachments", Arc::new(Noop)),
    )
    .unwrap()
}
fn event() -> Value {
    json!({"type":"user.message.outbound", "message":{"channel":"chat", "messages":[{
        "id":"message", "role":"assistant", "parts":[{"id":"body", "kind":"attachment", "mediaType":"application/octet-stream", "selection":"body", "body":{"ref":"ahp:host-pending"}}]
    }]}})
}
fn attachment_input(
    event: Value,
    attachment: Attachment,
) -> HostInput<UserMessageOutboundInput, Attachment> {
    let metadata =
        serde_json::from_value(event["message"]["messages"][0]["parts"][0].clone()).unwrap();
    let input: UserMessageOutboundInput = serde_json::from_value(event).unwrap();
    input
        .with_sources()
        .with_message_messages(vec![MessageInput::from_parts(
            CanonicalMessageRole::Assistant,
            vec![PartInput::attachment(metadata, attachment)],
        )])
}
fn registration() -> Value {
    json!({"protocolVersion":"draft", "hooks":[{
        "id":"org.example.attachments", "transport":{"type":"stdio","command":"never-run","lifecycle":"persistent"},
        "subscriptions":[{"events":["user.message.outbound"],"mode":"intercept","timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":"metadata"}}]
    }]})
}
struct Noop;
impl agenthooksprotocol::adapters::registered::ManagedBackend for Noop {
    fn call(
        &self,
        request: Value,
        _: std::time::Duration,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        Result<Value, agenthooksprotocol::client::HookError>,
    > {
        Box::pin(async move {
            Ok(
                json!({"jsonrpc":"2.0", "id":request["id"],"result":{"protocolVersion":"draft","effects":[]}}),
            )
        })
    }
    fn shutdown(
        &self,
    ) -> agenthooksprotocol::client::LocalFuture<
        '_,
        Result<(), agenthooksprotocol::client::HookError>,
    > {
        Box::pin(async { Ok(()) })
    }
}

const PATH: &str = "/message/messages/0/parts/0";
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    waker: Mutex<Option<Waker>>,
}
impl Gate {
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}
struct Source {
    gate: Arc<Gate>,
    reads: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    done: bool,
    fail: bool,
}
impl Drop for Source {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl BodyStream for Source {
    fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            poll_fn(|cx| {
                if *self.gate.open.lock().unwrap() {
                    Poll::Ready(())
                } else {
                    *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await;
            if self.fail {
                Err(BodyError::Read("shared source failure".into()))
            } else if self.done {
                Ok(None)
            } else {
                self.done = true;
                Ok(Some(vec![0, 255, 42]))
            }
        })
    }
}
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn setup(
    fail: bool,
) -> (
    agenthooksprotocol::content::OwnedContent,
    Arc<Gate>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let gate = Arc::new(Gate::default());
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let hooks = hooks(10);
    let result = block_on(
        hooks
            .user_message_outbound(attachment_input(
                event(),
                Attachment::lazy(Source {
                    gate: gate.clone(),
                    reads: reads.clone(),
                    drops: drops.clone(),
                    done: false,
                    fail,
                }),
            ))
            .into_future(),
    )
    .unwrap();
    block_on(hooks.shutdown()).unwrap();
    drop(hooks);
    (result.content, gate, reads, drops)
}
fn assert_send<T: Send>(_: &T) {}

#[test]
fn overlapping_reads_share_backing_and_wake_all_waiters_after_shutdown() {
    let (content, gate, reads, drops) = setup(false);
    let mut first = Box::pin(content.read(PATH));
    let mut second = Box::pin(content.read(PATH));
    assert_send(&first);
    let a = Arc::new(Counter(AtomicUsize::new(0)));
    let b = Arc::new(Counter(AtomicUsize::new(0)));
    let wa = Waker::from(a.clone());
    let wb = Waker::from(b.clone());
    assert!(
        first
            .as_mut()
            .poll(&mut Context::from_waker(&wa))
            .is_pending()
    );
    assert!(
        second
            .as_mut()
            .poll(&mut Context::from_waker(&wb))
            .is_pending()
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    gate.release();
    assert!(a.0.load(Ordering::SeqCst) > 0);
    assert!(b.0.load(Ordering::SeqCst) > 0);
    let one = block_on(first).unwrap();
    let two = block_on(second).unwrap();
    let three = block_on(content.read(PATH)).unwrap();
    assert_eq!(&*one, &[0, 255, 42]);
    assert!(Arc::ptr_eq(&one, &two));
    assert!(Arc::ptr_eq(&one, &three));
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn cancelling_one_waiter_keeps_the_shared_source_alive() {
    let (content, gate, reads, drops) = setup(false);
    let mut first = Box::pin(content.read(PATH));
    let mut second = Box::pin(content.read(PATH));
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    drop(first);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    gate.release();
    assert_eq!(&*block_on(second).unwrap(), &[0, 255, 42]);
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn cancelling_last_active_waiter_is_terminal_and_drops_source_once() {
    let (content, gate, reads, drops) = setup(false);
    let mut first = Box::pin(content.read(PATH));
    let mut second = Box::pin(content.read(PATH));
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    drop(second);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(first);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    gate.release();
    assert!(
        matches!(block_on(content.read(PATH)), Err(BodyError::Read(message))
        if message.contains("cancelled"))
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    drop(content);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn overlapping_errors_are_retained_without_rereading_the_source() {
    let (content, gate, reads, drops) = setup(true);
    let mut first = Box::pin(content.read(PATH));
    let mut second = Box::pin(content.read(PATH));
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    gate.release();
    for error in [
        block_on(first),
        block_on(second),
        block_on(content.read(PATH)),
    ] {
        assert!(
            matches!(error, Err(BodyError::Read(message)) if message == "shared source failure")
        );
    }
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn unpolled_reader_does_not_cancel_source_and_unread_owner_drop_cleans_up() {
    let (content, _, reads, drops) = setup(false);
    drop(content.read(PATH));
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(content);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
