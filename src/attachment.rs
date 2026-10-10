//! Owned binary sources. Invocation indexes contain owners, never stored body copies.
use crate::{
    body::{Body, BodyError, BodyStream},
    content::{ContentAccess, UploadError},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

/// A single-invocation attachment. Dropping an unread owner drops its source.
/// Metadata belongs to the bound content item, not a separate descriptor.
pub struct Attachment(Input);
enum Input {
    Bytes(Arc<[u8]>),
    Lazy(Body),
}
impl Attachment {
    pub fn bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Input::Bytes(bytes.into().into()))
    }
    pub fn lazy(source: impl BodyStream + 'static) -> Self {
        Self::from_body(Body::stream(source))
    }
    pub fn from_body(body: Body) -> Self {
        Self(Input::Lazy(body))
    }
    pub fn with_max_chunks(self, limit: usize) -> Self {
        match self.0 {
            Input::Lazy(body) => Self::from_body(body.with_max_chunks(limit)),
            _ => self,
        }
    }
    fn bind(
        self,
        budget: &Arc<Budget>,
        limit: usize,
        metadata: Value,
    ) -> Result<SharedAttachment, BodyError> {
        let (state, size) = match self.0 {
            Input::Bytes(bytes) => {
                let size = bytes.len();
                (State::Ready(bytes), size)
            }
            Input::Lazy(body) => (State::Pending(body), 0),
        };
        if size > limit {
            return Err(BodyError::TooLarge { limit });
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Ok(SharedAttachment(Arc::new(Owner {
            state: Mutex::new(state),
            limit,
            metadata,
            reference: json!({"ref":format!("ahp-attachment:{}", NEXT.fetch_add(1, Ordering::Relaxed))}),
            charge: Arc::new(Mutex::new(Some(budget.acquire(size)?))),
            planning: AtomicUsize::new(0),
        })))
    }
}

/// Non-owning accounting shared by active invocations. No bytes or handles live here.
pub(crate) struct Budget {
    usage: Mutex<(usize, usize)>,
    max_bytes: usize,
    max_entries: usize,
}
impl Budget {
    pub(crate) fn new(max_bytes: usize, max_entries: usize) -> Arc<Self> {
        Arc::new(Self {
            usage: Mutex::new((0, 0)),
            max_bytes,
            max_entries,
        })
    }
    fn acquire(self: &Arc<Self>, bytes: usize) -> Result<Charge, BodyError> {
        let mut usage = self.usage.lock().unwrap_or_else(|e| e.into_inner());
        if bytes > self.max_bytes.saturating_sub(usage.0) || usage.1 >= self.max_entries {
            return Err(BodyError::Capacity);
        }
        usage.0 += bytes;
        usage.1 += 1;
        Ok(Charge {
            budget: self.clone(),
            bytes,
        })
    }
}
struct Charge {
    budget: Arc<Budget>,
    bytes: usize,
}
impl Charge {
    fn reserve(&mut self, bytes: usize) -> Result<(), BodyError> {
        let mut usage = self.budget.usage.lock().unwrap_or_else(|e| e.into_inner());
        if bytes > self.budget.max_bytes.saturating_sub(usage.0) {
            return Err(BodyError::Capacity);
        }
        usage.0 += bytes;
        self.bytes += bytes;
        Ok(())
    }
}
impl Charge {
    fn release_bytes(&mut self) {
        let mut usage = self.budget.usage.lock().unwrap_or_else(|e| e.into_inner());
        usage.0 -= self.bytes;
        self.bytes = 0;
    }
}
// Numerical accounting only: no owner pointer, payload, or backing cache.
struct PartialCharge {
    charge: Arc<Mutex<Option<Charge>>>,
    committed: bool,
}
impl Drop for PartialCharge {
    fn drop(&mut self) {
        if !self.committed
            && let Some(charge) = self
                .charge
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_mut()
        {
            charge.release_bytes();
        }
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        let mut usage = self.budget.usage.lock().unwrap_or_else(|e| e.into_inner());
        usage.0 -= self.bytes;
        usage.1 -= 1;
    }
}
#[derive(Clone)]
pub(crate) struct SharedAttachment(Arc<Owner>);
struct Owner {
    state: Mutex<State>,
    limit: usize,
    metadata: Value,
    reference: Value,
    charge: Arc<Mutex<Option<Charge>>>,
    planning: AtomicUsize,
}
enum State {
    Pending(Body),
    Reading {
        future: Pin<Box<dyn Future<Output = Result<Vec<u8>, BodyError>> + Send>>,
        wake: Arc<ReadWake>,
    },
    Failed(BodyError),
    Cancelled,
    Ready(Arc<[u8]>),
}

// Fan out the source waker without retaining the attachment owner.
struct ReadWake {
    notified: AtomicBool,
    waiters: Mutex<BTreeMap<u64, Waker>>,
}
impl ReadWake {
    fn notify(&self) {
        self.notified.store(true, Ordering::Release);
        let waiters: Vec<_> = self
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        for waiter in waiters {
            waiter.wake();
        }
    }
}
impl Wake for ReadWake {
    fn wake(self: Arc<Self>) {
        self.notify();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

// serde_json::Error is not Clone; retain its diagnostic using its public
// IO constructor. All spool and upload errors preserve their typed variants.
fn copy_error(error: &BodyError) -> BodyError {
    match error {
        BodyError::Json(error) => BodyError::Json(serde_json::Error::io(std::io::Error::other(
            error.to_string(),
        ))),
        BodyError::Read(message) => BodyError::Read(message.clone()),
        BodyError::TooLarge { limit } => BodyError::TooLarge { limit: *limit },
        BodyError::TooManyChunks { limit } => BodyError::TooManyChunks { limit: *limit },
        BodyError::Capacity => BodyError::Capacity,
        BodyError::Upload(error) => BodyError::Upload(error.clone()),
    }
}

struct AttachmentRead<'a> {
    owner: &'a SharedAttachment,
    limit: usize,
    registration: Option<(Arc<ReadWake>, u64)>,
}
impl Future for AttachmentRead<'_> {
    type Output = Result<Arc<[u8]>, BodyError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let owner = self.owner;
        let mut state = owner.0.state.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(*state, State::Pending(_)) {
            let State::Pending(body) = std::mem::replace(&mut *state, State::Cancelled) else {
                unreachable!()
            };
            let limit = owner.0.limit;
            let charge = owner.0.charge.clone();
            *state = State::Reading {
                future: Box::pin(async move {
                    let mut partial = PartialCharge {
                        charge,
                        committed: false,
                    };
                    let bytes = body
                        .into_bytes_accounted(limit, |size| {
                            if let Some(charge) = partial
                                .charge
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .as_mut()
                            {
                                charge.reserve(size)?;
                            }
                            Ok(())
                        })
                        .await?;
                    partial.committed = true;
                    Ok(bytes)
                }),
                wake: Arc::new(ReadWake {
                    notified: AtomicBool::new(true),
                    waiters: Mutex::new(BTreeMap::new()),
                }),
            };
        }
        let mut completed_wake = None;
        if let State::Reading { future, wake } = &mut *state {
            let id = match &self.registration {
                Some((_, id)) => *id,
                None => {
                    static NEXT_WAITER: AtomicU64 = AtomicU64::new(0);
                    let id = NEXT_WAITER.fetch_add(1, Ordering::Relaxed);
                    self.registration = Some((wake.clone(), id));
                    id
                }
            };
            wake.waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id, cx.waker().clone());
            if !wake.notified.swap(false, Ordering::AcqRel) {
                return Poll::Pending;
            }
            let waker = Waker::from(wake.clone());
            let mut source_cx = Context::from_waker(&waker);
            match future.as_mut().poll(&mut source_cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    completed_wake = Some(wake.clone());
                    let result = result.and_then(|bytes| {
                        let bytes: Arc<[u8]> = bytes.into();
                        owner.validate(&bytes, owner.0.limit)?;
                        Ok(bytes)
                    });
                    *state = match result {
                        Ok(bytes) => State::Ready(bytes),
                        Err(error) => {
                            if let Some(charge) = owner
                                .0
                                .charge
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .as_mut()
                            {
                                charge.release_bytes();
                            }
                            State::Failed(error)
                        }
                    };
                }
            }
        }
        let result = match &*state {
            State::Ready(bytes) => owner.validate(bytes, self.limit).map(|()| bytes.clone()),
            State::Failed(error) => Err(copy_error(error)),
            State::Cancelled => Err(BodyError::Read("attachment read cancelled".into())),
            _ => unreachable!(),
        };
        drop(state);
        if let Some(wake) = completed_wake {
            wake.notify();
        }
        Poll::Ready(result)
    }
}
impl Drop for AttachmentRead<'_> {
    fn drop(&mut self) {
        if let Some((wake, id)) = self.registration.take() {
            let mut state = self.owner.0.state.lock().unwrap_or_else(|e| e.into_inner());
            let empty = {
                let mut waiters = wake.waiters.lock().unwrap_or_else(|e| e.into_inner());
                waiters.remove(&id);
                waiters.is_empty()
            };
            if empty
                && self.owner.0.planning.load(Ordering::Acquire) == 0
                && matches!(*state, State::Reading { .. })
            {
                // No detached driver: losing the last polled reader is terminal.
                *state = State::Cancelled;
            }
        }
    }
}
impl SharedAttachment {
    fn validate(&self, bytes: &Arc<[u8]>, limit: usize) -> Result<(), BodyError> {
        if bytes.len() > limit {
            return Err(BodyError::TooLarge { limit });
        }
        crate::content::validate_attachment_metadata(&self.0.metadata, bytes)
            .map_err(BodyError::Upload)
    }
    pub(crate) async fn read(&self) -> Result<Arc<[u8]>, BodyError> {
        self.read_limited(self.0.limit).await
    }
    async fn read_limited(&self, limit: usize) -> Result<Arc<[u8]>, BodyError> {
        AttachmentRead {
            owner: self,
            limit: limit.min(self.0.limit),
            registration: None,
        }
        .await
    }
    pub(crate) fn ready(&self) -> Result<Arc<[u8]>, UploadError> {
        let state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        match &*state {
            State::Ready(bytes) => {
                self.validate(bytes, self.0.limit)
                    .map_err(|_| UploadError::Descriptor)?;
                Ok(bytes.clone())
            }
            _ => Err(UploadError::Unavailable),
        }
    }
    pub(crate) fn ready_for(&self, item: &Value) -> Result<Arc<[u8]>, UploadError> {
        if item["body"] != self.0.reference {
            return Err(UploadError::Descriptor);
        }
        let bytes = self.ready()?;
        crate::content::validate_attachment_metadata(item, &bytes)?;
        Ok(bytes)
    }
    fn detach(&self) {
        self.0
            .charge
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
}

/// An invocation's slot-to-owner index. Clones share the index; transactions clone
/// only its owner pointers, never backing bytes. Local references are shape markers
/// for canonical events and are never looked up to obtain content.
#[derive(Clone)]
pub(crate) struct InvocationAttachments {
    slots: Arc<Mutex<BTreeMap<String, SharedAttachment>>>,
    // Transaction checkpoint: shared owner pointers only, never payload copies.
    originals: Option<Arc<BTreeMap<String, SharedAttachment>>>,
    budget: Arc<Budget>,
    limit: usize,
}
// Pending authorized fanout consumers keep a coalesced source alive even when
// a short-lived route times out before another bounded planner reaches it.
pub(crate) struct PlanningReads(Vec<SharedAttachment>);
impl Drop for PlanningReads {
    fn drop(&mut self) {
        for owner in &self.0 {
            if owner.0.planning.fetch_sub(1, Ordering::AcqRel) == 1 {
                let mut state = owner.0.state.lock().unwrap_or_else(|e| e.into_inner());
                if let State::Reading { wake, .. } = &*state
                    && wake
                        .waiters
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .is_empty()
                {
                    *state = State::Cancelled;
                }
            }
        }
    }
}
impl InvocationAttachments {
    pub(crate) fn planning_reads(&self) -> PlanningReads {
        let owners = self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for owner in &owners {
            owner.0.planning.fetch_add(1, Ordering::AcqRel);
        }
        PlanningReads(owners)
    }
    pub(crate) fn bind(
        event: &mut Value,
        bindings: Vec<crate::ergonomic_inputs::ContentSourceBinding<Attachment>>,
        budget: Arc<Budget>,
        limit: usize,
    ) -> Result<Self, BodyError> {
        let mut slots = BTreeMap::new();
        let allowed_slots = crate::hooks_content::locations(event);
        for binding in bindings {
            let path = format!(
                "/{}",
                binding
                    .path
                    .iter()
                    .map(|part| part.replace('~', "~0").replace('/', "~1"))
                    .collect::<Vec<_>>()
                    .join("/")
            );
            if !allowed_slots.contains(&path) {
                return Err(BodyError::Read(
                    "attachment binding must address a canonical content slot".into(),
                ));
            }
            if slots.contains_key(&path) {
                return Err(BodyError::Read("duplicate attachment slot".into()));
            }
            let item = event
                .pointer_mut(&path)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| BodyError::Read("attachment slot requires a content item".into()))?;
            if item.get("kind") != Some(&json!("attachment")) {
                return Err(BodyError::Read(
                    "owned body requires a binary attachment part".into(),
                ));
            }
            let mut metadata = serde_json::Map::new();
            for key in ["size", "sha256"] {
                if let Some(value) = item.remove(key) {
                    metadata.insert(key.into(), value);
                }
            }
            let owner = binding
                .source
                .bind(&budget, limit, Value::Object(metadata))?;
            item.remove("gap");
            item.insert("selection".into(), json!("body"));
            item.insert("body".into(), owner.0.reference.clone());
            slots.insert(path, owner);
        }
        Ok(Self {
            slots: Arc::new(Mutex::new(slots)),
            originals: None,
            budget,
            limit,
        })
    }
    pub(crate) fn fork(&self) -> Self {
        let original = self.slots.lock().unwrap_or_else(|e| e.into_inner()).clone();
        Self {
            slots: Arc::new(Mutex::new(original.clone())),
            originals: Some(Arc::new(original)),
            budget: self.budget.clone(),
            limit: self.limit,
        }
    }
    pub(crate) fn commit(&self, staged: Self) {
        let next = staged
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let old = std::mem::replace(
            &mut *self.slots.lock().unwrap_or_else(|e| e.into_inner()),
            next,
        );
        drop(old);
    }
    pub(crate) async fn materialize(
        &self,
        path: &str,
        max_bytes: usize,
    ) -> Result<Arc<[u8]>, BodyError> {
        let owner = self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)
            .cloned()
            .ok_or_else(|| BodyError::Read("missing attachment slot".into()))?;
        owner.read_limited(max_bytes).await
    }
    #[cfg(test)]
    pub(crate) fn metadata(&self, path: &str) -> Option<Value> {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)
            .map(|owner| owner.0.metadata.clone())
    }
    pub(crate) fn finish_for(&self, event: &Value) -> crate::content::OwnedContent {
        let allowed = crate::hooks_content::locations(event);
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let remapped = allowed
            .into_iter()
            .filter_map(|path| {
                let item = event.pointer(&path)?;
                let owner = slots
                    .values()
                    .chain(
                        self.originals
                            .iter()
                            .flat_map(|originals| originals.values()),
                    )
                    .find(|owner| item["body"] == owner.0.reference)?;
                Some((path, owner.clone()))
            })
            .collect();
        // Match only canonical final slots, not references in opaque JSON.
        // Multiple final slots may retain the same original immutable owner.
        *slots = remapped;
        drop(slots);
        self.finish()
    }
    pub(crate) fn finish(&self) -> crate::content::OwnedContent {
        let slots = self.slots.lock().unwrap_or_else(|e| e.into_inner()).clone();
        for owner in slots.values() {
            owner.detach();
        }
        crate::content::OwnedContent { attachments: slots }
    }
}
impl ContentAccess for InvocationAttachments {
    fn restore_original(&self, path: &str, item: &Value) -> Result<(), UploadError> {
        let original = self
            .originals
            .as_ref()
            .and_then(|slots| slots.get(path))
            .ok_or(UploadError::Unavailable)?;
        original.ready_for(item)?;
        let old = self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path.into(), original.clone());
        drop(old);
        Ok(())
    }

    fn resolve_selected(&self, path: &str, item: &Value) -> Result<Option<Arc<[u8]>>, UploadError> {
        if item["selection"] == "metadata" || item["selection"] == "omit" {
            return Ok(None);
        }
        if item["selection"] != "body" || item.get("gap").is_some() {
            return Err(UploadError::Unavailable);
        }
        let slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let owner = slots
            .get(path)
            .filter(|owner| item["body"] == owner.0.reference)
            .or_else(|| {
                slots
                    .values()
                    .chain(
                        self.originals
                            .iter()
                            .flat_map(|originals| originals.values()),
                    )
                    .find(|owner| item["body"] == owner.0.reference)
            })
            .cloned()
            .ok_or(UploadError::Unavailable)?;
        drop(slots);
        owner.ready_for(item).map(Some)
    }
    fn put(&self, path: &str, bytes: &[u8]) -> Result<Value, UploadError> {
        let owner = Attachment::bytes(bytes.to_vec())
            .bind(&self.budget, self.limit, json!({}))
            .map_err(|error| match error {
                BodyError::TooLarge { .. } => UploadError::TooLarge,
                _ => UploadError::Capacity,
            })?;
        let reference = owner.0.reference.clone();
        let old = self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path.into(), owner);
        drop(old);
        Ok(reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    fn invocation(owner: SharedAttachment) -> InvocationAttachments {
        InvocationAttachments {
            slots: Arc::new(Mutex::new(BTreeMap::from([(
                "/message/messages/0/parts/0".into(),
                owner,
            )]))),
            originals: None,
            budget: Budget::new(100, 10),
            limit: 10,
        }
    }

    struct ChunkThenGate {
        phase: usize,
        advance: Arc<AtomicBool>,
        eof: Arc<AtomicBool>,
        wake: Arc<Mutex<Option<Waker>>>,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for ChunkThenGate {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }
    impl crate::body::BodyStream for ChunkThenGate {
        fn next_chunk(&mut self) -> crate::body::BodyChunkFuture<'_> {
            Box::pin(std::future::poll_fn(move |cx| {
                if self.phase == 0 || (self.phase == 1 && self.advance.load(Ordering::Acquire)) {
                    self.phase += 1;
                    return Poll::Ready(Ok(Some(vec![42; 128 * 1024])));
                }
                if self.phase == 2 && self.eof.load(Ordering::Acquire) {
                    return Poll::Ready(Ok(None));
                }
                *self.wake.lock().unwrap() = Some(cx.waker().clone());
                Poll::Pending
            }))
        }
    }

    #[test]
    fn eight_distinct_materializations_reserve_before_accepting_chunks() {
        block_on(async {
            const CAP: usize = 1024 * 1024;
            const CHUNK: usize = 128 * 1024;
            let budget = Budget::new(CAP, 8);
            let advance = Arc::new(AtomicBool::new(false));
            let dropped = Arc::new(AtomicUsize::new(0));
            let wakes: Vec<_> = (0..8)
                .map(|_| Arc::new(Mutex::new(None::<Waker>)))
                .collect();
            let owners: Vec<_> = wakes
                .iter()
                .map(|wake| {
                    Attachment::lazy(ChunkThenGate {
                        phase: 0,
                        advance: advance.clone(),
                        eof: Arc::new(AtomicBool::new(false)),
                        wake: wake.clone(),
                        dropped: dropped.clone(),
                    })
                    .bind(&budget, CAP, json!({}))
                    .unwrap()
                })
                .collect();
            let mut reads: Vec<_> = owners.iter().map(|owner| Box::pin(owner.read())).collect();
            // All eight distinct sources are active; each accepted one chunk.
            for (index, read) in reads.iter_mut().enumerate() {
                assert!(futures::poll!(read.as_mut()).is_pending());
                assert_eq!(budget.usage.lock().unwrap().0, (index + 1) * CHUNK);
            }
            assert_eq!(budget.usage.lock().unwrap().0, CAP);
            advance.store(true, Ordering::Release);
            for wake in &wakes {
                wake.lock().unwrap().as_ref().unwrap().wake_by_ref();
            }
            let mut rejected = 0;
            for (index, read) in reads.iter_mut().enumerate() {
                match futures::poll!(read.as_mut()) {
                    Poll::Ready(Err(BodyError::Capacity)) => {
                        rejected += 1;
                        assert!(matches!(
                            *owners[index].0.state.lock().unwrap(),
                            State::Failed(_)
                        ));
                        assert_eq!(
                            owners[index]
                                .0
                                .charge
                                .lock()
                                .unwrap()
                                .as_ref()
                                .unwrap()
                                .bytes,
                            0
                        );
                        assert_eq!(dropped.load(Ordering::Acquire), rejected);
                    }
                    Poll::Pending => {
                        assert_eq!(
                            owners[index]
                                .0
                                .charge
                                .lock()
                                .unwrap()
                                .as_ref()
                                .unwrap()
                                .bytes,
                            2 * CHUNK
                        );
                    }
                    other => panic!("unexpected read result: {other:?}"),
                }
                let accepted: usize = owners
                    .iter()
                    .map(|o| o.0.charge.lock().unwrap().as_ref().unwrap().bytes)
                    .sum();
                assert_eq!(budget.usage.lock().unwrap().0, accepted);
                assert!(accepted <= CAP);
            }
            assert_eq!(rejected, 4);
            assert_eq!(budget.usage.lock().unwrap().0, CAP);
            // Cancelling the EOF-blocked consumers frees all accepted partial bytes.
            drop(reads);
            assert_eq!(budget.usage.lock().unwrap().0, 0);
            assert_eq!(dropped.load(Ordering::Acquire), 8);
            drop(owners);
            assert_eq!(*budget.usage.lock().unwrap(), (0, 0));
        });
    }

    #[test]
    fn successful_capture_keeps_one_charge_until_result_transfer() {
        block_on(async {
            let budget = Budget::new(6, 2);
            let owner = Attachment::from_body(Body::bytes(vec![1, 2, 3]))
                .bind(&budget, 10, json!({}))
                .unwrap();
            let bytes = owner.read().await.unwrap();
            assert_eq!(*budget.usage.lock().unwrap(), (3, 1));
            assert!(Arc::ptr_eq(&bytes, &owner.read().await.unwrap()));
            assert_eq!(*budget.usage.lock().unwrap(), (3, 1));
            owner.detach();
            assert_eq!(*budget.usage.lock().unwrap(), (0, 0));
            assert!(Arc::ptr_eq(&bytes, &owner.read().await.unwrap()));
            // Unread result owners are detached and retain only the per-body limit.
            let unread = Attachment::from_body(Body::bytes(vec![4; 8]))
                .bind(&budget, 10, json!({}))
                .unwrap();
            unread.detach();
            assert_eq!(unread.read().await.unwrap().len(), 8);
            assert_eq!(*budget.usage.lock().unwrap(), (0, 0));
        });
    }

    #[test]
    fn validation_failure_releases_successfully_spooled_reservations() {
        let budget = Budget::new(3, 1);
        let owner = Attachment::from_body(Body::bytes(vec![1, 2, 3]))
            .bind(&budget, 10, json!({"size":4}))
            .unwrap();
        assert!(block_on(owner.read()).is_err());
        assert_eq!(*budget.usage.lock().unwrap(), (0, 1));
        drop(owner);
        assert_eq!(*budget.usage.lock().unwrap(), (0, 0));
    }

    struct FailingSource(bool);
    impl crate::body::BodyStream for FailingSource {
        fn next_chunk(&mut self) -> crate::body::BodyChunkFuture<'_> {
            Box::pin(async move {
                if self.0 {
                    return Err(BodyError::Read("producer failure".into()));
                }
                self.0 = true;
                Ok(Some(vec![1, 2, 3]))
            })
        }
    }

    #[test]
    fn source_failure_and_per_body_limit_release_partial_bytes() {
        let budget = Budget::new(10, 2);
        let owner = Attachment::lazy(FailingSource(false))
            .bind(&budget, 10, json!({}))
            .unwrap();
        assert!(matches!(block_on(owner.read()), Err(BodyError::Read(_))));
        assert_eq!(*budget.usage.lock().unwrap(), (0, 1));
        let owner = Attachment::lazy(ChunkThenGate {
            phase: 0,
            advance: Arc::new(AtomicBool::new(true)),
            eof: Arc::new(AtomicBool::new(true)),
            wake: Arc::new(Mutex::new(None)),
            dropped: Arc::new(AtomicUsize::new(0)),
        })
        .bind(&Budget::new(1024 * 1024, 1), 128 * 1024, json!({}))
        .unwrap();
        assert!(matches!(
            block_on(owner.read()),
            Err(BodyError::TooLarge { .. })
        ));
        assert_eq!(owner.0.charge.lock().unwrap().as_ref().unwrap().bytes, 0);
    }

    struct GatedSource {
        ready: Arc<AtomicBool>,
        emitted: bool,
    }
    impl crate::body::BodyStream for GatedSource {
        fn next_chunk(&mut self) -> crate::body::BodyChunkFuture<'_> {
            Box::pin(std::future::poll_fn(move |_| {
                if !self.ready.load(Ordering::Acquire) {
                    return Poll::Pending;
                }
                let chunk = if self.emitted { None } else { Some(vec![42]) };
                self.emitted = true;
                Poll::Ready(Ok(chunk))
            }))
        }
    }

    #[test]
    fn bounded_pending_planner_survives_first_reader_cancellation() {
        block_on(async {
            let ready = Arc::new(AtomicBool::new(false));
            let owner = Attachment::lazy(GatedSource {
                ready: ready.clone(),
                emitted: false,
            })
            .bind(&Budget::new(100, 10), 10, json!({}))
            .unwrap();
            let invocation = invocation(owner.clone());
            let guard = invocation.planning_reads();
            let mut first = Box::pin(owner.read());
            assert!(futures::poll!(first.as_mut()).is_pending());
            drop(first);
            assert!(matches!(
                *owner.0.state.lock().unwrap(),
                State::Reading { .. }
            ));
            ready.store(true, Ordering::Release);
            if let State::Reading { wake, .. } = &*owner.0.state.lock().unwrap() {
                wake.notify();
            }
            assert_eq!(&*owner.read().await.unwrap(), &[42]);
            drop(guard);
            assert_eq!(owner.0.planning.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn cancelled_planning_releases_unobserved_pending_materialization() {
        block_on(async {
            let owner = Attachment::lazy(GatedSource {
                ready: Arc::new(AtomicBool::new(false)),
                emitted: false,
            })
            .bind(&Budget::new(100, 10), 10, json!({}))
            .unwrap();
            let invocation = invocation(owner.clone());
            let guard = invocation.planning_reads();
            let mut first = Box::pin(owner.read());
            assert!(futures::poll!(first.as_mut()).is_pending());
            drop(first);
            drop(guard);
            assert!(matches!(*owner.0.state.lock().unwrap(), State::Cancelled));
            assert!(
                matches!(owner.read().await, Err(BodyError::Read(message)) if message == "attachment read cancelled")
            );
        });
    }

    #[test]
    fn waiter_limit_does_not_poison_owner_capture() {
        let owner = Attachment::from_body(Body::bytes(vec![1, 2, 3]))
            .bind(&Budget::new(100, 10), 10, json!({}))
            .unwrap();
        assert!(matches!(
            block_on(owner.read_limited(1)),
            Err(BodyError::TooLarge { limit: 1 })
        ));
        let bytes = block_on(owner.read_limited(10)).unwrap();
        assert_eq!(&*bytes, &[1, 2, 3]);
        assert!(Arc::ptr_eq(&bytes, &block_on(owner.read()).unwrap()));
    }

    #[test]
    fn moved_and_duplicate_canonical_slots_keep_original_owner() {
        let owner = Attachment::bytes(vec![1, 2, 3])
            .bind(&Budget::new(100, 10), 10, json!({}))
            .unwrap();
        let item = json!({"id":"binary", "kind":"attachment",
            "mediaType":"application/octet-stream", "selection":"body",
            "body":owner.0.reference});
        let invocation = invocation(owner.clone());
        // Projection can resolve a relocated item even before final remapping.
        let resolved = invocation
            .resolve_selected("/message/messages/1/parts/0", &item)
            .unwrap()
            .unwrap();
        let event = json!({"type":"user.message.outbound", "message":{
            "channel":"chat", "messages":[
                {"id":"text", "role":"assistant", "parts":[{
                    "id":"caption", "kind":"text", "mediaType":"text/plain",
                    "selection":"body", "text":"caption"}]},
                {"id":"moved", "role":"assistant", "parts":[item.clone(), item.clone()]}
            ]}, "opaque":{"body":owner.0.reference}});
        let content = invocation.finish_for(&event);
        assert!(block_on(content.read("/message/messages/0/parts/0")).is_err());
        let first = block_on(content.read("/message/messages/1/parts/0")).unwrap();
        let second = block_on(content.read("/message/messages/1/parts/1")).unwrap();
        assert!(Arc::ptr_eq(&resolved, &first));
        assert!(Arc::ptr_eq(&first, &second));
        assert!(block_on(content.read("/opaque")).is_err());
    }
}
