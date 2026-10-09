//! Owned, runtime-neutral body inputs with explicit bounded in-memory spooling.
//!
//! Streams are not read until a spooling future is polled. Bytes are never
//! interpreted as media or implicitly decoded. A source owns its resources and
//! is dropped on completion, failure, or cancellation of the spooling future.

use crate::content::{ContentContext, UploadError};
use std::{fmt, future::Future, pin::Pin};

/// Maximum number of chunks accepted by default, including empty chunks.
pub const DEFAULT_MAX_CHUNKS: usize = 65_536;

/// A lazy, runtime-neutral read of one owned body chunk.
pub type BodyChunkFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, BodyError>> + Send + 'a>>;

/// A caller-owned chunk source. Sources and their futures are `Send` so operations can move between executor threads.
///
/// `None` marks EOF. Sources must yield control themselves when waiting for
/// input; chunk limits cannot interrupt a source future that never completes.
/// Each returned chunk is already allocated by the source, so callers must also
/// bound individual source allocations where that is required.
pub trait BodyStream: Send {
    fn next_chunk(&mut self) -> BodyChunkFuture<'_>;
}

impl<T: BodyStream + ?Sized> BodyStream for Box<T> {
    fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
        (**self).next_chunk()
    }
}

/// Failure while serializing, spooling, or publishing a body.
#[derive(Debug)]
pub enum BodyError {
    Json(serde_json::Error),
    /// A source-supplied read failure.
    Read(String),
    TooLarge {
        limit: usize,
    },
    TooManyChunks {
        limit: usize,
    },
    /// The spool could not reserve memory.
    Capacity,
    Upload(UploadError),
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "body JSON serialization failed: {error}"),
            Self::Read(message) => write!(f, "body read failed: {message}"),
            Self::TooLarge { limit } => write!(f, "body exceeds {limit} bytes"),
            Self::TooManyChunks { limit } => write!(f, "body exceeds {limit} chunks"),
            Self::Capacity => f.write_str("body spool allocation failed"),
            Self::Upload(error) => write!(f, "body publication failed: {error}"),
        }
    }
}

impl std::error::Error for BodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Upload(error) => Some(error),
            _ => None,
        }
    }
}

/// An owned body, not an unbounded streaming upload.
///
/// Publication explicitly spools the complete input before calling the verified
/// content store. Existing byte-oriented content APIs remain independent.
pub struct Body {
    input: Input,
    max_chunks: usize,
}

enum Input {
    Attachment(crate::attachment::SharedAttachment),
    Bytes(Vec<u8>),
    Stream(Box<dyn BodyStream>),
}

impl Body {
    pub(crate) fn attachment(source: crate::attachment::SharedAttachment) -> Self {
        Self {
            input: Input::Attachment(source),
            max_chunks: DEFAULT_MAX_CHUNKS,
        }
    }
    pub fn bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            input: Input::Bytes(bytes.into()),
            max_chunks: DEFAULT_MAX_CHUNKS,
        }
    }

    /// Preserve the exact UTF-8 representation, without normalization.
    pub fn text(text: impl Into<String>) -> Self {
        Self::bytes(text.into().into_bytes())
    }

    /// Serialize once into owned JSON bytes. No media decoding is performed.
    pub fn json(value: impl serde::Serialize) -> Result<Self, BodyError> {
        serde_json::to_vec(&value)
            .map(Self::bytes)
            .map_err(BodyError::Json)
    }

    /// Take ownership without requesting or polling any chunks.
    pub fn stream(source: impl BodyStream + 'static) -> Self {
        Self {
            input: Input::Stream(Box::new(source)),
            max_chunks: DEFAULT_MAX_CHUNKS,
        }
    }

    /// Limit all stream chunks, including empty chunks, to ensure finite work.
    ///
    /// The default is [`DEFAULT_MAX_CHUNKS`]. At most `max_chunks` chunks plus
    /// one EOF probe are requested. A zero limit accepts only immediate EOF.
    /// This limit does not apply to already-owned bytes, text, or JSON.
    pub fn with_max_chunks(mut self, max_chunks: usize) -> Self {
        self.max_chunks = max_chunks;
        self
    }

    /// Spool without growing the buffer past the explicit byte limit.
    ///
    /// The limit bounds payload bytes, not allocator overhead or memory already
    /// owned by the source. It is checked before extending the spool and without
    /// overflowing byte totals, even when `max_bytes` is `usize::MAX`.
    pub async fn into_bytes(self, max_bytes: usize) -> Result<Vec<u8>, BodyError> {
        match self.input {
            Input::Attachment(source) => {
                // Box the recursive owned-body path and apply the delivery limit
                // before polling any of the original source's chunks.
                Ok(Box::pin(source.read_limited(max_bytes)).await?.to_vec())
            }
            Input::Bytes(bytes) => {
                if bytes.len() > max_bytes {
                    Err(BodyError::TooLarge { limit: max_bytes })
                } else {
                    Ok(bytes)
                }
            }
            Input::Stream(mut source) => {
                let mut bytes = Vec::new();
                let mut chunks = 0;
                while let Some(chunk) = source.next_chunk().await? {
                    if chunks == self.max_chunks {
                        return Err(BodyError::TooManyChunks {
                            limit: self.max_chunks,
                        });
                    }
                    chunks += 1;
                    if chunk.len() > max_bytes - bytes.len() {
                        return Err(BodyError::TooLarge { limit: max_bytes });
                    }
                    bytes
                        .try_reserve_exact(chunk.len())
                        .map_err(|_| BodyError::Capacity)?;
                    bytes.extend_from_slice(&chunk);
                }
                Ok(bytes)
            }
        }
    }

    /// Publish only after complete, successful bounded spooling.
    ///
    /// Read and limit failures never call `ContentContext::put`. Publication
    /// uses its existing descriptor and exact-byte verification unchanged.
    pub async fn into_content(
        self,
        context: &ContentContext<'_>,
        max_bytes: usize,
    ) -> Result<serde_json::Value, BodyError> {
        let bytes = self.into_bytes(max_bytes).await?;
        context.put(&bytes).map_err(BodyError::Upload)
    }
}

// Local implementation handles, never published content references. Their shape
// remains canonical so ordinary event validation does not need an exception.
const DEFERRED_PREFIX: &str = "ahp-deferred:";

#[derive(Clone)]
pub(crate) struct DeferredBodies {
    inner: std::sync::Arc<DeferredInner>,
}

struct DeferredInner {
    namespace: u64,
    max_bytes: usize,
    max_entries: usize,
    entries: std::sync::Mutex<DeferredEntries>,
}

#[derive(Default)]
struct DeferredEntries {
    closed: bool,
    next_index: usize,
    states: std::collections::BTreeMap<usize, DeferredState>,
}

/// An owned, single-invocation lazy body handle. Dropping an unused handle
/// releases the source without reading it. Keep this owner alive until the boundary
/// completes or is cancelled, then drop it. Prefer a boundary's `body_source` / an explicit `ContentScope`.
pub struct StagedBody {
    pub(crate) guard: DeferredBodyGuard,
}
impl StagedBody {
    pub fn reference(&self) -> serde_json::Value {
        self.guard.reference.clone()
    }
}
impl std::ops::Deref for StagedBody {
    type Target = serde_json::Value;
    fn deref(&self) -> &Self::Target {
        &self.guard.reference
    }
}
impl serde::Serialize for StagedBody {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.guard.reference.serialize(serializer)
    }
}

/// Retires an operation-owned body on success, failure, or future cancellation.
pub(crate) struct DeferredBodyGuard {
    bodies: DeferredBodies,
    reference: serde_json::Value,
}
impl Drop for DeferredBodyGuard {
    fn drop(&mut self) {
        self.bodies.retire(&self.reference);
    }
}

enum DeferredState {
    Pending(Body),
    // Installed before awaiting: both read errors and cancellation are terminal.
    Consumed,
    Snapshot(serde_json::Value, usize),
}

impl DeferredBodies {
    pub(crate) fn new(max_bytes: usize, max_entries: usize) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self {
            inner: std::sync::Arc::new(DeferredInner {
                namespace: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                max_bytes,
                max_entries,
                entries: Default::default(),
            }),
        }
    }

    fn handle(&self, index: usize) -> serde_json::Value {
        serde_json::json!({
            "ref": format!("{DEFERRED_PREFIX}{}:{index}", self.inner.namespace)
        })
    }

    /// Transfer ownership without polling the source. The returned handle is local
    /// to this Hooks instance and must only be used in a registered content body.
    pub(crate) fn register(&self, body: Body) -> Result<serde_json::Value, BodyError> {
        let mut entries = self
            .inner
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if entries.closed {
            return Err(BodyError::Read("deferred body registry is closed".into()));
        }
        if entries.states.len() >= self.inner.max_entries {
            return Err(BodyError::Capacity);
        }
        let index = entries.next_index;
        entries.next_index = index.checked_add(1).ok_or(BodyError::Capacity)?;
        let handle = self.handle(index);
        entries.states.insert(index, DeferredState::Pending(body));
        Ok(handle)
    }

    pub(crate) fn guard(&self, reference: &serde_json::Value) -> DeferredBodyGuard {
        DeferredBodyGuard {
            bodies: self.clone(),
            reference: reference.clone(),
        }
    }

    /// Retire only this registry's unmodified handle. Never recycle its identity.
    pub(crate) fn retire(&self, reference: &serde_json::Value) {
        let prefix = format!("{DEFERRED_PREFIX}{}:", self.inner.namespace);
        let Some(index) = reference["ref"]
            .as_str()
            .and_then(|name| name.strip_prefix(&prefix))
            .and_then(|index| index.parse::<usize>().ok())
        else {
            return;
        };
        if *reference != self.handle(index) {
            return;
        }
        // Drop caller-owned resources outside the registry lock (Drop may reenter).
        let removed = self
            .inner
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .states
            .remove(&index);
        drop(removed);
    }

    pub(crate) fn clear(&self) {
        let removed = {
            let mut entries = self
                .inner
                .entries
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            entries.closed = true;
            std::mem::take(&mut entries.states)
        };
        drop(removed);
    }

    pub(crate) fn snapshot(&self, reference: &serde_json::Value) -> Option<serde_json::Value> {
        let prefix = format!("{DEFERRED_PREFIX}{}:", self.inner.namespace);
        let index = reference["ref"]
            .as_str()?
            .strip_prefix(&prefix)?
            .parse::<usize>()
            .ok()?;
        if *reference != self.handle(index) {
            return None;
        }
        let entries = self.inner.entries.lock().unwrap_or_else(|e| e.into_inner());
        match entries.states.get(&index)? {
            DeferredState::Snapshot(value, _) => Some(value.clone()),
            _ => None,
        }
    }

    pub(crate) async fn materialize(
        &self,
        reference: &serde_json::Value,
        context: &ContentContext<'_>,
        route_max_bytes: usize,
    ) -> Result<Option<serde_json::Value>, BodyError> {
        let Some(name) = reference["ref"]
            .as_str()
            .filter(|s| s.starts_with(DEFERRED_PREFIX))
        else {
            return Ok(None);
        };
        let prefix = format!("{DEFERRED_PREFIX}{}:", self.inner.namespace);
        let index = name
            .strip_prefix(&prefix)
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| BodyError::Read("unknown deferred body".into()))?;
        if *reference != self.handle(index) {
            return Err(BodyError::Read("modified deferred body handle".into()));
        }
        let body = {
            let mut entries = self
                .inner
                .entries
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let entry = entries
                .states
                .get_mut(&index)
                .ok_or_else(|| BodyError::Read("unknown deferred body".into()))?;
            match entry {
                DeferredState::Snapshot(reference, size) => {
                    if *size > route_max_bytes {
                        return Err(BodyError::TooLarge {
                            limit: route_max_bytes,
                        });
                    }
                    return Ok(Some(reference.clone()));
                }
                DeferredState::Consumed => {
                    return Err(BodyError::Read(
                        "deferred body failed, was cancelled, or is already being read".into(),
                    ));
                }
                DeferredState::Pending(_) => {}
            }
            match std::mem::replace(entry, DeferredState::Consumed) {
                DeferredState::Pending(body) => body,
                _ => unreachable!(),
            }
        };
        let bytes = body
            .into_bytes(self.inner.max_bytes.min(route_max_bytes))
            .await?;
        if !self
            .inner
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .states
            .contains_key(&index)
        {
            return Err(BodyError::Read("deferred body was retired".into()));
        }
        // ContentContext checks the descriptor and an exact-byte readback.
        let reference = context.put(&bytes).map_err(BodyError::Upload)?;
        let mut entries = self
            .inner
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !entries.states.contains_key(&index) {
            return Err(BodyError::Read("deferred body was retired".into()));
        }
        entries.states.insert(
            index,
            DeferredState::Snapshot(reference.clone(), bytes.len()),
        );
        Ok(Some(reference))
    }
}

/// Check all wire fields, without interpreting arbitrary objects as content.
pub(crate) fn contains_deferred(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => value.starts_with(DEFERRED_PREFIX),
        serde_json::Value::Array(values) => values.iter().any(contains_deferred),
        serde_json::Value::Object(values) => values
            .iter()
            .any(|(key, value)| key.starts_with(DEFERRED_PREFIX) || contains_deferred(value)),
        _ => false,
    }
}

#[cfg(test)]
mod deferred_tests {
    use super::*;
    use crate::content::{AuthorizedScope, MemoryContentStore};
    use futures::{executor::block_on, task::noop_waker};
    use std::{
        sync::Arc,
        sync::Mutex,
        task::{Context, Poll},
    };

    struct Source {
        calls: Arc<Mutex<usize>>,
        pending: bool,
        fail: bool,
    }
    impl BodyStream for Source {
        fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
            *self.calls.lock().unwrap() += 1;
            Box::pin(async move {
                if self.pending {
                    std::future::pending().await
                } else if self.fail {
                    Err(BodyError::Read("failure".into()))
                } else if *self.calls.lock().unwrap() == 1 {
                    Ok(Some(vec![1, 2, 3]))
                } else {
                    Ok(None)
                }
            })
        }
    }

    #[test]
    fn snapshot_is_verified_and_reused_without_rereading() {
        let registry = DeferredBodies::new(3, 1);
        let calls = Arc::new(Mutex::new(0));
        let handle = registry
            .register(Body::stream(Source {
                calls: calls.clone(),
                pending: false,
                fail: false,
            }))
            .unwrap();
        assert_eq!(*calls.lock().unwrap(), 0);
        let store = MemoryContentStore::new(3, 3, 1);
        let context = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("test"),
        };
        let first = block_on(registry.materialize(&handle, &context, 3))
            .unwrap()
            .unwrap();
        assert!(!contains_deferred(&first));
        assert_eq!(&*context.resolve(&first).unwrap(), &[1, 2, 3]);
        assert_eq!(*calls.lock().unwrap(), 2);
        assert_eq!(
            block_on(registry.materialize(&handle, &context, 3)).unwrap(),
            Some(first)
        );
        assert_eq!(*calls.lock().unwrap(), 2);
        assert!(matches!(
            block_on(registry.materialize(&handle, &context, 2)),
            Err(BodyError::TooLarge { limit: 2 })
        ));
        assert!(registry.register(Body::bytes([])).is_err());
    }

    #[test]
    fn retired_in_flight_source_cannot_restore_snapshot() {
        struct Delayed(Option<futures::channel::oneshot::Receiver<()>>);
        impl BodyStream for Delayed {
            fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
                Box::pin(async move {
                    if let Some(receiver) = self.0.take() {
                        receiver
                            .await
                            .map_err(|_| BodyError::Read("cancelled".into()))?;
                        Ok(Some(vec![1]))
                    } else {
                        Ok(None)
                    }
                })
            }
        }
        fn assert_send<T: Send>(_: &T) {}
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DeferredBodies>();
        let registry = DeferredBodies::new(3, 1);
        let (sender, receiver) = futures::channel::oneshot::channel();
        let handle = registry
            .register(Body::stream(Delayed(Some(receiver))))
            .unwrap();
        let store = MemoryContentStore::new(3, 3, 1);
        let context = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("test"),
        };
        let mut future = Box::pin(registry.materialize(&handle, &context, 3));
        assert_send(&future);
        let waker = noop_waker();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        // A competing reader cannot race the source or reopen it.
        assert!(block_on(registry.materialize(&handle, &context, 3)).is_err());
        registry.clear();
        sender.send(()).unwrap();
        assert!(block_on(future).is_err());
        assert!(block_on(registry.materialize(&handle, &context, 3)).is_err());
    }

    #[test]
    fn scoped_guard_drops_unused_source_and_reclaims_capacity_without_reusing_handle() {
        struct Unused(Arc<Mutex<bool>>);
        impl BodyStream for Unused {
            fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
                panic!("unused body must not be read");
            }
        }
        impl Drop for Unused {
            fn drop(&mut self) {
                *self.0.lock().unwrap() = true;
            }
        }
        let registry = DeferredBodies::new(3, 1);
        let dropped = Arc::new(Mutex::new(false));
        let first = registry
            .register(Body::stream(Unused(dropped.clone())))
            .unwrap();
        let guard = registry.guard(&first);
        assert!(!*dropped.lock().unwrap());
        drop(guard);
        assert!(*dropped.lock().unwrap());
        registry.retire(&first); // Repeated retirement is harmless.
        let second = registry.register(Body::bytes([2])).unwrap();
        assert_ne!(first, second);
        let store = MemoryContentStore::new(3, 3, 1);
        let context = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("test"),
        };
        assert!(block_on(registry.materialize(&first, &context, 3)).is_err());
        let second_guard = registry.guard(&second);
        assert!(block_on(registry.materialize(&second, &context, 3)).is_ok());
        drop(second_guard);
        assert!(block_on(registry.materialize(&second, &context, 3)).is_err());
        assert!(registry.register(Body::bytes([3])).is_ok());
    }

    #[test]
    fn clearing_registry_permanently_closes_and_drops_late_sources_unread() {
        struct Unused(Arc<Mutex<bool>>);
        impl BodyStream for Unused {
            fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
                panic!("closed registry must not read");
            }
        }
        impl Drop for Unused {
            fn drop(&mut self) {
                *self.0.lock().unwrap() = true;
            }
        }
        let registry = DeferredBodies::new(3, 1);
        registry.clear();
        registry.clear();
        let dropped = Arc::new(Mutex::new(false));
        assert!(
            registry
                .register(Body::stream(Unused(dropped.clone())))
                .is_err()
        );
        assert!(*dropped.lock().unwrap());
    }

    #[test]
    fn cancelled_and_failed_sources_are_never_reopened() {
        for (pending, fail, limit) in [(true, false, 3), (false, true, 3), (false, false, 2)] {
            let registry = DeferredBodies::new(3, 1);
            let calls = Arc::new(Mutex::new(0));
            let handle = registry
                .register(Body::stream(Source {
                    calls: calls.clone(),
                    pending,
                    fail,
                }))
                .unwrap();
            let store = MemoryContentStore::new(3, 3, 1);
            let context = ContentContext {
                store: &store,
                scope: AuthorizedScope::new("test"),
            };
            let mut future = Box::pin(registry.materialize(&handle, &context, limit));
            let waker = noop_waker();
            let result = future.as_mut().poll(&mut Context::from_waker(&waker));
            if pending {
                assert!(result.is_pending());
            } else {
                assert!(matches!(result, Poll::Ready(Err(_))));
            }
            drop(future);
            assert!(block_on(registry.materialize(&handle, &context, 3)).is_err());
            assert_eq!(*calls.lock().unwrap(), 1);
        }
    }
}
