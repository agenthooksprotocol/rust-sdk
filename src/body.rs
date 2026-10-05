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
    Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, BodyError>> + 'a>>;

/// A caller-owned chunk source. Neither the source nor its futures need `Send`.
///
/// `None` marks EOF. Sources must yield control themselves when waiting for
/// input; chunk limits cannot interrupt a source future that never completes.
/// Each returned chunk is already allocated by the source, so callers must also
/// bound individual source allocations where that is required.
pub trait BodyStream {
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
    Bytes(Vec<u8>),
    Stream(Box<dyn BodyStream>),
}

impl Body {
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
    inner: std::rc::Rc<DeferredInner>,
}

struct DeferredInner {
    namespace: u64,
    max_bytes: usize,
    max_entries: usize,
    entries: std::cell::RefCell<Vec<DeferredState>>,
}

enum DeferredState {
    Pending(Body),
    // Installed before awaiting: both read errors and cancellation are terminal.
    Consumed,
    Snapshot(serde_json::Value),
}

impl DeferredBodies {
    pub(crate) fn new(max_bytes: usize, max_entries: usize) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self {
            inner: std::rc::Rc::new(DeferredInner {
                namespace: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                max_bytes,
                max_entries,
                entries: Default::default(),
            }),
        }
    }

    fn handle(&self, index: usize) -> serde_json::Value {
        serde_json::json!({
            "ref": format!("{DEFERRED_PREFIX}{}:{index}", self.inner.namespace),
            "size": 0,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        })
    }

    /// Transfer ownership without polling the source. The returned handle is local
    /// to this Hooks instance and must only be used in a registered content body.
    pub(crate) fn register(&self, body: Body) -> Result<serde_json::Value, BodyError> {
        let mut entries = self.inner.entries.borrow_mut();
        if entries.len() >= self.inner.max_entries {
            return Err(BodyError::Capacity);
        }
        entries.try_reserve(1).map_err(|_| BodyError::Capacity)?;
        let handle = self.handle(entries.len());
        entries.push(DeferredState::Pending(body));
        Ok(handle)
    }

    pub(crate) fn clear(&self) {
        // Never recycle indices: old handles must not identify a new source.
        for entry in self.inner.entries.borrow_mut().iter_mut() {
            *entry = DeferredState::Consumed;
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
            let mut entries = self.inner.entries.borrow_mut();
            let entry = entries
                .get_mut(index)
                .ok_or_else(|| BodyError::Read("unknown deferred body".into()))?;
            match entry {
                DeferredState::Snapshot(reference) => return Ok(Some(reference.clone())),
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
        // ContentContext checks the descriptor and an exact-byte readback.
        let reference = context.put(&bytes).map_err(BodyError::Upload)?;
        self.inner.entries.borrow_mut()[index] = DeferredState::Snapshot(reference.clone());
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
        cell::Cell,
        rc::Rc,
        task::{Context, Poll},
    };

    struct Source {
        calls: Rc<Cell<usize>>,
        pending: bool,
        fail: bool,
    }
    impl BodyStream for Source {
        fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
            self.calls.set(self.calls.get() + 1);
            Box::pin(async move {
                if self.pending {
                    std::future::pending().await
                } else if self.fail {
                    Err(BodyError::Read("failure".into()))
                } else if self.calls.get() == 1 {
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
        let calls = Rc::new(Cell::new(0));
        let handle = registry
            .register(Body::stream(Source {
                calls: calls.clone(),
                pending: false,
                fail: false,
            }))
            .unwrap();
        assert_eq!(calls.get(), 0);
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
        assert_eq!(calls.get(), 2);
        assert_eq!(
            block_on(registry.materialize(&handle, &context, 3)).unwrap(),
            Some(first)
        );
        assert_eq!(calls.get(), 2);
        assert!(registry.register(Body::bytes([])).is_err());
    }

    #[test]
    fn cancelled_and_failed_sources_are_never_reopened() {
        for (pending, fail, limit) in [(true, false, 3), (false, true, 3), (false, false, 2)] {
            let registry = DeferredBodies::new(3, 1);
            let calls = Rc::new(Cell::new(0));
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
            assert_eq!(calls.get(), 1);
        }
    }
}
