//! Invocation-owned binary attachments. Metadata stays on the content item.
use crate::body::{Body, BodyError, BodyStream};
use std::sync::{Arc, Mutex};

/// An owned source consumed by a boundary's `attachment` binding.
/// Deliberately not Clone: sources are not cross-invocation handles.
/// Dropping an unopened attachment drops its source without reading it.
pub struct Attachment(Body);
impl Attachment {
    pub fn bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Body::bytes(bytes))
    }
    /// Take ownership without polling. Read at most once, on selected delivery
    /// or a result content read.
    pub fn lazy(source: impl BodyStream + 'static) -> Self {
        Self(Body::stream(source))
    }
    pub fn with_max_chunks(mut self, limit: usize) -> Self {
        self.0 = self.0.with_max_chunks(limit);
        self
    }
    pub(crate) fn bind(self, limit: usize) -> (Body, SharedAttachment) {
        let shared = SharedAttachment {
            state: Arc::new(Mutex::new(State::Pending(self.0))),
            limit,
        };
        (Body::attachment(shared.clone()), shared)
    }
}
#[derive(Clone)]
pub(crate) struct SharedAttachment {
    state: Arc<Mutex<State>>,
    limit: usize,
}
enum State {
    Pending(Body),
    ReadingOrFailed,
    Ready(Arc<[u8]>),
}
impl SharedAttachment {
    pub(crate) async fn read(&self) -> Result<Arc<[u8]>, BodyError> {
        self.read_limited(self.limit).await
    }
    pub(crate) async fn read_limited(&self, limit: usize) -> Result<Arc<[u8]>, BodyError> {
        let limit = limit.min(self.limit);
        let body = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let State::Ready(bytes) = &*state {
                return if bytes.len() <= limit {
                    Ok(bytes.clone())
                } else {
                    Err(BodyError::TooLarge { limit })
                };
            }
            match std::mem::replace(&mut *state, State::ReadingOrFailed) {
                State::Pending(body) => body,
                _ => {
                    return Err(BodyError::Read(
                        "attachment read failed, cancelled, or already in progress".into(),
                    ));
                }
            }
        };
        // Cancellation drops the source and leaves a terminal state.
        let bytes: Arc<[u8]> = body.into_bytes(limit).await?.into();
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = State::Ready(bytes.clone());
        Ok(bytes)
    }
}
