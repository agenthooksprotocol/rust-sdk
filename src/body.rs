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
        self.into_bytes_accounted(max_bytes, |_| Ok(())).await
    }

    // Reserve shared payload budget before accepting source bytes into the spool.
    // The caller owns rollback of reservations on failure or cancellation.
    pub(crate) async fn into_bytes_accounted(
        self,
        max_bytes: usize,
        mut reserve: impl FnMut(usize) -> Result<(), BodyError> + Send,
    ) -> Result<Vec<u8>, BodyError> {
        match self.input {
            Input::Bytes(bytes) => {
                if bytes.len() > max_bytes {
                    Err(BodyError::TooLarge { limit: max_bytes })
                } else {
                    reserve(bytes.len())?;
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
                    reserve(chunk.len())?;
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
