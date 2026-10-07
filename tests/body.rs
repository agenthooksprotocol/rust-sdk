use agenthooksprotocol::{
    body::{Body, BodyError, BodyStream, DEFAULT_MAX_CHUNKS},
    content::{
        AuthorizedScope, ContentContext, ContentReference, ContentStore, MemoryContentStore,
        UploadError,
    },
};
use futures::{executor::block_on, task::noop_waker};
use serde_json::json;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::Arc,
    sync::Mutex,
    task::{Context, Poll},
};

struct Chunks {
    chunks: VecDeque<Result<Vec<u8>, BodyError>>,
    calls: Arc<Mutex<usize>>,
    dropped: Arc<Mutex<bool>>,
}
impl BodyStream for Chunks {
    fn next_chunk(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, BodyError>> + Send + '_>> {
        *self.calls.lock().unwrap() += 1;
        Box::pin(async move { self.chunks.pop_front().transpose() })
    }
}
impl Drop for Chunks {
    fn drop(&mut self) {
        *self.dropped.lock().unwrap() = true;
    }
}
fn source(
    chunks: Vec<Result<Vec<u8>, BodyError>>,
) -> (Chunks, Arc<Mutex<usize>>, Arc<Mutex<bool>>) {
    let calls = Arc::new(Mutex::new(0));
    let dropped = Arc::new(Mutex::new(false));
    (
        Chunks {
            chunks: chunks.into(),
            calls: calls.clone(),
            dropped: dropped.clone(),
        },
        calls,
        dropped,
    )
}

#[test]
fn owned_lazy_source_preserves_raw_bytes_and_drops_on_completion() {
    let (source, calls, dropped) = source(vec![Ok(vec![0, 255]), Ok(vec![]), Ok(vec![128])]);
    let body = Body::stream(source);
    assert_eq!(*calls.lock().unwrap(), 0);
    let future = body.into_bytes(3);
    assert_eq!(*calls.lock().unwrap(), 0);
    assert_eq!(block_on(future).unwrap(), [0, 255, 128]);
    assert_eq!(*calls.lock().unwrap(), 4);
    assert!(*dropped.lock().unwrap());
}

#[test]
fn exact_text_json_and_zero_byte_limits() {
    let text = "héllo\r\n🌍";
    assert_eq!(
        block_on(Body::text(text).into_bytes(text.len())).unwrap(),
        text.as_bytes()
    );
    let value = json!({"hello": "🌍", "bytes": [0, 255]});
    assert_eq!(
        block_on(Body::json(value.clone()).unwrap().into_bytes(1024)).unwrap(),
        serde_json::to_vec(&value).unwrap()
    );
    assert!(
        block_on(Body::bytes(Vec::new()).into_bytes(0))
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        block_on(Body::bytes(vec![1]).into_bytes(0)),
        Err(BodyError::TooLarge { limit: 0 })
    ));
    assert_eq!(
        block_on(Body::bytes(vec![1]).into_bytes(usize::MAX)).unwrap(),
        [1]
    );
}

#[test]
fn exceeding_size_stops_reading_and_drops_source() {
    let (source, calls, dropped) = source(vec![Ok(vec![1, 2]), Ok(vec![3, 4]), Ok(vec![5])]);
    assert!(matches!(
        block_on(Body::stream(source).into_bytes(3)),
        Err(BodyError::TooLarge { limit: 3 })
    ));
    assert_eq!(*calls.lock().unwrap(), 2);
    assert!(*dropped.lock().unwrap());
}

struct EmptyForever(Arc<Mutex<usize>>);
impl BodyStream for EmptyForever {
    fn next_chunk(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, BodyError>> + Send + '_>> {
        *self.0.lock().unwrap() += 1;
        Box::pin(async { Ok(Some(vec![])) })
    }
}
#[test]
fn endless_empty_chunks_have_default_and_configurable_finite_limits() {
    for limit in [0, 2, DEFAULT_MAX_CHUNKS] {
        let calls = Arc::new(Mutex::new(0));
        let body = Body::stream(EmptyForever(calls.clone()));
        let body = if limit == DEFAULT_MAX_CHUNKS {
            body
        } else {
            body.with_max_chunks(limit)
        };
        assert!(
            matches!(block_on(body.into_bytes(0)), Err(BodyError::TooManyChunks { limit: actual }) if actual == limit)
        );
        assert_eq!(*calls.lock().unwrap(), limit + 1);
    }
    let (source, _, _) = source(vec![Ok(vec![1]), Ok(vec![])]);
    assert_eq!(
        block_on(Body::stream(source).with_max_chunks(2).into_bytes(1)).unwrap(),
        [1]
    );
}

struct PendingSource(Arc<Mutex<bool>>);
impl BodyStream for PendingSource {
    fn next_chunk(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, BodyError>> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}
impl Drop for PendingSource {
    fn drop(&mut self) {
        *self.0.lock().unwrap() = true;
    }
}
#[test]
fn dropping_body_or_cancelled_future_releases_owned_source() {
    let (source, calls, dropped) = source(vec![]);
    drop(Body::stream(source));
    assert_eq!(*calls.lock().unwrap(), 0);
    assert!(*dropped.lock().unwrap());
    let dropped = Arc::new(Mutex::new(false));
    let mut future = Box::pin(Body::stream(PendingSource(dropped.clone())).into_bytes(10));
    let waker = noop_waker();
    assert!(matches!(
        future.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Pending
    ));
    assert!(!*dropped.lock().unwrap());
    drop(future);
    assert!(*dropped.lock().unwrap());
}

struct CountingStore {
    puts: Mutex<usize>,
    memory: MemoryContentStore,
}
impl ContentStore for CountingStore {
    fn resolve(
        &self,
        scope: &AuthorizedScope,
        reference: &ContentReference,
    ) -> Result<Arc<[u8]>, UploadError> {
        self.memory.resolve(scope, reference)
    }
    fn put(
        &self,
        scope: &AuthorizedScope,
        bytes: Arc<[u8]>,
    ) -> Result<ContentReference, UploadError> {
        *self.puts.lock().unwrap() += 1;
        self.memory.put(scope, bytes)
    }
}
#[test]
fn failed_reads_and_limits_do_not_publish_partial_content() {
    let store = CountingStore {
        puts: Mutex::new(0),
        memory: MemoryContentStore::new(32, 32, 2),
    };
    let context = ContentContext {
        store: &store,
        scope: AuthorizedScope::new("test"),
    };
    let (source, calls, dropped) = source(vec![
        Ok(vec![1]),
        Err(BodyError::Read("broken".into())),
        Ok(vec![2]),
    ]);
    assert!(
        matches!(block_on(Body::stream(source).into_content(&context, 32)), Err(BodyError::Read(message)) if message == "broken")
    );
    assert_eq!(*calls.lock().unwrap(), 2);
    assert!(*dropped.lock().unwrap());
    assert!(block_on(Body::bytes(vec![1, 2]).into_content(&context, 1)).is_err());
    assert!(
        block_on(
            Body::stream(EmptyForever(Arc::new(Mutex::new(0))))
                .with_max_chunks(0)
                .into_content(&context, 32)
        )
        .is_err()
    );
    assert_eq!(*store.puts.lock().unwrap(), 0);
    let reference = block_on(Body::text("hé").into_content(&context, 3)).unwrap();
    assert_eq!(*store.puts.lock().unwrap(), 1);
    assert_eq!(&*context.resolve(&reference).unwrap(), "hé".as_bytes());
}
