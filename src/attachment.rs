//! Owned binary sources. Invocation indexes contain owners, never stored body copies.
use crate::{
    body::{Body, BodyError, BodyStream},
    content::{ContentAccess, UploadError},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
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
            charge: Mutex::new(Some(budget.acquire(size)?)),
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
    fn materialized(&mut self, bytes: usize) -> Result<(), BodyError> {
        let mut usage = self.budget.usage.lock().unwrap_or_else(|e| e.into_inner());
        if bytes > self.budget.max_bytes.saturating_sub(usage.0) {
            return Err(BodyError::Capacity);
        }
        usage.0 += bytes;
        self.bytes += bytes;
        Ok(())
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
    charge: Mutex<Option<Charge>>,
}
enum State {
    Pending(Body),
    ReadingOrFailed,
    Ready(Arc<[u8]>),
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
        let limit = limit.min(self.0.limit);
        let body = {
            let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
            if let State::Ready(bytes) = &*state {
                self.validate(bytes, limit)?;
                return Ok(bytes.clone());
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
        // The read future owns the source. Cancellation is terminal and drops it.
        let bytes: Arc<[u8]> = body.into_bytes(limit).await?.into();
        self.validate(&bytes, limit)?;
        if let Some(charge) = self
            .0
            .charge
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            charge.materialized(bytes.len())?;
        }
        *self.0.state.lock().unwrap_or_else(|e| e.into_inner()) = State::Ready(bytes.clone());
        Ok(bytes)
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
impl InvocationAttachments {
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
    pub(crate) fn metadata(&self, path: &str) -> Option<Value> {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)
            .map(|owner| owner.0.metadata.clone())
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
        let owner = self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)
            .cloned()
            .ok_or(UploadError::Unavailable)?;
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
pub(crate) fn contains_local(value: &Value) -> bool {
    match value {
        Value::String(value) => value.starts_with("ahp-attachment:"),
        Value::Array(values) => values.iter().any(contains_local),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| key.starts_with("ahp-attachment:") || contains_local(value)),
        _ => false,
    }
}
