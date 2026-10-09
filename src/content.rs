//! Immutable raw-byte uploads, independent of event credentials and transport.
//!
//! Callers supply a transport and (when needed) an explicit runtime deadline. This
//! module does not start a runtime, infer event credentials, or follow redirects.
pub use crate::generated::ContentUploadReceipt;
pub use crate::generated::content::*;
use crate::generated::{
    ParseResult, parse_content_reference_value, parse_content_upload_receipt_value,
};
use crate::transport::{Http, Request, Response};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, sync::Arc};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn header<'a>(request: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    request
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}
fn descriptor(value: serde_json::Value) -> Result<ContentReference, UploadError> {
    crate::canonical::validate("content-reference", &value).map_err(|_| UploadError::Descriptor)?;
    match parse_content_reference_value(value) {
        ParseResult::Success { value, .. } => Ok(value),
        _ => Err(UploadError::Descriptor),
    }
}
fn receipt(value: serde_json::Value) -> Result<ContentUploadReceipt, UploadError> {
    crate::canonical::validate("content-upload-receipt", &value)
        .map_err(|_| UploadError::Descriptor)?;
    match parse_content_upload_receipt_value(value) {
        ParseResult::Success { value, .. } => Ok(value),
        _ => Err(UploadError::Descriptor),
    }
}
impl ContentUploadReceipt {
    /// Drop upload confirmation metadata when publishing a protocol reference.
    pub fn reference(&self) -> ContentReference {
        ContentReference::new(self.ref_.clone())
    }
}
// Generated Integer validates exact integrality and the interoperable safe
// range before conversion. Thus 3, 3.0 and 3e0 compare equally without changing
// the descriptor's retained JSON representation or rounding unsafe numbers.
fn byte_size(number: &serde_json::Number) -> Option<u64> {
    let integer = crate::generated::Integer::new(number.clone())?;
    let value = integer.as_number().as_f64()?;
    (value >= 0.0).then_some(value as u64)
}
fn matches(reference: &ContentUploadReceipt, bytes: &[u8]) -> bool {
    byte_size(reference.size.as_number()) == u64::try_from(bytes.len()).ok()
        && reference.sha256 == digest(bytes)
}

/// Upload failures never yield a publishable content reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    Destination,
    Credentials,
    Unauthorized,
    Forbidden,
    Framing,
    TooLarge,
    Capacity,
    Descriptor,
    Unavailable,
    Transport,
    /// Preserve a bounded HTTP failure body, even on non-success status codes.
    Http {
        status: u16,
        body: Vec<u8>,
    },
}
impl fmt::Display for UploadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Destination => "upload requires HTTPS or explicitly enabled loopback HTTP",
            Self::Credentials => "invalid upload credentials",
            Self::Unauthorized => "upload authentication required",
            Self::Forbidden => "upload scope not authorized",
            Self::Framing => "invalid upload framing",
            Self::TooLarge => "upload exceeds transfer limit",
            Self::Capacity => "upload storage capacity exhausted",
            Self::Descriptor => "upload descriptor does not verify exact bytes",
            Self::Unavailable => "content unavailable in authorized scope",
            Self::Transport => "upload transport failed",
            Self::Http { .. } => "upload HTTP request failed",
        })
    }
}
impl std::error::Error for UploadError {}

/// An upload-only credential. Debug output deliberately redacts its value.
#[derive(Clone)]
pub struct UploadCredential(String);
impl UploadCredential {
    pub fn bearer(token: impl Into<String>) -> Result<Self, UploadError> {
        let token = token.into();
        if token.is_empty() || token.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return Err(UploadError::Credentials);
        }
        Ok(Self(token))
    }
}
impl fmt::Debug for UploadCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UploadCredential([REDACTED])")
    }
}

/// Explicit upload binding. This has no access to event authentication state.
pub struct Uploader<'a, H: ?Sized> {
    http: &'a H,
    endpoint: String,
    credential: Option<UploadCredential>,
    max_bytes: usize,
}
impl<'a, H: Http + ?Sized> Uploader<'a, H> {
    /// `allow_loopback_http` is only for explicitly configured local tests.
    pub fn new(
        http: &'a H,
        endpoint: impl Into<String>,
        max_bytes: usize,
        credential: Option<UploadCredential>,
        allow_loopback_http: bool,
    ) -> Result<Self, UploadError> {
        let endpoint = endpoint.into();
        let url = url::Url::parse(&endpoint).map_err(|_| UploadError::Destination)?;
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none()
            || !(url.scheme() == "https"
                || (allow_loopback_http && loopback && url.scheme() == "http"))
        {
            return Err(UploadError::Destination);
        }
        Ok(Self {
            http,
            endpoint,
            credential,
            max_bytes,
        })
    }

    /// No request is sent until this future is polled. Bytes are neither encoded
    /// nor truncated. Only a verified receiver-allocated 201 receipt is returned.
    pub async fn upload(&self, bytes: &[u8]) -> Result<ContentUploadReceipt, UploadError> {
        if bytes.len() > self.max_bytes {
            return Err(UploadError::TooLarge);
        }
        let mut headers = BTreeMap::from([
            ("content-type".into(), "application/octet-stream".into()),
            ("content-length".into(), bytes.len().to_string()),
            ("ahp-content-sha256".into(), digest(bytes)),
        ]);
        if let Some(token) = &self.credential {
            headers.insert("authorization".into(), format!("Bearer {}", token.0));
        }
        let response = self
            .http
            .send(Request {
                method: "POST".into(),
                uri: self.endpoint.clone(),
                headers,
                body: bytes.to_vec(),
            })
            .await
            .map_err(|_| UploadError::Transport)?;
        if response.status != 201 {
            return Err(UploadError::Http {
                status: response.status,
                body: response.body.into_iter().take(8192).collect(),
            });
        }
        if response.body.len() > 8192
            || header(&response.headers, "content-type")
                .and_then(|v| v.split(';').next())
                .is_none_or(|v| !v.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(UploadError::Descriptor);
        }
        let reference =
            receipt(serde_json::from_slice(&response.body).map_err(|_| UploadError::Descriptor)?)?;
        if !matches(&reference, bytes) {
            return Err(UploadError::Descriptor);
        }
        Ok(reference)
    }
}

/// Receiver-local authorization scope, never inferred from a content reference,
/// subscription, event ID, or untrusted request metadata.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorizedScope(String);
impl AuthorizedScope {
    /// Construct only after authenticating and authorizing credentials (or after
    /// explicit anonymous authorization in an application-defined scope).
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

/// Authentication and authorization are supplied by the application. A valid
/// credential is not sufficient unless it is authorized to upload in the scope.
pub trait UploadAuthorizer {
    fn authorize(&self, request: &Request) -> Result<AuthorizedScope, UploadError>;
}
impl<F> UploadAuthorizer for F
where
    F: Fn(&Request) -> Result<AuthorizedScope, UploadError>,
{
    fn authorize(&self, request: &Request) -> Result<AuthorizedScope, UploadError> {
        self(request)
    }
}

/// Bounded immutable receiver storage. The application owns its lifetime and must
/// retain it until all events referring to its confirmed uploads are processed.
/// No implicit eviction, reference renewal, retrieval endpoint, or persistence.
pub struct UploadReceiver<A> {
    authorizer: A,
    route: String,
    store: MemoryContentStore,
}
impl<A: UploadAuthorizer> UploadReceiver<A> {
    pub fn new(
        authorizer: A,
        route: impl Into<String>,
        max_upload: usize,
        max_total: usize,
        max_entries: usize,
    ) -> Self {
        Self {
            authorizer,
            route: route.into(),
            store: MemoryContentStore::new(max_upload, max_total, max_entries),
        }
    }
    /// This uses the same runtime-neutral HTTP request and response as event handlers.
    pub fn handle(&mut self, request: Request) -> Response {
        if request.uri != self.route {
            return self.error_response(404, "unknown upload route");
        }
        match self.accept(&request) {
            Ok(reference) => Response {
                status: 201,
                headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
                body: serde_json::to_vec(&reference).expect("content reference serialization"),
            },
            Err(error) => {
                let status = match error {
                    UploadError::Unauthorized | UploadError::Credentials => 401,
                    UploadError::Forbidden => 403,
                    UploadError::TooLarge | UploadError::Capacity => 413,
                    _ => 400,
                };
                self.error_response(status, &error.to_string())
            }
        }
    }
    fn error_response(&self, status: u16, message: &str) -> Response {
        Response {
            status,
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: serde_json::to_vec(&json!({"error": message})).expect("error serialization"),
        }
    }
    fn accept(&mut self, request: &Request) -> Result<ContentUploadReceipt, UploadError> {
        let scope = self.authorizer.authorize(request)?;
        // Reject duplicate case-insensitive headers and ambiguous HTTP framing.
        let mut seen = std::collections::BTreeSet::new();
        if request
            .headers
            .keys()
            .any(|name| !seen.insert(name.to_ascii_lowercase()))
            || request.method != "POST"
            || header(&request.headers, "content-type") != Some("application/octet-stream")
            || header(&request.headers, "transfer-encoding").is_some()
            || header(&request.headers, "content-encoding").is_some()
            || header(&request.headers, "content-length")
                != Some(request.body.len().to_string().as_str())
            || header(&request.headers, "ahp-content-sha256")
                != Some(digest(&request.body).as_str())
        {
            return Err(UploadError::Framing);
        }
        let reference = self.store.put(&scope, Arc::from(request.body.as_slice()))?;
        receipt(
            json!({"ref": reference.ref_, "size": request.body.len(), "sha256": digest(&request.body)}),
        )
    }
    /// Verify availability and scope before publishing any
    /// effect or event that refers to this reference. Returns immutable bytes.
    pub fn resolve(
        &self,
        scope: &AuthorizedScope,
        reference: &ContentReference,
    ) -> Result<Arc<[u8]>, UploadError> {
        self.store.resolve(scope, reference)
    }
    /// A shared bridge for event handling in the same explicitly authorized scope.
    pub fn store(&self) -> MemoryContentStore {
        self.store.clone()
    }
}

/// Runtime-neutral immutable storage. References do not confer authorization.
/// Implementations must retain published bytes for the lifetime of their users.
/// Resolution trusts receiver-owned storage, not size/hash claims from events.
pub trait ContentStore: Send + Sync {
    fn resolve(
        &self,
        scope: &AuthorizedScope,
        reference: &ContentReference,
    ) -> Result<Arc<[u8]>, UploadError>;
    fn put(
        &self,
        scope: &AuthorizedScope,
        bytes: Arc<[u8]>,
    ) -> Result<ContentReference, UploadError>;
}

/// An explicitly authorized binding, independent of event metadata or credentials.
#[derive(Clone)]
pub struct ContentContext<'a> {
    pub store: &'a dyn ContentStore,
    pub scope: AuthorizedScope,
}

/// Bounded, shared storage with no eviction or mutable reference replacement.
#[derive(Clone)]
pub struct MemoryContentStore {
    state: Arc<std::sync::Mutex<MemoryState>>,
    max_upload: usize,
    max_total: usize,
    max_entries: usize,
    owner: Option<Arc<StoreOwner>>,
}
struct StoreOwner {
    state: Arc<std::sync::Mutex<MemoryState>>,
    keys: std::sync::Mutex<Vec<(AuthorizedScope, String)>>,
}
impl Drop for StoreOwner {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for key in self
            .keys
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            if let Some(bytes) = state.entries.remove(&key) {
                state.total -= bytes.len();
            }
        }
    }
}
#[derive(Default)]
struct MemoryState {
    closed: bool,
    total: usize,
    next: u64,
    entries: BTreeMap<(AuthorizedScope, String), Arc<[u8]>>,
}
impl MemoryContentStore {
    pub fn new(max_upload: usize, max_total: usize, max_entries: usize) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(MemoryState::default())),
            owner: None,
            max_upload,
            max_total,
            max_entries,
        }
    }
}
impl MemoryContentStore {
    /// Create an allocation owner sharing the exact same active-capacity budget.
    pub(crate) fn scoped(&self) -> Self {
        Self {
            owner: Some(Arc::new(StoreOwner {
                state: Arc::clone(&self.state),
                keys: Default::default(),
            })),
            ..self.clone()
        }
    }
    /// Terminal host shutdown, never eviction or an invocation cleanup strategy.
    pub(crate) fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        state.entries.clear();
        state.total = 0;
    }
    pub(crate) fn shares_budget(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}
impl ContentStore for MemoryContentStore {
    fn resolve(
        &self,
        scope: &AuthorizedScope,
        reference: &ContentReference,
    ) -> Result<Arc<[u8]>, UploadError> {
        descriptor(serde_json::to_value(reference).map_err(|_| UploadError::Descriptor)?)?;
        let state = self.state.lock().map_err(|_| UploadError::Unavailable)?;
        if let Some(owner) = &self.owner {
            let keys = owner.keys.lock().map_err(|_| UploadError::Unavailable)?;
            if !keys.contains(&(scope.clone(), reference.ref_.clone())) {
                return Err(UploadError::Unavailable);
            }
        }
        let bytes = state
            .entries
            .get(&(scope.clone(), reference.ref_.clone()))
            .ok_or(UploadError::Unavailable)?;
        Ok(Arc::clone(bytes))
    }
    fn put(
        &self,
        scope: &AuthorizedScope,
        bytes: Arc<[u8]>,
    ) -> Result<ContentReference, UploadError> {
        if bytes.len() > self.max_upload {
            return Err(UploadError::TooLarge);
        }
        let mut state = self.state.lock().map_err(|_| UploadError::Unavailable)?;
        if state.closed {
            return Err(UploadError::Unavailable);
        }
        if state.entries.len() >= self.max_entries
            || bytes.len() > self.max_total.saturating_sub(state.total)
        {
            return Err(UploadError::Capacity);
        }
        let next = state.next.checked_add(1).ok_or(UploadError::Capacity)?;
        let reference = descriptor(json!({"ref": format!("content-{next}")}))?;
        if let Some(owner) = &self.owner {
            owner
                .keys
                .lock()
                .map_err(|_| UploadError::Unavailable)?
                .push((scope.clone(), reference.ref_.clone()));
        }
        state.total += bytes.len();
        state.next = next;
        state
            .entries
            .insert((scope.clone(), reference.ref_.clone()), bytes);
        Ok(reference)
    }
}
impl ContentContext<'_> {
    /// Validate canonical shape and resolve bytes from the trusted scoped store.
    pub fn resolve(&self, reference: &serde_json::Value) -> Result<Arc<[u8]>, UploadError> {
        let reference = descriptor(reference.clone())?;
        self.store.resolve(&self.scope, &reference)
    }
    /// A descriptor is publishable only after both the write and read verify.
    pub fn put(&self, bytes: &[u8]) -> Result<serde_json::Value, UploadError> {
        let reference = self.store.put(&self.scope, Arc::from(bytes))?;
        let value = serde_json::to_value(&reference).map_err(|_| UploadError::Descriptor)?;
        descriptor(value.clone())?;
        if self.resolve(&value)?.as_ref() != bytes {
            return Err(UploadError::Descriptor);
        }
        Ok(value)
    }
    /// Metadata and omitted views never trigger reads. Body gaps fail closed.
    pub fn resolve_selected(
        &self,
        item: &serde_json::Value,
    ) -> Result<Option<Arc<[u8]>>, UploadError> {
        match item.get("selection").and_then(serde_json::Value::as_str) {
            Some("metadata" | "omit") => Ok(None),
            Some("body") => {
                if item.get("gap").is_some() {
                    return Err(UploadError::Unavailable);
                }
                if item.get("size").is_some() || item.get("sha256").is_some() {
                    return Err(UploadError::Descriptor);
                }
                let reference = item.get("body").ok_or(UploadError::Unavailable)?;
                let bytes = self.resolve(reference)?;
                Ok(Some(bytes))
            }
            _ => Err(UploadError::Descriptor),
        }
    }
    /// Apply a caller-selected bound to the resolved stored bytes.
    pub fn resolve_limited(
        &self,
        reference: &serde_json::Value,
        max_bytes: usize,
    ) -> Result<Arc<[u8]>, UploadError> {
        let bytes = self.resolve(reference)?;
        if bytes.len() > max_bytes {
            return Err(UploadError::TooLarge);
        }
        Ok(bytes)
    }
    pub fn resolve_text(
        &self,
        reference: &serde_json::Value,
        max_bytes: usize,
    ) -> Result<String, UploadError> {
        let bytes = self.resolve_limited(reference, max_bytes)?;
        std::str::from_utf8(&bytes)
            .map(str::to_owned)
            .map_err(|_| UploadError::Descriptor)
    }
    pub fn resolve_json(
        &self,
        reference: &serde_json::Value,
        max_bytes: usize,
    ) -> Result<serde_json::Value, UploadError> {
        serde_json::from_str(&self.resolve_text(reference, max_bytes)?)
            .map_err(|_| UploadError::Descriptor)
    }
    /// Stage a new immutable body without changing the caller's item. Logical
    /// identity, role, and view metadata are retained; bodies contain only a reference.
    pub fn rewrite_body(
        &self,
        item: &serde_json::Value,
        bytes: &[u8],
    ) -> Result<serde_json::Value, UploadError> {
        if item.get("selection").and_then(serde_json::Value::as_str) != Some("body") {
            return Err(UploadError::Descriptor);
        }
        self.resolve_selected(item)?;
        let reference = self.put(bytes)?;
        let mut staged = item.clone();
        let object = staged.as_object_mut().ok_or(UploadError::Descriptor)?;
        object.remove("gap");
        object.remove("size");
        object.remove("sha256");
        object.insert("body".into(), reference);
        Ok(staged)
    }
    /// Publish the returned batch only after this function succeeds. A failed
    /// batch can leave unreferenced uploads, but never mutates input items.
    pub fn rewrite_bodies(
        &self,
        updates: &[(&serde_json::Value, &[u8])],
    ) -> Result<Vec<serde_json::Value>, UploadError> {
        updates
            .iter()
            .map(|(item, bytes)| self.rewrite_body(item, bytes))
            .collect()
    }
}

/// Explicit staging lifetime for one Hooks invocation. Dropping an unused scope
/// releases its allocations. Move it into `.content_scope(scope)` for dispatch.
/// This is deliberately not Clone: an invocation cannot retain another scope's archive.
pub struct ContentScope {
    pub(crate) store: MemoryContentStore,
    pub(crate) scope: AuthorizedScope,
    pub(crate) bodies: Option<crate::body::DeferredBodies>,
    pub(crate) guards: Vec<crate::body::DeferredBodyGuard>,
}
impl ContentScope {
    /// Own an unread source until this scope is dispatched or dropped. Prefer a
    /// boundary's `.body_source(...)` when using generated input slots.
    pub async fn stage_body(
        &mut self,
        body: crate::body::Body,
    ) -> Result<serde_json::Value, crate::body::BodyError> {
        let bodies = self
            .bodies
            .as_ref()
            .ok_or_else(|| crate::body::BodyError::Read("scope has no body registry".into()))?;
        let reference = bodies.register(body)?;
        self.guards.push(bodies.guard(&reference));
        Ok(reference)
    }
    pub fn context(&self) -> ContentContext<'_> {
        ContentContext {
            store: self,
            scope: self.scope.clone(),
        }
    }
    pub fn put(&self, bytes: &[u8]) -> Result<serde_json::Value, UploadError> {
        self.context().put(bytes)
    }
    pub fn resolve(&self, reference: &serde_json::Value) -> Result<Arc<[u8]>, UploadError> {
        self.context().resolve(reference)
    }
    pub(crate) fn retain(&self, references: &[&serde_json::Value]) -> OwnedContent {
        let mut result = OwnedContent {
            scope: self.scope.clone(),
            entries: BTreeMap::new(),
            attachments: BTreeMap::new(),
            attachment_results: BTreeMap::new(),
            attachment_metadata: BTreeMap::new(),
        };
        for reference in references {
            result.collect_reference(reference, &self.context());
        }
        result
    }
}

/// Immutable result-owned payloads, independent of the invocation store and its
/// active staging budget. Only schema-owned content slots and explicitly bound
/// content targets retain payloads; reference-shaped opaque JSON does not.
#[derive(Clone)]
pub struct OwnedContent {
    pub(crate) attachments: BTreeMap<String, crate::attachment::SharedAttachment>,
    attachment_results: BTreeMap<String, Arc<[u8]>>,
    attachment_metadata: BTreeMap<String, AttachmentMetadata>,
    scope: AuthorizedScope,
    entries: BTreeMap<String, Arc<[u8]>>,
}
#[derive(Clone)]
struct AttachmentMetadata {
    size: Option<serde_json::Value>,
    sha256: Option<serde_json::Value>,
}
impl AttachmentMetadata {
    fn validate(&self, bytes: &[u8]) -> Result<(), crate::body::BodyError> {
        let size_matches = self.size.as_ref().is_none_or(|size| {
            size.as_number().and_then(byte_size) == u64::try_from(bytes.len()).ok()
        });
        let digest_matches = self.sha256.as_ref().is_none_or(|sha256| {
            sha256
                .as_str()
                .is_some_and(|expected| expected == digest(bytes))
        });
        if size_matches && digest_matches {
            Ok(())
        } else {
            Err(crate::body::BodyError::Upload(UploadError::Descriptor))
        }
    }
}
impl OwnedContent {
    /// Read by content-item JSON pointer (for example `/items/0`). Sources and
    /// immutable bytes outlive Hooks. Serialize concurrent first reads of a lazy
    /// source; read failure and cancellation are terminal and never retried.
    /// Effective item size and SHA-256 metadata are checked on every read.
    pub async fn read(&self, path: &str) -> Result<Arc<[u8]>, crate::body::BodyError> {
        let bytes = if let Some(bytes) = self.attachment_results.get(path) {
            bytes.clone()
        } else {
            self.attachments
                .get(path)
                .ok_or_else(|| crate::body::BodyError::Read("unknown attachment slot".into()))?
                .read()
                .await?
        };
        // Validate every access, including cached lazy reads and resolved bytes.
        // Metadata belongs to the effective item, not its transport reference.
        if let Some(metadata) = self.attachment_metadata.get(path) {
            metadata.validate(&bytes)?;
        }
        Ok(bytes)
    }

    pub(crate) fn retain_attachment_results(&mut self, event: &serde_json::Value) {
        for path in self.attachments.keys().cloned().collect::<Vec<_>>() {
            if let Some(item) = event.pointer(&path) {
                self.attachment_metadata.insert(
                    path.clone(),
                    AttachmentMetadata {
                        size: item.get("size").cloned(),
                        sha256: item.get("sha256").cloned(),
                    },
                );
            }
            if let Some(body) = event.pointer(&path).and_then(|item| item.get("body"))
                && let Ok(bytes) = self.resolve(body)
            {
                self.attachments.remove(&path);
                self.attachment_results.insert(path, bytes);
            }
        }
    }

    // Callers supply exact schema-owned reference slots, never opaque JSON roots.
    fn collect_reference(&mut self, value: &serde_json::Value, context: &ContentContext<'_>) {
        if let Ok(reference) = descriptor(value.clone())
            && let Ok(bytes) = context.resolve(value)
        {
            self.entries.insert(reference.ref_, bytes);
        }
    }
    pub fn context(&self) -> ContentContext<'_> {
        ContentContext {
            store: self,
            scope: self.scope.clone(),
        }
    }
    pub fn resolve(&self, reference: &serde_json::Value) -> Result<Arc<[u8]>, UploadError> {
        self.context().resolve(reference)
    }
}
impl ContentStore for OwnedContent {
    fn resolve(
        &self,
        scope: &AuthorizedScope,
        reference: &ContentReference,
    ) -> Result<Arc<[u8]>, UploadError> {
        if scope != &self.scope {
            return Err(UploadError::Unavailable);
        }
        self.entries
            .get(&reference.ref_)
            .cloned()
            .ok_or(UploadError::Unavailable)
    }
    fn put(&self, _: &AuthorizedScope, _: Arc<[u8]>) -> Result<ContentReference, UploadError> {
        Err(UploadError::Unavailable)
    }
}

impl ContentStore for ContentScope {
    fn resolve(
        &self,
        scope: &AuthorizedScope,
        reference: &ContentReference,
    ) -> Result<Arc<[u8]>, UploadError> {
        let value = serde_json::to_value(reference).map_err(|_| UploadError::Descriptor)?;
        let snapshot = self
            .bodies
            .as_ref()
            .and_then(|bodies| bodies.snapshot(&value));
        let snapshot = snapshot.map(descriptor).transpose()?;
        self.store
            .resolve(scope, snapshot.as_ref().unwrap_or(reference))
    }
    fn put(
        &self,
        scope: &AuthorizedScope,
        bytes: Arc<[u8]>,
    ) -> Result<ContentReference, UploadError> {
        self.store.put(scope, bytes)
    }
}

#[cfg(test)]
mod owned_attachment_metadata_tests {
    use super::*;

    #[test]
    fn resolved_attachment_reads_validate_effective_metadata_on_every_access() {
        futures::executor::block_on(async {
            for (size, sha256, valid) in [
                (json!(999), json!(digest(b"abc")), false),
                (json!(3), json!("0".repeat(64)), false),
                (json!(3.0), json!(digest(b"abc")), true),
            ] {
                let store = MemoryContentStore::new(10, 10, 10);
                let context = ContentContext {
                    store: &store,
                    scope: AuthorizedScope::new("attachment-test"),
                };
                let reference = context.put(b"abc").unwrap();
                let mut content = OwnedContent {
                    attachments: BTreeMap::new(),
                    attachment_results: BTreeMap::new(),
                    attachment_metadata: BTreeMap::new(),
                    scope: context.scope.clone(),
                    entries: BTreeMap::new(),
                };
                content.collect_reference(&reference, &context);
                // The effective resolved bytes replace the original attachment.
                let (_, original) = crate::Attachment::bytes(b"original".to_vec()).bind(10);
                content.attachments.insert("/items/0".into(), original);
                content.retain_attachment_results(&json!({"items":[{
                    "body":reference, "size":size, "sha256":sha256
                }]}));
                assert!(content.attachments.is_empty());
                drop(store);
                for _ in 0..2 {
                    let read = content.read("/items/0").await;
                    assert_eq!(read.is_ok(), valid);
                    if valid {
                        assert_eq!(&*read.unwrap(), b"abc");
                    } else {
                        assert!(matches!(
                            read,
                            Err(crate::body::BodyError::Upload(UploadError::Descriptor))
                        ));
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod deferred_attachment_metadata_tests {
    use super::*;
    use crate::body::{BodyChunkFuture, BodyStream};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Source {
        reads: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        done: bool,
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
                if self.done {
                    Ok(None)
                } else {
                    self.done = true;
                    Ok(Some(b"abc".to_vec()))
                }
            })
        }
    }
    #[test]
    fn deferred_reads_check_retained_metadata_after_shutdown_and_on_repeat() {
        futures::executor::block_on(async {
            for (metadata, valid) in [
                (json!({"size":999}), false),
                (json!({"sha256":"0".repeat(64)}), false),
                (json!({"size":3.0,"sha256":digest(b"abc")}), true),
                (json!({}), true),
            ] {
                let reads = Arc::new(AtomicUsize::new(0));
                let drops = Arc::new(AtomicUsize::new(0));
                let (delivery, source) = crate::Attachment::lazy(Source {
                    reads: reads.clone(),
                    drops: drops.clone(),
                    done: false,
                })
                .bind(10);
                let mut content = OwnedContent {
                    attachments: BTreeMap::from([("/items/0".into(), source)]),
                    attachment_results: BTreeMap::new(),
                    attachment_metadata: BTreeMap::new(),
                    scope: AuthorizedScope::new("metadata-test"),
                    entries: BTreeMap::new(),
                };
                let mut event = json!({"items":[metadata]});
                content.retain_attachment_results(&event);
                assert_eq!(reads.load(Ordering::SeqCst), 0);
                // The result's metadata snapshot and source survive the invocation.
                drop(delivery);
                event["items"][0] = json!({});
                for _ in 0..2 {
                    let read = content.read("/items/0").await;
                    assert_eq!(read.is_ok(), valid);
                    if valid {
                        assert_eq!(&*read.unwrap(), b"abc");
                    } else {
                        assert!(matches!(
                            read,
                            Err(crate::body::BodyError::Upload(UploadError::Descriptor))
                        ));
                    }
                }
                assert_eq!(reads.load(Ordering::SeqCst), 2);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
            }
        });
    }
}
