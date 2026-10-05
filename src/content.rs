//! Immutable raw-byte uploads, independent of event credentials and transport.
//!
//! Callers supply a transport and (when needed) an explicit runtime deadline. This
//! module does not start a runtime, infer event credentials, or follow redirects.
pub use crate::generated::content::*;
use crate::generated::{ParseResult, parse_content_reference_value};
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
// Generated Integer validates exact integrality and the interoperable safe
// range before conversion. Thus 3, 3.0 and 3e0 compare equally without changing
// the descriptor's retained JSON representation or rounding unsafe numbers.
fn byte_size(number: &serde_json::Number) -> Option<u64> {
    let integer = crate::generated::Integer::new(number.clone())?;
    let value = integer.as_number().as_f64()?;
    (value >= 0.0).then_some(value as u64)
}
fn matches(reference: &ContentReference, bytes: &[u8]) -> bool {
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
    /// nor truncated. Only a verified receiver-allocated 201 reference is returned.
    pub async fn upload(&self, bytes: &[u8]) -> Result<ContentReference, UploadError> {
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
        let reference = descriptor(
            serde_json::from_slice(&response.body).map_err(|_| UploadError::Descriptor)?,
        )?;
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
    fn accept(&mut self, request: &Request) -> Result<ContentReference, UploadError> {
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
        self.store.put(&scope, Arc::from(request.body.as_slice()))
    }
    /// Verify availability, scope, exact size and hash before publishing any
    /// effect or event that refers to this descriptor. Returns immutable bytes.
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
pub trait ContentStore {
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
}
#[derive(Default)]
struct MemoryState {
    total: usize,
    next: u64,
    entries: BTreeMap<(AuthorizedScope, String), Arc<[u8]>>,
}
impl MemoryContentStore {
    pub fn new(max_upload: usize, max_total: usize, max_entries: usize) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(MemoryState::default())),
            max_upload,
            max_total,
            max_entries,
        }
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
        let bytes = state
            .entries
            .get(&(scope.clone(), reference.ref_.clone()))
            .ok_or(UploadError::Unavailable)?;
        if !matches(reference, bytes) {
            return Err(UploadError::Descriptor);
        }
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
        if state.entries.len() >= self.max_entries
            || bytes.len() > self.max_total.saturating_sub(state.total)
        {
            return Err(UploadError::Capacity);
        }
        let next = state.next.checked_add(1).ok_or(UploadError::Capacity)?;
        let reference = descriptor(
            json!({"ref": format!("content-{next}"), "size": bytes.len(), "sha256": digest(&bytes)}),
        )?;
        state.total += bytes.len();
        state.next = next;
        state
            .entries
            .insert((scope.clone(), reference.ref_.clone()), bytes);
        Ok(reference)
    }
}
impl ContentContext<'_> {
    /// Validate canonical shape and verify exact bytes even for a host-supplied store.
    pub fn resolve(&self, reference: &serde_json::Value) -> Result<Arc<[u8]>, UploadError> {
        let reference = descriptor(reference.clone())?;
        let bytes = self.store.resolve(&self.scope, &reference)?;
        if !matches(&reference, &bytes) {
            return Err(UploadError::Descriptor);
        }
        Ok(bytes)
    }
    /// A descriptor is publishable only after both the write and read verify.
    pub fn put(&self, bytes: &[u8]) -> Result<serde_json::Value, UploadError> {
        let reference = self.store.put(&self.scope, Arc::from(bytes))?;
        let value = serde_json::to_value(&reference).map_err(|_| UploadError::Descriptor)?;
        let reference = descriptor(value.clone())?;
        if !matches(&reference, bytes) {
            return Err(UploadError::Descriptor);
        }
        self.resolve(&value)?;
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
                let reference = item.get("body").ok_or(UploadError::Unavailable)?;
                let bytes = self.resolve(reference)?;
                if item.get("size").is_some_and(|size| {
                    size.as_number().and_then(byte_size) != u64::try_from(bytes.len()).ok()
                }) || item
                    .get("sha256")
                    .is_some_and(|hash| hash.as_str() != Some(digest(&bytes).as_str()))
                {
                    return Err(UploadError::Descriptor);
                }
                Ok(Some(bytes))
            }
            _ => Err(UploadError::Descriptor),
        }
    }
    /// Apply a caller-selected bound before fetching and after verification.
    pub fn resolve_limited(
        &self,
        reference: &serde_json::Value,
        max_bytes: usize,
    ) -> Result<Arc<[u8]>, UploadError> {
        let parsed = descriptor(reference.clone())?;
        let size = byte_size(parsed.size.as_number()).ok_or(UploadError::Descriptor)?;
        if size > max_bytes as u64 {
            return Err(UploadError::TooLarge);
        }
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
    /// identity, role, and view metadata are retained; size/hash describe the new bytes.
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
        object.insert("size".into(), reference["size"].clone());
        object.insert("sha256".into(), reference["sha256"].clone());
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
