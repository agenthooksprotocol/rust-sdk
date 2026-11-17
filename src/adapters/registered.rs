//! Owned, lazy transports for canonical registration backends.
//!
//! No runtime or worker thread is created. Call `shutdown` before dropping the
//! caller's runtime to deterministically reap children after cancellation.
use super::registered_headers;
pub use super::registered_headers::{HeaderContext, HeaderResolver, HeaderSource};
use crate::client::{HookError, LocalFuture};
use serde_json::Value;
#[cfg(any(feature = "reqwest", feature = "tokio-process"))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

/// Destination-specific authorization. Upload credentials never inherit event credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthPurpose {
    Event,
    Upload,
}
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub backend_id: String,
    pub authentication: Option<Value>,
    pub destination: String,
    pub purpose: AuthPurpose,
    /// The operation owns this deadline and cancellation (by dropping the future).
    pub deadline: std::time::Instant,
}
/// Deliberately has no Debug implementation: tokens must not enter diagnostics.
#[derive(Clone)]
pub struct BearerCredential {
    pub token: String,
    /// Opaque host identity, not the token or a reversible representation of it.
    pub attempt_id: String,
}
#[derive(Clone, Debug)]
pub struct AuthChallenge {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub attempt_id: Option<String>,
}
/// Host owns secret storage, OAuth, refresh coordination and provider lifecycle.
/// Implementations must not detach work from the lifetime of these futures.
pub trait AuthProvider: Send + Sync {
    fn credential(
        &self,
        context: AuthContext,
    ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>>;
    fn challenge(
        &self,
        context: AuthContext,
        challenge: AuthChallenge,
    ) -> LocalFuture<'_, Result<(), HookError>>;
}

/// A backend owns its transport and can be shared across subscriptions.
pub trait ManagedBackend: Send + Sync {
    fn call(&self, request: Value, timeout: Duration) -> LocalFuture<'_, Result<Value, HookError>>;
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>>;
}
#[derive(Clone)]
pub struct BackendOptions {
    /// Host-owned authentication; futures are cancelled with the operation.
    pub auth_provider: Option<Arc<dyn AuthProvider>>,
    /// Host-owned per-dispatch header resolution. Defaults to environment/credentials lookup.
    pub header_resolver: Option<Arc<dyn HeaderResolver>>,
    /// Explicit bearer references. `tokenEnv` authorizes an environment lookup.
    pub credentials: BTreeMap<String, String>,
    pub allow_loopback_http: bool,
    pub max_frame_bytes: usize,
    /// SDK-level opt-out, not a protocol setting. When `false` (the
    /// default), stdio children receive only a minimal base environment
    /// (`PATH`, `HOME`, locale, temp-directory and similar variables) plus
    /// the registration's `env` entries. When `true`, children inherit the
    /// full host environment, with `env` entries applied on top.
    pub inherit_environment: bool,
}
impl Default for BackendOptions {
    fn default() -> Self {
        Self {
            auth_provider: None,
            header_resolver: None,
            credentials: BTreeMap::new(),
            allow_loopback_http: false,
            max_frame_bytes: 1024 * 1024,
            inherit_environment: false,
        }
    }
}
impl BackendOptions {
    pub(crate) fn resolve_secret(&self, source: &HeaderSource) -> Option<String> {
        match source {
            HeaderSource::Environment(key) => std::env::var(key).ok(),
            HeaderSource::Reference(key) => self.credentials.get(key).cloned(),
        }
    }
}
pub(super) fn error(message: &str) -> HookError {
    use crate::generated::DeliveryDiagnosticCode;
    let code = if message.contains("deadline") {
        DeliveryDiagnosticCode::DeadlineExceeded
    } else if matches!(
        message,
        "invalid protocol JSON response"
            | "response correlation mismatch"
            | "invalid protocol response"
            | "unsupported response effects"
            | "expected one application/json response header"
            | "invalid notification acknowledgment"
            | "response exceeds frame limit"
            | "unsupported protocol method"
            | "request correlation mismatch"
    ) {
        DeliveryDiagnosticCode::ProtocolRejection
    } else {
        DeliveryDiagnosticCode::Transport
    };
    HookError::new(message).classified(code)
}

/// Validate configuration without opening sockets or spawning children.
/// Unsupported authentication is never downgraded to bearer or anonymous access.
pub fn from_registration(
    backend: &Value,
    options: &BackendOptions,
) -> Result<Arc<dyn ManagedBackend>, HookError> {
    if options.max_frame_bytes == 0 {
        return Err(error("frame limit must be positive"));
    }
    let transport = &backend["transport"];
    let headers = if transport["type"] == "http" {
        registered_headers::parse(transport.get("headers"))?
    } else {
        Default::default()
    };
    let auth = backend
        .get("authentication")
        .filter(|_| !headers.contains_key("authorization"));
    if let Some(auth) = auth {
        match auth["type"].as_str() {
            Some("bearer") => {}
            Some("oauth") if options.auth_provider.is_some() => {
                if !matches!(
                    auth["flow"].as_str(),
                    Some("authorization_code_pkce" | "client_credentials")
                ) {
                    return Err(HookError::authentication(
                        crate::auth::AuthErrorCode::UnsupportedBinding,
                    ));
                }
            }
            _ => {
                return Err(HookError::authentication(
                    crate::auth::AuthErrorCode::UnsupportedBinding,
                ));
            }
        }
    }
    match transport["type"].as_str() {
        Some("http") => {
            let endpoint = transport["url"]
                .as_str()
                .ok_or_else(|| error("missing HTTP URL"))?;
            let url = url::Url::parse(endpoint).map_err(|_| error("invalid HTTP URL"))?;
            let loopback = url.host_str().is_some_and(|h| {
                h == "localhost"
                    || h.trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(error(
                    "HTTP URL must have a host and no credentials or fragment",
                ));
            }
            if url.scheme() != "https"
                && !(url.scheme() == "http" && loopback && options.allow_loopback_http)
            {
                return Err(error(
                    "HTTPS required; loopback HTTP requires explicit opt-in",
                ));
            }
            let authorization = if options.auth_provider.is_some() {
                None
            } else {
                match auth {
                    None => None,
                    Some(auth) => {
                        let token = match (auth.get("tokenRef"), auth.get("tokenEnv")) {
                        (Some(reference), None) => reference
                            .as_str()
                            .and_then(|key| options.resolve_secret(&HeaderSource::Reference(key.into()))),
                        (None, Some(env)) => env
                            .as_str()
                            .filter(|key| {
                                !key.is_empty()
                                    && key.bytes().enumerate().all(|(i, b)| {
                                        b == b'_'
                                            || b.is_ascii_alphabetic()
                                            || (i > 0 && b.is_ascii_digit())
                                    })
                            })
                            .and_then(|key| options.resolve_secret(&HeaderSource::Environment(key.into()))),
                        _ => {
                            return Err(error(
                                "bearer authentication requires exactly one tokenRef or tokenEnv",
                            ));
                        }
                    }
                    .filter(|token| {
                        !token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic())
                    })
                    .ok_or_else(|| HookError::authentication(crate::auth::AuthErrorCode::CredentialUnavailable))?;
                        Some(format!("Bearer {token}"))
                    }
                }
            };
            #[cfg(feature = "reqwest")]
            {
                Ok(Arc::new(HttpBackend {
                    endpoint: endpoint.into(),
                    headers,
                    backend_id: backend["id"].as_str().unwrap_or("").into(),
                    authentication: auth.cloned(),
                    authorization,
                    options: options.clone(),
                    closed: AtomicBool::new(false),
                }))
            }
            #[cfg(not(feature = "reqwest"))]
            {
                let _ = (authorization, headers);
                Err(error("HTTP backend requires the reqwest feature"))
            }
        }
        Some("stdio") => {
            if auth.is_some() {
                return Err(error("authentication on stdio is unsupported"));
            }
            let command = transport["command"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| error("stdio command is required"))?;
            let per_event = match transport["lifecycle"].as_str() {
                Some("persistent") => false,
                Some("per_event") => true,
                _ => return Err(error("stdio lifecycle must be persistent or per_event")),
            };
            let args = match transport.get("args") {
                None => Vec::new(),
                Some(value) => value
                    .as_array()
                    .ok_or_else(|| error("stdio args must be an array"))?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(String::from)
                            .ok_or_else(|| error("stdio arguments must be strings"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            };
            let cwd = transport
                .get("cwd")
                .map(|v| {
                    v.as_str()
                        .map(String::from)
                        .ok_or_else(|| error("stdio cwd must be a string"))
                })
                .transpose()?;
            // Literal values: no expansion, interpolation or secret resolution.
            // Diagnostics never include values.
            let env = match transport.get("env") {
                None => Vec::new(),
                Some(value) => value
                    .as_object()
                    .ok_or_else(|| error("stdio env must be an object"))?
                    .iter()
                    .map(|(name, value)| match value.as_str() {
                        Some(value)
                            if !name.is_empty()
                                && !name.contains(['=', '\0'])
                                && !value.contains('\0') =>
                        {
                            Ok((name.clone(), value.to_owned()))
                        }
                        _ => Err(error("stdio env entries must be valid name/string pairs")),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            };
            #[cfg(feature = "tokio-process")]
            {
                Ok(Arc::new(StdioBackend {
                    command: command.into(),
                    args,
                    cwd,
                    env,
                    inherit_environment: options.inherit_environment,
                    per_event,
                    limit: options.max_frame_bytes,
                    closed: AtomicBool::new(false),
                    process: std::sync::Mutex::new(None),
                    gate: tokio::sync::Mutex::new(()),
                }))
            }
            #[cfg(not(feature = "tokio-process"))]
            {
                let _ = (command, args, cwd, env, per_event);
                Err(error("stdio backend requires the tokio-process feature"))
            }
        }
        _ => Err(error("unsupported backend transport")),
    }
}
// Classification only: providers still validate the complete challenge and scope policy.
#[cfg(feature = "reqwest")]
use crate::auth::challenge::insufficient_scope;

#[cfg(any(feature = "reqwest", feature = "tokio-process"))]
fn validate_request(request: &Value) -> Result<bool, HookError> {
    let (schema, notification) = match request["method"].as_str() {
        Some("hooks/intercept") => ("intercept-request", false),
        Some("hooks/capabilities") => ("capabilities-request", false),
        Some("hooks/configuration") => ("configuration-request", false),
        Some("hooks/observe") => ("observe-notification", true),
        _ => return Err(error("unsupported protocol method")),
    };
    crate::canonical::validate(schema, request).map_err(|_| error("invalid protocol response"))?;
    if schema == "intercept-request" && request["id"] != request["params"]["event"]["id"] {
        return Err(error("request correlation mismatch"));
    }
    Ok(notification)
}
#[cfg(any(feature = "reqwest", feature = "tokio-process"))]
fn validate_response(request: &Value, body: &[u8]) -> Result<Value, HookError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| error("invalid protocol JSON response"))?;
    if value["id"] != request["id"] {
        return Err(error("response correlation mismatch"));
    }
    crate::client::check_rpc_error(&value, &request["id"])?;
    let intercept = request["method"] == "hooks/intercept";
    if !intercept {
        crate::canonical::validate(
            if request["method"] == "hooks/configuration" {
                "configuration-response"
            } else {
                "capabilities-response"
            },
            &value,
        )
        .map_err(|_| error("invalid protocol response"))?;
    }
    if intercept {
        crate::server::validate_effect_capabilities(request, &value)
            .map_err(|_| error("unsupported response effects"))?;
    }
    Ok(value)
}
#[cfg(feature = "reqwest")]
struct HttpBackend {
    headers: registered_headers::Headers,
    backend_id: String,
    authentication: Option<Value>,
    endpoint: String,
    authorization: Option<String>,
    options: BackendOptions,
    closed: AtomicBool,
}
#[cfg(feature = "reqwest")]
impl ManagedBackend for HttpBackend {
    fn call(&self, request: Value, timeout: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            tokio::time::timeout(timeout, async move {
                let started = std::time::Instant::now();
                if self.closed.load(Ordering::Acquire) {
                    return Err(error("backend is shut down"));
                }
                let notification = validate_request(&request)?;
                let body = serde_json::to_vec(&request).map_err(|_| error("invalid request"))?;
                if body.len() > self.options.max_frame_bytes {
                    return Err(error("request exceeds frame limit"));
                }
                let context = AuthContext {
                    backend_id: self.backend_id.clone(),
                    authentication: self.authentication.clone(),
                    destination: self.endpoint.clone(),
                    purpose: AuthPurpose::Event,
                    deadline: started
                        .checked_add(timeout)
                        .ok_or_else(|| error("invalid deadline"))?,
                };
                // Capability discovery must not resolve arbitrary registration secrets.
                // Explicit Authorization remains an intentional auth override on every request.
                let capability_headers = (request["method"] == "hooks/capabilities").then(|| {
                    self.headers
                        .iter()
                        .filter(|(name, _)| name.as_str() == "authorization")
                        .map(|(name, value)| (name.clone(), value.clone()))
                        .collect()
                });
                let headers = registered_headers::resolve(
                    capability_headers.as_ref().unwrap_or(&self.headers),
                    &self.backend_id,
                    &self.endpoint,
                    context.deadline,
                    AuthPurpose::Event,
                    &self.options,
                )
                .await?;
                let client = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|_| error("HTTP client initialization failed"))?;
                let explicit_auth = self.headers.contains_key("authorization");
                let provider = self
                    .options
                    .auth_provider
                    .as_ref()
                    .filter(|_| !explicit_auth);
                // Challenged replay: at most once, same id and buffered body, and only
                // for requests that expect a response. Notifications are never replayed.
                let mut challenged = false;
                let mut response = loop {
                    let credential = if let Some(provider) = provider {
                        provider
                            .credential(context.clone())
                            .await
                            .map_err(crate::auth::sanitize_provider_error)?
                    } else {
                        None
                    };
                    if provider.is_some() && credential.is_none() && self.authentication.is_some() {
                        return Err(HookError::authentication(
                            crate::auth::AuthErrorCode::CredentialUnavailable,
                        ));
                    }
                    let mut outgoing = client
                        .post(&self.endpoint)
                        .header("content-type", "application/json")
                        .body(body.clone());
                    if let Some(credential) = &credential {
                        if credential.token.is_empty()
                            || !credential.token.bytes().all(|b| b.is_ascii_graphic())
                        {
                            return Err(HookError::authentication(
                                crate::auth::AuthErrorCode::CredentialUnavailable,
                            ));
                        }
                        outgoing = outgoing.bearer_auth(&credential.token);
                    } else if let Some(auth) = &self.authorization {
                        outgoing = outgoing.header("authorization", auth);
                    }
                    let mut configured = reqwest::header::HeaderMap::new();
                    for (name, value) in &headers {
                        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                            .map_err(|_| error("invalid HTTP header name"))?;
                        let mut value = reqwest::header::HeaderValue::from_str(value)
                            .map_err(|_| error("invalid HTTP header value"))?;
                        value.set_sensitive(true);
                        configured.insert(name, value);
                    }
                    outgoing = outgoing.headers(configured);
                    let remaining = timeout
                        .checked_sub(started.elapsed())
                        .filter(|d| !d.is_zero())
                        .ok_or_else(|| error("HTTP deadline exceeded"))?;
                    let response = outgoing.timeout(remaining).send().await.map_err(|e| {
                        error(if e.is_timeout() {
                            "HTTP deadline exceeded"
                        } else {
                            "HTTP transport failed"
                        })
                    })?;
                    let status = response.status().as_u16();
                    // Only authentication metadata is exposed, never response bodies.
                    let challenge_header = response
                        .headers()
                        .get_all(reqwest::header::WWW_AUTHENTICATE)
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .collect::<Vec<_>>()
                        .join(", ");
                    if (status == 401 || (status == 403 && insufficient_scope(&challenge_header)))
                        && let Some(provider) = provider
                        && !std::mem::replace(&mut challenged, true)
                    {
                        provider
                            .challenge(
                                context.clone(),
                                AuthChallenge {
                                    status,
                                    headers: BTreeMap::from([(
                                        "www-authenticate".into(),
                                        challenge_header,
                                    )]),
                                    attempt_id: credential.as_ref().map(|c| c.attempt_id.clone()),
                                },
                            )
                            .await
                            .map_err(crate::auth::sanitize_provider_error)?;
                        // A second rejection is an operational failure.
                        if !notification {
                            continue;
                        }
                    }
                    break response;
                };
                let status = response.status().as_u16();
                if !notification {
                    if status != 200 {
                        return Err(error("unexpected HTTP response status"));
                    }
                    // Inspect HeaderMap before flattening: duplicate media headers are invalid.
                    let types: Vec<_> = response
                        .headers()
                        .get_all(reqwest::header::CONTENT_TYPE)
                        .iter()
                        .collect();
                    if types.len() != 1
                        || !types[0]
                            .to_str()
                            .unwrap_or("")
                            .split(';')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .eq_ignore_ascii_case("application/json")
                    {
                        return Err(error("expected one application/json response header"));
                    }
                }
                let limit = self.options.max_frame_bytes;
                if response.content_length().is_some_and(|n| n > limit as u64) {
                    return Err(error("response exceeds frame limit"));
                }
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|e| {
                    error(if e.is_timeout() {
                        "HTTP deadline exceeded"
                    } else {
                        "HTTP body failed"
                    })
                })? {
                    if chunk.len() > limit.saturating_sub(body.len()) {
                        return Err(error("response exceeds frame limit"));
                    }
                    body.extend_from_slice(&chunk);
                }
                let result = if notification {
                    if matches!(status, 202 | 204) && body.is_empty() {
                        Ok(Value::Null)
                    } else {
                        Err(error("invalid notification acknowledgment"))
                    }
                } else {
                    validate_response(&request, &body)
                };
                if started.elapsed() >= timeout {
                    return Err(error("HTTP deadline exceeded"));
                }
                result
            })
            .await
            .map_err(|_| error("HTTP deadline exceeded"))?
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async {
            self.closed.store(true, Ordering::Release);
            Ok(())
        })
    }
}
/// The smallest practical base environment a stdio child receives by default.
#[cfg(feature = "tokio-process")]
fn base_environment_name(name: &str) -> bool {
    const PORTABLE: &[&str] = &[
        "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "TZ", "TMPDIR", "TEMP", "TMP",
    ];
    const WINDOWS: &[&str] = &[
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
    ];
    if cfg!(windows) {
        let upper = name.to_ascii_uppercase();
        PORTABLE.contains(&upper.as_str())
            || WINDOWS.contains(&upper.as_str())
            || upper.starts_with("LC_")
    } else {
        PORTABLE.contains(&name) || name.starts_with("LC_")
    }
}
#[cfg(feature = "tokio-process")]
struct StdioBackend {
    command: String,
    args: Vec<String>,
    cwd: Option<String>,
    env: Vec<(String, String)>,
    inherit_environment: bool,
    per_event: bool,
    limit: usize,
    closed: AtomicBool,
    process: std::sync::Mutex<Option<Arc<super::process::Process>>>,
    gate: tokio::sync::Mutex<()>,
}
#[cfg(feature = "tokio-process")]
impl StdioBackend {
    async fn reap(&self) -> Result<(), HookError> {
        let process = self.process.lock().expect("process lock poisoned").clone();
        if let Some(process) = process {
            process
                .shutdown()
                .await
                .map_err(|_| error("subprocess shutdown failed"))?;
            self.process.lock().expect("process lock poisoned").take();
        }
        Ok(())
    }
}
#[cfg(feature = "tokio-process")]
impl ManagedBackend for StdioBackend {
    fn call(&self, request: Value, timeout: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            use crate::transport::Http;
            if timeout.is_zero() {
                return Err(error("subprocess deadline must be positive"));
            }
            if tokio::runtime::Handle::try_current().is_err() {
                return Err(error("stdio requires a Tokio runtime"));
            }
            let started = std::time::Instant::now();
            tokio::time::timeout(timeout, async {
                let _gate = self.gate.lock().await;
                if self.closed.load(Ordering::Acquire) {
                    return Err(error("backend is shut down"));
                }
                let notification = validate_request(&request)?;
                let body = serde_json::to_vec(&request).map_err(|_| error("invalid request"))?;
                if body.len() > self.limit {
                    return Err(error("request exceeds frame limit"));
                }
                if started.elapsed() >= timeout {
                    return Err(error("subprocess deadline exceeded before spawn"));
                }
                if self.per_event {
                    self.reap().await?;
                }
                if self
                    .process
                    .lock()
                    .expect("process lock poisoned")
                    .is_none()
                {
                    let mut command = tokio::process::Command::new(&self.command);
                    command.args(&self.args);
                    if let Some(cwd) = &self.cwd {
                        command.current_dir(cwd);
                    }
                    if !self.inherit_environment {
                        command.env_clear();
                        command.envs(
                            std::env::vars_os().filter(|(name, _)| {
                                name.to_str().is_some_and(base_environment_name)
                            }),
                        );
                    }
                    // Registration entries replace base values of the same name.
                    command.envs(self.env.iter().map(|(name, value)| (name, value)));
                    // The outer deadline includes queueing and is per-call, not the
                    // first request's budget retained for the lifetime of the process.
                    let process =
                        super::process::Process::spawn(command, self.limit, Duration::MAX)
                            .await
                            .map_err(|_| error("subprocess spawn failed"))?;
                    *self.process.lock().expect("process lock poisoned") = Some(Arc::new(process));
                }
                let process = self
                    .process
                    .lock()
                    .expect("process lock poisoned")
                    .as_ref()
                    .expect("initialized process")
                    .clone();
                let message = crate::transport::Request {
                    body,
                    ..Default::default()
                };
                let mut result = if notification {
                    process
                        .notify(message)
                        .await
                        .map(|_| Value::Null)
                        .map_err(|_| error("subprocess notification failed"))
                } else {
                    match process.send(message).await {
                        Ok(response) => validate_response(&request, &response.body),
                        Err(_) => Err(error("subprocess exchange failed")),
                    }
                };
                if self.per_event && notification && result.is_ok() {
                    // Reserve half the remaining call budget for forced termination/reaping.
                    let grace =
                        (timeout.saturating_sub(started.elapsed()) / 2).min(Duration::from_secs(1));
                    result = process
                        .finish_notification(grace)
                        .await
                        .map(|_| Value::Null)
                        .map_err(|_| error("subprocess notification did not complete gracefully"));
                }
                if self.per_event || result.is_err() {
                    self.reap().await?;
                }
                if started.elapsed() >= timeout {
                    return Err(error("subprocess deadline exceeded"));
                }
                result
            })
            .await
            .map_err(|_| {
                error("subprocess deadline exceeded; interrupted child retained for shutdown")
            })?
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async {
            self.closed.store(true, Ordering::Release);
            let _gate = self.gate.lock().await;
            self.reap().await
        })
    }
}

#[cfg(all(test, feature = "reqwest"))]
mod transport_auth_tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Mutex, atomic::AtomicUsize};
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
    };

    const TIMEOUT: Duration = Duration::from_secs(3);
    #[derive(Default)]
    struct Provider {
        credentials: AtomicUsize,
        challenges: Mutex<Vec<AuthChallenge>>,
        pending_credential: bool,
        pending_challenge: bool,
        dropped: Arc<AtomicBool>,
    }
    struct OnDrop(Arc<AtomicBool>);
    impl Drop for OnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    impl AuthProvider for Provider {
        fn credential(
            &self,
            _: AuthContext,
        ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
            Box::pin(async move {
                self.credentials.fetch_add(1, Ordering::SeqCst);
                let _drop = OnDrop(self.dropped.clone());
                if self.pending_credential {
                    std::future::pending::<()>().await;
                }
                Ok(Some(BearerCredential {
                    token: "cached-unbound".into(),
                    attempt_id: "attempt".into(),
                }))
            })
        }
        fn challenge(
            &self,
            _: AuthContext,
            challenge: AuthChallenge,
        ) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async move {
                self.challenges.lock().unwrap().push(challenge);
                let _drop = OnDrop(self.dropped.clone());
                if self.pending_challenge {
                    std::future::pending::<()>().await;
                }
                Ok(())
            })
        }
    }
    fn request() -> Value {
        json!({"jsonrpc":"2.0","id":"caps","method":"hooks/capabilities","params":{"protocolVersion":"draft"}})
    }
    fn effectful(notification: bool) -> Value {
        let mut request = json!({"jsonrpc":"2.0","id":"evt_demo","method":"hooks/intercept","params":{"protocolVersion":"draft","event":{"id":"evt_demo","harness":{"name":"test","version":"1"},"source":"urn:example:demo","type":"tool.before","time":"2026-08-24T08:51:14Z","session":{"id":"sess_demo","cwd":"/repo","workspaceRoots":["/repo"]},"tool":{"name":"Bash","kind":"shell","input":{"command":"echo hello"},"origin":"native"},"call":{"id":"call_demo"},"path":"example"},"capabilities":{"effects":["deny"]}}});
        if notification {
            request.as_object_mut().unwrap().remove("id");
            request["method"] = json!("hooks/observe");
            request["params"]
                .as_object_mut()
                .unwrap()
                .remove("capabilities");
        }
        request
    }
    async fn backend(
        provider: Arc<Provider>,
        explicit: bool,
    ) -> (Arc<dyn ManagedBackend>, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut registration = json!({"id":"test.auth","transport":{"type":"http","url":format!("http://{}/hooks", listener.local_addr().unwrap())}});
        if explicit {
            registration["transport"]["headers"] = json!({"aUtHoRiZaTiOn":"Bearer explicit"});
            // Explicit headers bypass even an unsupported portable binding.
            registration["authentication"] = json!({"type":"unknown"});
        }
        (
            from_registration(
                &registration,
                &BackendOptions {
                    auth_provider: Some(provider),
                    allow_loopback_http: true,
                    ..Default::default()
                },
            )
            .unwrap(),
            listener,
        )
    }
    async fn respond(listener: &TcpListener, status: u16, challenge: &str) -> String {
        let (socket, _) = tokio::time::timeout(TIMEOUT, listener.accept())
            .await
            .expect("transport did not send a request")
            .unwrap();
        let mut reader = BufReader::new(socket);
        let (mut headers, mut size) = (String::new(), 0);
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                size = value.trim().parse().unwrap();
            }
            headers.push_str(&line.to_ascii_lowercase());
        }
        let mut body = vec![0; size];
        reader.read_exact(&mut body).await.unwrap();
        reader.get_mut().write_all(format!("HTTP/1.1 {status} Rejected\r\nWWW-Authenticate: {challenge}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        headers
    }
    async fn no_replay(listener: &TcpListener) {
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn explicit_authorization_bypasses_provider_on_capabilities() {
        let provider = Arc::new(Provider::default());
        let (backend, listener) = backend(provider.clone(), true).await;
        let (result, headers) = tokio::join!(
            backend.call(request(), TIMEOUT),
            respond(&listener, 401, "Bearer")
        );
        assert!(result.is_err());
        assert!(headers.contains("authorization: bearer explicit\r\n"));
        assert_eq!(provider.credentials.load(Ordering::SeqCst), 0);
        assert!(provider.challenges.lock().unwrap().is_empty());
        no_replay(&listener).await;
    }

    #[tokio::test]
    async fn challenged_replay_is_once_and_never_for_notifications() {
        for (status, challenge) in [
            (401, "Bearer error=\"invalid_token\""),
            (403, "Bearer error=\"insufficient_scope\", scope=\"write\""),
        ] {
            for request in [request(), effectful(false), effectful(true)] {
                let notification = request.get("id").is_none();
                let provider = Arc::new(Provider::default());
                let (backend, listener) = backend(provider.clone(), false).await;
                let (result, ()) = tokio::join!(backend.call(request, TIMEOUT), async {
                    respond(&listener, status, challenge).await;
                    if !notification {
                        respond(&listener, status, challenge).await;
                    }
                });
                // A second rejection is an operational failure without a second challenge.
                assert!(result.is_err());
                let attempts = if notification { 1 } else { 2 };
                assert_eq!(provider.credentials.load(Ordering::SeqCst), attempts);
                let challenges = provider.challenges.lock().unwrap().clone();
                assert_eq!(challenges.len(), 1);
                assert_eq!(challenges[0].status, status);
                assert_eq!(challenges[0].attempt_id.as_deref(), Some("attempt"));
                no_replay(&listener).await;
            }
        }
    }

    #[tokio::test]
    async fn unrelated_and_malformed_403_do_not_trigger_auth_recovery() {
        for challenge in [
            "Basic realm=\"insufficient_scope\"",
            "Bearer error=\"invalid_token\"",
            "Bearer error=\"insufficient_scope\", error=\"invalid_token\"",
            "Bearer error=\"insufficient_scope",
        ] {
            let provider = Arc::new(Provider::default());
            let (backend, listener) = backend(provider.clone(), false).await;
            let (result, _) = tokio::join!(
                backend.call(request(), TIMEOUT),
                respond(&listener, 403, challenge)
            );
            assert!(result.is_err());
            assert!(provider.challenges.lock().unwrap().is_empty());
            no_replay(&listener).await;
        }
    }

    #[tokio::test]
    async fn dropping_dispatch_cancels_provider_futures_natively() {
        for challenge in [false, true] {
            let provider = Arc::new(Provider {
                pending_credential: !challenge,
                pending_challenge: challenge,
                ..Default::default()
            });
            let (backend, listener) = backend(provider.clone(), false).await;
            let mut dispatch = backend.call(request(), TIMEOUT);
            if challenge {
                let mut response = Box::pin(respond(&listener, 401, "Bearer"));
                tokio::select! {
                    _ = &mut dispatch => panic!("pending provider completed"),
                    _ = &mut response => {},
                }
                // Poll once more to enter the challenge future after the socket response.
                while provider.challenges.lock().unwrap().is_empty() {
                    tokio::select! {
                        _ = &mut dispatch => panic!("pending provider completed"),
                        _ = tokio::task::yield_now() => {},
                    }
                }
                provider.dropped.store(false, Ordering::SeqCst);
            } else {
                assert!(futures::poll!(&mut dispatch).is_pending());
            }
            drop(dispatch);
            assert!(provider.dropped.load(Ordering::SeqCst));
            no_replay(&listener).await;
        }
    }

    #[test]
    fn scope_classifier_handles_other_schemes_and_quoted_commas() {
        assert!(insufficient_scope(
            "NewScheme abc==, bEaReR realm=\"a,b\", error=\"insufficient_scope\""
        ));
        assert!(!insufficient_scope("Basic error=\"insufficient_scope\""));
    }

    #[tokio::test]
    async fn provider_deadline_drops_inflight_work_without_auth_reclassification() {
        let provider = Arc::new(Provider {
            pending_credential: true,
            ..Default::default()
        });
        let (backend, listener) = backend(provider.clone(), false).await;
        let error = backend
            .call(request(), Duration::from_millis(10))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "HTTP deadline exceeded");
        assert_eq!(
            error.code(),
            crate::generated::DeliveryDiagnosticCode::DeadlineExceeded
        );
        assert_eq!(error.auth_code(), None);
        assert!(provider.dropped.load(Ordering::SeqCst));
        no_replay(&listener).await;
    }

    #[test]
    fn unknown_binding_never_falls_back_to_a_provider_or_anonymous() {
        let error = from_registration(
            &json!({"authentication":{"type":"unknown"},"transport":{"type":"http","url":"https://example.com/hooks"}}),
            &BackendOptions { auth_provider: Some(Arc::new(Provider::default())), ..Default::default() },
        ).err().unwrap();
        assert_eq!(
            error.auth_code(),
            Some(crate::auth::AuthErrorCode::UnsupportedBinding)
        );
    }

    #[test]
    fn unknown_transport_never_falls_back() {
        let err = from_registration(
            &json!({"transport":{"type":"mystery"}}),
            &BackendOptions::default(),
        )
        .err()
        .unwrap();
        assert_eq!(err.to_string(), "unsupported backend transport");
    }
}
