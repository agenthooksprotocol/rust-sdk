//! Owned, lazy transports for canonical registration backends.
//!
//! No runtime or worker thread is created. Call `shutdown` before dropping the
//! caller's runtime to deterministically reap children after cancellation.
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
    /// Explicit bearer references. `tokenEnv` authorizes an environment lookup.
    pub credentials: BTreeMap<String, String>,
    /// Retained for compatibility. Absent authentication permits anonymous delivery;
    /// configured authentication always fails closed if its credential is unavailable.
    pub allow_anonymous_http: bool,
    pub allow_loopback_http: bool,
    pub max_frame_bytes: usize,
}
impl Default for BackendOptions {
    fn default() -> Self {
        Self {
            auth_provider: None,
            credentials: BTreeMap::new(),
            allow_anonymous_http: false,
            allow_loopback_http: false,
            max_frame_bytes: 1024 * 1024,
        }
    }
}
fn error(message: &str) -> HookError {
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
    HookError(message.into()).classified(code)
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
    let auth = backend.get("authentication");
    if let Some(auth) = auth {
        match auth["type"].as_str() {
            Some("bearer") => {}
            Some("oauth") if options.auth_provider.is_some() => {
                if !matches!(
                    auth["flow"].as_str(),
                    Some("authorization_code_pkce" | "client_credentials")
                ) {
                    return Err(error("unsupported OAuth flow"));
                }
            }
            _ => return Err(error("unsupported backend authentication")),
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
                            .and_then(|key| options.credentials.get(key))
                            .cloned(),
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
                            .and_then(|key| std::env::var(key).ok()),
                        _ => {
                            return Err(error(
                                "bearer authentication requires exactly one tokenRef or tokenEnv",
                            ));
                        }
                    }
                    .filter(|token| {
                        !token.is_empty() && token.bytes().all(|b| b.is_ascii_graphic())
                    })
                    .ok_or_else(|| error("bearer credential unavailable or invalid"))?;
                        Some(format!("Bearer {token}"))
                    }
                }
            };
            #[cfg(feature = "reqwest")]
            {
                Ok(Arc::new(HttpBackend {
                    endpoint: endpoint.into(),
                    backend_id: backend["id"].as_str().unwrap_or("").into(),
                    authentication: auth.cloned(),
                    authorization,
                    options: options.clone(),
                    closed: AtomicBool::new(false),
                }))
            }
            #[cfg(not(feature = "reqwest"))]
            {
                let _ = authorization;
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
            #[cfg(feature = "tokio-process")]
            {
                Ok(Arc::new(StdioBackend {
                    command: command.into(),
                    args,
                    cwd,
                    per_event,
                    limit: options.max_frame_bytes,
                    closed: AtomicBool::new(false),
                    process: std::sync::Mutex::new(None),
                    gate: tokio::sync::Mutex::new(()),
                }))
            }
            #[cfg(not(feature = "tokio-process"))]
            {
                let _ = (command, args, cwd, per_event);
                Err(error("stdio backend requires the tokio-process feature"))
            }
        }
        _ => Err(error("unsupported backend transport")),
    }
}
#[cfg(any(feature = "reqwest", feature = "tokio-process"))]
fn validate_request(request: &Value) -> Result<bool, HookError> {
    let (schema, notification) = match request["method"].as_str() {
        Some("hooks/intercept") => ("intercept-request", false),
        Some("hooks/capabilities") => ("capabilities-request", false),
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
    crate::canonical::validate(
        if intercept {
            "intercept-response"
        } else {
            "capabilities-response"
        },
        &value,
    )
    .map_err(|_| error("invalid protocol response"))?;
    if intercept {
        crate::server::validate_effect_capabilities(request, &value)
            .map_err(|_| error("unsupported response effects"))?;
    }
    Ok(value)
}
#[cfg(feature = "reqwest")]
struct HttpBackend {
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
                let client = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|_| error("HTTP client initialization failed"))?;
                let mut retry = false;
                let mut response = loop {
                    let credential = if let Some(provider) = &self.options.auth_provider {
                        provider
                            .credential(context.clone())
                            .await
                            .map_err(|_| error("authentication provider failed"))?
                    } else {
                        None
                    };
                    if self.options.auth_provider.is_some()
                        && credential.is_none()
                        && self.authentication.is_some()
                    {
                        return Err(error("configured credential unavailable"));
                    }
                    let mut outgoing = client
                        .post(&self.endpoint)
                        .header("content-type", "application/json")
                        .body(body.clone());
                    if let Some(credential) = &credential {
                        if credential.token.is_empty()
                            || !credential.token.bytes().all(|b| b.is_ascii_graphic())
                        {
                            return Err(error("invalid bearer credential"));
                        }
                        outgoing = outgoing.bearer_auth(&credential.token);
                    } else if let Some(auth) = &self.authorization {
                        outgoing = outgoing.header("authorization", auth);
                    }
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
                    if response.status().as_u16() == 401
                        && let Some(provider) = &self.options.auth_provider
                    {
                        // Only authentication metadata is exposed, never response bodies.
                        let headers = response
                            .headers()
                            .get_all(reqwest::header::WWW_AUTHENTICATE)
                            .iter()
                            .filter_map(|v| v.to_str().ok())
                            .collect::<Vec<_>>()
                            .join(", ");
                        provider
                            .challenge(
                                context.clone(),
                                AuthChallenge {
                                    status: 401,
                                    headers: BTreeMap::from([("www-authenticate".into(), headers)]),
                                    attempt_id: credential.as_ref().map(|c| c.attempt_id.clone()),
                                },
                            )
                            .await
                            .map_err(|_| error("authentication challenge failed"))?;
                        // Auth recovery does not authorize replaying effectful deliveries.
                        if !retry && request["method"] == "hooks/capabilities" {
                            retry = true;
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
#[cfg(feature = "tokio-process")]
struct StdioBackend {
    command: String,
    args: Vec<String>,
    cwd: Option<String>,
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
