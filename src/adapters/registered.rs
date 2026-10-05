//! Owned, lazy transports for canonical registration backends.
//!
//! No runtime or worker thread is created. Call `shutdown` before dropping the
//! caller's runtime to deterministically reap children after cancellation.
use crate::client::{HookError, LocalFuture};
use serde_json::Value;
#[cfg(any(feature = "reqwest", feature = "tokio-process"))]
use std::cell::Cell;
use std::{collections::BTreeMap, rc::Rc, time::Duration};

/// A backend owns its transport and can be shared across subscriptions.
pub trait ManagedBackend {
    fn call(&self, request: Value, timeout: Duration) -> LocalFuture<'_, Result<Value, HookError>>;
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>>;
}
#[derive(Clone)]
pub struct BackendOptions {
    /// Explicit bearer references. `tokenEnv` authorizes an environment lookup.
    pub credentials: BTreeMap<String, String>,
    pub allow_anonymous_http: bool,
    pub allow_loopback_http: bool,
    pub max_frame_bytes: usize,
}
impl Default for BackendOptions {
    fn default() -> Self {
        Self {
            credentials: BTreeMap::new(),
            allow_anonymous_http: false,
            allow_loopback_http: false,
            max_frame_bytes: 1024 * 1024,
        }
    }
}
fn error(message: &str) -> HookError {
    HookError(message.into())
}

/// Validate configuration without opening sockets or spawning children.
/// Unsupported authentication is never downgraded to bearer or anonymous access.
pub fn from_registration(
    backend: &Value,
    options: &BackendOptions,
) -> Result<Rc<dyn ManagedBackend>, HookError> {
    if options.max_frame_bytes == 0 {
        return Err(error("frame limit must be positive"));
    }
    let transport = &backend["transport"];
    let auth = backend.get("authentication");
    if let Some(auth) = auth {
        if auth["type"] != "bearer" {
            return Err(error(
                "unsupported backend authentication (only bearer is implemented)",
            ));
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
            let authorization = match auth {
                None if options.allow_anonymous_http => None,
                None => {
                    return Err(error(
                        "HTTP authentication required; anonymous access requires explicit opt-in",
                    ));
                }
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
            };
            #[cfg(feature = "reqwest")]
            {
                Ok(Rc::new(HttpBackend {
                    endpoint: endpoint.into(),
                    authorization,
                    options: options.clone(),
                    closed: Cell::new(false),
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
                Ok(Rc::new(StdioBackend {
                    command: command.into(),
                    args,
                    cwd,
                    per_event,
                    limit: options.max_frame_bytes,
                    closed: Cell::new(false),
                    process: std::cell::RefCell::new(None),
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
    crate::canonical::validate(schema, request).map_err(HookError)?;
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
    if value.get("error").is_some() {
        return Err(error("backend returned a protocol error"));
    }
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
    endpoint: String,
    authorization: Option<String>,
    options: BackendOptions,
    closed: Cell<bool>,
}
#[cfg(feature = "reqwest")]
impl ManagedBackend for HttpBackend {
    fn call(&self, request: Value, timeout: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            if self.closed.get() {
                return Err(error("backend is shut down"));
            }
            let notification = validate_request(&request)?;
            let body = serde_json::to_vec(&request).map_err(|_| error("invalid request"))?;
            if body.len() > self.options.max_frame_bytes {
                return Err(error("request exceeds frame limit"));
            }
            let remaining = timeout
                .checked_sub(started.elapsed())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| error("HTTP deadline exceeded"))?;
            let client = reqwest::Client::builder()
                .timeout(remaining)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| error("HTTP client initialization failed"))?;
            let mut outgoing = client
                .post(&self.endpoint)
                .header("content-type", "application/json")
                .body(body);
            if let Some(auth) = &self.authorization {
                outgoing = outgoing.header("authorization", auth);
            }
            let mut response = outgoing
                .send()
                .await
                .map_err(|_| error("HTTP transport failed or deadline exceeded"))?;
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
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| error("HTTP body failed or deadline exceeded"))?
            {
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
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async {
            self.closed.set(true);
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
    closed: Cell<bool>,
    process: std::cell::RefCell<Option<Rc<super::process::Process>>>,
    gate: tokio::sync::Mutex<()>,
}
#[cfg(feature = "tokio-process")]
impl StdioBackend {
    async fn reap(&self) -> Result<(), HookError> {
        let process = self.process.borrow().clone();
        if let Some(process) = process {
            process
                .shutdown()
                .await
                .map_err(|_| error("subprocess shutdown failed"))?;
            self.process.borrow_mut().take();
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
                if self.closed.get() {
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
                if self.process.borrow().is_none() {
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
                    *self.process.borrow_mut() = Some(Rc::new(process));
                }
                let process = self
                    .process
                    .borrow()
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
            self.closed.set(true);
            let _gate = self.gate.lock().await;
            self.reap().await
        })
    }
}
