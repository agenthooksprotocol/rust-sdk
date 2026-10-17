//! Request-local registration metadata. Never put resolved values in diagnostics.
use super::registered::BackendOptions;
use super::registered::{AuthPurpose, error};
use crate::client::{HookError, LocalFuture};
use serde_json::Value;
use std::{collections::BTreeMap, time::Instant};

/// Secret source, without a Debug implementation to avoid exposing references.
#[derive(Clone)]
pub enum HeaderSource {
    Environment(String),
    Reference(String),
}
/// Host-owned resolution context; cancellation drops the resolver future.
#[derive(Clone)]
pub struct HeaderContext {
    pub backend_id: String,
    pub destination: String,
    pub purpose: AuthPurpose,
    pub deadline: Instant,
    pub source: HeaderSource,
}
/// Resolves complete values, without adding a Bearer prefix. Errors are redacted.
pub trait HeaderResolver: Send + Sync {
    fn resolve(&self, context: HeaderContext) -> LocalFuture<'_, Result<String, HookError>>;
}
#[derive(Clone)]
pub(crate) enum ConfiguredValue {
    Literal(String),
    Source(HeaderSource),
}
pub(crate) type Headers = BTreeMap<String, ConfiguredValue>;
pub(crate) fn parse(value: Option<&Value>) -> Result<Headers, HookError> {
    let mut headers = BTreeMap::new();
    let Some(value) = value else {
        return Ok(headers);
    };
    let object = value
        .as_object()
        .ok_or_else(|| error("invalid HTTP headers"))?;
    for (name, value) in object {
        let name = name.to_ascii_lowercase();
        http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| error("invalid HTTP header name"))?;
        let configured = match value {
            Value::String(s) => {
                http::HeaderValue::from_str(s).map_err(|_| error("invalid HTTP header value"))?;
                ConfiguredValue::Literal(s.clone())
            }
            Value::Object(source)
                if source.contains_key("valueEnv") != source.contains_key("valueRef") =>
            {
                if let Some(Value::String(s)) = source.get("valueEnv") {
                    if s.is_empty()
                        || !s.bytes().enumerate().all(|(i, b)| {
                            b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                        })
                    {
                        return Err(error("invalid HTTP header source"));
                    }
                    ConfiguredValue::Source(HeaderSource::Environment(s.clone()))
                } else if let Some(Value::String(s)) = source.get("valueRef") {
                    if s.is_empty() {
                        return Err(error("invalid HTTP header source"));
                    }
                    ConfiguredValue::Source(HeaderSource::Reference(s.clone()))
                } else {
                    return Err(error("invalid HTTP header source"));
                }
            }
            _ => return Err(error("invalid HTTP header value")),
        };
        headers.insert(name, configured);
    }
    Ok(headers)
}
pub(crate) async fn resolve(
    headers: &Headers,
    backend_id: &str,
    destination: &str,
    deadline: Instant,
    purpose: AuthPurpose,
    options: &BackendOptions,
) -> Result<BTreeMap<String, String>, HookError> {
    let mut result = BTreeMap::new();
    for (name, configured) in headers {
        let value = match configured {
            ConfiguredValue::Literal(value) => value.clone(),
            ConfiguredValue::Source(source) => {
                if let Some(resolver) = &options.header_resolver {
                    resolver
                        .resolve(HeaderContext {
                            backend_id: backend_id.into(),
                            destination: destination.into(),
                            purpose,
                            deadline,
                            source: source.clone(),
                        })
                        .await
                        .map_err(|_| error("HTTP header resolution failed"))?
                } else {
                    options
                        .resolve_secret(source)
                        .ok_or_else(|| error("HTTP header source unavailable"))?
                }
            }
        };
        http::HeaderValue::from_str(&value).map_err(|_| error("invalid HTTP header value"))?;
        result.insert(name.clone(), value);
    }
    Ok(result)
}
