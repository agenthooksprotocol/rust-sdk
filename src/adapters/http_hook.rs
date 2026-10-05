//! Bridge from the serial interception API to a runtime-neutral HTTP transport.
use crate::{
    client::{Hook, HookError, LocalFuture},
    generated as g,
    transport::{Http, Request},
};
use serde_json::Value;
use std::collections::BTreeMap;
/// The supplied HTTP implementation must enforce deadlines and response bounds.
/// `ReqwestHttp` provides both. Credentials are explicitly supplied by the caller;
/// event reference fields are never inspected for authentication.
pub struct HttpHook<T> {
    pub http: T,
    pub endpoint: String,
    pub authorization: String,
}
impl<T: Http> Hook for HttpHook<T> {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            if self.authorization.trim().is_empty() {
                return Err(HookError("missing HTTP credential".into()));
            }
            let method = request["method"].as_str().unwrap_or("");
            let valid = match method {
                "hooks/intercept" => {
                    g::parse_intercept_request_value(request.clone())
                        .into_value()
                        .is_some()
                        && request["id"] == request["params"]["event"]["id"]
                }
                "hooks/observe" => g::parse_observe_notification_value(request.clone())
                    .into_value()
                    .is_some(),
                "hooks/capabilities" => g::parse_capabilities_request_value(request.clone())
                    .into_value()
                    .is_some(),
                _ => false,
            };
            if !valid {
                return Err(HookError("invalid outgoing protocol message".into()));
            }
            let schema = match method {
                "hooks/intercept" => "intercept-request",
                "hooks/observe" => "observe-notification",
                _ => "capabilities-request",
            };
            crate::canonical::validate(schema, &request).map_err(HookError)?;
            let response = self
                .http
                .send(Request {
                    method: "POST".into(),
                    uri: self.endpoint.clone(),
                    headers: BTreeMap::from([
                        ("content-type".into(), "application/json".into()),
                        ("authorization".into(), self.authorization.clone()),
                    ]),
                    body: serde_json::to_vec(&request).map_err(|e| HookError(e.to_string()))?,
                })
                .await
                .map_err(|e| HookError(e.to_string()))?;
            if method == "hooks/observe" {
                return if matches!(response.status, 202 | 204) && response.body.is_empty() {
                    Ok(Value::Null)
                } else {
                    Err(HookError(format!(
                        "invalid notification acknowledgment (HTTP {}): {}",
                        response.status,
                        String::from_utf8_lossy(&response.body)
                    )))
                };
            }
            if response.status != 200 {
                return Err(HookError(format!(
                    "HTTP {}: {}",
                    response.status,
                    String::from_utf8_lossy(&response.body)
                )));
            }
            let content_types: Vec<_> = response
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .collect();
            if content_types.len() != 1
                || !content_types[0]
                    .1
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/json")
            {
                return Err(HookError("invalid response media type".into()));
            }
            let value: Value =
                serde_json::from_slice(&response.body).map_err(|e| HookError(e.to_string()))?;
            if value["id"] != request["id"] {
                return Err(HookError("response correlation mismatch".into()));
            }
            // Error envelopes remain operational failures even when sent with HTTP 200.
            if value.get("error").is_some() {
                return Err(HookError(format!("protocol error: {}", value["error"])));
            }
            let valid = if method == "hooks/intercept" {
                g::parse_intercept_response_value(value.clone())
                    .into_value()
                    .is_some()
            } else {
                g::parse_capabilities_response_value(value.clone())
                    .into_value()
                    .is_some()
            };
            if !valid {
                return Err(HookError("invalid protocol response".into()));
            }
            let schema = if method == "hooks/intercept" {
                "intercept-response"
            } else {
                "capabilities-response"
            };
            crate::canonical::validate(schema, &value).map_err(HookError)?;
            if method == "hooks/intercept" {
                crate::server::validate_effect_capabilities(&request, &value).map_err(HookError)?;
            }
            Ok(value)
        })
    }
}
