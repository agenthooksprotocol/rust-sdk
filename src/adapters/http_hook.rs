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
fn protocol_error(message: &str) -> HookError {
    HookError(message.into()).classified(g::DeliveryDiagnosticCode::ProtocolRejection)
}
impl<T: Http + Send + Sync> Hook for HttpHook<T> {
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
                return Err(protocol_error("invalid outgoing protocol message"));
            }
            let schema = match method {
                "hooks/intercept" => "intercept-request",
                "hooks/observe" => "observe-notification",
                _ => "capabilities-request",
            };
            crate::canonical::validate(schema, &request)
                .map_err(|_| protocol_error("invalid protocol message"))?;
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
                .map_err(|_| HookError("HTTP transport failed".into()))?;
            if method == "hooks/observe" {
                return if matches!(response.status, 202 | 204) && response.body.is_empty() {
                    Ok(Value::Null)
                } else {
                    Err(protocol_error("invalid notification acknowledgment"))
                };
            }
            if response.status != 200 {
                return Err(HookError(format!(
                    "unexpected HTTP response status {}",
                    response.status
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
                return Err(protocol_error("invalid response media type"));
            }
            let value: Value = serde_json::from_slice(&response.body)
                .map_err(|_| protocol_error("invalid protocol JSON response"))?;
            if value["id"] != request["id"] {
                return Err(protocol_error("response correlation mismatch"));
            }
            crate::client::check_rpc_error(&value, &request["id"])?;
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
                return Err(protocol_error("invalid protocol response"));
            }
            let schema = if method == "hooks/intercept" {
                "intercept-response"
            } else {
                "capabilities-response"
            };
            crate::canonical::validate(schema, &value)
                .map_err(|_| protocol_error("invalid protocol message"))?;
            if method == "hooks/intercept" {
                crate::server::validate_effect_capabilities(&request, &value)
                    .map_err(|_| protocol_error("invalid protocol message"))?;
            }
            Ok(value)
        })
    }
}
