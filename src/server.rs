//! One validated dispatcher shared by HTTP and line framing adapters.
use crate::{
    content::{AuthorizedScope, ContentContext, ContentStore, UploadError},
    generated as g,
    transport::{Request, Response},
};
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};
/// Identity supplied by credential verification, never event reference fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub subject: String,
}
/// Only transport credentials are supplied, not untrusted protocol payloads.
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, authorization: Option<&str>) -> Result<Principal, String>;
}
#[derive(Debug)]
pub enum Incoming {
    Capabilities(Box<g::CapabilitiesRequest>),
    Intercept(Box<g::InterceptRequest>),
    Observe(Box<g::ObserveNotification>),
}
#[derive(Debug)]
pub enum Outgoing {
    Capabilities(Box<g::CapabilitiesResponse>),
    Intercept(Box<g::InterceptResponse>),
    Observed,
}
pub type HandlerFuture<'a> = Pin<Box<dyn Future<Output = Result<Outgoing, String>> + Send + 'a>>;
pub trait Handler: Send + Sync {
    fn handle(&self, principal: Principal, message: Incoming) -> HandlerFuture<'_>;
    /// Called only after every selected body has verified. Override to consume
    /// immutable bytes without resolving references again. The default preserves
    /// existing handlers while still enforcing the resolution gate.
    fn handle_verified(
        &self,
        principal: Principal,
        message: Incoming,
        _content: ResolvedContent,
    ) -> HandlerFuture<'_> {
        self.handle(principal, message)
    }
}
/// Verified immutable bodies, keyed by their exact JSON pointer in the request.
/// Metadata/omit items are intentionally absent. Logical IDs may repeat across
/// fields, so pointers rather than IDs prevent accidental collisions.
#[derive(Clone, Debug, Default)]
pub struct ResolvedContent {
    bodies: BTreeMap<String, Arc<[u8]>>,
}
impl ResolvedContent {
    pub fn get(&self, pointer: &str) -> Option<&Arc<[u8]>> {
        self.bodies.get(pointer)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Arc<[u8]>)> {
        self.bodies
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes))
    }
    pub fn len(&self) -> usize {
        self.bodies.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bodies.is_empty()
    }
}
type Prepared = (
    Principal,
    Incoming,
    serde_json::Value,
    Option<ResolvedContent>,
);

pub struct Server<H, A> {
    pub handler: H,
    pub authenticator: A,
    pub max_body_bytes: usize,
}
fn response(status: u16, body: Vec<u8>) -> Response {
    Response {
        status,
        body,
        headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
    }
}
fn failure(status: u16, message: &str) -> Response {
    response(
        status,
        serde_json::to_vec(&serde_json::json!({"error":message})).expect("JSON string"),
    )
}
fn header<'a>(request: &'a Request, name: &str) -> Result<Option<&'a str>, ()> {
    let mut matches = request
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name));
    let first = matches.next().map(|(_, v)| v.as_str());
    if matches.next().is_some() {
        Err(())
    } else {
        Ok(first)
    }
}
impl<H: Handler, A: Authenticator> Server<H, A> {
    pub async fn handle(&self, request: Request) -> Response {
        self.dispatch(self.prepare(request, None)).await
    }
    /// Opt into automatic verification. Scope comes exclusively from the
    /// authenticated principal, never principalRef/session/source or body refs.
    /// Resolution is synchronous; the returned future does not borrow the store.
    pub fn handle_with_content<'a>(
        &'a self,
        request: Request,
        store: &dyn ContentStore,
    ) -> impl Future<Output = Response> + Send + 'a + use<'a, H, A> {
        let prepared = self.prepare(request, Some(store));
        self.dispatch(prepared)
    }
    fn prepare(
        &self,
        request: Request,
        store: Option<&dyn ContentStore>,
    ) -> Result<Prepared, Response> {
        if request.method != "POST" {
            return Err(failure(405, "POST required"));
        }
        if request.body.len() > self.max_body_bytes {
            return Err(failure(413, "body too large"));
        }
        let authorization = match header(&request, "authorization") {
            Ok(v) => v,
            Err(_) => return Err(failure(401, "ambiguous credentials")),
        };
        let principal = match self.authenticator.authenticate(authorization) {
            Ok(p) => p,
            Err(_) => return Err(failure(401, "authentication failed")),
        };
        if !matches!(header(&request, "content-type"), Ok(Some(v)) if v.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(failure(415, "application/json required"));
        }
        let raw: serde_json::Value = match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(_) => return Err(failure(400, "invalid JSON")),
        };
        let method = raw["method"].as_str().unwrap_or("");
        let schema = match method {
            "hooks/intercept" => "intercept-request",
            "hooks/observe" => "observe-notification",
            "hooks/capabilities" => "capabilities-request",
            _ => return Err(failure(400, "unsupported method")),
        };
        if crate::canonical::validate(schema, &raw).is_err() {
            return Err(failure(400, "invalid canonical message"));
        }
        let incoming = match method {
            "hooks/capabilities" => g::parse_capabilities_request_value(raw.clone())
                .into_value()
                .map(|value| Incoming::Capabilities(Box::new(value))),
            "hooks/intercept" => {
                if raw["id"] != raw["params"]["event"]["id"] {
                    return Err(failure(400, "event correlation mismatch"));
                }
                g::parse_intercept_request_value(raw.clone())
                    .into_value()
                    .map(|value| Incoming::Intercept(Box::new(value)))
            }
            "hooks/observe" => g::parse_observe_notification_value(raw.clone())
                .into_value()
                .map(|value| Incoming::Observe(Box::new(value))),
            _ => return Err(failure(400, "unsupported method")),
        };
        let Some(incoming) = incoming else {
            return Err(failure(400, "invalid protocol message"));
        };

        let content = if let Some(store) = store {
            let context = ContentContext {
                store,
                scope: AuthorizedScope::new(principal.subject.clone()),
            };
            Some(
                resolve_event_content(&raw, &context)
                    .map_err(|_| failure(400, "selected content unavailable or invalid"))?,
            )
        } else {
            None
        };
        Ok((principal, incoming, raw, content))
    }
    async fn dispatch(&self, prepared: Result<Prepared, Response>) -> Response {
        let (principal, incoming, raw, content) = match prepared {
            Ok(prepared) => prepared,
            Err(response) => return response,
        };
        let method = raw["method"].as_str().unwrap_or("");
        let future = match content {
            Some(content) => self.handler.handle_verified(principal, incoming, content),
            None => self.handler.handle(principal, incoming),
        };
        let outgoing = match future.await {
            Ok(v) => v,
            Err(_) => return failure(500, "handler failed"),
        };
        let value = match (method, outgoing) {
            ("hooks/observe", Outgoing::Observed) => return response(204, Vec::new()),
            ("hooks/intercept", Outgoing::Intercept(v)) => serde_json::to_value(v),
            ("hooks/capabilities", Outgoing::Capabilities(v)) => serde_json::to_value(v),
            _ => return failure(500, "response kind mismatch"),
        };
        let Ok(value) = value else {
            return failure(500, "response serialization failed");
        };
        let valid = match method {
            "hooks/intercept" => contextual_response(&raw, &value).is_ok(),
            _ => g::parse_capabilities_response_value(value.clone())
                .into_value()
                .is_some(),
        };
        let schema = if method == "hooks/intercept" {
            "intercept-response"
        } else {
            "capabilities-response"
        };
        if !valid
            || (method != "hooks/intercept" && crate::canonical::validate(schema, &value).is_err())
            || value["id"] != raw["id"]
        {
            return failure(500, "invalid or uncorrelated response");
        }
        if method == "hooks/intercept" && validate_effect_capabilities(&raw, &value).is_err() {
            return failure(500, "response exceeds advertised capabilities");
        }
        response(200, serde_json::to_vec(&value).expect("JSON value"))
    }
}

/// Parse contextually and retain canonical checks without inspecting unknown effects.
pub(crate) fn contextual_response(
    request: &serde_json::Value,
    response: &serde_json::Value,
) -> Result<g::ContextualResponse, String> {
    let event_type = request["params"]["event"]["type"]
        .as_str()
        .ok_or("missing originating event type")?;
    crate::canonical::validate("intercept-response", response)?;
    crate::protocol::parse(event_type, response).map_err(|e| e.to_string())
}

pub(crate) fn authority_name(kind: &crate::protocol::Kind<'_>) -> Option<&'static str> {
    use crate::protocol::Kind;
    Some(match kind {
        Kind::Deny => "deny",
        Kind::Allow => "allow",
        Kind::Ask => "ask",
        Kind::Modify { .. } => "modify",
        Kind::Message(_) => "message",
        Kind::Inject(_) => "inject",
        Kind::ReturnTool(_)
        | Kind::ReturnMessages(_)
        | Kind::ReturnText(_)
        | Kind::ReturnForm(_) => "return",
        Kind::Stop | Kind::Continue(_) => "flow",
        Kind::Unknown => return None,
    })
}

/// Check effect grants independently of event-specific application or tool execution.
/// Call after canonical message validation. Unknown effects never grant authority.
/// This does not resolve selected elicitation bodies or apply their semantic effects.
pub fn validate_effect_capabilities(
    request: &serde_json::Value,
    response: &serde_json::Value,
) -> Result<(), String> {
    use crate::protocol::{Kind, Operation};
    use serde_json::Value;
    fn contains(array: &Value, value: &str) -> bool {
        array
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(value)))
    }
    let caps = &request["params"]["capabilities"];
    let typed = contextual_response(request, response)?;
    let effects = crate::protocol::effects(&typed).map_err(|e| e.to_string())?;
    let event = &request["params"]["event"];
    if effects
        .iter()
        .any(|effect| !matches!(effect.kind, Kind::Unknown))
        && matches!(
            event["type"].as_str(),
            Some("user.elicitation.request" | "user.elicitation.result")
        )
    {
        let mode = event["elicitation"]["mode"]
            .as_str()
            .ok_or("missing elicitation mode")?;
        if !matches!(mode, "form" | "url") || !caps["elicitation"][mode].is_object() {
            return Err("unadvertised elicitation mode".into());
        }
    }
    // Canonical JSON integers include 1.0 and 1e0. The generated Integer
    // guard checks integrality and the safe range before numeric conversion.
    fn budget(value: &Value) -> Result<u64, String> {
        let integer = value
            .as_number()
            .cloned()
            .and_then(g::Integer::new)
            .ok_or("invalid continuation budget integer")?;
        let number = integer
            .as_number()
            .as_f64()
            .ok_or("invalid continuation budget integer")?;
        if number < 0.0 {
            return Err("negative continuation budget".into());
        }
        Ok(number as u64)
    }
    let continuation_already_pending = request["params"]["state"]["flow"] == "continue";
    for effect in &effects {
        let name = authority_name(&effect.kind).ok_or("unknown effect")?;
        if !contains(&caps["effects"], name) {
            return Err("unadvertised effect".into());
        }
        match &effect.kind {
            Kind::Modify {
                target, operation, ..
            } => {
                let operation = match operation {
                    Operation::Replace => "replace",
                    Operation::Merge => "merge",
                };
                if caps["modify"][*target][operation] != true {
                    return Err("unadvertised modification".into());
                }
            }
            Kind::Stop | Kind::Continue(_) => {
                let operation = if matches!(effect.kind, Kind::Continue(_)) {
                    "continue"
                } else {
                    "stop"
                };
                if !contains(&caps["flow"]["operations"], operation) {
                    return Err("unadvertised flow operation".into());
                }
                if matches!(effect.kind, Kind::Continue(_)) {
                    let remaining = budget(&caps["flow"]["remainingContinuations"])?;
                    let count = budget(&caps["flow"]["continuationCount"])?;
                    let max = caps["flow"]
                        .get("maxContinuations")
                        .map(budget)
                        .transpose()?;
                    // Coalesce continuation requests into one reserved follow-up.
                    if !continuation_already_pending
                        && (remaining == 0 || max.is_some_and(|max| count >= max))
                    {
                        return Err("continuation budget exhausted".into());
                    }
                }
            }
            Kind::Inject(injection) => {
                if caps["inject"]["context"]["append"] != true
                    || !contains(
                        &caps["inject"]["context"]["deliverAt"],
                        injection.deliver_at.as_str(),
                    )
                {
                    return Err("unadvertised context injection".into());
                }
            }
            Kind::Deny
            | Kind::Allow
            | Kind::Ask
            | Kind::Message(_)
            | Kind::ReturnTool(_)
            | Kind::ReturnMessages(_)
            | Kind::ReturnText(_)
            | Kind::ReturnForm(_)
            | Kind::Unknown => {}
        }
    }

    Ok(())
}

// Keep traversal tied to canonical event fields. Never recursively inspect tool
// input/output, extension objects, task data, or another open JSON payload.
fn resolve_event_content(
    request: &serde_json::Value,
    context: &ContentContext<'_>,
) -> Result<ResolvedContent, UploadError> {
    let mut result = ResolvedContent::default();
    if !matches!(
        request["method"].as_str(),
        Some("hooks/intercept" | "hooks/observe")
    ) {
        return Ok(result);
    }
    let event = &request["params"]["event"];
    for path in crate::hooks_content::locations(event) {
        let item = event.pointer(&path).ok_or(UploadError::Descriptor)?;
        // Inline text belongs to the event, not an upload or resolver cache.
        if item["kind"] == "attachment"
            && let Some(bytes) = context.resolve_selected(item)?
        {
            result.bodies.insert(format!("/params/event{path}"), bytes);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod contextual_response_tests {
    use super::*;
    use serde_json::{Value, json};

    fn request() -> Value {
        json!({"params":{"event":{"type":"tool.before"},"capabilities":{
            "effects":["deny","modify"],"modify":{"input":{"replace":true}}
        }}})
    }

    fn reply(effects: Value) -> Value {
        json!({"jsonrpc":"2.0","id":"rpc","result":{
            "protocolVersion":"draft","effects":effects
        }})
    }

    #[test]
    fn absent_effects_are_empty_but_null_is_invalid() {
        let mut response = reply(json!([]));
        response["result"]
            .as_object_mut()
            .unwrap()
            .remove("effects");
        assert!(validate_effect_capabilities(&request(), &response).is_ok());
        assert!(response["result"].get("effects").is_none());
        assert!(validate_effect_capabilities(&request(), &reply(Value::Null)).is_err());
    }

    #[test]
    fn unknown_effects_are_preserved_by_codec_but_rejected_by_canonical_boundary() {
        let response = reply(json!([{
            "type":"vendor.future", "effects":[{"type":"deny"}],
            "target":"input", "operation":"replace", "value":{"type":"modify"}
        }]));
        let original = response.clone();
        let typed = crate::protocol::parse("tool.before", &response).unwrap();
        assert!(
            crate::protocol::effects(&typed)
                .unwrap()
                .iter()
                .all(|effect| matches!(effect.kind, crate::protocol::Kind::Unknown))
        );
        assert!(contextual_response(&request(), &response).is_err());
        assert!(validate_effect_capabilities(&request(), &response).is_err());
        assert_eq!(response, original);

        let mut extras = reply(json!([]));
        extras["result"]["extensions"] = json!({"vendor.future":{"type":"deny"}});
        extras["result"]["vendor.future"] = json!({"effects":[{"type":"modify"}]});
        let original = extras.clone();
        assert!(validate_effect_capabilities(&request(), &extras).is_ok());
        assert_eq!(extras, original);
    }

    #[test]
    fn known_effects_require_contextual_shape_and_actual_grants() {
        let effect = json!({"type":"modify","target":"input","operation":"replace","value":{}});
        assert!(validate_effect_capabilities(&request(), &reply(json!([effect]))).is_ok());
        let mut ungranted = request();
        ungranted["params"]["capabilities"]["modify"]["input"]["replace"] = json!(false);
        assert!(validate_effect_capabilities(&ungranted, &reply(json!([effect]))).is_err());
        let wrong_target =
            json!({"type":"modify","target":"output","operation":"replace","value":{}});
        assert!(contextual_response(&request(), &reply(json!([wrong_target]))).is_err());
        let malformed = json!({"type":"modify","target":"input","operation":"replace"});
        assert!(contextual_response(&request(), &reply(json!([malformed]))).is_err());
    }
}
