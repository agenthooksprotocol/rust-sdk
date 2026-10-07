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
            "hooks/intercept" => g::parse_intercept_response_value(value.clone())
                .into_value()
                .is_some(),
            _ => g::parse_capabilities_response_value(value.clone())
                .into_value()
                .is_some(),
        };
        let schema = if method == "hooks/intercept" {
            "intercept-response"
        } else {
            "capabilities-response"
        };
        if !valid || crate::canonical::validate(schema, &value).is_err() || value["id"] != raw["id"]
        {
            return failure(500, "invalid or uncorrelated response");
        }
        if method == "hooks/intercept" && validate_effect_capabilities(&raw, &value).is_err() {
            return failure(500, "response exceeds advertised capabilities");
        }
        response(200, serde_json::to_vec(&value).expect("JSON value"))
    }
}

/// Check effect grants independently of event-specific application or tool execution.
/// Call after canonical message validation. Unknown effects never grant authority.
/// This does not resolve selected elicitation bodies or apply their semantic effects.
pub fn validate_effect_capabilities(
    request: &serde_json::Value,
    response: &serde_json::Value,
) -> Result<(), String> {
    use serde_json::Value;
    fn contains(array: &Value, value: &Value) -> bool {
        array.as_array().is_some_and(|items| items.contains(value))
    }
    let caps = &request["params"]["capabilities"];
    let effects = response["result"]["effects"]
        .as_array()
        .ok_or("missing effects")?;
    let event = &request["params"]["event"];
    if !effects.is_empty()
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
    for effect in effects {
        if !contains(&caps["effects"], &effect["type"]) {
            return Err("unadvertised effect".into());
        }
        match effect["type"].as_str().ok_or("missing effect type")? {
            "modify" => {
                let target = effect["target"].as_str().ok_or("missing modify target")?;
                let operation = effect["operation"]
                    .as_str()
                    .ok_or("missing modify operation")?;
                if !matches!(operation, "replace" | "merge")
                    || caps["modify"][target][operation] != true
                {
                    return Err("unadvertised modification".into());
                }
            }
            "flow" => {
                if !contains(&caps["flow"]["operations"], &effect["operation"]) {
                    return Err("unadvertised flow operation".into());
                }
                match effect["operation"].as_str() {
                    Some("stop") => {}
                    Some("continue") => {
                        let remaining = budget(&caps["flow"]["remainingContinuations"])?;
                        let count = budget(&caps["flow"]["continuationCount"])?;
                        let max = caps["flow"]
                            .get("maxContinuations")
                            .map(budget)
                            .transpose()?;
                        // Instructions coalesce into one follow-up step; an earlier
                        // interceptor may already have reserved that allowance.
                        if !continuation_already_pending
                            && (remaining == 0 || max.is_some_and(|max| count >= max))
                        {
                            return Err("continuation budget exhausted".into());
                        }
                    }
                    _ => return Err("unknown flow operation".into()),
                }
            }
            "inject" => {
                if effect["target"] != "context"
                    || effect["operation"] != "append"
                    || caps["inject"]["context"]["append"] != true
                    || !contains(
                        &caps["inject"]["context"]["deliverAt"],
                        &effect["deliverAt"],
                    )
                {
                    return Err("unadvertised context injection".into());
                }
            }
            "allow" | "ask" | "deny" | "return" | "message" => {}
            _ => return Err("unknown effect".into()),
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
    use serde_json::Value;
    fn selected(
        result: &mut ResolvedContent,
        context: &ContentContext<'_>,
        item: &Value,
        pointer: String,
    ) -> Result<(), UploadError> {
        if let Some(bytes) = context.resolve_selected(item)? {
            result.bodies.insert(pointer, bytes);
        }
        Ok(())
    }
    fn array(
        result: &mut ResolvedContent,
        context: &ContentContext<'_>,
        event: &Value,
        path: &str,
    ) -> Result<(), UploadError> {
        if let Some(items) = event.pointer(path).and_then(Value::as_array) {
            for (index, item) in items.iter().enumerate() {
                selected(
                    result,
                    context,
                    item,
                    format!("/params/event{path}/{index}"),
                )?;
            }
        }
        Ok(())
    }
    let mut result = ResolvedContent::default();
    if !matches!(
        request["method"].as_str(),
        Some("hooks/intercept" | "hooks/observe")
    ) {
        return Ok(result);
    }
    let event = &request["params"]["event"];
    let kind = event["type"].as_str().ok_or(UploadError::Descriptor)?;
    if matches!(
        kind,
        "session.start"
            | "session.end"
            | "tool.before"
            | "tool.after"
            | "config.change.before"
            | "config.change.after"
            | "turn.start"
            | "turn.finish.before"
            | "turn.end"
            | "turn.progress"
            | "model.request.before"
            | "model.response.after"
            | "model.error"
            | "model.switch.before"
            | "model.switch.after"
            | "tool.permission.request"
            | "tool.permission.resolved"
            | "tool.progress"
            | "tool.batch.after"
            | "context.compact.before"
            | "context.compact.after"
            | "task.change.before"
            | "task.change.after"
            | "workspace.change.before"
            | "workspace.change.after"
            | "file.changed"
            | "user.attention"
            | "user.elicitation.request"
            | "user.elicitation.result"
            | "user.message.inbound"
            | "user.message.outbound"
            | "hook.failure"
    ) {
        array(&mut result, context, event, "/items")?;
    }
    let item_path = match kind {
        "turn.progress" => Some("/delta"),
        "tool.progress" => Some("/partialOutput"),
        "context.compact.before" => Some("/instructions"),
        "context.compact.after" => Some("/summary"),
        "user.elicitation.request" => Some("/elicitation/request"),
        "user.elicitation.result" => Some("/elicitation/result"),
        _ => None,
    };
    if let Some(path) = item_path
        && let Some(item) = event.pointer(path)
    {
        selected(&mut result, context, item, format!("/params/event{path}"))?;
    }
    match kind {
        "user.attention" => {
            array(&mut result, context, event, "/attention/message")?;
            array(&mut result, context, event, "/attention/title")?;
        }
        "user.message.inbound" => array(&mut result, context, event, "/message/text")?,
        "user.message.outbound" => array(&mut result, context, event, "/message/payload")?,
        "file.changed" => {
            if let Some(changes) = event["changes"].as_array() {
                for (index, change) in changes.iter().enumerate() {
                    for field in ["before", "after"] {
                        if let Some(reference) = change.get(field) {
                            result.bodies.insert(
                                format!("/params/event/changes/{index}/{field}"),
                                context.resolve(reference)?,
                            );
                        }
                    }
                }
            }
        }
        _ => {}
    }
    Ok(result)
}
