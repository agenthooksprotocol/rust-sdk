//! Runtime-neutral, canonical full-event transactions. No application execution occurs here.
use crate::client::*;
use crate::client::{ProgressGuard, error, has, subset, validate_request};
use crate::content::ContentContext;
use crate::elicitation::Exchange;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{future::IntoFuture, task::Poll, time::Instant};

#[must_use = "a boundary does nothing until awaited"]
pub struct EventBoundary<'a, T> {
    client: &'a Client,
    name: Option<&'static str>,
    event: T,
    initial: Decision,
    initial_candidate: Option<Value>,
    state_present: bool,
    capabilities: Option<Value>,
    gates_passed: bool,
    reauthorization: bool,
    progress: BoundaryProgress,
    content: Option<ContentContext<'a>>,
    exchange: Option<&'a Exchange>,
    continuation_budget: Option<(u64, u64, u64)>,
    content_targets: std::collections::BTreeMap<String, String>,
}
impl<'a, T> EventBoundary<'a, T> {
    pub(crate) fn new(client: &'a Client, name: Option<&'static str>, event: T) -> Self {
        Self {
            client,
            name,
            event,
            initial: Decision::None,
            initial_candidate: None,
            state_present: false,
            capabilities: None,
            gates_passed: true,
            reauthorization: true,
            progress: BoundaryProgress::default(),
            content: None,
            exchange: None,
            continuation_budget: None,
            content_targets: Default::default(),
        }
    }
    /// Host-owned allowance. The SDK requests at most one step per boundary.
    pub fn continuation_budget(mut self, remaining: u64, count: u64, maximum: u64) -> Self {
        self.continuation_budget = Some((remaining, count, maximum));
        self
    }
    pub fn progress(&self) -> BoundaryProgress {
        self.progress.clone()
    }
    pub fn initial_state(mut self, decision: Decision) -> Self {
        self.initial = decision;
        self.state_present = true;
        self
    }
    pub fn initial_candidate(mut self, candidate: Value) -> Self {
        self.initial_candidate = Some(candidate);
        self.state_present = true;
        self
    }
    pub fn capabilities(mut self, capabilities: Value) -> Self {
        self.capabilities = Some(capabilities);
        self
    }
    pub fn mandatory_gates_passed(mut self, passed: bool) -> Self {
        self.gates_passed = passed;
        self
    }
    pub fn reauthorization_available(mut self, available: bool) -> Self {
        self.reauthorization = available;
        self
    }
    /// Bind a generic effect target to one host-selected canonical content item.
    /// The pointer must address a direct element of the event's canonical primary
    /// content array. Descriptor kind, category and role never select a target.
    /// Validation and content resolution remain lazy until this builder is awaited.
    pub fn content_target(mut self, target: impl Into<String>, pointer: impl Into<String>) -> Self {
        self.content_targets.insert(target.into(), pointer.into());
        self
    }
    pub fn content(mut self, content: ContentContext<'a>) -> Self {
        self.content = Some(content);
        self
    }
    pub fn elicitation_exchange(mut self, exchange: &'a Exchange) -> Self {
        self.exchange = Some(exchange);
        self
    }
}
/// A settled protocol outcome and a fresh decode of its complete effective event.
pub struct EventResult<'a, T> {
    pub outcome: ProtocolOutcome,
    pub effective_event: Value,
    pub event: Result<T, InputDecodeError>,
    pub observations: Vec<Observation<'a>>,
}
fn matches_event(subscription: &Subscription, name: &str) -> bool {
    subscription.events.iter().any(|pattern| {
        pattern == name
            || pattern == "*"
            || pattern.strip_suffix(".*").is_some_and(|prefix| {
                name.strip_prefix(prefix)
                    .is_some_and(|tail| tail.starts_with('.'))
            })
    })
}
impl<'a, T: Serialize + DeserializeOwned + 'a> IntoFuture for EventBoundary<'a, T> {
    type Output = Result<EventResult<'a, T>, BoundaryError>;
    type IntoFuture = LocalFuture<'a, Self::Output>;
    fn into_future(self) -> Self::IntoFuture {
        let progress = self.progress.clone();
        Box::pin(async move {
            let mut guard = ProgressGuard::new(progress.clone());
            let result: Result<EventResult<'a, T>, HookError> = async move {
            if self.progress.interrupted() { return Err(error("boundary interrupted")); }
            let mut input = serde_json::to_value(self.event).map_err(|e| error(e.to_string()))?;
            let name = input["type"].as_str().ok_or_else(|| error("missing canonical event type"))?.to_owned();
            if self.name.is_some_and(|expected| expected != name) { return Err(error("event name mismatch")); }
            let mut supported = supported_capabilities(&name, self.continuation_budget)?;
            if let Some(caps) = supported.as_mut() {
                narrow_content_support(caps, &input, self.content.as_ref(), &self.content_targets)?;
                narrow_specialized_support(caps, &input, self.content.as_ref(), self.exchange)?;
            } else if !self.content_targets.is_empty() { return Err(error("content mapping requires an interceptable target")); }
            let interceptable = supported.is_some();
            let mut capabilities = self.capabilities.unwrap_or_else(|| supported.clone().unwrap_or(json!({"effects":[]})));
            if !subset(&capabilities, &supported.unwrap_or(json!({"effects":[]}))) {
                return Err(error("capabilities may only narrow supported operations"));
            }
            narrow_specialized_support(&mut capabilities, &input, self.content.as_ref(), self.exchange)?;
            if self.client.subscriptions.iter().any(|s| matches_event(s, &name) && interceptable && matches!(s.mode, Mode::Intercept(_)) && s.timeout.is_zero()) {
                return Err(error("interception timeout must be positive"));
            }
            let event = input.clone();
            let mut state_present = self.state_present;
            let mut candidate_descriptor = self.initial_candidate.unwrap_or(Value::Null);
            let mut state = ProtocolOutcome {
                decision: self.initial,
                stopped: false,
                continuation_requested: false,
                instructions: vec![],
                candidate: candidate_descriptor.get("value").cloned(),
                messages: vec![],
                injections: vec![],
                approval_invalidated: false,
                authorized: false,
                failures: vec![],
            };
            let mut request = json!({"jsonrpc":"2.0","id":event["id"],"method":"hooks/intercept","params":{"protocolVersion":"draft","event":event,"capabilities":capabilities}});
            // Validate the full native descriptor even if initial denial skips all hooks.
            if state_present { request["params"]["state"] = json!({"permission":state.decision,"candidate":candidate_descriptor}); }
            if interceptable { validate_request(&request)?; } else {
                crate::canonical::validate("observe-notification", &json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":input}})).map_err(HookError)?;
            }
            // Specialized boundaries require their verification context even with
            // no subscriptions, no effects, or an initially denied/allowed path.
            // Metadata/omit descriptors remain no-read views inside the stages.
            if name.starts_with("user.elicitation.") || name.starts_with("context.compact.") {
                let content = self.content.as_ref().ok_or_else(|| error("specialized boundary requires an authorized content resolver"))?;
                if name == "user.elicitation.result" && self.exchange.is_none() {
                    return Err(error("elicitation result requires original exchange"));
                }
                validate_selected_bodies(&input, content)?;
                if name.starts_with("user.elicitation.") {
                    crate::elicitation::stage_boundary(&request, &[], content, self.exchange).map_err(|e| error(e.to_string()))?;
                } else {
                    crate::compaction::stage_boundary(&request, &[], content).map_err(|e| error(e.to_string()))?;
                }
            }
            if state.decision == Decision::Deny { state.candidate = None; candidate_descriptor = Value::Null; }
            self.progress.publish(&state, &input);
            let mut called = vec![false; self.client.subscriptions.len()];
            for (index, subscription) in self.client.subscriptions.iter().enumerate() {
                if state.decision == Decision::Deny || state.stopped {
                    break;
                }
                if !interceptable || !matches_event(subscription, &name) {
                    continue;
                }
                let Mode::Intercept(policy) = subscription.mode else {
                    continue;
                };
                if state_present {
                    request["params"]["state"] = json!({"permission":state.decision,"candidate":candidate_descriptor});
                    // Optional fields are not parser defaults. Absent native state
                    // stays absent until an interceptor has accepted a response.
                    if state.stopped { request["params"]["state"]["flow"] = json!("stop"); }
                    else if state.continuation_requested { request["params"]["state"]["flow"] = json!("continue"); }
                    if !state.instructions.is_empty() { request["params"]["state"]["instructions"] = json!(state.instructions); }
                    if !state.injections.is_empty() { request["params"]["state"]["injections"] = json!(state.injections); }
                }
                // candidate:null is REQUIRED by the canonical state schema.
                // Validate state as well as the effective event before dispatch.
                let started = Instant::now();
                // A prior JSON replacement can remove merge support. Never
                // re-expand explicitly narrowed or previously removed grants.
                let mut current_caps = request["params"]["capabilities"].clone();
                narrow_content_support(&mut current_caps, &input, self.content.as_ref(), &self.content_targets)?;
                narrow_specialized_support(&mut current_caps, &input, self.content.as_ref(), self.exchange)?;
                request["params"]["capabilities"] = current_caps;
                let response = match validate_request(&request) {
                    Ok(()) => {
                        called[index] = true;
                        let mut pending = subscription.hook.call(request.clone());
                        std::future::poll_fn(|cx| {
                            if self.progress.interrupted() { return Poll::Ready(Err(error("boundary interrupted"))); }
                            self.progress.0.borrow_mut().waker = Some(cx.waker().clone());
                            pending.as_mut().poll(cx)
                        }).await
                    }
                    Err(error) => Err(error),
                };
                self.progress.0.borrow_mut().waker = None;
                if self.progress.interrupted() { return Err(error("boundary interrupted")); }
                let accepted = response.and_then(|response| stage(&request, &response, &state, self.content.as_ref(), self.exchange, &self.content_targets));
                // Check the original monotonic budget after full parsing/staging,
                // immediately before atomic publication. Never salvage a late deny.
                let accepted = if started.elapsed() >= subscription.timeout {
                    Err(error("interception deadline exceeded"))
                } else { accepted };
                match accepted {
                    Ok((next, next_state, replaced_candidate)) => {
                        state_present = true;
                        if next_state.candidate.is_none() {
                            candidate_descriptor = Value::Null;
                        } else if next != input || replaced_candidate {
                            candidate_descriptor = next_state.candidate.as_ref().map(|value| json!({"value":value})).unwrap_or(Value::Null);
                        }
                        input = next;
                        state = next_state;
                        request["params"]["event"] = input.clone();
                        if state.approval_invalidated
                            && state.decision == Decision::None
                            && !self.reauthorization
                        {
                            state.decision = Decision::Deny;
                            state.candidate = None;
                            candidate_descriptor = Value::Null;
                        }
                    }
                    Err(error) => {
                        state.failures.push(SubscriptionFailure {
                            subscription_id: subscription.id.clone(),
                            error,
                            policy,
                        });
                        if policy == FailurePolicy::Closed {
                            state.decision = Decision::Deny;
                            state.candidate = None;
                            candidate_descriptor = Value::Null;
                        }
                    }
                }
                self.progress.publish(&state, &input);
            }
            if !self.gates_passed {
                state.decision = Decision::Deny;
                state.candidate = None;
            }
            state.authorized =
                interceptable && state.decision == Decision::Allow && !state.stopped && self.gates_passed;
            let observations = self.client.subscriptions.iter().enumerate().filter(|(i,s)| matches_event(s, &name) && (s.mode == Mode::Observe || !called[*i])).map(|(_,s)| Observation {
            subscription_id: &s.id, hook: s.hook.as_ref(), notification: json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":request["params"]["event"]}}),
        }).collect();
            self.progress.publish(&state, &input);
            let decoded = serde_json::from_value(input.clone()).map_err(InputDecodeError);
            Ok(EventResult {
                outcome: state,
                effective_event: input,
                event: decoded,
                observations,
            })
            }.await;
            let result = if progress.interrupted() {
                Err(error("boundary interrupted"))
            } else {
                result
            };
            match result {
                Ok(result) => {
                    guard.finish(BoundaryStatus::Settled);
                    Ok(result)
                }
                Err(cause) => {
                    let partial = progress.snapshot().partial;
                    let kind = if progress.interrupted() {
                        BoundaryErrorKind::Interrupted
                    } else if partial.is_none() {
                        BoundaryErrorKind::Preflight
                    } else {
                        BoundaryErrorKind::Operational
                    };
                    guard.finish(if kind == BoundaryErrorKind::Interrupted {
                        BoundaryStatus::Interrupted
                    } else {
                        BoundaryStatus::Failed
                    });
                    Err(BoundaryError {
                        kind,
                        cause,
                        partial,
                    })
                }
            }
        })
    }
}

/// Derive semantic grants from the same canonical schema bundle used for validation.
/// No handwritten list determines which concrete events can execute.
fn supported_capabilities(
    name: &str,
    budget: Option<(u64, u64, u64)>,
) -> Result<Option<Value>, HookError> {
    let descriptor = crate::generated::boundary::ALL_BOUNDARIES
        .iter()
        .find(|boundary| boundary.name == name)
        .ok_or_else(|| error("unknown concrete boundary"))?;
    let Some(schema_ref) = descriptor.capability_schema else {
        return Ok(None);
    };
    let schema = crate::canonical::schema(schema_ref).map_err(HookError)?;
    let properties = &schema["allOf"][1]["properties"];
    let mut caps = json!({"effects":properties["effects"]["items"]["enum"]});
    if has(&caps, "effects", &json!("modify")) {
        for target in properties["modify"]["propertyNames"]["enum"]
            .as_array()
            .ok_or_else(|| error("missing modify targets"))?
        {
            let target = target
                .as_str()
                .ok_or_else(|| error("invalid modify target"))?;
            caps["modify"][target] =
                json!({"replace":true,"merge":!matches!(target, "instructions" | "summary")});
        }
    }
    if has(&caps, "effects", &json!("inject")) {
        caps["inject"] = json!({"context":{"append":true,"deliverAt":["now","next_turn"]}});
    }
    if has(&caps, "effects", &json!("flow")) {
        let mut operations = properties["flow"]["properties"]["operations"]["items"]["enum"]
            .as_array()
            .ok_or_else(|| error("missing flow operations"))?
            .clone();
        if operations.contains(&json!("continue")) {
            if let Some((remaining, count, maximum)) = budget {
                if count > maximum || remaining > maximum - count {
                    return Err(error("invalid continuation budget"));
                }
                caps["flow"] = json!({"remainingContinuations":remaining,"continuationCount":count,"maxContinuations":maximum});
            } else {
                operations.retain(|op| op != "continue");
            }
        }
        caps["flow"]["operations"] = json!(operations);
    }
    // Both pinned MCP modes have concrete staging implementations. Callers may
    // independently remove either mode with `.capabilities(...)`; absence grants
    // no mode-dependent control effects (checked independently of stage logic).
    if name.starts_with("user.elicitation.") {
        caps["elicitation"] = json!({"form":{},"url":{}});
    }
    Ok(Some(caps))
}

fn stage(
    request: &Value,
    response: &Value,
    prior: &ProtocolOutcome,
    content: Option<&ContentContext<'_>>,
    exchange: Option<&Exchange>,
    targets: &std::collections::BTreeMap<String, String>,
) -> Result<(Value, ProtocolOutcome, bool), HookError> {
    crate::canonical::validate("intercept-response", response).map_err(HookError)?;
    if let crate::generated::ParseResult::Failure { diagnostics, .. } =
        crate::generated::parse_intercept_response_value(response.clone())
    {
        return Err(error(format!("invalid response: {diagnostics:?}")));
    }
    if response["id"] != request["id"] {
        return Err(error("response correlation mismatch"));
    }
    let effects = response["result"]["effects"]
        .as_array()
        .ok_or_else(|| error("missing effects"))?;
    let caps = &request["params"]["capabilities"];
    let event = &request["params"]["event"];
    if event["type"]
        .as_str()
        .is_some_and(|name| name.starts_with("user.elicitation."))
        && effects
            .iter()
            .any(|effect| matches!(effect["type"].as_str(), Some("deny" | "return" | "modify")))
    {
        let mode = event["elicitation"]["mode"]
            .as_str()
            .ok_or_else(|| error("missing elicitation mode"))?;
        if !caps["elicitation"].get(mode).is_some_and(Value::is_object) {
            return Err(error("elicitation mode not granted"));
        }
    }
    // Check the whole grant set before performing any content staging.
    for effect in effects {
        if !has(caps, "effects", &effect["type"]) {
            return Err(error("unadvertised effect"));
        }
        match effect["type"].as_str().unwrap_or("") {
            "modify" => {
                let target = effect["target"].as_str().unwrap_or("");
                let operation = effect["operation"].as_str().unwrap_or("");
                if caps["modify"][target][operation] != true {
                    return Err(error("unadvertised modification"));
                }
            }
            "flow" => {
                if !has(&caps["flow"], "operations", &effect["operation"]) {
                    return Err(error("unadvertised flow operation"));
                }
                if effect["operation"] == "continue" && !prior.continuation_requested {
                    let remaining = caps["flow"]["remainingContinuations"].as_u64().unwrap_or(0);
                    let count = caps["flow"]["continuationCount"]
                        .as_u64()
                        .unwrap_or(u64::MAX);
                    let maximum = caps["flow"]["maxContinuations"]
                        .as_u64()
                        .unwrap_or(u64::MAX);
                    if remaining == 0 || count >= maximum {
                        return Err(error("continuation allowance exhausted"));
                    }
                }
            }
            "inject" => {
                if effect["target"] != "context"
                    || effect["operation"] != "append"
                    || caps["inject"]["context"]["append"] != true
                    || !has(
                        &caps["inject"]["context"],
                        "deliverAt",
                        &effect["deliverAt"],
                    )
                {
                    return Err(error("unadvertised injection"));
                }
            }
            "deny" | "allow" | "ask" | "return" | "message" => {}
            _ => return Err(error("unsupported effect")),
        }
    }
    let original = &request["params"]["event"];
    let name = original["type"]
        .as_str()
        .ok_or_else(|| error("missing event type"))?;
    let mut event = original.clone();
    let mut state = prior.clone();
    let specialized = name.starts_with("user.elicitation.") || name.starts_with("context.compact.");
    let staged = if specialized {
        let content =
            content.ok_or_else(|| error("body effects require an authorized content resolver"))?;
        Some(
            if name.starts_with("user.elicitation.") {
                crate::elicitation::stage_boundary(
                    request,
                    &effects
                        .iter()
                        .filter(|effect| effect["type"] != "message")
                        .cloned()
                        .collect::<Vec<_>>(),
                    content,
                    exchange,
                )
            } else {
                crate::compaction::stage_boundary(request, effects, content)
            }
            .map_err(|e| error(e.to_string()))?,
        )
    } else {
        None
    };
    if let Some(staged) = &staged {
        event = staged["event"].clone();
    } else {
        for effect in effects.iter().filter(|e| e["type"] == "modify") {
            modify(&mut event, effect, content, targets)?;
        }
        // Intermediate immutable uploads are not publication. If the response
        // restores the original bytes, retain the original descriptor exactly so
        // neither approval nor a bound candidate is spuriously invalidated.
        if let Some(content) = content {
            for pointer in targets.values() {
                if let (Some(before), Some(after)) =
                    (original.pointer(pointer), event.pointer(pointer))
                    && before != after
                    && content
                        .resolve_selected(before)
                        .map_err(|e| error(e.to_string()))?
                        == content
                            .resolve_selected(after)
                            .map_err(|e| error(e.to_string()))?
                {
                    *event
                        .pointer_mut(pointer)
                        .ok_or_else(|| error("missing mapped item"))? = before.clone();
                }
            }
        }
    }
    let mut effective = request.clone();
    effective["params"]["event"] = event.clone();
    validate_request(&effective)?;
    if &event != original {
        state.candidate = None;
        if state.decision == Decision::Allow {
            state.decision = Decision::None;
            state.approval_invalidated = true;
        }
    }
    for effect in effects {
        match effect["type"].as_str().unwrap_or("") {
            "deny" => state.decision = Decision::Deny,
            "ask" if state.decision != Decision::Deny => state.decision = Decision::Ask,
            "allow" if !matches!(state.decision, Decision::Deny | Decision::Ask) => {
                state.decision = Decision::Allow
            }
            "return" => {
                state.candidate = Some(
                    staged
                        .as_ref()
                        .and_then(|s| s.get("candidate"))
                        .unwrap_or(&effect["value"])
                        .clone(),
                )
            }
            "message" => state.messages.push(effect.clone()),
            "inject" => state.injections.push(effect.clone()),
            "flow" if effect["operation"] == "stop" => state.stopped = true,
            "flow" => {
                state.continuation_requested = true;
                if let Some(instruction) = effect["instruction"].as_str() {
                    state.instructions.push(instruction.to_owned());
                }
            }
            _ => {}
        }
    }
    if state.stopped {
        state.continuation_requested = false;
    }
    if matches!(state.decision, Decision::Deny | Decision::Ask) || state.stopped {
        state.candidate = None;
    }
    Ok((event, state, effects.iter().any(|e| e["type"] == "return")))
}

fn change(current: &mut Value, effect: &Value) -> Result<(), HookError> {
    let replacement = &effect["value"];
    if effect["operation"] == "merge" {
        let value = replacement
            .as_object()
            .ok_or_else(|| error("merge requires object"))?;
        current
            .as_object_mut()
            .ok_or_else(|| error("merge target must be object"))?
            .extend(value.clone());
    } else {
        if effect["target"] == "input" && !replacement.is_object() {
            return Err(error("input replacement requires object"));
        }
        *current = replacement.clone();
    }
    Ok(())
}
fn modify(
    event: &mut Value,
    effect: &Value,
    content: Option<&ContentContext<'_>>,
    targets: &std::collections::BTreeMap<String, String>,
) -> Result<(), HookError> {
    let target = effect["target"]
        .as_str()
        .ok_or_else(|| error("missing target"))?;
    match target {
        "input" => change(&mut event["tool"]["input"], effect),
        "workspace" => change(&mut event["workspace"]["change"], effect),
        "request" => change(&mut event["params"], effect),
        "prompt" | "response" | "output" | "content" => {
            let content = content
                .ok_or_else(|| error("body effects require an authorized content resolver"))?;
            let pointer = targets
                .get(target)
                .ok_or_else(|| error("unmapped content target"))?;
            let item = event
                .pointer_mut(pointer)
                .ok_or_else(|| error("missing mapped content item"))?;
            let bytes = content
                .resolve_selected(item)
                .map_err(|e| error(e.to_string()))?
                .ok_or_else(|| error("primary body not selected"))?;
            let json_body = is_json_media(item["mediaType"].as_str().unwrap_or(""));
            let mut value = if json_body {
                serde_json::from_slice(&bytes).map_err(|e| error(e.to_string()))?
            } else {
                Value::String(
                    std::str::from_utf8(&bytes)
                        .map_err(|e| error(e.to_string()))?
                        .to_owned(),
                )
            };
            let original_value = value.clone();
            change(&mut value, effect)?;
            if value == original_value {
                return Ok(());
            }
            let new_bytes = if json_body {
                serde_json::to_vec(&value).map_err(|e| error(e.to_string()))?
            } else {
                value
                    .as_str()
                    .ok_or_else(|| error("text replacement must be a string"))?
                    .as_bytes()
                    .to_vec()
            };
            if new_bytes.as_slice() != bytes.as_ref() {
                let reference = content.put(&new_bytes).map_err(|e| error(e.to_string()))?;
                if item.get("size").is_some() {
                    item["size"] = reference["size"].clone();
                }
                if item.get("sha256").is_some() {
                    item["sha256"] = reference["sha256"].clone();
                }
                item["body"] = reference;
            }
            Ok(())
        }
        _ => Err(error("unsupported primary target")),
    }
}

fn validate_selected_bodies(event: &Value, content: &ContentContext<'_>) -> Result<(), HookError> {
    for pointer in ["/items", "/message/text", "/message/payload"] {
        if let Some(items) = event.pointer(pointer).and_then(Value::as_array) {
            for item in items {
                content
                    .resolve_selected(item)
                    .map_err(|e| error(e.to_string()))?;
            }
        }
    }
    for pointer in [
        "/instructions",
        "/summary",
        "/elicitation/request",
        "/elicitation/result",
    ] {
        if let Some(item) = event.pointer(pointer) {
            content
                .resolve_selected(item)
                .map_err(|e| error(e.to_string()))?;
        }
    }
    Ok(())
}

fn is_json_media(media: &str) -> bool {
    media == "application/json" || (media.starts_with("application/") && media.ends_with("+json"))
}
fn content_array(name: &str, target: &str) -> Option<&'static str> {
    match (name, target) {
        ("turn.start", "prompt")
        | ("turn.finish.before" | "model.response.after", "response")
        | ("tool.after", "output") => Some("/items"),
        ("user.message.inbound", "prompt") => Some("/message/text"),
        ("user.message.outbound", "content") => Some("/message/payload"),
        _ => None,
    }
}
/// The schema is only a ceiling. Actual generic body operations require an
/// explicit, structurally valid host mapping and an available supported body.
fn narrow_content_support(
    caps: &mut Value,
    event: &Value,
    content: Option<&ContentContext<'_>>,
    targets: &std::collections::BTreeMap<String, String>,
) -> Result<(), HookError> {
    let name = event["type"]
        .as_str()
        .ok_or_else(|| error("missing event type"))?;
    for (target, pointer) in targets {
        let array = content_array(name, target)
            .ok_or_else(|| error("invalid mapped target for boundary"))?;
        let index = pointer
            .strip_prefix(array)
            .and_then(|tail| tail.strip_prefix('/'))
            .filter(|index| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| {
                error("content mapping must address a direct canonical array element")
            })?;
        let parsed = index
            .parse::<usize>()
            .map_err(|_| error("invalid content item index"))?;
        if parsed.to_string() != index
            || event
                .pointer(array)
                .and_then(Value::as_array)
                .and_then(|a| a.get(parsed))
                .is_none()
        {
            return Err(error(
                "content mapping points outside canonical content array",
            ));
        }
    }
    for target in ["prompt", "response", "output", "content"] {
        if content_array(name, target).is_none() || caps["modify"].get(target).is_none() {
            continue;
        }
        let mut operations = None;
        if let (Some(content), Some(pointer)) = (content, targets.get(target)) {
            let item = event
                .pointer(pointer)
                .ok_or_else(|| error("missing mapped content item"))?;
            let media = item["mediaType"].as_str().unwrap_or("");
            if item["selection"] == "body"
                && item.get("gap").is_none()
                && item.get("body").is_some()
                && (is_json_media(media) || media.starts_with("text/"))
            {
                let bytes = content
                    .resolve_selected(item)
                    .map_err(|e| error(e.to_string()))?
                    .ok_or_else(|| error("mapped body unavailable"))?;
                let merge = if is_json_media(media) {
                    serde_json::from_slice::<Value>(&bytes)
                        .map_err(|e| error(e.to_string()))?
                        .is_object()
                } else {
                    std::str::from_utf8(&bytes).map_err(|e| error(e.to_string()))?;
                    false
                };
                operations = Some(merge);
            }
        }
        if let Some(merge) = operations {
            // Do not expand a caller's explicit operation narrowing.
            if !merge {
                caps["modify"][target]["merge"] = json!(false);
            }
            if caps["modify"][target]["replace"] != true && caps["modify"][target]["merge"] != true
            {
                caps["modify"].as_object_mut().unwrap().remove(target);
            }
        } else {
            caps["modify"].as_object_mut().unwrap().remove(target);
        }
    }
    if caps["modify"]
        .as_object()
        .is_some_and(|targets| targets.is_empty())
    {
        caps.as_object_mut().unwrap().remove("modify");
        if let Some(effects) = caps["effects"].as_array_mut() {
            effects.retain(|effect| effect != "modify");
        }
    }
    Ok(())
}

fn remove_effect(caps: &mut Value, kind: &str) {
    if let Some(effects) = caps["effects"].as_array_mut() {
        effects.retain(|effect| effect != kind);
    }
    if matches!(kind, "modify" | "inject" | "flow") {
        caps.as_object_mut().unwrap().remove(kind);
    }
}
fn narrow_specialized_support(
    caps: &mut Value,
    event: &Value,
    content: Option<&ContentContext<'_>>,
    original: Option<&Exchange>,
) -> Result<(), HookError> {
    let name = event["type"].as_str().unwrap_or("");
    if name.starts_with("context.compact.") {
        let target = if name == "context.compact.before" {
            "instructions"
        } else {
            "summary"
        };
        let available = if let (Some(content), Some(item)) = (content, event.get(target)) {
            match content
                .resolve_selected(item)
                .map_err(|e| error(e.to_string()))?
            {
                Some(bytes) => {
                    std::str::from_utf8(&bytes).map_err(|e| error(e.to_string()))?;
                    true
                }
                None => false,
            }
        } else {
            false
        };
        if !available {
            remove_effect(caps, "modify");
        }
    } else if name.starts_with("user.elicitation.") {
        let mode = event["elicitation"]["mode"].as_str().unwrap_or("");
        let mode_supported = caps["elicitation"].get(mode).is_some_and(Value::is_object);
        let request_stage = name == "user.elicitation.request";
        let request_available = if request_stage {
            if let Some(content) = content {
                let envelope = json!({"jsonrpc":"2.0","id":event["id"],"method":"hooks/intercept","params":{"protocolVersion":"draft","event":event,"capabilities":caps}});
                Exchange::new(&envelope, content)
                    .map_err(|e| error(e.to_string()))?
                    .original_request()
                    .is_some()
            } else {
                false
            }
        } else {
            original.and_then(Exchange::original_request).is_some()
        };
        if !mode_supported || !request_available {
            for effect in ["deny", "return", "modify"] {
                remove_effect(caps, effect);
            }
        } else if !request_stage {
            let editable = if let (Some(content), Some(item)) =
                (content, event["elicitation"].get("result"))
            {
                match content
                    .resolve_selected(item)
                    .map_err(|e| error(e.to_string()))?
                {
                    Some(bytes) => {
                        let answer: Value =
                            serde_json::from_slice(&bytes).map_err(|e| error(e.to_string()))?;
                        mode == "form" && answer["action"] == "accept"
                    }
                    None => false,
                }
            } else {
                false
            };
            if !editable {
                remove_effect(caps, "modify");
            }
        }
    }
    Ok(())
}
