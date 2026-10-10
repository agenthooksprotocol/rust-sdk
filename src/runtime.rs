//! Runtime-neutral, canonical full-event transactions. No application execution occurs here.
use crate::attachment::InvocationAttachments;
use crate::client::*;
use crate::client::{
    ProgressGuard, delivery_diagnostics, error, has, native_outcome, snapshot_value, subset,
    validate_request,
};
use crate::content::{ContentAccess, ContentContext};
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
    initial_snapshot: Option<Value>,
    state_present: bool,
    capabilities: Option<Value>,
    gates_passed: bool,
    reauthorization: bool,
    progress: BoundaryProgress,
    content: Option<ContentContext<'a>>,
    attachments: Option<InvocationAttachments>,
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
            initial_snapshot: None,
            state_present: false,
            capabilities: None,
            gates_passed: true,
            reauthorization: true,
            progress: BoundaryProgress::default(),
            content: None,
            attachments: None,
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
        if let Some(snapshot) = self
            .initial_snapshot
            .as_mut()
            .and_then(Value::as_object_mut)
        {
            snapshot.insert("permission".into(), json!(decision));
        }
        self.state_present = true;
        self
    }
    /// Preserve a complete native snapshot, including optional flow and context.
    /// This records a decision already made for this occurrence, not authorization.
    pub fn initial_snapshot(mut self, snapshot: impl Serialize) -> Result<Self, HookError> {
        self.initial_snapshot =
            Some(serde_json::to_value(snapshot).map_err(|e| error(e.to_string()))?);
        self.state_present = true;
        Ok(self)
    }
    pub fn initial_candidate(mut self, candidate: Value) -> Self {
        if let Some(snapshot) = self
            .initial_snapshot
            .as_mut()
            .and_then(Value::as_object_mut)
        {
            snapshot.insert("candidate".into(), candidate.clone());
        }
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
    /// Retain an advanced host mapping for compatibility.
    /// Canonical inline edits address the complete message list for their target;
    /// this mapping does not select a part or trigger attachment reads.
    pub fn content_target(mut self, target: impl Into<String>, pointer: impl Into<String>) -> Self {
        self.content_targets.insert(target.into(), pointer.into());
        self
    }
    pub fn content(mut self, content: ContentContext<'a>) -> Self {
        self.content = Some(content);
        self
    }
    pub(crate) fn attachments(mut self, attachments: InvocationAttachments) -> Self {
        self.attachments = Some(attachments);
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
    pub diagnostics: Vec<DeliveryDiagnostic>,
}
impl<T> EventResult<'_, T> {
    pub fn permission(&self) -> Decision {
        self.outcome.permission()
    }
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
impl<'a, T: Serialize + DeserializeOwned + Send + 'a> IntoFuture for EventBoundary<'a, T> {
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
            let inline_attachments = InvocationAttachments::bind(&mut input, vec![],
                crate::attachment::Budget::new(usize::MAX, usize::MAX), usize::MAX)
                .map_err(|e| error(e.to_string()))?;
            let content: Option<&(dyn ContentAccess + Sync)> = self.attachments.as_ref().map(|a| a as &(dyn ContentAccess + Sync))
                .or_else(|| self.content.as_ref().map(|c| c as &(dyn ContentAccess + Sync)))
                .or(Some(&inline_attachments as &(dyn ContentAccess + Sync)));
            let mut supported = supported_capabilities(&name, self.continuation_budget)?;
            if let Some(caps) = supported.as_mut() {
                narrow_content_support(caps, &input, content, &self.content_targets)?;
                narrow_specialized_support(caps, &input, content, self.exchange)?;
            } else if !self.content_targets.is_empty() { return Err(error("content mapping requires an interceptable target")); }
            let interceptable = supported.is_some();
            let mut capabilities = self.capabilities.unwrap_or_else(|| supported.clone().unwrap_or(json!({"effects":[]})));
            if !subset(&capabilities, &supported.unwrap_or(json!({"effects":[]}))) {
                return Err(error("capabilities may only narrow supported operations"));
            }
            narrow_specialized_support(&mut capabilities, &input, content, self.exchange)?;
            if self.client.subscriptions.iter().any(|s| matches_event(s, &name) && interceptable && matches!(s.mode, Mode::Intercept(_)) && s.timeout.is_zero()) {
                return Err(error("interception timeout must be positive"));
            }
            let event = input.clone();
            let mut state_present = self.state_present;
            let native = self.initial_snapshot.unwrap_or_else(|| json!({"permission":self.initial,"candidate":self.initial_candidate.unwrap_or(Value::Null)}));
            let (mut state, mut candidate_descriptor) = native_outcome(&native)?;
            let mut request = json!({"jsonrpc":"2.0","id":event["id"],"method":"hooks/intercept","params":{"protocolVersion":"draft","event":event,"capabilities":capabilities}});
            // Validate the full native descriptor even if initial denial skips all hooks.
            if state_present { request["params"]["state"] = snapshot_value(&native, &state, &candidate_descriptor); }
            if interceptable { validate_request(&request)?; } else {
                crate::canonical::validate("observe-notification", &json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":input}})).map_err(HookError)?;
            }
            // Specialized boundaries require their verification context even with
            // no subscriptions, no effects, or an initially denied/allowed path.
            // Metadata/omit descriptors remain no-read views inside the stages.
            if name.starts_with("user.elicitation.") || name.starts_with("context.compact.") {
                let content = content.ok_or_else(|| error("specialized boundary requires an authorized content resolver"))?;
                if name == "user.elicitation.result" && self.exchange.is_none() {
                    return Err(error("elicitation result requires original exchange"));
                }
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
                    request["params"]["state"] = snapshot_value(&native, &state, &candidate_descriptor);
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
                narrow_content_support(&mut current_caps, &input, content, &self.content_targets)?;
                narrow_specialized_support(&mut current_caps, &input, content, self.exchange)?;
                request["params"]["capabilities"] = current_caps;
                let response = match validate_request(&request) {
                    Ok(()) => {
                        called[index] = true;
                        let mut pending = subscription.hook.call(request.clone());
                        std::future::poll_fn(|cx| {
                            if self.progress.interrupted() { return Poll::Ready(Err(error("boundary interrupted"))); }
                            self.progress.0.lock().expect("progress lock poisoned").waker = Some(cx.waker().clone());
                            pending.as_mut().poll(cx)
                        }).await
                    }
                    Err(error) => Err(error),
                };
                self.progress.0.lock().expect("progress lock poisoned").waker = None;
                if self.progress.interrupted() { return Err(error("boundary interrupted")); }
                let raw_response = response.as_ref().ok().cloned();
                let staged_attachments = self.attachments.as_ref().map(InvocationAttachments::fork);
                let stage_content = staged_attachments.as_ref().map(|a| a as &(dyn ContentAccess + Sync)).or(content);
                let accepted = response.and_then(|response| stage(&request, &response, &state, stage_content, self.exchange, &self.content_targets).map_err(|e| e.classify_if_unset(crate::generated::DeliveryDiagnosticCode::ProtocolRejection)));
                // Check the original monotonic budget after full parsing/staging,
                // immediately before atomic publication. Never salvage a late deny.
                let accepted = if started.elapsed() >= subscription.timeout {
                    Err(error("interception deadline exceeded").classified(crate::generated::DeliveryDiagnosticCode::DeadlineExceeded))
                } else { accepted };
                match accepted {
                    Ok((next, next_state, replaced_candidate)) => {
                        if let (Some(attachments), Some(staged)) = (&self.attachments, staged_attachments) {
                            attachments.commit(staged);
                        }
                        state_present = true;
                        if next_state.candidate.is_none() {
                            candidate_descriptor = Value::Null;
                        } else if next != input || replaced_candidate {
                            candidate_descriptor = next_state.candidate.as_ref().map(|value| json!({"value":value})).unwrap_or(Value::Null);
                        }
                        input = next;
                        state = next_state;
                        if let Some(response) = raw_response { state.responses.push(response); }
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
                diagnostics: delivery_diagnostics(&state),
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
            caps["modify"][target] = json!({"replace":true,"merge":true});
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
    content: Option<&(dyn ContentAccess + Sync)>,
    exchange: Option<&Exchange>,
    targets: &std::collections::BTreeMap<String, String>,
) -> Result<(Value, ProtocolOutcome, bool), HookError> {
    crate::client::check_rpc_error(response, &request["id"])?;
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
        if effect["type"] == "inject"
            || (effect["type"] == "return" && event["type"] == "model.request.before")
        {
            let candidate =
                json!({"type":"user.message.outbound","message":{"messages":effect["value"]}});
            validate_attachment_edits(event, &candidate)?;
        }
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
        for effect in effects.iter().filter(|effect| effect["type"] == "modify") {
            modify(&mut event, effect, content, targets)?;
            validate_attachment_edits(original, &event)?;
            // Validate each contextual result, not only the final batch. An
            // invalid intermediate event cannot be repaired by a later effect.
            let mut intermediate = request.clone();
            intermediate["params"]["event"] = event.clone();
            validate_request(&intermediate)?;
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

// Binary parts can move, repeat, or disappear, but effects cannot invent or
// change their immutable contents. Application/native values remain opaque.
fn validate_attachment_edits(original: &Value, current: &Value) -> Result<(), HookError> {
    let originals: Vec<&Value> = crate::hooks_content::locations(original)
        .iter()
        .filter_map(|path| original.pointer(path))
        .filter(|part| part["kind"] == "attachment")
        .collect();
    for path in crate::hooks_content::locations(current) {
        let Some(part) = current
            .pointer(&path)
            .filter(|part| part["kind"] == "attachment")
        else {
            continue;
        };
        let known = originals.iter().any(|prior| {
            ["id", "mediaType", "category", "synthesized"]
                .iter()
                .all(|field| prior[*field] == part[*field])
                && (part["selection"] != "body" || prior["body"] == part["body"])
        });
        if !known {
            return Err(error("effects cannot create or mutate binary attachments"));
        }
    }
    Ok(())
}
fn change(current: &mut Value, effect: &Value) -> Result<(), HookError> {
    let replacement = &effect["value"];
    if effect["operation"] == "merge" {
        match (current, replacement) {
            (Value::Array(current), Value::Array(value)) => current.extend(value.clone()),
            (Value::Object(current), Value::Object(value)) => current.extend(value.clone()),
            _ => return Err(error("merge requires matching lists or objects")),
        }
    } else {
        if matches!(effect["target"].as_str(), Some("input" | "workspace"))
            && !replacement.is_object()
        {
            return Err(error("object target replacement requires object"));
        }
        *current = replacement.clone();
    }
    Ok(())
}
fn modify(
    event: &mut Value,
    effect: &Value,
    _content: Option<&(dyn ContentAccess + Sync)>,
    _targets: &std::collections::BTreeMap<String, String>,
) -> Result<(), HookError> {
    let target = effect["target"]
        .as_str()
        .ok_or_else(|| error("missing target"))?;
    let pointer = match target {
        "input" => "/tool/input",
        "workspace" => "/workspace/change",
        _ => content_array(event["type"].as_str().unwrap_or(""), target)
            .ok_or_else(|| error("unsupported primary target"))?,
    };
    if content_array(event["type"].as_str().unwrap_or(""), target).is_some()
        && !effect["value"].is_array()
    {
        return Err(error("canonical message target requires a list"));
    }
    let current = event
        .pointer_mut(pointer)
        .ok_or_else(|| error("missing primary target"))?;
    change(current, effect)
}

fn content_array(name: &str, target: &str) -> Option<&'static str> {
    match (name, target) {
        ("turn.start", "prompt")
        | ("turn.finish.before" | "model.response.after", "response")
        | ("model.request.before", "request")
        | ("tool.after", "output") => Some("/items"),
        ("user.message.inbound", "prompt") | ("user.message.outbound", "content") => {
            Some("/message/messages")
        }
        _ => None,
    }
}
/// Inline list edits need neither a body resolver nor a mapped attachment.
fn narrow_content_support(
    caps: &mut Value,
    event: &Value,
    _content: Option<&(dyn ContentAccess + Sync)>,
    _targets: &std::collections::BTreeMap<String, String>,
) -> Result<(), HookError> {
    let name = event["type"]
        .as_str()
        .ok_or_else(|| error("missing event type"))?;
    for target in ["prompt", "request", "response", "output", "content"] {
        if let Some(pointer) = content_array(name, target)
            && !event.pointer(pointer).is_some_and(Value::is_array)
            && let Some(modify) = caps["modify"].as_object_mut()
        {
            modify.remove(target);
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
    content: Option<&(dyn ContentAccess + Sync)>,
    original: Option<&Exchange>,
) -> Result<(), HookError> {
    let name = event["type"].as_str().unwrap_or("");
    if name.starts_with("context.compact.") {
        let target = if name == "context.compact.before" {
            "instructions"
        } else {
            "summary"
        };
        let available = event
            .get(target)
            .and_then(Value::as_array)
            .is_some_and(|parts| {
                parts.iter().all(|part| {
                    part["selection"] == "body"
                        && part.get("gap").is_none()
                        && part["text"].is_string()
                })
            });
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
            let editable = event["elicitation"]["result"]["text"]
                .as_str()
                .map(serde_json::from_str::<Value>)
                .transpose()
                .map_err(|e| error(e.to_string()))?
                .is_some_and(|answer| mode == "form" && answer["action"] == "accept");
            if !editable {
                remove_effect(caps, "modify");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod inline_tests {
    use super::*;

    fn parts(text: &str) -> Value {
        json!([{"id":"part","kind":"text","mediaType":"text/plain","selection":"body","text":text}])
    }
    fn messages(text: &str) -> Value {
        json!([{"id":"message","role":"assistant","parts":parts(text)}])
    }
    fn event() -> Value {
        json!({"id":"event","source":"urn:test","time":"2026-09-15T12:00:00Z",
            "type":"user.message.outbound","message":{"channel":"test","messages":messages("original")}})
    }
    fn effect(operation: &str, value: Value) -> Value {
        json!({"type":"modify","target":"content","operation":operation,"value":value})
    }
    fn apply(
        event: &Value,
        effects: &[Value],
    ) -> Result<(Value, ProtocolOutcome, bool), HookError> {
        let caps = json!({"effects":["modify"],"modify":{"content":{"replace":true,"merge":true}}});
        let request = json!({"jsonrpc":"2.0","id":"event","method":"hooks/intercept",
            "params":{"protocolVersion":"draft","event":event,"capabilities":caps}});
        let state = ProtocolOutcome {
            decision: Decision::Allow,
            candidate: Some(json!("candidate")),
            stopped: false,
            continuation_requested: false,
            instructions: vec![],
            messages: vec![],
            injections: vec![],
            approval_invalidated: false,
            authorized: false,
            failures: vec![],
            responses: vec![],
        };
        let response = json!({"jsonrpc":"2.0","id":"event","result":{"protocolVersion":"draft","effects":effects}});
        stage(&request, &response, &state, None, None, &Default::default())
    }
    #[test]
    fn inline_replace_needs_no_resolver_or_mapping() {
        let original = event();
        let (next, state, _) = apply(&original, &[effect("replace", messages("changed"))]).unwrap();
        assert_eq!(next["message"]["messages"], messages("changed"));
        assert_eq!(original["message"]["messages"], messages("original"));
        assert_eq!(state.decision, Decision::None);
        assert!(state.candidate.is_none());
        assert!(state.approval_invalidated);
    }
    #[test]
    fn list_merge_appends_in_order_preserving_duplicates() {
        let (next, _, _) = apply(
            &event(),
            &[
                effect("merge", messages("original")),
                effect("merge", messages("last")),
            ],
        )
        .unwrap();
        let list = next["message"]["messages"].as_array().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0], list[1]);
        assert_eq!(list[2]["parts"][0]["text"], "last");
    }
    #[test]
    fn exact_revert_preserves_approval_and_candidate() {
        let original = event();
        let (next, state, _) = apply(
            &original,
            &[
                effect("replace", messages("temporary")),
                effect("replace", messages("original")),
            ],
        )
        .unwrap();
        assert_eq!(next, original);
        assert_eq!(state.decision, Decision::Allow);
        assert_eq!(state.candidate, Some(json!("candidate")));
        assert!(!state.approval_invalidated);
    }
    #[test]
    fn malformed_list_effect_rolls_back_whole_response() {
        let original = event();
        assert!(
            apply(
                &original,
                &[
                    effect("replace", messages("leak")),
                    effect("merge", json!({"bad":true}))
                ]
            )
            .is_err()
        );
        assert_eq!(original, event());
    }
    #[test]
    fn ordinary_content_object_cannot_be_repaired_by_a_later_list() {
        let original = event();
        assert!(
            apply(
                &original,
                &[
                    effect("replace", json!({"answer":"specialized only"})),
                    effect("replace", messages("repaired")),
                ]
            )
            .is_err()
        );
        assert_eq!(original, event());
    }

    #[test]
    fn object_merge_is_shallow_and_keeps_literal_null() {
        let mut object = json!({"nested":{"before":1},"keep":true});
        change(
            &mut object,
            &json!({"operation":"merge","value":{"nested":{"after":2},"null":null}}),
        )
        .unwrap();
        assert_eq!(
            object,
            json!({"nested":{"after":2},"keep":true,"null":null})
        );
    }
    #[test]
    fn capability_negotiation_does_not_require_body_access() {
        let mut caps =
            json!({"effects":["modify"],"modify":{"content":{"replace":true,"merge":true}}});
        narrow_content_support(&mut caps, &event(), None, &Default::default()).unwrap();
        assert_eq!(caps["modify"]["content"]["merge"], true);
    }
}
