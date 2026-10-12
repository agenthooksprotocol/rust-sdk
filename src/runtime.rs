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
    admission: crate::contracts::Admission,
    client: &'a Client,
    name: Option<crate::generated::EventType>,
    event: T,
    initial: Permission,
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
    pub(crate) fn admission(mut self, admission: crate::contracts::Admission) -> Self {
        self.admission = admission;
        self
    }
    pub(crate) fn new(
        client: &'a Client,
        name: Option<crate::generated::EventType>,
        event: T,
    ) -> Self {
        Self {
            admission: Default::default(),
            client,
            name,
            event,
            initial: Permission::None,
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
    pub fn initial_state(mut self, decision: Permission) -> Self {
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
    /// Supply an explicit host content mapping outside canonical attachment slots.
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
    /// Complete schema-owned effective event, including opaque host facts.
    pub event: crate::generated::Event,
    /// Caller-owned projection decoded after acceptance; failure does not roll back effects.
    pub decoded_event: Result<T, InputDecodeError>,
    pub(crate) effective_event: Value,
    pub observations: Vec<Observation<'a>>,
    pub diagnostics: Vec<DeliveryDiagnostic>,
}
impl<T> EventResult<'_, T> {
    pub fn permission(&self) -> Permission {
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
            let event_type = if let Some(expected) = self.name {
                if input["type"].as_str() != Some(expected.as_str()) { return Err(error("event name mismatch")); }
                expected
            } else {
                // Explicit complete-event wire input: unknown names fail decoding.
                serde_json::from_value::<crate::generated::EventType>(input["type"].clone())
                    .map_err(|cause| error(format!("invalid canonical event type: {cause}")))?
            };
            let name = event_type.as_str().to_owned();
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
                crate::canonical::validate("observe-notification", &json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":input}})).map_err(HookError::new)?;
            }
            self.admission.event(&request["params"]["event"])?;
            self.admission.candidate(&candidate_descriptor)?;
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
            if state.decision == Permission::Deny { state.candidate = None; candidate_descriptor = Value::Null; }
            self.progress.publish(&state, &input, &candidate_descriptor, &name)?;
            let mut called = vec![false; self.client.subscriptions.len()];
            for (index, subscription) in self.client.subscriptions.iter().enumerate() {
                if state.decision == Permission::Deny || state.stopped {
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
                let accepted = response.and_then(|response| stage(&request, &response, &state, stage_content, self.exchange, &self.content_targets, &self.admission).map_err(|e| e.classify_if_unset(crate::generated::DeliveryDiagnosticCode::ProtocolRejection)));
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
                            && state.decision == Permission::None
                            && !self.reauthorization
                        {
                            state.decision = Permission::Deny;
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
                            state.decision = Permission::Deny;
                            state.candidate = None;
                            candidate_descriptor = Value::Null;
                        }
                    }
                }
                self.progress.publish(&state, &input, &candidate_descriptor, &name)?;
            }
            if !self.gates_passed {
                state.decision = Permission::Deny;
                state.candidate = None;
            }
            state.authorized =
                interceptable && state.decision == Permission::Allow && !state.stopped && self.gates_passed;
            let observations = self.client.subscriptions.iter().enumerate().filter(|(i,s)| matches_event(s, &name) && (s.mode == Mode::Observe || !called[*i])).map(|(_,s)| Observation {
            subscription_id: &s.id, hook: s.hook.as_ref(), notification: json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":request["params"]["event"]}}),
        }).collect();
            self.progress.publish(&state, &input, &candidate_descriptor, &name)?;
            let decoded = serde_json::from_value(input.clone()).map_err(InputDecodeError);
            let event = serde_json::from_value(input.clone()).map_err(|cause| {
                crate::protocol::failure(cause).with_settlement(&state, &input, &candidate_descriptor)
            })?;
            let outcome = ProtocolOutcome::decode(state.clone(), &name, &candidate_descriptor)
                .map_err(|cause| cause.with_settlement(&state, &input, &candidate_descriptor))?;
            Ok(EventResult {
                diagnostics: delivery_diagnostics(&state),
                outcome,
                event,
                effective_event: input,
                decoded_event: decoded,
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
    let schema = crate::canonical::schema(schema_ref).map_err(HookError::new)?;
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
    prior: &RawProtocolOutcome,
    content: Option<&(dyn ContentAccess + Sync)>,
    exchange: Option<&Exchange>,
    _targets: &std::collections::BTreeMap<String, String>,
    admission: &crate::contracts::Admission,
) -> Result<(Value, RawProtocolOutcome, bool), HookError> {
    use crate::protocol::Kind;
    crate::client::check_rpc_error(response, &request["id"])?;
    crate::canonical::validate("intercept-response", response).map_err(HookError::new)?;
    if response["id"] != request["id"] {
        return Err(error("response correlation mismatch"));
    }
    let mut typed_request: crate::generated::InterceptRequest =
        serde_json::from_value(request.clone()).map_err(crate::protocol::failure)?;
    // The originating envelope is a wire input, so decode its canonical name fallibly.
    let event_type: crate::generated::EventType =
        serde_json::from_value(request["params"]["event"]["type"].clone())
            .map_err(crate::protocol::failure)?;
    let typed_response = crate::protocol::parse(event_type, response)?;
    let name = event_type.as_str();
    crate::server::validate_effect_capabilities(request, response).map_err(error)?;
    let effects = crate::protocol::effects(&typed_response)?;
    let original = typed_request.params.event.as_ref().clone();
    for effect in &effects {
        if let Some(value) = crate::protocol::returned(&effect.kind)? {
            admission.returned(&value)?;
        }
        match &effect.kind {
            Kind::Inject(effect) => validate_message_attachments(&original, &effect.value)?,
            Kind::ReturnMessages(effect) => validate_message_attachments(&original, &effect.value)?,
            Kind::Unknown => return Err(error("unsupported effect")),
            _ => {}
        }
    }
    let specialized = name.starts_with("user.elicitation.") || name.starts_with("context.compact.");
    let staged = if specialized {
        let content =
            content.ok_or_else(|| error("body effects require an authorized content resolver"))?;
        let effects: Vec<_> = effects
            .iter()
            .filter(|effect| !matches!(effect.kind, Kind::Message(_)))
            .map(|effect| effect.wire.clone())
            .collect();
        Some(
            if name.starts_with("user.elicitation.") {
                crate::elicitation::stage_boundary_admitted(
                    request, &effects, content, exchange, admission,
                )
            } else {
                crate::compaction::stage_boundary_admitted(request, &effects, content, admission)
            }
            .map_err(|e| error(e.to_string()))?,
        )
    } else {
        None
    };
    if let Some(staged) = &staged {
        if let Some(candidate) = staged.get("candidate") {
            admission.returned(candidate)?;
        }
        *typed_request.params.event =
            serde_json::from_value(staged["event"].clone()).map_err(crate::protocol::failure)?;
        admission.event(&crate::protocol::value(&typed_request.params.event)?)?;
    } else {
        for effect in &effects {
            if let Kind::Modify {
                target,
                operation,
                value,
            } = &effect.kind
            {
                crate::protocol::apply(&mut typed_request.params.event, target, *operation, value)?;
                validate_attachment_edits(&original, &typed_request.params.event)?;
                admission.event(&crate::protocol::value(&typed_request.params.event)?)?;
                validate_request(&crate::protocol::value(&typed_request)?)?;
            }
        }
    }
    let mut state = prior.clone();
    if *typed_request.params.event != original {
        state.candidate = None;
        if state.decision == Permission::Allow {
            state.decision = Permission::None;
            state.approval_invalidated = true;
        }
    }
    let mut replaced = false;
    for effect in &effects {
        if let Some(mut value) = crate::protocol::returned(&effect.kind)? {
            if let Some(candidate) = staged.as_ref().and_then(|staged| staged.get("candidate")) {
                value = match &effect.kind {
                    Kind::ReturnText(_) => crate::protocol::value(
                        &serde_json::from_value::<crate::generated::TextParts>(candidate.clone())
                            .map_err(crate::protocol::failure)?,
                    )?,
                    Kind::ReturnForm(_) => crate::protocol::value(
                        &serde_json::from_value::<crate::generated::McpElicitationElicitResult>(
                            candidate.clone(),
                        )
                        .map_err(crate::protocol::failure)?,
                    )?,
                    _ => value,
                };
            }
            state.candidate = Some(value);
            replaced = true;
        }
        match &effect.kind {
            Kind::Deny => state.decision = Permission::Deny,
            Kind::Ask if state.decision != Permission::Deny => state.decision = Permission::Ask,
            Kind::Allow if !matches!(state.decision, Permission::Deny | Permission::Ask) => {
                state.decision = Permission::Allow
            }
            Kind::Message(message) => state.messages.push(crate::protocol::value(message)?),
            Kind::Inject(injection) => state.injections.push(crate::protocol::value(injection)?),
            Kind::Stop => state.stopped = true,
            Kind::Continue(effect) => {
                state.continuation_requested = true;
                if let crate::generated::Presence::Present(instruction) = &effect.instruction {
                    state.instructions.push(instruction.clone());
                }
            }
            _ => {}
        }
    }
    if state.stopped {
        state.continuation_requested = false;
    }
    if matches!(state.decision, Permission::Deny | Permission::Ask) || state.stopped {
        state.candidate = None;
    }
    Ok((
        crate::protocol::value(&typed_request.params.event)?,
        state,
        replaced,
    ))
}

fn validate_message_attachments(
    original: &crate::generated::Event,
    messages: &crate::generated::CanonicalMessages,
) -> Result<(), HookError> {
    let parts: Vec<_> = messages
        .0
        .iter()
        .flat_map(|message| message.parts.iter().map(|part| part.as_ref()))
        .collect();
    validate_parts(&crate::protocol::parts(original), &parts)
}
fn validate_attachment_edits(
    original: &crate::generated::Event,
    next: &crate::generated::Event,
) -> Result<(), HookError> {
    validate_parts(
        &crate::protocol::parts(original),
        &crate::protocol::parts(next),
    )
}
fn validate_parts(
    originals: &[&crate::generated::ContentItem],
    parts: &[&crate::generated::ContentItem],
) -> Result<(), HookError> {
    use crate::generated::{ContentItem, ContentReference, Presence};
    struct Identity<'a> {
        id: &'a str,
        media: &'a str,
        category: &'a Presence<String>,
        synthesized: &'a Presence<bool>,
        body: Option<&'a ContentReference>,
    }
    fn identity(part: &ContentItem) -> Option<Identity<'_>> {
        match part {
            ContentItem::AttachmentBodyPart(part) => Some(Identity {
                id: &part.id,
                media: &part.media_type,
                category: &part.category,
                synthesized: &part.synthesized,
                body: Some(&part.body),
            }),
            ContentItem::AttachmentGapPart(part) => Some(Identity {
                id: &part.id,
                media: &part.media_type,
                category: &part.category,
                synthesized: &part.synthesized,
                body: None,
            }),
            ContentItem::AttachmentMetadata(part) => Some(Identity {
                id: &part.id,
                media: &part.media_type,
                category: &part.category,
                synthesized: &part.synthesized,
                body: None,
            }),
            ContentItem::AttachmentOmit(part) => Some(Identity {
                id: &part.id,
                media: &part.media_type,
                category: &part.category,
                synthesized: &part.synthesized,
                body: None,
            }),
            _ => None,
        }
    }
    for part in parts.iter().filter_map(|part| identity(part)) {
        if !originals
            .iter()
            .filter_map(|part| identity(part))
            .any(|prior| {
                prior.id == part.id
                    && prior.media == part.media
                    && prior.category == part.category
                    && prior.synthesized == part.synthesized
                    && (part.body.is_none() || prior.body == part.body)
            })
        {
            return Err(error("effects cannot create or mutate binary attachments"));
        }
    }
    Ok(())
}

pub(crate) fn content_array(name: &str, target: &str) -> Option<&'static str> {
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
    ) -> Result<(Value, RawProtocolOutcome, bool), HookError> {
        let caps = json!({"effects":["modify"],"modify":{"content":{"replace":true,"merge":true}}});
        let request = json!({"jsonrpc":"2.0","id":"event","method":"hooks/intercept",
            "params":{"protocolVersion":"draft","event":event,"capabilities":caps}});
        let state = RawProtocolOutcome {
            decision: Permission::Allow,
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
        stage(
            &request,
            &response,
            &state,
            None,
            None,
            &Default::default(),
            &Default::default(),
        )
    }
    #[test]
    fn inline_replace_needs_no_resolver_or_mapping() {
        let original = event();
        let (next, state, _) = apply(&original, &[effect("replace", messages("changed"))]).unwrap();
        assert_eq!(next["message"]["messages"], messages("changed"));
        assert_eq!(original["message"]["messages"], messages("original"));
        assert_eq!(state.decision, Permission::None);
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
        assert_eq!(state.decision, Permission::Allow);
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
        use crate::generated as g;
        let mut event:g::Event=serde_json::from_value(json!({"id":"event","source":"urn:test:typed","time":"2026-09-15T12:00:00Z","type":"tool.before",
            "path":"native","call":{"id":"call"},"tool":{"name":"test","origin":"native","input":{"nested":{"before":1},"keep":true}}})).unwrap();
        let patch = std::collections::BTreeMap::from([
            ("nested".into(), json!({"after":2})),
            ("null".into(), Value::Null),
        ]);
        crate::protocol::apply(
            &mut event,
            "input",
            crate::protocol::Operation::Merge,
            &crate::protocol::Payload::Opaque(&patch),
        )
        .unwrap();
        assert_eq!(
            crate::protocol::value(&event).unwrap()["tool"]["input"],
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
