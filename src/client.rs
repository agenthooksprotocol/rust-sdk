//! Runtime-neutral serial interception. This SDK never executes application tools.
//! Transport adapters own authentication, deadlines, and authorized content projection.
pub use crate::generated::client::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    fmt,
    future::{Future, IntoFuture},
    pin::Pin,
    rc::Rc,
    task::{Poll, Waker},
    time::{Duration, Instant},
};

/// Futures deliberately have no `Send` requirement.
pub type LocalFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookError(pub String);
impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for HookError {}
/// One subscription's transport. Adapters MUST enforce their configured deadline,
/// reject late responses, authenticate without fallback, and apply the existing
/// content permissions/selections before delivery. `hooks/observe` is one-way.
pub trait Hook {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>>;
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    #[default]
    None,
    Allow,
    Ask,
    Deny,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    Open,
    Closed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Intercept(FailurePolicy),
    Observe,
}
/// Distinct subscriptions remain independent even when sharing a backend.
pub struct Subscription {
    pub id: String,
    pub events: Vec<String>,
    pub mode: Mode,
    pub hook: Box<dyn Hook>,
    /// Full interception budget, including response validation and staging.
    /// The adapter also needs a timer to interrupt a transport which stays pending.
    pub timeout: Duration,
}
impl Subscription {
    pub fn intercept(
        id: impl Into<String>,
        policy: FailurePolicy,
        hook: impl Hook + 'static,
    ) -> Self {
        Self {
            id: id.into(),
            events: vec!["tool.before".into()],
            mode: Mode::Intercept(policy),
            hook: Box::new(hook),
            timeout: Duration::from_secs(30),
        }
    }
    pub fn observe(id: impl Into<String>, hook: impl Hook + 'static) -> Self {
        Self {
            id: id.into(),
            events: vec!["tool.before".into()],
            mode: Mode::Observe,
            hook: Box::new(hook),
            timeout: Duration::from_secs(30),
        }
    }
    /// Set the full interception budget (default: 30 seconds). Zero is invalid.
    /// Runtime-specific adapters must bound pending I/O by this same budget.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    fn matches(&self) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e.as_str(), "tool.before" | "tool.*" | "*"))
    }
}
/// Canonical event context including source, time, session, tool, and call fields.
/// `type` and `tool.input` are set per occurrence. Supply a fresh logical event ID.
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub event: Value,
}
impl ToolContext {
    pub fn new(event: Value) -> Self {
        Self { event }
    }
}
pub struct Client {
    context: ToolContext,
    pub(crate) subscriptions: Vec<Subscription>,
}
impl Client {
    crate::ahp_event_boundary_methods!();
    /// Defer a complete canonical event boundary until awaited.
    pub fn event<T: Serialize + DeserializeOwned>(
        &self,
        event: T,
    ) -> crate::runtime::EventBoundary<'_, T> {
        crate::runtime::EventBoundary::new(self, None, event)
    }
    /// Bind a complete event to an expected canonical name (checked on await).
    pub fn event_for<T: Serialize + DeserializeOwned>(
        &self,
        name: &'static str,
        event: T,
    ) -> crate::runtime::EventBoundary<'_, T> {
        crate::runtime::EventBoundary::new(self, Some(name), event)
    }
    pub fn new(context: ToolContext) -> Self {
        Self {
            context,
            subscriptions: vec![],
        }
    }
    pub fn with_subscription(mut self, subscription: Subscription) -> Self {
        self.subscriptions.push(subscription);
        self
    }
    /// Creating or dropping this builder performs no serialization or I/O.
    /// The application input needs only `Serialize + DeserializeOwned`; no
    /// `Clone`, `Default`, `Send`, or `Sync` bound is imposed.
    ///
    /// Inputs which cannot be serialized fail at compile time:
    /// ```compile_fail
    /// use agenthooksprotocol::client::{Client, ToolContext};
    /// #[derive(serde::Deserialize)]
    /// struct NotSerializable { count: u64 }
    /// let client = Client::new(ToolContext::new(serde_json::json!({})));
    /// let _ = client.tool_before(NotSerializable { count: 1 });
    /// ```
    /// Deserialization must produce owned data, not borrow from transient wire JSON:
    /// ```compile_fail
    /// use agenthooksprotocol::client::{Client, ToolContext};
    /// #[derive(serde::Serialize, serde::Deserialize)]
    /// struct Borrowed<'a> { text: &'a str }
    /// let client = Client::new(ToolContext::new(serde_json::json!({})));
    /// let text = String::from("borrowed");
    /// let _ = client.tool_before(Borrowed { text: &text });
    /// ```
    pub fn tool_before<T: Serialize + DeserializeOwned>(&self, input: T) -> ToolBefore<'_, T> {
        ToolBefore {
            client: self,
            input,
            initial: Decision::None,
            initial_candidate: None,
            state_present: false,
            capabilities: capabilities(),
            gates_passed: true,
            reauthorization: true,
            context: None,
            progress: BoundaryProgress::default(),
        }
    }
}
/// Supported protocol operations, not a claim that the SDK executes tools/prompts.
pub fn capabilities() -> Value {
    json!({"effects":["deny","allow","ask","modify","return","message","flow","inject"],"modify":{"input":{"replace":true,"merge":true}},"flow":{"operations":["stop"]},"inject":{"context":{"append":true,"deliverAt":["now","next_turn"]}}})
}
#[must_use = "a boundary does nothing until awaited"]
pub struct ToolBefore<'a, T> {
    client: &'a Client,
    input: T,
    initial: Decision,
    initial_candidate: Option<Value>,
    state_present: bool,
    capabilities: Value,
    gates_passed: bool,
    reauthorization: bool,
    context: Option<ToolContext>,
    progress: BoundaryProgress,
}
impl<T> ToolBefore<'_, T> {
    /// Obtain cancellation-safe evidence before consuming this builder in `.await`.
    /// Reading progress never serializes input or starts interception.
    pub fn progress(&self) -> BoundaryProgress {
        self.progress.clone()
    }
    /// Ordinary permission for this occurrence only, never persistent client state.
    /// Calling this explicitly includes canonical state on the first request,
    /// even for `Decision::None`; otherwise native state is absent by default.
    pub fn initial_state(mut self, decision: Decision) -> Self {
        self.initial = decision;
        self.state_present = true;
        self
    }
    /// Native candidate context for this occurrence, never session state or an
    /// authorization claim. Supply the full canonical `{ "value": ..., "provenance": ... }`
    /// descriptor; optional fields and their presence are preserved until the
    /// candidate is replaced or invalidated. `null` means no candidate.
    /// Validation occurs only when awaited, including on an initially denied path.
    pub fn initial_candidate(mut self, candidate: Value) -> Self {
        self.initial_candidate = Some(candidate);
        self.state_present = true;
        self
    }
    /// Remove capabilities, never expand support. Checked when awaited.
    pub fn capabilities(mut self, capabilities: Value) -> Self {
        self.capabilities = capabilities;
        self
    }
    /// Trusted host authority; false blocks execution and supplied results even
    /// when an interceptor returns allow. This is not untrusted request state.
    pub fn mandatory_gates_passed(mut self, passed: bool) -> Self {
        self.gates_passed = passed;
        self
    }
    pub fn reauthorization_available(mut self, available: bool) -> Self {
        self.reauthorization = available;
        self
    }
    pub fn context(mut self, context: ToolContext) -> Self {
        self.context = Some(context);
        self
    }
}
#[derive(Debug)]
pub struct InputDecodeError(pub serde_json::Error);
impl fmt::Display for InputDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "accepted effective input cannot be decoded: {}", self.0)
    }
}
impl std::error::Error for InputDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
#[derive(Debug, Clone)]
pub struct ProtocolOutcome {
    pub decision: Decision,
    pub stopped: bool,
    /// Requested continuation only; never evidence that a step ran.
    pub continuation_requested: bool,
    pub instructions: Vec<String>,
    pub candidate: Option<Value>,
    pub messages: Vec<Value>,
    pub injections: Vec<Value>,
    pub approval_invalidated: bool,
    /// Permission is allow and all mandatory gates passed. No execution occurred.
    pub authorized: bool,
    pub failures: Vec<SubscriptionFailure>,
}
impl ProtocolOutcome {
    pub fn is_denied(&self) -> bool {
        self.decision == Decision::Deny
    }
    pub fn requires_approval(&self) -> bool {
        matches!(self.decision, Decision::None | Decision::Ask) && !self.stopped
    }
    pub fn candidate(&self) -> Option<&Value> {
        self.candidate.as_ref()
    }
    pub fn can_execute(&self) -> bool {
        self.authorized && !self.stopped && self.candidate.is_none()
    }
    pub fn supplied_result(&self) -> Option<&Value> {
        if self.authorized && !self.stopped {
            self.candidate.as_ref()
        } else {
            None
        }
    }
}
/// Lifecycle of local evidence, not a wire disposition or execution receipt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BoundaryStatus {
    #[default]
    NotStarted,
    Running,
    Settled,
    Failed,
    Interrupted,
}

/// Accepted protocol evidence only. `outcome.authorized` is always false in this
/// snapshot: partial or historical evidence must never authorize execution.
#[derive(Debug, Clone)]
pub struct BoundaryPartial {
    pub outcome: ProtocolOutcome,
    pub effective_input: Value,
}
#[derive(Debug, Clone, Default)]
pub struct BoundarySnapshot {
    pub status: BoundaryStatus,
    pub partial: Option<BoundaryPartial>,
}
/// A local, cloneable audit handle which survives dropping the boundary future.
/// No transport, serialization, callbacks or external work occur on creation.
#[derive(Debug, Clone, Default)]
pub struct BoundaryProgress(pub(crate) Rc<RefCell<ProgressState>>);
#[derive(Debug, Default)]
pub(crate) struct ProgressState {
    snapshot: BoundarySnapshot,
    pub(crate) waker: Option<Waker>,
}
impl BoundaryProgress {
    pub fn snapshot(&self) -> BoundarySnapshot {
        self.0.borrow().snapshot.clone()
    }
    /// Interrupt a pending boundary and wake its executor. Interruption never
    /// applies fail-open, publishes pending effects, or authorizes prior approval.
    /// Returns false if the boundary has already finished or been interrupted.
    pub fn interrupt(&self) -> bool {
        let waker = {
            let mut state = self.0.borrow_mut();
            if !matches!(
                state.snapshot.status,
                BoundaryStatus::NotStarted | BoundaryStatus::Running
            ) {
                return false;
            }
            state.snapshot.status = BoundaryStatus::Interrupted;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }
    pub(crate) fn interrupted(&self) -> bool {
        self.0.borrow().snapshot.status == BoundaryStatus::Interrupted
    }
    pub(crate) fn publish(&self, outcome: &ProtocolOutcome, input: &Value) {
        let mut outcome = outcome.clone();
        outcome.authorized = false;
        self.0.borrow_mut().snapshot.partial = Some(BoundaryPartial {
            outcome,
            effective_input: input.clone(),
        });
    }
}
/// Outer failures are distinct from accepted-protocol input decoding failures.
/// Preflight errors have no partial state; any prior accepted state is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryErrorKind {
    Preflight,
    Operational,
    Interrupted,
}
#[derive(Debug, Clone)]
pub struct BoundaryError {
    pub kind: BoundaryErrorKind,
    pub cause: HookError,
    pub partial: Option<BoundaryPartial>,
}
impl fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}
impl std::error::Error for BoundaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
impl From<HookError> for BoundaryError {
    fn from(cause: HookError) -> Self {
        Self {
            kind: BoundaryErrorKind::Preflight,
            cause,
            partial: None,
        }
    }
}
pub(crate) struct ProgressGuard {
    progress: BoundaryProgress,
    finished: bool,
}
impl ProgressGuard {
    pub(crate) fn new(progress: BoundaryProgress) -> Self {
        if !progress.interrupted() {
            progress.0.borrow_mut().snapshot.status = BoundaryStatus::Running;
        }
        Self {
            progress,
            finished: false,
        }
    }
    pub(crate) fn finish(&mut self, status: BoundaryStatus) {
        let mut state = self.progress.0.borrow_mut();
        state.snapshot.status = status;
        state.waker = None;
        self.finished = true;
    }
}
impl Drop for ProgressGuard {
    fn drop(&mut self) {
        if !self.finished {
            let mut state = self.progress.0.borrow_mut();
            state.snapshot.status = BoundaryStatus::Interrupted;
            state.waker = None;
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubscriptionFailure {
    pub subscription_id: String,
    pub error: HookError,
    pub policy: FailurePolicy,
}
/// A deferred, best-effort observation; schedule independently after settlement.
/// Dropping it is permitted. Adapter permissions must match interception. Errors
/// or returned effects never reopen settlement. No runtime or task spawning needed.
pub struct Observation<'a> {
    pub subscription_id: &'a str,
    pub notification: Value,
    pub(crate) hook: &'a dyn Hook,
}
impl Observation<'_> {
    pub async fn deliver(self) -> Result<(), HookError> {
        crate::canonical::validate("observe-notification", &self.notification)
            .map_err(HookError)?;
        self.hook.call(self.notification).await.map(|_| ())
    }
}
pub struct BoundaryResult<'a, T> {
    pub outcome: ProtocolOutcome,
    pub effective_input: Value,
    /// Freshly decoded after protocol acceptance; failure never rolls back effects.
    pub input: Result<T, InputDecodeError>,
    pub observations: Vec<Observation<'a>>,
}
pub(crate) fn error(message: impl Into<String>) -> HookError {
    HookError(message.into())
}
pub(crate) fn validate_request(request: &Value) -> Result<(), HookError> {
    crate::canonical::validate("intercept-request", request).map_err(HookError)?;
    match crate::generated::parse_intercept_request_value(request.clone()) {
        crate::generated::ParseResult::Success { .. } => Ok(()),
        crate::generated::ParseResult::Failure { diagnostics, .. } => {
            Err(error(format!("invalid request: {diagnostics:?}")))
        }
    }
}
pub(crate) fn subset(value: &Value, supported: &Value) -> bool {
    match (value, supported) {
        (Value::Object(v), Value::Object(s)) => v
            .iter()
            .all(|(k, v)| s.get(k).is_some_and(|s| subset(v, s))),
        (Value::Array(v), Value::Array(s)) => v.iter().all(|v| s.contains(v)),
        (Value::Bool(false), Value::Bool(true)) => true,
        _ => value == supported,
    }
}
pub(crate) fn has(caps: &Value, key: &str, value: &Value) -> bool {
    caps[key].as_array().is_some_and(|a| a.contains(value))
}
/// Pure staging; canonical wire validation, never consumer-T validation.
fn stage(
    request: &Value,
    response: &Value,
    prior: &ProtocolOutcome,
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
    let original = &request["params"]["event"]["tool"]["input"];
    let mut input = original.clone();
    let mut state = prior.clone();
    for effect in effects {
        let kind = effect["type"]
            .as_str()
            .ok_or_else(|| error("missing effect type"))?;
        if !has(caps, "effects", &effect["type"]) {
            return Err(error("unadvertised effect"));
        }
        match kind {
            "modify" => {
                let op = effect["operation"].as_str().unwrap_or("");
                if effect["target"] != "input"
                    || !matches!(op, "replace" | "merge")
                    || caps["modify"]["input"][op] != true
                {
                    return Err(error("unsupported input modification"));
                }
                let value = effect["value"]
                    .as_object()
                    .ok_or_else(|| error("input modification requires object"))?;
                if op == "replace" {
                    input = effect["value"].clone();
                } else {
                    input
                        .as_object_mut()
                        .ok_or_else(|| error("input must be object"))?
                        .extend(value.clone());
                }
            }
            "flow"
                if effect["operation"] == "stop"
                    && has(&caps["flow"], "operations", &effect["operation"]) => {}
            "inject"
                if effect["target"] == "context"
                    && effect["operation"] == "append"
                    && caps["inject"]["context"]["append"] == true
                    && has(
                        &caps["inject"]["context"],
                        "deliverAt",
                        &effect["deliverAt"],
                    ) => {}
            "deny" | "allow" | "ask" | "return" | "message" => {}
            _ => return Err(error("unsupported effect operation")),
        }
    }
    let mut effective_request = request.clone();
    effective_request["params"]["event"]["tool"]["input"] = input.clone();
    validate_request(&effective_request)?;
    if &input != original {
        state.candidate = None;
        if state.decision == Decision::Allow {
            state.decision = Decision::None;
            state.approval_invalidated = true;
        }
    }
    // All modifications precede binding this response's return or permission.
    for effect in effects {
        match effect["type"].as_str().unwrap_or("") {
            "deny" => state.decision = Decision::Deny,
            "ask" if state.decision != Decision::Deny => state.decision = Decision::Ask,
            "allow" if !matches!(state.decision, Decision::Deny | Decision::Ask) => {
                state.decision = Decision::Allow
            }
            "return" => state.candidate = Some(effect["value"].clone()),
            "message" => state.messages.push(effect.clone()),
            "inject" => state.injections.push(effect.clone()),
            "flow" => state.stopped = true,
            _ => {}
        }
    }
    if matches!(state.decision, Decision::Deny | Decision::Ask) || state.stopped {
        state.candidate = None;
    }
    let replaced_candidate = effects.iter().any(|effect| effect["type"] == "return");
    Ok((input, state, replaced_candidate))
}
impl<'a, T: Serialize + DeserializeOwned + 'a> IntoFuture for ToolBefore<'a, T> {
    type Output = Result<BoundaryResult<'a, T>, BoundaryError>;
    type IntoFuture = LocalFuture<'a, Self::Output>;
    fn into_future(self) -> Self::IntoFuture {
        let progress = self.progress.clone();
        Box::pin(async move {
            let mut guard = ProgressGuard::new(progress.clone());
            let result: Result<BoundaryResult<'a, T>, HookError> = async move {
            if self.progress.interrupted() { return Err(error("boundary interrupted")); }
            if self.client.subscriptions.iter().any(|s| s.matches() && matches!(s.mode, Mode::Intercept(_)) && s.timeout.is_zero()) {
                return Err(error("interception timeout must be positive"));
            }
            let mut input = serde_json::to_value(self.input).map_err(|e| error(e.to_string()))?;
            if !subset(&self.capabilities, &capabilities()) {
                return Err(error("capabilities may only narrow supported operations"));
            }
            let mut event = self
                .context
                .as_ref()
                .unwrap_or(&self.client.context)
                .event
                .clone();
            if !event.is_object() || !event["tool"].is_object() {
                return Err(error("tool context requires a canonical event and tool"));
            }
            event["type"] = json!("tool.before");
            event["tool"]["input"] = input.clone();
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
            let mut request = json!({"jsonrpc":"2.0","id":event["id"],"method":"hooks/intercept","params":{"protocolVersion":"draft","event":event,"capabilities":self.capabilities}});
            // Validate the full native descriptor even if initial denial skips all hooks.
            if state_present { request["params"]["state"] = json!({"permission":state.decision,"candidate":candidate_descriptor}); }
            validate_request(&request)?;
            if state.decision == Decision::Deny { state.candidate = None; candidate_descriptor = Value::Null; }
            self.progress.publish(&state, &input);
            let mut called = vec![false; self.client.subscriptions.len()];
            for (index, subscription) in self.client.subscriptions.iter().enumerate() {
                if state.decision == Decision::Deny || state.stopped {
                    break;
                }
                if !subscription.matches() {
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
                    if !state.injections.is_empty() { request["params"]["state"]["injections"] = json!(state.injections); }
                }
                // candidate:null is REQUIRED by the canonical state schema.
                // Validate state as well as the effective event before dispatch.
                let started = Instant::now();
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
                let accepted = response.and_then(|response| stage(&request, &response, &state));
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
                        request["params"]["event"]["tool"]["input"] = input.clone();
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
                state.decision == Decision::Allow && !state.stopped && self.gates_passed;
            let observations = self.client.subscriptions.iter().enumerate().filter(|(i,s)| s.matches() && (s.mode == Mode::Observe || !called[*i])).map(|(_,s)| Observation {
            subscription_id: &s.id, hook: s.hook.as_ref(), notification: json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":request["params"]["event"]}}),
        }).collect();
            self.progress.publish(&state, &input);
            let decoded = serde_json::from_value(input.clone()).map_err(InputDecodeError);
            Ok(BoundaryResult {
                outcome: state,
                effective_input: input,
                input: decoded,
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
