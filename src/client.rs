//! Runtime-neutral serial interception. This SDK never executes application tools.
//! Transport adapters own authentication, deadlines, and authorized content projection.
pub use crate::generated::client::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fmt,
    future::{Future, IntoFuture},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Poll, Waker},
    time::{Duration, Instant},
};

/// Executor-neutral, movable futures; no runtime or background worker is required.
pub type LocalFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookError {
    message: String,
    code: Option<crate::generated::DeliveryDiagnosticCode>,
    accepted_settlement: Option<Value>,
}
impl HookError {
    /// Construct an unclassified transport failure.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: None,
            accepted_settlement: None,
        }
    }
    /// Raw canonical evidence retained when the consumer cannot decode an accepted settlement.
    /// This is not execution authorization and does not roll back accepted protocol effects.
    pub fn accepted_settlement(&self) -> Option<&Value> {
        self.accepted_settlement.as_ref()
    }
    pub(crate) fn with_settlement(
        mut self,
        outcome: &RawProtocolOutcome,
        effective: &Value,
        candidate: &Value,
    ) -> Self {
        self.accepted_settlement = Some(json!({
            "effectiveValue": effective, "permission": outcome.decision,
            "candidate": candidate, "messages": outcome.messages,
            "injections": outcome.injections, "responses": outcome.responses,
            "stopped": outcome.stopped, "continuationRequested": outcome.continuation_requested,
            "instructions": outcome.instructions, "approvalInvalidated": outcome.approval_invalidated
        }));
        self.classified(crate::generated::DeliveryDiagnosticCode::ProtocolRejection)
    }

    pub fn classified(mut self, code: crate::generated::DeliveryDiagnosticCode) -> Self {
        self.code = Some(code);
        self
    }
    pub fn code(&self) -> crate::generated::DeliveryDiagnosticCode {
        self.code
            .unwrap_or(crate::generated::DeliveryDiagnosticCode::Transport)
    }
    pub(crate) fn classify_if_unset(
        mut self,
        code: crate::generated::DeliveryDiagnosticCode,
    ) -> Self {
        if self.code.is_none() {
            self.code = Some(code);
        }
        self
    }
}
impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for HookError {}
/// One subscription's transport. Adapters MUST enforce their configured deadline,
/// reject late responses, authenticate without fallback, and apply the existing
/// content permissions/selections before delivery. `hooks/observe` is one-way.
pub trait Hook: Send + Sync {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>>;
}
/// Shared generated permission vocabulary; no independent settlement state.
pub use crate::generated::Permission;
// The permission enum is generated; keep its runtime default without editing artifacts.
#[allow(clippy::derivable_impls)]
impl Default for Permission {
    fn default() -> Self {
        Self::None
    }
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
    /// Wire subscription selectors, including `*` and dotted-prefix wildcards.
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
    crate::generated::ahp_event_boundary_methods!();
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
        name: crate::generated::EventType,
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
    /// `Clone`, `Default`, or `Sync` bound is imposed. Awaiting requires `Send`.
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
            initial: Permission::None,
            initial_candidate: None,
            initial_snapshot: None,
            state_present: false,
            capabilities: capabilities(),
            gates_passed: true,
            reauthorization: true,
            context: None,
            progress: BoundaryProgress::default(),
            admission: Default::default(),
        }
    }
}
/// Supported protocol operations, not a claim that the SDK executes tools/prompts.
pub fn capabilities() -> Value {
    json!({"effects":["deny","allow","ask","modify","return","message","flow","inject"],"modify":{"input":{"replace":true,"merge":true}},"flow":{"operations":["stop"]},"inject":{"context":{"append":true,"deliverAt":["now","next_turn"]}}})
}
#[must_use = "a boundary does nothing until awaited"]
pub struct ToolBefore<'a, T> {
    admission: crate::contracts::Admission,
    client: &'a Client,
    input: T,
    initial: Permission,
    initial_candidate: Option<Value>,
    initial_snapshot: Option<Value>,
    state_present: bool,
    capabilities: Value,
    gates_passed: bool,
    reauthorization: bool,
    context: Option<ToolContext>,
    progress: BoundaryProgress,
}
impl<T> ToolBefore<'_, T> {
    pub(crate) fn admission(mut self, admission: crate::contracts::Admission) -> Self {
        self.admission = admission;
        self
    }
    /// Obtain cancellation-safe evidence before consuming this builder in `.await`.
    /// Reading progress never serializes input or starts interception.
    pub fn progress(&self) -> BoundaryProgress {
        self.progress.clone()
    }
    /// Ordinary permission for this occurrence only, never persistent client state.
    /// Calling this explicitly includes canonical state on the first request,
    /// even for `Permission::None`; otherwise native state is absent by default.
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
    /// Native candidate context for this occurrence, never session state or an
    /// authorization claim. Supply the full canonical `{ "value": ..., "provenance": ... }`
    /// descriptor; optional fields and their presence are preserved until the
    /// candidate is replaced or invalidated. `null` means no candidate.
    /// Validation occurs only when awaited, including on an initially denied path.
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
pub(crate) struct RawProtocolOutcome {
    pub decision: Permission,
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
    /// Accepted canonical backend responses in subscription order, for advanced consumers.
    /// Their presence is not authorization or evidence of host execution.
    pub responses: Vec<Value>,
}
/// Schema-owned settlement data for the high-level consumer facade.
#[derive(Debug, Clone)]
pub struct ProtocolOutcome<C = SettledCandidate, P = Value> {
    pub messages: Vec<crate::generated::MessageEffect>,
    pub injections: Vec<crate::generated::InjectEffect>,
    pub responses: Vec<crate::generated::InterceptResponse>,
    pub settled_candidate: Option<crate::generated::Candidate<C, P>>,
    pub decision: Permission,
    pub stopped: bool,
    /// Requested continuation only; never evidence that a step ran.
    pub continuation_requested: bool,
    pub instructions: Vec<String>,
    pub approval_invalidated: bool,
    /// Permission is allow and all mandatory gates passed. No execution occurred.
    pub authorized: bool,
    pub failures: Vec<SubscriptionFailure>,
}

/// Returned values whose ownership is determined by the originating event.
/// Tool/application results remain opaque; use a declared contract or typed tool boundary.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum SettledCandidate {
    Summary(crate::generated::TextParts),
    Messages(crate::generated::CanonicalMessages),
    Elicitation(crate::generated::McpElicitationElicitResult),
    Opaque(Value),
}

impl<C, P> ProtocolOutcome<C, P> {
    pub fn permission(&self) -> Permission {
        self.decision
    }
    pub fn is_denied(&self) -> bool {
        self.decision == Permission::Deny
    }
    pub fn requires_approval(&self) -> bool {
        matches!(self.decision, Permission::None | Permission::Ask) && !self.stopped
    }
    pub fn can_execute(&self) -> bool {
        self.authorized && !self.stopped && self.settled_candidate.is_none()
    }
    pub fn candidate(&self) -> Option<&C> {
        self.settled_candidate
            .as_ref()
            .map(|candidate| &candidate.value)
    }
    /// Decode a caller-owned candidate and provenance without erasing its envelope.
    /// Use a boundary contract to validate these types atomically before acceptance.
    pub fn candidate_as<R: DeserializeOwned, Q: DeserializeOwned>(
        &self,
    ) -> Result<Option<crate::generated::Candidate<R, Q>>, HookError>
    where
        C: Serialize,
        P: Serialize,
    {
        self.settled_candidate
            .as_ref()
            .map(|candidate| {
                let value = serde_json::to_value(candidate).map_err(crate::protocol::failure)?;
                serde_json::from_value(value).map_err(crate::protocol::failure)
            })
            .transpose()
    }
    pub fn supplied_result(&self) -> Option<&C> {
        if self.authorized && !self.stopped {
            self.candidate()
        } else {
            None
        }
    }
    /// Convert the caller-owned candidate contract without duplicating settlement data.
    pub(crate) fn retype<R: DeserializeOwned, Q: DeserializeOwned>(
        self,
    ) -> Result<ProtocolOutcome<R, Q>, HookError>
    where
        C: Serialize,
        P: Serialize,
    {
        let settled_candidate = self.candidate_as()?;
        Ok(ProtocolOutcome {
            decision: self.decision,
            stopped: self.stopped,
            continuation_requested: self.continuation_requested,
            instructions: self.instructions,
            approval_invalidated: self.approval_invalidated,
            authorized: self.authorized,
            failures: self.failures,
            messages: self.messages,
            injections: self.injections,
            responses: self.responses,
            settled_candidate,
        })
    }
}
impl ProtocolOutcome {
    pub(crate) fn decode(
        raw: RawProtocolOutcome,
        event_type: &str,
        descriptor: &Value,
    ) -> Result<Self, HookError> {
        fn decode<T: DeserializeOwned>(value: &Value) -> Result<T, HookError> {
            serde_json::from_value(value.clone()).map_err(crate::protocol::failure)
        }
        let messages = raw.messages.iter().map(decode).collect::<Result<_, _>>()?;
        let injections = raw
            .injections
            .iter()
            .map(decode)
            .collect::<Result<_, _>>()?;
        let responses = raw.responses.iter().map(decode).collect::<Result<_, _>>()?;
        let value = raw
            .candidate
            .as_ref()
            .map(|value| -> Result<_, HookError> {
                Ok(match event_type {
                    "context.compact.before" => SettledCandidate::Summary(decode(value)?),
                    "model.request.before" => SettledCandidate::Messages(decode(value)?),
                    "user.elicitation.request" => SettledCandidate::Elicitation(decode(value)?),
                    _ => SettledCandidate::Opaque(value.clone()),
                })
            })
            .transpose()?;
        let settled_candidate = match value {
            None => None,
            Some(value) => {
                let descriptor: crate::generated::Candidate<Value> = decode(descriptor)?;
                Some(crate::generated::Candidate {
                    value,
                    provenance: descriptor.provenance,
                    additional_properties: descriptor.additional_properties,
                })
            }
        };
        Ok(Self {
            messages,
            injections,
            responses,
            settled_candidate,
            decision: raw.decision,
            stopped: raw.stopped,
            continuation_requested: raw.continuation_requested,
            instructions: raw.instructions,
            approval_invalidated: raw.approval_invalidated,
            authorized: raw.authorized,
            failures: raw.failures,
        })
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
    pub event: crate::generated::Event,
}
#[derive(Debug, Clone, Default)]
pub struct BoundarySnapshot {
    pub status: BoundaryStatus,
    pub partial: Option<BoundaryPartial>,
}
/// A local, cloneable audit handle which survives dropping the boundary future.
/// No transport, serialization, callbacks or external work occur on creation.
#[derive(Debug, Clone, Default)]
pub struct BoundaryProgress(pub(crate) Arc<Mutex<ProgressState>>);
#[derive(Debug, Default)]
pub(crate) struct ProgressState {
    snapshot: BoundarySnapshot,
    pub(crate) waker: Option<Waker>,
}
impl BoundaryProgress {
    pub fn snapshot(&self) -> BoundarySnapshot {
        self.0
            .lock()
            .expect("progress lock poisoned")
            .snapshot
            .clone()
    }
    /// Interrupt a pending boundary and wake its executor. Interruption never
    /// applies fail-open, publishes pending effects, or authorizes prior approval.
    /// Returns false if the boundary has already finished or been interrupted.
    pub fn interrupt(&self) -> bool {
        let waker = {
            let mut state = self.0.lock().expect("progress lock poisoned");
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
        self.0
            .lock()
            .expect("progress lock poisoned")
            .snapshot
            .status
            == BoundaryStatus::Interrupted
    }
    pub(crate) fn publish(
        &self,
        raw: &RawProtocolOutcome,
        input: &Value,
        descriptor: &Value,
        event_type: &str,
    ) -> Result<(), HookError> {
        let event = serde_json::from_value(input.clone()).map_err(|cause| {
            crate::protocol::failure(cause).with_settlement(raw, input, descriptor)
        })?;
        let mut outcome = ProtocolOutcome::decode(raw.clone(), event_type, descriptor)
            .map_err(|cause| cause.with_settlement(raw, input, descriptor))?;
        outcome.authorized = false;
        self.0
            .lock()
            .expect("progress lock poisoned")
            .snapshot
            .partial = Some(BoundaryPartial { outcome, event });
        Ok(())
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
            progress
                .0
                .lock()
                .expect("progress lock poisoned")
                .snapshot
                .status = BoundaryStatus::Running;
        }
        Self {
            progress,
            finished: false,
        }
    }
    pub(crate) fn finish(&mut self, status: BoundaryStatus) {
        let mut state = self.progress.0.lock().expect("progress lock poisoned");
        state.snapshot.status = status;
        state.waker = None;
        self.finished = true;
    }
}
impl Drop for ProgressGuard {
    fn drop(&mut self) {
        if !self.finished {
            let mut state = self.progress.0.lock().expect("progress lock poisoned");
            state.snapshot.status = BoundaryStatus::Interrupted;
            state.waker = None;
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeliveryDiagnostic {
    pub code: crate::generated::DeliveryDiagnosticCode,
    pub stage: DeliveryStage,
    pub subscription_id: String,
    pub backend_id: Option<String>,
    pub policy: Option<FailurePolicy>,
    pub synthetic_denial: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStage {
    Preparation,
    Intercept,
    Observe,
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
            .map_err(HookError::new)?;
        self.hook.call(self.notification).await.map(|_| ())
    }
}
pub struct BoundaryResult<'a, T> {
    pub outcome: ProtocolOutcome,
    /// Complete schema-owned effective event, including opaque host facts.
    pub event: crate::generated::Event,
    pub(crate) raw_outcome: RawProtocolOutcome,
    pub(crate) candidate_descriptor: Value,
    pub(crate) effective_input: Value,
    /// Freshly decoded after protocol acceptance; failure never rolls back effects.
    pub input: Result<T, InputDecodeError>,
    pub observations: Vec<Observation<'a>>,
    pub diagnostics: Vec<DeliveryDiagnostic>,
}
impl<T> BoundaryResult<'_, T> {
    pub fn permission(&self) -> Permission {
        self.outcome.permission()
    }
}
pub(crate) fn delivery_diagnostics(state: &RawProtocolOutcome) -> Vec<DeliveryDiagnostic> {
    state
        .failures
        .iter()
        .map(|failure| DeliveryDiagnostic {
            code: failure.error.code(),
            stage: if failure.error.code() == crate::generated::DeliveryDiagnosticCode::Preparation
            {
                DeliveryStage::Preparation
            } else {
                DeliveryStage::Intercept
            },
            subscription_id: failure.subscription_id.clone(),
            backend_id: None,
            policy: Some(failure.policy),
            synthetic_denial: failure.policy == FailurePolicy::Closed,
        })
        .collect()
}

pub(crate) fn native_outcome(native: &Value) -> Result<(RawProtocolOutcome, Value), HookError> {
    use crate::generated as g;
    let typed: g::InterceptRequestParamsState =
        serde_json::from_value(native.clone()).map_err(crate::protocol::failure)?;
    let decision = match typed.permission {
        g::InterceptRequestParamsStatePermission::None => Permission::None,
        g::InterceptRequestParamsStatePermission::Allow => Permission::Allow,
        g::InterceptRequestParamsStatePermission::Ask => Permission::Ask,
        g::InterceptRequestParamsStatePermission::Deny => Permission::Deny,
        g::InterceptRequestParamsStatePermission::Unknown(_) => {
            return Err(error("invalid native permission"));
        }
    };
    let candidate_value = match &typed.candidate {
        g::InterceptRequestParamsStateCandidate::Null(()) => None,
        g::InterceptRequestParamsStateCandidate::ValueObject(candidate) => {
            Some(candidate.value.clone())
        }
    };
    let candidate = crate::protocol::value(&typed.candidate)?;
    let stopped = matches!(
        typed.flow,
        g::Presence::Present(g::InterceptRequestParamsStateFlow::Stop)
    );
    let continuation_requested = matches!(
        typed.flow,
        g::Presence::Present(g::InterceptRequestParamsStateFlow::Continue)
    );
    let instructions = match typed.instructions {
        g::Presence::Missing => vec![],
        g::Presence::Present(values) => values,
    };
    let injections = match typed.injections {
        g::Presence::Missing => vec![],
        g::Presence::Present(values) => values
            .iter()
            .map(crate::protocol::value)
            .collect::<Result<_, _>>()?,
    };
    Ok((
        RawProtocolOutcome {
            decision,
            stopped,
            continuation_requested,
            instructions,
            candidate: candidate_value,
            messages: vec![],
            injections,
            approval_invalidated: false,
            authorized: false,
            failures: vec![],
            responses: vec![],
        },
        candidate,
    ))
}

pub(crate) fn snapshot_value(
    native: &Value,
    state: &RawProtocolOutcome,
    candidate: &Value,
) -> Value {
    use crate::generated as g;
    let mut snapshot: g::InterceptRequestParamsState =
        serde_json::from_value(native.clone()).expect("validated native state");
    snapshot.permission = match state.decision {
        Permission::None => g::InterceptRequestParamsStatePermission::None,
        Permission::Allow => g::InterceptRequestParamsStatePermission::Allow,
        Permission::Ask => g::InterceptRequestParamsStatePermission::Ask,
        Permission::Deny => g::InterceptRequestParamsStatePermission::Deny,
    };
    snapshot.candidate =
        serde_json::from_value(candidate.clone()).expect("validated candidate descriptor");
    if state.stopped {
        snapshot.flow = g::Presence::Present(g::InterceptRequestParamsStateFlow::Stop);
    } else if state.continuation_requested {
        snapshot.flow = g::Presence::Present(g::InterceptRequestParamsStateFlow::Continue);
    }
    if !state.instructions.is_empty() || !snapshot.instructions.is_missing() {
        snapshot.instructions = g::Presence::Present(state.instructions.clone());
    }
    if !state.injections.is_empty() || !snapshot.injections.is_missing() {
        snapshot.injections = g::Presence::Present(
            state
                .injections
                .iter()
                .map(|effect| serde_json::from_value(effect.clone()).expect("validated injection"))
                .collect(),
        );
    }
    serde_json::to_value(snapshot).expect("serializable typed state")
}

pub(crate) fn error(message: impl Into<String>) -> HookError {
    HookError::new(message)
}
/// Classify a remote JSON-RPC error only after validating its envelope.
/// Backend message/data are intentionally excluded from diagnostics.
pub(crate) fn check_rpc_error(response: &Value, expected_id: &Value) -> Result<(), HookError> {
    if let Some(remote) = response.get("error") {
        let valid = response["jsonrpc"] == "2.0"
            && response.get("id") == Some(expected_id)
            && response.get("result").is_none()
            && remote.is_object()
            && remote["code"].as_i64().is_some()
            && remote["message"].is_string();
        return Err(if valid {
            error("backend JSON-RPC error")
                .classified(crate::generated::DeliveryDiagnosticCode::RemoteRpc)
        } else {
            error("malformed JSON-RPC error envelope")
                .classified(crate::generated::DeliveryDiagnosticCode::ProtocolRejection)
        });
    }
    Ok(())
}
pub(crate) fn validate_request(request: &Value) -> Result<(), HookError> {
    crate::canonical::validate("intercept-request", request).map_err(HookError::new)?;
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
    prior: &RawProtocolOutcome,
    admission: &crate::contracts::Admission,
) -> Result<(Value, RawProtocolOutcome, bool), HookError> {
    use crate::protocol::Kind;
    check_rpc_error(response, &request["id"])?;
    crate::canonical::validate("intercept-response", response).map_err(HookError::new)?;
    if response["id"] != request["id"] {
        return Err(error("response correlation mismatch"));
    }
    let mut typed_request: crate::generated::InterceptRequest =
        serde_json::from_value(request.clone()).map_err(crate::protocol::failure)?;
    let typed_response = crate::protocol::parse(crate::generated::EventType::ToolBefore, response)?;
    crate::server::validate_effect_capabilities(request, response).map_err(error)?;
    let effects = crate::protocol::effects(&typed_response)?;
    let original = match typed_request.params.event.as_ref() {
        crate::generated::Event::ToolBefore(event) => crate::protocol::value(&event.tool.input)?,
        _ => return Err(error("not a tool.before request")),
    };
    let mut state = prior.clone();
    for effect in &effects {
        match &effect.kind {
            Kind::Modify {
                target,
                operation,
                value,
            } => {
                crate::protocol::apply(&mut typed_request.params.event, target, *operation, value)?;
                admission.event(&crate::protocol::value(&typed_request.params.event)?)?;
            }
            Kind::ReturnTool(value) => admission.returned(&value.value)?,
            Kind::Unknown => return Err(error("unsupported effect")),
            _ => {}
        }
    }
    let input = match typed_request.params.event.as_ref() {
        crate::generated::Event::ToolBefore(event) => crate::protocol::value(&event.tool.input)?,
        _ => unreachable!(),
    };
    validate_request(&crate::protocol::value(&typed_request)?)?;
    if input != original {
        state.candidate = None;
        if state.decision == Permission::Allow {
            state.decision = Permission::None;
            state.approval_invalidated = true;
        }
    }
    let mut replaced_candidate = false;
    for effect in &effects {
        match &effect.kind {
            Kind::Deny => state.decision = Permission::Deny,
            Kind::Ask if state.decision != Permission::Deny => state.decision = Permission::Ask,
            Kind::Allow if !matches!(state.decision, Permission::Deny | Permission::Ask) => {
                state.decision = Permission::Allow
            }
            Kind::ReturnTool(value) => {
                state.candidate = Some(value.value.clone());
                replaced_candidate = true;
            }
            Kind::Message(message) => state.messages.push(crate::protocol::value(message)?),
            Kind::Inject(injection) => state.injections.push(crate::protocol::value(injection)?),
            Kind::Stop => {
                state.stopped = true;
                state.continuation_requested = false;
            }
            _ => {}
        }
    }
    if matches!(state.decision, Permission::Deny | Permission::Ask) || state.stopped {
        state.candidate = None;
    }
    Ok((input, state, replaced_candidate))
}
impl<'a, T: Serialize + DeserializeOwned + Send + 'a> IntoFuture for ToolBefore<'a, T> {
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
            let native = self.initial_snapshot.unwrap_or_else(|| json!({"permission":self.initial,"candidate":self.initial_candidate.unwrap_or(Value::Null)}));
            let (mut state, mut candidate_descriptor) = native_outcome(&native)?;
            let mut request = json!({"jsonrpc":"2.0","id":event["id"],"method":"hooks/intercept","params":{"protocolVersion":"draft","event":event,"capabilities":self.capabilities}});
            // Validate the full native descriptor even if initial denial skips all hooks.
            if state_present { request["params"]["state"] = snapshot_value(&native, &state, &candidate_descriptor); }
            validate_request(&request)?;
            self.admission.event(&request["params"]["event"])?;
            self.admission.candidate(&candidate_descriptor)?;
            if state.decision == Permission::Deny { state.candidate = None; candidate_descriptor = Value::Null; }
            self.progress.publish(&state, &request["params"]["event"], &candidate_descriptor, "tool.before")?;
            let mut called = vec![false; self.client.subscriptions.len()];
            for (index, subscription) in self.client.subscriptions.iter().enumerate() {
                if state.decision == Permission::Deny || state.stopped {
                    break;
                }
                if !subscription.matches() {
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
                            self.progress.0.lock().expect("progress lock poisoned").waker = Some(cx.waker().clone());
                            pending.as_mut().poll(cx)
                        }).await
                    }
                    Err(error) => Err(error),
                };
                self.progress.0.lock().expect("progress lock poisoned").waker = None;
                if self.progress.interrupted() { return Err(error("boundary interrupted")); }
                let raw_response = response.as_ref().ok().cloned();
                let accepted = response.and_then(|response| stage(&request, &response, &state, &self.admission).map_err(|e| e.classify_if_unset(crate::generated::DeliveryDiagnosticCode::ProtocolRejection)));
                // Check the original monotonic budget after full parsing/staging,
                // immediately before atomic publication. Never salvage a late deny.
                let accepted = if started.elapsed() >= subscription.timeout {
                    Err(error("interception deadline exceeded").classified(crate::generated::DeliveryDiagnosticCode::DeadlineExceeded))
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
                        if let Some(response) = raw_response { state.responses.push(response); }
                        request["params"]["event"]["tool"]["input"] = input.clone();
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
                self.progress.publish(&state, &request["params"]["event"], &candidate_descriptor, "tool.before")?;
            }
            if !self.gates_passed {
                state.decision = Permission::Deny;
                state.candidate = None;
                candidate_descriptor = Value::Null;
            }
            state.authorized =
                state.decision == Permission::Allow && !state.stopped && self.gates_passed;
            let observations = self.client.subscriptions.iter().enumerate().filter(|(i,s)| s.matches() && (s.mode == Mode::Observe || !called[*i])).map(|(_,s)| Observation {
            subscription_id: &s.id, hook: s.hook.as_ref(), notification: json!({"jsonrpc":"2.0","method":"hooks/observe","params":{"protocolVersion":"draft","event":request["params"]["event"]}}),
        }).collect();
            self.progress.publish(&state, &request["params"]["event"], &candidate_descriptor, "tool.before")?;
            let decoded = serde_json::from_value(input.clone()).map_err(InputDecodeError);
            let effective_event = request["params"]["event"].clone();
            let event = serde_json::from_value(effective_event.clone()).map_err(|cause| {
                crate::protocol::failure(cause).with_settlement(&state, &effective_event, &candidate_descriptor)
            })?;
            let outcome = ProtocolOutcome::decode(state.clone(), "tool.before", &candidate_descriptor)
                .map_err(|cause| cause.with_settlement(&state, &effective_event, &candidate_descriptor))?;
            Ok(BoundaryResult {
                candidate_descriptor,
                diagnostics: delivery_diagnostics(&state),
                outcome,
                event,
                raw_outcome: state,
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

#[cfg(test)]
mod consumer_outcome_tests {
    use super::*;
    use crate::generated::{
        Candidate, CanonicalMessages, InjectEffect, InterceptResponse, MessageEffect, Presence,
    };

    fn outcome(candidate: Value) -> (RawProtocolOutcome, Value) {
        native_outcome(&json!({"permission":"allow", "candidate":candidate})).unwrap()
    }

    #[test]
    fn typed_settlement_preserves_complete_envelopes_and_opaque_nested_extras() {
        let messages = json!([{"id":"msg", "role":"assistant", "parts":[{"id":"part", "kind":"text", "mediaType":"text/plain", "selection":"body", "text":"ok", "vendor":{"opaque":[null,42]}}], "vendor":{"data":true}}]);
        let descriptor =
            json!({"value":messages,"provenance":{"vendor":[null,1]},"extra":{"keep":true}});
        let (mut raw, candidate) = outcome(descriptor.clone());
        raw.authorized = true;
        raw.messages.push(json!({"type":"message","text":"notice"}));
        let injection = json!({"type":"inject","target":"context","operation":"append","deliverAt":"next_turn","value":messages});
        raw.injections.push(injection.clone());
        let response = json!({"jsonrpc":"2.0","id":"accepted","result":{"protocolVersion":"draft","effects":[injection.clone()],"extensions":{"vendor":{"opaque":[null,1]}}},"vendor":{"envelope":true}});
        raw.responses.push(response.clone());
        let typed = ProtocolOutcome::decode(raw, "model.request.before", &candidate).unwrap();
        let _: &Vec<MessageEffect> = &typed.messages;
        let _: &Vec<InjectEffect> = &typed.injections;
        let _: &Vec<InterceptResponse> = &typed.responses;
        assert_eq!(typed.messages[0].text, "notice");
        assert_eq!(
            serde_json::to_value(&typed.injections[0]).unwrap(),
            injection
        );
        assert_eq!(serde_json::to_value(&typed.responses[0]).unwrap(), response);
        let candidate: &Candidate<SettledCandidate> = typed.settled_candidate.as_ref().unwrap();
        assert_eq!(serde_json::to_value(candidate).unwrap(), descriptor);
        assert_eq!(
            candidate.provenance,
            Presence::Present(descriptor["provenance"].clone())
        );
        assert_eq!(
            candidate.additional_properties["extra"],
            descriptor["extra"]
        );
        let SettledCandidate::Messages(value) = typed.supplied_result().unwrap() else {
            panic!("messages must remain typed")
        };
        let _: &CanonicalMessages = value;
        assert_eq!(serde_json::to_value(value).unwrap(), messages);
        let retyped: ProtocolOutcome<Value, Value> = typed.retype().unwrap();
        assert!(retyped.authorized);
        assert_eq!(retyped.permission(), Permission::Allow);
        assert_eq!(
            serde_json::to_value(retyped.settled_candidate.unwrap()).unwrap(),
            descriptor
        );
        assert_eq!(
            serde_json::to_value(&retyped.responses[0]).unwrap(),
            response
        );
        assert_eq!(
            serde_json::to_value(&retyped.injections[0]).unwrap(),
            injection
        );
    }

    #[test]
    fn absence_and_supplied_null_remain_distinct_and_invalid_owned_candidates_fail() {
        let (raw, candidate) = outcome(Value::Null);
        assert!(
            ProtocolOutcome::decode(raw, "tool.before", &candidate)
                .unwrap()
                .candidate()
                .is_none()
        );
        let (raw, candidate) = outcome(json!({"value":null}));
        let typed = ProtocolOutcome::decode(raw.clone(), "tool.before", &candidate).unwrap();
        let decoded: Option<Candidate<Option<String>, Value>> = typed.candidate_as().unwrap();
        assert_eq!(decoded.unwrap().value, None);
        assert!(matches!(
            ProtocolOutcome::decode(raw.clone(), "tool.before", &candidate)
                .unwrap()
                .candidate(),
            Some(SettledCandidate::Opaque(Value::Null))
        ));
        assert!(ProtocolOutcome::decode(raw, "model.request.before", &candidate).is_err());
        let (mut raw, candidate) = outcome(Value::Null);
        raw.messages.push(json!({"type":"message", "text":42}));
        assert!(ProtocolOutcome::decode(raw, "tool.before", &candidate).is_err());
    }

    #[test]
    fn summary_candidate_uses_text_parts_without_erasing_open_part_extras() {
        let value = json!([{"id":"summary", "kind":"text", "mediaType":"text/plain", "selection":"body", "text":"summary", "vendor":{"opaque":[null,1]}}]);
        let descriptor =
            json!({"value":value,"provenance":{"vendor":"source"},"vendor":{"extra":1}});
        let (raw, candidate) = outcome(descriptor.clone());
        let typed = ProtocolOutcome::decode(raw, "context.compact.before", &candidate).unwrap();
        let SettledCandidate::Summary(parts) = typed.candidate().unwrap() else {
            panic!("summary must be text parts")
        };
        let _: &crate::generated::TextParts = parts;
        assert_eq!(
            serde_json::to_value(typed.settled_candidate.as_ref().unwrap()).unwrap(),
            descriptor
        );
    }

    #[test]
    fn elicitation_retains_action_meta_and_open_answer_payload() {
        let value = json!({"action":"accept","content":{"anything":"opaque","flags":["one","two"]},"_meta":{"vendor":{"keep":1}}});
        let (raw, candidate) = outcome(json!({"value":value}));
        let typed = ProtocolOutcome::decode(raw, "user.elicitation.request", &candidate).unwrap();
        let SettledCandidate::Elicitation(answer) = typed.candidate().unwrap() else {
            panic!("complete form answer")
        };
        assert_eq!(serde_json::to_value(answer).unwrap(), value);
    }
}
