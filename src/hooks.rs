//! Primary registration-driven harness. Configuration is ordinary serde JSON;
//! applications retain execution policy. No transport starts before dispatch.
use crate::{
    adapters::registered::{self, BackendOptions, ManagedBackend},
    attachment::{Budget, InvocationAttachments},
    auth::{AuthErrorCode, AuthRecovery},
    client::{
        Client, DeliveryDiagnostic, DeliveryStage, FailurePolicy, Hook, HookError, LocalFuture,
        Mode, Permission, ProtocolOutcome, Subscription, ToolContext,
    },
    content::OwnedContent,
    elicitation::Exchange,
    generated,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::{Future, IntoFuture, poll_fn},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Poll, Waker},
    time::{Duration, Instant},
};

pub use crate::generated::Harness;
use crate::generated::capability::HostCapabilities;

/// Non-event session-start manifest metadata. Event authority belongs exclusively
/// to `capability::HostCapabilities`. Opaque extras cannot replace known members.
#[derive(Clone, Debug)]
pub struct ManifestMetadata {
    pub authentication: Vec<generated::StaticCapabilityManifestAuthenticationItem>,
    pub content_categories: Vec<String>,
    pub correlation_identity_fields: Vec<String>,
    pub gaps: Vec<generated::StaticCapabilityManifestGapsItem>,
    pub limits: generated::StaticCapabilityManifestLimits,
    pub managed_policy: generated::StaticCapabilityManifestManagedPolicy,
    pub tool_paths: Vec<String>,
    pub transports: Vec<generated::StaticCapabilityManifestTransportsItem>,
    pub additional_properties: BTreeMap<String, generated::JsonValue>,
}
impl Default for ManifestMetadata {
    fn default() -> Self {
        Self {
            authentication: Vec::new(),
            content_categories: Vec::new(),
            correlation_identity_fields: Vec::new(),
            gaps: Vec::new(),
            limits: generated::StaticCapabilityManifestLimits::new(),
            managed_policy: generated::StaticCapabilityManifestManagedPolicy::new(true, vec![]),
            tool_paths: Vec::new(),
            transports: vec![generated::StaticCapabilityManifestTransportsItem::InProcess],
            additional_properties: BTreeMap::new(),
        }
    }
}
impl ManifestMetadata {
    fn wire(&self) -> Value {
        let mut limits = self.limits.clone();
        for key in [
            "maxContinuations",
            "maxTimeoutMs",
            "maxUploadBytes",
            "minTimeoutMs",
        ] {
            limits.additional_properties.remove(key);
        }
        let mut policy = self.managed_policy.clone();
        for key in ["disableable", "scopes"] {
            policy.additional_properties.remove(key);
        }
        let gaps: Vec<_> = self
            .gaps
            .iter()
            .cloned()
            .map(|mut gap| {
                gap.additional_properties.remove("path");
                gap.additional_properties.remove("reason");
                gap
            })
            .collect();
        let mut wire = json!({
            "authentication": self.authentication,
            "contentCategories": self.content_categories,
            "correlationIdentityFields": self.correlation_identity_fields,
            "gaps": gaps,
            "limits": limits,
            "managedPolicy": policy,
            "toolPaths": self.tool_paths,
            "transports": self.transports,
        });
        for (key, value) in &self.additional_properties {
            if key != "events" && wire.get(key).is_none() {
                wire[key] = value.clone();
            }
        }
        wire
    }
}

/// Host authority, not registration data. Ordinary callers supply a source and
/// harness identity and explicit per-event grants; registration still owns routing
/// and transport.
pub struct HooksOptions {
    pub source: String,
    pub harness: Harness,
    pub capabilities: HostCapabilities,
    pub manifest_metadata: ManifestMetadata,
    pub backend: BackendOptions,
    pub observation_timeout: Duration,
    pub max_observations: usize,
    /// Maximum simultaneous upload transfers across active Hooks operations.
    pub max_concurrent_uploads: usize,
    pub max_body_bytes: usize,
    /// Active attachment byte budget. Historical name; no harness store exists.
    pub max_stored_bytes: usize,
    /// Active attachment owner budget; returned results release this accounting.
    pub max_stored_entries: usize,
    backends: BTreeMap<String, Arc<dyn ManagedBackend>>,
    configuration_diagnostics: Option<ConfigurationDiagnosticSink>,
    configuration_backoff: (Duration, Duration),
}
type ConfigurationDiagnosticSink = Arc<dyn Fn(&ConfigurationDiagnostic) + Send + Sync>;
impl HooksOptions {
    pub fn new(
        source: impl Into<String>,
        harness: Harness,
        capabilities: HostCapabilities,
    ) -> Self {
        Self {
            source: source.into(),
            harness,
            capabilities,
            manifest_metadata: ManifestMetadata::default(),
            backend: BackendOptions::default(),
            observation_timeout: Duration::from_secs(30),
            max_observations: 1024,
            max_concurrent_uploads: 8,
            max_body_bytes: 4 * 1024 * 1024,
            max_stored_bytes: 64 * 1024 * 1024,
            max_stored_entries: 4096,
            backends: BTreeMap::new(),
            configuration_diagnostics: None,
            configuration_backoff: (Duration::from_secs(30), Duration::from_secs(3600)),
        }
    }
    /// Optional low-level escape hatch for a host-owned neutral transport.
    /// Built-in HTTP/process transports need no callback or factory from callers.
    pub fn with_backend(mut self, id: impl Into<String>, backend: Arc<dyn ManagedBackend>) -> Self {
        self.backends.insert(id.into(), backend);
        self
    }
    /// Receive a [`ConfigurationDiagnostic`] for every backend that server-driven
    /// configuration skips, at construction, initialization or a failed
    /// re-attempt. Called synchronously on the admitting task; it must not block.
    pub fn on_configuration_skipped(
        mut self,
        sink: impl Fn(&ConfigurationDiagnostic) + Send + Sync + 'static,
    ) -> Self {
        self.configuration_diagnostics = Some(Arc::new(sink));
        self
    }
    /// Backoff before a backend skipped with
    /// [`ConfigurationSkipCode::Unavailable`] is re-attempted at the next event
    /// admission or initialization: `initial`, doubling after each failed
    /// attempt, capped at `max`. Defaults to 30 seconds and 1 hour. Skips whose
    /// auth recovery is not `retry` are never re-attempted on backoff.
    pub fn configuration_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.configuration_backoff = (initial, max);
        self
    }
}

/// Why server-driven configuration skipped a backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfigurationSkipCode {
    /// Transport failure, timeout, non-success HTTP status, a JSON-RPC error
    /// other than method-not-found, or an endpoint authentication failure.
    /// Re-attempted after a successful host `prepare` for the backend's event
    /// endpoint, or on backoff when there is no auth error or its recovery is
    /// `retry`.
    Unavailable,
    /// Method-not-found, or an uncorrelated, malformed or version-incompatible
    /// response. Not re-attempted.
    Invalid,
    /// A valid advertisement with no supported subscriptions. Not re-attempted.
    NoApplicableSubscriptions,
    /// Discovered upload authentication names a local secret reference. Not
    /// re-attempted.
    LocalSecret,
}
impl ConfigurationSkipCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "configuration_unavailable",
            Self::Invalid => "configuration_invalid",
            Self::NoApplicableSubscriptions => "no_applicable_subscriptions",
            Self::LocalSecret => "configuration_local_secret",
        }
    }
}

/// Host-visible diagnostic for a backend that server-driven configuration
/// skipped. Redacted: never credentials, tokens, response bodies or event
/// content. Serializes as `{backendId, code, authError?, recovery?}`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfigurationDiagnostic {
    pub backend_id: String,
    pub code: ConfigurationSkipCode,
    /// The safe authentication code, when an endpoint authentication error
    /// caused the skip.
    pub auth_error: Option<AuthErrorCode>,
    /// The recovery paired with `auth_error`.
    pub recovery: Option<AuthRecovery>,
}
impl ConfigurationDiagnostic {
    fn new(
        backend_id: &str,
        code: ConfigurationSkipCode,
        auth_error: Option<AuthErrorCode>,
    ) -> Self {
        Self {
            backend_id: backend_id.into(),
            code,
            auth_error,
            recovery: auth_error.map(AuthErrorCode::recovery),
        }
    }
    /// Whether backoff may re-attempt this skip: only `Unavailable` without an
    /// auth error or with recovery `retry`.
    fn backoff_retry(&self) -> bool {
        self.code == ConfigurationSkipCode::Unavailable
            && self.recovery.is_none_or(|r| r == AuthRecovery::Retry)
    }
}
impl Serialize for ConfigurationDiagnostic {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("backendId", &self.backend_id)?;
        map.serialize_entry("code", self.code.as_str())?;
        if let Some(auth_error) = self.auth_error {
            map.serialize_entry("authError", auth_error.as_str())?;
        }
        if let Some(recovery) = self.recovery {
            map.serialize_entry("recovery", recovery.as_str())?;
        }
        map.end()
    }
}
/// The skip for a failed discovery exchange, keeping only a safe auth code.
fn configuration_failure(error: &HookError) -> (ConfigurationSkipCode, Option<AuthErrorCode>) {
    if let Some(code) = error.auth_code() {
        (ConfigurationSkipCode::Unavailable, Some(code))
    } else if error.is_method_not_found()
        || error.code() == generated::DeliveryDiagnosticCode::ProtocolRejection
    {
        (ConfigurationSkipCode::Invalid, None)
    } else {
        (ConfigurationSkipCode::Unavailable, None)
    }
}
/// A backend without explicit subscriptions awaiting discovery: all of them
/// before initialization, then only those skipped as unavailable.
struct PendingBackend {
    id: String,
    backend: Value,
    transport: Arc<dyn ManagedBackend>,
    /// The event endpoint a host prepares, for HTTP backends.
    endpoint: Option<crate::adapters::registered::AuthContext>,
    /// Host preparations observed before the last attempt.
    prepared: u64,
    /// When backoff makes the backend eligible; `None` means never.
    retry_at: Option<Instant>,
    delay: Duration,
}

/// Admitted routes and server-driven configuration state, shared by `Hooks`
/// and its detached discovery task.
struct Discovery {
    /// A re-attempt replaces the whole set, never an element, so an event's
    /// snapshot never changes under it.
    routes: Mutex<Arc<Vec<Route>>>,
    initialized: AtomicBool,
    /// Changed only by the discovery task, after all its attempts finished.
    pending: Mutex<Vec<PendingBackend>>,
    /// The single in-flight discovery: initialization or a re-attempt.
    task: Mutex<Option<DiscoveryTask>>,
    backend_order: Vec<String>,
    grants: BTreeMap<generated::EventType, Value>,
    observation_timeout: Duration,
    backoff: (Duration, Duration),
    sink: Option<ConfigurationDiagnosticSink>,
    auth_provider: Option<Arc<dyn crate::adapters::registered::AuthProvider>>,
    life: Arc<Lifecycle>,
    next_id: AtomicU64,
}
struct DiscoveryTask {
    future: LocalFuture<'static, Vec<ConfigurationDiagnostic>>,
    wakers: Arc<Wakers>,
}
/// Every poller's waker; waking the task wakes all of them.
#[derive(Default)]
struct Wakers(Mutex<Vec<Waker>>);
impl std::task::Wake for Wakers {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let wakers = std::mem::take(&mut *self.0.lock().unwrap());
        for waker in wakers {
            waker.wake();
        }
    }
}
type Attempt = (usize, Value, Arc<dyn ManagedBackend>, u64, bool);
type Discovered = Result<Vec<Route>, (ConfigurationSkipCode, Option<AuthErrorCode>)>;
impl Discovery {
    fn routes(&self) -> Arc<Vec<Route>> {
        self.routes.lock().unwrap().clone()
    }
    /// Drop the in-flight task, which holds this `Discovery`, and wake its
    /// pollers. Without it, a task nothing polls would keep the routes and
    /// pending transports alive after shutdown or drop.
    fn cancel(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(DiscoveryTask { future, wakers }) = task {
            drop(future);
            std::task::Wake::wake(wakers);
        }
    }
    /// Host preparations for a pending backend's event endpoint.
    fn preparations(&self, pending: &PendingBackend) -> u64 {
        match (&self.auth_provider, &pending.endpoint) {
            (Some(provider), Some(endpoint)) => provider.preparations(endpoint),
            _ => 0,
        }
    }
    /// `Some(prepared)` when `pending` may be re-attempted; `prepared` is true
    /// when a host prepare, not backoff, made it eligible.
    fn eligible(&self, pending: &PendingBackend, now: Instant) -> Option<bool> {
        if self.preparations(pending) > pending.prepared {
            Some(true)
        } else {
            pending
                .retry_at
                .is_some_and(|at| now >= at)
                .then_some(false)
        }
    }
    /// Start the discovery task if none runs and initialization or a
    /// re-attempt is due: the shared admission.
    fn start(self: &Arc<Self>) {
        if self.life.closing.load(Ordering::SeqCst) {
            return;
        }
        let mut task = self.task.lock().unwrap();
        if task.is_some() {
            return;
        }
        let first = !self.initialized.load(Ordering::SeqCst);
        let attempts: Vec<Attempt> = {
            let now = Instant::now();
            let pending = self.pending.lock().unwrap();
            pending
                .iter()
                .enumerate()
                .filter_map(|(index, p)| {
                    let prepared = if first {
                        Some(false)
                    } else {
                        self.eligible(p, now)
                    }?;
                    Some((
                        index,
                        p.backend.clone(),
                        Arc::clone(&p.transport),
                        self.preparations(p),
                        prepared,
                    ))
                })
                .collect()
        };
        if attempts.is_empty() {
            if first {
                self.initialized.store(true, Ordering::SeqCst);
            }
            return;
        }
        let this = Arc::clone(self);
        *task = Some(DiscoveryTask {
            future: Box::pin(async move { this.run(attempts).await }),
            wakers: Arc::default(),
        });
        drop(task);
        #[cfg(any(
            feature = "managed-oauth",
            feature = "reqwest",
            feature = "tokio-process"
        ))]
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let this = Arc::clone(self);
            drop(runtime.spawn(poll_fn(move |cx| this.poll(Some(cx.waker())))));
        }
    }
    /// Advance the discovery task; `Ready` once none is in flight. Without a
    /// waker this never waits: a contended task is left to its other poller.
    fn poll(&self, waker: Option<&Waker>) -> Poll<()> {
        let mut slot = match waker {
            Some(_) => self.task.lock().unwrap(),
            None => match self.task.try_lock() {
                Ok(slot) => slot,
                Err(_) => return Poll::Pending,
            },
        };
        let Some(task) = slot.as_mut() else {
            return Poll::Ready(());
        };
        if let Some(waker) = waker {
            let mut wakers = task.wakers.0.lock().unwrap();
            if !wakers.iter().any(|w| w.will_wake(waker)) {
                wakers.push(waker.clone());
            }
        }
        let task_waker = Waker::from(Arc::clone(&task.wakers));
        let Poll::Ready(diagnostics) = task
            .future
            .as_mut()
            .poll(&mut std::task::Context::from_waker(&task_waker))
        else {
            return Poll::Pending;
        };
        let finished = slot.take().expect("discovery task");
        drop(slot);
        std::task::Wake::wake(finished.wakers);
        if let Some(sink) = &self.sink {
            for diagnostic in &diagnostics {
                sink(diagnostic);
            }
        }
        Poll::Ready(())
    }
    /// Run every attempt, then record the outcome at once. A cancelled
    /// (shutdown) task changes nothing.
    async fn run(&self, attempts: Vec<Attempt>) -> Vec<ConfigurationDiagnostic> {
        let mut outcomes = Vec::with_capacity(attempts.len());
        for (index, backend, transport, observed, prepared) in attempts {
            match self.discover(&backend, &transport).await {
                Ok(outcome) => outcomes.push((index, outcome, observed, prepared)),
                Err(_) => return Vec::new(),
            }
        }
        let mut diagnostics = Vec::new();
        let now = Instant::now();
        let (initial, max) = self.backoff;
        let mut pending = self.pending.lock().unwrap();
        let mut admitted = Vec::new();
        let mut finished = Vec::new();
        for (index, outcome, observed, prepared) in outcomes {
            let entry = &mut pending[index];
            match outcome {
                Ok(routes) => {
                    admitted.extend(routes);
                    finished.push(index);
                }
                Err((code, auth_error)) => {
                    let diagnostic = ConfigurationDiagnostic::new(&entry.id, code, auth_error);
                    if code == ConfigurationSkipCode::Unavailable {
                        if prepared {
                            entry.delay = initial;
                        }
                        entry.prepared = observed;
                        entry.retry_at = diagnostic
                            .backoff_retry()
                            .then(|| now.checked_add(entry.delay))
                            .flatten();
                        entry.delay = entry.delay.saturating_mul(2).min(max);
                    } else {
                        finished.push(index);
                    }
                    diagnostics.push(diagnostic);
                }
            }
        }
        for index in finished.into_iter().rev() {
            pending.remove(index);
        }
        if !admitted.is_empty() {
            let mut current = self.routes.lock().unwrap();
            let mut routes = Vec::clone(&current);
            routes.extend(admitted);
            routes.sort_by_key(|route| {
                self.backend_order
                    .iter()
                    .position(|id| id == &route.backend_id)
                    .unwrap()
            });
            *current = Arc::new(routes);
        }
        self.initialized.store(true, Ordering::SeqCst);
        diagnostics
    }
    /// One discovery exchange: the backend's routes, or why it is skipped.
    /// Only cancellation is an error.
    async fn discover(
        &self,
        backend: &Value,
        transport: &Arc<dyn ManagedBackend>,
    ) -> Result<Discovered, HookError> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": format!("configuration-{}", self.next_id.fetch_add(1, Ordering::SeqCst)),
            "method": "hooks/configuration",
            "params": {"protocolVersion": generated::PROTOCOL_VERSION}
        });
        let expected_id = request["id"].clone();
        let owned_transport = Arc::clone(transport);
        let timeout = self.observation_timeout;
        let response = self
            .life
            .run(Box::pin(async move {
                owned_transport.call(request, timeout).await
            }))
            .await;
        if self.life.closing.load(Ordering::SeqCst) {
            return Err(err("configuration discovery cancelled by shutdown")
                .classified(generated::DeliveryDiagnosticCode::Cancelled));
        }
        let response = match response {
            Ok(response) => response,
            Err(error) if error.code() == generated::DeliveryDiagnosticCode::Cancelled => {
                return Err(error);
            }
            Err(error) => return Ok(Err(configuration_failure(&error))),
        };
        // Built-in transports already reject JSON-RPC errors; host transports may not.
        if let Err(error) = crate::client::check_rpc_error(&response, &expected_id) {
            return Ok(Err(configuration_failure(&error)));
        }
        if response["id"] != expected_id
            || crate::canonical::validate("configuration-response", &response).is_err()
        {
            return Ok(Err((ConfigurationSkipCode::Invalid, None)));
        }
        let configuration = &response["result"]["configuration"];
        if names_local_secret(configuration) {
            return Ok(Err((ConfigurationSkipCode::LocalSecret, None)));
        }
        let mut resolved = backend.clone();
        resolved["subscriptions"] = configuration["subscriptions"].clone();
        Ok(
            match routes_for(
                &resolved,
                transport,
                &self.grants,
                self.observation_timeout,
                true,
            ) {
                Ok(routes) if routes.is_empty() => {
                    Err((ConfigurationSkipCode::NoApplicableSubscriptions, None))
                }
                Ok(routes) => Ok(routes),
                Err(_) => Err((ConfigurationSkipCode::Invalid, None)),
            },
        )
    }
}

fn observes(grant: &Value) -> bool {
    grant["modes"]
        .as_array()
        .is_some_and(|modes| modes.iter().any(|mode| mode.as_str() == Some("observe")))
}

#[derive(Clone)]
struct Route {
    id: String,
    backend_id: String,
    events: Vec<generated::EventType>,
    mode: Mode,
    timeout: Duration,
    configuration: Value,
    headers: Option<Value>,
    backend: Arc<dyn ManagedBackend>,
}
impl Route {
    fn observation_diagnostic(&self, error: &HookError) -> DeliveryDiagnostic {
        DeliveryDiagnostic::new(
            error,
            DeliveryStage::Observe,
            self.id.clone(),
            Some(self.backend_id.clone()),
            None,
        )
    }
}
type UploadPlans = BTreeMap<String, Result<crate::hooks_content::Receipts, HookError>>;

#[derive(Clone)]
struct RouteHook {
    route: Route,
    life: Weak<Lifecycle>,
    deadline: Option<Instant>,
    prepare_only: bool,
    uploads: Arc<UploadPlans>,
}
impl Hook for RouteHook {
    fn call(&self, mut request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        let owned = self.clone();
        let work = Box::pin(async move {
            let start = Instant::now();
            let timeout = owned
                .deadline
                .map(|deadline| deadline.saturating_duration_since(start))
                .unwrap_or(owned.route.timeout)
                .min(owned.route.timeout);
            if timeout.is_zero() {
                return Err(err("hook operation budget exceeded")
                    .classified(generated::DeliveryDiagnosticCode::DeadlineExceeded));
            }
            if owned.route.configuration["includeNative"] != true
                && let Some(event) = request["params"]["event"].as_object_mut()
            {
                event.remove("native");
            }
            let local_event = request["params"]["event"].clone();
            let receipts = owned
                .uploads
                .get(&owned.route.id)
                .ok_or_else(|| err("missing authorized upload plan"))?
                .as_ref()
                .map_err(Clone::clone)?;
            request = crate::hooks_content::project_receipts(
                request,
                &owned.route.configuration["content"],
                receipts,
            )
            .map_err(|error| {
                error.classify_if_unset(generated::DeliveryDiagnosticCode::Preparation)
            })?;
            let remaining = timeout
                .checked_sub(start.elapsed())
                .filter(|v| !v.is_zero())
                .ok_or_else(|| {
                    err("subscription deadline exceeded during content preparation")
                        .classified(generated::DeliveryDiagnosticCode::DeadlineExceeded)
                })?;
            if owned.prepare_only {
                return Ok(request);
            }
            let mut response = owned.route.backend.call(request.clone(), remaining).await?;
            if request["method"] == "hooks/intercept" {
                crate::client::check_rpc_error(&response, &request["id"])?;
                crate::hooks_content::validate_response_grants(&request, &response).map_err(
                    |error| error.classified(generated::DeliveryDiagnosticCode::ProtocolRejection),
                )?;
                restore_effect_attachment_refs(&local_event, receipts, &mut response)?;
            }
            Ok(response)
        });
        match self.life.upgrade() {
            Some(life) => life.run(work),
            None => Box::pin(async { Err(err("Hooks has been dropped")) }),
        }
    }
}
// A backend speaks its own confirmed receipt namespace. Restore only canonical
// effect message parts to invocation owner identities before serial staging.
fn restore_effect_attachment_refs(
    original: &Value,
    receipts: &crate::hooks_content::Receipts,
    response: &mut Value,
) -> Result<(), HookError> {
    let original_event: generated::Event = serde_json::from_value(original.clone()).map_err(err)?;
    let originals: Vec<_> = crate::protocol::parts(&original_event)
        .into_iter()
        .filter_map(|part| {
            if let generated::ContentItem::AttachmentBodyPart(part) = part {
                Some(part.as_ref())
            } else {
                None
            }
        })
        .collect();
    // Decode the event name at this explicit wire-envelope negotiation boundary.
    let event_type: generated::EventType =
        serde_json::from_value(original["type"].clone()).map_err(err)?;
    let mut typed = crate::protocol::parse(event_type, response)?;
    crate::protocol::visit_messages_mut(&mut typed, |messages| {
        for message in &mut messages.0 {
            for part in &mut message.parts {
                let generated::ContentItem::AttachmentBodyPart(part) = part.as_mut() else {
                    continue;
                };
                let receipt_body = crate::protocol::value(&part.body)?;
                let prior = originals
                    .iter()
                    .find(|prior| {
                        prior.id == part.id
                            && prior.media_type == part.media_type
                            && prior.category == part.category
                            && prior.synthesized == part.synthesized
                            && receipts.get(&prior.body.ref_) == Some(&receipt_body)
                    })
                    .ok_or_else(|| {
                        err("effect references an unconfirmed or unknown binary attachment")
                            .classified(generated::DeliveryDiagnosticCode::ProtocolRejection)
                    })?;
                part.body = prior.body.clone();
            }
        }
        Ok(())
    })?;
    *response = crate::protocol::response_value(&typed)?;
    Ok(())
}
fn err(value: impl std::fmt::Display) -> HookError {
    HookError::new(value.to_string())
}
fn matches(pattern: &str, name: &str) -> bool {
    pattern == name
        || pattern == "*"
        || pattern.strip_suffix(".*").is_some_and(|prefix| {
            name.strip_prefix(prefix)
                .is_some_and(|tail| tail.starts_with('.'))
        })
}
fn filtered(config: &Value, event: &Value) -> bool {
    for (key, actual) in [
        ("paths", &event["path"]),
        ("toolKinds", &event["tool"]["kind"]),
    ] {
        if let Some(values) = config["filters"][key].as_array()
            && !values.contains(actual)
        {
            return true;
        }
    }
    false
}
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObservationFailure {
    pub subscription_id: String,
    pub error: String,
    /// The typed authentication failure, if any; see `DeliveryDiagnostic::auth_code`.
    pub auth_code: Option<crate::auth::AuthErrorCode>,
    pub required_scopes: Vec<String>,
}
impl ObservationFailure {
    fn new(subscription_id: String, error: impl Into<String>, cause: Option<&HookError>) -> Self {
        Self {
            subscription_id,
            error: error.into(),
            auth_code: cause.and_then(HookError::auth_code),
            required_scopes: cause.map_or(Vec::new(), |e| e.required_scopes().to_vec()),
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct ObservationReport {
    pub delivered: usize,
    pub failures: Vec<ObservationFailure>,
    pub omitted_failures: usize,
}
#[derive(Default)]
struct Lifecycle {
    closing: AtomicBool,
    closed: AtomicBool,
    active: AtomicUsize,
    cleaning: AtomicBool,
    waiters: Mutex<Vec<Waker>>,
    report: Mutex<ObservationReport>,
    work: Mutex<Vec<Weak<OwnedWork>>>,
}
// The harness owns each transport/projection future independently of the caller's
// boundary future. Shutdown can drop it even if that caller stops polling.
struct OwnedWork {
    future: Mutex<Option<LocalFuture<'static, Result<Value, HookError>>>>,
    waker: Mutex<Option<Waker>>,
}
impl OwnedWork {
    fn cancel(&self) {
        let future = self.future.lock().unwrap().take();
        drop(future);
        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
impl Lifecycle {
    fn run(
        &self,
        future: LocalFuture<'static, Result<Value, HookError>>,
    ) -> LocalFuture<'static, Result<Value, HookError>> {
        let mut registry = self.work.lock().unwrap();
        if self.closing.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(err("Hooks is shutting down")
                    .classified(generated::DeliveryDiagnosticCode::Cancelled))
            });
        }
        let work = Arc::new(OwnedWork {
            future: Mutex::new(Some(future)),
            waker: Mutex::new(None),
        });
        registry.retain(|entry| entry.strong_count() != 0);
        registry.push(Arc::downgrade(&work));
        Box::pin(poll_fn(move |cx| {
            *work.waker.lock().unwrap() = Some(cx.waker().clone());
            let mut slot = work.future.lock().unwrap();
            let Some(future) = slot.as_mut() else {
                return Poll::Ready(Err(err("hook work cancelled by shutdown")
                    .classified(generated::DeliveryDiagnosticCode::Cancelled)));
            };
            let result = future.as_mut().poll(cx);
            if result.is_ready() {
                slot.take();
            }
            result
        }))
    }
    fn cancel_work(&self) {
        let work = std::mem::take(&mut *self.work.lock().unwrap());
        for entry in work {
            if let Some(work) = entry.upgrade() {
                work.cancel();
            }
        }
    }
    fn wake(&self) {
        let waiters = std::mem::take(&mut *self.waiters.lock().unwrap());
        for w in waiters {
            w.wake();
        }
    }
    fn failure(&self, failure: ObservationFailure) {
        let mut report = self.report.lock().unwrap();
        if report.failures.len() < 1024 {
            report.failures.push(failure);
        } else {
            report.omitted_failures = report.omitted_failures.saturating_add(1);
        }
    }
    fn begin(&self) -> Result<Active<'_>, HookError> {
        self.active.fetch_add(1, Ordering::SeqCst);
        let active = Active(self);
        if self.closing.load(Ordering::SeqCst) {
            return Err(err("Hooks is shutting down")
                .classified(generated::DeliveryDiagnosticCode::Cancelled));
        }
        Ok(active)
    }
    async fn ready(&self) {
        poll_fn(|cx| {
            let mut waiters = self.waiters.lock().unwrap();
            if self.active.load(Ordering::SeqCst) == 0 {
                Poll::Ready(())
            } else {
                if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                    waiters.push(cx.waker().clone());
                }
                Poll::Pending
            }
        })
        .await
    }
}
struct Active<'a>(&'a Lifecycle);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.wake();
    }
}
struct Cleanup<'a>(&'a Lifecycle);
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        self.0.cleaning.store(false, Ordering::SeqCst);
        self.0.wake();
    }
}
struct PreparedObservation<'a> {
    route: Route,
    request: Value,
    deadline: Option<Instant>,
    remaining: Duration,
    delivery: Delivery<'a>,
}
struct Delivery<'a> {
    life: &'a Lifecycle,
    id: String,
    finished: bool,
}
impl Drop for Delivery<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.life.failure(ObservationFailure::new(
                self.id.clone(),
                "observation delivery cancelled; not retried",
                None,
            ));
        }
    }
}

/// Whether discovered upload authentication names a secret that only a client
/// registration may name. Such a backend is skipped whole, before any resolution.
fn names_local_secret(configuration: &Value) -> bool {
    configuration["subscriptions"]
        .as_array()
        .is_some_and(|subscriptions| {
            subscriptions.iter().any(|subscription| {
                ["tokenEnv", "tokenRef", "clientSecretRef"]
                    .iter()
                    .any(|key| subscription["upload"]["auth"].get(key).is_some())
            })
        })
}

fn routes_for(
    backend: &Value,
    transport: &Arc<dyn ManagedBackend>,
    grants: &BTreeMap<generated::EventType, Value>,
    observation_timeout: Duration,
    discovered: bool,
) -> Result<Vec<Route>, HookError> {
    let id = backend["id"].as_str().ok_or_else(|| err("backend id"))?;
    let mut routes = Vec::new();
    for (index, subscription) in backend["subscriptions"]
        .as_array()
        .ok_or_else(|| err("subscriptions"))?
        .iter()
        .enumerate()
    {
        let intercept = subscription["mode"] == "intercept";
        let mode = if intercept {
            Mode::Intercept(if subscription["failurePolicy"] == "fail-open" {
                FailurePolicy::Open
            } else {
                FailurePolicy::Closed
            })
        } else {
            Mode::Observe
        };
        let mut events = BTreeSet::new();
        for selector in subscription["events"]
            .as_array()
            .ok_or_else(|| err("events"))?
        {
            let selector = selector.as_str().ok_or_else(|| err("event selector"))?;
            let matched: Vec<_> = grants
                .iter()
                .filter(|(name, grant)| {
                    matches(selector, name.as_str())
                        && if intercept {
                            grant.get("capabilities").is_some()
                        } else {
                            observes(grant)
                        }
                })
                .map(|(name, _)| *name)
                .collect();
            if matched.is_empty() && !discovered {
                return Err(err(format!(
                    "registration selector {selector} has no explicitly granted mode"
                )));
            }
            events.extend(matched);
        }
        if events.is_empty() {
            continue;
        }
        let timeout = if intercept {
            Duration::from_millis(
                subscription["timeoutMs"]
                    .as_u64()
                    .ok_or_else(|| err("timeoutMs"))?,
            )
        } else {
            observation_timeout
        };
        if timeout.is_zero() {
            return Err(err("subscription timeout must be positive"));
        }
        routes.push(Route {
            id: format!("{id}:{index}"),
            backend_id: id.into(),
            events: events.into_iter().collect(),
            mode,
            timeout,
            configuration: subscription.clone(),
            headers: (backend["transport"]["type"] == "http")
                .then(|| backend["transport"].get("headers").cloned())
                .flatten(),
            backend: Arc::clone(transport),
        });
    }
    Ok(routes)
}

/// JSON-registration harness. Construction validates configuration without
/// network I/O or subprocess spawning. Dispatch is lazy; shutdown is explicit.
pub struct Hooks {
    options: HooksOptions,
    harness: Value,
    /// Admitted routes and server-driven configuration, shared with the
    /// detached discovery task.
    discovery: Arc<Discovery>,
    grants: BTreeMap<generated::EventType, Value>,
    backends: Vec<Arc<dyn ManagedBackend>>,
    budget: Arc<Budget>,
    life: Arc<Lifecycle>,
    next_id: AtomicU64,
    upload_limiter: crate::upload_plan::UploadLimiter,
}
impl Drop for Hooks {
    fn drop(&mut self) {
        self.life.closing.store(true, Ordering::SeqCst);
        self.life.cancel_work();
        self.discovery.cancel();
    }
}
impl Hooks {
    pub fn new(registration: impl Serialize, options: HooksOptions) -> Result<Self, HookError> {
        if options.source.is_empty() || url::Url::parse(&options.source).is_err() {
            return Err(err("source must be an absolute URI"));
        }
        let harness = serde_json::to_value(&options.harness).map_err(err)?;
        crate::canonical::validate("common#harness", &harness).map_err(HookError::new)?;
        if options.observation_timeout.is_zero()
            || options.max_observations == 0
            || options.max_concurrent_uploads == 0
            || options.max_body_bytes == 0
            || options.max_stored_entries == 0
        {
            return Err(err("Hooks bounds must be positive"));
        }
        let (initial, max) = options.configuration_backoff;
        if initial.is_zero() || max < initial {
            return Err(err(
                "configuration backoff must be positive and capped above it",
            ));
        }
        let registration = serde_json::to_value(registration).map_err(err)?;
        crate::canonical::validate("registration", &registration)
            .map_err(|_| HookError::new("invalid registration"))?;
        // Render owned wire data once. Typed declarations are already valid; this
        // does not parse, hydrate, or schema-validate host authority.
        let grants: BTreeMap<generated::EventType, Value> = options
            .capabilities
            .to_wire()
            .into_iter()
            .map(|(name, grant)| {
                (
                    name,
                    serde_json::to_value(grant).expect("typed capability serialization"),
                )
            })
            .collect();
        let mut ids = BTreeSet::new();
        let mut routes = vec![];
        let mut backends = vec![];
        let mut pending = vec![];
        let mut backend_order = Vec::new();
        for backend in registration["hooks"]
            .as_array()
            .ok_or_else(|| err("hooks"))?
        {
            let id = backend["id"].as_str().ok_or_else(|| err("backend id"))?;
            if !ids.insert(id.to_owned()) {
                return Err(err("duplicate backend id"));
            }
            if backend["transport"]["type"] == "http" {
                crate::adapters::registered_headers::parse(backend["transport"].get("headers"))?;
            }
            backend_order.push(id.to_owned());
            let transport = if let Some(custom) = options.backends.get(id) {
                Arc::clone(custom)
            } else {
                match registered::from_registration(backend, &options.backend) {
                    Ok(transport) => transport,
                    Err(error) if backend.get("subscriptions").is_none() => {
                        // Without a provider that could ever be prepared, an auth
                        // failure here (an unresolvable bearer reference or an
                        // unsupported binding) cannot become eligible again.
                        let code = if error.auth_code().is_some() {
                            ConfigurationSkipCode::Unavailable
                        } else {
                            ConfigurationSkipCode::Invalid
                        };
                        if let Some(sink) = &options.configuration_diagnostics {
                            sink(&ConfigurationDiagnostic::new(id, code, error.auth_code()));
                        }
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            };
            if backend.get("subscriptions").is_some() {
                routes.extend(routes_for(
                    backend,
                    &transport,
                    &grants,
                    options.observation_timeout,
                    false,
                )?);
            } else {
                let endpoint = (backend["transport"]["type"] == "http")
                    .then(|| backend["transport"]["url"].as_str())
                    .flatten()
                    .map(|url| crate::adapters::registered::AuthContext {
                        backend_id: id.into(),
                        authentication: backend.get("authentication").cloned(),
                        destination: url.into(),
                        purpose: crate::adapters::registered::AuthPurpose::Event,
                        deadline: Instant::now(),
                    });
                pending.push(PendingBackend {
                    id: id.into(),
                    backend: backend.clone(),
                    transport: Arc::clone(&transport),
                    endpoint,
                    prepared: 0,
                    retry_at: None,
                    delay: initial,
                });
            }
            backends.push(transport);
        }
        let budget = Budget::new(options.max_stored_bytes, options.max_stored_entries);
        let life = Arc::new(Lifecycle::default());
        let discovery = Arc::new(Discovery {
            routes: Mutex::new(Arc::new(routes)),
            initialized: AtomicBool::new(false),
            pending: Mutex::new(pending),
            task: Mutex::new(None),
            backend_order,
            grants: grants.clone(),
            observation_timeout: options.observation_timeout,
            backoff: options.configuration_backoff,
            sink: options.configuration_diagnostics.clone(),
            auth_provider: options.backend.auth_provider.clone(),
            life: Arc::clone(&life),
            next_id: AtomicU64::new(0),
        });
        Ok(Self {
            upload_limiter: crate::upload_plan::UploadLimiter::new(options.max_concurrent_uploads),
            options,
            harness,
            discovery,
            grants,
            backends,
            budget,
            life,
            next_id: AtomicU64::new(0),
        })
    }
    /// The current admitted routes; an event uses one snapshot throughout.
    fn routes(&self) -> Arc<Vec<Route>> {
        self.discovery.routes()
    }

    /// Resolve backend defaults without creating an executor or worker.
    /// Explicit subscriptions never perform discovery. Awaited event delivery
    /// waits for the first initialization; hosts may await it before
    /// inspecting interest.
    ///
    /// Every skipped backend is reported to
    /// [`HooksOptions::on_configuration_skipped`]. A backend skipped with
    /// [`ConfigurationSkipCode::Unavailable`] is re-attempted at the next
    /// event admission or `initialize`, once a host `prepare` for its event
    /// endpoint succeeded or its backoff elapsed. Discovery is one shared task
    /// bounded by `observation_timeout` per backend, never by a caller: dropping
    /// a caller does not cancel it, and a later caller continues it. It is
    /// driven by a Tokio task when a Tokio runtime is current, and otherwise by
    /// whoever polls `initialize` or admits an event. `initialize` waits for
    /// it; event admission waits only for the first initialization and
    /// otherwise uses the current routes. A successful re-attempt installs the
    /// backend's routes at once; earlier events are not replayed to it.
    pub async fn initialize(&self) -> Result<(), HookError> {
        let _active = self.life.begin()?;
        self.discovery.start();
        poll_fn(|cx| self.discovery.poll(Some(cx.waker()))).await;
        self.check_open()
    }
    /// Event admission: the first initialization is awaited; a re-attempt is
    /// started or advanced without waiting.
    async fn admit(&self) -> Result<(), HookError> {
        self.discovery.start();
        if self.discovery.initialized.load(Ordering::SeqCst) {
            let _ = self.discovery.poll(None);
            return Ok(());
        }
        poll_fn(|cx| self.discovery.poll(Some(cx.waker()))).await;
        self.check_open()
    }
    fn check_open(&self) -> Result<(), HookError> {
        if self.life.closing.load(Ordering::SeqCst) {
            return Err(err("configuration initialization cancelled by shutdown")
                .classified(generated::DeliveryDiagnosticCode::Cancelled));
        }
        Ok(())
    }

    /// Static subscription interest for a canonical event.
    /// Includes interception and observation routes eligible under host grants.
    /// Payload-dependent filters are not evaluated, so true is not permission
    /// or a guarantee of delivery. This lookup performs no input preparation,
    /// transport, authentication, uploads, or mutation. Before initialization,
    /// backend-provided defaults have not yet contributed subscription interest.
    pub fn subscribes(&self, event: generated::EventType) -> bool {
        let Some(grant) = self.grants.get(&event) else {
            return false;
        };
        self.routes().iter().any(|route| {
            route.events.contains(&event)
                && match route.mode {
                    Mode::Intercept(_) => grant.get("capabilities").is_some(),
                    Mode::Observe => observes(grant),
                }
        })
    }

    /// Whether any interception route the host granted selects `event`.
    /// Payload-dependent filters are not evaluated.
    pub fn intercepts(&self, event: generated::EventType) -> bool {
        let Some(grant) = self.grants.get(&event) else {
            return false;
        };
        grant.get("capabilities").is_some()
            && self.routes().iter().any(|route| {
                route.events.contains(&event) && matches!(route.mode, Mode::Intercept(_))
            })
    }

    pub fn event<T: Serialize>(&self, event: T) -> EventBoundary<'_, T> {
        EventBoundary {
            hooks: self,
            event,
            name: None,
            settings: Settings::default(),
        }
    }
    pub fn event_for<T: Serialize>(
        &self,
        name: generated::EventType,
        event: T,
    ) -> EventBoundary<'_, T> {
        EventBoundary {
            hooks: self,
            event,
            name: Some(name),
            settings: Settings::default(),
        }
    }
    /// Generated named methods defer consuming host projection until await.
    #[doc(hidden)]
    pub(crate) fn host_input_for<
        T: generated::inputs::__support::ProjectHostInput<crate::Attachment>,
    >(
        &self,
        name: generated::EventType,
        input: T,
    ) -> InputBoundary<'_, T> {
        InputBoundary {
            hooks: self,
            input,
            name,
            settings: Settings::default(),
        }
    }
    /// Typed host facts. Projection and serialization are deferred until await.
    pub fn tool_before<T: Serialize + DeserializeOwned>(
        &self,
        input: impl Into<ToolHostInput<T>>,
    ) -> ToolBoundary<'_, T> {
        ToolBoundary {
            result: None,
            provenance: None,
            hooks: self,
            input: input.into().0,
            context: json!({}),
            settings: Settings::default(),
        }
    }
    /// Return the complete canonical event for typed tool facts and owned parts.
    pub fn tool_before_event<
        I: generated::inputs::__support::ProjectHostInput<crate::Attachment>,
    >(
        &self,
        input: I,
    ) -> InputBoundary<'_, I> {
        self.host_input_for(generated::EventType::ToolBefore, input)
    }
    /// Advanced application-input API; provide canonical context with `.context(...)`.
    pub fn tool_input<T: Serialize + DeserializeOwned>(&self, input: T) -> ToolBoundary<'_, T> {
        ToolBoundary {
            result: None,
            provenance: None,
            hooks: self,
            input: ToolInput::Raw(input),
            context: json!({}),
            settings: Settings::default(),
        }
    }
    fn prepare(&self, mut event: Value) -> Result<(Value, generated::EventType, Value), HookError> {
        let event_object = event
            .as_object_mut()
            .ok_or_else(|| err("event must be an object"))?;
        if event_object
            .get("source")
            .is_some_and(|s| s != &json!(self.options.source))
        {
            return Err(err("event source differs from configured source"));
        }
        event_object.insert("source".into(), json!(self.options.source));
        if event_object
            .get("harness")
            .is_some_and(|harness| harness != &self.harness)
        {
            return Err(err("event harness differs from configured harness"));
        }
        event_object.insert("harness".into(), self.harness.clone());
        if !event_object.contains_key("time") {
            event_object.insert(
                "time".into(),
                json!(
                    time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .map_err(err)?
                ),
            );
        }
        if !event_object.contains_key("id") {
            let id = self
                .next_id
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
                .map_err(|_| err("event identity exhausted"))?
                + 1;
            event_object.insert(
                "id".into(),
                json!(format!(
                    "ahp-{}-{}-{id}",
                    std::process::id(),
                    time::OffsetDateTime::now_utc().unix_timestamp_nanos()
                )),
            );
        }
        // Complete-event input is an explicit wire boundary; decode unknown names fallibly.
        let name: generated::EventType =
            serde_json::from_value(event["type"].clone()).map_err(err)?;
        if name == generated::EventType::SessionStart {
            let manifest = self.manifest();
            if event
                .get("manifest")
                .is_some_and(|value| value != &manifest)
            {
                return Err(err("event manifest differs from configured manifest"));
            }
            event["manifest"] = manifest;
        }
        let grant = self
            .grants
            .get(&name)
            .ok_or_else(|| err(format!("event not explicitly granted: {}", name.as_str())))?;
        Ok((
            event,
            name,
            grant
                .get("capabilities")
                .cloned()
                .unwrap_or_else(|| json!({"effects": []})),
        ))
    }
    /// Canonical static host declaration used by session.start.
    pub fn manifest(&self) -> Value {
        let events: Vec<_> = self
            .grants
            .iter()
            .map(|(name, grant)| {
                let mut entry = grant.clone();
                entry["event"] = json!(name.as_str());
                entry
            })
            .collect();
        let mut manifest = self.options.manifest_metadata.wire();
        manifest["events"] = json!(events);
        manifest
    }
    async fn plan_uploads(
        &self,
        routes: &[Route],
        event: &Value,
        name: &generated::EventType,
        deadline: Option<Instant>,
        attachments: &InvocationAttachments,
    ) -> Arc<UploadPlans> {
        let _materialization = attachments.planning_reads();
        let limiter = self.upload_limiter.clone();
        let mut jobs: Vec<
            LocalFuture<'static, (String, Result<crate::hooks_content::Receipts, HookError>)>,
        > = Vec::new();
        for route in routes.iter().filter(|route| {
            route.events.contains(name)
                && !filtered(&route.configuration, event)
                && (route.mode != Mode::Observe || observes(&self.grants[name]))
        }) {
            let route = route.clone();
            let id = route.id.clone();
            let event = event.clone();
            let owners = attachments.clone();
            let options = self.options.backend.clone();
            let limiter = limiter.clone();
            let work = Box::pin(async move {
                let now = Instant::now();
                let end = now
                    .checked_add(route.timeout)
                    .ok_or_else(|| err("subscription deadline overflow"))?;
                let end = deadline.map_or(end, |deadline| end.min(deadline));
                let request = json!({"params":{"event":event}});
                let receipts = crate::hooks_content::preupload(
                    request,
                    &route.configuration["content"],
                    route.configuration.get("upload"),
                    route.headers.as_ref(),
                    &owners,
                    &options,
                    &route.backend_id,
                    end,
                    &limiter,
                )
                .await
                .map_err(|e| e.classify_if_unset(generated::DeliveryDiagnosticCode::Preparation))?;
                serde_json::to_value(receipts).map_err(err)
            });
            let owned = self.life.run(work);
            jobs.push(Box::pin(async move {
                let result = owned
                    .await
                    .and_then(|value| serde_json::from_value(value).map_err(err));
                (id, result)
            }));
        }
        Arc::new(
            crate::upload_plan::run_bounded(jobs, self.options.max_concurrent_uploads)
                .await
                .into_iter()
                .collect(),
        )
    }
    fn client(
        &self,
        routes: &[Route],
        event: &Value,
        name: &generated::EventType,
        deadline: Option<Instant>,
        attachments: &InvocationAttachments,
        uploads: &Arc<UploadPlans>,
    ) -> Client {
        routes
            .iter()
            .filter(|route| route.events.contains(name) && !filtered(&route.configuration, event))
            .fold(
                Client::new(ToolContext::new(event.clone())),
                |client, route| {
                    client.with_subscription(Subscription {
                        id: route.id.clone(),
                        events: vec![name.as_str().into()],
                        mode: route.mode,
                        timeout: route.timeout,
                        hook: Box::new(self.route_hook(route, deadline, attachments, uploads)),
                    })
                },
            )
    }
    fn route_hook(
        &self,
        route: &Route,
        deadline: Option<Instant>,
        _attachments: &InvocationAttachments,
        uploads: &Arc<UploadPlans>,
    ) -> RouteHook {
        RouteHook {
            route: route.clone(),
            life: Arc::downgrade(&self.life),
            deadline,
            prepare_only: false,
            uploads: uploads.clone(),
        }
    }
    async fn prepare_observations<'a>(
        &'a self,
        routes: &[Route],
        name: &generated::EventType,
        observations: Vec<crate::client::Observation<'_>>,
        deadline: Option<Instant>,
        attachments: &InvocationAttachments,
        uploads: &Arc<UploadPlans>,
    ) -> (Vec<PreparedObservation<'a>>, Vec<DeliveryDiagnostic>) {
        let mut prepared = Vec::new();
        let mut diagnostics = vec![];
        if !observes(&self.grants[name]) {
            return (prepared, diagnostics);
        }
        for (index, observation) in observations.into_iter().enumerate() {
            let route = routes
                .iter()
                .find(|r| r.id == observation.subscription_id)
                .expect("owned route");
            if self.life.closing.load(Ordering::SeqCst) {
                break;
            }
            if index >= self.options.max_observations {
                diagnostics.push(
                    route.observation_diagnostic(
                        &err("observation operation limit reached")
                            .classified(generated::DeliveryDiagnosticCode::Capacity),
                    ),
                );
                self.life.failure(ObservationFailure::new(
                    route.id.clone(),
                    "observation operation limit reached",
                    None,
                ));
                continue;
            }
            let mut delivery = Delivery {
                life: &self.life,
                id: route.id.clone(),
                finished: false,
            };
            let started = Instant::now();
            let route_deadline = started
                .checked_add(route.timeout)
                .map(|end| deadline.map_or(end, |deadline| deadline.min(end)));
            let mut hook = self.route_hook(route, route_deadline, attachments, uploads);
            hook.prepare_only = true;
            let result =
                match crate::canonical::validate("observe-notification", &observation.notification)
                {
                    Ok(()) => hook.call(observation.notification).await,
                    Err(e) => Err(HookError::new(e)
                        .classified(generated::DeliveryDiagnosticCode::ProtocolRejection)),
                };
            match result {
                Ok(request) => prepared.push(PreparedObservation {
                    route: route.clone(),
                    request,
                    deadline,
                    remaining: route.timeout.saturating_sub(started.elapsed()),
                    delivery,
                }),
                Err(e) => {
                    delivery.finished = true;
                    diagnostics.push(route.observation_diagnostic(&e));
                    self.life.failure(ObservationFailure::new(
                        route.id.clone(),
                        format!("observation preparation failed ({:?})", e.code()),
                        Some(&e),
                    ));
                }
            }
        }
        (prepared, diagnostics)
    }
    async fn deliver_observations(
        &self,
        observations: Vec<PreparedObservation<'_>>,
    ) -> Vec<DeliveryDiagnostic> {
        let mut diagnostics = Vec::new();
        for mut observation in observations {
            if self.life.closing.load(Ordering::SeqCst) {
                break;
            }
            let route = observation.route;
            let backend = route.backend.clone();
            let request = observation.request;
            let remaining = observation
                .deadline
                .map(|deadline| {
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(observation.remaining)
                })
                .unwrap_or(observation.remaining);
            // The delivery future owns only its projected wire payload and backend.
            // Projection has already borrowed attachments and owns wire payloads.
            let result = self
                .life
                .run(Box::pin(async move {
                    if remaining.is_zero() {
                        return Err(err("observation deadline exceeded")
                            .classified(generated::DeliveryDiagnosticCode::DeadlineExceeded));
                    }
                    backend.call(request, remaining).await
                }))
                .await;
            observation.delivery.finished = true;
            match result {
                Ok(_) => self.life.report.lock().unwrap().delivered += 1,
                Err(e) => {
                    diagnostics.push(route.observation_diagnostic(&e));
                    self.life.failure(ObservationFailure::new(
                        route.id.clone(),
                        format!("observation delivery failed ({:?})", e.code()),
                        Some(&e),
                    ));
                }
            }
        }
        diagnostics
    }
    /// Compatibility waiter: waits for active operations, but never starts work.
    /// Awaiting an operation already awaits all of its selected observations.
    pub async fn wait_until_idle(&self) -> ObservationReport {
        self.life.ready().await;
        self.life.report.lock().unwrap().clone()
    }
    /// Stop admission, cancel owned work, and close
    /// every backend. Suspended caller boundaries need not be polled for cleanup.
    /// Repeated shutdown is safe; cleanup failures can be retried.
    pub async fn shutdown(&self) -> Result<ObservationReport, HookError> {
        self.life.closing.store(true, Ordering::SeqCst);
        self.life.cancel_work();
        self.discovery.cancel();
        poll_fn(|cx| {
            let mut waiters = self.life.waiters.lock().unwrap();
            if !self.life.cleaning.swap(true, Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                    waiters.push(cx.waker().clone());
                }
                Poll::Pending
            }
        })
        .await;
        let _cleanup = Cleanup(&self.life);
        if !self.life.closed.load(Ordering::SeqCst) {
            let mut errors = vec![];
            for backend in &self.backends {
                if let Err(e) = backend.shutdown().await {
                    errors.push(e.to_string());
                }
            }
            if !errors.is_empty() {
                return Err(err(errors.join("; ")));
            }
            self.life.closed.store(true, Ordering::SeqCst);
        }
        Ok(self.life.report.lock().unwrap().clone())
    }
}

#[derive(Default)]
struct Settings<'a> {
    admission: crate::contracts::Admission,
    snapshot: Option<Value>,
    deadline: Option<Instant>,
    budget: Option<LocalFuture<'a, ()>>,
    cancellation: Option<LocalFuture<'a, ()>>,
    initial: Option<Permission>,
    candidate: Option<Value>,
    capabilities: Option<generated::capability::ToolBefore>,
    gates: Option<bool>,
    reauthorization: Option<bool>,
    continuation: Option<(u64, u64, u64)>,
    exchange: Option<&'a Exchange>,
    targets: BTreeMap<String, String>,
    sources: Vec<generated::inputs::__support::ContentSourceBinding<crate::Attachment>>,
}
macro_rules! settings_methods {
    () => {
        /// Declare a caller-owned field codec at an event JSON pointer. Missing
        /// optional fields remain absent; present values are validated in staging.
        pub fn host_contract<HostT>(
            mut self,
            pointer: impl Into<String>,
            contract: crate::contracts::Contract<HostT>,
        ) -> Self {
            self.settings.admission.field(pointer.into(), contract);
            self
        }
        /// Validate every returned candidate before response publication.
        pub fn return_contract<ResultT>(
            mut self,
            contract: crate::contracts::Contract<ResultT>,
        ) -> Self {
            self.settings.admission.result(contract);
            self
        }
        pub fn initial_snapshot(mut self, snapshot: impl Serialize) -> Result<Self, HookError> {
            self.settings.snapshot = Some(serde_json::to_value(snapshot).map_err(err)?);
            self.settings.initial = None;
            self.settings.candidate = None;
            Ok(self)
        }
        /// Supply an absolute deadline and its runtime-native wakeup future.
        /// The same deadline spans preparation, auth, transport and observations.
        pub fn deadline_with(
            mut self,
            deadline: Instant,
            expiry: impl Future<Output = ()> + Send + 'a,
        ) -> Self {
            self.settings.deadline = Some(deadline);
            self.settings.budget = Some(Box::pin(expiry));
            self
        }
        /// Bound the whole operation using a caller-owned timer future. No runtime is required.
        /// Expiry returns an error, never permission to execute. Backend limits may shorten this budget.
        pub fn budget(mut self, expiry: impl Future<Output = ()> + Send + 'a) -> Self {
            self.settings.budget = Some(Box::pin(expiry));
            self
        }
        /// Cancel using a caller-owned signal. Dropping the operation also cancels its owned I/O.
        pub fn cancel_when(mut self, signal: impl Future<Output = ()> + Send + 'a) -> Self {
            self.settings.cancellation = Some(Box::pin(signal));
            self
        }
        pub fn initial_state(mut self, decision: Permission) -> Self {
            self.settings.initial = Some(decision);
            self
        }
        pub fn initial_candidate(mut self, candidate: Value) -> Self {
            self.settings.candidate = Some(candidate);
            self
        }
        pub fn mandatory_gates_passed(mut self, passed: bool) -> Self {
            self.settings.gates = Some(passed);
            self
        }
        pub fn reauthorization_available(mut self, available: bool) -> Self {
            self.settings.reauthorization = Some(available);
            self
        }
    };
}
/// Lazy projection of generated host facts into a canonical event.
#[must_use]
pub struct InputBoundary<'a, T> {
    hooks: &'a Hooks,
    input: T,
    name: generated::EventType,
    settings: Settings<'a>,
}
impl<'a, T> InputBoundary<'a, T> {
    settings_methods!();
    pub fn continuation_budget(mut self, remaining: u64, count: u64, maximum: u64) -> Self {
        self.settings.continuation = Some((remaining, count, maximum));
        self
    }
    pub fn elicitation_exchange(mut self, exchange: &'a Exchange) -> Self {
        self.settings.exchange = Some(exchange);
        self
    }
    /// Map a text/JSON edit target to its owned content slot. Negotiation reads
    /// that attachment when needed; binary editing is not supported.
    pub fn content_target(mut self, target: impl Into<String>, pointer: impl Into<String>) -> Self {
        self.settings.targets.insert(target.into(), pointer.into());
        self
    }
}
impl<'a, T: generated::inputs::__support::ProjectHostInput<crate::Attachment> + Send + 'a>
    IntoFuture for InputBoundary<'a, T>
{
    type Output = Result<EventOutcome, HookError>;
    type IntoFuture = LocalFuture<'a, Self::Output>;
    fn into_future(mut self) -> Self::IntoFuture {
        let budget = self.settings.budget.take();
        let cancellation = self.settings.cancellation.take();
        bounded(
            self.settings.deadline,
            budget,
            cancellation,
            Box::pin(async move {
                if self.hooks.life.closing.load(Ordering::SeqCst) {
                    return Err(err("Hooks is shutting down")
                        .classified(generated::DeliveryDiagnosticCode::Cancelled));
                }
                let (event, sources) = self.input.into_host_event().map_err(err)?;
                self.settings.sources.extend(sources);
                let result = EventBoundary {
                    hooks: self.hooks,
                    event,
                    name: Some(self.name),
                    settings: self.settings,
                }
                .await?;
                Ok(EventOutcome {
                    event: result.event,
                    content: result.content,
                    diagnostics: result.diagnostics,
                    outcome: result.outcome,
                })
            }),
        )
    }
}

/// No serialization, process startup or network work occurs before await.
#[must_use]
pub struct EventBoundary<'a, T> {
    hooks: &'a Hooks,
    event: T,
    name: Option<generated::EventType>,
    settings: Settings<'a>,
}
impl<'a, T> EventBoundary<'a, T> {
    settings_methods!();
    pub fn continuation_budget(mut self, remaining: u64, count: u64, maximum: u64) -> Self {
        self.settings.continuation = Some((remaining, count, maximum));
        self
    }
    pub fn elicitation_exchange(mut self, exchange: &'a Exchange) -> Self {
        self.settings.exchange = Some(exchange);
        self
    }
    /// Map a text/JSON edit target to its owned content slot. Negotiation reads
    /// that attachment when needed; binary editing is not supported.
    pub fn content_target(mut self, target: impl Into<String>, pointer: impl Into<String>) -> Self {
        self.settings.targets.insert(target.into(), pointer.into());
        self
    }
}
pub struct EventOutcome {
    /// Payloads in schema-owned event slots and explicitly declared content targets.
    pub content: OwnedContent,
    pub diagnostics: Vec<DeliveryDiagnostic>,
    pub outcome: ProtocolOutcome,
    /// Complete schema-owned effective event, retaining unknown fields losslessly.
    pub event: generated::Event,
}
impl EventOutcome {
    pub fn permission(&self) -> Permission {
        self.outcome.permission()
    }
}
impl<'a, T: Serialize + Send + 'a> IntoFuture for EventBoundary<'a, T> {
    type Output = Result<EventOutcome, HookError>;
    type IntoFuture = LocalFuture<'a, Self::Output>;
    fn into_future(mut self) -> Self::IntoFuture {
        let budget = self.settings.budget.take();
        let cancellation = self.settings.cancellation.take();
        bounded(
            self.settings.deadline,
            budget,
            cancellation,
            Box::pin(async move {
                let _active = self.hooks.life.begin()?;
                self.hooks.admit().await?;
                // One route snapshot for the whole event.
                let routes = self.hooks.routes();
                let mut event = serde_json::to_value(self.event).map_err(err)?;
                if let Some(expected) = self.name {
                    let object = event
                        .as_object_mut()
                        .ok_or_else(|| err("event must be an object"))?;
                    if object
                        .get("type")
                        .is_some_and(|actual| actual != expected.as_str())
                    {
                        return Err(err("event name mismatch"));
                    }
                    object.insert("type".into(), json!(expected.as_str()));
                }
                let content = InvocationAttachments::bind(
                    &mut event,
                    self.settings.sources,
                    self.hooks.budget.clone(),
                    self.hooks.options.max_body_bytes,
                )
                .map_err(|error| {
                    err(error).classified(generated::DeliveryDiagnosticCode::Preparation)
                })?;
                let (event, name, granted) = self.hooks.prepare(event)?;
                let caps = granted;
                let uploads = self
                    .hooks
                    .plan_uploads(&routes, &event, &name, self.settings.deadline, &content)
                    .await;
                let client = self.hooks.client(
                    &routes,
                    &event,
                    &name,
                    self.settings.deadline,
                    &content,
                    &uploads,
                );
                let mut boundary = client
                    .event(event)
                    .capabilities(caps)
                    .attachments(content.clone())
                    .admission(self.settings.admission);
                if let Some(snapshot) = self.settings.snapshot {
                    boundary = boundary.initial_snapshot(snapshot)?;
                }
                if let Some(initial) = self.settings.initial {
                    boundary = boundary.initial_state(initial);
                }
                if let Some(candidate) = self.settings.candidate {
                    boundary = boundary.initial_candidate(candidate);
                }
                if let Some(gates) = self.settings.gates {
                    boundary = boundary.mandatory_gates_passed(gates);
                }
                if let Some(reauth) = self.settings.reauthorization {
                    boundary = boundary.reauthorization_available(reauth);
                }
                if let Some((remaining, count, maximum)) = self.settings.continuation {
                    boundary = boundary.continuation_budget(remaining, count, maximum);
                }
                if let Some(exchange) = self.settings.exchange {
                    boundary = boundary.elicitation_exchange(exchange);
                }
                for (target, pointer) in &self.settings.targets {
                    boundary = boundary.content_target(target.clone(), pointer.clone());
                }
                let result = boundary.await.map_err(err)?;
                if self.hooks.life.closing.load(Ordering::SeqCst) {
                    return Err(err("Hooks is shutting down")
                        .classified(generated::DeliveryDiagnosticCode::Cancelled));
                }
                let crate::runtime::EventResult {
                    outcome,
                    effective_event,
                    event,
                    observations,
                    mut diagnostics,
                    ..
                } = result;
                for diagnostic in &mut diagnostics {
                    diagnostic.backend_id = routes
                        .iter()
                        .find(|route| route.id == diagnostic.subscription_id)
                        .map(|route| route.backend_id.clone());
                }
                let (observations, preparation_diagnostics) = self
                    .hooks
                    .prepare_observations(
                        &routes,
                        &name,
                        observations,
                        self.settings.deadline,
                        &content,
                        &uploads,
                    )
                    .await;
                diagnostics.extend(preparation_diagnostics);
                let retained = content.finish_for(&effective_event);
                drop(client);
                drop(content);
                diagnostics.extend(self.hooks.deliver_observations(observations).await);
                if self.hooks.life.closing.load(Ordering::SeqCst) {
                    return Err(err("Hooks is shutting down")
                        .classified(generated::DeliveryDiagnosticCode::Cancelled));
                }
                Ok(EventOutcome {
                    content: retained,
                    outcome,
                    diagnostics,
                    event,
                })
            }),
        )
    }
}
/// Consuming typed host facts accepted by `Hooks::tool_before`.
#[doc(hidden)]
pub struct ToolHostInput<T>(ToolInput<T>);
impl<T> From<generated::inputs::ToolBeforeInput<T>> for ToolHostInput<T> {
    fn from(input: generated::inputs::ToolBeforeInput<T>) -> Self {
        Self(ToolInput::Host(Box::new(input)))
    }
}
impl<T> From<generated::inputs::HostInput<generated::inputs::ToolBeforeInput<T>, crate::Attachment>>
    for ToolHostInput<T>
{
    fn from(
        input: generated::inputs::HostInput<
            generated::inputs::ToolBeforeInput<T>,
            crate::Attachment,
        >,
    ) -> Self {
        Self(ToolInput::Owned(Box::new(input)))
    }
}
enum ToolInput<T> {
    Owned(
        Box<generated::inputs::HostInput<generated::inputs::ToolBeforeInput<T>, crate::Attachment>>,
    ),
    Host(Box<generated::inputs::ToolBeforeInput<T>>),
    Raw(T),
}
#[must_use]
pub struct ToolBoundary<'a, T, R = Value, P = Value> {
    result: Option<crate::contracts::Contract<R>>,
    provenance: Option<crate::contracts::Contract<P>>,
    hooks: &'a Hooks,
    input: ToolInput<T>,
    context: Value,
    settings: Settings<'a>,
}
impl<'a, T, R, P> ToolBoundary<'a, T, R, P> {
    settings_methods!();
    pub fn capabilities(mut self, capabilities: generated::capability::ToolBefore) -> Self {
        self.settings.capabilities = Some(capabilities);
        self
    }
    pub fn context(mut self, context: ToolContext) -> Self {
        self.context = context.event;
        self
    }
}
pub struct ToolOutcome<T, R = Value, P = Value> {
    /// Schema-owned returned payloads. Opaque application input, candidates, and
    /// effect values do not confer ownership of reference-shaped data.
    pub content: OwnedContent,
    pub diagnostics: Vec<DeliveryDiagnostic>,
    pub outcome: ProtocolOutcome<R, P>,
    /// Complete schema-owned settled event, retaining opaque host event facts.
    pub event: generated::Event,
    pub input: T,
}
impl<T, R, P> ToolOutcome<T, R, P> {
    pub fn permission(&self) -> Permission {
        self.outcome.permission()
    }
}
fn narrow(
    caps: Option<generated::capability::ToolBefore>,
    granted: Value,
) -> Result<Value, HookError> {
    if let Some(caps) = caps {
        let declaration = serde_json::to_value(caps).map_err(err)?;
        let caps = declaration["capabilities"].clone();
        if caps.is_null() {
            return Err(err("per-occurrence tool capabilities require interception"));
        }
        if !crate::client::subset(&caps, &granted) {
            return Err(err(
                "per-occurrence capabilities may only narrow explicit host grants",
            ));
        }
        Ok(caps)
    } else {
        Ok(granted)
    }
}
impl<'a, T, R, P> IntoFuture for ToolBoundary<'a, T, R, P>
where
    T: Serialize + DeserializeOwned + Send + 'a,
    R: Serialize + DeserializeOwned + Send + 'a,
    P: Serialize + DeserializeOwned + Send + 'a,
{
    type Output = Result<ToolOutcome<T, R, P>, HookError>;
    type IntoFuture = LocalFuture<'a, Self::Output>;
    fn into_future(mut self) -> Self::IntoFuture {
        let budget = self.settings.budget.take();
        let cancellation = self.settings.cancellation.take();
        bounded(
            self.settings.deadline,
            budget,
            cancellation,
            Box::pin(async move {
                let _active = self.hooks.life.begin()?;
                self.hooks.admit().await?;
                // One route snapshot for the whole event.
                let routes = self.hooks.routes();
                let (input, mut context) = match self.input {
                    ToolInput::Host(host) => {
                        let host = *host;
                        let context =
                            generated::inputs::__support::project_event(&host).map_err(err)?;
                        (host.input, context)
                    }
                    ToolInput::Owned(host) => {
                        let (context, sources) = (*host).into_host_event().map_err(err)?;
                        self.settings.sources.extend(sources);
                        let input = serde_json::from_value(context["tool"]["input"].clone())
                            .map_err(err)?;
                        (input, context)
                    }
                    ToolInput::Raw(input) => (input, self.context),
                };
                context
                    .as_object_mut()
                    .ok_or_else(|| err("tool context must be an object"))?
                    .insert("type".into(), json!("tool.before"));
                let content = InvocationAttachments::bind(
                    &mut context,
                    self.settings.sources,
                    self.hooks.budget.clone(),
                    self.hooks.options.max_body_bytes,
                )
                .map_err(|error| {
                    err(error).classified(generated::DeliveryDiagnosticCode::Preparation)
                })?;
                let (context, name, granted) = self.hooks.prepare(context)?;
                let caps = narrow(self.settings.capabilities, granted)?;
                let uploads = self
                    .hooks
                    .plan_uploads(&routes, &context, &name, self.settings.deadline, &content)
                    .await;
                let client = self.hooks.client(
                    &routes,
                    &context,
                    &name,
                    self.settings.deadline,
                    &content,
                    &uploads,
                );
                let mut boundary = client
                    .tool_before(input)
                    .capabilities(caps)
                    .admission(self.settings.admission);
                if let Some(snapshot) = self.settings.snapshot {
                    boundary = boundary.initial_snapshot(snapshot)?;
                }
                if let Some(initial) = self.settings.initial {
                    boundary = boundary.initial_state(initial);
                }
                if let Some(candidate) = self.settings.candidate {
                    boundary = boundary.initial_candidate(candidate);
                }
                if let Some(gates) = self.settings.gates {
                    boundary = boundary.mandatory_gates_passed(gates);
                }
                if let Some(reauth) = self.settings.reauthorization {
                    boundary = boundary.reauthorization_available(reauth);
                }
                let result = boundary.await.map_err(err)?;
                if self.hooks.life.closing.load(Ordering::SeqCst) {
                    return Err(err("Hooks is shutting down")
                        .classified(generated::DeliveryDiagnosticCode::Cancelled));
                }
                let crate::client::BoundaryResult {
                    outcome,
                    raw_outcome,
                    candidate_descriptor,
                    effective_input,
                    event,
                    input,
                    observations,
                    mut diagnostics,
                    ..
                } = result;
                let input = input.map_err(|error| {
                    err(error).with_settlement(
                        &raw_outcome,
                        &effective_input,
                        &candidate_descriptor,
                    )
                })?;
                for diagnostic in &mut diagnostics {
                    diagnostic.backend_id = routes
                        .iter()
                        .find(|route| route.id == diagnostic.subscription_id)
                        .map(|route| route.backend_id.clone());
                }
                let (observations, preparation_diagnostics) = self
                    .hooks
                    .prepare_observations(
                        &routes,
                        &name,
                        observations,
                        self.settings.deadline,
                        &content,
                        &uploads,
                    )
                    .await;
                diagnostics.extend(preparation_diagnostics);
                // Application input and return/injection values are opaque JSON, not
                // event envelopes or schema-owned content-reference locations.
                let retained = content.finish();
                drop(client);
                drop(content);
                diagnostics.extend(self.hooks.deliver_observations(observations).await);
                if self.hooks.life.closing.load(Ordering::SeqCst) {
                    return Err(err("Hooks is shutting down")
                        .classified(generated::DeliveryDiagnosticCode::Cancelled));
                }
                let outcome = outcome.retype::<R, P>().map_err(|error| {
                    error.with_settlement(&raw_outcome, &effective_input, &candidate_descriptor)
                })?;
                Ok(ToolOutcome {
                    content: retained,
                    outcome,
                    diagnostics,
                    event,
                    input,
                })
            }),
        )
    }
}

// Both the named methods and their inventory are generated from the schema catalogue.
pub const NAMED_BOUNDARIES: &[generated::EventType] =
    crate::generated::ahp_hooks_boundary_methods!(inventory);
impl<T: Serialize> generated::inputs::__support::ProjectHostInput<crate::Attachment>
    for generated::inputs::ToolBeforeInput<T>
{
    fn into_host_event(
        self,
    ) -> Result<
        (
            Value,
            Vec<generated::inputs::__support::ContentSourceBinding<crate::Attachment>>,
        ),
        serde_json::Error,
    > {
        Ok((
            generated::inputs::__support::project_event(&self)?,
            Vec::new(),
        ))
    }
}
// Named methods accept either canonical generated facts or direct owned host inputs.
macro_rules! host_methods {
    ($(($method:ident, $input:ident, $name:path)),* $(,)?) => {
        $(impl generated::inputs::__support::ProjectHostInput<crate::Attachment>
            for generated::inputs::$input {
            fn into_host_event(self) -> Result<(Value, Vec<generated::inputs::__support::ContentSourceBinding<crate::Attachment>>), serde_json::Error> {
                Ok((generated::inputs::__support::project_event(&self)?, Vec::new()))
            }
        })*
        impl Hooks {
            $(pub fn $method<I: generated::inputs::__support::ProjectHostInput<crate::Attachment>>(&self, input: I) -> InputBoundary<'_, I> {
                self.host_input_for($name, input)
            })*
        }
    };
}
host_methods! {
    (config_change_after, ConfigChangeAfterInput, generated::EventType::ConfigChangeAfter),
    (config_change_before, ConfigChangeBeforeInput, generated::EventType::ConfigChangeBefore),
    (context_compact_after, ContextCompactAfterInput, generated::EventType::ContextCompactAfter),
    (context_compact_before, ContextCompactBeforeInput, generated::EventType::ContextCompactBefore),
    (file_changed, FileChangedInput, generated::EventType::FileChanged),
    (hook_failure, HookFailureInput, generated::EventType::HookFailure),
    (model_error, ModelErrorInput, generated::EventType::ModelError),
    (model_request_before, ModelRequestBeforeInput, generated::EventType::ModelRequestBefore),
    (model_response_after, ModelResponseAfterInput, generated::EventType::ModelResponseAfter),
    (model_switch_after, ModelSwitchAfterInput, generated::EventType::ModelSwitchAfter),
    (model_switch_before, ModelSwitchBeforeInput, generated::EventType::ModelSwitchBefore),
    (session_end, SessionEndInput, generated::EventType::SessionEnd),
    (session_start, SessionStartInput, generated::EventType::SessionStart),
    (task_change_after, TaskChangeAfterInput, generated::EventType::TaskChangeAfter),
    (task_change_before, TaskChangeBeforeInput, generated::EventType::TaskChangeBefore),
    (tool_batch_after, ToolBatchAfterInput, generated::EventType::ToolBatchAfter),
    (turn_end, TurnEndInput, generated::EventType::TurnEnd),
    (turn_finish_before, TurnFinishBeforeInput, generated::EventType::TurnFinishBefore),
    (turn_progress, TurnProgressInput, generated::EventType::TurnProgress),
    (turn_start, TurnStartInput, generated::EventType::TurnStart),
    (user_attention, UserAttentionInput, generated::EventType::UserAttention),
    (user_elicitation_request, UserElicitationRequestInput, generated::EventType::UserElicitationRequest),
    (user_elicitation_result, UserElicitationResultInput, generated::EventType::UserElicitationResult),
    (user_message_inbound, UserMessageInboundInput, generated::EventType::UserMessageInbound),
    (user_message_outbound, UserMessageOutboundInput, generated::EventType::UserMessageOutbound),
    (workspace_change_after, WorkspaceChangeAfterInput, generated::EventType::WorkspaceChangeAfter),
    (workspace_change_before, WorkspaceChangeBeforeInput, generated::EventType::WorkspaceChangeBefore),
}

// Tool facts retain caller-owned arguments while the event envelope is SDK-owned.
macro_rules! generic_host_methods {
    ($(($method:ident, $input:ident, $name:path)),* $(,)?) => {
        $(impl<T: Serialize> generated::inputs::__support::ProjectHostInput<crate::Attachment>
            for generated::inputs::$input<T> {
            fn into_host_event(self) -> Result<(Value, Vec<generated::inputs::__support::ContentSourceBinding<crate::Attachment>>), serde_json::Error> {
                Ok((generated::inputs::__support::project_event(&self)?, Vec::new()))
            }
        })*
        impl Hooks {
            $(pub fn $method<I: generated::inputs::__support::ProjectHostInput<crate::Attachment>>(&self, input: I) -> InputBoundary<'_, I> {
                self.host_input_for($name, input)
            })*
        }
    };
}
generic_host_methods! {
    (tool_after, ToolAfterInput, generated::EventType::ToolAfter),
    (tool_permission_request, ToolPermissionRequestInput, generated::EventType::ToolPermissionRequest),
    (tool_permission_resolved, ToolPermissionResolvedInput, generated::EventType::ToolPermissionResolved),
    (tool_progress, ToolProgressInput, generated::EventType::ToolProgress),
}

fn bounded<'a, T: Send + 'a>(
    deadline: Option<Instant>,
    mut budget: Option<LocalFuture<'a, ()>>,
    mut cancellation: Option<LocalFuture<'a, ()>>,
    operation: LocalFuture<'a, Result<T, HookError>>,
) -> LocalFuture<'a, Result<T, HookError>> {
    let mut operation = Some(operation);
    Box::pin(poll_fn(move |cx| {
        if cancellation
            .as_mut()
            .is_some_and(|signal| signal.as_mut().poll(cx).is_ready())
        {
            operation.take();
            return Poll::Ready(Err(err("hook operation cancelled by caller")
                .classified(generated::DeliveryDiagnosticCode::Cancelled)));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline)
            || budget
                .as_mut()
                .is_some_and(|signal| signal.as_mut().poll(cx).is_ready())
        {
            operation.take();
            return Poll::Ready(Err(err("hook operation budget exceeded")
                .classified(generated::DeliveryDiagnosticCode::DeadlineExceeded)));
        }
        let result = operation
            .as_mut()
            .expect("operation polled after completion")
            .as_mut()
            .poll(cx);
        // Synchronous preparation or a ready backend can consume the remaining budget
        // or trigger a signal within one poll. Never expose interruption as permission.
        if cancellation
            .as_mut()
            .is_some_and(|signal| signal.as_mut().poll(cx).is_ready())
        {
            operation.take();
            return Poll::Ready(Err(err("hook operation cancelled by caller")
                .classified(generated::DeliveryDiagnosticCode::Cancelled)));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline)
            || budget
                .as_mut()
                .is_some_and(|signal| signal.as_mut().poll(cx).is_ready())
        {
            operation.take();
            return Poll::Ready(Err(err("hook operation budget exceeded")
                .classified(generated::DeliveryDiagnosticCode::DeadlineExceeded)));
        }
        if result.is_ready() {
            operation.take();
        }
        result
    }))
}

impl<'a, A: Serialize + DeserializeOwned, R, P> ToolBoundary<'a, A, R, P> {
    /// Declare argument decoding and optional host invariants before publication.
    pub fn arguments_contract(mut self, contract: crate::contracts::Contract<A>) -> Self {
        self.settings
            .admission
            .field("/tool/input".into(), contract);
        self
    }
    pub fn declare_arguments(self) -> Self {
        self.arguments_contract(crate::contracts::Contract::new())
    }
    /// Declare the tool's result type, independently of its argument type.
    pub fn result_type<Next: Serialize + DeserializeOwned>(self) -> ToolBoundary<'a, A, Next, P> {
        self.result_contract(crate::contracts::Contract::new())
    }
    pub fn result_contract<Next: Serialize + DeserializeOwned>(
        mut self,
        contract: crate::contracts::Contract<Next>,
    ) -> ToolBoundary<'a, A, Next, P> {
        self.settings
            .admission
            .field_default("/tool/input".into(), crate::contracts::Contract::<A>::new());
        self.settings.admission.result(contract.clone());
        ToolBoundary {
            hooks: self.hooks,
            input: self.input,
            context: self.context,
            settings: self.settings,
            result: Some(contract),
            provenance: self.provenance,
        }
    }
    /// Optional caller-owned provenance remains associated only with its candidate.
    pub fn provenance_type<Next: Serialize + DeserializeOwned>(
        self,
    ) -> ToolBoundary<'a, A, R, Next> {
        self.provenance_contract(crate::contracts::Contract::new())
    }
    pub fn provenance_contract<Next: Serialize + DeserializeOwned>(
        mut self,
        contract: crate::contracts::Contract<Next>,
    ) -> ToolBoundary<'a, A, R, Next> {
        self.settings.admission.provenance(contract.clone());
        ToolBoundary {
            hooks: self.hooks,
            input: self.input,
            context: self.context,
            settings: self.settings,
            result: self.result,
            provenance: Some(contract),
        }
    }
}

#[cfg(test)]
pub(crate) mod configuration_tests;
