//! Primary registration-driven harness. Configuration is ordinary serde JSON;
//! applications retain execution policy. No transport starts before dispatch.
use crate::{
    adapters::registered::{self, BackendOptions, ManagedBackend},
    body::{Body, BodyError, DeferredBodies},
    client::{
        Client, Decision, DeliveryDiagnostic, DeliveryStage, FailurePolicy, Hook, HookError,
        InputDecodeError, LocalFuture, Mode, ProtocolOutcome, Subscription, ToolContext,
    },
    content::{AuthorizedScope, ContentContext, MemoryContentStore},
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

/// Explicit effect/operation grants. No constructor infers elicitation modes.
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct Capabilities(Value);
impl Default for Capabilities {
    fn default() -> Self {
        Self::none()
    }
}
impl Capabilities {
    pub fn none() -> Self {
        Self(json!({"effects":[]}))
    }
    /// Accept generated capability models or ordinary JSON; canonical validation
    /// runs here and event-specific validation runs in Hooks::new.
    pub fn from_value(value: impl Serialize) -> Result<Self, HookError> {
        let value = serde_json::to_value(value).map_err(err)?;
        crate::canonical::validate("capabilities", &value).map_err(HookError)?;
        Ok(Self(value))
    }
    fn effect(mut self, name: &str) -> Self {
        let effects = self.0["effects"]
            .as_array_mut()
            .expect("capabilities effects");
        if !effects.contains(&json!(name)) {
            effects.push(json!(name));
        }
        self
    }
    pub fn allow(self) -> Self {
        self.effect("allow")
    }
    pub fn deny(self) -> Self {
        self.effect("deny")
    }
    pub fn ask(self) -> Self {
        self.effect("ask")
    }
    pub fn message(self) -> Self {
        self.effect("message")
    }
    pub fn return_value(self) -> Self {
        self.effect("return")
    }
    pub fn modify(mut self, target: &str, replace: bool, merge: bool) -> Self {
        self = self.effect("modify");
        if self.0.get("modify").is_none() {
            self.0["modify"] = json!({});
        }
        self.0["modify"][target] = json!({"replace":replace,"merge":merge});
        self
    }
    pub fn modify_input(self) -> Self {
        self.modify("input", true, true)
    }
    pub fn elicitation_form(mut self) -> Self {
        if self.0.get("elicitation").is_none() {
            self.0["elicitation"] = json!({});
        }
        self.0["elicitation"]["form"] = json!({});
        self
    }
    pub fn elicitation_url(mut self) -> Self {
        if self.0.get("elicitation").is_none() {
            self.0["elicitation"] = json!({});
        }
        self.0["elicitation"]["url"] = json!({});
        self
    }
    pub fn flow_stop(mut self) -> Self {
        self = self.effect("flow");
        self.0["flow"] = json!({"operations":["stop"]});
        self
    }
    pub fn as_value(&self) -> &Value {
        &self.0
    }
}
/// A missing entry grants neither mode. The interception convenience grants both;
/// exact independent mode declarations are preserved by `HooksOptions::from_manifest`.
#[derive(Clone, Debug)]
pub struct EventGrant {
    intercept: Option<Capabilities>,
    observe: bool,
}
impl EventGrant {
    /// Admit a generated capability declaration without inferring omitted modes.
    pub fn from_declaration(declaration: impl Serialize) -> Result<Self, HookError> {
        let value = serde_json::to_value(declaration).map_err(err)?;
        let modes = value["modes"]
            .as_array()
            .ok_or_else(|| err("declaration requires modes"))?;
        if modes.is_empty()
            || modes
                .iter()
                .any(|mode| mode != "intercept" && mode != "observe")
            || modes
                .iter()
                .map(Value::as_str)
                .collect::<BTreeSet<_>>()
                .len()
                != modes.len()
        {
            return Err(err("invalid declaration modes"));
        }
        let intercept = modes.contains(&json!("intercept"));
        let capabilities = value.get("capabilities");
        if intercept != capabilities.is_some() {
            return Err(err(
                "interception mode requires exactly its capability block",
            ));
        }
        Ok(Self {
            intercept: capabilities.map(Capabilities::from_value).transpose()?,
            observe: modes.contains(&json!("observe")),
        })
    }
    /// Grant interception and observation together.
    pub fn intercept(capabilities: Capabilities) -> Self {
        Self {
            intercept: Some(capabilities),
            observe: true,
        }
    }
    pub fn observe() -> Self {
        Self {
            intercept: None,
            observe: true,
        }
    }
    pub fn with_observe(mut self) -> Self {
        self.observe = true;
        self
    }
}
pub type EventCapabilities = BTreeMap<String, EventGrant>;

/// Host authority, not registration data. Ordinary callers supply a source and
/// explicit per-event grants; registration still owns routing and transport.
pub struct HooksOptions {
    pub source: String,
    pub capabilities: EventCapabilities,
    pub backend: BackendOptions,
    pub observation_timeout: Duration,
    pub max_observations: usize,
    manifest: Option<Value>,
    pub max_body_bytes: usize,
    pub max_stored_bytes: usize,
    pub max_stored_entries: usize,
    backends: BTreeMap<String, Arc<dyn ManagedBackend>>,
}
impl HooksOptions {
    /// Compose generated event keys and immutable declarations into host authority.
    /// Boundary-specific admission still occurs in `Hooks::new` before delivery.
    pub fn from_declarations<K: Serialize, D: Serialize>(
        source: impl Into<String>,
        declarations: impl IntoIterator<Item = (K, D)>,
    ) -> Result<Self, HookError> {
        let mut grants = BTreeMap::new();
        for (event, declaration) in declarations {
            let event = serde_json::to_value(event).map_err(err)?;
            let name = event
                .as_str()
                .ok_or_else(|| err("event key must be a canonical string"))?;
            if grants
                .insert(name.to_owned(), EventGrant::from_declaration(declaration)?)
                .is_some()
            {
                return Err(err("duplicate event declaration"));
            }
        }
        Ok(Self::new(source, grants))
    }
    pub fn new(source: impl Into<String>, capabilities: EventCapabilities) -> Self {
        Self {
            source: source.into(),
            capabilities,
            backend: BackendOptions::default(),
            observation_timeout: Duration::from_secs(30),
            max_observations: 1024,
            manifest: None,
            max_body_bytes: 4 * 1024 * 1024,
            max_stored_bytes: 64 * 1024 * 1024,
            max_stored_entries: 4096,
            backends: BTreeMap::new(),
        }
    }
    /// Optional low-level escape hatch for a host-owned neutral transport.
    /// Built-in HTTP/process transports need no callback or factory from callers.
    pub fn with_backend(mut self, id: impl Into<String>, backend: Arc<dyn ManagedBackend>) -> Self {
        self.backends.insert(id.into(), backend);
        self
    }
    /// Alternative to the event map, using a complete generated manifest.
    pub fn from_manifest(
        source: impl Into<String>,
        manifest: generated::StaticCapabilityManifest,
    ) -> Result<Self, HookError> {
        let manifest = serde_json::to_value(manifest).map_err(err)?;
        crate::canonical::validate("capabilities-response", &json!({"jsonrpc":"2.0","id":"manifest","result":{"protocolVersion":"draft","manifest":manifest}})).map_err(HookError)?;
        let mut grants = BTreeMap::new();
        for entry in manifest["events"]
            .as_array()
            .ok_or_else(|| err("manifest events"))?
        {
            let name = entry["event"]
                .as_str()
                .ok_or_else(|| err("manifest event"))?;
            let modes = entry["modes"]
                .as_array()
                .ok_or_else(|| err("manifest modes"))?;
            let intercept = if modes.contains(&json!("intercept")) {
                Some(Capabilities::from_value(
                    entry
                        .get("capabilities")
                        .ok_or_else(|| err("interception requires explicit capabilities"))?,
                )?)
            } else {
                None
            };
            if grants
                .insert(
                    name.into(),
                    EventGrant {
                        intercept,
                        observe: modes.contains(&json!("observe")),
                    },
                )
                .is_some()
            {
                return Err(err("duplicate manifest event"));
            }
        }
        let mut options = Self::new(source, grants);
        options.manifest = Some(manifest);
        Ok(options)
    }
}
#[derive(Clone)]
struct Route {
    id: String,
    backend_id: String,
    events: Vec<String>,
    mode: Mode,
    timeout: Duration,
    configuration: Value,
    backend: Arc<dyn ManagedBackend>,
}
impl Route {
    fn observation_diagnostic(
        &self,
        code: generated::DeliveryDiagnosticCode,
    ) -> DeliveryDiagnostic {
        DeliveryDiagnostic {
            code,
            stage: DeliveryStage::Observe,
            subscription_id: self.id.clone(),
            backend_id: Some(self.backend_id.clone()),
            policy: None,
            synthetic_denial: false,
        }
    }
}
#[derive(Clone)]
struct RouteHook {
    route: Route,
    store: MemoryContentStore,
    options: BackendOptions,
    bodies: DeferredBodies,
    life: Weak<Lifecycle>,
    deadline: Option<Instant>,
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
            // This store is owned by this Hooks instance. Scope is an explicit
            // local host policy, never derived from source/event/reference IDs.
            let context = ContentContext {
                store: &owned.store,
                scope: local_scope(),
            };
            request = crate::hooks_content::project_with_bodies(
                request,
                &owned.route.configuration["content"],
                owned.route.configuration.get("upload"),
                &context,
                &owned.options,
                &owned.bodies,
                &owned.route.backend_id,
                start
                    .checked_add(timeout)
                    .ok_or_else(|| err("subscription deadline overflow"))?,
            )
            .await
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
            let response = owned.route.backend.call(request.clone(), remaining).await?;
            if request["method"] == "hooks/intercept" {
                crate::client::check_rpc_error(&response, &request["id"])?;
                crate::hooks_content::validate_response_grants(&request, &response).map_err(
                    |error| error.classified(generated::DeliveryDiagnosticCode::ProtocolRejection),
                )?;
            }
            Ok(response)
        });
        match self.life.upgrade() {
            Some(life) => life.run(work),
            None => Box::pin(async { Err(err("Hooks has been dropped")) }),
        }
    }
}
fn local_scope() -> AuthorizedScope {
    AuthorizedScope::new("explicit-hooks-local-store")
}
fn err(value: impl std::fmt::Display) -> HookError {
    HookError(value.to_string())
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
pub struct ObservationFailure {
    pub subscription_id: String,
    pub error: String,
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
struct Delivery<'a> {
    life: &'a Lifecycle,
    id: String,
    finished: bool,
}
impl Drop for Delivery<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.life.failure(ObservationFailure {
                subscription_id: self.id.clone(),
                error: "observation delivery cancelled; not retried".into(),
            });
        }
    }
}

/// JSON-registration harness. Construction validates configuration without
/// network I/O or subprocess spawning. Dispatch is lazy; shutdown is explicit.
pub struct Hooks {
    options: HooksOptions,
    routes: Vec<Route>,
    backends: Vec<Arc<dyn ManagedBackend>>,
    store: MemoryContentStore,
    bodies: DeferredBodies,
    life: Arc<Lifecycle>,
    next_id: AtomicU64,
}
impl Hooks {
    pub fn new(registration: impl Serialize, options: HooksOptions) -> Result<Self, HookError> {
        if options.source.is_empty() || url::Url::parse(&options.source).is_err() {
            return Err(err("source must be an absolute URI"));
        }
        if options.observation_timeout.is_zero()
            || options.max_observations == 0
            || options.max_body_bytes == 0
            || options.max_stored_entries == 0
        {
            return Err(err("Hooks bounds must be positive"));
        }
        let registration = serde_json::to_value(registration).map_err(err)?;
        crate::canonical::validate("registration", &registration).map_err(HookError)?;
        for (name, grant) in &options.capabilities {
            let descriptor = generated::boundary::ALL_BOUNDARIES
                .iter()
                .find(|b| b.name == name)
                .ok_or_else(|| err(format!("unknown event grant: {name}")))?;
            if let Some(caps) = &grant.intercept {
                let schema = descriptor
                    .capability_schema
                    .ok_or_else(|| err(format!("{name} is observation-only")))?;
                crate::canonical::validate(schema, &caps.0).map_err(HookError)?;
            }
        }
        let mut ids = BTreeSet::new();
        let mut routes = vec![];
        let mut backends = vec![];
        for backend in registration["hooks"]
            .as_array()
            .ok_or_else(|| err("hooks"))?
        {
            let id = backend["id"].as_str().ok_or_else(|| err("backend id"))?;
            if !ids.insert(id.to_owned()) {
                return Err(err("duplicate backend id"));
            }
            let transport = if let Some(custom) = options.backends.get(id) {
                Arc::clone(custom)
            } else {
                registered::from_registration(backend, &options.backend)?
            };
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
                    let matched: Vec<_> = options
                        .capabilities
                        .iter()
                        .filter(|(name, grant)| {
                            matches(selector, name)
                                && if intercept {
                                    grant.intercept.is_some()
                                } else {
                                    grant.observe
                                }
                        })
                        .map(|(name, _)| name.clone())
                        .collect();
                    if matched.is_empty() {
                        return Err(err(format!(
                            "registration selector {selector} has no explicitly granted mode"
                        )));
                    }
                    events.extend(matched);
                }
                let timeout = if intercept {
                    Duration::from_millis(
                        subscription["timeoutMs"]
                            .as_u64()
                            .ok_or_else(|| err("timeoutMs"))?,
                    )
                } else {
                    options.observation_timeout
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
                    backend: Arc::clone(&transport),
                });
            }
            backends.push(transport);
        }
        let bodies = DeferredBodies::new(options.max_body_bytes, options.max_stored_entries);
        let store = MemoryContentStore::new(
            options.max_body_bytes,
            options.max_stored_bytes,
            options.max_stored_entries,
        );
        Ok(Self {
            options,
            routes,
            backends,
            store,
            bodies,
            life: Arc::new(Lifecycle::default()),
            next_id: AtomicU64::new(0),
        })
    }
    pub fn event<T: Serialize + DeserializeOwned>(&self, event: T) -> EventBoundary<'_, T> {
        EventBoundary {
            hooks: self,
            event,
            name: None,
            settings: Settings::default(),
        }
    }
    pub fn event_for<T: Serialize + DeserializeOwned>(
        &self,
        name: &'static str,
        event: T,
    ) -> EventBoundary<'_, T> {
        EventBoundary {
            hooks: self,
            event,
            name: Some(name),
            settings: Settings::default(),
        }
    }
    /// Generated named methods use this lazy projection adapter.
    pub fn input_for<T>(
        &self,
        name: &'static str,
        input: T,
        project: fn(&T) -> Result<Value, serde_json::Error>,
    ) -> InputBoundary<'_, T> {
        InputBoundary {
            hooks: self,
            input,
            name,
            project,
            settings: Settings::default(),
        }
    }
    /// Typed host facts. Projection and serialization are deferred until await.
    pub fn tool_before<T: Serialize + DeserializeOwned>(
        &self,
        input: generated::ergonomic_inputs::ToolBeforeInput<T>,
    ) -> ToolBoundary<'_, T> {
        ToolBoundary {
            hooks: self,
            input: ToolInput::Host(Box::new(input)),
            context: json!({}),
            settings: Settings::default(),
        }
    }
    /// Advanced application-input API; provide canonical context with `.context(...)`.
    pub fn tool_input<T: Serialize + DeserializeOwned>(&self, input: T) -> ToolBoundary<'_, T> {
        ToolBoundary {
            hooks: self,
            input: ToolInput::Raw(input),
            context: json!({}),
            settings: Settings::default(),
        }
    }
    pub fn content_context(&self) -> ContentContext<'_> {
        ContentContext {
            store: &self.store,
            scope: local_scope(),
        }
    }
    /// Own a lazy body without polling it. Only a selected body route reads it.
    /// The returned local handle must remain in a content-item body field.
    pub async fn stage_body(&self, body: Body) -> Result<Value, BodyError> {
        let _active = self
            .life
            .begin()
            .map_err(|e| BodyError::Read(e.to_string()))?;
        self.bodies.register(body)
    }
    fn bind_sources(
        &self,
        event: &mut Value,
        sources: Vec<generated::ergonomic_inputs::ContentSourceBinding<Body>>,
    ) -> Result<Vec<crate::body::DeferredBodyGuard>, HookError> {
        let mut guards = Vec::with_capacity(sources.len());
        let mut seen = BTreeSet::new();
        for binding in sources {
            let pointer = format!(
                "/{}",
                binding
                    .path
                    .iter()
                    .map(|part| part.replace('~', "~0").replace('/', "~1"))
                    .collect::<Vec<_>>()
                    .join("/")
            );
            if !seen.insert(pointer.clone()) {
                return Err(err("duplicate body source binding")
                    .classified(generated::DeliveryDiagnosticCode::Preparation));
            }
            let item = event
                .pointer_mut(&pointer)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| {
                    err("body source slot requires a content item")
                        .classified(generated::DeliveryDiagnosticCode::Preparation)
                })?;
            let reference = self
                .bodies
                .register(binding.source)
                .map_err(|e| err(e).classified(generated::DeliveryDiagnosticCode::Preparation))?;
            guards.push(self.bodies.guard(&reference));
            item.insert("selection".into(), json!("body"));
            item.insert("body".into(), reference);
        }
        Ok(guards)
    }
    fn prepare(&self, mut event: Value) -> Result<(Value, String, Capabilities), HookError> {
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
        let name = event["type"]
            .as_str()
            .ok_or_else(|| err("missing event type"))?
            .to_owned();
        if name == "session.start" {
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
            .options
            .capabilities
            .get(&name)
            .ok_or_else(|| err(format!("event not explicitly granted: {name}")))?;
        Ok((
            event,
            name,
            grant.intercept.clone().unwrap_or_else(Capabilities::none),
        ))
    }
    /// Canonical static host declaration used by session.start.
    pub fn manifest(&self) -> Value {
        self.options.manifest.clone().unwrap_or_else(|| {
            let events: Vec<_> = self
                .options
                .capabilities
                .iter()
                .map(|(name, grant)| {
                    let mut modes = Vec::new();
                    let mut entry = json!({"event":name});
                    if let Some(caps) = &grant.intercept {
                        modes.push("intercept");
                        entry["capabilities"] = caps.0.clone();
                    }
                    if grant.observe {
                        modes.push("observe");
                    }
                    entry["modes"] = json!(modes);
                    entry
                })
                .collect();
            json!({"events":events,"gaps":[],"transports":["in_process"],
                "authentication":[],"toolPaths":[],"contentCategories":[],
                "limits":{},"managedPolicy":{"scopes":[],"disableable":true},
                "correlationIdentityFields":[]})
        })
    }
    fn client(&self, event: &Value, name: &str, deadline: Option<Instant>) -> Client {
        self.routes
            .iter()
            .filter(|route| {
                route.events.iter().any(|e| e == name) && !filtered(&route.configuration, event)
            })
            .fold(
                Client::new(ToolContext::new(event.clone())),
                |client, route| {
                    client.with_subscription(Subscription {
                        id: route.id.clone(),
                        events: vec![name.into()],
                        mode: route.mode,
                        timeout: route.timeout,
                        hook: Box::new(self.route_hook(route, deadline)),
                    })
                },
            )
    }
    fn route_hook(&self, route: &Route, deadline: Option<Instant>) -> RouteHook {
        RouteHook {
            route: route.clone(),
            store: self.store.clone(),
            options: self.options.backend.clone(),
            bodies: self.bodies.clone(),
            life: Arc::downgrade(&self.life),
            deadline,
        }
    }
    async fn observations(
        &self,
        name: &str,
        observations: Vec<crate::client::Observation<'_>>,
        deadline: Option<Instant>,
    ) -> Vec<DeliveryDiagnostic> {
        let mut diagnostics = vec![];
        if !self.options.capabilities[name].observe {
            return diagnostics;
        }
        for (index, observation) in observations.into_iter().enumerate() {
            let route = self
                .routes
                .iter()
                .find(|r| r.id == observation.subscription_id)
                .expect("owned route");
            if self.life.closing.load(Ordering::SeqCst) {
                return diagnostics;
            }
            if index >= self.options.max_observations {
                diagnostics.push(
                    route.observation_diagnostic(generated::DeliveryDiagnosticCode::Capacity),
                );
                self.life.failure(ObservationFailure {
                    subscription_id: route.id.clone(),
                    error: "observation operation limit reached".into(),
                });
                continue;
            }
            let mut delivery = Delivery {
                life: &self.life,
                id: route.id.clone(),
                finished: false,
            };
            let result =
                match crate::canonical::validate("observe-notification", &observation.notification)
                {
                    Ok(()) => self
                        .route_hook(route, deadline)
                        .call(observation.notification)
                        .await
                        .map(|_| ()),
                    Err(e) => Err(HookError(e)
                        .classified(generated::DeliveryDiagnosticCode::ProtocolRejection)),
                };
            delivery.finished = true;
            match result {
                Ok(()) => self.life.report.lock().unwrap().delivered += 1,
                Err(e) => {
                    diagnostics.push(route.observation_diagnostic(e.code()));
                    self.life.failure(ObservationFailure {
                        subscription_id: route.id.clone(),
                        error: format!("observation delivery failed ({:?})", e.code()),
                    });
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
        self.bodies.clear();
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
    snapshot: Option<Value>,
    deadline: Option<Instant>,
    budget: Option<LocalFuture<'a, ()>>,
    cancellation: Option<LocalFuture<'a, ()>>,
    initial: Option<Decision>,
    candidate: Option<Value>,
    capabilities: Option<Capabilities>,
    gates: Option<bool>,
    reauthorization: Option<bool>,
    continuation: Option<(u64, u64, u64)>,
    exchange: Option<&'a Exchange>,
    targets: BTreeMap<String, String>,
    sources: Vec<generated::ergonomic_inputs::ContentSourceBinding<Body>>,
}
macro_rules! settings_methods {
    () => {
        /// Transfer a lazy source into a generated named content slot. No reads occur here.
        pub fn body_source(
            mut self,
            binding: generated::ergonomic_inputs::ContentSourceBinding<Body>,
        ) -> Self {
            self.settings.sources.push(binding);
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
        pub fn initial_state(mut self, decision: Decision) -> Self {
            self.settings.initial = Some(decision);
            self
        }
        pub fn initial_candidate(mut self, candidate: Value) -> Self {
            self.settings.candidate = Some(candidate);
            self
        }
        pub fn capabilities(mut self, capabilities: Capabilities) -> Self {
            self.settings.capabilities = Some(capabilities);
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
    name: &'static str,
    project: fn(&T) -> Result<Value, serde_json::Error>,
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
    pub fn content_target(mut self, target: impl Into<String>, pointer: impl Into<String>) -> Self {
        self.settings.targets.insert(target.into(), pointer.into());
        self
    }
}
impl<'a, T: Send + 'a> IntoFuture for InputBoundary<'a, T> {
    type Output = Result<EventOutcome<Value>, HookError>;
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
                let event = (self.project)(&self.input).map_err(err)?;
                EventBoundary {
                    hooks: self.hooks,
                    event,
                    name: Some(self.name),
                    settings: self.settings,
                }
                .await
            }),
        )
    }
}

/// No serialization, process startup or network work occurs before await.
#[must_use]
pub struct EventBoundary<'a, T> {
    hooks: &'a Hooks,
    event: T,
    name: Option<&'static str>,
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
    pub fn content_target(mut self, target: impl Into<String>, pointer: impl Into<String>) -> Self {
        self.settings.targets.insert(target.into(), pointer.into());
        self
    }
}
pub struct EventOutcome<T> {
    pub diagnostics: Vec<DeliveryDiagnostic>,
    pub outcome: ProtocolOutcome,
    pub effective_event: Value,
    pub event: Result<T, InputDecodeError>,
}
impl<T> EventOutcome<T> {
    pub fn permission(&self) -> Decision {
        self.outcome.permission()
    }
}
impl<'a, T: Serialize + DeserializeOwned + Send + 'a> IntoFuture for EventBoundary<'a, T> {
    type Output = Result<EventOutcome<T>, HookError>;
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
                let mut event = serde_json::to_value(self.event).map_err(err)?;
                let _sources = self.hooks.bind_sources(&mut event, self.settings.sources)?;
                if let Some(expected) = self.name {
                    let object = event
                        .as_object_mut()
                        .ok_or_else(|| err("event must be an object"))?;
                    if object.get("type").is_some_and(|actual| actual != expected) {
                        return Err(err("event name mismatch"));
                    }
                    object.insert("type".into(), json!(expected));
                }
                let (event, name, granted) = self.hooks.prepare(event)?;
                let caps = narrow(self.settings.capabilities, granted)?;
                let client = self.hooks.client(&event, &name, self.settings.deadline);
                let mut boundary = client
                    .event(event)
                    .capabilities(caps.0)
                    .content(self.hooks.content_context());
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
                for (target, pointer) in self.settings.targets {
                    boundary = boundary.content_target(target, pointer);
                }
                let result = boundary.await.map_err(err)?;
                if self.hooks.life.closing.load(Ordering::SeqCst) {
                    return Err(err("Hooks is shutting down")
                        .classified(generated::DeliveryDiagnosticCode::Cancelled));
                }
                let mut diagnostics = result.diagnostics;
                for diagnostic in &mut diagnostics {
                    diagnostic.backend_id = self
                        .hooks
                        .routes
                        .iter()
                        .find(|route| route.id == diagnostic.subscription_id)
                        .map(|route| route.backend_id.clone());
                }
                diagnostics.extend(
                    self.hooks
                        .observations(&name, result.observations, self.settings.deadline)
                        .await,
                );
                if self.hooks.life.closing.load(Ordering::SeqCst) {
                    return Err(err("Hooks is shutting down")
                        .classified(generated::DeliveryDiagnosticCode::Cancelled));
                }
                let event = serde_json::from_value(result.effective_event.clone())
                    .map_err(InputDecodeError);
                Ok(EventOutcome {
                    outcome: result.outcome,
                    diagnostics,
                    effective_event: result.effective_event,
                    event,
                })
            }),
        )
    }
}
enum ToolInput<T> {
    Host(Box<generated::ergonomic_inputs::ToolBeforeInput<T>>),
    Raw(T),
}
#[must_use]
pub struct ToolBoundary<'a, T> {
    hooks: &'a Hooks,
    input: ToolInput<T>,
    context: Value,
    settings: Settings<'a>,
}
impl<'a, T> ToolBoundary<'a, T> {
    settings_methods!();
    pub fn context(mut self, context: ToolContext) -> Self {
        self.context = context.event;
        self
    }
}
pub struct ToolOutcome<T> {
    pub diagnostics: Vec<DeliveryDiagnostic>,
    pub outcome: ProtocolOutcome,
    pub effective_input: Value,
    pub input: Result<T, InputDecodeError>,
}
impl<T> ToolOutcome<T> {
    pub fn permission(&self) -> Decision {
        self.outcome.permission()
    }
}
fn narrow(caps: Option<Capabilities>, granted: Capabilities) -> Result<Capabilities, HookError> {
    if let Some(caps) = caps {
        if !crate::client::subset(&caps.0, &granted.0) {
            return Err(err(
                "per-occurrence capabilities may only narrow explicit host grants",
            ));
        }
        Ok(caps)
    } else {
        Ok(granted)
    }
}
impl<'a, T: Serialize + DeserializeOwned + Send + 'a> IntoFuture for ToolBoundary<'a, T> {
    type Output = Result<ToolOutcome<T>, HookError>;
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
                let (input, mut context) = match self.input {
                    ToolInput::Host(host) => {
                        let host = *host;
                        let context = host.to_event_value().map_err(err)?;
                        (host.input, context)
                    }
                    ToolInput::Raw(input) => (input, self.context),
                };
                context
                    .as_object_mut()
                    .ok_or_else(|| err("tool context must be an object"))?
                    .insert("type".into(), json!("tool.before"));
                let _sources = self
                    .hooks
                    .bind_sources(&mut context, self.settings.sources)?;
                let (context, name, granted) = self.hooks.prepare(context)?;
                let caps = narrow(self.settings.capabilities, granted)?;
                let client = self.hooks.client(&context, &name, self.settings.deadline);
                let mut boundary = client.tool_before(input).capabilities(caps.0);
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
                let mut diagnostics = result.diagnostics;
                for diagnostic in &mut diagnostics {
                    diagnostic.backend_id = self
                        .hooks
                        .routes
                        .iter()
                        .find(|route| route.id == diagnostic.subscription_id)
                        .map(|route| route.backend_id.clone());
                }
                diagnostics.extend(
                    self.hooks
                        .observations(&name, result.observations, self.settings.deadline)
                        .await,
                );
                if self.hooks.life.closing.load(Ordering::SeqCst) {
                    return Err(err("Hooks is shutting down")
                        .classified(generated::DeliveryDiagnosticCode::Cancelled));
                }
                Ok(ToolOutcome {
                    outcome: result.outcome,
                    diagnostics,
                    effective_input: result.effective_input,
                    input: result.input,
                })
            }),
        )
    }
}

// Both the named methods and their inventory are generated from the schema catalogue.
pub const NAMED_BOUNDARIES: &[&str] = crate::ahp_hooks_boundary_methods!(inventory);
impl Hooks {
    crate::ahp_ergonomic_hook_methods!();
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
