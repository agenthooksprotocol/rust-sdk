//! Primary registration-driven harness. Configuration is ordinary serde JSON;
//! applications retain execution policy. No transport starts before dispatch.
use crate::{
    adapters::registered::{self, BackendOptions, ManagedBackend},
    body::{Body, BodyError, DeferredBodies},
    client::{
        Client, Decision, FailurePolicy, Hook, HookError, InputDecodeError, LocalFuture, Mode,
        ProtocolOutcome, Subscription, ToolContext,
    },
    content::{AuthorizedScope, ContentContext, MemoryContentStore},
    elicitation::Exchange,
    generated,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::{IntoFuture, poll_fn},
    rc::{Rc, Weak},
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
/// Interception and observation are independent opt-ins. A missing entry grants neither.
#[derive(Clone, Debug)]
pub struct EventGrant {
    intercept: Option<Capabilities>,
    observe: bool,
}
impl EventGrant {
    pub fn intercept(capabilities: Capabilities) -> Self {
        Self {
            intercept: Some(capabilities),
            observe: false,
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
    /// Required when registration enables observation routes. The host must drive
    /// its executor independently of `wait_until_idle`.
    pub observation_scheduler: Option<Rc<dyn ObservationScheduler>>,
    manifest: Option<Value>,
    pub max_body_bytes: usize,
    pub max_stored_bytes: usize,
    pub max_stored_entries: usize,
    backends: BTreeMap<String, Rc<dyn ManagedBackend>>,
}
impl HooksOptions {
    pub fn new(source: impl Into<String>, capabilities: EventCapabilities) -> Self {
        Self {
            source: source.into(),
            capabilities,
            backend: BackendOptions::default(),
            observation_timeout: Duration::from_secs(30),
            max_observations: 1024,
            observation_scheduler: None,
            manifest: None,
            max_body_bytes: 4 * 1024 * 1024,
            max_stored_bytes: 64 * 1024 * 1024,
            max_stored_entries: 4096,
            backends: BTreeMap::new(),
        }
    }
    /// Optional low-level escape hatch for a host-owned neutral transport.
    /// Built-in HTTP/process transports need no callback or factory from callers.
    pub fn with_backend(mut self, id: impl Into<String>, backend: Rc<dyn ManagedBackend>) -> Self {
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
/// An explicitly supplied local executor. It must start polling without a
/// completion waiter, retain no detached work, and return a handle that cancels
/// work when dropped. Submission must not panic or lose the future.
pub trait ObservationScheduler {
    fn schedule(&self, work: LocalFuture<'static, ()>) -> Rc<dyn ObservationTask>;
}
/// Owned completion of a scheduled worker. Completion must be repeatable and
/// cancellation-safe: dropping a completion waiter must not cancel the worker.
pub trait ObservationTask {
    /// Request cancellation. Completion must await destruction of owned work.
    fn cancel(&self);
    fn completion(&self) -> LocalFuture<'_, ()>;
}

/// Explicit Tokio LocalSet integration; never creates a runtime or thread.
/// Dispatch inside an entered LocalSet (or LocalRuntime).
#[cfg(feature = "tokio-process")]
pub struct TokioObservationScheduler;
#[cfg(feature = "tokio-process")]
impl ObservationScheduler for TokioObservationScheduler {
    fn schedule(&self, work: LocalFuture<'static, ()>) -> Rc<dyn ObservationTask> {
        #[derive(Default)]
        struct Completion {
            done: Cell<bool>,
            waiters: RefCell<Vec<Waker>>,
        }
        struct Done(Rc<Completion>);
        impl Drop for Done {
            fn drop(&mut self) {
                self.0.done.set(true);
                for waker in self.0.waiters.take() {
                    waker.wake();
                }
            }
        }
        struct Task {
            handle: tokio::task::JoinHandle<()>,
            state: Rc<Completion>,
        }
        impl Drop for Task {
            fn drop(&mut self) {
                self.handle.abort();
            }
        }
        impl ObservationTask for Task {
            fn cancel(&self) {
                self.handle.abort();
            }
            fn completion(&self) -> LocalFuture<'_, ()> {
                Box::pin(poll_fn(|cx| {
                    if self.state.done.get() {
                        return Poll::Ready(());
                    }
                    let mut waiters = self.state.waiters.borrow_mut();
                    if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                        waiters.push(cx.waker().clone());
                    }
                    Poll::Pending
                }))
            }
        }
        let state = Rc::new(Completion::default());
        let done = Done(state.clone());
        let handle = tokio::task::spawn_local(async move {
            let _done = done;
            work.await;
        });
        Rc::new(Task { handle, state })
    }
}

#[derive(Clone)]
struct Route {
    id: String,
    events: Vec<String>,
    mode: Mode,
    timeout: Duration,
    configuration: Value,
    backend: Rc<dyn ManagedBackend>,
}
#[derive(Clone)]
struct RouteHook {
    route: Route,
    store: MemoryContentStore,
    options: BackendOptions,
    bodies: DeferredBodies,
    life: Weak<Lifecycle>,
}
impl Hook for RouteHook {
    fn call(&self, mut request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        let owned = self.clone();
        let work = Box::pin(async move {
            let start = Instant::now();
            if owned.route.configuration["includeNative"] != true {
                if let Some(event) = request["params"]["event"].as_object_mut() {
                    event.remove("native");
                }
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
            )
            .await?;
            let remaining = owned
                .route
                .timeout
                .checked_sub(start.elapsed())
                .filter(|v| !v.is_zero())
                .ok_or_else(|| err("subscription deadline exceeded during content preparation"))?;
            let response = owned.route.backend.call(request.clone(), remaining).await?;
            if request["method"] == "hooks/intercept" {
                crate::hooks_content::validate_response_grants(&request, &response)?;
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
        if let Some(values) = config["filters"][key].as_array() {
            if !values.contains(actual) {
                return true;
            }
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
struct PendingObservation {
    id: String,
    hook: RouteHook,
    notification: Value,
}
#[derive(Default)]
struct Lifecycle {
    closing: Cell<bool>,
    closed: Cell<bool>,
    active: Cell<usize>,
    draining: Cell<bool>,
    cleaning: Cell<bool>,
    waiters: RefCell<Vec<Waker>>,
    pending: RefCell<VecDeque<PendingObservation>>,
    report: RefCell<ObservationReport>,
    work: RefCell<Vec<Weak<OwnedWork>>>,
}
// The harness owns each transport/projection future independently of the caller's
// boundary future. Shutdown can drop it even if that caller stops polling.
struct OwnedWork {
    future: RefCell<Option<LocalFuture<'static, Result<Value, HookError>>>>,
    waker: RefCell<Option<Waker>>,
}
impl OwnedWork {
    fn cancel(&self) {
        self.future.borrow_mut().take();
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}
impl Lifecycle {
    fn run(
        &self,
        future: LocalFuture<'static, Result<Value, HookError>>,
    ) -> LocalFuture<'static, Result<Value, HookError>> {
        if self.closing.get() {
            return Box::pin(async { Err(err("Hooks is shutting down")) });
        }
        let work = Rc::new(OwnedWork {
            future: RefCell::new(Some(future)),
            waker: RefCell::new(None),
        });
        let mut registry = self.work.borrow_mut();
        registry.retain(|entry| entry.strong_count() != 0);
        registry.push(Rc::downgrade(&work));
        Box::pin(poll_fn(move |cx| {
            *work.waker.borrow_mut() = Some(cx.waker().clone());
            let mut slot = work.future.borrow_mut();
            let Some(future) = slot.as_mut() else {
                return Poll::Ready(Err(err("hook work cancelled by shutdown")));
            };
            let result = future.as_mut().poll(cx);
            if result.is_ready() {
                slot.take();
            }
            result
        }))
    }
    fn cancel_work(&self) {
        for entry in self.work.take() {
            if let Some(work) = entry.upgrade() {
                work.cancel();
            }
        }
    }
    fn wake(&self) {
        for w in self.waiters.take() {
            w.wake();
        }
    }
    fn failure(&self, failure: ObservationFailure) {
        let mut report = self.report.borrow_mut();
        if report.failures.len() < 1024 {
            report.failures.push(failure);
        } else {
            report.omitted_failures = report.omitted_failures.saturating_add(1);
        }
    }
    fn begin(&self) -> Result<Active<'_>, HookError> {
        if self.closing.get() {
            return Err(err("Hooks is shutting down"));
        }
        self.active.set(self.active.get() + 1);
        Ok(Active(self))
    }
    async fn ready(&self) {
        poll_fn(|cx| {
            if self.active.get() == 0 && !self.draining.get() {
                Poll::Ready(())
            } else {
                let mut waiters = self.waiters.borrow_mut();
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
        self.0.active.set(self.0.active.get() - 1);
        self.0.wake();
    }
}
struct Cleanup<'a>(&'a Lifecycle);
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        self.0.cleaning.set(false);
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
    backends: Vec<Rc<dyn ManagedBackend>>,
    store: MemoryContentStore,
    bodies: DeferredBodies,
    life: Rc<Lifecycle>,
    worker: RefCell<Option<Rc<dyn ObservationTask>>>,
    next_id: Cell<u64>,
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
                Rc::clone(custom)
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
                    events: events.into_iter().collect(),
                    mode,
                    timeout,
                    configuration: subscription.clone(),
                    backend: Rc::clone(&transport),
                });
            }
            backends.push(transport);
        }
        if options.observation_scheduler.is_none()
            && routes.iter().any(|route| route.mode == Mode::Observe)
        {
            return Err(err("observation routes require an ObservationScheduler"));
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
            life: Rc::new(Lifecycle::default()),
            worker: RefCell::new(None),
            next_id: Cell::new(0),
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
    /// Supply ordinary tool/call/path context with `.context(...)`. Source,
    /// timestamp and a fresh event ID are supplied by this harness if absent.
    pub fn tool_before<T: Serialize + DeserializeOwned>(&self, input: T) -> ToolBoundary<'_, T> {
        ToolBoundary {
            hooks: self,
            input,
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
                .get()
                .checked_add(1)
                .ok_or_else(|| err("event identity exhausted"))?;
            self.next_id.set(id);
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
    fn client(&self, event: &Value, name: &str) -> Client {
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
                        hook: Box::new(self.route_hook(route)),
                    })
                },
            )
    }
    fn route_hook(&self, route: &Route) -> RouteHook {
        RouteHook {
            route: route.clone(),
            store: self.store.clone(),
            options: self.options.backend.clone(),
            bodies: self.bodies.clone(),
            life: Rc::downgrade(&self.life),
        }
    }
    fn observations(&self, name: &str, observations: Vec<crate::client::Observation<'_>>) {
        if self.life.closing.get() || !self.options.capabilities[name].observe {
            return;
        }
        for observation in observations {
            let route = self
                .routes
                .iter()
                .find(|r| r.id == observation.subscription_id)
                .expect("owned route");
            if self.life.pending.borrow().len() >= self.options.max_observations {
                self.life.failure(ObservationFailure {
                    subscription_id: route.id.clone(),
                    error: "observation queue limit reached".into(),
                });
                continue;
            }
            self.life
                .pending
                .borrow_mut()
                .push_back(PendingObservation {
                    id: route.id.clone(),
                    hook: self.route_hook(route),
                    notification: observation.notification,
                });
        }
        self.life.wake();
        if let Some(scheduler) = &self.options.observation_scheduler {
            if !self.life.draining.replace(true) {
                let life = self.life.clone();
                // Capture before submission, covering cancellation before poll.
                let guard = OwnedDrain(life.clone());
                let worker = scheduler.schedule(Box::pin(async move {
                    let _guard = guard;
                    deliver_pending(&life).await;
                }));
                *self.worker.borrow_mut() = Some(worker);
            }
        }
    }
    /// Await automatically scheduled work without delivering or scheduling it.
    /// Dropping this waiter does not cancel an automatically scheduled worker.
    pub async fn wait_until_idle(&self) -> ObservationReport {
        loop {
            self.life.ready().await;
            let worker = self.worker.borrow().clone();
            if let Some(worker) = worker {
                worker.completion().await;
            }
            if self.life.active.get() == 0
                && !self.life.draining.get()
                && self.life.pending.borrow().is_empty()
            {
                return self.life.report.borrow().clone();
            }
        }
    }
    /// Stop admission, cancel owned work, await worker destruction, and close
    /// every backend. Suspended caller boundaries need not be polled for cleanup.
    /// Repeated shutdown is safe; cleanup failures can be retried.
    pub async fn shutdown(&self) -> Result<ObservationReport, HookError> {
        self.life.closing.set(true);
        self.life.cancel_work();
        for pending in self.life.pending.take() {
            self.life.failure(ObservationFailure {
                subscription_id: pending.id,
                error: "observation delivery cancelled by shutdown; not retried".into(),
            });
        }
        let worker = self.worker.borrow().clone();
        if let Some(worker) = worker {
            worker.cancel();
            worker.completion().await;
        }
        self.bodies.clear();
        poll_fn(|cx| {
            if !self.life.cleaning.replace(true) {
                Poll::Ready(())
            } else {
                let mut waiters = self.life.waiters.borrow_mut();
                if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                    waiters.push(cx.waker().clone());
                }
                Poll::Pending
            }
        })
        .await;
        let _cleanup = Cleanup(&self.life);
        if !self.life.closed.get() {
            let mut errors = vec![];
            for backend in &self.backends {
                if let Err(e) = backend.shutdown().await {
                    errors.push(e.to_string());
                }
            }
            if !errors.is_empty() {
                return Err(err(errors.join("; ")));
            }
            self.life.closed.set(true);
        }
        Ok(self.life.report.borrow().clone())
    }
}

struct OwnedDrain(Rc<Lifecycle>);
impl Drop for OwnedDrain {
    fn drop(&mut self) {
        self.0.draining.set(false);
        self.0.wake();
    }
}
async fn deliver_pending(life: &Lifecycle) {
    loop {
        let next = life.pending.borrow_mut().pop_front();
        let Some(next) = next else { break };
        let mut delivery = Delivery {
            life,
            id: next.id.clone(),
            finished: false,
        };
        let result = match crate::canonical::validate("observe-notification", &next.notification) {
            Ok(()) => next.hook.call(next.notification).await.map(|_| ()),
            Err(e) => Err(HookError(e)),
        };
        delivery.finished = true;
        match result {
            Ok(()) => life.report.borrow_mut().delivered += 1,
            Err(e) => life.failure(ObservationFailure {
                subscription_id: next.id,
                error: e.to_string(),
            }),
        }
    }
}

#[derive(Default)]
struct Settings<'a> {
    initial: Option<Decision>,
    candidate: Option<Value>,
    capabilities: Option<Capabilities>,
    gates: Option<bool>,
    reauthorization: Option<bool>,
    continuation: Option<(u64, u64, u64)>,
    exchange: Option<&'a Exchange>,
    targets: BTreeMap<String, String>,
}
macro_rules! settings_methods {
    () => {
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
    pub outcome: ProtocolOutcome,
    pub effective_event: Value,
    pub event: Result<T, InputDecodeError>,
}
impl<'a, T: Serialize + DeserializeOwned + 'a> IntoFuture for EventBoundary<'a, T> {
    type Output = Result<EventOutcome<T>, HookError>;
    type IntoFuture = LocalFuture<'a, Self::Output>;
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let _active = self.hooks.life.begin()?;
            let mut event = serde_json::to_value(self.event).map_err(err)?;
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
            let client = self.hooks.client(&event, &name);
            let mut boundary = client
                .event(event)
                .capabilities(caps.0)
                .content(self.hooks.content_context());
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
            if self.hooks.life.closing.get() {
                return Err(err("Hooks is shutting down"));
            }
            self.hooks.observations(&name, result.observations);
            let event =
                serde_json::from_value(result.effective_event.clone()).map_err(InputDecodeError);
            Ok(EventOutcome {
                outcome: result.outcome,
                effective_event: result.effective_event,
                event,
            })
        })
    }
}
#[must_use]
pub struct ToolBoundary<'a, T> {
    hooks: &'a Hooks,
    input: T,
    context: Value,
    settings: Settings<'a>,
}
impl<T> ToolBoundary<'_, T> {
    settings_methods!();
    pub fn context(mut self, context: ToolContext) -> Self {
        self.context = context.event;
        self
    }
}
pub struct ToolOutcome<T> {
    pub outcome: ProtocolOutcome,
    pub effective_input: Value,
    pub input: Result<T, InputDecodeError>,
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
impl<'a, T: Serialize + DeserializeOwned + 'a> IntoFuture for ToolBoundary<'a, T> {
    type Output = Result<ToolOutcome<T>, HookError>;
    type IntoFuture = LocalFuture<'a, Self::Output>;
    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let _active = self.hooks.life.begin()?;
            let mut context = self.context;
            context
                .as_object_mut()
                .ok_or_else(|| err("tool context must be an object"))?
                .insert("type".into(), json!("tool.before"));
            let (context, name, granted) = self.hooks.prepare(context)?;
            let caps = narrow(self.settings.capabilities, granted)?;
            let client = self.hooks.client(&context, &name);
            let mut boundary = client.tool_before(self.input).capabilities(caps.0);
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
            if self.hooks.life.closing.get() {
                return Err(err("Hooks is shutting down"));
            }
            self.hooks.observations(&name, result.observations);
            Ok(ToolOutcome {
                outcome: result.outcome,
                effective_input: result.effective_input,
                input: result.input,
            })
        })
    }
}

// Both the named methods and their inventory are generated from the schema catalogue.
pub const NAMED_BOUNDARIES: &[&str] = crate::ahp_hooks_boundary_methods!(inventory);
impl Hooks {
    crate::ahp_hooks_boundary_methods!();
}
