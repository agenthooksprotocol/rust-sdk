//! Skipped server-driven configuration: diagnostics, re-attempts and atomic routes.
use super::*;
use crate::{
    adapters::registered::{AuthChallenge, AuthContext, AuthProvider, BearerCredential},
    client::ToolContext,
    generated::capability,
};
use futures::{channel::oneshot, executor::block_on};
use std::{collections::VecDeque, sync::atomic::AtomicU64};

pub(crate) enum Reply {
    Subscriptions(Value),
    Raw(Value),
    Fail(HookError),
    Wait(oneshot::Receiver<Value>),
    /// Run a host action while the attempt is in flight, then fail it.
    FailDuring(Box<dyn FnOnce() + Send>, HookError),
}
/// Answers configuration requests from a script; records every request.
#[derive(Default)]
pub(crate) struct Scripted {
    pub(crate) replies: Mutex<VecDeque<Reply>>,
    pub(crate) requests: Mutex<Vec<Value>>,
    pub(crate) shutdowns: AtomicU64,
}
impl Scripted {
    pub(crate) fn new(replies: impl IntoIterator<Item = Reply>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into_iter().collect()),
            requests: Mutex::default(),
            shutdowns: AtomicU64::new(0),
        })
    }
    pub(crate) fn configuration_calls(&self) -> usize {
        self.count("hooks/configuration")
    }
    pub(crate) fn count(&self, method: &str) -> usize {
        let requests = self.requests.lock().unwrap();
        requests.iter().filter(|r| r["method"] == method).count()
    }
}
impl ManagedBackend for Scripted {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(request.clone());
            let id = request["id"].clone();
            if request["method"] != "hooks/configuration" {
                return Ok(
                    json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"draft","effects":[]}}),
                );
            }
            let reply = self.replies.lock().unwrap().pop_front();
            let subscriptions = match reply.expect("scripted configuration reply") {
                Reply::Subscriptions(subscriptions) => subscriptions,
                Reply::Raw(mut raw) => {
                    if raw["id"] == "same" {
                        raw["id"] = id;
                    }
                    return Ok(raw);
                }
                Reply::Fail(error) => return Err(error),
                Reply::Wait(receiver) => receiver.await.unwrap(),
                Reply::FailDuring(action, error) => {
                    action();
                    return Err(error);
                }
            };
            Ok(
                json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"draft",
                "configuration":{"subscriptions":subscriptions}}}),
            )
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}
/// Counts host preparations for exactly one backend's event endpoint.
#[derive(Default)]
pub(crate) struct Prepared(pub(crate) AtomicU64);
impl AuthProvider for Prepared {
    fn credential(
        &self,
        _: AuthContext,
    ) -> LocalFuture<'_, Result<Option<BearerCredential>, HookError>> {
        Box::pin(async { Ok(None) })
    }
    fn challenge(
        &self,
        _: AuthContext,
        _: AuthChallenge,
    ) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Err(HookError::authentication(AuthErrorCode::AccessDenied)) })
    }
    fn preparations(&self, context: &AuthContext) -> u64 {
        if context.backend_id == "com.a" && context.destination == "https://com.a/hooks" {
            self.0.load(Ordering::SeqCst)
        } else {
            0
        }
    }
}
pub(crate) fn intercept() -> Value {
    json!([{"events":["tool.before"],"mode":"intercept","timeoutMs":1000,
        "failurePolicy":"fail-open","content":{"default":"metadata"}}])
}
pub(crate) fn registration(ids: &[&str]) -> Value {
    let hooks: Vec<_> = ids
        .iter()
        .map(|id| json!({"id":id,"transport":{"type":"http","url":format!("https://{id}/hooks")}}))
        .collect();
    json!({"protocolVersion":"draft","hooks":hooks})
}
pub(crate) type Seen = Arc<Mutex<Vec<Value>>>;
pub(crate) fn options(
    backends: &[(&str, Arc<Scripted>)],
    provider: Option<Arc<Prepared>>,
    backoff: Duration,
) -> (HooksOptions, Seen) {
    let seen: Seen = Arc::default();
    let sink = seen.clone();
    let mut options = HooksOptions::new(
        "urn:example:host",
        Harness::new("test", "1"),
        HostCapabilities {
            tool_before: Some(capability::tool_before().allow().deny()),
            ..Default::default()
        },
    )
    .configuration_backoff(backoff, backoff * 4)
    .on_configuration_skipped(move |d| {
        sink.lock().unwrap().push(serde_json::to_value(d).unwrap());
    });
    for (id, backend) in backends {
        options = options.with_backend(*id, backend.clone() as Arc<dyn ManagedBackend>);
    }
    options.backend.auth_provider = provider.map(|p| p as Arc<dyn AuthProvider>);
    (options, seen)
}
async fn admit(hooks: &Hooks) {
    hooks
        .tool_input(json!({"command":"x"}))
        .context(ToolContext::new(
            json!({"tool":{"name":"shell","kind":"shell","origin":"native"},
            "call":{"id":"call-1"},"path":"native"}),
        ))
        .await
        .unwrap();
}
fn event(hooks: &Hooks) {
    block_on(admit(hooks));
}
/// Run one event first so lazy schema compilation does not eat into backoff.
fn warm() {
    let backend = Scripted::new([Reply::Subscriptions(intercept())]);
    let (options, _) = options(&[("com.a", backend)], None, Duration::from_secs(1));
    event(&Hooks::new(registration(&["com.a"]), options).unwrap());
}
fn unavailable() -> HookError {
    HookError::new("HTTP transport failed")
}
fn diagnostic(id: &str, code: &str) -> Value {
    json!({"backendId":id,"code":code})
}

#[test]
pub(crate) fn configuration_unavailable_backoff() {
    warm();
    let backoff = Duration::from_millis(250);
    let backend = Scripted::new([
        Reply::Fail(unavailable()),
        Reply::Fail(HookError::authentication(AuthErrorCode::ProviderFailed)),
        Reply::Fail(unavailable()),
        Reply::Subscriptions(intercept()),
    ]);
    let (options, seen) = options(&[("com.a", backend.clone())], None, backoff);
    let hooks = Hooks::new(registration(&["com.a"]), options).unwrap();
    block_on(hooks.initialize()).unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        [diagnostic("com.a", "configuration_unavailable")]
    );
    // Earlier admissions do not contact the backend.
    block_on(hooks.initialize()).unwrap();
    event(&hooks);
    assert_eq!(backend.configuration_calls(), 1);
    std::thread::sleep(backoff);
    // The first admission after backoff re-attempts; recovery `retry` is retried too.
    event(&hooks);
    assert_eq!(backend.configuration_calls(), 2);
    assert_eq!(
        seen.lock().unwrap()[1],
        json!({"backendId":"com.a","code":"configuration_unavailable",
            "authError":"provider_failed","recovery":"retry"})
    );
    // Backoff doubled: one initial delay is no longer enough.
    std::thread::sleep(backoff);
    block_on(hooks.initialize()).unwrap();
    assert_eq!(backend.configuration_calls(), 2);
    std::thread::sleep(backoff);
    block_on(hooks.initialize()).unwrap();
    assert_eq!(backend.configuration_calls(), 3);
    assert!(!hooks.intercepts(generated::EventType::ToolBefore));
    // Capped at 4x: a cap elapsing always suffices.
    std::thread::sleep(backoff * 4);
    event(&hooks);
    assert_eq!(backend.configuration_calls(), 4);
    assert!(hooks.intercepts(generated::EventType::ToolBefore));
    assert_eq!(backend.count("hooks/intercept"), 1);
    assert_eq!(seen.lock().unwrap().len(), 3);
}

#[test]
fn configuration_backoff_defaults_double_and_cap() {
    let backend = Scripted::new((0..10).map(|_| Reply::Fail(unavailable())));
    let (mut options, _) = options(&[("com.a", backend.clone())], None, Duration::from_secs(1));
    options.configuration_backoff = HooksOptions::new(
        "urn:example:host",
        Harness::new("test", "1"),
        HostCapabilities::default(),
    )
    .configuration_backoff;
    assert_eq!(
        options.configuration_backoff,
        (Duration::from_secs(30), Duration::from_secs(3600))
    );
    let hooks = Hooks::new(registration(&["com.a"]), options).unwrap();
    let mut delays = Vec::new();
    for _ in 0..9 {
        let before = Instant::now();
        // Force eligibility; the schedule is what is under test.
        if let Some(p) = hooks.discovery.pending.lock().unwrap().first_mut() {
            p.retry_at = p.retry_at.map(|_| before);
        }
        block_on(hooks.initialize()).unwrap();
        let pending = hooks.discovery.pending.lock().unwrap();
        let at = pending[0].retry_at.unwrap();
        delays.push((at - before).as_secs());
    }
    assert_eq!(delays, [30, 60, 120, 240, 480, 960, 1920, 3600, 3600]);
    for (initial, max) in [
        (Duration::ZERO, Duration::from_secs(1)),
        (Duration::from_secs(2), Duration::from_secs(1)),
    ] {
        let (bad, _) = options_with_backoff(initial, max);
        assert!(Hooks::new(registration(&["com.a"]), bad).is_err());
    }
}
fn options_with_backoff(initial: Duration, max: Duration) -> (HooksOptions, Seen) {
    let (options, seen) = options(&[("com.a", Scripted::new([]))], None, initial);
    (options.configuration_backoff(initial, max), seen)
}

#[test]
pub(crate) fn configuration_auth_failure_not_retried_on_backoff() {
    for (code, recovery) in [
        (AuthErrorCode::InteractionRequired, "login"),
        (AuthErrorCode::CredentialUnavailable, "configure"),
        (AuthErrorCode::AccessDenied, "none"),
    ] {
        let backoff = Duration::from_millis(5);
        let backend = Scripted::new([
            Reply::Fail(HookError::authentication(code)),
            Reply::Subscriptions(intercept()),
        ]);
        let provider = Arc::new(Prepared::default());
        let (options, seen) = options(
            &[("com.a", backend.clone())],
            Some(provider.clone()),
            backoff,
        );
        let hooks = Hooks::new(registration(&["com.a"]), options).unwrap();
        block_on(hooks.initialize()).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            [
                json!({"backendId":"com.a","code":"configuration_unavailable",
                "authError":code.as_str(),"recovery":recovery})
            ]
        );
        std::thread::sleep(backoff * 8);
        event(&hooks);
        block_on(hooks.initialize()).unwrap();
        assert_eq!(
            backend.configuration_calls(),
            1,
            "{recovery}: no backoff retry"
        );
        // Only a successful host prepare for the endpoint makes it eligible.
        provider.0.fetch_add(1, Ordering::SeqCst);
        event(&hooks);
        assert_eq!(backend.configuration_calls(), 2, "{recovery}");
        assert!(hooks.intercepts(generated::EventType::ToolBefore));
        assert_eq!(backend.count("hooks/intercept"), 1);
    }
}

#[test]
pub(crate) fn configuration_invalid_not_retried() {
    let rpc = |code: i64| {
        Reply::Raw(json!({"jsonrpc":"2.0","id":"same","error":{"code":code,"message":"no"}}))
    };
    let local_secret = json!([{"events":["tool.before"],"mode":"intercept","timeoutMs":1000,
        "failurePolicy":"fail-open","content":{"default":"body"},
        "upload":{"endpoint":"https://upload.example/content","maxBytes":16,"timeoutMs":500,
            "auth":{"type":"bearer","tokenEnv":"TOKEN"}}}]);
    let observe_only =
        json!([{"events":["session.end"],"mode":"observe","content":{"default":"metadata"}}]);
    for (reply, code) in [
        (rpc(-32601), "configuration_invalid"),
        (
            Reply::Fail(
                HookError::new("method not found")
                    .classified(generated::DeliveryDiagnosticCode::ProtocolRejection),
            ),
            "configuration_invalid",
        ),
        (
            Reply::Raw(
                json!({"jsonrpc":"2.0","id":"other","result":{"protocolVersion":"draft",
                "configuration":{"subscriptions":intercept()}}}),
            ),
            "configuration_invalid",
        ),
        (
            Reply::Raw(
                json!({"jsonrpc":"2.0","id":"same","result":{"protocolVersion":"0.0",
                "configuration":{"subscriptions":intercept()}}}),
            ),
            "configuration_invalid",
        ),
        (Reply::Subscriptions(json!([])), "configuration_invalid"),
        (
            Reply::Subscriptions(observe_only),
            "no_applicable_subscriptions",
        ),
        (
            Reply::Subscriptions(local_secret),
            "configuration_local_secret",
        ),
        (rpc(-32000), "configuration_unavailable"),
    ] {
        let backoff = Duration::from_millis(5);
        let backend = Scripted::new([reply, Reply::Subscriptions(intercept())]);
        let provider = Arc::new(Prepared::default());
        let (options, seen) = options(
            &[("com.a", backend.clone())],
            Some(provider.clone()),
            backoff,
        );
        let hooks = Hooks::new(registration(&["com.a"]), options).unwrap();
        block_on(hooks.initialize()).unwrap();
        assert_eq!(*seen.lock().unwrap(), [diagnostic("com.a", code)]);
        std::thread::sleep(backoff * 2);
        provider.0.fetch_add(1, Ordering::SeqCst);
        event(&hooks);
        block_on(hooks.initialize()).unwrap();
        let retried = code == "configuration_unavailable";
        assert_eq!(
            backend.configuration_calls(),
            1 + usize::from(retried),
            "{code}"
        );
        assert_eq!(hooks.intercepts(generated::EventType::ToolBefore), retried);
    }
    // A transport this client cannot open is reported, never retried.
    let seen: Seen = Arc::default();
    let sink = seen.clone();
    let mut unopenable = registration(&["com.a"]);
    unopenable["hooks"][0]["transport"]["url"] = json!("http://com.a/hooks");
    let options = HooksOptions::new(
        "urn:example:host",
        Harness::new("test", "1"),
        HostCapabilities::default(),
    )
    .on_configuration_skipped(move |d| sink.lock().unwrap().push(serde_json::to_value(d).unwrap()));
    let hooks = Hooks::new(unopenable, options).unwrap();
    block_on(hooks.initialize()).unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        [diagnostic("com.a", "configuration_invalid")]
    );
    // So is one whose local auth cannot be built: invalid, with no auth fields.
    for authentication in [
        json!({"type":"bearer","tokenEnv":"AHP_TEST_UNSET_TOKEN_ENV"}),
        json!({"type":"oauth","flow":"client_credentials","issuer":"https://issuer.example",
            "resource":"https://com.a/hooks","clientId":"client"}),
    ] {
        let seen: Seen = Arc::default();
        let sink = seen.clone();
        let mut unbuildable = registration(&["com.a"]);
        unbuildable["hooks"][0]["authentication"] = authentication;
        let options = HooksOptions::new(
            "urn:example:host",
            Harness::new("test", "1"),
            HostCapabilities::default(),
        )
        .on_configuration_skipped(move |d| {
            sink.lock().unwrap().push(serde_json::to_value(d).unwrap())
        });
        let hooks = Hooks::new(unbuildable, options).unwrap();
        block_on(hooks.initialize()).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            [diagnostic("com.a", "configuration_invalid")]
        );
    }
}

#[test]
pub(crate) fn configuration_retry_atomic_routes() {
    let backoff = Duration::from_millis(5);
    let (release, wait) = oneshot::channel();
    let a = Scripted::new([
        Reply::Fail(unavailable()),
        Reply::Subscriptions(intercept()),
    ]);
    let b = Scripted::new([Reply::Fail(unavailable()), Reply::Wait(wait)]);
    let (options, seen) = options(&[("com.a", a.clone()), ("com.b", b.clone())], None, backoff);
    let hooks = Hooks::new(registration(&["com.a", "com.b"]), options).unwrap();
    block_on(hooks.initialize()).unwrap();
    assert_eq!(seen.lock().unwrap().len(), 2);
    std::thread::sleep(backoff * 2);
    block_on(async {
        let retry = hooks.initialize();
        let observer = async {
            // `a` answered and `b` is in flight: no partial route set is visible,
            // and a concurrent admission uses the previous routes at once.
            assert_eq!(a.configuration_calls(), 2);
            assert_eq!(b.configuration_calls(), 2);
            assert!(!hooks.intercepts(generated::EventType::ToolBefore));
            admit(&hooks).await;
            assert_eq!(a.count("hooks/intercept") + b.count("hooks/intercept"), 0);
            release.send(intercept()).unwrap();
        };
        let (retried, ()) = futures::join!(retry, observer);
        retried.unwrap();
    });
    assert!(hooks.intercepts(generated::EventType::ToolBefore));
    let routes = hooks.routes();
    let backends: Vec<_> = routes.iter().map(|r| r.backend_id.as_str()).collect();
    assert_eq!(backends, ["com.a", "com.b"]);
    // The earlier event is not replayed; the next one reaches both, once each.
    assert_eq!(a.count("hooks/intercept") + b.count("hooks/intercept"), 0);
    event(&hooks);
    assert_eq!(
        (a.count("hooks/intercept"), b.count("hooks/intercept")),
        (1, 1)
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[test]
fn many_admissions_share_one_retry() {
    let backoff = Duration::from_millis(5);
    let (release, wait) = oneshot::channel();
    let (first, gate) = oneshot::channel();
    let a = Scripted::new([
        Reply::Wait(gate),
        Reply::Fail(unavailable()),
        Reply::Wait(wait),
    ]);
    let b = Scripted::new([
        Reply::Fail(unavailable()),
        Reply::Subscriptions(intercept()),
    ]);
    let (options, _) = options(&[("com.a", a.clone()), ("com.b", b.clone())], None, backoff);
    let hooks = Hooks::new(registration(&["com.a", "com.b"]), options).unwrap();
    // Concurrent initial admissions wait for one discovery per backend.
    block_on(async {
        let waiters = futures::future::join_all((0..10).map(|_| hooks.initialize()));
        let open = async {
            first.send(intercept()).unwrap();
        };
        let (results, ()) = futures::join!(waiters, open);
        assert!(results.into_iter().all(|r| r.is_ok()));
    });
    assert_eq!((a.configuration_calls(), b.configuration_calls()), (1, 1));
    std::thread::sleep(backoff * 2);
    block_on(async {
        let retry = hooks.initialize();
        let others = async {
            for _ in 0..20 {
                admit(&hooks).await;
                hooks.initialize().await.unwrap();
            }
            release.send(intercept()).unwrap();
        };
        let (retried, ()) = futures::join!(retry, others);
        retried.unwrap();
    });
    // a: admitted at first; b: one failed initial attempt and one shared retry.
    assert_eq!((a.configuration_calls(), b.configuration_calls()), (1, 2));
    assert!(hooks.intercepts(generated::EventType::ToolBefore));
}

#[test]
fn dropped_caller_does_not_cancel_discovery() {
    let backoff = Duration::from_millis(5);
    let (release, wait) = oneshot::channel::<Value>();
    let a = Scripted::new([Reply::Fail(unavailable()), Reply::Wait(wait)]);
    let (first, seen) = options(&[("com.a", a.clone())], None, backoff);
    let hooks = Hooks::new(registration(&["com.a"]), first).unwrap();
    block_on(hooks.initialize()).unwrap();
    std::thread::sleep(backoff * 2);
    // A dropped caller leaves the re-attempt in flight; nothing restarts it.
    {
        let mut retry = Box::pin(hooks.initialize());
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        assert!(retry.as_mut().poll(&mut cx).is_pending());
    }
    event(&hooks);
    assert_eq!(a.configuration_calls(), 2);
    assert_eq!(seen.lock().unwrap().len(), 1);
    release.send(intercept()).unwrap();
    block_on(hooks.initialize()).unwrap();
    assert_eq!(a.configuration_calls(), 2);
    assert!(hooks.intercepts(generated::EventType::ToolBefore));
    // Retries reuse the transport Hooks owns, so none is left open.
    block_on(hooks.shutdown()).unwrap();
    assert_eq!(a.shutdowns.load(Ordering::SeqCst), 1);
    // Shutdown cancels an in-flight discovery: an error, never a diagnostic.
    let (_release, wait) = oneshot::channel::<Value>();
    let b = Scripted::new([Reply::Wait(wait)]);
    let (second, seen) = options(&[("com.b", b.clone())], None, backoff);
    let hooks = Hooks::new(registration(&["com.b"]), second).unwrap();
    let mut initialization = Box::pin(hooks.initialize());
    let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
    assert!(initialization.as_mut().poll(&mut cx).is_pending());
    block_on(hooks.shutdown()).unwrap();
    assert_eq!(
        block_on(initialization).unwrap_err().code(),
        generated::DeliveryDiagnosticCode::Cancelled
    );
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(b.shutdowns.load(Ordering::SeqCst), 1);
}

/// An explicit fail-closed backend beside a discovered one.
fn mixed() -> Value {
    let mut registration = registration(&["com.e", "com.s"]);
    let mut explicit = intercept();
    explicit[0]["failurePolicy"] = json!("fail-closed");
    registration["hooks"][0]["subscriptions"] = explicit;
    registration
}
/// A runtime-free wakeup for an event deadline.
fn timer(within: Duration) -> impl Future<Output = ()> + Send {
    let (fire, fired) = oneshot::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(within);
        let _ = fire.send(());
    });
    async move {
        let _ = fired.await;
    }
}
fn deadline_event(hooks: &Hooks, within: Duration) -> Result<(), HookError> {
    block_on(
        hooks
            .tool_input(json!({"command":"x"}))
            .context(ToolContext::new(
                json!({"tool":{"name":"shell","kind":"shell","origin":"native"},
                "call":{"id":"call-1"},"path":"native"}),
            ))
            .deadline_with(Instant::now() + within, timer(within))
            .into_future(),
    )
    .map(|_| ())
}

#[test]
fn hung_retry_does_not_delay_fail_closed_delivery() {
    let backoff = Duration::from_millis(5);
    let (_never, wait) = oneshot::channel::<Value>();
    let e = Scripted::new([]);
    let s = Scripted::new([Reply::Fail(unavailable()), Reply::Wait(wait)]);
    let (options, _) = options(&[("com.e", e.clone()), ("com.s", s.clone())], None, backoff);
    let hooks = Hooks::new(mixed(), options).unwrap();
    block_on(hooks.initialize()).unwrap();
    std::thread::sleep(backoff * 2);
    let started = Instant::now();
    for _ in 0..3 {
        deadline_event(&hooks, Duration::from_millis(200)).unwrap();
    }
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(e.count("hooks/intercept"), 3);
    assert_eq!(
        s.configuration_calls(),
        2,
        "one hung re-attempt, never restarted"
    );
}

#[test]
fn short_deadlines_do_not_starve_slow_discovery() {
    let backoff = Duration::from_millis(5);
    let (release, wait) = oneshot::channel::<Value>();
    let e = Scripted::new([]);
    let s = Scripted::new([Reply::Fail(unavailable()), Reply::Wait(wait)]);
    let (options, _) = options(&[("com.e", e.clone()), ("com.s", s.clone())], None, backoff);
    let hooks = Hooks::new(mixed(), options).unwrap();
    block_on(hooks.initialize()).unwrap();
    std::thread::sleep(backoff * 2);
    for _ in 0..5 {
        deadline_event(&hooks, Duration::from_millis(1)).ok();
    }
    assert_eq!(
        s.configuration_calls(),
        2,
        "short deadlines never restart it"
    );
    // The slow backend answers; the same in-flight attempt completes.
    release.send(intercept()).unwrap();
    deadline_event(&hooks, Duration::from_millis(200)).unwrap();
    deadline_event(&hooks, Duration::from_millis(200)).unwrap();
    assert_eq!(s.configuration_calls(), 2);
    assert!(s.count("hooks/intercept") >= 1);
}

/// A host prepare that lands while an attempt is in flight is not lost: the
/// count observed before the attempt is what the skip records.
#[test]
fn prepare_during_attempt_is_not_lost() {
    let backoff = Duration::from_secs(3600);
    let provider = Arc::new(Prepared::default());
    let during = |provider: &Arc<Prepared>| {
        let provider = provider.clone();
        Reply::FailDuring(
            Box::new(move || {
                provider.0.fetch_add(1, Ordering::SeqCst);
            }),
            HookError::authentication(AuthErrorCode::InteractionRequired),
        )
    };
    let a = Scripted::new([
        during(&provider),
        during(&provider),
        Reply::Subscriptions(intercept()),
    ]);
    let (options, _) = options(&[("com.a", a.clone())], Some(provider.clone()), backoff);
    let hooks = Hooks::new(registration(&["com.a"]), options).unwrap();
    // Initial discovery: prepared mid-flight, so the next admission re-attempts.
    block_on(hooks.initialize()).unwrap();
    event(&hooks);
    assert_eq!(a.configuration_calls(), 2);
    // The same holds for a prepare during a re-attempt.
    event(&hooks);
    assert_eq!(a.configuration_calls(), 3);
    assert!(hooks.intercepts(generated::EventType::ToolBefore));
}

/// A successful host prepare resets the backoff to its initial delay.
#[test]
fn prepare_resets_backoff() {
    let initial = Duration::from_secs(10);
    let backend = Scripted::new((0..5).map(|_| Reply::Fail(unavailable())));
    let provider = Arc::new(Prepared::default());
    let (options, _) = options(
        &[("com.a", backend.clone())],
        Some(provider.clone()),
        initial,
    );
    let hooks = Hooks::new(registration(&["com.a"]), options).unwrap();
    let delay = |hooks: &Hooks, before: Instant| {
        let pending = hooks.discovery.pending.lock().unwrap();
        (pending[0].retry_at.unwrap() - before).as_secs()
    };
    let mut before = Instant::now();
    block_on(hooks.initialize()).unwrap();
    assert_eq!(delay(&hooks, before), 10);
    // Two elapsed backoffs grow the delay to 40s.
    for expected in [20, 40] {
        before = Instant::now();
        hooks.discovery.pending.lock().unwrap()[0].retry_at = Some(before);
        block_on(hooks.initialize()).unwrap();
        assert_eq!(delay(&hooks, before), expected);
    }
    // A prepare makes it eligible at once and the failed attempt starts over.
    provider.0.fetch_add(1, Ordering::SeqCst);
    before = Instant::now();
    block_on(hooks.initialize()).unwrap();
    assert_eq!(backend.configuration_calls(), 4);
    assert_eq!(delay(&hooks, before), 10);
    assert_eq!(
        hooks.discovery.pending.lock().unwrap()[0].delay,
        initial * 2
    );
}

/// Nothing drives a queued task without a runtime; drop and shutdown release
/// it, so the routes and transports it holds are freed.
#[test]
fn drop_and_shutdown_release_undriven_discovery() {
    for shutdown in [false, true] {
        let backoff = Duration::from_millis(5);
        let (_never, wait) = oneshot::channel::<Value>();
        let (_never_too, wait_too) = oneshot::channel::<Value>();
        let a = Scripted::new([Reply::Subscriptions(intercept())]);
        let b = Scripted::new([Reply::Fail(unavailable()), Reply::Wait(wait)]);
        let c = Scripted::new([Reply::Wait(wait_too)]);
        let (first, _) = options(&[("com.a", a.clone()), ("com.b", b.clone())], None, backoff);
        let hooks = Hooks::new(registration(&["com.a", "com.b"]), first).unwrap();
        block_on(hooks.initialize()).unwrap();
        std::thread::sleep(backoff * 2);
        // An event queues a re-attempt of `b` and returns; nothing polls it again.
        event(&hooks);
        assert_eq!(b.configuration_calls(), 2);
        assert!(hooks.discovery.task.lock().unwrap().is_some());
        // An undriven first initialization of another client.
        let (second, _) = options(&[("com.c", c.clone())], None, backoff);
        let other = Hooks::new(registration(&["com.c"]), second).unwrap();
        {
            let mut first = Box::pin(other.initialize());
            let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
            assert!(first.as_mut().poll(&mut cx).is_pending());
        }
        if shutdown {
            block_on(hooks.shutdown()).unwrap();
            block_on(other.shutdown()).unwrap();
            assert!(hooks.discovery.task.lock().unwrap().is_none());
            assert!(other.discovery.task.lock().unwrap().is_none());
        }
        drop(hooks);
        drop(other);
        assert_eq!(
            (
                Arc::strong_count(&a),
                Arc::strong_count(&b),
                Arc::strong_count(&c)
            ),
            (1, 1, 1),
            "shutdown first: {shutdown}"
        );
    }
}

/// A dropped event does not cancel the first initialization it waited on:
/// the next caller continues the same attempt.
#[test]
fn dropped_event_does_not_cancel_first_initialization() {
    let (release, wait) = oneshot::channel::<Value>();
    let a = Scripted::new([Reply::Wait(wait), Reply::Subscriptions(intercept())]);
    let (options, seen) = options(&[("com.a", a.clone())], None, Duration::from_secs(60));
    let hooks = Hooks::new(registration(&["com.a"]), options).unwrap();
    {
        let mut admitted = Box::pin(admit(&hooks));
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        assert!(admitted.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(a.configuration_calls(), 1);
    release.send(intercept()).unwrap();
    event(&hooks);
    assert_eq!(a.configuration_calls(), 1, "the same attempt completed");
    assert!(hooks.intercepts(generated::EventType::ToolBefore));
    assert_eq!(a.count("hooks/intercept"), 1);
    assert!(seen.lock().unwrap().is_empty());
}
