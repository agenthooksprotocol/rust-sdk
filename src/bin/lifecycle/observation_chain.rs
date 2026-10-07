use super::*;
use agenthooksprotocol::client::{
    Client, FailurePolicy, Hook, HookError, LocalFuture, Subscription, ToolContext,
};
use std::future::IntoFuture;

// This adapter supplies only transport and the receiver's test-controller gates.
// One SDK operation owns the entire serial chain and its observation plan.
struct ChainHook {
    wire: EventWire,
    control_http: reqwest::blocking::Client,
    control: String,
    subscription: Value,
    interrupt: bool,
    called: Arc<Mutex<Vec<Value>>>,
    workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
}
impl Hook for ChainHook {
    fn call(&self, mut request: Value) -> LocalFuture<'_, std::result::Result<Value, HookError>> {
        Box::pin(async move {
            let observe = request["method"] == "hooks/observe";
            let event = &mut request["params"]["event"];
            if self.subscription["content"] == "omit" {
                event["items"] = json!([]);
            } else if let Some(items) = event.get_mut("items").and_then(Value::as_array_mut) {
                for item in items {
                    let item = item
                        .as_object_mut()
                        .ok_or_else(|| HookError("invalid item".into()))?;
                    item.remove("body");
                    item.remove("gap");
                    item.insert("selection".into(), json!("metadata"));
                }
            }
            let count = if observe {
                0
            } else {
                let mut called = self.called.lock().unwrap();
                called.push(self.subscription["id"].clone());
                called.len()
            };
            let wire = self.wire.clone();
            let http = self.control_http.clone();
            let control = self.control.clone();
            let interrupt = self.interrupt;
            let (tx, rx) = futures::channel::oneshot::channel();
            self.workers.lock().unwrap().push(thread::spawn(move || {
                let result = (|| -> Result<Value> {
                    if observe {
                        if let Some(stdin) = &wire.stdin {
                            let mut stdin = stdin.lock().unwrap();
                            writeln!(stdin, "{request}")?;
                            stdin.flush()?;
                        } else {
                            wire.event_http
                                .post(format!("{}/observe", wire.endpoint))
                                .bearer_auth(&wire.token)
                                .json(&request)
                                .send()?
                                .error_for_status()?;
                        }
                        return Ok(Value::Null);
                    }
                    let id = s(&request, "id");
                    let reply = wire.send(&request)?;
                    http.post(format!("{control}/wait"))
                        .json(&json!({"id":id,"count":count}))
                        .send()?
                        .error_for_status()?;
                    if !interrupt {
                        http.post(format!("{control}/release"))
                            .json(&json!({"id":id}))
                            .send()?
                            .error_for_status()?;
                    }
                    Ok(reply
                        .recv_timeout(TIMEOUT)?
                        .map_err(|e| format!("transport: {e}"))?)
                })();
                // After cancellation this send fails: the SDK operation, not the
                // late transport response, owns permission to resume the chain.
                let _ = tx.send(result.map_err(|e| HookError(e.to_string())));
            }));
            rx.await.map_err(|e| HookError(e.to_string()))?
        })
    }
}

pub(super) fn run(
    scenario: &Value,
    transport: &mut Transport,
    validation: &Validation,
) -> Result<Value> {
    let original = &scenario["requests"]["a"];
    validation.core.validate("intercept-request", original)?;
    let id = s(original, "id");
    let called = Arc::new(Mutex::new(Vec::new()));
    let workers = Arc::new(Mutex::new(Vec::new()));
    let interrupted = scenario["chain"]["interrupt"] == true;
    let mut client = Client::new(ToolContext::new(original["params"]["event"].clone()));
    for subscription in scenario["chain"]["subscriptions"]
        .as_array()
        .ok_or("missing subscriptions")?
    {
        let hook = ChainHook {
            wire: transport.event_wire(),
            control_http: transport.http.clone(),
            control: transport.control.clone(),
            subscription: subscription.clone(),
            interrupt: interrupted,
            called: called.clone(),
            workers: workers.clone(),
        };
        let subscription = if subscription["mode"] == "observe" {
            Subscription::observe(s(subscription, "id"), hook)
        } else {
            Subscription::intercept(
                s(subscription, "id"),
                if subscription["failurePolicy"] == "fail-closed" {
                    FailurePolicy::Closed
                } else {
                    FailurePolicy::Open
                },
                hook,
            )
        };
        client = client.with_subscription(subscription);
    }
    let boundary = client
        .tool_before(original["params"]["event"]["tool"]["input"].clone())
        .initial_snapshot(original["params"]["state"].clone())?
        .capabilities(original["params"]["capabilities"].clone());
    let progress = boundary.progress();
    let mut operation = boundary.into_future();
    let result = if interrupted {
        // Start the real operation, wait for receiver acquisition, then drop
        // its pending future. No failed-hook policy or observation phase runs.
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        if operation.as_mut().poll(&mut cx).is_ready() {
            return Err("chain completed before the cancellation gate".into());
        }
        transport.control("/wait", &json!({"id":id,"count":1}))?;
        transport.control(
            "/mark",
            &json!({"scenario":scenario["id"],"kind":"cancelled","id":id}),
        )?;
        drop(operation);
        None
    } else {
        Some(futures::executor::block_on(operation)?)
    };
    transport.control(
        "/mark",
        &json!({"scenario":scenario["id"],"kind":"chain-settled","id":id}),
    )?;
    let (input, failures, observations) = if let Some(result) = result {
        let observations = result
            .observations
            .iter()
            .map(|o| json!(o.subscription_id))
            .collect::<Vec<_>>();
        let failures = result
            .outcome
            .failures
            .iter()
            .map(|f| json!(f.subscription_id))
            .collect::<Vec<_>>();
        // Poll all SDK-issued observation deliveries before the controller drains
        // them; held observers must never gate boundary settlement.
        thread::scope(|scope| -> Result<()> {
            let handles = result
                .observations
                .into_iter()
                .map(|observation| {
                    scope.spawn(move || futures::executor::block_on(observation.deliver()))
                })
                .collect::<Vec<_>>();
            if !observations.is_empty() {
                transport.control(
                    "/wait-observed",
                    &json!({"eventId":id,"count":observations.len()}),
                )?;
            }
            if scenario["chain"]["holdObservers"] == true {
                transport.control("/release", &json!({"id":format!("{id}:observers")}))?;
            }
            for handle in handles {
                handle.join().map_err(|_| "observer worker panicked")??;
            }
            Ok(())
        })?;
        (result.effective_input, failures, observations)
    } else {
        // Drain only the already-started wire call after operation cancellation.
        transport.control("/release", &json!({"id":id}))?;
        let snapshot = progress.snapshot();
        assert_eq!(
            snapshot.status,
            agenthooksprotocol::client::BoundaryStatus::Interrupted
        );
        (
            snapshot
                .partial
                .map(|p| p.effective_input)
                .unwrap_or_else(|| original["params"]["event"]["tool"]["input"].clone()),
            vec![],
            vec![],
        )
    };
    for worker in workers.lock().unwrap().drain(..) {
        worker.join().map_err(|_| "transport worker panicked")?;
    }
    Ok(
        json!({"called":*called.lock().unwrap(),"failures":failures,"observations":observations,"input":input}),
    )
}
