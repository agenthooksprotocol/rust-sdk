use agenthooksprotocol::client::{
    Client, Decision, FailurePolicy, Hook, HookError, LocalFuture, Subscription, ToolContext,
};
use futures::executor::block_on;
use serde_json::{Value, json};
use std::{
    future::IntoFuture,
    sync::{Arc, Mutex},
};

fn context() -> ToolContext {
    ToolContext::new(
        json!({"id":"evt_native","source":"https://example.test/runtime","type":"tool.before","time":"2026-08-24T08:51:14Z","path":"native","session":{"id":"s"},"call":{"id":"c"},"tool":{"name":"counter","kind":"file_read","origin":"native","input":{}}}),
    )
}
struct Capture(Arc<Mutex<Vec<Value>>>);
impl Hook for Capture {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(request.clone());
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":[]}}),
            )
        })
    }
}
impl agenthooksprotocol::adapters::registered::ManagedBackend for Capture {
    fn call(
        &self,
        request: Value,
        _: std::time::Duration,
    ) -> LocalFuture<'_, Result<Value, HookError>> {
        Hook::call(self, request)
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}
#[test]
fn complete_native_snapshot_reaches_each_subscription_without_loss() {
    let calls = Arc::new(Mutex::new(vec![]));
    let client = Client::new(context())
        .with_subscription(Subscription::intercept(
            "a",
            FailurePolicy::Closed,
            Capture(calls.clone()),
        ))
        .with_subscription(Subscription::intercept(
            "b",
            FailurePolicy::Closed,
            Capture(calls.clone()),
        ));
    let native = json!({"permission":"allow","candidate":{"value":null,"provenance":{"native":"cache"}},"flow":"none","instructions":["retain native context"],"injections":[],"com.example.state":true});
    let result = block_on(async {
        client
            .tool_before(json!({"count":1}))
            .initial_snapshot(native.clone())
            .unwrap()
            .await
            .unwrap()
    });
    assert_eq!(result.permission(), Decision::Allow);
    assert_eq!(result.outcome.candidate(), Some(&Value::Null));
    assert_eq!(result.outcome.instructions, ["retain native context"]);
    assert_eq!(result.outcome.responses.len(), 2);
    assert_eq!(result.outcome.responses[0]["result"]["effects"], json!([]));
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    for call in calls.iter() {
        assert_eq!(call["params"]["state"], native);
    }
}
#[test]
fn native_stop_does_not_authorize_execution() {
    let client = Client::new(context());
    let result = block_on(async {
        client
            .tool_before(json!({}))
            .initial_snapshot(json!({"permission":"allow","candidate":null,"flow":"stop"}))
            .unwrap()
            .await
            .unwrap()
    });
    assert_eq!(result.permission(), Decision::Allow);
    assert!(result.outcome.stopped);
    assert!(!result.outcome.can_execute());
}
#[test]
fn ordinary_futures_and_progress_are_movable_between_threads() {
    fn send<T: Send>(_: T) {}
    fn shared<T: Send + Sync>() {}
    shared::<Client>();
    shared::<agenthooksprotocol::client::BoundaryProgress>();
    shared::<agenthooksprotocol::Hooks>();
    let client = Client::new(context());
    send(client.tool_before(json!({})).into_future());
    send(client.event(context().event).into_future());
}

#[test]
fn generated_capability_declarations_are_immutable_and_boundary_checked() {
    use agenthooksprotocol::{
        EventType, Hooks,
        capability::{self, ModifyOperation},
        hooks::{EventGrant, HooksOptions},
    };
    let base = capability::intercept().deny();
    let modified = base.modify_input([ModifyOperation::Replace]).unwrap();
    assert_eq!(
        serde_json::to_value(&base).unwrap()["capabilities"]["effects"],
        json!(["deny"])
    );
    assert_eq!(
        serde_json::to_value(&modified).unwrap()["modes"],
        json!(["intercept", "observe"])
    );
    assert!(base.modify_input([]).is_err());
    assert!(EventGrant::from_declaration(capability::intercept()).is_err());
    let registration = json!({"protocolVersion":"draft","hooks":[{"id":"org.example.capabilities","transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},"subscriptions":[{"events":["tool.before"],"mode":"intercept","timeoutMs":1000,"failurePolicy":"fail-closed","content":{"default":"metadata"}}]}]});
    let options =
        HooksOptions::from_declarations("urn:typed-host", [(EventType::ToolBefore, modified)])
            .unwrap();
    let hooks = Hooks::new(
        registration.clone(),
        options.with_backend(
            "org.example.capabilities",
            Arc::new(Capture(Arc::new(Mutex::new(vec![])))),
        ),
    )
    .unwrap();
    assert_eq!(
        hooks.manifest()["events"][0]["modes"],
        json!(["intercept", "observe"])
    );
    let invalid =
        HooksOptions::from_declarations("urn:typed-host", [(EventType::SessionEnd, base)]).unwrap();
    assert!(
        Hooks::new(
            registration,
            invalid.with_backend(
                "org.example.capabilities",
                Arc::new(Capture(Arc::new(Mutex::new(vec![]))))
            )
        )
        .is_err()
    );
}

#[test]
fn generated_effect_helpers_return_canonical_effects() {
    use agenthooksprotocol::effect;
    assert_eq!(
        serde_json::to_value(effect::deny("reason".into())).unwrap(),
        json!({"type":"deny","reason":"reason"})
    );
    assert_eq!(
        serde_json::to_value(effect::modify_input::replace(json!({"x":2}))).unwrap(),
        json!({"type":"modify","target":"input","operation":"replace","value":{"x":2}})
    );
    assert_eq!(
        serde_json::to_value(effect::return_(Value::Null)).unwrap(),
        json!({"type":"return","value":null})
    );
}

struct Reply(Value);
impl Hook for Reply {
    fn call(&self, request: Value) -> LocalFuture<'_, Result<Value, HookError>> {
        let mut reply = self.0.clone();
        reply["id"] = request["id"].clone();
        Box::pin(async move { Ok(reply) })
    }
}
#[test]
fn diagnostics_distinguish_remote_rpc_from_malformed_envelopes_without_leaking_data() {
    use agenthooksprotocol::DeliveryDiagnosticCode as Code;
    for (response, code) in [
        (
            json!({"jsonrpc":"2.0","error":{"code":-32000,"message":"private backend secret","data":{"token":"private"}}}),
            Code::RemoteRpc,
        ),
        (
            json!({"jsonrpc":"2.0","error":{"code":"bad","message":"private backend secret"}}),
            Code::ProtocolRejection,
        ),
        (
            json!({"jsonrpc":"2.0","result":{"protocolVersion":"draft","effects":[]},"error":{"code":-32000,"message":"private"}}),
            Code::ProtocolRejection,
        ),
    ] {
        let client = Client::new(context()).with_subscription(Subscription::intercept(
            "policy",
            FailurePolicy::Closed,
            Reply(response),
        ));
        let result = block_on(async { client.tool_before(json!({})).await.unwrap() });
        assert_eq!(result.permission(), Decision::Deny);
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(result.diagnostics[0].code, code);
        assert!(result.diagnostics[0].synthetic_denial);
        assert_eq!(result.diagnostics[0].subscription_id, "policy");
        assert!(!format!("{:?}", result.diagnostics).contains("private"));
        assert!(
            !result.outcome.failures[0]
                .error
                .to_string()
                .contains("private")
        );
    }
}
#[test]
fn generated_state_candidate_distinguishes_null_from_absence() {
    use agenthooksprotocol::{Permission, state};
    let empty = serde_json::to_value(state::initial(Permission::Allow)).unwrap();
    let supplied = serde_json::to_value(
        state::initial(Permission::Allow).candidate(state::Candidate::new(Value::Null)),
    )
    .unwrap();
    assert_eq!(empty["candidate"], Value::Null);
    assert_eq!(supplied["candidate"], json!({"value":null}));
}
