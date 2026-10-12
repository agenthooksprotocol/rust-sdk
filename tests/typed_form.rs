#![cfg(feature = "typed-form")]
use agenthooksprotocol::capability;

use agenthooksprotocol::form::{Form, FormAnswer, decode_url_result};
use agenthooksprotocol::generated::{ElicitResult, McpElicitationElicitResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Answer {
    user_name: String,
    #[schemars(range(min = 1, max = 10))]
    count: i32,
    enabled: bool,
    choice: Choice,
    choices: Vec<Choice>,
    #[serde(default)]
    note: String,
}
#[derive(Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum Choice {
    First,
    Second,
}
fn wire_result(value: serde_json::Value) -> McpElicitationElicitResult {
    serde_json::from_value(value).unwrap()
}
fn result<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> ElicitResult<T> {
    serde_json::from_value(value).unwrap()
}
fn content() -> serde_json::Value {
    json!({"userName":"Ada", "count":2, "enabled":true,"choice":"first", "choices":["second"]})
}

#[test]
fn single_declaration_drives_wire_and_answer() {
    let form = Form::<Answer>::new().unwrap();
    assert_eq!(
        serde_json::to_value(form.requested_schema()).unwrap()["type"],
        "object"
    );
    let wire = serde_json::to_value(form.request("Tell us")).unwrap();
    assert_eq!(wire["mode"], "form");
    assert_eq!(wire["message"], "Tell us");
    let schema = &wire["requestedSchema"];
    assert_eq!(schema["properties"]["count"]["minimum"], 1);
    assert_eq!(
        schema["properties"]["choice"]["enum"],
        json!(["first", "second"])
    );
    assert_eq!(
        schema["properties"]["choices"]["items"]["enum"],
        json!(["first", "second"])
    );
    assert!(
        !schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("note"))
    );
    assert!(schema.get("$defs").is_none());
    let answer = form
        .decode(&result(json!({"action":"accept","content":content()})))
        .unwrap();
    let FormAnswer::Accepted(answer) = answer else {
        panic!("expected answer")
    };
    assert_eq!(answer.user_name, "Ada");
    assert_eq!(answer.note, "");
    let accepted = form.accept(&answer).unwrap();
    assert_eq!(
        form.decode(&accepted).unwrap(),
        FormAnswer::Accepted(answer)
    );
}

#[test]
fn constraints_and_required_fields_are_validated() {
    let form = Form::<Answer>::new().unwrap();
    for bad in [
        json!({}),
        {
            let mut value = content();
            value["count"] = json!(11);
            value
        },
        {
            let mut value = content();
            value["choice"] = json!("third");
            value
        },
        {
            let mut value = content();
            value["choices"] = json!(["third"]);
            value
        },
        {
            let mut value = content();
            value["enabled"] = json!("true");
            value
        },
        {
            let mut value = content();
            value["extra"] = json!(true);
            value
        },
    ] {
        assert!(
            form.decode_wire(&wire_result(json!({"action":"accept","content":bad})))
                .is_err()
        );
    }
    assert!(
        form.decode_wire(&wire_result(json!({"action":"accept"})))
            .is_err()
    );
}

#[test]
fn decline_cancel_and_url_never_have_content() {
    let form = Form::<Answer>::new().unwrap();
    for action in ["decline", "cancel"] {
        let response = wire_result(json!({"action":action}));
        assert!(form.decode_wire(&response).is_ok());
        assert!(decode_url_result(&response).is_ok());
        let response = wire_result(json!({"action":action,"content":{}}));
        assert!(form.decode_wire(&response).is_err());
        assert!(decode_url_result(&response).is_err());
    }
    assert!(decode_url_result(&wire_result(json!({"action":"accept"}))).is_ok());
    assert!(decode_url_result(&wire_result(json!({"action":"accept","content":{}}))).is_err());
    assert!(
        form.decode_wire(&wire_result(json!({"action":"future"})))
            .is_err()
    );
}

#[test]
fn unsupported_shapes_fail_before_request() {
    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Nested {
        answer: Inner,
    }
    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Inner {
        value: String,
    }
    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Nullable {
        value: Option<String>,
    }
    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Array {
        values: Vec<String>,
    }
    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Pattern {
        #[schemars(regex(pattern = "^a"))]
        value: String,
    }
    assert!(Form::<Nested>::new().is_err());
    assert!(Form::<Nullable>::new().is_err());
    assert!(Form::<Array>::new().is_err());
    assert!(Form::<Pattern>::new().is_err());
    assert!(Form::<String>::new().is_err());
}

#[test]
fn accepted_empty_form_can_omit_content() {
    #[derive(Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
    struct Empty {}
    let form = Form::<Empty>::new().unwrap();
    assert_eq!(
        form.decode(&result(json!({"action":"accept"}))).unwrap(),
        FormAnswer::Accepted(Empty {})
    );
}

#[test]
fn scalar_constraints_and_large_integer_answers_survive_projection() {
    #[derive(Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
    struct Scalars {
        #[schemars(length(min = 2, max = 4))]
        label: String,
        #[schemars(email)]
        email: String,
        #[schemars(range(min = 0.5, max = 1.5))]
        ratio: f64,
        large: u64,
    }
    let form = Form::<Scalars>::new().unwrap();
    let answer = Scalars {
        label: "Ada".into(),
        email: "ada@example.com".into(),
        ratio: 1.0,
        large: u64::MAX,
    };
    let accepted = form.accept(&answer).unwrap();
    assert_eq!(
        form.decode(&accepted).unwrap(),
        FormAnswer::Accepted(answer)
    );
    for bad in [
        json!({"label":"A", "email":"ada@example.com", "ratio":1.0, "large":1}),
        json!({"label":"Ada", "email":"not-an-email", "ratio":1.0, "large":1}),
        json!({"label":"Ada", "email":"ada@example.com", "ratio":2.0, "large":1}),
    ] {
        assert!(
            form.decode_wire(&wire_result(json!({"action":"accept", "content":bad})))
                .is_err()
        );
    }
}

#[test]
fn recursive_and_composite_shapes_are_rejected_without_recursing() {
    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Recursive {
        values: Vec<Recursive>,
    }
    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Composite {
        value: Union,
    }
    #[derive(Serialize, Deserialize, JsonSchema)]
    #[serde(untagged)]
    enum Union {
        Text(String),
        Number(i32),
    }
    assert!(Form::<Recursive>::new().is_err());
    assert!(Form::<Composite>::new().is_err());
}

#[test]
fn declared_form_answers_are_admitted_atomically_through_public_hooks() {
    use agenthooksprotocol::{
        Hooks,
        adapters::registered::ManagedBackend,
        client::{HookError, LocalFuture},
        hooks::HooksOptions,
    };
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    struct Replies {
        requests: Arc<Mutex<Vec<serde_json::Value>>>,
    }
    impl ManagedBackend for Replies {
        fn call(
            &self,
            request: serde_json::Value,
            _: Duration,
        ) -> LocalFuture<'_, Result<serde_json::Value, HookError>> {
            Box::pin(async move {
                let mut requests = self.requests.lock().unwrap();
                let index = requests.len();
                requests.push(request.clone());
                let effects = if index == 0 {
                    json!([{"type":"message","text":"must roll back"},{"type":"return","value":{"action":"accept","content":{"count":0}}}])
                } else if index == 2 {
                    json!([{"type":"return","value":{"action":"accept","content":{"count":3},"_meta":{"trace":"keep"},"vendor":{"opaque":[1,2]}}}])
                } else {
                    json!([])
                };
                Ok(
                    json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":effects}}),
                )
            })
        }
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { Ok(()) })
        }
    }
    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Count {
        #[schemars(range(min = 1, max = 10))]
        count: u64,
    }
    futures::executor::block_on(async {
        let form = Form::<Count>::new().unwrap();
        let requests = Arc::new(Mutex::new(vec![]));
        let sub = json!({"events":["user.elicitation.request"],"mode":"intercept","failurePolicy":"fail-open","timeoutMs":1000,"content":{"default":"body"}});
        let hooks=Hooks::new(json!({"protocolVersion":"draft","hooks":[{"id":"org.example.form","transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},"subscriptions":[sub.clone(),sub]}]}),
            HooksOptions::new("urn:test:form",capability::HostCapabilities { user_elicitation_request: Some(capability::user_elicitation_request().return_result().message().elicitation_form()), ..Default::default() })
            .with_backend("org.example.form",Arc::new(Replies {requests:requests.clone()}))).unwrap();
        let event = json!({"id":"evt","source":"urn:test:form","time":"2026-09-15T12:00:00Z","type":"user.elicitation.request","session":{"id":"session"},
            "elicitation":{"server":"mcp","mode":"form","request":{"id":"form","kind":"text","mediaType":"text/plain","selection":"body","text":serde_json::to_string(&form.request("Count?")).unwrap()}}});
        let outcome = hooks
            .event(event.clone())
            .return_contract(form.result_contract())
            .await
            .unwrap();
        assert_eq!(outcome.outcome.failures.len(), 1);
        assert!(outcome.outcome.settled_candidate.is_none());
        assert!(outcome.outcome.messages.is_empty());
        assert_eq!(serde_json::to_value(&outcome.event).unwrap(), event);
        assert_eq!(requests.lock().unwrap().len(), 2);

        let contract: agenthooksprotocol::contracts::Contract<
            agenthooksprotocol::generated::ElicitResult<Count>,
        > = form.result_contract();
        let valid = hooks
            .event(event)
            .return_contract(contract.clone())
            .await
            .unwrap();
        assert!(
            valid.outcome.failures.is_empty(),
            "{:?}",
            valid.outcome.failures
        );
        let candidate = serde_json::to_value(valid.outcome.candidate().unwrap()).unwrap();
        let result = contract.decode(&candidate).unwrap();
        let FormAnswer::Accepted(answer) = form.decode(&result).unwrap() else {
            panic!("expected accepted answer")
        };
        assert_eq!(answer.count, 3);
        assert_eq!(candidate["_meta"]["trace"], "keep");
        assert_eq!(candidate["vendor"], json!({"opaque":[1,2]}));
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        let forwarded = serde_json::to_string(&requests[3]).unwrap();
        assert!(forwarded.contains("opaque"));
        assert!(forwarded.contains("keep"));
    });
}

#[test]
fn generated_result_uses_the_same_answer_and_retains_metadata() {
    use agenthooksprotocol::{
        contracts::Contract,
        generated::{ElicitResult, Presence},
    };
    let form = Form::<Answer>::new().unwrap();
    let contract: Contract<ElicitResult<Answer>> = form.result_contract();
    let raw = json!({"action":"accept", "content":content(),
        "_meta":{"vendor":{"trace":"opaque"}}, "vendorResult":{"keep":[1,2]}});
    let result: ElicitResult<Answer> = contract.decode(&raw).unwrap();
    let Presence::Present(answer) = &result.content else {
        panic!("missing typed answer")
    };
    assert_eq!(answer.user_name, "Ada");
    assert_eq!(answer.count, 2);
    assert!(matches!(
        form.decode(&result).unwrap(),
        FormAnswer::Accepted(_)
    ));
    let encoded = serde_json::to_value(&result).unwrap();
    assert_eq!(encoded["_meta"], raw["_meta"]);
    assert_eq!(encoded["vendorResult"], raw["vendorResult"]);
    let mut invalid = raw.clone();
    invalid["content"]["count"] = json!(0);
    assert!(contract.decode(&invalid).is_err());
    for action in ["decline", "cancel"] {
        let absent = contract
            .decode(&json!({"action":action,"vendorResult":42}))
            .unwrap();
        assert!(form.decode(&absent).is_ok());
        let mut with_content = raw.clone();
        with_content["action"] = json!(action);
        assert!(contract.decode(&with_content).is_err());
    }
}

#[test]
fn modified_form_answer_contract_rejects_dropped_fields_before_later_interceptors() {
    use agenthooksprotocol::{
        Hooks,
        adapters::registered::ManagedBackend,
        client::{HookError, LocalFuture},
        content::{AuthorizedScope, ContentContext, MemoryContentStore},
        elicitation::Exchange,
        hooks::HooksOptions,
    };
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Count {
        count: u64,
    }
    struct Replies(Arc<Mutex<Vec<serde_json::Value>>>);
    impl ManagedBackend for Replies {
        fn call(
            &self,
            request: serde_json::Value,
            _: Duration,
        ) -> LocalFuture<'_, Result<serde_json::Value, HookError>> {
            Box::pin(async move {
                let mut requests = self.0.lock().unwrap();
                let first = requests.is_empty();
                requests.push(request.clone());
                let effects = if first {
                    json!([{"type":"modify","target":"content","operation":"merge","value":{"count":2,"extra":"must not drop"}}])
                } else {
                    json!([])
                };
                Ok(
                    json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":effects}}),
                )
            })
        }
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { Ok(()) })
        }
    }
    futures::executor::block_on(async {
        let form = Form::<Count>::new().unwrap();
        let store = MemoryContentStore::new(4096, 65536, 100);
        let content = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("form"),
        };
        let request_event = json!({"id":"request","source":"urn:test:form","time":"2026-09-15T12:00:00Z","type":"user.elicitation.request","session":{"id":"session"},
            "elicitation":{"server":"mcp","mode":"form","request":{"id":"request-part","kind":"text","mediaType":"text/plain","selection":"body","text":serde_json::to_string(&form.request("Count?")).unwrap()}}});
        let request = json!({"jsonrpc":"2.0","id":"request","method":"hooks/intercept","params":{"protocolVersion":"draft","event":request_event,"capabilities":{"effects":[],"elicitation":{"form":{}}}}});
        let exchange = Exchange::new(&request, &content).unwrap();
        let original_answer = json!({"action":"accept","content":{"count":1}});
        let event = json!({"id":"result","source":"urn:test:form","parentEventId":"request","time":"2026-09-15T12:00:00Z","type":"user.elicitation.result","session":{"id":"session"},
            "elicitation":{"server":"mcp","mode":"form","action":"accept","result":{"id":"result-part","kind":"text","mediaType":"text/plain","selection":"body","text":original_answer.to_string()}}});
        let requests = Arc::new(Mutex::new(vec![]));
        let sub = json!({"events":["user.elicitation.result"],"mode":"intercept","failurePolicy":"fail-open","timeoutMs":1000,"content":{"default":"body"}});
        let hooks=Hooks::new(json!({"protocolVersion":"draft","hooks":[{"id":"org.example.form","transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},"subscriptions":[sub.clone(),sub]}]}),
            HooksOptions::new("urn:test:form",capability::HostCapabilities { user_elicitation_result: Some(capability::user_elicitation_result().modify_content(capability::Modify::ReplaceAndMerge).elicitation_form()), ..Default::default() })
            .with_backend("org.example.form",Arc::new(Replies(requests.clone())))).unwrap();
        let outcome = hooks
            .event(event.clone())
            .elicitation_exchange(&exchange)
            .return_contract(form.result_contract())
            .await
            .unwrap();
        assert_eq!(outcome.outcome.failures.len(), 1);
        assert_eq!(serde_json::to_value(&outcome.event).unwrap(), event);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        let next: serde_json::Value = serde_json::from_str(
            requests[1]["params"]["event"]["elicitation"]["result"]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(next, original_answer);
    });
}

#[test]
fn invalid_intermediate_form_answer_cannot_be_repaired_later_in_same_response() {
    use agenthooksprotocol::{
        Hooks,
        adapters::registered::ManagedBackend,
        client::{HookError, LocalFuture},
        content::{AuthorizedScope, ContentContext, MemoryContentStore},
        elicitation::Exchange,
        hooks::HooksOptions,
    };
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Count {
        #[schemars(range(min = 1, max = 5))]
        count: u64,
    }
    struct Replies(Arc<Mutex<Vec<serde_json::Value>>>, serde_json::Value);
    impl ManagedBackend for Replies {
        fn call(
            &self,
            request: serde_json::Value,
            _: Duration,
        ) -> LocalFuture<'_, Result<serde_json::Value, HookError>> {
            Box::pin(async move {
                let mut requests = self.0.lock().unwrap();
                let index = requests.len();
                requests.push(request.clone());
                let effects = match index {
                    0 => {
                        json!([{"type":"modify","target":"content","operation":"replace","value":{"count":3}}])
                    }
                    1 => json!([
                        {"type":"modify","target":"content","operation":"replace","value":self.1},
                        {"type":"modify","target":"content","operation":"replace","value":{"count":2}}
                    ]),
                    _ => json!([]),
                };
                Ok(
                    json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":effects}}),
                )
            })
        }
        fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async { Ok(()) })
        }
    }
    futures::executor::block_on(async {
        for invalid in [
            json!({"count":-1}),
            json!({"count":9}),
            json!({"count":2,"extra":"must not drop"}),
        ] {
            let form = Form::<Count>::new().unwrap();
            let store = MemoryContentStore::new(4096, 65536, 100);
            let content = ContentContext {
                store: &store,
                scope: AuthorizedScope::new("form"),
            };
            let request_event = json!({"id":"request","source":"urn:test:form","time":"2026-09-15T12:00:00Z","type":"user.elicitation.request","session":{"id":"session"},
            "elicitation":{"server":"mcp","mode":"form","request":{"id":"request-part","kind":"text","mediaType":"text/plain","selection":"body","text":serde_json::to_string(&form.request("Count?")).unwrap()}}});
            let request = json!({"jsonrpc":"2.0","id":"request","method":"hooks/intercept","params":{"protocolVersion":"draft","event":request_event,"capabilities":{"effects":[],"elicitation":{"form":{}}}}});
            let exchange = Exchange::new(&request, &content).unwrap();
            let original_answer = json!({"action":"accept","content":{"count":1}});
            let event = json!({"id":"result","source":"urn:test:form","parentEventId":"request","time":"2026-09-15T12:00:00Z","type":"user.elicitation.result","session":{"id":"session"},
            "elicitation":{"server":"mcp","mode":"form","action":"accept","result":{"id":"result-part","kind":"text","mediaType":"text/plain","selection":"body","text":original_answer.to_string()}}});
            let requests = Arc::new(Mutex::new(vec![]));
            let sub = json!({"events":["user.elicitation.result"],"mode":"intercept","failurePolicy":"fail-open","timeoutMs":1000,"content":{"default":"body"}});
            let hooks=Hooks::new(json!({"protocolVersion":"draft","hooks":[{"id":"org.example.form","transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},"subscriptions":[sub.clone(),sub.clone(),sub]}]}),
            HooksOptions::new("urn:test:form",capability::HostCapabilities { user_elicitation_result: Some(capability::user_elicitation_result().modify_content(capability::Modify::ReplaceAndMerge).elicitation_form()), ..Default::default() })
            .with_backend("org.example.form",Arc::new(Replies(requests.clone(),invalid)))).unwrap();
            let outcome = hooks
                .event(event.clone())
                .elicitation_exchange(&exchange)
                .return_contract(form.result_contract())
                .await
                .unwrap();
            assert_eq!(outcome.outcome.failures.len(), 1);
            let mut retained_event = event;
            retained_event["elicitation"]["result"]["text"] =
                json!({"action":"accept","content":{"count":3}})
                    .to_string()
                    .into();
            assert_eq!(
                serde_json::to_value(&outcome.event).unwrap(),
                retained_event
            );
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 3);
            let next: serde_json::Value = serde_json::from_str(
                requests[2]["params"]["event"]["elicitation"]["result"]["text"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(next, json!({"action":"accept","content":{"count":3}}));
        }
    });
}
