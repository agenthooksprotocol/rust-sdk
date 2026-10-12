use agenthooksprotocol::capability;
use agenthooksprotocol::{
    Hooks, ToolBeforeInputOrigin,
    adapters::registered::ManagedBackend,
    client::{HookError, LocalFuture},
    contracts::Contract,
    hooks::HooksOptions,
    inputs::ToolBeforeInput,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

struct Replies {
    replies: Vec<Value>,
    requests: Arc<Mutex<Vec<Value>>>,
}
impl ManagedBackend for Replies {
    fn call(&self, request: Value, _: Duration) -> LocalFuture<'_, Result<Value, HookError>> {
        Box::pin(async move {
            let mut requests = self.requests.lock().unwrap();
            let effects = self.replies[requests.len()].clone();
            requests.push(request.clone());
            Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"draft","effects":effects}}),
            )
        })
    }
    fn shutdown(&self) -> LocalFuture<'_, Result<(), HookError>> {
        Box::pin(async { Ok(()) })
    }
}
fn hooks(replies: Vec<Value>) -> (Hooks, Arc<Mutex<Vec<Value>>>) {
    let requests = Arc::new(Mutex::new(vec![]));
    let subscriptions: Vec<_> = replies
        .iter()
        .map(|_| {
            json!({"events":["tool.before"],"mode":"intercept",
        "timeoutMs":1000,"failurePolicy":"fail-open","content":{"default":"metadata"}})
        })
        .collect();
    let backend = Arc::new(Replies {
        replies,
        requests: requests.clone(),
    });
    let hooks=Hooks::new(json!({"protocolVersion":"draft","hooks":[{"id":"org.example.contracts",
        "transport":{"type":"stdio","command":"unused","lifecycle":"persistent"},"subscriptions":subscriptions}]}),
        HooksOptions::new("urn:test:contracts",capability::HostCapabilities { tool_before: Some(
            capability::tool_before().return_result().modify_input(capability::Modify::ReplaceAndMerge)), ..Default::default() })
        .with_backend("org.example.contracts",backend)).unwrap();
    (hooks, requests)
}
fn input<A: Serialize>(args: A) -> ToolBeforeInput<A> {
    ToolBeforeInput::new(
        "call".into(),
        "native".into(),
        args,
        "counter".into(),
        ToolBeforeInputOrigin::Native,
    )
}
fn merge(patch: Value) -> Value {
    json!({"type":"modify","target":"input","operation":"merge","value":patch})
}
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Arguments {
    count: u64,
    nullable: Option<String>,
    nested: BTreeMap<String, Value>,
    #[serde(flatten)]
    extras: BTreeMap<String, Value>,
}
fn args() -> Arguments {
    Arguments {
        count: 1,
        nullable: Some("keep".into()),
        nested: BTreeMap::from([("keep".into(), json!(true)), ("old".into(), json!(1))]),
        extras: BTreeMap::new(),
    }
}
fn contract() -> Contract<Arguments> {
    Contract::validated(|args: &Arguments| {
        if args.count <= 10 {
            Ok(())
        } else {
            Err("count exceeds host limit".into())
        }
    })
}
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ResultValue {
    answer: String,
}
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Provenance {
    source: String,
}

#[test]
fn partial_merge_preserves_omission_null_and_replaces_nested_whole() {
    futures::executor::block_on(async {
        let (hooks, requests) = hooks(vec![
            json!([merge(json!({"count":2}))]),
            json!([merge(json!({"nullable":null,"nested":{"new":true},"opaque":{"parts":[{"body":{"ref":"not-a-grant"}}]}})),{"type":"return","value":{"answer":"done"}}]),
            json!([]),
        ]);
        let outcome = hooks
            .tool_before(input(args()))
            .arguments_contract(contract())
            .result_type::<ResultValue>()
            .await
            .unwrap();
        assert!(outcome.outcome.failures.is_empty());
        let accepted = outcome.input;
        assert_eq!(accepted.count, 2);
        assert_eq!(accepted.nullable, None);
        assert_eq!(
            accepted.nested,
            BTreeMap::from([("new".into(), json!(true))])
        );
        assert_eq!(
            accepted.extras["opaque"]["parts"][0]["body"]["ref"],
            "not-a-grant"
        );
        assert_eq!(
            outcome.outcome.settled_candidate.unwrap().value,
            ResultValue {
                answer: "done".into()
            }
        );
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests[1]["params"]["event"]["tool"]["input"]["nullable"],
            "keep"
        );
        assert!(
            requests[2]["params"]["event"]["tool"]["input"]["nested"]
                .get("old")
                .is_none()
        );
    });
}
#[test]
fn invalid_later_response_publishes_none_and_prior_accepted_state_survives() {
    futures::executor::block_on(async {
        for invalid in [
            merge(json!({"count":"wrong"})),
            merge(json!({"count":11})),
            json!({"type":"return","value":{"answer":7}}),
        ] {
            let (hooks, requests) = hooks(vec![
                json!([merge(json!({"count":2})),{"type":"return","value":{"answer":"prior"}}]),
                json!([merge(json!({"count":3})), invalid]),
                json!([]),
            ]);
            let outcome = hooks
                .tool_before(input(args()))
                .result_type::<ResultValue>()
                .arguments_contract(contract())
                .await
                .unwrap();
            assert_eq!(outcome.outcome.failures.len(), 1);
            assert_eq!(outcome.input.count, 2);
            assert_eq!(
                outcome.outcome.settled_candidate.unwrap().value.answer,
                "prior"
            );
            let requests = requests.lock().unwrap();
            assert_eq!(requests[2]["params"]["event"]["tool"]["input"]["count"], 2);
            assert_eq!(
                requests[2]["params"]["state"]["candidate"]["value"]["answer"],
                "prior"
            );
        }
    });
}
#[test]
fn invalid_intermediate_value_cannot_be_repaired_later_in_same_response() {
    futures::executor::block_on(async {
        let (hooks, requests) = hooks(vec![
            json!([merge(json!({"count":11})), merge(json!({"count":2}))]),
            json!([]),
        ]);
        let outcome = hooks
            .tool_before(input(args()))
            .arguments_contract(contract())
            .result_type::<ResultValue>()
            .await
            .unwrap();
        assert_eq!(outcome.outcome.failures.len(), 1);
        assert_eq!(outcome.input.count, 1);
        assert_eq!(
            requests.lock().unwrap()[1]["params"]["event"]["tool"]["input"]["count"],
            1
        );
    });
}
#[test]
fn dropped_unknown_fields_are_rejected_not_silently_decoded() {
    #[derive(Serialize, Deserialize)]
    struct Bare {
        count: u64,
    }
    futures::executor::block_on(async {
        let (hooks, requests) = hooks(vec![
            json!([merge(json!({"extra":{"parts":[]}}))]),
            json!([]),
        ]);
        let outcome = hooks
            .tool_before(input(Bare { count: 1 }))
            .declare_arguments()
            .await
            .unwrap();
        assert_eq!(outcome.outcome.failures.len(), 1);
        assert!(
            requests.lock().unwrap()[1]["params"]["event"]["tool"]["input"]
                .get("extra")
                .is_none()
        );
    });
}
#[test]
fn candidate_null_presence_and_provenance_replacement_are_distinct() {
    futures::executor::block_on(async {
        for (native, effects, present, provenance) in [
            (Value::Null, json!([]), false, false),
            (
                json!({"value":null,"provenance":{"source":"cache"}}),
                json!([]),
                true,
                true,
            ),
            (
                json!({"value":null,"provenance":{"source":"cache"}}),
                json!([{"type":"return","value":null}]),
                true,
                false,
            ),
            (
                json!({"value":null,"provenance":{"source":"cache"}}),
                json!([merge(json!({"count":2}))]),
                false,
                false,
            ),
        ] {
            let (hooks, _) = hooks(vec![effects]);
            let outcome = hooks
                .tool_before(input(args()))
                .result_type::<Option<String>>()
                .provenance_type::<Provenance>()
                .initial_candidate(native)
                .await
                .unwrap();
            assert!(outcome.outcome.failures.is_empty());
            assert_eq!(outcome.outcome.settled_candidate.is_some(), present);
            if let Some(candidate) = outcome.outcome.settled_candidate {
                assert_eq!(candidate.value, None);
                assert_eq!(!candidate.provenance.is_missing(), provenance);
            }
        }
    });
}
#[test]
fn native_contracts_validate_before_first_interceptor() {
    futures::executor::block_on(async {
        let (hooks, requests) = hooks(vec![json!([])]);
        let outcome = hooks
            .tool_before(input(args()))
            .result_type::<ResultValue>()
            .provenance_type::<Provenance>()
            .initial_candidate(json!({"value":{"answer":"ok"},"provenance":{"source":7}}))
            .await;
        assert!(outcome.is_err());
        assert!(requests.lock().unwrap().is_empty());
        let (hooks, requests) = self::hooks(vec![json!([])]);
        let outcome = hooks
            .tool_before(input(args()))
            .arguments_contract(Contract::validated(|_: &Arguments| {
                Err("reject native".into())
            }))
            .result_type::<ResultValue>()
            .await;
        assert!(outcome.is_err());
        assert!(requests.lock().unwrap().is_empty());
    });
}

#[test]
fn host_owned_native_codec_is_opt_in_and_retains_opaque_extra_bags() {
    #[derive(Serialize, Deserialize)]
    struct Native {
        host: String,
        #[serde(flatten)]
        extras: BTreeMap<String, Value>,
    }
    futures::executor::block_on(async {
        for declared in [false, true] {
            let (hooks, _) = hooks(vec![json!([])]);
            let context = agenthooksprotocol::client::ToolContext::new(
                json!({"id":"evt","source":"urn:test:contracts",
                "time":"2026-09-15T12:00:00Z","type":"tool.before","call":{"id":"call"},"path":"native",
                "tool":{"name":"counter","origin":"native"},"native":{"host":"host","opaque":{"parts":[{"body":{"ref":"no-grant"}}]}}}),
            );
            let mut boundary = hooks.tool_input(args()).context(context);
            if declared {
                boundary = boundary.host_contract("/native", Contract::<Native>::new());
            }
            let outcome = boundary.await.unwrap();
            assert!(outcome.outcome.failures.is_empty());
        }
        let (hooks, requests) = hooks(vec![json!([])]);
        let context = agenthooksprotocol::client::ToolContext::new(
            json!({"id":"evt","source":"urn:test:contracts",
            "time":"2026-09-15T12:00:00Z","type":"tool.before","call":{"id":"call"},"path":"native",
            "tool":{"name":"counter","origin":"native"},"native":{"host":"host"}}),
        );
        let outcome = hooks
            .tool_input(args())
            .context(context)
            .host_contract(
                "/native",
                Contract::<Native>::validated(|_| Err("host invariant".into())),
            )
            .await;
        assert!(outcome.is_err());
        assert!(requests.lock().unwrap().is_empty());
    });
}

#[test]
fn specialized_typed_tool_retains_complete_settled_event_and_opaque_extensions() {
    futures::executor::block_on(async {
        let (hooks, requests) = hooks(vec![json!([merge(json!({"count":2}))]), json!([])]);
        let opaque = json!({"org.example.event":{"nested":{"opaque":[null,{"kind":"caller-defined","parts":[1,2]}]}}});
        let native = json!({"vendor":{"opaque":[null,42],"ref":"not-an-attachment"}});
        let mut proposal = input(args());
        proposal.id = Some("original-tool-event".into());
        proposal.extensions = Some(Box::new(serde_json::from_value(opaque.clone()).unwrap()));
        proposal.native = Some(Box::new(native.clone()));
        let outcome = hooks
            .tool_before(proposal)
            .arguments_contract(contract())
            .result_type::<ResultValue>()
            .provenance_type::<Provenance>()
            .initial_candidate(
                json!({"value":{"answer":"cached"},"provenance":{"source":"native"}}),
            )
            .await
            .unwrap();
        let _: &agenthooksprotocol::hooks::ToolOutcome<Arguments, ResultValue, Provenance> =
            &outcome;
        let _: &agenthooksprotocol::Event = &outcome.event;
        assert!(outcome.outcome.failures.is_empty());
        let mut expected = requests.lock().unwrap()[0]["params"]["event"].clone();
        expected["tool"]["input"]["count"] = json!(2);
        // Private native facts are retained locally but withheld from this backend.
        expected["native"] = native.clone();
        let settled = serde_json::to_value(&outcome.event).unwrap();
        assert_eq!(settled, expected);
        assert_eq!(settled["id"], "original-tool-event");
        assert_eq!(settled["extensions"], opaque);
        assert_eq!(settled["native"], native);
        assert_eq!(
            settled["tool"]["input"],
            serde_json::to_value(&outcome.input).unwrap()
        );
        assert_eq!(outcome.input.count, 2);
        // A modification invalidates the initial candidate; a subsequent occurrence
        // still preserves the typed result/provenance generics and event facts.
        assert!(outcome.outcome.settled_candidate.is_none());
        let mut proposal = input(args());
        proposal.extensions = Some(Box::new(serde_json::from_value(opaque.clone()).unwrap()));
        let (hooks, _) = self::hooks(vec![json!([])]);
        let returned = hooks
            .tool_before(proposal)
            .result_type::<ResultValue>()
            .provenance_type::<Provenance>()
            .initial_candidate(
                json!({"value":{"answer":"cached"},"provenance":{"source":"native"}}),
            )
            .await
            .unwrap();
        let candidate = returned.outcome.settled_candidate.unwrap();
        assert_eq!(
            candidate.value,
            ResultValue {
                answer: "cached".into()
            }
        );
        assert_eq!(
            candidate.provenance,
            agenthooksprotocol::Presence::Present(Provenance {
                source: "native".into()
            })
        );
        assert_eq!(
            serde_json::to_value(&returned.event).unwrap()["extensions"],
            opaque
        );
    });
}
