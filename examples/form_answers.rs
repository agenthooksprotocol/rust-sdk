//! Run: cargo run --example form_answers --features typed-form
use agenthooksprotocol::{
    form::{Form, FormAnswer},
    generated::{ElicitResult, McpElicitationElicitResultAction, Presence},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Answer {
    name: String,
    #[schemars(range(min = 1, max = 5))]
    rating: u8,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let form = Form::<Answer>::new()?;
    let request = form.request("How was the result?");
    println!("request: {}", serde_json::to_string(&request)?);
    let result: ElicitResult<Answer> = form.accept(&Answer {
        name: "Ada".into(),
        rating: 5,
    })?;
    match form.decode(&result)? {
        FormAnswer::Accepted(answer) => assert_eq!(answer.rating, 5),
        _ => unreachable!("accepted result"),
    }
    let declined = ElicitResult::<Answer> {
        action: McpElicitationElicitResultAction::Decline,
        content: Presence::Missing,
        meta: Presence::Missing,
        additional_properties: BTreeMap::new(),
    };
    assert!(matches!(form.decode(&declined)?, FormAnswer::Declined));
    println!("accepted answer validated; declined answer has no content");
    Ok(())
}
