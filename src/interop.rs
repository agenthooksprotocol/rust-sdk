//! Canonically validated synthetic boundary runtime for cross-SDK interoperability.
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub struct Schemas {
    validators: BTreeMap<String, jsonschema::Validator>,
}
fn localize(v: &mut Value, file: &str) {
    match v {
        Value::Object(m) => {
            m.remove("$id");
            if let Some(Value::String(r)) = m.get_mut("$ref") {
                let old = r.clone();
                let (f, frag) = old.split_once('#').unwrap_or((&old, ""));
                *r = format!(
                    "#/$defs/files/{}{}",
                    if f.is_empty() { file } else { f },
                    frag
                );
            }
            for x in m.values_mut() {
                localize(x, file);
            }
        }
        Value::Array(a) => {
            for x in a {
                localize(x, file);
            }
        }
        _ => {}
    }
}
impl Schemas {
    pub fn load(path: &Path) -> Result<Self> {
        let mut files = serde_json::Map::new();
        for entry in fs::read_dir(path)? {
            let p = entry?.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let name = p.file_name().unwrap().to_str().unwrap().to_string();
            let mut v: Value = serde_json::from_slice(&fs::read(&p)?)?;
            localize(&mut v, &name);
            files.insert(name, v);
        }
        Self::compile(files)
    }
    /// Validate offline against the canonical schema bundle shipped with this crate.
    pub fn bundled() -> Result<Self> {
        let schemas: Vec<Value> = serde_json::from_str(include_str!("schemas.json"))?;
        let mut files = serde_json::Map::new();
        for mut schema in schemas {
            let name = schema["$id"]
                .as_str()
                .ok_or("schema ID missing")?
                .rsplit('/')
                .next()
                .ok_or("schema filename missing")?
                .to_owned();
            localize(&mut schema, &name);
            files.insert(name, schema);
        }
        Self::compile(files)
    }
    fn compile(files: serde_json::Map<String, Value>) -> Result<Self> {
        let mut validators = BTreeMap::new();
        for name in [
            "registration",
            "intercept-request",
            "intercept-response",
            "capabilities",
            "capabilities-request",
            "capabilities-response",
        ] {
            let schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema", "$ref":format!("#/$defs/files/{name}.schema.json"), "$defs":{"files":files}});
            validators.insert(
                name.into(),
                jsonschema::options()
                    .should_validate_formats(true)
                    .build(&schema)?,
            );
        }
        Ok(Self { validators })
    }
    pub fn validate(&self, name: &str, value: &Value) -> Result<()> {
        match name {
            "registration" => {
                if !crate::generated::parse_registration_value(value.clone()).is_ok() {
                    return Err("generated registration validation failed".into());
                }
            }
            "intercept-request" => {
                if !crate::generated::parse_intercept_request_value(value.clone()).is_ok() {
                    return Err("generated request validation failed".into());
                }
            }
            "intercept-response" => {
                if !crate::generated::parse_intercept_response_value(value.clone()).is_ok() {
                    return Err("generated response validation failed".into());
                }
            }
            "capabilities" => {
                if !crate::generated::parse_capabilities_value(value.clone()).is_ok() {
                    return Err("generated capabilities validation failed".into());
                }
            }
            "capabilities-request" => {
                if !crate::generated::parse_capabilities_request_value(value.clone()).is_ok() {
                    return Err("generated discovery request validation failed".into());
                }
            }
            "capabilities-response" => {
                if !crate::generated::parse_capabilities_response_value(value.clone()).is_ok() {
                    return Err("generated discovery response validation failed".into());
                }
            }
            _ => return Err("unknown schema".into()),
        }
        self.validators[name]
            .validate(value)
            .map_err(|_| format!("canonical {name} validation failed").into())
    }
}
pub fn capabilities() -> Value {
    json!({"effects":["deny","allow","ask","modify","message","return","flow","inject"],"modify":{"input":{"replace":true,"merge":true}},"flow":{"operations":["stop"]},"inject":{"context":{"append":true,"deliverAt":["now","next_turn"]}}})
}
/// Advertise only operations the synthetic boundary can enforce.
pub fn capabilities_for(event: &str) -> Result<Value> {
    Ok(match event {
        "tool.before" => capabilities(),
        "turn.finish.before" => {
            json!({"effects":["flow","message"],"flow":{"operations":["stop","continue"],"remainingContinuations":2,"maxContinuations":2,"continuationCount":0}})
        }
        "task.change.before" | "workspace.change.before" => json!({"effects":["deny","message"]}),
        _ => return Err("unsupported synthetic boundary".into()),
    })
}
/// Stage on a private copy; nothing is published until every effect is accepted.
pub fn apply(request: &Value, response: &Value, schemas: &Schemas) -> Result<Value> {
    schemas.validate("intercept-request", request)?;
    schemas.validate("intercept-response", response)?;
    if request["id"] != request["params"]["event"]["id"] || response["id"] != request["id"] {
        return Err("correlation mismatch".into());
    }
    let p = &request["params"];
    if ![
        "tool.before",
        "turn.finish.before",
        "task.change.before",
        "workspace.change.before",
    ]
    .contains(&p["event"]["type"].as_str().unwrap_or(""))
    {
        return Err("unsupported boundary".into());
    }
    let effects = response["result"]["effects"]
        .as_array()
        .ok_or("missing effects")?;
    let caps = &p["capabilities"];
    for e in effects {
        let kind = e["type"].as_str().ok_or("missing effect type")?;
        if !caps["effects"]
            .as_array()
            .ok_or("missing capabilities")?
            .contains(&e["type"])
        {
            return Err("unadvertised effect".into());
        }
        if ![
            "deny", "allow", "ask", "modify", "message", "return", "flow", "inject",
        ]
        .contains(&kind)
        {
            return Err("unknown or unsupported effect".into());
        }
        if ["task.change.before", "workspace.change.before"]
            .contains(&p["event"]["type"].as_str().unwrap_or(""))
            && !["deny", "message"].contains(&kind)
        {
            return Err("unsupported task/workspace effect".into());
        }
        if p["event"]["type"] == "turn.finish.before" && !["flow", "message"].contains(&kind) {
            return Err("unsupported effect at finish boundary".into());
        }
        if kind == "modify"
            && (e["target"] != "input"
                || !["merge", "replace"].contains(&e["operation"].as_str().unwrap_or(""))
                || caps["modify"]["input"][e["operation"].as_str().unwrap_or("")] != true)
        {
            return Err("unsupported modification".into());
        }
    }
    for e in effects {
        if e["type"] == "flow" {
            if !["stop", "continue"].contains(&e["operation"].as_str().unwrap_or("")) {
                return Err("unsupported flow operation".into());
            }
            if e["operation"] == "continue" && p["event"]["type"] != "turn.finish.before" {
                return Err("continue requires finish boundary".into());
            }
            if !caps["flow"]["operations"]
                .as_array()
                .is_some_and(|ops| ops.contains(&e["operation"]))
            {
                return Err("unadvertised flow".into());
            }
            if e["operation"] == "continue"
                && p["state"]["flow"] != "continue"
                && (caps["flow"]["remainingContinuations"].as_u64().unwrap_or(0) == 0
                    || (caps["flow"]["maxContinuations"].is_number()
                        && caps["flow"]["continuationCount"].as_u64().unwrap_or(0)
                            >= caps["flow"]["maxContinuations"].as_u64().unwrap_or(0)))
            {
                return Err("continuation budget exhausted".into());
            }
        }
        if e["type"] == "inject"
            && (e["target"] != "context"
                || e["operation"] != "append"
                || caps["inject"]["context"]["append"] != true
                || !caps["inject"]["context"]["deliverAt"]
                    .as_array()
                    .is_some_and(|times| times.contains(&e["deliverAt"])))
        {
            return Err("unadvertised injection".into());
        }
    }
    let original = p["event"]["tool"]["input"].clone();
    let mut input = original.clone();
    for e in effects.iter().filter(|e| e["type"] == "modify") {
        let value = e["value"].as_object().ok_or("input must be object")?;
        if e["operation"] == "replace" {
            input = e["value"].clone();
        } else {
            input
                .as_object_mut()
                .ok_or("input must be object")?
                .extend(value.clone());
        }
        if input["task"].as_u64().filter(|n| *n > 0).is_none() {
            return Err("invalid effective tool input".into());
        }
    }
    let mut decision = p["state"]["permission"].as_str().unwrap_or("none");
    let mut candidate = p["state"]["candidate"].get("value").cloned();
    if input != original {
        candidate = None;
        if decision == "allow" {
            decision = "none";
        }
    }
    let mut messages = Vec::new();
    let mut injections = p["state"]["injections"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let prior_flow = p["state"]["flow"].as_str().filter(|flow| *flow != "none");
    let mut flow = prior_flow;
    let mut continuation_instructions = p["state"]["instructions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for e in effects {
        match e["type"].as_str().unwrap() {
            "deny" => decision = "deny",
            "ask" if decision != "deny" => decision = "ask",
            "allow" if decision != "deny" && decision != "ask" => decision = "allow",
            "return" => candidate = Some(e["value"].clone()),
            "message" => messages.push(e["text"].clone()),
            "flow" => {
                if e["operation"] == "continue" {
                    if let Some(instruction) = e.get("instruction") {
                        continuation_instructions.push(instruction.clone());
                    }
                }
                if flow != Some("stop") {
                    flow = e["operation"].as_str();
                }
            }
            "inject" => injections.push(e.clone()),
            _ => {}
        }
    }
    if decision == "deny" || decision == "ask" {
        candidate = None;
    }
    let mut actual = json!({"decision":if decision == "none" { "allow" } else {decision},"executed":decision != "deny" && decision != "ask" && candidate.is_none(),"input":input,"messages":messages});
    if p["event"]["type"] != "tool.before" {
        actual["executed"] = json!(false);
    }
    if flow == Some("stop") {
        candidate = None;
        actual["executed"] = json!(false);
    }
    if let Some(value) = candidate {
        actual["result"] = value;
    }
    if let Some(flow) = flow {
        actual["flow"] = json!(flow);
        if let Some(remaining) = caps["flow"]["remainingContinuations"].as_u64() {
            actual["continuationInstructions"] = json!(continuation_instructions);
            actual["continuationRemaining"] = json!(
                remaining
                    .checked_sub(u64::from(
                        flow == "continue" && prior_flow != Some("continue")
                    ))
                    .ok_or("continuation budget exhausted")?
            );
        }
    }
    if !continuation_instructions.is_empty() {
        actual["continuationInstructions"] = json!(continuation_instructions);
    }
    if !injections.is_empty() {
        actual["injections"] = json!(injections);
    }
    Ok(actual)
}
