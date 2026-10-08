//! Offline canonical validation shared by executable protocol entrypoints.
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

fn localize(value: &mut Value, file: &str) {
    match value {
        Value::Object(map) => {
            map.remove("$id");
            if let Some(Value::String(reference)) = map.get_mut("$ref") {
                let old = reference.clone();
                let (target, fragment) = old.split_once('#').unwrap_or((&old, ""));
                *reference = format!(
                    "#/$defs/files/{}{}",
                    if target.is_empty() { file } else { target },
                    fragment
                );
            }
            for child in map.values_mut() {
                localize(child, file);
            }
        }
        Value::Array(array) => {
            for child in array {
                localize(child, file);
            }
        }
        _ => {}
    }
}
fn documents() -> Result<&'static BTreeMap<String, Value>, String> {
    static DOCUMENTS: OnceLock<Result<BTreeMap<String, Value>, String>> = OnceLock::new();
    DOCUMENTS
        .get_or_init(|| {
            let schemas: Vec<Value> =
                serde_json::from_str(include_str!("schemas.json")).map_err(|e| e.to_string())?;
            schemas
                .into_iter()
                .map(|schema| {
                    let name = schema["$id"]
                        .as_str()
                        .and_then(|s| s.rsplit('/').next())
                        .ok_or("missing bundled schema ID")?
                        .to_owned();
                    Ok((name, schema))
                })
                .collect()
        })
        .as_ref()
        .map_err(Clone::clone)
}
fn address(name: &str) -> Result<(String, String), String> {
    let (file, fragment) = name.split_once('#').unwrap_or((name, ""));
    let file = if file.ends_with(".schema.json") {
        file.to_owned()
    } else {
        format!("{file}.schema.json")
    };
    let pointer = if fragment.is_empty() {
        String::new()
    } else if fragment.starts_with('/') {
        fragment.to_owned()
    } else {
        format!("/$defs/{fragment}")
    };
    let doc = documents()?
        .get(&file)
        .ok_or_else(|| format!("unknown bundled schema {file}"))?;
    if doc.pointer(&pointer).is_none() {
        return Err(format!("unknown bundled schema fragment {name}"));
    }
    Ok((file, pointer))
}
/// Return an unmodified bundled schema or local fragment for schema-derived
/// runtime metadata. This never resolves an external resource.
pub(crate) fn schema(name: &str) -> Result<Value, String> {
    let (file, pointer) = address(name)?;
    documents()?[&file]
        .pointer(&pointer)
        .cloned()
        .ok_or_else(|| "unknown schema fragment".into())
}
fn validator(name: &str) -> Result<Arc<jsonschema::Validator>, String> {
    static CACHE: OnceLock<Mutex<BTreeMap<String, Arc<jsonschema::Validator>>>> = OnceLock::new();
    let (file, pointer) = address(name)?;
    let key = format!("{file}#{pointer}");
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(validator) = cache
        .lock()
        .map_err(|_| "canonical validator lock")?
        .get(&key)
    {
        return Ok(Arc::clone(validator));
    }
    let mut files = documents()?.clone();
    for (file, schema) in &mut files {
        localize(schema, file);
    }
    let root = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":format!("#/$defs/files/{file}{pointer}"),"$defs":{"files":files}});
    let compiled = Arc::new(
        jsonschema::options()
            .should_validate_formats(true)
            .build(&root)
            .map_err(|e| e.to_string())?,
    );
    let mut cache = cache.lock().map_err(|_| "canonical validator lock")?;
    Ok(Arc::clone(cache.entry(key).or_insert(compiled)))
}
/// Structural generated parsing remains separate so runtime constraints never
/// insert defaults or alter unknown-property/presence behavior in codecs.
pub(crate) fn validate(name: &str, value: &Value) -> Result<(), String> {
    validator(name)?
        .validate(value)
        .map_err(|error| format!("invalid canonical {name}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_bundled_fragments_are_offline_and_strict() {
        let answer = json!({"action":"decline"});
        validate("mcp-elicitation#result", &answer).unwrap();
        validate("mcp-elicitation.schema.json#/$defs/result", &answer).unwrap();
        assert!(validate("mcp-elicitation#result", &json!({"action":"invented"})).is_err());
        assert!(validate("missing", &answer).is_err());
        assert!(validate("mcp-elicitation#missing", &answer).is_err());
        assert!(schema("capabilities").unwrap().is_object());
    }
}

#[cfg(test)]
mod content_reference_tests {
    use super::*;
    use crate::generated::{
        ParseResult, parse_content_item_value, parse_content_reference_value,
        parse_intercept_request_value, parse_observe_notification_value,
    };

    #[test]
    fn ref_only_bodies_and_disclosure_views_have_distinct_boundaries() {
        let reference = json!({"ref":"stored"});
        validate("content-reference", &reference).unwrap();
        assert!(matches!(
            parse_content_reference_value(reference.clone()),
            ParseResult::Success { .. }
        ));
        let body = json!({"id":"item", "kind":"text", "mediaType":"text/plain", "selection":"body", "body":reference});
        validate("content-item", &body).unwrap();
        assert!(matches!(
            parse_content_item_value(body.clone()),
            ParseResult::Success { .. }
        ));
        for (key, value) in [
            ("size", json!(3)),
            ("sha256", json!("0".repeat(64))),
            ("size", Value::Null),
            ("sha256", Value::Null),
        ] {
            let mut legacy_ref = reference.clone();
            legacy_ref[key] = value.clone();
            assert!(validate("content-reference", &legacy_ref).is_err());
            assert!(!matches!(
                parse_content_reference_value(legacy_ref),
                ParseResult::Success { .. }
            ));
            for nested in [true, false] {
                let mut legacy_item = body.clone();
                if nested {
                    legacy_item["body"][key] = value.clone();
                } else {
                    legacy_item[key] = value.clone();
                }
                assert!(validate("content-item", &legacy_item).is_err());
                assert!(!matches!(
                    parse_content_item_value(legacy_item.clone()),
                    ParseResult::Success { .. }
                ));
                let event = json!({"id":"event", "source":"urn:test", "time":"2026-09-01T00:00:00Z", "type":"tool.before", "path":"native", "call":{"id":"call"}, "tool":{"name":"read", "origin":"native", "input":{}}, "items":[legacy_item]});
                let intercept = json!({"jsonrpc":"2.0", "id":"rpc", "method":"hooks/intercept", "params":{"protocolVersion":"draft", "capabilities":{"effects":[]}, "event":event}});
                let observe = json!({"jsonrpc":"2.0", "method":"hooks/observe", "params":{"protocolVersion":"draft", "event":event}});
                assert!(validate("intercept-request", &intercept).is_err());
                assert!(!matches!(
                    parse_intercept_request_value(intercept),
                    ParseResult::Success { .. }
                ));
                assert!(validate("observe-notification", &observe).is_err());
                assert!(!matches!(
                    parse_observe_notification_value(observe),
                    ParseResult::Success { .. }
                ));
            }
            if value.is_null() {
                continue;
            }
            let mut metadata = body.clone();
            metadata.as_object_mut().unwrap().remove("body");
            metadata["selection"] = json!("metadata");
            metadata[key] = value;
            validate("content-item", &metadata).unwrap();
            assert!(matches!(
                parse_content_item_value(metadata),
                ParseResult::Success { .. }
            ));
            let mut gap = body.clone();
            gap.as_object_mut().unwrap().remove("body");
            gap["gap"] = json!({"reason":"unavailable"});
            gap[key] = if key == "size" {
                json!(3)
            } else {
                json!("0".repeat(64))
            };
            validate("content-item", &gap).unwrap();
            assert!(matches!(
                parse_content_item_value(gap),
                ParseResult::Success { .. }
            ));
        }
    }
}
