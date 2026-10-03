//! Registration enforcement against an actually discovered host manifest.
use crate::interop::{Result, Schemas};
use serde_json::Value;
use std::collections::BTreeSet;
fn has(v: &Value, member: &Value) -> bool {
    v.as_array().is_some_and(|a| a.contains(member))
}
fn selects(selector: &Value, event: &Value) -> bool {
    match (selector.as_str(), event.as_str()) {
        (Some("*"), Some(_)) => true,
        (Some(selector), Some(event)) => {
            selector == event
                || selector
                    .strip_suffix('*')
                    .is_some_and(|prefix| selector.ends_with(".*") && event.starts_with(prefix))
        }
        _ => false,
    }
}
fn subscribed(manifest: &Value, selector: &Value, mode: &Value) -> Result<()> {
    let entries = manifest["events"].as_array().ok_or("missing host events")?;
    let matches: Vec<_> = entries
        .iter()
        .filter(|entry| selects(selector, &entry["event"]))
        .collect();
    if matches.is_empty() || matches.iter().any(|entry| !has(&entry["modes"], mode)) {
        return Err("selector/mode not covered".into());
    }
    Ok(())
}
fn advertised<'a>(manifest: &'a Value, event: &Value, mode: &Value) -> Result<&'a Value> {
    manifest["events"]
        .as_array()
        .ok_or("missing manifest events")?
        .iter()
        .find(|e| e["event"] == *event && has(&e["modes"], mode))
        .ok_or_else(|| "event/mode unsupported".into())
}
fn authentication(auth: &Value, manifest: &Value, context: &Value) -> Result<()> {
    if auth.is_null() {
        return Ok(());
    }
    if !has(&manifest["authentication"], &auth["type"]) {
        return Err("authentication unavailable".into());
    }
    // Only environment-backed bearer resolution is supplied by this synthetic host.
    // Reference resolvers must be explicitly installed before other setups are enforceable.
    if auth["type"] != "bearer"
        || !auth["tokenEnv"].as_str().is_some_and(|key| {
            context["environment"][key]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        })
    {
        return Err("credential resolution unavailable".into());
    }
    Ok(())
}
pub fn validate(
    registration: &Value,
    manifest: &Value,
    requirements: &Value,
    context: &Value,
    schemas: &Schemas,
) -> Result<()> {
    schemas.validate("registration", registration)?;
    let mut ids = BTreeSet::new();
    for hook in registration["hooks"].as_array().ok_or("missing hooks")? {
        if !ids.insert(hook["id"].as_str().ok_or("missing backend id")?) {
            return Err("duplicate backend id".into());
        }
        if !has(&manifest["transports"], &hook["transport"]["type"]) {
            return Err("unsupported backend transport".into());
        }
        authentication(&hook["authentication"], manifest, context)?;
        for sub in hook["subscriptions"]
            .as_array()
            .ok_or("missing subscriptions")?
        {
            let scope = sub
                .get("scope")
                .cloned()
                .unwrap_or(Value::String("user".into()));
            if !has(&manifest["managedPolicy"]["scopes"], &scope)
                || (scope == "managed"
                    && (manifest["managedPolicy"]["disableable"] != false
                        || sub["disableable"] != false))
            {
                return Err("policy scope unenforceable".into());
            }
            for event in sub["events"].as_array().ok_or("missing events")? {
                subscribed(manifest, event, &sub["mode"])?;
            }
            if sub["timeoutMs"].as_u64().is_some_and(|n| {
                manifest["limits"]["maxTimeoutMs"]
                    .as_u64()
                    .is_some_and(|max| n > max)
                    || manifest["limits"]["minTimeoutMs"]
                        .as_u64()
                        .is_some_and(|min| n < min)
            }) {
                return Err("timeout outside host limits".into());
            }
            authentication(&sub["upload"]["auth"], manifest, context)?;
        }
    }
    for requirement in requirements
        .as_array()
        .ok_or("requirements must be a list")?
    {
        let entry = advertised(manifest, &requirement["event"], &requirement["mode"])?;
        let subscribed = registration["hooks"].as_array().unwrap().iter().any(|h| {
            h["subscriptions"].as_array().unwrap().iter().any(|s| {
                s["mode"] == requirement["mode"]
                    && s["events"].as_array().is_some_and(|events| {
                        events
                            .iter()
                            .any(|selector| selects(selector, &requirement["event"]))
                    })
            })
        });
        if !subscribed {
            return Err("requirement not subscribed".into());
        }
        let caps = &entry["capabilities"];
        if let Some(effects) = requirement["effects"].as_array() {
            for effect in effects {
                if !has(&caps["effects"], effect)
                    || (effect == "ask" && context["interactive"] != true)
                {
                    return Err("effect unenforceable".into());
                }
            }
        }
        if let Some(targets) = requirement["modify"].as_object() {
            for (target, operations) in targets {
                for (operation, required) in operations
                    .as_object()
                    .ok_or("invalid modify requirements")?
                {
                    if *required == true && caps["modify"][target][operation] != true {
                        return Err("modification unsupported".into());
                    }
                }
            }
        }
    }
    Ok(())
}
