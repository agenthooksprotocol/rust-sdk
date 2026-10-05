//! Private, registration-driven projection. Never walk arbitrary application JSON.
use crate::{adapters::registered::BackendOptions, client::HookError, content::ContentContext};
use serde_json::Value;

fn error(message: impl ToString) -> HookError {
    HookError(message.to_string())
}

fn category(item: &Value) -> &str {
    if let Some(category) = item["category"].as_str() {
        return category;
    }
    if item["kind"] == "reasoning" {
        return "reasoning";
    }
    let media = item["mediaType"].as_str().unwrap_or("");
    if media.starts_with("text/") || media == "application/json" {
        "text"
    } else if media.starts_with("image/") {
        "images"
    } else if media.starts_with("audio/") {
        "audio"
    } else if media.starts_with("video/") {
        "video"
    } else {
        "files"
    }
}

// These are protocol locations, not a recursive search for objects resembling items.
fn locations(event: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    let mut array = |path: &str| {
        if let Some(items) = event.pointer(path).and_then(Value::as_array) {
            paths.extend((0..items.len()).map(|i| format!("{path}/{i}")));
        }
    };
    // Common `items` is canonical on built-in events only. Extension payloads
    // must not become implicit content authorities.
    if matches!(
        event["type"].as_str().unwrap_or(""),
        "session.start"
            | "session.end"
            | "tool.before"
            | "tool.after"
            | "turn.start"
            | "turn.finish.before"
            | "turn.end"
            | "turn.progress"
            | "model.request.before"
            | "model.response.after"
            | "model.error"
            | "model.switch.before"
            | "model.switch.after"
            | "tool.permission.request"
            | "tool.permission.resolved"
            | "tool.progress"
            | "tool.batch.after"
            | "context.compact.before"
            | "context.compact.after"
            | "config.change.before"
            | "config.change.after"
            | "user.attention"
            | "user.elicitation.request"
            | "user.elicitation.result"
            | "user.message.inbound"
            | "user.message.outbound"
            | "hook.failure"
            | "task.change.before"
            | "task.change.after"
            | "workspace.change.before"
            | "workspace.change.after"
            | "file.changed"
    ) {
        array("/items");
    }
    match event["type"].as_str().unwrap_or("") {
        "user.message.inbound" => array("/message/text"),
        "user.message.outbound" => array("/message/payload"),
        "user.attention" => {
            array("/attention/message");
            array("/attention/title");
        }
        _ => {}
    }
    let singular: &[&str] = match event["type"].as_str().unwrap_or("") {
        "turn.progress" => &["/delta"],
        "tool.progress" => &["/partialOutput"],
        "context.compact.before" => &["/instructions"],
        "context.compact.after" => &["/summary"],
        "user.elicitation.request" => &["/elicitation/request"],
        "user.elicitation.result" => &["/elicitation/result"],
        _ => &[],
    };
    paths.extend(
        singular
            .iter()
            .filter(|p| event.pointer(p).is_some())
            .map(|p| p.to_string()),
    );
    if event["type"] == "tool.after" {
        if let Some(changes) = event["fileChanges"].as_array() {
            for (i, change) in changes.iter().enumerate() {
                for stage in ["before", "after"] {
                    if change.get(stage).is_some() {
                        paths.push(format!("/fileChanges/{i}/{stage}"));
                    }
                }
            }
        }
    }
    paths
}

fn upload_credential(
    upload: &Value,
    options: &BackendOptions,
) -> Result<Option<crate::content::UploadCredential>, HookError> {
    let Some(auth) = upload.get("auth") else {
        return if options.allow_anonymous_http {
            Ok(None)
        } else {
            Err(error(
                "upload authentication required (independent of event authentication)",
            ))
        };
    };
    if auth["type"] != "bearer" {
        return Err(error("unsupported upload authentication"));
    }
    let (key, env) = match (auth["tokenRef"].as_str(), auth["tokenEnv"].as_str()) {
        (Some(key), None) => (key, false),
        (None, Some(key)) => (key, true),
        _ => {
            return Err(error(
                "upload authentication requires exactly one tokenRef or tokenEnv",
            ));
        }
    };
    let token = options
        .credentials
        .get(key)
        .cloned()
        .or_else(|| if env { std::env::var(key).ok() } else { None })
        .ok_or_else(|| error("upload credential unavailable"))?;
    crate::content::UploadCredential::bearer(token)
        .map(Some)
        .map_err(error)
}

fn selected_body(item: &Value) -> bool {
    item["selection"] == "body" && item.get("body").is_some() && item.get("gap").is_none()
}

fn remove_effect(caps: &mut Value, kind: &str) {
    if let Some(effects) = caps["effects"].as_array_mut() {
        effects.retain(|effect| effect != kind);
    }
    if kind == "modify" {
        if let Some(object) = caps.as_object_mut() {
            object.remove("modify");
        }
    }
}

/// The wire request does not carry the host's generic target-to-index mapping.
/// Therefore retain a generic target only if *all* canonical candidate items
/// retain bodies. This conservative narrowing cannot grant access through an
/// ambiguous mapping. Singular targets can be checked exactly, without reads.
fn narrow_projected_grants(request: &mut Value) {
    let event = &request["params"]["event"];
    let name = event["type"].as_str().unwrap_or("");
    let mut removed = Vec::new();
    for (target, path, array) in match name {
        "turn.start" => vec![("prompt", "/items", true)],
        "turn.finish.before" | "model.response.after" => vec![("response", "/items", true)],
        "tool.after" => vec![("output", "/items", true)],
        "user.message.inbound" => vec![("prompt", "/message/text", true)],
        "user.message.outbound" => vec![("content", "/message/payload", true)],
        "context.compact.before" => vec![("instructions", "/instructions", false)],
        "context.compact.after" => vec![("summary", "/summary", false)],
        _ => vec![],
    } {
        let available = if array {
            event
                .pointer(path)
                .and_then(Value::as_array)
                .is_some_and(|items| !items.is_empty() && items.iter().all(selected_body))
        } else {
            event.pointer(path).is_some_and(selected_body)
        };
        if !available {
            removed.push(target);
        }
    }
    let elicitation_reduced = match name {
        "user.elicitation.request" => !selected_body(&event["elicitation"]["request"]),
        "user.elicitation.result" => !selected_body(&event["elicitation"]["result"]),
        _ => false,
    };
    let Some(caps) = request.pointer_mut("/params/capabilities") else {
        return;
    };
    if let Some(targets) = caps["modify"].as_object_mut() {
        for target in removed {
            targets.remove(target);
        }
        // False operations do not constitute an effective grant.
        targets.retain(|_, operations| {
            operations
                .as_object()
                .is_some_and(|ops| ops.values().any(|v| v == true))
        });
    }
    if caps["modify"]
        .as_object()
        .is_none_or(|targets| targets.is_empty())
    {
        remove_effect(caps, "modify");
    }
    if elicitation_reduced {
        for kind in ["deny", "return", "modify"] {
            remove_effect(caps, kind);
        }
    }
}

/// Validate only the actual wire grants. Core runtime still owns correlation,
/// specialized body validation, staging and applying the effect batch exactly once.
pub(crate) fn validate_response_grants(request: &Value, response: &Value) -> Result<(), HookError> {
    crate::canonical::validate("intercept-response", response).map_err(error)?;
    let caps = &request["params"]["capabilities"];
    let event = &request["params"]["event"];
    let effects = response["result"]["effects"]
        .as_array()
        .ok_or_else(|| error("missing effects"))?;
    let advertised = |object: &Value, key: &str, value: &Value| {
        object[key]
            .as_array()
            .is_some_and(|values| values.contains(value))
    };
    for effect in effects {
        if !advertised(caps, "effects", &effect["type"]) {
            return Err(error("unadvertised effect in projected request"));
        }
        let kind = effect["type"].as_str().unwrap_or("");
        if event["type"]
            .as_str()
            .is_some_and(|name| name.starts_with("user.elicitation."))
            && matches!(kind, "deny" | "return" | "modify")
        {
            let mode = event["elicitation"]["mode"].as_str().unwrap_or("");
            if !caps["elicitation"][mode].is_object() {
                return Err(error("elicitation mode not granted in projected request"));
            }
        }
        match kind {
            "modify" => {
                let target = effect["target"].as_str().unwrap_or("");
                let operation = effect["operation"].as_str().unwrap_or("");
                if !matches!(operation, "replace" | "merge")
                    || caps["modify"][target][operation] != true
                {
                    return Err(error("unadvertised modification in projected request"));
                }
            }
            "flow" => {
                if !advertised(&caps["flow"], "operations", &effect["operation"]) {
                    return Err(error("unadvertised flow operation in projected request"));
                }
            }
            "inject" => {
                if effect["target"] != "context"
                    || effect["operation"] != "append"
                    || caps["inject"]["context"]["append"] != true
                    || !advertised(
                        &caps["inject"]["context"],
                        "deliverAt",
                        &effect["deliverAt"],
                    )
                {
                    return Err(error("unadvertised injection in projected request"));
                }
            }
            "deny" | "allow" | "ask" | "return" | "message" => {}
            _ => return Err(error("unsupported effect")),
        }
    }
    Ok(())
}

pub(crate) async fn project_with_bodies(
    request: Value,
    selection: &Value,
    upload: Option<&Value>,
    content: &ContentContext<'_>,
    options: &BackendOptions,
    bodies: &crate::body::DeferredBodies,
) -> Result<Value, HookError> {
    project_inner(request, selection, upload, content, options, Some(bodies)).await
}

#[cfg(test)]
pub(crate) async fn project(
    request: Value,
    selection: &Value,
    upload: Option<&Value>,
    content: &ContentContext<'_>,
    options: &BackendOptions,
) -> Result<Value, HookError> {
    project_inner(request, selection, upload, content, options, None).await
}

async fn project_inner(
    mut request: Value,
    selection: &Value,
    upload: Option<&Value>,
    content: &ContentContext<'_>,
    options: &BackendOptions,
    deferred: Option<&crate::body::DeferredBodies>,
) -> Result<Value, HookError> {
    crate::canonical::validate("content-selection", selection).map_err(error)?;
    let event = request
        .pointer_mut("/params/event")
        .ok_or_else(|| error("missing event"))?;
    let mut selected = Vec::new();
    for path in locations(event) {
        let item = event
            .pointer_mut(&path)
            .ok_or_else(|| error("missing content item"))?;
        let mode = selection
            .get(category(item))
            .unwrap_or(&selection["default"]);
        match mode.as_str() {
            Some("metadata" | "omit") => {
                // Preserve descriptor presence, identity and metadata; do not resolve bytes.
                let object = item
                    .as_object_mut()
                    .ok_or_else(|| error("invalid content item"))?;
                object.remove("body");
                object.remove("gap");
                object.insert("selection".into(), mode.clone());
            }
            Some("body") => {
                // Selection is not authorization: already-reduced views cannot be escalated.
                match item["selection"].as_str() {
                    Some("metadata" | "omit") => continue,
                    Some("body") => selected.push(path),
                    _ => return Err(error("invalid content selection")),
                }
            }
            _ => return Err(error("invalid registration content selection")),
        }
    }
    narrow_projected_grants(&mut request);
    if selected.is_empty() {
        reject_deferred(&request)?;
        return Ok(request);
    }
    let event = request
        .pointer_mut("/params/event")
        .ok_or_else(|| error("missing event"))?;
    let upload = upload.ok_or_else(|| error("selected bodies require an upload endpoint"))?;
    let endpoint = upload["endpoint"]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| error("selected bodies require an upload endpoint"))?;
    let max_bytes = upload["maxBytes"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| error("upload maxBytes is required"))?;
    let timeout = upload["timeoutMs"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or_else(|| error("positive upload timeoutMs is required"))?;
    let credential = upload_credential(upload, options)?;
    // Verify the complete batch before performing any upload. Failed uploads may
    // leave immutable receiver allocations, but no partial wire request escapes.
    let mut bodies = Vec::new();
    for path in selected {
        let item = event
            .pointer_mut(&path)
            .ok_or_else(|| error("missing content item"))?;
        if item.get("gap").is_some() {
            return Err(error("selected body unavailable"));
        }
        if let Some(deferred) = deferred {
            if let Some(reference) = deferred
                .materialize(&item["body"], content, max_bytes)
                .await
                .map_err(error)?
            {
                item["body"] = reference;
            }
        }
        if item["body"]["size"]
            .as_u64()
            .is_some_and(|n| n > max_bytes as u64)
        {
            return Err(error("upload exceeds maxBytes"));
        }
        let bytes = content
            .resolve_selected(item)
            .map_err(error)?
            .ok_or_else(|| error("selected body unavailable"))?;
        if bytes.len() > max_bytes {
            return Err(error("upload exceeds maxBytes"));
        }
        bodies.push((path, bytes));
    }
    // Check before any upload, not merely before backend delivery.
    reject_deferred(&request)?;
    #[cfg(not(feature = "reqwest"))]
    {
        let _ = (endpoint, timeout, credential, bodies);
        Err(error(
            "selected body upload requires the reqwest feature, including for stdio hooks",
        ))
    }
    #[cfg(feature = "reqwest")]
    {
        let http = crate::adapters::reqwest::ReqwestHttp::with_timeout(
            options.max_frame_bytes.min(8192),
            options.allow_loopback_http,
            std::time::Duration::from_millis(timeout),
        )
        .map_err(error)?;
        let uploader = crate::content::Uploader::new(
            &http,
            endpoint,
            max_bytes,
            credential,
            options.allow_loopback_http,
        )
        .map_err(error)?;
        let event = request
            .pointer_mut("/params/event")
            .ok_or_else(|| error("missing event"))?;
        for (path, bytes) in bodies {
            let reference = uploader.upload(&bytes).await.map_err(error)?;
            let reference = serde_json::to_value(reference).map_err(error)?;
            let item = event
                .pointer_mut(&path)
                .ok_or_else(|| error("missing content item"))?;
            for field in ["size", "sha256"] {
                if item.get(field).is_some() {
                    item[field] = reference[field].clone();
                }
            }
            item["body"] = reference;
        }
        reject_deferred(&request)?;
        Ok(request)
    }
}

fn reject_deferred(request: &Value) -> Result<(), HookError> {
    if crate::body::contains_deferred(request) {
        return Err(error(
            "deferred body handle outside a selected content location",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{AuthorizedScope, ContentReference, ContentStore, UploadError};
    use serde_json::json;
    use std::{collections::BTreeMap, sync::Arc};

    struct NoReads;
    impl ContentStore for NoReads {
        fn resolve(
            &self,
            _: &AuthorizedScope,
            _: &ContentReference,
        ) -> Result<Arc<[u8]>, UploadError> {
            panic!("projection must not read unselected bytes")
        }
        fn put(&self, _: &AuthorizedScope, _: Arc<[u8]>) -> Result<ContentReference, UploadError> {
            panic!("projection must not allocate host content")
        }
    }
    fn options() -> BackendOptions {
        BackendOptions {
            credentials: BTreeMap::new(),
            allow_anonymous_http: false,
            allow_loopback_http: false,
            max_frame_bytes: 8192,
        }
    }
    fn item() -> Value {
        json!({"id":"one","kind":"text","mediaType":"text/plain","role":"assistant",
            "selection":"body","body":{"ref":"host-only","size":3,"sha256":"0".repeat(64)},
            "size":3,"sha256":"0".repeat(64)})
    }
    fn context() -> ContentContext<'static> {
        ContentContext {
            store: &NoReads,
            scope: AuthorizedScope::new("test"),
        }
    }
    #[test]
    fn misplaced_deferred_handles_cannot_escape_in_arbitrary_json() {
        let registry = crate::body::DeferredBodies::new(8, 1);
        let handle = registry.register(crate::body::Body::bytes([1])).unwrap();
        let request = json!({"params":{"event":{"type":"tool.before","input":{"nested":handle}}}});
        assert!(
            futures::executor::block_on(project_with_bodies(
                request,
                &json!({"default":"metadata"}),
                None,
                &context(),
                &options(),
                &registry,
            ))
            .is_err()
        );
    }

    #[test]
    fn reduced_views_preserve_presence_without_reading() {
        for mode in ["metadata", "omit"] {
            let original = json!({"params":{"event":{"type":"tool.after","items":[item()],
                "fileChanges":[{"before":item(),"after":item()}],"tool":{"input":{"items":[item()]}}}}});
            let result = futures::executor::block_on(project(
                original.clone(),
                &json!({"default":mode}),
                None,
                &context(),
                &options(),
            ))
            .unwrap();
            for path in ["/items/0", "/fileChanges/0/before", "/fileChanges/0/after"] {
                let projected = result["params"]["event"].pointer(path).unwrap();
                assert_eq!(projected["selection"], mode);
                assert!(projected.get("body").is_none());
                assert_eq!(projected["id"], "one");
                assert_eq!(projected["size"], 3);
                crate::canonical::validate("content-item", projected).unwrap();
            }
            assert_eq!(
                result["params"]["event"]["tool"]["input"],
                original["params"]["event"]["tool"]["input"]
            );
            assert!(
                original["params"]["event"]["items"][0]
                    .get("body")
                    .is_some()
            );
        }
    }
    #[test]
    fn singular_and_nested_locations_are_exact() {
        for (kind, path) in [
            ("turn.progress", "/delta"),
            ("tool.progress", "/partialOutput"),
            ("context.compact.before", "/instructions"),
            ("context.compact.after", "/summary"),
            ("user.elicitation.request", "/elicitation/request"),
            ("user.elicitation.result", "/elicitation/result"),
            ("user.message.inbound", "/message/text/0"),
            ("user.message.outbound", "/message/payload/0"),
            ("user.attention", "/attention/title/0"),
        ] {
            let mut event = json!({"type":kind,"delta":item(),"partialOutput":item(),"instructions":item(),"summary":item(),
                "elicitation":{"request":item(),"result":item()},"message":{"text":[item()],"payload":[item()]},
                "attention":{"title":[item()],"message":[item()]},"tool":{"input":item()}});
            let original = event.clone();
            let result = futures::executor::block_on(project(
                json!({"params":{"event":event}}),
                &json!({"default":"omit"}),
                None,
                &context(),
                &options(),
            ))
            .unwrap();
            event = result["params"]["event"].clone();
            assert_eq!(event.pointer(path).unwrap()["selection"], "omit");
            assert_eq!(event["tool"], original["tool"]);
        }
    }
    #[test]
    fn missing_upload_and_missing_body_fail_closed() {
        let request = json!({"params":{"event":{"type":"tool.after","items":[item()]}}});
        assert!(
            futures::executor::block_on(project(
                request,
                &json!({"default":"body"}),
                None,
                &context(),
                &options()
            ))
            .is_err()
        );
        let mut missing = item();
        missing.as_object_mut().unwrap().remove("body");
        let mut options = options();
        options
            .credentials
            .insert("upload-only".into(), "secret".into());
        let upload = json!({"endpoint":"https://upload.example/exact","maxBytes":100,"timeoutMs":50,"auth":{"type":"bearer","tokenRef":"upload-only"}});
        let request = json!({"params":{"event":{"type":"tool.after","items":[missing]}}});
        let err = futures::executor::block_on(project(
            request,
            &json!({"default":"body"}),
            Some(&upload),
            &context(),
            &options,
        ))
        .unwrap_err();
        assert!(err.0.contains("unavailable"));
    }
    #[test]
    fn upload_credentials_never_fall_back_to_event_credentials() {
        let mut options = options();
        options
            .credentials
            .insert("event-token".into(), "secret".into());
        assert!(upload_credential(&json!({}), &options).is_err());
        assert!(
            upload_credential(
                &json!({"auth":{"type":"bearer","tokenRef":"upload-token"}}),
                &options
            )
            .is_err()
        );
        assert!(upload_credential(&json!({"auth":{"type":"bearer","tokenEnv":"AHP_TEST_MISSING_UPLOAD_CREDENTIAL_319670"}}), &options).is_err());
        options
            .credentials
            .insert("upload-token".into(), "upload-secret".into());
        assert!(
            upload_credential(
                &json!({"auth":{"type":"bearer","tokenRef":"upload-token"}}),
                &options
            )
            .is_ok()
        );
    }
    #[test]
    fn missing_store_bytes_and_explicit_gaps_fail_closed() {
        let store = crate::content::MemoryContentStore::new(100, 100, 10);
        let context = ContentContext {
            store: &store,
            scope: AuthorizedScope::new("test"),
        };
        let mut options = options();
        options.allow_anonymous_http = true;
        let upload =
            json!({"endpoint":"https://upload.example/exact","maxBytes":100,"timeoutMs":50});
        let mut descriptor = item();
        let request = json!({"params":{"event":{"type":"tool.after","items":[descriptor]}}});
        assert!(
            futures::executor::block_on(project(
                request,
                &json!({"default":"body"}),
                Some(&upload),
                &context,
                &options
            ))
            .is_err()
        );
        descriptor.as_object_mut().unwrap().remove("body");
        descriptor["gap"] = json!({"reason":"unavailable"});
        let request = json!({"params":{"event":{"type":"tool.after","items":[descriptor]}}});
        assert!(
            futures::executor::block_on(project(
                request.clone(),
                &json!({"default":"body"}),
                Some(&upload),
                &context,
                &options
            ))
            .is_err()
        );
        let result = futures::executor::block_on(project(
            request,
            &json!({"default":"metadata"}),
            None,
            &self::context(),
            &options,
        ))
        .unwrap();
        assert!(result["params"]["event"]["items"][0].get("gap").is_none());
    }

    fn response(effect: Value) -> Value {
        json!({"jsonrpc":"2.0","id":"event","result":{"protocolVersion":"draft","effects":[effect]}})
    }

    #[test]
    fn registration_reduction_revokes_original_modify_grant() {
        let original = json!({"jsonrpc":"2.0","id":"event","method":"hooks/intercept","params":{
            "protocolVersion":"draft","event":{"type":"tool.after","items":[item()]},
            "capabilities":{"effects":["modify","message"],"modify":{"output":{"replace":true,"merge":true}}}
        }});
        let reply = response(
            json!({"type":"modify","target":"output","operation":"replace","value":"changed"}),
        );
        assert!(validate_response_grants(&original, &reply).is_ok());
        for mode in ["metadata", "omit"] {
            let projected = futures::executor::block_on(project(
                original.clone(),
                &json!({"default":mode}),
                None,
                &context(),
                &options(),
            ))
            .unwrap();
            assert_eq!(
                projected["params"]["capabilities"]["effects"],
                json!(["message"])
            );
            assert!(projected["params"]["capabilities"].get("modify").is_none());
            assert!(validate_response_grants(&projected, &reply).is_err());
        }
        assert!(validate_response_grants(&original, &reply).is_ok());
    }

    #[test]
    fn reduced_content_does_not_revoke_tool_input_grants() {
        let request = json!({"params":{"event":{"type":"tool.before","items":[item()],"tool":{"input":{"original":true}}},
            "capabilities":{"effects":["modify"],"modify":{"input":{"replace":true,"merge":false}}}}});
        let projected = futures::executor::block_on(project(
            request.clone(),
            &json!({"default":"metadata"}),
            None,
            &context(),
            &options(),
        ))
        .unwrap();
        assert_eq!(
            projected["params"]["capabilities"],
            request["params"]["capabilities"]
        );
        assert!(
            validate_response_grants(
                &projected,
                &response(
                    json!({"type":"modify","target":"input","operation":"replace","value":{}})
                )
            )
            .is_ok()
        );
        assert!(
            validate_response_grants(
                &projected,
                &response(json!({"type":"modify","target":"input","operation":"merge","value":{}}))
            )
            .is_err()
        );
        assert!(
            validate_response_grants(
                &projected,
                &response(
                    json!({"type":"modify","target":"output","operation":"replace","value":{}})
                )
            )
            .is_err()
        );
    }

    #[test]
    fn body_reduced_elicitation_grants_only_keep_non_body_effects() {
        for mode in ["form", "url"] {
            for stage in ["request", "result"] {
                let mut event =
                    json!({"type":format!("user.elicitation.{stage}"),"elicitation":{"mode":mode}});
                event["elicitation"][stage] = item();
                let request = json!({"params":{"event":event,"capabilities":{"effects":["deny","return","modify","message"],
                    "modify":{"content":{"replace":true}},"elicitation":{"form":{},"url":{}}}}});
                let projected = futures::executor::block_on(project(
                    request,
                    &json!({"default":"metadata"}),
                    None,
                    &context(),
                    &options(),
                ))
                .unwrap();
                assert_eq!(
                    projected["params"]["capabilities"]["effects"],
                    json!(["message"])
                );
                assert!(
                    validate_response_grants(
                        &projected,
                        &response(json!({"type":"deny","reason":"no"}))
                    )
                    .is_err()
                );
                assert!(
                    validate_response_grants(
                        &projected,
                        &response(json!({"type":"return","value":null}))
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn unknown_effects_are_rejected_even_if_advertised() {
        let request = json!({"params":{"capabilities":{"effects":["com.example.unknown"]}}});
        assert!(
            validate_response_grants(&request, &response(json!({"type":"com.example.unknown"})))
                .is_err()
        );
    }

    #[test]
    fn mixed_generic_views_fail_closed_without_host_index_mapping() {
        let mut reduced = item();
        reduced["selection"] = json!("metadata");
        reduced.as_object_mut().unwrap().remove("body");
        let mut request = json!({"params":{"event":{"type":"turn.start","items":[item(),reduced]},
            "capabilities":{"effects":["modify"],"modify":{"prompt":{"replace":true}}}}});
        narrow_projected_grants(&mut request);
        assert_eq!(request["params"]["capabilities"]["effects"], json!([]));
    }

    #[test]
    fn category_override_uses_media_not_enclosing_role() {
        let mut image = item();
        image["mediaType"] = json!("image/png");
        image["role"] = json!("user");
        let request = json!({"params":{"event":{"type":"model.request.before","items":[image]}}});
        let result = futures::executor::block_on(project(
            request,
            &json!({"default":"body","images":"metadata"}),
            None,
            &context(),
            &options(),
        ))
        .unwrap();
        assert_eq!(
            result["params"]["event"]["items"][0]["selection"],
            "metadata"
        );
    }
}
