//! Private, registration-driven projection. Never walk arbitrary application JSON.
use crate::adapters::registered::{AuthContext, AuthPurpose};
#[cfg(test)]
use crate::content::ContentContext;
use crate::{adapters::registered::BackendOptions, client::HookError, content::ContentAccess};
use serde_json::Value;
use std::time::{Duration, Instant};

fn error(message: impl ToString) -> HookError {
    HookError(message.to_string()).classified(crate::generated::DeliveryDiagnosticCode::Preparation)
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
pub(crate) fn locations(event: &Value) -> Vec<String> {
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
    if event["type"] == "tool.after"
        && let Some(changes) = event["fileChanges"].as_array()
    {
        for (i, change) in changes.iter().enumerate() {
            for stage in ["before", "after"] {
                if change.get(stage).is_some() {
                    paths.push(format!("/fileChanges/{i}/{stage}"));
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
        // An absent upload binding authorizes anonymous upload, never inheritance
        // of the selected backend's event credentials.
        return Ok(None);
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

fn remaining_upload_budget(deadline: Instant) -> Result<Duration, HookError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            HookError("upload deadline exceeded".into())
                .classified(crate::generated::DeliveryDiagnosticCode::DeadlineExceeded)
        })
}

async fn await_upload_phase<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = Result<T, HookError>>,
) -> Result<T, HookError> {
    let remaining = remaining_upload_budget(deadline)?;
    #[cfg(feature = "reqwest")]
    {
        tokio::time::timeout(remaining, future).await.map_err(|_| {
            HookError("upload deadline exceeded".into())
                .classified(crate::generated::DeliveryDiagnosticCode::DeadlineExceeded)
        })?
    }
    #[cfg(not(feature = "reqwest"))]
    {
        let _ = remaining;
        future.await
    }
}

async fn prepare_upload_credential(
    upload: &Value,
    options: &BackendOptions,
    context: &AuthContext,
) -> Result<(Option<crate::content::UploadCredential>, Option<String>), HookError> {
    remaining_upload_budget(context.deadline)?;
    let Some(provider) = &options.auth_provider else {
        return upload_credential(upload, options).map(|credential| (credential, None));
    };
    let credential = await_upload_phase(context.deadline, async {
        provider
            .credential(context.clone())
            .await
            .map_err(|_| error("upload authentication provider failed"))
    })
    .await?;
    remaining_upload_budget(context.deadline)?;
    match credential {
        Some(credential) => Ok((
            Some(
                crate::content::UploadCredential::bearer(credential.token)
                    .map_err(|_| error("invalid upload bearer credential"))?,
            ),
            Some(credential.attempt_id),
        )),
        None if context.authentication.is_none() => Ok((None, None)),
        None => Err(error("configured upload credential unavailable")),
    }
}

#[cfg(any(feature = "reqwest", test))]
struct ChallengeHttp<'a, H> {
    inner: &'a H,
    provider: Option<&'a dyn crate::adapters::registered::AuthProvider>,
    context: &'a AuthContext,
    attempt_id: Option<&'a str>,
}
#[cfg(any(feature = "reqwest", test))]
impl<H: crate::transport::Http> crate::transport::Http for ChallengeHttp<'_, H> {
    fn send(
        &self,
        request: crate::transport::Request,
    ) -> crate::client::LocalFuture<
        '_,
        Result<crate::transport::Response, crate::transport::TransportError>,
    > {
        Box::pin(async move {
            use crate::{adapters::registered::AuthChallenge, transport::TransportError};
            remaining_upload_budget(self.context.deadline)
                .map_err(|e| TransportError(e.to_string()))?;
            let response = self.inner.send(request).await?;
            if response.status == 401
                && let Some(provider) = self.provider
            {
                remaining_upload_budget(self.context.deadline)
                    .map_err(|e| TransportError(e.to_string()))?;
                await_upload_phase(self.context.deadline, async {
                    provider
                        .challenge(
                            self.context.clone(),
                            AuthChallenge {
                                status: response.status,
                                headers: response
                                    .headers
                                    .iter()
                                    .filter(|(key, _)| key.eq_ignore_ascii_case("www-authenticate"))
                                    .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
                                    .collect(),
                                attempt_id: self.attempt_id.map(str::to_owned),
                            },
                        )
                        .await
                        .map_err(|_| error("upload authentication challenge failed"))
                })
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            }
            // Upload allocation is effectful: authentication recovery does not grant replay.
            Ok(response)
        })
    }
}

fn selected_body(item: &Value) -> bool {
    item["selection"] == "body" && item.get("body").is_some() && item.get("gap").is_none()
}

fn remove_effect(caps: &mut Value, kind: &str) {
    if let Some(effects) = caps["effects"].as_array_mut() {
        effects.retain(|effect| effect != kind);
    }
    if kind == "modify"
        && let Some(object) = caps.as_object_mut()
    {
        object.remove("modify");
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn project_attachments(
    request: Value,
    selection: &Value,
    upload: Option<&Value>,
    attachments: &crate::attachment::InvocationAttachments,
    options: &BackendOptions,
    backend_id: &str,
    deadline: Instant,
) -> Result<Value, HookError> {
    project_inner(
        request,
        selection,
        upload,
        attachments,
        options,
        Some(attachments),
        backend_id,
        deadline,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn project(
    request: Value,
    selection: &Value,
    upload: Option<&Value>,
    content: &ContentContext<'_>,
    options: &BackendOptions,
) -> Result<Value, HookError> {
    project_inner(
        request,
        selection,
        upload,
        content,
        options,
        None,
        "test",
        Instant::now() + Duration::from_secs(30),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn project_inner(
    mut request: Value,
    selection: &Value,
    upload: Option<&Value>,
    content: &dyn ContentAccess,
    options: &BackendOptions,
    attachments: Option<&crate::attachment::InvocationAttachments>,
    backend_id: &str,
    deadline: Instant,
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
                if let Some(metadata) = attachments.and_then(|owners| owners.metadata(&path))
                    && let Some(metadata) = metadata.as_object()
                {
                    object.extend(metadata.clone());
                }
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
    let deadline = deadline.min(
        Instant::now()
            .checked_add(Duration::from_millis(timeout))
            .ok_or_else(|| error("invalid upload deadline"))?,
    );
    let auth_context = AuthContext {
        backend_id: backend_id.into(),
        authentication: upload.get("auth").cloned(),
        destination: endpoint.into(),
        purpose: AuthPurpose::Upload,
        deadline,
    };
    let (credential, attempt_id) =
        prepare_upload_credential(upload, options, &auth_context).await?;
    // Verify the complete batch before performing any upload. Failed uploads may
    // leave immutable receiver allocations, but no partial wire request escapes.
    let mut bodies = Vec::new();
    for path in selected {
        remaining_upload_budget(deadline)?;
        let item = event
            .pointer_mut(&path)
            .ok_or_else(|| error("missing content item"))?;
        if item.get("gap").is_some() {
            return Err(error("selected body unavailable"));
        }
        let bytes = selected_bytes(&path, item, content, attachments, max_bytes, deadline).await?;
        bodies.push((path, bytes));
    }
    // Local slot markers are replaced with receiver receipts before delivery.
    #[cfg(not(feature = "reqwest"))]
    {
        let _ = (endpoint, timeout, credential, bodies, attempt_id);
        Err(error(
            "selected body upload requires the reqwest feature, including for stdio hooks",
        ))
    }
    #[cfg(feature = "reqwest")]
    {
        let event = request
            .pointer_mut("/params/event")
            .ok_or_else(|| error("missing event"))?;
        for (path, bytes) in bodies {
            let remaining = remaining_upload_budget(deadline)?;
            let transport = crate::adapters::reqwest::ReqwestHttp::with_timeout(
                options.max_frame_bytes.min(8192),
                options.allow_loopback_http,
                remaining,
            )
            .map_err(error)?;
            let http = ChallengeHttp {
                inner: &transport,
                provider: options.auth_provider.as_deref(),
                context: &auth_context,
                attempt_id: attempt_id.as_deref(),
            };
            let uploader = crate::content::Uploader::new(
                &http,
                endpoint,
                max_bytes,
                credential.clone(),
                options.allow_loopback_http,
            )
            .map_err(error)?;
            let result = uploader.upload(&bytes).await;
            remaining_upload_budget(deadline)?;
            let reference = result.map_err(error)?;
            let reference = serde_json::to_value(reference.reference()).map_err(error)?;
            let item = event
                .pointer_mut(&path)
                .ok_or_else(|| error("missing content item"))?;
            for field in ["size", "sha256"] {
                item.as_object_mut()
                    .ok_or_else(|| error("invalid content item"))?
                    .remove(field);
            }
            item["body"] = reference;
        }
        reject_deferred(&request)?;
        Ok(request)
    }
}

async fn selected_bytes(
    path: &str,
    item: &Value,
    content: &dyn ContentAccess,
    attachments: Option<&crate::attachment::InvocationAttachments>,
    max_bytes: usize,
    deadline: Instant,
) -> Result<std::sync::Arc<[u8]>, HookError> {
    if let Some(attachments) = attachments {
        await_upload_phase(deadline, async {
            attachments
                .materialize(path, max_bytes)
                .await
                .map_err(error)
        })
        .await?;
    }
    let bytes = content
        .resolve_selected(path, item)
        .map_err(error)?
        .ok_or_else(|| error("selected body unavailable"))?;
    if bytes.len() > max_bytes {
        return Err(error("upload exceeds maxBytes"));
    }
    Ok(bytes)
}

fn reject_deferred(request: &Value) -> Result<(), HookError> {
    if crate::attachment::contains_local(request) {
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
            auth_provider: None,
            allow_anonymous_http: false,
            allow_loopback_http: false,
            max_frame_bytes: 8192,
        }
    }
    fn item() -> Value {
        json!({"id":"one","kind":"text","mediaType":"text/plain","role":"assistant",
            "selection":"body","body":{"ref":"host-only"}})
    }
    fn context() -> ContentContext<'static> {
        ContentContext {
            store: &NoReads,
            scope: AuthorizedScope::new("test"),
        }
    }
    #[derive(Default)]
    struct Provider {
        contexts: std::sync::Mutex<Vec<AuthContext>>,
        challenges: std::sync::Mutex<Vec<crate::adapters::registered::AuthChallenge>>,
        missing: bool,
        fail: bool,
    }
    impl crate::adapters::registered::AuthProvider for Provider {
        fn credential(
            &self,
            context: AuthContext,
        ) -> crate::client::LocalFuture<
            '_,
            Result<Option<crate::adapters::registered::BearerCredential>, HookError>,
        > {
            Box::pin(async move {
                self.contexts.lock().unwrap().push(context);
                if self.fail {
                    return Err(error("secret-provider-detail"));
                }
                Ok(if self.missing {
                    None
                } else {
                    Some(crate::adapters::registered::BearerCredential {
                        token: "upload-only-token".into(),
                        attempt_id: "opaque-attempt".into(),
                    })
                })
            })
        }
        fn challenge(
            &self,
            context: AuthContext,
            challenge: crate::adapters::registered::AuthChallenge,
        ) -> crate::client::LocalFuture<'_, Result<(), HookError>> {
            Box::pin(async move {
                self.contexts.lock().unwrap().push(context);
                self.challenges.lock().unwrap().push(challenge);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn upload_provider_gets_independent_binding_and_challenge_without_replay() {
        struct Rejected(std::sync::atomic::AtomicUsize);
        impl crate::transport::Http for Rejected {
            fn send(
                &self,
                request: crate::transport::Request,
            ) -> crate::client::LocalFuture<
                '_,
                Result<crate::transport::Response, crate::transport::TransportError>,
            > {
                Box::pin(async move {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    assert_eq!(request.headers["authorization"], "Bearer upload-only-token");
                    Ok(crate::transport::Response {
                        status: 401,
                        headers: BTreeMap::from([
                            (
                                "WWW-Authenticate".into(),
                                "Bearer error=invalid_token".into(),
                            ),
                            ("set-cookie".into(), "secret".into()),
                        ]),
                        body: vec![],
                    })
                })
            }
        }
        let provider = Arc::new(Provider::default());
        let mut options = options();
        options.auth_provider = Some(provider.clone());
        options
            .credentials
            .insert("event".into(), "event-only-token".into());
        let upload = json!({"auth":{"type":"bearer","tokenRef":"upload"}});
        let context = AuthContext {
            backend_id: "selected-backend".into(),
            authentication: upload.get("auth").cloned(),
            destination: "https://upload.example.test/content".into(),
            purpose: AuthPurpose::Upload,
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let (credential, attempt) =
            futures::executor::block_on(prepare_upload_credential(&upload, &options, &context))
                .unwrap();
        let inner = Rejected(std::sync::atomic::AtomicUsize::new(0));
        let http = ChallengeHttp {
            inner: &inner,
            provider: Some(provider.as_ref()),
            context: &context,
            attempt_id: attempt.as_deref(),
        };
        let uploader =
            crate::content::Uploader::new(&http, &context.destination, 8, credential, false)
                .unwrap();
        assert!(futures::executor::block_on(uploader.upload(b"body")).is_err());
        assert_eq!(inner.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        let contexts = provider.contexts.lock().unwrap();
        assert_eq!(contexts.len(), 2);
        for actual in contexts.iter() {
            assert_eq!(actual.backend_id, context.backend_id);
            assert_eq!(actual.authentication, context.authentication);
            assert_eq!(actual.destination, context.destination);
            assert_eq!(actual.purpose, AuthPurpose::Upload);
            assert_eq!(actual.deadline, context.deadline);
        }
        let challenges = provider.challenges.lock().unwrap();
        assert_eq!(challenges[0].attempt_id.as_deref(), Some("opaque-attempt"));
        assert_eq!(challenges[0].headers.len(), 1);
        assert_eq!(
            challenges[0].headers["www-authenticate"],
            "Bearer error=invalid_token"
        );
    }

    #[tokio::test]
    async fn upload_provider_missing_credentials_fail_closed_and_errors_are_sanitized() {
        let upload = json!({"auth":{"type":"bearer","tokenRef":"upload"}});
        for (missing, fail) in [(true, false), (false, true)] {
            let mut options = options();
            options.auth_provider = Some(Arc::new(Provider {
                missing,
                fail,
                ..Default::default()
            }));
            let context = AuthContext {
                backend_id: "selected-backend".into(),
                authentication: upload.get("auth").cloned(),
                destination: "https://upload.example.test/content".into(),
                purpose: AuthPurpose::Upload,
                deadline: Instant::now() + Duration::from_secs(10),
            };
            let result =
                futures::executor::block_on(prepare_upload_credential(&upload, &options, &context));
            let Err(error) = result else {
                panic!("must fail closed");
            };
            assert!(!error.to_string().contains("secret-provider-detail"));
            assert_eq!(
                error.code(),
                crate::generated::DeliveryDiagnosticCode::Preparation
            );
        }
        let provider = Arc::new(Provider::default());
        let mut options = options();
        options.auth_provider = Some(provider.clone());
        let context = AuthContext {
            backend_id: "selected-backend".into(),
            authentication: upload.get("auth").cloned(),
            destination: "https://upload.example.test/content".into(),
            purpose: AuthPurpose::Upload,
            deadline: Instant::now(),
        };
        let result =
            futures::executor::block_on(prepare_upload_credential(&upload, &options, &context));
        let Err(error) = result else {
            panic!("expired budget must fail");
        };
        assert_eq!(
            error.code(),
            crate::generated::DeliveryDiagnosticCode::DeadlineExceeded
        );
        assert!(provider.contexts.lock().unwrap().is_empty());
    }

    #[cfg(feature = "reqwest")]
    #[tokio::test]
    async fn pending_upload_auth_is_interrupted_by_phase_budget() {
        let result = await_upload_phase::<()>(
            Instant::now() + Duration::from_millis(5),
            std::future::pending(),
        )
        .await;
        assert_eq!(
            result.unwrap_err().code(),
            crate::generated::DeliveryDiagnosticCode::DeadlineExceeded
        );
    }

    #[test]
    fn misplaced_deferred_handles_cannot_escape_in_arbitrary_json() {
        let request = json!({"params":{"event":{"type":"tool.before","input":{"nested":{"ref":"ahp-attachment:0"}}}}});
        assert!(
            futures::executor::block_on(project(
                request,
                &json!({"default":"metadata"}),
                None,
                &context(),
                &options(),
            ))
            .is_err()
        );
    }

    #[tokio::test]
    async fn selected_upload_and_result_share_the_same_attachment_owner() {
        use crate::{
            Attachment,
            attachment::{Budget, InvocationAttachments},
            body::{BodyChunkFuture, BodyStream},
        };
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct Source {
            reads: Arc<AtomicUsize>,
            done: bool,
        }
        impl BodyStream for Source {
            fn next_chunk(&mut self) -> BodyChunkFuture<'_> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    if self.done {
                        Ok(None)
                    } else {
                        self.done = true;
                        Ok(Some(vec![0, 255, 42]))
                    }
                })
            }
        }
        for lazy in [false, true] {
            let reads = Arc::new(AtomicUsize::new(0));
            let attachment = if lazy {
                Attachment::lazy(Source {
                    reads: reads.clone(),
                    done: false,
                })
            } else {
                Attachment::bytes(vec![0, 255, 42])
            };
            let mut event = json!({"type":"tool.after", "items":[item()]});
            let content = InvocationAttachments::bind(
                &mut event,
                vec![crate::ergonomic_inputs::ContentSourceBinding {
                    path: vec!["items".into(), "0".into()],
                    source: attachment,
                }],
                Budget::new(8, 1),
                8,
            )
            .unwrap();
            let item = &event["items"][0];
            // This is the same helper used by selected HTTP upload. It lends
            // the owner's Arc, not a stored or re-spooled snapshot.
            let uploaded = selected_bytes(
                "/items/0",
                item,
                &content,
                Some(&content),
                8,
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .unwrap();
            let second = selected_bytes(
                "/items/0",
                item,
                &content,
                Some(&content),
                8,
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .unwrap();
            assert!(Arc::ptr_eq(&uploaded, &second));
            let result = content.finish();
            drop(content);
            let returned = result.read("/items/0").await.unwrap();
            assert!(Arc::ptr_eq(&uploaded, &returned));
            assert_eq!(&*returned, &[0, 255, 42]);
            assert_eq!(reads.load(Ordering::SeqCst), if lazy { 2 } else { 0 });
        }
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
                assert!(projected.get("size").is_none());
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
        assert!(err.to_string().contains("unavailable"));
    }
    #[test]
    fn upload_credentials_never_fall_back_to_event_credentials() {
        let mut options = options();
        options
            .credentials
            .insert("event-token".into(), "secret".into());
        assert!(upload_credential(&json!({}), &options).unwrap().is_none());
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
