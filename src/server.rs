//! One validated dispatcher shared by HTTP and line framing adapters.
use crate::{
    content::{AuthorizedScope, ContentContext, ContentStore, UploadError},
    generated as g,
    transport::{Request, Response},
};
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};
/// Identity supplied by credential verification, never event reference fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub subject: String,
}
/// Only transport credentials are supplied, not untrusted protocol payloads.
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, authorization: Option<&str>) -> Result<Principal, String>;
}
/// Owned future returned by an event-specific callback.
pub type ServerFuture<T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'static>>;
/// Event-correlated response. Only an interception context can create one.
pub struct Reply<E> {
    scope: Arc<()>,
    effects: Vec<E>,
}
impl<E> Reply<E> {
    /// Retains the entire canonical effect, including ordering and opaque members.
    pub fn effect(mut self, effect: E) -> Self {
        self.effects.push(effect);
        self
    }
}
/// Authenticated, validated interception state. Protocol response headers are server-owned.
pub struct InterceptContext<E> {
    pub principal: Principal,
    pub verified_content: ResolvedContent,
    request: Arc<serde_json::Value>,
    scope: Arc<()>,
    marker: std::marker::PhantomData<fn() -> E>,
}
impl<E> InterceptContext<E> {
    /// An empty reply is a valid no-op.
    pub fn reply(&self) -> Reply<E> {
        Reply {
            scope: self.scope.clone(),
            effects: Vec::new(),
        }
    }
    pub fn grants(&self) -> &serde_json::Value {
        &self.request["params"]["capabilities"]
    }
    pub fn request(&self) -> &serde_json::Value {
        &self.request
    }
    /// Decode caller-owned data without dropping wire members or bypassing invariants.
    pub fn decode<T: serde::Serialize + serde::de::DeserializeOwned>(
        &self,
        pointer: &str,
        contract: &crate::contracts::Contract<T>,
    ) -> Result<T, String> {
        contract
            .decode(
                self.request
                    .pointer(pointer)
                    .ok_or("missing caller-owned data")?,
            )
            .map_err(|error| error.to_string())
    }
}
/// Observation state intentionally has no reply or effect methods.
pub struct ObserveContext<E> {
    pub principal: Principal,
    pub verified_content: ResolvedContent,
    request: Arc<serde_json::Value>,
    marker: std::marker::PhantomData<fn() -> E>,
}
impl<E> ObserveContext<E> {
    pub fn request(&self) -> &serde_json::Value {
        &self.request
    }
    /// Decode caller-owned data without dropping wire members or bypassing invariants.
    pub fn decode<T: serde::Serialize + serde::de::DeserializeOwned>(
        &self,
        pointer: &str,
        contract: &crate::contracts::Contract<T>,
    ) -> Result<T, String> {
        contract
            .decode(
                self.request
                    .pointer(pointer)
                    .ok_or("missing caller-owned data")?,
            )
            .map_err(|error| error.to_string())
    }
}
pub struct DiscoveryContext {
    pub principal: Principal,
    pub verified_content: ResolvedContent,
    scope: Arc<()>,
}
pub struct DiscoveryReply {
    scope: Arc<()>,
    manifest: g::CapabilitiesResponseResultManifest,
}
impl DiscoveryContext {
    pub fn reply(&self, manifest: g::CapabilitiesResponseResultManifest) -> DiscoveryReply {
        DiscoveryReply {
            scope: self.scope.clone(),
            manifest,
        }
    }
}
pub type ToolBeforeContext = InterceptContext<g::ToolBeforeEffect>;
pub type ToolBeforeReply = Reply<g::ToolBeforeEffect>;
pub type ToolAfterContext = InterceptContext<g::ToolAfterEffect>;
pub type ToolAfterReply = Reply<g::ToolAfterEffect>;
pub type SessionStartContext = InterceptContext<g::SessionStartEffect>;
pub type SessionStartReply = Reply<g::SessionStartEffect>;
pub type ConfigChangeBeforeContext = InterceptContext<g::ConfigChangeBeforeEffect>;
pub type ConfigChangeBeforeReply = Reply<g::ConfigChangeBeforeEffect>;
pub type TurnStartContext = InterceptContext<g::TurnStartEffect>;
pub type TurnStartReply = Reply<g::TurnStartEffect>;
pub type TurnFinishBeforeContext = InterceptContext<g::TurnFinishBeforeEffect>;
pub type TurnFinishBeforeReply = Reply<g::TurnFinishBeforeEffect>;
pub type ModelRequestBeforeContext = InterceptContext<g::ModelRequestBeforeEffect>;
pub type ModelRequestBeforeReply = Reply<g::ModelRequestBeforeEffect>;
pub type ModelResponseAfterContext = InterceptContext<g::ModelResponseAfterEffect>;
pub type ModelResponseAfterReply = Reply<g::ModelResponseAfterEffect>;
pub type ModelSwitchBeforeContext = InterceptContext<g::ModelSwitchBeforeEffect>;
pub type ModelSwitchBeforeReply = Reply<g::ModelSwitchBeforeEffect>;
pub type ToolPermissionRequestContext = InterceptContext<g::ToolPermissionRequestEffect>;
pub type ToolPermissionRequestReply = Reply<g::ToolPermissionRequestEffect>;
pub type ToolBatchAfterContext = InterceptContext<g::ToolBatchAfterEffect>;
pub type ToolBatchAfterReply = Reply<g::ToolBatchAfterEffect>;
pub type ContextCompactBeforeContext = InterceptContext<g::ContextCompactBeforeEffect>;
pub type ContextCompactBeforeReply = Reply<g::ContextCompactBeforeEffect>;
pub type ContextCompactAfterContext = InterceptContext<g::ContextCompactAfterEffect>;
pub type ContextCompactAfterReply = Reply<g::ContextCompactAfterEffect>;
pub type TaskChangeBeforeContext = InterceptContext<g::TaskChangeBeforeEffect>;
pub type TaskChangeBeforeReply = Reply<g::TaskChangeBeforeEffect>;
pub type UserElicitationRequestContext = InterceptContext<g::UserElicitationRequestEffect>;
pub type UserElicitationRequestReply = Reply<g::UserElicitationRequestEffect>;
pub type UserElicitationResultContext = InterceptContext<g::UserElicitationResultEffect>;
pub type UserElicitationResultReply = Reply<g::UserElicitationResultEffect>;
pub type UserMessageInboundContext = InterceptContext<g::UserMessageInboundEffect>;
pub type UserMessageInboundReply = Reply<g::UserMessageInboundEffect>;
pub type UserMessageOutboundContext = InterceptContext<g::UserMessageOutboundEffect>;
pub type UserMessageOutboundReply = Reply<g::UserMessageOutboundEffect>;
pub type WorkspaceChangeBeforeContext = InterceptContext<g::WorkspaceChangeBeforeEffect>;
pub type WorkspaceChangeBeforeReply = Reply<g::WorkspaceChangeBeforeEffect>;
pub type ToolBeforeObserveContext = ObserveContext<g::ToolBeforeEvent>;
pub type ToolAfterObserveContext = ObserveContext<g::ToolAfterEvent>;
pub type SessionStartObserveContext = ObserveContext<g::SessionStartEvent>;
pub type SessionEndObserveContext = ObserveContext<g::SessionEndEvent>;
pub type ConfigChangeBeforeObserveContext = ObserveContext<g::ConfigChangeBeforeEvent>;
pub type ConfigChangeAfterObserveContext = ObserveContext<g::ConfigChangeAfterEvent>;
pub type TurnStartObserveContext = ObserveContext<g::TurnStartEvent>;
pub type TurnFinishBeforeObserveContext = ObserveContext<g::TurnFinishBeforeEvent>;
pub type TurnEndObserveContext = ObserveContext<g::TurnEndEvent>;
pub type TurnProgressObserveContext = ObserveContext<g::TurnProgressEvent>;
pub type ModelRequestBeforeObserveContext = ObserveContext<g::ModelRequestBeforeEvent>;
pub type ModelResponseAfterObserveContext = ObserveContext<g::ModelResponseAfterEvent>;
pub type ModelErrorObserveContext = ObserveContext<g::ModelErrorEvent>;
pub type ModelSwitchBeforeObserveContext = ObserveContext<g::ModelSwitchBeforeEvent>;
pub type ModelSwitchAfterObserveContext = ObserveContext<g::ModelSwitchAfterEvent>;
pub type ToolPermissionRequestObserveContext = ObserveContext<g::ToolPermissionRequestEvent>;
pub type ToolPermissionResolvedObserveContext = ObserveContext<g::ToolPermissionResolvedEvent>;
pub type ToolProgressObserveContext = ObserveContext<g::ToolProgressEvent>;
pub type ToolBatchAfterObserveContext = ObserveContext<g::ToolBatchAfterEvent>;
pub type ContextCompactBeforeObserveContext = ObserveContext<g::ContextCompactBeforeEvent>;
pub type ContextCompactAfterObserveContext = ObserveContext<g::ContextCompactAfterEvent>;
pub type TaskChangeBeforeObserveContext = ObserveContext<g::TaskChangeBeforeEvent>;
pub type TaskChangeAfterObserveContext = ObserveContext<g::TaskChangeAfterEvent>;
pub type UserAttentionObserveContext = ObserveContext<g::UserAttentionEvent>;
pub type UserElicitationRequestObserveContext = ObserveContext<g::UserElicitationRequestEvent>;
pub type UserElicitationResultObserveContext = ObserveContext<g::UserElicitationResultEvent>;
pub type UserMessageInboundObserveContext = ObserveContext<g::UserMessageInboundEvent>;
pub type UserMessageOutboundObserveContext = ObserveContext<g::UserMessageOutboundEvent>;
pub type WorkspaceChangeBeforeObserveContext = ObserveContext<g::WorkspaceChangeBeforeEvent>;
pub type WorkspaceChangeAfterObserveContext = ObserveContext<g::WorkspaceChangeAfterEvent>;
pub type FileChangedObserveContext = ObserveContext<g::FileChangedEvent>;
pub type HookFailureObserveContext = ObserveContext<g::HookFailureEvent>;
type Callback<C, E, R> = Arc<dyn Fn(C, E) -> ServerFuture<R> + Send + Sync>;
#[derive(Default)]
pub struct InterceptHandlers {
    pub tool_before: Option<Callback<ToolBeforeContext, g::ToolBeforeEvent, ToolBeforeReply>>,
    pub tool_after: Option<Callback<ToolAfterContext, g::ToolAfterEvent, ToolAfterReply>>,
    pub session_start:
        Option<Callback<SessionStartContext, g::SessionStartEvent, SessionStartReply>>,
    pub config_change_before: Option<
        Callback<ConfigChangeBeforeContext, g::ConfigChangeBeforeEvent, ConfigChangeBeforeReply>,
    >,
    pub turn_start: Option<Callback<TurnStartContext, g::TurnStartEvent, TurnStartReply>>,
    pub turn_finish_before:
        Option<Callback<TurnFinishBeforeContext, g::TurnFinishBeforeEvent, TurnFinishBeforeReply>>,
    pub model_request_before: Option<
        Callback<ModelRequestBeforeContext, g::ModelRequestBeforeEvent, ModelRequestBeforeReply>,
    >,
    pub model_response_after: Option<
        Callback<ModelResponseAfterContext, g::ModelResponseAfterEvent, ModelResponseAfterReply>,
    >,
    pub model_switch_before: Option<
        Callback<ModelSwitchBeforeContext, g::ModelSwitchBeforeEvent, ModelSwitchBeforeReply>,
    >,
    pub tool_permission_request: Option<
        Callback<
            ToolPermissionRequestContext,
            g::ToolPermissionRequestEvent,
            ToolPermissionRequestReply,
        >,
    >,
    pub tool_batch_after:
        Option<Callback<ToolBatchAfterContext, g::ToolBatchAfterEvent, ToolBatchAfterReply>>,
    pub context_compact_before: Option<
        Callback<
            ContextCompactBeforeContext,
            g::ContextCompactBeforeEvent,
            ContextCompactBeforeReply,
        >,
    >,
    pub context_compact_after: Option<
        Callback<ContextCompactAfterContext, g::ContextCompactAfterEvent, ContextCompactAfterReply>,
    >,
    pub task_change_before:
        Option<Callback<TaskChangeBeforeContext, g::TaskChangeBeforeEvent, TaskChangeBeforeReply>>,
    pub user_elicitation_request: Option<
        Callback<
            UserElicitationRequestContext,
            g::UserElicitationRequestEvent,
            UserElicitationRequestReply,
        >,
    >,
    pub user_elicitation_result: Option<
        Callback<
            UserElicitationResultContext,
            g::UserElicitationResultEvent,
            UserElicitationResultReply,
        >,
    >,
    pub user_message_inbound: Option<
        Callback<UserMessageInboundContext, g::UserMessageInboundEvent, UserMessageInboundReply>,
    >,
    pub user_message_outbound: Option<
        Callback<UserMessageOutboundContext, g::UserMessageOutboundEvent, UserMessageOutboundReply>,
    >,
    pub workspace_change_before: Option<
        Callback<
            WorkspaceChangeBeforeContext,
            g::WorkspaceChangeBeforeEvent,
            WorkspaceChangeBeforeReply,
        >,
    >,
}
#[derive(Default)]
pub struct ObserveHandlers {
    pub tool_before: Option<Callback<ToolBeforeObserveContext, g::ToolBeforeEvent, ()>>,
    pub tool_after: Option<Callback<ToolAfterObserveContext, g::ToolAfterEvent, ()>>,
    pub session_start: Option<Callback<SessionStartObserveContext, g::SessionStartEvent, ()>>,
    pub session_end: Option<Callback<SessionEndObserveContext, g::SessionEndEvent, ()>>,
    pub config_change_before:
        Option<Callback<ConfigChangeBeforeObserveContext, g::ConfigChangeBeforeEvent, ()>>,
    pub config_change_after:
        Option<Callback<ConfigChangeAfterObserveContext, g::ConfigChangeAfterEvent, ()>>,
    pub turn_start: Option<Callback<TurnStartObserveContext, g::TurnStartEvent, ()>>,
    pub turn_finish_before:
        Option<Callback<TurnFinishBeforeObserveContext, g::TurnFinishBeforeEvent, ()>>,
    pub turn_end: Option<Callback<TurnEndObserveContext, g::TurnEndEvent, ()>>,
    pub turn_progress: Option<Callback<TurnProgressObserveContext, g::TurnProgressEvent, ()>>,
    pub model_request_before:
        Option<Callback<ModelRequestBeforeObserveContext, g::ModelRequestBeforeEvent, ()>>,
    pub model_response_after:
        Option<Callback<ModelResponseAfterObserveContext, g::ModelResponseAfterEvent, ()>>,
    pub model_error: Option<Callback<ModelErrorObserveContext, g::ModelErrorEvent, ()>>,
    pub model_switch_before:
        Option<Callback<ModelSwitchBeforeObserveContext, g::ModelSwitchBeforeEvent, ()>>,
    pub model_switch_after:
        Option<Callback<ModelSwitchAfterObserveContext, g::ModelSwitchAfterEvent, ()>>,
    pub tool_permission_request:
        Option<Callback<ToolPermissionRequestObserveContext, g::ToolPermissionRequestEvent, ()>>,
    pub tool_permission_resolved:
        Option<Callback<ToolPermissionResolvedObserveContext, g::ToolPermissionResolvedEvent, ()>>,
    pub tool_progress: Option<Callback<ToolProgressObserveContext, g::ToolProgressEvent, ()>>,
    pub tool_batch_after:
        Option<Callback<ToolBatchAfterObserveContext, g::ToolBatchAfterEvent, ()>>,
    pub context_compact_before:
        Option<Callback<ContextCompactBeforeObserveContext, g::ContextCompactBeforeEvent, ()>>,
    pub context_compact_after:
        Option<Callback<ContextCompactAfterObserveContext, g::ContextCompactAfterEvent, ()>>,
    pub task_change_before:
        Option<Callback<TaskChangeBeforeObserveContext, g::TaskChangeBeforeEvent, ()>>,
    pub task_change_after:
        Option<Callback<TaskChangeAfterObserveContext, g::TaskChangeAfterEvent, ()>>,
    pub user_attention: Option<Callback<UserAttentionObserveContext, g::UserAttentionEvent, ()>>,
    pub user_elicitation_request:
        Option<Callback<UserElicitationRequestObserveContext, g::UserElicitationRequestEvent, ()>>,
    pub user_elicitation_result:
        Option<Callback<UserElicitationResultObserveContext, g::UserElicitationResultEvent, ()>>,
    pub user_message_inbound:
        Option<Callback<UserMessageInboundObserveContext, g::UserMessageInboundEvent, ()>>,
    pub user_message_outbound:
        Option<Callback<UserMessageOutboundObserveContext, g::UserMessageOutboundEvent, ()>>,
    pub workspace_change_before:
        Option<Callback<WorkspaceChangeBeforeObserveContext, g::WorkspaceChangeBeforeEvent, ()>>,
    pub workspace_change_after:
        Option<Callback<WorkspaceChangeAfterObserveContext, g::WorkspaceChangeAfterEvent, ()>>,
    pub file_changed: Option<Callback<FileChangedObserveContext, g::FileChangedEvent, ()>>,
    pub hook_failure: Option<Callback<HookFailureObserveContext, g::HookFailureEvent, ()>>,
}
#[derive(Default)]
pub struct HandlerSet {
    pub intercept: InterceptHandlers,
    pub observe: ObserveHandlers,
    pub discovery: Option<Callback<DiscoveryContext, g::CapabilitiesRequest, DiscoveryReply>>,
}
/// Verified immutable bodies, keyed by their exact JSON pointer in the request.
/// Metadata/omit items are intentionally absent. Logical IDs may repeat across
/// fields, so pointers rather than IDs prevent accidental collisions.
#[derive(Clone, Debug, Default)]
pub struct ResolvedContent {
    bodies: BTreeMap<String, Arc<[u8]>>,
}
impl ResolvedContent {
    pub fn get(&self, pointer: &str) -> Option<&Arc<[u8]>> {
        self.bodies.get(pointer)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Arc<[u8]>)> {
        self.bodies
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes))
    }
    pub fn len(&self) -> usize {
        self.bodies.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bodies.is_empty()
    }
}
type Prepared = (Principal, serde_json::Value, Option<ResolvedContent>);
pub struct Server<A> {
    pub handlers: HandlerSet,
    pub authenticator: A,
    pub max_body_bytes: usize,
}
fn response(status: u16, body: Vec<u8>) -> Response {
    Response {
        status,
        body,
        headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
    }
}
fn failure(status: u16, message: &str) -> Response {
    response(
        status,
        serde_json::to_vec(&serde_json::json!({"error":message})).expect("JSON string"),
    )
}
fn header<'a>(request: &'a Request, name: &str) -> Result<Option<&'a str>, ()> {
    let mut matches = request
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name));
    let first = matches.next().map(|(_, v)| v.as_str());
    if matches.next().is_some() {
        Err(())
    } else {
        Ok(first)
    }
}
impl<A: Authenticator> Server<A> {
    async fn invoke(
        &self,
        principal: Principal,
        raw: &serde_json::Value,
        content: ResolvedContent,
    ) -> Result<Option<serde_json::Value>, String> {
        let scope = Arc::new(());
        let request = Arc::new(raw.clone());
        // These macros only remove repetitive framing. Every arm still invokes
        // a different statically typed callback with a canonical event model.
        macro_rules! intercept {
            ($field:ident, $event:ty) => {{
                let event: $event = serde_json::from_value(raw["params"]["event"].clone())
                    .map_err(|e| e.to_string())?;
                let handler = self
                    .handlers
                    .intercept
                    .$field
                    .as_ref()
                    .ok_or("interception not configured")?;
                let reply = handler(
                    InterceptContext {
                        principal,
                        verified_content: content,
                        request,
                        scope: scope.clone(),
                        marker: std::marker::PhantomData,
                    },
                    event,
                )
                .await?;
                if !Arc::ptr_eq(&scope, &reply.scope) {
                    return Err("reply scope mismatch".into());
                }
                serde_json::to_value(reply.effects).map_err(|e| e.to_string())?
            }};
        }
        macro_rules! observe {
            ($field:ident, $event:ty) => {{
                let event: $event = serde_json::from_value(raw["params"]["event"].clone())
                    .map_err(|e| e.to_string())?;
                if let Some(handler) = &self.handlers.observe.$field {
                    handler(
                        ObserveContext {
                            principal,
                            verified_content: content,
                            request,
                            marker: std::marker::PhantomData,
                        },
                        event,
                    )
                    .await?;
                }
            }};
        }
        match raw["method"].as_str().ok_or("missing method")? {
            "hooks/capabilities" => {
                let handler = self
                    .handlers
                    .discovery
                    .as_ref()
                    .ok_or("discovery not configured")?;
                let event = serde_json::from_value(raw.clone()).map_err(|e| e.to_string())?;
                let reply = handler(
                    DiscoveryContext {
                        principal,
                        verified_content: content,
                        scope: scope.clone(),
                    },
                    event,
                )
                .await?;
                if !Arc::ptr_eq(&scope, &reply.scope) {
                    return Err("reply scope mismatch".into());
                }
                Ok(Some(
                    serde_json::json!({"jsonrpc":"2.0", "id":raw["id"], "result":{"protocolVersion":g::PROTOCOL_VERSION, "manifest":reply.manifest}}),
                ))
            }
            "hooks/intercept" => {
                let effects = match raw["params"]["event"]["type"]
                    .as_str()
                    .ok_or("missing event type")?
                {
                    "tool.before" => intercept!(tool_before, g::ToolBeforeEvent),
                    "tool.after" => intercept!(tool_after, g::ToolAfterEvent),
                    "session.start" => intercept!(session_start, g::SessionStartEvent),
                    "config.change.before" => {
                        intercept!(config_change_before, g::ConfigChangeBeforeEvent)
                    }
                    "turn.start" => intercept!(turn_start, g::TurnStartEvent),
                    "turn.finish.before" => {
                        intercept!(turn_finish_before, g::TurnFinishBeforeEvent)
                    }
                    "model.request.before" => {
                        intercept!(model_request_before, g::ModelRequestBeforeEvent)
                    }
                    "model.response.after" => {
                        intercept!(model_response_after, g::ModelResponseAfterEvent)
                    }
                    "model.switch.before" => {
                        intercept!(model_switch_before, g::ModelSwitchBeforeEvent)
                    }
                    "tool.permission.request" => {
                        intercept!(tool_permission_request, g::ToolPermissionRequestEvent)
                    }
                    "tool.batch.after" => intercept!(tool_batch_after, g::ToolBatchAfterEvent),
                    "context.compact.before" => {
                        intercept!(context_compact_before, g::ContextCompactBeforeEvent)
                    }
                    "context.compact.after" => {
                        intercept!(context_compact_after, g::ContextCompactAfterEvent)
                    }
                    "task.change.before" => {
                        intercept!(task_change_before, g::TaskChangeBeforeEvent)
                    }
                    "user.elicitation.request" => {
                        intercept!(user_elicitation_request, g::UserElicitationRequestEvent)
                    }
                    "user.elicitation.result" => {
                        intercept!(user_elicitation_result, g::UserElicitationResultEvent)
                    }
                    "user.message.inbound" => {
                        intercept!(user_message_inbound, g::UserMessageInboundEvent)
                    }
                    "user.message.outbound" => {
                        intercept!(user_message_outbound, g::UserMessageOutboundEvent)
                    }
                    "workspace.change.before" => {
                        intercept!(workspace_change_before, g::WorkspaceChangeBeforeEvent)
                    }
                    _ => return Err("unsupported interception".into()),
                };
                Ok(Some(
                    serde_json::json!({"jsonrpc":"2.0", "id":raw["id"], "result":{"protocolVersion":g::PROTOCOL_VERSION, "effects":effects}}),
                ))
            }
            "hooks/observe" => {
                match raw["params"]["event"]["type"]
                    .as_str()
                    .ok_or("missing event type")?
                {
                    "tool.before" => observe!(tool_before, g::ToolBeforeEvent),
                    "tool.after" => observe!(tool_after, g::ToolAfterEvent),
                    "session.start" => observe!(session_start, g::SessionStartEvent),
                    "session.end" => observe!(session_end, g::SessionEndEvent),
                    "config.change.before" => {
                        observe!(config_change_before, g::ConfigChangeBeforeEvent)
                    }
                    "config.change.after" => {
                        observe!(config_change_after, g::ConfigChangeAfterEvent)
                    }
                    "turn.start" => observe!(turn_start, g::TurnStartEvent),
                    "turn.finish.before" => observe!(turn_finish_before, g::TurnFinishBeforeEvent),
                    "turn.end" => observe!(turn_end, g::TurnEndEvent),
                    "turn.progress" => observe!(turn_progress, g::TurnProgressEvent),
                    "model.request.before" => {
                        observe!(model_request_before, g::ModelRequestBeforeEvent)
                    }
                    "model.response.after" => {
                        observe!(model_response_after, g::ModelResponseAfterEvent)
                    }
                    "model.error" => observe!(model_error, g::ModelErrorEvent),
                    "model.switch.before" => {
                        observe!(model_switch_before, g::ModelSwitchBeforeEvent)
                    }
                    "model.switch.after" => observe!(model_switch_after, g::ModelSwitchAfterEvent),
                    "tool.permission.request" => {
                        observe!(tool_permission_request, g::ToolPermissionRequestEvent)
                    }
                    "tool.permission.resolved" => {
                        observe!(tool_permission_resolved, g::ToolPermissionResolvedEvent)
                    }
                    "tool.progress" => observe!(tool_progress, g::ToolProgressEvent),
                    "tool.batch.after" => observe!(tool_batch_after, g::ToolBatchAfterEvent),
                    "context.compact.before" => {
                        observe!(context_compact_before, g::ContextCompactBeforeEvent)
                    }
                    "context.compact.after" => {
                        observe!(context_compact_after, g::ContextCompactAfterEvent)
                    }
                    "task.change.before" => observe!(task_change_before, g::TaskChangeBeforeEvent),
                    "task.change.after" => observe!(task_change_after, g::TaskChangeAfterEvent),
                    "user.attention" => observe!(user_attention, g::UserAttentionEvent),
                    "user.elicitation.request" => {
                        observe!(user_elicitation_request, g::UserElicitationRequestEvent)
                    }
                    "user.elicitation.result" => {
                        observe!(user_elicitation_result, g::UserElicitationResultEvent)
                    }
                    "user.message.inbound" => {
                        observe!(user_message_inbound, g::UserMessageInboundEvent)
                    }
                    "user.message.outbound" => {
                        observe!(user_message_outbound, g::UserMessageOutboundEvent)
                    }
                    "workspace.change.before" => {
                        observe!(workspace_change_before, g::WorkspaceChangeBeforeEvent)
                    }
                    "workspace.change.after" => {
                        observe!(workspace_change_after, g::WorkspaceChangeAfterEvent)
                    }
                    "file.changed" => observe!(file_changed, g::FileChangedEvent),
                    "hook.failure" => observe!(hook_failure, g::HookFailureEvent),
                    _ => return Err("unsupported observation".into()),
                }
                Ok(None)
            }
            _ => Err("unsupported method".into()),
        }
    }
    pub async fn handle(&self, request: Request) -> Response {
        self.dispatch(self.prepare(request, None)).await
    }
    /// Opt into automatic verification. Scope comes exclusively from the
    /// authenticated principal, never principalRef/session/source or body refs.
    /// Resolution is synchronous; the returned future does not borrow the store.
    pub fn handle_with_content<'a>(
        &'a self,
        request: Request,
        store: &dyn ContentStore,
    ) -> impl Future<Output = Response> + Send + 'a + use<'a, A> {
        let prepared = self.prepare(request, Some(store));
        self.dispatch(prepared)
    }
    fn prepare(
        &self,
        request: Request,
        store: Option<&dyn ContentStore>,
    ) -> Result<Prepared, Response> {
        if request.method != "POST" {
            return Err(failure(405, "POST required"));
        }
        if request.body.len() > self.max_body_bytes {
            return Err(failure(413, "body too large"));
        }
        let authorization = match header(&request, "authorization") {
            Ok(v) => v,
            Err(_) => return Err(failure(401, "ambiguous credentials")),
        };
        let principal = match self.authenticator.authenticate(authorization) {
            Ok(p) => p,
            Err(_) => return Err(failure(401, "authentication failed")),
        };
        if !matches!(header(&request, "content-type"), Ok(Some(v)) if v.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(failure(415, "application/json required"));
        }
        let raw: serde_json::Value = match serde_json::from_slice(&request.body) {
            Ok(v) => v,
            Err(_) => return Err(failure(400, "invalid JSON")),
        };
        let method = raw["method"].as_str().unwrap_or("");
        let schema = match method {
            "hooks/intercept" => "intercept-request",
            "hooks/observe" => "observe-notification",
            "hooks/capabilities" => "capabilities-request",
            _ => return Err(failure(400, "unsupported method")),
        };
        if crate::canonical::validate(schema, &raw).is_err() {
            return Err(failure(400, "invalid canonical message"));
        }
        let parsed = match method {
            "hooks/capabilities" => g::parse_capabilities_request_value(raw.clone())
                .into_value()
                .is_some(),
            "hooks/intercept" => {
                if raw["id"] != raw["params"]["event"]["id"] {
                    return Err(failure(400, "event correlation mismatch"));
                }
                g::parse_intercept_request_value(raw.clone())
                    .into_value()
                    .is_some()
            }
            "hooks/observe" => g::parse_observe_notification_value(raw.clone())
                .into_value()
                .is_some(),
            _ => false,
        };
        if !parsed {
            return Err(failure(400, "invalid protocol message"));
        }

        let content = if let Some(store) = store {
            let context = ContentContext {
                store,
                scope: AuthorizedScope::new(principal.subject.clone()),
            };
            Some(
                resolve_event_content(&raw, &context)
                    .map_err(|_| failure(400, "selected content unavailable or invalid"))?,
            )
        } else {
            None
        };
        Ok((principal, raw, content))
    }
    async fn dispatch(&self, prepared: Result<Prepared, Response>) -> Response {
        let (principal, raw, content) = match prepared {
            Ok(prepared) => prepared,
            Err(response) => return response,
        };
        let method = raw["method"].as_str().unwrap_or("");
        let value = match self
            .invoke(principal, &raw, content.unwrap_or_default())
            .await
        {
            Ok(Some(value)) => value,
            Ok(None) => return response(204, Vec::new()),
            Err(_) => return failure(500, "handler failed or reply scope mismatch"),
        };
        let valid = match method {
            "hooks/intercept" => contextual_response(&raw, &value).is_ok(),
            _ => g::parse_capabilities_response_value(value.clone())
                .into_value()
                .is_some(),
        };
        let schema = if method == "hooks/intercept" {
            "intercept-response"
        } else {
            "capabilities-response"
        };
        if !valid
            || (method != "hooks/intercept" && crate::canonical::validate(schema, &value).is_err())
            || value["id"] != raw["id"]
        {
            return failure(500, "invalid or uncorrelated response");
        }
        if method == "hooks/intercept" && validate_effect_capabilities(&raw, &value).is_err() {
            return failure(500, "response exceeds advertised capabilities");
        }
        response(200, serde_json::to_vec(&value).expect("JSON value"))
    }
}

/// Parse contextually and retain canonical checks without inspecting unknown effects.
pub(crate) fn contextual_response(
    request: &serde_json::Value,
    response: &serde_json::Value,
) -> Result<g::ContextualResponse, String> {
    let event_type = request["params"]["event"]["type"]
        .as_str()
        .ok_or("missing originating event type")?;
    crate::canonical::validate("intercept-response", response)?;
    crate::protocol::parse(event_type, response).map_err(|e| e.to_string())
}

pub(crate) fn authority_name(kind: &crate::protocol::Kind<'_>) -> Option<&'static str> {
    use crate::protocol::Kind;
    Some(match kind {
        Kind::Deny => "deny",
        Kind::Allow => "allow",
        Kind::Ask => "ask",
        Kind::Modify { .. } => "modify",
        Kind::Message(_) => "message",
        Kind::Inject(_) => "inject",
        Kind::ReturnTool(_)
        | Kind::ReturnMessages(_)
        | Kind::ReturnText(_)
        | Kind::ReturnForm(_) => "return",
        Kind::Stop | Kind::Continue(_) => "flow",
        Kind::Unknown => return None,
    })
}

/// Check effect grants independently of event-specific application or tool execution.
/// Call after canonical message validation. Unknown effects never grant authority.
/// This does not resolve selected elicitation bodies or apply their semantic effects.
pub fn validate_effect_capabilities(
    request: &serde_json::Value,
    response: &serde_json::Value,
) -> Result<(), String> {
    use crate::protocol::{Kind, Operation};
    use serde_json::Value;
    fn contains(array: &Value, value: &str) -> bool {
        array
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(value)))
    }
    let caps = &request["params"]["capabilities"];
    let typed = contextual_response(request, response)?;
    let effects = crate::protocol::effects(&typed).map_err(|e| e.to_string())?;
    let event = &request["params"]["event"];
    if effects
        .iter()
        .any(|effect| !matches!(effect.kind, Kind::Unknown))
        && matches!(
            event["type"].as_str(),
            Some("user.elicitation.request" | "user.elicitation.result")
        )
    {
        let mode = event["elicitation"]["mode"]
            .as_str()
            .ok_or("missing elicitation mode")?;
        if !matches!(mode, "form" | "url") || !caps["elicitation"][mode].is_object() {
            return Err("unadvertised elicitation mode".into());
        }
    }
    // Canonical JSON integers include 1.0 and 1e0. The generated Integer
    // guard checks integrality and the safe range before numeric conversion.
    fn budget(value: &Value) -> Result<u64, String> {
        let integer = value
            .as_number()
            .cloned()
            .and_then(g::Integer::new)
            .ok_or("invalid continuation budget integer")?;
        let number = integer
            .as_number()
            .as_f64()
            .ok_or("invalid continuation budget integer")?;
        if number < 0.0 {
            return Err("negative continuation budget".into());
        }
        Ok(number as u64)
    }
    let continuation_already_pending = request["params"]["state"]["flow"] == "continue";
    for effect in &effects {
        let name = authority_name(&effect.kind).ok_or("unknown effect")?;
        if !contains(&caps["effects"], name) {
            return Err("unadvertised effect".into());
        }
        match &effect.kind {
            Kind::Modify {
                target, operation, ..
            } => {
                let operation = match operation {
                    Operation::Replace => "replace",
                    Operation::Merge => "merge",
                };
                if caps["modify"][*target][operation] != true {
                    return Err("unadvertised modification".into());
                }
            }
            Kind::Stop | Kind::Continue(_) => {
                let operation = if matches!(effect.kind, Kind::Continue(_)) {
                    "continue"
                } else {
                    "stop"
                };
                if !contains(&caps["flow"]["operations"], operation) {
                    return Err("unadvertised flow operation".into());
                }
                if matches!(effect.kind, Kind::Continue(_)) {
                    let remaining = budget(&caps["flow"]["remainingContinuations"])?;
                    let count = budget(&caps["flow"]["continuationCount"])?;
                    let max = caps["flow"]
                        .get("maxContinuations")
                        .map(budget)
                        .transpose()?;
                    // Coalesce continuation requests into one reserved follow-up.
                    if !continuation_already_pending
                        && (remaining == 0 || max.is_some_and(|max| count >= max))
                    {
                        return Err("continuation budget exhausted".into());
                    }
                }
            }
            Kind::Inject(injection) => {
                if caps["inject"]["context"]["append"] != true
                    || !contains(
                        &caps["inject"]["context"]["deliverAt"],
                        injection.deliver_at.as_str(),
                    )
                {
                    return Err("unadvertised context injection".into());
                }
            }
            Kind::Deny
            | Kind::Allow
            | Kind::Ask
            | Kind::Message(_)
            | Kind::ReturnTool(_)
            | Kind::ReturnMessages(_)
            | Kind::ReturnText(_)
            | Kind::ReturnForm(_)
            | Kind::Unknown => {}
        }
    }

    Ok(())
}

// Keep traversal tied to canonical event fields. Never recursively inspect tool
// input/output, extension objects, task data, or another open JSON payload.
fn resolve_event_content(
    request: &serde_json::Value,
    context: &ContentContext<'_>,
) -> Result<ResolvedContent, UploadError> {
    let mut result = ResolvedContent::default();
    if !matches!(
        request["method"].as_str(),
        Some("hooks/intercept" | "hooks/observe")
    ) {
        return Ok(result);
    }
    let event = &request["params"]["event"];
    for path in crate::hooks_content::locations(event) {
        let item = event.pointer(&path).ok_or(UploadError::Descriptor)?;
        // Inline text belongs to the event, not an upload or resolver cache.
        if item["kind"] == "attachment"
            && let Some(bytes) = context.resolve_selected(item)?
        {
            result.bodies.insert(format!("/params/event{path}"), bytes);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod contextual_response_tests {
    use super::*;
    use serde_json::{Value, json};

    fn request() -> Value {
        json!({"params":{"event":{"type":"tool.before"},"capabilities":{
            "effects":["deny","modify"],"modify":{"input":{"replace":true}}
        }}})
    }

    fn reply(effects: Value) -> Value {
        json!({"jsonrpc":"2.0","id":"rpc","result":{
            "protocolVersion":"draft","effects":effects
        }})
    }

    #[test]
    fn absent_effects_are_empty_but_null_is_invalid() {
        let mut response = reply(json!([]));
        response["result"]
            .as_object_mut()
            .unwrap()
            .remove("effects");
        assert!(validate_effect_capabilities(&request(), &response).is_ok());
        assert!(response["result"].get("effects").is_none());
        assert!(validate_effect_capabilities(&request(), &reply(Value::Null)).is_err());
    }

    #[test]
    fn unknown_effects_are_preserved_by_codec_but_rejected_by_canonical_boundary() {
        let response = reply(json!([{
            "type":"vendor.future", "effects":[{"type":"deny"}],
            "target":"input", "operation":"replace", "value":{"type":"modify"}
        }]));
        let original = response.clone();
        let typed = crate::protocol::parse("tool.before", &response).unwrap();
        assert!(
            crate::protocol::effects(&typed)
                .unwrap()
                .iter()
                .all(|effect| matches!(effect.kind, crate::protocol::Kind::Unknown))
        );
        assert!(contextual_response(&request(), &response).is_err());
        assert!(validate_effect_capabilities(&request(), &response).is_err());
        assert_eq!(response, original);

        let mut extras = reply(json!([]));
        extras["result"]["extensions"] = json!({"vendor.future":{"type":"deny"}});
        extras["result"]["vendor.future"] = json!({"effects":[{"type":"modify"}]});
        let original = extras.clone();
        assert!(validate_effect_capabilities(&request(), &extras).is_ok());
        assert_eq!(extras, original);
    }

    #[test]
    fn known_effects_require_contextual_shape_and_actual_grants() {
        let effect = json!({"type":"modify","target":"input","operation":"replace","value":{}});
        assert!(validate_effect_capabilities(&request(), &reply(json!([effect]))).is_ok());
        let mut ungranted = request();
        ungranted["params"]["capabilities"]["modify"]["input"]["replace"] = json!(false);
        assert!(validate_effect_capabilities(&ungranted, &reply(json!([effect]))).is_err());
        let wrong_target =
            json!({"type":"modify","target":"output","operation":"replace","value":{}});
        assert!(contextual_response(&request(), &reply(json!([wrong_target]))).is_err());
        let malformed = json!({"type":"modify","target":"input","operation":"replace"});
        assert!(contextual_response(&request(), &reply(json!([malformed]))).is_err());
    }
}
