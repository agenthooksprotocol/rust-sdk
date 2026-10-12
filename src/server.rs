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
    /// The observed event type, or `None` for a type this SDK does not know.
    pub fn event_type(&self) -> Option<g::EventType> {
        serde_json::from_value(self.request["params"]["event"]["type"].clone()).ok()
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
/// Context for the catch-all observer: the whole validated notification.
pub type AnyObserveContext = ObserveContext<g::ObserveNotification>;
/// A shareable event callback. Build one with [`callback`] or [`with_state`].
pub type Callback<C, E, R> = Arc<dyn Fn(C, E) -> ServerFuture<R> + Send + Sync>;
/// Wrap an async closure as a [`Callback`] without manual `Arc`/`Box::pin`.
/// Annotate the context parameter when the closure calls methods on it.
///
/// ```
/// use agenthooksprotocol::server::{HandlerSet, ToolBeforeContext, callback};
/// let mut handlers = HandlerSet::default();
/// handlers.intercept.tool_before = Some(callback(|ctx: ToolBeforeContext, _event| async move {
///     Ok(ctx.reply())
/// }));
/// ```
pub fn callback<C, E, R, F, Fut>(f: F) -> Callback<C, E, R>
where
    F: Fn(C, E) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<R, String>> + Send + 'static,
{
    Arc::new(move |context, event| Box::pin(f(context, event)))
}
/// Like [`callback`], but hands every invocation a clone of shared `state`,
/// so callbacks need no per-closure `Arc` cloning.
///
/// ```
/// use agenthooksprotocol::server::{HandlerSet, ToolBeforeContext, with_state};
/// use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
/// let seen = Arc::new(AtomicUsize::new(0));
/// let mut handlers = HandlerSet::default();
/// handlers.observe.tool_after = Some(with_state(seen.clone(), |seen, _ctx, _event| async move {
///     seen.fetch_add(1, Ordering::Relaxed);
///     Ok(())
/// }));
/// handlers.intercept.tool_before = Some(with_state(seen, |seen, ctx: ToolBeforeContext, _event| async move {
///     let _ = seen.load(Ordering::Relaxed);
///     Ok(ctx.reply())
/// }));
/// ```
pub fn with_state<S, C, E, R, F, Fut>(state: Arc<S>, f: F) -> Callback<C, E, R>
where
    S: ?Sized + Send + Sync + 'static,
    F: Fn(Arc<S>, C, E) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<R, String>> + Send + 'static,
{
    Arc::new(move |context, event| Box::pin(f(state.clone(), context, event)))
}
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
    /// Catch-all observer, invoked only for events whose per-event observer is
    /// `None`. It receives the validated notification; see
    /// [`ObserveContext::event_type`].
    pub any: Option<Callback<AnyObserveContext, g::ObserveNotification, ()>>,
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
/// A validated message, parsed exactly once.
enum Message {
    Intercept(Box<g::InterceptRequest>),
    Observe(g::ObserveNotification),
    Capabilities(g::CapabilitiesRequest),
}
struct Prepared {
    principal: Principal,
    raw: Arc<serde_json::Value>,
    message: Message,
    content: Option<ResolvedContent>,
}
fn parsed<T>(result: g::ParseResult<T>) -> Option<(T, serde_json::Value)> {
    match result {
        g::ParseResult::Success { value, raw, .. } => Some((value, raw)),
        g::ParseResult::Failure { .. } => None,
    }
}
pub struct Server<A> {
    pub handlers: HandlerSet,
    pub authenticator: A,
    pub max_body_bytes: usize,
}
/// Server-side JSON-RPC failure classes. Messages are fixed strings: handler
/// errors and validation diagnostics never reach the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RpcError {
    Parse,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    /// Invalid params: selected content could not be verified for this principal.
    ContentUnavailable,
    Internal,
    UnsupportedProtocolVersion,
    UnsupportedEvent,
    BackendInternal,
}
impl RpcError {
    fn code(self) -> i64 {
        match self {
            Self::Parse => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams | Self::ContentUnavailable => -32602,
            Self::Internal => -32603,
            Self::UnsupportedProtocolVersion => -32001,
            Self::UnsupportedEvent => -32002,
            Self::BackendInternal => -32004,
        }
    }
    fn message(self) -> &'static str {
        match self {
            Self::Parse => "Parse error",
            Self::InvalidRequest => "Invalid Request",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::ContentUnavailable => "Selected content unavailable or invalid",
            Self::Internal => "Internal error",
            Self::UnsupportedProtocolVersion => "Unsupported AHP protocol version",
            Self::UnsupportedEvent => "Unsupported event",
            Self::BackendInternal => "Backend internal error",
        }
    }
    /// HTTP status carrying the envelope: caller errors are 400, server errors 500.
    fn status(self) -> u16 {
        match self {
            Self::Internal | Self::BackendInternal => 500,
            _ => 400,
        }
    }
}
/// Why a message was not dispatched to a callback.
enum Rejection {
    /// Transport-level rejection before any JSON-RPC message is known.
    Transport(u16),
    /// A notification never receives a JSON-RPC response of any kind.
    Notification,
    /// A request receives a correlated (or null-id) JSON-RPC error.
    Request(serde_json::Value, RpcError),
}
/// Events that `hooks/intercept` can deliver. Must match the `invoke` match arms.
const INTERCEPT_EVENTS: &[&str] = &[
    "tool.before",
    "tool.after",
    "session.start",
    "config.change.before",
    "turn.start",
    "turn.finish.before",
    "model.request.before",
    "model.response.after",
    "model.switch.before",
    "tool.permission.request",
    "tool.batch.after",
    "context.compact.before",
    "context.compact.after",
    "task.change.before",
    "user.elicitation.request",
    "user.elicitation.result",
    "user.message.inbound",
    "user.message.outbound",
    "workspace.change.before",
];
fn response(status: u16, body: Vec<u8>) -> Response {
    Response {
        status,
        body,
        headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
    }
}
/// Bodyless status: transport rejections and notification acknowledgments.
fn empty(status: u16) -> Response {
    Response {
        status,
        ..Default::default()
    }
}
/// Build a JSON-RPC error envelope. `data` never carries handler diagnostics.
pub(crate) fn rpc_error(id: &serde_json::Value, error: RpcError) -> Response {
    let mut body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": error.code(), "message": error.message()},
    });
    if error == RpcError::UnsupportedProtocolVersion {
        body["error"]["data"] = serde_json::json!({"supported": [g::PROTOCOL_VERSION]});
    }
    response(
        error.status(),
        serde_json::to_vec(&body).expect("JSON value"),
    )
}
/// JSON-RPC notification: a request object (string `method`) without an `id` member.
pub(crate) fn is_notification(message: &serde_json::Value) -> bool {
    message.as_object().is_some_and(|object| {
        !object.contains_key("id")
            && object
                .get("method")
                .is_some_and(serde_json::Value::is_string)
    })
}
/// A transport-level rejection for a framed request, expressed as a JSON-RPC error.
/// Notifications and unparseable frames are left untouched.
pub(crate) fn frame_rejection(frame: &[u8], response: Response) -> Response {
    if !response.body.is_empty() || (200..300).contains(&response.status) {
        return response;
    }
    match serde_json::from_slice::<serde_json::Value>(frame) {
        Ok(message) if is_notification(&message) => empty(204),
        Ok(message) => {
            let id = match message.get("id") {
                Some(id @ (serde_json::Value::String(_) | serde_json::Value::Number(_))) => {
                    id.clone()
                }
                _ => serde_json::Value::Null,
            };
            rpc_error(&id, RpcError::InvalidRequest)
        }
        Err(_) => rpc_error(&serde_json::Value::Null, RpcError::Parse),
    }
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
    async fn invoke(&self, prepared: Prepared) -> Result<Option<serde_json::Value>, RpcError> {
        let Prepared {
            principal,
            raw,
            message,
            content,
        } = prepared;
        let content = content.unwrap_or_default();
        let scope = Arc::new(());
        // These macros only remove repetitive framing. Every arm still invokes
        // a different statically typed callback with the already-parsed event.
        macro_rules! intercept {
            ($field:ident, $event:expr) => {{
                let handler = self
                    .handlers
                    .intercept
                    .$field
                    .as_ref()
                    .ok_or(RpcError::UnsupportedEvent)?;
                let reply = handler(
                    InterceptContext {
                        principal,
                        verified_content: content,
                        request: raw.clone(),
                        scope: scope.clone(),
                        marker: std::marker::PhantomData,
                    },
                    *$event,
                )
                .await
                .map_err(|_| RpcError::BackendInternal)?;
                if !Arc::ptr_eq(&scope, &reply.scope) {
                    return Err(RpcError::Internal);
                }
                serde_json::to_value(reply.effects).map_err(|_| RpcError::Internal)?
            }};
        }
        match message {
            Message::Capabilities(request) => {
                let handler = self
                    .handlers
                    .discovery
                    .as_ref()
                    .ok_or(RpcError::MethodNotFound)?;
                let reply = handler(
                    DiscoveryContext {
                        principal,
                        verified_content: content,
                        scope: scope.clone(),
                    },
                    request,
                )
                .await
                .map_err(|_| RpcError::BackendInternal)?;
                if !Arc::ptr_eq(&scope, &reply.scope) {
                    return Err(RpcError::Internal);
                }
                Ok(Some(
                    serde_json::json!({"jsonrpc":"2.0", "id":raw["id"], "result":{"protocolVersion":g::PROTOCOL_VERSION, "manifest":reply.manifest}}),
                ))
            }
            Message::Intercept(request) => {
                use g::Event as E;
                let effects = match *request.params.event {
                    E::ToolBefore(e) => intercept!(tool_before, e),
                    E::ToolAfter(e) => intercept!(tool_after, e),
                    E::SessionStart(e) => intercept!(session_start, e),
                    E::ConfigChangeBefore(e) => intercept!(config_change_before, e),
                    E::TurnStart(e) => intercept!(turn_start, e),
                    E::TurnFinishBefore(e) => intercept!(turn_finish_before, e),
                    E::ModelRequestBefore(e) => intercept!(model_request_before, e),
                    E::ModelResponseAfter(e) => intercept!(model_response_after, e),
                    E::ModelSwitchBefore(e) => intercept!(model_switch_before, e),
                    E::ToolPermissionRequest(e) => intercept!(tool_permission_request, e),
                    E::ToolBatchAfter(e) => intercept!(tool_batch_after, e),
                    E::ContextCompactBefore(e) => intercept!(context_compact_before, e),
                    E::ContextCompactAfter(e) => intercept!(context_compact_after, e),
                    E::TaskChangeBefore(e) => intercept!(task_change_before, e),
                    E::UserElicitationRequest(e) => intercept!(user_elicitation_request, e),
                    E::UserElicitationResult(e) => intercept!(user_elicitation_result, e),
                    E::UserMessageInbound(e) => intercept!(user_message_inbound, e),
                    E::UserMessageOutbound(e) => intercept!(user_message_outbound, e),
                    E::WorkspaceChangeBefore(e) => intercept!(workspace_change_before, e),
                    _ => return Err(RpcError::UnsupportedEvent),
                };
                Ok(Some(
                    serde_json::json!({"jsonrpc":"2.0", "id":raw["id"], "result":{"protocolVersion":g::PROTOCOL_VERSION, "effects":effects}}),
                ))
            }
            Message::Observe(notification) => {
                self.observe(principal, content, raw, notification)
                    .await
                    .map_err(|_| RpcError::BackendInternal)?;
                Ok(None)
            }
        }
    }
    /// Per-event observers take precedence; `any` sees every other validated
    /// notification. With neither, observation is a silent no-op.
    async fn observe(
        &self,
        principal: Principal,
        content: ResolvedContent,
        raw: Arc<serde_json::Value>,
        notification: g::ObserveNotification,
    ) -> Result<(), String> {
        macro_rules! observe {
            ($($variant:ident => $field:ident),+ $(,)?) => {
                match &*notification.params.event {
                    $(g::Event::$variant(_) if self.handlers.observe.$field.is_some() => {
                        let g::Event::$variant(event) = *notification.params.event else {
                            unreachable!("matched variant")
                        };
                        let handler = self.handlers.observe.$field.as_ref().expect("checked");
                        handler(
                            ObserveContext {
                                principal,
                                verified_content: content,
                                request: raw,
                                marker: std::marker::PhantomData,
                            },
                            *event,
                        )
                        .await
                    })+
                    _ => match &self.handlers.observe.any {
                        Some(any) => {
                            any(
                                ObserveContext {
                                    principal,
                                    verified_content: content,
                                    request: raw,
                                    marker: std::marker::PhantomData,
                                },
                                notification,
                            )
                            .await
                        }
                        None => Ok(()),
                    },
                }
            };
        }
        observe!(
            ToolBefore => tool_before,
            ToolAfter => tool_after,
            SessionStart => session_start,
            SessionEnd => session_end,
            ConfigChangeBefore => config_change_before,
            ConfigChangeAfter => config_change_after,
            TurnStart => turn_start,
            TurnFinishBefore => turn_finish_before,
            TurnEnd => turn_end,
            TurnProgress => turn_progress,
            ModelRequestBefore => model_request_before,
            ModelResponseAfter => model_response_after,
            ModelError => model_error,
            ModelSwitchBefore => model_switch_before,
            ModelSwitchAfter => model_switch_after,
            ToolPermissionRequest => tool_permission_request,
            ToolPermissionResolved => tool_permission_resolved,
            ToolProgress => tool_progress,
            ToolBatchAfter => tool_batch_after,
            ContextCompactBefore => context_compact_before,
            ContextCompactAfter => context_compact_after,
            TaskChangeBefore => task_change_before,
            TaskChangeAfter => task_change_after,
            UserAttention => user_attention,
            UserElicitationRequest => user_elicitation_request,
            UserElicitationResult => user_elicitation_result,
            UserMessageInbound => user_message_inbound,
            UserMessageOutbound => user_message_outbound,
            WorkspaceChangeBefore => workspace_change_before,
            WorkspaceChangeAfter => workspace_change_after,
            FileChanged => file_changed,
            HookFailure => hook_failure,
        )
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
    ) -> Result<Prepared, Rejection> {
        if request.method != "POST" {
            return Err(Rejection::Transport(405));
        }
        if request.body.len() > self.max_body_bytes {
            return Err(Rejection::Transport(413));
        }
        let authorization =
            header(&request, "authorization").map_err(|_| Rejection::Transport(401))?;
        let principal = self
            .authenticator
            .authenticate(authorization)
            .map_err(|_| Rejection::Transport(401))?;
        if !matches!(header(&request, "content-type"), Ok(Some(v)) if v.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(Rejection::Transport(415));
        }
        let raw: serde_json::Value = serde_json::from_slice(&request.body)
            .map_err(|_| Rejection::Request(serde_json::Value::Null, RpcError::Parse))?;
        // Classify notification-ness first: every later failure for a
        // notification is silent, whatever its cause.
        let notification = is_notification(&raw);
        let id = match raw.get("id") {
            None | Some(serde_json::Value::Null) => serde_json::Value::Null,
            Some(id @ (serde_json::Value::String(_) | serde_json::Value::Number(_))) => id.clone(),
            Some(_) => {
                return Err(Rejection::Request(
                    serde_json::Value::Null,
                    RpcError::InvalidRequest,
                ));
            }
        };
        let reject = |error: RpcError| {
            if notification {
                Rejection::Notification
            } else {
                Rejection::Request(id.clone(), error)
            }
        };
        if !raw.is_object() || raw["jsonrpc"] != "2.0" || !raw["method"].is_string() {
            return Err(reject(RpcError::InvalidRequest));
        }
        let method = raw["method"].as_str().unwrap_or("");
        let schema = match method {
            "hooks/intercept" => "intercept-request",
            "hooks/observe" => "observe-notification",
            "hooks/capabilities" => "capabilities-request",
            _ => return Err(reject(RpcError::MethodNotFound)),
        };
        if let Some(version) = raw["params"]["protocolVersion"].as_str()
            && version != g::PROTOCOL_VERSION
        {
            return Err(reject(RpcError::UnsupportedProtocolVersion));
        }
        if method == "hooks/intercept"
            && let Some(event_type) = raw["params"]["event"]["type"].as_str()
            && !INTERCEPT_EVENTS.contains(&event_type)
        {
            return Err(reject(RpcError::UnsupportedEvent));
        }
        if crate::canonical::validate(schema, &raw).is_err() {
            return Err(reject(RpcError::InvalidParams));
        }
        if method == "hooks/intercept" && raw["id"] != raw["params"]["event"]["id"] {
            return Err(reject(RpcError::InvalidParams));
        }
        // The codec hands the validated document back, so nothing is cloned.
        let (message, raw) = match schema {
            "intercept-request" => parsed(g::parse_intercept_request_value(raw))
                .map(|(value, raw)| (Message::Intercept(Box::new(value)), raw)),
            "observe-notification" => parsed(g::parse_observe_notification_value(raw))
                .map(|(value, raw)| (Message::Observe(value), raw)),
            _ => parsed(g::parse_capabilities_request_value(raw))
                .map(|(value, raw)| (Message::Capabilities(value), raw)),
        }
        .ok_or_else(|| reject(RpcError::InvalidParams))?;

        let content = if let Some(store) = store {
            let context = ContentContext {
                store,
                scope: AuthorizedScope::new(principal.subject.clone()),
            };
            Some(
                resolve_event_content(&raw, &context)
                    .map_err(|_| reject(RpcError::ContentUnavailable))?,
            )
        } else {
            None
        };
        Ok(Prepared {
            principal,
            raw: Arc::new(raw),
            message,
            content,
        })
    }
    async fn dispatch(&self, prepared: Result<Prepared, Rejection>) -> Response {
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(Rejection::Transport(status)) => return empty(status),
            Err(Rejection::Notification) => return empty(204),
            Err(Rejection::Request(id, error)) => return rpc_error(&id, error),
        };
        let raw = prepared.raw.clone();
        let notification = matches!(prepared.message, Message::Observe(_));
        let intercept = matches!(prepared.message, Message::Intercept(_));
        let value = match self.invoke(prepared).await {
            Ok(Some(value)) if !notification => value,
            Ok(_) if notification => return empty(204),
            // An observer failure is a bodyless transport signal, never a JSON-RPC reply.
            Err(_) if notification => return empty(500),
            Ok(_) => return rpc_error(&raw["id"], RpcError::Internal),
            Err(error) => return rpc_error(&raw["id"], error),
        };
        if value["id"] != raw["id"] {
            return rpc_error(&raw["id"], RpcError::Internal);
        }
        if intercept {
            let Ok(typed) = contextual_response(&raw, &value) else {
                return rpc_error(&raw["id"], RpcError::Internal);
            };
            if validate_typed_effect_capabilities(&raw, &typed).is_err() {
                // The callback returned effects the harness did not grant.
                return rpc_error(&raw["id"], RpcError::BackendInternal);
            }
        } else if crate::canonical::validate("capabilities-response", &value).is_err()
            || !g::parse_capabilities_response_value(value.clone()).is_ok()
        {
            return rpc_error(&raw["id"], RpcError::Internal);
        }
        response(200, serde_json::to_vec(&value).expect("JSON value"))
    }
}

/// Parse contextually and retain canonical checks without inspecting unknown effects.
pub(crate) fn contextual_response(
    request: &serde_json::Value,
    response: &serde_json::Value,
) -> Result<g::ContextualResponse, String> {
    // This is an external originating envelope, not typed declaration transfer.
    let event_type: g::EventType =
        serde_json::from_value(request["params"]["event"]["type"].clone())
            .map_err(|cause| format!("invalid originating event type: {cause}"))?;
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
    validate_typed_effect_capabilities(request, &contextual_response(request, response)?)
}
/// `validate_effect_capabilities` for a response already parsed by `contextual_response`.
pub(crate) fn validate_typed_effect_capabilities(
    request: &serde_json::Value,
    typed: &g::ContextualResponse,
) -> Result<(), String> {
    use crate::protocol::{Kind, Operation};
    use serde_json::Value;
    fn contains(array: &Value, value: &str) -> bool {
        array
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(value)))
    }
    let caps = &request["params"]["capabilities"];
    let effects = crate::protocol::effects(typed).map_err(|e| e.to_string())?;
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
        let typed = crate::protocol::parse(g::EventType::ToolBefore, &response).unwrap();
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
