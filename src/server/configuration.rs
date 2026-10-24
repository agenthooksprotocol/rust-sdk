//! Additive builders and authenticated configuration callbacks.
use super::*;

/// Authenticated discovery invocation. Dropping its dispatch future cancels the
/// callback future; callbacks must keep work owned by that future.
pub struct ConfigurationContext {
    pub principal: Principal,
    pub verified_content: ResolvedContent,
    pub(super) scope: Arc<()>,
}
impl ConfigurationContext {
    /// Return an owned declaration scoped to this invocation. The dispatcher
    /// validates it and supplies correlation and protocol-version fields.
    pub fn reply(&self, configuration: crate::Configuration) -> ConfigurationReply {
        ConfigurationReply {
            scope: self.scope.clone(),
            configuration,
        }
    }
}
/// A non-null configuration reply belonging to one authenticated invocation.
///
/// ```compile_fail
/// use agenthooksprotocol::server::{HandlerSet, ConfigurationContext, ConfigurationReply, callback};
/// let handlers = HandlerSet::new().configuration(callback(|_: ConfigurationContext, _| async {
///     Ok(None::<ConfigurationReply>) // A missing result is not configuration.
/// }));
/// ```
pub struct ConfigurationReply {
    pub(super) scope: Arc<()>,
    pub(super) configuration: crate::Configuration,
}
/// Build with [`callback`] or [`with_state`], just like event handlers.
pub type ConfigurationFunc =
    Callback<ConfigurationContext, crate::ConfigurationRequest, ConfigurationReply>;

/// A static declaration or an authenticated, per-request callback.
pub trait ConfigurationSource: Send + Sync + 'static {
    fn resolve(
        &self,
        context: ConfigurationContext,
        request: crate::ConfigurationRequest,
    ) -> ServerFuture<ConfigurationReply>;
}
impl ConfigurationSource for crate::Configuration {
    fn resolve(
        &self,
        context: ConfigurationContext,
        _: crate::ConfigurationRequest,
    ) -> ServerFuture<ConfigurationReply> {
        let snapshot = self.clone();
        Box::pin(async move { Ok(context.reply(snapshot)) })
    }
}
impl ConfigurationSource for ConfigurationFunc {
    fn resolve(
        &self,
        context: ConfigurationContext,
        request: crate::ConfigurationRequest,
    ) -> ServerFuture<ConfigurationReply> {
        self(context, request)
    }
}

/// Builder result retaining existing event handlers and an erased, typed
/// configuration source. Existing [`HandlerSet`] literals remain unchanged.
pub struct ConfiguredHandlerSet {
    handlers: HandlerSet,
    configuration: Option<Arc<dyn ConfigurationSource>>,
}
impl From<HandlerSet> for ConfiguredHandlerSet {
    fn from(handlers: HandlerSet) -> Self {
        Self {
            handlers,
            configuration: None,
        }
    }
}
impl HandlerSet {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn configuration(self, source: impl ConfigurationSource) -> ConfiguredHandlerSet {
        ConfiguredHandlerSet::from(self).configuration(source)
    }
    pub fn intercept(mut self, handlers: InterceptHandlers) -> Self {
        self.intercept = handlers;
        self
    }
    pub fn observe(mut self, handlers: ObserveHandlers) -> Self {
        self.observe = handlers;
        self
    }
}
impl ConfiguredHandlerSet {
    pub fn configuration(mut self, source: impl ConfigurationSource) -> Self {
        self.handlers.configuration = None;
        self.configuration = Some(Arc::new(source));
        self
    }
    pub fn intercept(mut self, handlers: InterceptHandlers) -> Self {
        self.handlers.intercept = handlers;
        self
    }
    pub fn observe(mut self, handlers: ObserveHandlers) -> Self {
        self.handlers.observe = handlers;
        self
    }
    pub fn build<A: Authenticator>(
        self,
        authenticator: A,
        max_body_bytes: usize,
    ) -> ConfiguredServer<A> {
        ConfiguredServer::new(self, authenticator, max_body_bytes)
    }
}
impl<A: Authenticator> Server<A> {
    /// Construct the existing concrete server without a struct literal.
    pub fn new(handlers: HandlerSet, authenticator: A, max_body_bytes: usize) -> Self {
        Self {
            handlers,
            authenticator,
            max_body_bytes,
        }
    }
}
/// Server constructed from static or dynamic configuration builders. Uses the
/// same authenticated dispatcher as [`Server`], without changing its type.
pub struct ConfiguredServer<A> {
    inner: Server<A>,
    configuration: Option<Arc<dyn ConfigurationSource>>,
}
impl<A: Authenticator> ConfiguredServer<A> {
    pub fn new(
        handlers: impl Into<ConfiguredHandlerSet>,
        authenticator: A,
        max_body_bytes: usize,
    ) -> Self {
        let handlers = handlers.into();
        Self {
            inner: Server::new(handlers.handlers, authenticator, max_body_bytes),
            configuration: handlers.configuration,
        }
    }
    pub async fn handle(&self, request: Request) -> Response {
        self.inner
            .dispatch(
                self.inner.prepare(request, None),
                self.configuration.as_deref(),
            )
            .await
    }
    pub fn handle_with_content<'a>(
        &'a self,
        request: Request,
        store: &dyn ContentStore,
    ) -> impl Future<Output = Response> + Send + 'a + use<'a, A> {
        self.inner.dispatch(
            self.inner.prepare(request, Some(store)),
            self.configuration.as_deref(),
        )
    }
}

/// Shared adapter interface preserving existing `Server<A>` entry points.
pub trait RequestHandler<A: Authenticator>: Send + Sync {
    fn max_body_bytes(&self) -> usize;
    fn handle(&self, request: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>>;
}
impl<A: Authenticator> RequestHandler<A> for Server<A> {
    fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }
    fn handle(&self, request: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(Server::handle(self, request))
    }
}
impl<A: Authenticator> RequestHandler<A> for ConfiguredServer<A> {
    fn max_body_bytes(&self) -> usize {
        self.inner.max_body_bytes
    }
    fn handle(&self, request: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(ConfiguredServer::handle(self, request))
    }
}

// Preserve adapter deref coercions for Arc, Box, references, and host wrappers.
impl<A, T> RequestHandler<A> for T
where
    A: Authenticator,
    T: std::ops::Deref + Send + Sync,
    T::Target: RequestHandler<A>,
{
    fn max_body_bytes(&self) -> usize {
        self.deref().max_body_bytes()
    }
    fn handle(&self, request: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        self.deref().handle(request)
    }
}

macro_rules! handler_builders {
    ($kind:ident { $($field:ident: $callback:ty),* $(,)? }) => {
        impl $kind {
            pub fn new() -> Self { Self::default() }
            $(pub fn $field(mut self, handler: $callback) -> Self {
                self.$field = Some(handler);
                self
            })*
        }
    };
}

handler_builders!(InterceptHandlers {
    tool_before: Callback<ToolBeforeContext, g::ToolBeforeEvent, ToolBeforeReply>,
    tool_after: Callback<ToolAfterContext, g::ToolAfterEvent, ToolAfterReply>,
    session_start: Callback<SessionStartContext, g::SessionStartEvent, SessionStartReply>,
    config_change_before: Callback<ConfigChangeBeforeContext, g::ConfigChangeBeforeEvent, ConfigChangeBeforeReply>,
    turn_start: Callback<TurnStartContext, g::TurnStartEvent, TurnStartReply>,
    turn_finish_before: Callback<TurnFinishBeforeContext, g::TurnFinishBeforeEvent, TurnFinishBeforeReply>,
    model_request_before: Callback<ModelRequestBeforeContext, g::ModelRequestBeforeEvent, ModelRequestBeforeReply>,
    model_response_after: Callback<ModelResponseAfterContext, g::ModelResponseAfterEvent, ModelResponseAfterReply>,
    model_switch_before: Callback<ModelSwitchBeforeContext, g::ModelSwitchBeforeEvent, ModelSwitchBeforeReply>,
    tool_permission_request: Callback< ToolPermissionRequestContext, g::ToolPermissionRequestEvent, ToolPermissionRequestReply, >,
    tool_batch_after: Callback<ToolBatchAfterContext, g::ToolBatchAfterEvent, ToolBatchAfterReply>,
    context_compact_before: Callback< ContextCompactBeforeContext, g::ContextCompactBeforeEvent, ContextCompactBeforeReply, >,
    context_compact_after: Callback<ContextCompactAfterContext, g::ContextCompactAfterEvent, ContextCompactAfterReply>,
    task_change_before: Callback<TaskChangeBeforeContext, g::TaskChangeBeforeEvent, TaskChangeBeforeReply>,
    user_elicitation_request: Callback< UserElicitationRequestContext, g::UserElicitationRequestEvent, UserElicitationRequestReply, >,
    user_elicitation_result: Callback< UserElicitationResultContext, g::UserElicitationResultEvent, UserElicitationResultReply, >,
    user_message_inbound: Callback<UserMessageInboundContext, g::UserMessageInboundEvent, UserMessageInboundReply>,
    user_message_outbound: Callback<UserMessageOutboundContext, g::UserMessageOutboundEvent, UserMessageOutboundReply>,
    workspace_change_before: Callback< WorkspaceChangeBeforeContext, g::WorkspaceChangeBeforeEvent, WorkspaceChangeBeforeReply, >,
});

handler_builders!(ObserveHandlers {
    tool_before: Callback<ToolBeforeObserveContext, g::ToolBeforeEvent, ()>,
    tool_after: Callback<ToolAfterObserveContext, g::ToolAfterEvent, ()>,
    session_start: Callback<SessionStartObserveContext, g::SessionStartEvent, ()>,
    session_end: Callback<SessionEndObserveContext, g::SessionEndEvent, ()>,
    config_change_before: Callback<ConfigChangeBeforeObserveContext, g::ConfigChangeBeforeEvent, ()>,
    config_change_after: Callback<ConfigChangeAfterObserveContext, g::ConfigChangeAfterEvent, ()>,
    turn_start: Callback<TurnStartObserveContext, g::TurnStartEvent, ()>,
    turn_finish_before: Callback<TurnFinishBeforeObserveContext, g::TurnFinishBeforeEvent, ()>,
    turn_end: Callback<TurnEndObserveContext, g::TurnEndEvent, ()>,
    turn_progress: Callback<TurnProgressObserveContext, g::TurnProgressEvent, ()>,
    model_request_before: Callback<ModelRequestBeforeObserveContext, g::ModelRequestBeforeEvent, ()>,
    model_response_after: Callback<ModelResponseAfterObserveContext, g::ModelResponseAfterEvent, ()>,
    model_error: Callback<ModelErrorObserveContext, g::ModelErrorEvent, ()>,
    model_switch_before: Callback<ModelSwitchBeforeObserveContext, g::ModelSwitchBeforeEvent, ()>,
    model_switch_after: Callback<ModelSwitchAfterObserveContext, g::ModelSwitchAfterEvent, ()>,
    tool_permission_request: Callback<ToolPermissionRequestObserveContext, g::ToolPermissionRequestEvent, ()>,
    tool_permission_resolved: Callback<ToolPermissionResolvedObserveContext, g::ToolPermissionResolvedEvent, ()>,
    tool_progress: Callback<ToolProgressObserveContext, g::ToolProgressEvent, ()>,
    tool_batch_after: Callback<ToolBatchAfterObserveContext, g::ToolBatchAfterEvent, ()>,
    context_compact_before: Callback<ContextCompactBeforeObserveContext, g::ContextCompactBeforeEvent, ()>,
    context_compact_after: Callback<ContextCompactAfterObserveContext, g::ContextCompactAfterEvent, ()>,
    task_change_before: Callback<TaskChangeBeforeObserveContext, g::TaskChangeBeforeEvent, ()>,
    task_change_after: Callback<TaskChangeAfterObserveContext, g::TaskChangeAfterEvent, ()>,
    user_attention: Callback<UserAttentionObserveContext, g::UserAttentionEvent, ()>,
    user_elicitation_request: Callback<UserElicitationRequestObserveContext, g::UserElicitationRequestEvent, ()>,
    user_elicitation_result: Callback<UserElicitationResultObserveContext, g::UserElicitationResultEvent, ()>,
    user_message_inbound: Callback<UserMessageInboundObserveContext, g::UserMessageInboundEvent, ()>,
    user_message_outbound: Callback<UserMessageOutboundObserveContext, g::UserMessageOutboundEvent, ()>,
    workspace_change_before: Callback<WorkspaceChangeBeforeObserveContext, g::WorkspaceChangeBeforeEvent, ()>,
    workspace_change_after: Callback<WorkspaceChangeAfterObserveContext, g::WorkspaceChangeAfterEvent, ()>,
    file_changed: Callback<FileChangedObserveContext, g::FileChangedEvent, ()>,
    hook_failure: Callback<HookFailureObserveContext, g::HookFailureEvent, ()>,
    any: Callback<AnyObserveContext, g::ObserveNotification, ()>,
});
