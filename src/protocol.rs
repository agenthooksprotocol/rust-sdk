//! Internal typed adapter over generator-owned contextual response contracts.
use crate::{client::HookError, generated as g};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Replace,
    Merge,
}
pub(crate) enum Payload<'a> {
    Messages(&'a g::CanonicalMessages),
    Text,
    Workspace(&'a g::WorkspaceChange),
    Form,
    Opaque(&'a std::collections::BTreeMap<String, Value>),
}
pub(crate) enum Kind<'a> {
    Deny,
    Allow,
    Ask,
    Modify {
        target: &'static str,
        operation: Operation,
        value: Payload<'a>,
    },
    Message(&'a g::MessageEffect),
    Inject(&'a g::InjectEffect),
    ReturnTool(&'a g::ReturnToolEffect),
    ReturnMessages(&'a g::ReturnMessagesEffect),
    ReturnText(&'a g::ReturnTextEffect),
    ReturnForm(&'a g::ReturnElicitResultEffect),
    Stop,
    Continue(&'a g::ContinueFlowEffect),
    Unknown,
}
pub(crate) struct Effect<'a> {
    pub kind: Kind<'a>,
    pub wire: Value,
}
pub(crate) fn failure(error: impl std::fmt::Display) -> HookError {
    HookError::new(error.to_string())
}
pub(crate) fn value(value: &impl Serialize) -> Result<Value, HookError> {
    serde_json::to_value(value).map_err(failure)
}
pub(crate) fn convert<T: Serialize, U: DeserializeOwned>(value: &T) -> Result<U, HookError> {
    serde_json::from_value(self::value(value)?).map_err(failure)
}
pub(crate) fn parse(
    event_type: g::EventType,
    response: &Value,
) -> Result<g::ContextualResponse, HookError> {
    match g::response_for_request(
        event_type,
        &serde_json::to_string(response).map_err(failure)?,
    ) {
        g::ParseResult::Success { value, .. } => Ok(value),
        g::ParseResult::Failure { diagnostics, .. } => Err(failure(format!(
            "invalid contextual response: {diagnostics:?}"
        ))),
    }
}
pub(crate) fn effects(response: &g::ContextualResponse) -> Result<Vec<Effect<'_>>, HookError> {
    let mut result = Vec::new();
    match response {
        g::ContextualResponse::ConfigChangeBefore(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::ConfigChangeBeforeEffect::Deny(_) => Kind::Deny,
                        g::ConfigChangeBeforeEffect::Message(value) => Kind::Message(value),
                        g::ConfigChangeBeforeEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::ContextCompactAfter(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::ContextCompactAfterEffect::InjectAppendContext(value) => {
                            Kind::Inject(value)
                        }
                        g::ContextCompactAfterEffect::ModifySummary(value) => Kind::Modify {
                            target: "summary",
                            operation: match value.operation {
                                g::ContextCompactAfterModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::ContextCompactAfterModifyEffectOperation::Merge(_) => {
                                    Operation::Merge
                                }
                            },
                            value: Payload::Text,
                        },
                        g::ContextCompactAfterEffect::Message(value) => Kind::Message(value),
                        g::ContextCompactAfterEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::ContextCompactBefore(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::ContextCompactBeforeEffect::Deny(_) => Kind::Deny,
                        g::ContextCompactBeforeEffect::ModifyInstructions(value) => Kind::Modify {
                            target: "instructions",
                            operation: match value.operation {
                                g::ContextCompactBeforeModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::ContextCompactBeforeModifyEffectOperation::Merge(_) => {
                                    Operation::Merge
                                }
                            },
                            value: Payload::Text,
                        },
                        g::ContextCompactBeforeEffect::Return(value) => Kind::ReturnText(value),
                        g::ContextCompactBeforeEffect::InjectAppendContext(value) => {
                            Kind::Inject(value)
                        }
                        g::ContextCompactBeforeEffect::Message(value) => Kind::Message(value),
                        g::ContextCompactBeforeEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::ModelRequestBefore(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::ModelRequestBeforeEffect::Deny(_) => Kind::Deny,
                        g::ModelRequestBeforeEffect::ModifyRequest(value) => Kind::Modify {
                            target: "request",
                            operation: match value.operation {
                                g::ModelRequestBeforeModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::ModelRequestBeforeModifyEffectOperation::Merge(_) => {
                                    Operation::Merge
                                }
                            },
                            value: Payload::Messages(&value.value),
                        },
                        g::ModelRequestBeforeEffect::InjectAppendContext(value) => {
                            Kind::Inject(value)
                        }
                        g::ModelRequestBeforeEffect::Return(value) => Kind::ReturnMessages(value),
                        g::ModelRequestBeforeEffect::FlowStop(_) => Kind::Stop,
                        g::ModelRequestBeforeEffect::Message(value) => Kind::Message(value),
                        g::ModelRequestBeforeEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::ModelResponseAfter(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::ModelResponseAfterEffect::ModifyResponse(value) => Kind::Modify {
                            target: "response",
                            operation: match value.operation {
                                g::ModelResponseAfterModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::ModelResponseAfterModifyEffectOperation::Merge(_) => {
                                    Operation::Merge
                                }
                            },
                            value: Payload::Messages(&value.value),
                        },
                        g::ModelResponseAfterEffect::FlowStop(_) => Kind::Stop,
                        g::ModelResponseAfterEffect::Message(value) => Kind::Message(value),
                        g::ModelResponseAfterEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::ModelSwitchBefore(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::ModelSwitchBeforeEffect::Deny(_) => Kind::Deny,
                        g::ModelSwitchBeforeEffect::FlowStop(_) => Kind::Stop,
                        g::ModelSwitchBeforeEffect::Message(value) => Kind::Message(value),
                        g::ModelSwitchBeforeEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::SessionStart(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::SessionStartEffect::InjectAppendContext(value) => Kind::Inject(value),
                        g::SessionStartEffect::Message(value) => Kind::Message(value),
                        g::SessionStartEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::TaskChangeBefore(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::TaskChangeBeforeEffect::Deny(_) => Kind::Deny,
                        g::TaskChangeBeforeEffect::Message(value) => Kind::Message(value),
                        g::TaskChangeBeforeEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::ToolAfter(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::ToolAfterEffect::ModifyOutput(value) => Kind::Modify {
                            target: "output",
                            operation: match value.operation {
                                g::ToolAfterModifyEffectOperation::Replace(_) => Operation::Replace,
                                g::ToolAfterModifyEffectOperation::Merge(_) => Operation::Merge,
                            },
                            value: Payload::Messages(&value.value),
                        },
                        g::ToolAfterEffect::InjectAppendContext(value) => Kind::Inject(value),
                        g::ToolAfterEffect::FlowStop(_) => Kind::Stop,
                        g::ToolAfterEffect::FlowContinue(value) => Kind::Continue(value),
                        g::ToolAfterEffect::Message(value) => Kind::Message(value),
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::ToolBatchAfter(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::ToolBatchAfterEffect::FlowStop(_) => Kind::Stop,
                        g::ToolBatchAfterEffect::InjectAppendContext(value) => Kind::Inject(value),
                        g::ToolBatchAfterEffect::Message(value) => Kind::Message(value),
                        g::ToolBatchAfterEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::ToolBefore(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::ToolBeforeEffect::Deny(_) => Kind::Deny,
                        g::ToolBeforeEffect::Allow(_) => Kind::Allow,
                        g::ToolBeforeEffect::Ask(_) => Kind::Ask,
                        g::ToolBeforeEffect::ModifyInput(value) => Kind::Modify {
                            target: "input",
                            operation: match value.operation {
                                g::ToolBeforeModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::ToolBeforeModifyEffectOperation::Merge(_) => Operation::Merge,
                            },
                            value: Payload::Opaque(&value.value.additional_properties),
                        },
                        g::ToolBeforeEffect::InjectAppendContext(value) => Kind::Inject(value),
                        g::ToolBeforeEffect::FlowStop(_) => Kind::Stop,
                        g::ToolBeforeEffect::Return(value) => Kind::ReturnTool(value),
                        g::ToolBeforeEffect::Message(value) => Kind::Message(value),
                        g::ToolBeforeEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::ToolPermissionRequest(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::ToolPermissionRequestEffect::Allow(_) => Kind::Allow,
                        g::ToolPermissionRequestEffect::Deny(_) => Kind::Deny,
                        g::ToolPermissionRequestEffect::ModifyInput(value) => Kind::Modify {
                            target: "input",
                            operation: match value.operation {
                                g::ToolPermissionRequestModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::ToolPermissionRequestModifyEffectOperation::Merge(_) => {
                                    Operation::Merge
                                }
                            },
                            value: Payload::Opaque(&value.value.additional_properties),
                        },
                        g::ToolPermissionRequestEffect::FlowStop(_) => Kind::Stop,
                        g::ToolPermissionRequestEffect::Message(value) => Kind::Message(value),
                        g::ToolPermissionRequestEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::TurnFinishBefore(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::TurnFinishBeforeEffect::ModifyResponse(value) => Kind::Modify {
                            target: "response",
                            operation: match value.operation {
                                g::TurnFinishBeforeModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::TurnFinishBeforeModifyEffectOperation::Merge(_) => {
                                    Operation::Merge
                                }
                            },
                            value: Payload::Messages(&value.value),
                        },
                        g::TurnFinishBeforeEffect::FlowStop(_) => Kind::Stop,
                        g::TurnFinishBeforeEffect::FlowContinue(value) => Kind::Continue(value),
                        g::TurnFinishBeforeEffect::Message(value) => Kind::Message(value),
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::TurnStart(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::TurnStartEffect::Deny(_) => Kind::Deny,
                        g::TurnStartEffect::ModifyPrompt(value) => Kind::Modify {
                            target: "prompt",
                            operation: match value.operation {
                                g::TurnStartModifyEffectOperation::Replace(_) => Operation::Replace,
                                g::TurnStartModifyEffectOperation::Merge(_) => Operation::Merge,
                            },
                            value: Payload::Messages(&value.value),
                        },
                        g::TurnStartEffect::InjectAppendContext(value) => Kind::Inject(value),
                        g::TurnStartEffect::FlowStop(_) => Kind::Stop,
                        g::TurnStartEffect::Message(value) => Kind::Message(value),
                        g::TurnStartEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::UserElicitationRequest(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::UserElicitationRequestEffect::Deny(_) => Kind::Deny,
                        g::UserElicitationRequestEffect::Return(value) => Kind::ReturnForm(value),
                        g::UserElicitationRequestEffect::Message(value) => Kind::Message(value),
                        g::UserElicitationRequestEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::UserElicitationResult(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::UserElicitationResultEffect::ModifyContent(value) => Kind::Modify {
                            target: "content",
                            operation: match value.operation {
                                g::UserElicitationResultModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::UserElicitationResultModifyEffectOperation::Merge(_) => {
                                    Operation::Merge
                                }
                            },
                            value: Payload::Form,
                        },
                        g::UserElicitationResultEffect::Message(value) => Kind::Message(value),
                        g::UserElicitationResultEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::UserMessageInbound(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::UserMessageInboundEffect::Deny(_) => Kind::Deny,
                        g::UserMessageInboundEffect::ModifyPrompt(value) => Kind::Modify {
                            target: "prompt",
                            operation: match value.operation {
                                g::UserMessageInboundModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::UserMessageInboundModifyEffectOperation::Merge(_) => {
                                    Operation::Merge
                                }
                            },
                            value: Payload::Messages(&value.value),
                        },
                        g::UserMessageInboundEffect::Message(value) => Kind::Message(value),
                        g::UserMessageInboundEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::UserMessageOutbound(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::UserMessageOutboundEffect::Deny(_) => Kind::Deny,
                        g::UserMessageOutboundEffect::ModifyContent(value) => Kind::Modify {
                            target: "content",
                            operation: match value.operation {
                                g::UserMessageOutboundModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::UserMessageOutboundModifyEffectOperation::Merge(_) => {
                                    Operation::Merge
                                }
                            },
                            value: Payload::Messages(&value.value),
                        },
                        g::UserMessageOutboundEffect::Message(value) => Kind::Message(value),
                        g::UserMessageOutboundEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
        g::ContextualResponse::WorkspaceChangeBefore(response) => {
            if let g::Presence::Present(effects) = &response.result.effects {
                for effect in effects {
                    let kind = match effect.as_ref() {
                        g::WorkspaceChangeBeforeEffect::Deny(_) => Kind::Deny,
                        g::WorkspaceChangeBeforeEffect::ModifyWorkspace(value) => Kind::Modify {
                            target: "workspace",
                            operation: match value.operation {
                                g::WorkspaceChangeBeforeModifyEffectOperation::Replace(_) => {
                                    Operation::Replace
                                }
                                g::WorkspaceChangeBeforeModifyEffectOperation::Merge(_) => {
                                    Operation::Merge
                                }
                            },
                            value: Payload::Workspace(&value.value),
                        },
                        g::WorkspaceChangeBeforeEffect::Message(value) => Kind::Message(value),
                        g::WorkspaceChangeBeforeEffect::Unknown(_) => Kind::Unknown,
                    };
                    result.push(Effect {
                        kind,
                        wire: value(effect)?,
                    });
                }
            }
        }
    }
    Ok(result)
}
pub(crate) fn visit_messages_mut(
    response: &mut g::ContextualResponse,
    mut visit: impl FnMut(&mut g::CanonicalMessages) -> Result<(), HookError>,
) -> Result<(), HookError> {
    match response {
        g::ContextualResponse::ContextCompactAfter(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    if let g::ContextCompactAfterEffect::InjectAppendContext(value) =
                        effect.as_mut()
                    {
                        visit(&mut value.value)?;
                    }
                }
            }
        }
        g::ContextualResponse::ContextCompactBefore(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    if let g::ContextCompactBeforeEffect::InjectAppendContext(value) =
                        effect.as_mut()
                    {
                        visit(&mut value.value)?;
                    }
                }
            }
        }
        g::ContextualResponse::ModelRequestBefore(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    match effect.as_mut() {
                        g::ModelRequestBeforeEffect::ModifyRequest(value) => {
                            visit(&mut value.value)?
                        }
                        g::ModelRequestBeforeEffect::InjectAppendContext(value) => {
                            visit(&mut value.value)?
                        }
                        g::ModelRequestBeforeEffect::Return(value) => visit(&mut value.value)?,
                        _ => {}
                    }
                }
            }
        }
        g::ContextualResponse::ModelResponseAfter(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    if let g::ModelResponseAfterEffect::ModifyResponse(value) = effect.as_mut() {
                        visit(&mut value.value)?;
                    }
                }
            }
        }
        g::ContextualResponse::SessionStart(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    if let g::SessionStartEffect::InjectAppendContext(value) = effect.as_mut() {
                        visit(&mut value.value)?;
                    }
                }
            }
        }
        g::ContextualResponse::ToolAfter(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    match effect.as_mut() {
                        g::ToolAfterEffect::ModifyOutput(value) => visit(&mut value.value)?,
                        g::ToolAfterEffect::InjectAppendContext(value) => visit(&mut value.value)?,
                        _ => {}
                    }
                }
            }
        }
        g::ContextualResponse::ToolBatchAfter(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    if let g::ToolBatchAfterEffect::InjectAppendContext(value) = effect.as_mut() {
                        visit(&mut value.value)?;
                    }
                }
            }
        }
        g::ContextualResponse::ToolBefore(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    if let g::ToolBeforeEffect::InjectAppendContext(value) = effect.as_mut() {
                        visit(&mut value.value)?;
                    }
                }
            }
        }
        g::ContextualResponse::TurnFinishBefore(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    if let g::TurnFinishBeforeEffect::ModifyResponse(value) = effect.as_mut() {
                        visit(&mut value.value)?;
                    }
                }
            }
        }
        g::ContextualResponse::TurnStart(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    match effect.as_mut() {
                        g::TurnStartEffect::ModifyPrompt(value) => visit(&mut value.value)?,
                        g::TurnStartEffect::InjectAppendContext(value) => visit(&mut value.value)?,
                        _ => {}
                    }
                }
            }
        }
        g::ContextualResponse::UserMessageInbound(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    if let g::UserMessageInboundEffect::ModifyPrompt(value) = effect.as_mut() {
                        visit(&mut value.value)?;
                    }
                }
            }
        }
        g::ContextualResponse::UserMessageOutbound(response) => {
            if let g::Presence::Present(effects) = &mut response.result.effects {
                for effect in effects {
                    if let g::UserMessageOutboundEffect::ModifyContent(value) = effect.as_mut() {
                        visit(&mut value.value)?;
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}
pub(crate) fn response_value(response: &g::ContextualResponse) -> Result<Value, HookError> {
    match response {
        g::ContextualResponse::ConfigChangeBefore(response) => value(response),
        g::ContextualResponse::ContextCompactAfter(response) => value(response),
        g::ContextualResponse::ContextCompactBefore(response) => value(response),
        g::ContextualResponse::ModelRequestBefore(response) => value(response),
        g::ContextualResponse::ModelResponseAfter(response) => value(response),
        g::ContextualResponse::ModelSwitchBefore(response) => value(response),
        g::ContextualResponse::SessionStart(response) => value(response),
        g::ContextualResponse::TaskChangeBefore(response) => value(response),
        g::ContextualResponse::ToolAfter(response) => value(response),
        g::ContextualResponse::ToolBatchAfter(response) => value(response),
        g::ContextualResponse::ToolBefore(response) => value(response),
        g::ContextualResponse::ToolPermissionRequest(response) => value(response),
        g::ContextualResponse::TurnFinishBefore(response) => value(response),
        g::ContextualResponse::TurnStart(response) => value(response),
        g::ContextualResponse::UserElicitationRequest(response) => value(response),
        g::ContextualResponse::UserElicitationResult(response) => value(response),
        g::ContextualResponse::UserMessageInbound(response) => value(response),
        g::ContextualResponse::UserMessageOutbound(response) => value(response),
        g::ContextualResponse::WorkspaceChangeBefore(response) => value(response),
    }
}

pub(crate) fn apply(
    event: &mut g::Event,
    target: &str,
    operation: Operation,
    payload: &Payload<'_>,
) -> Result<(), HookError> {
    fn list<T>(current: &mut Vec<T>, next: Vec<T>, operation: Operation) {
        if operation == Operation::Merge {
            current.extend(next);
        } else {
            *current = next;
        }
    }
    match (event, payload) {
        (g::Event::ToolBefore(event), Payload::Opaque(value)) => {
            if operation == Operation::Replace {
                event.tool.input.additional_properties = (*value).clone();
            } else {
                event
                    .tool
                    .input
                    .additional_properties
                    .extend((*value).clone());
            }
        }
        (g::Event::ToolPermissionRequest(event), Payload::Opaque(value)) => {
            if operation == Operation::Replace {
                event.0.tool.input.additional_properties = (*value).clone();
            } else {
                event
                    .0
                    .tool
                    .input
                    .additional_properties
                    .extend((*value).clone());
            }
        }
        (g::Event::WorkspaceChangeBefore(event), Payload::Workspace(value)) => {
            let current = &mut event.0.workspace.change;
            if operation == Operation::Replace {
                **current = (*value).clone();
            } else {
                if !value.cwd.is_missing() {
                    current.cwd = value.cwd.clone();
                }
                if !value.workspace_roots.is_missing() {
                    current.workspace_roots = value.workspace_roots.clone();
                }
                current
                    .additional_properties
                    .extend(value.additional_properties.clone());
            }
        }
        (g::Event::ModelRequestBefore(event), Payload::Messages(value)) => list(
            &mut event.0.items,
            value
                .0
                .iter()
                .cloned()
                .map(|value| Box::new(g::ModelVisibleItem(value)))
                .collect(),
            operation,
        ),
        (g::Event::ModelResponseAfter(event), Payload::Messages(value)) => list(
            &mut event.0.items,
            value
                .0
                .iter()
                .cloned()
                .map(|value| Box::new(g::ModelVisibleItem(value)))
                .collect(),
            operation,
        ),
        (g::Event::TurnStart(event), Payload::Messages(value)) => list(
            &mut event.0.items,
            value
                .0
                .iter()
                .cloned()
                .map(|value| Box::new(g::ModelVisibleItem(value)))
                .collect(),
            operation,
        ),
        (g::Event::TurnFinishBefore(event), Payload::Messages(value)) => list(
            &mut event.0.items,
            value
                .0
                .iter()
                .cloned()
                .map(|value| Box::new(g::ModelVisibleItem(value)))
                .collect(),
            operation,
        ),
        (g::Event::ToolAfter(event), Payload::Messages(value)) => list(
            &mut event.items,
            value
                .0
                .iter()
                .cloned()
                .map(|value| Box::new(g::ModelVisibleItem(value)))
                .collect(),
            operation,
        ),
        (g::Event::UserMessageInbound(event), Payload::Messages(value)) => {
            list(&mut event.message.messages, convert(&value.0)?, operation)
        }
        (g::Event::UserMessageOutbound(event), Payload::Messages(value)) => {
            list(&mut event.message.messages, convert(&value.0)?, operation)
        }
        _ => {
            return Err(failure(format!(
                "unsupported contextual modification {target}"
            )));
        }
    }
    Ok(())
}
pub(crate) fn returned(kind: &Kind<'_>) -> Result<Option<Value>, HookError> {
    match kind {
        Kind::ReturnTool(effect) => Ok(Some(effect.value.clone())),
        Kind::ReturnMessages(effect) => Ok(Some(value(&effect.value)?)),
        Kind::ReturnText(effect) => Ok(Some(value(&effect.value)?)),
        Kind::ReturnForm(effect) => Ok(Some(value(&effect.value)?)),
        _ => Ok(None),
    }
}
pub(crate) fn parts(event: &g::Event) -> Vec<&g::ContentItem> {
    let mut parts = Vec::new();
    match event {
        g::Event::ToolBefore(event) => {
            if let g::Presence::Present(items) = &event.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ToolAfter(event) => {
            let items = &event.items;
            for item in items {
                for part in &item.0.parts {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::SessionStart(event) => {
            let items = &event.items;
            for item in items {
                for part in &item.0.parts {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::SessionEnd(event) => {
            if let g::Presence::Present(items) = &event.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ConfigChangeBefore(event) => {
            if let g::Presence::Present(items) = &event.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ConfigChangeAfter(event) => {
            if let g::Presence::Present(items) = &event.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::TurnStart(event) => {
            let items = &event.0.items;
            for item in items {
                for part in &item.0.parts {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::TurnFinishBefore(event) => {
            let items = &event.0.items;
            for item in items {
                for part in &item.0.parts {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::TurnEnd(event) => {
            let items = &event.0.items;
            for item in items {
                for part in &item.0.parts {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::TurnProgress(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ModelRequestBefore(event) => {
            let items = &event.0.items;
            for item in items {
                for part in &item.0.parts {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ModelResponseAfter(event) => {
            let items = &event.0.items;
            for item in items {
                for part in &item.0.parts {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ModelError(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ModelSwitchBefore(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ModelSwitchAfter(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ToolPermissionRequest(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ToolPermissionResolved(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ToolProgress(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ToolBatchAfter(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ContextCompactBefore(event) => {
            let items = &event.0.items;
            for item in items {
                for part in &item.0.parts {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::ContextCompactAfter(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for item in items {
                    for part in &item.0.parts {
                        parts.push(part.as_ref());
                    }
                }
            }
        }
        g::Event::TaskChangeBefore(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::TaskChangeAfter(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::UserAttention(event) => {
            if let g::Presence::Present(items) = &event.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::UserElicitationRequest(event) => {
            if let g::Presence::Present(items) = &event.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::UserElicitationResult(event) => {
            if let g::Presence::Present(items) = &event.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::UserMessageInbound(event) => {
            if let g::Presence::Present(items) = &event.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
            for message in &event.message.messages {
                for part in &message.parts {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::UserMessageOutbound(event) => {
            if let g::Presence::Present(items) = &event.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
            for message in &event.message.messages {
                for part in &message.parts {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::WorkspaceChangeBefore(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::WorkspaceChangeAfter(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::FileChanged(event) => {
            if let g::Presence::Present(items) = &event.0.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        g::Event::HookFailure(event) => {
            if let g::Presence::Present(items) = &event.items {
                for part in items {
                    parts.push(part.as_ref());
                }
            }
        }
        _ => {}
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_and_empty_effects_use_the_same_empty_typed_batch_without_wire_mutation() {
        for result in [
            serde_json::json!({"protocolVersion":"draft"}),
            serde_json::json!({"protocolVersion":"draft","effects":[]}),
        ] {
            let wire = serde_json::json!({"jsonrpc":"2.0","id":"neutral","result":result});
            let original = wire.clone();
            crate::canonical::validate("intercept-response", &wire).unwrap();
            let typed = parse(g::EventType::ToolBefore, &wire).unwrap();
            assert!(effects(&typed).unwrap().is_empty());
            assert_eq!(response_value(&typed).unwrap(), wire);
            assert_eq!(wire, original);
        }
        let null = serde_json::json!({"jsonrpc":"2.0","id":"neutral","result":{"protocolVersion":"draft","effects":null}});
        assert!(parse(g::EventType::ToolBefore, &null).is_err());
        assert!(crate::canonical::validate("intercept-response", &null).is_err());
    }
}
