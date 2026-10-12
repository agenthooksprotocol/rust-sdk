# Migrating

## 0.4 → 0.5

0.5 removes the draft compatibility surfaces. Servers register one typed callback
per event, host authority is declared with event-specific typed builders, event
identifiers are the generated `EventType`, and settlements expose one canonical
event instead of parallel raw and typed views.

### Quick reference

| Removed in 0.5 | Replacement |
| --- | --- |
| `server::Handler`, `server::HandlerFuture` | `server::HandlerSet` with `intercept`, `observe`, and `discovery` slots; callbacks return `server::ServerFuture` |
| `server::Incoming` | The event-specific slot that receives the request, such as `handlers.intercept.tool_before` |
| `server::Outgoing` | `ctx.reply()` / `ctx.reply().effect(..)` for interception, `Ok(())` for observation, `ctx.reply(manifest)` for discovery |
| `Handler::handle_verified` | `ctx.verified_content` on every interception and observation context |
| `Server<H, A>` with `handler: H` | `Server<A>` with `handlers: HandlerSet` |
| `hooks::{Capabilities, EventGrant, EventCapabilities}` | `capability::HostCapabilities` with event-specific builders such as `capability::tool_before()` |
| `HooksOptions::from_declarations(source, ..)` | `HooksOptions::new(source, HostCapabilities { .. })` (infallible) |
| `HooksOptions::from_manifest(source, manifest)` | `HooksOptions::new(..)` plus `options.manifest_metadata` for non-event manifest fields |
| `capability::intercept()` / `capability::observe()` generic builders, `.build()` | `capability::<event>()` builders; `.observe()` on a declaration, or `capability::Observe` for observe-only events |
| `capability::{Event, EffectType}` | `EventType`, `EffectId` (crate root) |
| `capability::ModifyOperation` arrays in `modify_*` | `capability::Modify::{Replace, Merge, ReplaceAndMerge}` |
| `.r#return()` on builders | `.return_result()` |
| `Hooks::event_for("session.start", ..)`, `Client::event_for(&'static str, ..)` | `event_for(EventType::SessionStart, ..)` |
| `client::Decision` | `client::Permission` |
| `client::ConsumerProtocolOutcome` | `client::ProtocolOutcome` |
| `hooks::EventOutcome<T>` with `effective_event`, `settled_event`, `event: Result<T, _>` | Non-generic `hooks::EventOutcome` with `event: generated::Event` |
| `hooks::ToolOutcome::{input: Result<T, _>, candidate, effective_input, settled_event}` | `input: T`, `outcome.settled_candidate`, `event: generated::Event`; decode failure is an outer `HookError` (see `accepted_settlement()`) |
| `client::BoundaryResult::{effective_input, effective_event}` | `event: generated::Event` (`input` stays `Result<T, InputDecodeError>`) |
| `runtime::EventResult::{effective_event, candidate_descriptor, event: Result<T, _>}` | `event: generated::Event`, `decoded_event: Result<T, InputDecodeError>` |
| `compaction::{run_compaction, run_compaction_observed, CompactionHook, CompactionObserver, DeferredCompaction, CompactionObservation, CompactionSnapshot, SummaryGenerator, ObserverCallback}` | `compaction::{capabilities, selected_text, stage_boundary}`; the host owns generation, scheduling, and observer delivery |

### Server: `Handler` → `HandlerSet`

Before (0.4):

```rust,ignore
use agenthooksprotocol::{generated as g, server::*};

struct Policy;
impl Handler for Policy {
    fn handle(&self, principal: Principal, message: Incoming) -> HandlerFuture<'_> {
        Box::pin(async move {
            match message {
                Incoming::Intercept(request) => {
                    let response = serde_json::json!({"jsonrpc": "2.0", "id": request.id,
                        "result": {"protocolVersion": "draft", "effects": []}});
                    Ok(Outgoing::Intercept(Box::new(
                        g::parse_intercept_response_value(response)
                            .into_value()
                            .ok_or("invalid response")?,
                    )))
                }
                Incoming::Observe(_) => Ok(Outgoing::Observed),
                Incoming::Capabilities(_) => Err("not configured".into()),
            }
        })
    }
}

let server = Server { handler: Policy, authenticator: Credentials, max_body_bytes: 65536 };
```

After (0.5):

```rust
use agenthooksprotocol::server::{Authenticator, HandlerSet, Principal, Server};
use std::sync::Arc;

struct Credentials;
impl Authenticator for Credentials {
    fn authenticate(&self, authorization: Option<&str>) -> Result<Principal, String> {
        match authorization {
            Some("Bearer local-demo") => Ok(Principal { subject: "local-demo-user".into() }),
            _ => Err("invalid credential".into()),
        }
    }
}

let mut handlers = HandlerSet::default();
// Interception: typed event in, correlated reply out. The server builds the envelope.
handlers.intercept.tool_before = Some(Arc::new(|ctx, event| {
    Box::pin(async move {
        let _input = &event.tool.input;
        Ok(ctx.reply()) // an empty reply is a valid no-op
    })
}));
// Observation: a separate map that returns unit and cannot emit effects.
handlers.observe.tool_before = Some(Arc::new(|ctx, _event| {
    Box::pin(async move {
        let _who = &ctx.principal.subject;
        Ok(())
    })
}));
let server = Server { handlers, authenticator: Credentials, max_body_bytes: 65536 };
```

Effects are the generated per-event effect type, so a reply cannot carry an
effect for another event:

```rust
use agenthooksprotocol::{generated as g, server::HandlerSet};
use std::sync::Arc;

let mut handlers = HandlerSet::default();
handlers.intercept.tool_before = Some(Arc::new(|ctx, _event| {
    Box::pin(async move {
        let deny: g::ToolBeforeEffect =
            serde_json::from_value(serde_json::json!({"type": "deny", "reason": "policy"}))
                .map_err(|e| e.to_string())?;
        Ok(ctx.reply().effect(deny))
    })
}));
```

Discovery replaces `Incoming::Capabilities` / `Outgoing::Capabilities`:

```rust
use agenthooksprotocol::{generated as g, server::HandlerSet};
use std::sync::Arc;

fn handlers(manifest: g::CapabilitiesResponseResultManifest) -> HandlerSet {
    HandlerSet {
        discovery: Some(Arc::new(move |ctx, _request| {
            let manifest = manifest.clone();
            Box::pin(async move { Ok(ctx.reply(manifest)) })
        })),
        ..Default::default()
    }
}
```

### Server: `handle_verified` → `ctx.verified_content`

`Server::handle_with_content(request, &store)` is unchanged. Instead of
overriding `Handler::handle_verified`, read the verified bytes from the context:

```rust
use agenthooksprotocol::server::HandlerSet;
use std::sync::Arc;

let mut handlers = HandlerSet::default();
handlers.intercept.tool_before = Some(Arc::new(|ctx, _event| {
    Box::pin(async move {
        for (pointer, bytes) in ctx.verified_content.iter() {
            let _ = (pointer, bytes.len()); // keyed by request JSON pointer
        }
        Ok(ctx.reply())
    })
}));
```

### Host authority: `EventGrant` and `from_*` → `HostCapabilities`

Before (0.4):

```rust,ignore
use agenthooksprotocol::hooks::{Capabilities, EventGrant, HooksOptions};

let options = HooksOptions::new(
    "urn:example:host",
    BTreeMap::from([(
        "tool.before".into(),
        EventGrant::intercept(Capabilities::none().allow().deny().modify_input().return_value()),
    )]),
);
// or
let options = HooksOptions::from_declarations(
    "urn:example:host",
    [(EventType::ToolBefore, capability::intercept().allow().deny().r#return()
        .modify_input([ModifyOperation::Replace, ModifyOperation::Merge])?)],
)?;
```

After (0.5):

```rust
use agenthooksprotocol::{
    capability::{self, HostCapabilities, Modify, Observe},
    hooks::HooksOptions,
};

let options = HooksOptions::new(
    "urn:example:host",
    HostCapabilities {
        tool_before: Some(
            capability::tool_before()
                .allow()
                .deny()
                .return_result()
                .modify_input(Modify::ReplaceAndMerge)
                .observe(), // observation is now explicit
        ),
        session_end: Some(Observe), // observe-only events
        ..HostCapabilities::default()
    },
);
```

`EventGrant::intercept` granted observation implicitly; in 0.5 omitted fields
grant nothing, so add `.observe()` where observation was relied on.
`HooksOptions::from_manifest` users move non-event manifest fields (transports,
authentication, tool paths, limits, extension members) to
`options.manifest_metadata` (`hooks::ManifestMetadata`); event authority always
comes from `HostCapabilities`.

### Event identifiers

```rust
use agenthooksprotocol::{EventType, Hooks};

fn prepare(hooks: &Hooks, event: serde_json::Value) {
    if hooks.subscribes(EventType::ToolBefore) {
        // prepare expensive input only when a route is interested
    }
    let _boundary = hooks.event_for(EventType::SessionStart, event);
}
```

`hooks::NAMED_BOUNDARIES` is now `&[EventType]`. Registration selectors remain
wire strings.

### Settlements

```rust
use agenthooksprotocol::{
    client::{Permission, ProtocolOutcome},
    hooks::{EventOutcome, ToolOutcome},
};

fn allowed(outcome: &ProtocolOutcome) -> bool {
    outcome.permission() == Permission::Allow // was client::Decision
}
fn event_json(result: &EventOutcome) -> serde_json::Value {
    serde_json::to_value(&result.event).unwrap() // was result.effective_event
}
fn tool(result: ToolOutcome<serde_json::Value>) {
    let _input: serde_json::Value = result.input; // was Result<T, InputDecodeError>
    let _candidate = result.outcome.settled_candidate; // was result.candidate
}
```

A `ToolOutcome` input decode failure now fails the await with a `HookError`;
`HookError::accepted_settlement()` retains the accepted, non-executable evidence.

### Compaction

The bundled compaction runner and observer scheduler were removed. Use
`compaction::capabilities` to build boundary grants, `compaction::selected_text`
to read authorized immutable text, and `compaction::stage_boundary` to stage
accepted effects atomically. Summary generation, scheduling, and observer
delivery stay in the host.
