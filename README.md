# Agent Hooks Protocol SDK for Rust

The active draft also provides MCP-aligned elicitation, operation-owned short-circuit
observations, and before/after compaction controls. See the shared
[boundary API guide](https://github.com/agenthooksprotocol/agent-hooks-protocol/blob/main/docs/accepted-boundary-apis.md)
for entrypoints, upload binding, trusted-host obligations, and test scope.

Runtime-neutral Rust SDK, generated models, and JSON codecs for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The crate follows the current AHP `draft` schema snapshot and requires Rust 1.88 or newer.

## Installation

Install from [crates.io](https://crates.io/crates/agenthooksprotocol):

```toml
[dependencies]
agenthooksprotocol = "0.1"
```

## Registration-driven hooks

`Hooks` accepts an ordinary `Registration` and `HooksOptions` with
explicit per-event `EventGrant` authority. Registration selects routes; it does
not grant effects or observation permission. `tool_before(ToolBeforeInput<T>)`
accepts flattened typed host facts and preserves the application argument type.
`tool_input(T).context(...)` and `event(...)` retain advanced canonical paths.
All 32 named event methods accept their generated `ergonomic_inputs::*Input`
with projection deferred until await. `tool_before_event(ToolBeforeInput<T>)`
returns the complete effective event; the primary `tool_before` instead preserves
the application argument type in `result.input`. Capability vocabulary is available
as `capability::{Event, EffectType, ModifyTarget}` with canonical wire spellings.

Enable `reqwest` for registered HTTP and `tokio-process` for registered stdio.
Default features remain empty. Construction and unpolled boundaries perform no
transport I/O. The host supplies an executor; the SDK creates no executor or
background observation thread. Local HTTP requires explicit policy; upload
credentials are independent of event credentials. Absent authentication permits
anonymous delivery, but does not authorize discovery or credential disclosure.

See [`examples/registered_hooks.rs`](examples/registered_hooks.rs) for JSON
registration, explicit grants, typed input, and real transports:

```sh
cargo run --example registered_hooks --features reqwest,tokio-process -- registration.json
```

A `Hooks` operation owns interception, selected content preparation, authentication,
and best-effort observation delivery. Its normal completion leaves no detached
observation work. The host can spawn the **whole operation** on its own executor;
ordinary futures are `Send`, and no `LocalSet`, scheduler injection, private runtime,
or background observation thread is required. Hosts must still await interception
before acting on permission. `permission()` reports `None`, `Allow`, `Ask`, or
`Deny`; it is not a replacement for interruption, host approval, decoding, and
execution gates.

`wait_until_idle()` waits for active operations and reports cumulative delivery
failures; it never starts delivery. `shutdown()` stops admission, cancels owned
work, closes owned content sources, and reaps SDK-created subprocesses. It does not
drain normal best-effort observations or close a harness-shared auth provider.
Retry shutdown after cleanup failure. Observation failures cannot change settled
results; reports retain at most 1,024 failure details and count additional failures
in `omitted_failures`.

A boundary can use `.budget(expiry)` or `.cancel_when(signal)` with a host-native
`Send` future. `.deadline_with(deadline, expiry)` also propagates the absolute
monotonic deadline to shorten transport work. The supplied expiry future provides
timer wakeups; the SDK does not create a timer runtime. The one operation budget
covers preparation, authentication, uploads, interception and owned observations;
phase changes do not reset it. Dropping or cancelling a call never authorizes an
incomplete interception. Bounded transport cleanup/reaping can outlast expiry.

Typed decoding occurs after settlement: `result.input` is a fresh
`Result<T, InputDecodeError>`, not an unchecked cast. A decoding error does not roll
back accepted effects. The host still owns application validation and execution.
`result.diagnostics` carries generated cause codes separately from delivery stage,
backend/subscription attribution, failure policy, and synthetic-denial evidence;
backend messages, bodies, and credentials are excluded. Canonical protocol denial
is not a delivery failure. Accepted raw responses remain in
`result.outcome.responses` for advanced consumers.

### Run both transports locally

From the SDK repository root, the stdio example starts and owns a real Python
policy process (Python 3 is required):

```sh
cargo run --example registered_hooks --features reqwest,tokio-process -- examples/stdio_registration.json
```

For HTTP, start the local fixture in one terminal:

```sh
REGISTERED_HOOK_TOKEN=local-demo-only python3 examples/http_policy.py
```

Run the client in another terminal, then stop the fixture with Ctrl-C:

```sh
REGISTERED_HOOK_TOKEN=local-demo-only cargo run --example registered_hooks --features reqwest,tokio-process -- examples/http_registration.json --allow-loopback-http
```

The example prints the authorized effective input but never executes it. The
local HTTP fixture is demonstration code, not a production server. Production
HTTP requires HTTPS; loopback HTTP is not enabled by default. Registered HTTP supports bearer delivery through a registration-aware
`BackendOptions::auth_provider`. The provider receives the selected binding,
backend identity, destination, event/upload purpose, and remaining deadline;
authentication challenges include the opaque attempted-credential identity.
Bearer `tokenEnv` remains available without a custom provider. The harness owns
OAuth discovery/trust, consent, token acquisition/refresh, and provider lifecycle.
Configured unsupported mechanisms and missing credentials fail closed. Event
credentials are never an implicit fallback for independently bound uploads.

### Event envelopes, manifests, and bodies

Named boundaries such as `hooks.session_start(facts).await` supply their event
`type`, identity, time, and configured source. Session start also supplies the
configured manifest; do not duplicate those fields in `facts`. Conflicting
caller values are rejected. Use `HooksOptions::from_manifest(source, manifest)`
for a complete `StaticCapabilityManifest`, including tool paths,
limits, and extension fields; the simple event-grant constructor only advertises
its supported event/mode/capability subset.

Use generated named attachment bindings, for example
`.attachment(ergonomic_inputs::tool_before_sources::items(index, Attachment::lazy(source)))`,
to transfer a source into an operation without raw JSON-pointer strings.
`Attachment::bytes(bytes)` supplies eager bytes; `Attachment::from_body(body)` and
`.body_source(...)` are conveniences for existing `Body` inputs, not staging APIs.
A lazy source is read only when selected delivery or an explicit
result read needs its bytes. For ordinary boundaries, metadata, omit, and unmatched routes do not read it.
Specialized compaction and elicitation selected-body validation can require
materialization even without a selected route, preserving protocol semantics.
Capture is shared immutably across fan-out and result reads, but each destination
has independent upload authority.

Selected bodies use bounded capture and size/SHA-256 verification. Configure
`max_body_bytes`, `max_stored_bytes`, and `max_stored_entries` in `HooksOptions`;
upload credentials are resolved separately from event credentials. This is
bounded in-memory capture, not unbounded or disk-backed streaming. Unused
attachments are dropped with their boundary or result owner.

## Quick start

Every public AHP schema has a Rust type plus `parse_*` and `encode_*` functions.

```rust
use agenthooksprotocol::{
    ParseResult,
    encode_capabilities,
    parse_capabilities,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = r#"{"effects":["deny"],"com.example.preview":true}"#;

    match parse_capabilities(input) {
        ParseResult::Success {
            value,
            diagnostics,
            ..
        } => {
            println!("{diagnostics:?}");
            println!("{}", encode_capabilities(&value)?);
        }
        ParseResult::Failure { diagnostics, .. } => {
            eprintln!("invalid payload: {diagnostics:?}");
        }
    }

    Ok(())
}
```

Successful parse results contain the typed value, the preserved `serde_json::Value`, and compatibility diagnostics. Failed results retain the raw value when the input was valid JSON and report diagnostics with a JSON Pointer path and machine-readable code.

## API

The `generated` module exports:

- `SCHEMA_REVISION` and `PROTOCOL_VERSION`
- typed models for registrations, JSON-RPC messages, hook events, requests, responses, capabilities, and effects
- `parse_<root>(&str)` and `parse_<root>_value(JsonValue)`
- `encode_<root>(&Type) -> Result<String, serde_json::Error>`
- `ParseResult`, `ParseDiagnostic`, `JsonValue`, and exact JSON number types

Open schema objects preserve unknown fields for forward compatibility; recognized fields remain validated. Closed objects, including effects and content references, reject unknown fields. Open enums retain unknown strings, while runtime evaluators reject unsupported effects and operations atomically. Parsing does not coerce values or insert defaults.

## Public boundaries and transports

The crate is `agenthooksprotocol`. The default feature set is empty. Core models,
canonical validation, typed boundaries, server dispatch, and immutable upload
verification do not depend on Reqwest, Axum, or Tokio. Generated semantic modules
include `event`, `effect`, `content`, `registration`, and `subscription`; generated
constructors take required values, supply schema literals/defaults, and expose
optional-member builders. Parsing still preserves absent members unchanged.

### Owned file and binary attachments

Use `Attachment::bytes(Vec<u8>)` or `Attachment::lazy(impl BodyStream)` with a
boundary's `.attachment(...)` method and a generated source binding:

```rust,ignore
use agenthooksprotocol::{Attachment, ergonomic_inputs::user_message_outbound_sources};

let result = hooks.user_message_outbound(input)
    .attachment(user_message_outbound_sources::message_payload(
        0, Attachment::lazy(file_source),
    ))
    .await?;
hooks.shutdown().await?;
let bytes = result.content.read("/message/payload/0").await?; // Arc<[u8]>
```

The content item still carries its media type, identity, role, and other metadata.
No store, scope, staging handle, or reference resolution is required. Moving an
attachment transfers ownership into one invocation; it is not a reusable
cross-invocation handle. Bytes are immutable, and `Arc::make_mut` creates a private
copy when other owners exist. `Body` inputs can be converted with
`Attachment::from_body` or passed through `.body_source(...)`.

A lazy source is read at most once, only for selected body delivery or an explicit
result read. Ordinary metadata-only and unmatched hooks do not read it. Specialized
compaction/elicitation selected-body validation may still require materialization. The result owns
unread sources as well as effective materialized bytes independently of Hooks;
dropping its last owner releases unopened sources. Read failure or cancellation is
terminal. Serialize concurrent first reads of the same lazy source. Invocation
cancellation, timeout, and errors drop invocation-owned sources; cancellation of a
result read drops its in-flight source too.

The configured `max_body_bytes` and source chunk limit apply to result reads;
selected deliveries additionally use upload budgets. Invocation byte and entry
budgets are shared across active boundaries; eager bytes reserve capacity at bind,
and lazy bytes reserve it when captured. Returned content detaches from active
invocation budgets. Result ownership does not create a session archive. Applications must bound the number of retained results themselves.
Lazy implementations must yield while waiting, and bound their own chunk allocations.

Attachments add no binary editing capability. Use `.content_target(...)` to map
text/JSON attachments for negotiated edits. Use `Attachment::bytes` for these
negotiated edits: eager bytes need no staging. Lazy inputs do not advertise edits
that require materialized target bytes.
See [`examples/file_attachment.rs`](examples/file_attachment.rs) for a standalone
file example with metadata-only auditing and a post-shutdown read.

### Typed, lazy interception

```rust,ignore
let result = client
    .tool_before(input) // T: Serialize + DeserializeOwned, inferred from input
    .initial_state(agenthooksprotocol::client::Decision::Allow)
    .await?;

// Protocol acceptance has already completed. Decoding is a separate inner result.
let effective_json = &result.effective_input;
match result.input {
    Ok(input) => { /* apply your own execution policy to the fresh typed input */ }
    Err(error) => { /* refuse execution; do not roll back accepted protocol effects */ }
}
```

Creating the builder does not serialize, send, or evaluate anything. The initial
native decision applies to this occurrence, not to future calls. Serial responses
are staged atomically; unsupported effects reject the whole compound response.
The SDK provides protocol outcomes and effective input, **never tool execution**.
A structurally accepted modification can be incompatible with your Rust type or
application policy. Keep protocol acceptance, host acceptance, and actual execution
separate. Application input-schema validation is not a protocol callback.

[`examples/typed_boundary.rs`](examples/typed_boundary.rs) is a complete typed
example using `futures::executor::block_on`, not Tokio. It demonstrates narrowed
capabilities and host-side execution policy. Per-occurrence `ToolContext` values
must carry canonical event metadata and fresh logical event IDs. A per-occurrence
`.initial_candidate(descriptor)` preserves a native candidate and optional provenance;
this provenance is not authorization. Absent initial state remains absent on the
first outgoing request, while explicit initial state is preserved.
`.initial_snapshot(snapshot)?` retains the complete canonical native snapshot,
including candidate provenance, flow, instructions, injections, and extensions.
A candidate whose value is JSON null remains distinct from no candidate. Native
state describes a decision already made for this occurrence; it grants neither
authenticated identity nor evidence of execution.

### Complete-event boundaries

`Client::event(event)` accepts a complete canonical event, including its identity
and context. Schema-derived named methods such as `tool_before_event(event)`
add an event-name check; `boundary::ALL_BOUNDARIES` exposes the generated
inventory. These APIs are distinct from `tool_before(input)`, which accepts only
application input and uses the client's `ToolContext`.

Complete-event boundaries are lazy. Their result separates `outcome` (settled
protocol state), `effective_event` (canonical JSON), and `event` (the subsequent
`Result<T, InputDecodeError>`). A failed typed decode does not undo accepted effects.
The SDK does not execute tools, install model context, or make application-policy
decisions.

Lower-level `Client` content-backed boundaries use
`.content(ContentContext { store, scope })`. The
scope must come from authenticated credentials or an explicit anonymous host
policy, never an event ID or content reference. `ContentStore` is the host-storage
interface; `MemoryContentStore` provides bounded immutable storage without durable
persistence. Resolution validates the canonical reference and uses the explicitly
authorized store. Metadata and omitted selections do not read bodies; required
unavailable bodies fail closed. Hosts must retain referenced bytes for the required
exchange lifetime.

### Hooks content lifetimes

`Hooks` does not own a global content store or staging registry. Each boundary
owns its attachments and transfers surviving attachments to its result. The
result retains the same shared owners used for delivery, rather than copies
recovered from canonical references. Errors and dropped futures release their
owners; result-owned bytes and unread sources survive `Hooks` shutdown and drop.
Applications that retain many results must bound their own history.

Attach eager bytes or a lazy source through a generated content-slot binding:

```rust,ignore
use agenthooksprotocol::{Attachment, ergonomic_inputs::user_message_outbound_sources::message_payload};

let event = serde_json::json!({
    "type": "user.message.outbound",
    "message": {"channel": "chat", "payload": [{
        "id": "text", "kind": "content", "category": "content", "role": "assistant",
        "mediaType": "text/plain", "selection": "metadata"
    }]}
});
let result = hooks.event(event)
    .attachment(message_payload(0, Attachment::bytes(b"original text".to_vec())))
    .content_target("content", "/message/payload/0")
    .await?;
let bytes = result.content.read("/message/payload/0").await?;
// `bytes` is an independently owned Arc<[u8]>; it survives result/Hooks drop.
```

`EventOutcome::content` and `ToolOutcome::content` are read-only, result-owned
payloads. Read them by the canonical content item's JSON pointer, not by copying
its body descriptor. Canonical local markers are not reusable handles: moving a
marker into another boundary does not transfer the attachment. To reuse bytes,
read them and create a new attachment. Only schema-owned content slots and
explicitly declared content targets retain attachments; reference-shaped objects
in opaque metadata, tool arguments, return candidates, and injection values do
not retain backing bytes.

Eager bytes are available immediately for mapped text/JSON edits through
`.content_target(...)`; no external staging is needed. Use `Attachment::bytes`
for negotiated edits. Ordinary lazy sources remain unread until selected body delivery or
`result.content.read(...)`; specialized selected-body validation may also read them. A failed
or cancelled read is terminal, and repeated reads do not restart the source.
Observation preparation confirms selected uploads before transport delivery;
each notification owns its projected wire payload independently.

The following scope and staging APIs are removed:
- `Hooks::{content_scope, content_context, stage_body}`
- boundary `.content_scope(...)`
- `content::ContentScope` and `body::StagedBody`
- `OwnedContent::{context, resolve}`

Use `.attachment(...)` (or the `.body_source(...)` conversion convenience) and
`result.content.read(pointer)`. Generated bindings are checked against canonical
content slots after the event type is supplied; a binding cannot attach bytes to
an arbitrary location inside opaque JSON.

`max_stored_bytes` and `max_stored_entries` retain their historical field names,
but now limit numeric active-owner accounting, not a content store. Returned
results release that accounting while retaining their own attachment owners.
Receiver-side `UploadReceiver` and standalone lower-level `ContentContext` /
`MemoryContentStore` APIs remain separate, caller-managed interfaces.

Generic prompt, response, output, and content modifications additionally require
`.content_target(target, pointer)`, an explicit host mapping to a canonical content
item (for example, `/items/0`). The SDK does not infer a primary item from its kind,
category, role, or position. Without a mapping and resolver, those modification
grants are absent. Verified text supports replacement; verified JSON objects can
also support merge. Metadata, omitted, gapped, and binary views do not advertise
these operations. The host is responsible for mapping the selected item to its
native operation.

For elicitation, capture an `elicitation::Exchange` from the original request and
its verified selected payload, then supply `.elicitation_exchange(&exchange)` to
the result boundary. Correlation and form-answer validation use that original
snapshot, not a later reread of a mutable request. Compaction replacement text is
verified UTF-8 and published through new immutable receiver-allocated references;
item identity and unrelated metadata remain intact. Failed staging does not commit
partial effects, although a host store may retain unreachable allocations from a
failed transaction. No replay or downstream model-consumption guarantee is implied.

Observation delivery is explicit: await each returned `Observation::deliver()`
(or schedule it on a host-owned executor). The legacy `dispatch_observations`
helper now also returns deferred observations instead of spawning threads. Its
synchronous callbacks run when delivery is polled and must not block an executor
thread unless the caller intentionally chooses that execution context.

### Interruption and acceptance deadlines

Keep `let progress = builder.progress()` before awaiting a boundary when you need
cancellation evidence. `progress.interrupt()` wakes the pending boundary and returns
an outer `BoundaryErrorKind::Interrupted`, regardless of fail-open policy. Dropping
a polled future also marks its progress interrupted. `progress.snapshot()` retains
already accepted effective input and protocol effects, but its outcome is always
non-executable. A pending response is never committed on interruption. Outer
`BoundaryError` values distinguish preflight, operational, and interruption failures
from the inner `InputDecodeError` of a settled boundary.

Each subscription has a configurable `.timeout(Duration)` acceptance budget
(30 seconds by default). The core measures monotonic elapsed time through response
parsing, validation, and atomic staging, rejecting expired effects before commit.
The selected transport still must enforce that budget while I/O is pending; elapsed
checks cannot wake a permanently pending custom transport. This separation is
intentional: the runtime-neutral core does not install a global timer or executor.

### Explicit integrations

| Feature | Purpose | Runtime contract |
| --- | --- | --- |
| none | `client`, `server`, `transport`, `content`, bounded stdio framing | Caller-owned futures executor; no global runtime |
| `reqwest` | `adapters::reqwest::ReqwestHttp` | Caller-owned runtime compatible with Reqwest; redirects disabled, bounded response capture |
| `axum` | `adapters::axum` server convenience | Caller-owned Axum runtime; delegates to the same core handler |
| `tokio-process` | `adapters::process::Process` persistent child transport | Explicit caller-owned Tokio runtime; subprocess deadlines, retirement, kill/reap |
| `interop` | Existing executable test hosts | Test-only blocking HTTP/process fixtures; not a default core dependency |

`transport::{Request, Response, Http}` do not expose Reqwest or Axum types.
Server callbacks receive generated request types and credential-derived principals;
request IDs, event IDs, and content references are correlation, not authorization.
Use `Server::handle_with_content(request, &store)` to verify schema-defined
selected content before dispatch. Override `Handler::handle_verified` to consume
`ResolvedContent` bytes indexed by request JSON pointer. The authenticated
principal determines the storage scope; arbitrary open payload fields are not
scanned for references. Plain `handle()` performs protocol validation without
automatic content resolution.
The bounded stdio adapter frames the **same** server handler rather than maintaining
a separate dispatcher. Notification completion is silent. HTTP errors retain bodies.

```sh
cargo run --no-default-features --example generated_models
cargo run --no-default-features --example typed_boundary
cargo run --no-default-features --example neutral_server
cargo run --features reqwest,axum --example http_roundtrip
```

The subprocess adapter is deliberately not claimed to work on every executor.
Dropping an in-flight subprocess future retires that stream, starts termination,
and prevents reuse; `shutdown().await` deterministically kills and reaps. `Drop`
only initiates best-effort cleanup. Applications must explicitly await shutdown
before stopping their runtime. Core framing alone does not launch processes or
supply deadlines.

### Binary uploads

`content::Uploader` sends exact raw bytes to an explicitly configured endpoint.
Upload credentials are supplied independently through `UploadCredential`, never
inherited from event credentials. HTTPS is required except explicitly enabled
loopback tests. A canonical HTTP 201 `ContentUploadReceipt` confirms the exact
size and SHA-256 of the sent bytes. Call `receipt.reference()` to publish only
`{ "ref": "receiver-allocated-id" }` in a body or effect; upload confirmation
metadata must not appear in event references or body-selected outer items. Redirects are not followed by the supplied
Reqwest adapter; custom transports must preserve that policy.

`content::UploadReceiver` authorizes a credential-derived scope before allocating
an opaque immutable reference. It bounds transfer size, total retained bytes, and
entry count, and resolves references only within that scope from trusted stored
bytes, without event-supplied size/hash metadata. `ContentContext::put` returns a
ref-only JSON value after an exact-byte readback check. The application owns storage lifetime and must retain confirmed bytes
through dependent event processing. It must resolve all referenced content before
publishing effects. The in-memory receiver is not durable storage or a retrieval
protocol. Upload deadlines must be enforced by the explicitly selected runtime or
transport; core code does not secretly start a timer runtime.

### Scope of the draft

The new typed convenience boundary currently focuses on `tool.before`. Existing
modules provide registration checks, source-scoped lineage, MCP-aligned elicitation,
settled observation delivery, and before/after compaction. These have distinct
entrypoints; their presence does not imply every boundary has the new generic API.
The core callback server supports discovery, interception and observation. Full
application authorization, content projection, and execution policy remain the host's
responsibility. Custom `Hook` implementations must honor authentication, deadlines,
content permissions, and notification semantics.

The [interoperability adapters](interop/README.md), [lifecycle transport](interop/LIFECYCLE.md),
and [catalogue adapter](interop/CATALOGUE.md) are synthetic hosts with deliberate,
explicit adversarial wire cases. They are not production harness implementations.

## Development

```sh
git clone https://github.com/agenthooksprotocol/rust-sdk.git
cd rust-sdk
cargo fmt --check
cargo check --locked --no-default-features --lib
cargo test --locked --no-default-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

Generated code lives in `src/generated.rs`. Its provenance is recorded in `src/ahp-codegen.lock.json`; schema changes are made in the [protocol repository](https://github.com/agenthooksprotocol/agent-hooks-protocol), not by editing the generated file.

The generator source is protocol commit `7544872e5beff69f29b04ae61686cc8ac25c3654`. From a protocol checkout at that commit, regenerate and verify with:

```sh
python3 tools/generate_sdk.py --rust-sdk ../rust-sdk
python3 tools/generate_sdk.py --rust-sdk ../rust-sdk --check
```

The root `ahp-codegen.lock.json` mirrors `src/ahp-codegen.lock.json`; both are generator-owned.

## License

Apache-2.0

### Typed composed payloads

MCP connection payloads expose typed structs rather than `JsonValue` wrappers.
For example, `ExecutionEventMcpConnectionHttp::new().with_url("https://mcp.example")`
constructs an HTTP payload; `with_gaps` accepts typed gap records. SSE, stdio, and
custom transport structs expose their location fields directly. Composed
capability arrays and scalar fields retain typed values, and `ModelVisibleItem`
exposes semantic content variants with a required `role`.

Migration: replace former JSON-wrapper constructors with the generated struct,
array, scalar, or enum constructors. Constructors model fields; existing parsing
and validation APIs remain responsible for predicates such as “location or
gaps.” Unknown variants and extension fields stay lossless. The nonliteral
custom transport tag retains the existing unknown-variant union fallback;
explicit custom payload models are still available for typed construction.

### Structural decoding and effect-family queries

Generated models implement checked `serde::Deserialize`. For example,
`serde_json::from_str::<InterceptRequest>(input)` and
`serde_json::from_value::<InterceptRequest>(value)` use the same original
structural descriptors as `parse_intercept_request`. This includes required
members, literals, known discriminator variants, and composed `oneOf`/`anyOf`
constraints, even where the Rust representation is a simpler projection.
Decoding a `serde_json::Value` or another application-owned type is **not** an SDK
validation boundary. Constructing a struct or calling a convenience constructor
also does not establish protocol validity; public mutable fields remain useful
for application construction.

Use `parse_*` when you need structured diagnostics, warning paths, or the original
JSON value on failure. Direct Serde decoding reports structural failures through
its normal error channel; it does not return the parser's warnings. Both routes
preserve extension data supported by the structural compatibility policy.
Canonical and contextual validation, effect admission, and host authority remain
separate checks. Descriptor caches and private synchronous, thread-local hydration scopes avoid
rechecking every nested subtree after a successful root check. The scope is
limited to generated model hydration on the current thread: it does not span
async suspension points or invoke application callbacks, and its drop guard
restores the previous scope even when unwinding. It is not process-global.

`state::InitialState` requires a `candidate` member. These values stay distinct:
`"candidate": null` means no candidate; `"candidate": {"value": null}` means a
present candidate whose application value is null; `"candidate": {"value": 0}`
retains zero. Missing `candidate`, or a candidate object missing `value`, is an
error rather than an implicit null default.

Query advertised effect-family membership on incoming generic or event-specific
capabilities with `capabilities.supports(EffectId::Deny)`. `EffectId` aliases the
schema's extensible effect vocabulary (also exported as
`capability::EffectType`), so
`capabilities.supports(EffectId::Unknown("vendor.effect".into()))` works for custom
families too. This query does not grant authorization and does not inspect
modify targets, operations, or other admission constraints. A populated `modify`
member does not imply membership of `"modify"` in `effects`.

**Migration:** `capability::EffectType` now aliases the schema identifier and
retains `as_str()`; because custom identifiers own strings it is no longer
`Copy`, and its string accessor borrows from `&self`. The canonical identifier
does not provide the former closed enum’s `Ord`/`Hash` derives; use its wire
string for ordered or hashed keys. Clone when reusing an owned identifier. `supports` compares typed identifiers without JSON serialization.
Direct Serde model decoding now rejects structurally invalid
inputs that older derived decoders admitted. Supply required members explicitly;
use an explicit null application value when that is intended. Primitive
intersection projections and forbidden-value schemas use transparent newtypes
instead of aliases where owning `Deserialize` is necessary to retain their
constraints. `state::Candidate` now aliases the canonical candidate descriptor: use its
constructor/builders rather than struct literals, and use `Presence` for direct
access to its optional provenance. This also preserves extension members when
decoding a candidate directly. The wire representation is unchanged. Numbers retain the existing
arbitrary-precision JSON policy; integer slots reject fractions and values outside
the interoperable safe-integer range. Fixed numeric literals may normalize their
spelling during encoding, while `parse_*` retains the original raw JSON value.
