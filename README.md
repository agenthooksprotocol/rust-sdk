# Agent Hooks Protocol SDK for Rust

The draft provides MCP-aligned elicitation, operation-owned short-circuit
observations, and before/after compaction controls. See the shared
[boundary API guide](https://github.com/agenthooksprotocol/agent-hooks-protocol/blob/main/docs/accepted-boundary-apis.md)
for entrypoints, upload binding, trusted-host obligations, and test scope.

Runtime-neutral Rust SDK, generated models, and JSON codecs for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The crate follows the current AHP `draft` schema snapshot and requires Rust 1.88 or newer.

## Installation

Install from [crates.io](https://crates.io/crates/agenthooksprotocol):

```toml
[dependencies]
agenthooksprotocol = "0.4"
```

## Registration-driven hooks

`Hooks` accepts an ordinary `Registration` and `HooksOptions` with
typed `capability::HostCapabilities` authority. Registration selects routes; it does
not grant effects or observation permission. `tool_before(ToolBeforeInput<T>)`
accepts flattened typed host facts and preserves the application argument type.
`tool_input(T).context(...)` and `event(...)` retain advanced canonical paths.
All 32 named event methods accept their generated `inputs::*Input`
with projection deferred until await, including `tool_after`,
`tool_permission_request`, `tool_permission_resolved`, and `tool_progress`.
Generic host inputs preserve caller-owned arguments.
`tool_before_event(ToolBeforeInput<T>)` returns an `EventOutcome` containing the
canonical event; `tool_before` preserves the application argument type in
`result.input`. Declare host authority with event-specific constructors in
`capability`; the fields of `capability::HostCapabilities` accept only matching
event declarations.

Use `hooks.subscribes(EventType::ToolBefore)` before expensive input preparation
when only subscribed consumers need that input. This synchronous lookup includes
eligible interception and observe-only routes, using registration's exact, `*`,
and dotted-prefix selectors. The argument is the generated `EventType`;
registration selectors remain wire strings. It returns `false` for unconfigured
events and events with no eligible matching route. Payload-dependent filters are
not evaluated: a matching filtered route remains potentially interested.
The lookup performs no input preparation, transport, authentication, uploads, or
mutation. It reports static interest, not permission or guaranteed delivery.

```rust,ignore
use agenthooksprotocol::generated::EventType;

if hooks.subscribes(EventType::ToolBefore) {
    let input = prepare_tool_facts();
    let outcome = hooks.tool_before(input).await?;
    // Apply host policy to the settlement before executing the tool.
}
```

Enable `reqwest` for registered HTTP and `tokio-process` for registered stdio.
Default features are empty. Construction and unpolled boundaries perform no
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

Typed decoding occurs after settlement: a successful Hooks tool boundary exposes
a freshly decoded caller-owned `result.input: T`, not an unchecked cast. Decoding
failure returns an outer `HookError` with accepted settlement evidence available
through `accepted_settlement()`; it does not roll back accepted effects. Use an
argument contract to validate edits before they are committed and forwarded to
later interceptors. The host still owns execution policy.
`result.diagnostics` carries generated cause codes separately from delivery stage,
backend/subscription attribution, failure policy, and synthetic-denial evidence;
backend messages, bodies, and credentials are excluded. Canonical protocol denial
is not a delivery failure. Full accepted canonical responses remain in
`result.outcome.responses` for inspection.

### Canonical settlement and caller-owned data

`client::ProtocolOutcome<C = SettledCandidate, P = serde_json::Value>` is the
settlement value. It owns permission, flow, authorization, failures, typed
`MessageEffect` values, full `InjectEffect` values, accepted `InterceptResponse`
values, and `settled_candidate: Option<generated::Candidate<C, P>>`. Injections
retain delivery timing and order. Candidate envelopes retain provenance and
extension fields; `candidate()` borrows their payload.

`hooks::EventOutcome` is non-generic and contains `event: generated::Event`,
`outcome`, diagnostics, and owned content. The event envelope is schema-owned; opaque host facts and
unknown properties are preserved. `hooks::ToolOutcome<T, R, P>` additionally
exposes the caller-owned `input: T` and uses
`ProtocolOutcome<R, P>` for application result and provenance contracts.
Low-level `client::BoundaryResult<T>` also separates the canonical `event` from
its decoded caller-owned `input: Result<T, InputDecodeError>`.

Use `client::Permission` for permission values. Serialize canonical models with
`serde_json::to_value` for wire inspection or JSON Pointer access. Unknown
properties do not override known fields or authorize execution.
`SettledCandidate` has typed summary, message, and elicitation variants;
`SettledCandidate::Opaque` carries application-owned results without imposing
an application schema.

Responses publish atomically. An invalid response publishes no edits or effects;
responses accepted earlier survive, and later edits cannot repair an invalid
edit in the rejected response. `HookError::accepted_settlement()` retains
non-executable diagnostic evidence when accepted settlement cannot satisfy a
caller's decode contract.

### Application contracts

`Hooks::tool_before(inputs::ToolBeforeInput<A>)` returns a lazy
`ToolBoundary<A, R = serde_json::Value, P = serde_json::Value>`. Arguments,
returned values, and candidate provenance have independent types. Awaiting yields
`ToolOutcome<A, R, P>` with `event: generated::Event`,
`input: A`, and `outcome: ProtocolOutcome<R, P>`. Input decoding failure returns
an outer `HookError` retaining accepted settlement evidence.
The authoritative candidate envelope is
`result.outcome.settled_candidate: Option<generated::Candidate<R, P>>`.
Use the generated candidate's
`value` and `provenance` members directly; `Presence` distinguishes omitted
provenance from a supplied value. A present candidate with a null value is not
an absent candidate.

```rust,ignore
use agenthooksprotocol::contracts::Contract;

let result = hooks.tool_before(input)
    .arguments_contract(Contract::<Arguments>::validated(|args| {
        if args.count <= 100 { Ok(()) } else { Err("count exceeds limit".into()) }
    }))
    .result_type::<ToolResult>()
    .provenance_type::<Provenance>()
    .await?;
let candidate = result.outcome.settled_candidate;
```

`Contract::new()` checks decoding and data preservation;
`Contract::validated(...)` adds application invariants from the same Rust type.
Decoding rejects supplied fields that serialization would drop or change. Use
closed structs to reject unknown members or flattened extension maps to preserve
them. Contracts evaluate complete proposed values, including merged arguments,
before atomic effect admission. Invalid edits or returned candidates reject the
compound response according to the configured failure policy. Partial merge
patches need not independently deserialize as the full argument type.

`.arguments_type()`, `.result_type::<R>()`, and `.provenance_type::<P>()` install
structural contracts. Use `.result_contract(...)` or `.provenance_contract(...)`
for additional invariants. Canonical settings such as `.capabilities(...)`,
`.initial_state(...)`, `.initial_candidate(...)`, `.initial_snapshot(...)`,
`.budget(...)`, and `.cancel_when(...)` compose on the same boundary.

See [`examples/tool_contracts.rs`](examples/tool_contracts.rs) for a complete
consumer example with a registered mock backend, distinct argument/result types,
and explicit host grants:

```sh
cargo run --no-default-features --example tool_contracts
```

### Typed elicitation forms

Run `cargo run --example form_answers --features typed-form` for a complete
answer-type example.

Enable `typed-form` and derive `Serialize`, `Deserialize`, and
`schemars::JsonSchema` (schemars 1.2.2) on one answer type `T`.
`form::Form::<T>::new()` derives and validates the restricted MCP form schema.
`request(message)` creates generated form request parameters; `accept(&answer)`
validates an answer and constructs an accepted result; `decode(&result)` returns
`form::FormAnswer<T>`, preserving decline and cancel as separate outcomes.
`result_contract()` binds answer validation to hook admission with generated
`ElicitResult<T>`, so an invalid accepted answer cannot reach a later interceptor.

Forms support flat objects with strings, numbers, booleans, string enums, and
arrays of string enums. Unsupported schema shapes fail during construction;
nullable fields, nested objects, and arbitrary arrays are not approximated.
URL elicitation has no answer content; use `form::decode_url_result` to validate
its action separately.

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
Bearer `tokenEnv` is available without a custom provider. The harness owns
OAuth discovery/trust, consent, token acquisition/refresh, and provider lifecycle.
Configured unsupported mechanisms and missing credentials fail closed. Event
credentials are never an implicit fallback for independently bound uploads.

### Event envelopes, manifests, and bodies

Named boundaries such as `hooks.session_start(facts).await` supply their event
`type`, identity, time, and configured source. Session start also supplies the
configured manifest; do not duplicate those fields in `facts`. Conflicting
caller values are rejected. `HooksOptions::new(source, HostCapabilities)` stores
typed authority without network I/O or JSON parsing. Each omitted field grants
nothing. A declaration explicitly opts into observation with `.observe()`;
interception selects supported controls or an elicitation facility.

```rust
use agenthooksprotocol::{capability::{self, HostCapabilities, Modify}, hooks::HooksOptions};

let options = HooksOptions::new("urn:example:host", HostCapabilities {
    tool_before: Some(capability::tool_before()
        .allow().deny().return_result().modify_input(Modify::ReplaceAndMerge)
        .observe()),
    ..HostCapabilities::default()
});
```

`Hooks::manifest()` renders the configured event/mode/capability subset for
session start. Set `HooksOptions::manifest_metadata` to customize typed transport,
authentication, tool-path, scope, limit, and other non-event metadata. Its opaque
extras cannot replace known fields or event authority. External registration and transport configuration are validated
by `Hooks::new`.

Use generated host inputs with `PartInput::inline_text(...)` and
`PartInput::owned(Attachment::lazy(source), media_type)` in canonical message
parts. `Attachment::bytes(bytes)` supplies eager bytes and
`Attachment::from_body(body)` accepts a `Body` source. Named Hooks methods
project these owners internally when awaited.
A lazy source is read only when selected delivery or an explicit result read
needs its bytes. Metadata, omit, and unmatched routes do not read attachments.
Capture is shared immutably across fan-out and result reads; each destination
has independent upload authority. Before serial interception begins, the operation
prepares and uploads selected binary bodies for every initially matching,
host-authorized route. `HooksOptions::max_concurrent_uploads` bounds simultaneous
transfers across active operations on the same `Hooks` instance. It defaults to
`8` and must be positive. Inline text needs no binary upload. Compaction and elicitation validate inline text, without
binary attachment reads.

Each route receives its own confirmed references and independently scoped upload
credentials, even when backends use the same endpoint URL. Confirmed receipts are
reused for that route's owned observations after denial; observations do not repeat
successful uploads. Upload failures are retained per route and applied at that
route's normal failure-policy point, so a fail-open upload failure does not prevent
healthy subscribers from receiving the same immutable source. Interceptors still
run serially. A later interceptor can remove an attachment after its upfront
upload; that unused upload does not invalidate the operation.

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
optional-member builders. Parsing preserves absent members unchanged.

### Owned file and binary attachments

Use `Attachment::bytes(Vec<u8>)` or `Attachment::lazy(impl BodyStream)` directly
in a generated host part. Messages own their role and ordered parts; text parts
carry inline strings and attachments carry immutable binary bodies.

```rust,ignore
use agenthooksprotocol::{Attachment, CanonicalMessageRole};
use agenthooksprotocol::inputs::{MessageInput, PartInput};

let result = hooks.user_message_outbound(
    input.with_sources().with_message_messages(vec![MessageInput::from_parts(
        CanonicalMessageRole::Assistant,
        vec![
            PartInput::inline_text("The requested file"),
            PartInput::owned(Attachment::lazy(file_source), "application/octet-stream"),
        ],
    )]),
).await?;
hooks.shutdown().await?;
let bytes = result.content.read("/message/messages/0/parts/1").await?; // Arc<[u8]>
drop(result.content); // release the returned content owner when finished
```

Messages and parts preserve supplied identities; convenience constructors mark
synthesized identities explicitly. Moving an attachment transfers ownership into
one invocation. The part carries media type and metadata; the message carries
its role. `Body` inputs can be converted with `Attachment::from_body`.

Projection and serialization happen when the hook is awaited. Projection does
not open an attachment. A lazy source is read at most once, only for selected
body delivery or an explicit result read. Metadata-only and unmatched hooks do
not read it. The result owns unread sources and effective materialized bytes
independently of Hooks. Callers must release returned content owners when finished:
drop the content owner and its clones to close unopened sources. Hooks shutdown
does not close returned content owners.
Concurrent first reads join one poll-driven materialization and share its
immutable result or terminal error. Cancelling one reader leaves other active
readers intact. Cancelling the last active reader is terminal and releases the
source. Invocation cancellation, timeout, and errors release invocation-owned
work; result-owned unread sources remain available after Hooks shutdown.

The configured `max_body_bytes` and source chunk limit apply to result reads;
selected deliveries additionally use upload budgets. Invocation byte and entry
budgets are shared across active boundaries; eager bytes reserve capacity at bind,
and lazy bytes reserve it when captured. Returned content detaches from active
invocation budgets. Result ownership does not create a session archive. Applications must bound the number of retained results themselves.
Lazy implementations must yield while waiting, and bound their own chunk allocations.

Binary attachments are immutable and do not support editing. Text edits operate
on inline text parts. Message and part-list merges append; replacements
substitute the selected list. Object merges are shallow.
See [`examples/file_attachment.rs`](examples/file_attachment.rs) for a standalone
file example with metadata-only auditing and a post-shutdown read.

### Typed, lazy interception

```rust,ignore
let result = client
    .tool_before(input) // T: Serialize + DeserializeOwned, inferred from input
    .initial_state(agenthooksprotocol::client::Permission::Allow)
    .await?;

// Protocol acceptance has already completed. Decoding is a separate inner result.
let effective_event = serde_json::to_value(&result.event)?;
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

Complete-event boundaries are lazy. Their `runtime::EventResult<T>` separates
`outcome` (typed settled protocol state), `event: generated::Event` (the canonical
effective event), and `decoded_event: Result<T, InputDecodeError>` (the caller-owned
projection). A failed typed decode does not undo accepted effects.
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

Each boundary owns its attachments and transfers surviving attachments to its
result. The result shares the immutable bytes used for delivery. Errors and
dropped futures release their owners; result-owned bytes and unread sources
survive `Hooks` shutdown and drop.
Applications that retain many results must bound their own history.

The generated host input accepts owners directly in its canonical part slots.
Normal named methods, including `tool_before` and `tool_before_event`, project
those inputs internally. No source registration or body preparation call is
required. Attachment results are read by their canonical JSON Pointer, such as
`/message/messages/0/parts/1`.

Canonical local markers are not reusable handles. To reuse bytes in another
invocation, read them and construct a new attachment. Only schema-owned part
slots retain attachments; objects in application inputs, native snapshots,
results, and extensions are opaque and do not create content authority.

### Interruption and acceptance deadlines

Keep `let progress = builder.progress()` before awaiting a boundary when you need
cancellation evidence. `progress.interrupt()` wakes the pending boundary and returns
an outer `BoundaryErrorKind::Interrupted`, regardless of fail-open policy. Dropping
a polled future also marks its progress interrupted. `progress.snapshot()` retains
a `BoundaryPartial` with the accepted canonical `event: generated::Event` and
typed `outcome`, but its outcome is always non-authorizing. A pending response is
never committed on interruption. Outer
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
| `typed-form` | `form::Form<T>` and restricted MCP answer validation | Runtime-neutral schema derivation and validation |
| `interop` | Executable test hosts | Test-only blocking HTTP/process fixtures; not a default core dependency |

`transport::{Request, Response, Http}` do not expose Reqwest or Axum types.
`server::HandlerSet` registers callbacks in separate `intercept` and `observe`
maps. Each event slot receives its matching generated event type and an
authenticated context. Interception returns `ctx.reply().effect(effect)` with
matching canonical effects; `ctx.reply()` alone is a valid no-op. Observation
returns `Ok(())` and cannot return controls. Both maps can handle the same event.
The server owns envelope correlation. Request IDs, event IDs, and content
references are correlation, not authorization.
Use `Server::handle_with_content(request, &store)` to verify schema-defined
selected content before dispatch. Event-specific contexts expose verified content
bytes indexed by request JSON pointer. The authenticated principal determines
the storage scope; arbitrary open payload fields are not
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

### Transport envelopes and canonical reducers

Custom `Hook` and `ManagedBackend` implementations exchange canonical JSON
request and response envelopes through a runtime-neutral transport seam.
Construct transport failures with `HookError::new(message)`. Canonical validation
precedes settlement. `ToolContext`, complete-event inputs, declarations, and
native snapshots carry explicit host-owned facts or wire models.

Low-level content editing, elicitation staging, registration validation, and
lineage helpers operate on canonically validated JSON or caller-owned envelopes.
`compaction::capabilities`, `compaction::selected_text`, and
`compaction::stage_boundary` provide independent canonical compaction operations;
the host owns generation, scheduling, and downstream context installation.
JSON supports merge/replace operations and opaque application data at these
boundaries. Deferred observation callbacks carry projected wire envelopes;
the host owns their scheduling.

### Scope of the draft

The SDK provides typed event boundaries, registration checks, source-scoped
lineage, MCP-aligned elicitation, settled observation delivery, and before/after
compaction controls.
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

The generator source is protocol commit `acb35f107b038296fd082072bb5bb64e8013e4e1`. From a protocol checkout at that commit, regenerate and verify with:

```sh
python3 tools/generate_sdk.py --rust-sdk ../rust-sdk
python3 tools/generate_sdk.py --rust-sdk ../rust-sdk --check
```

The root `ahp-codegen.lock.json` mirrors `src/ahp-codegen.lock.json`; both are generator-owned.

### Typed composed payloads

MCP connection payloads expose typed structs.
For example, `ExecutionEventMcpConnectionHttp::new().with_url("https://mcp.example")`
constructs an HTTP payload; `with_gaps` accepts typed gap records. SSE, stdio, and
custom transport structs expose their location fields directly. Composed
capability arrays and scalar fields retain typed values, and `ModelVisibleItem`
exposes semantic content variants with a required `role`.

Constructors model fields; parsing and validation APIs check predicates such as
“location or gaps.” Unknown variants and extension fields stay lossless. Custom
transports use the unknown-variant union fallback; typed custom payload models
are available for construction.

### Structural decoding and effect-family queries

Generated models implement checked `serde::Deserialize`. For example,
`serde_json::from_str::<InterceptRequest>(input)` and
`serde_json::from_value::<InterceptRequest>(value)` use the same
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
separate checks.

`state::InitialState` requires a `candidate` member. These values stay distinct:
`"candidate": null` means no candidate; `"candidate": {"value": null}` means a
present candidate whose application value is null; `"candidate": {"value": 0}`
retains zero. Missing `candidate`, or a candidate object missing `value`, is an
error rather than an implicit null default.

Query advertised effect-family membership on incoming generic or event-specific
capabilities with `capabilities.supports(EffectId::Deny)`. `EffectId` aliases the
schema's extensible effect vocabulary, so
`capabilities.supports(EffectId::Unknown("vendor.effect".into()))` works for custom
families too. This query does not grant authorization and does not inspect
modify targets, operations, or other admission constraints. A populated `modify`
member does not imply membership of `"modify"` in `effects`.

Use `EffectId::as_str()` to borrow an identifier's wire spelling
and to obtain keys for ordered or hashed collections. Clone an identifier when reusing its
owned string. `supports` compares typed identifiers without JSON serialization.

Supply required members explicitly when decoding models, and use an explicit
null application value when that is intended. Construct `state::Candidate` with
its constructor and builders; use `Presence` for direct access to its optional
provenance. Candidate decoding preserves extension members.

Numbers use arbitrary-precision JSON; integer slots reject fractions and values
outside the interoperable safe-integer range. Fixed numeric literals may normalize
their spelling during encoding, while `parse_*` retains the original raw JSON value.

## License

Apache-2.0
