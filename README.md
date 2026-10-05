# Agent Hooks Protocol SDK for Rust

The active draft also provides MCP-aligned elicitation, deferred short-circuit
observations, and before/after compaction controls. See the shared
[boundary API guide](https://github.com/agenthooksprotocol/agent-hooks-protocol/blob/main/docs/accepted-boundary-apis.md)
for entrypoints, upload binding, trusted-host obligations, and test scope.

Runtime-neutral Rust SDK, generated models, and JSON codecs for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The crate follows the current AHP `draft` schema snapshot and requires Rust 1.88 or newer.

## Installation

The crate is not yet published to crates.io. Until the first release, pin it from GitHub:

```toml
[dependencies]
agenthooksprotocol = { git = "https://github.com/agenthooksprotocol/rust-sdk", rev = "<commit-sha>" }
```

## Quick start

Every public AHP schema has a Rust type plus `parse_*` and `encode_*` functions.

```rust
use agenthooksprotocol::generated::{
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

### Complete-event boundaries

`Client::event(event)` accepts a complete canonical event, including its identity
and context. Schema-derived named methods such as `tool_before_event(event)`
add an event-name check; `generated::boundary::ALL_BOUNDARIES` exposes the generated
inventory. These APIs are distinct from `tool_before(input)`, which accepts only
application input and uses the client's `ToolContext`.

Complete-event boundaries are lazy. Their result separates `outcome` (settled
protocol state), `effective_event` (canonical JSON), and `event` (the subsequent
`Result<T, InputDecodeError>`). A failed typed decode does not undo accepted effects.
The SDK does not execute tools, install model context, or make application-policy
decisions.

Content-backed boundaries use `.content(ContentContext { store, scope })`. The
scope must come from authenticated credentials or an explicit anonymous host
policy, never an event ID or content reference. `ContentStore` is the host-storage
interface; `MemoryContentStore` provides bounded immutable storage without durable
persistence. Resolution verifies descriptor size and SHA-256 even for a custom
store. Metadata and omitted selections do not read bodies; required unavailable
or corrupt bodies fail closed. Hosts must retain referenced bytes for the required
exchange lifetime.

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
loopback tests. Only a canonical HTTP 201 JSON descriptor whose size and SHA-256
match the exact bytes can be published. Redirects are not followed by the supplied
Reqwest adapter; custom transports must preserve that policy.

`content::UploadReceiver` authorizes a credential-derived scope before allocating
an opaque immutable reference. It bounds transfer size, total retained bytes, and
entry count, and resolves descriptors only within that scope after exact size/hash
verification. The application owns storage lifetime and must retain confirmed bytes
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
