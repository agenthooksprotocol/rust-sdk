# Agent Hooks Protocol SDK for Rust

The active draft also provides MCP-aligned elicitation, automatic short-circuit
observation delivery, and before/after compaction controls. See the shared
[boundary API guide](https://github.com/agenthooksprotocol/agent-hooks-protocol/blob/main/docs/accepted-boundary-apis.md)
for entrypoints, upload binding, trusted-host obligations, and test scope.

Typed Rust models and JSON codecs for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The crate follows the current AHP `draft` schema snapshot and requires Rust 1.88 or newer.

## Installation

The crate is not yet published to crates.io. Until the first release, pin it from GitHub:

```toml
[dependencies]
agent-hooks-protocol = { git = "https://github.com/agenthooksprotocol/rust-sdk", rev = "<commit-sha>" }
```

## Quick start

Every public AHP schema has a Rust type plus `parse_*` and `encode_*` functions.

```rust
use agent_hooks_protocol::generated::{
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

## Boundary runtimes

The handwritten modules provide registration checks, source-scoped lineage,
MCP-aligned elicitation, settled observation delivery, and before/after compaction.
`interop::Schemas::bundled()` validates offline using the canonical schemas included
in this crate. The composition evaluator stages effects privately and rejects an
entire response when an effect or operation is unsupported.

The [interoperability adapters](interop/README.md), [lifecycle transport](interop/LIFECYCLE.md),
and [catalogue adapter](interop/CATALOGUE.md) exercise these boundaries over real
stdio and authenticated HTTP. They are synthetic test hosts, not production harness
integrations. Subscription routing remains host-local; raw upload receivers allocate
immutable references that senders validate before publishing dependent events.

## Development

```sh
git clone https://github.com/agenthooksprotocol/rust-sdk.git
cd rust-sdk
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Generated code lives in `src/generated.rs`. Its provenance is recorded in `src/ahp-codegen.lock.json`; schema changes are made in the [protocol repository](https://github.com/agenthooksprotocol/agent-hooks-protocol), not by editing the generated file.

## License

Apache-2.0
