# Agent Hooks Protocol Rust SDK

Official, non-normative Rust models and structural codecs for the [Agent Hooks Protocol](https://github.com/agenthooksprotocol/agent-hooks-protocol).

> [!WARNING]
> A successful structural parse is not canonical schema validation and must not be used alone for authorization or response classification. Validate security-sensitive messages against the canonical Draft 2020-12 schemas.

## Development

Rust 1.88 or newer is required.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

`src/generated.rs` and `ahp-codegen.lock.json` are maintained by schema-sync automation. Do not edit them manually.
