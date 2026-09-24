# Catalogue, lineage, and registration adapter

Select `suite:"catalogue"` on the existing lifecycle client and server. This
uses the same authenticated HTTP event transport or process-trusted stdio and
independently authenticated raw upload listener. Unknown suites and operations
fail rather than being skipped.

The client makes one real `hooks/capabilities` request. Both sides validate the
canonical generated Rust codec and JSON Schema, correlate the response exactly,
and retain the actual request/response in discovery evidence. Registration reads
that response's manifest, never a fixture-supplied replacement or expected value.

The synthetic catalogue host advertises observe support for 17 Execution event
types and task/workspace/file events. Only `tool.before` advertises interception
in this suite. User and project scope are enforceable; managed scope is not.
Authentication and transport support describe the real adapter bindings, not a
remote self-asserted principal.

## Operations

- `notify`: a native settled occurrence supplied by the fixture; canonical Rust
  validation and source-scoped lineage checks precede sending the exact message.
  It does not fabricate an interception response.
- `rawNotify`: send the adversarial JSON unchanged without local semantic checks.
  The receiver still uses its ordinary canonical validator and lineage engine.
  Schema and lineage rejections are recorded with the exact received message,
  and return HTTP 400 and 409 respectively. Stdio notifications receive no reply.
  Rejected deliveries do not mutate lineage or produce observed receipts.
- `register`: `registration::validate` checks canonical registration, unique backend
  IDs, event/mode coverage, effects and modify operations, native interactive ask
  support, transport support, scope enforceability, timeouts, and credentials.
  The synthetic context supplies environment-backed bearer resolution. Other
  credential-reference setups fail closed unless a resolver is implemented;
  merely advertising an auth method never proves configured credentials exist.

Receiver and sender lineage persist for the connection. Unknown filtered parents
are legal; known pair identities and late-edge cycles are checked atomically.
The existing `/wait-observed` barrier counts both observed and rejected receipts;
it supplies timing only. There is no semantic control endpoint or expected-ID
lookup. Reports never include credential values.

## Verification

```sh
cargo test --no-fail-fast
cargo build --bins
# From workspace root:
python-sdk/.venv/bin/python agent-hooks-protocol/interop/catalogue_matrix.py \
  --client rust --server rust --timeout 45 --output /tmp/rust-catalogue-all.json
```
