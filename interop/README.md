# Rust synthetic interop adapters

Run from `rust-sdk`:

```sh
cargo build --bin interop
cargo test --test interop
python3 interop/test_local.py
python3 interop/test_transport.py
cargo run --quiet --bin interop -- server --config /absolute/server.json
cargo run --quiet --bin interop -- client --config /absolute/client.json
```

`adapter.json` provides the central runner's launch commands. Configuration follows
`../agent-hooks-protocol/interop/CONTRACT.md`. Canonical request/response envelopes
are sent directly on HTTP and stdio, never double-wrapped. Canonical schemas are
loaded from `../agent-hooks-protocol/schema/draft` (override with `schemaDir`).
Generated Rust structural parsers AND canonical draft-2020-12 validators are used.
Unknown effect kinds and unadvertised operations reject the entire response.

The synthetic pending-boundary evaluator implements deny/allow/ask, shallow
merge and whole-input replace, message, return, flow stop/continue, and context
append injection. It stages privately before publication; input changes precede
candidate binding and invalidate prior input-bound candidate/allow state. Deny
wins over ask, ask over allow; candidate results never authorize execution.
The fixture tool requires a positive integer `task` after each input mutation.
Flow stop prevents tool execution and discards candidates. Continuation requires
a finish boundary and remaining allowance. Accepted instructions accumulate in order,
with one allowance consumed per accepted continuation response. Stop preserves the
instructions and allowance without scheduling continuation. Injections represent accepted scheduled
work, not proof of content delivery. The tool.before, turn.finish.before, task.change.before and
workspace.change.before boundaries are implemented; other boundaries are rejected.

HTTP supports bearer, actual OAuth client-credentials token acquisition, signed
HS256 workload assertion verification, and actual mutual TLS with CA-based client
certificate verification. OAuth/workload validate issuer, audience, purpose,
expiry, nbf and iat against the configured test clock. Duplicate Authorization headers
are rejected before recording receipts. All HTTP clients reject redirects, including
OAuth token acquisition, so credentials cannot cross redirect resource boundaries. Test-only trust is NOT
production workload federation. mTLS uses a bounded TLS frontend and a secret-
protected loopback backend; it supports Content-Length HTTP/1.1, not chunked uploads.
Stdio uses process trust, and HTTP auth combinations are marked inapplicable.

The server provides a separate loopback control listener for readiness, redacted
exact canonical request receipts, barrier release, and shutdown. Readiness/report writes are atomic.
HTTP requests and stdio replies have 15-second deadlines; barriers use a condition
variable with a 15-second deadline. The client kills and reaps its stdio child on
success or failure. This is a test adapter, not a production HTTP server: no durable
queue, retries, multiplexed stdio, production policy/approval UI, external tool
execution, or complete event/content-selection runtime. HTTP GET /capabilities
returns the adapter capability object; canonical stdio hooks/capabilities returns
an independently validated manifest. No legacy stdio method aliases or discovery
response shapes are accepted. Negative response fixtures intentionally bypass server output
validation so that client rejection is actually exercised. `expectError` only passes
when an acquired JSON response fails canonical/application validation; transport
status failures, disconnects, EOF, and watchdog timeouts remain failed cases.

The local Python smoke test imports the central scenario builder and auth helpers
without modifying shared scenarios, then tests Rust-to-Rust stdio and HTTP
none/bearer/OAuth/workload/mTLS. This is not a claim that every cross-language pair
has been exercised; the central runner owns that matrix.


Core accepted-request receipts include the unchanged `message` envelope; both
`/receipts.requests` and `/health.requests` expose that evidence for local tests.
Transport credential headers are never included. These are test-only control
listeners; the exact event payload is intentionally retained, not redacted into
an ID/method claim.
