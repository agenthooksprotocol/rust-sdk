# Rust lifecycle runtime

Build the actual Rust binaries before running a language pair:

```sh
cargo build --bin lifecycle_client --bin lifecycle_server
cargo test --no-fail-fast
```

`src/bin/lifecycle` owns transport and settlement; `interop::apply` is the Rust
composition evaluator. Both incoming and outgoing envelopes pass the generated
Rust codec and canonical JSON Schema validator. An out-of-date generated codec fails closed rather than silently falling back
to untyped JSON acceptance.

## Settlement and observations

Observers receive the permission-filtered effective event,
with the same logical event ID and no generic disposition or decision summary.
After short-circuiting, remaining uncalled matching intercept subscriptions get
`hooks/observe` under their existing permissions and selections. Already-called
interceptors get no automatic second copy; explicit observation subscriptions
remain independent. Interruption ends pending decisions immediately and does not
wait for observer uploads or processing. Upload readiness precedes each delivered
notification. There is no downgrade flag or `/view` fallback.

Receiver reports retain the unchanged notification under `message`; `/view` has
been removed. `/mark`, `/wait-observed`, `/release` and `/emit` are test rendezvous,
not protocol decisions. Observer responses never reopen a boundary.

## Raw content binding

Client configuration has an independent upload binding:

```json
{"upload":{"endpoint":"http://127.0.0.1:PORT/upload",
 "auth":{"type":"bearer","tokenEnv":"AHP_INTEROP_UPLOAD_TOKEN"},
 "timeoutMs":5000,"maxBytes":1048576}}
```

Matrix receiver config uses `uploadAuth:{token,scope:"body"}`.
The receiver exposes a separate raw HTTP listener and publishes `uploadEndpoint`
in readiness. Stdio clients use readiness only when `upload.endpoint` is omitted;
an explicit endpoint is never replaced. HTTP clients receive the endpoint in
`upload.endpoint`. The sender uses the exact configured
endpoint including query, without appending a route. HTTPS is required except
explicit loopback tests. Redirects are disabled. Upload tokens are resolved
independently: event credentials and client certificates are never inherited.
The receiver binds authenticated upload credentials to its configured scope;
`auth.scope` selects the independently authenticated event scope. JSON-RPC IDs
and event IDs never select authorization. Anonymous upload authorization requires
explicit `anonymous: true`, never an implicit credential fallback.

Fixture upload steps carry `bodyBase64` (fixture encoding only), `subscription`,
and `ref`. Negative fixtures can override declared size/hash to exercise real
receiver rejection; they are not local-validation successes. The client decodes once and sends raw arbitrary octets, exact length,
SHA-256 headers. Subscription routing remains harness-local and is not sent on
the wire. The receiver verifies framing/hash/size, allocates an immutable reference,
and returns HTTP 201 with `{ref,size,sha256}`. The sender validates the returned
size and hash before recording the reference or publishing a dependent event.
Both observe and intercept recursively resolve content bodies against confirmed
bytes before delivery and on receipt. Failed upload never falls back to inline
content or a local path. The old JSON `/upload` control route returns 404.

## Task and workspace integration

Canonical schemas enforce typed payloads. The receiver maintains source-scoped
lineage, permits unknown subscriber ancestors and after-only events, rejects
late-edge cycles atomically, checks known task before/after identity and rejects
known-prior actual no-ops. It does not constrain parent lifetime or native status
vocabulary. Task/workspace interception supports advertised deny/message only;
tool permissions do not grant task-change authorization. Producers remain
responsible for reporting actual applied changes, not speculative downstream task
proposals or a fabricated before event.

## Focused checks

```sh
cargo test --lib
cargo test --bin lifecycle_client binary_upload
cargo test --bin lifecycle_client disposition_comes
```

Limits: this is a synthetic boundary adapter, not native harness integration.
HTTP event transport supports all five core adapter modes: `none`, `bearer`,
`oauth` client credentials, signed `workload`, and verified client-certificate
`mtls`. JWT checks include signature, issuer, audience, purpose, and time. Redirects
are disabled. Stdio accepts only explicit process-trust (`none`), not HTTP tokens.
The raw upload binding uses independent bearer auth across all event modes. No durable storage, native cancellation guarantee,
indivisible multi-task changeset, or production HTTPS listener is claimed.

## Verification

Language unit and integration tests: `cargo test --no-fail-fast`.
Core self-pairs: `../python-sdk/.venv/bin/python interop/test_local.py`.
Transport failure/redirect regressions: `../python-sdk/.venv/bin/python interop/test_transport.py`.
For the Rust lifecycle self-pair across every mode, from workspace root:

```sh
python-sdk/.venv/bin/python agent-hooks-protocol/interop/lifecycle_matrix.py \
  --client rust --server rust --timeout 45 --output /tmp/rust-lifecycle-auth-all.json
```

Task/workspace coverage includes canonical typed payloads, deny-only authorization
capabilities plus messages, unchanged receipt envelopes, no-op rejection and
unknown/late ancestor checks. This is not a claim of native adapter enforceability
or coverage of every execution catalogue event. Observation construction rejects
unsupported combinations rather than inventing a disposition. Interruption remains
terminal.


## Serial settlement safety

The Rust evaluator stages on a private copy. Incoming accepted `state.flow`,
`state.instructions`, and `state.injections` are retained across later responses,
including an empty response. Stop remains dominant and prevents execution and
candidate delivery. Later injections/instructions append in order. A continuation
already selected by an earlier response is not charged a second allowance;
remaining allowance is carried by the next request's dynamic capabilities.

Rust does not invoke an external native-authorization callback inside this
synthetic evaluator. Native refusal/pending permission must be represented in
accepted permission state; deny/ask gate supplied candidates as well as execution.
Publication checks the terminal state again, so cancellation between evaluation
and publication cannot be overwritten. A deterministic two-barrier thread test
covers this interval without sleeps. Existing tests cover preservation of already
accepted changes when interrupted.

The sender isolation regression configures real event bearer authentication,
performs an actual HTTP observation, then runs an upload with `upload.auth` absent.
A real HTTP capture verifies that the event carries Authorization but the upload
at its configured path/query does not, and that binary bytes are unchanged.

### Serial-chain wire coverage

Shared `chain` fixtures execute actual adapter transport calls, then automatically
notify remaining uncalled intercept subscriptions and explicit observers after
settlement. Cases cover deny/stop/compound deny+stop, fail-open continuation,
fail-closed short-circuiting, native observation, effective input, content
metadata/omit projection, and already-called subscription suppression. The held
observer-processing probe verifies interruption does not wait for observation
responses. See the protocol repo's `spec/draft/observation-disposition.md` and
`interop/observation-chain-scenarios.json`; helper unit tests alone are not this
integration evidence.
