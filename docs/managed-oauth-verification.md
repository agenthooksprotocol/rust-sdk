# Authentication acceptance verification

Local verification: 2026-11-16, Rust 1.88.0, existing `feat/auth-ergonomics` branch / PR #55. No release version or generated wire models changed.

## Executed checks

| Check | Result |
| --- | --- |
| `cargo +1.88.0 fmt --check` | passed |
| `cargo +1.88.0 clippy --locked --all-targets --all-features -- -D warnings` | passed, includes managed example |
| `cargo +1.88.0 check --locked --no-default-features --lib` | passed |
| `cargo +1.88.0 test --locked --no-default-features -- --test-threads=1` | 342 passed across 45 result groups |
| `cargo +1.88.0 test --locked --features reqwest,axum,tokio-process -- --test-threads=1` | 424 passed across 45 result groups |
| `cargo +1.88.0 test --locked --features interop -- --test-threads=1` with required schema/fixture environment | 526 passed across 53 result groups |
| `cargo +1.88.0 test --locked --no-default-features --features managed-oauth --lib` | 67 passed |
| `cargo +1.88.0 test --locked --features managed-oauth,interop --lib auth::managed` | 36 passed: 12 discovery + 24 host-owned TLS tests |
| Protocol generator `--rust-sdk . --check` at CI-pinned `1d98c19bf4558d998ef8af32b2ac54f604899c20` | codec, canonical schemas and lock match |
| `git diff --check` | passed |

The initial interop invocation lacked its mandatory `AHP_SCHEMA_DIR` and `AHP_INTEROP_FIXTURE_ROOT`; the corrected complete run above used the pinned protocol fixtures. Local full suites use one test thread because existing external-consumer fixtures use colliding timestamp temporary directories; hosted CI retains its normal concurrency.

## Accepted parity cases

| Case | Executable coverage |
| --- | --- |
| explicit-authorization | `tests/auth_ergonomics.rs::explicit_authorization` |
| mixed-bearer-oauth | `mixed_bearer_oauth` |
| missing-bearer-secret | `missing_bearer_secret` |
| oauth-no-credential | `oauth_no_credential` |
| unconfigured-challenge | core `unconfigured_challenge`; managed `unbound_initial_none_then_challenge_hint_and_well_known_order` |
| purpose-isolation | canonical Hooks upload tests; managed `namespace_destination_upload_isolation_and_login_cancellation` |
| destination-isolation | managed `namespace_destination_upload_isolation_and_login_cancellation` |
| stale-401 / refresh-single-flight | managed `serialized_refresh_preserves_resource_and_ignores_stale_401` |
| transient-refresh / invalid-grant | managed `refresh_transient_retains_secret_and_definitive_rejection_calls_hook_once`, `malformed_503_refresh_is_uncertain_and_never_retransmitted` |
| deadline-cancel | managed `expired_budget_and_store_wait_are_redacted_and_release_waiter`, both `dropping_*` tests |
| redaction | core `redaction`, `classified_provider_error_has_no_secret_cause_chain`; managed deadline/store regression |
| effectful-no-replay | core `effectful_no_replay`; helper never owns delivery/replay |
| pkce-completion | managed PKCE completion, pending cancellation, redirect-change and challenge-scope tests |
| client-credentials | managed `client_credentials_expiry_and_cache`, `saved_pkce_grant_cannot_be_reopened_as_client_credentials` |

Additional discovery tests cover quoted/escaped and ambiguous challenges, exact issuer locations, resource path coverage and hostile prefixes/origins/queries, explicit exact resource identity, endpoint validation and local scope selection. Real TLS tests verify resource parameters at exchange and refresh, mandatory endpoint denial before secret delivery, scope increases, definitive rejection hooks, uncertain rotation and rejected-access-token persistence.

## RFC 9728 section 3.3 source-identity correction

Resource coverage alone is not sufficient. Every discovery candidate now carries its exact expected resource identifier: the full endpoint path/query for path-specific well-known metadata, the origin without an appended slash for root metadata, and the actual resource request URL for a challenge-advertised metadata URL. A 200 response with a covering but incorrect resource fails before issuer discovery or token exchange and cannot trigger broader fallback. Explicit resource presets remain an additional exact constraint.

Persisted schema-2 hints retain retrieval source and expected resource, validated before cached metadata/credentials are used and again on discovery. Source-less legacy hints and mismatched root/path/challenge provenance fail closed. Regressions cover all three wrong-source cases, root versus path fallback, exact query identity, repeated prepare/complete with saved hints, legacy records, tampering and incompatible explicit presets. The focused, standalone and strict lint checks above were rerun after this correction.

## Review and boundaries

Independent code review identified and corrected endpoint trust, callback cancellation recovery, persisted challenge scopes, flow isolation, redirect-generation binding and access-rejection persistence. Dependency provenance/advisory review is recorded in [managed-oauth-dependency-review.md](managed-oauth-dependency-review.md): zero new audit findings; five inherited vulnerabilities and three inherited warning entries remain outside the managed-only normal dependency tree. This is not a clean-lockfile audit claim.

The requested shared-state, user-docs, persistent-artifact and Rust dependency-security skills were not available in the supplied skill catalog or installed local skill paths. The implementation uses explicit host ownership instead of a shared SDK registry; documentation and manual dependency/provenance evidence are retained in this repository. No unavailable-skill compliance is claimed. PR and shepherd instructions were loaded.

Host adapters remain security-critical: connection-time DNS/IP policy, TLS, no redirects, bounded streaming reads, secret-safe logging and cross-process exclusive/CAS storage cannot be certified by a generic SDK trait. No live external issuer, production credential, or downstream Kit migration was exercised in this SDK-only assignment. These tests validate the complete SDK mechanics with host-controlled TLS fixtures, not arbitrary host infrastructure. GitHub CI and review state must be checked on the pushed head separately; this record does not imply approval or merge authorization.
