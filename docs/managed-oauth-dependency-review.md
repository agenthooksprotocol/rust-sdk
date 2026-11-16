# Managed OAuth dependency review

Reviewed 2026-11-16 UTC against the working manifest/lockfile and published upstream sources. Scope: optional `managed-oauth`, Rust 1.88, `oauth2 = "=5.0.0"`, `default-features = false`, `features = ["timing-resistant-secret-traits"]`.

## Gate decision

**Conditional accept for this dependency addition; not a clean repository security gate.** The fresh audit introduces **zero advisory or warning findings relative to the supplied baseline**. Five inherited vulnerabilities and three inherited unmaintained-package warning entries remain. An organization-wide zero-advisory gate must remain blocked until those are remediated or explicitly accepted. No policy exception is silently granted here.

The dependency-security skill is **unavailable** (none found in the supplied skill catalog or the previously checked `~/.agents/skills`). This is an evidence-based manual review, not a claim of compliance with an unavailable skill or formal security certification.

Integration conditions:

- Keep OAuth optional, exact-pinned, and without bundled HTTP/TLS defaults; re-review upgrades and feature-unification changes.
- Treat `OAuthNetwork` implementations as security-critical: validate resolved destinations at connection time, forbid redirects, verify TLS, cap streaming response bytes, and avoid credential-bearing request/response logging. The SDK's post-buffer check cannot replace these controls.
- The optional module deliberately exposes the pinned primitive’s client-secret and HTTP request/response types, as described below. Keep that coupling limited to this opt-in module and re-review upgrades.
- Track/remediate inherited audit failures separately; do not describe the entire lockfile as passing `cargo audit`.

## Provenance, publisher, and maintenance

Live crates.io API requests confirmed:

- Package/repository: [`oauth2`](https://crates.io/crates/oauth2/5.0.0), [`ramosbugs/oauth2-rs`](https://github.com/ramosbugs/oauth2-rs).
- Version 5.0.0 published 2025-01-21T00:40:54Z; not yanked; declared Rust version 1.65; license `MIT OR Apache-2.0`.
- Current registry owner: `ramosbugs` (David Ramos); release publisher is the same account. This is a single-owner/bus-factor risk, not evidence of malicious ownership. Owner information is a current snapshot, not ownership-history proof.
- Downloaded the actual registry archive from `https://static.crates.io/crates/oauth2/oauth2-5.0.0.crate`. Its independently computed SHA-256 equals both crates.io's version metadata and `Cargo.lock`:

  `51e219e79014df21a225b1860a479e2dcd7cbd9130f4defd4bd0e191ea31d67d`

- Archive `.cargo_vcs_info.json` identifies commit [`f3424b4b2190c83c6d031fdc71eed2351d49e0df`](https://github.com/ramosbugs/oauth2-rs/commit/f3424b4b2190c83c6d031fdc71eed2351d49e0df). GitHub confirms the commit exists, authored 2025-01-21, message `Update Cargo-1.65.lock`. GitHub reports it **unsigned**; checksum consistency is not a signed supply-chain attestation.
- Compared `src/types.rs` from the published/local registry source with raw GitHub content at that commit: byte-identical. This was a targeted source comparison, not a full reproducible-build certification.
- GitHub repository is not archived; API `pushed_at` is 2026-02-22T23:22:25Z. Registry's latest update is the 5.0.0 release. Release cadence and single ownership warrant monitoring; neither a maintenance badge nor a recent push guarantees response time.
- Archive contains `LICENSE-MIT` and `LICENSE-APACHE`; no `build.rs` in oauth2 itself. Transitive procedural macros/build scripts still execute normally during compilation; this is not a claim of a build-script-free dependency closure.

Sources actually queried: crates.io `/api/v1/crates/oauth2`, `/oauth2/5.0.0`, `/oauth2/owners`; GitHub repository and commit APIs; published crate archive and raw source at the recorded commit.

## API and security characteristics

The inspected published source offers endpoint typestate (`EndpointSet` / `EndpointNotSet`), `BasicClient`, PKCE-S256 helpers, typed token/secret wrappers, and `AsyncHttpClient` for caller-supplied transport. These are a useful mechanics layer, not an issuer trust policy, secure credential store, or a complete OAuth application.

Only `timing-resistant-secret-traits` resolves for oauth2 in Cargo metadata. Its secret wrappers redact `Debug`; enabled equality/hash implementations hash secret contents with SHA-256 before comparing/hashing fixed-size digests. This reduces direct secret-comparison leakage; it is **not** a blanket constant-time guarantee, zeroization, encrypted storage, or a license to log serialized tokens. Explicit `.secret()` access and owned copies still require care. PKCE plain and oauth2's reqwest/curl integrations are not enabled.

Upstream's `src/lib.rs` explicitly warns that HTTP clients must not follow redirects because of SSRF. The local SDK delegates networking instead of installing an HTTP client:

- `OAuthNetwork::check` and `send` carry endpoint purpose and an absolute operation budget. Its contract requires destination policy against resolved IPs including rebinding, certificate/hostname verification, bounded reads, no redirects, and no request/response logs.
- `checked_network_send` parses the actual request URI, requires HTTPS, calls `check` before `send`, enforces the deadline, and rejects redirection responses and buffered bodies above 1 MiB.
- Discovery validation rejects missing hosts, URL credentials/fragments, and issuer query strings. Discovered HTTPS endpoints are not inherently trusted merely because they parse.
- **Residual boundary:** an adapter can follow a redirect before returning a final 200, allocate an oversized body before the SDK checks it, or connect to a rebound/private address after an earlier DNS check. Therefore `send` must repeat/pin connection-time validation, refuse redirects at the transport layer, and enforce an incremental byte cap. A permissive adapter violates this API's security contract; the SDK cannot certify it remotely. Authorization URLs also require policy checks before host/browser interaction. Host trust decisions, private-address exceptions, and storage/CAS policy remain host responsibilities.

This review checks the dependency and selected integration boundary, not every protocol state transition or all host implementations.

## Optional tree, licenses, and MSRV

Observed manifest: `default = []`; `managed-oauth = ["dep:oauth2", "dep:tokio"]`. `cargo tree --locked --no-default-features -e normal` contains neither oauth2 nor tokio. Enabling only managed-oauth adds oauth2 and tokio, but normal dependency-tree filtering finds **no reqwest, rustls, ring, or webpki**. The lockfile still contains optional interop/TLS dependencies; a lockfile audit scans them regardless of active feature selection. Tokio's existing process/time/io-util/sync/rt flags are broader than OAuth mechanics alone, although this code does not spawn a browser, listener, or background runtime.

OAuth's resolved direct dependencies are base64 0.22.1, chrono 0.4.45, getrandom 0.2.17, http 1.5.0, rand 0.8.8, serde, serde_json, serde_path_to_error, sha2 0.10.9, thiserror 1.0.69, and url. This introduces another sha2 major alongside the SDK's sha2 0.11. Chrono/time-zone, RNG/platform, hashing, and serialization support are part of the footprint; HTTP/TLS is not.

Cargo metadata traversal of oauth2's resolved closure (including platform-conditioned dependencies) found no missing license declaration and these expressions:

- `MIT`, `MIT OR Apache-2.0`, `Apache-2.0 OR MIT`, legacy `MIT/Apache-2.0`;
- `BSD-2-Clause OR Apache-2.0 OR MIT`, `Unlicense OR MIT`;
- `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`;
- `Unicode-3.0`, `(MIT OR Apache-2.0) AND Unicode-3.0`, `Zlib`.

These are permissive choices compatible with an Apache-2.0 SDK, subject to retaining required license/notice text when redistributing. Metadata review is not legal advice or exhaustive source-level license scanning. No GPL/AGPL obligation was observed in that resolved closure.

No declared closure MSRV exceeds 1.88. Actual `cargo +1.88.0 check --locked --no-default-features --features managed-oauth --lib --quiet` **passed** on aarch64-apple-darwin. This validates the current resolved library graph on that target; it is not proof of every target or future semver-compatible transitive resolution.

## Why not rmcp 3.5.1?

The actual rmcp 3.5.1 registry archive was inspected, not inferred from its name. crates.io reports Rust 1.88, Apache-2.0, not yanked, published 2026-10-05; repository is `modelcontextprotocol/rust-sdk`. Its current owners are `jamadeo` and `alexhancock` (publisher). The requested security baseline explicitly excludes rmcp 3.5.1 for OAuth SSRF advisory RUSTSEC-2026-0457 (fixed in 3.7.0); no rmcp version is used here. Rejection is not based on a fabricated MSRV/license mismatch.

Its `auth` feature explicitly enables `async-trait`, `oauth2`, `__reqwest`, and `url`; `__reqwest` enables reqwest 0.13.2 with json/stream. Its oauth2 dependency is itself version `5.0`, optional, defaults disabled. Pulling the full MCP SDK into this AHP SDK to reach the same OAuth primitive adds another protocol framework and a concrete HTTP-client dependency while weakening the intended host-only networking boundary. Direct oauth2 with a small host adapter is the narrower fit. No complete rmcp dependency/advisory approval is implied by this comparison.

## Public external types: deliberate compatibility cost

`src/auth/managed.rs` publicly re-exports `oauth2::ClientSecret`, `HttpRequest as OAuthRequest`, and `HttpResponse as OAuthResponse`; `OAuthNetwork::send` also directly names oauth2 request/response aliases in its signature. Those aliases resolve to http 1 request/response bodies, but `ClientSecret` is an upstream nominal type. Consequently consumers can depend on oauth2/http identity and behavior through this optional public API. This is **not** a fully implementation-private dependency. Exact pinning controls the current choice but does not eliminate semver coupling. Either document and accept that boundary, or add SDK-owned wrappers before promising a stable independent API.

## Fresh advisory audit and baseline delta

Executed `cargo audit --json` with cargo-audit 0.22.1; **exit status 1**. Database: 1,509 advisories, commit `02e2517f457a359fc6d3440ea4560c8ea188fee8`, last updated 2026-11-15T10:59:21+01:00. Baseline `/tmp/rust-managed-baseline-audit.json` uses the identical database commit. Compared advisory ID/package/version tuples and unmaintained warning entries: **no new findings**.

| Finding | Locked package | Classification | Remediation reported by audit |
| --- | --- | --- | --- |
| RUSTSEC-2025-0009 | ring 0.16.20 | inherited vulnerability; AES panic under overflow checks | >=0.17.12 |
| RUSTSEC-2024-0336 | rustls 0.20.9 | inherited vulnerability; network-triggered complete_io loop | >=0.23.5, or patched 0.22/0.21 branches |
| RUSTSEC-2026-0349 | rustls 0.20.9 | inherited vulnerability; ServerHello downgrade | >=0.23.46 |
| RUSTSEC-2026-0382 | rustls-webpki 0.103.15 | inherited vulnerability; distrusted intermediate acceptance | >=0.103.16 below 0.104 alpha, or >=0.104.0-alpha.8 |
| RUSTSEC-2026-0383 | webpki-root-certs 1.0.9 | inherited vulnerability; distrusted emSign intermediates | >=1.0.10; unaffected =0.26.11 |
| RUSTSEC-2025-0010 | ring 0.16.20 | inherited unmaintained warning | migrate off pre-0.17 |
| RUSTSEC-2025-0134 | rustls-pemfile (two locked versions) | two inherited unmaintained warning entries | replace/remove per upstream guidance |

Those affected TLS packages are not in the observed managed-oauth-only normal tree. This limits the feature-specific delta, **not** the importance of fixing existing interop/other-feature exposure. Neither oauth2 nor its selected normal dependency closure produced an audit finding in this run.

Also queried GitHub's public repository security advisories and global advisory API filtered by `ecosystem=rust&affects=oauth2@5.0.0`: both returned empty lists. Absence of published advisories does not establish absence of vulnerabilities or unpublished reports. The referenced `sdk-audit.json` was not present at the root, `/tmp/sdk-audit.json`, or in a bounded `/private/tmp` search; it was not used as invented evidence.

Reproduction (read-only with respect to manifest/lockfile):

```sh
cargo audit --json
cargo tree --locked --no-default-features -e normal
cargo tree --locked --no-default-features --features managed-oauth -e normal
cargo metadata --locked --format-version 1 --no-default-features --features managed-oauth
cargo +1.88.0 check --locked --no-default-features --features managed-oauth --lib --quiet
```

This record is the only repository file authored by this review. No manifest, lockfile, implementation, commit, or push was performed by the reviewer.
