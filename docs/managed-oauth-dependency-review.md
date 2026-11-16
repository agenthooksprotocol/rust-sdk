# Managed OAuth dependency review

## Decision and scope

Accept the SDK's optional `managed-oauth` addition for the exact locked feature and target graph described here. This is a bounded source/provenance and reachability review, not a clean whole-repository security gate or certification of every upstream public API.

The addition uses `oauth2 = "=5.0.0"`, with default features disabled and only `timing-resistant-secret-traits` enabled. No HTTP/TLS implementation, listener, browser or credential store is bundled. The implementation head `0508015a1bebdae21f4eab027da858e6f195aa19` has the same manifest/lockfile delta as the original managed feature: **21 package/version additions, no replacement or removal of pre-existing versions**. An isolated snapshot passed `cargo metadata --locked --offline --format-version 1 --no-default-features --features managed-oauth` without changing its lockfile. Unrelated versions selected by exploratory re-resolution were rejected; no downgrade or additional platform pin was applied.

Five Windows helper packages are **resolver-only** in this graph; their provenance was checked, but they are not cleared for unrelated runtime use. The target proof below is part of this SDK acceptance. No supported platform is excluded, and no platform-policy exception is assumed.

Five inherited advisory findings and three unmaintained-package warning entries remain. A fresh `cargo audit --json` comparison against `origin/main`, using the same advisory database, found **zero introduced vulnerability findings**. Do not describe the entire lockfile as passing `cargo audit`.

## Required host security boundaries

- `OAuthNetwork` must enforce connection-time DNS/egress policy, TLS validation, redirect rejection and incremental response-byte limits. A URL check or the SDK's post-buffer size check cannot prevent rebinding, redirected requests or oversized buffering inside an incorrectly implemented adapter.
- Every metadata, authorization and token endpoint goes through local policy. Discovery is untrusted input, not permission to send secrets. Client/issuer/resource/scope decisions remain local.
- Host storage must provide atomic generation comparisons and coordination, honor cancellation, and retain uncertainty markers after ambiguous external exchanges. No transaction can roll back an authorization server's rotated token.
- Secret strings are not zeroized automatically. Explicit secret access, serialized records and host logging need care. Hashing before equality is not a blanket constant-time guarantee.

## Provenance and source reconciliation

For every added release, archive SHA-256 values match both the exact `Cargo.lock` checksum and fresh registry version metadata. All releases are unyanked. Original/normalized manifests, features, platform/build dependencies, proc macros, license material and security-relevant source were inspected. Packaged non-Cargo-generated files were reconciled with the declared upstream VCS commits. Thirteen generic-array files differ only by CRLF/LF normalization; no unexplained source differences remain.

Current owner/publisher and adjacent release history checks are snapshots, not proof of historical ownership or infrastructure integrity. Registry trusted-publishing records for iana-time-zone and rand reconcile to their declared commits and successful GitHub release workflows. No unexplained executable payload, source symlink or network/download behavior was accepted. Build scripts were read before acceptance; source comparison is not a reproducible-build attestation.

In the table, **C** means GitHub reports the commit signature verified; **T** means a verified annotated release tag; **L** means a lightweight tag; **—** means no matching conventional release tag was found. These observations do not replace an independently managed signing-key policy. Single-account ownership, unsigned commits and missing/lightweight tags remain residual provenance risks.

| Newly selected package | Publisher; current registry owners | Exact upstream commit / tag evidence | Decision |
| --- | --- | --- | --- |
| `android_system_properties 0.1.6` | nical; nical | [`f859a346ba25`](https://github.com/nical/android_system_properties/commit/f859a346ba256d92ef047e7a49d6a2f59972257b); — (unsigned commit) | Accept |
| `block-buffer 0.10.4` | newpavlov; newpavlov, github:rustcrypto:utils | [`6d35952d3d3b`](https://github.com/RustCrypto/utils/commit/6d35952d3d3b124bc1049ad6fb406b42b1ce4bfe); block-buffer-v0.10.4 (C, L) | Accept |
| `chrono 0.4.45` | djc; lifthrasiir, github:chronotope:release-manager | [`170338250e83`](https://github.com/chronotope/chrono/commit/170338250e836976a211e64728ec956e45e78a39); v0.4.45 (T) | Accept |
| `cpufeatures 0.2.17` | tarcieri; tarcieri, github:rustcrypto:utils | [`9d92d5e95ab4`](https://github.com/RustCrypto/utils/commit/9d92d5e95ab4c07c5d8bfd024bf2a17e96d20feb); cpufeatures-v0.2.17 (C, L) | Accept |
| `crypto-common 0.1.7` | newpavlov; newpavlov, github:rustcrypto:traits | [`66a997ccf577`](https://github.com/RustCrypto/traits/commit/66a997ccf5776ce873da5a48e2885a9908e940f6); crypto-common-v0.1.7 (C, L) | Accept |
| `digest 0.10.7` | tarcieri; newpavlov, github:rustcrypto:traits | [`344389411fd9`](https://github.com/RustCrypto/traits/commit/344389411fd9718a0742435152e933a9e71461ee); digest-v0.10.7 (L) | Accept |
| `generic-array 0.14.7` | novacrazy; fizyk20, novacrazy | [`1397d2bb40c4`](https://github.com/fizyk20/generic-array/commit/1397d2bb40c406901b7827161b73b34b056cbe3a); — (unsigned commit) | Accept |
| `iana-time-zone 0.1.65` | GitHub trusted publishing; astraw, Kijewski | [`3726968181ae`](https://github.com/strawlab/iana-time-zone/commit/3726968181ae67d95c8de2f750a95b9c703ae4c8); v0.1.65 (L) | Accept |
| `iana-time-zone-haiku 0.1.2` | astraw; astraw, Kijewski | [`668ef37a8916`](https://github.com/strawlab/iana-time-zone/commit/668ef37a89162b7d24fb1cf8ee90054a8a2f3ad9); haiku/v0.1.2 (C, T) | Accept |
| `oauth2 5.0.0` | ramosbugs; ramosbugs | [`f3424b4b2190`](https://github.com/ramosbugs/oauth2-rs/commit/f3424b4b2190c83c6d031fdc71eed2351d49e0df); 5.0.0 (L) | Accept |
| `ppv-lite86 0.2.21` | kazcw; kazcw | [`000a6cd6bbcb`](https://github.com/cryptocorrosion/cryptocorrosion/commit/000a6cd6bbcb0b091381dc5f8fe6d6efa480b818); ppv-lite86-0.2.21 (L) | Accept |
| `rand 0.8.8` | GitHub trusted publishing; dhardy, github:rust-random:maintainers | [`572d3b0c1760`](https://github.com/rust-random/rand/commit/572d3b0c176085c485b8fa7818a04b769097bd72); 0.8.8 (C, L) | Accept |
| `rand_chacha 0.3.1` | dhardy; dhardy, github:rust-random:maintainers | [`98a0339f99ec`](https://github.com/rust-random/rand/commit/98a0339f99ecfe0467b2829c329bd8b7525a1c21); rand_chacha-0.3.1 (C, L) | Accept |
| `sha2 0.10.9` | newpavlov; tarcieri, newpavlov, github:rustcrypto:hashes | [`82c36a428f8d`](https://github.com/RustCrypto/hashes/commit/82c36a428f8d6f05f3bfccdedb243e9d1f85359d); sha2-v0.10.9 (C, L) | Accept |
| `thiserror 1.0.69` | dtolnay; dtolnay | [`41938bd3a03a`](https://github.com/dtolnay/thiserror/commit/41938bd3a03a70d34ed8e53d99c89c770c7c9c41); 1.0.69 (C, T) | Accept |
| `thiserror-impl 1.0.69` | dtolnay; dtolnay | [`41938bd3a03a`](https://github.com/dtolnay/thiserror/commit/41938bd3a03a70d34ed8e53d99c89c770c7c9c41); 1.0.69 (C, T) | Accept |
| `windows-core 0.62.2` | kennykerr; kennykerr | [`32c3144490c0`](https://github.com/microsoft/windows-rs/commit/32c3144490c016fe496a0aed769bce60987a2e9d); — (unsigned commit) | Resolver-only; see target proof |
| `windows-implement 0.60.2` | kennykerr; kennykerr | [`32c3144490c0`](https://github.com/microsoft/windows-rs/commit/32c3144490c016fe496a0aed769bce60987a2e9d); — (unsigned commit) | Resolver-only; see target proof |
| `windows-interface 0.59.3` | kennykerr; kennykerr | [`32c3144490c0`](https://github.com/microsoft/windows-rs/commit/32c3144490c016fe496a0aed769bce60987a2e9d); — (unsigned commit) | Resolver-only; see target proof |
| `windows-result 0.4.1` | kennykerr; kennykerr | [`32c3144490c0`](https://github.com/microsoft/windows-rs/commit/32c3144490c016fe496a0aed769bce60987a2e9d); — (unsigned commit) | Resolver-only; see target proof |
| `windows-strings 0.5.1` | kennykerr; kennykerr | [`32c3144490c0`](https://github.com/microsoft/windows-rs/commit/32c3144490c016fe496a0aed769bce60987a2e9d); — (unsigned commit) | Resolver-only; see target proof |

## Target reachability: lock entries are not executable dependencies

The full-feature production normal/build inverse graph has exactly this incoming path for the Windows helpers:

```text
SDK → oauth2 → chrono → iana-time-zone → windows-core → windows-strings
```

Chrono 0.4.45 declares its iana-time-zone dependency only under `cfg(unix)`. Iana-time-zone 0.1.65 declares windows-core only under `cfg(target_os = "windows")`. These are normal dependencies in the same target context, with no intervening host build-dependency/proc-macro transition. None of Rust 1.88's 288 built-in targets satisfies both predicates. Consequently windows-core, windows-strings, windows-result, windows-implement and windows-interface are resolved into the lockfile but are not compiled or exposed through this SDK graph.

Independent all-feature normal/build inverse-tree checks were empty on nine representative targets, including i686 MSVC, i686 GNU, x86_64 MSVC, Linux, macOS, Android, Haiku and wasm. The actual managed library also passes Rust 1.88 `cargo check` for **i686-pc-windows-msvc**; Windows support is not disabled. Adding a direct dependency, changing conditional declarations, introducing another incoming path, or changing toolchain target definitions invalidates this proof and requires another review. This conclusion is not approval to use the dormant packages independently.

## Executable and cryptographic surface

The exact OAuth feature selection enables no reqwest/curl/TLS defaults. The managed-only normal tree contains no ring, rustls or webpki. The lockfile still contains optional interop/TLS packages, which a repository-wide advisory audit correctly continues to scan.

The added build scripts are generic-array's compiler/cfg probe, thiserror's compiler capability probe, and Haiku's fixed local C++ timezone helper. Thiserror-impl performs compile-time error-implementation generation. The two new Windows proc-macro packages are in the dormant branch above. No new binary target is introduced; dependency-crate examples/tests/dev-dependencies do not execute during a normal SDK build.

Bounded inspection covers hashing/block-buffer layout and intrinsics, CPU detection, RNG/platform entropy behavior, secret wrappers, timezone FFI/OS files and generated macro output. Unsafe/FFI/SIMD and compiler execution remain trusted boundaries, not formal memory-safety proofs. Optional sha2 assembly support is disabled. Generic-array is legacy and pinned by crypto-common; sole-owner packages and unsigned/lightweight releases warrant re-review on upgrades.

All additions declare permissive `MIT OR Apache-2.0`, except generic-array (`MIT`). Some Windows archives declare licenses in their manifests while the actual texts are at the reconciled upstream repository root; redistributors must retain/provide the required material. No unacceptable license was found; this is not legal advice.

Declared compiler floors do not exceed Rust 1.88. Packages without a declared `rust-version` do not thereby guarantee compatibility; actual Rust 1.88 base/managed/all-feature checks are the functional evidence. Target-union feature lists must not be mistaken for code compiled on every platform.

## Library choice and API coupling

Rmcp 3.5.1 was not selected because of the published RUSTSEC-2026-0457 OAuth SSRF advisory. The adapter instead reuses the smaller audited oauth2 primitive surface and enforces AHP discovery, policy, storage and replay boundaries separately.

The optional module publicly exposes oauth2's `ClientSecret` and HTTP request/response aliases. This is deliberate semver/type coupling confined to the opt-in API, not a claim that the primitive dependency is implementation-private. Exact pinning controls the current choice; upgrades and feature unification need another review. Core provider APIs and wire models do not require the optional feature.

## Inherited advisory baseline

A fresh audit returns nonzero because these findings were already present in `origin/main`:

| Advisory | Locked package | Reported remediation |
| --- | --- | --- |
| RUSTSEC-2025-0009 | ring 0.16.20 | >=0.17.12 |
| RUSTSEC-2024-0336 | rustls 0.20.9 | >=0.23.5 or supported patched branches |
| RUSTSEC-2026-0349 | rustls 0.20.9 | >=0.23.46 |
| RUSTSEC-2026-0382 | rustls-webpki 0.103.15 | >=0.103.16 below the 0.104 alpha line, or >=0.104.0-alpha.8 |
| RUSTSEC-2026-0383 | webpki-root-certs 1.0.9 | >=1.0.10; unaffected =0.26.11 |

The inherited warnings are ring RUSTSEC-2025-0010 and two rustls-pemfile versions under RUSTSEC-2025-0134. None is introduced by the OAuth additions or present in the managed-only normal graph. This does not waive their existing interop/other-feature exposure or an organization's zero-advisory policy.

## Reproduce the bounded checks

```sh
cargo audit --json
cargo +1.88.0 metadata --locked --offline --format-version 1 --no-default-features --features managed-oauth
cargo +1.88.0 tree --locked --no-default-features --features managed-oauth -e normal
cargo +1.88.0 tree --locked --all-features --target all -e normal,build -i windows-strings
cargo +1.88.0 tree --locked --all-features --target i686-pc-windows-msvc -e normal,build -i windows-strings
cargo +1.88.0 check --locked --no-default-features --features managed-oauth --lib
cargo +1.88.0 check --locked --no-default-features --features managed-oauth --target i686-pc-windows-msvc --lib
```

The Windows check requires the matching Rust standard-library target. Offline metadata requires cached registry packages. Reproduce the advisory delta against the baseline lockfile, not merely a prior audit's prose; advisory databases and publisher metadata change over time.
