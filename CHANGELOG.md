# Changelog

## Unreleased

- Check original structural descriptors at generated Serde decode boundaries, preserving the richer `parse_*` diagnostics API. Direct decoding is stricter; primitive constrained aliases can become transparent newtypes.
- Add schema-derived `EffectId` and typed, allocation-free `Capabilities::supports` effect-family membership queries, including custom identifiers, without changing authorization or admission policy. `capability::EffectType` aliases `EffectId`; `as_str()` is retained, but the identifier is no longer a closed `Copy` enum.

## [0.1.1](https://github.com/agenthooksprotocol/rust-sdk/compare/v0.1.0...v0.1.1) (2026-10-07)


### Bug Fixes

* expose models and codecs at the crate root ([#9](https://github.com/agenthooksprotocol/rust-sdk/issues/9)) ([9567fe9](https://github.com/agenthooksprotocol/rust-sdk/commit/9567fe9ade3d08a0033ee540b5fe6f525a49dbc6))

## 0.1.0 (2026-10-07)


### Features

* bootstrap Rust SDK ([c042aa4](https://github.com/agenthooksprotocol/rust-sdk/commit/c042aa4ba08ac667e8cb9362b5b2e898e41854bf))
* implement draft boundary runtimes and authenticated adapters ([#3](https://github.com/agenthooksprotocol/rust-sdk/issues/3)) ([6e7922c](https://github.com/agenthooksprotocol/rust-sdk/commit/6e7922c3afd7b9bcad042c8c73b350ddd4c9f357))
* provide the public Rust SDK and lazy event runtime ([#5](https://github.com/agenthooksprotocol/rust-sdk/issues/5)) ([782881d](https://github.com/agenthooksprotocol/rust-sdk/commit/782881d12ccdc7de4023afe805973a9766cd9562))


### Bug Fixes

* add SDK usage documentation ([ab47b1d](https://github.com/agenthooksprotocol/rust-sdk/commit/ab47b1d27a206ddb8a55b27e5a9f7595901f3108))
* align portable authentication with bearer and OAuth ([#4](https://github.com/agenthooksprotocol/rust-sdk/issues/4)) ([0c4579b](https://github.com/agenthooksprotocol/rust-sdk/commit/0c4579bce64108f2521870b1f9e58b07d9c38629))
* keep SDK documentation focused ([4d776fc](https://github.com/agenthooksprotocol/rust-sdk/commit/4d776fc473803d75c51942c3148cde047153cfac))
* preserve exact JSON numbers ([89198b4](https://github.com/agenthooksprotocol/rust-sdk/commit/89198b4a1d86513a8bba85ee3ef014dd315525f4))
