# Rust SDK releases

This repository releases independently of the other SDKs. Release Please updates
`Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, and its version manifest in a release PR.
The manifest starts at the current source version, `0.0.0`; `release-as` forces the
first automated release to `0.1.0`.

## One-time setup

1. Add the repository Actions secret `RELEASE_PLEASE_TOKEN`: a fine-grained GitHub
   PAT limited to `agenthooksprotocol/rust-sdk`, with **Contents: read/write** and
   **Pull requests: read/write**. Approve it for the organization if required.
   Using a PAT lets release PRs trigger normal PR checks. Keep existing branch
   protection and required CI checks enabled.
2. Create the GitHub environment **release**, restrict deployments to **main**,
   and configure required reviewers as appropriate. The workflow runs on main
   but checks out the exact release commit for publishing.
3. Ensure a maintainer owns the `agenthooksprotocol` crate on crates.io.
   **Trusted publishing cannot create a new crate**: the
   [official documentation](https://crates.io/docs/trusted-publishing) requires an
   initial API-token publication. If the crate has never been published, an
   authorized maintainer must first publish the approved `0.0.0` baseline from
   this publishing-enabled configuration using `cargo publish --locked` and a
   locally supplied, narrowly scoped crates.io API token. Do this before merging
   the first automated release PR. Do not store that bootstrap token in GitHub.
   If the crate already exists, no bootstrap publication is needed.
4. In the crate's **Settings → Trusted Publishing**, add a GitHub publisher:
   - Repository owner: `agenthooksprotocol`
   - Repository name: `rust-sdk`
   - Workflow filename: `release.yml` (not its full path)
   - Environment: `release`

The registry prerequisites were checked against the
[official crates.io documentation source](https://github.com/rust-lang/crates.io/blob/main/svelte/src/routes/docs/trusted-publishing/+page.svelte).
There are no automated registry probes or bootstrap publications.

## Release lifecycle

- Use Conventional Commits (`fix:`, `feat:`, and breaking-change markers).
- Each push to main calls the existing CI workflow. Only after it succeeds does
  Release Please create or update the release PR, or create the GitHub release
  after that PR merges.
- Review and merge the release PR through normal branch protection. When Release
  Please reports a newly created release, the same workflow publishes its exact
  commit using `rust-lang/crates-io-auth-action` and `cargo publish --locked`.
  Only the publish job can request an OIDC token. Environment approval, if
  configured, happens before that job starts.
- After `0.1.0` is released, remove `release-as` from
  `release-please-config.json` in a follow-up PR so later versions follow
  Conventional Commits. Keep the manifest at the last released version.
- Publishing failure does not roll back the GitHub release. Resolve the cause
  and re-run the failed **publish** job in its original run, preserving its
  release outputs. Do not re-run the successful Release Please job or move tags;
  already published crate versions cannot be overwritten.

No release/tag-triggered publisher, install tests, registry probes, or
post-publish verification jobs are added.
