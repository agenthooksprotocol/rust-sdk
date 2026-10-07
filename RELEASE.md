# Rust SDK releases

This repository releases independently of the other SDKs. Release Please updates
`Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, and its version manifest in a release PR.
The manifest starts at `0.0.0`, the sentinel for no previous automated release.
`initial-version` sets the first release to `0.1.0` and only affects that first
release; subsequent versions follow Conventional Commits.

## One-time setup

1. Use the existing **Agent Hooks Protocol Bot** GitHub App. Install it on this
   repository with **Contents: read/write** and **Pull requests: read/write**.
   Set Actions variable **`RELEASE_APP_ID`** to its App ID and Actions secret
   **`RELEASE_APP_PRIVATE_KEY`** to a PEM private key generated in its settings.
   Organization-level values may be shared with just the four SDK repositories.
   The workflow mints a short-lived installation token scoped to this repository
   and those two permissions; it is revoked when the job ends. Release PRs,
   tags, and GitHub releases use the bot identity and trigger normal PR CI.
   No personal access token is needed. Keep branch protection enabled.
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
- Keep the manifest at the last released version. The `initial-version` setting
  can remain in place; no follow-up configuration change is needed.
- Publishing failure does not roll back the GitHub release. Resolve the cause
  and re-run the failed **publish** job in its original run, preserving its
  release outputs. Do not re-run the successful Release Please job or move tags;
  already published crate versions cannot be overwritten.

No release/tag-triggered publisher, install tests, registry probes, or
post-publish verification jobs are added.

## Contract compatibility notification

After the complete **Release** workflow succeeds for a `main` push, the separate
`release-notify.yml` workflow sends a `sdk-released` repository dispatch to
`agenthooksprotocol/agent-hooks-protocol`. It requires the `publish` job from that exact run attempt to have succeeded. It also checks that a
non-draft, non-prerelease GitHub release has a stable version tag pointing at that
exact workflow run head, including annotated tag dereferencing. Ordinary Release
Please PR updates do not send a notification.

The notification triggers compatibility CI directly in the contract repository.
For release dispatches, the receiver snapshots the latest stable SDK releases;
normal CI snapshots SDK `main` heads. All integration shards use the same exact
revisions recorded in an artifact, without tracked pin updates or bot PRs.
The sender includes the repository, revision, and run ID. This is event-driven:
the notifier adds no schedule, registry probe, package installation, or publishing
step.
The notifier does not check out or execute SDK code. Its repository token has only
Actions and Contents read access for release metadata; a separate short-lived App
token has only Contents write access to the contract repository for dispatch.

The existing `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY` must identify an App
installed on **agenthooksprotocol/agent-hooks-protocol** with **Contents: read/write**,
in addition to its existing SDK installation. The notifier explicitly scopes the
App token to that target repository and revokes it at job completion. Installing
this workflow does not replay earlier releases (including the initial `0.1.0`);
after the receiver is merged, run the contract integration workflow manually for
existing releases instead of rerunning a publishing workflow.
