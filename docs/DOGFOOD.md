# Owner Dogfood Profile

This profile defines the first real Iniza use: protecting the project owner's important developer state before a clean installation of their current Apple Silicon Mac running macOS 26.5.1. It narrows the broader product specifications without weakening their safety rules.

## Must-protect scope

- Every Project discovered beneath `~/Documents/projects`; the initial discovery found 22 repositories. A preliminary metadata-only check on 2026-09-07 found 23 working-repository markers, so the real Plan review must reconcile the changed count rather than assuming the original inventory is still current.
- SSH, Git, Bash, and Zsh configuration.
- Reviewed application configuration beneath explicit roots such as `~/.config`.
- Named high-value files and directories added during Plan review.
- Reviewed static secrets and configuration, certificates, and irreplaceable project uploads.
- Consistent exports of any live databases that the owner marks must-protect.

Every Must-Protect Item must be included and verified. Every required Project must be Restorable and Synchronized. Any excluded, unavailable, unsupported, changed, or unverified must-protect state blocks readiness.

## Optional protection candidates

- Visual Studio Code state is currently unselected because the owner no longer uses the application; it remains a visible Optional Protection Candidate if that decision changes.
- Homebrew package inventory.
- Rust, Bun, and other tool/version inventories.
- Settings normally synchronized by an application account.
- Raw state for applications without a curated recipe.

Account sync is informational, not verified protection. Optional candidates remain visible when unselected. Raw application state may be encrypted into the Bundle, but unsupported restore behavior must be reported.

Downloadable caches, package registries, build outputs, installed toolchain payloads, and Homebrew caches are suggested exclusions.

## Project evidence

Each required Project needs two separate outcomes:

- **Restorable**: its reviewed repository and local-only state round-trips through a verified Project Capsule.
- **Synchronized**: required upstream branches are remotely checked, are not behind, and approved ahead commits are pushed.

Iniza never pulls, merges, rebases, commits, resets, or force-pushes. Local-only branches and tags stay in the Project Capsule unless the owner separately approves publication.

## Recovery and storage

- The official Bitwarden `bw` CLI stores one generated Vaultwarden Recovery Secret in an exact Secure Note and proves that it unlocks the completed Bundle.
- A separately generated Offline Recovery Key is written to owner-selected removable media and independently rehearsed.
- Bundle copy 1 is written to external storage and verified after writing.
- Bundle copy 2 is written to iCloud Drive and independently verified.
- Time Machine and a separately stored direct copy of the most important files remain conventional backups; neither counts as a verified Bundle copy.

The Vaultwarden service is external to the source Mac. Fresh-device sign-in, including an independent MFA recovery path, must be rehearsed. Iniza never receives the Vaultwarden master password.

## Restore rehearsals

1. Restore into an isolated directory or external volume without modifying source state.
2. Restore under a fresh macOS user account or on another Mac where available.
3. Validate file hashes, Project state, portable metadata, disabled hooks, and representative project builds.

## Current prerequisite snapshot

The following observations were collected on 2026-09-07 as preliminary host metadata. They are not Receipts, Owner Attestations, or substitutes for the later real Plan and storage rehearsals.

- The official Bitwarden command-line client version 2026.8.0 is installed and passes Iniza's non-credentialed executable and interpreter review. The real owner-service recovery transaction, fresh-device sign-in, and independent multi-factor recovery confirmation remain incomplete.
- A writable two-terabyte external Universal Serial Bus volume is mounted with approximately 832 gigabytes free and a verified Self-Monitoring, Analysis and Reporting Technology status. It uses exFAT and is only a candidate encrypted Bundle destination: it cannot prove restored macOS ownership or extended metadata, has not been selected by the owner, and cannot also satisfy the separately stored Offline Recovery Key failure domain.
- Time Machine is not running and reports no configured destination. No current conventional-backup validation or representative Restore Attestation has been recorded.
- The documented projects root occupies approximately 16.6 gibibytes before reviewed generated exclusions. The source volume currently reports approximately 3.9 gibibytes available, which is a narrow margin for temporary artifacts and a locally materialized iCloud Verified Copy.
- iCloud Drive is configured, but it shares the same reported local filesystem availability. This check does not prove cloud quota, complete local materialization, upload completion, independent availability, or enough capacity for a Verified Copy.
- The preliminary repository-marker count is 23 rather than the original 22. COKS-40 must use Iniza discovery and owner review to determine whether every current Project is Must-Protect, Optional, excluded with a reason, or unsupported.

## Reviewed Project evidence

On 2026-09-07 the owner approved Project Plan `plan_blake3_83eccc795023f7b06e6f9d55c6545d8f5c2b01283df6a5e3d1ed47f478a1e479`. The approved Plan contains all twenty-three reviewed Project roots as Included and Must-Protect, the exact two hundred approved generated exclusions, thirty-one reviewed symbolic-link inclusions, and the `review-separately` publication policy. It contains no unresolved Must-Protect Plan Disposition.

The post-approval read-only audit reported all twenty-three local observations verified and unchanged and all twenty-three ignored-state inventories Complete. It found 1,319 current ignored candidates retained for later encrypted Project Capsule review and 712,885 ignored entries covered by exact approved Plan exclusions. The prior direct inventory counted 1,320 retained candidates; the current complete audit is authoritative for the approved Plan, but the one-item snapshot drift remains recorded rather than silently normalized.

The approved capsule-only reference manifest still matched all fifteen branches and seventeen tags by exact local object identifier. Those references remain unpublished and require verified Project Capsule protection. One `cashsynq` existing-upstream non-force action was prepared as immutable Push Plan `push_plan_blake3_b0adf61d28d24473a8bbde184c44e47057766c9b88bcc981d86b9f4142a58a2a`; it was neither approved nor executed. Push Plans expire after fifteen minutes and must be regenerated before later review when stale.

Project synchronization remains incomplete: `cashsynq` has one unpublished ahead commit, `beyond-scences` is three commits behind its locally known upstream, four current branches have no upstream, and the `halferpay/halferpay-core` remote check failed. Iniza does not reconcile these states. Owner Dogfood remains blocked until required Projects are both Restorable and Synchronized or an accepted capsule-only decision satisfies the local-only-reference rule.

## Dependency security evidence

On 2026-09-07 cargo-audit 0.22.2 checked the exact committed `Cargo.lock` against 1,240 advisories at RustSec database commit `faedffd5118c1835e13cca3babb6059afb1eb8d0`. All 98 locked dependencies passed with zero vulnerabilities and zero informational, unmaintained, unsound, notice, or yanked-package warnings while `--deny warnings` was active. The reproducible inputs and command are recorded in [the Owner Dogfood RustSec audit](research/owner-dogfood-rustsec-audit-2026-09-07.md).

This automated result does not replace the independent cryptographic, parser, and key-lifecycle review required by ADR 0005. Real sole-copy owner data remains outside the currently accepted format scope.

Owner Dogfood remains blocked until the external storage, conventional backups, current Project inventory, both Recovery Methods, and required rehearsals are present and verified.

## Completion rule

The final status aggregates machine-verifiable Receipts and explicit Owner Attestations. It may report that Bundle verification and recovery testing succeeded. It never decides or states that the Mac is safe to erase.
