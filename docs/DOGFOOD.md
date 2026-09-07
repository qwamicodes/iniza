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

- VS Code settings, keybindings, snippets, and extension inventory.
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

Owner Dogfood remains blocked until the external storage, conventional backups, current Project inventory, both Recovery Methods, and required rehearsals are present and verified.

## Completion rule

The final status aggregates machine-verifiable Receipts and explicit Owner Attestations. It may report that Bundle verification and recovery testing succeeded. It never decides or states that the Mac is safe to erase.
