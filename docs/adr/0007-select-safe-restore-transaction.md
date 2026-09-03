# Select the authenticated new-destination Restore transaction

- Status: Accepted for synthetic and duplicated data; Owner Dogfood gates remain
- Date: 2026-09-01
- Issue: COKS-29

## Context

A Bundle can authenticate content while still carrying hostile names, symbolic-link targets, filesystem metadata, executable content, or resource claims. The destination can also change after preflight. Restore therefore needs a transaction boundary that does not trust protected metadata before Bundle authentication, does not overwrite existing content, never executes restored bytes, and leaves an understandable recovery state after interruption.

This decision selects the reusable Rust core transaction. Recovery Secret acquisition and the supported command-line adapter remain COKS-33 and COKS-36. This decision does not authorize sole-copy or real owner data.

## Decision

`RestoreEngine::restore(RestoreRequest) -> RestoreReport` is the public core seam. A request borrows an in-memory `RecoverySecret`, identifies one sealed Bundle and one destination, defaults to a new transaction, and may provide a path-free event sink and cancellation boundary. Resume is an explicit request mode. `DestinationCapacity` remains the injectable capacity seam.

### Authenticate before trust

Restore opens the Bundle once with no-follow semantics and keeps that file handle for both authentication passes. It authenticates the IZ2 header, selected Recovery Method, encrypted Manifest, Index, Completion, record ordering, and whole encrypted prefix before it interprets any protected path, type, count, size, or metadata. The first pass returns only authenticated internal Restore data. Content is decrypted in a second streaming pass from the same opened file into staging; every record authentication tag, item digest, chunk order, and logical size must pass again before publication. The independently computed whole-Bundle hashes from both passes must match. Replacing the source pathname cannot redirect the second pass, and mutation of the opened Bundle fails closed without publication.

### Bounded path planning

Planning rejects more than 100,000 Manifest entries, paths longer than 4,096 bytes or 128 components, and more than 16 tebibytes of declared regular-file data. Writes accept only normal relative components. Absolute paths, parent traversal, the reserved `.iniza-restore` subtree, duplicate names, case-fold collisions, and canonically equivalent Unicode names are rejected before destination creation.

Authenticated device, socket, and unknown filesystem-item evidence blocks Restore. Symbolic-link targets must be relative and must remain inside the destination under lexical resolution; targets that escape or address transaction control are rejected. A destination identity is recorded after creation or resume validation and checked immediately before publication, detecting a rename, mount-like replacement, or symbolic-link substitution at the tested boundary.

### Staging and publication

A new Restore accepts an absent or empty directory only. The destination, transaction control at `.iniza-restore`, and staging directories are created with mode `0700` in the creation operation; staged regular files are created and explicitly held at mode `0600` with no-follow semantics on supported Unix systems. File and directory creation, bounded enumeration, validation, cleanup, metadata application, and publication are relative to retained directory capabilities. Enumeration streams entries, retains no queued child-directory descriptors, and stops when the authenticated entry-count or path-depth bound is exceeded. Materialization and finalization use a bounded one-item descriptor window rather than retaining one descriptor per Migration Item. The full staged tree must exactly match the authenticated Plan, and every regular-file size, content hash, restrictive validation mode, device identity, and inode identity is recorded or revalidated before publication and again after each top-level publication move before its durable completion checkpoint. During finalization, Restore reopens one item at a time with no-follow semantics, requires its stable identity to match, rehashes regular-file content, and applies reviewed modes and metadata through that same checked descriptor, with execute bits removed. Before transaction control is removed, Restore re-enumerates the exact final tree, rechecks symbolic-link targets, and proves each visible path still names the validated filesystem object.

Top-level staged entries are moved with the operating system's atomic no-replace rename primitive: `renameatx_np` with `RENAME_EXCL` on macOS and `renameat2` with `RENAME_NOREPLACE` on Linux. Targets are preflighted and ordered deterministically. A durable authenticated intent precedes each move and a durable completion checkpoint follows it. A conflict before publication removes only Iniza-owned transaction artifacts; a failure or interruption after publication begins retains authenticated recovery state. No overwrite or merge flag exists.

The selected production architecture is descriptor-relative: record the destination identity, open a directory capability, verify that the opened descriptor has exactly the recorded identity before emitting a secured-destination event or writing any child, then retain that capability for the transaction. Child directories and files are opened or created with no-follow semantics. Lookup, creation, metadata application, publication, recovery, and cleanup proceed through retained capabilities. The Rust core uses `cap-std` for capability-relative traversal and explicit platform no-replace rename operations. A destination-path substitution can stop publication but cannot redirect decrypted staging, metadata, or cleanup into the substituted path.

### Interruption, journal, and recovery boundaries

An authenticated materialization checkpoint is durable before decrypted files are written. Cancellation is observed only after all staged content validates and an authenticated journal is durable, and again after every top-level publication checkpoint. The journal contains no paths, names, content, or Recovery Secret. Journal schema version 2 binds the whole encrypted-Bundle BLAKE3 hash, staged item count, staged byte count, transaction phase, completed top-level count, and optional publication or rollback intent with a domain-separated keyed BLAKE3 tag derived from the borrowed Recovery Secret. Journal files are synchronized before atomic replacement, their containing directory is synchronized after every replacement, and an interrupted leftover partial journal is discarded only after the previous journal authenticates.

Resume first reauthenticates the Bundle. A non-empty destination is accepted only when it contains `.iniza-restore` plus the exact authenticated top-level prefix recorded by the journal, transaction control contains exactly the authenticated journal, staging, and at most one interrupted partial-journal replacement, the staging entry is a real directory, the journal is bounded and canonical, its tag authenticates with the supplied Recovery Secret, and its Bundle identity and counts match the authenticated Manifest. A visible item's mode must be either the restrictive validation mode or its exact authenticated final mode. Resume normalizes an already-applied final mode back to the restrictive mode with a descriptor-relative no-follow operation, working from parent directories toward children, then reauthenticates every visible published entry before moving or removing it. An outstanding publication or rollback intent is reconciled from the source and target entries without trusting the pathname. Published entries are moved back through directory capabilities with a write-ahead rollback intent and a durable completion checkpoint after every move, then staging is rebuilt from the authenticated Bundle. This makes interruption during mode finalization recoverable and remains a safe restart from durable item boundaries rather than partial-file continuation.

Before publication, failure removes only known transaction control through the retained destination capability and retains the empty outer destination. Restore never deletes that outer pathname during failure cleanup, because a concurrent pathname substitution could otherwise make cleanup delete unrelated data. After a publication intent becomes durable, every error, cancellation, or abrupt interruption retains the journal and staging for explicit resume. Cleanup failures are returned rather than ignored. Once exclusive publication succeeds, content is authenticated and trusted; cleanup never invokes it.

### Metadata and executable content

IZ2 encrypted Manifest schema revision 2 adds optional Portable Operating System Interface modes, symbolic-link targets, bounded extended attributes, and access-control text. Revision 1 remains readable; missing metadata evidence is reported rather than invented.

Regular-file and directory modes round-trip where supported, including regular-file modes without owner-read permission. Regular files remain owner-readable only through candidate authentication; the reviewed final mode is applied through the already-open file descriptor afterward. Safe symbolic links are recreated only when their Plan disposition was explicitly changed to Included, and links are never followed during capture or Restore. The macOS adapter applies bounded extended attributes and extended access-control entries through open file or directory descriptors. Ownership is never applied. Missing, unsupported, malformed, symbolic-link, or failed metadata application increments `unapplied_metadata` in the report. Fallible nested-directory modes are applied while the authenticated recovery journal remains present; failure to apply the destination-root mode after transaction cleanup is reported as unapplied metadata rather than turning authenticated published content into an unrecoverable error.

Every regular file carrying an execute bit is restored with execute bits removed. Repository hooks are identified beneath `.git/hooks`, remain disabled, and are counted separately. Original reviewed modes remain authenticated metadata for a later explicit approval workflow. Restore never launches content or invokes Git hooks.

### Automation contract

`RestoreReport` has deterministic human and versioned one-line JavaScript Object Notation renderers. Reports expose state, counts, bytes, disabled hooks, quarantined executables, and unapplied metadata, but structurally omit paths, names, content, journals, and Recovery Secrets. `RestoreEvent` emits versioned path-free JavaScript Object Notation Lines. Supported command-line secret acquisition and final exit-code mapping remain downstream adapters and must not add Recovery Secrets to arguments, environment variables, ordinary files, or output.

### Future merge boundary

In-place merge is a different operation, not a flag on this transaction. It requires an authenticated dry run, explicit per-conflict owner choices, recoverable backups, a rollback journal, destination snapshot assumptions, and a separate architecture decision. This new-destination implementation must never silently become merge-capable.

## Evidence

- Exact-byte, empty-file, empty-directory, Portable Operating System Interface mode, safe symbolic-link, macOS extended-attribute, and macOS access-control round trips.
- Wrong Recovery Secret, non-canonical or unauthenticated journal, same-handle Bundle mutation, Bundle-path replacement, escaping symbolic link, device/socket evidence, case collision, Unicode-normalization collision, destination identity replacement, staged-directory substitution, same-size staged-content substitution, unplanned or overdeep staged content, publication-candidate content or executable-mode substitution before and after its checkpoint, owner-unreadable reviewed mode, non-empty destination conflict classification, insufficient capacity, destination race, and permission-loss faults.
- Restrictive creation, descriptor-relative containment, no-overwrite exclusive publication, disabled repository hooks, quarantined executable content, authenticated staging pause/resume, publication pause/resume, abrupt-interruption resume, interrupted final-mode recovery, and unrelated destination rejection.
- Deterministic path-free report and event rendering.
- Checked-in IZ2 revision-1 golden compatibility and the complete existing cryptographic, Bundle, Plan, Project audit, fixture, and command-line suites.

## Consequences

- COKS-29 proves the core transaction with synthetic and duplicated data. It does not make Owner Dogfood ready and does not state that a Mac is safe to erase.
- Linux extended metadata, filesystem durability certification across supported filesystem types, fuzzing, and independent security review remain gates before real owner data.
- Supported command-line Restore, Recovery Secret acquisition, Receipts, and readiness aggregation remain later issues.
- Resume rebuilds authenticated staging rather than continuing within a partially written file.

## Owner decision

- [x] I approve the hardened Restore transaction, its synthetic-only scope, and the remaining gates.
- Owner: Kwaame Ofori-adjekum
- Decision date: 2026-09-03
- Notes: The original decision was approved on 2026-09-01. The owner confirmed and approved the descriptor-relative, authenticated-resume, and resumable-publication hardening. Acceptance does not authorize sole-copy data, real Owner Dogfood, machine erasure, or removal of independent backups.
