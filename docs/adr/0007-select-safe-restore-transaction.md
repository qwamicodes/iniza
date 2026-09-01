# Select the authenticated new-destination Restore transaction

- Status: Accepted for synthetic and duplicated data; Owner Dogfood hardening still required
- Date: 2026-09-01
- Issue: COKS-29

## Context

A Bundle can authenticate content while still carrying hostile names, symbolic-link targets, filesystem metadata, executable content, or resource claims. The destination can also change after preflight. Restore therefore needs a transaction boundary that does not trust protected metadata before Bundle authentication, does not overwrite existing content, never executes restored bytes, and leaves an understandable recovery state after interruption.

This decision selects the reusable Rust core transaction. Recovery Secret acquisition and the supported command-line adapter remain COKS-33 and COKS-36. This decision does not authorize sole-copy or real owner data.

## Decision

`RestoreEngine::restore(RestoreRequest) -> RestoreReport` is the public core seam. A request borrows an in-memory `RecoverySecret`, identifies one sealed Bundle and one destination, defaults to a new transaction, and may provide a path-free event sink and cancellation boundary. Resume is an explicit request mode. `DestinationCapacity` remains the injectable capacity seam.

### Authenticate before trust

Restore opens and authenticates the IZ2 header, selected Recovery Method, encrypted Manifest, Index, Completion, record ordering, and whole encrypted prefix before it interprets any protected path, type, count, size, or metadata. The first pass returns only authenticated internal Restore data. Content is decrypted in a second streaming pass into staging; every record authentication tag, item digest, chunk order, and logical size must pass again before publication. A Bundle change between the passes fails closed and publishes nothing.

### Bounded path planning

Planning rejects more than 100,000 Manifest entries, paths longer than 4,096 bytes or 128 components, and more than 16 tebibytes of declared regular-file data. Writes accept only normal relative components. Absolute paths, parent traversal, the reserved `.iniza-restore` subtree, duplicate names, case-fold collisions, and canonically equivalent Unicode names are rejected before destination creation.

Authenticated device, socket, and unknown filesystem-item evidence blocks Restore. Symbolic-link targets must be relative and must remain inside the destination under lexical resolution; targets that escape or address transaction control are rejected. A destination identity is recorded after creation or resume validation and checked immediately before publication, detecting a rename, mount-like replacement, or symbolic-link substitution at the tested boundary.

### Staging and publication

A new Restore accepts an absent or empty directory only. Transaction control lives at `.iniza-restore`; its staging directories use mode `0700` and staged regular files use mode `0600` with no-follow creation on supported Unix systems. Content hashes and sizes are validated before publication.

Top-level staged entries are moved with the operating system's atomic no-replace rename primitive: `renamex_np` with `RENAME_EXCL` on macOS and `renameat2` with `RENAME_NOREPLACE` on Linux. Targets are preflighted and ordered deterministically. If a later top-level publication conflicts, earlier top-level names are moved back into staging. No overwrite or merge flag exists.

The selected production architecture is descriptor-relative: open the destination and transaction directories once with no-follow semantics, retain their identities, and perform child lookup, creation, metadata application, and publication through directory descriptors. The current Rust prototype proves authenticated staging, destination identity checks, no-follow regular-file creation, and exclusive same-filesystem publication. It still uses path-based metadata calls and child traversal. Owner Dogfood with real data remains blocked until a platform adapter replaces those calls with descriptor-relative operations and receives focused race review.

### Interruption, journal, and recovery boundaries

Cancellation is observed only after all staged content validates and an authenticated journal is durable. The journal contains no paths, names, content, or Recovery Secret. It binds schema version, whole encrypted-Bundle BLAKE3 hash, staged item count, and staged byte count with a domain-separated keyed BLAKE3 tag derived from the borrowed Recovery Secret.

Resume first reauthenticates the Bundle. A non-empty destination is accepted only when its sole entry is `.iniza-restore`, transaction control contains exactly `journal.json` and `staging`, the staging entry is a real directory, the journal is bounded and canonical, its tag authenticates with the supplied Recovery Secret, its Bundle hash matches, and its item count matches the authenticated Manifest. The prototype then rebuilds staging from the authenticated Bundle before publication. This is a safe restart from a durable boundary rather than a partial-chunk continuation.

Before publication, failure removes only known transaction control and an engine-created empty destination. Permission recovery is attempted for an engine-created destination so cleanup can finish. After the journaled boundary, cancellation retains the journal and staging for explicit resume. Once exclusive publication succeeds, content is authenticated and trusted; cleanup never invokes it.

### Metadata and executable content

IZ2 encrypted Manifest schema revision 2 adds optional Portable Operating System Interface modes, symbolic-link targets, bounded extended attributes, and access-control text. Revision 1 remains readable; missing metadata evidence is reported rather than invented.

Regular-file and directory modes round-trip where supported. Safe symbolic links are recreated without following them. The macOS adapter round-trips bounded extended attributes and extended access-control entries. Ownership is never applied. Missing, unsupported, malformed, or failed metadata application increments `unapplied_metadata` in the report.

Every regular file carrying an execute bit is restored with execute bits removed. Repository hooks are identified beneath `.git/hooks`, remain disabled, and are counted separately. Original reviewed modes remain authenticated metadata for a later explicit approval workflow. Restore never launches content or invokes Git hooks.

### Automation contract

`RestoreReport` has deterministic human and versioned one-line JavaScript Object Notation renderers. Reports expose state, counts, bytes, disabled hooks, quarantined executables, and unapplied metadata, but structurally omit paths, names, content, journals, and Recovery Secrets. `RestoreEvent` emits versioned path-free JavaScript Object Notation Lines. Supported command-line secret acquisition and final exit-code mapping remain downstream adapters and must not add Recovery Secrets to arguments, environment variables, ordinary files, or output.

### Future merge boundary

In-place merge is a different operation, not a flag on this transaction. It requires an authenticated dry run, explicit per-conflict owner choices, recoverable backups, a rollback journal, destination snapshot assumptions, and a separate architecture decision. This new-destination implementation must never silently become merge-capable.

## Evidence

- Exact-byte, empty-file, empty-directory, Portable Operating System Interface mode, safe symbolic-link, macOS extended-attribute, and macOS access-control round trips.
- Wrong Recovery Secret, Bundle mutation between passes, escaping symbolic link, device/socket evidence, case collision, Unicode-normalization collision, destination identity replacement, insufficient capacity, destination race, and permission-loss faults.
- Restrictive staging, no-overwrite exclusive publication, disabled repository hooks, quarantined executable content, authenticated pause/resume, and unrelated destination rejection.
- Deterministic path-free report and event rendering.
- Checked-in IZ2 revision-1 golden compatibility and the complete existing cryptographic, Bundle, Plan, Project audit, fixture, and command-line suites.

## Consequences

- COKS-29 proves the core transaction with synthetic and duplicated data. It does not make Owner Dogfood ready and does not state that a Mac is safe to erase.
- Full descriptor-relative traversal and metadata application, Linux extended metadata, filesystem durability certification, fuzzing, and independent security review remain gates before real owner data.
- Supported command-line Restore, Recovery Secret acquisition, Receipts, and readiness aggregation remain later issues.
- Resume currently rebuilds authenticated staging rather than continuing within a partially written file.

## Owner decision

- [x] I approve the Restore transaction, its synthetic-only scope, and the listed hardening gates.
- Owner: Kwaame Ofori-adjekum
- Decision date: 2026-09-01
- Notes: Approved in the COKS-29 implementation thread. Approval does not authorize sole-copy data, real Owner Dogfood, machine erasure, or removal of independent backups.
