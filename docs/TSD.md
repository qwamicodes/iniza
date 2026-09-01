# Iniza Technical Specification Document

**Status:** Revised architecture baseline
**Implementation language:** Rust
**Initial interfaces:** Interactive and non-interactive CLI
**Initial platforms:** macOS and Linux

## 1. Purpose

This document defines the architecture for Iniza’s CLI-first implementation. It replaces the earlier SwiftUI-first MoveMyMac architecture. The Rust core owns discovery, planning, encryption, bundle parsing, Git project protection, restore transactions, verification, and connector orchestration. Future desktop clients call the same public core API.

## 2. Design drivers

### Functional drivers

- Scan explicit roots and supported configuration recipes.
- Audit Git repositories and preserve local-only state.
- Separate optional remote Git synchronization from local bundle protection.
- Create a versioned encrypted `.iniza` bundle.
- Protect the bundle key through Bitwarden and an offline recovery method.
- Verify bundles and copies without extraction.
- Restore safely across compatible macOS and Linux destinations.
- Produce receipts and an explicit **Not Protected** report.

### Quality drivers

- Fail closed on authentication or structural ambiguity.
- Stream data; do not load entire projects into memory.
- Resume long writes and restores from authenticated checkpoints.
- Treat every bundle and repository as untrusted input.
- Keep secrets out of logs, arguments, configuration, and diagnostics.
- Make operations deterministic and machine-readable.
- Never silently overwrite files or publish Git refs.

## 3. Scope

### MVP

- Rust CLI and reusable Rust core
- macOS and Linux
- Explicit paths, SSH, Git config, shell config
- Project discovery and capsules
- Optional reviewed pushes through installed Git
- `.iniza` format version 0
- Bitwarden through installed official `bw` CLI
- Offline recovery key
- Local, removable, NAS, and filesystem-synchronized destinations
- New-directory restore, validation, receipts, and verified copies

### Deferred

- SwiftUI or other desktop shell
- Windows
- Hosted services
- Licensing and purchase flows
- Additional password managers
- Direct Git provider APIs
- Arbitrary executable recipes
- Live database and Docker-volume capture
- In-place merge restore

## 4. Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                         iniza CLI                           │
│ interactive flow · flags · JSON · terminal rendering       │
└──────────────────────────────┬──────────────────────────────┘
                               │ typed commands/events
┌──────────────────────────────▼──────────────────────────────┐
│                       iniza-core                            │
│ coordinator · domain model · policies · receipts           │
├──────────────┬───────────────┬──────────────┬───────────────┤
│ scan/recipe  │ project/git   │ bundle/crypto│ restore       │
├──────────────┴───────────────┴──────────────┴───────────────┤
│ platform adapters · connector interfaces · protected state │
└──────────────┬──────────────────────┬───────────────────────┘
               │ subprocess boundary  │ filesystem boundary
        ┌──────▼──────┐         ┌─────▼────────────────────┐
        │ git / bw    │         │ source, bundle, restore │
        └─────────────┘         └──────────────────────────┘
```

### Ownership rules

- `iniza-cli` owns parsing, prompts, rendering, and process exit codes.
- `iniza-core` owns orchestration and policy; it contains no terminal rendering.
- `iniza-bundle` owns parsing and serialization.
- `iniza-crypto` owns key derivation, slots, encryption, signatures, and secret types.
- `iniza-projects` owns repository discovery, audit, capsule generation, and Git command planning.
- `iniza-connectors` owns connector traits; Bitwarden is its first implementation.
- `iniza-platform` owns platform paths and metadata adapters.
- No UI, connector, or platform layer may implement alternate bundle cryptography.

## 5. Repository layout

```text
iniza/
├── Cargo.toml
├── crates/
│   ├── iniza-cli/
│   ├── iniza-core/
│   ├── iniza-bundle/
│   ├── iniza-crypto/
│   ├── iniza-scan/
│   ├── iniza-projects/
│   ├── iniza-connectors/
│   ├── iniza-platform/
│   └── iniza-testkit/
├── docs/
├── fixtures/
│   ├── sources/
│   ├── repositories/
│   ├── bundles/
│   └── adversarial/
└── fuzz/
```

The first scaffold may begin with fewer crates. Boundaries should be extracted when code begins to mix policy, I/O, and format concerns—not merely to match this tree.

## 6. Core domain model

```rust
struct MigrationId(Uuid);
struct BundleId(Uuid);
struct ItemId(String);
struct ProjectId(String);
struct ChunkId(u64);

enum ItemDisposition {
    Included,
    Excluded,
    RequiresReview,
    Unsupported,
    Unavailable,
}

enum ProtectionRequirement {
    MustProtect,
    Optional,
}

enum Portability {
    Portable,
    MacOsOnly,
    LinuxOnly,
    ManualMapping,
}

enum VerificationState {
    NotRun,
    Verified,
    Warning,
    Failed,
}
```

### Migration item

A migration item contains stable identity, recipe or explicit-path origin, logical and original paths, kind, sensitivity, portability, estimated size, source metadata, disposition, exclusion reason, and validation rules.

### Logical paths

Manifests store tokens rather than assuming usernames:

- `$HOME`
- `$CONFIG`
- `$CACHE`
- `$DATA`
- `$PROJECTS/<root-id>`

The original path is retained for audit. Automatic restore uses only mappings valid for the destination platform.

## 7. Operation state machines

### Plan

```text
Draft → Scanning → ReviewRequired → Approved
           │              │
           └── Failed     └── Revised → Approved
```

### Bundle

```text
Absent → Writing → Sealed → Verified → CopiedAndVerified
             │        │         │
             ├ Partial└ Invalid └ VerificationFailed
             └ Failed
```

Only `Sealed` bundles contain an authenticated completion footer. Partial files use a distinct suffix and are never accepted by normal restore.

### Restore

```text
Planned → Preflight → Writing → Validating → Complete
              │          │          │
              └ Blocked  ├ Paused   └ ValidationFailed
                         └ Failed → Rollback/Resume
```

## 8. Scan and plan engine

### Scan phases

1. Resolve and validate user-approved roots.
2. Perform shallow metadata discovery without following unsafe symlinks.
3. Apply recipe candidates and platform mapping.
4. Discover repositories beneath approved project roots.
5. Classify ignored and generated content.
6. Detect unsupported-risk indicators such as databases, Docker state, sockets, and unreadable paths.
7. Estimate size and output capacity.
8. Write `iniza.toml` and a machine-readable plan snapshot.

### Plan invariants

- Every selected path is beneath an approved root or a known recipe root.
- Directory Plan schema version 2 records the approved root, each Migration Item and its stable identifier, recipes, exclusions, destination preference, publication policy, and mount-crossing policy.
- Every item has a Protection Requirement independent of its Disposition; unresolved Must-Protect Items block Owner Dogfood readiness.
- Every item has exactly one Disposition: Included, Excluded, Requires Review, Unsupported, or Unavailable. Requires Review, Unsupported, and Unavailable Optional items produce warnings instead of Must-Protect blockers.
- Canonicalization failures remain review items; they are not guessed.
- Exclusions record origin: built-in, recipe, plan, command line, or user review.
- Secret values and file contents never enter the plan.
- Plans have a schema version and deterministic TOML representation. The canonical approval hash covers every approval-relevant field and excludes only the stored approval metadata.
- An approval binds the reviewed canonical hash. A mismatched hash is rejected, and editing an approval-relevant field makes an existing approval stale.
- Human comparison output may identify reviewed relative paths. Machine comparison output uses change kinds and stable Migration Item identifiers so automation does not receive source paths by default.

### Change detection

Before reading a file, capture identity, size, modification time, and platform-specific file identifier where available. Recheck after capture. Retry bounded times; otherwise mark the item changed and prevent a clean readiness result.

Directory discovery does not follow symbolic links. A mount boundary is a visible Requires Review item unless the Plan explicitly enables traversal. Unreadable roots and items, special files, observations that change during discovery, and failures to inspect an entry remain visible as blocking or warning classifications rather than disappearing from coverage.

## 9. Recipe system

MVP recipes are compiled, declarative definitions shipped with Iniza. External community recipes are deferred.

A recipe can declare:

- Candidate paths by platform
- File types and traversal limits
- Default exclusions
- Sensitivity and portability
- Restore path mappings
- Permission expectations
- Validation checks

A recipe cannot execute arbitrary shell commands. Git-specific operations are implemented by the reviewed project adapter, not generic recipes.

Initial recipes:

- SSH
- Git user configuration
- Bash and Zsh configuration
- VS Code user settings, keybindings, snippets, and extension inventory as optional Protection Candidates
- Homebrew package inventory as a reproducible, non-executing setup record
- Reviewed application configuration beneath explicit paths such as `$CONFIG`
- Explicit custom paths

Account-synchronized application settings are not assumed protected. Their compiled recipes produce unselected Protection Candidates by default, allowing the owner to include the local state after review. Downloadable caches, package registries, and installed toolchain payloads are suggested exclusions; version and package inventories remain candidates.

## 10. Project discovery and audit

### Discovery

- Search only approved roots.
- Detect working trees, bare repositories, submodules, and nested repositories.
- Avoid descending into known generated or dependency directories unless explicitly included.
- Assign stable project IDs from canonical source identity plus migration ID; do not expose raw absolute paths in diagnostics.

### Audit

The adapter invokes the installed `git` binary with a sanitized environment, explicit working directory, no shell interpolation, and disabled optional prompts when running non-interactively.

Audit collects:

- Remotes without credentials embedded in displayed URLs
- HEAD, current branch, upstream, refs, and tags
- Worktree and index status
- Untracked and ignored inventory
- Stash refs
- Submodule status
- Git LFS presence and pointer inventory
- Ahead/behind when fetch-free local refs permit it
- Remote reachability only when the user requested a network check

### Capsule representation

The baseline capsule consists of:

1. A Git-native object/ref archive sufficient to recreate reachable local refs.
2. A worktree overlay containing tracked content and local filesystem state needed to reproduce staged, unstaged, and untracked work.
3. Reviewed ignored files.
4. Sanitized remote and repository metadata.
5. Submodule and LFS manifests.
6. Pre- and post-capture audit hashes.

The prototype must compare this representation with a full repository snapshot. The selected design must restore binary changes, executable bits, symlinks, empty directories when selected, stashes, detached HEAD, local-only branches, and repositories without remotes.

### Git push plan

Push is a separate operation with its own immutable review object:

```rust
struct PushAction {
    project_id: ProjectId,
    remote: String,
    local_ref: String,
    remote_ref: String,
    force: bool, // always false in MVP
}
```

Rules:

- No force push in MVP.
- Existing upstream branches only by default.
- Publishing new refs requires individual approval.
- Exact actions are displayed before execution.
- Network/auth failure cannot block capsule creation.
- Remote output is redacted before logging.
- Successful push is rechecked against local remote-tracking information when possible.

## 11. `.iniza` bundle format

### Format principles

- Purpose-built, public, and versioned.
- Streaming reads and writes.
- Authenticated metadata and payloads.
- Multiple independent key slots wrapping one data-encryption key (DEK).
- Chunk-level verification and resumability.
- Strict limits before allocation or decompression.
- Unknown critical fields cause rejection.

### Logical layout

```text
Fixed header
Public format metadata
Key slot directory
Encrypted chunk records
Encrypted manifest
Authenticated chunk index
Completion footer
Optional authenticated resume journal for partial output
```

The public header exposes only format version, suite ID, non-secret limits, and offsets required to locate key slots. Selected paths, usernames, hostnames, recipe names, and content counts remain encrypted unless a later format explicitly justifies disclosure.

### Provisional cryptographic suite `IZ1`

The suite remains provisional until independent review:

- Random 256-bit DEK from the operating-system CSPRNG
- XChaCha20-Poly1305 for chunk and manifest AEAD
- Argon2id for human-entered or generated passphrase slots
- HKDF-SHA-256 for context-separated subkeys
- BLAKE3 for non-secret content addressing and copy comparison
- Ed25519 only where a signing use case is explicitly defined; signatures do not replace AEAD

Exact crates, KDF parameters, salt sizes, nonce construction, chunk size, and associated-data schema require an ADR and known-answer tests before real sole-copy data is permitted.

### Key slots

MVP slots:

1. **Bitwarden secret slot:** a generated high-entropy secret wraps the DEK. The secret is saved in Bitwarden; the bundle stores only salt, KDF parameters, slot ID, and wrapped DEK.
2. **Offline recovery slot:** an independently generated recovery secret wraps the same DEK and is rendered or saved through an explicit secure flow.

Slots have independent identifiers and derivation inputs. Losing one does not weaken or invalidate the other. Adding or replacing a slot must rewrap only the DEK and authenticate the updated directory; payload chunks are not re-encrypted.

### Chunk record

Each chunk includes bounded encrypted length, item/chunk sequence context in associated data, nonce material defined by the suite, ciphertext, and authentication tag. Duplicate, missing, reordered, or oversized chunks fail validation.

### Manifest

The encrypted manifest contains bundle identity, source platform, plan hash, items, project capsules, logical paths, source metadata, content hashes, chunk mappings, exclusions, unsupported findings, validation rules, and creation state.

### Completion and resume

- The completion footer authenticates manifest and index locations and the final bundle state.
- A partial bundle cannot be opened by normal `inspect`, `verify`, or `restore` without explicit recovery mode.
- Resume journals contain no plaintext paths or secrets and are authenticated using a derived journal key.
- Resume verifies the last complete checkpoint before appending.

### Streaming multi-file format `IZ2`

ADR 0005 defines format version 2 for reviewed directory Plans. IZ2 retains the reviewed cryptographic suite while changing the record format instead of altering IZ1 byte semantics. Content uses bounded one-mebibyte encrypted chunks, the encrypted Manifest binds Plan coverage and per-item content digests, the encrypted fixed-entry Index binds chunk locations, and the authenticated Completion binds the exact preceding stream.

Pack performs three bounded source-consistency attempts. Every attempt stages only ciphertext, and discarded attempts consume record sequences so nonces are never reused. Inspect authenticates metadata, index, and completion without decrypting Content or extracting files. Full Verify authenticates every selected chunk and recomputes content digests without whole-Bundle memory loading.

Capacity is checked before creation and before persisted writes. Only a synchronized Bundle with a valid Completion can receive the final `.iniza` name. Cross-process Recovery Method storage remains assigned to the Offline Recovery Key and Vaultwarden issues.

## 12. Bitwarden connector

### Boundary

Iniza integrates with the official `bw` executable rather than implementing Bitwarden protocols directly. This delegates server selection, self-hosted configuration, login, MFA, and vault encryption to Bitwarden.

### Preconditions

- Resolve `bw` from an explicit configuration or trusted `PATH`.
- Verify executable identity and minimum supported version.
- Call `bw status` and parse strict JSON.
- If locked or unauthenticated, explain the required user action. Iniza does not receive a master password.

### Session handling

- Prefer an already unlocked official CLI session.
- If a returned session token is required, retain it only in a zeroizing in-memory type.
- Never persist it, print it, include it in arguments where avoidable, or place it in receipts.
- Child process environment is minimized.
- End the temporary flow with `bw lock` only when Iniza created or explicitly owns that session; never unexpectedly lock an unrelated user session.

### Item schema

```text
Type: Secure Note
Name: Iniza Recovery — <friendly bundle name> — <date>
Fields:
  iniza_bundle_id     non-secret identifier
  iniza_format        format/suite version
  iniza_secret        hidden unlocking secret
  iniza_created_at    timestamp
  iniza_location_hint optional, non-secret and user-approved
```

### Verification transaction

1. Seal bundle with Bitwarden and offline slots.
2. Create the Secure Note.
3. Sync.
4. Retrieve by recorded item ID, not fuzzy name search.
5. Decode the hidden secret in memory.
6. Unlock and authenticate the completed bundle.
7. Record only success, item ID, server identity hash, and time in the receipt.

Failure leaves the bundle usable through offline recovery but not fully ready for owner dogfood.

## 13. Storage and verified copy

The CLI writes through ordinary filesystem paths so local disks, external media, NAS mounts, and cloud-synchronized folders work without vendor APIs.

Rules:

- Write to a distinct partial filename in the target directory.
- Preflight free space with a safety margin.
- Flush file data and metadata where supported before sealing success.
- Atomically rename partial to final where the filesystem permits it.
- Warn when atomic rename, durable flush, sparse files, or metadata are unsupported.
- `copy` performs a byte copy, then reopens and authenticates the destination and compares its whole-file hash.

## 14. Restore engine

### Preflight

- Authenticate the bundle before trusting paths or counts.
- Resolve logical paths for the destination platform.
- Enforce maximum sizes, counts, depths, and expansion ratios.
- Reject absolute writes, `..` traversal, unsafe device nodes, sockets, and symlink escapes.
- Default to a new destination directory.
- Estimate required space and permission limitations.

### Transaction

1. Create a restore journal and staging area inside the approved destination.
2. Materialize regular files with restrictive temporary permissions.
3. Validate content hashes before final placement.
4. Create directories and safe symlinks.
5. Apply supported permissions and metadata.
6. Restore projects with hooks disabled/quarantined.
7. Run non-executing validation checks.
8. Seal the receipt and retain unsupported-metadata reports.

MVP never merges into existing paths. Future merge mode requires dry-run, conflict choices, backups, and rollback.

### Project validation

- `git fsck` or equivalent structural validation
- Expected refs and HEAD are present
- Worktree file hashes match the capsule
- Staged/unstaged classification is reproduced where promised
- Submodule and LFS requirements are reported without automatically fetching
- Hooks remain disabled until user approval

## 15. Platform adapters

### macOS

- POSIX mode, uid/gid as informational metadata, symlink target
- Extended attributes and ACLs where APIs permit
- APFS clone/sparse behavior treated as optimization, not correctness
- Apple Silicon and Intel builds

### Linux

- XDG paths
- POSIX mode, uid/gid as informational metadata, symlink target
- Extended attributes and ACLs where available
- Current Ubuntu LTS as first certification target

### Portability policy

- Ownership is never blindly applied across users or operating systems.
- Platform-only metadata is retained but reported when unapplied.
- Recipe mappings explicitly declare portable and manual outcomes.
- Executable bits are preserved only where supported and never automatically executed.

## 16. Error model

```rust
enum ErrorKind {
    Usage,
    PlanInvalid,
    PermissionDenied,
    SourceChanged,
    UnsupportedSource,
    InsufficientSpace,
    BundleInvalid,
    AuthenticationFailed,
    RecoveryUnavailable,
    ConnectorUnavailable,
    ConnectorProtocol,
    GitAuditFailed,
    GitPushFailed,
    RestoreConflict,
    ValidationFailed,
    Interrupted,
    Internal,
}
```

Errors contain a stable code, safe user message, redacted context, retryability, and optional remediation. Secret-bearing external output is never embedded verbatim.

## 17. Events and cancellation

Core operations emit typed events:

- Phase started/completed
- Item discovered/classified/captured
- Bytes and items progressed
- Review required
- Warning and safe error
- Checkpoint written
- Verification result

Cancellation is cooperative and checkpoint-aware. Ctrl-C first requests a clean stop; a repeated interrupt may terminate immediately with a partial file clearly marked.

## 18. Local state

Use the platform configuration/data directory for:

- Non-secret preferences
- Plan history and hashes
- Redacted operation receipts
- Resume metadata where not embedded
- Connector item identifiers

Do not store bundle secrets, recovery keys, Bitwarden session tokens, decrypted manifests, or migrated content. If a local database is introduced, its schema and protection require a separate ADR.

## 19. CLI and automation boundary

The CLI calls core library functions and renders typed results. JSON output uses a versioned envelope and writes progress to stderr only when explicitly enabled. Secret fields are structurally absent, not merely redacted at render time.

The complete syntax, output modes, confirmation rules, and exit codes are normative in `CLI_SPEC.md`.

## 20. Diagnostics and privacy

- No telemetry in MVP.
- Structured local logs default to warning/error detail.
- Paths use stable redacted IDs unless the user explicitly requests local verbose output.
- Git URLs have userinfo and sensitive query values removed.
- Subprocess stdout/stderr is parsed and discarded unless a safe diagnostic code is required.
- Diagnostic export displays its exact file list and requires confirmation.

## 21. Testing strategy

### Unit and property tests

- Path normalization and traversal rejection
- Plan schema round trips
- Key derivation and slot independence
- Chunk ordering, truncation, duplication, and bounds
- Manifest limits and unknown fields
- Exclusion precedence
- Git status parsing and push-plan policy
- Bitwarden JSON parsing with hostile output

### Golden corpus

- One golden bundle per format/suite version
- Empty, tiny, large, sparse, binary, and highly compressible files
- Unicode and normalization variants
- Permission, xattr, ACL, and symlink fixtures
- Repository states: dirty, staged, detached, stashed, local branch, no remote, submodule, LFS

### Fuzzing

- Header, slot directory, chunk parser, manifest, index, and footer
- Recipe and plan parsing
- Git and Bitwarden JSON adapters
- Path mapping and restore planner

### Fault injection

- Process kill at every persisted state transition
- Disk full and permission change
- Source mutation during capture
- Bundle mutation during copy
- Network loss during push or Bitwarden sync
- Destination collision and unsupported metadata

### End-to-end matrix

- macOS Apple Silicon source/destination
- macOS Intel build and round trip
- Current Ubuntu LTS round trip
- Portable macOS-to-Linux and Linux-to-macOS items
- Both recovery methods
- Two independent verified copies

Real sole-copy credentials are prohibited until the dogfood gate in the PRD is satisfied.

## 22. Build and release

### Dogfood

- Build from the Rust workspace using a pinned stable toolchain.
- Commit `Cargo.lock`.
- Run formatting, linting, tests, and dependency audit.
- Produce local Apple Silicon, Intel, and Linux artifacts as the matrix becomes available.

### Private alpha

- Reproducible release profile
- Checksums and provenance
- Signed/notarized macOS artifact when distributed outside the owner’s machine
- Signed Linux checksums or packages
- SBOM and dependency/license report

Package-manager distribution and automatic updates are deferred until the CLI contract stabilizes.

## 23. Implementation milestones

### M0: Workspace and vertical skeleton

- CLI parsing and typed core boundary
- Explicit-path plan
- Unencrypted fixture archive only for plumbing tests
- JSON envelope, cancellation, and CI

### M1: Bundle core

- `IZ1` implementation behind suite abstraction
- Key slots, chunks, manifest, index, footer, resume
- Inspect, verify, golden corpus, and fuzz targets

### M2: Safe restore

- Logical paths, traversal defense, new-directory transaction
- Metadata adapters, validation, interruption recovery

### M3: Project protection

- Discovery, audit, capsule prototype comparison
- Ignored-file classification
- Restore and integrity validation

### M4: Vaultwarden and offline recovery

- Official Bitwarden `bw` CLI preflight and strict subprocess adapter against the owner's Vaultwarden service
- Secure Note transaction and unlock proof
- Offline recovery rehearsal

### M5: Git synchronization and readiness

- Reviewed push plans and execution
- Verified copies
- Not Protected report and readiness receipt

### M6: Owner dogfood

- Synthetic and duplicated-data migration
- Isolated-directory or external-volume rehearsal followed by a fresh-user or second-Mac rehearsal
- Time Machine and independently stored direct-copy validation
- Apple Silicon macOS 26.5.1 artifact and dogfood issue closure

### M7: Private alpha

- Hardening, signed artifacts, documentation
- Security review package
- Additional compiled recipes

## 24. Architecture decisions

Recorded:

- ADR-0001: CLI-first Rust core and future client boundary
- ADR-0002: Project protection remains separate from Git publication
- ADR-0003: Independent Vaultwarden and offline recovery methods
- ADR-0004: IZ1 cryptographic suite and immutable prototype format
- ADR-0005: IZ2 streaming multi-file Bundle format

Required from HITL technical spikes before their affected implementation proceeds:

- Project Capsule representation
- Git subprocess trust and immutable publication execution
- Logical paths and metadata portability
- Restore transaction and future merge boundary
- Receipt authenticity, local state, and diagnostic redaction

## 25. Open technical decisions

- Minimum platform versions
- Compression algorithm and per-file heuristic
- Capsule representation selected by prototype
- Git version floor and LFS behavior
- Minimum `bw` version and session transport
- Durable-flush guarantees by filesystem
- Local receipt storage format
- Desktop binding mechanism after the CLI stabilizes

## 26. Technical spike exit criteria

The spike is complete when:

1. A synthetic explicit-path fixture can be planned, encrypted, inspected, verified, restored, and compared.
2. Both key slots independently unlock the same completed bundle.
3. Bitwarden create/retrieve/unlock verification works against the owner’s configured server.
4. A dirty Git fixture with local-only state round-trips without silent loss.
5. A proposed push is fully previewed and cannot execute without approval.
6. Interrupted pack and restore operations fail safely and resume or restart clearly.
7. The Apple Silicon macOS 26.5.1 build path is proven for Owner Dogfood; Intel and Linux build paths are tracked for private alpha.
8. Logs, receipts, plan files, and process arguments pass secret-leak tests.
