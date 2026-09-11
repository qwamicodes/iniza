# COKS-41 complete migration interface comparison

- Status: Confirmed by the owner; implementation may proceed through these seams
- Date: 2026-09-08
- Issue: COKS-41

## Problem space

Iniza already has reusable Rust interfaces for reviewed Plans, Project audits, immutable Push Plans, Project Capsules, authenticated encrypted Bundles, Pack pause and Resume, Offline Recovery Keys, Vaultwarden Recovery Secrets, full verification, Verified Copies, safe Restore, and append-only Readiness Evidence. The supported executable does not yet connect those interfaces into the workflow the owner needs to migrate this Mac.

COKS-41 must prove the connected workflow with synthetic and deliberately duplicated data before COKS-42 reads personal source content. It must exercise every destructive-looking or external boundary without weakening Plan approval, Git publication approval, Recovery Method containment, no-overwrite Restore, Verified Copy authentication, Receipt invalidation, or the rule that Iniza never decides whether a machine is safe to erase.

The difficult interface question is Recovery Method continuity. Pack generates two independent Recovery Secrets in memory. The completed Bundle must be authenticated before the Offline Recovery Key document can be written and before a Vaultwarden preflight review can identify the exact Bundle. Persisting either secret in a generic resume file, environment variable, command argument, configuration file, or ordinary operation record would violate the accepted recovery decisions.

## Existing constraints

- `CONTEXT.md` supplies the canonical terms Plan, Must-Protect Item, Bundle, Recovery Method, Vaultwarden Recovery Secret, Offline Recovery Key, Verified Copy, Project Capsule, Restorable Project, Synchronized Project, Push Plan, Receipt, Owner Attestation, Readiness Evidence, Not Protected Report, and Restore Rehearsal.
- The command-line adapter remains thin. Core modules own orchestration, validation, policy, persistence ordering, and typed results.
- Only an approved, non-stale Plan may begin Pack or Project Capsule capture.
- Project protection and Git publication remain separate. A Push Plan is exact, immutable, non-force, independently approved, and revalidated immediately before execution.
- Pack success may be presented only after both Recovery Methods are stored and independently rehearse the same completed Bundle.
- The Offline Recovery Key document is the only intentional plaintext Recovery Secret location. Later commands accept its path, never the key itself.
- Vaultwarden access uses only the reviewed official Bitwarden command-line client, an existing unlocked `BW_SESSION`, the exact item identifier, the expected server identity hash, and exact installation review.
- Inspect, Verify, Verified Copy, Restore, and Project Capsule Restore Rehearsal borrow a zeroizing in-memory Recovery Method loaded through one of the approved storage flows.
- Existing final destinations are never overwritten. Partial Bundle and Verified Copy artifacts are never mistaken for Completion.
- Restore writes only into an absent or approved empty destination, resumes only from matching authenticated state, and does not execute restored content.
- Readiness Evidence is append-only. Owner Attestations remain owner-stated and never become machine verification.
- Real source content remains outside COKS-41. Automated and manual rehearsal data must be synthetic, duplicated, disposable, or isolated.

## Interface alternatives

### Alternative A: Put orchestration directly in every command handler

Each `pack`, `inspect`, `verify`, `copy`, `restore`, and `status` branch would load files and call the existing engines independently.

This is rejected because Recovery Method selection, review binding, Receipt recording, redaction, output state, and error mapping would be repeated across command branches. The security behavior would become shallow and scattered, and tests would need to couple themselves to argument parsing rather than the migration behavior.

### Alternative B: Add one command that silently performs the whole migration

A new `iniza migrate` command would scan, approve, publish, pack, copy, restore, and record evidence in one invocation.

This is rejected because it collapses distinct owner decisions into one operation. Plan approval, Push Plan approval, Vaultwarden item creation, Verified Copy destinations, Restore destinations, and Owner Attestations have different review scopes and failure consequences. One broad confirmation would be unsafe and incompatible with the existing command specification.

### Alternative C: Persist generated Recovery Secrets for cross-process Pack Resume

Pack would encrypt or serialize its Recovery Secrets into local resume state so a later process could continue before the Recovery Methods had been stored.

This is rejected. No separately reviewed secret-escrow format, key hierarchy, operating-system key store, or deletion lifecycle exists. Adding one inside an integration issue would create a third Recovery Method and widen the secret-bearing surface. A cooperative pause can Resume in the same live command while both secrets remain in memory. If that process ends before recovery storage completes, Iniza must guide the owner to restart Pack without treating the previous partial as complete.

### Alternative D: Add one deep migration workflow module and a shared stored-recovery loader

One migration workflow module coordinates the existing engines and returns typed secret-free reports. A shared stored-recovery module converts only approved non-secret locators into a non-cloneable, redacted, zeroizing loaded Recovery Method. Thin command handlers parse arguments, collect exact owner reviews where allowed, call these modules, render results, and map stable exit codes.

This alternative is proposed because it preserves the existing security modules, centralizes orchestration invariants, gives later owner capture one reusable interface, and lets behavior tests exercise the same seams as command callers.

## Proposed public seams

### 1. Complete migration capture

`MigrationWorkflowEngine::capture(MigrationCaptureRequest) -> MigrationCaptureReport` accepts one approved, non-stale Plan, the final Bundle destination, a friendly Bundle name, an Offline Recovery Key document destination, a reviewed Bitwarden installation request, an owner-review adapter, an optional cancellation source, and path-free event sink.

It revalidates the Plan, performs authenticated Pack, writes and rehearses the Offline Recovery Key document, performs Vaultwarden installation review and Bundle-bound preflight review, stores and rehearses the exact Vaultwarden item, and fully verifies the completed Bundle through both Recovery Methods before returning success.

The report contains authenticated identities, review bindings, typed Receipts, state, and warnings. It structurally omits Recovery Secrets, protected content, raw Bitwarden output, credentials, and unnecessary paths.

### 2. Exact owner review during one live capture

`MigrationCaptureOwnerReview` is the owner-decision seam used only by the human command adapter and deterministic test adapter. It receives the complete Bitwarden installation review and Vaultwarden preflight review and must return the exact reviewed hashes.

The human adapter displays the complete review and requires the full hash. It never accepts a generic yes. The JavaScript Object Notation and non-interactive adapters never prompt and fail with review-required status when an exact review cannot be supplied safely.

### 3. Cooperative Pack pause and safe restart

The live capture retains the `PackRecoveryContext` only in memory. A first interruption requests a checkpoint-aware pause. The command may Resume from that checkpoint while it remains alive and the owner confirms continuation. A repeated interruption may terminate immediately with an incomplete artifact and recovery guidance.

If the process exits before both Recovery Methods are stored, no command claims cross-process Resume. A later invocation revalidates the Plan and sources and performs a new Pack. Existing partial artifacts remain recognizable and are never accepted as completed Bundles or deleted without a separate reviewed action.

### 4. Stored Recovery Method loading

`StoredRecoveryMethodEngine::load(StoredRecoveryMethodRequest) -> LoadedRecoveryMethod` accepts the Bundle and exactly one non-secret locator:

- `OfflineRecoveryLocator`, containing only the restrictive Offline Recovery Key document path; or
- `VaultwardenRecoveryLocator`, containing only the exact item identifier, expected server identity hash, reviewed Bitwarden installation hash, and trusted-path or explicit executable selection.

`LoadedRecoveryMethod` owns the existing `LoadedOfflineRecoveryKey` or `LoadedVaultwardenRecoverySecret` and exposes only a borrowed `RecoverySecret` to authenticated operations. It is non-cloneable, redacted in debugging, and zeroized when dropped.

### 5. Supported encrypted command-line operations

The existing executable gains the documented `pack`, `inspect`, `verify`, `copy`, `restore`, and `status` commands. Post-Pack commands select one stored Recovery Method with explicit non-secret locator arguments. `verify --recovery both` requires both locators and proves both Recovery Methods independently.

Command handlers do not recreate migration policy. They parse input, construct a request, invoke the workflow or stored-recovery module, render the returned report, and map its typed failure to the documented exit code.

### 6. Complete synthetic migration rehearsal

`SyntheticMigrationRehearsalEngine::run(SyntheticMigrationRehearsalRequest) -> SyntheticMigrationRehearsalReport` builds and exercises one isolated fixture through the public migration interfaces.

The fixture includes developer configuration, optional account-synchronized application candidates, ordinary text and binary files, symbolic links, supported metadata, unsupported entries, unavailable entries, changing files, and representative attached, detached, staged, unstaged, untracked, ignored, stashed, local-only-reference, no-remote, and disabled-hook Project state.

The fixture constants and expected bytes are independent sources of truth. The rehearsal does not reproduce implementation algorithms inside its assertions.

### 7. Project protection and disposable publication

The rehearsal performs a read-only Project audit, records Restorable and Synchronized outcomes separately, captures and rehearses Project Capsules, and exercises one immutable approved Push Plan against a disposable local Git remote adapter.

Automated tests never publish to a live remote. A later live disposable publication still requires a current exact Push Plan and separate owner approval. COKS-37 evidence is not treated as permission for a new publication.

### 8. Verified Copies, safe Restore, and independent comparison

The rehearsal creates at least two authenticated Verified Copies using storage adapters that independently report External storage and iCloud Drive. It reopens and authenticates each copy and records its typed Receipt.

Restore is interrupted after a documented durable transition, resumed through the same public Restore interface with a freshly loaded stored Recovery Method, and completed into a new destination. The expected fixture comparison verifies byte content, supported metadata, Project references, index state, working-tree state, reviewed ignored content, and permanently disabled hooks without executing restored content.

### 9. Append-only evidence and Not Protected reporting

The workflow records successful typed Receipts through `ReadinessEvidenceEngine` rather than writing ad hoc result files. It demonstrates supersession or invalidation by changing a duplicated artifact and proving that current status becomes blocking.

Owner Attestation preparation and confirmation use the existing exact confirmation seam. The final status keeps owner-stated claims distinct from machine-verified evidence. The Not Protected Report lists every intentional exclusion, unsupported category, unavailable item, source change, unverified result, and Project gap.

### 10. Failure adapters at genuine system boundaries

Failure behaviors use the existing filesystem, capacity, Pack persistence, Verified Copy persistence, Restore cancellation, Git process, Bitwarden command-line, clock, and event seams. Tests inject storage exhaustion, source mutation, Bundle mutation, remote failure, Vaultwarden failure, and destination collision without mocking Iniza-owned modules or asserting their private call order.

Every failure proves containment through observable files, state, reports, exit behavior, and absence of false Receipts.

### 11. Human and machine-readable results

Human output remains understandable with color disabled and identifies the next safe action. JavaScript Object Notation mode emits exactly one versioned result on standard output, emits events on standard error only when requested, never prompts, and never contains Recovery Secrets, protected content, private paths, credentials, raw remote addresses, or raw external-process output.

The connected commands preserve the documented exit-code meanings for approval failure, source change, Bundle invalidity, authentication failure, storage failure, connector failure, Git failure, Restore conflict, Restore validation failure, and safe interruption.

### 12. Honest completion and owner review

`SyntheticMigrationRehearsalReport` states exactly which behaviors were proven and which warnings remain. It may report authenticated Bundle, independent Recovery Method, Verified Copy, Restorable Project, Synchronized Project, Restore Rehearsal, and Complete Evidence outcomes only when their underlying public interfaces returned current success.

It never claims a complete machine backup, authorizes real source capture, authorizes a new Git publication, authorizes deletion, or says that the Mac is safe to erase. COKS-41 remains incomplete until the owner reviews the full rehearsal evidence and every remaining warning.

## Testing adapters and fixtures

The behavior-test seams are `MigrationWorkflowEngine::capture`, `StoredRecoveryMethodEngine::load`, each supported executable command, and `SyntheticMigrationRehearsalEngine::run`.

Real isolated directories, real encrypted Bundles, real Offline Recovery Key documents on a synthetic removable-storage adapter, real safe Restore destinations, and disposable local Git repositories exercise important integration paths. The existing Bitwarden and storage ports receive strict deterministic test adapters because they represent true external or operating-system boundaries.

The tests will separately prove:

1. reviewed fixture planning and unresolved Must-Protect blocking;
2. same-process Pack pause and Resume without secret persistence;
3. Pack Completion followed by both independently rehearsed Recovery Methods;
4. cross-process Offline and Vaultwarden loading without secret-bearing arguments;
5. authenticated Inspect and full Verify through either Recovery Method;
6. two independently classified and authenticated Verified Copies;
7. interrupted and resumed safe Restore without overwrite or execution;
8. exact fixture and Project Capsule comparison;
9. accurate Not Protected and Readiness Evidence status;
10. Receipt invalidation and honest Owner Attestation behavior;
11. deterministic human and machine-readable command results; and
12. containment and secret absence across every required injected failure.

## Proposed first tracer bullet after confirmation

Through `StoredRecoveryMethodEngine::load`, create a synthetic completed Bundle and restrictive Offline Recovery Key document using existing public interfaces. In a fresh caller scope, load the document by path and use the returned `LoadedRecoveryMethod` to fully verify the Bundle. Assert the known Bundle identity and prove that debug output and the public report omit the known synthetic key.

The first test must fail because `StoredRecoveryMethodEngine` does not exist. The minimum implementation will add only the shared non-secret Offline Recovery locator and loaded wrapper. Vaultwarden loading, command parsing, migration capture, rehearsal orchestration, copies, Restore, evidence aggregation, and failure injection follow as separate red-to-green tracer bullets.

## Confirmation required

The owner confirmed all twelve seams on 2026-09-08. COKS-41 behavior tests and implementation may proceed through these interfaces without reopening the decision unless a public seam must materially change.

## Implementation completion evidence

The confirmed interfaces are implemented. The supported executable now performs approved interactive Pack with both Recovery Methods, loads either the Offline Recovery Key document or the exact reviewed Vaultwarden item for authenticated Inspect, Verify, Verified Copy, and Restore, and supports `verify --recovery both` to prove both stored methods authenticate the same Bundle identity. The complete synthetic rehearsal still exercises Pack pause and Resume in one live workflow, two independently classified Verified Copies, interrupted and resumed Restore, Project Capsule validation, append-only Readiness Evidence, Receipt invalidation, and the Not Protected Report.

The final COKS-41 verification accounted for 329 passing tests with zero failures and zero ignored tests. The sixty-three-test Pack persistence suite passed, every other integration suite passed, strict Clippy passed with warnings denied, formatting passed, and the Git diff check passed. The local manual quality-assurance walkthrough is recorded in [COKS-41 complete migration rehearsal](../manual-qa/COKS-41-complete-migration-rehearsal.md).

This completes the synthetic and deliberately duplicated-data implementation. It does not authorize personal-data capture, Git publication, a real Vaultwarden mutation, deletion, or machine erasure. Those real operations retain their separate COKS-42 reviews and approvals.
