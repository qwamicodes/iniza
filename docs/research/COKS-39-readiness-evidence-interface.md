# COKS-39 Readiness Evidence interface comparison

- Status: Proposed for owner confirmation
- Date: 2026-09-07
- Issue: COKS-39

## Problem space

Iniza already produces operation-specific evidence for approved Plans, encrypted Bundles, Offline Recovery Key rehearsals, Vaultwarden Recovery Secret rehearsals, Verified Copies, Project Capsules, Restore Rehearsals, and immutable Push Plans. Those values currently live in separate in-memory reports or operation files. COKS-39 must bind them into one durable Readiness Evidence model without turning an old or copied result into current proof and without making an erase-safety decision.

The model must preserve a strict distinction between machine verification and an Owner Attestation. It must invalidate dependent evidence when a Plan changes, a Bundle or Verified Copy is replaced, a Project changes, a remote publication result becomes stale, or a later operation supersedes an earlier one. It must also report missing and contradictory evidence as blocking gaps.

No separately anchored signing key exists in the current architecture. A local checksum can detect incomplete or accidental modification, but it cannot honestly prove authorship against a hostile local administrator who can replace the record and recompute the checksum. The initial design therefore uses tamper-evident canonical records, restrictive local storage, immutable operation bindings, and revalidation against current artifacts. It does not claim cryptographic authorship or protection from a hostile administrator.

## Existing constraints

- `CONTEXT.md` supplies the canonical terms Receipt, Owner Attestation, Readiness Evidence, Not Protected Report, Restorable Project, and Synchronized Project.
- Any unresolved Must-Protect Item is blocking.
- A Project must report Restorable and Synchronized independently. A local-only reference may remain deliberately unpublished only when its Project Capsule protection and owner decision are both recorded.
- A machine Receipt can state only the exact operation it proves. It cannot become proof of a later operation by aggregation.
- An Owner Attestation is always labelled owner-stated. It is never rendered as machine-verified, even when it refers to a valid Receipt.
- The evidence model never says that a machine is safe to erase and never claims a complete machine backup.
- Recovery Secrets, decrypted manifests, credentials, protected content, raw remote addresses, and unnecessary paths never enter stored records, diagnostics, or machine results.
- COKS-36 and COKS-37 remain required dependencies. Their real owner-service and publication rehearsals must complete before COKS-39 can itself complete.

## Interface alternatives

### Alternative A: One mutable readiness document

Every operation would update a single current-status document. This is rejected because a crash during replacement could lose all evidence, historical withdrawal and supersession would be ambiguous, and a copied older document could look current unless every operation reconstructed the full state perfectly.

### Alternative B: Persist each existing report exactly as it is

Every module would serialize its current report into a shared directory and status would scan those unrelated formats. This is rejected because report schemas were designed for immediate callers, not durable compatibility. Binding, redaction, invalidation, and retention logic would spread across every operation module and command-line caller.

### Alternative C: Append immutable canonical evidence records behind one Readiness Evidence module

The Readiness Evidence module accepts typed successful operation Receipts, prepares and records exact Owner Attestations, records withdrawals, and derives status by revalidating the current artifacts named by the private local store. Each stored record has a version, store identity, sequence, previous-record digest, operation kind, exact non-secret bindings, occurrence time, and canonical BLAKE3 digest.

Records are never edited or deleted by Iniza. Supersession and withdrawal are new records. A missing sequence, invalid chain, unsupported schema, copied store identity, changed binding, failed artifact revalidation, or contradictory current result blocks status. This alternative is selected for implementation after owner confirmation.

## Proposed public seams

### 1. Initialize one Plan-bound evidence store

`ReadinessEvidenceEngine::initialize(ReadinessEvidenceInitializationRequest) -> ReadinessEvidenceStoreReport` creates one private evidence directory for one exact approved, non-stale Plan.

The store header contains schema version one, a random non-secret store identity, the exact Plan hash, creation time, and the first canonical record digest. The requested directory and every final record path must be absent. Existing directories, symbolic links, non-private parents, invalid names, and unsupported storage semantics fail before publication.

Initialization does not scan personal content, create a Bundle, contact a remote, or infer that any readiness gate has passed.

### 2. Record only typed successful operation Receipts

`ReadinessEvidenceEngine::record_receipt(ReadinessReceiptRecordRequest) -> ReadinessReceiptRecordReport` accepts a typed `ReadinessReceiptInput` borrowed from an already successful Iniza operation.

Supported inputs cover:

- approved Plan evidence;
- completed and fully verified Bundle evidence;
- Offline Recovery Key rehearsal;
- Vaultwarden Recovery Secret rehearsal;
- Verified Copy;
- Project Capsule capture and Recovery-Method-specific Restore Rehearsal;
- safe Restore Rehearsal;
- complete or partial Push Plan execution; and
- the generated Not Protected Report.

The module derives canonical fields from the typed source. A caller cannot construct a generic successful Receipt from arbitrary strings. Partial or failed operations remain evidence of a gap and can never be promoted to success by the record request.

Every record binds the relevant store identity, Plan hash, Bundle identity, Project identity, destination identity or stable destination evidence identifier, Recovery Method identity, operation result, and Unix time. Fields that do not apply are structurally absent rather than empty.

### 3. Prepare an exact Owner Attestation without writing

`ReadinessEvidenceEngine::prepare_attestation(OwnerAttestationPreparationRequest) -> OwnerAttestationReview` is read-only. It accepts one supported fixed claim kind plus the exact non-secret evidence reference to which the claim applies.

Supported claim kinds initially include:

- conventional backup validated;
- representative restored-Project build completed;
- second-environment rehearsal completed;
- Not Protected Report reviewed;
- reviewed external Vaultwarden service confirmed;
- fresh-device Vaultwarden access confirmed; and
- independent multi-factor recovery path confirmed.

The review shows the fixed complete claim text, relevant evidence identifier, current time, consequences, and exact canonical review hash. Free-form secret-bearing claim text is not supported.

### 4. Confirm an Owner Attestation by exact review hash

`ReadinessEvidenceEngine::confirm_attestation(OwnerAttestationConfirmationRequest) -> OwnerAttestationRecord` requires the unchanged `OwnerAttestationReview`, its exact review hash, and the fixed owner-confirmation acknowledgement.

The stored record contains the claim kind and exact fixed text, owner-confirmed state, confirmation time, evidence reference, store identity, Plan hash, and record digest. Machine and human results label it `owner-stated`. They never label the claim verified, guaranteed, or automatically observed.

### 5. Withdraw or supersede without rewriting history

`ReadinessEvidenceEngine::withdraw_attestation(OwnerAttestationWithdrawalRequest) -> OwnerAttestationWithdrawalRecord` requires the exact active attestation identifier and a fixed withdrawal acknowledgement.

Withdrawal appends a new record. It never edits or deletes the original. A withdrawn claim is absent from satisfied gates and remains visible by identifier and time in the audit history. Recording a newer Receipt for the same operation similarly supersedes the older Receipt without erasing it.

### 6. Revalidate current evidence before deriving status

`ReadinessEvidenceEngine::status(ReadinessEvidenceStatusRequest) -> ReadinessEvidenceStatusReport` parses and validates the complete record chain, recomputes the current Plan hash, reopens the selected Bundle and Verified Copies, compares current whole-file digests and authenticated identities to their Receipts, and checks current Project evidence against Project Capsule and Push Plan bindings. Authenticated Bundle identity revalidation borrows one already loaded Recovery Method through the existing secure in-memory seam; it never accepts a secret-bearing command argument or ordinary file.

Remote Project revalidation is an explicit request mode because it can contact configured remotes. Without it, a Project cannot receive a fresh Synchronized result; the report shows remote verification as not performed and blocking where required. Status never pushes, fetches objects, merges, rebases, commits, resets, stashes, restores, or executes Project content.

Changed Plans, replaced Bundles, modified copies, stale Project observations, failed remote checks, superseding failures, missing records, and withdrawn attestations invalidate only the dependent conclusion and remain visible as blocking gaps.

### 7. Report Project outcomes independently

`ReadinessProjectEvidence` always has separate Restorable and Synchronized conclusions.

Restorable requires a verified Project Capsule plus a source-independent successful Restore Rehearsal for the same Plan, Project, review, Bundle, and Recovery Method binding. Synchronized requires current remote evidence and successful approved publication where the Project was ahead.

A deliberately unpublished local-only reference is not called missing only when the exact owner decision and its successful Project Capsule protection are both current. The report never treats publication as recovery or recovery as publication.

### 8. Deterministic status and gap language

`ReadinessEvidenceStatusReport` provides deterministic human output, versioned JavaScript Object Notation, stable event records, and an exit code.

The report covers Plan coverage, Must-Protect gaps, Bundle verification, both Recovery Methods, Restore Rehearsals, Verified Copies, each required Project, source changes, current publication evidence, the Not Protected Report, and active Owner Attestations.

The only aggregate states are `Complete evidence` and `Blocking gaps`. `Complete evidence` means that the evidence model found every configured gate current; it is immediately followed by `This is not permission to erase a machine.` The prohibited phrases `safe to erase`, `complete machine backup`, and equivalent guarantees cannot be produced by result constructors.

### 9. Restrictive append-only local storage

`ReadinessEvidenceStorage` is the external filesystem seam with a local adapter and failure-injecting test adapter. The local adapter uses a private directory, restrictive regular files, no-follow opens, exclusive record creation, file synchronization, and directory synchronization.

Each record name is the zero-padded sequence plus its canonical digest. Records are bounded in size and count. Unknown fields, duplicate fields, invalid sequence, broken previous-record binding, unsupported schema, oversized input, symbolic-link substitution, and record replacement fail closed. An interrupted candidate remains under an incomplete name rejected by status.

Iniza provides no record deletion operation. The evidence directory remains until the owner separately approves its retention or removal outside the COKS-39 transaction.

### 10. Explicit compatibility and retention rules

Schema version one readers accept only version one records. A future reader may add a separately tested migration path, but it must preserve the original bytes, record digests, operation meaning, and owner-stated classification. Unknown newer versions are blocking rather than ignored.

The default retention policy keeps every record for the full Migration and through the owner-reviewed post-migration retention period. Superseded, partial, contradictory, and withdrawn evidence remains auditable. No cleanup is inferred from a successful status.

## Testing adapters and fixtures

The public initialization, Receipt recording, attestation preparation and confirmation, withdrawal, and status interfaces are the behavior-test seams. Tests use real isolated evidence directories, Plans, encrypted Bundles, Verified Copies, disposable Git Projects, Project Capsules, and safe Restore destinations.

The failure-injecting storage adapter delegates to real isolated storage while injecting failures at exclusive creation, write, synchronization, and publication transitions. Existing Git, Vaultwarden, Bundle, and filesystem adapters remain the genuine external seams; Iniza-owned modules are not mocked.

Fixtures separately prove:

1. a complete synthetic evidence chain with every required evidence class;
2. changed Plan, replaced Bundle, modified copy, stale Project, and failed remote invalidation;
3. forged bytes, copied records, copied store identity, missing sequence, reordered record, broken chain, unsupported version, and incomplete record rejection;
4. partial operation evidence never becoming successful;
5. exact Owner Attestation review and confirmation, withdrawal, supersession, and contradictory claims;
6. independent Restorable and Synchronized Project results including deliberate non-publication;
7. unresolved Must-Protect coverage remaining blocking;
8. secret, credential, path, protected-name, and protected-content omission;
9. deterministic human, JavaScript Object Notation, event, and exit-code behavior; and
10. absence of erase-safety and complete-machine-backup claims from every result constructor.

## Proposed first tracer bullet after dependency completion and owner confirmation

Initialize a version-one evidence store from one exact approved synthetic Plan, then append one typed Bundle verification Receipt. Reopen the store through `status` and prove the Receipt is current only while the Plan hash, Bundle identity, and whole-file digest still match.

The first behavior test must fail because the Readiness Evidence module does not exist. The minimum implementation adds only initialization, one Bundle verification record, canonical record chaining, restrictive storage, and status for that one evidence type. Other Receipt types, attestations, Project aggregation, invalidation cases, and result rendering follow as separate red-to-green slices.

## Confirmation and dependency gate

No COKS-39 behavior test or implementation begins until:

1. the owner confirms or revises these ten seams;
2. COKS-36 completes the real owner Vaultwarden service rehearsal and required Owner Attestations; and
3. COKS-37 completes the exact approved synthetic publication rehearsal.

Confirming this interface does not approve any Git publication, Vaultwarden write, personal-data capture, evidence deletion, or machine erasure.
