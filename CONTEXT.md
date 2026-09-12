# Iniza Migration

Iniza describes the evidence-producing preservation and recovery of a person's curated computer state before a reinstall or machine move. This glossary is the canonical language shared by the product documents and implementation issues.

## Workflow

**Migration**:
The complete journey from selecting source state through proving recovery and reviewing remaining gaps.
_Avoid_: Backup job, transfer

**Owner Dogfood**:
The first real migration performed by the project owner for a clean reinstall of their own Mac, subject to the documented acceptance gate.
_Avoid_: Production release, sole backup

**Plan**:
The reviewable description of a Migration's approved scope, exclusions, destinations, recipes, and publication policy. A Plan contains neither protected content nor recovery secrets.
_Avoid_: Configuration, manifest

**Migration Item**:
A distinct piece of source state considered by a Plan and assigned exactly one Disposition.
_Avoid_: File, asset

**Protection Candidate**:
Discovered developer or application state that the owner may select as a Migration Item. Discovery does not imply inclusion, and an account-sync claim is not verification by Iniza.
_Avoid_: Auto-selected item, supported backup

**Must-Protect Item**:
A Migration Item the owner considers necessary for the clean install. Any unresolved coverage or verification gap for a Must-Protect Item blocks Owner Dogfood readiness.
_Avoid_: Critical file, required path

**Disposition**:
The coverage outcome assigned to a Migration Item: Included, Excluded, Requires Review, Unsupported, or Unavailable.
_Avoid_: Status, result

## Protection and recovery

**Bundle**:
A portable, versioned, encrypted container containing the protected state and the evidence needed to authenticate and restore it.
_Avoid_: Backup, archive file

**Recovery Method**:
One independently usable way to unlock a Bundle. Owner Dogfood requires both a Vaultwarden-held secret and a separately stored Offline Recovery Key.
_Avoid_: Password, account recovery

**Vaultwarden Recovery Secret**:
A generated high-entropy Bundle-unlocking secret stored in one Vaultwarden Secure Note through the official Bitwarden CLI. It is neither the Bundle nor the owner's Vaultwarden password.
_Avoid_: Bundle copy, master password, Offline Recovery Key

**Offline Recovery Key**:
The independently generated recovery secret written to owner-selected separate storage and rehearsed before Owner Dogfood can pass.
_Avoid_: Backup password, emergency code

**Verified Copy**:
A copy of a Bundle whose bytes and authenticated Bundle identity were checked after copying.
_Avoid_: Duplicate, filesystem copy

## Projects and publication

**Project**:
A discovered Git repository whose remote and local-only state may require protection.
_Avoid_: Migration, workspace

**Project Capsule**:
The protected representation of a Project's reconstructable repository, working-tree, and reviewed local-only state.
_Avoid_: Git backup, repository copy

**Restorable Project**:
A Project whose reviewed local state has been preserved in a verified Project Capsule and reproduced by a Restore Rehearsal.
_Avoid_: Backed-up repository, pushed repository

**Synchronized Project**:
A Project whose live reviewed remote is authoritative for tracked state, with no unpublished local commits. A behind local checkout is informational and need not be updated. Local-only state is separately approved for publication or explicitly retained only in a verified Project Capsule.
_Avoid_: Clean repository, backed-up repository

**Push Plan**:
An immutable, separately reviewed description of exact Git publication actions. Approval of a Migration Plan or Bundle never approves a Push Plan.
_Avoid_: Sync plan, deployment plan

## Evidence

**Receipt**:
A secret-free record binding an operation's result to the relevant Plan, Bundle, and time.
_Avoid_: Log, certificate

**Owner Attestation**:
An explicit, timestamped statement by the owner about evidence Iniza cannot verify itself, such as the existence of a conventional backup.
_Avoid_: Automatic check, guarantee

**Readiness Evidence**:
The combined machine-verifiable Receipts and Owner Attestations used to show which Owner Dogfood gates are satisfied or still missing.
_Avoid_: Erase approval, safety guarantee

**Not Protected Report**:
The reviewable account of excluded, unsupported, unavailable, changed, or unverified state remaining outside proven Bundle coverage.
_Avoid_: Error report, ignore list

**Restore Rehearsal**:
A validated restoration of a Bundle into a safe destination performed to prove recoverability without modifying the source system.
_Avoid_: Restore preview, dry run
