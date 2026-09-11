# COKS-40 intelligent Project protection classification

- Status: Implemented after owner confirmation
- Date: 2026-09-11
- Issue: COKS-40

## Owner intent

The owner does not want tracked Project content duplicated into the encrypted Bundle when a Project is clean, verified, and fully synchronized with its reviewed remote. For those Projects, Iniza should protect only reviewed ignored state such as environment files and important local configuration, together with the encrypted recovery recipe needed to reconstruct the exact tracked revision.

Projects containing local-only state still require a full Project Capsule. Projects that are ahead, behind, diverged, missing an upstream, or not remotely verified require an explicit synchronization action or owner decision before Iniza may classify them as remotely reconstructable.

This proposal narrows the full-repository-snapshot decision in Architecture Decision Record 0012. That representation remains the safe default for Projects containing local-only state. A remotely reconstructable Project becomes a second reviewed representation only after its own Restore Rehearsal proves the complete flow.

## Proposed public seams

Behavior tests will exercise the existing `ProjectAuditEngine::audit(ProjectAuditRequest)` interface, a new `ProjectProtectionEngine::classify(ProjectProtectionRequest)` interface, and the supported `iniza projects scan` command.

1. `iniza projects scan` reports staged, unstaged, untracked, stash, local-only branch, local-only tag, upstream, ahead, behind, and remote-check outcomes in both human and path-free machine output. Ahead and behind counts are explicit numbers, not only generic gap text.
2. Classification has exactly three caller-visible outcomes: `Full Project Capsule`, `Remote Reconstruction with Local Overlay`, and `Action Required`.
3. `Remote Reconstruction with Local Overlay` is eligible only when the local observation is verified and unchanged, the working tree has no staged, unstaged, or untracked state, no stash or local-only reference exists, an upstream exists, the reviewed remote check succeeds, and both ahead and behind counts are zero.
4. `Full Project Capsule` is required when reviewed local state exists that the remote cannot reproduce, including staged, unstaged, untracked, stashed, detached, local-only reference, repository-without-remote, or explicitly retained unpublished state.
5. `Action Required` is returned for an ahead, behind, diverged, failed-remote, missing-upstream, changed, or unverified state. Ahead-only state may prepare a separate immutable Push Plan. Behind or diverged state must be reconciled by the owner outside Iniza. Iniza never automatically pulls, merges, rebases, resets, switches branches, or pushes.
6. Every ignored candidate remains separately reviewable. Environment files and important local configuration enter the encrypted local overlay only through explicit stable candidate decisions. Generated ignored trees remain excluded. An incomplete ignored-state inventory always blocks classification.
7. The reviewed protection decision changes the canonical Plan hash. For a remotely reconstructable Project, tracked working-tree bytes and the Git object database are excluded from Bundle content; the encrypted Bundle retains the exact reviewed remote locator, branch or detached revision, commit object identifier, selected ignored overlay, and validation expectation. Public diagnostics expose only stable identifiers and sanitized remote evidence.
8. Restore never writes into an existing Project or overwrites local files. The later remotely reconstructed Restore flow must use a separately reviewed network operation to reproduce the exact tracked revision in a new destination, then publish the authenticated local overlay without executing restored content. If the exact remote revision cannot be obtained, Restore fails closed and reports the Project as not Restorable.
9. A Project is never called `Restorable` merely because it is synchronized. The remotely reconstructed representation must pass a source-independent Restore Rehearsal before it can satisfy the same Restorable Project gate as a full Project Capsule.
10. The classifier is deterministic: the same approved Plan, verified audit, ignored-state decisions, and remote observations produce the same classification and review hash. Any changed observation invalidates the decision before Bundle capture.

## Test-driven implementation order

After owner confirmation:

1. Red and green: expose exact ahead and behind counts through human command output while retaining the current machine contract.
2. Red and green: classify one clean, current, remotely verified Project as eligible for remote reconstruction with a local overlay.
3. Red and green: require a full Project Capsule for each form of local-only state.
4. Red and green: return Action Required for ahead, behind, diverged, missing-upstream, failed-remote, changed, and unverified states without running a Git mutation.
5. Red and green: bind reviewed ignored-state decisions and the protection representation to a deterministic review hash and revised Plan.
6. Red and green: prove generated state remains excluded, secrets remain absent from machine output, and incomplete ignored-state enumeration fails closed.
7. Run the focused Project suites, formatting, strict static analysis, and the complete repository suite.
8. Recreate and review the real COKS-40 Plans only after the new classifier passes.

## Authorization boundary

Confirming these seams authorizes test-driven implementation with synthetic repositories only. It does not approve a real Plan, read ignored file contents, publish Git state, pull or merge a Project, contact Vaultwarden, capture a real Bundle, delete data, or authorize machine erasure.

## Owner decision

- [x] I confirm all ten COKS-40 intelligent Project protection classification seams.
- Owner: Kwaame Ofori-adjekum
- Decision date: 2026-09-11
- Notes: The owner authorized test-driven implementation with synthetic repositories only. The approval does not authorize Git publication, Bundle capture, Vaultwarden access, deletion, or machine erasure.

## Implementation evidence

The confirmed public interfaces now expose exact upstream counts, the three protection classifications, typed reasons, deterministic protection review hashes, stable ignored-state candidate identifiers, and path-free machine output. Plan preparation requires a complete one-decision-per-candidate review and rejects stale or ineligible selections. Its resulting unapproved Plan excludes remotely reconstructable tracked and Git-database bytes, retains the selected local overlay, and records the sanitized remote locator, upstream, exact commit object, review hash, and validation expectation.

A live remote must advertise the exact local commit on the configured upstream branch. Mere remote reachability or a locally cached remote-tracking reference is insufficient. The final verification passed thirty-one focused Project tests, two command-line Project tests, strict formatting and static analysis, and all 336 repository tests with zero failures and zero ignored tests.

The real read-only audit classified twenty-one Projects for full Project Capsules, one Project as Action Required, and one Project for remote reconstruction with a local overlay. The exact reviewed `top-society` decisions produced unapproved proposed Plan `plan_blake3_c3777899f7597ae53a2e2c1694532a222cd7b7b68df80389a132f4bba211997d`. The Plan remains subject to owner approval; no Bundle or external mutation followed.
