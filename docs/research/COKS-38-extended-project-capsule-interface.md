# COKS-38 extended Project Capsule interface comparison

- Status: Proposed for owner confirmation
- Date: 2026-09-07
- Issue: COKS-38

## Problem space

The selected Project Capsule is a full repository filesystem snapshot encrypted directly into an IZ2 Bundle. COKS-34 proved the representation with one dirty synthetic Project and added a production capture interface, but it deliberately left several Owner Dogfood requirements unresolved.

COKS-38 must prove the promised supported Project state, make unsupported state visibly blocking, and validate a restored Project without depending on the source Project still being available. It must cover staged and unstaged changes, untracked state, reviewed ignored state, stashes, attached and detached current state, local-only branches and tags, binary content, executable modes, symbolic links, and selected empty directories. Submodules and incomplete Git Large File Storage state must be reported without fetching. Live database files must never receive a verified result merely because their raw bytes were copied.

The current `ProjectCapsuleEngine::validate_restored` interface observes the original source Project during validation. That is useful for the COKS-34 comparison, but it cannot prove a Restore Rehearsal on a new Mac where the source is absent. COKS-38 therefore needs an independent capture expectation that is created before capture, bound to the authenticated Bundle identity, and usable after the source machine is unavailable.

## Existing constraints

- The complete issue, `CONTEXT.md`, architecture decisions 0005, 0006, 0007, 0010, and 0012, and the COKS-34 comparison evidence govern this design.
- Project Capsule capture never fetches, pushes, pulls, merges, rebases, commits, checks out, resets, stashes, or executes Project content.
- A Project can be Restorable without being Synchronized. Publication remains a separately reviewed Push Plan.
- Full repository snapshot capture must stream directly into Bundle encryption and must not create a reusable plaintext archive.
- Restore writes only into a safe new destination, overwrites nothing, executes nothing, and keeps repository hooks disabled.
- Human results may show reviewed paths when necessary. Saved machine results, Receipts, diagnostics, and logs contain stable identifiers rather than paths, protected content, raw remote addresses, credentials, or Recovery Secrets.

## Interface alternatives

### Alternative A: Add more path setters to the existing capture request

This would extend `ProjectCapsuleCaptureRequest` with more methods such as `with_database`, `with_submodule`, and `with_large_file`. It is rejected because callers would need to reproduce support classification, sensitivity review, local-object checks, retry rules, and blocking-gap logic. The interface would grow almost as quickly as the implementation and would not solve source-independent validation.

### Alternative B: Put all behavior directly in command-line argument handling

This would parse reviewed paths and call the existing capture and Restore modules directly from each command. It is rejected because behavior would be spread across command-line branches, difficult to test without subprocess coupling, and unavailable to the later complete synthetic rehearsal and readiness evidence modules.

### Alternative C: Add review, capture, and rehearsal stages to the Project Capsule module

This design keeps the complex state classification and validation inside one deep module. Review is read-only and produces an exact hash. Capture accepts only the confirmed review and produces a Bundle-bound expectation. Rehearsal accepts that expectation and one independently loaded Recovery Method, performs safe Restore, and validates the result without consulting the source Project. This alternative is selected for implementation after owner confirmation.

## Ten proposed public seams

### 1. Read-only Project Capsule review

`ProjectCapsuleEngine::review(ProjectCapsuleReviewRequest) -> ProjectCapsuleReview` accepts one approved, non-stale Plan and one fresh, verified Project audit. It performs metadata and Git-structure inspection only, reads no ignored sensitive file content, creates no Bundle, contacts no remote, and changes no repository state.

The review records the stable Project identity, current observation hash, supported state, every ignored candidate, every blocking repository feature, and an exact canonical review hash. The hash changes when any capture-relevant decision or observed Project state changes.

### 2. Typed review decisions for ignored and sensitive state

`ProjectCapsuleReviewDecision` addresses candidates by the stable identifier from the Project audit rather than by an unbound display path. Each ignored candidate receives exactly one decision:

- include as encrypted reviewed state;
- exclude as reproducible generated state with an owner-visible reason; or
- replace a detected live database with a separately created export and an approved validation rule.

Static environment files, certificates, local configuration, and irreplaceable uploads can be included only through the explicit encrypted-state decision. Known dependency trees and build outputs start as suggested exclusions but can be overridden through the same explicit review. Missing or undecided Must-Protect state remains a blocking gap.

### 3. Database export validation, never raw live-database verification

`ProjectDatabaseExportReview` binds the live database candidate, the selected export Migration Item, the approved validation description, two matching stable-file observations, and the Project Capsule review hash. The first implementation validates only a pre-created export already included by the approved Plan; it never opens a live database for copying, runs an exporter, or labels a raw live database file verified.

Database consistency that requires application-specific knowledge remains an explicit blocking human-review requirement unless a later trusted validator interface is separately designed and approved. Stable bytes alone are reported as stable export evidence, not as proof of application-level consistency.

### 4. Explicit repository support classification

`ProjectCapsuleSupportReport` classifies repository state before capture.

Supported state includes attached or detached current state, stashes, local-only branches and tags, staged and unstaged changes, untracked files, reviewed ignored files, binary content, executable modes, safe symbolic links, selected empty directories, and Projects without remotes.

Submodules, bare repositories, linked worktrees, object alternates, sparse checkouts, partial clones, promisor objects, active locks, and non-portable filesystem names are blocking and Unverified. They are never silently omitted or fetched.

Git Large File Storage is supported only when every referenced object is already local and its object identifier and size validate. Missing or malformed objects are blocking. Inspection performs no network operation and no automatic fetch.

### 5. Reviewed capture request

`ProjectCapsuleEngine::capture(ProjectCapsuleCaptureRequest) -> ProjectCapsuleCaptureReport` requires the approved Plan, fresh Project audit, completed review, exact review hash, absent final Bundle destination, and bounded retry policy. Raw unreviewed ignored paths are no longer sufficient authorization.

Capture revalidates the Plan, Project audit, support report, review decisions, and review hash immediately before reading protected content. It streams the selected full repository snapshot directly into encrypted Pack and fully verifies the completed Bundle before returning success.

### 6. Bounded changed-source retries

`ProjectCapsuleRetryPolicy` permits at most three total capture attempts and has no unbounded mode. Every attempt repeats the pre-capture observation, encrypted Pack, full Verify, and post-capture observation.

Only an unchanged attempt may become the requested final Bundle. Changed attempts remain visibly Unverified, use names ordinary Bundle commands reject, and are never overwritten or reported as completed. Exhausting the bound returns a changed-and-unverified report with exact retry guidance and without deleting source state.

### 7. Source-independent capture expectation

`ProjectCapsuleExpectation` is produced only from a verified unchanged capture. It binds the Project identity, Plan hash, review hash, Bundle identity, repository kind, current state, exact local reference object identifiers, index digest, reviewed worktree entry kinds and content digests, reviewed ignored classifications, selected empty directories, original portable modes, safe symbolic-link targets, local Git Large File Storage evidence, and the capture time.

Displayable forms omit paths, names, content, credentials, and Recovery Secrets. COKS-39 will define authenticated persistence and retention for this expectation as part of a Receipt. COKS-38 keeps it in memory and proves that copied, stale, or mismatched expectations are rejected.

### 8. Recovery-Method-specific Restore Rehearsal

`ProjectCapsuleEngine::rehearse(ProjectCapsuleRehearsalRequest) -> ProjectCapsuleRehearsalReceipt` accepts the completed Bundle, one Bundle-bound `ProjectCapsuleExpectation`, one independently loaded Recovery Method, and one absent or approved empty destination.

It authenticates the Bundle, performs safe Restore, and validates against the capture expectation without reading the source Project. Separate calls prove the Vaultwarden Recovery Secret and Offline Recovery Key independently. The Receipt states which Recovery Method was used and never contains the secret.

### 9. Structural validation without execution or network access

Rehearsal validation runs Git structural checks with hooks disabled, prompting disabled, external transports disabled, and no fetch. It proves current attached or detached state, exact references, index state, worktree digests, reviewed ignored state, stashes, binary bytes, file kinds, selected empty directories, safe symbolic links, and locally complete Git Large File Storage evidence.

Reviewed non-hook executable modes require the existing exact Bundle-bound executable-mode review hash before restoration. Repository hooks always remain non-executable. Validation never executes Project code, a hook, a build, a database command, or a downloaded object.

### 10. Sanitized results and honest state language

`ProjectCapsuleReview`, `ProjectCapsuleCaptureReport`, `ProjectCapsuleSupportReport`, and `ProjectCapsuleRehearsalReceipt` provide deterministic human and versioned JavaScript Object Notation representations. Saved machine results use stable identifiers and counts and structurally omit paths, filenames, content, raw Git output, raw remote addresses, credentials, and Recovery Secrets.

Only a complete source-independent rehearsal may call the Project Restorable for the captured expectation. No Project Capsule result calls the Project Synchronized, claims a complete machine backup, grants erase permission, or hides an unsupported, excluded, unavailable, changed, or unverified state.

## Testing adapters and fixtures

The public review, capture, and rehearsal interfaces are the behavior-test seams. Real disposable repositories, encrypted Bundles, and safe Restore destinations exercise the installed Git and filesystem adapters. Iniza-owned modules are not mocked.

The existing `GitProcess` adapter remains the external Git seam. A controlled test adapter may inject a source mutation or missing Git Large File Storage object, because those are genuine external-state changes. Tests do not assert private command call order except at the installed external-process safety seam.

Fixtures will separately prove:

1. all supported dirty repository states through capture and source-independent rehearsal;
2. detached state and unreachable current commits;
3. local-complete and missing Git Large File Storage objects without network access;
4. visible blocking submodule and linked-worktree state without fetching;
5. explicit encryption of reviewed static secrets, certificates, local configuration, and uploads;
6. generated-tree exclusion and owner override;
7. live-database rejection and separately selected stable export evidence;
8. bounded retry success and retry exhaustion after Project mutation;
9. copied, stale, forged, and Bundle-mismatched capture expectations;
10. permanent hook quarantine, reviewed executable-mode restoration, secret-free results, and absence of execution sentinels.

## Proposed first tracer bullet after confirmation

Through `ProjectCapsuleEngine::review`, create a complete review of the existing dirty Project fixture. Assert from independent fixture constants that supported state is classified correctly, one sensitive ignored candidate requires an explicit encrypted-state decision, one generated ignored tree is suggested for exclusion, and the exact review hash changes after a decision changes.

The first test must fail because the review interface does not exist. The minimum implementation will add only the read-only review and the behavior needed for this fixture. Capture changes, source-independent expectations, retries, Git Large File Storage validation, and Restore Rehearsal follow as separate red-to-green tracer bullets.

## Confirmation required

No COKS-38 behavior test or implementation begins until the owner confirms or revises all ten seams above.
