# COKS-34 Project Capsule interface comparison

- Status: Proposed; owner confirmation required before tests or implementation
- Date: 2026-09-06
- Issue: COKS-34

## Problem space

A Project remote cannot preserve staged changes, unstaged changes, untracked files, reviewed ignored files, stashes, detached current state, local-only branches or tags, executable modes, symbolic links, empty selected directories, or a Project without a remote. A Project Capsule must preserve the reviewed subset of that state, travel inside an encrypted Bundle, Restore into a new destination without overwriting or executing content, and then prove that the reconstructed Project matches an independent expected fixture.

The comparison must evaluate two representations:

1. a Git-native object and reference archive plus a filesystem overlay; and
2. a full repository filesystem snapshot.

Both representations must be measured for correctness, encrypted size, portability, resumability, and maintenance cost. Capture must bind pre-capture and post-capture audit hashes. Any change between those observations makes the candidate unverified. Remote addresses and Project metadata must be sanitized before entering diagnostics or Receipts.

## Dependencies and seams

- The filesystem is local-substitutable. Tests should use real disposable repositories and files rather than a public filesystem mock.
- Git is an installed operating-system dependency. The already approved `GitProcess` seam and `InstalledGit` adapter remain the only Git subprocess interface. Tests use the installed Git executable for faithful round trips and a scripted adapter only for system failures or hostile output.
- `BundleEngine` and `RestoreEngine` are owned modules. Project Capsule callers should not orchestrate them or learn their internal record, staging, or publication interfaces.
- Time, cryptographic randomness, and encrypted persistence remain hidden behind the existing Bundle interfaces.
- Git publication is out of scope. No Project Capsule operation may fetch, push, pull, merge, rebase, commit, check out, reset, or stash.

## Design one: one comparison entry point

```rust
ProjectCapsuleEngine::compare(
    ProjectCapsuleComparisonRequest,
) -> Result<ProjectCapsuleComparisonReport, CoreError>
```

The request identifies one approved Project, reviewed ignored paths, a disposable comparison workspace, and destinations for the two synthetic encrypted Bundles. The module captures both representations, packs and fully verifies each Bundle, restores each candidate, validates Git and filesystem state, records pre-capture and post-capture audit hashes, and returns the evidence plus a recommendation.

### Depth and locality

This is the deepest interface for the spike. One operation hides all orchestration, and a correctness defect is fixed in one module. Callers cannot accidentally compare different fixtures or omit verification for one representation.

### Weakness

The interface is specific to the comparison. COKS-38 would need a second production interface, and common capture and validation behavior could become duplicated unless the internal module is carefully reused.

## Design two: expose representation operations

```rust
ProjectCapsuleEngine::capture(
    ProjectCapsuleCaptureRequest,
) -> Result<ProjectCapsuleArtifact, CoreError>

ProjectCapsuleEngine::restore(
    ProjectCapsuleRestoreRequest,
) -> Result<ProjectCapsuleRestoreReport, CoreError>

ProjectCapsuleEngine::validate(
    ProjectCapsuleValidationRequest,
) -> Result<ProjectCapsuleValidationReport, CoreError>
```

The capture request chooses either `GitNativeArchiveWithOverlay` or `FullRepositorySnapshot`. The caller packs each artifact, invokes Restore, and feeds the output into validation.

### Depth and flexibility

This interface supports later capture and validation work directly and allows individual operations to be retried.

### Weakness

It is shallow at the most safety-sensitive point. Callers must understand operation order, temporary plaintext containment, Bundle approval, Recovery Methods, verification, Restore, and comparison. Tests would partly verify orchestration rather than Project Capsule behavior, and different callers could omit a required step.

## Recommended hybrid

Use one deep module with three public entry points:

```rust
ProjectCapsuleEngine::compare(
    ProjectCapsuleComparisonRequest,
) -> Result<ProjectCapsuleComparisonReport, CoreError>

ProjectCapsuleEngine::capture(
    ProjectCapsuleCaptureRequest,
) -> Result<ProjectCapsuleCaptureReport, CoreError>

ProjectCapsuleEngine::validate_restored(
    ProjectCapsuleValidationRequest,
) -> Result<ProjectCapsuleValidationReport, CoreError>
```

For COKS-34, only `compare` and `validate_restored` need implementation. `compare` owns the complete two-representation experiment and returns the selected representation only when both candidates received equivalent encryption, full verification, Restore, and structural validation. `validate_restored` is the independent result seam through which tests and future rehearsals prove observable Project behavior.

`capture` is reserved for the representation accepted in the architecture decision and is implemented only after the owner accepts that decision. This prevents the comparison’s temporary design from becoming an accidental production contract.

The engine accepts `GitProcess` as its one external adapter. Bundle and Restore engines remain internal. Real disposable filesystem fixtures cross the same public interfaces as future callers; no Iniza-owned collaborator is mocked.

## Request and result invariants

### `ProjectCapsuleComparisonRequest`

- references exactly one Project from an approved, non-stale Plan and verified local Project audit;
- lists every reviewed ignored path explicitly and rejects parent traversal, absolute paths, duplicate paths, and state still requiring review;
- uses an absent disposable comparison workspace and absent Bundle and Restore destinations;
- permits no network or publication capability; and
- carries no Recovery Secret, credential, or raw remote address in displayable fields.

### `ProjectCapsuleComparisonReport`

- contains one result for each required representation;
- records pre-capture and post-capture audit hashes, encrypted Bundle size, restored size, portability findings, resumability findings, maintenance findings, and validation failures;
- uses the word Restorable only when encrypted Pack, full Verify, safe Restore, Git structural validation, and explicit filesystem comparisons all succeed;
- recommends a representation only when it is faithful to the entire reviewed fixture;
- exposes stable Project and representation identities but no local paths, protected names, protected content, credentials, raw Git output, or Recovery Secrets in machine output; and
- never implies that synchronization, publication, Owner Dogfood readiness, or machine erasure has been proven.

### `ProjectCapsuleValidationReport`

- proves references, current branch or detached state, index state, worktree content, file modes, symbolic links, reviewed local files, selected empty directories, and repository-without-remote behavior;
- confirms restored repository hooks remain disabled and launches no restored executable;
- distinguishes supported equality, quarantined executable-mode review, unsupported state, and mismatch; and
- is deterministic and secret-free for automation.

## Representation hypotheses to test

### Git-native archive plus overlay

Expected advantages are smaller encrypted size, Git-level portability, and explicit reference validation. Risks are incomplete detached or unreachable object capture, exact index reconstruction, Git version compatibility, submodule and Git Large File Storage behavior, and the need to prevent an intermediate plaintext Git archive from becoming a production dependency. A faithful production design likely needs direct streaming into Bundle encryption rather than a reusable plaintext artifact.

### Full repository snapshot

Expected advantages are exact capture of the repository database, index, worktree, reviewed ignored state, and Projects without remotes through the existing streaming Bundle path. Risks are larger size, Git implementation details and lock files, absolute or machine-specific repository configuration, generated object duplication, and weaker portability across Git or filesystem versions.

The comparison must not preselect either hypothesis. The architecture decision should choose the smallest representation that passes every behavioral validation, not the smallest byte count among incomplete candidates.

## Proposed first tracer bullet after confirmation

Create one disposable Project with two commits, a current branch, a staged text change, an unstaged binary change, an untracked file, one reviewed ignored configuration file, a symbolic link, an executable script, one selected empty directory, a stash, a local-only branch, a local-only tag, and no remote. Through `ProjectCapsuleEngine::compare`, require both representation results to complete encrypted Pack, full Verify, safe Restore, and independent validation without executing the script or a restored hook.

The initial red test should fail because no Project Capsule module exists. The minimum green implementation should support only this first complete fixture behavior; additional detached, submodule, Git Large File Storage, change-during-capture, sanitization, and failure behaviors follow as separate vertical slices.
