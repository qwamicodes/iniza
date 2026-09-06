# COKS-34 Project Capsule interface comparison

- Status: Confirmed and implemented for comparison; ADR 0012 owner acceptance pending
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

Executable-mode restoration is a distinct reviewed action inside `ProjectCapsuleValidationRequest`. The request binds an exact validation hash covering the expected Project identity, restored Bundle identity, and authenticated original modes. Without that matching hash, validation confirms that executable files are quarantined and reports mode restoration as pending. With it, validation may restore authenticated execute bits for reviewed non-hook files through no-follow descriptors, but repository hooks always remain non-executable. Validation never launches Project content.

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

## Exact first fixture

The first disposable Project uses the installed Git executable through direct argument vectors and no network. Test setup fixes author and committer identity and time so expected object identifiers can come from checked-in literals rather than from the implementation under test.

The Project contains:

- two commits on branch `main`, with the second commit as the current `HEAD`;
- local-only branch `feature/local` pointing at the first commit;
- local-only annotated tag `owner-snapshot` pointing at the second commit;
- one stash created before the final dirty state;
- `staged.txt`, changed from committed content to the exact staged content `selected staged content\n`;
- `binary.dat`, committed as four known bytes and changed only in the worktree to the eight known bytes `00 ff 10 20 30 40 50 60`;
- untracked `notes.txt` containing `selected untracked content\n`;
- ignored and explicitly reviewed `.env.local` containing a synthetic marker only;
- symbolic link `current-config` whose exact target is `config/development.json`;
- executable non-hook file `scripts/rebuild.sh` with reviewed mode `100755`, containing a marker that would create a sentinel if executed;
- executable hook `.git/hooks/pre-commit` containing a different sentinel marker;
- selected empty directory `uploads/empty`; and
- no configured remote.

The sentinel paths begin absent and must remain absent after capture, Pack, Verify, Restore, executable-mode review, and validation.

## Independent expected result

The expected fixture is declared before either representation is captured. A successful candidate must prove all of the following through `validate_restored`:

1. `git fsck --full --strict --no-reflogs` succeeds without fetching.
2. Exactly the expected current `HEAD`, `refs/heads/main`, `refs/heads/feature/local`, `refs/tags/owner-snapshot`, and `refs/stash` object identifiers exist.
3. `HEAD` is attached to `refs/heads/main`.
4. No Git remote exists.
5. The index contains the staged blob for `staged.txt`, while the worktree contains that same staged content.
6. `binary.dat` has the exact eight worktree bytes and its index retains the committed four-byte blob.
7. `notes.txt` is untracked and `.env.local` is ignored rather than tracked.
8. The symbolic link remains a symbolic link with the exact relative target.
9. The selected empty directory exists.
10. The non-hook script carries its authenticated reviewed executable mode only after the exact mode-review hash is supplied.
11. The restored hook exists for evidence but carries no execute bit.
12. Neither sentinel exists, proving that capture and validation launched no restored content.
13. Explicit byte comparisons match every staged, worktree, untracked, ignored, binary, and link fixture value.

The test must not derive these expectations by asking the restored Project what it should contain. Git object identifiers are calculated once from the fixed fixture and checked in as known literals after independent command-line verification.

## Candidate construction

### Git-native archive plus overlay

The synthetic prototype creates a Git bundle containing `HEAD` and every local reference. Its overlay contains:

- a canonical metadata record identifying the current symbolic or detached `HEAD`;
- the exact index;
- every worktree path required to reproduce tracked, untracked, and explicitly reviewed ignored state;
- selected empty directories and portable modes and symbolic-link targets; and
- protected repository configuration needed for reconstruction, while displayable reports retain only sanitized metadata.

The prototype may use a restrictive disposable plaintext workspace because every input is synthetic and duplicated. That workspace is removed after the encrypted Bundle is verified. The representation is not eligible for personal data until COKS-38 streams generated archive bytes directly into Bundle encryption or an equivalent no-plaintext design is approved.

### Full repository snapshot

The snapshot candidate scans the entire Project root, including its repository database, index, worktree, untracked content, and only the ignored paths explicitly approved by the fixture. Known generated and transient Git lock files are excluded by reviewed rules rather than silently omitted. The existing Bundle engine encrypts source bytes directly without an intermediate Project Capsule artifact.

Both candidates use separate approved synthetic Plans, separate `.iniza` destinations, full verification, and separate new Restore destinations. They receive the same Recovery Method treatment and validation hash so size and correctness comparisons are meaningful.

## Pre-capture and post-capture observation

The comparison computes one canonical Project observation before candidate construction and repeats it after the candidate Bundle reaches authenticated Completion. The observation contains:

- `HEAD` attachment and object identifier;
- sorted local references and peeled annotated tags;
- the complete version-two porcelain status stream including index, worktree, untracked, and ignored classifications;
- stash object identifiers;
- the exact index digest;
- selected overlay path kinds, portable modes, link targets, lengths, and content digests; and
- the absence or sanitized identity of configured remotes.

The canonical observation is bounded, domain-separated, and hashed with BLAKE3. Reports expose only the digest. Any mismatch marks that candidate Changed and Unverified and prevents it from being recommended, even if its Bundle authenticates.

## Measurements and selection rule

Each result records independently measured:

- encrypted Bundle bytes from completed-file metadata;
- authenticated logical bytes from full Verify;
- restored bytes and Migration Item count;
- correctness findings for every expected behavior above;
- portability limits, including Git version and filesystem semantics;
- resumability, distinguishing native Bundle checkpoint support from candidate construction that must restart; and
- maintenance risk, with concrete format and external-command dependencies rather than a numeric score invented by the implementation.

Only candidates with equal pre-capture and post-capture hashes and no validation failure are faithful. The report recommends the faithful candidate with the smaller completed encrypted Bundle. A smaller candidate with any missing state, plaintext-production dependency, unsupported Restore behavior, or validation mismatch is not eligible. A tie prefers the representation with native resumability and fewer format-specific reconstruction steps. If neither is faithful, the report makes no recommendation and COKS-34 remains incomplete.

## Planned vertical slices

1. Complete the exact first fixture through both encrypted candidate round trips and return independent validation findings.
2. Detect Project mutation between pre-capture and post-capture observations and withhold a recommendation.
3. Prove sanitized human and machine results with hostile Project names and remote addresses.
4. Prove executable-mode review, permanent hook quarantine, and absence of both execution sentinels.
5. Add detached current state and unreachable-current-commit coverage.
6. Compare correctness, completed Bundle size, portability, resumability, and maintenance findings and apply the selection rule.
7. Record the architecture decision, then obtain explicit owner acceptance before implementing the selected `capture` interface.
