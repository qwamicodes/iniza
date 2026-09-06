# Select the full repository snapshot for Project Capsules

- Status: Accepted
- Date: 2026-09-06
- Issue: COKS-34

## Context

A Git remote cannot preserve staged and unstaged changes, untracked files, explicitly reviewed ignored files, stashes, detached current state, local-only references, executable modes, symbolic links, selected empty directories, or a Project without a remote. A Project Capsule must preserve that reviewed local state in an encrypted Bundle, Restore it into a new destination without overwriting or executing content, and prove the reconstructed Project through an independent structural and byte-level validation.

COKS-34 compared two representations through the same synthetic dirty Project, IZ2 encryption, full Verify, safe Restore, and validation gates:

1. a Git-native bundle containing HEAD and every local reference, plus a worktree overlay, exact index, index-only blob objects, current-state record, reviewed ignored data, modes, links, and empty directories; and
2. a full repository filesystem snapshot, with unreviewed ignored paths excluded before Pack.

The fixture has two fixed commits, an attached branch, a local-only branch, an annotated tag, a stash, staged and unstaged changes, binary data, an untracked file, one reviewed and one unreviewed ignored file, a symbolic link, a reviewed executable, an executable Git hook, an empty directory, and no remote. A separate behavior also proves a detached current commit that is not named by a reference.

## Evidence

Both representations were Restorable in the fixed fixture. They reproduced fixed reference object identifiers, exact index bytes, staged and worktree content, binary bytes, untracked and reviewed ignored classifications, symbolic-link target, selected empty directory, reviewed executable mode, disabled hook mode, and remote absence. The command git fsck --full --strict --no-reflogs succeeded without network access. Neither executable sentinel was created.

A representative local run measured:

- Git-native archive with overlay: 18,047 encrypted Bundle bytes and 2,726 authenticated restored bytes.
- Full repository snapshot: 77,770 encrypted Bundle bytes and 31,527 authenticated restored bytes.

The byte totals are fixture evidence rather than format constants. Every comparison report measures its own completed Bundle and authenticated restored bytes.

The Git-native candidate is smaller, but its prototype must first write a reusable plaintext Git bundle and then separately maintain reference reconstruction, detached HEAD, exact index transport, index-only objects, worktree overlay semantics, modes, links, and repository configuration. Candidate construction must restart after interruption even though the later encrypted Pack has authenticated checkpoints. A production version would require new direct streaming from Git output into Bundle encryption and a durable reconstruction format.

The full repository snapshot is larger but crosses the existing approved directory Plan, direct encrypted Pack, full Verify, and safe Restore paths. It introduces no reusable plaintext Project artifact and inherits authenticated Pack checkpoint support. Its principal portability constraint is compatibility of the captured Git repository database and filesystem semantics on the destination.

Mutation evidence is bound by a canonical BLAKE3 Project observation before and after each candidate reaches authenticated Completion. Any change withholds Restorable status and a recommendation. Human and machine results expose no Project path, protected name, raw remote address, credential, protected content, or Recovery Secret.

An active Git lock is rejected before the disposable comparison workspace or either Bundle path is created. Lock files are never treated as repository state.

## Decision

Select the full repository filesystem snapshot as the Project Capsule representation.

Correctness and containment take precedence over encrypted size. The smaller Git-native prototype is not production-eligible because its current construction creates reusable plaintext and adds a second repository reconstruction format. The full snapshot is the smallest eligible design that passed every fixture behavior while reusing direct IZ2 encryption and safe Restore.

The production ProjectCapsuleEngine::capture interface may be implemented only after the owner explicitly accepts this decision. Capture must:

- require one approved, non-stale directory Plan and a verified, unchanged local Project audit;
- include the repository database, exact index, reviewed worktree and local-only state;
- include ignored paths only when they were explicitly reviewed;
- reject stale observations and transient repository lock state;
- use direct encrypted Pack with no intermediate plaintext Project Capsule;
- fully verify the completed Bundle before returning success;
- keep Git hooks non-executable;
- require an exact validation hash bound to the expected Project identity, completed Bundle identity, and authenticated original modes before restoring execute bits for reviewed non-hook files; and
- expose only sanitized, stable evidence.

## Unsupported and excluded state

The first production slice does not claim support for:

- bare repositories, linked worktrees, submodules, or repositories using object alternates;
- Git Large File Storage content whose required objects are not already local and proven present;
- sparse checkouts, partial clones, or promisor-object repositories;
- filesystem names that cannot be represented by the selected portable path encoding;
- destination filesystems that cannot faithfully represent required case, symbolic-link, or executable-mode semantics; or
- a repository with active lock files or a Project that changes during capture.

These states must be reported as blocking and Unverified. They must not be silently omitted, fetched, normalized, or downgraded to warnings. Git publication remains separate under ADR 0002; Project Capsule capture never fetches, pushes, pulls, merges, rebases, commits, checks out, resets, or stashes.

## Consequences

- Project Capsules are larger than the Git-native prototype but have fewer format-specific reconstruction steps and no intermediate plaintext archive.
- Exact local repository state can be protected even when there is no remote or publication is intentionally deferred.
- A completed Project Capsule does not by itself make a Project Synchronized or make the machine safe to erase.
- COKS-38 must integrate the selected capture with approved Plans, verified Project audits, Recovery Methods, Receipts, and Restore Rehearsals.
- Owner Dogfood still requires real Project selection, a real encrypted Bundle, verified independent copies, both Recovery Method rehearsals, and a successful Restore Rehearsal before any readiness conclusion.

## Owner decision

- [x] I approve the full repository snapshot as the Project Capsule representation.
- Owner: Kwaame Ofori-adjekum
- Decision date: 2026-09-06
- Notes: Accepted in the implementation thread. This decision authorizes implementation of the production Project Capsule capture seam. It does not authorize capture of sole-copy personal data, Git publication, external writes, or erasing the old Mac.
