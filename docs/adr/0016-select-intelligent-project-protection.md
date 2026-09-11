# Select intelligent Project protection

- Status: Accepted
- Date: 2026-09-11
- Decision: COKS-40 owner-confirmed Project protection seams

## Context

Architecture Decision Record 0012 selected a full repository snapshot as the safe Project Capsule representation. That remains necessary whenever a Project contains state that its remote cannot reproduce. It needlessly duplicates tracked bytes, however, when a Project is clean and its exact current commit is already present on a reviewed remote.

Git working-tree cleanliness alone is not proof of remote recoverability. A local repository can have stashes, unpublished references, a missing upstream, stale remote-tracking references, or a live remote that advertises a different commit.

## Decision

Iniza classifies each freshly audited Project as exactly one of:

- `Full Project Capsule` when local-only state must be preserved;
- `Remote Reconstruction with Local Overlay` when the remote can reproduce the exact tracked revision and only explicitly reviewed ignored state needs encrypted capture; or
- `Action Required` when synchronization or audit evidence is incomplete.

Remote reconstruction is eligible only when all of the following are true:

- the local audit is verified and unchanged;
- the working tree has no staged, unstaged, or untracked state;
- no stash, local-only branch, local-only tag, detached head, or unborn head exists;
- an upstream and its configured remote exist;
- ahead and behind counts are both zero;
- a live read-only remote check succeeds; and
- the upstream branch advertised by that live remote points to the exact local commit object.

A successful connection alone is insufficient. A stale remote-tracking reference cannot establish eligibility.

Every pending ignored-state candidate receives one explicit include-or-exclude decision. An unavailable inventory, missing decision, duplicate decision, unknown Project, stale review hash, or changed observation fails closed. An eligible decision creates a new unapproved Plan. That Plan excludes the Project's tracked working tree and Git database, retains only the selected ignored overlay and its ancestor directories, and records an encrypted recovery recipe containing the sanitized remote locator, upstream, exact commit object, protection review hash, and validation expectation.

Iniza does not fetch into, pull, merge, rebase, reset, switch, commit, or push a source Project as part of classification. Publication remains governed by Architecture Decision Record 0013. A synchronized Project is not called Restorable until the later remote-reconstruction Restore flow passes a source-independent Restore Rehearsal.

## Consequences

- Clean Projects with an exact remotely advertised revision can avoid duplicating tracked bytes in a Bundle.
- Dirty and local-only Projects continue to receive full Project Capsule protection.
- Ahead, behind, diverged, failed-remote, missing-upstream, unverified, changed, and remote-revision-mismatch states remain visible and require an explicit next action.
- The Plan hash changes when the owner selects a Project representation or ignored-state decision, so Bundle capture cannot silently reuse the prior approval.
- Remote reconstruction and its Restore Rehearsal remain later work; this decision only prepares the authenticated Plan representation.

