# Select intelligent Project protection

- Status: Accepted
- Date: 2026-09-11
- Decision: COKS-40 owner-confirmed Project protection seams

## Context

Architecture Decision Record 0012 selected a full repository snapshot as the safe Project Capsule representation. That remains necessary whenever a Project contains state that its remote cannot reproduce or when no usable authoritative remote exists. It needlessly duplicates tracked bytes, however, when a Project has no unpublished local state and its reviewed live remote is authoritative.

Git working-tree cleanliness alone is not proof that nothing local needs protection. A local repository can have stashes, unpublished references, a missing upstream, or ahead commits. Conversely, a behind checkout or stale remote-tracking reference is not itself a protection gap when the owner has selected the live remote as authoritative.

## Decision

Iniza classifies each freshly audited Project as exactly one of:

- `Full Project Capsule` when local-only state must be preserved or no usable authoritative remote exists;
- `Remote Reconstruction with Local Overlay` when the reviewed live remote is authoritative for tracked state and only explicitly reviewed ignored state needs encrypted capture; or
- `Action Required` when synchronization or audit evidence is incomplete.

Remote reconstruction is eligible only when all of the following are true:

- the local audit is verified and unchanged;
- the working tree has no staged, unstaged, or untracked state;
- no stash, local-only branch, local-only tag, detached head, or unborn head exists;
- an upstream and its configured remote exist;
- the locally known ahead count is zero; a behind count is retained as informational evidence;
- a live read-only remote check succeeds; and
- the live remote advertises the reviewed upstream branch and exact authoritative commit object.

A successful connection alone is insufficient: the reviewed upstream branch must be present in the live advertisement. The local checkout does not need to equal that live commit and Iniza does not update it. When the cached comparison says there are no ahead commits, the live advertised commit becomes the reconstruction source of truth.

Every pending ignored-state candidate receives one explicit include-or-exclude decision. An unavailable inventory, missing decision, duplicate decision, unknown Project, stale review hash, or changed observation fails closed. An eligible decision creates a new unapproved Plan. That Plan excludes the Project's tracked working tree and Git database, retains only the selected ignored overlay and its ancestor directories, and records an encrypted recovery recipe containing the sanitized remote locator, upstream, exact commit object, protection review hash, and validation expectation.

Iniza does not fetch into, pull, merge, rebase, reset, switch, commit, or push a source Project as part of classification. Publication remains governed by Architecture Decision Record 0013. Ahead or diverged state remains Action Required. A Project with an inaccessible or absent remote uses a full Project Capsule and requires a current verified capsule plus an exact owner decision to retain it without publication before it is Synchronized. A synchronized Project is not called Restorable until the selected representation passes a source-independent Restore Rehearsal.

## Consequences

- Clean Projects with zero locally known ahead commits and a live advertised upstream branch can avoid duplicating tracked bytes in a Bundle, even when their local checkout is behind.
- Dirty and local-only Projects continue to receive full Project Capsule protection.
- Missing or inaccessible remotes fall back to full Project Capsules. Ahead, diverged, missing-upstream, unverified, and changed states remain visible and require an explicit next action.
- Behind counts remain visible, but do not block remote-authoritative protection or require a pull.
- The Plan hash changes when the owner selects a Project representation or ignored-state decision, so Bundle capture cannot silently reuse the prior approval.
- Remote reconstruction and its Restore Rehearsal remain later work; this decision only prepares the authenticated Plan representation.
