# Adopt immutable, non-force Push Plans

- Status: Accepted
- Date: 2026-09-06
- Issue: COKS-35

## Context

A Git remote can preserve published commits and tags, but it cannot preserve staged, unstaged, untracked, ignored, stashed, detached, or deliberately unpublished Project state. Publication can also trigger continuous integration, deployments, notifications, and other remote automation. Directory Plan approval, Pack approval, and Project Capsule acceptance therefore cannot authorize a Git push.

Publication inputs are security-sensitive. Repository configuration, remote addresses, reference names, Git output, hooks, credential helpers, transport helpers, environment variables, and the installed Git executable may be hostile or stale. A safe workflow must let the owner review the exact remote transition while making force push, deletion, wildcard publication, and arbitrary Git arguments structurally unavailable.

## Decision

Iniza uses three separate public operations:

```rust
PushPlanEngine::draft(PushPlanDraftRequest) -> PushPlanDocumentReport
PushPlanEngine::approve(PushPlanApprovalRequest) -> PushPlanApprovalReceipt
PushPlanEngine::execute(PushPlanExecutionRequest) -> PushExecutionReport
```

Draft writes an exclusive-create, canonical Push Plan. The document contains a stable Project identifier, configured remote name, creation and expiry times, exact local and remote references, expected old and proposed new object identifiers, stable action identifiers, action classes, the fixed `non-force-only` policy, and the remote-side-effect warning. It contains no local path, raw remote address, credential, Project name, or protected content. The maximum approval and revalidation window is fifteen minutes.

Approval reopens the exact canonical Push Plan without following a final symbolic link, compares its domain-separated BLAKE3 digest with the owner-reviewed hash, requires explicit acknowledgement of remote side effects, and writes a separate exclusive-create approval receipt. New remote branches and tags require their stable action identifiers to be approved item by item. Existing upstream branches require no additional per-action selection. The approval receipt has an operating-system-random public identifier and approval time and contains no secret or repository identity.

Execution reopens and validates both immutable documents, checks their binding, confirms the approved directory Plan and verified Project audit, recomputes the complete Project status-and-reference observation, and re-observes each exact local and remote reference immediately before publication. Behind, diverged, absent, created, moved, or otherwise stale references are never reconciled. A stale or rejected action produces durable sanitized Partial evidence. Successful actions are proven by an exact post-publication remote observation. Execution creates an append-only JavaScript Object Notation Lines result log before contacting the remote. Its synchronized header lists every planned stable action identity; each proven action is appended and synchronized before the next publication attempt; and its summary explicitly counts succeeded, failed, and pending actions. Interruption therefore preserves the exact completed prefix while unattempted actions remain visibly Pending.

`GitPublicationProcess` is a distinct capability boundary from the read-only `GitProcess` in architecture decision 0006. Its typed operations permit only complete local observation, exact local-reference observation, exact remote-reference observation, ancestry checking, and exact non-force publication. Remote names, references, and object identifiers are private-field validated value types, so a force prefix, deletion, wildcard, option injection, or non-object argument cannot be constructed. The schema and operation type contain no force switch, deletion form, arbitrary refspec, wildcard, configuration mutation, or arbitrary argument vector.

The production adapter executes the trusted system Git path directly without a shell. It clears and allowlists the environment, disables prompts, credential helpers, hooks, optional locks, filesystem monitoring, global and system Git configuration, external transport helpers, unauthenticated Git transport, and local file transport. It permits only Hypertext Transfer Protocol Secure and Secure Shell transport, pins the Secure Shell executable, drains standard output and standard error concurrently, retains at most one mebibyte per stream, and never copies raw Git output into a report.

Iniza never fetches, pulls, merges, rebases, commits, checks out, resets, stashes, updates local references, edits configuration, deletes a remote reference, or force-pushes as part of this workflow. Publication success never substitutes for a verified Project Capsule, and publication failure never invalidates local Project protection evidence.

## Evidence

- A real disposable working repository and bare remote prove exact existing-upstream publication, exact old and new object identifiers, unchanged dirty local state, post-publication remote verification, and disabled executable hooks.
- Real disposable repositories prove item-by-item approval and publication for a new branch and a tag.
- Remote mutation, local Project-observation mutation, remote rejection, divergence, and a mismatched remote advertisement prove fail-closed or durable Partial behavior without overwrite.
- A synthetic interruption before a second approved action proves that the first successful action record is synchronized before the next publication attempt.
- A three-action rejection proves that the completed prefix remains successful, the rejected action remains failed, the remaining action stays Pending, and no later publication is attempted.
- Approval and persistence tests prove that an edited Push Plan, a directory Plan hash, missing remote-side-effect acknowledgement, missing new-reference decisions, and a symbolic-link document substitution cannot create an approval receipt; an existing result destination is never overwritten and blocks publication before remote contact.
- Value-type tests and executable fixtures prove unrepresentable force, deletion, wildcard, and option-injection inputs; a clean environment; exact non-force arguments; disabled hooks and implicit tags; denied local transport; and bounded concurrent output capture.
- Human, machine, Push Plan, approval, and result evidence are checked for local paths, raw remote paths, Project names, changed object identifiers, and hostile raw Git output.

Run `cargo test --test push_plan` for the focused evidence.

## Consequences

- The owner reviews one additional immutable document and retains a separate approval receipt.
- A fifteen-minute Push Plan must be regenerated when review or execution takes too long.
- Authentication must already be available through the configured Secure Shell environment or another separately approved secure connector; Iniza never accepts a token, password, or Recovery Secret as a publication argument.
- Local file remotes are available only through test-owned adapters and are unsupported by the production adapter.
- A deliberate decision to leave a local-only reference unpublished remains separate Project Capsule and Readiness Evidence work.
- Supported cross-process orchestration and final Owner Dogfood aggregation remain later integration work. This decision does not authorize sole-copy use, machine erasure, or removal of independent conventional backups.

## Owner decision

- [x] I reviewed and accept the immutable non-force Push Plan decision and its fifteen-minute revalidation policy.
- Owner: Kwaame Ofori-adjekum
- Decision date: 2026-09-06
- Notes: Interface choices were confirmed before implementation on 2026-09-06. The owner accepted the final decision and confirmed the implementation evidence on 2026-09-06.
