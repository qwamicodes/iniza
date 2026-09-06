# COKS-35 immutable Push Plan interface comparison

- Status: Proposed; owner seam confirmation required before tests or implementation
- Date: 2026-09-06
- Issue: COKS-35

## Problem space

A Project is Synchronized only when required upstream branches were checked against their remotes, are not behind, and every approved ahead commit was published successfully. Publication cannot protect staged, unstaged, untracked, ignored, stashed, detached, or deliberately unpublished state, so it remains independent of Project Capsule protection.

The boundary must show exact local and remote reference transitions without credentials, create an immutable Push Plan, require approval of its exact canonical hash, revalidate local and remote state immediately before each action, structurally prohibit force push, execute only approved actions, and report partial outcomes without affecting Restorable Project evidence.

The first fixture uses a real disposable local bare repository through a test-owned adapter. Production network access remains limited to configured Hypertext Transfer Protocol Secure and Secure Shell remotes. No shell command, hook, prompt, credential helper, local transport, external transport helper, or restored executable receives control.

## Existing boundary

ProjectAuditEngine and GitProcess are read-only evidence seams under ADR 0006. They cannot authorize publication and must not be widened with push capability.

Push Plan approval is separate from directory Plan approval, Pack approval, Project Capsule acceptance, Recovery Method verification, and any automation confirmation. The first external publication approval cannot be bypassed with a general yes flag.

## Design one: mutable plan object

~~~rust
PushPlanEngine::draft(PushPlanDraftRequest)
    -> Result<PushPlan, CoreError>

PushPlan::approve(reviewed_hash)
    -> Result<(), CoreError>

PushPlanEngine::execute(PushPlanExecutionRequest)
    -> Result<PushExecutionReport, CoreError>
~~~

The draft contains discovered actions and approval state. The caller mutates the in-memory plan with an approval hash and passes it back for execution.

### Strength

This resembles the existing directory Plan API and is easy for an interactive caller to understand.

### Weakness

An approved mutable value blurs the boundary between reviewed bytes and execution input. A caller could accidentally rebuild or modify fields after approval, and a cross-process command would need another persistence format with its own canonicalization behavior.

## Design two: immutable document plus approval receipt

~~~rust
PushPlanEngine::draft(PushPlanDraftRequest)
    -> Result<PushPlanDocument, CoreError>

PushPlanEngine::approve(PushPlanApprovalRequest)
    -> Result<PushPlanApprovalReceipt, CoreError>

PushPlanEngine::execute(PushPlanExecutionRequest)
    -> Result<PushExecutionReport, CoreError>
~~~

Draft writes a canonical, exclusive-create Push Plan document. Approve reopens that document, verifies its canonical hash against the owner-reviewed hash, and writes a separate exclusive-create approval receipt bound to the document digest and remote observation. Execute reopens both immutable documents, checks their device and file identities, recomputes every digest, re-observes local and remote reference values, and then performs only exact approved actions.

### Strength

The reviewed object is the exact cross-process execution input. Approval cannot be preserved by mutating the plan, and the approval receipt can be stored separately from execution results. Time-of-check versus time-of-use checks are explicit.

### Weakness

The workflow creates two small documents rather than one mutable value and must specify exclusive creation, canonical encoding, durability, and stale-document recovery.

## Recommended design

Use design two with these public interfaces:

~~~rust
PushPlanEngine::draft(
    PushPlanDraftRequest,
) -> Result<PushPlanDocumentReport, CoreError>

PushPlanEngine::approve(
    PushPlanApprovalRequest,
) -> Result<PushPlanApprovalReceipt, CoreError>

PushPlanEngine::execute(
    PushPlanExecutionRequest,
) -> Result<PushExecutionReport, CoreError>
~~~

GitPublicationProcess is the external side-effect seam. Its production adapter owns only the bounded reference observation and non-force push operations needed by these methods. It is deliberately separate from GitProcess so read-only audit code cannot acquire publication authority.

Tests use:

- real disposable working and bare repositories for reference behavior;
- a local-transport test adapter that is never constructed by the supported command-line path;
- a scripted adapter only for stale observations, hostile or oversized output, authentication failures, and partial publication; and
- a persistence transition seam for exclusive creation, synchronization, identity substitution, and abrupt-failure tests.

## Push Plan document

The versioned canonical document contains:

- a stable Project identifier, never its local path or protected name;
- a sanitized remote identifier and transport class, never its raw address;
- creation time and an expiry or maximum revalidation age;
- one sorted action per exact local-reference to remote-reference transition;
- the expected local object identifier;
- the expected old remote object identifier, or explicit absence for individually approved new references;
- the proposed new remote object identifier;
- the action class: existing upstream branch, new remote branch, or tag;
- non-force policy fixed to true;
- whether item-by-item owner approval is required; and
- a warning that publication can trigger continuous integration, deployments, notifications, and other remote automation.

The schema has no force field that can become true. Refspecs beginning with plus, force options, deletion refspecs, wildcard refspecs, matching refspecs, remote configuration mutation, and arbitrary Git arguments are unrepresentable.

Existing upstream branches are the only actions batch-selectable by default. A new branch or tag has a distinct stable action identifier and requires exact item-by-item approval recorded in the approval receipt. Local-only references may instead remain unpublished when their protection in a verified Project Capsule and the owner decision are recorded.

## Approval receipt

Approval accepts:

- the exact canonical Push Plan document path;
- the owner-reviewed Push Plan hash;
- explicit action identifiers for each new branch or tag;
- acknowledgement of remote side effects; and
- an absent approval receipt destination.

It rejects an edited plan, a duplicate or missing item decision, general directory Plan or Pack hashes, an existing destination, unsafe path replacement, and a first-publication attempt that supplies only non-interactive yes.

The receipt contains the document digest, approved action identifiers, acknowledgement version, approval time, and a random public receipt identifier. It contains no credential, token, raw remote address, repository path, Project name, Git output, or protected content.

## Execution and time-of-check versus time-of-use

Execution follows one narrow action at a time:

1. Open the plan and approval receipt without following final symbolic links and bind their device and file identities.
2. Recompute and compare both canonical digests.
3. Re-observe the exact local reference.
4. Query the exact remote reference immediately before publication.
5. Reject behind, diverged, deleted, created, or otherwise changed state as stale. Iniza never reconciles it.
6. Invoke the publication adapter with the configured remote name and the exact non-force local-reference to remote-reference refspec.
7. Query the exact remote reference again and require it to equal the approved new object identifier.
8. Append and synchronize one secret-free result record before moving to the next approved action.

Execution never fetches, pulls, merges, rebases, commits, checks out, resets, stashes, updates local references, edits configuration, deletes a remote reference, or force-pushes.

A stale action is not attempted. A failed action ends that action with a sanitized failure code. Already proven actions remain successful, unattempted actions remain pending, and the overall exit state is Partial. The Project remains eligible for local Bundle protection regardless of publication outcome.

## Command-line shape

The proposed supported commands are:

~~~text
iniza projects push-plan draft --plan <DIRECTORY_PLAN> --project <PROJECT_ID> --output <PUSH_PLAN>
iniza projects push-plan approve --plan <PUSH_PLAN> --reviewed-hash <HASH> --output <APPROVAL_RECEIPT>
iniza projects push-plan execute --plan <PUSH_PLAN> --approval <APPROVAL_RECEIPT>
~~~

Draft and approve do not contact a remote unless the issue decision explicitly accepts approval-time remote observation. Execute always performs immediate remote revalidation. Machine output is one versioned JavaScript Object Notation result plus optional versioned event lines and stable exit codes. No command accepts a credential, token, password, arbitrary Git option, arbitrary refspec, or Recovery Secret.

## Proposed first tracer bullet after confirmation

Create one disposable Project and local bare remote. Publish the initial main branch outside Iniza, add one local commit, draft one existing-upstream action from the observed remote object identifier to the fixed new local object identifier, write and independently approve the exact Push Plan hash, execute through the local test adapter, and prove the remote main reference equals the approved new object identifier.

The test must also prove:

- the plan contains no force representation;
- no repository hook or fixture executable ran;
- directory Plan and Pack approval values cannot satisfy Push Plan approval;
- the production result and event formats contain no path, raw remote address, credential, protected name, content, or raw Git output; and
- the Project's local dirty and Project Capsule eligibility evidence is unchanged.

The first red test fails because no Push Plan module or public interface exists. Later vertical slices add stale local state, stale remote state, behind and diverged branches, separately approved new branches and tags, partial outcomes, process failure, hostile output, persistence failure, and first-publication command-line approval.

## Owner confirmation requested

Before any COKS-35 test or implementation, confirm or revise:

1. the draft, approve, and execute public seams;
2. the separate immutable approval receipt rather than a mutable approved plan;
3. the distinct GitPublicationProcess capability boundary;
4. sequential exact-ref execution with durable partial outcomes rather than an atomic batch;
5. existing upstream branches as the only default batch actions; and
6. item-by-item approval for new branches and tags, with force push structurally unrepresentable.
