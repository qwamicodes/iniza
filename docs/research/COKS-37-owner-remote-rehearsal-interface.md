# COKS-37 owner-remote rehearsal interface clarification

- Status: Proposed for owner confirmation
- Date: 2026-09-07
- Issue: COKS-37

## Existing accepted interfaces

Architecture decision 0013 and the accepted COKS-35 interface define three immutable Push Plan operations: draft, approve, and execute. They also define the separate `GitPublicationProcess` capability, exact non-force reference transitions, a fifteen-minute review window, item-by-item approval for new branches and tags, durable partial results, and post-publication remote verification.

COKS-37 does not change those interfaces or safety rules. It adds the supported command-line binding and rehearses it against one private disposable remote controlled by the owner.

The following command-line behaviors are already implemented and tested:

```text
iniza projects push-plan draft
  --plan <DIRECTORY_PLAN>
  --project <PROJECT_IDENTIFIER>
  --output <PUSH_PLAN>

iniza projects push-plan approve
  --plan <PUSH_PLAN>
  --reviewed-hash <HASH>
  --output <APPROVAL_RECEIPT>
  --acknowledge-remote-side-effects
  [--approve-action <ACTION_IDENTIFIER>]...
```

Draft reconstructs the selected Project only from the approved directory Plan and stable Project identifier, infers the configured remote from the existing upstream branch, and displays every exact transition. Approval contacts no remote. It requires the exact Push Plan hash, explicit acknowledgement, and the exact action identifier for every selected new branch or tag.

## Execution command clarification

The earlier illustrative execution command named only the Push Plan and approval receipt. The core execution interface must also re-open the approved directory Plan, re-audit the exact Project, and exclusively create the durable result log before any remote contact. A stable Project identifier alone cannot locate a Project without the directory Plan, and an implicit result path would weaken no-overwrite and recovery behavior.

The proposed complete command is therefore:

```text
iniza projects push-plan execute
  --directory-plan <DIRECTORY_PLAN>
  --project <PROJECT_IDENTIFIER>
  --push-plan <PUSH_PLAN>
  --approval <APPROVAL_RECEIPT>
  --result <RESULT_LOG>
```

All five inputs are required and may appear in any order. The directory Plan must remain approved and non-stale. The Project identifier must resolve to exactly one fresh, verified Project audit. The Push Plan and approval receipt must be canonical, unchanged, mutually bound, unexpired, and owned by that Project. The result path must be absent.

Execution creates and synchronizes the result-log header before contacting the remote. It then revalidates one exact local and remote reference, performs one non-force publication, re-reads that exact remote reference, and synchronizes the outcome before considering another action. A stale, rejected, canceled, or failed action produces secret-free Partial evidence and leaves all later actions Pending.

The command accepts no credential, token, password, arbitrary Git argument, arbitrary reference specification, force option, deletion, wildcard, recovery secret, or general yes flag. Existing keychain and Secure Shell authentication may operate only inside the installed Git process.

## Disposable owner remote

The proposed rehearsal remote is a new private GitHub repository named `qwamicodes/iniza-publication-rehearsal`. A read-only lookup on 2026-09-07 found no existing repository with that name.

The repository will be created empty, without a template, workflow, deployment, webhook, secret, branch protection exception, or production integration. Only synthetic text and synthetic Git history will be used. The rehearsal will:

1. publish the initial `main` branch outside Iniza to establish an existing upstream;
2. add one synthetic local commit and harmless dirty local state;
3. draft and review the exact existing-upstream transition;
4. require the owner-reviewed hash and remote-side-effect acknowledgement;
5. execute one non-force publication and verify the remote `main` reference;
6. separately rehearse cancellation, stale-state rejection, authentication failure evidence, and one item-approved synthetic branch or tag only after the existing-upstream path succeeds; and
7. retain the remote until the owner reviews the result. Any later deletion requires a separate explicit owner request.

No personal Project, source file, credential, Recovery Secret, or production repository will enter this rehearsal.

## Confirmation required

Before implementation of the side-effecting execution command or creation of the external repository, the owner must confirm:

1. the five-input execution command above;
2. creation of the private disposable GitHub repository;
3. use of synthetic history only;
4. no remote mutation before exact Push Plan approval; and
5. retention of the disposable repository until a separately approved cleanup.
