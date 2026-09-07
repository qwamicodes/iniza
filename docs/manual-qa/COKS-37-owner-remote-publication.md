# COKS-37 owner-remote publication — local testing guide

## What was implemented

Iniza now exposes the safe command-line foundation for immutable Push Plans.

`projects push-plan draft` reopens one approved directory Plan, resolves one stable Project identifier, repeats the local Project audit, infers the configured remote from the existing upstream branch, performs exact read-only remote reference observations, and writes one exclusive immutable Push Plan. Its result displays the exact local and remote references, expected old object identifier, proposed new object identifier, non-force policy, action identifier, and warning about continuous integration, deployment, and notification side effects.

`projects push-plan approve` contacts no remote. It reopens the exact Push Plan, requires its reviewed hash, requires explicit acknowledgement of remote side effects, requires each new branch or tag action identifier separately, and exclusively writes a secret-free approval receipt.

Production drafting permits only Hypertext Transfer Protocol Secure or Secure Shell transport. Local-file transport remains available only through test-owned adapters and is rejected by the command-line executable. Existing Secure Shell and keychain authentication can operate without entering an Iniza argument, Plan, Receipt, result, or diagnostic.

The side-effecting `projects push-plan execute` binding and the real disposable owner-remote publication remain pending owner confirmation. Nothing in this guide contacts or changes a real remote.

## Prerequisites

- macOS or another Unix development environment with Rust, Cargo, and Git installed.
- The current Iniza repository checkout.
- Completed COKS-28 Project audit and COKS-35 immutable Push Plan core behavior.
- No credential, token, password, Vaultwarden session, personal Project, network connection, or external storage is required for these local tests.

Use only the disposable synthetic repositories created by the tests.

## Setup

From the repository root:

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo build
cargo test --test push_plan_cli --no-run
```

Expected result: both commands succeed and create only ordinary Rust build output beneath `target/`.

## Primary walkthrough

1. Prove exact cross-process approval:

   ```sh
   cargo test --test push_plan_cli automation_can_approve_the_exact_immutable_push_plan_without_contacting_the_remote -- --exact --nocapture
   ```

   Expected result: one test passes. A valid immutable Push Plan is prepared through the public core interface, then the real command-line executable writes an approval receipt only after receiving the exact reviewed hash and remote-side-effect acknowledgement. The command makes no remote call.

2. Prove item-by-item new-reference approval:

   ```sh
   cargo test --test push_plan_cli command_line_approval_requires_the_exact_new_reference_action_identifier -- --exact --nocapture
   ```

   Expected result: one test passes. General acknowledgement alone cannot approve the synthetic new branch. Supplying the exact stable action identifier produces the approval receipt. No branch is published.

3. Prove the production transport restriction:

   ```sh
   cargo test --test push_plan_cli production_draft_command_rejects_local_transport_without_creating_a_push_plan -- --exact --nocapture
   ```

   Expected result: one test passes because the command returns publication exit code 41, emits a sanitized error, and creates no Push Plan for the local-file remote.

## Expected result

- Exact immutable Push Plan approval works across process boundaries.
- Missing acknowledgement or missing new-reference decisions create no approval receipt.
- Production drafting cannot use a local-file remote.
- Machine-readable results contain one versioned JavaScript Object Notation object and stable error codes.
- No result contains the disposable Project path, remote path, Project name, credential, token, protected content, or raw Git output.
- No test publishes, force-pushes, deletes, or changes a remote reference.

## Failure and safety checks

Run the missing-acknowledgement behavior:

```sh
cargo test --test push_plan_cli missing_remote_side_effect_acknowledgement_creates_no_push_plan_approval -- --exact --nocapture
```

Expected result: the test passes because the command exits with approval-required code 10, reports `INIZA-E010`, and leaves the approval destination absent.

Run the core stale-state, remote-rejection, partial-result, and unsafe-input checks:

```sh
cargo test --test push_plan remote_change_after_approval_is_contained_as_partial_without_publication_attempt -- --exact
cargo test --test push_plan changed_local_project_observation_after_approval_blocks_publication -- --exact
cargo test --test push_plan actions_after_a_rejection_remain_explicitly_pending_and_are_never_attempted -- --exact
cargo test --test push_plan publication_capabilities_cannot_represent_force_deletion_or_option_injection -- --exact
```

Expected result: all four tests pass. Stale local or remote state prevents publication, rejection retains durable Partial evidence and leaves later actions Pending, and unsafe publication shapes cannot be constructed.

## Automated verification

Run the focused command and core suites:

```sh
cargo test --test push_plan_cli
cargo test --test push_plan
```

Expected result: 4 command-line tests and 16 core tests pass with no failure.

Run repository-wide verification:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Expected result: formatting and static analysis succeed, and every repository test passes with no ignored or skipped safety regression. The complete test run was observed passing on 2026-09-07 after the command-line foundation was added.

## Cleanup or recovery

The tests create uniquely named disposable directories under the operating-system temporary directory and remove them automatically. They do not alter the Iniza repository or any real remote.

If a test process is forcibly terminated, inspect before cleanup:

```sh
find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -name 'iniza-push-plan-cli-*' -print
```

Move only an exact inspected synthetic directory to Trash. Do not use a wildcard deletion command and do not target a personal Project.

## Known limitations

- The side-effecting execution command is not implemented because its complete five-input interface awaits owner confirmation.
- The private disposable GitHub repository has not been created and no external reference has been changed.
- Authentication failure, server rejection, cancellation, mixed-action partial failure, existing-upstream publication, and item-approved new-reference publication must still be rehearsed against the owner-controlled disposable remote.
- COKS-37 remains In Progress until the owner reviews the real remote result.
- Publication proves only Synchronized evidence. It does not make a Project Restorable, establish Owner Dogfood readiness, or authorize erasing the old Mac.
