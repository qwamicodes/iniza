# COKS-35 local manual quality assurance: immutable Push Plans

## What was implemented

COKS-35 adds a core Push Plan workflow that discovers exact existing-upstream publication actions, optionally adds selected local-only branches or tags, writes an immutable review document, requires its exact hash and a separate remote-side-effect acknowledgement, and executes only unchanged non-force actions. It creates an append-only result log before remote contact and synchronizes every proven action before attempting another. It produces durable sanitized Complete or Partial evidence without changing dirty local Project state. Force push, deletion, wildcard publication, hooks, arbitrary Git arguments, and local-file transport in the production adapter are unavailable.

## Prerequisites

- macOS or another Unix development environment with Rust and Git installed.
- The Iniza repository and completed COKS-28 Project audit behavior.
- No credential, token, password, Vaultwarden session, personal repository, or network connection is required.
- Use only the disposable local repositories created by the tests. Do not substitute a personal Project or a real remote for this walkthrough.

## Setup

From the repository root:

```sh
cargo build
cargo test --test push_plan --no-run
```

Expected result: both commands finish successfully and create only normal Rust build artifacts under `target/`.

## Primary walkthrough

1. Prove the existing-upstream review and publication workflow:

   ```sh
   cargo test --test push_plan exact_approved_existing_upstream_action_publishes_without_changing_local_project_state -- --exact --nocapture
   ```

   Expected result: one test passes. The test proves the Push Plan contains exact local and remote references and object identifiers, a fixed non-force policy, a fifteen-minute validity window, and a remote automation warning. A wrong directory Plan hash and missing acknowledgement are rejected. Exact Push Plan approval advances only the disposable remote branch, preserves dirty local state, suppresses the executable pre-push hook, and writes secret-free Complete evidence.

2. Prove separate approval for new references:

   ```sh
   cargo test --test push_plan new_remote_branch_requires_exact_item_approval_before_publication -- --exact --nocapture
   cargo test --test push_plan new_remote_tag_requires_exact_item_approval_before_publication -- --exact --nocapture
   ```

   Expected result: both tests pass. General acknowledgement alone cannot authorize the new branch. The stable new-branch or tag action identifier must be included in the separate approval receipt before the disposable remote reference is created.

3. Prove production subprocess containment:

   ```sh
   cargo test --test push_plan production_publication_adapter_uses_exact_non_force_arguments_and_a_clean_environment -- --exact --nocapture
   cargo test --test push_plan production_publication_adapter_rejects_oversized_git_output -- --exact --nocapture
   cargo test --test push_plan publication_capabilities_cannot_represent_force_deletion_or_option_injection -- --exact --nocapture
   ```

   Expected result: all three tests pass. Validated value types reject force prefixes, deletion, wildcards, option injection, unsafe remote names, and non-object identifiers. The executable fixture sees direct non-force arguments, disabled hooks and implicit tags, denied local-file transport, no inherited home environment variable, disabled prompts, and disabled credential-manager interaction. Output larger than one mebibyte fails closed.

## Failure and safety checks

Run the stale, rejection, substitution, divergence, and hostile-advertisement checks:

```sh
cargo test --test push_plan remote_change_after_approval_is_contained_as_partial_without_publication_attempt -- --exact --nocapture
cargo test --test push_plan changed_local_project_observation_after_approval_blocks_publication -- --exact --nocapture
cargo test --test push_plan rejected_publication_is_recorded_as_sanitized_partial_evidence -- --exact --nocapture
cargo test --test push_plan approval_rejects_a_symbolic_link_instead_of_following_an_immutable_push_plan -- --exact --nocapture
cargo test --test push_plan divergent_remote_branch_requires_manual_reconciliation_without_creating_a_push_plan -- --exact --nocapture
cargo test --test push_plan mismatched_remote_advertisement_is_rejected_instead_of_authorizing_another_reference -- --exact --nocapture
cargo test --test push_plan each_successful_action_is_synchronized_before_the_next_publication_attempt -- --exact --nocapture
cargo test --test push_plan actions_after_a_rejection_remain_explicitly_pending_and_are_never_attempted -- --exact --nocapture
cargo test --test push_plan edited_push_plan_and_existing_result_destination_fail_before_publication -- --exact --nocapture
```

Expected result: all nine tests pass. Changed local or remote state and remote rejection produce sanitized Partial evidence without overwriting the remote. Edited and symbolic-link-substituted Push Plans create no approval receipt. An existing result file is preserved and blocks remote contact. Divergence and a mismatched advertised reference create no Push Plan. An interruption before action two leaves action one's synchronized success record in the append-only result log. A rejection in a three-action plan records one success, one failure, and one Pending action without attempting the final publication. No pre-push hook runs.

## Automated verification

Run:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test push_plan
cargo test --all-targets --all-features
```

Expected result: formatting and linting report no issue, all focused Push Plan tests pass, and the full repository suite has zero failures and zero ignored safety regressions.

## Cleanup or recovery

The tests create unique directories under the operating system temporary directory and remove them automatically. If a test process is killed, inspect before removal:

```sh
find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -name 'iniza-push-plan-*' -print
```

Remove only an exact disposable path after inspecting it. Never use a wildcard removal command and never target a personal repository.

## Known limitations

- This issue exposes the reviewed core capability. Supported cross-process command-line orchestration is part of the later integration stage.
- The production adapter supports configured Hypertext Transfer Protocol Secure and Secure Shell remotes only. Disposable local remotes are a test-owned capability.
- Authentication must already be available through a separately approved secure mechanism; Iniza accepts no credential argument.
- The result proves publication, not local recoverability. A verified Project Capsule and Restore Rehearsal remain required.
- This synthetic rehearsal does not establish Owner Dogfood readiness and never authorizes erasing the old Mac.
