# COKS-38 local manual quality assurance: extended Project Capsules

## What was implemented

Iniza can review one approved and freshly audited Git Project, classify supported and blocking state, bind every ignored-state decision to a stable candidate identifier, capture the reviewed full repository snapshot directly into an encrypted Bundle, and validate a safe Restore without consulting the source Project.

The completed behavior preserves attached or detached current state, exact local references, stashes, index state, staged and unstaged changes, untracked and explicitly reviewed ignored state, binary bytes, safe symbolic links, selected empty directories, reviewed executable modes, disabled hooks, and locally complete Git Large File Storage objects. It supports one to three bounded capture attempts. Changed attempts remain Unverified under incomplete names; only an unchanged, fully verified attempt receives the requested final Bundle name.

Static environment files, certificates, local configuration, uploads, and owner-overridden generated state require explicit encrypted-state decisions. A raw live database is never labelled verified. A separately selected export must pass two stable observations and remain unchanged through capture, while application-level database consistency remains explicitly unverified.

## Prerequisites

- macOS or another Unix environment with Git, Rust, and Cargo installed.
- The Iniza repository with COKS-27 encrypted Bundle, COKS-28 safe Restore, COKS-33 Offline Recovery Key, COKS-34 Project Capsule selection, and COKS-36 Vaultwarden Recovery Method code present.
- No credential, network connection, Vaultwarden account, removable disk, or personal Project is required.
- Use only the synthetic, isolated fixtures created by the tests. This walkthrough does not authorize personal-data capture or erasing the old Mac.

## Setup

From the repository root:

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo build
cargo test --test project_capsule --no-run
```

Expected result: both commands succeed. Only normal generated Rust build artifacts are written under `target/`.

## Primary walkthrough

1. Prove the complete reviewed dirty Project through both Recovery Methods:

   ```sh
   cargo test --test project_capsule complete_dirty_state_rehearses_independently_through_both_recovery_methods -- --exact --nocapture
   ```

   Expected result: one test passes. Offline and Vaultwarden Recovery Methods independently restore exact references, stash, index, worktree, reviewed ignored bytes, binary data, link target, empty directory, and approved executable mode. The source Project is absent during validation, hooks remain disabled, and no executable sentinel runs.

2. Prove detached and locally unreferenced current state:

   ```sh
   cargo test --test project_capsule detached_unreferenced_current_state_is_supported_by_source_independent_rehearsal -- --exact
   ```

   Expected result: one test passes and the restored Project has the exact detached object identifier without relying on a branch or the original source directory.

3. Prove reviewed sensitive state and generated-state override:

   ```sh
   cargo test --test project_capsule explicit_review_encrypts_each_sensitive_class_and_can_override_generated_exclusion -- --exact
   cargo test --test project_capsule reviewed_capture_encrypts_sensitive_state_and_excludes_reproducible_generated_state -- --exact
   ```

   Expected result: both tests pass. Explicitly selected environment, certificate, local-configuration, upload, and generated-tree fixtures restore from encrypted Bundles. A separately excluded reproducible tree does not restore.

4. Prove live-database replacement by stable export evidence:

   ```sh
   cargo test --test project_capsule live_database_is_replaced_by_stable_selected_export_without_verifying_raw_database_bytes -- --exact
   ```

   Expected result: one test passes. The raw live database is absent, the selected export restores, the Receipt records one export-evidence decision, and it reports that application consistency was not automatically verified.

5. Prove local Git Large File Storage completion without fetching:

   ```sh
   cargo test --test project_capsule locally_complete_git_large_file_storage_round_trips_without_fetching -- --exact
   ```

   Expected result: one test passes using only a synthetic local object whose object identifier, size, and digest validate before capture and after Restore.

## Failure and safety checks

1. Prove every unsupported repository shape is visibly blocking:

   ```sh
   cargo test --test project_capsule project_capsule_review_reports_submodules_as_blocking_without_creating_a_bundle -- --exact
   cargo test --test project_capsule project_capsule_review_blocks_bare_repositories_and_linked_worktrees -- --exact
   cargo test --test project_capsule project_capsule_review_blocks_external_or_incomplete_repository_storage -- --exact
   cargo test --test project_capsule project_capsule_review_blocks_active_locks_and_nonportable_names -- --exact
   cargo test --test project_capsule project_capsule_review_supports_only_locally_complete_git_large_file_storage -- --exact
   ```

   Expected result: all five tests pass. The support report blocks submodules, bare repositories, linked worktrees, object alternates, sparse checkouts, partial clones, promisor objects, active locks, non-portable names, and missing Git Large File Storage objects. No network fetch or Bundle creation occurs for blocked state.

2. Prove review freshness and exact authorization:

   ```sh
   cargo test --test project_capsule project_capsule_capture_requires_the_exact_completed_review_hash -- --exact
   cargo test --test project_capsule project_capsule_capture_rejects_ignored_state_added_after_review -- --exact
   cargo test --test project_capsule project_capsule_capture_rejects_repository_blocker_added_after_review -- --exact
   cargo test --test project_capsule changed_database_export_is_rejected_before_project_capsule_bundle_creation -- --exact
   cargo test --test project_capsule production_capture_rejects_a_project_changed_after_its_verified_audit -- --exact
   ```

   Expected result: all five tests pass because an incorrect hash, newly appeared ignored file, newly introduced sparse state, changed export, or stale Project audit stops before a Bundle attempt.

3. Prove bounded retries and incomplete evidence handling:

   ```sh
   cargo test --test project_capsule project_capsule_retry_policy_allows_only_one_to_three_total_attempts -- --exact
   cargo test --test project_capsule bounded_retry_retains_changed_evidence_and_publishes_only_an_unchanged_attempt -- --exact
   cargo test --test project_capsule exhausted_capture_retains_changed_evidence_without_publishing_a_final_bundle -- --exact
   ```

   Expected result: all three tests pass. Zero and more than three attempts are rejected. Changed attempt evidence uses an incomplete name that ordinary Bundle inspection rejects. Only a later unchanged attempt becomes the final Bundle; exhaustion leaves no final Bundle.

4. Prove sanitized and honest output plus Bundle binding:

   ```sh
   cargo test --test project_capsule project_capsule_public_results_are_versioned_sanitized_and_honest -- --exact
   ```

   Expected result: one test passes. Human and versioned JavaScript Object Notation results contain no protected path, filename, content, credential, or Recovery Secret. Capture says Restore Rehearsal was not performed and synchronization was not evaluated. Rehearsal alone may say Restorable. An expectation copied from another authenticated Bundle is rejected before creating a Restore destination.

## Automated verification

Run the focused and repository-wide verification:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test project_capsule
cargo test --all-targets --all-features
git diff --check
```

Expected result: formatting and linting succeed, the focused suite reports 29 passed with zero failures, every repository target passes, and no whitespace error is reported.

## Cleanup or recovery

Passing tests remove their uniquely named synthetic directories from the operating-system temporary directory. No personal Project, external service, or remote repository is changed.

If a test process is interrupted, inspect possible leftovers before taking action:

```sh
find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -name 'iniza-project-capsule-*' -print
```

Open and confirm the exact directory contains only synthetic fixture markers. Move only that exact directory to Trash. Do not use a wildcard deletion command and do not target any personal Project.

Generated Cargo artifacts under `target/` may remain. They do not affect migration evidence.

## Known limitations

- COKS-38 exposes the reviewed in-process Project Capsule interface. COKS-39 provides durable authenticated expectation and Receipt persistence; supported cross-process owner orchestration is not yet complete.
- Database export validation proves stable selected bytes, not application-specific transactional consistency. The owner must provide and review the export procedure.
- Unsupported repository state remains blocking; Iniza does not normalize, fetch, or silently omit it.
- Destination filesystem compatibility still must be proven by the actual Restore Rehearsal on the new Mac.
- Passing synthetic tests does not prove the owner's real Projects are Restorable or Synchronized, does not establish two independent verified copies, and does not authorize erasing the old Mac.
