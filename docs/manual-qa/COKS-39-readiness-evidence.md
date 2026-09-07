# COKS-39 Readiness Evidence local manual quality assurance

## What was implemented

COKS-39 combines typed, secret-free operation Receipts and exact Owner Attestations into one private append-only Readiness Evidence store. Status reopens current artifacts before reporting them as current, keeps each Project's Restorable and Synchronized conclusions separate, reports missing or contradictory evidence as blocking, and never grants permission to erase a machine. Complete Evidence requires one current Verified Copy classified as external storage and another classified as iCloud Drive; destination paths are neither stored nor rendered.

## Prerequisites

- Apple Silicon macOS or another supported Rust development host.
- Rust and Git available on `PATH`.
- The Iniza repository and its locked dependencies.
- No Vaultwarden credential, personal file, real remote, or real Recovery Secret is required.
- COKS-29, COKS-31, COKS-33, COKS-34, COKS-35, COKS-36, COKS-37, and COKS-38 completed.

All walkthroughs use disposable synthetic directories, an in-process synthetic Vaultwarden adapter, generated Recovery Secrets, and a local bare Git remote. They do not contact or change an external service.

## Setup

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo build --locked
```

Expected result: the debug build completes without warnings or dependency changes.

## Primary walkthrough

1. Exercise the complete Readiness Evidence story:

   ```sh
   cargo test --locked --test readiness_evidence complete_synthetic_evidence_chain_reports_complete_evidence_without_erase_permission -- --exact --nocapture
   ```

   Expected result: one test passes. Its synthetic filesystem boundary classifies one current Verified Copy as external storage and the other as iCloud Drive. The resulting status is `Complete evidence`, exits successfully, and still states `This is not permission to erase a machine.`

2. Observe independent Project conclusions and remote revalidation:

   ```sh
   cargo test --locked --test readiness_evidence complete_push_plan_execution_makes_only_the_project_synchronized -- --exact --nocapture
   cargo test --locked --test readiness_evidence project_capsule_and_restore_rehearsal_make_only_the_project_restorable -- --exact --nocapture
   ```

   Expected result: both tests pass. The first proves a complete exact synthetic Push Plan makes only Synchronized current and that a later remote change invalidates it. The second proves a verified Project Capsule and source-independent rehearsal make only Restorable current.

3. Observe the deliberate capsule-only path for local-only Project references:

   ```sh
   cargo test --locked --test readiness_evidence local_only_references_are_synchronized_only_with_current_capsule_protection_and_owner_decision -- --exact --nocapture
   ```

   Expected result: one test passes. Before the fixed owner decision, the Project is Restorable but not Synchronized. An arbitrary evidence reference is rejected. The exact current Project Capsule capture Receipt makes Synchronized current, and withdrawing that decision makes it blocking again. The synthetic remote is never changed.

4. Observe both Recovery Methods, safe Restore, and every selected Verified Copy:

   ```sh
   cargo test --locked --test readiness_evidence typed_vaultwarden_receipt_revalidates_through_the_loaded_recovery_method -- --exact --nocapture
   cargo test --locked --test readiness_evidence typed_recovery_and_copy_receipts_are_current_only_while_their_artifacts_revalidate -- --exact --nocapture
   cargo test --locked --test readiness_evidence completed_restore_rehearsal_is_current_only_for_its_bundle_and_destination -- --exact --nocapture
   cargo test --locked --test readiness_evidence every_selected_verified_copy_must_revalidate_independently -- --exact --nocapture
   ```

   Expected result: all four tests pass. A changed copy cannot be hidden by another healthy copy, and every current conclusion remains bound to its authenticated artifact and Recovery Method.

## Failure and safety checks

1. Exercise corrupt and interrupted evidence storage:

   ```sh
   cargo test --locked --test readiness_evidence tampered_evidence_record_fails_closed -- --exact --nocapture
   cargo test --locked --test readiness_evidence missing_evidence_sequence_fails_closed -- --exact --nocapture
   cargo test --locked --test readiness_evidence incomplete_evidence_candidate_fails_closed -- --exact --nocapture
   cargo test --locked --test readiness_evidence record_candidate_creation_failure_preserves_the_last_valid_evidence_chain -- --exact --nocapture
   ```

   Expected result: all four tests pass. Each corruption or interruption is isolated and blocks status without hiding the last valid chain.

2. Exercise Owner Attestation containment:

   ```sh
   cargo test --locked --test readiness_evidence exact_owner_attestation_is_prepared_without_writing_and_recorded_only_as_owner_stated -- --exact --nocapture
   cargo test --locked --test readiness_evidence withdrawing_an_owner_attestation_appends_history_and_removes_the_active_claim -- --exact --nocapture
   cargo test --locked --test readiness_evidence contradictory_active_owner_attestations_remain_a_blocking_gap -- --exact --nocapture
   ```

   Expected result: all three tests pass. Preparation is read-only, confirmation is owner-stated, withdrawal preserves history, and contradictory active claims remain blocking.

   Then exercise the operation-specific bindings:

   ```sh
   cargo test --locked --test readiness_evidence typed_vaultwarden_receipt_revalidates_through_the_loaded_recovery_method -- --exact --nocapture
   cargo test --locked --test readiness_evidence project_capsule_and_restore_rehearsal_make_only_the_project_restorable -- --exact --nocapture
   cargo test --locked --test readiness_evidence completed_restore_rehearsal_is_current_only_for_its_bundle_and_destination -- --exact --nocapture
   ```

   Expected result: all three tests pass. Arbitrary evidence references are rejected. Vaultwarden claims bind the current Vaultwarden Receipt, the representative build claim binds the current Project Capsule rehearsal Receipt, and the second-environment claim binds the current Restore Rehearsal Receipt. A superseding Vaultwarden Receipt makes older statements blocking.

3. Prove that two files on one ordinary filesystem are not independent protection:

   ```sh
   cargo test --locked --test readiness_evidence two_verified_copy_files_on_one_filesystem_are_not_independent_protection -- --exact --nocapture
   ```

   Expected result: the test passes by observing Blocking Gaps. Both required location classes remain missing: one external-storage Verified Copy and one iCloud Drive Verified Copy. Different file names and directories do not satisfy the requirement.

## Automated verification

```sh
cargo test --locked --test readiness_evidence
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Expected result: every command exits successfully with zero failed or ignored tests and no Clippy or formatting findings.

## Cleanup and recovery

The tests create unique temporary directories and remove them automatically. They do not leave a Vaultwarden item or remote repository. If a test process is force-terminated, inspect the printed temporary path before removing only that directory; never remove a broad temporary, home, or project root.

## Known limitations

- COKS-39 exposes Rust interfaces; COKS-41 must connect them to the supported encrypted command-line workflow.
- The complete walkthrough uses synthetic data and a local bare Git remote.
- Automated tests inject the two positive storage classes at the operating-system boundary. The owner's eventual personal migration must separately create and revalidate copies on an actual external volume and in iCloud Drive through the supported command-line workflow delivered by COKS-41.
- A local record digest does not prove authorship against a hostile administrator who can replace the entire store and recompute digests.
- Passing these tests does not authorize personal sole-copy use, deletion of independent backups, external Git publication, or erasing a machine.
