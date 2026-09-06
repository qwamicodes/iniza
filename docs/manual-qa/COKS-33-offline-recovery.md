# COKS-33 Offline Recovery Key — local synthetic testing guide

## What was implemented

Iniza can authenticate a completed Bundle, write its independently generated Offline Recovery Key to a restrictive self-identifying document through a separate-storage boundary, and independently reopen that document to fully authenticate the Bundle. Successful rehearsal records only the Bundle identity, Recovery Method identity, and time.

The command line supports rehearsal with document and Bundle paths. The key itself never belongs in a process argument, environment variable, prompt, standard output, standard error, Plan, Receipt, diagnostic, or clipboard.

## Prerequisites

- The repository Rust toolchain and installed dependencies.
- Completed COKS-27 IZ2 Bundle support.
- No Vaultwarden account, personal data, real Recovery Secret, or removable storage is needed for this synthetic guide.

Do not substitute a personal Bundle or real recovery target. Physical removable-media rehearsal is a later Owner Dogfood gate.

## Setup

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo test --test offline_recovery --no-run
cargo test --test offline_recovery_cli --no-run
```

Both test binaries should compile. Their fixtures use isolated temporary directories and an explicit synthetic removable-storage adapter.

## Primary walkthrough

1. Write and independently rehearse a document through the public core:

   ```sh
   cargo test --test offline_recovery owner_can_write_and_independently_rehearse_an_offline_recovery_key -- --exact --nocapture
   ```

   Expect one passing test. The produced document is self-identifying, contains only eight fixed fields, has mode `0600` on Unix, and unlocks the completed synthetic Bundle on a fresh read.

2. Exercise the supported cross-process command:

   ```sh
   cargo test --test offline_recovery_cli owner_and_automation_can_rehearse_using_only_the_saved_offline_document -- --exact --nocapture
   ```

   Expect one passing test. The test invokes `iniza recovery offline rehearse` in both human and JavaScript Object Notation modes. Human output explains the proven unlock; machine output is one versioned line. Neither output contains paths, protected content, or the key.

3. Prove the loaded document can drive Restore without the other Recovery Method:

   ```sh
   cargo test --test offline_recovery saved_offline_recovery_key_can_drive_restore_without_the_other_method -- --exact
   ```

   Expect one passing test and an exact restored synthetic file. The loaded Recovery Method remains inside a redacted, zeroizing handle.

4. Inspect the secret-leak boundary:

   ```sh
   cargo test --test offline_recovery process_arguments_outputs_plan_and_receipt_never_disclose_the_offline_secret -- --exact
   cargo test --test offline_recovery offline_recovery_randomness_is_distinct_across_methods_and_bundles -- --exact
   ```

   Expect both tests to pass. Only the recovery document contains the encoded key. Process captures, arguments, the Plan, reports, and the rehearsal Receipt do not. Fresh Packs produce different keys, and treating the Offline Recovery Key as the Vaultwarden Recovery Method does not unlock that independent slot.

## Failure and safety checks

```sh
cargo test --test offline_recovery existing_recovery_document_is_never_overwritten -- --exact
cargo test --test offline_recovery wrong_truncated_modified_and_mismatched_documents_fail_without_comparison_details -- --exact
cargo test --test offline_recovery prepublication_persistence_failure_never_leaves_a_recovery_document -- --exact
cargo test --test offline_recovery symbolic_links_and_overly_permissive_documents_are_rejected -- --exact
cargo test --test offline_recovery losing_the_offline_document_explains_that_there_is_no_backdoor -- --exact
```

Expect every test to pass. Existing files and symbolic-link targets remain untouched. Hostile documents return only `Bundle authentication failed`. Injected create, write, and synchronization failures never report success or leave the transaction's prepublication document. Loss guidance states that Iniza cannot reconstruct the key.

## Automated verification

```sh
cargo test --test offline_recovery
cargo test --test offline_recovery_cli
cargo test --test multifile_bundle
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
git diff --check
```

Every test must pass with no ignored failures. Clippy must produce no warnings, and formatting and whitespace checks must succeed.

## Cleanup or recovery

Passing tests remove their isolated temporary directories. If a test is interrupted, inspect the exact `iniza-offline-recovery-<process>-<time>-<number>` or `iniza-offline-recovery-cli-<process>-<time>-<number>` path under the operating-system temporary directory and move only that confirmed synthetic directory to Trash. Do not use wildcard deletion.

## Known limitations

- The synthetic write adapter deliberately stands in for removable storage. No physical Offline Recovery Key has been created or rehearsed yet.
- The supported Pack command awaits Vaultwarden integration so it can persist and prove both independent Recovery Methods in one transaction.
- Existing recovery documents are never replaced in this release; choose and review a new target.
- The key document is intentionally plaintext secret material protected by storage separation and file permissions. Never store it beside either Bundle copy.
- These tests do not authorize personal or sole-copy use, formatting the old Mac, or deleting any conventional backup.
