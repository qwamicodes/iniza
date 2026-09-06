# COKS-31 Verified Copy — local synthetic testing guide

## What was implemented

The Rust core can copy a completed encrypted Bundle to an exact new `.iniza` destination, synchronize it, compare every byte, authenticate the copy before and after atomic publication, and return a secret-free Receipt only when every required check succeeds. Cancellation and failures leave recognizable partial output or a final name that still requires independent verification.

This issue does not yet add a supported cross-process `iniza copy` command because secure Recovery Method loading belongs to COKS-33 and COKS-36. No secret is accepted through command arguments, environment variables, or an ordinary file as a shortcut.

## Prerequisites

- The repository Rust toolchain and installed dependencies.
- Completed COKS-27 Bundle support and COKS-30 partial-name and publication rules.
- No Vaultwarden account, external service, mounted removable media, personal data, or real Recovery Secret is required.

## Setup

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo test --test verified_copy --no-run
```

Compilation should succeed. Every test creates its own isolated temporary directory and synthetic files. Do not substitute personal data or real credentials.

## Primary walkthrough

1. Create and authenticate a Verified Copy:

   ```sh
   cargo test --test verified_copy owner_can_create_a_verified_copy_with_matching_bytes_identity_and_digest -- --exact --nocapture
   ```

   Expect one passing test. Source and destination bytes and whole-file digest match, both files authenticate to the same Bundle identifier, the completed name passes full verification, and the path-free Receipt records the verified result and time.

2. Interrupt and explicitly retry a copy:

   ```sh
   cargo test --test verified_copy cancelled_copy_stays_visibly_partial_and_can_be_explicitly_retried -- --exact --nocapture
   cargo test --test verified_copy only_an_explicitly_approved_matching_partial_copy_can_be_replaced -- --exact
   ```

   Expect two passing tests. Cancellation leaves no completed name; ordinary Verify rejects the partial name. The explicit retry succeeds only when the existing partial is an exact prefix of the authenticated source, while unrelated partial bytes are preserved.

3. Observe weaker durability disclosure:

   ```sh
   cargo test --test verified_copy verified_copy_reports_when_the_destination_has_weaker_durability -- --exact
   ```

   Expect one passing test. The copy is byte- and authentication-verified, but the report explicitly warns that the destination adapter offers weaker filesystem durability.

## Failure and safety checks

```sh
cargo test --test verified_copy verified_copy_refuses_incomplete_or_invalid_source_bundles -- --exact
cargo test --test verified_copy verified_copy_never_overwrites_an_existing_final_destination -- --exact
cargo test --test verified_copy destination_created_during_copy_is_preserved_and_never_overwritten -- --exact
cargo test --test verified_copy permission_failure_at_every_copy_transition_never_reports_an_unchecked_verified_copy -- --exact
cargo test --test verified_copy cloud_placeholder_read_failure_stops_before_destination_creation -- --exact
cargo test --test verified_copy truncated_or_mutated_copy_output_is_never_reported_as_verified -- --exact
cargo test --test verified_copy verified_copy_requires_an_iniza_destination_so_interruption_is_always_recognizable -- --exact
cargo test --test verified_copy verified_copy_receipt_and_results_never_disclose_recovery_secrets_or_paths -- --exact
```

All tests must pass. Incomplete or invalid input is rejected. Existing and late-created destinations are preserved. Permission and unavailable-placeholder failures never produce a successful report. Truncated or mutated bytes never receive the Verified Copy label. Partial output always uses a name ordinary commands reject. Results and Receipts expose neither paths nor Recovery Secrets.

## Automated verification

```sh
cargo test --test verified_copy
cargo test --test multifile_bundle
cargo test --test bundle_resume
cargo test --test restore_transaction
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
git diff --check
```

Every test must pass with no ignored failures. Clippy must produce no warnings, and formatting and whitespace checks must succeed.

## Cleanup or recovery

Passing tests automatically remove their temporary directories. Cargo build artifacts remain under `target`. If a test process is interrupted, inspect the exact `iniza-verified-copy-<process>-<time>-<number>` directory under the operating system temporary directory and move only that confirmed synthetic directory to Trash. Do not use wildcard deletion.

## Known limitations

- The supported command-line flow awaits secure Recovery Method loading in COKS-33 and COKS-36.
- Receipt persistence and readiness aggregation await COKS-39.
- Cloud-placeholder behavior is represented by an injected unavailable-read boundary; provider-specific status reporting is not implemented.
- Only exact-prefix partial replacement is supported. The implementation safely recopies into a new candidate rather than appending in place.
- These tests use synthetic data and do not authorize Owner Dogfood, sole-copy use, or erasing the old Mac.
