# COKS-29 local manual quality assurance

## What was implemented

The Rust core can authenticate an IZ2 Bundle and restore synthetic or duplicated content into an absent or empty destination. Both authentication passes remain bound to one no-follow Bundle file handle. Restore creates restrictive transaction state, performs bounded exact-tree validation, and publishes without overwrite through retained directory capabilities. Materialization and finalization use bounded, identity-checked descriptor windows instead of keeping one open file per Migration Item. Restore applies supported metadata without path traversal, disables hooks and executable content, revalidates each published candidate's authenticated bytes and restrictive mode before applying its reviewed final mode, and can resume from a staged pause, a publication pause, or an abrupt publication interruption through an authenticated path-free journal.

## Prerequisites

- macOS with the Rust toolchain used by this repository.
- Repository dependencies installed through `cargo`.
- COKS-27 complete.
- No credentials, Vaultwarden session, personal files, or sole-copy data are required or permitted for this walkthrough.

## Setup

From the repository root, create one disposable parent and run the synthetic example into an absent child:

```sh
qa_parent="$(mktemp -d /tmp/iniza-coks29-qa.XXXXXX)"
cargo run --example restore_rehearsal -- "$qa_parent/rehearsal"
```

Keep the printed `qa_parent` value in the same terminal. The example generates its own in-memory Recovery Secret and never prints or persists it.

## Primary walkthrough

1. Read the human Restore result printed by the example. It should say `Restore completed`, report four restored items and nineteen restored bytes, and report zero disabled hooks and zero unapplied metadata on the supported macOS adapter.
2. Compare the non-empty file:

   ```sh
   cmp "$qa_parent/rehearsal/synthetic-source/settings.txt" "$qa_parent/rehearsal/restored/settings.txt"
   ```

   `cmp` should print nothing and exit successfully.
3. Compare the empty file and inspect the completed destination:

   ```sh
   test ! -s "$qa_parent/rehearsal/restored/nested/empty.txt"
   test ! -e "$qa_parent/rehearsal/restored/.iniza-restore"
   find "$qa_parent/rehearsal/restored" -print
   ```

   Both `test` commands should succeed. The listing should contain only the restored tree, with no transaction-control directory.

## Failure and safety check

Create an unrelated destination entry, then rerun the example against a different absent workspace only; the example itself refuses any existing workspace. The automated publication-race test exercises the more precise boundary:

```sh
cargo test --test restore_transaction restore_never_overwrites_a_file_created_during_publication -- --exact
```

It should pass, proving the competing bytes remain unchanged and transaction control is removed. Also run:

```sh
cargo test --test restore_transaction destination_identity_change_is_rejected_before_publication -- --exact
cargo test --test restore_transaction destination_substitution_between_identity_and_open_is_rejected_before_staging -- --exact
```

It should pass without placing content through the substituted destination path.

Then exercise staged-content containment and publication recovery:

```sh
cargo test --test restore_transaction staged_content_substitution_with_the_same_size_is_rejected_before_publication -- --exact
cargo test --test restore_transaction restore_rejects_an_unplanned_item_injected_into_staging -- --exact
cargo test --test restore_transaction owner_can_resume_a_restore_paused_during_publication -- --exact
cargo test --test restore_transaction owner_can_resume_after_an_abrupt_materialization_interruption -- --exact
cargo test --test restore_transaction owner_can_resume_after_an_abrupt_publication_interruption -- --exact
cargo test --test restore_transaction restore_reauthenticates_each_publication_candidate_before_checkpointing_it -- --exact
cargo test --test restore_transaction restore_rejects_a_publication_candidate_made_executable_before_checkpointing_it -- --exact
cargo test --test restore_transaction owner_can_resume_only_the_matching_authenticated_paused_restore -- --exact
cargo test --test restore_transaction restore_preserves_a_reviewed_mode_that_the_destination_owner_cannot_read -- --exact
cargo test --test restore_transaction restore_stops_enumerating_a_staged_tree_beyond_the_path_depth_limit -- --exact
cargo test --test restore_transaction owner_can_resume_when_interrupted_final_mode_application_made_a_file_unreadable -- --exact
cargo test --test restore_transaction restore_rejects_a_publication_candidate_replaced_after_its_checkpoint -- --exact
cargo test --test restore_transaction restore_reports_an_existing_nonempty_destination_as_a_conflict -- --exact
cargo test --test restore_transaction restore_handles_more_planned_items_than_the_open_file_limit -- --exact
```

All tests should pass. They prove that altered, extra, or overdeep staged content is never published, a substituted destination is rejected before staging, publication candidates are reopened without following symbolic links and must keep their authenticated stable identity through finalization, the number of planned items can exceed a deliberately low open-file limit, reviewed owner-unreadable modes can be applied after validation and safely normalized for authenticated Resume, non-empty destinations produce a conflict without changing unrelated bytes, non-canonical or unauthenticated journals are rejected, interrupted rollback state is recoverable, and cooperative or abrupt interruption can resume to exact authenticated content. The materialization test deliberately uses a disposable destination path containing spaces.

## Automated verification

Run the focused and repository-wide checks:

```sh
cargo test --test restore_transaction
cargo test --test multifile_bundle
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
git diff --check
```

Every test must pass, Clippy must report no warnings, formatting must be clean, and `git diff --check` must print nothing.

## Cleanup or recovery

First verify the variable still points to the disposable path created above:

```sh
test -n "$qa_parent"
case "$qa_parent" in /tmp/iniza-coks29-qa.*) ;; *) exit 1 ;; esac
```

Then move that exact directory to the macOS Trash rather than deleting unrelated data:

```sh
mv "$qa_parent" "$HOME/.Trash/"
unset qa_parent
```

If a paused automated test is interrupted, remove only its generated `iniza-restore-*` temporary directory after confirming it contains synthetic fixtures.

## Known limitations

- This is a synthetic and duplicated-data prototype, not authorization to restore real sole-copy owner data.
- The supported command-line Restore and Recovery Secret acquisition workflow is deferred to COKS-33 and COKS-36; this walkthrough uses the reusable Rust core example.
- Resume rebuilds authenticated staging rather than continuing within a partially written file.
- macOS metadata is implemented; other platforms report unsupported metadata.
- Capability-relative traversal, metadata application, publication, recovery, and cleanup are implemented. Filesystem durability certification across supported filesystem types, fuzzing, and independent security review remain Owner Dogfood gates.
- In-place merge, overwrite, automatic execution, and machine-erasure decisions are intentionally unsupported.
