# COKS-29 local manual quality assurance

## What was implemented

The Rust core can authenticate an IZ2 Bundle and restore synthetic or duplicated content into an absent or empty destination. It stages and validates content before atomic no-overwrite publication, restores supported metadata, disables hooks and executable content, and can pause and resume through an authenticated path-free journal.

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
```

It should pass without placing content through the substituted destination path.

## Automated verification

Run the focused and repository-wide checks:

```sh
cargo test --test restore_transaction
cargo test --test multifile_bundle
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
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
- Full descriptor-relative child traversal and metadata application, filesystem durability certification, fuzzing, and independent security review remain Owner Dogfood gates.
- In-place merge, overwrite, automatic execution, and machine-erasure decisions are intentionally unsupported.
