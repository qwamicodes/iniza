# COKS-30 synthetic testing guide — issue still in progress

## What is available

The Rust core can pause Pack at a Migration Item boundary, save an encrypted authenticated checkpoint, revalidate it, and Resume into a completed Bundle. Both Recovery Methods independently verify and restore completed protected content. This is not yet a supported cross-process command-line migration workflow.

## Prerequisites and setup

Use the repository's Rust toolchain and installed dependencies on macOS. COKS-27 supplies the Bundle engine and COKS-29 supplies Restore. No Vaultwarden account, external service, real Recovery Secret, or personal data is needed.

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo test --test bundle_resume --no-run
```

Compilation should succeed. Every walkthrough command below creates its own isolated temporary directory and synthetic data. Nothing is pushed, uploaded, or overwritten outside that disposable directory. Do not substitute personal data or real credentials.

## Primary walkthrough

1. Exercise a clean pause:

   ```sh
   cargo test --test bundle_resume owner_can_interrupt_pack_at_a_checkpoint_without_publishing_a_bundle -- --exact --nocapture
   ```

   Expect one passing test. It checks Paused, an authenticated checkpoint event, no final Bundle, rejected Inspect and Verify of the partial, and rejected Restore with no destination created.

2. Resume and restore the protected content:

   ```sh
   cargo test --test bundle_resume owner_can_resume_a_paused_bundle_and_restore_every_protected_item -- --exact --nocapture
   ```

   Expect one passing test. Both Recovery Methods verify two content chunks containing forty-three bytes. Restore reproduces `first.txt` and `second.txt` exactly; the completed Bundle has no remaining canonical partial file.

3. Pause an already resumed attempt and Resume again:

   ```sh
   cargo test --test bundle_resume owner_can_pause_resumed_pack_and_resume_again -- --exact --nocapture
   ```

   Expect one passing test with a fully verified final Bundle and no ordinary checkpoint artifacts left after success.

4. Exercise process termination:

   ```sh
   cargo test --test bundle_resume process_termination_preserves_only_authenticated_resumable_progress -- --exact --nocapture
   ```

   This deliberately terminates disposable child processes with exit code 73. The parent test must pass: a saved checkpoint resumes; uncheckpointed output remains partial and requires a restart; completed output fully verifies; source bytes remain unchanged. This checks exposed progress events, not every operating-system persistence transition.

5. Exercise termination after a resumed checkpoint becomes durable:

   ```sh
   cargo test --test bundle_resume owner_can_resume_after_termination_at_a_resumed_pack_checkpoint -- --exact --nocapture
   ```

   Expect one passing test. The next invocation authenticates the older and newer progress, continues from the authentic newer checkpoint, fully verifies the completed Bundle, and leaves the synthetic source unchanged.

6. Exercise termination after every durable promotion transition:

   ```sh
   cargo test --test bundle_resume owner_can_resume_after_termination_at_every_checkpoint_promotion_step -- --exact --nocapture
   ```

   Expect one passing test. Disposable children exit with code 73 after the promotion journal is synchronized, after each of the four synchronized exclusive renames, after each synchronized superseded-artifact removal, and after journal removal. Every following Resume must authenticate and finish the Bundle without changing the synthetic source.

## Failure and safety checks

```sh
cargo test --test bundle_resume resume_rejects_untrusted_inputs_without_changing_saved_progress -- --exact
cargo test --test bundle_resume every_partial_artifact_name_is_rejected_even_with_complete_bundle_bytes -- --exact
cargo test --test bundle_resume checkpoint_capacity_failure_preserves_previous_resumable_progress -- --exact
cargo test --test bundle_resume corrupted_interrupted_resume_never_displaces_older_authenticated_progress -- --exact
cargo test --test bundle_resume completed_resume_never_removes_an_unrelated_saved_path_replacement -- --exact
cargo test --test bundle_resume completed_resume_never_removes_an_unrelated_checkpoint_path_replacement -- --exact
cargo test --test bundle_resume paused_resume_never_promotes_through_a_replaced_saved_partial -- --exact
cargo test --test bundle_resume paused_resume_never_promotes_through_a_replaced_saved_checkpoint -- --exact
```

All tests must pass. Modified inputs cannot change saved progress or publish a final Bundle. Partial artifact names cannot be read as completed Bundles. Simulated capacity loss at checkpoint creation retains the earlier authenticated progress, which subsequently resumes and verifies. Corrupted newer progress cannot displace the older pair, and saved-path replacements are preserved rather than moved or deleted.

## Automated verification

```sh
cargo test --test bundle_resume
cargo test --test multifile_bundle
cargo test --test restore_transaction
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
git diff --check
```

Every test must pass with no ignored failures. Clippy must produce no warnings, and formatting and whitespace checks must succeed.

## Cleanup and recovery

Passing tests automatically remove their generated temporary directories, including artifacts from the deliberately terminated children. Cargo build artifacts remain in `target` as usual. If the parent test is interrupted, inspect the exact `iniza-pack-resume-*` directory under the operating system's temporary directory and move only that confirmed synthetic directory to Trash. Do not use a wildcard deletion or remove unrelated temporary directories.

No personal state or external session is changed. Do not attempt to salvage real data using the prototype checkpoint files.

## Known limitations

- COKS-30 remains In Progress. The complete disk-full and permission-loss matrix and capability-relative publication and cleanup hardening are not complete. Process termination at every checkpoint-promotion persistence boundary is covered.
- A pause waits for a whole Migration Item, potentially a large file. Resume authenticates and re-encrypts saved progress and requires additional disk space.
- Resume currently needs both Recovery Secrets in memory. Either one independently unlocks a completed Bundle.
- Recovery Method storage and the supported command-line workflow remain dependent on COKS-33 and COKS-36. These tests use no real secret transport.
- There is no Verified Copy command, readiness Receipt, complete migration rehearsal, or erase-readiness claim in this slice.
- Keep independent conventional backups. These tests do not authorize using Iniza as the only protection for a machine move.
