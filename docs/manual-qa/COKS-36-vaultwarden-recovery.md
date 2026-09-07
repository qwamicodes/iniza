# COKS-36 Vaultwarden recovery — local testing and owner-service rehearsal

## What was implemented

Iniza can inspect and bind a trusted official Bitwarden command-line installation, observe the configured Vaultwarden server and account without reading a master password, create one exact recovery Secure Note, synchronize, retrieve the exact returned item identifier, reconstruct the hidden Recovery Secret only in zeroizing memory, and prove that it authenticates the completed Bundle.

Failures after remote creation retain the exact item for a safe retry and never delete it. The independent Offline Recovery Key remains a separate recovery path. Iniza never calls login, unlock, lock, search, edit, delete, export, or an arbitrary Bitwarden command.

## Prerequisites

- The repository Rust toolchain and installed dependencies.
- Completed COKS-27 IZ2 Bundle support and COKS-33 Offline Recovery Key support.
- For automated testing: no account, credential, network connection, or personal file is required.
- For the real owner-service rehearsal: Homebrew, the official Bitwarden command-line client version `2026.8.0` or newer, the owner's external Vaultwarden service, and the owner's normal fresh-device and independent multi-factor recovery methods.

The real rehearsal creates one Secure Note in the owner's service. That is an external state change. Run it only after separately approving that change. The harness uses a disposable synthetic Bundle and never reads personal migration content.

## Setup

Prepare the isolated automated tests:

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo test --test vaultwarden_recovery --no-run
cargo check --example coks_36_owner_rehearsal
```

Both commands should compile successfully.

For the real rehearsal, install or upgrade the official client through the owner's trusted Homebrew channel:

```sh
brew install bitwarden-cli
```

If it is already installed but older than `2026.8.0`:

```sh
brew upgrade bitwarden-cli
```

Configure and authenticate with the official client outside Iniza. Substitute the reviewed external service origin:

```sh
bw config server https://YOUR-VAULTWARDEN-SERVICE
bw login
export BW_SESSION="$(bw unlock --raw)"
```

The official client may prompt for the master password. Iniza does not receive that prompt or password. Do not paste the session into chat, shell arguments, files, screenshots, or issue comments.

## Primary walkthrough

1. Exercise the complete synthetic connector through its public interface:

   ```sh
   cargo test --test vaultwarden_recovery exact_vaultwarden_secure_note_is_retrieved_and_authenticates_the_completed_bundle -- --exact --nocapture
   ```

   Expect one passing test. The created typed note is synchronized, retrieved by its exact identifier, and its secret independently authenticates the disposable Bundle.

2. Exercise the real child-process boundary without a network service:

   ```sh
   cargo test --test vaultwarden_recovery production_sync_and_exact_get_complete_bundle_rehearsal -- --exact --nocapture
   ```

   Expect one passing test. The executable fixture verifies the exact non-interactive arguments, cleared environment, environment-only session, standard-input encoding, strict synchronization response, exact-identifier retrieval, and successful Bundle authentication.

3. After separately approving creation of one real Vaultwarden Secure Note, run the owner-service harness:

   ```sh
   cargo run --example coks_36_owner_rehearsal -- --bitwarden-executable /opt/homebrew/bin/bw
   ```

   Use `/usr/local/bin/bw` only when that is the reviewed canonical installation path. The harness first displays the selected executable, interpreter, version, and installation review hash. Type the complete hash to authorize credentialed work.

4. Review the preflight JavaScript Object Notation. Confirm the server origin, server identity hash, unlocked state, Bundle identity, exact Secure Note name, creation time, optional location hint, and preflight review hash. Type the complete preflight hash to authorize creation.

5. Expect a `verified` result with one exact item identifier, the authenticated Bundle identity, server identity hash, and verification time. No secret, session, account identifier, protected content, or personal path should appear.

6. On the new Mac or an equivalent isolated fresh device, sign in to the reviewed external Vaultwarden service and locate the exact item identifier. Exercise the owner's independent multi-factor recovery path without giving any credential to Iniza. Return to the harness and type each exact Owner Attestation phrase only after independently observing the claimed result.

7. When finished, remove the session from the current shell:

   ```sh
   unset BW_SESSION
   ```

## Expected result

- Installation inspection is review-required and binds the canonical executable, any shebang interpreter, version, and complete identities.
- Preflight is review-required and binds the same installation, external server identity, account identity, completed Bundle, exact item schema, and creation intent.
- Successful storage reports `verified`, retains the exact Vaultwarden item, and produces a secret-free Receipt.
- Fresh-device and independent multi-factor facts are recorded only as explicit Owner Attestations, never as automated claims.
- The disposable local source and Bundle are removed after a complete rehearsal. The Vaultwarden Secure Note remains because Iniza never automatically deletes recovery items.

## Failure and safety checks

Run the adversarial process-output and session tests:

```sh
cargo test --test vaultwarden_recovery production_installation_inspection_does_not_leave_the_client_without_a_home_directory -- --exact
cargo test --test vaultwarden_recovery production_status_rejects_unknown_duplicate_and_oversized_output -- --exact
cargo test --test vaultwarden_recovery production_get_rejects_extra_changed_and_duplicate_iniza_fields -- --exact
cargo test --test vaultwarden_recovery non_base64_session_is_rejected_before_bitwarden_receives_it -- --exact
```

Expect all four tests to pass. Installation inspection supplies only the verified user home instead of allowing the client to create configuration under the repository. Hostile status output, oversized output, extra or duplicate Iniza fields, wrong hidden-field types, and invalid sessions fail closed without disclosure.

Prove post-creation containment and independent recovery:

```sh
cargo test --test vaultwarden_recovery post_creation_failure_retains_the_exact_item_for_retry_and_offline_recovery -- --exact
cargo test --test vaultwarden_recovery locked_vault_stops_before_remote_creation_and_keeps_master_password_outside_iniza -- --exact
```

Expect both tests to pass. A post-creation failure returns `ItemCreatedButUnverified` with the exact identifier and leaves Offline Recovery usable. A locked vault stops before creation and directs the owner to unlock through the official client.

If the real owner rehearsal reports `ItemCreatedButUnverified`, record the exact identifier and retained disposable Bundle path. Do not delete or replace the item. Keep the independent Offline Recovery Key and use an exact-identifier rehearsal after resolving the service or client failure.

## Automated verification

```sh
cargo test --test vaultwarden_recovery
cargo test --test multifile_bundle
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
git diff --check
```

Every test must pass with no ignored failures. Clippy must produce no warnings, and formatting and whitespace checks must succeed.

## Cleanup or recovery

Passing automated tests remove their isolated temporary directories. If a test is interrupted, inspect the exact `iniza-vaultwarden-recovery-<process>-<time>-<number>` directory under the operating-system temporary directory and move only that confirmed synthetic directory to Trash. Never use a wildcard deletion.

A successful owner rehearsal removes its disposable local source and Bundle but intentionally retains the real Vaultwarden Secure Note. Review or remove that note manually through the trusted Vaultwarden interface only when it is no longer required. Iniza never deletes it.

If a partial owner rehearsal retains an `iniza-coks-36-owner-rehearsal-<process>-<time>` directory, preserve it for exact-identifier retry. After a verified retry and owner review, move only that exact confirmed disposable directory to Trash.

## Known limitations

- Until the real owner-service rehearsal and Owner Attestation are complete, COKS-36 is not complete.
- Owner Dogfood proves only the reviewed service and official client version; compatibility with every Bitwarden-compatible deployment is not promised.
- The harness deliberately uses synthetic content. Personal migration capture and full command-line orchestration remain later Owner Dogfood work.
- Successful Vaultwarden recovery does not prove Offline Recovery Key separation, Verified Copies, Restore rehearsals, repository publication, conventional backups, Readiness Evidence, or permission to erase the old Mac.
