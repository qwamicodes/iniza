# COKS-32 Protection Candidates — local synthetic testing guide

## What was implemented

The command line can list curated macOS Protection Candidates and create a narrow Plan from explicitly selected filesystem candidates. Secure Shell, Git, Bash, and Zsh are offered as Must-Protect defaults. Visual Studio Code local state remains Optional and unselected even when account sync is claimed. Homebrew packages, editor extensions, and language tools are represented by non-installing inventory commands, while caches, registries, installed toolchains, and build outputs are suggested exclusions.

Missing selected candidates remain visible as Unavailable Migration Items. Raw application folders can be offered only through safe home-relative paths and clearly report unsupported application-level Restore semantics. Candidate discovery reads metadata but not protected file content.

## Prerequisites

- The repository Rust toolchain and installed dependencies.
- Completed Plan, Bundle, Verify, and Restore core issues.
- No Vaultwarden account, external service, personal data, or real credential is required.

Use only the synthetic home created below. Do not point these commands at your real home yet.

## Setup

```sh
cd /Users/qwamicodes/Documents/projects/iniza
demo_root="$(mktemp -d /tmp/iniza-candidates.XXXXXX)"
demo_home="$demo_root/home"
mkdir -p "$demo_home/.ssh" "$demo_home/Library/Application Support/Code/User" "$demo_home/Documents/unselected"
printf 'Host synthetic-only\n' > "$demo_home/.ssh/config"
printf '{"synthetic":true}\n' > "$demo_home/Library/Application Support/Code/User/settings.json"
printf 'must stay unselected\n' > "$demo_home/Documents/unselected/private.txt"
cargo build
```

Keep the terminal open so `demo_root` and `demo_home` remain defined.

## Primary walkthrough

1. List the candidates:

   ```sh
   ./target/debug/iniza scan "$demo_home" --list-protection-candidates
   ```

   Expect Secure Shell, Git, Bash, Zsh, Visual Studio Code, Homebrew, language-tool, and suggested-exclusion entries. Each entry shows its classification and validation. Visual Studio Code entries say `RequiresReview`, `Optional`, and `account sync claim: unverified`. Protected file content is absent.

2. Inspect deterministic machine output:

   ```sh
   ./target/debug/iniza --json scan "$demo_home" --list-protection-candidates
   ```

   Expect exactly one JavaScript Object Notation line with schema version `1`. It contains candidate identifiers and inventory argument vectors but not the absolute synthetic home path or either file's contents.

3. Select only Secure Shell and Visual Studio Code settings:

   ```sh
   ./target/debug/iniza scan "$demo_home" \
     --candidate secure-shell-configuration \
     --candidate visual-studio-code-settings \
     --output-plan "$demo_root/iniza.toml"
   ./target/debug/iniza plan show --plan "$demo_root/iniza.toml"
   ```

   Expect the Plan to contain `.ssh`, its synthetic configuration, the selected settings file, and only the parent directories needed to restore that file. `Documents/unselected/private.txt` must not appear.

4. Exercise the encrypted round trip through the confirmed public core interface:

   ```sh
   cargo test --test protection_candidates selected_candidate_plan_round_trips_without_unselected_home_content -- --exact --nocapture
   ```

   Expect one passing test. Both selected files authenticate and Restore exactly, and the unselected Documents directory is absent from the destination.

## Failure and safety checks

```sh
cargo test --test protection_candidates selected_unavailable_must_protect_candidate_remains_visible_in_the_plan -- --exact
cargo test --test protection_candidates raw_application_folder_must_stay_beneath_the_reviewed_home -- --exact
```

Expect both tests to pass. Missing Secure Shell state remains an Unavailable Must-Protect item. Absolute and parent-traversing raw application paths are rejected before discovery.

## Automated verification

```sh
cargo test --test protection_candidates
cargo test --test protection_candidates_cli
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
git diff --check
```

Every test must pass with no ignored failures. Clippy must produce no warnings, and formatting and whitespace checks must succeed.

## Cleanup or recovery

Review the exact temporary path before removing it:

```sh
printf '%s\n' "$demo_root"
test -n "$demo_root" && test "$demo_root" != / && rm -rf -- "$demo_root"
unset demo_root demo_home
```

This removes only the synthetic directory created by `mktemp`. Automated tests remove their isolated temporary directories when they pass.

## Known limitations

- Candidate discovery describes inventory commands but deliberately does not execute them. Supported capture orchestration must bind their output to the approved Plan before it can count as protected evidence.
- Raw application folders preserve reviewed bytes but do not promise application consistency or supported application-level Restore behavior.
- The supported cross-process Bundle command line awaits secure Offline Recovery Key and Vaultwarden loading.
- These tests do not authorize scanning personal data, relying on Iniza as the only copy, or erasing the old Mac.
