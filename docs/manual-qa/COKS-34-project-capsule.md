# COKS-34 Project Capsule comparison manual quality assurance

## What was implemented

Iniza can compare a Git-native archive with overlay against a full repository snapshot by sending both synthetic candidates through encrypted Pack, full Verify, safe Restore, and independent Project validation.

The comparison proves the reviewed dirty Project state: fixed commits and local references, attached or detached current state, exact index, staged and unstaged files, binary bytes, untracked files, explicitly reviewed ignored files, symbolic links, reviewed executable modes, disabled Git hooks, selected empty directories, stashes, and repositories without remotes. A changed Project is marked Changed and Unverified. Human and machine results omit Project paths, protected names, remote addresses, credentials, content, and Recovery Secrets.

ADR 0012 proposes the full repository snapshot because it enters direct encryption without the Git-native prototype's reusable plaintext archive and reconstruction format.

## Prerequisites

- macOS or another Unix environment with symbolic-link and executable-mode support.
- Rust and Cargo compatible with the repository toolchain.
- Git installed and available at /usr/bin/git or on the process path.
- The completed COKS-27 encrypted Bundle and COKS-28 safe Restore dependencies already present in this checkout.
- No credentials, Vaultwarden account, removable storage, network access, or personal files are needed.

All walkthrough data is synthetic, isolated, and automatically removed by the tests.

## Setup

From the repository root:

~~~sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo build
~~~

Expected result: Cargo completes successfully and builds the iniza library and command-line binary.

## Primary walkthrough

1. Run the complete dirty Project round trip:

   ~~~sh
   cargo test --test project_capsule both_project_capsule_representations_restore_the_complete_reviewed_dirty_project -- --exact
   ~~~

   Expected result: one test passes. Both encrypted candidates reproduce the checked-in reference identifiers and explicit byte fixtures. The unreviewed ignored marker is absent. The script and hook sentinels remain absent. The temporary plaintext Git-native source and restored capsule container are removed after use.

2. Run the detached-current-state round trip:

   ~~~sh
   cargo test --test project_capsule both_representations_restore_a_detached_unreferenced_current_commit -- --exact
   ~~~

   Expected result: one test passes. Both candidates restore a detached current commit that is not named by a local reference.

3. Review the proposed representation decision:

   ~~~sh
   sed -n '1,260p' docs/adr/0012-select-full-repository-project-capsule.md
   ~~~

   Expected result: the decision recommends the full repository snapshot, records representative size evidence for both candidates, explains why the smaller Git-native candidate is ineligible, and lists unsupported states as blockers.

## Failure and safety checks

1. Prove mutation containment:

   ~~~sh
   cargo test --test project_capsule project_change_during_capture_withholds_a_recommendation -- --exact
   ~~~

   Expected result: the test passes because the altered Project is reported Changed and Unverified and the report has no recommendation.

2. Prove executable quarantine and exact review:

   ~~~sh
   cargo test --test project_capsule executable_mode_requires_the_exact_validation_hash_bound_to_the_restored_bundle -- --exact
   ~~~

   Expected result: the test passes. No or incorrect review hashes leave the script non-executable; the exact Project-and-Bundle-bound hash restores only the reviewed non-hook mode; all Git hooks stay disabled; no sentinel runs.

3. Prove result sanitization:

   ~~~sh
   cargo test --test project_capsule project_capsule_results_do_not_expose_project_names_paths_or_remote_credentials -- --exact
   ~~~

   Expected result: the test passes with hostile Project names and credential-bearing remote configuration absent from both result formats.

4. Prove active-lock rejection:

   ~~~sh
   cargo test --test project_capsule active_git_lock_blocks_comparison_before_any_output_is_created -- --exact
   ~~~

   Expected result: the test passes because an active Git lock blocks comparison before a workspace, partial artifact, or completed Bundle is created.

## Automated verification

Run the focused suite:

~~~sh
cargo test --test project_capsule
~~~

Expected result: 6 passed, 0 failed.

Run formatting, static analysis, and every repository test:

~~~sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
~~~

Expected result: formatting and static analysis return successfully, and every test passes with no ignored or skipped safety regression.

## Cleanup and recovery

The tests create uniquely named directories beneath the operating-system temporary directory and remove them automatically, including successful encrypted test Bundles and restored fixtures. They do not modify personal Projects.

Cargo build artifacts remain under the repository's target directory for faster later runs. They are generated artifacts and may be left in place. No cleanup command is required.

If a test process is forcibly terminated, inspect the operating-system temporary directory for a directory whose name begins with iniza-project-capsule. Confirm it contains only synthetic markers from this walkthrough before moving that exact directory to Trash. Do not use a broad recursive deletion.

## Known limitations

- This issue is a representation comparison and architecture decision, not yet the supported personal-data capture command.
- ProjectCapsuleEngine::capture and command-line integration remain gated on explicit owner acceptance of ADR 0012 and later COKS-38 integration.
- Bare repositories, linked worktrees, submodules, object alternates, incomplete Git Large File Storage state, sparse or partial clones, non-portable names, incompatible destination filesystem semantics, active Git locks, and changing Projects are not claimed as supported.
- The size values in ADR 0012 come from the fixed synthetic fixture and are not estimates for a personal Project.
- Passing this walkthrough does not establish Owner Dogfood readiness or authorize erasing the old Mac.
