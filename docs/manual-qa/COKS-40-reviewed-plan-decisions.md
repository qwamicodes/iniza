# COKS-40 local manual quality assurance: reviewed Plan decisions

## What was implemented

Iniza can now record an owner's positive review of an exact symbolic link, or a subtree containing symbolic links, while preparing a directory Plan. The supported command-line decision is repeatable:

```text
--include-reviewed <RELATIVE_PATH>
```

Each stable reviewed symbolic link becomes Included, retains its existing Protection Requirement, remains visible in the Plan, and is never followed during discovery. The decision changes the canonical Plan hash and appears in Plan comparison output. Unsafe, missing, excluded, changed, unavailable, unsupported, and mount-boundary state fails closed rather than being silently included.

This interface supports revising a Plan before approval. It does not approve a Plan, capture a Bundle, contact a Git remote, publish a repository, delete source data, or authorize erasing a Mac.

## Prerequisites

- macOS or another Unix environment that supports symbolic links.
- Rust and Cargo installed.
- The current Iniza repository checkout.
- No personal data, credential, network connection, Vaultwarden session, external disk, or remote repository is required.

Use only the disposable synthetic directory created below. Do not use a personal Project for this walkthrough.

## Setup

From the repository root, build Iniza and create an isolated fixture:

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo build
COKS40_QA_DIR="$(mktemp -d /tmp/iniza-coks40-manual.XXXXXX)"
mkdir -p "$COKS40_QA_DIR/source/skills"
printf '%s\n' 'synthetic settings' > "$COKS40_QA_DIR/source/skills/settings.txt"
ln -s settings.txt "$COKS40_QA_DIR/source/skills/settings-link"
```

Expected result: the build succeeds and the isolated source contains one ordinary file plus one symbolic link to that file.

## Primary walkthrough

1. Create the initial unapproved Plan without a reviewed-inclusion decision:

   ```sh
   target/debug/iniza scan "$COKS40_QA_DIR/source" \
     --output-plan "$COKS40_QA_DIR/unreviewed.toml"
   target/debug/iniza plan show --plan "$COKS40_QA_DIR/unreviewed.toml"
   ```

   Expected result: `skills/settings-link` is Requires Review and Must-Protect. The Plan has one Must-Protect blocker. The command does not read or copy the target through the link.

2. Record the exact reviewed subtree and create a revised Plan:

   ```sh
   target/debug/iniza scan "$COKS40_QA_DIR/source" \
     --include-reviewed skills \
     --output-plan "$COKS40_QA_DIR/reviewed.toml"
   target/debug/iniza plan show --plan "$COKS40_QA_DIR/reviewed.toml"
   ```

   Expected result: `skills/settings-link` is Included and Must-Protect with the explanation `included by explicit owner review`. The ordinary `settings.txt` remains Included for its original discovery reason. The Plan has zero Must-Protect blockers and remains Unapproved.

3. Inspect the approval-relevant difference:

   ```sh
   target/debug/iniza plan diff \
     "$COKS40_QA_DIR/unreviewed.toml" \
     "$COKS40_QA_DIR/reviewed.toml"
   ```

   Expected result: the output reports the symbolic link Disposition changing from RequiresReview to Included and its coverage explanation changing. The two Plans have different approval hashes.

4. Inspect path-free automation output:

   ```sh
   target/debug/iniza --json plan show --plan "$COKS40_QA_DIR/reviewed.toml"
   ```

   Expected result: one versioned JavaScript Object Notation object is printed. It contains counts, stable item identifiers, item kinds, Dispositions, Protection Requirements, and explanations, but no source root, relative path, filename, file content, credential, or Recovery Secret.

## Failure and safety checks

1. Prove that an exclusion and reviewed inclusion cannot overlap:

   ```sh
   target/debug/iniza scan "$COKS40_QA_DIR/source" \
     --exclude skills \
     --include-reviewed skills/settings-link \
     --output-plan "$COKS40_QA_DIR/conflicting.toml"
   ```

   Expected result: the command fails with `reviewed inclusion conflicts with a Plan exclusion`, and `conflicting.toml` is not created.

2. Prove that a missing decision cannot become a silent no-operation:

   ```sh
   target/debug/iniza scan "$COKS40_QA_DIR/source" \
     --include-reviewed missing-link \
     --output-plan "$COKS40_QA_DIR/missing.toml"
   ```

   Expected result: the command fails with `reviewed inclusion does not match a review-required Migration Item`, and `missing.toml` is not created.

3. Prove that a path cannot escape the approved root:

   ```sh
   target/debug/iniza scan "$COKS40_QA_DIR/source" \
     --include-reviewed ../outside \
     --output-plan "$COKS40_QA_DIR/unsafe.toml"
   ```

   Expected result: the command fails with `reviewed inclusion must be a safe relative path`, and `unsafe.toml` is not created.

## Automated verification

Run the focused and repository-wide checks:

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo test --test directory_plan
cargo test --test directory_plan_cli
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
git diff --check
```

Expected result: the focused directory Plan suite reports seventeen passing tests, the command-line suite reports seven passing tests, formatting and static analysis succeed, every repository test passes, and no whitespace error is reported.

## Cleanup or recovery

Print and inspect the exact temporary directory before removing anything:

```sh
printf '%s\n' "$COKS40_QA_DIR"
find "$COKS40_QA_DIR" -maxdepth 3 -print
```

Confirm that the path begins with `/tmp/iniza-coks40-manual.` and contains only the synthetic files created above. Move that exact directory to Trash with Finder. Do not use a wildcard deletion command and do not target a personal Project.

Generated Cargo artifacts under `target/` may remain. They do not change migration evidence.

## Known limitations

- One directory Plan has exactly one approved root. The real Projects collection and the selected developer-state paths therefore remain separate Plans until later orchestration binds them into the owner migration workflow.
- A reviewed inclusion supports stable symbolic links only. Changed files, mount boundaries, unavailable state, special filesystem items, and other unsupported state remain blocking.
- The decision retains a symbolic-link object; it does not prove that the link target will exist or be meaningful on the new Mac. Restore Rehearsal must validate the recovered result.
- This walkthrough proves the public review interface with synthetic data. It does not approve the owner's real Plans, prove the owner's Projects Restorable or Synchronized, establish two verified copies, or authorize erasing the old Mac.
