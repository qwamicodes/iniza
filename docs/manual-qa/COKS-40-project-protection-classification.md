# COKS-40 local manual quality assurance: intelligent Project protection

## What was implemented

`iniza projects scan` now shows exact upstream ahead and behind counts, one protection classification, its reasons, a deterministic review hash, and stable identifiers for every ignored-state candidate. The same command can turn a clean, current, remotely verified Project into a smaller unapproved Plan containing only explicitly selected ignored state plus an exact remote-reconstruction recipe. Local-only state still selects a full Project Capsule. Unsafe or incomplete evidence selects Action Required.

No Git write, publication, Bundle capture, Vaultwarden access, deletion, or machine erasure is performed by this workflow.

## Prerequisites

- Rust, Cargo, and Git installed.
- The Iniza checkout at `/Users/qwamicodes/Documents/projects/iniza`.
- COKS-28 Project audit and the COKS-40 reviewed Plan-decision work completed.
- Only disposable synthetic repositories for the local walkthrough.

The live-remote eligibility proof uses an injected synthetic Git boundary in the automated suite. Do not create or publish a remote merely for this walkthrough.

## Setup

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo build --locked
COKS40_PROJECT_QA="$(mktemp -d /tmp/iniza-coks40-project.XXXXXX)"
mkdir -p "$COKS40_PROJECT_QA/source"
git -C "$COKS40_PROJECT_QA/source" init -q
git -C "$COKS40_PROJECT_QA/source" config user.name "Synthetic Owner"
git -C "$COKS40_PROJECT_QA/source" config user.email "synthetic@example.invalid"
printf '%s\n' 'synthetic tracked file' > "$COKS40_PROJECT_QA/source/tracked.txt"
printf '%s\n' '.env' 'node_modules/' > "$COKS40_PROJECT_QA/source/.gitignore"
git -C "$COKS40_PROJECT_QA/source" add tracked.txt .gitignore
git -C "$COKS40_PROJECT_QA/source" commit -q -m 'synthetic fixture'
printf '%s\n' 'SYNTHETIC_ONLY=value' > "$COKS40_PROJECT_QA/source/.env"
mkdir -p "$COKS40_PROJECT_QA/source/node_modules"
printf '%s\n' 'generated fixture' > "$COKS40_PROJECT_QA/source/node_modules/generated.js"
target/debug/iniza scan "$COKS40_PROJECT_QA/source" \
  --exclude node_modules \
  --output-plan "$COKS40_PROJECT_QA/project-plan.toml"
REVIEWED_HASH="$(target/debug/iniza plan show --plan "$COKS40_PROJECT_QA/project-plan.toml" | sed -n 's/^Plan approval hash: //p')"
target/debug/iniza plan approve \
  --plan "$COKS40_PROJECT_QA/project-plan.toml" \
  --approved-hash "$REVIEWED_HASH"
```

Expected result: the synthetic directory Plan is approved. Nothing contacts a network service.

## Primary walkthrough

1. Inspect the Project without a remote check:

   ```sh
   target/debug/iniza projects scan \
     --plan "$COKS40_PROJECT_QA/project-plan.toml"
   ```

   Expected result: the command exits `1` because recovery evidence is incomplete. It displays the Project identifier, ignored `.env` path with its stable candidate identifier, exact local counts, `Action Required`, and a reason explaining that remote evidence is unavailable or no remote exists.

2. Create local-only state and repeat the scan:

   ```sh
   printf '%s\n' 'synthetic local-only state' > "$COKS40_PROJECT_QA/source/local-only.txt"
   target/debug/iniza projects scan \
     --plan "$COKS40_PROJECT_QA/project-plan.toml"
   ```

   Expected result: the output shows one untracked item and selects `Full Project Capsule`. Iniza does not stage, commit, remove, or otherwise change the file.

3. Inspect path-free machine output:

   ```sh
   target/debug/iniza --json projects scan \
     --plan "$COKS40_PROJECT_QA/project-plan.toml"
   ```

   Expected result: one versioned JavaScript Object Notation result reports the same counts, classification, reason codes, review hash, and ignored candidate identifier. It does not contain `.env`, `local-only.txt`, the source path, or file contents.

4. For a Project that a separately authorized live remote check classifies as `Remote Reconstruction with Local Overlay`, prepare a revised Plan by copying the exact Project identifier, protection review hash, and every ignored candidate identifier from that same scan:

   ```text
   target/debug/iniza projects scan \
     --plan APPROVED_PLAN \
     --remote-check \
     --remote-overlay PROJECT_IDENTIFIER:REVIEW_HASH \
     --include-ignored PROJECT_IDENTIFIER:CANDIDATE_IDENTIFIER \
     --exclude-ignored PROJECT_IDENTIFIER:ANOTHER_CANDIDATE_IDENTIFIER \
     --output-plan NEW_PLAN
   ```

   This template is intentionally not directly runnable. Substitute only identifiers reviewed from one current scan and supply exactly one decision for every ignored candidate. The command may contact the reviewed remote and therefore requires separate approval. Expected result: `NEW_PLAN` is created as Unapproved, its hash differs from the source Plan, and the source Plan is unchanged. If the Project or remote changes, the command fails and creates no Plan.

## Failure and safety check

The focused automated test `reachable_remote_with_a_different_revision_requires_owner_action` supplies a successful live-remote response whose branch advertises a different commit than the local head. The classifier returns `Action Required` with `remote-revision-mismatch`; it never treats reachability as recoverability.

The focused test `clean_current_project_uses_remote_reconstruction_with_a_local_overlay` also proves that a missing ignored-state decision and a stale protection review hash both fail before a revised Plan exists.

## Automated verification

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo test --locked --test project_audit
cargo test --locked --test project_audit_cli
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
git diff --check
```

Expected result: every focused and repository-wide test passes, formatting is unchanged, strict static analysis reports no warning, and Git reports no whitespace error.

## Cleanup or recovery

```sh
case "$COKS40_PROJECT_QA" in
  /tmp/iniza-coks40-project.*) rm -rf -- "$COKS40_PROJECT_QA" ;;
  *) printf '%s\n' 'Refusing cleanup: unexpected path' ;;
esac
unset COKS40_PROJECT_QA REVIEWED_HASH
```

Only the disposable directory created with `mktemp` is removed. Confirm the variable still begins with `/tmp/iniza-coks40-project.` before running the cleanup command.

## Known limitations

- This issue prepares the protection classification and revised Plan representation. The network-backed reconstruction and source-independent Restore Rehearsal are completed by the later Restore issues.
- A real Project may require a separately approved Push Plan or owner-performed reconciliation before it becomes eligible.
- A Project is not Restorable until its selected representation passes Restore Rehearsal and current evidence is recorded.
