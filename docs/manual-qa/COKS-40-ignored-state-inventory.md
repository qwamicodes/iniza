# COKS-40 local manual quality assurance: complete ignored-state inventory

## What was implemented

Iniza now reports each Project's ignored state as explicitly Complete or Unavailable. A Complete result lists every ignored candidate still awaiting review and counts candidates already covered by an exact approved Plan exclusion. Git failure, malformed output, or output beyond the bounded allowance becomes an Unavailable Restorable gap instead of a false zero. Other Projects and their verified observations remain in the report.

Human output may show local paths for owner review. Machine output contains stable identifiers, classifications, counts, state, and reason codes, but no local paths, filenames, contents, raw Git output, or credentials. This audit does not capture a Bundle, publish Git state, delete data, contact Vaultwarden, or authorize machine erasure.

## Prerequisites

- macOS or another Unix environment with Git, Rust, and Cargo installed.
- The current Iniza repository checkout.
- Completed COKS-28 Project-audit support and COKS-40 reviewed Plan-decision support.
- No credential, personal Project, network connection, external disk, or Vaultwarden session is required.

Use only the disposable synthetic directory created below.

## Setup

From the Iniza repository root, build the command and create one isolated synthetic Project:

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo build
COKS40_IGNORED_QA_DIR="$(mktemp -d /tmp/iniza-coks40-ignored.XXXXXX)"
mkdir -p "$COKS40_IGNORED_QA_DIR/source/node_modules/example"
git -C "$COKS40_IGNORED_QA_DIR/source" init -q
printf '%s\n' 'node_modules/' '.env' > "$COKS40_IGNORED_QA_DIR/source/.gitignore"
printf '%s\n' 'synthetic generated file' > "$COKS40_IGNORED_QA_DIR/source/node_modules/example/index.js"
printf '%s\n' 'synthetic value only' > "$COKS40_IGNORED_QA_DIR/source/.env"
```

Expected result: the build succeeds. The disposable Project contains one generated ignored file and one synthetic ignored environment file. The value is not a real secret.

## Primary walkthrough

1. Create an unapproved Plan with one exact generated-tree exclusion:

   ```sh
   target/debug/iniza scan "$COKS40_IGNORED_QA_DIR/source" \
     --exclude node_modules \
     --output-plan "$COKS40_IGNORED_QA_DIR/plan.toml"
   target/debug/iniza plan validate --plan "$COKS40_IGNORED_QA_DIR/plan.toml"
   ```

   Expected result: validation prints the canonical `plan_blake3_...` approval hash and says approval is required. Copy that exact hash; it contains no protected content.

2. Approve only this synthetic Plan, replacing `<EXACT_HASH>` with the hash from step 1:

   ```sh
   target/debug/iniza plan approve \
     --plan "$COKS40_IGNORED_QA_DIR/plan.toml" \
     --approved-hash <EXACT_HASH>
   ```

   Expected result: the synthetic Plan becomes Approved. This approval authorizes no Bundle capture or publication.

3. Run the human Project audit:

   ```sh
   target/debug/iniza projects scan --plan "$COKS40_IGNORED_QA_DIR/plan.toml"
   ```

   Expected result: the command exits `1` because Project Capsule and synchronization gaps still exist. The report says `ignored state: complete (1 pending, 1 excluded by Plan)`, shows `.env` as Requires Review, and does not repeat `node_modules/example/index.js` as pending.

4. Run the path-free machine audit:

   ```sh
   target/debug/iniza --json projects scan --plan "$COKS40_IGNORED_QA_DIR/plan.toml"
   ```

   Expected result: one JavaScript Object Notation line reports `ignored_state.state` as `complete`, `candidate_count` as `1`, and `excluded_by_plan_count` as `1`. It contains a stable ignored-item identifier and classification but contains neither `.env`, `node_modules`, the temporary root, nor the synthetic value.

## Failure or safety check

Create a separate revised but unapproved Plan, then prove it cannot drive an audit:

```sh
target/debug/iniza scan "$COKS40_IGNORED_QA_DIR/source" \
  --exclude node_modules \
  --output-plan "$COKS40_IGNORED_QA_DIR/unapproved-plan.toml"
target/debug/iniza projects scan --plan "$COKS40_IGNORED_QA_DIR/unapproved-plan.toml"
```

Expected result: the command fails because Project audit requires an approved, non-stale directory Plan. It does not silently audit unapproved scope and does not run a Git publication command. The focused automated tests below additionally inject Git failure, malformed output, and bounded-output overflow and prove each becomes Unavailable.

## Automated verification

Run the focused and repository-wide checks:

```sh
cd /Users/qwamicodes/Documents/projects/iniza
cargo test --test project_audit
cargo test --test project_audit_cli
cargo test --test project_capsule --no-run
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
git diff --check
```

Expected result: every focused Project-audit test passes, Project Capsule compiles against the explicit inventory contract, formatting and static analysis succeed, every repository test passes, and no whitespace error is reported.

## Cleanup or recovery

Print and inspect the exact temporary directory before removing anything:

```sh
printf '%s\n' "$COKS40_IGNORED_QA_DIR"
find "$COKS40_IGNORED_QA_DIR" -maxdepth 4 -print
```

Confirm that the path begins with `/tmp/iniza-coks40-ignored.` and contains only the synthetic files created above. Move that exact directory to Trash with Finder. Do not use a wildcard deletion command and do not target a personal Project.

Generated Cargo artifacts under `target/` may remain.

## Known limitations

- The ignored enumeration standard-output allowance is bounded at thirty-two mebibytes. Larger inventories become Unavailable and block Restorable status until the Plan is narrowed or the implementation is deliberately revised.
- Non-Unicode or unsafe relative paths fail closed as malformed Git output instead of being guessed or rewritten.
- Complete enumeration proves review coverage, not Project recoverability. A verified Project Capsule and Restore Rehearsal are still required.
- This walkthrough uses synthetic data. It does not approve the owner's revised real Project Plan, execute a `cashsynq` Push Plan, capture a Bundle, establish Verified Copies, satisfy either Recovery Method, or authorize erasing the old Mac.
