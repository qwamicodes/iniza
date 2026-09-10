# COKS-41 complete migration rehearsal — local manual quality assurance

## 1. What was implemented

COKS-41 connects the previously separate migration safety engines into one synthetic end-to-end rehearsal and into the supported command-line workflow.

The delivered behavior:

- captures one approved, non-stale Plan into an authenticated encrypted Bundle;
- stores and independently rehearses both the Vaultwarden Recovery Method and the Offline Recovery Key;
- loads a stored Recovery Method in a fresh caller scope for Inspect, Verify, Verified Copy, Restore, and Readiness Evidence status;
- creates an External-storage Verified Copy and an iCloud Drive Verified Copy through classified test boundaries;
- interrupts Restore at a durable checkpoint, reloads recovery, resumes, and compares restored bytes without executing restored content;
- audits attached and detached synthetic Projects with staged, unstaged, untracked, ignored, stashed, local-only-reference, no-remote, and disabled-hook state;
- captures and restores a Project Capsule while keeping hooks disabled;
- appends machine Receipts to Readiness Evidence, detects a deliberately changed copy, and records a replacement copy without rewriting prior evidence;
- reports every excluded, Requires Review, Unsupported, and Unavailable Migration Item through the Not Protected Report; and
- always reports that this evidence is not permission to erase a machine.

## 2. Prerequisites

- Run from the Iniza repository root.
- Rust and Cargo must be installed.
- Git must be installed and available through `PATH`.
- No Vaultwarden account, Bitwarden session, personal file, real remote, removable drive, or iCloud Drive folder is needed for the synthetic rehearsal.
- COKS-29 through COKS-40 must remain present because COKS-41 composes their public interfaces.

Do not place credentials or personal data in the synthetic fixture.

## 3. Setup

```bash
cd /Users/qwamicodes/Documents/projects/iniza
cargo build --locked
```

For a visible command-line dry run, create a disposable source and Plan:

```bash
INIZA_COKS41_QA="$(mktemp -d /tmp/iniza-coks41-qa.XXXXXX)"
mkdir -p "$INIZA_COKS41_QA/source"
printf 'synthetic command-line settings\n' > "$INIZA_COKS41_QA/source/settings.txt"
cargo run --locked -- scan "$INIZA_COKS41_QA/source" --output-plan "$INIZA_COKS41_QA/plan.toml"
cargo run --locked -- plan validate --plan "$INIZA_COKS41_QA/plan.toml"
```

Copy the complete approval hash printed by the final command, then approve only that synthetic Plan:

```bash
cargo run --locked -- plan approve --plan "$INIZA_COKS41_QA/plan.toml" --approved-hash '<COMPLETE_APPROVAL_HASH>'
```

## 4. Primary walkthrough

1. Run the complete isolated rehearsal through its public workflow interface:

   ```bash
   cargo test --locked --test migration_workflow complete_rehearsal_creates_two_verified_copies_and_resumes_an_exact_restore -- --exact --nocapture
   ```

2. Exercise the supported Pack validation command without reading full protected content, writing artifacts, or contacting Vaultwarden:

   ```bash
   cargo run --locked -- --json pack \
     --plan "$INIZA_COKS41_QA/plan.toml" \
     --output "$INIZA_COKS41_QA/migration.iniza" \
     --name 'Synthetic command-line migration' \
     --bitwarden \
     --offline-recovery "$INIZA_COKS41_QA/separate.iniza-recovery" \
     --dry-run
   ```

3. Confirm that the dry run did not create either protected artifact:

   ```bash
   test ! -e "$INIZA_COKS41_QA/migration.iniza"
   test ! -e "$INIZA_COKS41_QA/separate.iniza-recovery"
   ```

## 5. Expected result

- The focused rehearsal test ends with `1 passed; 0 failed`.
- The rehearsal internally completes both Recovery Methods, two Verified Copies, interrupted and resumed Restore, exact byte comparison, two Project audits, a Restorable Project Capsule, append-only evidence recording, Receipt invalidation, and replacement-copy revalidation.
- The Pack dry run writes exactly one versioned JavaScript Object Notation result to standard output with `status` equal to `success`, `recovery_methods` equal to `2`, `would_contact_vaultwarden` equal to `false`, and `would_create_artifacts` equal to `false`.
- No output says that the Mac is safe to erase.

## 6. Failure or safety check

Prove that machine mode cannot bypass the two exact interactive owner reviews:

```bash
set +e
cargo run --locked -- --json pack \
  --plan "$INIZA_COKS41_QA/plan.toml" \
  --output "$INIZA_COKS41_QA/migration.iniza" \
  --name 'Synthetic command-line migration' \
  --bitwarden \
  --offline-recovery "$INIZA_COKS41_QA/separate.iniza-recovery"
INIZA_COKS41_EXIT=$?
set -e
test "$INIZA_COKS41_EXIT" -eq 10
test ! -e "$INIZA_COKS41_QA/migration.iniza"
test ! -e "$INIZA_COKS41_QA/separate.iniza-recovery"
```

The result must contain error code `INIZA-E010`, must explain that interactive owner review is required, and must not prompt or create either artifact.

## 7. Automated verification

Run the focused connected suites:

```bash
cargo test --locked --test migration_workflow
cargo test --locked --test encrypted_cli
cargo test --locked --test stored_recovery_method
cargo test --locked --test readiness_evidence
cargo test --locked --test project_audit
cargo test --locked --test project_capsule
cargo test --locked --test vaultwarden_recovery
```

Run the repository-wide gates:

```bash
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
```

Every command must exit successfully. No test may be skipped or weakened.

## 8. Cleanup or recovery

The automated rehearsal removes its own randomly named temporary directory.

Remove only the disposable manual directory created in section 3:

```bash
test -n "$INIZA_COKS41_QA"
test "${INIZA_COKS41_QA#/tmp/iniza-coks41-qa.}" != "$INIZA_COKS41_QA"
rm -rf -- "$INIZA_COKS41_QA"
unset INIZA_COKS41_QA INIZA_COKS41_EXIT
```

Do not remove a real Bundle, Offline Recovery Key document, Vaultwarden Secure Note, Receipt store, Project Capsule, or Verified Copy using these cleanup steps.

## 9. Known limitations

- COKS-41 authorizes and proves synthetic or deliberately duplicated data only. It does not authorize reading personal source content; that is the COKS-42 Owner Dogfood gate.
- The production Pack command requires an actual separate removable destination, an already unlocked official Bitwarden command-line session, and exact installation and preflight hash review. This manual walkthrough intentionally does not contact that external service.
- Pack Resume is deliberately limited to the same live migration workflow because generated Recovery Secrets are never persisted into a generic resume file. A fresh `--resume` invocation fails with deterministic recovery guidance.
- Readiness Evidence can remain Blocking when owner-stated attestations are absent. Synthetic automation never invents those owner statements.
- No COKS-41 result authorizes Git publication, deletion, machine erasure, or a claim that every personal file has been protected.
