# Iniza CLI Command Contract

**Status:** Initial normative contract
**Compatibility:** Commands may evolve before `0.1.0`; JSON schemas and bundle formats are independently versioned

## 1. Invocation

```text
iniza [GLOBAL OPTIONS] <COMMAND> [COMMAND OPTIONS]
iniza                         # guided flow when attached to a TTY
```

Global options:

```text
--config <PATH>       configuration file
--plan <PATH>         migration plan; defaults to ./iniza.toml when applicable
--json                one JSON result on stdout; disables prompts
--json-events         JSON Lines progress events on stderr
--no-color            disable ANSI color
--non-interactive     disable prompts without enabling JSON
--yes                 approve eligible reviewed local actions; never authorizes first-time Git publication
-v, --verbose         local verbose detail; repeatable
-q, --quiet           final result only
-h, --help
-V, --version
```

## 2. Commands

### `iniza scan`

```text
iniza scan <ROOT>
  --list-protection-candidates
  --candidate <IDENTIFIER>...
  --raw-application-folder <HOME_RELATIVE_PATH>...
  --exclude <RELATIVE_PATH>...
  --optional <RELATIVE_PATH>...
  --include-reviewed <RELATIVE_PATH>...
  --recipe <NAME>...
  --destination <BUNDLE_PATH>
  --publication-policy <protect-locally-only|review-separately>
  --output-plan <PATH>
  --cross-mounts
```

Directory scanning is read-only metadata discovery beneath exactly one explicit approved root. The filesystem root is rejected as too broad. Relative exclusions and Optional classifications remain visible in the Plan. Symbolic links are recorded but never followed. Mount boundaries are recorded and not crossed unless `--cross-mounts` is explicitly enabled. A regular-file source continues to create a development-only fixture Plan for the `fixture` workflow.

`--include-reviewed` records an explicit positive review decision for an exact symbolic link or a subtree containing review-required symbolic links. It promotes only stable symbolic-link observations from Requires Review to Included, never follows their targets, preserves their Protection Requirement, and changes the canonical Plan hash. Unsafe or missing paths, overlap with an exclusion, changed source state, mount-boundary state, Unsupported items, and Unavailable items fail closed rather than being promoted. Repeated `--exclude`, `--optional`, and `--include-reviewed` decisions let the owner revise exact paths or subtrees before approving one complete final Plan hash.

`--list-protection-candidates` treats `<ROOT>` as the reviewed macOS home and reports curated Secure Shell, Git, Bash, Zsh, Visual Studio Code, Homebrew, language-tool, and regenerable-state candidates without reading candidate file contents. Human output identifies sources, sensitivity, portability, proposed Disposition, Protection Requirement, availability, validation, and unverified account-sync claims. Versioned JavaScript Object Notation output omits absolute paths and protected content.

`--candidate <IDENTIFIER>` may be repeated with `--output-plan` to create a narrow filesystem Plan. Only the chosen candidate paths and the parent directories required to restore them are inspected; unrelated home content is not enumerated. Missing selected state remains an Unavailable Migration Item, so missing Must-Protect Items cannot disappear from coverage. Visual Studio Code state is unselected by default. A raw application folder must be a safe home-relative path and remains Optional with unsupported application-level Restore semantics explicitly visible. Inventory candidates describe deterministic, read-only inventory commands and do not include installed toolchains, caches, package registries, or build outputs as payloads; their command execution belongs to the supported capture orchestration rather than candidate discovery.

### `iniza plan`

```text
iniza plan show [--plan <PATH>]
iniza plan validate [--plan <PATH>]
iniza plan approve --plan <PATH> --approved-hash <HASH>
iniza plan diff <OLD> <NEW>
```

`show` renders Included, Excluded, Requires Review, Unsupported, and Unavailable totals together with the Must-Protect blocker and Optional warning totals. The human view may show reviewed relative paths; JSON output emits stable item identifiers and classifications without source roots or relative paths.

`validate` emits the canonical approval hash and reports whether the Plan is unapproved, approved, or stale. `approve` succeeds only when `--approved-hash` exactly matches the current canonical Plan. Approval metadata is stored in the Plan but excluded from the canonical approval hash. Any change to an approval-relevant field makes the stored approval stale and causes validation to exit with the approval-required status.

`diff` explains approval-relevant changes without reading or showing protected content. JSON diff records contain a stable change kind and, for Migration Item changes, the stable item identifier; paths are intentionally omitted.

### `iniza projects scan`

```text
iniza projects scan --plan <PATH> [--remote-check]
```

The Plan must be approved and non-stale. Project roots and must-protect or optional requirements come from that reviewed Plan; arbitrary roots are not accepted by this implementation. Without `--remote-check`, the command performs no intentional network operation. With it, the command performs a read-only `git ls-remote` check and never fetches, pushes, checks out, commits, merges, rebases, resets, or stashes.

The human result may show local paths, sanitized remote addresses, pending ignored-state paths, and the count of ignored paths already covered by exact Plan exclusions. Each Project reports its ignored-state inventory as Complete or Unavailable. Git failure, malformed output, or bounded-output overflow is Unavailable and adds a Restorable gap; it is never rendered as a successful zero count. JavaScript Object Notation schema version 2 uses stable identifiers, classifications, counts, state, and reason codes; it redacts local remote paths and structurally omits source roots, relative paths, filenames, protected content, and raw Git output. A completed audit exits `1` while Restorable or Synchronized gaps remain; command failure exits `40`.

### `iniza projects push`

```text
iniza projects push
  --plan <PATH>
  --push-plan <PATH>
  --approved-hash <HASH>
  --review
  --apply
```

Interactive review generates the canonical hash of the exact Push Plan. Execution re-hashes and revalidates the plan immediately before applying it. Non-interactive execution requires the immutable Push Plan file, its separately recorded `--approved-hash`, and `--apply`; a mismatch or stale Git state exits without publication. Force push is unsupported. A Migration Plan is not a Push Plan.

### `iniza pack`

```text
iniza pack
  --plan <PATH>
  --output <PATH.iniza>
  --name <FRIENDLY_NAME>
  --bitwarden
  --offline-recovery <PATH>
  --resume
  --dry-run
```

Owner Dogfood requires both Vaultwarden and offline recovery. Interactive `pack` may collect the missing choices through review prompts. In `--non-interactive` or `--json` mode, `--bitwarden` and `--offline-recovery <PATH>` are required; omission exits with code 10. `--dry-run` validates and estimates but does not read full file contents, create recovery material, contact Vaultwarden, or write the final bundle.

The supported interactive command keeps both generated Recovery Secrets in zeroizing memory, writes and rehearses the Offline Recovery Key document, reviews and stores the Vaultwarden Secure Note, and independently authenticates the completed Bundle through both Recovery Methods before reporting Pack success. `--bitwarden-executable <PATH>` selects an explicitly reviewed Bitwarden command-line executable when trusted-path discovery is not appropriate. Recovery Secrets are never accepted through command arguments, generic environment variables, configuration files, or ordinary operation records; only the existing unlocked `BW_SESSION` is read by the reviewed Bitwarden adapter.

The completed COKS-30 core transaction adds cooperative Pack pause, repeated-interrupt escalation, authenticated Resume, atomic no-overwrite publication, persistence-failure containment, and deterministic recovery guidance. Pause occurs after a complete Migration Item; Resume requires both Recovery Methods, authenticates all saved progress and current source observations, and re-encrypts saved progress into a fresh encryption domain. The CLI accepts `--resume` only to explain that a fresh process cannot reconstruct the intentionally non-persisted Recovery Secrets; live Resume remains an in-process workflow capability. See [the accepted core design and remaining Owner Dogfood gates](adr/0008-prototype-authenticated-pack-resume.md) and [the synthetic testing guide](manual-qa/COKS-30-pack-resume-progress.md).

### `iniza inspect`

```text
iniza inspect <BUNDLE>
  --recovery <bitwarden|offline>
  --show-items
  --show-paths
```

Successful recovery is required before authenticated metadata is shown. Interactive mode may ask the user to select an available Recovery Method; `--non-interactive` and `--json` require `--recovery`. No content extraction occurs. `--show-paths` is ignored in redacted diagnostic contexts.

### `iniza recovery offline rehearse`

```text
iniza recovery offline rehearse
  --bundle <PATH.iniza>
  --document <PATH.iniza-recovery>
```

The command opens the restrictive self-identifying recovery document without following a final symbolic link, reconstructs the Offline Recovery Key only in zeroizing memory, fully authenticates the completed Bundle, and requires the authenticated Bundle and Recovery Method identities to match the document. The key is never accepted through an argument or environment variable. Success emits a secret-free rehearsal Receipt; all wrong, truncated, modified, mismatched, symbolic-link, or overly permissive documents produce the same authentication failure without comparison details.

The reusable write transaction is invoked in the same process that completes Pack, while the generated Offline Recovery Key is still in memory. It authenticates the completed Bundle before exclusively creating a `0600` document on an owner-selected separate mounted target, synchronizes the file and containing directory, and never overwrites an existing path. Supported Pack command orchestration remains gated on the Vaultwarden transaction so both required Recovery Methods are stored before Pack success is presented to the owner.

### `iniza fixture`

```text
iniza scan <SOURCE> --output-plan <PLAN>
iniza plan validate --plan <PLAN>
iniza fixture pack --plan <PLAN> --output <PATH.iniza-fixture>
iniza fixture inspect <PATH.iniza-fixture>
iniza fixture restore <PATH.iniza-fixture> --to <NEW_DESTINATION>
```

The `fixture` namespace is a development-only plumbing interface for synthetic data. Its container is deliberately marked `TEST-ONLY UNENCRYPTED`, uses a format that is structurally distinct from an encrypted Bundle, and must never be used for personal or production data. Normal `inspect`, `verify`, and `restore` commands reject this format. Fixture inspection shows only the embedded source file name and logical size. Fixture Restore requires an absent destination directory and never overwrites an existing path.

These commands support the global `--json` option. Machine mode emits one versioned result object on standard output, emits no progress or prompts, and never includes source file content.

### `iniza verify`

```text
iniza verify <BUNDLE>
  --recovery <bitwarden|offline|both>
  --full
  --write-receipt <PATH>
```

Default verifies structural/authenticated metadata. `--full` reads and authenticates every selected chunk. `both` proves each slot independently.

### `iniza copy`

```text
iniza copy <BUNDLE> <DESTINATION>
  --overwrite-partial
  --dry-run
```

Existing final destinations are never overwritten in MVP. The command copies, flushes where supported, hashes, reopens, and authenticates the destination.

COKS-31 implements this transaction in the reusable Rust core, including cancellation, explicit exact-prefix partial replacement, no-overwrite publication, durability warnings, and a secret-free Receipt. The supported cross-process command remains gated on loading a Recovery Method through the COKS-33 Offline Recovery Key or COKS-36 Vaultwarden flow; Recovery Secrets must not be passed through command arguments, environment variables, or ordinary files as an interim shortcut.

### `iniza restore`

```text
iniza restore <BUNDLE>
  --to <NEW_DIRECTORY>
  --recovery <bitwarden|offline>
  --platform-only <skip|review-directory>
  --dry-run
  --resume
```

For a new restore, the destination must be absent or empty. `--resume` may use a non-empty destination only when it contains the matching canonical authenticated Restore journal, staging state, and exact journaled prefix of already-published top-level entries, with no unrelated entries; otherwise it exits with code 50. Published candidates are revalidated for authenticated bytes and restrictive non-executable mode before a durable completion checkpoint; reviewed final modes are applied through open descriptors afterward. Failed pre-publication cleanup retains an empty outer destination rather than risking deletion through a substituted pathname. In-place merge and overwrite flags do not exist in the first release.

### `iniza status`

```text
iniza status [BUNDLE]
  --receipts <DIRECTORY>
```

Summarizes available evidence. It never returns an erase-safety decision.

### `iniza connector bitwarden status`

Displays executable path, supported version, configured server class, and authenticated/unlocked state. User email and full server URL are redacted in saved output.

### `iniza connector bitwarden test`

Performs a non-destructive status/sync test by default. An explicit interactive test may create and delete a temporary item, with both actions shown and confirmed.

## 3. Configuration

Default locations:

```text
macOS:  ~/Library/Application Support/Iniza/config.toml
Linux:  $XDG_CONFIG_HOME/iniza/config.toml
```

Example:

```toml
schema_version = 1

[ui]
color = "auto"
progress = "auto"

[scan]
cross_mounts = false

[tools]
git = "/usr/bin/git"
bw = "/opt/homebrew/bin/bw"

[limits]
max_file_size = "100GiB"
max_items = 5000000
```

Configuration must not contain master passwords, bundle secrets, recovery keys, Bitwarden sessions, Git tokens, or remote credentials.

## 4. Environment

Recognized non-secret environment variables:

- `NO_COLOR`
- `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, and `XDG_CACHE_HOME` on Linux
- `INIZA_CONFIG` as an alternative config path
- `RUST_BACKTRACE` for local development only

Iniza may observe an official `BW_SESSION` created by the user’s Bitwarden workflow but never prints, persists, or forwards it beyond the minimum `bw` child process. Secret environment variables are excluded from diagnostic output.

## 5. JSON result envelope

```json
{
  "schema_version": 1,
  "command": "verify",
  "status": "success_with_warnings",
  "operation_id": "op_...",
  "data": {},
  "warnings": [
    {"code": "INIZA-W221", "message": "One source item changed during capture"}
  ],
  "errors": []
}
```

Rules:

- stdout contains exactly one result object in `--json` mode.
- Progress is absent unless `--json-events` is selected.
- JSON event output goes to stderr as versioned JSON Lines.
- Secret values and decrypted file content have no schema fields.
- Unknown additive fields must be ignored by clients; schema-version changes follow documented compatibility rules.

## 6. Exit codes

| Code | Meaning |
|---:|---|
| 0 | Success |
| 1 | Success with warnings or partial optional outcome |
| 2 | Usage or invalid flags |
| 10 | Invalid or unapproved plan |
| 11 | Permission denied or source unavailable |
| 12 | Source changed; consistent capture not proven |
| 20 | Bundle invalid, corrupt, incomplete, or unsupported |
| 21 | Authentication or recovery failed |
| 22 | Insufficient storage or storage I/O failure |
| 30 | Connector unavailable or incompatible |
| 31 | Bitwarden operation failed |
| 40 | Git audit failed |
| 41 | Git push partially or fully failed |
| 50 | Restore conflict or unsafe destination |
| 51 | Restore validation failed |
| 70 | Interrupted with a safe checkpoint or partial state |
| 100 | Internal error |

Exit code 1 must still include a complete structured result. Scripts requiring warning-free completion should accept only 0.

## 7. Confirmation contract

- `--json` and `--non-interactive` never prompt.
- Missing approval causes an exit with code 10 rather than implicit consent.
- `--yes` can confirm a reviewed local operation but cannot create a new Git publication plan.
- Push execution requires the hash of the exact reviewed plan.
- Recovery-item deletion is not part of MVP.
- Restore cannot overwrite even with `--yes`.

## 8. Streams and secrets

- Human progress: stderr
- Human final output: stdout
- JSON result: stdout
- JSON events: stderr
- Hidden secret input: controlling TTY only
- Never accept recovery secrets as ordinary flags
- Never include secrets in errors or panic output

## 9. Stability policy

- Bundle format compatibility is governed by bundle version and suite, not CLI version.
- Plan and JSON schemas declare independent versions.
- Before `0.1.0`, command syntax may change with migration notes.
- After `1.0.0`, existing non-experimental flags and exit meanings remain compatible within the major version.
- Security policy may reject a cryptographic suite even when its parser remains available; rejection must be explicit and documented.
