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
iniza scan [ROOT ...]
  --deep
  --exclude <PATH_OR_PATTERN>...
  --recipe <ssh|git|shell|custom>...
  --project-root <PATH>...
  --output-plan <PATH>
  --cross-mounts
```

Default behavior is read-only metadata discovery. `--deep` without a root is invalid. Mount boundaries are not crossed unless explicitly enabled.

### `iniza plan`

```text
iniza plan show [--plan <PATH>]
iniza plan validate [--plan <PATH>]
iniza plan diff <OLD> <NEW>
```

`show` renders included, excluded, review, unsupported, and unavailable categories. `validate` emits a stable plan hash.

### `iniza projects scan`

```text
iniza projects scan [ROOT ...]
  --remote-check
  --include-ignored
  --plan <PATH>
```

Without `--remote-check`, the command performs no intentional network operation.

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

### `iniza inspect`

```text
iniza inspect <BUNDLE>
  --recovery <bitwarden|offline>
  --show-items
  --show-paths
```

Successful recovery is required before authenticated metadata is shown. Interactive mode may ask the user to select an available Recovery Method; `--non-interactive` and `--json` require `--recovery`. No content extraction occurs. `--show-paths` is ignored in redacted diagnostic contexts.

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

### `iniza restore`

```text
iniza restore <BUNDLE>
  --to <NEW_DIRECTORY>
  --recovery <bitwarden|offline>
  --platform-only <skip|review-directory>
  --dry-run
  --resume
```

For a new restore, the destination must be absent or empty. `--resume` may use a non-empty destination only when it contains the matching authenticated Restore journal and staging state and no unrelated entries; otherwise it exits with code 50. In-place merge and overwrite flags do not exist in MVP.

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
