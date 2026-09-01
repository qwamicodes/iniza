# Iniza CLI Functional Design Specification

**Status:** Revised CLI-first interaction specification
**Primary interface:** Terminal
**Future interface:** Desktop client using the same plans, core events, and receipts

## 1. Purpose

This document defines how people interact with the Iniza CLI. It replaces the previous desktop-first functional design. The legacy wireframes remain historical concept material and are not normative.

## 2. Experience principles

### Show coverage, not confidence theater

Every flow separates protected, excluded, unsupported, unavailable, changed, and unverified data. Success language is specific to the operation completed.

### Review before side effects

Scanning is read-only. Packing reads approved content and writes a bundle. Git pushes, Bitwarden writes, copies, and restores each have their own review boundary.

### Keep secrets visually quiet

The terminal never prints unlocking secrets or decrypted values by default. Secret fields are represented by state—available, stored, verified—not masked content.

### Preserve reversibility

MVP restore writes to a new directory. Iniza never wipes, commits, resets, force-pushes, or overwrites.

### Work without color or interactivity

All meaning has text/symbol redundancy. Commands support stable JSON for automation, while interactive mode offers guided defaults.

## 3. Command map

```text
iniza
├── scan        discover and write a plan
├── plan        show or validate a plan
├── projects
│   ├── scan    audit repositories
│   └── push    review and execute approved pushes
├── pack        create a .iniza bundle
├── inspect     show authenticated safe metadata
├── verify      authenticate bundle and recovery
├── copy        create and verify another copy
├── restore     restore into a new destination
├── status      summarize receipts and readiness evidence
└── connector
    └── bitwarden
        ├── status
        ├── test
        └── cleanup   explicit recovery-item cleanup, deferred from MVP
```

Running `iniza` with an interactive terminal starts the guided migration flow. Without a TTY, it prints help and exits with a usage error rather than guessing.

## 4. Guided flow

```text
Welcome to Iniza

What are you preparing for?
  1. Format or reinstall this machine
  2. Move to another machine
  3. Create a protected setup archive
  4. Test Iniza with sample data

This changes guidance only. It does not change what Iniza can protect.
```

The flow proceeds through:

```text
Purpose → Roots → Scan → Coverage review → Project review
→ Git push review → Bundle destination → Recovery setup
→ Pack → Verify → Restore rehearsal → Copy → Receipt
```

The user may save and exit after any non-mutating phase. Persistent state identifies the exact plan and completed checkpoints.

## 5. Scan experience

### Root selection

```text
Protect these locations:
  ✓ ~/.ssh                         SSH recipe
  ✓ ~/.gitconfig                   Git configuration
  ✓ ~/.zshrc                       Shell configuration
  ✓ ~/Code                         Project root
  ○ VS Code settings              account sync detected; optional
  ○ Homebrew inventory            regenerable setup inventory
  + Add another path

Optional deep scan: off
```

Deep scan requires an explicit root and offers exclusions before traversal.

### Progress

```text
Scanning ~/Code
  37 projects found
  12,481 files classified
  6 items require review

Press Ctrl-C to stop cleanly after the current item.
```

### Coverage summary

```text
Coverage
  Included           8.4 GB   9,842 items
  Must-protect gaps      —    0 blocking items
  Excluded          21.7 GB   generated/caches
  Needs review       1.2 GB   6 items
  Unsupported          —      3 categories detected
  Unavailable          —      2 unreadable paths
```

Each category expands into exact paths in local interactive output. JSON uses item IDs and includes paths only when requested by the caller.

## 6. Project safety experience

### Repository row

```text
api-service
  remote: origin (configured)
  branch: main → origin/main, 2 commits ahead
  working tree: 3 modified, 2 untracked
  ignored review: .env, local.db
  protection: local capsule required
  remote sync: available after review
```

### Push review

```text
External Git changes

The following pushes may trigger CI, deployments, or notifications.

  api-service   main → origin/main   2 commits
  website       fix/nav → origin/fix/nav   1 commit

No force pushes. No new remote branches.

Choose: [Review each] [Push these 2] [Skip]
```

Pack confirmation never implies push confirmation. In non-interactive mode, a reviewed push-plan hash and explicit `--apply` are required.

### Push outcome

```text
Git synchronization
  ✓ api-service/main
  ✕ website/fix/nav       authentication failed

Both projects will still be protected in the encrypted bundle.
```

Project results distinguish **Restorable** from **Synchronized**. A Project can remain Restorable when a push fails, but a required Project does not satisfy Owner Dogfood readiness until its upstream state is synchronized or the owner resolves the reported remote divergence. Iniza reports behind branches and never pulls or merges them.

## 7. Ignored-file review

Ignored files are grouped by likely disposition:

```text
Suggested exclusion
  node_modules/       4.8 GB   regenerable dependency tree
  target/             3.1 GB   Rust build output

Review before excluding
  .env                2 KB     likely secret/configuration
  local.db          128 MB     database; live capture unsupported
  uploads/          640 MB     likely user data
```

The user can include reviewed static secrets, configuration, certificates, and irreplaceable uploads. Live databases remain warned or unsupported even if raw files are selected because consistency is not guaranteed; a validated consistent export is required for Must-Protect database state.

Application settings synchronized by an account are shown as optional Protection Candidates rather than silently selected or silently omitted. Iniza does not claim the account copy is verified. The user can select the local settings for Bundle protection, or leave them unselected with that choice visible in coverage.

## 8. Plan review

```text
Plan: iniza.toml
Plan ID: 7f1c…

Will read:
  9,848 selected items

Will write:
  /Volumes/Backup/kwame-2026-08-28.iniza

Will contact:
  Bitwarden through installed bw CLI

Will not do:
  Push Git refs (already skipped)
  Overwrite files
  Upload the bundle to Iniza
  Erase or modify the source machine
```

The plan must pass validation before `pack`. Changes after approval produce a new plan hash and require review.

## 9. Recovery experience

### Bitwarden preflight

```text
Bitwarden
  executable     /opt/homebrew/bin/bw
  server         self-hosted.example
  vault status   locked

Unlock your Bitwarden CLI, then return here.
Iniza will never ask for your Bitwarden master password.
```

Iniza may wait and recheck, or exit with a resumable instruction. It never prints a command containing a secret.

### Offline recovery

The user chooses a secure file destination on separately stored media. Iniza writes the recovery document with restrictive permissions and does not print the recovery secret to ordinary terminal output. Before completion, Iniza requires the user to unlock the bundle with the saved offline method.

```text
Offline recovery key
  created      ✓
  saved        ✓ /Volumes/Recovery/iniza-recovery.txt
  rehearsed    pending
```

No recovery secret appears in ordinary terminal scrollback.

## 10. Pack experience

```text
Creating kwame-2026-08-28.iniza

  Scanning consistency      ✓
  Encrypting files          6.1 / 8.4 GB
  Project capsules          31 / 37
  Sealing manifest          pending
  Bitwarden verification    pending

  73% · 184 MB/s · about 14s remaining
```

Timing is approximate and omitted when unstable. Ctrl-C requests a checkpointed stop. Partial output is named clearly and cannot be mistaken for a completed bundle.

### Completion

```text
Bundle created
  path              /Volumes/Backup/kwame-2026-08-28.iniza
  bundle ID         iz_01…
  size              7.2 GB
  structure         verified
  Bitwarden         verified
  offline recovery  not yet rehearsed

This bundle is not yet ready for the formatting rehearsal.
Next: iniza verify ... --recovery offline
```

## 11. Inspect and verify

`inspect` displays only authenticated, safe metadata after successful unlock. It does not extract content.

`verify` supports structural verification, full chunk verification, recovery-method proof, and receipt output.

```text
Verification complete
  header and key slot       ✓
  encrypted manifest        ✓
  chunks             18,422 ✓
  project capsules          ✓ 37
  selected bytes            ✓ 8.4 GB
  source-change warnings      1

Result: verified with warnings
```

Warnings link to exact local details and prevent an all-clear readiness state when they affect completeness.

## 12. Restore experience

### Preflight

```text
Restore plan
  bundle       kwame-2026-08-28.iniza
  destination  ~/Iniza-Restored
  mode         new directory
  items        9,848
  projects     37
  required     8.9 GB

Existing content will not be overwritten.
Repository hooks will be restored disabled.
```

If the destination exists and is non-empty, MVP exits with a conflict and suggests a new path.

### Cross-platform mapping

```text
Portable and mapped       9,711
Source-platform only        121
Manual mapping required      16
```

Platform-only items can be extracted into a review subtree but are never automatically applied.

### Completion

```text
Restore completed with warnings
  file integrity            ✓
  project integrity         ✓ 37
  portable metadata         ✓
  unapplied macOS metadata  14 items
  disabled hooks             5

Receipt: ~/.local/share/iniza/receipts/restore-iz_01….json
```

## 13. Verified copy

```text
iniza copy source.iniza /Volumes/SecondBackup/

Copying       7.2 GB ✓
Byte hash            ✓
Bundle authentication ✓

Verified copy created.
```

A filesystem copy without post-copy authentication is never labelled verified.

## 14. Status and readiness

```text
Migration evidence
  Bundle verification          ✓
  Bitwarden recovery           ✓
  Offline recovery             ✓
  Temporary restore rehearsal  ✓
  Second-environment rehearsal pending
  Independent bundle copies    2 verified
  Conventional backup          user-confirmed
  Not Protected report         acknowledgement pending
  Must-protect gaps             0
  Required projects             37 restorable · 36 synchronized

Result: recovery tested; remaining evidence required
```

Machine-verifiable rows come from Receipts. Human-only facts such as the conventional backup, representative project validation, and review of the **Not Protected** report are recorded as explicit, timestamped Owner Attestations. An attestation records what the owner asserted without presenting it as an automated verification.

Permitted success language:

- Bundle created
- Bundle verified
- Recovery tested
- Restore completed
- Copy verified

Prohibited language:

- Safe to erase
- Everything is backed up
- Complete machine backup
- Guaranteed migration

## 15. Error design

Every error includes:

1. What failed
2. What was and was not changed
3. Whether protected output remains valid
4. The safest next command or action
5. A stable error code

Example:

```text
INIZA-E340: Bitwarden verification failed

The encrypted bundle is sealed and can still be opened with its offline
recovery key. The Bitwarden item could not be retrieved after sync.

No source files were changed. No Git pushes were attempted.

Next: unlock Bitwarden and run `iniza verify bundle.iniza --recovery bitwarden`
```

Errors never embed raw external stderr when it may contain credentials.

## 16. Confirmation rules

| Action | Review | Confirmation |
|---|---|---|
| Scan explicit roots | Root list | Once per plan revision |
| Read selected content | Included/excluded plan | Pack confirmation |
| Write bundle | Exact destination | Pack confirmation |
| Create Bitwarden item | Server and item metadata | Recovery confirmation |
| Push existing upstreams | Exact immutable push plan | Separate confirmation |
| Publish new Git refs | Each ref | Individual confirmation |
| Copy bundle | Exact destination | Copy confirmation |
| Restore | Bundle, destination, mappings | Restore confirmation |
| Delete Bitwarden item | Exact item ID/name | Explicit cleanup confirmation |

`--yes` may approve previously reviewable local actions but cannot silently authorize first-time external Git publication or recovery-item deletion.

## 17. Output modes

### Human

- Concise by default
- Expandable local detail with `--verbose`
- Progress on stderr when appropriate
- Final result and actionable output on stdout

### JSON

- One versioned result envelope on stdout
- No ANSI sequences
- No prompts
- Progress disabled unless `--json-events` sends JSON Lines to stderr
- Secret fields structurally absent

## 18. Accessibility

- `NO_COLOR` and `--no-color` supported.
- Symbols always have text labels.
- Progress has periodic text summaries and can be disabled.
- Prompts have unique choices and accept full words where practical.
- Screen-reader mode suppresses animated redraws.
- Errors and final receipts remain understandable when copied as plain text.
- Interactive tasks have equivalent flags or plan-file inputs.

## 19. Localization

MVP command names, flags, error codes, and JSON fields remain English and stable. Human messages are designed for future localization but English-only dogfood does not block terminal use on systems configured for other languages.

## 20. Privacy

- No telemetry.
- No automatic diagnostic upload.
- Local paths are visible in ordinary interactive review because the user must verify them.
- Saved receipts and normal logs use redacted IDs where full paths are unnecessary.
- Diagnostic export previews all included files and fields.

## 21. Acceptance criteria

- A first-time user can complete the guided synthetic-data flow without reading command documentation.
- Every external or destination mutation has an independent review boundary.
- The CLI works without color and under a screen reader-friendly mode.
- JSON mode never prompts or emits secrets.
- Interrupted pack and restore explain the valid state and next action.
- A user can identify every unsupported or unverified category before viewing readiness evidence.
- The interface never implies responsibility for formatting or wiping.

## 22. Future desktop relationship

The desktop application will consume the same plan schema, core events, bundle format, connector policies, receipts, and confirmation boundaries. It may improve navigation and visualization but cannot weaken CLI safety rules.

Earlier MoveMyMac wireframes are inspiration only. A new desktop FDS will be created after owner dogfood validates the CLI workflow.
