# Tracked Git history secret scan — 2026-09-07

This evidence records an independent scanner run against the complete tracked Iniza Git history at `2026-09-07T17:16:07Z`.

## Tool provenance

- Scanner: Gitleaks 8.30.1
- Official release metadata: `v8.30.1`, published `2026-03-21T02:17:58Z`
- Downloaded asset: `gitleaks_8.30.1_darwin_arm64.tar.gz`
- Official checksum and observed archive SHA-256: `b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5`
- Extracted executable SHA-256: `ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f`

The release checksum manifest and Apple Silicon archive were downloaded from the official Gitleaks GitHub release into an isolated temporary directory. The archive checksum was verified before extraction or execution. The scanner was not installed globally or committed to this repository.

## Scope and command

- Repository commit: `93d4c71def37e5eb1e67d70893b8873753f9b4cb`
- Git revisions reachable through all local references: 50
- Scanner configuration: Gitleaks built-in default rules; no allow-list or baseline
- Secret output: fully redacted
- Nested archive traversal: disabled by the default scanner configuration
- Timeout: 300 seconds

```console
gitleaks git \
  --redact=100 \
  --no-banner \
  --no-color \
  --log-level warn \
  --report-format json \
  --report-path /private/tmp/iniza-gitleaks.qf9de6/report.json \
  --timeout 300 \
  .
```

## Result

- Process exit status: 0
- Findings: 0
- Machine report: an empty JavaScript Object Notation array followed by a newline, 3 bytes
- Machine-report SHA-256: `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570`

The temporary report contains no finding or secret value and remains outside the repository.

## Limitations

This result covers tracked Git history reachable through the local repository's references at the stated commit. It does not inspect untracked personal files, ignored Project state outside this repository, deleted unreachable Git objects, external service history, screenshots, terminal scrollback, shell history, Vaultwarden, Migration Plans stored in private temporary locations, or future commits. Built-in rule coverage cannot prove the absence of every possible secret format.

Refresh this scan after source changes and before publishing a release. Any future finding must be reviewed without copying the detected value into chat, issue comments, screenshots, or ordinary logs.
