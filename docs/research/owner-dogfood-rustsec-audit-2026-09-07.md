# Owner Dogfood RustSec dependency audit — 2026-09-07

This evidence records an automated advisory check of the exact Rust dependency lockfile used by the Owner Dogfood build. It is a dependency-health check only. It does not satisfy the independent cryptographic, parser, or key-lifecycle review required by [ADR 0005](../adr/0005-adopt-iz2-streaming-multifile-bundle.md).

## Audited inputs

- Repository commit: `af3b109e138e80223446316a180db86147058a07`
- `Cargo.lock` SHA-256: `87afbe4b19b743fb914d1dfd5f4472a63ea36c422643c9246bdb174fc96e6b88`
- Rust compiler: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Cargo: `cargo 1.97.1 (c980f4866 2026-06-30)`
- cargo-audit: `0.22.2`

The audit used the official RustSec advisory database at commit `faedffd5118c1835e13cca3babb6059afb1eb8d0`, reported as last updated `2026-09-07T14:50:40+02:00`.

## Exact command

```console
/private/tmp/iniza-security-audit-tools/bin/cargo-audit audit \
  --file Cargo.lock \
  --db /private/tmp/iniza-rustsec-advisory-db \
  --deny warnings \
  --format json
```

The tool and advisory database were placed outside the repository in temporary, isolated directories. No application source, approved Plan, Bundle, Project remote, or Vaultwarden state was changed by this check.

## Result

- Locked dependencies checked: 98
- RustSec advisories in the database: 1,240
- Vulnerabilities: 0
- Informational warnings: 0
- Unmaintained warnings: 0
- Unsound warnings: 0
- Notice warnings: 0
- Yanked-package warnings: 0
- Process result: success with exit status 0 while `--deny warnings` was active

This result is point-in-time evidence. It must be refreshed against the then-current `Cargo.lock` and advisory database before a later release gate. The synthetic-and-duplicated-data restriction in ADR 0005 remains in force until the independent review and remaining Owner Dogfood gates are satisfied.
