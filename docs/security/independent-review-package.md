# Independent security review package

This package prepares the bounded source and evidence set for an independent review of Iniza's encrypted Bundle, Recovery Method, Verified Copy, and safe Restore design. It is anchored to repository commit `6f5152e1c1dfb07d62b23986a7237e7411d94d06` at `2026-09-07T17:11:51Z`.

Preparing this package does not constitute independent review, accept a finding, authorize real sole-copy data, or make a machine-erasure decision.

## Integrity

From the repository root, verify the review inputs before reading or testing them:

```console
shasum -a 256 -c docs/security/review-manifest.sha256
```

Every listed file must report `OK`. A later source change invalidates the package until the manifest, automated evidence, and software bill of materials are regenerated and reviewed.

## Required reading order

1. `CONTEXT.md` for canonical domain language.
2. `docs/THREAT_MODEL.md` for assets, trust boundaries, abuse cases, and release gates.
3. Architecture decisions 0003, 0005, 0008, 0009, 0011, and 0014 for Recovery Method separation, the IZ2 format, Pack resume, Verified Copy, Offline Recovery Key storage, and Vaultwarden integration.
4. `Cargo.toml`, `Cargo.lock`, and `docs/security/iniza.cdx.json` for the exact dependency boundary.
5. `src/bundle.rs`, `src/offline_recovery.rs`, `src/vaultwarden_recovery.rs`, `src/restore.rs`, `src/restore_fs.rs`, and `src/project_capsule.rs` for the reviewed implementation surface.
6. The behavior tests listed in `docs/security/review-manifest.sha256`.
7. The RustSec audit, dependency-policy audit, and automated verification snapshot under `docs/security/`.

Real Migration Plans, Recovery Secrets, Bundle contents, Vaultwarden service details, personal Project paths, and owner credentials are deliberately excluded. The reviewer should use only synthetic fixtures.

## Review questions

The review must independently answer at least these questions:

1. Does IZ2 derive and separate data-encryption, metadata-authentication, and both Recovery Method slot keys without cross-slot dependence or unsafe reuse?
2. Are header, record, completion, and checkpoint associated-data schemas unambiguous, domain-separated, length-bounded, and resistant to reordering, truncation, substitution, and downgrade?
3. Are nonces unique for every key domain across fresh Pack, paused Pack, authenticated Resume, and regenerated output?
4. Does every parser reject unsupported versions, algorithms, lengths, record counts, paths, and completion states before unsafe allocation or materialization?
5. Can an attacker distinguish a wrong Recovery Secret from corrupted or mismatched protected material in a way that creates an oracle?
6. Are both Recovery Methods generated independently, zeroized appropriately, and excluded from arguments, ordinary output, diagnostics, Plans, Receipts, and persistent files other than the intentional Offline Recovery Key document and Vaultwarden Secure Note?
7. Does the Bitwarden command-line boundary constrain executable identity, environment, standard input, standard output, standard error, interaction, output sizes, server/account changes, and post-creation ambiguity sufficiently?
8. Do Pack and Verified Copy persistence transitions ever permit an incomplete, unauthenticated, stale, or replaced artifact to receive the final Bundle or Verified Copy identity?
9. Does Restore remain bound to opened descriptors and authenticated content while rejecting traversal, device entries, sockets, escaping links, normalization collisions, staged substitutions, malicious hooks, and unexpected executable content?
10. Can filesystem durability behavior lead the tool to claim success after data that was not safely persisted, especially across exFAT, cloud-backed storage, abrupt power loss, or directory-synchronization failure?
11. Are capacity, decompression, logical-size, item-count, path-size, depth, and command-output limits complete and applied before attacker-controlled resource consumption?
12. Can Project Capsule capture or source-independent rehearsal accidentally trust changed source state, incomplete Git Large File Storage objects, live database bytes, unreviewed ignored state, external Git storage, or active repository locks?
13. Are zeroization expectations valid under Rust moves, errors, subprocess transport, allocator behavior, and operating-system crash handling?
14. Do the known-answer tests use independent published vectors and do mutation/failure tests cover the security properties rather than duplicating implementation logic?
15. What changes, if any, are required before using the format for real owner data that is not a sole copy?

## Reproduction commands

```console
cargo test --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The current automated snapshot records 284 passing tests, zero failures, and zero ignored tests. The reviewer must rerun the commands on the verified package rather than relying only on that prior result.

To refresh advisory evidence, use cargo-audit with the exact `Cargo.lock`, fail on warnings, and record the RustSec database commit. To review license and source policy, use cargo-deny but do not treat the default no-configuration license rejection as a compatibility decision.

## Known unresolved decisions and gaps

- The IZ2 libraries and parameters are accepted only for synthetic and duplicated data; independent acceptance is absent.
- Parser fuzz harnesses and recorded fuzzing results are absent.
- Hard-link finalization, directory durability semantics, broader platform metadata, and compression/decompression policy remain open.
- Secure cross-process Pack orchestration and interrupted-Pack Recovery Method continuity are not implemented in the supported command-line interface.
- Trusted `git` and `bw` executable resolution, temporary Bitwarden session transport, receipt/local-state protection, release signing, and reproducibility remain open decisions.
- Iniza declares no project license, and no reviewed cargo-deny license/source/duplicate policy exists.
- The lockfile has eleven duplicate-version warning families recorded in the dependency-policy audit.
- The bounded tracked-repository pattern check is not an independent entropy-based secret scan.
- The real owner Vaultwarden transaction, physical Offline Recovery Key rehearsal, real Bundle capture, two Verified Copies, conventional backup, and both Restore Rehearsal environments remain incomplete.

## Expected deliverable

The independent reviewer should return a dated report bound to the Git commit and manifest hash. Each finding should state severity, affected contract or file, reproducible evidence, exploit or failure scenario, recommended correction, and whether it blocks Owner Dogfood, private alpha, or public beta. The owner must explicitly accept or require remediation for every finding; silence is not approval.
