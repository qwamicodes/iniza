# Security verification snapshot — 2026-09-07

This snapshot records automated verification of the exact Iniza repository state at `2026-09-07T15:26:00Z`. It is evidence for review, not a substitute for the independent cryptographic, parser, and key-lifecycle review required by architecture decision 0005.

## Inputs

- Repository commit: `ebf6d567a74d164c9409adc7381450de187fc72b`
- Cargo.lock SHA-256: `87afbe4b19b743fb914d1dfd5f4472a63ea36c422643c9246bdb174fc96e6b88`
- Rust compiler: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Cargo: `cargo 1.97.1 (c980f4866 2026-06-30)`

## Full automated behavior suite

```console
cargo test --locked --all-targets --all-features
```

Result: 284 tests passed, zero failed, zero ignored. The run included:

- Pack interruption, persistence-failure, authenticated resume, and publication-race containment;
- official cryptographic known-answer vectors;
- Plan review, approval, stale-state, mount-boundary, and symbolic-link behavior;
- authenticated Bundle creation, mutation rejection, Inspect, and Verify behavior;
- Offline Recovery Key storage, loading, independent rehearsal, and secret-containment behavior;
- complete Project audit and Project Capsule capture and source-independent rehearsal behavior;
- immutable non-force Push Plan behavior;
- safe Restore interruption, destination-substitution, no-overwrite, metadata, hook, and executable containment;
- Vaultwarden installation review, secret transport, exact Secure Note, retrieval, and rehearsal behavior; and
- Verified Copy interruption, no-overwrite, byte identity, authentication, and durability reporting.

## Static checks

```console
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Both commands exited successfully with no warnings or formatting differences.

## Repository secret-pattern check

The tracked repository was searched for common private-key headers, literal Bitwarden session assignments, Vaultwarden credential assignments, common GitHub token prefixes, and Amazon Web Services access-key prefixes. The only match was the intentional private-shell instruction in `docs/manual-qa/COKS-36-vaultwarden-recovery.md`:

```console
export BW_SESSION="$(bw unlock --raw)"
```

That line obtains the session at runtime and contains no stored credential value. The check found no matching private-key block or token value.

This pattern check is deliberately reported as narrow evidence. It is not entropy-based secret scanning, does not inspect untracked personal files, and cannot prove that arbitrary protected content is absent. A later release review must use an independent secret scanner and review its findings.

A subsequent checksum-verified [Gitleaks scan of the complete tracked Git history](secret-scan-2026-09-07.md) returned zero findings. Its separate scope and limitations remain in force; it does not retroactively make this bounded pattern check broader.

## Remaining gates

This snapshot does not prove the real owner Vaultwarden transaction, physical Offline Recovery Key separation, real Bundle capture, two Verified Copies, fresh-environment Restore Rehearsals, Project synchronization, conventional backup, command-line orchestration, fuzzing, or independent review. No machine-erasure conclusion can be derived from it.
