# Dependency policy audit — 2026-09-07

This report records a cargo-deny policy inventory at `2026-09-07T17:10:10Z`. It intentionally does not add blanket allowances or claim that an absent policy is a passing policy.

## Inputs

- Repository commit: `8ce54287deddaa7d6c770d146460cb9e9d3767aa`
- Cargo.lock SHA-256: `87afbe4b19b743fb914d1dfd5f4472a63ea36c422643c9246bdb174fc96e6b88`
- cargo-deny: 0.20.2, installed in an isolated temporary tool directory
- Dependency selection: exact locked graph with all features
- Repository cargo-deny configuration: absent

## Commands and outcomes

```console
cargo deny --locked --all-features check advisories --hide-inclusion-graph --show-stats
cargo deny --locked --all-features check sources --hide-inclusion-graph --show-stats
cargo deny --locked --all-features check bans --hide-inclusion-graph --show-stats
cargo deny --locked --all-features check licenses --hide-inclusion-graph --show-stats
```

- Advisories: zero errors and zero warnings.
- Sources: zero errors and zero warnings. The locked graph resolves through the configured crates.io registry source; no unknown Git or path dependency was reported.
- Bans: zero errors and eleven duplicate-version warnings.
- Licenses: the no-configuration run rejected every license not explicitly allowed. Ninety-four `rejected` diagnostics therefore mean “no allow-list exists,” not that those licenses were independently judged incompatible. The run also identified the root Iniza crate as genuinely unlicensed because `Cargo.toml` declares no license.

The separate RustSec audit remains the canonical point-in-time advisory evidence because it records the exact advisory database revision.

## Duplicate-version inventory

The eleven warning families are:

1. `io-lifetimes` 2.0.4 and 3.0.1;
2. `windows-sys` 0.59.0, 0.60.2, and 0.61.2;
3. `windows-targets` 0.52.6 and 0.53.5; and
4. eight Windows architecture support packages at 0.52.6 and 0.53.1.

The host-relevant `io-lifetimes` split is transitive beneath `cap-std` 4.0.2 and `cap-primitives` 4.0.3. Version 2.0.4 enters through `fs-set-times` 0.20.3; version 3.0.1 enters directly through the capability crates and `io-extras` 0.19.0. No direct dependency update or suppression was attempted because it requires compatibility testing and an explicit policy decision.

The Windows duplicate families remain relevant to the all-target software bill of materials even though they are not linked into the Apple Silicon Owner Dogfood build.

## License inventory requiring review

The dependency graph contains expressions drawing from Apache-2.0, Apache-2.0 with LLVM exception, MIT, MIT-0, CC0-1.0, Unicode-3.0, Zlib, Unlicense, and an LGPL-2.1-or-later alternative for `r-efi`. Cargo metadata and the software bill of materials provide the exact package-to-expression mapping.

Before enabling a repository `deny.toml`, the owner must explicitly choose the Iniza project license and approve the allowed dependency-license policy. A later implementation should then deny unknown registries and Git sources, deny unapproved licenses, and either resolve or document each accepted duplicate-version family individually. This report is not that approval.

## Gate effect

The advisory and source checks add useful evidence, but the dependency-policy gate is incomplete. It remains blocked by the undeclared Iniza license, absent reviewed allow-list, and unresolved duplicate-version decisions. None of these findings authorizes real sole-copy data or changes the Owner Dogfood restrictions.
