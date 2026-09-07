# Security artifacts

## CycloneDX software bill of materials

`iniza.cdx.json` is the deterministic CycloneDX 1.5 software bill of materials for every target-platform dependency in the exact committed `Cargo.lock`.

Generation evidence:

- Cargo.lock SHA-256: `87afbe4b19b743fb914d1dfd5f4472a63ea36c422643c9246bdb174fc96e6b88`
- Source date epoch: `1788398546`, the commit time of the current `Cargo.lock`
- Generator: cargo-cyclonedx 0.5.9
- Included scope: all dependencies, all features, all target platforms, build dependencies included
- CycloneDX specification: 1.5 JSON
- SBOM SHA-256 after local-path normalization: `8d93e9d0c0e3e0636107ef358f321d09ea79a63d32722131a32b646702168d0c`
- Components: 97 dependencies plus the root Iniza component
- Dependency graph nodes: 98

The generation command is:

```console
SOURCE_DATE_EPOCH=1788398546 cargo cyclonedx \
  --manifest-path Cargo.toml \
  --format json \
  --all \
  --all-features \
  --target all \
  --spec-version 1.5 \
  --license-strict
```

cargo-cyclonedx emits the absolute source checkout in the root component identifier and local package uniform resource locators. Before publication, replace only those exact Iniza root and target references with the stable package identifiers already used in `iniza.cdx.json`. Do not change registry component identifiers, package hashes, licenses, dependency edges, or target-platform coverage.

Validation requires all of the following:

1. Parse the file as JavaScript Object Notation.
2. Require `bomFormat` `CycloneDX` and `specVersion` `1.5`.
3. Require every component reference to be unique.
4. Require every dependency graph reference to resolve to the root component or one listed component.
5. Reject an artifact containing an absolute user path, a username, or a local `file://` reference.
6. Recompute and update the recorded SHA-256 after any dependency or generator change.

This artifact supports dependency review and later release-gate work. It does not satisfy the independent cryptographic, parser, or key-lifecycle review, and it does not authorize real sole-copy owner data.

## Verification snapshots

- [2026-09-07 automated verification](verification-2026-09-07.md) records the exact commit and lockfile used for the full behavior suite, strict static checks, and narrow tracked-repository secret-pattern check.
