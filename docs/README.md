# Iniza

Iniza is a cross-platform, local-first migration tool for preserving a working computer setup before a reinstall, replacement, or operating-system move. The first product is a Rust CLI for macOS and Linux. A desktop application will later consume the same Rust core.

## Current status

Iniza is in specification and dogfood development. The first user is the project owner, who intends to format a Mac only after Iniza has successfully captured, verified, copied, and rehearsed restoration of duplicated test data and an independent conventional backup exists.

The working brand is **Iniza**. Public release still requires package, domain, and trademark clearance.

## Documentation

- [Product requirements](PRD.md)
- [Technical specification](TSD.md)
- [Threat model](THREAT_MODEL.md)
- [CLI functional design](FDS.md)
- [CLI command contract](CLI_SPEC.md)
- [Owner dogfood profile](DOGFOOD.md)
- [Architecture decisions](adr/)

## Implementation tracking

Approved implementation slices are tracked in the [Iniza Linear project](https://linear.app/topsociety/project/iniza-55ffc9161890). Issues use fully written user stories, testable acceptance criteria, explicit dependency links, and spelled-out work-mode labels.

## Product decisions

- Rust core and supported CLI first.
- macOS and Linux first; Windows later.
- Desktop UI after the CLI proves the complete workflow.
- Encrypted, portable `.iniza` bundles stored wherever the user chooses.
- Vaultwarden is the owner-dogfood recovery service and is accessed through the official Bitwarden `bw` CLI.
- An independent offline recovery key remains available.
- Project discovery, local-state capture, and explicitly approved Git pushes are MVP capabilities.
- Iniza never wipes a machine and never states that a machine is safe to erase.
- No telemetry in the first release.

## Legacy concept material

The `wireframes/` directory contains the earlier MoveMyMac desktop concept. It is retained as design research, but it is superseded by the CLI-first specifications and must not be treated as the current interface contract.
