# Iniza Threat Model

**Status:** Revised CLI-first baseline
**Method:** Asset and trust-boundary analysis informed by STRIDE
**Scope:** CLI, Rust core, `.iniza` bundles, Git operations, Bitwarden connector, local storage, and restore

## 1. Purpose

Iniza handles credentials, private source code, configuration, and recovery secrets. This threat model defines what must be protected, where trust changes, how the product can be abused, and which controls gate dogfood and external release.

This document does not claim that an alpha bundle is an adequate sole backup. It explicitly requires independent backup and restore rehearsal before the owner formats a machine.

## 2. Security objectives

1. **Confidentiality:** Untrusted storage, sync providers, and observers cannot learn protected content or encrypted manifest details.
2. **Integrity:** Modification, truncation, reordering, substitution, or corruption is detected before affected data is trusted or restored.
3. **Recovery:** Either approved recovery method can unlock the bundle independently.
4. **Restore safety:** A bundle cannot write outside the approved destination, silently overwrite data, or automatically execute restored content.
5. **Publication safety:** Iniza cannot silently push Git refs, trigger remote automation, or publish local-only work.
6. **Secret containment:** Secrets do not enter plans, logs, receipts, diagnostics, process arguments, or persistent connector state.
7. **Honest coverage:** Unsupported, excluded, changed, and unreadable data remain visible.
8. **Supply-chain integrity:** Released binaries, dependencies, recipes, and updates are controlled and auditable.

## 3. System and trust boundaries

```text
User/terminal
    │ TB1
Iniza CLI ── TB2 ── Rust core
    │                    ├─ TB3 ─ source files and repositories
    │                    ├─ TB4 ─ git subprocess and remote
    │                    ├─ TB5 ─ bw subprocess and Bitwarden server
    │                    ├─ TB6 ─ encrypted bundle/untrusted storage
    │                    └─ TB7 ─ destination filesystem
    └──────────────── TB8 ─ local logs, plans, receipts, resume state

Release pipeline ───── TB9 ─ installed Iniza binary and dependencies
```

### TB1: User to CLI

Terminal input, environment variables, redirected streams, current directory, shell history, and TTY availability are not inherently safe. Prompts may be spoofed by a compromised terminal or wrapper.

### TB2: CLI to core

The CLI is a presentation adapter. Typed requests must preserve approval decisions and may not convert display strings back into trusted paths or secrets.

### TB3: Source filesystem and repositories

Names, symlinks, permissions, special files, Git metadata, hooks, and source content may be malicious or may change during capture.

### TB4: Git subprocess and remotes

Executable resolution, configuration, hooks, credential helpers, remote URLs, server responses, and push side effects cross a trust boundary. A push may trigger CI or deployment.

### TB5: Bitwarden subprocess and server

`bw` executable identity, its configuration, session token, JSON output, self-hosted TLS, vault item identity, and server availability are security-sensitive. Owner Dogfood targets the owner's actual Vaultwarden service and must verify the complete connector transaction against it; that result does not imply compatibility with other deployments.

### TB6: Bundle and storage

Local disks, external media, NAS, and cloud-synchronized folders are untrusted for confidentiality and integrity. Bundle bytes may be attacker-controlled.

### TB7: Destination filesystem

Existing files, mount points, symlinks, races, permissions, case sensitivity, and platform metadata can redirect or alter writes.

### TB8: Local operational state

Plans, receipts, journals, and diagnostics can leak paths or operation history even when bundle contents remain encrypted.

### TB9: Supply chain

Rust crates, build runners, signing keys, package repositories, release hosting, and future recipe/update infrastructure can compromise all other controls.

## 4. Assets and classification

| Asset | Classification | Required protection |
|---|---|---|
| SSH/private keys and credentials | Critical secret | Confidentiality, integrity, least exposure |
| Project source and local state | Confidential | Confidentiality, integrity, completeness |
| Bundle DEK and recovery secrets | Critical secret | Non-persistence, separation, recoverability |
| Bitwarden session | Critical ephemeral secret | Memory-only, minimum lifetime |
| Encrypted bundle | Sensitive ciphertext | Integrity, availability, version compatibility |
| Decrypted manifest and paths | Confidential | Memory-only where possible, redacted diagnostics |
| Migration plan | Sensitive metadata | No secrets or contents; controlled permissions |
| Git publication plan | High-impact action | Exact review, immutable approval |
| Receipts and logs | Sensitive metadata | Redaction, local-only default |
| Release/signing material | Critical secret | Isolated access and auditable use |

## 5. Threat actors

- Thief or observer with a copied `.iniza` bundle
- Cloud, NAS, network, or removable-media attacker
- Local unprivileged process running as another user
- Malicious process running as the same user
- Compromised source machine or repository
- Malicious bundle author
- Compromised Git remote, credential helper, or hook
- Malicious or substituted `bw` executable or server
- Supply-chain attacker
- Well-intentioned user making an irreversible mistake

## 6. Assumptions and non-guarantees

- The operating system CSPRNG and cryptographic libraries are trusted when uncompromised.
- Iniza cannot protect secrets from malware with equal or greater privilege while plaintext is in use.
- Iniza cannot guarantee availability if both recovery methods or every bundle copy are lost.
- Iniza cannot make a compromised source trustworthy; it can only preserve and label its state.
- A successful Git push is not a complete project backup.
- Unsupported applications, databases, volumes, and system state can remain after a successful bundle.
- Iniza never determines that formatting or wiping is safe.

## 7. Threat register

| ID | Threat | Impact | Required controls |
|---|---|---|---|
| T01 | Offline guessing of Bitwarden-stored bundle secret | Critical | Random high-entropy secret, memory-hard slot KDF, independent recovery slot |
| T02 | Recovery secret logged or written to shell history | Critical | Hidden input, structured secret types, no secret CLI flags, log tests |
| T03 | Bitwarden session exposed in arguments/environment/logs | Critical | Prefer inherited unlocked session, memory-only token, minimized child environment, redaction |
| T04 | Fake `bw` executable captures secret | Critical | Trusted resolution, explicit override, version/identity display, install guidance |
| T05 | Wrong Bitwarden item retrieved by name collision | High | Record and retrieve exact item ID, verify bundle ID and unlock |
| T06 | Self-hosted TLS interception or incompatible Vaultwarden | High | Delegate TLS to official client, respect configured CA, display server identity, compatibility test |
| T07 | Bundle header or manifest causes oversized allocation | High | Strict limits before allocation/decompression; fuzzing |
| T08 | Chunk truncation, replay, reordering, or substitution | Critical | AEAD with bundle/item/chunk context; authenticated index/footer |
| T09 | Partial output mistaken for complete | Critical | Distinct partial state/suffix; mandatory authenticated footer |
| T10 | Source changes during capture | High | Pre/post identity checks, retry, unverified result blocks readiness |
| T11 | Symlink escapes approved scan root | High | `lstat`-style traversal, no unsafe following, root containment checks |
| T12 | Special file blocks or leaks data | High | Reject devices/sockets/FIFOs by default; explicit unsupported report |
| T13 | Restore path traversal or absolute path write | Critical | Authenticate first, logical paths, canonical containment, component-wise safe creation |
| T14 | Destination symlink race redirects write | Critical | Descriptor-relative APIs where available, no-follow flags, staging, revalidation |
| T15 | Existing destination content overwritten | Critical | New-directory default; no overwrite in MVP |
| T16 | Restored hook or executable code runs | Critical | Never execute; quarantine/disable hooks; explicit later approval |
| T17 | Ignored `.env` or database silently omitted | High | Classify ignored content; highlight likely irreplaceable data; Not Protected report |
| T18 | Generated dependency trees inflate bundle | Medium | Known exclusion catalog, size preview, overrideable review |
| T19 | Silent Git push publishes private work | Critical | Immutable push plan, exact refs/remotes, explicit approval, no default new refs |
| T20 | Push triggers CI/deployment | High | Clear external-side-effect warning; never bundle with pack approval |
| T21 | Malicious Git config invokes helpers or hooks | High | Minimal Git commands, cleared environment, disabled hooks and helpers, protocol allowlist, direct arguments without a shell |
| T22 | Git URL or subprocess output leaks credentials | High | Strip credentials, queries, fragments, and local paths; neutralize controls; bound output; never persist raw subprocess text |
| T23 | Copy corruption goes unnoticed | High | Reopen, authenticate, and whole-file hash each copy |
| T24 | Plan/receipt leaks sensitive paths | Medium | Redacted IDs by default, restrictive permissions, explicit verbose mode |
| T25 | Diagnostic export leaks source or secrets | High | Allowlist fields/files, preview, secret scanning, explicit consent |
| T26 | Malicious dependency or release binary | Critical | Lockfile, audit, SBOM, reproducible build goals, signed artifacts |
| T27 | Downgrade to weak bundle format | High | Version policy, reject unsupported/forbidden suites, explicit migration tooling |
| T28 | User relies on alpha as sole backup | Critical | Product warnings, dogfood gate, independent backup and restore rehearsal |
| T29 | User loses both recovery methods | Critical | Require confirmation and recovery rehearsal; state unrecoverability plainly |
| T30 | Denial of service from huge or deeply nested data | Medium | Configured depth/count/size/time limits; streaming and cancellation |

## 8. Key lifecycle

### Creation

1. Generate bundle ID and 256-bit DEK using the OS CSPRNG.
2. Generate independent high-entropy Bitwarden and offline recovery secrets.
3. Derive independent wrapping keys using slot-specific salts, parameters, and context.
4. Wrap the DEK separately into each slot.
5. Encrypt chunks and manifest using context-separated keys derived from the DEK.
6. Seal the authenticated footer.
7. Create the Bitwarden item, retrieve it by ID, and prove it unlocks the completed bundle.
8. Require offline-key unlock rehearsal before dogfood readiness.
9. Zeroize plaintext secret buffers as soon as practical.

### Opening

1. Parse only bounded public metadata.
2. Select a recovery slot.
3. Derive the slot key and authenticate the wrapped DEK.
4. Authenticate manifest and indexes before trusting paths or counts.
5. Decrypt chunks only when requested and release plaintext promptly.

### Prohibited flows

- No plaintext DEK or recovery secret in bundle metadata.
- No recovery secret in plan, config, receipt, logs, arguments, clipboard by default, or diagnostic export.
- No Iniza-hosted escrow in MVP.
- No derivation of one recovery secret from the other.
- No automatic deletion of a Bitwarden item when a local bundle disappears.

## 9. Git safety model

- Audit is read-only unless the user separately requests remote checks.
- Pack approval cannot authorize push.
- Push plans list repository, remote, local ref, remote ref, and non-force status.
- Force push is prohibited in MVP.
- Existing upstreams are the only batch-selectable default.
- New remote refs require item-by-item confirmation.
- Failures are partial results and never erase the local capsule.
- Iniza does not commit, rewrite history, stash, checkout, merge, or reset the user’s repository.

## 10. Restore safety model

- A bundle remains attacker-controlled until authenticated and structurally validated.
- An authentic bundle from a compromised source can still contain malicious code.
- Default restore is an empty/new root with restrictive permissions.
- Writes are staged and journaled.
- Absolute paths, traversal, devices, sockets, and escaping links are rejected.
- Existing files are not overwritten in MVP.
- Executable content is never run as validation.
- Git hooks are disabled or quarantined.
- Unsupported metadata is reported rather than guessed.

## 11. Abuse cases and responses

### Unknown bundle

Display source and signature/recovery facts only after authentication. Restore into quarantine/new directory and warn that authentic content may still be malicious.

### User selects the filesystem root

Reject broad system roots by default. Deep scan requires an explicit home/project scope and exclusions; system directories remain unsupported unless a future reviewed recipe exists.

### Private key has permissive permissions

Include only after review, preserve original mode as metadata, and restore with a safe restrictive mode plus a warning.

### Bitwarden unavailable

Allow offline recovery. Mark Bitwarden recovery unverified and block a clean dogfood-readiness result.

### Both recovery methods lost

State plainly that Iniza cannot decrypt the bundle and has no backdoor or account recovery.

### Repository changes while packing

Retry bounded times. If consistency cannot be proven, protect what can be authenticated but mark the project unverified and block readiness.

### Git push fails

Continue local capsule protection, report the exact repository outcome safely, and do not retry indefinitely or change refs.

## 12. Release security gates

### Technical spike

- Known-answer and round-trip crypto tests
- Parser bounds and fuzz harnesses
- Synthetic credential fixtures only
- Secret-leak tests for logs, environment handling, arguments, receipts, and plans
- Restore traversal and symlink adversarial tests
- Fake Git and Bitwarden adapters for hostile output

### Owner dogfood

- Independent conventional backup exists
- Both recovery methods rehearsed
- Two verified bundle copies
- Temporary and second-environment restore rehearsals
- Project integrity and representative builds validated
- Not Protected report reviewed
- No known critical or data-loss defect

### Private alpha

- Dependency audit and SBOM
- Signed/checksummed artifacts
- Fault injection across persistent transitions
- macOS and Linux matrix
- Security review package prepared

### Public beta

- Independent cryptography/key-handling review underway or complete
- Public bundle-format documentation
- Vulnerability disclosure process
- Incident and key-rotation playbooks
- No known critical vulnerability

## 13. Verification strategy

- Unit, property, golden-format, fuzz, and fault-injection tests
- Mutation tests for policy-critical branches
- Static analysis and dependency advisories
- Secret scanning of produced artifacts and process captures
- Adversarial repositories, paths, symlinks, archives, and subprocess JSON
- Manual review of Bitwarden lifecycle and Git publication UX
- Cross-platform restore comparison

## 14. Incident response requirements

Maintain playbooks for cryptographic weakness, malicious release/dependency, Bitwarden connector leakage, Git publication bug, bundle corruption/data loss, and recipe/path vulnerability.

A format weakness triggers explicit reader/update guidance and authenticated rewrap or migration tooling where possible. Iniza never silently changes the interpretation of an existing suite.

## 15. Open security decisions

- Final `IZ1` libraries and parameters
- Secure transport of a temporary `bw` session to subprocesses
- Trusted `git`/`bw` executable resolution policy
- Platform-specific descriptor-relative restore APIs
- Compression and decompression limits
- Receipt/local-state protection
- Release signing and reproducibility design
- Support posture for Vaultwarden
