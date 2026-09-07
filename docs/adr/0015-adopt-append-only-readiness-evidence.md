# Adopt append-only, revalidated Readiness Evidence

- Status: Accepted
- Date: 2026-09-07
- Issue: COKS-39

## Context

Owner Dogfood readiness depends on evidence produced by separate Plan, Bundle, Recovery Method, Verified Copy, Project Capsule, Restore, and Push Plan transactions. A mutable summary could lose history during replacement or allow an old copied result to appear current. Persisting each operation report directly would spread compatibility, redaction, invalidation, and retention rules across unrelated modules.

Iniza has no separately anchored signing key. A local digest can detect incomplete or accidental modification, but it cannot prove authorship against a hostile administrator who can replace records and recompute their digests. Readiness Evidence must state this limit honestly and must never grant permission to erase a machine.

## Decision

`ReadinessEvidenceEngine` owns one deep public interface for initialization, typed Receipt recording, exact Owner Attestation preparation and confirmation, append-only withdrawal, and current status derivation.

An evidence store is bound to one exact approved Plan. It is a private directory containing exclusive-create, canonical version-one records. Every record contains a random store identity, monotonically increasing sequence, previous-record digest, operation-specific non-secret fields, operation time, and a domain-separated BLAKE3 digest. Record replacement, missing middle sequences, broken chains, symbolic links, incomplete candidates, oversized records, unknown fields, and unsupported schema versions fail closed. Iniza provides no evidence-deletion operation.

Receipt requests accept typed results from successful Iniza operations. Callers cannot construct a generic successful Receipt from arbitrary strings. Stored bindings cover the exact Plan, authenticated Bundle identity, whole-file digest, Recovery Method, stable destination evidence identity, Project identity, Project Capsule review, Push Plan, published references, and operation time where applicable. Partial operations remain partial and cannot satisfy a readiness conclusion.

Status reparses the complete chain and revalidates current artifacts. It reopens the Bundle and every selected Verified Copy, independently authenticates both Recovery Methods, checks the safe Restore destination, revalidates Project Capsules, and performs remote Project checks only when explicitly requested. Remote checks use the constrained `GitPublicationProcess` capability and cannot push, fetch, merge, rebase, commit, reset, stash, delete, or force-push.

Every selected Verified Copy is classified at the filesystem boundary as `External storage`, `iCloud Drive`, or `Other`. The classification is re-derived when status revalidates the copy; no destination path is persisted in the evidence record or rendered result. Complete Evidence requires at least one current external-storage Verified Copy and at least one current iCloud Drive Verified Copy. Multiple files on the same ordinary filesystem remain blocking, even when their names or parent directories differ.

Every Project reports `Restorable` and `Synchronized` independently. A Project Capsule or Restore Rehearsal cannot substitute for publication evidence, and a successful Push Plan cannot substitute for a Project Capsule.

A Project with reviewed local-only branches or tags may satisfy Synchronized without publication only when its current Project Capsule is Restorable and an active fixed Owner Attestation references that exact current Project Capsule capture Receipt. The attestation states that the reviewed references are deliberately retained only in the verified Project Capsule and must not be published. An arbitrary or superseded reference is rejected, and withdrawal immediately returns the Project to a blocking Synchronized result.

Owner Attestations use fixed claim text, exact review hashes, explicit owner acknowledgement, and non-secret evidence references. They are always labelled `owner-stated`. Withdrawal appends a record instead of changing history. Missing, withdrawn, duplicated contradictory, or unconfirmed required claims remain blocking.

Claims that describe an Iniza operation must reference the current typed Receipt for that operation. This applies to the Not Protected Report review, all three Vaultwarden confirmations, the representative restored-Project build, the second-environment Restore Rehearsal, and the deliberate capsule-only Project decision. Recording a newer relevant Receipt supersedes the old binding; arbitrary references are rejected during preparation.

`Complete evidence` is derived only when every configured machine conclusion is current, the required independent durable Verified Copies are current, every required Owner Attestation is active and bound to current evidence where applicable, and every Must-Protect Project derived from the approved Plan is both Restorable and Synchronized. Human and machine results always preserve the statement `This is not permission to erase a machine.` They never claim a complete machine backup.

The filesystem persistence seam is `ReadinessEvidenceStorage`. Its local adapter performs restrictive creation, synchronized writes, no-overwrite publication, candidate removal, and directory synchronization. Failure-injecting adapters exercise each transition without mocking Iniza-owned behavior.

## Evidence

- Focused behavior tests cover exact Plan-to-Bundle binding, source-content drift, changed copies, same-filesystem copy rejection, changed remote references, omitted Must-Protect Projects, already-synchronized upstreams, unresolved Must-Protect Items, superseded and contradictory attestations, withdrawal, tampered bytes, missing middle sequences, incomplete candidates, and every storage-transition failure.
- Existing Bundle, Restore, Project Capsule, Push Plan, Offline Recovery Key, and Vaultwarden suites remain the independent sources of typed operation evidence.
- The complete synthetic chain reaches Complete Evidence only with a current external-storage copy and a current iCloud Drive copy. The same-filesystem negative path remains blocking with both required storage locations reported missing.
- A local-only-reference behavior test proves that current Project Capsule protection and the exact fixed owner decision are jointly required, that arbitrary evidence references are rejected, and that withdrawal blocks Synchronized again.
- Receipt-binding behaviors prove that operation-dependent Owner Attestations reject arbitrary references and stop satisfying readiness after the relevant Receipt is superseded.

Run `cargo test --locked --test readiness_evidence` for focused evidence. Run `cargo test --locked` for the repository-wide regression suite.

## Consequences

- Evidence records are retained for the full Migration and the owner-reviewed post-migration period. Supersession and withdrawal increase the store rather than rewriting it.
- A local chain is tamper-evident, not a cryptographic authorship guarantee against a hostile administrator.
- Remote revalidation can require configured Git authentication but cannot mutate the remote.
- COKS-41 remains responsible for the supported cross-process command-line workflow that creates and consumes this evidence.
- This decision does not authorize personal-data capture, sole-copy reliance, deletion, publication, or machine erasure.

## Owner decision

- [x] I reviewed and confirmed all ten COKS-39 Readiness Evidence seams.
- [x] I confirmed the Verified Copy storage-location seam: machine classification, no stored path, one current external-storage copy, and one current iCloud Drive copy.
- Owner: Kwaame Ofori-adjekum
- Decision date: 2026-09-07
- Notes: The owner confirmations authorized implementation of the documented public seams. They did not authorize Git publication, Bundle capture, deletion, Vaultwarden access, or machine erasure.
