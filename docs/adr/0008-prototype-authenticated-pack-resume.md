# Prototype authenticated Pack pause and Resume

- Status: In progress; not accepted as a completed storage transaction
- Date: 2026-09-03
- Issue: COKS-30

## Scope

This records the current synthetic-data implementation and its unresolved completion gates. It does not authorize Owner Dogfood, sole-copy data, machine erasure, or removal of independent backups. The final IZ2 Bundle format from architecture decision 0005 is unchanged.

## Current interface

`BundleEngine::pack(PackRequest) -> PackReport` returns Complete or Paused. Cancellation requests a cooperative stop after the current Migration Item. The request distinguishes New from Resume and can borrow an in-memory `PackRecoveryContext` before any output is written. Callers retain that context on failure. Recovery Secrets remain redacted, zeroizing, non-serializable values.

`PackReport` provides human and versioned machine-readable results, recovery context access, and an exit-code value. A paused report instructs the caller to Resume only after revalidation. `BundleEvent::CheckpointWritten` contains counts only. The supported command-line signal handler and Recovery Method storage adapters are not supplied by this implementation.

## Authenticated checkpoint

A cooperative pause synchronizes `<destination>.partial` and writes `<destination>.partial.checkpoint` with restrictive creation permissions. The checkpoint contains the approved Plan hash, exact encrypted-prefix hash and length, record sequencing and index, captured Manifest entries, counts, and observations of selected regular sources. Those observations must still match before Resume.

The sidecar begins with `IZ2PAUS1`, followed by a random twenty-four-byte nonce and authenticated ciphertext. Its canonical, bounded plaintext is encrypted using a separately derived checkpoint key and the original header digest as associated data. The derivation label is `iniza IZ2 pack checkpoint key v1`. The plaintext limit is 128 mebibytes. Protected paths, content, and Recovery Secrets are not written in plaintext to the sidecar.

Both the partial and checkpoint are synchronized before a checkpoint event is emitted. A missing checkpoint requires a restart at a new destination while preserving partial output. Invalid, incompatible, changed, or unauthenticated progress is never treated as a complete Bundle. All current partial, resumed-partial, previous-partial, and checkpoint names are rejected by ordinary Inspect, Verify, and Restore even if complete Bundle bytes are placed under those names. Verified Copy is not implemented here.

## Fresh encryption domain on Resume

Resume authenticates both Recovery Methods, the Plan, the saved checkpoint, and current regular-source observations. It reads every saved chunk, verifies chunk ordering, authentication tags, item digests, and the exact prefix digest, and streams that content into fresh ciphertext before capturing remaining Migration Items. It does not decrypt saved content into ordinary filesystem storage.

Each attempt uses a fresh data-encryption key, Bundle identifier, salt, and nonce prefix. Replaying an old checkpoint therefore does not instruct the writer to reuse a previous content-encryption key and nonce pair. This costs a full streaming read and rewrite of saved progress; it is not an in-place append optimization.

The prototype requires both Recovery Secrets to Resume because it wraps the new data-encryption key into both fresh slots. Either Recovery Method alone can still Inspect, Verify, and Restore the completed Bundle. This additional Resume requirement needs explicit review before the command-line contract is finalized.

## Present storage handoff

A resumed attempt writes `<destination>.partial.resume`. A second pause advances the saved pair using exclusive renames through a retained directory capability, with directory synchronization between renames. A `.partial.previous` pair temporarily retains the earlier progress. Successful completion publishes through the existing no-overwrite hard-link method.

Before checkpointing or final publication, the visible partial path must still identify the opened regular file. Failure cleanup checks that the path identifies the file this attempt created, rather than deleting a competing file created after preflight. These checks cover tested substitution points, not arbitrary check-to-use races.

This multi-file handoff is not yet a crash-reconciled transaction. Interruption between the pair's renames can leave mixed or previous artifacts, and an abandoned resumed attempt can block retry. Such artifacts must be preserved; they must not be manually promoted or deleted on the assumption that they are authenticated progress.

Successful Resume currently cleans up the old partial pair by pathname. Replacement of those saved paths during Resume is therefore an unresolved ownership-safety gap, separate from the new-output identity checks above. Closing that gap and retaining authenticated recovery state across cleanup errors are required before this issue can be complete.

## Evidence and unresolved gates

The public-interface tests cover cooperative pause, repeated pause and Resume, exact protected-byte recovery through both Recovery Methods, source-identity change, changed Plan, wrong context, checkpoint and ciphertext tampering, incompatible headers, unrelated final output, redacted results, preflight partial conflicts, and child-process termination at the exposed start, captured-item, checkpoint, and completion events. Capacity loss immediately before checkpoint creation must preserve the earlier authenticated checkpoint for a later successful Resume.

The issue remains In Progress. Completion still requires:

1. Fault injection before and after every persistent operation, including actual write, synchronization, rename, publication, and cleanup failures. Existing event tests do not cover every persistent transition.
2. Authenticated reconciliation of interrupted checkpoint-pair advancement and abandoned resumed attempts.
3. Destination-capability and output-identity protection through publication and cleanup; pathname checks alone are insufficient for arbitrary concurrent replacement.
4. Explicit repeated-interrupt behavior and complete retry, Resume, or restart guidance for error results.
5. Review of the both-Recovery-Methods Resume requirement, item-boundary cancellation latency, and additional disk space needed for re-encryption.
6. Full verification, independent security review, and the remaining Owner Dogfood gates. Passing this issue's tests alone does not establish migration readiness.

## Proposed next testing seam, awaiting owner confirmation

Keep behavior tests at `BundleEngine::pack`, Inspect, Verify, and Restore. Inject a destination-storage adapter into BundleEngine to exercise genuine filesystem failures without mocking Iniza-owned collaborators. The local adapter retains directory capabilities; a faulting adapter delegates to isolated real storage but can fail or terminate a child process around create, write, synchronize, rename, publication, and cleanup operations.

Tests should assert preserved source and unrelated bytes, rejected partial output, recoverable authenticated progress, and verified final protected meaning. They should not assert the writer's internal call order or a fixed number of storage calls.
