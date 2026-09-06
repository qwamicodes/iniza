# Prototype authenticated Pack pause and Resume

- Status: Accepted for the core Pack storage transaction; Owner Dogfood remains gated
- Date: 2026-09-03
- Issue: COKS-30

## Scope

This records the current synthetic-data implementation and its unresolved completion gates. It does not authorize Owner Dogfood, sole-copy data, machine erasure, or removal of independent backups. The final IZ2 Bundle format from architecture decision 0005 is unchanged.

## Current interface

`BundleEngine::pack(PackRequest) -> PackReport` returns Complete or Paused. Cancellation requests a cooperative stop after the current Migration Item. The request distinguishes New from Resume and can borrow an in-memory `PackRecoveryContext` before any output is written. Callers retain that context on failure. Recovery Secrets remain redacted, zeroizing, non-serializable values.

`PackReport` provides human and versioned machine-readable results, recovery context access, and an exit-code value. A paused report instructs the caller to Resume only after revalidation. `BundleEvent::CheckpointWritten` contains counts only. `PackRecoveryAdvice` classifies a failed attempt as retry, Resume after revalidation, restart at a new destination, or verify the published Bundle; both its human and versioned machine-readable forms exclude Recovery Secrets. The supported command-line signal handler and Recovery Method storage adapters are not supplied by this implementation.

## Authenticated checkpoint

A cooperative pause synchronizes `<destination>.partial` and writes `<destination>.partial.checkpoint` with restrictive creation permissions. The checkpoint contains the approved Plan hash, exact encrypted-prefix hash and length, record sequencing and index, captured Manifest entries, counts, and observations of selected regular sources. Those observations must still match before Resume.

The sidecar begins with `IZ2PAUS1`, followed by a random twenty-four-byte nonce and authenticated ciphertext. Its canonical, bounded plaintext is encrypted using a separately derived checkpoint key and the original header digest as associated data. The derivation label is `iniza IZ2 pack checkpoint key v1`. The plaintext limit is 128 mebibytes. Protected paths, content, and Recovery Secrets are not written in plaintext to the sidecar.

Both the partial and checkpoint are synchronized before a checkpoint event is emitted. A missing checkpoint requires a restart at a new destination while preserving partial output. Invalid, incompatible, changed, or unauthenticated progress is never treated as a complete Bundle. All current partial, resumed-partial, previous-partial, and checkpoint names are rejected by ordinary Inspect, Verify, and Restore even if complete Bundle bytes are placed under those names. Verified Copy is not implemented here.

## Fresh encryption domain on Resume

Resume authenticates both Recovery Methods, the Plan, the saved checkpoint, and current regular-source observations. It reads every saved chunk, verifies chunk ordering, authentication tags, item digests, and the exact prefix digest, and streams that content into fresh ciphertext before capturing remaining Migration Items. It does not decrypt saved content into ordinary filesystem storage.

Each attempt uses a fresh data-encryption key, Bundle identifier, salt, and nonce prefix. Replaying an old checkpoint therefore does not instruct the writer to reuse a previous content-encryption key and nonce pair. This costs a full streaming read and rewrite of saved progress; it is not an in-place append optimization.

The prototype requires both Recovery Secrets to Resume because it wraps the new data-encryption key into both fresh slots. Either Recovery Method alone can still Inspect, Verify, and Restore the completed Bundle. The Owner accepted this requirement, the Migration-Item-boundary cancellation latency, and the additional temporary disk space needed for re-encryption during project review. The future command-line interface must explain these costs before starting or resuming Pack.

## Present storage handoff

A resumed attempt writes `<destination>.partial.resume`. A second pause advances the saved pair using exclusive renames through a retained directory capability, with directory synchronization between renames. A `.partial.previous` pair temporarily retains the earlier progress. Successful completion synchronizes the completed partial and atomically renames it to the completed name without overwrite through a retained directory capability, then synchronizes that directory. Publication therefore cannot leave both the final and ordinary partial names as successful output.

Before checkpointing or final publication, the visible partial path must still identify the opened regular file. Failure cleanup checks that the path identifies the file this attempt created, rather than deleting a competing file created after preflight. These checks cover tested substitution points, not arbitrary check-to-use races.

An interruption after a resumed checkpoint becomes durable but before pair promotion leaves both the older canonical pair and newer resumed pair. Before moving either pair, Pack writes and synchronizes an encrypted, authenticated promotion journal to a unique partial staging name, then publishes and synchronizes it without overwrite. The journal is bound to the approved Plan, the advanced checkpoint, and the device and inode identities of all four progress artifacts. Each exclusive rename and cleanup is synchronized separately. On the next Resume, Pack authenticates the available checkpoint pair and the journal, recognizes every durable promotion state, revalidates the recorded identities, and continues from the first unfinished transition. A corrupted newer pair or journal cannot displace the older authenticated progress.

Successful Resume checks the opened device and inode identities before removing either saved artifact. Checkpoint promotion makes the same checks before moving saved paths. These checks reject the tested replacement cases and preserve unrelated bytes. Arbitrary malicious final-component replacement races outside the retained publication and promotion capabilities remain outside the tested owner-only operating model; Iniza must still be run from a private destination directory and must not be treated as protection against a hostile local administrator.

## Evidence and unresolved gates

The public-interface tests cover cooperative pause, repeated pause and Resume, exact protected-byte recovery through both Recovery Methods, source-identity change, changed Plan, wrong context, checkpoint and ciphertext tampering, incompatible headers, unrelated final output, redacted results, preflight partial conflicts, saved-path replacement, and child-process termination at the exposed start, captured-item, initial-checkpoint, resumed-checkpoint, every Pack persistence transition, every journal and promotion transition, and completion events. The failure-injectable `PackPersistence` boundary delegates to real isolated filesystem storage while injecting both storage-full and permission-denied errors before partial creation and writes, Migration Item staging, checkpoint writes and synchronization, final publication and directory synchronization, and every promotion transaction transition. Prepublication failures never expose the completed name; a directory-synchronization failure after atomic publication reports an error while leaving a Bundle that must fully verify before reliance. Capacity loss immediately before checkpoint creation preserves the earlier authenticated checkpoint for a later successful Resume. A corrupted interrupted Resume cannot displace older authenticated progress.

`PackCancellation::request_stop` returns `FinishCurrentItem` for the first request and `TerminateImmediately` for every later request. The caller owns immediate process termination; the core never converts the second request into publication or completion. A child-process test proves that acting on the second result leaves only a rejected partial artifact and requires a deliberate restart when no checkpoint became durable.

This completes the COKS-30 core behavior through the confirmed `BundleEngine::pack`, Inspect, Verify, Restore, cancellation, recovery-advice, and failure-injectable destination-storage seams. Tests assert preserved source and unrelated bytes, rejected partial output, recoverable authenticated progress, and verified final protected meaning without asserting an internal call count.

This decision does not establish complete migration readiness. Verified Copy must independently reject every partial artifact name in COKS-31. Supported Recovery Method storage and the cross-process command-line workflow remain COKS-33 and COKS-36 work. The complete synthetic rehearsal, real Plan review, real Bundle capture, independent copies, Restore rehearsals, security review, and Owner Dogfood approval gates remain mandatory before erasing the old machine.
