# Adopt an authenticated Verified Copy transaction

- Status: Accepted for synthetic and duplicated data only; Owner Dogfood remains gated
- Date: 2026-09-06
- Issue: COKS-31

## Scope

This decision defines how Iniza creates a Verified Copy of an already completed Bundle. It does not provide cross-process Recovery Method storage, authorize real sole-copy data, or claim that any destination will remain available. Those Owner Dogfood gates remain separate.

## Public interface

`BundleEngine::copy_verified(VerifiedCopyRequest) -> VerifiedCopyReport` is the reusable core seam. A request contains exact source and destination paths plus one in-memory Recovery Method. It can explicitly replace a matching partial, borrow a cancellation token and path-free event sink, and use the failure-injectable persistence seam.

Only a successful report uses the phrase **Verified Copy**. The report binds the source and destination whole-file BLAKE3 digest, their authenticated Bundle identifiers, the observed durability class, warnings, and a secret-free Receipt. Human and versioned machine-readable output contain no source paths, destination paths, protected names, content, or Recovery Secrets.

## Transaction

1. Require the completed destination name to end with `.iniza`, so `<destination>.partial` is rejected by ordinary Inspect, Verify, Verified Copy, and Restore operations.
2. Open the source without following a final symbolic link and fully authenticate its format, Completion, Manifest, Index, every selected content chunk, and whole-file digest through the chosen Recovery Method.
3. Refuse an existing final destination. Refuse an existing partial unless the owner explicitly requests replacement and every existing partial byte exactly matches the authenticated source prefix.
4. Write a fresh restrictive partial from the already authenticated source descriptor. When replacing matching progress, use a separate resumed-partial name so the old partial remains recoverable until success.
5. Synchronize the candidate, reopen it under the private copy-candidate policy, fully authenticate it, and require its whole-file digest and authenticated Bundle identifier to match the source.
6. Atomically rename the candidate to the final name without overwrite through a retained destination-directory capability, then synchronize that directory.
7. Reopen the completed name, fully authenticate it again, and repeat the digest and Bundle-identity comparison before returning a successful report and Receipt.
8. Remove an explicitly replaced matching partial only after successful final verification and only while its device and inode identity still match the file that was reviewed.

Cancellation is checked after each bounded copy buffer. It synchronizes the bytes already written, emits a path-free paused event, leaves only a recognizable partial name, and returns an interrupted result. A subsequent explicit retry must first prove that the partial is an exact source prefix.

## Filesystem failures and guarantees

`VerifiedCopyPersistence` exposes the source-read, partial create/write/synchronize/authenticate, final publication, directory synchronization, and final reopen transitions. Its local implementation performs real filesystem operations; isolated tests inject permission failure and unavailable cloud-placeholder behavior, and mutate or truncate real candidates around authentication boundaries.

Prepublication failure never exposes the completed name. A failure after atomic publication can leave a completed name, but no successful report or Receipt is returned; the owner must run full verification before relying on it. Late destination collision preserves the unrelated destination and leaves the candidate partial.

The local implementation synchronizes file data and metadata with `sync_all` and synchronizes the containing directory. An adapter that cannot promise those semantics returns `Weaker`; successful output is still byte- and authentication-verified, but both report forms carry a weaker-filesystem-durability warning.

## Receipt boundary

The version-one copy Receipt contains only:

- operation and verified result;
- source authenticated Bundle identifier;
- destination authenticated Bundle identifier;
- whole-file digest; and
- verification time as Unix seconds.

Receipt persistence and aggregation into Readiness Evidence are provided by COKS-39. The supported command-line adapter must obtain a Recovery Method through the COKS-33 or COKS-36 secure storage flows; this issue does not add an unsafe argument, environment-variable, or ordinary-file secret transport merely to expose `iniza copy` early.

## Remaining gates

- Recovery Method persistence and supported cross-process command-line use remain COKS-33 and COKS-36.
- The COKS-39 Readiness Evidence transaction stores and revalidates the typed Receipt.
- Complete synthetic rehearsal, independent destination rehearsal, real Plan review, real Bundle capture, and Restore rehearsals remain mandatory.
- Keep independent conventional copies until all Owner Dogfood evidence is reviewed. Iniza never grants permission to erase a machine.
