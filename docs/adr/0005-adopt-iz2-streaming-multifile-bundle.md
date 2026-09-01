# Adopt IZ2 for streaming multi-file Bundles

- Status: Accepted for synthetic and duplicated data only; independent review still required
- Date: 2026-09-01
- Issue: COKS-27

## Context

The IZ1 prototype proves one-file encryption and authentication, but its immutable byte semantics accept only one in-memory content record. A reviewed directory Plan requires streaming capture without changing how an existing IZ1 Bundle is interpreted. The source can change during capture, storage is untrusted, capacity can disappear, and partial output must never look complete.

## Decision

The multi-file format is `IZ2`, with magic `INIZAIZ2`, format version `2`, and cryptographic suite identifier `1`. IZ2 reuses ADR 0004's XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, BLAKE3, operating-system randomness, parameters, and zeroization policy. `Iz1Prototype` retains IZ1; `BundleEngine` owns IZ2.

Both formats remain restricted to synthetic and duplicated data until independent review and later Owner Dogfood gates pass.

### Header and Recovery Methods

The 296-byte public header retains two fixed, independently salted Recovery Method slots. Unknown version, suite, slot, Argon2 parameter, reserved byte, or header length is rejected before key derivation or attacker-directed allocation.

Recovery Secrets remain non-cloneable, non-displayable, non-serializable zeroizing values. `RecoverySecret::from_bytes` accepts an already zeroizing 32-byte value so later Vaultwarden and Offline Recovery Key adapters can reconstruct an in-memory secret without using arguments, environment variables, ordinary files, or terminal output.

### Record stream

Every record has a 28-byte public header containing:

1. record kind;
2. three zero critical flag and reserved bytes;
3. big-endian 64-bit global sequence;
4. big-endian 32-bit Migration Item ordinal;
5. big-endian 32-bit chunk ordinal;
6. big-endian 32-bit plaintext length; and
7. big-endian 32-bit ciphertext length, exactly plaintext length plus 16.

Kinds are Content `1`, Manifest `2`, Index `3`, and Completion `255`. Unknown kinds and nonzero critical flags fail closed. Sequences are strictly increasing. Gaps are permitted because discarded unstable attempts consume nonces; nonces are never reused.

Associated data is the public-header BLAKE3 digest, IZ2 magic, version, suite, Bundle identifier, and complete record header. The nonce is the random 16-byte Bundle prefix followed by the record sequence.

### Streaming capture

Regular content is read in at most one-mebibyte plaintext buffers. Every buffer is encrypted before payload bytes reach filesystem output. Empty content has one authenticated zero-length record.

Each attempt compares source length, identity, and change token before and after reading, and confirms the observed length equals captured bytes. There are three attempts total. Attempts stage only ciphertext. Discarded attempts consume their sequence values; a stable retry is copied as ciphertext into the Bundle. Exhausted instability is recorded as Changed and Unverified. Symbolic links and special files are not followed or read and remain authenticated Unsupported coverage.

On supported Unix platforms, the local source adapter observes entries without following symbolic links and opens approved regular files with the operating system's no-follow flag. A regular file replaced by a symbolic link after Plan approval is contained, recorded as Unverified, and never used to escape the reviewed root.

### Authenticated structures

The encrypted Manifest is compact JavaScript Object Notation limited to 16 mebibytes with unknown fields rejected. It binds the source display name, approved Plan hash, captured size, Included/Changed/Unsupported/Unverified totals, every Migration Item and capture outcome, chunk mappings, and per-item BLAKE3 content digests.

The encrypted Index begins with `IDX2`, a bounded 32-bit count, and fixed 32-byte entries containing sequence, item ordinal, chunk ordinal, file offset, plaintext length, and ciphertext length. Index plaintext is limited to 64 mebibytes. Checked counts and sizes precede allocation. Entries must exactly match observed records, item bounds, and chunk order.

The 61-byte encrypted Completion begins with `END2` and binds the BLAKE3 digest of every preceding Bundle byte, preceding record count, Manifest and Index sequences, and terminal state `1`.

Inspect authenticates the selected Recovery Method, Manifest, Index, Completion, and preceding ciphertext stream without decrypting Content or extracting files. Verify additionally decrypts and authenticates every selected chunk and recomputes each content digest. Both stream from one open Bundle and allocate only within record limits. IZ2 has no compression.

### Capacity and publication

`DestinationCapacity` has local and scripted adapters. Pack checks an overflow-safe estimate before creation and capacity before each persisted write. Insufficient capacity never creates final output.

The writer creates `.iniza.partial` exclusively, synchronizes it, creates the final name through a no-overwrite hard link, and removes the partial name. Known failure paths remove known item staging and partial paths. Filesystems without hard-link support remain unsupported pending a later finalization decision.

### Automation output

Pack and Verify emit typed path-free events which render as versioned JavaScript Object Notation Lines. Verification renders one versioned result object. Recovery material, paths, filenames, and content are structurally absent.

Cross-process Recovery Secret storage is intentionally deferred to COKS-33 and COKS-36. Command rendering is tested in-process with synthetic Recovery Secrets rather than adding an unsafe temporary transport.

## Evidence

- Approved multi-file Plans Pack, Inspect, and Verify through independent Recovery Methods.
- Empty, text, binary, multi-chunk large, Unicode-named, restrictive-permission, symbolic-link, and post-approval symbolic-link-swap fixtures.
- Byte-level protected-content and name leak checks.
- Scripted successful retry, three-attempt Unverified reporting, and capacity failures before and during writes.
- A checked-in golden IZ2 Bundle plus truncation, reordering, duplication, oversized-field, unknown-record, and unknown-flag mutations.
- Existing IZ1 vectors, mutations, containment, and round trips remain green.

## Consequences

- Crash-resumable checkpoints remain COKS-30; Restore remains COKS-29.
- Offline Recovery Key persistence remains COKS-33; Vaultwarden remains COKS-36.
- Hard-link finalization, directory durability, broader platform metadata, fuzzing, advisories, and independent cryptographic/parser/key-lifecycle review remain gates before Owner Dogfood.

## Owner decision

- [x] I approve the `BundleEngine` seams and IZ2 under the limitations above.
- Owner: Kwaame Ofori-adjekum
- Decision date: 2026-09-01
- Notes: Approved in the COKS-27 implementation thread. This does not authorize real sole-copy owner data or waive independent review.
