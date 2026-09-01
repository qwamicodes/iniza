# Select the IZ1 prototype Bundle format and cryptographic suite

- Status: Accepted for the next implementation stage — synthetic data only; independent review still required
- Date: 2026-09-01
- Issue: COKS-25

## Context

Iniza needs evidence that one synthetic file can be encrypted, sealed, independently recovered, authenticated, inspected, and restored before production multi-file Bundle work begins. The format must fail closed under wrong Recovery Secrets, record mutation or reordering, truncation, forged completion, unsupported versions, and attacker-controlled parser costs.

This decision governs a one-file technical prototype only. It does not authorize Owner Dogfood, real sole-copy data, or production compatibility claims.

## Decision

The prototype format is named `IZ1`. It uses format version `1` and cryptographic suite identifier `1`. The writer emits only those exact values. The reader rejects every unknown version, suite, reserved flag, field value, or trailing byte; it never silently reinterprets a Bundle.

### Maintained implementations and randomness

The Rust implementation pins these exact direct dependencies in `Cargo.toml` and resolves their transitive dependencies in `Cargo.lock`:

- `chacha20poly1305` `0.11.0`, with `zeroize`, for XChaCha20-Poly1305 authenticated encryption.
- `argon2` `0.6.0`, with `zeroize`, for Argon2id version `0x13` Recovery Secret key derivation.
- `hkdf` `0.13.0` and `sha2` `0.11.0` for HKDF-SHA-256 domain-separated subkeys.
- `blake3` `1.8.7` for content and exact-prefix digests inside authenticated records.
- `getrandom` `0.4.3` for operating-system cryptographic randomness.
- `zeroize` `1.9.0` for best-effort clearing of in-memory secrets and plaintext buffers.

Production randomness comes only from the operating-system cryptographic random-number generator through `getrandom::fill`. Failure to obtain randomness aborts sealing; there is no fallback generator.

### Keys and independent Recovery Methods

Each Bundle receives an independently random:

- 32-byte data-encryption key;
- 32-byte Vaultwarden Recovery Secret;
- 32-byte Offline Recovery Key;
- 16-byte Bundle identifier;
- 32-byte HKDF salt; and
- 16-byte record-nonce prefix.

The two Recovery Secrets are generated independently. Each slot has its own random 16-byte Argon2 salt and random 24-byte XChaCha20-Poly1305 nonce. Each Recovery Secret derives a 32-byte wrapping key with Argon2id version `0x13`, `m = 65,536 KiB`, `t = 3`, `p = 4`, and a 32-byte output. Each resulting wrapping key encrypts the same random data-encryption key. Either slot therefore unlocks the Bundle without the other.

The reader accepts only those exact Argon2 algorithm, version, and cost values. It rejects unrecognized cost fields before running Argon2, preventing attacker-selected memory or iteration costs.

The data-encryption key is passed through HKDF-SHA-256 with the Bundle's 32-byte HKDF salt. IZ1 derives independent 32-byte keys with these exact information values, each followed by the 16-byte Bundle identifier:

- `iniza IZ1 content key`
- `iniza IZ1 manifest key`
- `iniza IZ1 index key`
- `iniza IZ1 completion key`

### Public header and Recovery Method slots

The public header is exactly 296 bytes:

1. Eight-byte magic `INIZAIZ1`.
2. Big-endian format version `1` and suite identifier `1`.
3. Big-endian header length `296`.
4. Bundle identifier, HKDF salt, and record-nonce prefix.
5. Two-slot count and zeroed reserved bytes.
6. Two fixed 106-byte slots, one for Vaultwarden and one for Offline recovery.

Each slot serializes its Recovery Method identifier, Argon2 version and exact costs, salt, wrapping nonce, wrapped-key length, and 48-byte encrypted data-encryption key. Slot associated data is the exact concatenation of the magic, version, suite, Bundle identifier, HKDF salt, record-nonce prefix, and the slot fields preceding the wrapped key. Changing any of those fields makes the slot fail authentication or canonical parsing.

### Authenticated record stream

All integers are big-endian. Every encrypted record has a canonical 20-byte public record header followed by XChaCha20-Poly1305 ciphertext and its 16-byte tag. The header contains record type, zero flags and reserved bytes, a global 64-bit sequence number, plaintext length, and ciphertext length.

The XChaCha nonce is the Bundle's random 16-byte nonce prefix followed by the record's 64-bit big-endian global sequence number. A newly random data-encryption key and nonce prefix make the nonce domain unique per Bundle; the monotonically increasing global sequence prevents reuse within a Bundle. Sequence wrap is forbidden.

Record associated data is the exact concatenation of:

1. BLAKE3 hash of the complete 296-byte public header;
2. format magic, version, and suite;
3. Bundle identifier;
4. record type;
5. global sequence number;
6. plaintext length; and
7. ciphertext length.

The prototype emits four records in this exact order:

1. Content, sequence `0`, encrypted with the content key.
2. Manifest, sequence `1`, encrypted with the manifest key. It contains the source file name, logical size, BLAKE3 content digest, and canonical reserved fields.
3. Index, sequence `2`, encrypted with the index key. It identifies the single content record.
4. Completion, sequence `3`, encrypted with the completion key.

The prototype accepts one regular file and one content chunk of at most 1 MiB. It does not yet stream multi-file content. Inspect authenticates every slot-dependent and encrypted structure, including the content, but creates no extracted file. Restore authenticates the complete Bundle before it creates a new destination directory, refuses an existing destination, treats the authenticated source name as a single safe file name, writes bytes without executing them, and uses `create_new` for the restored file.

### Completion and incomplete output

The completion plaintext contains:

- marker `END1`;
- BLAKE3 digest of every exact serialized Bundle byte preceding the completion record;
- count `3` for the preceding records;
- manifest location as global sequence `1`;
- index location as global sequence `2`; and
- terminal state `complete` encoded as `1`.

The completion plaintext is encrypted and authenticated with the completion key. A bare digest is not treated as authentication.

The writer creates `<destination>.partial` exclusively, writes and synchronizes the full bytes, then creates the final `.iniza` name with a no-overwrite hard link and removes the partial name. A normal Inspect or Restore rejects any path ending in `.iniza.partial`, even if its bytes were copied from a complete Bundle. Writer errors clean up the known partial path. A final destination is never overwritten.

### Parser and allocation limits

The prototype uses checked cursor arithmetic, fixed-width fields, exact canonical values, and these upper bounds:

- complete Bundle file: 96 MiB;
- public header: exactly 296 bytes, below the 4 KiB design ceiling;
- Recovery Method slots: exactly two slots of 106 bytes each, below the eight-slot and 4 KiB-per-slot design ceilings;
- content plaintext record: 1 MiB;
- manifest plaintext record: 16 MiB;
- index plaintext record: 64 MiB;
- completion plaintext record: 64 bytes; and
- authenticated source file name: 1 to 4,096 UTF-8 bytes and one safe file-name component.

The reader opens the file once, checks that handle's metadata, and reads through a 96 MiB plus one-byte limiter. Unauthenticated lengths are used only for bounded parsing; no path, count, or length from protected metadata is returned or used for filesystem mutation until the corresponding record authenticates and validates canonically.

### Secret containment

COKS-25 deliberately exposes no command-line recovery-secret workflow. Recovery Secrets are generated and consumed as non-cloneable in-memory values. Their debug representation is redacted, they have no display or serialization interface, and secret-bearing types expose only their Recovery Method. Plaintext buffers, the data-encryption key, wrapping keys, derived keys, and Recovery Secrets use `zeroize` wrappers where practical.

No Recovery Secret or plaintext data-encryption key is placed in process arguments, environment variables, logs, Plans, Receipts, normal output, or error messages. Future Vaultwarden and Offline Recovery Key adapters must introduce a separately reviewed secret-input and secret-storage seam; they must not add secrets to process arguments or ordinary environment capture.

## Evidence

The prototype tests use only synthetic, non-secret files and real isolated filesystem behavior:

- one Bundle independently unlocks through each Recovery Method;
- authenticated Inspect and exact-byte Restore succeed;
- Restore refuses an existing destination;
- wrong Recovery Secrets and modified ciphertext fail authentication;
- reordered, truncated, trailing, or falsely completed Bundles fail closed;
- `.iniza.partial` is never accepted as completed;
- unsupported versions, suites, header lengths, and Argon2 costs are rejected;
- source and Bundle size limits are enforced;
- protected source content and source names do not appear in Bundle bytes;
- Plans and debug/error output contain no recovery secret; and
- XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, and BLAKE3 match published known-answer vectors.

The vector sources are [the XChaCha20-Poly1305 Internet-Draft appendix](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.1), [RFC 9106 section 5.3](https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3), [RFC 5869 appendix A.1](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1), and the [official BLAKE3 test vectors](https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json).

## Trade-offs and rejected alternatives

- XChaCha20-Poly1305 makes unique random per-Bundle nonce prefixes practical and supports one-pass record encryption. Its standardization document remains an expired Internet-Draft rather than an RFC, and its audit history predates the exact current Rust crate release. This is accepted only for the prototype pending independent review.
- AES-256-GCM was rejected because accidental nonce reuse is catastrophic and its platform acceleration is less uniform. AES-256-GCM-SIV remains the preferred fallback if review finds the IZ1 nonce argument insufficient, but it requires two encryption passes per record.
- Standard ChaCha20-Poly1305 was rejected because its shorter nonce gives less margin for random per-Bundle uniqueness.
- Password-Based Key Derivation Function 2 was rejected in favor of memory-hard Argon2id. Scrypt remains a credible fallback but is not the current RFC 9106 recommendation.
- Using BLAKE3 directly as the entire key schedule was rejected in favor of standardized HKDF-SHA-256 with explicit domain labels. BLAKE3 remains only a digest inside authenticated structures.
- Encrypting the whole Bundle as one message was rejected because independent bounded records provide clearer parser limits, corruption scope, future streaming, and authenticated structure.

## Compatibility policy

Once approved, format version `1` plus suite identifier `1` has immutable byte semantics. A behavioral or cryptographic change that alters those semantics requires a new suite identifier or format version, explicit migration behavior, new known-answer and round-trip evidence, and another architecture decision. Readers must reject unknown values rather than guess, downgrade, or silently migrate. Prototype Bundles are not promised long-term support until the production multi-file decision explicitly adopts or replaces IZ1.

## Consequences and remaining work

- COKS-27 may use this evidence to design streaming multi-file Pack, Inspect, and Verify behind the reusable Rust core, but it must not assume the one-file in-memory implementation is production-ready.
- The hard-link finalization method must be revisited for filesystems that do not support hard links, and directory durability must be specified and tested.
- Zero-length and exact chunk-boundary cases, deterministic complete-Bundle golden bytes, large streamed content, slot lifecycle and rotation, Vaultwarden transport, Offline Recovery Key storage, Receipts, and crash/power-loss rehearsal remain future work.
- Dependency advisories and release changes must be reviewed again before Owner Dogfood.
- An independent cryptography and key-handling expert must review the format, nonce construction, associated data, parser, secret lifecycle, and recovery adapters before Iniza supports real sole-copy data.
- Until that review and later Owner Dogfood gates pass, this prototype is for disposable synthetic data only and must not be used to protect the owner's Mac cleanup data.

## Owner decision

- [x] I accept IZ1 as the evidence-backed direction for the next production Bundle issue, subject to every limitation and independent-review requirement above.
- Owner: Kwaame Ofori-adjekum
- Decision date: 2026-09-01
- Notes: Accepted by the Owner in the COKS-25 implementation thread. This acceptance advances the synthetic prototype decision; it does not waive the independent-review or Owner Dogfood gates.
