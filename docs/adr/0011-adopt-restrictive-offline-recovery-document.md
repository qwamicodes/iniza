# Adopt a restrictive Offline Recovery Key document and independent rehearsal

- Status: Accepted for synthetic and duplicated data; physical removable-media rehearsal remains required
- Date: 2026-09-06
- Issue: COKS-33

## Context

Each IZ2 Bundle already has two independently salted Recovery Method slots. Pack generates the Vaultwarden Recovery Secret and Offline Recovery Key through separate operating-system cryptographic-randomness calls and rejects a supplied recovery context unless both secrets are distinct and correctly identified.

The Offline Recovery Key must survive loss of the source Mac without depending on Vaultwarden. It is therefore intentionally written as secret material to owner-selected separate removable storage. Everywhere else—including terminal output, process arguments, environment variables, Plans, Receipts, diagnostics, and clipboard operations—the key must remain absent.

## Public interfaces

`OfflineRecoveryEngine::write(OfflineRecoveryWriteRequest) -> OfflineRecoveryDocumentReport` authenticates a completed Bundle with the in-memory Offline Recovery Key and writes its document. `OfflineRecoveryEngine::rehearse(OfflineRecoveryRehearsalRequest) -> OfflineRecoveryRehearsalReceipt` reopens the saved document, reconstructs a zeroizing in-memory secret, fully verifies the Bundle, and compares authenticated identities.

`OfflineRecoveryEngine::load(OfflineRecoveryLoadRequest) -> LoadedOfflineRecoveryKey` applies the same full verification and identity checks, then retains the reconstructed Recovery Method only in a non-cloneable, redacted, zeroizing handle. Restore and Verified Copy can borrow that handle without adding a secret-bearing transport.

`OfflineRecoveryStorage` is the confirmed separate-storage and failure-injection seam. The local adapter requires the destination parent to resolve onto a mounted device distinct from the system root. Owner Dogfood additionally requires the owner to confirm that the selected mount is removable and stored separately. Synthetic tests use an explicit fake removable-storage adapter; this bypass is not exposed as a command-line option.

The supported cross-process command is:

```text
iniza recovery offline rehearse --bundle <BUNDLE> --document <RECOVERY_DOCUMENT>
```

It accepts paths only. It never accepts the key through a command argument, environment variable, standard input, prompt, or clipboard.

## Document format

The document name ends with `.iniza-recovery`, is at most 4,096 bytes, and contains exactly eight newline-delimited fields:

1. the `INIZA OFFLINE RECOVERY KEY` self-identifying header;
2. document schema version `1`;
3. the public authenticated Bundle identity;
4. Bundle format `IZ2`;
5. Recovery Method `offline`;
6. the non-secret identity `offline:<bundle-identity>:slot-2`;
7. the lowercase hexadecimal 256-bit Offline Recovery Key; and
8. fixed recovery and separation instructions.

The fixed, bounded format deliberately has no optional fields, source paths, filenames, protected content, owner identity, location hints, or arbitrary text. Unknown, missing, reordered, duplicated, or altered fields fail closed.

## Persistence and containment

Before writing, Iniza verifies the entire completed Bundle with the in-memory Offline Recovery Key. The target is opened with exclusive creation, restrictive mode `0600`, close-on-execution, and no-follow behavior where supported. Existing files and symbolic links are never overwritten; the owner must select and review a different target.

The document is written directly to the selected file, synchronized, and followed by containing-directory synchronization. A failure before file synchronization removes the exact device-and-inode identity created by this transaction when it remains safe to do so. A directory-synchronization failure returns no success report; the document may remain and must pass an independent rehearsal before reliance.

Loading requires a regular no-follow file, the size bound, and no group or other permission bits on Unix. Document parsing and Bundle authentication errors collapse to the generic `Bundle authentication failed` result so callers receive no expected-versus-actual or key-comparison information.

## Rehearsal Receipt and loss

A successful rehearsal Receipt contains only the Bundle identity, Recovery Method identity, and Unix verification time. It contains no key, document path, Bundle path, manifest, content name, or protected content.

Iniza has no backdoor and cannot reconstruct a lost Offline Recovery Key. The only independent alternative is the separately rehearsed Vaultwarden Recovery Secret. Loss guidance must say this plainly and must never imply that the machine is safe to erase.

## Consequences and remaining gates

- A saved document can independently unlock a completed Bundle in a fresh command-line process.
- The document is the one intentional plaintext location of the Offline Recovery Key and must remain separate from all Bundle copies.
- Supported Pack command orchestration still awaits the real Vaultwarden transaction, because Owner Dogfood requires both Recovery Methods to be stored and rehearsed.
- No removable storage was mounted during synthetic implementation. Physical-target review, real write, independent re-read, and fresh-environment rehearsal remain mandatory before Owner Dogfood.
- Independent cryptographic and key-lifecycle review, verified Bundle copies, Restore rehearsals, Readiness Evidence, and conventional backups remain required. Iniza never authorizes erasing the old Mac.
