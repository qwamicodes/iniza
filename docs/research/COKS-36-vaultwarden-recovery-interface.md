# COKS-36 Vaultwarden Recovery Secret interface comparison

- Status: All ten public seams confirmed; synthetic and production-adapter implementation verified; real owner-service rehearsal remains required
- Date: 2026-09-06
- Issue: COKS-36

## Problem space

Owner Dogfood requires the generated Vaultwarden Recovery Secret to survive loss of the source Mac independently of the Offline Recovery Key. Iniza must use the official Bitwarden command-line executable named `bw` against the owner's external Vaultwarden service, create one exact Secure Note, synchronize, retrieve the item by its returned identifier, reconstruct the secret only in zeroizing memory, and prove that it fully authenticates the completed Bundle.

This transaction crosses several hostile or stale boundaries at once: executable resolution, local executable replacement, process environment, session transport, configured server identity, account identity, command output, remote mutation, item schema, and Bundle replacement. Creation is irreversible from Iniza's perspective because Iniza must never automatically delete a recovery item. A failure after creation therefore needs to preserve the exact item identifier and support a later rehearsal without creating a duplicate.

The official `bw` executable is not installed on the source Mac as of 2026-09-06. Synthetic implementation can proceed after the public seams are confirmed, but COKS-36 cannot complete until the production adapter and real owner-service transaction are rehearsed.

## Existing boundaries

`BundleEngine::verify(VerifyRequest) -> BundleVerification` fully authenticates a completed Bundle with a borrowed in-memory `RecoverySecret` and returns the authenticated Bundle identity. `RecoverySecret` is non-serializable, redacted in diagnostic output, and zeroizes its bytes. The Vaultwarden connector must reuse this public boundary rather than add a new Bundle parser or accept a secret through an argument, ordinary file, prompt, standard output, or receipt.

`OfflineRecoveryEngine` proves that loading and rehearsal should be separate from storage. Vaultwarden needs the same separation so a retained item can be rehearsed again by exact identifier after a network or process failure and so later Inspect, Verify, Verified Copy, and Restore commands can borrow a loaded secret without secret-bearing transport.

Architecture decision 0003 requires two independent Recovery Methods. Vaultwarden failure must not damage the Bundle or Offline Recovery Key, and Vaultwarden success must not substitute for the separately stored Offline Recovery Key.

## Official Bitwarden behavior used by the design

The [official Bitwarden command-line documentation](https://bitwarden.com/help/cli/) defines Secure Note items as item type `2`, documents `bw status` as JavaScript Object Notation, provides `bw encode` for Base64 encoding standard input, states that vault changes are pushed automatically, and describes `bw sync` as a pull from the server.

The [official Bitwarden client source](https://github.com/bitwarden/clients/blob/main/apps/cli/src/vault.program.ts) states that `bw create item` accepts encoded JavaScript Object Notation through standard input. This lets Iniza keep the recovery secret out of the process argument list.

The [official Bitwarden field-type source](https://github.com/bitwarden/clients/blob/main/libs/common/src/vault/enums/field-type.enum.ts) defines text fields as type `0` and hidden fields as type `1`. Iniza therefore encodes only `iniza_secret` as hidden and treats the other approved metadata fields as non-secret text.

The current official release is Bitwarden command-line version `2026.8.0`. The [current Homebrew formula](https://formulae.brew.sh/formula/bitwarden-cli) provides that version, installs the `bw` executable, and depends on Node. The first supported production adapter should require version `2026.8.0` or newer and fail closed when strict response schemas are incompatible. This also excludes known session regressions reported against earlier 2026 releases; it does not claim compatibility with every future Bitwarden or Vaultwarden deployment.

## Design one: raw process operations in the recovery engine

~~~rust
VaultwardenRecoveryEngine::run(
    executable_path,
    arguments,
    environment,
    standard_input,
) -> ProcessOutput
~~~

The engine constructs each `bw` argument vector, reads the session environment, encodes and decodes item documents, and interprets raw standard output and standard error directly.

### Strength

This is a small amount of initial code and mirrors the external command closely.

### Weakness

Arbitrary arguments, environment values, and secret-bearing input become available to the domain layer. Tests would need to assert internal command order rather than caller-visible recovery behavior. It would also be easy for a later caller to add login, unlock, delete, export, fuzzy search, or a session argument without changing the public capability boundary.

This design is rejected.

## Design two: typed Bitwarden capability with review-bound transactions

~~~rust
VaultwardenRecoveryEngine::inspect_installation(
    VaultwardenInstallationRequest,
) -> Result<VaultwardenInstallationReport, CoreError>

VaultwardenRecoveryEngine::preflight(
    VaultwardenPreflightRequest,
) -> Result<VaultwardenPreflightReport, CoreError>

VaultwardenRecoveryEngine::store_and_rehearse(
    VaultwardenStoreRequest,
) -> Result<VaultwardenStoreReport, CoreError>

VaultwardenRecoveryEngine::rehearse(
    VaultwardenRehearsalRequest,
) -> Result<VaultwardenRecoveryReceipt, CoreError>

VaultwardenRecoveryEngine::load(
    VaultwardenLoadRequest,
) -> Result<LoadedVaultwardenRecoverySecret, CoreError>
~~~

`BitwardenCommandLine` is a narrow external capability with only installation inspection, status, exact Secure Note creation, synchronization, and exact item retrieval. It has no login, unlock, lock, delete, edit, export, search, arbitrary argument, or arbitrary environment operation. The production `InstalledBitwarden` adapter alone knows the concrete `bw` commands and process environment.

Installation inspection is separate so the command-line caller can display and review the selected executable, canonical path, version, and executable identity before any session-bearing child process runs. Preflight requires the reviewed installation hash, obtains status through the already unlocked external session, locally authenticates the completed Bundle, constructs the exact proposed Secure Note metadata, and returns a second canonical review hash binding the executable, version, server identity, account identity, Bundle identity, item name, and optional location hint.

Store requires both exact hashes, redoes installation and status checks, reauthenticates the Bundle, and rejects any changed binding before remote creation. It then creates one item, records its exact returned identifier in memory, synchronizes, retrieves that exact identifier, validates the complete Iniza field schema, reconstructs the Vaultwarden Recovery Secret in zeroizing memory, and fully verifies the Bundle.

If creation succeeds but synchronization, retrieval, parsing, or Bundle authentication fails, the returned report is `ItemCreatedButUnverified`, contains the exact non-secret item identifier and safe retry guidance, and never deletes the item. Only a complete rehearsal creates a `VaultwardenRecoveryReceipt`.

### Strength

The public boundary makes the allowed remote effects, review binding, partial outcome, and future recovery handle explicit. Login, master-password handling, fuzzy search, deletion, and arbitrary commands are structurally unavailable. Behavior tests can use a typed fake while separate executable fixtures prove the exact production process contract.

### Weakness

This creates two review hashes and five small public operations. It also requires careful result types for an item that was created but not yet verified.

## Design three: long-lived authenticated session object

~~~rust
let session = VaultwardenSession::open();
session.create(...);
session.sync();
session.retrieve(...);
session.lock();
~~~

The connector stores a session token inside a reusable object and closes or locks the session when the object is dropped.

### Strength

Repeated calls are convenient and the process environment can be prepared once.

### Weakness

The token lifetime becomes larger than the minimum transaction. Drop-triggered locking can unexpectedly lock a session created and owned by the user. A reusable session also invites unrelated Bitwarden operations and makes cross-process review binding unclear.

This design is rejected. Iniza does not create, unlock, own, or lock a Bitwarden session in COKS-36. The owner authenticates with the official client outside Iniza.

## Recommended public seams

Use design two with a generic engine matching existing Iniza adapter patterns:

~~~rust
pub struct VaultwardenRecoveryEngine<C = InstalledBitwarden> {
    command_line: C,
}

pub trait BitwardenCommandLine: Send + Sync {
    fn inspect_installation(...) -> ...;
    fn status(...) -> ...;
    fn create_recovery_note(...) -> ...;
    fn synchronize(...) -> ...;
    fn get_recovery_note(...) -> ...;
}
~~~

The trait arguments are validated private-field value types rather than raw strings. `VaultwardenItemIdentifier` accepts only the exact identifier form returned by a successful create response. `VaultwardenServerIdentity` and `BitwardenExecutableIdentity` bind exact observed values while public reports reveal only the reviewed canonical executable path, version, sanitized server origin, and domain-separated hashes.

`LoadedVaultwardenRecoverySecret` is non-cloneable, redacts diagnostic output, owns a zeroizing `RecoverySecret`, and exposes only Bundle identity, Recovery Method identity, server identity hash, item identifier, and a borrowed recovery secret.

## Trusted executable policy

The production adapter follows this policy:

1. Prefer an owner-configured absolute path. Otherwise inspect only `bw` candidates found in trusted absolute path entries for `/opt/homebrew/bin` and `/usr/local/bin`.
2. Canonicalize symbolic links once and require the final target to be a regular executable file.
3. Require the target and every checked ancestor to be owned by the current user or the system administrator account and to have no group-writable or other-writable mode bit.
4. Record device, inode, size, modification time, and a BLAKE3 executable digest.
5. If the final target is a script, require a single absolute shebang interpreter rather than `/usr/bin/env`, a relative interpreter, or interpreter options. Apply the same ownership, mode, identity, and digest checks to that interpreter. A native executable has no interpreter dependency.
6. Parse a small bounded version response and require version `2026.8.0` or newer.
7. Reopen and revalidate the same executable and interpreter identities and digests immediately before every process invocation.
8. Execute the canonical absolute path directly without a shell or inherited command search path.

The executable path, version, executable digest prefix, and any interpreter path and digest prefix appear in the installation review. Every full digest participates in both review hashes. This detects replacement during the transaction but does not prove vendor provenance. The owner must install the official Bitwarden command-line package through a separately trusted channel; the remaining provenance risk belongs in the architecture decision and Owner Dogfood evidence.

## Session and process policy

Iniza never invokes login or unlock and never reads a password. The production adapter reads an existing `BW_SESSION` once at the beginning of the credentialed transaction into a zeroizing value restricted to the Base64 character set, supplies it only as the `BW_SESSION` environment variable of the minimum required `bw` child process, and drops it after the transaction. It never uses `--session`, standard input, ordinary files, diagnostics, events, reports, or receipts for the session.

Every child clears the inherited environment. It restores only the verified user home needed for the official client's configuration, the zeroizing session for credentialed operations, and any narrowly documented non-secret runtime values proven necessary by the real owner rehearsal. Debug variables, proxies, dynamic-loader variables, alternate executables, and inherited command search paths are excluded by default.

Every operation uses `--nointeraction`. Standard output and standard error are drained concurrently, bounded to one mebibyte each, and zeroized after parsing. Raw external output never enters a caller-visible error. Secret-bearing Secure Note JavaScript Object Notation is written to `bw encode` through standard input, its Base64 result remains zeroizing memory, and that result is written to `bw create item` through standard input. No secret appears in an argument.

Because COKS-36 never creates or owns a session, it never calls `bw lock`. Any future Iniza-owned session flow requires a separate decision and tests proving exact ownership.

## Exact Secure Note schema

The proposed item is exactly:

~~~text
Type: Secure Note
Secure Note subtype: generic
Name: Iniza Recovery — <owner-approved friendly Bundle name> — <Coordinated Universal Time date>
Fields:
  iniza_bundle_id      text, authenticated Bundle identity
  iniza_format         text, authenticated format and suite descriptor
  iniza_secret         hidden, lowercase hexadecimal Vaultwarden Recovery Secret
  iniza_created_at     text, canonical Coordinated Universal Time timestamp
  iniza_location_hint  text, optional owner-approved non-secret value
~~~

The friendly name is explicit input rather than a Bundle path or protected source name. It must be non-empty, bounded, single-line text. The optional location hint is absent by default and stored only when explicitly supplied. Bundle identity and format are derived from full local Bundle authentication, not trusted from caller text.

Retrieval requires the exact returned item identifier and rejects a wrong type, name, Bundle identity, format, creation time, field name, duplicate field, missing field, extra Iniza field, wrong field type, malformed identifier, malformed timestamp, or secret that does not authenticate the Bundle. Item names are never searched.

## Result and receipt behavior

`VaultwardenStoreReport` has two caller-visible states:

- `Verified`: exact item retrieval succeeded and its secret authenticated the completed Bundle; a Receipt is available.
- `ItemCreatedButUnverified`: creation returned an exact identifier but a later step failed; the item is retained, the Offline Recovery Key remains usable, and retry guidance points to exact-identifier rehearsal.

Pre-creation failures return a safe error and create no report claiming an item exists. The successful Receipt contains only Bundle identity, Recovery Method identity, exact item identifier, server identity hash, and verification time. It contains no executable path, server address, account identifier, item name, location hint, Bundle path, secret, session, raw command output, or protected content.

Human and machine-readable results must remain secret-free under hostile server addresses, names, fields, process output, and environment values. A successful Vaultwarden Receipt never implies that the Offline Recovery Key, Verified Copies, Restore Rehearsals, or other Owner Dogfood gates passed.

## Human-review evidence outside the connector

The connector can hash the configured server identity and prove a transaction against it, but it cannot prove from software alone that the service is physically external to the source Mac or that independent multi-factor recovery works. COKS-36 completion therefore still requires the owner to:

1. identify the reviewed external Vaultwarden service;
2. sign in from a fresh device or equivalent isolated environment;
3. exercise the independent multi-factor recovery path without Iniza receiving credentials;
4. retrieve the exact created item and authenticate the Bundle; and
5. review the resulting Receipt and retained-item state.

That evidence is an Owner Attestation and rehearsal record, not a boolean command option. COKS-39 later binds the Receipt and attestation into Readiness Evidence.

## Test seams and tracer-bullet order

Tests use a typed `BitwardenCommandLine` fake for remote state and failures, a real executable fixture for argument, environment, standard-input, prompt, output-bound, and replacement behavior, and disposable completed Bundles for cryptographic verification.

The first tracer bullet will:

1. pack a disposable synthetic Bundle with both Recovery Methods;
2. inspect and approve a synthetic installation and unlocked self-hosted preflight;
3. create one typed fake Secure Note;
4. synchronize and retrieve the exact returned identifier;
5. reconstruct the hidden secret in zeroizing memory;
6. fully verify the completed Bundle; and
7. assert that every human, machine, diagnostic, and Receipt representation excludes the secret, session, paths, account identity, and raw external output.

Later red-to-green slices add missing and unsupported executable guidance, untrusted or replaced executables, locked and unauthenticated status, missing sessions, stale installation or preflight hashes, strict hostile JavaScript Object Notation, wrong and duplicate fields, wrong item identifiers, retained unverified items, network and subprocess failures, output limits, exact production arguments and environment, and independent load and rehearsal.

## Owner confirmation requested

Before any COKS-36 behavior test or implementation, confirm or revise:

1. the separate installation inspection, preflight, store-and-rehearse, rehearse, and load operations;
2. the typed `BitwardenCommandLine` capability rather than raw arbitrary process operations;
3. two exact review hashes: one before session-bearing work and one before remote item creation;
4. a retained `ItemCreatedButUnverified` result with exact item identifier after any post-create failure;
5. no login, unlock, lock, search, edit, delete, export, or arbitrary command capability;
6. `BW_SESSION` environment-only transport, one transaction lifetime, and a cleared child environment;
7. official Bitwarden version `2026.8.0` as the initial minimum supported version;
8. the exact Secure Note field schema and hidden hexadecimal secret;
9. a non-cloneable loaded-secret handle for later Inspect, Verify, Verified Copy, and Restore commands; and
10. separate owner attestation for external hosting, fresh-device sign-in, and independent multi-factor recovery.

The owner confirmed all ten seams on 2026-09-06. Any later change to these public interfaces or security boundaries requires renewed confirmation before behavior tests depend on it.
