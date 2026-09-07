# Adopt reviewed Vaultwarden recovery through the official Bitwarden command-line client

- Status: Accepted for synthetic and duplicated data; real owner-service rehearsal and Owner Attestation remain required
- Date: 2026-09-07
- Issue: COKS-36

## Context

Every IZ2 Bundle has independently derived Vaultwarden and Offline Recovery slots. The Vaultwarden Recovery Secret must survive loss of the source Mac without placing the Bundle, the owner's Vaultwarden master password, or the independent Offline Recovery Key in the service.

Implementing the Vaultwarden network protocol inside Iniza would create a second authentication client and expand the credential-handling boundary. The owner already trusts the official Bitwarden command-line client named `bw` to communicate with the self-hosted service. Iniza therefore needs a narrow process adapter that proves exactly which executable, account, server, item, and Bundle participated without accepting arbitrary Bitwarden operations.

## Decision

Iniza uses the official Bitwarden command-line client only through the typed `BitwardenCommandLine` capability. The capability can inspect an installation, read vault status, create one recovery Secure Note, synchronize, and retrieve one exact item identifier. It has no login, unlock, lock, search, list, edit, delete, export, or arbitrary-command operation.

The public transaction is separated into installation inspection, preflight, store-and-rehearse, later rehearsal, and loaded-secret acquisition. Installation inspection produces the first review hash before credentialed work. Preflight authenticates the completed Bundle, observes the unlocked account and external server, and produces a second review hash before remote creation. Both hashes must match exactly at the corresponding transition.

`LoadedVaultwardenRecoverySecret` is non-cloneable, redacts diagnostic output, owns a zeroizing Recovery Secret, and exposes only non-secret identities plus a borrowed secret for Inspect, Verify, Verified Copy, or Restore.

## Executable trust

Trusted-path discovery checks only `/opt/homebrew/bin/bw` and `/usr/local/bin/bw`; an explicit absolute path is also supported. The selected path is canonicalized once and must resolve to a regular executable owned by the current user or the system administrator account. The executable and every checked ancestor reject group-writable or other-writable permissions.

Native executables are hashed directly. Scripts must use one absolute shebang interpreter without an environment lookup, relative path, whitespace, or options. The interpreter receives the same ownership, permission, and BLAKE3 identity checks. Iniza launches a script by invoking that canonical reviewed interpreter with the canonical script path, so the operating system does not resolve the original shebang alias again. The executable and interpreter identities are revalidated immediately before every child process.

The initial compatibility floor is official Bitwarden command-line version `2026.8.0`. Missing software reports `brew install bitwarden-cli`; an older version reports `brew upgrade bitwarden-cli`. Iniza never falls back to an alternate Vaultwarden protocol. Displayed paths, versions, and review hashes support owner review but do not prove vendor provenance; installation through a separately trusted channel remains an owner responsibility.

## Session and process boundary

The owner logs in and unlocks with the official client outside Iniza. Iniza never prompts for or reads the Vaultwarden master password. It accepts an existing `BW_SESSION` value only as bounded Base64 text, retains its owned representation in zeroizing memory for the minimum operation, and supplies it only through the child environment. The session never appears in an argument, standard input, ordinary file, report, Receipt, diagnostic, or event.

Every child process executes the reviewed canonical path directly with no shell or command search. The environment is cleared, then restored only with the verified user home and, for credentialed commands, `BW_SESSION`. Every operation is non-interactive. Standard output and standard error are drained concurrently, bounded to one mebibyte each, held in zeroizing buffers, and never copied into caller-visible errors.

Because Iniza does not create or own a Bitwarden session, it never invokes `bw lock`. A future session-creation flow requires a new architecture decision and behavior tests proving exact ownership.

## Secure Note and retrieval contract

Iniza sends secret-bearing JavaScript Object Notation to `bw encode` through standard input. The resulting Base64 text is then sent to `bw create item` through standard input. The created object is one generic Secure Note with this exact application field schema:

1. `iniza_bundle_id`: text containing the authenticated Bundle identity;
2. `iniza_format`: text containing `IZ2/IZ1`;
3. `iniza_secret`: hidden lowercase hexadecimal Vaultwarden Recovery Secret;
4. `iniza_created_at`: text containing the canonical Coordinated Universal Time creation time; and
5. `iniza_location_hint`: optional text supplied and approved by the owner.

The item name is `Iniza Recovery — <friendly Bundle name> — <Coordinated Universal Time date>`. It contains no source path or protected content. The service stores the recovery secret and limited metadata, never the Bundle.

After creation, Iniza records the returned identifier, pulls current vault state with `bw sync`, and retrieves only with `bw get item <exact identifier>`. It never searches by name. Strict bounded parsers reject malformed identifiers, duplicate required response properties, unsupported item or Secure Note types, missing fields, extra fields, duplicate fields, wrong field types, malformed identities or timestamps, and a secret that does not authenticate the completed Bundle.

## Failure containment and evidence

A failure before successful creation returns an error and claims no remote item. Any failure after creation returns `ItemCreatedButUnverified` with the exact non-secret item identifier, no successful Receipt, and guidance to retry exact-identifier rehearsal. The item is retained; Iniza never automatically deletes it. Vaultwarden failure never changes or deletes the Bundle or Offline Recovery Key.

Only exact retrieval followed by complete Bundle authentication creates a `VaultwardenRecoveryReceipt`. The Receipt contains Bundle identity, Recovery Method identity, item identifier, server identity hash, and verification time. It excludes the secret, session, executable path, server address, account identifier, item name, location hint, Bundle path, and protected content.

The connector hashes the configured Hypertext Transfer Protocol Secure server origin and account identifier with separate domains. It cannot prove physical hosting location, possession of an independent multi-factor recovery method, or a fresh-device sign-in. COKS-36 therefore also requires an explicit Owner Attestation after the owner independently confirms the external service, fresh-device access, and the independent multi-factor recovery path. COKS-39 later binds that attestation and the machine-verifiable Receipt into Readiness Evidence.

## Compatibility scope and remaining risks

- Owner Dogfood proves one transaction against the owner's reviewed Vaultwarden service and official Bitwarden command-line version. It does not promise compatibility with every Bitwarden-compatible deployment or future client response.
- Transport Layer Security, configured certificate authorities, account authentication, and server communication remain delegated to the official client. A compromised client configuration or trusted executable can compromise this boundary.
- Review hashes detect replacement between reviewed stages but cannot eliminate every operating-system time-of-check to time-of-use race.
- The session necessarily exists in the parent environment and child-process environment during an operation even though Iniza does not persist or display it.
- Successful Vaultwarden recovery does not prove Offline Recovery Key separation, Verified Copies, Restore rehearsals, conventional backups, repository publication, or readiness to erase the old Mac.
