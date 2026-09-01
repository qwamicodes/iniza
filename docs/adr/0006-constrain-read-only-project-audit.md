# Constrain the read-only Project audit and Git subprocess boundary

- Status: Accepted
- Date: 2026-09-01
- Issue: COKS-28

## Context

Required Projects can contain recoverable state that a Git remote does not represent: staged, unstaged, untracked, ignored, stashed, detached, submodule, Git Large File Storage, and local-only reference state. Repository names, configuration, remote addresses, subprocess output, and the repository itself may also be hostile or change during inspection. The owner needs local recoverability risk even when network access is unavailable or a remote check fails.

ADR 0002 already separates Project protection from publication. This decision defines the narrower audit boundary that feeds later Project Capsule and immutable Push Plan work.

## Decision

`ProjectAuditEngine::audit(ProjectAuditRequest) -> ProjectAuditReport` is the core public seam. A request accepts only an approved, non-stale directory Plan. Discovery stays beneath its approved roots, skips known generated trees, and identifies working trees, bare repositories, nested repositories, and submodules. Each Project identifier is derived from the matching reviewed Migration Item identifier, and its must-protect or optional requirement is inherited from that item.

The default request is local-only and makes no intentional network request. `with_remote_check` is the sole audit capability that permits remote contact. It executes only `git ls-remote --heads --tags -- <remote-name>` and never fetches, pushes, checks out, commits, merges, rebases, resets, or stashes. Audit cannot reconcile remote differences or approve publication.

`GitProcess` is the dependency boundary. `InstalledGit` executes direct argument vectors against the installed Git executable with no shell, a cleared and allowlisted environment, prompts and credential helpers disabled, hooks disabled, optional locks and filesystem monitoring disabled, and terminal coloring disabled. Protocols default to denied; only Hypertext Transfer Protocol Secure and Secure Shell are enabled for explicit remote checks. File, external-helper, unauthenticated Git, and unknown transports are denied. Standard output and standard error are drained concurrently, retain at most one mebibyte per stream, and cause a safe failure when oversized. Raw subprocess errors are not copied into the report.

The report distinguishes Restorable gaps from Synchronized gaps. Local evidence survives a skipped or failed remote check. Status and references are observed before and after the audit; a mismatch marks the local result Changed and Unverified. Generated ignored content is a suggested exclusion. Other ignored content, including likely secrets, certificates, uploads, databases, local configuration, and unknown files, Requires Review.

Human output may identify local paths to support owner review, but terminal control characters are replaced. Machine output is a one-line, versioned JavaScript Object Notation object using stable identifiers. Source roots, relative paths, filenames, protected content, raw Git output, remote credentials, sensitive query values, fragments, and local remote paths are structurally absent or redacted.

## Evidence

- Disposable real repositories cover working trees, bare repositories, nesting, submodules, detached heads, local-only branches and tags, stashes, staged, unstaged, untracked, ignored, Git Large File Storage, generated-tree skipping, and changing repositories.
- Scripted boundary adapters cover explicit remote success, remote failure with hostile error text, and proof that the default path never attempts a remote command.
- Executable fixtures prove direct arguments, controlled environment, bounded command output, and rejection of external Git transport helpers.
- Rendering fixtures prove remote credential and local-path redaction, terminal-control neutralization, machine path and content omission, and separate Restorable and Synchronized gaps.

## Consequences

- A successful audit does not make a Project Restorable; Project Capsule creation and Restore Rehearsal remain later issues.
- A reachable remote does not prove synchronization and is not a Receipt. Publication remains a separate immutable Push Plan with its own approval and side-effect warning.
- Local file remotes cannot be contacted by the production audit adapter. Disposable test fixtures may use a scripted adapter to supply remote evidence without weakening the production protocol policy.
- Command-duration limits, cancellation, the final Git version floor, immutable publication execution, and Project Capsule representation remain decisions for their affected later issues.

## Owner decision

- [x] I approve the Project audit seams and constrained Git subprocess policy.
- Owner: Kwaame Ofori-adjekum
- Decision date: 2026-09-01
- Notes: Approved in the COKS-28 implementation thread. This audit is evidence collection only and does not authorize publication, deletion, or use of real sole-copy data.
