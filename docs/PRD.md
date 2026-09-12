# Iniza Product Requirements Document

**Status:** Revised working specification
**Product phase:** CLI dogfood
**Primary platforms:** macOS and Linux
**Future platforms:** Windows and desktop applications

## 1. Product summary

Iniza helps a person preserve the irreplaceable parts of a working computer setup before formatting, replacing, or moving between machines. It discovers selected configuration and project state, produces a reviewable plan, encrypts the selected data into a portable `.iniza` bundle, verifies recovery, and restores into a safe destination.

Iniza is not a disk image, continuous-backup service, cloud-storage provider, or wiping tool. It protects curated working state while telling the user exactly what remains outside its coverage.

The first supported interface is a Rust CLI. A later desktop application will orchestrate the same core and file format rather than reimplement migration logic.

## 2. Problem

Developers, designers, engineers, and other technical users accumulate state that does not move cleanly through ordinary file copying:

- SSH keys and configuration
- Git and shell configuration
- Local project history and uncommitted work
- Untracked or ignored project files
- Application settings and custom paths
- Credentials that require careful encrypted handling
- Metadata needed to restore files safely on another system

Git hosting is not a complete backup. It omits uncommitted changes, untracked files, ignored files, local-only branches, inaccessible remotes, and other local repository state. Similarly, copying a home directory without a plan can include caches, omit hidden state, lose permissions, or restore dangerous paths.

The central product question is:

> Can the user prove what was protected, restore it, and understand what was not protected before making an irreversible machine decision?

## 3. Target users and scenarios

### 3.1 Initial user

The first user is the project owner preparing to clean-install their Apple Silicon Mac. They have projects, SSH credentials, Git configuration, shell settings, and a self-hosted Vaultwarden service. They are willing to use a CLI and validate the product progressively with synthetic or duplicated data and independent backups.

### 3.2 Owner Dogfood scope

The initial Plan starts from a curated inventory rather than a broad home-directory scan. It covers SSH configuration, Git configuration, Bash and Zsh configuration, explicitly selected project roots, and named high-value files or directories. Additional application settings are opt-in only after the owner identifies them. Unsupported system and application state remains visible in the **Not Protected** report and must be covered by the independent conventional backups when it matters to the clean install.

The owner marks the important developer state needed after the clean install as Must-Protect Items. Owner Dogfood cannot pass while any Must-Protect Item is excluded, unavailable, unsupported, changed, or unverified. Optional items may complete with explicit warnings.

Supported developer and application settings are presented as Protection Candidates. Settings commonly synchronized by an application account, such as VS Code user settings, remain unselected by default but can be included after review. Iniza does not treat an application's claim of account synchronization as verified protection; an unselected candidate remains visible in Plan coverage.

### 3.3 Primary scenarios

1. Reinstall the same operating system on the same machine.
2. Replace a Mac and restore onto another Mac.
3. Move portable files and projects between macOS and Linux.
4. Preserve selected state as an encrypted, independently stored archive.
5. Audit projects and optionally synchronize eligible repositories with their configured Git remotes.

### 3.4 Future scenarios

- Windows source and destination support
- Native desktop experience
- Additional password managers and storage connectors
- Declarative community recipe packs
- Team policy and managed migrations

### 3.5 Owner Dogfood user stories

- **US-01:** As the owner, I can select important developer state and review every included, excluded, unsupported, unavailable, changed, or unverified item.
- **US-02:** As the owner, I can preserve and restore all reviewed local state for every required Project.
- **US-03:** As the owner, I can prove required upstream branches are current and publish approved ahead commits without Iniza changing branch history or reconciling remote changes.
- **US-04:** As the owner, I can create an authenticated encrypted Bundle on storage I control without partial output being mistaken for completion.
- **US-05:** As the owner, I can independently unlock the completed Bundle through Vaultwarden and an Offline Recovery Key.
- **US-06:** As the owner, I can inspect and fully verify a Bundle without extracting its content.
- **US-07:** As the owner, I can restore into a safe new destination and validate the result without overwriting or executing restored content.
- **US-08:** As the owner, I can choose whether to protect discovered application settings even when the application claims to synchronize them through an account.
- **US-09:** As the owner, I can create and authenticate independently stored Bundle copies.
- **US-10:** As the owner, I can see blocking readiness gaps and record human-only evidence without Iniza making an erase-safety decision.
- **US-11:** As the owner, I can interrupt and safely resume or restart long-running Bundle and Restore operations.
- **US-12:** As an automation caller, I receive deterministic JSON, events, and exit codes without prompts or secrets.

## 4. Goals

### 4.1 MVP goals

- Provide a supported, scriptable and interactive CLI.
- Scan explicit roots and optional deep-scan locations.
- Generate a human-readable plan before reading sensitive content.
- Protect explicit paths, SSH, Git configuration, shell configuration, and projects.
- Detect project state that remote Git hosting does not protect.
- Offer Git pushes only after explicit, reviewable approval.
- Create an encrypted, resumable and verifiable `.iniza` bundle.
- Store a bundle-unlocking secret in Bitwarden through the official `bw` CLI.
- Produce an independent offline recovery key.
- Inspect and verify a bundle without restoring it.
- Restore into a new destination by default without overwriting existing files.
- Produce a clear **Not Protected** report.
- Support macOS and Linux path and metadata differences safely.

### 4.2 Quality goals

- No silent data loss.
- No silent overwrite or Git publication.
- No plaintext secrets in logs, command arguments, plan files, or diagnostics.
- Useful interruption recovery for long bundle operations.
- Deterministic machine-readable output for automation.
- Accessible terminal interaction without relying on color.

## 5. Non-goals for the first release

- Formatting, wiping, resetting, or deleting the source machine
- Claiming that a machine is safe to erase
- Continuous or scheduled backup
- Disk imaging or full home-directory cloning
- Hosting user bundles on Iniza infrastructure
- Direct GitHub, GitLab, or Bitbucket API integrations
- Silent Git pushes, commits, branch publication, or tag publication
- Capturing live databases or Docker volumes
- Migrating browser profiles, email archives, or full system Keychains
- Arbitrary executable recipe scripts
- Windows support
- Native desktop UI
- Licensing, checkout, subscriptions, or team administration
- Telemetry

## 6. Product model

### 6.1 Plan

`iniza.toml` is a human-readable migration plan. It contains selected roots, recipes, exclusions, destination preferences, and Git-push policy. It never contains bundle keys, recovery keys, Bitwarden sessions, master passwords, or file contents.

### 6.2 Bundle

A `.iniza` bundle is a versioned encrypted container holding selected file content, a protected manifest, file hashes and metadata, project capsules, restore mappings and validation rules, recovery key slots, and completion records.

The user chooses bundle storage: local disk, external media, NAS, or a cloud-synchronized filesystem.

### 6.3 Recovery methods

The initial product supports two independent recovery methods:

1. A generated bundle-unlocking secret stored as a dedicated Secure Note in the owner's Vaultwarden service through the official Bitwarden `bw` CLI.
2. An offline recovery key saved separately by the user.

Vaultwarden stores the unlocking secret and limited metadata, not the `.iniza` bundle or migrated content.

The Vaultwarden Recovery Secret and Offline Recovery Key are independent wrappers for the same Bundle key. The owner unlocks Vaultwarden with their normal account credentials after the clean install; Iniza never knows the master password. If Vaultwarden or its account recovery is unavailable, the separately stored Offline Recovery Key must still unlock the Bundle.

### 6.4 Owner storage topology

Owner Dogfood uses two independently verified Bundle copies: one on external storage and one in iCloud Drive. The Offline Recovery Key is written to separately stored removable media and is not kept with either Bundle copy. Time Machine remains a conventional backup and does not count as a verified Bundle copy.

### 6.5 Project capsule

A project capsule preserves information that a remote alone cannot guarantee:

- Git refs and repository history required for restoration
- Staged and unstaged state
- Untracked files
- Stashes
- Remote and repository metadata
- Reviewed ignored files
- Submodule and Git LFS information
- A pre- and post-capture consistency record

The technical implementation may use a Git bundle plus a filesystem overlay, provided the outcome satisfies the acceptance criteria.

## 7. Primary workflow

1. User runs `iniza` or `iniza scan`.
2. Iniza asks why the user is protecting the machine and adjusts guidance without changing safety rules.
3. User selects explicit paths and project roots; optional deep scan accepts exclusions.
4. Iniza discovers supported items and unsupported-risk indicators.
5. Iniza writes and displays a plan with included, excluded, and unsupported content.
6. Iniza audits Git repositories and separates remote synchronization from local protection.
7. User reviews any proposed Git pushes and approves each or approves a reviewed set.
8. Iniza creates the encrypted bundle and an offline recovery key.
9. Iniza creates and re-reads the Bitwarden item, then proves that its secret unlocks the completed bundle.
10. Iniza verifies the bundle and can restore it into a temporary destination.
11. User creates at least one additional verified copy on independent storage.
12. Iniza presents a readiness receipt and the **Not Protected** report.

Iniza may state **Bundle verified and recovery tested**. It must never state **Safe to erase your machine**.

## 8. Functional requirements

### 8.1 Scan and planning

- Default scanning is limited to paths supplied by the user and supported recipe locations.
- Deep scan is optional and supports directory exclusions.
- Scanning separates metadata discovery from sensitive content reads.
- Every item receives a disposition: included, excluded, unsupported, unavailable, or requires review.
- Every item is classified as must-protect or optional for readiness purposes; must-protect gaps are blocking.
- The plan estimates logical size and required temporary/output capacity.
- The plan warns about unreadable files, special devices, sockets, mount boundaries, and unsafe paths.

### 8.2 Explicit files and configuration

- MVP recipes cover SSH, Git configuration, and common shell configuration.
- Users may add explicit files and directories.
- Known regenerable caches and build outputs are suggested for exclusion.
- The user can override suggestions after review.
- Symlinks are recorded without following them outside approved roots.

### 8.3 Project safety audit

For each discovered repository, Iniza reports repository root and remotes, current branch and upstream, ahead/behind status when available, staged and unstaged changes, untracked and ignored files, local-only branches and tags, stashes, submodules, Git LFS usage, protected size, and remote failures.

Ignored content is classified rather than omitted wholesale. Known generated content can be excluded automatically; likely secrets, databases, uploads, certificates, and local configuration require review.

Reviewed static secrets and configuration, certificates, and irreplaceable uploads may be included in the encrypted Bundle. A live database is not verified by copying its live files: a consistent export must be selected and validated, or the database remains a blocking Must-Protect gap.

### 8.4 Git synchronization

- Git synchronization is optional and independent of bundle creation.
- Iniza uses the installed Git client and configured remotes.
- Only branches with existing upstreams are proposed by default.
- Creating remote branches or publishing tags requires separate explicit approval.
- Iniza shows exact repository and ref changes before execution.
- A push failure does not prevent local project protection.
- Iniza records results without capturing Git credentials.
- Selected Projects track two independent outcomes: Restorable and Synchronized.
- A Project is Restorable only after its reviewed local state round-trips through a verified Project Capsule.
- A Project is Synchronized when a reviewed live remote is authoritative for tracked state and there are no unpublished local commits, or when current verified Project Capsule protection is paired with an exact owner decision to retain the Project without publication.
- A behind local checkout is informational and does not require reconciliation. Iniza never fetches into, pulls, merges, rebases, or otherwise updates it.
- Ahead or diverged state remains Action Required and any publication requires a separate approved Push Plan.
- Local-only branches and tags, dirty state, and Projects without a usable remote remain protected in a full Project Capsule unless the owner separately approves publication.

### 8.5 Bundle creation

- Output is encrypted before leaving the process boundary.
- Partial output is never reported as complete.
- Interrupted creation can resume when the authenticated checkpoint permits it.
- Source files that change during capture are retried or marked unverified.
- Completion requires an authenticated manifest, chunk index, and footer.
- Insufficient-space detection occurs before and during writing.

### 8.6 Vaultwarden connector

- MVP uses the official Bitwarden `bw` CLI against the owner's self-hosted Vaultwarden service.
- Existing server configuration is respected, including self-hosted endpoints.
- Iniza never asks for or stores the Bitwarden master password.
- A temporary unlocked session may be used only in memory and for minimum required commands.
- One Secure Note is created per bundle with a friendly name, bundle ID, created time, hidden unlocking secret, and optional non-secret location hint.
- Completion requires create, sync, retrieve, and bundle-unlock verification.
- Iniza never automatically deletes a Bitwarden recovery item.
- Owner Dogfood requires create, sync, retrieve, and unlock verification against the owner's actual Vaultwarden service. Compatibility with other Bitwarden-compatible deployments is not implied by that result.

### 8.7 Inspection and verification

- `inspect` shows safe metadata and coverage without extracting content.
- `verify` authenticates structure and selected chunks.
- Verification supports both recovery methods.
- A verified-copy operation compares authenticated identity and byte hash.
- Receipts contain no secrets.

### 8.8 Restore

- Default restore destination is an empty or new directory.
- Existing paths are never overwritten in MVP.
- Logical path tokens such as `$HOME` map to the destination platform.
- Unsupported metadata is preserved in the manifest and reported.
- Symlink and traversal checks constrain writes to the restore root.
- Repository hooks and executable content are restored disabled or quarantined until reviewed.
- Restoration is journaled and resumable.
- Validation checks hashes, portable permissions, Git integrity, and recipe rules.

### 8.9 Readiness receipt

Readiness Evidence combines machine-verifiable Receipts with explicit, timestamped Owner Attestations for facts Iniza cannot prove itself. It reports bundle verification, both recovery methods, restore rehearsals, verified copies, Git synchronization, changed source files, coverage dispositions, conventional-backup confirmation, representative project validation, and acknowledgement of the **Not Protected** report. It never grants permission to erase a machine.

Any unresolved Must-Protect Item or required Project that is not both Restorable and Synchronized blocks Owner Dogfood readiness. A deliberate decision to keep a local-only ref unpublished does not block synchronization when that ref remains verified in the Project Capsule and the decision is recorded.

## 9. CLI experience requirements

- Running `iniza` starts a guided workflow.
- Subcommands support non-interactive and JSON operation.
- Mutating commands support `--dry-run` where meaningful.
- Prompts state target, effect, and safe alternative.
- Color enhances but never carries meaning.
- Secret input is hidden and never echoed.
- `--yes` cannot bypass first-time approval for external Git publication.
- Stable exit codes distinguish validation, authentication, storage, source-change, and partial-success outcomes.

The normative command contract is defined in `CLI_SPEC.md`.

## 10. Platform requirements

### 10.1 macOS

- The first Owner Dogfood artifact targets the owner's current Apple Silicon Mac running macOS 26.5.1.
- Intel macOS compatibility is a private-alpha milestone and does not block Owner Dogfood.
- Exact minimum macOS version is determined by the technical spike.
- POSIX permissions, symlinks, extended attributes, and ACL metadata are preserved where possible.

### 10.2 Linux

- Initial testing targets a current Ubuntu LTS distribution.
- Linux compatibility remains an MVP product requirement but does not block the owner's first clean-install use.
- Distribution-independent Rust binaries are preferred where practical.
- XDG configuration paths are used.

### 10.3 Cross-platform restoration

- Only portable content and recipes are automatically mapped.
- Platform-specific content can be extracted for review but is not applied automatically.
- The manifest retains source platform, architecture, path, and metadata.

## 11. Security and privacy requirements

- Use established cryptographic libraries and versioned primitives.
- Keep cryptographic policy in the Rust core.
- Authenticate structure before trusting paths or sizes.
- Zeroize secret buffers where supported.
- Never place secrets in logs, process arguments, configuration files, shell history suggestions, or crash reports.
- Diagnostics are local and redacted.
- No telemetry in MVP.
- No hosted Iniza account or bundle service is required.
- Dependencies are pinned, audited, and included in an SBOM before public beta.

See `THREAT_MODEL.md` for the complete threat register.

## 12. Dogfood acceptance gate

The owner must not format a machine based solely on an alpha Iniza bundle. Completion requires:

1. Synthetic and duplicated fixtures pass round-trip tests.
2. The real migration plan has been reviewed.
3. A complete Time Machine backup and a separately stored direct copy of the owner's most important files exist, and representative restores from both have succeeded.
4. The `.iniza` bundle verifies completely.
5. Vaultwarden recovery unlocks the completed bundle.
6. Offline recovery unlocks the completed bundle.
7. Restoration succeeds in an isolated directory or external volume without modifying the source state.
8. A second rehearsal succeeds under a fresh macOS user account or on another Mac where available.
9. Representative restored projects open and build.
10. The external-storage and iCloud Drive Bundle copies both verify independently.
11. The owner reviews and accepts the **Not Protected** report.

## 13. Success measures

### Dogfood

- Zero unexplained missing selected files.
- Zero silent overwrites or publications.
- 100% authentication of completed chunks.
- Successful restore with both recovery methods.
- Accurate project-state reporting for the owner’s repositories.

### Private alpha

- 25 successful synthetic or duplicated migrations.
- Tested interruption at scan, pack, copy, and restore stages.
- Tested macOS-to-macOS and portable macOS/Linux restores.
- No known critical security or data-loss issue.

### Public beta gate

- 100 successful end-to-end migrations.
- Independent review of cryptography and key handling underway or complete.
- Signed release artifacts and documented update path.
- Compatibility and unsupported-state documentation published.

## 14. Roadmap

### Phase 0: Core proof

- Rust workspace and CLI skeleton
- Explicit paths
- Versioned encrypted bundle
- Inspect, verify, and restore to a new directory
- Synthetic fixtures and fault tests

### Phase 1: Owner dogfood

- SSH, Git, and shell recipes
- Project scan and capsules
- Reviewed Git pushes
- Bitwarden connector and offline recovery
- Verified copies and readiness receipt

### Phase 2: Private alpha

- Hardened cross-platform behavior
- More configuration recipes
- Signed macOS and Linux binaries
- External security review preparation

### Phase 3: Desktop

- Native macOS interface consuming the Rust core
- Equivalent plans, bundles, receipts, and restore semantics
- Additional connectors only after Bitwarden is proven

### Later

- Windows, more Linux distributions, community recipes, teams, licensing, and commercial packaging

## 15. Settled decisions

- Working name: Iniza
- CLI and core first
- macOS and Linux first
- `.iniza` bundle extension
- User-controlled bundle storage
- Vaultwarden via the official Bitwarden `bw` CLI as the owner-dogfood connector
- Independent offline recovery key
- Offline recovery is written to owner-selected separate storage and must be rehearsed
- Readiness combines machine-verifiable receipts with explicit owner attestations
- Project audit and capsules in MVP
- Git pushes are optional, reviewed, and never silent
- Default restore never overwrites
- No telemetry in MVP
- No wiping responsibility

## 16. Open decisions

- Formal name, package, domain, and trademark clearance
- Exact minimum macOS and Linux versions
- Final cryptographic crates, parameters, and chunk size
- Exact project-capsule representation after prototyping
- Public licensing and commercial model
- Desktop framework and distribution after CLI validation
