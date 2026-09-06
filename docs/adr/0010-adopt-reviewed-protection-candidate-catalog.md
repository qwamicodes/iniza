# Adopt a reviewed macOS Protection Candidate catalog

- Status: Accepted for candidate discovery and narrow filesystem Plans
- Date: 2026-09-06
- Issue: COKS-32

## Context

Owner Dogfood must begin with a deliberate inventory of important developer state rather than a broad home-directory scan. Application account synchronization is useful context but is not evidence that local state is protected. Regenerable packages and tools should be represented by inventories instead of copying installed payloads, caches, registries, or build outputs.

Discovery must not read sensitive candidate content before the owner selects it in Plan review. Missing Must-Protect state must remain visible rather than disappearing from coverage.

## Decision

`ProtectionCandidateEngine::macos().discover(ProtectionCandidateRequest)` is the reusable discovery seam. It resolves one reviewed home and offers:

- Secure Shell, Git, Bash, and Zsh filesystem state as proposed Included Must-Protect candidates;
- Visual Studio Code settings, keybindings, snippets, and extension inventory as unselected Optional candidates;
- Homebrew package and language-tool version inventories as non-installing, inventory-only recipes;
- downloadable caches, build outputs, package registries, installed toolchain payloads, and Homebrew caches as suggested exclusions; and
- owner-named raw application folders as Optional encrypted-preservation candidates with unsupported application-level Restore semantics.

Every candidate identifies its source kind, source paths or direct program-and-argument inventory commands, sensitivity, portability, proposed Disposition, Protection Requirement, availability, validation method, and whether an application account-sync claim exists. Account synchronization is always reported as unverified.

Catalog discovery uses filesystem metadata only. It never opens or reads candidate file content and never executes inventory commands. Human output may show candidate paths after neutralizing terminal control characters. Version-one machine output is deterministic, single-line, path-free, and content-free.

## Selection and Plan behavior

`ProtectionCandidateReport::plan_request` accepts explicit filesystem candidate identifiers and produces a narrow `ScanRequest`. `PlanEngine` observes only those selected paths and the ancestor directories needed for a valid Restore; it does not enumerate unrelated children of the reviewed home.

Existing selected files and directories become ordinary Migration Items. Missing selected sources become Unavailable Migration Items and retain their Protection Requirement. This ensures an absent Secure Shell or other Must-Protect candidate remains a blocking coverage fact. Selected candidates add a stable recipe identifier to the Plan.

Inventory candidates remain review descriptions at this layer. Their commands are direct executable and argument vectors that report installed package or tool versions; they do not install software and they are not shell fragments. Supported command execution and capture must preserve the approved recipe and must not be confused with copying installed payloads.

Raw application folders must be non-empty, normal, home-relative paths. Their bytes may be selected for an encrypted Bundle through the same filesystem Plan, but Iniza does not claim the restored bytes constitute a supported or consistent application restore.

## Consequences

- The owner can inspect and select important developer state without a broad home scan.
- Visual Studio Code and other account-synchronized state remain offered but unselected until reviewed.
- Missing Must-Protect candidates cannot be hidden by discovery.
- Inventory descriptions are safe to review and automate, while actual supported capture remains an orchestration responsibility.
- Owner Dogfood remains gated on Recovery Method storage, supported command-line Bundle operations, verified copies, rehearsal evidence, and independent conventional backups. This decision never authorizes erasing the old Mac.
