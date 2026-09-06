use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::plan_engine::SelectedCandidatePath;
use crate::{CoreError, Disposition, ProtectionRequirement, ScanRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateSensitivity {
    Public,
    Personal,
    Sensitive,
    HighlySensitive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidatePortability {
    Portable,
    Partial,
    NotPortable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateValidation {
    ExactFilesystemState,
    InventoryOnly,
    UnsupportedRestore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateSourceKind {
    Filesystem,
    InventoryCommand,
    SuggestedExclusion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryCommand {
    program: String,
    arguments: Vec<String>,
}

impl InventoryCommand {
    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub fn executes_or_installs_payloads(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionCandidate {
    id: String,
    sources: Vec<PathBuf>,
    source_kind: CandidateSourceKind,
    sensitivity: CandidateSensitivity,
    portability: CandidatePortability,
    proposed_disposition: Disposition,
    protection_requirement: ProtectionRequirement,
    validation: CandidateValidation,
    account_sync_claimed: bool,
    available: bool,
    inventory_commands: Vec<InventoryCommand>,
}

impl ProtectionCandidate {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn sources(&self) -> &[PathBuf] {
        &self.sources
    }

    pub fn source_kind(&self) -> CandidateSourceKind {
        self.source_kind
    }

    pub fn sensitivity(&self) -> CandidateSensitivity {
        self.sensitivity
    }

    pub fn portability(&self) -> CandidatePortability {
        self.portability
    }

    pub fn proposed_disposition(&self) -> Disposition {
        self.proposed_disposition
    }

    pub fn protection_requirement(&self) -> ProtectionRequirement {
        self.protection_requirement
    }

    pub fn validation(&self) -> CandidateValidation {
        self.validation
    }

    pub fn account_sync_claimed(&self) -> bool {
        self.account_sync_claimed
    }

    pub fn account_sync_verified(&self) -> bool {
        false
    }

    pub fn available(&self) -> bool {
        self.available
    }

    pub fn inventory_commands(&self) -> &[InventoryCommand] {
        &self.inventory_commands
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionCandidateRequest {
    home: PathBuf,
    raw_application_folders: Vec<PathBuf>,
}

impl ProtectionCandidateRequest {
    pub fn for_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            raw_application_folders: Vec::new(),
        }
    }

    pub fn with_raw_application_folder(mut self, relative_path: impl Into<PathBuf>) -> Self {
        self.raw_application_folders.push(relative_path.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionCandidateReport {
    home: PathBuf,
    candidates: Vec<ProtectionCandidate>,
}

impl ProtectionCandidateReport {
    pub fn candidates(&self) -> &[ProtectionCandidate] {
        &self.candidates
    }

    pub fn candidate(&self, id: &str) -> Option<&ProtectionCandidate> {
        self.candidates.iter().find(|candidate| candidate.id == id)
    }

    pub fn to_human_text(&self) -> String {
        let mut output = String::from("Protection Candidates\n");
        for candidate in &self.candidates {
            output.push_str(&format!("\n{}\n", candidate.id));
            for source in &candidate.sources {
                output.push_str(&format!(
                    "  source: {}\n",
                    safe_human_text(&source.display().to_string())
                ));
            }
            for command in &candidate.inventory_commands {
                output.push_str(&format!(
                    "  inventory: {} {}\n",
                    command.program,
                    command.arguments.join(" ")
                ));
            }
            output.push_str(&format!(
                "  source kind: {:?}\n  sensitivity: {:?}\n  portability: {:?}\n  proposed disposition: {:?}\n  protection requirement: {:?}\n  available: {}\n",
                candidate.source_kind,
                candidate.sensitivity,
                candidate.portability,
                candidate.proposed_disposition,
                candidate.protection_requirement,
                if candidate.available { "yes" } else { "no" }
            ));
            if candidate.account_sync_claimed {
                output.push_str("  account sync claim: unverified\n");
            }
            if candidate.validation == CandidateValidation::UnsupportedRestore {
                output.push_str("  validation: unsupported Restore semantics\n");
            } else {
                output.push_str(&format!("  validation: {:?}\n", candidate.validation));
            }
        }
        output
    }

    pub fn machine_json_result(&self) -> String {
        let candidates = self
            .candidates
            .iter()
            .map(|candidate| {
                let inventory_commands = candidate
                    .inventory_commands
                    .iter()
                    .map(|command| {
                        serde_json::json!({
                            "program": command.program,
                            "arguments": command.arguments,
                            "executes_or_installs_payloads": false,
                        })
                    })
                    .collect::<Vec<_>>();
                serde_json::json!({
                    "id": candidate.id,
                    "source_kind": candidate.source_kind,
                    "sensitivity": candidate.sensitivity,
                    "portability": candidate.portability,
                    "proposed_disposition": candidate.proposed_disposition,
                    "protection_requirement": candidate.protection_requirement,
                    "validation": candidate.validation,
                    "available": candidate.available,
                    "account_sync_claimed": candidate.account_sync_claimed,
                    "account_sync_verified": false,
                    "source_count": candidate.sources.len(),
                    "inventory_commands": inventory_commands,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema_version": 1,
            "command": "candidates scan",
            "status": "success",
            "data": { "candidates": candidates },
            "warnings": [],
            "errors": [],
        })
        .to_string()
    }

    pub fn plan_request(&self, selected_ids: &[&str]) -> Result<ScanRequest, CoreError> {
        if selected_ids.is_empty() {
            return Err(CoreError::InvalidPlan(
                "at least one Protection Candidate must be selected".to_owned(),
            ));
        }
        let mut selected_paths = Vec::new();
        let mut recipes = Vec::new();
        for id in selected_ids {
            let candidate = self.candidate(id).ok_or_else(|| {
                CoreError::InvalidPlan(format!("unknown Protection Candidate identifier: {id}"))
            })?;
            if candidate.source_kind != CandidateSourceKind::Filesystem {
                return Err(CoreError::InvalidPlan(format!(
                    "Protection Candidate {id} is not filesystem state"
                )));
            }
            for source in &candidate.sources {
                let relative_path = source.strip_prefix(&self.home).map_err(|_| {
                    CoreError::InvalidPlan(
                        "Protection Candidate escaped its reviewed home root".to_owned(),
                    )
                })?;
                selected_paths.push(SelectedCandidatePath {
                    relative_path: relative_path.to_path_buf(),
                    protection_requirement: candidate.protection_requirement,
                    explanation: format!("selected Protection Candidate {id}"),
                });
            }
            recipes.push(format!(
                "protection-candidate:{id}:{}",
                validation_name(candidate.validation)
            ));
        }
        let mut request = ScanRequest::for_selected_candidates(&self.home, selected_paths);
        for recipe in recipes {
            request = request.with_recipe(recipe);
        }
        Ok(request)
    }
}

fn safe_human_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProtectionCandidateEngine;

impl ProtectionCandidateEngine {
    pub fn macos() -> Self {
        Self
    }

    pub fn discover(
        &self,
        request: ProtectionCandidateRequest,
    ) -> Result<ProtectionCandidateReport, CoreError> {
        let home = fs::canonicalize(&request.home).map_err(|source| CoreError::Io {
            action: "resolve Protection Candidate home",
            path: request.home,
            source,
        })?;
        if home.parent().is_none() {
            return Err(CoreError::InvalidPlan(
                "Protection Candidate home is too broad".to_owned(),
            ));
        }
        if request
            .raw_application_folders
            .iter()
            .any(|path| !is_safe_relative_path(path))
        {
            return Err(CoreError::InvalidPlan(
                "raw application Protection Candidate must be a safe home-relative path".to_owned(),
            ));
        }
        let mut candidates = vec![
            filesystem_candidate(
                "secure-shell-configuration",
                &home,
                &[".ssh"],
                CandidateSensitivity::HighlySensitive,
                CandidatePortability::Partial,
                Disposition::Included,
                ProtectionRequirement::MustProtect,
                CandidateValidation::ExactFilesystemState,
                false,
            ),
            filesystem_candidate(
                "git-configuration",
                &home,
                &[".gitconfig", ".config/git"],
                CandidateSensitivity::Sensitive,
                CandidatePortability::Portable,
                Disposition::Included,
                ProtectionRequirement::MustProtect,
                CandidateValidation::ExactFilesystemState,
                false,
            ),
            filesystem_candidate(
                "bash-configuration",
                &home,
                &[".bashrc", ".bash_profile", ".profile"],
                CandidateSensitivity::Sensitive,
                CandidatePortability::Portable,
                Disposition::Included,
                ProtectionRequirement::MustProtect,
                CandidateValidation::ExactFilesystemState,
                false,
            ),
            filesystem_candidate(
                "zsh-configuration",
                &home,
                &[".zshrc", ".zprofile", ".zshenv"],
                CandidateSensitivity::Sensitive,
                CandidatePortability::Portable,
                Disposition::Included,
                ProtectionRequirement::MustProtect,
                CandidateValidation::ExactFilesystemState,
                false,
            ),
            filesystem_candidate(
                "visual-studio-code-settings",
                &home,
                &["Library/Application Support/Code/User/settings.json"],
                CandidateSensitivity::Sensitive,
                CandidatePortability::Portable,
                Disposition::RequiresReview,
                ProtectionRequirement::Optional,
                CandidateValidation::ExactFilesystemState,
                true,
            ),
            filesystem_candidate(
                "visual-studio-code-keybindings",
                &home,
                &["Library/Application Support/Code/User/keybindings.json"],
                CandidateSensitivity::Personal,
                CandidatePortability::Portable,
                Disposition::RequiresReview,
                ProtectionRequirement::Optional,
                CandidateValidation::ExactFilesystemState,
                true,
            ),
            filesystem_candidate(
                "visual-studio-code-snippets",
                &home,
                &["Library/Application Support/Code/User/snippets"],
                CandidateSensitivity::Sensitive,
                CandidatePortability::Portable,
                Disposition::RequiresReview,
                ProtectionRequirement::Optional,
                CandidateValidation::ExactFilesystemState,
                true,
            ),
            inventory_candidate(
                "visual-studio-code-extension-inventory",
                true,
                Disposition::RequiresReview,
                vec![inventory_command(
                    "code",
                    &["--list-extensions", "--show-versions"],
                )],
            ),
            inventory_candidate(
                "homebrew-package-inventory",
                false,
                Disposition::Included,
                vec![
                    inventory_command("brew", &["list", "--formula", "--versions"]),
                    inventory_command("brew", &["list", "--cask", "--versions"]),
                ],
            ),
            inventory_candidate(
                "language-tool-version-inventory",
                false,
                Disposition::Included,
                vec![
                    inventory_command("rustc", &["--version"]),
                    inventory_command("cargo", &["--version"]),
                    inventory_command("node", &["--version"]),
                    inventory_command("npm", &["--version"]),
                    inventory_command("python3", &["--version"]),
                    inventory_command("go", &["version"]),
                ],
            ),
            suggested_exclusion("downloadable-caches", &home, &[".cache", "Library/Caches"]),
            suggested_exclusion("build-outputs", &home, &["**/target", "**/node_modules"]),
            suggested_exclusion(
                "package-registries",
                &home,
                &[".cargo/registry", ".npm/_cacache", ".cache/pip"],
            ),
            suggested_exclusion(
                "installed-toolchain-payloads",
                &home,
                &[".rustup/toolchains", ".nvm/versions"],
            ),
            suggested_exclusion("homebrew-caches", &home, &["Library/Caches/Homebrew"]),
        ];
        for relative_path in request.raw_application_folders {
            let id = format!(
                "raw-application-folder-{}",
                &blake3::hash(relative_path.to_string_lossy().as_bytes()).to_hex()[..16]
            );
            let path = home.join(relative_path);
            candidates.push(ProtectionCandidate {
                id,
                available: fs::symlink_metadata(&path).is_ok(),
                sources: vec![path],
                source_kind: CandidateSourceKind::Filesystem,
                sensitivity: CandidateSensitivity::HighlySensitive,
                portability: CandidatePortability::Partial,
                proposed_disposition: Disposition::RequiresReview,
                protection_requirement: ProtectionRequirement::Optional,
                validation: CandidateValidation::UnsupportedRestore,
                account_sync_claimed: false,
                inventory_commands: Vec::new(),
            });
        }
        candidates.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(ProtectionCandidateReport { home, candidates })
    }
}

fn validation_name(validation: CandidateValidation) -> &'static str {
    match validation {
        CandidateValidation::ExactFilesystemState => "exact-filesystem-state",
        CandidateValidation::InventoryOnly => "inventory-only",
        CandidateValidation::UnsupportedRestore => "unsupported-restore",
    }
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

#[allow(clippy::too_many_arguments)]
fn filesystem_candidate(
    id: &str,
    home: &Path,
    relative_sources: &[&str],
    sensitivity: CandidateSensitivity,
    portability: CandidatePortability,
    proposed_disposition: Disposition,
    protection_requirement: ProtectionRequirement,
    validation: CandidateValidation,
    account_sync_claimed: bool,
) -> ProtectionCandidate {
    let sources = relative_sources
        .iter()
        .map(|source| home.join(source))
        .collect::<Vec<_>>();
    let available = sources
        .iter()
        .any(|source| fs::symlink_metadata(source).is_ok());
    ProtectionCandidate {
        id: id.to_owned(),
        sources,
        source_kind: CandidateSourceKind::Filesystem,
        sensitivity,
        portability,
        proposed_disposition,
        protection_requirement,
        validation,
        account_sync_claimed,
        available,
        inventory_commands: Vec::new(),
    }
}

fn inventory_candidate(
    id: &str,
    account_sync_claimed: bool,
    proposed_disposition: Disposition,
    inventory_commands: Vec<InventoryCommand>,
) -> ProtectionCandidate {
    ProtectionCandidate {
        id: id.to_owned(),
        sources: Vec::new(),
        source_kind: CandidateSourceKind::InventoryCommand,
        sensitivity: CandidateSensitivity::Personal,
        portability: CandidatePortability::Portable,
        proposed_disposition,
        protection_requirement: ProtectionRequirement::Optional,
        validation: CandidateValidation::InventoryOnly,
        account_sync_claimed,
        available: true,
        inventory_commands,
    }
}

fn inventory_command(program: &str, arguments: &[&str]) -> InventoryCommand {
    InventoryCommand {
        program: program.to_owned(),
        arguments: arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
    }
}

fn suggested_exclusion(id: &str, home: &Path, patterns: &[&str]) -> ProtectionCandidate {
    ProtectionCandidate {
        id: id.to_owned(),
        sources: patterns.iter().map(|pattern| home.join(pattern)).collect(),
        source_kind: CandidateSourceKind::SuggestedExclusion,
        sensitivity: CandidateSensitivity::Personal,
        portability: CandidatePortability::NotPortable,
        proposed_disposition: Disposition::Excluded,
        protection_requirement: ProtectionRequirement::Optional,
        validation: CandidateValidation::InventoryOnly,
        account_sync_claimed: false,
        available: true,
        inventory_commands: Vec::new(),
    }
}
