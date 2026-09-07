use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

mod bundle;
mod iz1;
mod offline_recovery;
mod plan_comparison;
mod plan_document;
mod plan_engine;
mod platform_metadata;
mod project_audit;
mod project_capsule;
mod protection_candidates;
mod push_plan;
mod readiness_evidence;
mod restore;
mod restore_fs;
mod vaultwarden_recovery;

pub use bundle::{
    BundleEngine, BundleEvent, BundleEventSink, BundleSource, BundleSourceObservation,
    BundleVerification, DestinationCapacity, InspectRequest, LocalBundleSource,
    LocalDestinationCapacity, LocalPackPersistence, LocalVerifiedCopyPersistence, PackCancellation,
    PackCheckpointPromotionStep, PackPersistence, PackPersistenceTransition, PackRecoveryAdvice,
    PackRecoveryContext, PackReport, PackRequest, PackState, PackStopAction,
    VerifiedCopyCancellation, VerifiedCopyDurability, VerifiedCopyEvent, VerifiedCopyEventSink,
    VerifiedCopyPersistence, VerifiedCopyPersistenceTransition, VerifiedCopyReceipt,
    VerifiedCopyReport, VerifiedCopyRequest, VerifyRequest,
};
pub use iz1::{
    AuthenticatedBundleSummary, Iz1Prototype, RecoveryMethod, RecoverySecret, SealedBundle,
};
pub use offline_recovery::{
    LoadedOfflineRecoveryKey, LocalOfflineRecoveryStorage, OfflineRecoveryDocumentReport,
    OfflineRecoveryEngine, OfflineRecoveryLoadRequest, OfflineRecoveryPersistenceTransition,
    OfflineRecoveryRehearsalReceipt, OfflineRecoveryRehearsalRequest, OfflineRecoveryStorage,
    OfflineRecoveryWriteRequest,
};
pub use plan_comparison::{PlanChange, PlanChangeKind, PlanComparison};
pub use plan_engine::{
    CoverageSummary, Disposition, MigrationItem, MigrationItemKind, PlanEngine,
    ProtectionRequirement, PublicationPolicy, ScanRequest, SourceEntryKind, SourceFilesystem,
    SourceObservation,
};
pub use platform_metadata::ExtendedAttribute;
pub use project_audit::{
    GitLargeFileStorageAudit, GitProcess, GitProcessOutput, IgnoredCandidate, IgnoredReview,
    IgnoredStateInventory, IgnoredStateUnavailableReason, InstalledGit, ProjectAudit,
    ProjectAuditEngine, ProjectAuditReport, ProjectAuditRequest, ProjectHead, ProjectKind,
    ProjectLocalState, ProjectSubmodule, RemoteCheckOutcome, SanitizedRemote,
};
pub use project_capsule::{
    ProjectCapsuleBlockingFeature, ProjectCapsuleCandidateReport, ProjectCapsuleCaptureReport,
    ProjectCapsuleCaptureRequest, ProjectCapsuleCaptureState, ProjectCapsuleComparisonReport,
    ProjectCapsuleComparisonRequest, ProjectCapsuleEngine, ProjectCapsuleExpectation,
    ProjectCapsuleIgnoredRecommendation, ProjectCapsuleIgnoredReview,
    ProjectCapsuleRehearsalReceipt, ProjectCapsuleRehearsalRequest, ProjectCapsuleRepresentation,
    ProjectCapsuleRetryPolicy, ProjectCapsuleReview, ProjectCapsuleReviewDecision,
    ProjectCapsuleReviewDecisionKind, ProjectCapsuleReviewRequest, ProjectCapsuleSupportReport,
    ProjectCapsuleSupportedState, ProjectCapsuleValidationReport, ProjectCapsuleValidationRequest,
    ProjectDatabaseExportReview, ProjectDatabaseExportReviewRequest,
};
pub use protection_candidates::{
    CandidatePortability, CandidateSensitivity, CandidateSourceKind, CandidateValidation,
    InventoryCommand, ProtectionCandidate, ProtectionCandidateEngine, ProtectionCandidateReport,
    ProtectionCandidateRequest,
};
pub use push_plan::{
    GitObjectIdentifier, GitPublicationOperation, GitPublicationOutput, GitPublicationProcess,
    GitReference, GitRemoteName, InstalledGitPublication, PushAction, PushExecutionReport,
    PushExecutionState, PushPlanApprovalReceipt, PushPlanApprovalRequest, PushPlanDocumentReport,
    PushPlanDraftRequest, PushPlanEngine, PushPlanExecutionRequest,
};
pub use readiness_evidence::{
    OwnerAttestationClaimKind, OwnerAttestationConfirmationRequest,
    OwnerAttestationPreparationRequest, OwnerAttestationRecord, OwnerAttestationReview,
    OwnerAttestationStatus, OwnerAttestationWithdrawalRecord, OwnerAttestationWithdrawalRequest,
    ReadinessEvidenceConclusion, ReadinessEvidenceEngine, ReadinessEvidenceEvent,
    ReadinessEvidenceInitializationRequest, ReadinessEvidenceState, ReadinessEvidenceStatusReport,
    ReadinessEvidenceStatusRequest, ReadinessEvidenceStoreReport, ReadinessReceiptRecordReport,
    ReadinessReceiptRecordRequest,
};
pub use restore::{
    RestoreCancellation, RestoreEngine, RestoreEvent, RestoreEventSink, RestoreReport,
    RestoreRequest, RestoreState,
};
pub use vaultwarden_recovery::{
    BitwardenCommandLine, BitwardenInstallationObservation, BitwardenRecoveryNote,
    BitwardenRetrievedRecoveryNote, BitwardenVaultObservation, InstalledBitwarden,
    LoadedVaultwardenRecoverySecret, VaultwardenInstallationReport, VaultwardenInstallationRequest,
    VaultwardenItemIdentifier, VaultwardenLoadRequest, VaultwardenPreflightReport,
    VaultwardenPreflightRequest, VaultwardenRecoveryEngine, VaultwardenRecoveryReceipt,
    VaultwardenRehearsalRequest, VaultwardenStoreReport, VaultwardenStoreRequest,
    VaultwardenStoreState,
};

pub const FIXTURE_MAGIC: &[u8] = b"INIZA-TEST-FIXTURE-V0\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub schema_version: u32,
    kind: PlanKind,
    pub source_path: PathBuf,
    pub source_name: String,
    pub logical_size: u64,
    approved_roots: Vec<PathBuf>,
    items: Vec<MigrationItem>,
    recipes: Vec<String>,
    exclusions: Vec<PathBuf>,
    destination_preference: Option<PathBuf>,
    publication_policy: PublicationPolicy,
    cross_mounts: bool,
    approved_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanKind {
    Fixture,
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanApprovalState {
    Unapproved,
    Approved,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureSummary {
    pub source_name: String,
    pub logical_size: u64,
}

impl Plan {
    pub fn is_directory_plan(&self) -> bool {
        self.kind == PlanKind::Directory
    }

    pub fn approved_roots(&self) -> &[PathBuf] {
        &self.approved_roots
    }

    pub fn items(&self) -> &[MigrationItem] {
        &self.items
    }

    pub fn estimated_logical_size(&self) -> u64 {
        self.items
            .iter()
            .filter(|item| item.kind == MigrationItemKind::RegularFile)
            .map(|item| item.estimated_size)
            .sum()
    }

    pub fn coverage_summary(&self) -> CoverageSummary {
        CoverageSummary::from_items(&self.items)
    }

    pub fn recipes(&self) -> &[String] {
        &self.recipes
    }

    pub fn exclusions(&self) -> &[PathBuf] {
        &self.exclusions
    }

    pub fn destination_preference(&self) -> Option<&Path> {
        self.destination_preference.as_deref()
    }

    pub fn publication_policy(&self) -> PublicationPolicy {
        self.publication_policy
    }

    pub fn cross_mounts(&self) -> bool {
        self.cross_mounts
    }

    pub fn write_to(&self, destination: &Path) -> Result<(), CoreError> {
        if self.kind == PlanKind::Directory {
            return plan_document::write(self, destination);
        }
        let source_path = quote_plan_string(&self.source_path.to_string_lossy());
        let source_name = quote_plan_string(&self.source_name);
        let text = format!(
            "schema_version = {}\nplan_kind = \"fixture\"\nsource_path = \"{}\"\nsource_name = \"{}\"\nlogical_size = {}\ndisposition = \"included\"\nprotection_requirement = \"must-protect\"\n",
            self.schema_version, source_path, source_name, self.logical_size
        );
        fs::write(destination, text).map_err(|source| CoreError::Io {
            action: "write Plan",
            path: destination.to_path_buf(),
            source,
        })
    }

    pub fn read_from(source: &Path) -> Result<Self, CoreError> {
        let text = fs::read_to_string(source).map_err(|error| CoreError::Io {
            action: "read Plan",
            path: source.to_path_buf(),
            source: error,
        })?;
        if text.contains("plan_kind = \"directory\"") {
            return plan_document::decode(&text);
        }
        let mut fields = BTreeMap::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| CoreError::InvalidPlan(format!("invalid Plan line: {line}")))?;
            fields.insert(key.trim().to_owned(), value.trim().to_owned());
        }

        require_exact_field(&fields, "plan_kind", "\"fixture\"")?;
        require_exact_field(&fields, "disposition", "\"included\"")?;
        require_exact_field(&fields, "protection_requirement", "\"must-protect\"")?;

        let schema_version = parse_number(&fields, "schema_version")?;
        if schema_version != 1 {
            return Err(CoreError::InvalidPlan(format!(
                "unsupported Plan schema version: {schema_version}"
            )));
        }

        Ok(Self {
            schema_version,
            kind: PlanKind::Fixture,
            source_path: PathBuf::from(parse_quoted_string(&fields, "source_path")?),
            source_name: parse_quoted_string(&fields, "source_name")?,
            logical_size: parse_number(&fields, "logical_size")?,
            approved_roots: Vec::new(),
            items: Vec::new(),
            recipes: Vec::new(),
            exclusions: Vec::new(),
            destination_preference: None,
            publication_policy: PublicationPolicy::ProtectLocallyOnly,
            cross_mounts: false,
            approved_hash: None,
        })
    }

    pub fn approval_hash(&self) -> Result<String, CoreError> {
        plan_document::approval_hash(self)
    }

    pub fn approve(&mut self, reviewed_hash: &str) -> Result<(), CoreError> {
        let current = self.approval_hash()?;
        if reviewed_hash != current {
            return Err(CoreError::InvalidPlan(
                "reviewed Plan hash does not match the current Plan".to_owned(),
            ));
        }
        self.approved_hash = Some(current);
        Ok(())
    }

    pub fn approval_state(&self) -> Result<PlanApprovalState, CoreError> {
        match &self.approved_hash {
            None => Ok(PlanApprovalState::Unapproved),
            Some(approved) if approved == &self.approval_hash()? => Ok(PlanApprovalState::Approved),
            Some(_) => Ok(PlanApprovalState::Stale),
        }
    }

    pub fn compare(&self, revised: &Self) -> PlanComparison {
        plan_comparison::compare(self, revised)
    }
}

#[derive(Debug)]
pub enum CoreError {
    AuthenticationFailed,
    BundleIncomplete(PathBuf),
    BundleInvalid(String),
    CopyInterrupted(PathBuf),
    DestinationAlreadyExists(PathBuf),
    InsufficientSpace {
        path: PathBuf,
        required: u64,
        available: u64,
    },
    InvalidFixture(String),
    InvalidFixtureOutput(PathBuf),
    InvalidPlan(String),
    ReadinessEvidence(String),
    SourceIsNotARegularFile(PathBuf),
    SourceHasNoFileName(PathBuf),
    TestFixtureIsNotBundle(PathBuf),
    Vaultwarden(String),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => formatter.write_str("Bundle authentication failed"),
            Self::BundleIncomplete(path) => {
                write!(formatter, "Bundle output is incomplete: {}", path.display())
            }
            Self::BundleInvalid(message) => formatter.write_str(message),
            Self::CopyInterrupted(path) => write!(
                formatter,
                "Verified Copy interrupted; partial output remains at {}",
                path.display()
            ),
            Self::DestinationAlreadyExists(path) => {
                write!(formatter, "destination already exists: {}", path.display())
            }
            Self::InsufficientSpace {
                path,
                required,
                available,
            } => write!(
                formatter,
                "insufficient destination space at {}: requires at least {required} bytes, {available} bytes available",
                path.display()
            ),
            Self::InvalidFixtureOutput(path) => write!(
                formatter,
                "test-only fixture output must end with .iniza-fixture: {}",
                path.display()
            ),
            Self::InvalidFixture(message) => formatter.write_str(message),
            Self::InvalidPlan(message) => formatter.write_str(message),
            Self::ReadinessEvidence(message) => formatter.write_str(message),
            Self::SourceIsNotARegularFile(path) => {
                write!(
                    formatter,
                    "source is not a regular file: {}",
                    path.display()
                )
            }
            Self::SourceHasNoFileName(path) => {
                write!(formatter, "source has no file name: {}", path.display())
            }
            Self::TestFixtureIsNotBundle(path) => write!(
                formatter,
                "test-only fixture is not an encrypted Bundle and is accepted only by the fixture commands: {}",
                path.display()
            ),
            Self::Vaultwarden(message) => formatter.write_str(message),
            Self::Io {
                action,
                path,
                source,
            } => write!(
                formatter,
                "could not {action} at {}: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct InizaCore;

impl InizaCore {
    pub fn scan_explicit_file(&self, source: &Path) -> Result<Plan, CoreError> {
        let metadata = fs::metadata(source).map_err(|error| CoreError::Io {
            action: "read source metadata",
            path: source.to_path_buf(),
            source: error,
        })?;
        if !metadata.is_file() {
            return Err(CoreError::SourceIsNotARegularFile(source.to_path_buf()));
        }

        let source_name = source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CoreError::SourceHasNoFileName(source.to_path_buf()))?
            .to_owned();

        let source_path = fs::canonicalize(source).map_err(|error| CoreError::Io {
            action: "resolve source path",
            path: source.to_path_buf(),
            source: error,
        })?;

        Ok(Plan {
            schema_version: 1,
            kind: PlanKind::Fixture,
            source_path: source_path.clone(),
            source_name,
            logical_size: metadata.len(),
            approved_roots: vec![source_path.clone()],
            items: vec![MigrationItem {
                id: plan_engine::stable_item_id(&source_path, Path::new("."), "regular-file"),
                relative_path: PathBuf::from("."),
                kind: MigrationItemKind::RegularFile,
                estimated_size: metadata.len(),
                disposition: Disposition::Included,
                protection_requirement: ProtectionRequirement::MustProtect,
                explanation: "explicitly approved file".to_owned(),
            }],
            recipes: Vec::new(),
            exclusions: Vec::new(),
            destination_preference: None,
            publication_policy: PublicationPolicy::ProtectLocallyOnly,
            cross_mounts: false,
            approved_hash: None,
        })
    }

    pub fn validate_plan(&self, source: &Path) -> Result<Plan, CoreError> {
        Plan::read_from(source)
    }

    pub fn pack_fixture(
        &self,
        plan_path: &Path,
        destination: &Path,
    ) -> Result<FixtureSummary, CoreError> {
        if destination.extension().and_then(|value| value.to_str()) != Some("iniza-fixture") {
            return Err(CoreError::InvalidFixtureOutput(destination.to_path_buf()));
        }

        let plan = Plan::read_from(plan_path)?;
        let content = fs::read(&plan.source_path).map_err(|error| CoreError::Io {
            action: "read selected source",
            path: plan.source_path.clone(),
            source: error,
        })?;
        if content.len() as u64 != plan.logical_size {
            return Err(CoreError::InvalidPlan(
                "selected source size changed after Plan creation".to_owned(),
            ));
        }

        let name = plan.source_name.as_bytes();
        let name_length = u32::try_from(name.len())
            .map_err(|_| CoreError::InvalidPlan("selected source name is too long".to_owned()))?;

        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    CoreError::DestinationAlreadyExists(destination.to_path_buf())
                } else {
                    CoreError::Io {
                        action: "create test-only fixture container",
                        path: destination.to_path_buf(),
                        source: error,
                    }
                }
            })?;
        output
            .write_all(FIXTURE_MAGIC)
            .and_then(|_| output.write_all(&name_length.to_le_bytes()))
            .and_then(|_| output.write_all(&(content.len() as u64).to_le_bytes()))
            .and_then(|_| output.write_all(name))
            .and_then(|_| output.write_all(&content))
            .map_err(|error| CoreError::Io {
                action: "write test-only fixture container",
                path: destination.to_path_buf(),
                source: error,
            })?;

        Ok(FixtureSummary {
            source_name: plan.source_name,
            logical_size: plan.logical_size,
        })
    }

    pub fn inspect_fixture(&self, source: &Path) -> Result<FixtureSummary, CoreError> {
        let mut input = fs::File::open(source).map_err(|error| CoreError::Io {
            action: "open test-only fixture container",
            path: source.to_path_buf(),
            source: error,
        })?;
        let file_length = input
            .metadata()
            .map_err(|error| CoreError::Io {
                action: "read test-only fixture metadata",
                path: source.to_path_buf(),
                source: error,
            })?
            .len();

        let mut magic = vec![0; FIXTURE_MAGIC.len()];
        read_fixture_bytes(&mut input, &mut magic, source)?;
        if magic != FIXTURE_MAGIC {
            return Err(CoreError::InvalidFixture(
                "not an Iniza test-only fixture container".to_owned(),
            ));
        }

        let mut name_length_bytes = [0; 4];
        read_fixture_bytes(&mut input, &mut name_length_bytes, source)?;
        let name_length = u32::from_le_bytes(name_length_bytes) as u64;
        if name_length == 0 || name_length > 4096 {
            return Err(CoreError::InvalidFixture(
                "test-only fixture source name has an invalid length".to_owned(),
            ));
        }

        let mut content_length_bytes = [0; 8];
        read_fixture_bytes(&mut input, &mut content_length_bytes, source)?;
        let content_length = u64::from_le_bytes(content_length_bytes);
        let header_length = u64::try_from(FIXTURE_MAGIC.len())
            .expect("fixture header length should fit in a u64")
            + 4
            + 8;
        let expected_length = header_length
            .checked_add(name_length)
            .and_then(|length| length.checked_add(content_length))
            .ok_or_else(|| {
                CoreError::InvalidFixture("test-only fixture length is invalid".to_owned())
            })?;
        if expected_length != file_length {
            return Err(CoreError::InvalidFixture(
                "test-only fixture length does not match its metadata".to_owned(),
            ));
        }

        let mut name = vec![0; name_length as usize];
        read_fixture_bytes(&mut input, &mut name, source)?;
        let source_name = String::from_utf8(name).map_err(|_| {
            CoreError::InvalidFixture("test-only fixture source name is not valid text".to_owned())
        })?;
        if !is_safe_file_name(&source_name) {
            return Err(CoreError::InvalidFixture(
                "test-only fixture source name is not a safe file name".to_owned(),
            ));
        }

        Ok(FixtureSummary {
            source_name,
            logical_size: content_length,
        })
    }

    pub fn restore_fixture(&self, source: &Path, destination: &Path) -> Result<PathBuf, CoreError> {
        let summary = self.inspect_fixture(source)?;
        let mut input = fs::File::open(source).map_err(|error| CoreError::Io {
            action: "open test-only fixture container for Restore",
            path: source.to_path_buf(),
            source: error,
        })?;
        let payload_offset = u64::try_from(FIXTURE_MAGIC.len())
            .expect("fixture header length should fit in a u64")
            + 4
            + 8
            + u64::try_from(summary.source_name.len())
                .expect("validated fixture source name length should fit in a u64");
        input
            .seek(SeekFrom::Start(payload_offset))
            .map_err(|error| CoreError::Io {
                action: "locate test-only fixture payload",
                path: source.to_path_buf(),
                source: error,
            })?;

        fs::create_dir(destination).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CoreError::DestinationAlreadyExists(destination.to_path_buf())
            } else {
                CoreError::Io {
                    action: "create Restore destination",
                    path: destination.to_path_buf(),
                    source: error,
                }
            }
        })?;

        let restored_file = destination.join(&summary.source_name);
        let restore_result = (|| {
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&restored_file)
                .map_err(|error| CoreError::Io {
                    action: "create restored file",
                    path: restored_file.clone(),
                    source: error,
                })?;
            let copied =
                io::copy(&mut input.take(summary.logical_size), &mut output).map_err(|error| {
                    CoreError::Io {
                        action: "restore test-only fixture payload",
                        path: restored_file.clone(),
                        source: error,
                    }
                })?;
            if copied != summary.logical_size {
                return Err(CoreError::InvalidFixture(
                    "test-only fixture payload is truncated".to_owned(),
                ));
            }
            Ok(())
        })();

        if let Err(error) = restore_result {
            let _ = fs::remove_file(&restored_file);
            let _ = fs::remove_dir(destination);
            return Err(error);
        }

        Ok(restored_file)
    }

    pub fn inspect_bundle(&self, source: &Path) -> Result<(), CoreError> {
        let mut input = fs::File::open(source).map_err(|error| CoreError::Io {
            action: "open Bundle for inspection",
            path: source.to_path_buf(),
            source: error,
        })?;
        let mut prefix = vec![0; FIXTURE_MAGIC.len()];
        match input.read_exact(&mut prefix) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(CoreError::BundleInvalid(
                    "Bundle header is incomplete".to_owned(),
                ));
            }
            Err(error) => {
                return Err(CoreError::Io {
                    action: "read Bundle header",
                    path: source.to_path_buf(),
                    source: error,
                });
            }
        }
        if prefix == FIXTURE_MAGIC {
            return Err(CoreError::TestFixtureIsNotBundle(source.to_path_buf()));
        }

        Err(CoreError::BundleInvalid(
            "encrypted Bundle inspection is not implemented yet".to_owned(),
        ))
    }
}

fn read_fixture_bytes(
    input: &mut fs::File,
    buffer: &mut [u8],
    source: &Path,
) -> Result<(), CoreError> {
    input.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            CoreError::InvalidFixture("test-only fixture is truncated".to_owned())
        } else {
            CoreError::Io {
                action: "read test-only fixture container",
                path: source.to_path_buf(),
                source: error,
            }
        }
    })
}

fn is_safe_file_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn require_exact_field(
    fields: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), CoreError> {
    match fields.get(key) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(CoreError::InvalidPlan(format!(
            "invalid {key}: expected {expected}, found {actual}"
        ))),
        None => Err(CoreError::InvalidPlan(format!(
            "Plan is missing required field: {key}"
        ))),
    }
}

fn parse_number<T>(fields: &BTreeMap<String, String>, key: &str) -> Result<T, CoreError>
where
    T: std::str::FromStr,
{
    let value = fields
        .get(key)
        .ok_or_else(|| CoreError::InvalidPlan(format!("Plan is missing required field: {key}")))?;
    value
        .parse()
        .map_err(|_| CoreError::InvalidPlan(format!("invalid numeric Plan field: {key}")))
}

fn parse_quoted_string(fields: &BTreeMap<String, String>, key: &str) -> Result<String, CoreError> {
    let value = fields
        .get(key)
        .ok_or_else(|| CoreError::InvalidPlan(format!("Plan is missing required field: {key}")))?;
    let inner = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| CoreError::InvalidPlan(format!("invalid quoted Plan field: {key}")))?;

    let mut result = String::new();
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            result.push(character);
            continue;
        }
        let escaped = characters.next().ok_or_else(|| {
            CoreError::InvalidPlan(format!("incomplete escape in Plan field: {key}"))
        })?;
        result.push(match escaped {
            '\\' => '\\',
            '"' => '"',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => {
                return Err(CoreError::InvalidPlan(format!(
                    "unsupported escape in Plan field: {key}"
                )));
            }
        });
    }
    Ok(result)
}

fn quote_plan_string(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}
