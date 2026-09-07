use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

use crate::bundle::{
    local_verified_copy_storage_location, verified_copy_destination_evidence_identity,
};
use crate::push_plan::{
    PushPublicationProof, revalidate_already_synchronized_project, revalidate_synchronized_project,
};
use crate::restore::current_restore_destination_evidence_identity;

use crate::{
    BundleEngine, BundleVerification, CoreError, GitPublicationProcess, InstalledGitPublication,
    LoadedVaultwardenRecoverySecret, OfflineRecoveryEngine, OfflineRecoveryRehearsalReceipt,
    OfflineRecoveryRehearsalRequest, Plan, PlanApprovalState, ProjectAudit, ProjectAuditEngine,
    ProjectAuditRequest, ProjectCapsuleCaptureReport, ProjectCapsuleExpectation,
    ProjectCapsuleRehearsalReceipt, ProtectionRequirement, PushExecutionReport, PushExecutionState,
    RecoveryMethod, RecoverySecret, RestoreReport, RestoreState, VaultwardenRecoveryReceipt,
    VerifiedCopyDurability, VerifiedCopyReport, VerifiedCopyStorageLocation, VerifyRequest,
};

const RECORD_SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const MAX_RECORDS: usize = 10_000;
const OWNER_ATTESTATION_ACKNOWLEDGEMENT: &str = "I confirm this Owner Attestation as my statement.";
const OWNER_ATTESTATION_WITHDRAWAL_ACKNOWLEDGEMENT: &str = "I withdraw this Owner Attestation.";

#[derive(Debug)]
pub struct ReadinessEvidenceInitializationRequest<'a> {
    plan: &'a Plan,
    directory: PathBuf,
}

impl<'a> ReadinessEvidenceInitializationRequest<'a> {
    pub fn new(plan: &'a Plan, directory: impl Into<PathBuf>) -> Self {
        Self {
            plan,
            directory: directory.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessEvidenceStoreReport {
    store_identity: String,
    plan_hash: String,
}

impl ReadinessEvidenceStoreReport {
    pub fn schema_version(&self) -> u32 {
        RECORD_SCHEMA_VERSION
    }

    pub fn store_identity(&self) -> &str {
        &self.store_identity
    }

    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }
}

#[derive(Debug)]
pub struct ReadinessReceiptRecordRequest<'a> {
    directory: PathBuf,
    plan: &'a Plan,
    input: ReadinessReceiptInput<'a>,
}

#[derive(Debug)]
enum ReadinessReceiptInput<'a> {
    BundleVerification {
        bundle: PathBuf,
        verification: &'a BundleVerification,
    },
    OfflineRecovery(&'a OfflineRecoveryRehearsalReceipt),
    VaultwardenRecovery(&'a VaultwardenRecoveryReceipt),
    VerifiedCopy(&'a VerifiedCopyReport),
    NotProtectedReport,
    ProjectCapsuleCapture(&'a ProjectCapsuleCaptureReport),
    ProjectCapsuleRehearsal(&'a ProjectCapsuleRehearsalReceipt),
    RestoreRehearsal(&'a RestoreReport),
    PushExecution(&'a PushExecutionReport),
}

impl<'a> ReadinessReceiptRecordRequest<'a> {
    pub fn bundle_verification(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        bundle: impl Into<PathBuf>,
        verification: &'a BundleVerification,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            input: ReadinessReceiptInput::BundleVerification {
                bundle: bundle.into(),
                verification,
            },
        }
    }

    pub fn offline_recovery(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        receipt: &'a OfflineRecoveryRehearsalReceipt,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            input: ReadinessReceiptInput::OfflineRecovery(receipt),
        }
    }

    pub fn verified_copy(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        report: &'a VerifiedCopyReport,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            input: ReadinessReceiptInput::VerifiedCopy(report),
        }
    }

    pub fn vaultwarden_recovery(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        receipt: &'a VaultwardenRecoveryReceipt,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            input: ReadinessReceiptInput::VaultwardenRecovery(receipt),
        }
    }

    pub fn not_protected_report(directory: impl Into<PathBuf>, plan: &'a Plan) -> Self {
        Self {
            directory: directory.into(),
            plan,
            input: ReadinessReceiptInput::NotProtectedReport,
        }
    }

    pub fn project_capsule_capture(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        report: &'a ProjectCapsuleCaptureReport,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            input: ReadinessReceiptInput::ProjectCapsuleCapture(report),
        }
    }

    pub fn project_capsule_rehearsal(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        receipt: &'a ProjectCapsuleRehearsalReceipt,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            input: ReadinessReceiptInput::ProjectCapsuleRehearsal(receipt),
        }
    }

    pub fn restore_rehearsal(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        report: &'a RestoreReport,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            input: ReadinessReceiptInput::RestoreRehearsal(report),
        }
    }

    pub fn push_execution(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        report: &'a PushExecutionReport,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            input: ReadinessReceiptInput::PushExecution(report),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessReceiptRecordReport {
    operation: &'static str,
    sequence: u64,
    evidence_reference: String,
}

impl ReadinessReceiptRecordReport {
    pub fn operation(&self) -> &'static str {
        self.operation
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn evidence_reference(&self) -> &str {
        &self.evidence_reference
    }
}

#[derive(Debug)]
pub struct ReadinessEvidenceStatusRequest<'a> {
    directory: PathBuf,
    plan: &'a Plan,
    bundle: Option<BundleStatusInput<'a>>,
    offline_recovery_document: Option<PathBuf>,
    vaultwarden_recovery: Option<&'a LoadedVaultwardenRecoverySecret>,
    verified_copies: Vec<PathBuf>,
    project_capsules: Vec<ProjectCapsuleStatusInput<'a>>,
    restore_rehearsal_destination: Option<PathBuf>,
    project_publications: Vec<&'a ProjectAudit>,
}

#[derive(Debug)]
struct BundleStatusInput<'a> {
    bundle: PathBuf,
    recovery_secret: &'a RecoverySecret,
}

#[derive(Debug)]
struct ProjectCapsuleStatusInput<'a> {
    bundle: PathBuf,
    expectation: &'a ProjectCapsuleExpectation,
    recovery_secret: &'a RecoverySecret,
}

impl<'a> ReadinessEvidenceStatusRequest<'a> {
    pub fn new(directory: impl Into<PathBuf>, plan: &'a Plan) -> Self {
        Self {
            directory: directory.into(),
            plan,
            bundle: None,
            offline_recovery_document: None,
            vaultwarden_recovery: None,
            verified_copies: Vec::new(),
            project_capsules: Vec::new(),
            restore_rehearsal_destination: None,
            project_publications: Vec::new(),
        }
    }

    pub fn with_bundle(
        mut self,
        bundle: impl Into<PathBuf>,
        recovery_secret: &'a RecoverySecret,
    ) -> Self {
        self.bundle = Some(BundleStatusInput {
            bundle: bundle.into(),
            recovery_secret,
        });
        self
    }

    pub fn with_offline_recovery_document(mut self, document: impl Into<PathBuf>) -> Self {
        self.offline_recovery_document = Some(document.into());
        self
    }

    pub fn with_verified_copy(mut self, bundle: impl Into<PathBuf>) -> Self {
        self.verified_copies.push(bundle.into());
        self
    }

    pub fn with_vaultwarden_recovery(
        mut self,
        loaded: &'a LoadedVaultwardenRecoverySecret,
    ) -> Self {
        self.vaultwarden_recovery = Some(loaded);
        self
    }

    pub fn with_project_capsule(
        mut self,
        bundle: impl Into<PathBuf>,
        expectation: &'a ProjectCapsuleExpectation,
        recovery_secret: &'a RecoverySecret,
    ) -> Self {
        self.project_capsules.push(ProjectCapsuleStatusInput {
            bundle: bundle.into(),
            expectation,
            recovery_secret,
        });
        self
    }

    pub fn with_restore_rehearsal(mut self, destination: impl Into<PathBuf>) -> Self {
        self.restore_rehearsal_destination = Some(destination.into());
        self
    }

    pub fn with_project_publication(mut self, project: &'a ProjectAudit) -> Self {
        self.project_publications.push(project);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadinessEvidenceConclusion {
    Current,
    Missing,
    Invalidated,
    Blocking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessEvidenceState {
    CompleteEvidence,
    BlockingGaps,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessEvidenceStatusReport {
    state: ReadinessEvidenceState,
    plan_coverage: ReadinessEvidenceConclusion,
    bundle_verification: ReadinessEvidenceConclusion,
    offline_recovery_method: ReadinessEvidenceConclusion,
    vaultwarden_recovery_method: ReadinessEvidenceConclusion,
    verified_copy: ReadinessEvidenceConclusion,
    not_protected_report: ReadinessEvidenceConclusion,
    restore_rehearsal: ReadinessEvidenceConclusion,
    blocking_gaps: Vec<ReadinessEvidenceGap>,
    active_owner_attestations: Vec<OwnerAttestationStatus>,
    withdrawn_owner_attestation_identifiers: Vec<String>,
    projects: Vec<ReadinessProjectEvidence>,
    events: Vec<ReadinessEvidenceEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadinessProjectEvidence {
    project_identity: String,
    restorable: ReadinessEvidenceConclusion,
    synchronized: ReadinessEvidenceConclusion,
}

impl ReadinessProjectEvidence {
    pub fn project_identity(&self) -> &str {
        &self.project_identity
    }

    pub fn restorable(&self) -> ReadinessEvidenceConclusion {
        self.restorable
    }

    pub fn synchronized(&self) -> ReadinessEvidenceConclusion {
        self.synchronized
    }
}

impl ReadinessEvidenceStatusReport {
    pub fn state(&self) -> ReadinessEvidenceState {
        self.state
    }

    pub fn plan_coverage(&self) -> ReadinessEvidenceConclusion {
        self.plan_coverage
    }

    pub fn bundle_verification(&self) -> ReadinessEvidenceConclusion {
        self.bundle_verification
    }

    pub fn offline_recovery_method(&self) -> ReadinessEvidenceConclusion {
        self.offline_recovery_method
    }

    pub fn vaultwarden_recovery_method(&self) -> ReadinessEvidenceConclusion {
        self.vaultwarden_recovery_method
    }

    pub fn verified_copy(&self) -> ReadinessEvidenceConclusion {
        self.verified_copy
    }

    pub fn not_protected_report(&self) -> ReadinessEvidenceConclusion {
        self.not_protected_report
    }

    pub fn restore_rehearsal(&self) -> ReadinessEvidenceConclusion {
        self.restore_rehearsal
    }

    pub fn blocking_gaps(&self) -> &[ReadinessEvidenceGap] {
        &self.blocking_gaps
    }

    pub fn active_owner_attestations(&self) -> &[OwnerAttestationStatus] {
        &self.active_owner_attestations
    }

    pub fn withdrawn_owner_attestation_identifiers(&self) -> &[String] {
        &self.withdrawn_owner_attestation_identifiers
    }

    pub fn projects(&self) -> &[ReadinessProjectEvidence] {
        &self.projects
    }

    pub fn exit_code(&self) -> u8 {
        match self.state {
            ReadinessEvidenceState::CompleteEvidence => 0,
            ReadinessEvidenceState::BlockingGaps => 2,
        }
    }

    pub fn human_result(&self) -> String {
        format!(
            "Readiness Evidence\n  state: {}\n  Bundle verification: {}\nThis is not permission to erase a machine.",
            self.state.human_label(),
            self.bundle_verification.human_label(),
        )
    }

    pub fn machine_json_result(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "command": "readiness status",
            "status": self.state.machine_label(),
            "data": {
                "bundle_verification": self.bundle_verification.machine_label(),
                "plan_coverage": self.plan_coverage.machine_label(),
                "offline_recovery_method": self.offline_recovery_method.machine_label(),
                "vaultwarden_recovery_method": self.vaultwarden_recovery_method.machine_label(),
                "verified_copy": self.verified_copy.machine_label(),
                "not_protected_report": self.not_protected_report.machine_label(),
                "restore_rehearsal": self.restore_rehearsal.machine_label(),
                "blocking_gaps": self.blocking_gaps,
                "active_owner_attestations": self.active_owner_attestations,
                "withdrawn_owner_attestation_identifiers": self.withdrawn_owner_attestation_identifiers,
                "projects": self.projects,
            },
            "warnings": ["This is not permission to erase a machine."],
            "errors": [],
        })
        .to_string()
    }

    pub fn events(&self) -> &[ReadinessEvidenceEvent] {
        &self.events
    }
}

impl ReadinessEvidenceState {
    fn human_label(self) -> &'static str {
        match self {
            Self::CompleteEvidence => "Complete evidence",
            Self::BlockingGaps => "Blocking gaps",
        }
    }

    fn machine_label(self) -> &'static str {
        match self {
            Self::CompleteEvidence => "complete-evidence",
            Self::BlockingGaps => "blocking-gaps",
        }
    }
}

impl ReadinessEvidenceConclusion {
    fn human_label(self) -> &'static str {
        match self {
            Self::Current => "Current",
            Self::Missing => "Missing",
            Self::Invalidated => "Invalidated",
            Self::Blocking => "Blocking",
        }
    }

    fn machine_label(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Missing => "missing",
            Self::Invalidated => "invalidated",
            Self::Blocking => "blocking",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadinessEvidenceGap {
    code: &'static str,
    count: u64,
}

impl ReadinessEvidenceGap {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn count(&self) -> u64 {
        self.count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessEvidenceEvent {
    state: ReadinessEvidenceState,
    bundle_verification: ReadinessEvidenceConclusion,
}

impl ReadinessEvidenceEvent {
    pub fn machine_json_line(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "event": "readiness-evaluated",
            "state": self.state.machine_label(),
            "bundle_verification": self.bundle_verification.machine_label(),
        })
        .to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerAttestationClaimKind {
    ConventionalBackupValidated,
    RepresentativeRestoredProjectBuildCompleted,
    SecondEnvironmentRehearsalCompleted,
    NotProtectedReportReviewed,
    ReviewedExternalVaultwardenServiceConfirmed,
    FreshDeviceVaultwardenAccessConfirmed,
    IndependentMultiFactorRecoveryPathConfirmed,
    LocalOnlyProjectReferencesRetainedInProjectCapsule,
}

impl OwnerAttestationClaimKind {
    fn claim_text(self) -> &'static str {
        match self {
            Self::ConventionalBackupValidated => {
                "I confirm that the conventional backup was validated."
            }
            Self::RepresentativeRestoredProjectBuildCompleted => {
                "I confirm that a representative restored Project build completed."
            }
            Self::SecondEnvironmentRehearsalCompleted => {
                "I confirm that the second-environment Restore Rehearsal completed."
            }
            Self::NotProtectedReportReviewed => {
                "I confirm that I reviewed the Not Protected Report."
            }
            Self::ReviewedExternalVaultwardenServiceConfirmed => {
                "I confirm that the reviewed Vaultwarden service is external to the source Mac."
            }
            Self::FreshDeviceVaultwardenAccessConfirmed => {
                "I confirm that fresh-device Vaultwarden access succeeded."
            }
            Self::IndependentMultiFactorRecoveryPathConfirmed => {
                "I confirm that the independent multi-factor recovery path succeeded."
            }
            Self::LocalOnlyProjectReferencesRetainedInProjectCapsule => {
                "I confirm that this Project's reviewed local-only references are deliberately retained only in its verified Project Capsule and must not be published."
            }
        }
    }

    fn machine_label(self) -> &'static str {
        match self {
            Self::ConventionalBackupValidated => "conventional-backup-validated",
            Self::RepresentativeRestoredProjectBuildCompleted => {
                "representative-restored-project-build-completed"
            }
            Self::SecondEnvironmentRehearsalCompleted => "second-environment-rehearsal-completed",
            Self::NotProtectedReportReviewed => "not-protected-report-reviewed",
            Self::ReviewedExternalVaultwardenServiceConfirmed => {
                "reviewed-external-vaultwarden-service-confirmed"
            }
            Self::FreshDeviceVaultwardenAccessConfirmed => {
                "fresh-device-vaultwarden-access-confirmed"
            }
            Self::IndependentMultiFactorRecoveryPathConfirmed => {
                "independent-multi-factor-recovery-path-confirmed"
            }
            Self::LocalOnlyProjectReferencesRetainedInProjectCapsule => {
                "local-only-project-references-retained-in-project-capsule"
            }
        }
    }
}

#[derive(Debug)]
pub struct OwnerAttestationPreparationRequest<'a> {
    directory: PathBuf,
    plan: &'a Plan,
    claim_kind: OwnerAttestationClaimKind,
    evidence_reference: String,
}

impl<'a> OwnerAttestationPreparationRequest<'a> {
    pub fn new(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        claim_kind: OwnerAttestationClaimKind,
        evidence_reference: impl Into<String>,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            claim_kind,
            evidence_reference: evidence_reference.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAttestationReview {
    store_identity: String,
    plan_hash: String,
    claim_kind: OwnerAttestationClaimKind,
    claim_text: String,
    evidence_reference: String,
    prepared_at_unix_seconds: u64,
    review_hash: String,
}

impl OwnerAttestationReview {
    pub fn claim_kind(&self) -> OwnerAttestationClaimKind {
        self.claim_kind
    }

    pub fn claim_text(&self) -> &str {
        &self.claim_text
    }

    pub fn evidence_reference(&self) -> &str {
        &self.evidence_reference
    }

    pub fn prepared_at_unix_seconds(&self) -> u64 {
        self.prepared_at_unix_seconds
    }

    pub fn review_hash(&self) -> &str {
        &self.review_hash
    }

    pub fn required_acknowledgement(&self) -> &'static str {
        OWNER_ATTESTATION_ACKNOWLEDGEMENT
    }
}

#[derive(Debug)]
pub struct OwnerAttestationConfirmationRequest<'a> {
    directory: PathBuf,
    plan: &'a Plan,
    review: &'a OwnerAttestationReview,
    reviewed_hash: String,
    acknowledgement: String,
}

impl<'a> OwnerAttestationConfirmationRequest<'a> {
    pub fn new(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        review: &'a OwnerAttestationReview,
        reviewed_hash: impl Into<String>,
        acknowledgement: impl Into<String>,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            review,
            reviewed_hash: reviewed_hash.into(),
            acknowledgement: acknowledgement.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAttestationRecord {
    attestation_identifier: String,
    claim_kind: OwnerAttestationClaimKind,
    claim_text: String,
    evidence_reference: String,
    confirmed_at_unix_seconds: u64,
}

impl OwnerAttestationRecord {
    pub fn classification(&self) -> &'static str {
        "owner-stated"
    }

    pub fn attestation_identifier(&self) -> &str {
        &self.attestation_identifier
    }

    pub fn claim_kind(&self) -> OwnerAttestationClaimKind {
        self.claim_kind
    }

    pub fn claim_text(&self) -> &str {
        &self.claim_text
    }

    pub fn evidence_reference(&self) -> &str {
        &self.evidence_reference
    }

    pub fn confirmed_at_unix_seconds(&self) -> u64 {
        self.confirmed_at_unix_seconds
    }

    pub fn machine_json_result(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "command": "readiness attestation confirm",
            "status": "owner-stated",
            "data": {
                "attestation_identifier": self.attestation_identifier,
                "claim_kind": self.claim_kind.machine_label(),
                "claim_text": self.claim_text,
                "evidence_reference": self.evidence_reference,
                "confirmed_at_unix_seconds": self.confirmed_at_unix_seconds,
                "classification": "owner-stated",
            },
            "warnings": ["Owner Attestation is not machine verification."],
            "errors": [],
        })
        .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnerAttestationStatus {
    attestation_identifier: String,
    claim_kind: OwnerAttestationClaimKind,
    evidence_reference: String,
    classification: &'static str,
}

impl OwnerAttestationStatus {
    pub fn attestation_identifier(&self) -> &str {
        &self.attestation_identifier
    }

    pub fn claim_kind(&self) -> OwnerAttestationClaimKind {
        self.claim_kind
    }

    pub fn evidence_reference(&self) -> &str {
        &self.evidence_reference
    }

    pub fn classification(&self) -> &'static str {
        self.classification
    }
}

#[derive(Debug)]
pub struct OwnerAttestationWithdrawalRequest<'a> {
    directory: PathBuf,
    plan: &'a Plan,
    attestation_identifier: String,
    acknowledgement: String,
}

impl<'a> OwnerAttestationWithdrawalRequest<'a> {
    pub fn new(
        directory: impl Into<PathBuf>,
        plan: &'a Plan,
        attestation_identifier: impl Into<String>,
        acknowledgement: impl Into<String>,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            attestation_identifier: attestation_identifier.into(),
            acknowledgement: acknowledgement.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAttestationWithdrawalRecord {
    attestation_identifier: String,
    withdrawn_at_unix_seconds: u64,
}

impl OwnerAttestationWithdrawalRecord {
    pub fn attestation_identifier(&self) -> &str {
        &self.attestation_identifier
    }

    pub fn withdrawn_at_unix_seconds(&self) -> u64 {
        self.withdrawn_at_unix_seconds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessEvidenceStorageTransition {
    CreateRecordCandidate,
    WriteRecordCandidate,
    SynchronizeRecordCandidate,
    PublishRecord,
    RemoveRecordCandidate,
    SynchronizeEvidenceDirectory,
}

pub trait ReadinessEvidenceStorage: Send + Sync {
    fn prepare_transition(
        &self,
        transition: ReadinessEvidenceStorageTransition,
    ) -> std::io::Result<()>;

    fn verified_copy_storage_location(
        &self,
        source: &Path,
        destination: &Path,
    ) -> std::io::Result<VerifiedCopyStorageLocation> {
        local_verified_copy_storage_location(source, destination)
    }
}

#[derive(Debug, Default)]
pub struct LocalReadinessEvidenceStorage;

impl ReadinessEvidenceStorage for LocalReadinessEvidenceStorage {
    fn prepare_transition(
        &self,
        _transition: ReadinessEvidenceStorageTransition,
    ) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadinessEvidenceEngine<G = InstalledGitPublication, S = LocalReadinessEvidenceStorage> {
    git: G,
    storage: S,
}

impl ReadinessEvidenceEngine<InstalledGitPublication, LocalReadinessEvidenceStorage> {
    pub fn local() -> Self {
        Self {
            git: InstalledGitPublication::default(),
            storage: LocalReadinessEvidenceStorage,
        }
    }
}

impl<G> ReadinessEvidenceEngine<G, LocalReadinessEvidenceStorage> {
    pub fn with_git_publication_process(git: G) -> Self {
        Self {
            git,
            storage: LocalReadinessEvidenceStorage,
        }
    }
}

impl<S> ReadinessEvidenceEngine<InstalledGitPublication, S> {
    pub fn with_storage(storage: S) -> Self {
        Self {
            git: InstalledGitPublication::default(),
            storage,
        }
    }
}

impl<G, S> ReadinessEvidenceEngine<G, S> {
    pub fn with_adapters(git: G, storage: S) -> Self {
        Self { git, storage }
    }
}

impl<G: GitPublicationProcess, S: ReadinessEvidenceStorage> ReadinessEvidenceEngine<G, S> {
    pub fn initialize(
        &self,
        request: ReadinessEvidenceInitializationRequest<'_>,
    ) -> Result<ReadinessEvidenceStoreReport, CoreError> {
        require_approved_plan(request.plan)?;
        validate_new_store_path(&request.directory)?;

        fs::create_dir(&request.directory).map_err(|error| {
            readiness_error(format!(
                "could not create private evidence directory: {error}"
            ))
        })?;
        #[cfg(unix)]
        fs::set_permissions(&request.directory, fs::Permissions::from_mode(0o700)).map_err(
            |error| readiness_error(format!("could not secure evidence directory: {error}")),
        )?;

        let plan_hash = request.plan.approval_hash()?;
        let store_identity = random_identity()?;
        let created_at_unix_seconds = now_unix_seconds()?;
        let content = StoredRecordContent {
            schema_version: RECORD_SCHEMA_VERSION,
            store_identity: store_identity.clone(),
            sequence: 0,
            previous_record_digest: None,
            occurred_at_unix_seconds: created_at_unix_seconds,
            evidence: StoredEvidence::StoreInitialized {
                plan_hash: plan_hash.clone(),
            },
        };
        let record = StoredRecord::new(content)?;
        if let Err(error) = publish_record(&self.storage, &request.directory, &record) {
            let _ = fs::remove_dir(&request.directory);
            return Err(error);
        }

        Ok(ReadinessEvidenceStoreReport {
            store_identity,
            plan_hash,
        })
    }

    pub fn record_receipt(
        &self,
        request: ReadinessReceiptRecordRequest<'_>,
    ) -> Result<ReadinessReceiptRecordReport, CoreError> {
        require_approved_plan(request.plan)?;
        let records = read_validated_records(&request.directory)?;
        let header = records
            .first()
            .ok_or_else(|| readiness_error("evidence store has no initialization record"))?;
        let plan_hash = request.plan.approval_hash()?;
        if header.content.plan_hash() != Some(plan_hash.as_str()) {
            return Err(readiness_error(
                "evidence store is bound to a different Plan",
            ));
        }

        let (operation, evidence) = match request.input {
            ReadinessReceiptInput::BundleVerification {
                bundle,
                verification,
            } => {
                if verification.plan_hash() != plan_hash {
                    return Err(readiness_error(
                        "Bundle verification is bound to a different Plan",
                    ));
                }
                let whole_file_digest = whole_file_digest(&bundle)?;
                (
                    "bundle-verification",
                    StoredEvidence::BundleVerification {
                        plan_hash,
                        bundle_identity: verification.bundle_identity().to_owned(),
                        whole_file_digest,
                    },
                )
            }
            ReadinessReceiptInput::OfflineRecovery(receipt) => (
                "offline-recovery-rehearsal",
                StoredEvidence::OfflineRecoveryRehearsal {
                    plan_hash,
                    bundle_identity: receipt.bundle_identity().to_owned(),
                    recovery_method_identity: receipt.recovery_method_identity().to_owned(),
                    verified_at_unix_seconds: receipt.verified_at_unix_seconds(),
                },
            ),
            ReadinessReceiptInput::VaultwardenRecovery(receipt) => (
                "vaultwarden-recovery-rehearsal",
                StoredEvidence::VaultwardenRecoveryRehearsal {
                    plan_hash,
                    bundle_identity: receipt.bundle_identity().to_owned(),
                    recovery_method_identity: receipt.recovery_method_identity().to_owned(),
                    item_identifier: receipt.item_identifier().as_str().to_owned(),
                    server_identity_hash: receipt.server_identity_hash().to_owned(),
                    verified_at_unix_seconds: receipt.verified_at_unix_seconds(),
                },
            ),
            ReadinessReceiptInput::VerifiedCopy(report) => (
                "verified-copy",
                StoredEvidence::VerifiedCopy {
                    plan_hash,
                    source_bundle_identity: report.source_bundle_identity().to_owned(),
                    destination_bundle_identity: report.destination_bundle_identity().to_owned(),
                    whole_file_digest: report.destination_digest().to_owned(),
                    destination_evidence_identity: report
                        .destination_evidence_identity()
                        .to_owned(),
                    durability: StoredVerifiedCopyDurability::from(report.durability()),
                    storage_location: report.storage_location(),
                    verified_at_unix_seconds: report.receipt().verified_at_unix_seconds(),
                },
            ),
            ReadinessReceiptInput::NotProtectedReport => (
                "not-protected-report",
                StoredEvidence::NotProtectedReport {
                    plan_hash,
                    coverage: CoverageEvidence::from_plan(request.plan),
                },
            ),
            ReadinessReceiptInput::ProjectCapsuleCapture(report) => {
                if !report.is_verified() {
                    return Err(readiness_error(
                        "only a verified Project Capsule capture can become Readiness Evidence",
                    ));
                }
                let expectation = report.expectation().ok_or_else(|| {
                    readiness_error(
                        "verified Project Capsule capture is missing its bound expectation",
                    )
                })?;
                if expectation.plan_hash() != plan_hash {
                    return Err(readiness_error(
                        "Project Capsule capture is bound to a different Plan",
                    ));
                }
                (
                    "project-capsule-capture",
                    StoredEvidence::ProjectCapsuleCapture {
                        plan_hash,
                        project_identity: expectation.project_id().to_owned(),
                        review_hash: expectation.review_hash().to_owned(),
                        bundle_identity: expectation.bundle_identity().to_owned(),
                        captured_at_unix_seconds: expectation.captured_unix_seconds(),
                    },
                )
            }
            ReadinessReceiptInput::ProjectCapsuleRehearsal(receipt) => {
                if !receipt.is_restorable() {
                    return Err(readiness_error(
                        "only a Restorable Project Capsule rehearsal can become Readiness Evidence",
                    ));
                }
                (
                    "project-capsule-rehearsal",
                    StoredEvidence::ProjectCapsuleRehearsal {
                        plan_hash,
                        project_identity: receipt.project_id().to_owned(),
                        bundle_identity: receipt.bundle_identity().to_owned(),
                        recovery_method: StoredRecoveryMethod::from(receipt.recovery_method()),
                    },
                )
            }
            ReadinessReceiptInput::RestoreRehearsal(report) => {
                if report.state() != RestoreState::Complete {
                    return Err(readiness_error(
                        "only a completed Restore Rehearsal can become Readiness Evidence",
                    ));
                }
                (
                    "restore-rehearsal",
                    StoredEvidence::RestoreRehearsal {
                        plan_hash,
                        bundle_identity: report.bundle_identity().to_owned(),
                        destination_evidence_identity: report
                            .destination_evidence_identity()
                            .to_owned(),
                        recovery_method: StoredRecoveryMethod::from(report.recovery_method()),
                        restored_at_unix_seconds: report.occurred_at_unix_seconds(),
                    },
                )
            }
            ReadinessReceiptInput::PushExecution(report) => {
                if report.plan_hash() != plan_hash {
                    return Err(readiness_error(
                        "Push Plan execution is bound to a different Plan",
                    ));
                }
                (
                    "push-plan-execution",
                    StoredEvidence::PushExecution {
                        plan_hash,
                        project_identity: report.project_identity().to_owned(),
                        push_plan_hash: report.push_plan_hash().to_owned(),
                        state: StoredPushExecutionState::from(report.state()),
                        remote: report.remote().to_owned(),
                        publication_proofs: report
                            .publication_proofs()
                            .iter()
                            .map(StoredPublicationProof::from)
                            .collect(),
                        executed_at_unix_seconds: report.occurred_at_unix_seconds(),
                    },
                )
            }
        };

        let previous = records
            .last()
            .ok_or_else(|| readiness_error("evidence store has no previous record"))?;
        let sequence = previous
            .content
            .sequence
            .checked_add(1)
            .ok_or_else(|| readiness_error("evidence sequence overflowed"))?;
        let content = StoredRecordContent {
            schema_version: RECORD_SCHEMA_VERSION,
            store_identity: header.content.store_identity.clone(),
            sequence,
            previous_record_digest: Some(previous.record_digest.clone()),
            occurred_at_unix_seconds: now_unix_seconds()?,
            evidence,
        };
        let record = StoredRecord::new(content)?;
        let evidence_reference = record_evidence_reference(&record);
        publish_record(&self.storage, &request.directory, &record)?;

        Ok(ReadinessReceiptRecordReport {
            operation,
            sequence,
            evidence_reference,
        })
    }

    pub fn status(
        &self,
        request: ReadinessEvidenceStatusRequest<'_>,
    ) -> Result<ReadinessEvidenceStatusReport, CoreError> {
        let records = read_validated_records(&request.directory)?;
        let header = records
            .first()
            .ok_or_else(|| readiness_error("evidence store has no initialization record"))?;
        let current_plan_hash = request.plan.approval_hash()?;
        let plan_is_current = request.plan.approval_state()? == PlanApprovalState::Approved
            && header.content.plan_hash() == Some(current_plan_hash.as_str());
        let current_coverage = CoverageEvidence::from_plan(request.plan);
        let plan_coverage = if !plan_is_current {
            ReadinessEvidenceConclusion::Invalidated
        } else if current_coverage.must_protect_blocking > 0 {
            ReadinessEvidenceConclusion::Blocking
        } else {
            ReadinessEvidenceConclusion::Current
        };
        let latest_not_protected =
            records
                .iter()
                .rev()
                .find_map(|record| match &record.content.evidence {
                    StoredEvidence::NotProtectedReport {
                        plan_hash,
                        coverage,
                    } => Some((plan_hash, coverage)),
                    _ => None,
                });
        let not_protected_report = match latest_not_protected {
            None => ReadinessEvidenceConclusion::Missing,
            Some((record_plan, coverage))
                if plan_is_current
                    && record_plan == &current_plan_hash
                    && coverage == &current_coverage =>
            {
                ReadinessEvidenceConclusion::Current
            }
            Some(_) => ReadinessEvidenceConclusion::Invalidated,
        };
        let latest_bundle =
            records
                .iter()
                .rev()
                .find_map(|record| match &record.content.evidence {
                    StoredEvidence::BundleVerification {
                        plan_hash,
                        bundle_identity,
                        whole_file_digest,
                    } => Some((plan_hash, bundle_identity, whole_file_digest)),
                    StoredEvidence::StoreInitialized { .. }
                    | StoredEvidence::OfflineRecoveryRehearsal { .. }
                    | StoredEvidence::VaultwardenRecoveryRehearsal { .. }
                    | StoredEvidence::VerifiedCopy { .. }
                    | StoredEvidence::NotProtectedReport { .. }
                    | StoredEvidence::ProjectCapsuleCapture { .. }
                    | StoredEvidence::ProjectCapsuleRehearsal { .. }
                    | StoredEvidence::RestoreRehearsal { .. }
                    | StoredEvidence::PushExecution { .. }
                    | StoredEvidence::OwnerAttestation { .. }
                    | StoredEvidence::OwnerAttestationWithdrawn { .. } => None,
                });

        let bundle_verification = match (plan_is_current, latest_bundle, request.bundle.as_ref()) {
            (false, Some(_), _) => ReadinessEvidenceConclusion::Invalidated,
            (_, None, _) | (_, Some(_), None) => ReadinessEvidenceConclusion::Missing,
            (true, Some((record_plan, record_identity, record_digest)), Some(bundle_input)) => {
                let verification = BundleEngine::local().verify(VerifyRequest::new(
                    &bundle_input.bundle,
                    bundle_input.recovery_secret,
                ));
                let current_digest = whole_file_digest(&bundle_input.bundle);
                let current_source = BundleEngine::local().revalidate_current_source(
                    request.plan,
                    &bundle_input.bundle,
                    bundle_input.recovery_secret,
                );
                match (verification, current_digest, current_source) {
                    (Ok(verification), Ok(current_digest), Ok(()))
                        if record_plan == &current_plan_hash
                            && verification.plan_hash() == current_plan_hash
                            && record_identity == verification.bundle_identity()
                            && record_digest == &current_digest =>
                    {
                        ReadinessEvidenceConclusion::Current
                    }
                    _ => ReadinessEvidenceConclusion::Invalidated,
                }
            }
        };

        let latest_offline =
            records
                .iter()
                .rev()
                .find_map(|record| match &record.content.evidence {
                    StoredEvidence::OfflineRecoveryRehearsal {
                        plan_hash,
                        bundle_identity,
                        recovery_method_identity,
                        ..
                    } => Some((plan_hash, bundle_identity, recovery_method_identity)),
                    _ => None,
                });
        let offline_recovery_method = match (
            plan_is_current,
            latest_offline,
            request.bundle.as_ref(),
            request.offline_recovery_document.as_ref(),
        ) {
            (false, Some(_), _, _) => ReadinessEvidenceConclusion::Invalidated,
            (_, None, _, _) | (_, Some(_), None, _) | (_, Some(_), _, None) => {
                ReadinessEvidenceConclusion::Missing
            }
            (
                true,
                Some((record_plan, record_bundle, record_method)),
                Some(bundle_input),
                Some(document),
            ) => match OfflineRecoveryEngine::local().rehearse(
                OfflineRecoveryRehearsalRequest::new(&bundle_input.bundle, document),
            ) {
                Ok(receipt)
                    if record_plan == &current_plan_hash
                        && record_bundle == receipt.bundle_identity()
                        && record_method == receipt.recovery_method_identity() =>
                {
                    ReadinessEvidenceConclusion::Current
                }
                _ => ReadinessEvidenceConclusion::Invalidated,
            },
        };

        let copy_records = records
            .iter()
            .filter_map(|record| match &record.content.evidence {
                StoredEvidence::VerifiedCopy {
                    plan_hash,
                    source_bundle_identity,
                    destination_bundle_identity,
                    whole_file_digest,
                    destination_evidence_identity,
                    durability,
                    storage_location,
                    ..
                } => Some((
                    plan_hash,
                    source_bundle_identity,
                    destination_bundle_identity,
                    whole_file_digest,
                    destination_evidence_identity,
                    durability,
                    storage_location,
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        let verified_copy = if copy_records.is_empty() || request.verified_copies.is_empty() {
            ReadinessEvidenceConclusion::Missing
        } else if !plan_is_current {
            ReadinessEvidenceConclusion::Invalidated
        } else if let Some(bundle_input) = request.bundle.as_ref() {
            let source = BundleEngine::local().verify(VerifyRequest::new(
                &bundle_input.bundle,
                bundle_input.recovery_secret,
            ));
            let conclusions = request
                .verified_copies
                .iter()
                .map(|copy| {
                    let current_destination_identity =
                        match verified_copy_destination_evidence_identity(copy) {
                            Ok(identity) => identity,
                            Err(_) => return ReadinessEvidenceConclusion::Invalidated,
                        };
                    let record = copy_records
                        .iter()
                        .rev()
                        .find(|record| record.4.as_str() == current_destination_identity.as_str());
                    let Some((
                        record_plan,
                        source_identity,
                        destination_identity,
                        record_digest,
                        _,
                        durability,
                        recorded_storage_location,
                    )) = record
                    else {
                        return ReadinessEvidenceConclusion::Missing;
                    };
                    let destination = BundleEngine::local()
                        .verify(VerifyRequest::new(copy, bundle_input.recovery_secret));
                    let copy_digest = whole_file_digest(copy);
                    let current_storage_location = self
                        .storage
                        .verified_copy_storage_location(&bundle_input.bundle, copy);
                    match (&source, destination, copy_digest, current_storage_location) {
                        (
                            Ok(source),
                            Ok(destination),
                            Ok(copy_digest),
                            Ok(current_storage_location),
                        ) if *record_plan == &current_plan_hash
                            && *source_identity == source.bundle_identity()
                            && *destination_identity == destination.bundle_identity()
                            && *record_digest == &copy_digest
                            && **durability == StoredVerifiedCopyDurability::Durable
                            && **recorded_storage_location == current_storage_location =>
                        {
                            ReadinessEvidenceConclusion::Current
                        }
                        _ => ReadinessEvidenceConclusion::Invalidated,
                    }
                })
                .collect::<Vec<_>>();
            if conclusions.contains(&ReadinessEvidenceConclusion::Invalidated) {
                ReadinessEvidenceConclusion::Invalidated
            } else if conclusions.contains(&ReadinessEvidenceConclusion::Missing) {
                ReadinessEvidenceConclusion::Missing
            } else {
                ReadinessEvidenceConclusion::Current
            }
        } else {
            ReadinessEvidenceConclusion::Missing
        };
        let selected_verified_copy_storage_locations = request
            .bundle
            .as_ref()
            .map(|bundle_input| {
                request
                    .verified_copies
                    .iter()
                    .filter_map(|copy| {
                        self.storage
                            .verified_copy_storage_location(&bundle_input.bundle, copy)
                            .ok()
                    })
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let latest_vaultwarden =
            records
                .iter()
                .rev()
                .find_map(|record| match &record.content.evidence {
                    StoredEvidence::VaultwardenRecoveryRehearsal {
                        plan_hash,
                        bundle_identity,
                        recovery_method_identity,
                        item_identifier,
                        server_identity_hash,
                        ..
                    } => Some((
                        plan_hash,
                        bundle_identity,
                        recovery_method_identity,
                        item_identifier,
                        server_identity_hash,
                    )),
                    _ => None,
                });
        let vaultwarden_recovery_method = match (
            plan_is_current,
            latest_vaultwarden,
            request.bundle.as_ref(),
            request.vaultwarden_recovery,
        ) {
            (false, Some(_), _, _) => ReadinessEvidenceConclusion::Invalidated,
            (_, None, _, _) | (_, Some(_), None, _) | (_, Some(_), _, None) => {
                ReadinessEvidenceConclusion::Missing
            }
            (
                true,
                Some((record_plan, bundle_identity, method_identity, item_identifier, server_hash)),
                Some(bundle_input),
                Some(loaded),
            ) => match BundleEngine::local().verify(VerifyRequest::new(
                &bundle_input.bundle,
                loaded.recovery_secret(),
            )) {
                Ok(verification)
                    if record_plan == &current_plan_hash
                        && bundle_identity == verification.bundle_identity()
                        && bundle_identity == loaded.bundle_identity()
                        && method_identity == loaded.recovery_method_identity()
                        && item_identifier == loaded.item_identifier().as_str()
                        && server_hash == loaded.server_identity_hash() =>
                {
                    ReadinessEvidenceConclusion::Current
                }
                _ => ReadinessEvidenceConclusion::Invalidated,
            },
        };
        let latest_restore =
            records
                .iter()
                .rev()
                .find_map(|record| match &record.content.evidence {
                    StoredEvidence::RestoreRehearsal {
                        plan_hash,
                        bundle_identity,
                        destination_evidence_identity,
                        recovery_method,
                        ..
                    } => Some((
                        plan_hash,
                        bundle_identity,
                        destination_evidence_identity,
                        recovery_method,
                    )),
                    _ => None,
                });
        let restore_rehearsal = match (
            plan_is_current,
            latest_restore,
            request.bundle.as_ref(),
            request.restore_rehearsal_destination.as_ref(),
        ) {
            (false, Some(_), _, _) => ReadinessEvidenceConclusion::Invalidated,
            (_, None, _, _) | (_, Some(_), None, _) | (_, Some(_), _, None) => {
                ReadinessEvidenceConclusion::Missing
            }
            (
                true,
                Some((record_plan, bundle_identity, destination_identity, recovery_method)),
                Some(bundle_input),
                Some(destination),
            ) => {
                let verification = BundleEngine::local().verify(VerifyRequest::new(
                    &bundle_input.bundle,
                    bundle_input.recovery_secret,
                ));
                let current_destination =
                    current_restore_destination_evidence_identity(destination);
                match (verification, current_destination) {
                    (Ok(verification), Ok(current_destination))
                        if record_plan == &current_plan_hash
                            && bundle_identity == verification.bundle_identity()
                            && destination_identity == &current_destination
                            && *recovery_method
                                == StoredRecoveryMethod::from(
                                    bundle_input.recovery_secret.method(),
                                ) =>
                    {
                        ReadinessEvidenceConclusion::Current
                    }
                    _ => ReadinessEvidenceConclusion::Invalidated,
                }
            }
        };

        let (active_owner_attestations, withdrawn_owner_attestation_identifiers) =
            active_attestation_status(&records)?;

        let current_project_audit =
            ProjectAuditEngine::local().audit(ProjectAuditRequest::from_plan(request.plan))?;
        let required_project_identities = current_project_audit
            .projects()
            .iter()
            .filter(|project| {
                project.protection_requirement() == ProtectionRequirement::MustProtect
            })
            .map(|project| project.id().to_owned())
            .collect::<BTreeSet<_>>();
        let mut projects_by_identity = current_project_audit
            .projects()
            .iter()
            .map(|project| {
                (
                    project.id().to_owned(),
                    ReadinessProjectEvidence {
                        project_identity: project.id().to_owned(),
                        restorable: ReadinessEvidenceConclusion::Missing,
                        synchronized: ReadinessEvidenceConclusion::Missing,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        for input in &request.project_capsules {
            let project_identity = input.expectation.project_id();
            let latest_capture =
                records
                    .iter()
                    .rev()
                    .find_map(|record| match &record.content.evidence {
                        StoredEvidence::ProjectCapsuleCapture {
                            plan_hash,
                            project_identity: record_project,
                            review_hash,
                            bundle_identity,
                            captured_at_unix_seconds,
                        } if record_project == project_identity => Some((
                            plan_hash,
                            review_hash,
                            bundle_identity,
                            captured_at_unix_seconds,
                        )),
                        _ => None,
                    });
            let latest_rehearsal =
                records
                    .iter()
                    .rev()
                    .find_map(|record| match &record.content.evidence {
                        StoredEvidence::ProjectCapsuleRehearsal {
                            plan_hash,
                            project_identity: record_project,
                            bundle_identity,
                            recovery_method,
                        } if record_project == project_identity => {
                            Some((plan_hash, bundle_identity, recovery_method))
                        }
                        _ => None,
                    });
            let restorable = if !plan_is_current
                || input.expectation.plan_hash() != current_plan_hash
            {
                ReadinessEvidenceConclusion::Invalidated
            } else {
                match (latest_capture, latest_rehearsal) {
                    (None, _) | (_, None) => ReadinessEvidenceConclusion::Missing,
                    (
                        Some((capture_plan, capture_review, capture_bundle, capture_time)),
                        Some((rehearsal_plan, rehearsal_bundle, recovery_method)),
                    ) => match BundleEngine::local()
                        .verify(VerifyRequest::new(&input.bundle, input.recovery_secret))
                    {
                        Ok(verification)
                            if capture_plan == &current_plan_hash
                                && capture_review == input.expectation.review_hash()
                                && capture_bundle == input.expectation.bundle_identity()
                                && capture_time == &input.expectation.captured_unix_seconds()
                                && rehearsal_plan == &current_plan_hash
                                && rehearsal_bundle == input.expectation.bundle_identity()
                                && *recovery_method
                                    == StoredRecoveryMethod::from(
                                        input.recovery_secret.method(),
                                    )
                                && verification.bundle_identity()
                                    == input.expectation.bundle_identity() =>
                        {
                            ReadinessEvidenceConclusion::Current
                        }
                        _ => ReadinessEvidenceConclusion::Invalidated,
                    },
                }
            };
            projects_by_identity
                .entry(project_identity.to_owned())
                .and_modify(|evidence| evidence.restorable = restorable)
                .or_insert_with(|| ReadinessProjectEvidence {
                    project_identity: project_identity.to_owned(),
                    restorable,
                    synchronized: ReadinessEvidenceConclusion::Missing,
                });
        }
        for project in &request.project_publications {
            let has_local_only_references = !project.local_state().local_only_branches().is_empty()
                || !project.local_state().local_only_tags().is_empty();
            let latest_capsule_reference =
                records
                    .iter()
                    .rev()
                    .find_map(|record| match &record.content.evidence {
                        StoredEvidence::ProjectCapsuleCapture {
                            project_identity, ..
                        } if project_identity == project.id() => {
                            Some(record_evidence_reference(record))
                        }
                        _ => None,
                    });
            let capsule_only_decision_is_current = latest_capsule_reference.as_deref().is_some_and(
                |reference| {
                    active_owner_attestations.iter().any(|attestation| {
                        attestation.claim_kind
                            == OwnerAttestationClaimKind::LocalOnlyProjectReferencesRetainedInProjectCapsule
                            && attestation.evidence_reference == reference
                    })
                },
            );
            let capsule_protection_is_current =
                projects_by_identity
                    .get(project.id())
                    .is_some_and(|evidence| {
                        evidence.restorable == ReadinessEvidenceConclusion::Current
                    });
            let latest_execution =
                records
                    .iter()
                    .rev()
                    .find_map(|record| match &record.content.evidence {
                        StoredEvidence::PushExecution {
                            plan_hash,
                            project_identity,
                            state,
                            remote,
                            publication_proofs,
                            ..
                        } if project_identity == project.id() => {
                            Some((plan_hash, state, remote, publication_proofs))
                        }
                        _ => None,
                    });
            let synchronized = match latest_execution {
                None if project.local_state().ahead() == Some(0)
                    && project.local_state().behind() == Some(0)
                    && (!has_local_only_references
                        || (capsule_protection_is_current && capsule_only_decision_is_current)) =>
                {
                    match revalidate_already_synchronized_project(&self.git, project) {
                        Ok(()) => ReadinessEvidenceConclusion::Current,
                        Err(_) => ReadinessEvidenceConclusion::Invalidated,
                    }
                }
                None => ReadinessEvidenceConclusion::Missing,
                Some((record_plan, state, remote, stored_proofs))
                    if plan_is_current
                        && record_plan == &current_plan_hash
                        && *state == StoredPushExecutionState::Complete =>
                {
                    let proofs = stored_proofs
                        .iter()
                        .map(PushPublicationProof::from)
                        .collect::<Vec<_>>();
                    match revalidate_synchronized_project(&self.git, project, remote, &proofs) {
                        Ok(()) => ReadinessEvidenceConclusion::Current,
                        Err(_) => ReadinessEvidenceConclusion::Invalidated,
                    }
                }
                Some(_) => ReadinessEvidenceConclusion::Invalidated,
            };
            let synchronized = if has_local_only_references
                && !(capsule_protection_is_current && capsule_only_decision_is_current)
            {
                ReadinessEvidenceConclusion::Missing
            } else {
                synchronized
            };
            projects_by_identity
                .entry(project.id().to_owned())
                .and_modify(|evidence| evidence.synchronized = synchronized)
                .or_insert_with(|| ReadinessProjectEvidence {
                    project_identity: project.id().to_owned(),
                    restorable: ReadinessEvidenceConclusion::Missing,
                    synchronized,
                });
        }
        let projects = projects_by_identity.into_values().collect::<Vec<_>>();

        let mut blocking_gaps = Vec::new();
        if current_coverage.must_protect_blocking > 0 {
            blocking_gaps.push(ReadinessEvidenceGap {
                code: "must-protect-coverage-unresolved",
                count: current_coverage.must_protect_blocking,
            });
        }
        push_conclusion_gap(
            &mut blocking_gaps,
            "plan-coverage-not-current",
            plan_coverage,
        );
        push_conclusion_gap(
            &mut blocking_gaps,
            "bundle-verification-not-current",
            bundle_verification,
        );
        push_conclusion_gap(
            &mut blocking_gaps,
            "offline-recovery-method-not-current",
            offline_recovery_method,
        );
        push_conclusion_gap(
            &mut blocking_gaps,
            "vaultwarden-recovery-method-not-current",
            vaultwarden_recovery_method,
        );
        push_conclusion_gap(
            &mut blocking_gaps,
            "verified-copies-not-current",
            verified_copy,
        );
        let missing_verified_copy_storage_locations = [
            VerifiedCopyStorageLocation::ExternalStorage,
            VerifiedCopyStorageLocation::ICloudDrive,
        ]
        .into_iter()
        .filter(|required| !selected_verified_copy_storage_locations.contains(required))
        .count();
        if missing_verified_copy_storage_locations > 0 {
            blocking_gaps.push(ReadinessEvidenceGap {
                code: "two-independent-verified-copies-required",
                count: missing_verified_copy_storage_locations as u64,
            });
        }
        push_conclusion_gap(
            &mut blocking_gaps,
            "restore-rehearsal-not-current",
            restore_rehearsal,
        );
        push_conclusion_gap(
            &mut blocking_gaps,
            "not-protected-report-not-current",
            not_protected_report,
        );
        let required_attestations = [
            OwnerAttestationClaimKind::ConventionalBackupValidated,
            OwnerAttestationClaimKind::RepresentativeRestoredProjectBuildCompleted,
            OwnerAttestationClaimKind::SecondEnvironmentRehearsalCompleted,
            OwnerAttestationClaimKind::NotProtectedReportReviewed,
            OwnerAttestationClaimKind::ReviewedExternalVaultwardenServiceConfirmed,
            OwnerAttestationClaimKind::FreshDeviceVaultwardenAccessConfirmed,
            OwnerAttestationClaimKind::IndependentMultiFactorRecoveryPathConfirmed,
        ];
        let missing_attestations = required_attestations
            .iter()
            .filter(|required| {
                !active_owner_attestations.iter().any(|active| {
                    active.claim_kind == **required
                        && owner_attestation_references_current_evidence(active, &records)
                })
            })
            .count();
        let contradictory_attestations = required_attestations
            .iter()
            .map(|required| {
                active_owner_attestations
                    .iter()
                    .filter(|active| {
                        active.claim_kind == *required
                            && owner_attestation_references_current_evidence(active, &records)
                    })
                    .count()
                    .saturating_sub(1)
            })
            .sum::<usize>();
        if missing_attestations > 0 {
            blocking_gaps.push(ReadinessEvidenceGap {
                code: "required-owner-attestations-missing",
                count: missing_attestations as u64,
            });
        }
        if contradictory_attestations > 0 {
            blocking_gaps.push(ReadinessEvidenceGap {
                code: "contradictory-owner-attestations",
                count: contradictory_attestations as u64,
            });
        }
        let projects_not_restorable = projects
            .iter()
            .filter(|project| {
                required_project_identities.contains(&project.project_identity)
                    && project.restorable != ReadinessEvidenceConclusion::Current
            })
            .count();
        if projects_not_restorable > 0 {
            blocking_gaps.push(ReadinessEvidenceGap {
                code: "required-projects-not-restorable",
                count: projects_not_restorable as u64,
            });
        }
        let projects_not_synchronized = projects
            .iter()
            .filter(|project| {
                required_project_identities.contains(&project.project_identity)
                    && project.synchronized != ReadinessEvidenceConclusion::Current
            })
            .count();
        if projects_not_synchronized > 0 {
            blocking_gaps.push(ReadinessEvidenceGap {
                code: "required-projects-not-synchronized",
                count: projects_not_synchronized as u64,
            });
        }

        let state = if blocking_gaps.is_empty() {
            ReadinessEvidenceState::CompleteEvidence
        } else {
            ReadinessEvidenceState::BlockingGaps
        };
        let events = vec![ReadinessEvidenceEvent {
            state,
            bundle_verification,
        }];
        Ok(ReadinessEvidenceStatusReport {
            state,
            plan_coverage,
            bundle_verification,
            offline_recovery_method,
            vaultwarden_recovery_method,
            verified_copy,
            not_protected_report,
            restore_rehearsal,
            blocking_gaps,
            active_owner_attestations,
            withdrawn_owner_attestation_identifiers,
            projects,
            events,
        })
    }

    pub fn prepare_attestation(
        &self,
        request: OwnerAttestationPreparationRequest<'_>,
    ) -> Result<OwnerAttestationReview, CoreError> {
        require_approved_plan(request.plan)?;
        validate_evidence_reference(&request.evidence_reference)?;
        let records = read_validated_records(&request.directory)?;
        let header = records
            .first()
            .ok_or_else(|| readiness_error("evidence store has no initialization record"))?;
        let plan_hash = request.plan.approval_hash()?;
        if header.content.plan_hash() != Some(plan_hash.as_str()) {
            return Err(readiness_error(
                "evidence store is bound to a different Plan",
            ));
        }
        let required_current_reference = match request.claim_kind {
            OwnerAttestationClaimKind::NotProtectedReportReviewed => {
                latest_evidence_reference(&records, |evidence| {
                    matches!(evidence, StoredEvidence::NotProtectedReport { .. })
                })
            }
            OwnerAttestationClaimKind::ReviewedExternalVaultwardenServiceConfirmed
            | OwnerAttestationClaimKind::FreshDeviceVaultwardenAccessConfirmed
            | OwnerAttestationClaimKind::IndependentMultiFactorRecoveryPathConfirmed => {
                latest_evidence_reference(&records, |evidence| {
                    matches!(
                        evidence,
                        StoredEvidence::VaultwardenRecoveryRehearsal { .. }
                    )
                })
            }
            OwnerAttestationClaimKind::RepresentativeRestoredProjectBuildCompleted => {
                latest_evidence_reference(&records, |evidence| {
                    matches!(evidence, StoredEvidence::ProjectCapsuleRehearsal { .. })
                })
            }
            OwnerAttestationClaimKind::SecondEnvironmentRehearsalCompleted => {
                latest_evidence_reference(&records, |evidence| {
                    matches!(evidence, StoredEvidence::RestoreRehearsal { .. })
                })
            }
            OwnerAttestationClaimKind::ConventionalBackupValidated
            | OwnerAttestationClaimKind::LocalOnlyProjectReferencesRetainedInProjectCapsule => None,
        };
        if matches!(
            request.claim_kind,
            OwnerAttestationClaimKind::NotProtectedReportReviewed
                | OwnerAttestationClaimKind::ReviewedExternalVaultwardenServiceConfirmed
                | OwnerAttestationClaimKind::FreshDeviceVaultwardenAccessConfirmed
                | OwnerAttestationClaimKind::IndependentMultiFactorRecoveryPathConfirmed
                | OwnerAttestationClaimKind::RepresentativeRestoredProjectBuildCompleted
                | OwnerAttestationClaimKind::SecondEnvironmentRehearsalCompleted
        ) && required_current_reference.as_deref() != Some(request.evidence_reference.as_str())
        {
            return Err(readiness_error(
                "Owner Attestation does not reference the current typed evidence Receipt",
            ));
        }
        if request.claim_kind
            == OwnerAttestationClaimKind::LocalOnlyProjectReferencesRetainedInProjectCapsule
        {
            let references_current_capsule = records.iter().rev().any(|record| {
                matches!(
                    record.content.evidence,
                    StoredEvidence::ProjectCapsuleCapture { .. }
                ) && record_evidence_reference(record) == request.evidence_reference
                    && !records
                        .iter()
                        .skip(record.content.sequence as usize + 1)
                        .any(
                            |later| match (&record.content.evidence, &later.content.evidence) {
                                (
                                    StoredEvidence::ProjectCapsuleCapture {
                                        project_identity, ..
                                    },
                                    StoredEvidence::ProjectCapsuleCapture {
                                        project_identity: later_project,
                                        ..
                                    },
                                ) => project_identity == later_project,
                                _ => false,
                            },
                        )
            });
            if !references_current_capsule {
                return Err(readiness_error(
                    "capsule-only Owner Attestation does not reference the current Project Capsule capture",
                ));
            }
        }
        let prepared_at_unix_seconds = now_unix_seconds()?;
        let mut review = OwnerAttestationReview {
            store_identity: header.content.store_identity.clone(),
            plan_hash,
            claim_kind: request.claim_kind,
            claim_text: request.claim_kind.claim_text().to_owned(),
            evidence_reference: request.evidence_reference,
            prepared_at_unix_seconds,
            review_hash: String::new(),
        };
        review.review_hash = owner_attestation_review_hash(&review)?;
        Ok(review)
    }

    pub fn confirm_attestation(
        &self,
        request: OwnerAttestationConfirmationRequest<'_>,
    ) -> Result<OwnerAttestationRecord, CoreError> {
        require_approved_plan(request.plan)?;
        let records = read_validated_records(&request.directory)?;
        let header = records
            .first()
            .ok_or_else(|| readiness_error("evidence store has no initialization record"))?;
        let plan_hash = request.plan.approval_hash()?;
        if header.content.store_identity != request.review.store_identity
            || header.content.plan_hash() != Some(plan_hash.as_str())
            || request.review.plan_hash != plan_hash
            || request.review.claim_text != request.review.claim_kind.claim_text()
            || request.review.review_hash != owner_attestation_review_hash(request.review)?
            || request.reviewed_hash != request.review.review_hash
            || request.acknowledgement != OWNER_ATTESTATION_ACKNOWLEDGEMENT
        {
            return Err(readiness_error(
                "Owner Attestation confirmation does not match the exact review",
            ));
        }

        let confirmed_at_unix_seconds = now_unix_seconds()?;
        let attestation_identifier = format!("attestation_{}", random_identity()?);
        let previous = records
            .last()
            .ok_or_else(|| readiness_error("evidence store has no previous record"))?;
        let sequence = previous
            .content
            .sequence
            .checked_add(1)
            .ok_or_else(|| readiness_error("evidence sequence overflowed"))?;
        let content = StoredRecordContent {
            schema_version: RECORD_SCHEMA_VERSION,
            store_identity: header.content.store_identity.clone(),
            sequence,
            previous_record_digest: Some(previous.record_digest.clone()),
            occurred_at_unix_seconds: confirmed_at_unix_seconds,
            evidence: StoredEvidence::OwnerAttestation {
                plan_hash,
                attestation_identifier: attestation_identifier.clone(),
                claim_kind: request.review.claim_kind,
                claim_text: request.review.claim_text.clone(),
                evidence_reference: request.review.evidence_reference.clone(),
                review_hash: request.review.review_hash.clone(),
                owner_confirmed: true,
            },
        };
        publish_record(
            &self.storage,
            &request.directory,
            &StoredRecord::new(content)?,
        )?;

        Ok(OwnerAttestationRecord {
            attestation_identifier,
            claim_kind: request.review.claim_kind,
            claim_text: request.review.claim_text.clone(),
            evidence_reference: request.review.evidence_reference.clone(),
            confirmed_at_unix_seconds,
        })
    }

    pub fn withdraw_attestation(
        &self,
        request: OwnerAttestationWithdrawalRequest<'_>,
    ) -> Result<OwnerAttestationWithdrawalRecord, CoreError> {
        require_approved_plan(request.plan)?;
        if request.acknowledgement != OWNER_ATTESTATION_WITHDRAWAL_ACKNOWLEDGEMENT {
            return Err(readiness_error(
                "Owner Attestation withdrawal acknowledgement did not match",
            ));
        }
        let records = read_validated_records(&request.directory)?;
        let header = records
            .first()
            .ok_or_else(|| readiness_error("evidence store has no initialization record"))?;
        let plan_hash = request.plan.approval_hash()?;
        if header.content.plan_hash() != Some(plan_hash.as_str()) {
            return Err(readiness_error(
                "evidence store is bound to a different Plan",
            ));
        }
        let (active, _) = active_attestation_status(&records)?;
        if !active
            .iter()
            .any(|attestation| attestation.attestation_identifier == request.attestation_identifier)
        {
            return Err(readiness_error(
                "Owner Attestation is not active in this evidence store",
            ));
        }

        let withdrawn_at_unix_seconds = now_unix_seconds()?;
        let previous = records
            .last()
            .ok_or_else(|| readiness_error("evidence store has no previous record"))?;
        let sequence = previous
            .content
            .sequence
            .checked_add(1)
            .ok_or_else(|| readiness_error("evidence sequence overflowed"))?;
        let content = StoredRecordContent {
            schema_version: RECORD_SCHEMA_VERSION,
            store_identity: header.content.store_identity.clone(),
            sequence,
            previous_record_digest: Some(previous.record_digest.clone()),
            occurred_at_unix_seconds: withdrawn_at_unix_seconds,
            evidence: StoredEvidence::OwnerAttestationWithdrawn {
                plan_hash,
                attestation_identifier: request.attestation_identifier.clone(),
            },
        };
        publish_record(
            &self.storage,
            &request.directory,
            &StoredRecord::new(content)?,
        )?;

        Ok(OwnerAttestationWithdrawalRecord {
            attestation_identifier: request.attestation_identifier,
            withdrawn_at_unix_seconds,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    content: StoredRecordContent,
    record_digest: String,
}

impl StoredRecord {
    fn new(content: StoredRecordContent) -> Result<Self, CoreError> {
        let record_digest = record_digest(&content)?;
        Ok(Self {
            content,
            record_digest,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecordContent {
    schema_version: u32,
    store_identity: String,
    sequence: u64,
    previous_record_digest: Option<String>,
    occurred_at_unix_seconds: u64,
    evidence: StoredEvidence,
}

impl StoredRecordContent {
    fn plan_hash(&self) -> Option<&str> {
        match &self.evidence {
            StoredEvidence::StoreInitialized { plan_hash }
            | StoredEvidence::BundleVerification { plan_hash, .. }
            | StoredEvidence::OfflineRecoveryRehearsal { plan_hash, .. }
            | StoredEvidence::VaultwardenRecoveryRehearsal { plan_hash, .. }
            | StoredEvidence::VerifiedCopy { plan_hash, .. }
            | StoredEvidence::NotProtectedReport { plan_hash, .. }
            | StoredEvidence::ProjectCapsuleCapture { plan_hash, .. }
            | StoredEvidence::ProjectCapsuleRehearsal { plan_hash, .. }
            | StoredEvidence::RestoreRehearsal { plan_hash, .. }
            | StoredEvidence::PushExecution { plan_hash, .. }
            | StoredEvidence::OwnerAttestation { plan_hash, .. }
            | StoredEvidence::OwnerAttestationWithdrawn { plan_hash, .. } => Some(plan_hash),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum StoredVerifiedCopyDurability {
    Durable,
    Weaker,
}

impl From<VerifiedCopyDurability> for StoredVerifiedCopyDurability {
    fn from(value: VerifiedCopyDurability) -> Self {
        match value {
            VerifiedCopyDurability::Durable => Self::Durable,
            VerifiedCopyDurability::Weaker => Self::Weaker,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum StoredRecoveryMethod {
    Vaultwarden,
    Offline,
}

impl From<RecoveryMethod> for StoredRecoveryMethod {
    fn from(value: RecoveryMethod) -> Self {
        match value {
            RecoveryMethod::Vaultwarden => Self::Vaultwarden,
            RecoveryMethod::Offline => Self::Offline,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum StoredPushExecutionState {
    Complete,
    Partial,
}

impl From<PushExecutionState> for StoredPushExecutionState {
    fn from(value: PushExecutionState) -> Self {
        match value {
            PushExecutionState::Complete => Self::Complete,
            PushExecutionState::Partial => Self::Partial,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum StoredEvidence {
    StoreInitialized {
        plan_hash: String,
    },
    BundleVerification {
        plan_hash: String,
        bundle_identity: String,
        whole_file_digest: String,
    },
    OfflineRecoveryRehearsal {
        plan_hash: String,
        bundle_identity: String,
        recovery_method_identity: String,
        verified_at_unix_seconds: u64,
    },
    VaultwardenRecoveryRehearsal {
        plan_hash: String,
        bundle_identity: String,
        recovery_method_identity: String,
        item_identifier: String,
        server_identity_hash: String,
        verified_at_unix_seconds: u64,
    },
    VerifiedCopy {
        plan_hash: String,
        source_bundle_identity: String,
        destination_bundle_identity: String,
        whole_file_digest: String,
        destination_evidence_identity: String,
        durability: StoredVerifiedCopyDurability,
        storage_location: VerifiedCopyStorageLocation,
        verified_at_unix_seconds: u64,
    },
    NotProtectedReport {
        plan_hash: String,
        coverage: CoverageEvidence,
    },
    ProjectCapsuleCapture {
        plan_hash: String,
        project_identity: String,
        review_hash: String,
        bundle_identity: String,
        captured_at_unix_seconds: u64,
    },
    ProjectCapsuleRehearsal {
        plan_hash: String,
        project_identity: String,
        bundle_identity: String,
        recovery_method: StoredRecoveryMethod,
    },
    RestoreRehearsal {
        plan_hash: String,
        bundle_identity: String,
        destination_evidence_identity: String,
        recovery_method: StoredRecoveryMethod,
        restored_at_unix_seconds: u64,
    },
    PushExecution {
        plan_hash: String,
        project_identity: String,
        push_plan_hash: String,
        state: StoredPushExecutionState,
        remote: String,
        publication_proofs: Vec<StoredPublicationProof>,
        executed_at_unix_seconds: u64,
    },
    OwnerAttestation {
        plan_hash: String,
        attestation_identifier: String,
        claim_kind: OwnerAttestationClaimKind,
        claim_text: String,
        evidence_reference: String,
        review_hash: String,
        owner_confirmed: bool,
    },
    OwnerAttestationWithdrawn {
        plan_hash: String,
        attestation_identifier: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPublicationProof {
    local_reference: String,
    remote_reference: String,
    proposed_new_remote_object: String,
}

impl From<&PushPublicationProof> for StoredPublicationProof {
    fn from(proof: &PushPublicationProof) -> Self {
        Self {
            local_reference: proof.local_reference.clone(),
            remote_reference: proof.remote_reference.clone(),
            proposed_new_remote_object: proof.proposed_new_remote_object.clone(),
        }
    }
}

impl From<&StoredPublicationProof> for PushPublicationProof {
    fn from(proof: &StoredPublicationProof) -> Self {
        Self {
            local_reference: proof.local_reference.clone(),
            remote_reference: proof.remote_reference.clone(),
            proposed_new_remote_object: proof.proposed_new_remote_object.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageEvidence {
    included: u64,
    excluded: u64,
    requires_review: u64,
    unsupported: u64,
    unavailable: u64,
    must_protect_blocking: u64,
    optional_warnings: u64,
}

impl CoverageEvidence {
    fn from_plan(plan: &Plan) -> Self {
        let coverage = plan.coverage_summary();
        Self {
            included: coverage.included,
            excluded: coverage.excluded,
            requires_review: coverage.requires_review,
            unsupported: coverage.unsupported,
            unavailable: coverage.unavailable,
            must_protect_blocking: coverage.must_protect_blocking,
            optional_warnings: coverage.optional_warnings,
        }
    }
}

fn active_attestation_status(
    records: &[StoredRecord],
) -> Result<(Vec<OwnerAttestationStatus>, Vec<String>), CoreError> {
    let mut active = BTreeMap::new();
    let mut withdrawn = Vec::new();
    for record in records {
        match &record.content.evidence {
            StoredEvidence::OwnerAttestation {
                attestation_identifier,
                claim_kind,
                claim_text,
                evidence_reference,
                owner_confirmed,
                ..
            } => {
                if !owner_confirmed || claim_text != claim_kind.claim_text() {
                    return Err(readiness_error("Owner Attestation record is invalid"));
                }
                let status = OwnerAttestationStatus {
                    attestation_identifier: attestation_identifier.clone(),
                    claim_kind: *claim_kind,
                    evidence_reference: evidence_reference.clone(),
                    classification: "owner-stated",
                };
                if active
                    .insert(attestation_identifier.clone(), status)
                    .is_some()
                {
                    return Err(readiness_error(
                        "duplicate Owner Attestation identifier blocks status",
                    ));
                }
            }
            StoredEvidence::OwnerAttestationWithdrawn {
                attestation_identifier,
                ..
            } => {
                if active.remove(attestation_identifier).is_none() {
                    return Err(readiness_error(
                        "withdrawal does not reference an active Owner Attestation",
                    ));
                }
                withdrawn.push(attestation_identifier.clone());
            }
            StoredEvidence::StoreInitialized { .. }
            | StoredEvidence::BundleVerification { .. }
            | StoredEvidence::OfflineRecoveryRehearsal { .. }
            | StoredEvidence::VaultwardenRecoveryRehearsal { .. }
            | StoredEvidence::VerifiedCopy { .. }
            | StoredEvidence::NotProtectedReport { .. }
            | StoredEvidence::ProjectCapsuleCapture { .. }
            | StoredEvidence::ProjectCapsuleRehearsal { .. }
            | StoredEvidence::RestoreRehearsal { .. }
            | StoredEvidence::PushExecution { .. } => {}
        }
    }
    Ok((active.into_values().collect(), withdrawn))
}

fn owner_attestation_references_current_evidence(
    attestation: &OwnerAttestationStatus,
    records: &[StoredRecord],
) -> bool {
    match attestation.claim_kind {
        OwnerAttestationClaimKind::NotProtectedReportReviewed => {
            latest_evidence_reference(records, |evidence| {
                matches!(evidence, StoredEvidence::NotProtectedReport { .. })
            })
            .is_some_and(|reference| reference == attestation.evidence_reference)
        }
        OwnerAttestationClaimKind::ReviewedExternalVaultwardenServiceConfirmed
        | OwnerAttestationClaimKind::FreshDeviceVaultwardenAccessConfirmed
        | OwnerAttestationClaimKind::IndependentMultiFactorRecoveryPathConfirmed => {
            latest_evidence_reference(records, |evidence| {
                matches!(
                    evidence,
                    StoredEvidence::VaultwardenRecoveryRehearsal { .. }
                )
            })
            .is_some_and(|reference| reference == attestation.evidence_reference)
        }
        OwnerAttestationClaimKind::RepresentativeRestoredProjectBuildCompleted => {
            latest_evidence_reference(records, |evidence| {
                matches!(evidence, StoredEvidence::ProjectCapsuleRehearsal { .. })
            })
            .is_some_and(|reference| reference == attestation.evidence_reference)
        }
        OwnerAttestationClaimKind::SecondEnvironmentRehearsalCompleted => {
            latest_evidence_reference(records, |evidence| {
                matches!(evidence, StoredEvidence::RestoreRehearsal { .. })
            })
            .is_some_and(|reference| reference == attestation.evidence_reference)
        }
        OwnerAttestationClaimKind::ConventionalBackupValidated => true,
        OwnerAttestationClaimKind::LocalOnlyProjectReferencesRetainedInProjectCapsule => records
            .iter()
            .rev()
            .find(|record| {
                record_evidence_reference(record) == attestation.evidence_reference
                    && matches!(
                        record.content.evidence,
                        StoredEvidence::ProjectCapsuleCapture { .. }
                    )
            })
            .is_some_and(|record| {
                let StoredEvidence::ProjectCapsuleCapture {
                    project_identity, ..
                } = &record.content.evidence
                else {
                    return false;
                };
                !records
                    .iter()
                    .skip(record.content.sequence as usize + 1)
                    .any(|later| {
                        matches!(
                            &later.content.evidence,
                            StoredEvidence::ProjectCapsuleCapture {
                                project_identity: later_project,
                                ..
                            } if later_project == project_identity
                        )
                    })
            }),
    }
}

fn latest_evidence_reference(
    records: &[StoredRecord],
    matches_evidence: impl Fn(&StoredEvidence) -> bool,
) -> Option<String> {
    records
        .iter()
        .rev()
        .find(|record| matches_evidence(&record.content.evidence))
        .map(record_evidence_reference)
}

fn require_approved_plan(plan: &Plan) -> Result<(), CoreError> {
    if plan.approval_state()? != PlanApprovalState::Approved {
        return Err(readiness_error(
            "Readiness Evidence requires an approved, current Plan",
        ));
    }
    Ok(())
}

fn push_conclusion_gap(
    gaps: &mut Vec<ReadinessEvidenceGap>,
    code: &'static str,
    conclusion: ReadinessEvidenceConclusion,
) {
    if conclusion != ReadinessEvidenceConclusion::Current {
        gaps.push(ReadinessEvidenceGap { code, count: 1 });
    }
}

fn validate_new_store_path(directory: &Path) -> Result<(), CoreError> {
    if fs::symlink_metadata(directory).is_ok() {
        return Err(readiness_error("evidence directory already exists"));
    }
    let parent = directory
        .parent()
        .ok_or_else(|| readiness_error("evidence directory must have a private parent"))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| readiness_error("evidence directory parent is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(readiness_error(
            "evidence directory parent must be a real directory",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(readiness_error("evidence directory parent is not private"));
    }
    Ok(())
}

fn publish_record(
    storage: &impl ReadinessEvidenceStorage,
    directory: &Path,
    record: &StoredRecord,
) -> Result<(), CoreError> {
    let bytes = serde_json::to_vec(record)
        .map_err(|_| readiness_error("could not encode canonical evidence record"))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(readiness_error("evidence record exceeds the size limit"));
    }
    let final_name = record_file_name(record.content.sequence, &record.record_digest);
    let final_path = directory.join(final_name);
    let candidate_path = directory.join(format!(
        "{:020}-{}.json.incomplete",
        record.content.sequence, record.record_digest
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    prepare_storage_transition(
        storage,
        ReadinessEvidenceStorageTransition::CreateRecordCandidate,
    )?;
    let mut candidate = options
        .open(&candidate_path)
        .map_err(|_| readiness_error("could not create exclusive evidence candidate"))?;
    prepare_storage_transition(
        storage,
        ReadinessEvidenceStorageTransition::WriteRecordCandidate,
    )?;
    candidate
        .write_all(&bytes)
        .map_err(|_| readiness_error("could not write evidence candidate"))?;
    prepare_storage_transition(
        storage,
        ReadinessEvidenceStorageTransition::SynchronizeRecordCandidate,
    )?;
    candidate
        .sync_all()
        .map_err(|_| readiness_error("could not synchronize evidence candidate"))?;
    prepare_storage_transition(storage, ReadinessEvidenceStorageTransition::PublishRecord)?;
    fs::hard_link(&candidate_path, &final_path)
        .map_err(|_| readiness_error("could not publish evidence record without overwrite"))?;
    prepare_storage_transition(
        storage,
        ReadinessEvidenceStorageTransition::SynchronizeEvidenceDirectory,
    )?;
    File::open(directory)
        .and_then(|directory_file| directory_file.sync_all())
        .map_err(|_| readiness_error("could not synchronize evidence directory"))?;
    prepare_storage_transition(
        storage,
        ReadinessEvidenceStorageTransition::RemoveRecordCandidate,
    )?;
    fs::remove_file(&candidate_path)
        .map_err(|_| readiness_error("could not remove published evidence candidate"))?;
    Ok(())
}

fn prepare_storage_transition(
    storage: &impl ReadinessEvidenceStorage,
    transition: ReadinessEvidenceStorageTransition,
) -> Result<(), CoreError> {
    storage
        .prepare_transition(transition)
        .map_err(|_| readiness_error("evidence storage transition failed"))
}

fn read_validated_records(directory: &Path) -> Result<Vec<StoredRecord>, CoreError> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| readiness_error("evidence directory is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(readiness_error("evidence store is not a real directory"));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(readiness_error("evidence directory is not private"));
    }

    let mut paths = fs::read_dir(directory)
        .map_err(|_| readiness_error("could not enumerate evidence records"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| readiness_error("could not enumerate evidence records"))?;
    if paths.len() > MAX_RECORDS {
        return Err(readiness_error("evidence record count exceeds the limit"));
    }
    paths.sort_by_key(|entry| entry.file_name());

    let mut records = Vec::with_capacity(paths.len());
    for entry in paths {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| readiness_error("evidence record name is not portable"))?;
        if name.ends_with(".incomplete") {
            return Err(readiness_error(
                "incomplete evidence candidate blocks status",
            ));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| readiness_error("evidence record metadata is unavailable"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_RECORD_BYTES
        {
            return Err(readiness_error(
                "evidence record is not a bounded regular file",
            ));
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(readiness_error("evidence record is not private"));
        }
        let mut file = open_regular_no_follow(&entry.path())?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| readiness_error("could not read evidence record"))?;
        let record: StoredRecord = serde_json::from_slice(&bytes)
            .map_err(|_| readiness_error("evidence record is not canonical version one data"))?;
        validate_record(&record, &name, records.last())?;
        records.push(record);
    }
    if records.is_empty() {
        return Err(readiness_error("evidence store is empty"));
    }
    Ok(records)
}

fn validate_record(
    record: &StoredRecord,
    file_name: &str,
    previous: Option<&StoredRecord>,
) -> Result<(), CoreError> {
    if record.content.schema_version != RECORD_SCHEMA_VERSION {
        return Err(readiness_error("unsupported evidence schema version"));
    }
    if record.record_digest != record_digest(&record.content)?
        || file_name != record_file_name(record.content.sequence, &record.record_digest)
    {
        return Err(readiness_error("evidence record digest is invalid"));
    }
    match previous {
        None => {
            if record.content.sequence != 0
                || record.content.previous_record_digest.is_some()
                || !matches!(
                    record.content.evidence,
                    StoredEvidence::StoreInitialized { .. }
                )
            {
                return Err(readiness_error("evidence initialization record is invalid"));
            }
        }
        Some(previous) => {
            if record.content.sequence != previous.content.sequence + 1
                || record.content.store_identity != previous.content.store_identity
                || record.content.previous_record_digest.as_deref()
                    != Some(previous.record_digest.as_str())
            {
                return Err(readiness_error("evidence record chain is invalid"));
            }
        }
    }
    Ok(())
}

fn record_digest(content: &StoredRecordContent) -> Result<String, CoreError> {
    let bytes = serde_json::to_vec(content)
        .map_err(|_| readiness_error("could not encode evidence digest input"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza readiness evidence record v1\0");
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn record_evidence_reference(record: &StoredRecord) -> String {
    format!("readiness-record:{}", record.record_digest)
}

fn whole_file_digest(path: &Path) -> Result<String, CoreError> {
    let mut file = open_regular_no_follow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| readiness_error("Bundle metadata is unavailable"))?;
    if !metadata.is_file() {
        return Err(readiness_error("Bundle is not a regular file"));
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| readiness_error("could not read Bundle for evidence binding"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn open_regular_no_follow(path: &Path) -> Result<File, CoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    options
        .open(path)
        .map_err(|_| readiness_error("could not open bounded evidence input"))
}

fn record_file_name(sequence: u64, digest: &str) -> String {
    format!("{sequence:020}-{digest}.json")
}

fn random_identity() -> Result<String, CoreError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| readiness_error("operating-system entropy failed"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn owner_attestation_review_hash(review: &OwnerAttestationReview) -> Result<String, CoreError> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "store_identity": review.store_identity,
        "plan_hash": review.plan_hash,
        "claim_kind": review.claim_kind.machine_label(),
        "claim_text": review.claim_text,
        "evidence_reference": review.evidence_reference,
        "prepared_at_unix_seconds": review.prepared_at_unix_seconds,
        "required_acknowledgement": OWNER_ATTESTATION_ACKNOWLEDGEMENT,
        "consequence": "This claim is owner-stated and is not machine verification.",
    }))
    .map_err(|_| readiness_error("could not encode Owner Attestation review"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza owner attestation review v1\0");
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_evidence_reference(reference: &str) -> Result<(), CoreError> {
    if reference.is_empty()
        || reference.len() > 256
        || !reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.'))
    {
        return Err(readiness_error(
            "Owner Attestation evidence reference is invalid",
        ));
    }
    Ok(())
}

fn now_unix_seconds() -> Result<u64, CoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| readiness_error("system clock precedes Unix epoch"))
}

fn readiness_error(message: impl Into<String>) -> CoreError {
    CoreError::ReadinessEvidence(message.into())
}
