use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

use crate::{
    BundleEngine, BundleVerification, CoreError, OfflineRecoveryEngine,
    OfflineRecoveryRehearsalReceipt, OfflineRecoveryRehearsalRequest, Plan, PlanApprovalState,
    RecoverySecret, VerifiedCopyReceipt, VerifyRequest,
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
    VerifiedCopy(&'a VerifiedCopyReceipt),
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
        receipt: &'a VerifiedCopyReceipt,
    ) -> Self {
        Self {
            directory: directory.into(),
            plan,
            input: ReadinessReceiptInput::VerifiedCopy(receipt),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessReceiptRecordReport {
    operation: &'static str,
    sequence: u64,
}

impl ReadinessReceiptRecordReport {
    pub fn operation(&self) -> &'static str {
        self.operation
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Debug)]
pub struct ReadinessEvidenceStatusRequest<'a> {
    directory: PathBuf,
    plan: &'a Plan,
    bundle: Option<BundleStatusInput<'a>>,
    offline_recovery_document: Option<PathBuf>,
    verified_copy: Option<PathBuf>,
}

#[derive(Debug)]
struct BundleStatusInput<'a> {
    bundle: PathBuf,
    recovery_secret: &'a RecoverySecret,
}

impl<'a> ReadinessEvidenceStatusRequest<'a> {
    pub fn new(directory: impl Into<PathBuf>, plan: &'a Plan) -> Self {
        Self {
            directory: directory.into(),
            plan,
            bundle: None,
            offline_recovery_document: None,
            verified_copy: None,
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
        self.verified_copy = Some(bundle.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessEvidenceConclusion {
    Current,
    Missing,
    Invalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessEvidenceState {
    CompleteEvidence,
    BlockingGaps,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessEvidenceStatusReport {
    state: ReadinessEvidenceState,
    bundle_verification: ReadinessEvidenceConclusion,
    offline_recovery_method: ReadinessEvidenceConclusion,
    vaultwarden_recovery_method: ReadinessEvidenceConclusion,
    verified_copy: ReadinessEvidenceConclusion,
    active_owner_attestations: Vec<OwnerAttestationStatus>,
    withdrawn_owner_attestation_identifiers: Vec<String>,
    events: Vec<ReadinessEvidenceEvent>,
}

impl ReadinessEvidenceStatusReport {
    pub fn state(&self) -> ReadinessEvidenceState {
        self.state
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

    pub fn active_owner_attestations(&self) -> &[OwnerAttestationStatus] {
        &self.active_owner_attestations
    }

    pub fn withdrawn_owner_attestation_identifiers(&self) -> &[String] {
        &self.withdrawn_owner_attestation_identifiers
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
                "offline_recovery_method": self.offline_recovery_method.machine_label(),
                "vaultwarden_recovery_method": self.vaultwarden_recovery_method.machine_label(),
                "verified_copy": self.verified_copy.machine_label(),
                "active_owner_attestations": self.active_owner_attestations,
                "withdrawn_owner_attestation_identifiers": self.withdrawn_owner_attestation_identifiers,
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
        }
    }

    fn machine_label(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Missing => "missing",
            Self::Invalidated => "invalidated",
        }
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

#[derive(Debug, Default)]
pub struct ReadinessEvidenceEngine;

impl ReadinessEvidenceEngine {
    pub fn local() -> Self {
        Self
    }

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
        if let Err(error) = publish_record(&request.directory, &record) {
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
            ReadinessReceiptInput::VerifiedCopy(receipt) => (
                "verified-copy",
                StoredEvidence::VerifiedCopy {
                    plan_hash,
                    source_bundle_identity: receipt.source_bundle_identity().to_owned(),
                    destination_bundle_identity: receipt.destination_bundle_identity().to_owned(),
                    whole_file_digest: receipt.whole_file_digest().to_owned(),
                    verified_at_unix_seconds: receipt.verified_at_unix_seconds(),
                },
            ),
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
        publish_record(&request.directory, &record)?;

        Ok(ReadinessReceiptRecordReport {
            operation,
            sequence,
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
                    | StoredEvidence::VerifiedCopy { .. }
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
                match (verification, current_digest) {
                    (Ok(verification), Ok(current_digest))
                        if record_plan == &current_plan_hash
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

        let latest_copy = records
            .iter()
            .rev()
            .find_map(|record| match &record.content.evidence {
                StoredEvidence::VerifiedCopy {
                    plan_hash,
                    source_bundle_identity,
                    destination_bundle_identity,
                    whole_file_digest,
                    ..
                } => Some((
                    plan_hash,
                    source_bundle_identity,
                    destination_bundle_identity,
                    whole_file_digest,
                )),
                _ => None,
            });
        let verified_copy = match (
            plan_is_current,
            latest_copy,
            request.bundle.as_ref(),
            request.verified_copy.as_ref(),
        ) {
            (false, Some(_), _, _) => ReadinessEvidenceConclusion::Invalidated,
            (_, None, _, _) | (_, Some(_), None, _) | (_, Some(_), _, None) => {
                ReadinessEvidenceConclusion::Missing
            }
            (
                true,
                Some((record_plan, source_identity, destination_identity, record_digest)),
                Some(bundle_input),
                Some(copy),
            ) => {
                let source = BundleEngine::local().verify(VerifyRequest::new(
                    &bundle_input.bundle,
                    bundle_input.recovery_secret,
                ));
                let destination = BundleEngine::local()
                    .verify(VerifyRequest::new(copy, bundle_input.recovery_secret));
                let copy_digest = whole_file_digest(copy);
                match (source, destination, copy_digest) {
                    (Ok(source), Ok(destination), Ok(copy_digest))
                        if record_plan == &current_plan_hash
                            && source_identity == source.bundle_identity()
                            && destination_identity == destination.bundle_identity()
                            && record_digest == &copy_digest =>
                    {
                        ReadinessEvidenceConclusion::Current
                    }
                    _ => ReadinessEvidenceConclusion::Invalidated,
                }
            }
        };
        let vaultwarden_recovery_method = ReadinessEvidenceConclusion::Missing;

        let (active_owner_attestations, withdrawn_owner_attestation_identifiers) =
            active_attestation_status(&records)?;

        let state = ReadinessEvidenceState::BlockingGaps;
        let events = vec![ReadinessEvidenceEvent {
            state,
            bundle_verification,
        }];
        Ok(ReadinessEvidenceStatusReport {
            state,
            bundle_verification,
            offline_recovery_method,
            vaultwarden_recovery_method,
            verified_copy,
            active_owner_attestations,
            withdrawn_owner_attestation_identifiers,
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
        publish_record(&request.directory, &StoredRecord::new(content)?)?;

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
        publish_record(&request.directory, &StoredRecord::new(content)?)?;

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
            | StoredEvidence::VerifiedCopy { plan_hash, .. }
            | StoredEvidence::OwnerAttestation { plan_hash, .. }
            | StoredEvidence::OwnerAttestationWithdrawn { plan_hash, .. } => Some(plan_hash),
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
    VerifiedCopy {
        plan_hash: String,
        source_bundle_identity: String,
        destination_bundle_identity: String,
        whole_file_digest: String,
        verified_at_unix_seconds: u64,
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
            | StoredEvidence::VerifiedCopy { .. } => {}
        }
    }
    Ok((active.into_values().collect(), withdrawn))
}

fn require_approved_plan(plan: &Plan) -> Result<(), CoreError> {
    if plan.approval_state()? != PlanApprovalState::Approved {
        return Err(readiness_error(
            "Readiness Evidence requires an approved, current Plan",
        ));
    }
    Ok(())
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

fn publish_record(directory: &Path, record: &StoredRecord) -> Result<(), CoreError> {
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
    let mut candidate = options
        .open(&candidate_path)
        .map_err(|_| readiness_error("could not create exclusive evidence candidate"))?;
    candidate
        .write_all(&bytes)
        .and_then(|_| candidate.sync_all())
        .map_err(|_| readiness_error("could not persist evidence candidate"))?;
    fs::hard_link(&candidate_path, &final_path)
        .map_err(|_| readiness_error("could not publish evidence record without overwrite"))?;
    fs::remove_file(&candidate_path)
        .map_err(|_| readiness_error("could not remove published evidence candidate"))?;
    File::open(directory)
        .and_then(|directory_file| directory_file.sync_all())
        .map_err(|_| readiness_error("could not synchronize evidence directory"))?;
    Ok(())
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
