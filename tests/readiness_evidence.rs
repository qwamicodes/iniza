use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

use iniza::{
    BitwardenCommandLine, BitwardenInstallationObservation, BitwardenRecoveryNote,
    BitwardenRetrievedRecoveryNote, BitwardenVaultObservation, BundleEngine, CoreError,
    GitPublicationOperation, GitPublicationOutput, GitPublicationProcess, OfflineRecoveryEngine,
    OfflineRecoveryPersistenceTransition, OfflineRecoveryRehearsalRequest, OfflineRecoveryStorage,
    OfflineRecoveryWriteRequest, OwnerAttestationClaimKind, OwnerAttestationConfirmationRequest,
    OwnerAttestationPreparationRequest, OwnerAttestationWithdrawalRequest, PackRecoveryContext,
    PackRequest, Plan, PlanEngine, ProjectAuditEngine, ProjectAuditRequest,
    ProjectCapsuleCaptureRequest, ProjectCapsuleEngine, ProjectCapsuleRehearsalRequest,
    ProjectCapsuleReviewRequest, PushPlanApprovalRequest, PushPlanDraftRequest, PushPlanEngine,
    PushPlanExecutionRequest, ReadinessEvidenceConclusion, ReadinessEvidenceEngine,
    ReadinessEvidenceInitializationRequest, ReadinessEvidenceState, ReadinessEvidenceStatusRequest,
    ReadinessEvidenceStorage, ReadinessEvidenceStorageTransition, ReadinessReceiptRecordRequest,
    RecoveryMethod, RecoverySecret, RestoreEngine, RestoreRequest, ScanRequest,
    VaultwardenInstallationRequest, VaultwardenItemIdentifier, VaultwardenLoadRequest,
    VaultwardenPreflightRequest, VaultwardenRecoveryEngine, VaultwardenStoreRequest,
    VerifiedCopyPersistence, VerifiedCopyPersistenceTransition, VerifiedCopyRequest,
    VerifiedCopyStorageLocation, VerifyRequest,
};
use zeroize::Zeroizing;

const SYNTHETIC_VAULTWARDEN_SECRET: [u8; 32] = [0x31; 32];
const SYNTHETIC_OFFLINE_SECRET: [u8; 32] = [0x47; 32];
const SYNTHETIC_ITEM_IDENTIFIER: &str = "12345678-1234-4234-8234-123456789abc";

struct TestDirectory(PathBuf);

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should follow the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-readiness-evidence-{}-{unique}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).expect("isolated test directory should be created");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("evidence parent should be private");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Default)]
struct SyntheticRemovableStorage;

impl OfflineRecoveryStorage for SyntheticRemovableStorage {
    fn validate_separate_removable_target(&self, _document: &Path) -> io::Result<()> {
        Ok(())
    }

    fn prepare_transition(
        &self,
        _transition: OfflineRecoveryPersistenceTransition,
    ) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct CreatedVaultwardenNote {
    item_name: String,
    bundle_identity: String,
    bundle_format: String,
    created_at: String,
    location_hint: Option<String>,
}

#[derive(Debug, Default)]
struct SyntheticBitwarden {
    created_note: Mutex<Option<CreatedVaultwardenNote>>,
}

impl BitwardenCommandLine for SyntheticBitwarden {
    fn inspect_installation(
        &self,
        _request: &VaultwardenInstallationRequest,
    ) -> Result<BitwardenInstallationObservation, CoreError> {
        BitwardenInstallationObservation::new(
            "/synthetic/trusted/bw",
            "2026.8.0",
            "1111111111111111111111111111111111111111111111111111111111111111",
            Option::<String>::None,
            Option::<String>::None,
        )
    }

    fn status(
        &self,
        _installation: &BitwardenInstallationObservation,
    ) -> Result<BitwardenVaultObservation, CoreError> {
        BitwardenVaultObservation::unlocked(
            "https://vaultwarden.example.test",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
    }

    fn create_recovery_note(
        &self,
        _installation: &BitwardenInstallationObservation,
        note: &BitwardenRecoveryNote<'_>,
    ) -> Result<VaultwardenItemIdentifier, CoreError> {
        *self
            .created_note
            .lock()
            .expect("synthetic vault should lock") = Some(CreatedVaultwardenNote {
            item_name: note.item_name().to_owned(),
            bundle_identity: note.bundle_identity().to_owned(),
            bundle_format: note.bundle_format().to_owned(),
            created_at: note.created_at().to_owned(),
            location_hint: note.location_hint().map(str::to_owned),
        });
        VaultwardenItemIdentifier::parse(SYNTHETIC_ITEM_IDENTIFIER)
    }

    fn synchronize(
        &self,
        _installation: &BitwardenInstallationObservation,
    ) -> Result<(), CoreError> {
        Ok(())
    }

    fn get_recovery_note(
        &self,
        _installation: &BitwardenInstallationObservation,
        item_identifier: &VaultwardenItemIdentifier,
    ) -> Result<BitwardenRetrievedRecoveryNote, CoreError> {
        let note = self
            .created_note
            .lock()
            .expect("synthetic vault should lock")
            .clone()
            .expect("synthetic note should exist");
        BitwardenRetrievedRecoveryNote::new(
            item_identifier.clone(),
            note.item_name,
            note.bundle_identity,
            note.bundle_format,
            note.created_at,
            note.location_hint,
            RecoverySecret::from_bytes(
                RecoveryMethod::Vaultwarden,
                Zeroizing::new(SYNTHETIC_VAULTWARDEN_SECRET),
            ),
        )
    }
}

#[test]
fn approved_plan_and_matching_bundle_produce_current_bundle_verification_evidence() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-developer-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");

    let bundle = directory.path().join("migration.iniza");
    let bundle_engine = BundleEngine::local();
    let packed = bundle_engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should produce a completed Bundle");
    let verification = bundle_engine
        .verify(VerifyRequest::new(&bundle, packed.offline_recovery_key()))
        .expect("completed Bundle should fully verify");

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    let initialized = engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    assert_eq!(initialized.schema_version(), 1);
    assert_eq!(initialized.plan_hash(), plan_hash);
    assert!(!initialized.store_identity().is_empty());

    let recorded = engine
        .record_receipt(ReadinessReceiptRecordRequest::bundle_verification(
            &evidence_directory,
            &plan,
            &bundle,
            &verification,
        ))
        .expect("typed successful Bundle verification should append a Receipt");
    assert_eq!(recorded.operation(), "bundle-verification");
    assert_eq!(recorded.sequence(), 1);

    let status = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, packed.offline_recovery_key()),
        )
        .expect("current evidence should reopen and revalidate");

    assert_eq!(status.state(), ReadinessEvidenceState::BlockingGaps);
    assert_eq!(
        status.bundle_verification(),
        ReadinessEvidenceConclusion::Current
    );
}

#[test]
fn bundle_verification_from_a_different_approved_plan_is_rejected() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-developer-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"first reviewed state\n")
        .expect("first synthetic source should be written");

    let mut first_plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("first synthetic source should scan");
    let first_plan_hash = first_plan
        .approval_hash()
        .expect("first Plan should have a hash");
    first_plan
        .approve(&first_plan_hash)
        .expect("exact first hash should approve the first Plan");

    let bundle = directory.path().join("first-plan.iniza");
    let bundle_engine = BundleEngine::local();
    let packed = bundle_engine
        .pack(PackRequest::new(&first_plan, &bundle))
        .expect("first approved Plan should produce a completed Bundle");
    let verification = bundle_engine
        .verify(VerifyRequest::new(&bundle, packed.offline_recovery_key()))
        .expect("first Plan Bundle should fully verify");

    fs::write(source.join("settings.txt"), b"second reviewed state\n")
        .expect("second synthetic source should be written");
    let mut second_plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("second synthetic source should scan");
    let second_plan_hash = second_plan
        .approval_hash()
        .expect("second Plan should have a hash");
    second_plan
        .approve(&second_plan_hash)
        .expect("exact second hash should approve the second Plan");
    assert_ne!(first_plan_hash, second_plan_hash);

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &second_plan,
            &evidence_directory,
        ))
        .expect("second approved Plan should initialize its evidence store");

    let error = engine
        .record_receipt(ReadinessReceiptRecordRequest::bundle_verification(
            &evidence_directory,
            &second_plan,
            &bundle,
            &verification,
        ))
        .expect_err("a Bundle from the first Plan must not become second-Plan evidence");
    assert_eq!(
        error.to_string(),
        "Bundle verification is bound to a different Plan"
    );
}

#[test]
fn source_content_changed_after_bundle_creation_invalidates_bundle_readiness_evidence() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-developer-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    let settings = source.join("settings.txt");
    fs::write(&settings, b"alpha\n").expect("initial synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let bundle = directory.path().join("migration.iniza");
    let bundle_engine = BundleEngine::local();
    let packed = bundle_engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should produce a completed Bundle");
    let verification = bundle_engine
        .verify(VerifyRequest::new(&bundle, packed.offline_recovery_key()))
        .expect("completed Bundle should fully verify");
    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::bundle_verification(
            &evidence_directory,
            &plan,
            &bundle,
            &verification,
        ))
        .expect("current Bundle verification should append");

    fs::write(&settings, b"omega\n")
        .expect("source should change without changing its byte length");
    let status = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, packed.offline_recovery_key()),
        )
        .expect("source drift should produce a blocking status");
    assert_eq!(
        status.bundle_verification(),
        ReadinessEvidenceConclusion::Invalidated
    );
}

#[test]
fn blocking_status_is_deterministic_secret_free_and_never_an_erase_safety_decision() {
    let directory = TestDirectory::new();
    let source = directory.path().join("private-source-name");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(
        source.join("protected-name.txt"),
        b"protected-content-marker-71f1",
    )
    .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");

    let bundle = directory.path().join("migration.iniza");
    let bundle_engine = BundleEngine::local();
    let packed = bundle_engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should produce a completed Bundle");
    let verification = bundle_engine
        .verify(VerifyRequest::new(&bundle, packed.offline_recovery_key()))
        .expect("completed Bundle should fully verify");
    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::bundle_verification(
            &evidence_directory,
            &plan,
            &bundle,
            &verification,
        ))
        .expect("typed successful Bundle verification should append a Receipt");

    let first = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, packed.offline_recovery_key()),
        )
        .expect("current evidence should produce status");
    let second = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, packed.offline_recovery_key()),
        )
        .expect("repeated status should remain deterministic");

    assert_eq!(first.exit_code(), 2);
    assert_eq!(first.human_result(), second.human_result());
    assert_eq!(first.machine_json_result(), second.machine_json_result());
    assert_eq!(first.events(), second.events());
    let machine: serde_json::Value =
        serde_json::from_str(&first.machine_json_result()).expect("status should be valid JSON");
    assert_eq!(machine["schema_version"], 1);
    assert_eq!(machine["command"], "readiness status");
    assert_eq!(machine["status"], "blocking-gaps");
    assert_eq!(machine["data"]["bundle_verification"], "current");
    assert_eq!(first.events().len(), 1);
    let event: serde_json::Value = serde_json::from_str(&first.events()[0].machine_json_line())
        .expect("status event should be valid JSON");
    assert_eq!(event["schema_version"], 1);
    assert_eq!(event["event"], "readiness-evaluated");

    let public_output = format!(
        "{}\n{}\n{}",
        first.human_result(),
        first.machine_json_result(),
        first.events()[0].machine_json_line()
    );
    for forbidden in [
        "private-source-name",
        "protected-name.txt",
        "protected-content-marker-71f1",
        directory.path().to_string_lossy().as_ref(),
        "safe to erase",
        "complete machine backup",
    ] {
        assert!(
            !public_output
                .to_lowercase()
                .contains(&forbidden.to_lowercase()),
            "public readiness output must omit {forbidden:?}"
        );
    }
    assert!(public_output.contains("This is not permission to erase a machine."));
}

#[test]
fn exact_owner_attestation_is_prepared_without_writing_and_recorded_only_as_owner_stated() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");

    let records_before = fs::read_dir(&evidence_directory)
        .expect("evidence store should be readable")
        .count();
    let review = engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::ConventionalBackupValidated,
            "conventional-backup:synthetic-reference-1",
        ))
        .expect("fixed owner-stated claim should prepare for review");
    assert_eq!(
        fs::read_dir(&evidence_directory)
            .expect("evidence store should remain readable")
            .count(),
        records_before,
        "attestation preparation must not write"
    );
    assert_eq!(
        review.claim_text(),
        "I confirm that the conventional backup was validated."
    );
    assert_eq!(
        review.evidence_reference(),
        "conventional-backup:synthetic-reference-1"
    );
    assert_eq!(
        review.required_acknowledgement(),
        "I confirm this Owner Attestation as my statement."
    );

    engine
        .confirm_attestation(OwnerAttestationConfirmationRequest::new(
            &evidence_directory,
            &plan,
            &review,
            "wrong-review-hash",
            review.required_acknowledgement(),
        ))
        .expect_err("a mismatched review hash must not record an attestation");
    assert_eq!(
        fs::read_dir(&evidence_directory)
            .expect("evidence store should remain readable")
            .count(),
        records_before,
        "rejected confirmation must not write"
    );

    let recorded = engine
        .confirm_attestation(OwnerAttestationConfirmationRequest::new(
            &evidence_directory,
            &plan,
            &review,
            review.review_hash(),
            review.required_acknowledgement(),
        ))
        .expect("exact owner confirmation should append the attestation");
    assert_eq!(recorded.classification(), "owner-stated");
    assert_eq!(recorded.claim_kind(), review.claim_kind());
    assert_eq!(recorded.claim_text(), review.claim_text());
    assert!(recorded.confirmed_at_unix_seconds() >= review.prepared_at_unix_seconds());

    let machine: serde_json::Value = serde_json::from_str(&recorded.machine_json_result())
        .expect("attestation result should be valid JSON");
    assert_eq!(machine["schema_version"], 1);
    assert_eq!(machine["status"], "owner-stated");
    assert!(machine.get("verified").is_none());
    assert!(machine.get("path").is_none());
}

#[test]
fn not_protected_attestation_requires_the_latest_report_evidence_reference() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    let report = engine
        .record_receipt(ReadinessReceiptRecordRequest::not_protected_report(
            &evidence_directory,
            &plan,
        ))
        .expect("Not Protected Report should append");

    engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::NotProtectedReportReviewed,
            "arbitrary-reference",
        ))
        .expect_err("an arbitrary reference must not bind a Not Protected Report review");
    let review = engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::NotProtectedReportReviewed,
            report.evidence_reference(),
        ))
        .expect("the latest Not Protected Report reference should prepare");
    assert_eq!(review.evidence_reference(), report.evidence_reference());
}

#[test]
fn a_superseding_not_protected_report_invalidates_the_older_owner_attestation() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    let first_report = engine
        .record_receipt(ReadinessReceiptRecordRequest::not_protected_report(
            &evidence_directory,
            &plan,
        ))
        .expect("first Not Protected Report should append");
    let review = engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::NotProtectedReportReviewed,
            first_report.evidence_reference(),
        ))
        .expect("first Not Protected Report should prepare for review");
    engine
        .confirm_attestation(OwnerAttestationConfirmationRequest::new(
            &evidence_directory,
            &plan,
            &review,
            review.review_hash(),
            review.required_acknowledgement(),
        ))
        .expect("exact first report review should append");

    let before = engine
        .status(ReadinessEvidenceStatusRequest::new(
            &evidence_directory,
            &plan,
        ))
        .expect("current reviewed report should produce status");
    assert!(
        before
            .blocking_gaps()
            .iter()
            .any(|gap| { gap.code() == "required-owner-attestations-missing" && gap.count() == 6 })
    );

    engine
        .record_receipt(ReadinessReceiptRecordRequest::not_protected_report(
            &evidence_directory,
            &plan,
        ))
        .expect("superseding Not Protected Report should append");
    let after = engine
        .status(ReadinessEvidenceStatusRequest::new(
            &evidence_directory,
            &plan,
        ))
        .expect("superseded report review should remain auditable");
    assert!(
        after
            .blocking_gaps()
            .iter()
            .any(|gap| { gap.code() == "required-owner-attestations-missing" && gap.count() == 7 })
    );
}

#[test]
fn withdrawing_an_owner_attestation_appends_history_and_removes_the_active_claim() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    let review = engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::ConventionalBackupValidated,
            "conventional-backup:synthetic-reference-2",
        ))
        .expect("fixed owner-stated claim should prepare for review");
    let attestation = engine
        .confirm_attestation(OwnerAttestationConfirmationRequest::new(
            &evidence_directory,
            &plan,
            &review,
            review.review_hash(),
            review.required_acknowledgement(),
        ))
        .expect("exact owner confirmation should append the attestation");

    let before = engine
        .status(ReadinessEvidenceStatusRequest::new(
            &evidence_directory,
            &plan,
        ))
        .expect("active attestation should be readable");
    assert_eq!(before.active_owner_attestations().len(), 1);
    assert_eq!(
        before.active_owner_attestations()[0].attestation_identifier(),
        attestation.attestation_identifier()
    );
    assert_eq!(
        before.active_owner_attestations()[0].classification(),
        "owner-stated"
    );
    let records_before_withdrawal = fs::read_dir(&evidence_directory)
        .expect("evidence store should be readable")
        .count();

    let withdrawal = engine
        .withdraw_attestation(OwnerAttestationWithdrawalRequest::new(
            &evidence_directory,
            &plan,
            attestation.attestation_identifier(),
            "I withdraw this Owner Attestation.",
        ))
        .expect("exact active attestation should be withdrawn append-only");
    assert_eq!(
        withdrawal.attestation_identifier(),
        attestation.attestation_identifier()
    );
    assert!(withdrawal.withdrawn_at_unix_seconds() >= attestation.confirmed_at_unix_seconds());
    assert_eq!(
        fs::read_dir(&evidence_directory)
            .expect("evidence store should remain readable")
            .count(),
        records_before_withdrawal + 1,
        "withdrawal must append instead of replacing history"
    );

    let after = engine
        .status(ReadinessEvidenceStatusRequest::new(
            &evidence_directory,
            &plan,
        ))
        .expect("withdrawn attestation history should remain readable");
    assert!(after.active_owner_attestations().is_empty());
    assert_eq!(after.withdrawn_owner_attestation_identifiers().len(), 1);
    assert_eq!(
        after.withdrawn_owner_attestation_identifiers()[0],
        attestation.attestation_identifier()
    );
}

#[test]
fn every_supported_owner_attestation_uses_fixed_non_free_form_claim_text() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    let not_protected_report = engine
        .record_receipt(ReadinessReceiptRecordRequest::not_protected_report(
            &evidence_directory,
            &plan,
        ))
        .expect("Not Protected Report should append");

    let cases = [
        (
            OwnerAttestationClaimKind::ConventionalBackupValidated,
            "I confirm that the conventional backup was validated.",
        ),
        (
            OwnerAttestationClaimKind::NotProtectedReportReviewed,
            "I confirm that I reviewed the Not Protected Report.",
        ),
    ];

    for (index, (claim_kind, expected_text)) in cases.into_iter().enumerate() {
        let evidence_reference =
            if claim_kind == OwnerAttestationClaimKind::NotProtectedReportReviewed {
                not_protected_report.evidence_reference().to_owned()
            } else {
                format!("evidence:synthetic-{index}")
            };
        let review = engine
            .prepare_attestation(OwnerAttestationPreparationRequest::new(
                &evidence_directory,
                &plan,
                claim_kind,
                evidence_reference,
            ))
            .expect("supported fixed claim should prepare");
        assert_eq!(review.claim_text(), expected_text);
        assert!(!review.claim_text().contains("synthetic-"));
    }
}

#[test]
fn typed_recovery_and_copy_receipts_are_current_only_while_their_artifacts_revalidate() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");

    let bundle = directory.path().join("migration.iniza");
    let copy = directory.path().join("verified-copy.iniza");
    let document = directory.path().join("offline.iniza-recovery");
    let bundle_engine = BundleEngine::local();
    let packed = bundle_engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should produce a completed Bundle");
    let verification = bundle_engine
        .verify(VerifyRequest::new(&bundle, packed.offline_recovery_key()))
        .expect("completed Bundle should fully verify");
    let copied = bundle_engine
        .copy_verified(VerifiedCopyRequest::new(
            &bundle,
            &copy,
            packed.offline_recovery_key(),
        ))
        .expect("second Bundle artifact should become a Verified Copy");
    let offline_engine = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage);
    offline_engine
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &document,
            packed.offline_recovery_key(),
        ))
        .expect("synthetic separate document should be written");
    let offline_receipt = offline_engine
        .rehearse(OfflineRecoveryRehearsalRequest::new(&bundle, &document))
        .expect("saved Offline Recovery Key should independently authenticate the Bundle");

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::bundle_verification(
            &evidence_directory,
            &plan,
            &bundle,
            &verification,
        ))
        .expect("Bundle verification should append");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::offline_recovery(
            &evidence_directory,
            &plan,
            &offline_receipt,
        ))
        .expect("typed Offline Recovery Key Receipt should append");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::verified_copy(
            &evidence_directory,
            &plan,
            &copied,
        ))
        .expect("typed Verified Copy Receipt should append");

    let current = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, packed.offline_recovery_key())
                .with_offline_recovery_document(&document)
                .with_verified_copy(&copy),
        )
        .expect("typed evidence should revalidate");
    assert_eq!(
        current.offline_recovery_method(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(
        current.vaultwarden_recovery_method(),
        ReadinessEvidenceConclusion::Missing
    );
    assert_eq!(
        current.verified_copy(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(current.state(), ReadinessEvidenceState::BlockingGaps);

    let mut copy_bytes = fs::read(&copy).expect("Verified Copy should be readable");
    let final_byte = copy_bytes.len() - 1;
    copy_bytes[final_byte] ^= 0x01;
    fs::write(&copy, copy_bytes).expect("synthetic copy should be mutable for invalidation");
    let changed = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, packed.offline_recovery_key())
                .with_offline_recovery_document(&document)
                .with_verified_copy(&copy),
        )
        .expect("changed copy should become a blocking conclusion");
    assert_eq!(
        changed.verified_copy(),
        ReadinessEvidenceConclusion::Invalidated
    );
}

#[test]
fn typed_vaultwarden_receipt_revalidates_through_the_loaded_recovery_method() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let recovery = PackRecoveryContext::from_secrets(
        RecoverySecret::from_bytes(
            RecoveryMethod::Vaultwarden,
            Zeroizing::new(SYNTHETIC_VAULTWARDEN_SECRET),
        ),
        RecoverySecret::from_bytes(
            RecoveryMethod::Offline,
            Zeroizing::new(SYNTHETIC_OFFLINE_SECRET),
        ),
    )
    .expect("synthetic Recovery Methods should be independent");
    let bundle = directory.path().join("migration.iniza");
    let bundle_engine = BundleEngine::local();
    bundle_engine
        .pack(PackRequest::new(&plan, &bundle).with_recovery_context(&recovery))
        .expect("approved Plan should produce a completed Bundle");
    let verification = bundle_engine
        .verify(VerifyRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
        ))
        .expect("completed Bundle should fully verify");

    let vaultwarden = VaultwardenRecoveryEngine::with_command_line(SyntheticBitwarden::default());
    let installation = vaultwarden
        .inspect_installation(VaultwardenInstallationRequest::trusted_path())
        .expect("synthetic official installation should inspect");
    let preflight = vaultwarden
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            "Synthetic migration",
            Option::<String>::None,
            &installation,
            installation.review_hash(),
        ))
        .expect("synthetic unlocked service should preflight");
    let stored = vaultwarden
        .store_and_rehearse(VaultwardenStoreRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            &preflight,
            preflight.review_hash(),
        ))
        .expect("synthetic Secure Note should be retrieved and verified");
    let receipt = stored
        .receipt()
        .expect("verified Vaultwarden operation should have a Receipt");
    let loaded = vaultwarden
        .load(VaultwardenLoadRequest::new(
            &bundle,
            receipt.item_identifier().clone(),
            receipt.server_identity_hash(),
            &installation,
            installation.review_hash(),
        ))
        .expect("exact Secure Note should produce a loaded Recovery Method");

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::bundle_verification(
            &evidence_directory,
            &plan,
            &bundle,
            &verification,
        ))
        .expect("Bundle verification should append");
    let vaultwarden_record = engine
        .record_receipt(ReadinessReceiptRecordRequest::vaultwarden_recovery(
            &evidence_directory,
            &plan,
            receipt,
        ))
        .expect("typed Vaultwarden Receipt should append");

    engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::ReviewedExternalVaultwardenServiceConfirmed,
            "unbound-vaultwarden-owner-statement",
        ))
        .expect_err("a Vaultwarden owner statement must bind the current typed Receipt");
    for (claim_kind, claim_text) in [
        (
            OwnerAttestationClaimKind::ReviewedExternalVaultwardenServiceConfirmed,
            "I confirm that the reviewed Vaultwarden service is external to the source Mac.",
        ),
        (
            OwnerAttestationClaimKind::FreshDeviceVaultwardenAccessConfirmed,
            "I confirm that fresh-device Vaultwarden access succeeded.",
        ),
        (
            OwnerAttestationClaimKind::IndependentMultiFactorRecoveryPathConfirmed,
            "I confirm that the independent multi-factor recovery path succeeded.",
        ),
    ] {
        let review = engine
            .prepare_attestation(OwnerAttestationPreparationRequest::new(
                &evidence_directory,
                &plan,
                claim_kind,
                vaultwarden_record.evidence_reference(),
            ))
            .expect("the current typed Vaultwarden Receipt should prepare the fixed statement");
        assert_eq!(review.claim_text(), claim_text);
        engine
            .confirm_attestation(OwnerAttestationConfirmationRequest::new(
                &evidence_directory,
                &plan,
                &review,
                review.review_hash(),
                review.required_acknowledgement(),
            ))
            .expect("exact Vaultwarden owner statement should append");
    }

    let status = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, loaded.recovery_secret())
                .with_vaultwarden_recovery(&loaded),
        )
        .expect("loaded Vaultwarden Recovery Method should revalidate its Receipt");
    assert_eq!(
        status.vaultwarden_recovery_method(),
        ReadinessEvidenceConclusion::Current
    );

    engine
        .record_receipt(ReadinessReceiptRecordRequest::vaultwarden_recovery(
            &evidence_directory,
            &plan,
            receipt,
        ))
        .expect("newer typed Vaultwarden Receipt should supersede the older binding");
    let superseded = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, loaded.recovery_secret())
                .with_vaultwarden_recovery(&loaded),
        )
        .expect("superseded owner statements should remain auditable but blocking");
    assert!(
        superseded
            .blocking_gaps()
            .iter()
            .any(|gap| { gap.code() == "required-owner-attestations-missing" && gap.count() == 7 })
    );
}

#[cfg(unix)]
#[test]
fn current_not_protected_report_never_hides_an_unresolved_must_protect_item() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    symlink("settings.txt", source.join("review-required-link"))
        .expect("review-required symbolic link should be created");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    assert_eq!(plan.coverage_summary().must_protect_blocking, 1);
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::not_protected_report(
            &evidence_directory,
            &plan,
        ))
        .expect("the exact Not Protected Report should append as gap evidence");

    let status = engine
        .status(ReadinessEvidenceStatusRequest::new(
            &evidence_directory,
            &plan,
        ))
        .expect("current gap evidence should produce status");
    assert_eq!(
        status.plan_coverage(),
        ReadinessEvidenceConclusion::Blocking
    );
    assert_eq!(
        status.not_protected_report(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(status.state(), ReadinessEvidenceState::BlockingGaps);
    assert!(
        status
            .blocking_gaps()
            .iter()
            .any(|gap| gap.code() == "must-protect-coverage-unresolved" && gap.count() == 1)
    );
    let public_output = format!(
        "{}\n{}",
        status.human_result(),
        status.machine_json_result()
    );
    assert!(!public_output.contains("review-required-link"));
    assert!(!public_output.contains(source.to_string_lossy().as_ref()));
}

#[cfg(unix)]
#[test]
fn project_capsule_and_restore_rehearsal_make_only_the_project_restorable() {
    let directory = TestDirectory::new();
    let project = directory.path().join("synthetic-project");
    fs::create_dir(&project).expect("synthetic Project should be created");
    run_git(&project, &["init", "-q", "--initial-branch=main"]);
    fs::write(project.join("README.md"), "synthetic Project\n")
        .expect("synthetic Project content should be written");
    run_git(&project, &["add", "README.md"]);
    run_git_with_identity(&project, &["commit", "-q", "-m", "Initial fixture"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    let project_audit = audit
        .projects()
        .first()
        .expect("Project should be discovered");
    let review = ProjectCapsuleEngine::local()
        .review(ProjectCapsuleReviewRequest::new(&plan, project_audit))
        .expect("clean Project should produce a Project Capsule review");
    let capsule = directory.path().join("project-capsule.iniza");
    let captured = ProjectCapsuleEngine::local()
        .capture(ProjectCapsuleCaptureRequest::new(
            &plan,
            project_audit,
            &review,
            review.review_hash(),
            &capsule,
        ))
        .expect("reviewed Project should capture into a verified Project Capsule");
    let expectation = captured
        .expectation()
        .expect("verified Project Capsule should bind an expectation");
    let restored = directory.path().join("restored-project");
    let rehearsal = ProjectCapsuleEngine::local()
        .rehearse(ProjectCapsuleRehearsalRequest::new(
            &capsule,
            expectation,
            captured.offline_recovery_key(),
            &restored,
        ))
        .expect("Project Capsule should rehearse independently from source");

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::project_capsule_capture(
            &evidence_directory,
            &plan,
            &captured,
        ))
        .expect("verified Project Capsule capture should append");
    let rehearsal_record = engine
        .record_receipt(ReadinessReceiptRecordRequest::project_capsule_rehearsal(
            &evidence_directory,
            &plan,
            &rehearsal,
        ))
        .expect("Restorable Project rehearsal should append");
    engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::RepresentativeRestoredProjectBuildCompleted,
            "unbound-restored-project-build",
        ))
        .expect_err("restored-Project build statement must bind the current rehearsal Receipt");
    let build_review = engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::RepresentativeRestoredProjectBuildCompleted,
            rehearsal_record.evidence_reference(),
        ))
        .expect("current Project Capsule rehearsal should prepare the fixed build statement");
    assert_eq!(
        build_review.claim_text(),
        "I confirm that a representative restored Project build completed."
    );

    let status =
        engine
            .status(
                ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                    .with_project_capsule(&capsule, expectation, captured.offline_recovery_key()),
            )
            .expect("Project evidence should revalidate");
    assert_eq!(status.projects().len(), 1);
    assert_eq!(status.projects()[0].project_identity(), project_audit.id());
    assert_eq!(
        status.projects()[0].restorable(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(
        status.projects()[0].synchronized(),
        ReadinessEvidenceConclusion::Missing
    );
}

#[test]
fn completed_restore_rehearsal_is_current_only_for_its_bundle_and_destination() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");

    let bundle = directory.path().join("migration.iniza");
    let packed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should produce a completed Bundle");
    let destination = directory.path().join("restore-rehearsal");
    let restored = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            packed.offline_recovery_key(),
        ))
        .expect("safe Restore Rehearsal should complete");

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    let restore_record = engine
        .record_receipt(ReadinessReceiptRecordRequest::restore_rehearsal(
            &evidence_directory,
            &plan,
            &restored,
        ))
        .expect("completed Restore Rehearsal should append");
    engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::SecondEnvironmentRehearsalCompleted,
            "unbound-second-environment-rehearsal",
        ))
        .expect_err("second-environment statement must bind the current Restore Receipt");
    let second_environment_review = engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::SecondEnvironmentRehearsalCompleted,
            restore_record.evidence_reference(),
        ))
        .expect("current Restore Rehearsal should prepare the fixed owner statement");
    assert_eq!(
        second_environment_review.claim_text(),
        "I confirm that the second-environment Restore Rehearsal completed."
    );

    let status = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, packed.offline_recovery_key())
                .with_restore_rehearsal(&destination),
        )
        .expect("Restore Rehearsal evidence should revalidate");
    assert_eq!(
        status.restore_rehearsal(),
        ReadinessEvidenceConclusion::Current
    );
}

#[test]
fn every_selected_verified_copy_must_revalidate_independently() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");

    let bundle = directory.path().join("migration.iniza");
    let bundle_engine = BundleEngine::local();
    let packed = bundle_engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should produce a completed Bundle");
    let first_copy = directory.path().join("first-copy.iniza");
    let second_copy = directory.path().join("second-copy.iniza");
    let first = bundle_engine
        .copy_verified(VerifiedCopyRequest::new(
            &bundle,
            &first_copy,
            packed.offline_recovery_key(),
        ))
        .expect("first Verified Copy should complete");
    let second = bundle_engine
        .copy_verified(VerifiedCopyRequest::new(
            &bundle,
            &second_copy,
            packed.offline_recovery_key(),
        ))
        .expect("second Verified Copy should complete");

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    for report in [&first, &second] {
        engine
            .record_receipt(ReadinessReceiptRecordRequest::verified_copy(
                &evidence_directory,
                &plan,
                report,
            ))
            .expect("each typed Verified Copy Receipt should append");
    }

    let status_request = || {
        ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
            .with_bundle(&bundle, packed.offline_recovery_key())
            .with_verified_copy(&first_copy)
            .with_verified_copy(&second_copy)
    };
    assert_eq!(
        engine
            .status(status_request())
            .expect("both Verified Copies should revalidate")
            .verified_copy(),
        ReadinessEvidenceConclusion::Current
    );

    fs::OpenOptions::new()
        .append(true)
        .open(&first_copy)
        .expect("first Verified Copy should reopen")
        .write_all(b"modified")
        .expect("first Verified Copy should be modified");
    assert_eq!(
        engine
            .status(status_request())
            .expect("modified Verified Copy should produce status")
            .verified_copy(),
        ReadinessEvidenceConclusion::Invalidated
    );
}

#[test]
fn two_verified_copy_files_on_one_filesystem_are_not_independent_protection() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");

    let bundle = directory.path().join("migration.iniza");
    let bundle_engine = BundleEngine::local();
    let packed = bundle_engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should produce a completed Bundle");
    let first_copy = directory.path().join("first-copy.iniza");
    let second_copy = directory.path().join("second-copy.iniza");
    let first_report = bundle_engine
        .copy_verified(VerifiedCopyRequest::new(
            &bundle,
            &first_copy,
            packed.offline_recovery_key(),
        ))
        .expect("first Verified Copy should complete");
    let second_report = bundle_engine
        .copy_verified(VerifiedCopyRequest::new(
            &bundle,
            &second_copy,
            packed.offline_recovery_key(),
        ))
        .expect("second Verified Copy should complete");

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    for report in [&first_report, &second_report] {
        engine
            .record_receipt(ReadinessReceiptRecordRequest::verified_copy(
                &evidence_directory,
                &plan,
                report,
            ))
            .expect("Verified Copy report should append");
    }

    let status = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, packed.offline_recovery_key())
                .with_verified_copy(&first_copy)
                .with_verified_copy(&second_copy),
        )
        .expect("same-filesystem copies should produce a blocking status");
    assert!(status.blocking_gaps().iter().any(|gap| {
        gap.code() == "two-independent-verified-copies-required" && gap.count() == 2
    }));
}

#[test]
fn complete_push_plan_execution_makes_only_the_project_synchronized() {
    let directory = TestDirectory::new();
    let project = directory.path().join("synthetic-project");
    let remote = directory.path().join("synthetic-remote.git");
    fs::create_dir(&project).expect("synthetic Project should be created");
    run_git(&project, &["init", "-q", "--initial-branch=main"]);
    run_git(
        directory.path(),
        &[
            "init",
            "-q",
            "--bare",
            remote.to_str().expect("fixture path should be Unicode"),
        ],
    );
    fs::write(project.join("tracked.txt"), "published base\n")
        .expect("base fixture should be written");
    run_git(&project, &["add", "tracked.txt"]);
    run_git_with_identity(&project, &["commit", "-q", "-m", "Published base"]);
    run_git(
        &project,
        &[
            "remote",
            "add",
            "origin",
            remote.to_str().expect("fixture path should be Unicode"),
        ],
    );
    run_git(&project, &["push", "-q", "-u", "origin", "main"]);
    fs::write(project.join("tracked.txt"), "approved ahead commit\n")
        .expect("ahead fixture should be written");
    run_git(&project, &["add", "tracked.txt"]);
    run_git_with_identity(&project, &["commit", "-q", "-m", "Approved ahead commit"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    let project_audit = audit
        .projects()
        .first()
        .expect("Project should be discovered");

    let push_plan = directory.path().join("publication.push-plan");
    let approval = directory.path().join("publication.push-approval");
    let result = directory.path().join("publication.push-result");
    let publication = PushPlanEngine::with_git_publication_process(LocalGitPublication);
    let draft = publication
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &push_plan,
        ))
        .expect("ahead Project should produce a Push Plan");
    publication
        .approve(
            PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &approval)
                .acknowledge_remote_side_effects(),
        )
        .expect("exact synthetic Push Plan should approve");
    let execution = publication
        .execute(PushPlanExecutionRequest::new(
            &plan,
            project_audit,
            &push_plan,
            &approval,
            &result,
        ))
        .expect("exact synthetic publication should complete");

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::with_git_publication_process(LocalGitPublication);
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::push_execution(
            &evidence_directory,
            &plan,
            &execution,
        ))
        .expect("typed Push Plan execution should append");

    let status = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_project_publication(project_audit),
        )
        .expect("explicit remote Project revalidation should produce status");
    assert_eq!(status.projects().len(), 1);
    assert_eq!(status.projects()[0].project_identity(), project_audit.id());
    assert_eq!(
        status.projects()[0].restorable(),
        ReadinessEvidenceConclusion::Missing
    );
    assert_eq!(
        status.projects()[0].synchronized(),
        ReadinessEvidenceConclusion::Current
    );

    let published_parent = git_stdout(&project, &["rev-parse", "refs/heads/main^"]);
    run_git(
        &remote,
        &["update-ref", "refs/heads/main", published_parent.trim()],
    );
    let changed_remote = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_project_publication(project_audit),
        )
        .expect("changed remote should produce a blocking Project conclusion");
    assert_eq!(
        changed_remote.projects()[0].synchronized(),
        ReadinessEvidenceConclusion::Invalidated
    );
}

#[test]
fn project_already_equal_to_its_upstream_is_synchronized_without_a_push_execution() {
    let directory = TestDirectory::new();
    let project = directory.path().join("synthetic-project");
    let remote = directory.path().join("synthetic-remote.git");
    fs::create_dir(&project).expect("synthetic Project should be created");
    run_git(&project, &["init", "-q", "--initial-branch=main"]);
    run_git(
        directory.path(),
        &[
            "init",
            "-q",
            "--bare",
            "--initial-branch=main",
            remote.to_str().expect("remote path should be Unicode"),
        ],
    );
    run_git(
        &project,
        &[
            "remote",
            "add",
            "origin",
            remote.to_str().expect("remote path should be Unicode"),
        ],
    );
    fs::write(project.join("tracked.txt"), "already published\n")
        .expect("tracked fixture should be written");
    run_git(&project, &["add", "tracked.txt"]);
    run_git_with_identity(&project, &["commit", "-q", "-m", "Published state"]);
    run_git(&project, &["push", "-q", "-u", "origin", "main"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("already-published Project should audit");
    let project_audit = audit
        .projects()
        .first()
        .expect("Project should be discovered");
    assert_eq!(project_audit.local_state().ahead(), Some(0));
    assert_eq!(project_audit.local_state().behind(), Some(0));

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::with_git_publication_process(LocalGitPublication);
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    let status = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_project_publication(project_audit),
        )
        .expect("read-only remote comparison should produce Project status");

    assert_eq!(status.projects().len(), 1);
    assert_eq!(
        status.projects()[0].synchronized(),
        ReadinessEvidenceConclusion::Current
    );
}

#[cfg(unix)]
#[test]
fn local_only_references_are_synchronized_only_with_current_capsule_protection_and_owner_decision()
{
    let directory = TestDirectory::new();
    let project = directory.path().join("synthetic-project");
    let remote = directory.path().join("synthetic-remote.git");
    fs::create_dir(&project).expect("synthetic Project should be created");
    run_git(&project, &["init", "-q", "--initial-branch=main"]);
    run_git(
        directory.path(),
        &[
            "init",
            "-q",
            "--bare",
            "--initial-branch=main",
            remote.to_str().expect("remote path should be Unicode"),
        ],
    );
    fs::write(project.join("tracked.txt"), "published state\n")
        .expect("tracked fixture should be written");
    run_git(&project, &["add", "tracked.txt"]);
    run_git_with_identity(&project, &["commit", "-q", "-m", "Published state"]);
    run_git(
        &project,
        &[
            "remote",
            "add",
            "origin",
            remote.to_str().expect("remote path should be Unicode"),
        ],
    );
    run_git(&project, &["push", "-q", "-u", "origin", "main"]);
    run_git(&project, &["checkout", "-q", "-b", "capsule-only-branch"]);
    fs::write(
        project.join("capsule-only.txt"),
        "deliberately unpublished\n",
    )
    .expect("capsule-only fixture should be written");
    run_git(&project, &["add", "capsule-only.txt"]);
    run_git_with_identity(&project, &["commit", "-q", "-m", "Capsule-only state"]);
    run_git(&project, &["checkout", "-q", "main"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan).with_remote_check())
        .expect("Project should audit");
    let project_audit = audit
        .projects()
        .first()
        .expect("Project should be discovered");
    assert_eq!(project_audit.local_state().ahead(), Some(0));
    assert_eq!(project_audit.local_state().behind(), Some(0));
    assert_eq!(project_audit.local_state().local_only_branches().len(), 1);

    let review = ProjectCapsuleEngine::local()
        .review(ProjectCapsuleReviewRequest::new(&plan, project_audit))
        .expect("local-only references should be included in the Project Capsule review");
    let capsule = directory.path().join("project-capsule.iniza");
    let capture = ProjectCapsuleEngine::local()
        .capture(ProjectCapsuleCaptureRequest::new(
            &plan,
            project_audit,
            &review,
            review.review_hash(),
            &capsule,
        ))
        .expect("reviewed Project should capture into a verified Project Capsule");
    let expectation = capture
        .expectation()
        .expect("verified Project Capsule should bind an expectation");
    let restored = directory.path().join("restored-project");
    let rehearsal = ProjectCapsuleEngine::local()
        .rehearse(ProjectCapsuleRehearsalRequest::new(
            &capsule,
            expectation,
            capture.offline_recovery_key(),
            &restored,
        ))
        .expect("Project Capsule should restore every reviewed local-only reference");

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::with_git_publication_process(LocalGitPublication);
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    let capture_record = engine
        .record_receipt(ReadinessReceiptRecordRequest::project_capsule_capture(
            &evidence_directory,
            &plan,
            &capture,
        ))
        .expect("verified Project Capsule capture should append");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::project_capsule_rehearsal(
            &evidence_directory,
            &plan,
            &rehearsal,
        ))
        .expect("Restorable Project rehearsal should append");

    let request = || {
        ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
            .with_project_capsule(&capsule, expectation, capture.offline_recovery_key())
            .with_project_publication(project_audit)
    };
    let without_decision = engine
        .status(request())
        .expect("missing owner decision should produce blocking Project evidence");
    assert_eq!(
        without_decision.projects()[0].restorable(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(
        without_decision.projects()[0].synchronized(),
        ReadinessEvidenceConclusion::Missing
    );

    assert!(
        engine
            .prepare_attestation(OwnerAttestationPreparationRequest::new(
                &evidence_directory,
                &plan,
                OwnerAttestationClaimKind::LocalOnlyProjectReferencesRetainedInProjectCapsule,
                "unbound-capsule-decision",
            ))
            .is_err(),
        "a capsule-only decision must bind the current Project Capsule capture"
    );
    let attestation_review = engine
        .prepare_attestation(OwnerAttestationPreparationRequest::new(
            &evidence_directory,
            &plan,
            OwnerAttestationClaimKind::LocalOnlyProjectReferencesRetainedInProjectCapsule,
            capture_record.evidence_reference(),
        ))
        .expect("exact Project Capsule reference should prepare the fixed owner decision");
    let attestation = engine
        .confirm_attestation(OwnerAttestationConfirmationRequest::new(
            &evidence_directory,
            &plan,
            &attestation_review,
            attestation_review.review_hash(),
            attestation_review.required_acknowledgement(),
        ))
        .expect("exact capsule-only owner decision should append");

    let with_decision = engine
        .status(request())
        .expect("current capsule protection and owner decision should revalidate");
    assert_eq!(
        with_decision.projects()[0].synchronized(),
        ReadinessEvidenceConclusion::Current
    );

    engine
        .withdraw_attestation(OwnerAttestationWithdrawalRequest::new(
            &evidence_directory,
            &plan,
            attestation.attestation_identifier(),
            "I withdraw this Owner Attestation.",
        ))
        .expect("owner should be able to withdraw the capsule-only decision");
    let after_withdrawal = engine
        .status(request())
        .expect("withdrawn decision should produce blocking Project evidence");
    assert_eq!(
        after_withdrawal.projects()[0].synchronized(),
        ReadinessEvidenceConclusion::Missing
    );
}

#[test]
fn an_omitted_must_protect_project_remains_visible_and_blocking() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-developer-state");
    let first_project = source.join("first-project");
    let second_project = source.join("second-project");
    fs::create_dir_all(&first_project).expect("first Project should be created");
    fs::create_dir_all(&second_project).expect("second Project should be created");
    for project in [&first_project, &second_project] {
        run_git(project, &["init", "-q", "--initial-branch=main"]);
        fs::write(project.join("tracked.txt"), "synthetic tracked state\n")
            .expect("tracked fixture should be written");
        run_git(project, &["add", "tracked.txt"]);
        run_git_with_identity(project, &["commit", "-q", "-m", "Initial state"]);
    }

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic developer state should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("both Projects should audit");
    assert_eq!(audit.projects().len(), 2);

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    let status = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_project_publication(&audit.projects()[0]),
        )
        .expect("required Project coverage should derive from the approved Plan");

    assert_eq!(status.projects().len(), 2);
    assert!(status.projects().iter().any(|project| {
        project.project_identity() == audit.projects()[1].id()
            && project.restorable() == ReadinessEvidenceConclusion::Missing
            && project.synchronized() == ReadinessEvidenceConclusion::Missing
    }));
    assert!(
        status
            .blocking_gaps()
            .iter()
            .any(|gap| { gap.code() == "required-projects-not-restorable" && gap.count() == 2 })
    );
}

#[test]
fn record_candidate_creation_failure_preserves_the_last_valid_evidence_chain() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let evidence_directory = directory.path().join("readiness-evidence");
    ReadinessEvidenceEngine::local()
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");

    let failed = ReadinessEvidenceEngine::with_storage(RejectCandidateCreation).record_receipt(
        ReadinessReceiptRecordRequest::not_protected_report(&evidence_directory, &plan),
    );
    assert!(
        failed.is_err(),
        "injected creation failure must be returned"
    );

    let status = ReadinessEvidenceEngine::local()
        .status(ReadinessEvidenceStatusRequest::new(
            &evidence_directory,
            &plan,
        ))
        .expect("last valid evidence chain should remain readable");
    assert_eq!(
        status.not_protected_report(),
        ReadinessEvidenceConclusion::Missing
    );
    assert_eq!(
        fs::read_dir(&evidence_directory)
            .expect("evidence directory should remain readable")
            .count(),
        1,
        "failed candidate creation must not add an evidence file"
    );
}

#[test]
fn record_write_failure_never_makes_failed_receipt_current() {
    assert_storage_failure_never_makes_receipt_current(
        ReadinessEvidenceStorageTransition::WriteRecordCandidate,
    );
}

#[test]
fn record_synchronization_failure_never_makes_failed_receipt_current() {
    assert_storage_failure_never_makes_receipt_current(
        ReadinessEvidenceStorageTransition::SynchronizeRecordCandidate,
    );
}

#[test]
fn record_publication_failure_never_makes_failed_receipt_current() {
    assert_storage_failure_never_makes_receipt_current(
        ReadinessEvidenceStorageTransition::PublishRecord,
    );
}

#[test]
fn record_candidate_removal_failure_never_makes_failed_receipt_current() {
    assert_storage_failure_never_makes_receipt_current(
        ReadinessEvidenceStorageTransition::RemoveRecordCandidate,
    );
}

#[test]
fn evidence_directory_synchronization_failure_never_makes_failed_receipt_current() {
    assert_storage_failure_never_makes_receipt_current(
        ReadinessEvidenceStorageTransition::SynchronizeEvidenceDirectory,
    );
}

fn assert_storage_failure_never_makes_receipt_current(
    rejected_transition: ReadinessEvidenceStorageTransition,
) {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let evidence_directory = directory.path().join("readiness-evidence");
    ReadinessEvidenceEngine::local()
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");

    ReadinessEvidenceEngine::with_storage(RejectStorageTransition(rejected_transition))
        .record_receipt(ReadinessReceiptRecordRequest::not_protected_report(
            &evidence_directory,
            &plan,
        ))
        .expect_err("the injected storage failure must prevent a successful record report");

    if let Ok(status) = ReadinessEvidenceEngine::local().status(
        ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan),
    ) {
        assert_ne!(
            status.not_protected_report(),
            ReadinessEvidenceConclusion::Current,
            "an operation that returned failure must not become current evidence"
        );
    }
}

#[test]
fn complete_synthetic_evidence_chain_reports_complete_evidence_without_erase_permission() {
    let directory = TestDirectory::new();
    let project = directory.path().join("synthetic-project");
    let remote = directory.path().join("synthetic-remote.git");
    fs::create_dir(&project).expect("synthetic Project should be created");
    run_git(&project, &["init", "-q", "--initial-branch=main"]);
    run_git(
        directory.path(),
        &[
            "init",
            "-q",
            "--bare",
            remote.to_str().expect("fixture path should be Unicode"),
        ],
    );
    fs::write(project.join("tracked.txt"), "published base\n")
        .expect("base fixture should be written");
    run_git(&project, &["add", "tracked.txt"]);
    run_git_with_identity(&project, &["commit", "-q", "-m", "Published base"]);
    run_git(
        &project,
        &[
            "remote",
            "add",
            "origin",
            remote.to_str().expect("fixture path should be Unicode"),
        ],
    );
    run_git(&project, &["push", "-q", "-u", "origin", "main"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    let project_audit = audit
        .projects()
        .first()
        .expect("Project should be discovered");
    assert_eq!(project_audit.local_state().ahead(), Some(0));
    assert_eq!(project_audit.local_state().behind(), Some(0));
    assert!(project_audit.local_state().local_only_branches().is_empty());
    assert!(project_audit.local_state().local_only_tags().is_empty());

    let project_capsule = directory.path().join("project-capsule.iniza");
    let capsule_review = ProjectCapsuleEngine::local()
        .review(ProjectCapsuleReviewRequest::new(&plan, project_audit))
        .expect("Project should produce a Project Capsule review");
    let capsule_capture = ProjectCapsuleEngine::local()
        .capture(ProjectCapsuleCaptureRequest::new(
            &plan,
            project_audit,
            &capsule_review,
            capsule_review.review_hash(),
            &project_capsule,
        ))
        .expect("Project Capsule should capture");
    let capsule_expectation = capsule_capture
        .expectation()
        .expect("verified Project Capsule should bind an expectation");
    let restored_project = directory.path().join("restored-project");
    let capsule_rehearsal = ProjectCapsuleEngine::local()
        .rehearse(ProjectCapsuleRehearsalRequest::new(
            &project_capsule,
            capsule_expectation,
            capsule_capture.offline_recovery_key(),
            &restored_project,
        ))
        .expect("Project Capsule should rehearse independently");

    let recovery = PackRecoveryContext::from_secrets(
        RecoverySecret::from_bytes(
            RecoveryMethod::Vaultwarden,
            Zeroizing::new(SYNTHETIC_VAULTWARDEN_SECRET),
        ),
        RecoverySecret::from_bytes(
            RecoveryMethod::Offline,
            Zeroizing::new(SYNTHETIC_OFFLINE_SECRET),
        ),
    )
    .expect("synthetic Recovery Methods should be independent");
    let bundle = directory.path().join("migration.iniza");
    let bundle_engine = BundleEngine::local();
    bundle_engine
        .pack(PackRequest::new(&plan, &bundle).with_recovery_context(&recovery))
        .expect("approved Plan should produce a completed Bundle");
    let verification = bundle_engine
        .verify(VerifyRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
        ))
        .expect("completed Bundle should fully verify");

    let offline_document = directory.path().join("offline.iniza-recovery");
    let offline = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage);
    offline
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &offline_document,
            recovery.offline_recovery_key(),
        ))
        .expect("Offline Recovery Key should write to synthetic separate storage");
    let offline_receipt = offline
        .rehearse(OfflineRecoveryRehearsalRequest::new(
            &bundle,
            &offline_document,
        ))
        .expect("Offline Recovery Key should independently authenticate the Bundle");

    let vaultwarden = VaultwardenRecoveryEngine::with_command_line(SyntheticBitwarden::default());
    let installation = vaultwarden
        .inspect_installation(VaultwardenInstallationRequest::trusted_path())
        .expect("synthetic official installation should inspect");
    let preflight = vaultwarden
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            "Synthetic migration",
            Option::<String>::None,
            &installation,
            installation.review_hash(),
        ))
        .expect("synthetic unlocked service should preflight");
    let stored = vaultwarden
        .store_and_rehearse(VaultwardenStoreRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            &preflight,
            preflight.review_hash(),
        ))
        .expect("synthetic Secure Note should be retrieved and verified");
    let vaultwarden_receipt = stored
        .receipt()
        .expect("verified Vaultwarden operation should have a Receipt");
    let loaded = vaultwarden
        .load(VaultwardenLoadRequest::new(
            &bundle,
            vaultwarden_receipt.item_identifier().clone(),
            vaultwarden_receipt.server_identity_hash(),
            &installation,
            installation.review_hash(),
        ))
        .expect("exact Secure Note should load a Recovery Method");

    let first_copy = directory.path().join("external-storage.iniza");
    let second_copy = directory.path().join("cloud-storage.iniza");
    let external_storage =
        SyntheticVerifiedCopyPersistence(VerifiedCopyStorageLocation::ExternalStorage);
    let icloud_drive = SyntheticVerifiedCopyPersistence(VerifiedCopyStorageLocation::ICloudDrive);
    let first_copy_report = bundle_engine
        .copy_verified(
            VerifiedCopyRequest::new(&bundle, &first_copy, loaded.recovery_secret())
                .with_persistence(&external_storage),
        )
        .expect("external-storage Verified Copy should complete");
    let second_copy_report = bundle_engine
        .copy_verified(
            VerifiedCopyRequest::new(&bundle, &second_copy, loaded.recovery_secret())
                .with_persistence(&icloud_drive),
        )
        .expect("cloud-storage Verified Copy should complete");
    let restore_destination = directory.path().join("restore-rehearsal");
    let restore_report = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &restore_destination,
            loaded.recovery_secret(),
        ))
        .expect("safe Restore Rehearsal should complete");

    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::with_adapters(
        LocalGitPublication,
        SyntheticReadinessStorageLocations {
            locations: BTreeMap::from([
                (
                    first_copy.clone(),
                    VerifiedCopyStorageLocation::ExternalStorage,
                ),
                (
                    second_copy.clone(),
                    VerifiedCopyStorageLocation::ICloudDrive,
                ),
            ]),
        },
    );
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::bundle_verification(
            &evidence_directory,
            &plan,
            &bundle,
            &verification,
        ))
        .expect("Bundle verification should append");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::offline_recovery(
            &evidence_directory,
            &plan,
            &offline_receipt,
        ))
        .expect("Offline Recovery Key Receipt should append");
    let vaultwarden_record = engine
        .record_receipt(ReadinessReceiptRecordRequest::vaultwarden_recovery(
            &evidence_directory,
            &plan,
            vaultwarden_receipt,
        ))
        .expect("Vaultwarden Receipt should append");
    for report in [&first_copy_report, &second_copy_report] {
        engine
            .record_receipt(ReadinessReceiptRecordRequest::verified_copy(
                &evidence_directory,
                &plan,
                report,
            ))
            .expect("Verified Copy Receipt should append");
    }
    let restore_record = engine
        .record_receipt(ReadinessReceiptRecordRequest::restore_rehearsal(
            &evidence_directory,
            &plan,
            &restore_report,
        ))
        .expect("Restore Rehearsal Receipt should append");
    engine
        .record_receipt(ReadinessReceiptRecordRequest::project_capsule_capture(
            &evidence_directory,
            &plan,
            &capsule_capture,
        ))
        .expect("Project Capsule capture should append");
    let capsule_rehearsal_record = engine
        .record_receipt(ReadinessReceiptRecordRequest::project_capsule_rehearsal(
            &evidence_directory,
            &plan,
            &capsule_rehearsal,
        ))
        .expect("Project Capsule rehearsal should append");
    let not_protected_report = engine
        .record_receipt(ReadinessReceiptRecordRequest::not_protected_report(
            &evidence_directory,
            &plan,
        ))
        .expect("Not Protected Report should append");

    for (index, claim_kind) in [
        OwnerAttestationClaimKind::ConventionalBackupValidated,
        OwnerAttestationClaimKind::RepresentativeRestoredProjectBuildCompleted,
        OwnerAttestationClaimKind::SecondEnvironmentRehearsalCompleted,
        OwnerAttestationClaimKind::NotProtectedReportReviewed,
        OwnerAttestationClaimKind::ReviewedExternalVaultwardenServiceConfirmed,
        OwnerAttestationClaimKind::FreshDeviceVaultwardenAccessConfirmed,
        OwnerAttestationClaimKind::IndependentMultiFactorRecoveryPathConfirmed,
    ]
    .into_iter()
    .enumerate()
    {
        let evidence_reference = match claim_kind {
            OwnerAttestationClaimKind::NotProtectedReportReviewed => {
                not_protected_report.evidence_reference().to_owned()
            }
            OwnerAttestationClaimKind::RepresentativeRestoredProjectBuildCompleted => {
                capsule_rehearsal_record.evidence_reference().to_owned()
            }
            OwnerAttestationClaimKind::SecondEnvironmentRehearsalCompleted => {
                restore_record.evidence_reference().to_owned()
            }
            OwnerAttestationClaimKind::ReviewedExternalVaultwardenServiceConfirmed
            | OwnerAttestationClaimKind::FreshDeviceVaultwardenAccessConfirmed
            | OwnerAttestationClaimKind::IndependentMultiFactorRecoveryPathConfirmed => {
                vaultwarden_record.evidence_reference().to_owned()
            }
            _ => format!("synthetic-evidence-{index}"),
        };
        let review = engine
            .prepare_attestation(OwnerAttestationPreparationRequest::new(
                &evidence_directory,
                &plan,
                claim_kind,
                evidence_reference,
            ))
            .expect("fixed Owner Attestation should prepare");
        engine
            .confirm_attestation(OwnerAttestationConfirmationRequest::new(
                &evidence_directory,
                &plan,
                &review,
                review.review_hash(),
                review.required_acknowledgement(),
            ))
            .expect("exact Owner Attestation should append");
    }

    let status = engine
        .status(
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, loaded.recovery_secret())
                .with_offline_recovery_document(&offline_document)
                .with_vaultwarden_recovery(&loaded)
                .with_verified_copy(&first_copy)
                .with_verified_copy(&second_copy)
                .with_restore_rehearsal(&restore_destination)
                .with_project_capsule(
                    &project_capsule,
                    capsule_expectation,
                    capsule_capture.offline_recovery_key(),
                )
                .with_project_publication(project_audit),
        )
        .expect("complete synthetic evidence should revalidate");
    assert_eq!(
        status.state(),
        ReadinessEvidenceState::CompleteEvidence,
        "{}",
        status.machine_json_result()
    );
    assert_eq!(status.exit_code(), 0);
    assert_eq!(status.projects().len(), 1);
    assert_eq!(
        status.projects()[0].restorable(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(
        status.projects()[0].synchronized(),
        ReadinessEvidenceConclusion::Current
    );
    assert!(status.human_result().contains("Complete evidence"));
    assert!(
        status
            .human_result()
            .contains("This is not permission to erase a machine.")
    );
}

fn three_record_evidence_store() -> (TestDirectory, Plan, PathBuf) {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");
    for _ in 0..2 {
        engine
            .record_receipt(ReadinessReceiptRecordRequest::not_protected_report(
                &evidence_directory,
                &plan,
            ))
            .expect("synthetic Receipt should append");
    }
    (directory, plan, evidence_directory)
}

#[test]
fn tampered_evidence_record_fails_closed() {
    let (directory, plan, evidence_directory) = three_record_evidence_store();
    let mut records = fs::read_dir(&evidence_directory)
        .expect("evidence records should enumerate")
        .map(|entry| entry.expect("evidence entry should be readable").path())
        .collect::<Vec<_>>();
    records.sort();
    assert_eq!(records.len(), 3);
    let middle = records[1].clone();
    let original = fs::read(&middle).expect("middle evidence record should be readable");

    let mut tampered = original.clone();
    let changed_byte = tampered
        .iter()
        .position(|byte| *byte == b'1')
        .expect("record should contain a digit");
    tampered[changed_byte] = b'2';
    fs::write(&middle, &tampered).expect("synthetic record should be tampered");
    assert!(
        ReadinessEvidenceEngine::local()
            .status(ReadinessEvidenceStatusRequest::new(
                &evidence_directory,
                &plan,
            ))
            .is_err(),
        "tampered record bytes must block status"
    );
    drop(directory);
}

#[test]
fn missing_evidence_sequence_fails_closed() {
    let (directory, plan, evidence_directory) = three_record_evidence_store();
    let mut records = fs::read_dir(&evidence_directory)
        .expect("evidence records should enumerate")
        .map(|entry| entry.expect("evidence entry should be readable").path())
        .collect::<Vec<_>>();
    records.sort();
    let middle = records[1].clone();
    fs::remove_file(&middle).expect("synthetic middle record should be removed");
    assert!(
        ReadinessEvidenceEngine::local()
            .status(ReadinessEvidenceStatusRequest::new(
                &evidence_directory,
                &plan,
            ))
            .is_err(),
        "missing sequence must block status"
    );
    drop(directory);
}

#[test]
fn incomplete_evidence_candidate_fails_closed() {
    let (directory, plan, evidence_directory) = three_record_evidence_store();
    fs::write(
        evidence_directory.join("interrupted.json.incomplete"),
        b"partial",
    )
    .expect("synthetic incomplete candidate should be written");
    assert!(
        ReadinessEvidenceEngine::local()
            .status(ReadinessEvidenceStatusRequest::new(
                &evidence_directory,
                &plan,
            ))
            .is_err(),
        "incomplete candidate must block status"
    );
    drop(directory);
}

#[test]
fn contradictory_active_owner_attestations_remain_a_blocking_gap() {
    let directory = TestDirectory::new();
    let source = directory.path().join("synthetic-state");
    fs::create_dir(&source).expect("synthetic source should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("synthetic source should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic source should scan");
    let plan_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&plan_hash)
        .expect("exact reviewed hash should approve the Plan");
    let evidence_directory = directory.path().join("readiness-evidence");
    let engine = ReadinessEvidenceEngine::local();
    engine
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))
        .expect("approved Plan should initialize a private evidence store");

    for evidence_reference in [
        "conventional-backup:first-observation",
        "conventional-backup:contradictory-observation",
    ] {
        let review = engine
            .prepare_attestation(OwnerAttestationPreparationRequest::new(
                &evidence_directory,
                &plan,
                OwnerAttestationClaimKind::ConventionalBackupValidated,
                evidence_reference,
            ))
            .expect("fixed Owner Attestation should prepare");
        engine
            .confirm_attestation(OwnerAttestationConfirmationRequest::new(
                &evidence_directory,
                &plan,
                &review,
                review.review_hash(),
                review.required_acknowledgement(),
            ))
            .expect("exact Owner Attestation should append");
    }

    let status = engine
        .status(ReadinessEvidenceStatusRequest::new(
            &evidence_directory,
            &plan,
        ))
        .expect("contradictory attestations should remain auditable");
    assert!(
        status
            .blocking_gaps()
            .iter()
            .any(|gap| gap.code() == "contradictory-owner-attestations" && gap.count() == 1)
    );
}

struct RejectCandidateCreation;

struct SyntheticVerifiedCopyPersistence(VerifiedCopyStorageLocation);

impl VerifiedCopyPersistence for SyntheticVerifiedCopyPersistence {
    fn prepare_transition(
        &self,
        _transition: VerifiedCopyPersistenceTransition,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn storage_location(
        &self,
        _source: &Path,
        _destination: &Path,
    ) -> std::io::Result<VerifiedCopyStorageLocation> {
        Ok(self.0)
    }
}

struct SyntheticReadinessStorageLocations {
    locations: BTreeMap<PathBuf, VerifiedCopyStorageLocation>,
}

impl ReadinessEvidenceStorage for SyntheticReadinessStorageLocations {
    fn prepare_transition(
        &self,
        _transition: ReadinessEvidenceStorageTransition,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn verified_copy_storage_location(
        &self,
        _source: &Path,
        destination: &Path,
    ) -> std::io::Result<VerifiedCopyStorageLocation> {
        self.locations.get(destination).copied().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "synthetic Verified Copy location was not registered",
            )
        })
    }
}

impl ReadinessEvidenceStorage for RejectCandidateCreation {
    fn prepare_transition(
        &self,
        transition: ReadinessEvidenceStorageTransition,
    ) -> std::io::Result<()> {
        if transition == ReadinessEvidenceStorageTransition::CreateRecordCandidate {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "synthetic candidate creation failure",
            ))
        } else {
            Ok(())
        }
    }
}

struct RejectStorageTransition(ReadinessEvidenceStorageTransition);

impl ReadinessEvidenceStorage for RejectStorageTransition {
    fn prepare_transition(
        &self,
        transition: ReadinessEvidenceStorageTransition,
    ) -> std::io::Result<()> {
        if transition == self.0 {
            Err(std::io::Error::other(
                "synthetic evidence storage transition failure",
            ))
        } else {
            Ok(())
        }
    }
}

struct LocalGitPublication;

impl GitPublicationProcess for LocalGitPublication {
    fn run(
        &self,
        repository: &Path,
        operation: GitPublicationOperation<'_>,
    ) -> std::io::Result<GitPublicationOutput> {
        let mut command = Command::new("git");
        command
            .arg("-c")
            .arg("protocol.file.allow=always")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("credential.helper=")
            .arg("-C")
            .arg(repository)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "Never");
        match operation {
            GitPublicationOperation::ReadWorkingTreeStatus => {
                command.args([
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                    "--ignore-submodules=all",
                ]);
            }
            GitPublicationOperation::ListLocalReferences => {
                command.args([
                    "for-each-ref",
                    "--format=%(objectname)%00%(refname)",
                    "refs/heads",
                    "refs/tags",
                    "refs/stash",
                ]);
            }
            GitPublicationOperation::ReadLocalReference { reference } => {
                command.args(["rev-parse", "--verify", reference.as_str()]);
            }
            GitPublicationOperation::ReadRemoteReference { remote, reference } => {
                command.args([
                    "ls-remote",
                    "--exit-code",
                    "--refs",
                    "--",
                    remote.as_str(),
                    reference.as_str(),
                ]);
            }
            GitPublicationOperation::CheckAncestor {
                ancestor,
                descendant,
            } => {
                command.args([
                    "merge-base",
                    "--is-ancestor",
                    ancestor.as_str(),
                    descendant.as_str(),
                ]);
            }
            GitPublicationOperation::PushReference {
                remote,
                local_reference,
                remote_reference,
            } => {
                command.args([
                    "push",
                    "--porcelain",
                    "--no-verify",
                    "--no-follow-tags",
                    "--",
                    remote.as_str(),
                    &format!("{}:{}", local_reference.as_str(), remote_reference.as_str()),
                ]);
            }
        }
        let output = command.output()?;
        Ok(GitPublicationOutput {
            status_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

fn run_git(project: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(arguments)
        .output()
        .expect("Git fixture command should start");
    assert!(
        output.status.success(),
        "Git fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_stdout(project: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(arguments)
        .output()
        .expect("Git fixture command should start");
    assert!(
        output.status.success(),
        "Git fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("Git fixture output should be Unicode")
}

fn run_git_with_identity(project: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(arguments)
        .env("GIT_AUTHOR_NAME", "Iniza Test")
        .env("GIT_AUTHOR_EMAIL", "iniza@example.invalid")
        .env("GIT_COMMITTER_NAME", "Iniza Test")
        .env("GIT_COMMITTER_EMAIL", "iniza@example.invalid")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .output()
        .expect("Git fixture command should start");
    assert!(
        output.status.success(),
        "Git fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
