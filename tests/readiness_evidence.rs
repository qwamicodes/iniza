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
    PackRequest, PlanEngine, ProjectAuditEngine, ProjectAuditRequest, ProjectCapsuleCaptureRequest,
    ProjectCapsuleEngine, ProjectCapsuleRehearsalRequest, ProjectCapsuleReviewRequest,
    PushPlanApprovalRequest, PushPlanDraftRequest, PushPlanEngine, PushPlanExecutionRequest,
    ReadinessEvidenceConclusion, ReadinessEvidenceEngine, ReadinessEvidenceInitializationRequest,
    ReadinessEvidenceState, ReadinessEvidenceStatusRequest, ReadinessReceiptRecordRequest,
    RecoveryMethod, RecoverySecret, RestoreEngine, RestoreRequest, ScanRequest,
    VaultwardenInstallationRequest, VaultwardenItemIdentifier, VaultwardenLoadRequest,
    VaultwardenPreflightRequest, VaultwardenRecoveryEngine, VaultwardenStoreRequest,
    VerifiedCopyRequest, VerifyRequest,
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
            OwnerAttestationClaimKind::ReviewedExternalVaultwardenServiceConfirmed,
            "vaultwarden-receipt:synthetic-reference-1",
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
        "I confirm that the reviewed Vaultwarden service is external to the source Mac."
    );
    assert_eq!(
        review.evidence_reference(),
        "vaultwarden-receipt:synthetic-reference-1"
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
            OwnerAttestationClaimKind::ReviewedExternalVaultwardenServiceConfirmed,
            "vaultwarden-receipt:synthetic-reference-2",
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

    let cases = [
        (
            OwnerAttestationClaimKind::ConventionalBackupValidated,
            "I confirm that the conventional backup was validated.",
        ),
        (
            OwnerAttestationClaimKind::RepresentativeRestoredProjectBuildCompleted,
            "I confirm that a representative restored Project build completed.",
        ),
        (
            OwnerAttestationClaimKind::SecondEnvironmentRehearsalCompleted,
            "I confirm that the second-environment Restore Rehearsal completed.",
        ),
        (
            OwnerAttestationClaimKind::NotProtectedReportReviewed,
            "I confirm that I reviewed the Not Protected Report.",
        ),
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
    ];

    for (index, (claim_kind, expected_text)) in cases.into_iter().enumerate() {
        let review = engine
            .prepare_attestation(OwnerAttestationPreparationRequest::new(
                &evidence_directory,
                &plan,
                claim_kind,
                format!("evidence:synthetic-{index}"),
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
            copied.receipt(),
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
    engine
        .record_receipt(ReadinessReceiptRecordRequest::vaultwarden_recovery(
            &evidence_directory,
            &plan,
            receipt,
        ))
        .expect("typed Vaultwarden Receipt should append");

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
    engine
        .record_receipt(ReadinessReceiptRecordRequest::project_capsule_rehearsal(
            &evidence_directory,
            &plan,
            &rehearsal,
        ))
        .expect("Restorable Project rehearsal should append");

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
    engine
        .record_receipt(ReadinessReceiptRecordRequest::restore_rehearsal(
            &evidence_directory,
            &plan,
            &restored,
        ))
        .expect("completed Restore Rehearsal should append");

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
    for receipt in [first.receipt(), second.receipt()] {
        engine
            .record_receipt(ReadinessReceiptRecordRequest::verified_copy(
                &evidence_directory,
                &plan,
                receipt,
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
