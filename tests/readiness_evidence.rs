use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use iniza::{
    BundleEngine, OfflineRecoveryEngine, OfflineRecoveryPersistenceTransition,
    OfflineRecoveryRehearsalRequest, OfflineRecoveryStorage, OfflineRecoveryWriteRequest,
    OwnerAttestationClaimKind, OwnerAttestationConfirmationRequest,
    OwnerAttestationPreparationRequest, OwnerAttestationWithdrawalRequest, PackRequest, PlanEngine,
    ReadinessEvidenceConclusion, ReadinessEvidenceEngine, ReadinessEvidenceInitializationRequest,
    ReadinessEvidenceState, ReadinessEvidenceStatusRequest, ReadinessReceiptRecordRequest,
    ScanRequest, VerifiedCopyRequest, VerifyRequest,
};

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
