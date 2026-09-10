use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BitwardenCommandLine, BitwardenInstallationObservation, BitwardenRecoveryNote,
    BitwardenRetrievedRecoveryNote, BitwardenVaultObservation, BundleEvent, BundleEventSink,
    CoreError, Disposition, MigrationCaptureOwnerReview, MigrationCaptureRequest,
    MigrationCaptureState, MigrationWorkflowEngine, OfflineRecoveryPersistenceTransition,
    OfflineRecoveryStorage, PackCancellation, PlanEngine, ProtectionRequirement,
    ReadinessEvidenceConclusion, ReadinessEvidenceState, RecoveryMethod, RecoverySecret,
    ScanRequest, SyntheticMigrationRehearsalEngine, SyntheticMigrationRehearsalRequest,
    VaultwardenInstallationReport, VaultwardenInstallationRequest, VaultwardenItemIdentifier,
    VaultwardenPreflightReport, VerifiedCopyDurability, VerifiedCopyPersistence,
    VerifiedCopyPersistenceTransition, VerifiedCopyStorageLocation,
};
use zeroize::Zeroizing;

struct TestDirectory(PathBuf);

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, AtomicOrdering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "iniza-migration-workflow-{}-{unique}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
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

#[derive(Debug, Clone, Default)]
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

struct StoredRecoveryNote {
    item_name: String,
    bundle_identity: String,
    bundle_format: String,
    created_at: String,
    location_hint: Option<String>,
    recovery_secret: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Default)]
struct SyntheticBitwarden {
    note: Arc<Mutex<Option<StoredRecoveryNote>>>,
}

impl SyntheticBitwarden {
    fn installation() -> BitwardenInstallationObservation {
        BitwardenInstallationObservation::new(
            "/synthetic/trusted/bw",
            "2026.8.0",
            "1111111111111111111111111111111111111111111111111111111111111111",
            Some("/synthetic/trusted/node"),
            Some("2222222222222222222222222222222222222222222222222222222222222222"),
        )
        .unwrap()
    }

    fn vault() -> BitwardenVaultObservation {
        BitwardenVaultObservation::unlocked(
            "https://vaultwarden.example.test",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
        .unwrap()
    }

    fn has_recovery_note(&self) -> bool {
        self.note.lock().unwrap().is_some()
    }
}

impl BitwardenCommandLine for SyntheticBitwarden {
    fn inspect_installation(
        &self,
        _request: &VaultwardenInstallationRequest,
    ) -> Result<BitwardenInstallationObservation, CoreError> {
        Ok(Self::installation())
    }

    fn status(
        &self,
        _installation: &BitwardenInstallationObservation,
    ) -> Result<BitwardenVaultObservation, CoreError> {
        Ok(Self::vault())
    }

    fn create_recovery_note(
        &self,
        _installation: &BitwardenInstallationObservation,
        note: &BitwardenRecoveryNote<'_>,
    ) -> Result<VaultwardenItemIdentifier, CoreError> {
        let secret = decode_secret(note.recovery_secret_hex_for_storage().as_str());
        *self.note.lock().unwrap() = Some(StoredRecoveryNote {
            item_name: note.item_name().to_owned(),
            bundle_identity: note.bundle_identity().to_owned(),
            bundle_format: note.bundle_format().to_owned(),
            created_at: note.created_at().to_owned(),
            location_hint: note.location_hint().map(str::to_owned),
            recovery_secret: Zeroizing::new(secret),
        });
        VaultwardenItemIdentifier::parse("37341026-a728-4465-9e3c-8d71b6c712b2")
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
        let note = self.note.lock().unwrap();
        let note = note
            .as_ref()
            .ok_or_else(|| CoreError::Vaultwarden("synthetic note is missing".to_owned()))?;
        BitwardenRetrievedRecoveryNote::new(
            item_identifier.clone(),
            &note.item_name,
            &note.bundle_identity,
            &note.bundle_format,
            &note.created_at,
            note.location_hint.clone(),
            RecoverySecret::from_bytes(
                RecoveryMethod::Vaultwarden,
                Zeroizing::new(*note.recovery_secret),
            ),
        )
    }
}

struct ExactOwnerReview;

impl MigrationCaptureOwnerReview for ExactOwnerReview {
    fn review_bitwarden_installation(
        &self,
        report: &VaultwardenInstallationReport,
    ) -> Result<String, CoreError> {
        Ok(report.review_hash().to_owned())
    }

    fn review_vaultwarden_preflight(
        &self,
        report: &VaultwardenPreflightReport,
    ) -> Result<String, CoreError> {
        Ok(report.review_hash().to_owned())
    }
}

struct StopAfterFirstCapturedItem<'a> {
    cancellation: &'a PackCancellation,
}

impl BundleEventSink for StopAfterFirstCapturedItem<'_> {
    fn emit(&mut self, event: BundleEvent) {
        if matches!(event, BundleEvent::ItemCaptured { .. }) {
            self.cancellation.request_stop();
        }
    }
}

#[test]
fn owner_can_capture_and_independently_verify_both_recovery_methods_before_success() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("developer-settings.txt"),
        b"synthetic developer settings that must stay protected\n",
    )
    .unwrap();

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let plan_hash = plan.approval_hash().unwrap();
    plan.approve(&plan_hash).unwrap();

    let bundle = directory.path().join("migration.iniza");
    let offline_document = directory.path().join("migration.iniza-recovery");
    let workflow = MigrationWorkflowEngine::with_boundaries(
        SyntheticBitwarden::default(),
        SyntheticRemovableStorage,
    );
    let report = workflow
        .capture(
            MigrationCaptureRequest::new(
                &plan,
                &bundle,
                &offline_document,
                "Complete synthetic migration",
                VaultwardenInstallationRequest::explicit("/synthetic/trusted/bw"),
                &ExactOwnerReview,
            )
            .with_location_hint("Synthetic COKS-41 migration rehearsal"),
        )
        .unwrap();

    assert_eq!(report.state(), MigrationCaptureState::Complete);
    assert!(bundle.is_file());
    assert!(offline_document.is_file());
    assert_eq!(
        report.offline_receipt().bundle_identity(),
        report.vaultwarden_receipt().bundle_identity()
    );
    assert_eq!(
        report.offline_verification().bundle_identity(),
        report.vaultwarden_verification().bundle_identity()
    );
    assert_eq!(
        report.offline_verification().bundle_identity(),
        report.offline_receipt().bundle_identity()
    );
    assert_ne!(
        report.offline_receipt().recovery_method_identity(),
        report.vaultwarden_receipt().recovery_method_identity()
    );
    assert_eq!(
        report.vaultwarden_receipt().item_identifier().as_str(),
        "37341026-a728-4465-9e3c-8d71b6c712b2"
    );
    assert_eq!(report.installation_review_hash().len(), 64);
    assert_eq!(report.preflight_review_hash().len(), 64);

    let human = report.human_summary();
    assert!(human.contains("both Recovery Methods independently authenticated"));
    assert!(human.contains("does not decide whether this machine is safe to erase"));
    assert!(!human.contains("\u{1b}["));

    let machine: serde_json::Value = serde_json::from_str(&report.machine_json_result()).unwrap();
    assert_eq!(machine["schema_version"], 1);
    assert_eq!(machine["command"], "migration capture");
    assert_eq!(machine["status"], "success");
    assert_eq!(machine["data"]["state"], "complete");
    assert_eq!(machine["data"]["offline_recovery_verified"], true);
    assert_eq!(machine["data"]["vaultwarden_recovery_verified"], true);
    assert_eq!(machine["data"]["safe_to_erase"], false);

    let output = format!("{report:?}\n{human}\n{}", report.machine_json_result());
    assert!(!output.contains("synthetic developer settings"));
    assert!(!output.contains(&source.display().to_string()));
    assert!(!output.contains(&offline_document.display().to_string()));
    assert!(!output.contains("recovery_secret"));
}

#[test]
fn owner_can_pause_and_resume_pack_only_inside_the_same_live_capture_engine() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("first.txt"), b"first protected value\n").unwrap();
    fs::write(source.join("second.txt"), b"second protected value\n").unwrap();

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let plan_hash = plan.approval_hash().unwrap();
    plan.approve(&plan_hash).unwrap();

    let bundle = directory.path().join("migration.iniza");
    let offline_document = directory.path().join("migration.iniza-recovery");
    let bitwarden = SyntheticBitwarden::default();
    let workflow =
        MigrationWorkflowEngine::with_boundaries(bitwarden.clone(), SyntheticRemovableStorage);
    let cancellation = PackCancellation::default();
    let mut events = StopAfterFirstCapturedItem {
        cancellation: &cancellation,
    };

    let paused = workflow
        .capture(
            MigrationCaptureRequest::new(
                &plan,
                &bundle,
                &offline_document,
                "Paused synthetic migration",
                VaultwardenInstallationRequest::explicit("/synthetic/trusted/bw"),
                &ExactOwnerReview,
            )
            .with_pack_cancellation(&cancellation)
            .with_pack_event_sink(&mut events),
        )
        .unwrap();

    assert_eq!(paused.state(), MigrationCaptureState::Paused);
    assert!(!bundle.exists());
    assert!(!offline_document.exists());
    assert!(!bitwarden.has_recovery_note());
    assert!(paused.human_summary().contains("same live process"));
    assert!(!format!("{paused:?}").contains("recovery_secret"));

    let completed = workflow
        .capture(
            MigrationCaptureRequest::new(
                &plan,
                &bundle,
                &offline_document,
                "Paused synthetic migration",
                VaultwardenInstallationRequest::explicit("/synthetic/trusted/bw"),
                &ExactOwnerReview,
            )
            .resume_paused_pack(),
        )
        .unwrap();

    assert_eq!(completed.state(), MigrationCaptureState::Complete);
    assert!(bundle.is_file());
    assert!(offline_document.is_file());
    assert!(bitwarden.has_recovery_note());
    assert_eq!(
        completed.offline_receipt().bundle_identity(),
        completed.vaultwarden_receipt().bundle_identity()
    );
}

#[derive(Debug)]
struct ClassifiedCopyStorage(VerifiedCopyStorageLocation);

impl VerifiedCopyPersistence for ClassifiedCopyStorage {
    fn prepare_transition(&self, _transition: VerifiedCopyPersistenceTransition) -> io::Result<()> {
        Ok(())
    }

    fn durability(&self) -> VerifiedCopyDurability {
        VerifiedCopyDurability::Durable
    }

    fn storage_location(
        &self,
        _source: &Path,
        _destination: &Path,
    ) -> io::Result<VerifiedCopyStorageLocation> {
        Ok(self.0)
    }
}

#[test]
fn complete_rehearsal_creates_two_verified_copies_and_resumes_an_exact_restore() {
    let directory = TestDirectory::new();
    let rehearsal_root = directory.path().join("complete-rehearsal");
    let bitwarden = SyntheticBitwarden::default();
    let engine = SyntheticMigrationRehearsalEngine::with_boundaries(
        bitwarden,
        SyntheticRemovableStorage,
        ClassifiedCopyStorage(VerifiedCopyStorageLocation::ExternalStorage),
        ClassifiedCopyStorage(VerifiedCopyStorageLocation::ICloudDrive),
    );

    let report = engine
        .run(SyntheticMigrationRehearsalRequest::new(
            &rehearsal_root,
            VaultwardenInstallationRequest::explicit("/synthetic/trusted/bw"),
            &ExactOwnerReview,
        ))
        .unwrap();

    assert_eq!(report.capture().state(), MigrationCaptureState::Complete);
    assert!(report.external_copy().is_verified());
    assert_eq!(
        report.external_copy().storage_location(),
        VerifiedCopyStorageLocation::ExternalStorage
    );
    assert!(report.cloud_copy().is_verified());
    assert_eq!(
        report.cloud_copy().storage_location(),
        VerifiedCopyStorageLocation::ICloudDrive
    );
    assert_ne!(
        report.external_copy().destination_evidence_identity(),
        report.cloud_copy().destination_evidence_identity()
    );
    assert!(report.restore_was_resumed());
    assert!(report.exact_comparison_passed());
    assert!(report.receipt_invalidation_was_detected());
    assert_eq!(
        report.readiness_status().state(),
        ReadinessEvidenceState::BlockingGaps,
        "synthetic machine evidence must not invent the owner attestations"
    );
    assert_eq!(
        report.readiness_status().bundle_verification(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(
        report.readiness_status().offline_recovery_method(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(
        report.readiness_status().vaultwarden_recovery_method(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(
        report.readiness_status().verified_copy(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(
        report.readiness_status().not_protected_report(),
        ReadinessEvidenceConclusion::Current
    );
    assert_eq!(
        report.readiness_status().restore_rehearsal(),
        ReadinessEvidenceConclusion::Current
    );
    let not_protected = report.not_protected_report();
    assert!(!not_protected.has_must_protect_gap());
    assert!(not_protected.entries().iter().any(|entry| {
        entry.relative_path() == Path::new("generated.cache")
            && entry.disposition() == Disposition::Excluded
            && entry.protection_requirement() == ProtectionRequirement::Optional
    }));
    assert!(not_protected.entries().iter().any(|entry| {
        entry.relative_path() == Path::new("review-needed-link")
            && entry.disposition() == Disposition::RequiresReview
            && entry.protection_requirement() == ProtectionRequirement::Optional
    }));
    assert!(not_protected.entries().iter().any(|entry| {
        entry.relative_path() == Path::new("optional-worker.pipe")
            && entry.disposition() == Disposition::Unsupported
            && entry.protection_requirement() == ProtectionRequirement::Optional
    }));
    assert!(
        not_protected
            .report_identity()
            .starts_with("not_protected_blake3_")
    );
    assert_eq!(
        fs::read(
            rehearsal_root
                .join("restored")
                .join("developer-config")
                .join("shell-settings.txt")
        )
        .unwrap(),
        b"synthetic shell settings\n"
    );
    assert!(!rehearsal_root.join("restored/.iniza-restore").exists());

    let human = report.human_summary();
    assert!(human.contains("two Verified Copies"));
    assert!(human.contains("Restore Rehearsal"));
    assert!(human.contains("append-only Readiness Evidence"));
    assert!(human.contains("Owner Attestations remain unconfirmed"));
    assert!(human.contains("does not authorize real source capture"));
    assert!(human.contains("does not decide whether this machine is safe to erase"));
    assert!(!human.contains("\u{1b}["));

    let machine: serde_json::Value = serde_json::from_str(&report.machine_json_result()).unwrap();
    assert_eq!(machine["schema_version"], 1);
    assert_eq!(machine["command"], "migration rehearse");
    assert_eq!(machine["status"], "success");
    assert_eq!(machine["data"]["verified_copies"], 2);
    assert_eq!(machine["data"]["restore_resumed"], true);
    assert_eq!(machine["data"]["exact_comparison_passed"], true);
    assert_eq!(machine["data"]["not_protected_items"], 3);
    assert_eq!(machine["data"]["must_protect_gaps"], 0);
    assert_eq!(machine["data"]["receipt_invalidation_detected"], true);
    assert_eq!(machine["data"]["readiness_state"], "blocking-gaps");
    assert_eq!(machine["data"]["real_source_capture_authorized"], false);
    assert_eq!(machine["data"]["safe_to_erase"], false);

    let output = format!("{report:?}\n{human}\n{}", report.machine_json_result());
    assert!(!output.contains(&rehearsal_root.display().to_string()));
    assert!(!output.contains("synthetic shell settings"));
    assert!(!output.contains("recovery_secret"));
}

fn decode_secret(encoded: &str) -> [u8; 32] {
    assert_eq!(encoded.len(), 64);
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).unwrap();
    }
    decoded
}
