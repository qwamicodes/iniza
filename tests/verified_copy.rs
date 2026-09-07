use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BundleEngine, CoreError, PackRecoveryContext, PackRequest, PlanEngine, RecoveryMethod,
    RecoverySecret, ScanRequest, VerifiedCopyCancellation, VerifiedCopyDurability,
    VerifiedCopyEvent, VerifiedCopyEventSink, VerifiedCopyPersistence,
    VerifiedCopyPersistenceTransition, VerifiedCopyRequest, VerifyRequest,
};
use zeroize::Zeroizing;

struct TestDirectory(PathBuf);

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should follow the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-verified-copy-{}-{unique}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).expect("isolated test directory should be created");
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

#[test]
fn owner_can_create_a_verified_copy_with_matching_bytes_identity_and_digest() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source-state");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let source_bundle = directory.path().join("source.iniza");
    let destination_bundle = directory.path().join("independent-copy.iniza");
    let engine = BundleEngine::local();
    let packed = engine
        .pack(PackRequest::new(&plan, &source_bundle))
        .unwrap();

    let copied = engine
        .copy_verified(VerifiedCopyRequest::new(
            &source_bundle,
            &destination_bundle,
            packed.offline_recovery_key(),
        ))
        .unwrap();

    assert!(copied.is_verified());
    assert_eq!(
        fs::read(&source_bundle).unwrap(),
        fs::read(&destination_bundle).unwrap()
    );
    assert_eq!(copied.source_digest(), copied.destination_digest());
    assert_eq!(
        copied.source_bundle_identity(),
        copied.destination_bundle_identity()
    );
    assert_eq!(
        BundleEngine::local()
            .verify(VerifyRequest::new(
                &destination_bundle,
                packed.vaultwarden_recovery_secret(),
            ))
            .unwrap()
            .authenticated_bytes,
        19
    );

    let receipt = copied.receipt();
    assert_eq!(receipt.schema_version(), 1);
    assert_eq!(receipt.operation(), "verified-copy");
    assert_eq!(receipt.result(), "verified");
    assert_eq!(
        receipt.source_bundle_identity(),
        copied.source_bundle_identity()
    );
    assert_eq!(
        receipt.destination_bundle_identity(),
        copied.destination_bundle_identity()
    );
    assert_eq!(receipt.whole_file_digest(), copied.destination_digest());
    assert!(receipt.verified_at_unix_seconds() > 0);
    let machine: serde_json::Value = serde_json::from_str(&receipt.machine_json_result()).unwrap();
    assert_eq!(machine["schema_version"], 1);
    assert_eq!(machine["operation"], "verified-copy");
    assert_eq!(machine["result"], "verified");
    assert!(machine.get("destination_evidence_identity").is_none());
    assert!(machine.get("durability").is_none());
    assert!(machine.get("source_path").is_none());
    assert!(machine.get("destination_path").is_none());
    assert_eq!(copied.human_summary(), "Verified Copy created.");
    let result: serde_json::Value = serde_json::from_str(&copied.machine_json_result()).unwrap();
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "copy");
    assert_eq!(result["status"], "success");
    assert_eq!(result["data"]["verified"], true);
    assert_eq!(
        result["data"]["whole_file_digest"],
        copied.destination_digest()
    );
    assert_eq!(result["warnings"], serde_json::json!([]));
}

#[test]
fn verified_copy_refuses_incomplete_or_invalid_source_bundles() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source-state");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let completed = directory.path().join("source.iniza");
    let engine = BundleEngine::local();
    let packed = engine.pack(PackRequest::new(&plan, &completed)).unwrap();
    let disguised_partial = directory.path().join("disguised.iniza.partial");
    fs::copy(&completed, &disguised_partial).unwrap();
    let destination = directory.path().join("copy.iniza");

    let partial_error = engine
        .copy_verified(VerifiedCopyRequest::new(
            &disguised_partial,
            &destination,
            packed.offline_recovery_key(),
        ))
        .unwrap_err();
    assert!(matches!(partial_error, CoreError::BundleIncomplete(_)));
    assert!(!destination.exists());

    let invalid = directory.path().join("invalid.iniza");
    fs::write(&invalid, b"not an authenticated Bundle").unwrap();
    engine
        .copy_verified(VerifiedCopyRequest::new(
            &invalid,
            &destination,
            packed.offline_recovery_key(),
        ))
        .unwrap_err();
    assert!(!destination.exists());
    assert!(!directory.path().join("copy.iniza.partial").exists());
}

#[test]
fn verified_copy_never_overwrites_an_existing_final_destination() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source-state");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let source_bundle = directory.path().join("source.iniza");
    let destination = directory.path().join("copy.iniza");
    let engine = BundleEngine::local();
    let packed = engine
        .pack(PackRequest::new(&plan, &source_bundle))
        .unwrap();
    fs::write(&destination, b"unrelated destination bytes").unwrap();

    let error = engine
        .copy_verified(VerifiedCopyRequest::new(
            &source_bundle,
            &destination,
            packed.offline_recovery_key(),
        ))
        .unwrap_err();

    assert!(matches!(error, CoreError::DestinationAlreadyExists(path) if path == destination));
    assert_eq!(
        fs::read(directory.path().join("copy.iniza")).unwrap(),
        b"unrelated destination bytes"
    );
    assert!(!directory.path().join("copy.iniza.partial").exists());
}

#[test]
fn only_an_explicitly_approved_matching_partial_copy_can_be_replaced() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source-state");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let source_bundle = directory.path().join("source.iniza");
    let destination = directory.path().join("copy.iniza");
    let partial = directory.path().join("copy.iniza.partial");
    let engine = BundleEngine::local();
    let packed = engine
        .pack(PackRequest::new(&plan, &source_bundle))
        .unwrap();
    let source_bytes = fs::read(&source_bundle).unwrap();
    fs::write(&partial, &source_bytes[..source_bytes.len() / 2]).unwrap();

    engine
        .copy_verified(VerifiedCopyRequest::new(
            &source_bundle,
            &destination,
            packed.offline_recovery_key(),
        ))
        .unwrap_err();
    assert_eq!(
        fs::read(&partial).unwrap(),
        &source_bytes[..source_bytes.len() / 2]
    );

    let copied = engine
        .copy_verified(
            VerifiedCopyRequest::new(&source_bundle, &destination, packed.offline_recovery_key())
                .replace_matching_partial(),
        )
        .unwrap();
    assert!(copied.is_verified());
    assert!(!partial.exists());

    let second_destination = directory.path().join("second-copy.iniza");
    let unrelated_partial = directory.path().join("second-copy.iniza.partial");
    fs::write(&unrelated_partial, b"unrelated partial bytes").unwrap();
    engine
        .copy_verified(
            VerifiedCopyRequest::new(
                &source_bundle,
                &second_destination,
                packed.offline_recovery_key(),
            )
            .replace_matching_partial(),
        )
        .unwrap_err();
    assert_eq!(
        fs::read(&unrelated_partial).unwrap(),
        b"unrelated partial bytes"
    );
    assert!(!second_destination.exists());
}

#[derive(Default)]
struct CopyEvents(Vec<VerifiedCopyEvent>);

impl VerifiedCopyEventSink for CopyEvents {
    fn emit(&mut self, event: VerifiedCopyEvent) {
        self.0.push(event);
    }
}

#[test]
fn cancelled_copy_stays_visibly_partial_and_can_be_explicitly_retried() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source-state");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let source_bundle = directory.path().join("source.iniza");
    let destination = directory.path().join("copy.iniza");
    let partial = directory.path().join("copy.iniza.partial");
    let engine = BundleEngine::local();
    let packed = engine
        .pack(PackRequest::new(&plan, &source_bundle))
        .unwrap();
    let cancellation = VerifiedCopyCancellation::default();
    cancellation.request_stop();
    let mut events = CopyEvents::default();

    let error = engine
        .copy_verified(
            VerifiedCopyRequest::new(&source_bundle, &destination, packed.offline_recovery_key())
                .with_cancellation(&cancellation)
                .with_event_sink(&mut events),
        )
        .unwrap_err();

    assert!(matches!(error, CoreError::CopyInterrupted(path) if path == partial));
    assert!(!destination.exists());
    assert!(partial.is_file());
    assert!(matches!(
        engine.verify(VerifyRequest::new(&partial, packed.offline_recovery_key(),)),
        Err(CoreError::BundleIncomplete(_))
    ));
    assert!(matches!(
        events.0.first(),
        Some(VerifiedCopyEvent::CopyStarted)
    ));
    assert!(matches!(
        events.0.last(),
        Some(VerifiedCopyEvent::CopyPaused { copied_bytes }) if *copied_bytes > 0
    ));

    let completed = engine
        .copy_verified(
            VerifiedCopyRequest::new(&source_bundle, &destination, packed.offline_recovery_key())
                .replace_matching_partial(),
        )
        .unwrap();
    assert!(completed.is_verified());
    assert!(!partial.exists());
}

struct WeakerDurability;

impl VerifiedCopyPersistence for WeakerDurability {
    fn prepare_transition(&self, _transition: VerifiedCopyPersistenceTransition) -> io::Result<()> {
        Ok(())
    }

    fn durability(&self) -> VerifiedCopyDurability {
        VerifiedCopyDurability::Weaker
    }
}

#[test]
fn verified_copy_reports_when_the_destination_has_weaker_durability() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source-state");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let source_bundle = directory.path().join("source.iniza");
    let destination = directory.path().join("copy.iniza");
    let engine = BundleEngine::local();
    let packed = engine
        .pack(PackRequest::new(&plan, &source_bundle))
        .unwrap();

    let copied = engine
        .copy_verified(
            VerifiedCopyRequest::new(&source_bundle, &destination, packed.offline_recovery_key())
                .with_persistence(&WeakerDurability),
        )
        .unwrap();

    assert!(copied.is_verified());
    assert_eq!(copied.durability(), VerifiedCopyDurability::Weaker);
    assert!(
        copied
            .warnings()
            .iter()
            .any(|warning| warning.contains("weaker filesystem durability"))
    );
}

struct FailCopyPersistenceOnce {
    target: VerifiedCopyPersistenceTransition,
    kind: io::ErrorKind,
    failed: AtomicBool,
}

enum CopyMutation {
    Truncate,
    ReplaceFirstByte,
}

struct MutateCopyAtTransition {
    target: VerifiedCopyPersistenceTransition,
    path: PathBuf,
    mutation: CopyMutation,
    mutated: AtomicBool,
}

impl VerifiedCopyPersistence for MutateCopyAtTransition {
    fn prepare_transition(&self, transition: VerifiedCopyPersistenceTransition) -> io::Result<()> {
        if transition == self.target && !self.mutated.swap(true, Ordering::SeqCst) {
            match self.mutation {
                CopyMutation::Truncate => {
                    let length = fs::metadata(&self.path)?.len();
                    fs::OpenOptions::new()
                        .write(true)
                        .open(&self.path)?
                        .set_len(length / 2)?;
                }
                CopyMutation::ReplaceFirstByte => {
                    use std::io::{Seek, SeekFrom, Write};

                    let mut file = fs::OpenOptions::new().write(true).open(&self.path)?;
                    file.seek(SeekFrom::Start(0))?;
                    file.write_all(b"X")?;
                    file.sync_all()?;
                }
            }
        }
        Ok(())
    }
}

impl VerifiedCopyPersistence for FailCopyPersistenceOnce {
    fn prepare_transition(&self, transition: VerifiedCopyPersistenceTransition) -> io::Result<()> {
        if transition == self.target && !self.failed.swap(true, Ordering::SeqCst) {
            return Err(io::Error::from(self.kind));
        }
        Ok(())
    }
}

#[test]
fn permission_failure_at_every_copy_transition_never_reports_an_unchecked_verified_copy() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source-state");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let source_bundle = directory.path().join("source.iniza");
    let engine = BundleEngine::local();
    let packed = engine
        .pack(PackRequest::new(&plan, &source_bundle))
        .unwrap();

    for (ordinal, transition, final_may_exist) in [
        (0, VerifiedCopyPersistenceTransition::ReadSource, false),
        (1, VerifiedCopyPersistenceTransition::CreatePartial, false),
        (2, VerifiedCopyPersistenceTransition::WritePartial, false),
        (
            3,
            VerifiedCopyPersistenceTransition::SynchronizePartial,
            false,
        ),
        (
            4,
            VerifiedCopyPersistenceTransition::AuthenticatePartial,
            false,
        ),
        (
            5,
            VerifiedCopyPersistenceTransition::PublishCompleted,
            false,
        ),
        (
            6,
            VerifiedCopyPersistenceTransition::SynchronizeDirectory,
            true,
        ),
        (7, VerifiedCopyPersistenceTransition::ReopenCompleted, true),
    ] {
        let destination = directory.path().join(format!("copy-{ordinal}.iniza"));
        let persistence = FailCopyPersistenceOnce {
            target: transition,
            kind: io::ErrorKind::PermissionDenied,
            failed: AtomicBool::new(false),
        };

        engine
            .copy_verified(
                VerifiedCopyRequest::new(
                    &source_bundle,
                    &destination,
                    packed.offline_recovery_key(),
                )
                .with_persistence(&persistence),
            )
            .unwrap_err();

        assert!(persistence.failed.load(Ordering::SeqCst));
        if final_may_exist {
            assert_eq!(
                engine
                    .verify(VerifyRequest::new(
                        &destination,
                        packed.offline_recovery_key(),
                    ))
                    .unwrap()
                    .authenticated_bytes,
                19
            );
        } else {
            assert!(!destination.exists());
        }
    }
}

#[test]
fn cloud_placeholder_read_failure_stops_before_destination_creation() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source-state");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let source_bundle = directory.path().join("source.iniza");
    let destination = directory.path().join("copy.iniza");
    let engine = BundleEngine::local();
    let packed = engine
        .pack(PackRequest::new(&plan, &source_bundle))
        .unwrap();
    let persistence = FailCopyPersistenceOnce {
        target: VerifiedCopyPersistenceTransition::ReadSource,
        kind: io::ErrorKind::WouldBlock,
        failed: AtomicBool::new(false),
    };

    let error = engine
        .copy_verified(
            VerifiedCopyRequest::new(&source_bundle, &destination, packed.offline_recovery_key())
                .with_persistence(&persistence),
        )
        .unwrap_err();

    assert!(
        matches!(error, CoreError::Io { source, .. } if source.kind() == io::ErrorKind::WouldBlock)
    );
    assert!(!destination.exists());
    assert!(!directory.path().join("copy.iniza.partial").exists());
}

#[test]
fn truncated_or_mutated_copy_output_is_never_reported_as_verified() {
    for (ordinal, transition, mutation, final_is_visible) in [
        (
            0,
            VerifiedCopyPersistenceTransition::AuthenticatePartial,
            CopyMutation::Truncate,
            false,
        ),
        (
            1,
            VerifiedCopyPersistenceTransition::ReopenCompleted,
            CopyMutation::ReplaceFirstByte,
            true,
        ),
    ] {
        let directory = TestDirectory::new();
        let source = directory.path().join("source-state");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
        let mut plan = PlanEngine::local()
            .scan(ScanRequest::for_directory(&source))
            .unwrap();
        let reviewed_hash = plan.approval_hash().unwrap();
        plan.approve(&reviewed_hash).unwrap();
        let source_bundle = directory.path().join("source.iniza");
        let destination = directory.path().join(format!("copy-{ordinal}.iniza"));
        let mutation_path = if final_is_visible {
            destination.clone()
        } else {
            directory
                .path()
                .join(format!("copy-{ordinal}.iniza.partial"))
        };
        let engine = BundleEngine::local();
        let packed = engine
            .pack(PackRequest::new(&plan, &source_bundle))
            .unwrap();
        let persistence = MutateCopyAtTransition {
            target: transition,
            path: mutation_path,
            mutation,
            mutated: AtomicBool::new(false),
        };

        engine
            .copy_verified(
                VerifiedCopyRequest::new(
                    &source_bundle,
                    &destination,
                    packed.offline_recovery_key(),
                )
                .with_persistence(&persistence),
            )
            .unwrap_err();

        assert!(persistence.mutated.load(Ordering::SeqCst));
        assert_eq!(destination.exists(), final_is_visible);
        assert!(
            engine
                .verify(VerifyRequest::new(
                    &destination,
                    packed.offline_recovery_key(),
                ))
                .is_err()
        );
    }
}

#[test]
fn verified_copy_requires_an_iniza_destination_so_interruption_is_always_recognizable() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source-state");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let source_bundle = directory.path().join("source.iniza");
    let unsafe_destination = directory.path().join("copy.bundle");
    let engine = BundleEngine::local();
    let packed = engine
        .pack(PackRequest::new(&plan, &source_bundle))
        .unwrap();

    let error = engine
        .copy_verified(VerifiedCopyRequest::new(
            &source_bundle,
            &unsafe_destination,
            packed.offline_recovery_key(),
        ))
        .unwrap_err();

    assert!(
        matches!(error, CoreError::BundleInvalid(message) if message.contains("must end with .iniza"))
    );
    assert!(!unsafe_destination.exists());
    assert!(!directory.path().join("copy.bundle.partial").exists());
}

struct CreateCollisionAtPublication {
    destination: PathBuf,
    created: AtomicBool,
}

impl VerifiedCopyPersistence for CreateCollisionAtPublication {
    fn prepare_transition(&self, transition: VerifiedCopyPersistenceTransition) -> io::Result<()> {
        if transition == VerifiedCopyPersistenceTransition::PublishCompleted
            && !self.created.swap(true, Ordering::SeqCst)
        {
            fs::write(&self.destination, b"late unrelated destination")?;
        }
        Ok(())
    }
}

#[test]
fn destination_created_during_copy_is_preserved_and_never_overwritten() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source-state");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let source_bundle = directory.path().join("source.iniza");
    let destination = directory.path().join("copy.iniza");
    let engine = BundleEngine::local();
    let packed = engine
        .pack(PackRequest::new(&plan, &source_bundle))
        .unwrap();
    let persistence = CreateCollisionAtPublication {
        destination: destination.clone(),
        created: AtomicBool::new(false),
    };

    let error = engine
        .copy_verified(
            VerifiedCopyRequest::new(&source_bundle, &destination, packed.offline_recovery_key())
                .with_persistence(&persistence),
        )
        .unwrap_err();

    assert!(matches!(error, CoreError::DestinationAlreadyExists(path) if path == destination));
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"late unrelated destination"
    );
    assert!(directory.path().join("copy.iniza.partial").is_file());
}

#[test]
fn verified_copy_receipt_and_results_never_disclose_recovery_secrets_or_paths() {
    let directory = TestDirectory::new();
    let source = directory.path().join("sensitive-source-name");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("secret-file-name.txt"), b"synthetic settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let source_bundle = directory.path().join("sensitive-source.iniza");
    let destination = directory.path().join("sensitive-destination.iniza");
    let recovery = PackRecoveryContext::from_secrets(
        RecoverySecret::from_bytes(RecoveryMethod::Vaultwarden, Zeroizing::new([0x31_u8; 32])),
        RecoverySecret::from_bytes(RecoveryMethod::Offline, Zeroizing::new([0x47_u8; 32])),
    )
    .unwrap();
    let engine = BundleEngine::local();
    engine
        .pack(PackRequest::new(&plan, &source_bundle).with_recovery_context(&recovery))
        .unwrap();

    let copied = engine
        .copy_verified(VerifiedCopyRequest::new(
            &source_bundle,
            &destination,
            recovery.offline_recovery_key(),
        ))
        .unwrap();
    let output = format!(
        "{:?}\n{}\n{}",
        copied,
        copied.machine_json_result(),
        copied.receipt().machine_json_result()
    );

    assert!(!output.contains("31313131"));
    assert!(!output.contains("47474747"));
    assert!(!output.contains("sensitive-source"));
    assert!(!output.contains("sensitive-destination"));
    assert!(!output.contains("secret-file-name"));
}
