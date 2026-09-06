use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BundleEngine, OfflineRecoveryEngine, OfflineRecoveryLoadRequest,
    OfflineRecoveryPersistenceTransition, OfflineRecoveryRehearsalRequest, OfflineRecoveryStorage,
    OfflineRecoveryWriteRequest, PackRequest, PlanEngine, RecoveryMethod, RecoverySecret,
    RestoreEngine, RestoreRequest, ScanRequest, VerifyRequest,
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
        let path = std::env::temp_dir().join(format!(
            "iniza-offline-recovery-{}-{unique}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::SeqCst)
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

fn completed_bundle(directory: &TestDirectory) -> (PathBuf, iniza::PackReport) {
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic owner settings\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let bundle = directory.path().join("migration.iniza");
    let report = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .unwrap();
    (bundle, report)
}

#[test]
fn owner_can_write_and_independently_rehearse_an_offline_recovery_key() {
    let directory = TestDirectory::new();
    let (bundle, packed) = completed_bundle(&directory);
    let recovery_document = directory.path().join("separate.iniza-recovery");
    let engine = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage);

    let written = engine
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &recovery_document,
            packed.offline_recovery_key(),
        ))
        .unwrap();

    assert!(recovery_document.is_file());
    let document = fs::read_to_string(&recovery_document).unwrap();
    assert!(document.starts_with("INIZA OFFLINE RECOVERY KEY\n"));
    assert!(document.contains("schema_version: 1\n"));
    assert!(document.contains("bundle_format: IZ2\n"));
    assert!(document.contains("recovery_method: offline\n"));
    assert_eq!(document.lines().count(), 8);
    assert!(!document.contains("synthetic owner settings"));
    assert!(!format!("{written:?}").contains("recovery_secret"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&recovery_document)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let receipt = engine
        .rehearse(OfflineRecoveryRehearsalRequest::new(
            &bundle,
            &recovery_document,
        ))
        .unwrap();
    assert_eq!(receipt.bundle_identity(), written.bundle_identity());
    assert_eq!(
        receipt.recovery_method_identity(),
        written.recovery_method_identity()
    );
    assert!(receipt.verified_at_unix_seconds() > 0);
    assert!(!format!("{receipt:?}").contains("recovery_secret"));
}

#[test]
fn saved_offline_recovery_key_can_drive_restore_without_the_other_method() {
    let directory = TestDirectory::new();
    let (bundle, packed) = completed_bundle(&directory);
    let recovery_document = directory.path().join("restore.iniza-recovery");
    let engine = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage);
    engine
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &recovery_document,
            packed.offline_recovery_key(),
        ))
        .unwrap();

    let loaded = engine
        .load(OfflineRecoveryLoadRequest::new(&bundle, &recovery_document))
        .unwrap();
    let destination = directory.path().join("restored");
    RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            loaded.recovery_secret(),
        ))
        .unwrap();

    assert_eq!(
        fs::read(destination.join("settings.txt")).unwrap(),
        b"synthetic owner settings\n"
    );
    assert!(!format!("{loaded:?}").contains("recovery_secret_hex"));
}

#[test]
fn offline_recovery_process_capture_child() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_OFFLINE_RECOVERY_CHILD") else {
        return;
    };
    let directory = TestDirectory(PathBuf::from(root));
    let (bundle, packed) = completed_bundle(&directory);
    let plan_path = directory.path().join("reviewed-plan.toml");
    let source = directory.path().join("source");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    plan.write_to(&plan_path).unwrap();
    let document = directory.path().join("captured.iniza-recovery");
    let engine = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage);
    let written = engine
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &document,
            packed.offline_recovery_key(),
        ))
        .unwrap();
    println!("{}", written.human_summary());
    println!("{}", written.machine_json_result());
    let receipt = engine
        .rehearse(OfflineRecoveryRehearsalRequest::new(&bundle, &document))
        .unwrap();
    println!("{}", receipt.human_summary());
    println!("{}", receipt.machine_json_result());
    eprintln!("{}", engine.lost_document_guidance());
    std::mem::forget(directory);
}

#[test]
fn process_arguments_outputs_plan_and_receipt_never_disclose_the_offline_secret() {
    let directory = TestDirectory::new();
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("offline_recovery_process_capture_child")
        .arg("--exact")
        .arg("--nocapture")
        .env("INIZA_SYNTHETIC_OFFLINE_RECOVERY_CHILD", directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document_path = directory.path().join("captured.iniza-recovery");
    let document = fs::read_to_string(&document_path).unwrap();
    let secret = document
        .lines()
        .find_map(|line| line.strip_prefix("recovery_secret_hex: "))
        .unwrap();
    assert_eq!(secret.len(), 64);
    let plan = fs::read_to_string(directory.path().join("reviewed-plan.toml")).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!plan.contains(secret));
    assert!(!stdout.contains(secret));
    assert!(!stderr.contains(secret));
    assert!(!stdout.contains(&document_path.display().to_string()));
    assert!(!stderr.contains(&document_path.display().to_string()));
    assert!(!format!("{:?}", output.status).contains(secret));
}

#[test]
fn existing_recovery_document_is_never_overwritten() {
    let directory = TestDirectory::new();
    let (bundle, packed) = completed_bundle(&directory);
    let recovery_document = directory.path().join("existing.iniza-recovery");
    fs::write(&recovery_document, b"existing owner recovery material\n").unwrap();
    let before = fs::read(&recovery_document).unwrap();
    let engine = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage);

    let error = engine
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &recovery_document,
            packed.offline_recovery_key(),
        ))
        .unwrap_err();

    assert!(error.to_string().contains("destination already exists"));
    assert_eq!(fs::read(&recovery_document).unwrap(), before);
}

#[test]
fn offline_recovery_randomness_is_distinct_across_methods_and_bundles() {
    let first_directory = TestDirectory::new();
    let (first_bundle, first_packed) = completed_bundle(&first_directory);
    let first_document = first_directory.path().join("first.iniza-recovery");
    OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage)
        .write(OfflineRecoveryWriteRequest::new(
            &first_bundle,
            &first_document,
            first_packed.offline_recovery_key(),
        ))
        .unwrap();
    let first_secret = recovery_secret_bytes(&first_document);

    let wrong_method =
        RecoverySecret::from_bytes(RecoveryMethod::Vaultwarden, Zeroizing::new(*first_secret));
    let error = BundleEngine::local()
        .verify(VerifyRequest::new(&first_bundle, &wrong_method))
        .unwrap_err();
    assert_eq!(error.to_string(), "Bundle authentication failed");

    let second_directory = TestDirectory::new();
    let (second_bundle, second_packed) = completed_bundle(&second_directory);
    let second_document = second_directory.path().join("second.iniza-recovery");
    OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage)
        .write(OfflineRecoveryWriteRequest::new(
            &second_bundle,
            &second_document,
            second_packed.offline_recovery_key(),
        ))
        .unwrap();
    let second_secret = recovery_secret_bytes(&second_document);

    assert_ne!(*first_secret, *second_secret);
    assert_ne!(*first_secret, [0_u8; 32]);
    assert_ne!(*second_secret, [0_u8; 32]);
}

#[test]
fn wrong_truncated_modified_and_mismatched_documents_fail_without_comparison_details() {
    let directory = TestDirectory::new();
    let (bundle, packed) = completed_bundle(&directory);
    let document = directory.path().join("valid.iniza-recovery");
    let engine = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage);
    engine
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &document,
            packed.offline_recovery_key(),
        ))
        .unwrap();
    let valid = fs::read_to_string(&document).unwrap();
    let secret = valid
        .lines()
        .find_map(|line| line.strip_prefix("recovery_secret_hex: "))
        .unwrap();
    let mut wrong_secret = secret.to_owned();
    wrong_secret.replace_range(0..2, if &secret[0..2] == "00" { "01" } else { "00" });

    let other_directory = TestDirectory::new();
    let (other_bundle, other_packed) = completed_bundle(&other_directory);
    let other_document = other_directory.path().join("other.iniza-recovery");
    let other_engine = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage);
    other_engine
        .write(OfflineRecoveryWriteRequest::new(
            &other_bundle,
            &other_document,
            other_packed.offline_recovery_key(),
        ))
        .unwrap();
    let mismatched = fs::read_to_string(&other_document).unwrap();

    let cases = [
        valid.replace(secret, &wrong_secret),
        valid[..valid.len() / 2].to_owned(),
        valid.replace("schema_version: 1", "schema_version: 2"),
        mismatched,
    ];
    for (index, content) in cases.into_iter().enumerate() {
        let hostile = directory
            .path()
            .join(format!("hostile-{index}.iniza-recovery"));
        fs::write(&hostile, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hostile, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = engine
            .rehearse(OfflineRecoveryRehearsalRequest::new(&bundle, &hostile))
            .unwrap_err();
        assert_eq!(error.to_string(), "Bundle authentication failed");
        assert!(!error.to_string().contains(secret));
        assert!(!error.to_string().contains("expected"));
        assert!(!error.to_string().contains("actual"));
    }
}

#[derive(Debug)]
struct FailingStorage {
    failure: OfflineRecoveryPersistenceTransition,
    observed: Mutex<Vec<OfflineRecoveryPersistenceTransition>>,
}

impl OfflineRecoveryStorage for FailingStorage {
    fn validate_separate_removable_target(&self, _document: &Path) -> io::Result<()> {
        Ok(())
    }

    fn prepare_transition(
        &self,
        transition: OfflineRecoveryPersistenceTransition,
    ) -> io::Result<()> {
        self.observed.lock().unwrap().push(transition);
        if transition == self.failure {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic persistence denial",
            ))
        } else {
            Ok(())
        }
    }
}

#[test]
fn prepublication_persistence_failure_never_leaves_a_recovery_document() {
    for failure in [
        OfflineRecoveryPersistenceTransition::CreateDocument,
        OfflineRecoveryPersistenceTransition::RestrictDocument,
        OfflineRecoveryPersistenceTransition::WriteDocument,
        OfflineRecoveryPersistenceTransition::SynchronizeDocument,
    ] {
        let directory = TestDirectory::new();
        let (bundle, packed) = completed_bundle(&directory);
        let document = directory.path().join("failed.iniza-recovery");
        let storage = FailingStorage {
            failure,
            observed: Mutex::new(Vec::new()),
        };
        let engine = OfflineRecoveryEngine::with_storage(storage);

        let error = engine
            .write(OfflineRecoveryWriteRequest::new(
                &bundle,
                &document,
                packed.offline_recovery_key(),
            ))
            .unwrap_err();

        assert!(error.to_string().contains("synthetic persistence denial"));
        assert!(!document.exists());
    }
}

#[test]
fn losing_the_offline_document_explains_that_there_is_no_backdoor() {
    let guidance = OfflineRecoveryEngine::local().lost_document_guidance();

    assert!(guidance.contains("no backdoor"));
    assert!(guidance.contains("cannot reconstruct"));
    assert!(guidance.contains("Vaultwarden Recovery Secret"));
    assert!(!guidance.contains("safe to erase"));
}

fn recovery_secret_bytes(document: &Path) -> Zeroizing<[u8; 32]> {
    let text = Zeroizing::new(fs::read_to_string(document).unwrap());
    let encoded = text
        .lines()
        .find_map(|line| line.strip_prefix("recovery_secret_hex: "))
        .unwrap();
    let mut bytes = Zeroizing::new([0_u8; 32]);
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

#[cfg(unix)]
#[test]
fn symbolic_links_and_overly_permissive_documents_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = TestDirectory::new();
    let (bundle, packed) = completed_bundle(&directory);
    let valid = directory.path().join("valid.iniza-recovery");
    let engine = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage);
    engine
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &valid,
            packed.offline_recovery_key(),
        ))
        .unwrap();

    fs::set_permissions(&valid, fs::Permissions::from_mode(0o644)).unwrap();
    let error = engine
        .rehearse(OfflineRecoveryRehearsalRequest::new(&bundle, &valid))
        .unwrap_err();
    assert_eq!(error.to_string(), "Bundle authentication failed");
    fs::set_permissions(&valid, fs::Permissions::from_mode(0o600)).unwrap();

    let linked = directory.path().join("linked.iniza-recovery");
    symlink(&valid, &linked).unwrap();
    let error = engine
        .rehearse(OfflineRecoveryRehearsalRequest::new(&bundle, &linked))
        .unwrap_err();
    assert_eq!(error.to_string(), "Bundle authentication failed");

    let victim = directory.path().join("victim.txt");
    fs::write(&victim, b"unrelated owner content\n").unwrap();
    let linked_output = directory.path().join("output.iniza-recovery");
    symlink(&victim, &linked_output).unwrap();
    let before = fs::read(&victim).unwrap();
    let error = engine
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &linked_output,
            packed.offline_recovery_key(),
        ))
        .unwrap_err();
    assert!(error.to_string().contains("destination already exists"));
    assert_eq!(fs::read(&victim).unwrap(), before);
}
