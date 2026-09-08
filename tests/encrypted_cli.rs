use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BundleEngine, OfflineRecoveryEngine, OfflineRecoveryPersistenceTransition,
    OfflineRecoveryStorage, OfflineRecoveryWriteRequest, PackRecoveryContext, PackRequest,
    PlanEngine, RecoveryMethod, RecoverySecret, ScanRequest,
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
            "iniza-encrypted-cli-{}-{unique}-{}",
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

fn iniza(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iniza"))
        .args(arguments)
        .output()
        .expect("iniza should run")
}

fn completed_bundle_and_offline_document(directory: &TestDirectory) -> (PathBuf, PathBuf) {
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("settings.txt"),
        b"synthetic encrypted command-line settings\n",
    )
    .unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let recovery = PackRecoveryContext::from_secrets(
        RecoverySecret::from_bytes(RecoveryMethod::Vaultwarden, Zeroizing::new([0x31; 32])),
        RecoverySecret::from_bytes(RecoveryMethod::Offline, Zeroizing::new([0x47; 32])),
    )
    .unwrap();
    let bundle = directory.path().join("migration.iniza");
    BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle).with_recovery_context(&recovery))
        .unwrap();
    let document = directory.path().join("separate.iniza-recovery");
    OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage)
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &document,
            recovery.offline_recovery_key(),
        ))
        .unwrap();
    (bundle, document)
}

#[test]
fn owner_and_automation_can_fully_verify_a_bundle_using_only_the_offline_document_locator() {
    let directory = TestDirectory::new();
    let (bundle, document) = completed_bundle_and_offline_document(&directory);
    let bundle_text = bundle.to_str().unwrap();
    let document_text = document.to_str().unwrap();

    let human = iniza(&[
        "verify",
        "--bundle",
        bundle_text,
        "--offline-recovery-document",
        document_text,
    ]);
    assert!(
        human.status.success(),
        "verification should succeed: {}",
        String::from_utf8_lossy(&human.stderr)
    );
    let human_output = String::from_utf8_lossy(&human.stdout);
    assert!(human_output.contains("Bundle fully verified"));
    assert!(human_output.contains("Recovery Method: Offline"));
    assert!(human_output.contains("Authenticated chunks:"));
    assert!(!human_output.contains('\u{1b}'));
    assert!(!human_output.contains(bundle_text));
    assert!(!human_output.contains(document_text));
    assert!(!human_output.contains(&"47".repeat(32)));

    let machine = iniza(&[
        "--json",
        "verify",
        "--bundle",
        bundle_text,
        "--offline-recovery-document",
        document_text,
    ]);
    assert!(
        machine.status.success(),
        "machine verification should succeed: {}",
        String::from_utf8_lossy(&machine.stderr)
    );
    assert!(machine.stderr.is_empty());
    let machine_output = String::from_utf8_lossy(&machine.stdout);
    assert_eq!(machine_output.lines().count(), 1);
    let result: serde_json::Value = serde_json::from_str(machine_output.trim()).unwrap();
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "verify");
    assert_eq!(result["status"], "success");
    assert_eq!(result["data"]["format_version"], 2);
    assert_eq!(result["data"]["cryptographic_suite"], "IZ1");
    assert!(result["data"]["authenticated_chunks"].as_u64().unwrap() > 0);
    assert_eq!(result["warnings"], serde_json::json!([]));
    assert_eq!(result["errors"], serde_json::json!([]));
    assert!(!machine_output.contains(bundle_text));
    assert!(!machine_output.contains(document_text));
    assert!(!machine_output.contains(&"47".repeat(32)));
}

#[test]
fn owner_and_automation_can_inspect_an_authenticated_bundle_using_only_the_offline_document_locator()
 {
    let directory = TestDirectory::new();
    let (bundle, document) = completed_bundle_and_offline_document(&directory);
    let bundle_text = bundle.to_str().unwrap();
    let document_text = document.to_str().unwrap();

    let human = iniza(&[
        "inspect",
        "--bundle",
        bundle_text,
        "--offline-recovery-document",
        document_text,
    ]);
    assert!(
        human.status.success(),
        "inspection should succeed: {}",
        String::from_utf8_lossy(&human.stderr)
    );
    let human_output = String::from_utf8_lossy(&human.stdout);
    assert!(human_output.contains("Authenticated Bundle inspection"));
    assert!(human_output.contains("Recovery Method: Offline"));
    assert!(human_output.contains("Bundle format: IZ2/IZ1"));
    assert!(human_output.contains("Included Migration Items: 2"));
    assert!(!human_output.contains('\u{1b}'));
    assert!(!human_output.contains(bundle_text));
    assert!(!human_output.contains(document_text));
    assert!(!human_output.contains(&"47".repeat(32)));

    let machine = iniza(&[
        "--json",
        "inspect",
        "--bundle",
        bundle_text,
        "--offline-recovery-document",
        document_text,
    ]);
    assert!(
        machine.status.success(),
        "machine inspection should succeed: {}",
        String::from_utf8_lossy(&machine.stderr)
    );
    assert!(machine.stderr.is_empty());
    let machine_output = String::from_utf8_lossy(&machine.stdout);
    assert_eq!(machine_output.lines().count(), 1);
    let result: serde_json::Value = serde_json::from_str(machine_output.trim()).unwrap();
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "inspect");
    assert_eq!(result["status"], "success");
    assert_eq!(result["data"]["format_version"], 2);
    assert_eq!(result["data"]["cryptographic_suite"], "IZ1");
    assert_eq!(result["data"]["included_items"], 2);
    assert_eq!(result["warnings"], serde_json::json!([]));
    assert_eq!(result["errors"], serde_json::json!([]));
    assert!(!machine_output.contains(bundle_text));
    assert!(!machine_output.contains(document_text));
    assert!(!machine_output.contains(&"47".repeat(32)));
}

#[test]
fn owner_and_automation_can_restore_exact_bytes_without_overwriting_using_only_the_offline_document_locator()
 {
    let directory = TestDirectory::new();
    let (bundle, document) = completed_bundle_and_offline_document(&directory);
    let bundle_text = bundle.to_str().unwrap();
    let document_text = document.to_str().unwrap();
    let owner_destination = directory.path().join("owner-restore");
    let owner_destination_text = owner_destination.to_str().unwrap();

    let human = iniza(&[
        "restore",
        "--bundle",
        bundle_text,
        "--to",
        owner_destination_text,
        "--offline-recovery-document",
        document_text,
    ]);
    assert!(
        human.status.success(),
        "Restore should succeed: {}",
        String::from_utf8_lossy(&human.stderr)
    );
    assert_eq!(
        fs::read(owner_destination.join("settings.txt")).unwrap(),
        b"synthetic encrypted command-line settings\n"
    );
    let human_output = String::from_utf8_lossy(&human.stdout);
    assert!(human_output.contains("Restore completed"));
    assert!(human_output.contains("Recovery Method: Offline"));
    assert!(!human_output.contains('\u{1b}'));
    assert!(!human_output.contains(bundle_text));
    assert!(!human_output.contains(document_text));
    assert!(!human_output.contains(&"47".repeat(32)));

    let before_collision = fs::read(owner_destination.join("settings.txt")).unwrap();
    let collision = iniza(&[
        "restore",
        "--bundle",
        bundle_text,
        "--to",
        owner_destination_text,
        "--offline-recovery-document",
        document_text,
    ]);
    assert_eq!(collision.status.code(), Some(50));
    assert!(String::from_utf8_lossy(&collision.stderr).contains("destination already exists"));
    assert_eq!(
        fs::read(owner_destination.join("settings.txt")).unwrap(),
        before_collision
    );

    let automation_destination = directory.path().join("automation-restore");
    let automation_destination_text = automation_destination.to_str().unwrap();
    let machine = iniza(&[
        "--json",
        "restore",
        "--bundle",
        bundle_text,
        "--to",
        automation_destination_text,
        "--offline-recovery-document",
        document_text,
    ]);
    assert!(
        machine.status.success(),
        "machine Restore should succeed: {}",
        String::from_utf8_lossy(&machine.stderr)
    );
    assert!(machine.stderr.is_empty());
    assert_eq!(
        fs::read(automation_destination.join("settings.txt")).unwrap(),
        b"synthetic encrypted command-line settings\n"
    );
    let machine_output = String::from_utf8_lossy(&machine.stdout);
    assert_eq!(machine_output.lines().count(), 1);
    let result: serde_json::Value = serde_json::from_str(machine_output.trim()).unwrap();
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "restore");
    assert_eq!(result["status"], "success");
    assert_eq!(result["data"]["state"], "complete");
    assert_eq!(result["data"]["restored_items"], 2);
    assert_eq!(result["warnings"], serde_json::json!([]));
    assert_eq!(result["errors"], serde_json::json!([]));
    assert!(!machine_output.contains(bundle_text));
    assert!(!machine_output.contains(document_text));
    assert!(!machine_output.contains(automation_destination_text));
    assert!(!machine_output.contains(&"47".repeat(32)));
}

#[test]
fn owner_and_automation_can_create_a_verified_copy_without_overwriting_using_only_the_offline_document_locator()
 {
    let directory = TestDirectory::new();
    let (bundle, document) = completed_bundle_and_offline_document(&directory);
    let bundle_text = bundle.to_str().unwrap();
    let document_text = document.to_str().unwrap();
    let owner_copy = directory.path().join("owner-copy.iniza");
    let owner_copy_text = owner_copy.to_str().unwrap();

    let human = iniza(&[
        "copy",
        "--bundle",
        bundle_text,
        "--to",
        owner_copy_text,
        "--offline-recovery-document",
        document_text,
    ]);
    assert!(
        human.status.success(),
        "Verified Copy should succeed: {}",
        String::from_utf8_lossy(&human.stderr)
    );
    assert_eq!(fs::read(&owner_copy).unwrap(), fs::read(&bundle).unwrap());
    let human_output = String::from_utf8_lossy(&human.stdout);
    assert!(human_output.contains("Verified Copy created"));
    assert!(human_output.contains("Recovery Method: Offline"));
    assert!(!human_output.contains('\u{1b}'));
    assert!(!human_output.contains(bundle_text));
    assert!(!human_output.contains(document_text));
    assert!(!human_output.contains(owner_copy_text));
    assert!(!human_output.contains(&"47".repeat(32)));

    let before_collision = fs::read(&owner_copy).unwrap();
    let collision = iniza(&[
        "copy",
        "--bundle",
        bundle_text,
        "--to",
        owner_copy_text,
        "--offline-recovery-document",
        document_text,
    ]);
    assert_eq!(collision.status.code(), Some(50));
    assert!(String::from_utf8_lossy(&collision.stderr).contains("destination already exists"));
    assert_eq!(fs::read(&owner_copy).unwrap(), before_collision);

    let automation_copy = directory.path().join("automation-copy.iniza");
    let automation_copy_text = automation_copy.to_str().unwrap();
    let machine = iniza(&[
        "--json",
        "copy",
        "--bundle",
        bundle_text,
        "--to",
        automation_copy_text,
        "--offline-recovery-document",
        document_text,
    ]);
    assert!(
        machine.status.success(),
        "machine Verified Copy should succeed: {}",
        String::from_utf8_lossy(&machine.stderr)
    );
    assert!(machine.stderr.is_empty());
    assert_eq!(
        fs::read(&automation_copy).unwrap(),
        fs::read(&bundle).unwrap()
    );
    let machine_output = String::from_utf8_lossy(&machine.stdout);
    assert_eq!(machine_output.lines().count(), 1);
    let result: serde_json::Value = serde_json::from_str(machine_output.trim()).unwrap();
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "copy");
    assert_eq!(result["status"], "success");
    assert_eq!(result["data"]["verified"], true);
    assert_eq!(result["warnings"], serde_json::json!([]));
    assert_eq!(result["errors"], serde_json::json!([]));
    assert!(!machine_output.contains(bundle_text));
    assert!(!machine_output.contains(document_text));
    assert!(!machine_output.contains(automation_copy_text));
    assert!(!machine_output.contains(&"47".repeat(32)));
}
