use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BundleEngine, OfflineRecoveryEngine, OfflineRecoveryPersistenceTransition,
    OfflineRecoveryStorage, OfflineRecoveryWriteRequest, PackRequest, PlanEngine, ScanRequest,
};

struct TestDirectory(PathBuf);

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-offline-recovery-cli-{}-{unique}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
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
        .unwrap()
}

#[test]
fn owner_and_automation_can_rehearse_using_only_the_saved_offline_document() {
    let directory = TestDirectory::new();
    let source = directory.0.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("protected.txt"),
        b"never print this protected marker",
    )
    .unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let bundle = directory.0.join("migration.iniza");
    let packed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .unwrap();
    let document = directory.0.join("separate.iniza-recovery");
    OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage)
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &document,
            packed.offline_recovery_key(),
        ))
        .unwrap();
    let document_text = fs::read_to_string(&document).unwrap();
    let secret = document_text
        .lines()
        .find_map(|line| line.strip_prefix("recovery_secret_hex: "))
        .unwrap();

    let human = iniza(&[
        "recovery",
        "offline",
        "rehearse",
        "--bundle",
        bundle.to_str().unwrap(),
        "--document",
        document.to_str().unwrap(),
    ]);
    assert!(
        human.status.success(),
        "rehearsal failed: {}",
        String::from_utf8_lossy(&human.stderr)
    );
    let human_output = format!(
        "{}{}",
        String::from_utf8_lossy(&human.stdout),
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(human_output.contains("independently unlocked and authenticated"));
    assert!(!human_output.contains(secret));
    assert!(!human_output.contains("never print this protected marker"));

    let machine = iniza(&[
        "--json",
        "recovery",
        "offline",
        "rehearse",
        "--bundle",
        bundle.to_str().unwrap(),
        "--document",
        document.to_str().unwrap(),
    ]);
    assert!(machine.status.success());
    assert!(machine.stderr.is_empty());
    assert_eq!(String::from_utf8_lossy(&machine.stdout).lines().count(), 1);
    let value: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
    assert_eq!(value["command"], "recovery offline rehearse");
    assert_eq!(value["status"], "success");
    let machine_output = String::from_utf8_lossy(&machine.stdout);
    assert!(!machine_output.contains(secret));
    assert!(!machine_output.contains(&bundle.display().to_string()));
    assert!(!machine_output.contains(&document.display().to_string()));
}
