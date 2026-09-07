use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BitwardenCommandLine, BitwardenInstallationObservation, BitwardenRecoveryNote,
    BitwardenRetrievedRecoveryNote, BitwardenVaultObservation, BundleEngine, CoreError,
    InstalledBitwarden, PackRecoveryContext, PackRequest, PlanEngine, RecoveryMethod,
    RecoverySecret, RestoreEngine, RestoreRequest, ScanRequest, VaultwardenInstallationRequest,
    VaultwardenItemIdentifier, VaultwardenLoadRequest, VaultwardenPreflightRequest,
    VaultwardenRecoveryEngine, VaultwardenRehearsalRequest, VaultwardenStoreRequest,
    VaultwardenStoreState, VerifyRequest,
};
use zeroize::Zeroizing;

const VAULTWARDEN_SECRET_BYTES: [u8; 32] = [0x31; 32];
const OFFLINE_SECRET_BYTES: [u8; 32] = [0x47; 32];
const ITEM_IDENTIFIER: &str = "12345678-1234-4234-8234-123456789abc";

struct TestDirectory(PathBuf);

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-vaultwarden-recovery-{}-{unique}-{}",
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreatedNoteEvidence {
    item_name: String,
    bundle_identity: String,
    bundle_format: String,
    created_at: String,
    location_hint: Option<String>,
    recovery_method: RecoveryMethod,
}

#[derive(Debug)]
struct SyntheticBitwarden {
    created_note: Mutex<Option<CreatedNoteEvidence>>,
    fail_synchronization: AtomicBool,
    synchronized: AtomicBool,
    retrieved_identifier: Mutex<Option<String>>,
    vault: Mutex<BitwardenVaultObservation>,
}

impl SyntheticBitwarden {
    fn new() -> Self {
        Self {
            created_note: Mutex::new(None),
            fail_synchronization: AtomicBool::new(false),
            synchronized: AtomicBool::new(false),
            retrieved_identifier: Mutex::new(None),
            vault: Mutex::new(Self::unlocked_vault()),
        }
    }

    fn with_vault(vault: BitwardenVaultObservation) -> Self {
        Self {
            vault: Mutex::new(vault),
            ..Self::new()
        }
    }

    fn fail_synchronization(&self) {
        self.fail_synchronization.store(true, Ordering::SeqCst);
    }

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

    fn unlocked_vault() -> BitwardenVaultObservation {
        BitwardenVaultObservation::unlocked(
            "https://vaultwarden.example.test",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
        .unwrap()
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
        Ok(self.vault.lock().unwrap().clone())
    }

    fn create_recovery_note(
        &self,
        _installation: &BitwardenInstallationObservation,
        note: &BitwardenRecoveryNote<'_>,
    ) -> Result<VaultwardenItemIdentifier, CoreError> {
        *self.created_note.lock().unwrap() = Some(CreatedNoteEvidence {
            item_name: note.item_name().to_owned(),
            bundle_identity: note.bundle_identity().to_owned(),
            bundle_format: note.bundle_format().to_owned(),
            created_at: note.created_at().to_owned(),
            location_hint: note.location_hint().map(str::to_owned),
            recovery_method: note.recovery_method(),
        });
        VaultwardenItemIdentifier::parse(ITEM_IDENTIFIER)
    }

    fn synchronize(
        &self,
        _installation: &BitwardenInstallationObservation,
    ) -> Result<(), CoreError> {
        if self.fail_synchronization.load(Ordering::SeqCst) {
            return Err(CoreError::Vaultwarden(
                "Bitwarden synchronization failed".to_owned(),
            ));
        }
        self.synchronized.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn get_recovery_note(
        &self,
        _installation: &BitwardenInstallationObservation,
        item_identifier: &VaultwardenItemIdentifier,
    ) -> Result<BitwardenRetrievedRecoveryNote, CoreError> {
        *self.retrieved_identifier.lock().unwrap() = Some(item_identifier.as_str().to_owned());
        let created = self.created_note.lock().unwrap().clone().unwrap();
        BitwardenRetrievedRecoveryNote::new(
            item_identifier.clone(),
            created.item_name,
            created.bundle_identity,
            created.bundle_format,
            created.created_at,
            created.location_hint,
            RecoverySecret::from_bytes(
                RecoveryMethod::Vaultwarden,
                Zeroizing::new(VAULTWARDEN_SECRET_BYTES),
            ),
        )
    }
}

fn completed_bundle(directory: &TestDirectory) -> (PathBuf, PackRecoveryContext) {
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("settings.txt"),
        b"synthetic owner settings for Vaultwarden recovery\n",
    )
    .unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let recovery = PackRecoveryContext::from_secrets(
        RecoverySecret::from_bytes(
            RecoveryMethod::Vaultwarden,
            Zeroizing::new(VAULTWARDEN_SECRET_BYTES),
        ),
        RecoverySecret::from_bytes(
            RecoveryMethod::Offline,
            Zeroizing::new(OFFLINE_SECRET_BYTES),
        ),
    )
    .unwrap();
    let bundle = directory.path().join("migration.iniza");
    BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle).with_recovery_context(&recovery))
        .unwrap();
    (bundle, recovery)
}

#[test]
fn exact_vaultwarden_secure_note_is_retrieved_and_authenticates_the_completed_bundle() {
    let directory = TestDirectory::new();
    let (bundle, recovery) = completed_bundle(&directory);
    let bitwarden = SyntheticBitwarden::new();
    let engine = VaultwardenRecoveryEngine::with_command_line(bitwarden);

    let installation = engine
        .inspect_installation(VaultwardenInstallationRequest::trusted_path())
        .unwrap();
    assert_eq!(
        installation.executable_path(),
        Path::new("/synthetic/trusted/bw")
    );
    assert_eq!(installation.version(), "2026.8.0");
    assert!(
        installation
            .human_summary()
            .contains("/synthetic/trusted/bw")
    );
    assert!(installation.human_summary().contains("2026.8.0"));

    let preflight = engine
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            "Owner migration",
            Some("verified external Bundle copy"),
            &installation,
            installation.review_hash(),
        ))
        .unwrap();
    assert_eq!(preflight.vault_state(), "unlocked");
    assert_eq!(
        preflight.server_origin(),
        "https://vaultwarden.example.test"
    );
    assert!(
        preflight
            .item_name()
            .starts_with("Iniza Recovery — Owner migration — ")
    );

    let report = engine
        .store_and_rehearse(VaultwardenStoreRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            &preflight,
            preflight.review_hash(),
        ))
        .unwrap();

    assert_eq!(report.state(), VaultwardenStoreState::Verified);
    assert_eq!(report.item_identifier().unwrap().as_str(), ITEM_IDENTIFIER);
    let receipt = report
        .receipt()
        .expect("verified storage must produce a Receipt");
    assert_eq!(receipt.bundle_identity(), preflight.bundle_identity());
    assert_eq!(
        receipt.recovery_method_identity(),
        format!("vaultwarden:{}:slot-1", preflight.bundle_identity())
    );
    assert_eq!(receipt.item_identifier().as_str(), ITEM_IDENTIFIER);
    assert_eq!(
        receipt.server_identity_hash(),
        preflight.server_identity_hash()
    );
    assert!(receipt.verified_at_unix_seconds() > 0);

    let command_line = engine.command_line();
    let created = command_line.created_note.lock().unwrap().clone().unwrap();
    assert_eq!(created.bundle_identity, preflight.bundle_identity());
    assert_eq!(created.bundle_format, "IZ2/IZ1");
    assert_eq!(
        created.location_hint.as_deref(),
        Some("verified external Bundle copy")
    );
    assert_eq!(created.recovery_method, RecoveryMethod::Vaultwarden);
    assert!(command_line.synchronized.load(Ordering::SeqCst));
    assert_eq!(
        command_line.retrieved_identifier.lock().unwrap().as_deref(),
        Some(ITEM_IDENTIFIER)
    );

    let secret_hex = "31".repeat(32);
    let bundle_path = bundle.to_string_lossy().into_owned();
    let directory_path = directory.path().to_string_lossy().into_owned();
    let sensitive_fragments = [
        secret_hex.as_str(),
        "synthetic owner settings for Vaultwarden recovery",
        bundle_path.as_str(),
        directory_path.as_str(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    ];
    let visible = format!(
        "{:?}\n{}\n{}\n{:?}\n{}\n{}",
        installation,
        installation.human_summary(),
        installation.machine_json_result(),
        preflight,
        preflight.machine_json_result(),
        report.machine_json_result(),
    );
    for sensitive in sensitive_fragments {
        assert!(
            !visible.contains(sensitive),
            "visible evidence leaked {sensitive:?}"
        );
    }
}

#[test]
fn post_creation_failure_retains_the_exact_item_for_retry_and_offline_recovery() {
    let directory = TestDirectory::new();
    let (bundle, recovery) = completed_bundle(&directory);
    let bitwarden = SyntheticBitwarden::new();
    bitwarden.fail_synchronization();
    let engine = VaultwardenRecoveryEngine::with_command_line(bitwarden);
    let installation = engine
        .inspect_installation(VaultwardenInstallationRequest::trusted_path())
        .unwrap();
    let preflight = engine
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            "Retained recovery item",
            Option::<String>::None,
            &installation,
            installation.review_hash(),
        ))
        .unwrap();

    let report = engine
        .store_and_rehearse(VaultwardenStoreRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            &preflight,
            preflight.review_hash(),
        ))
        .expect("post-create failure must preserve exact retained-item evidence");

    assert_eq!(
        report.state(),
        VaultwardenStoreState::ItemCreatedButUnverified
    );
    assert_eq!(report.item_identifier().unwrap().as_str(), ITEM_IDENTIFIER);
    assert!(report.receipt().is_none());
    assert!(
        report
            .human_summary()
            .contains("retained and is not yet verified")
    );
    let machine = report.machine_json_result();
    assert!(machine.contains("item-created-but-unverified"));
    assert!(machine.contains(ITEM_IDENTIFIER));
    assert!(!machine.contains(&"31".repeat(32)));
    assert!(!machine.contains(&bundle.to_string_lossy().into_owned()));

    let offline_verification = BundleEngine::local()
        .verify(VerifyRequest::new(&bundle, recovery.offline_recovery_key()))
        .expect("Vaultwarden failure must not damage independent offline recovery");
    assert_eq!(
        offline_verification.bundle_identity(),
        preflight.bundle_identity()
    );
}

#[test]
fn exact_vaultwarden_item_can_be_rehearsed_later_and_loaded_for_restore() {
    let directory = TestDirectory::new();
    let (bundle, recovery) = completed_bundle(&directory);
    let engine = VaultwardenRecoveryEngine::with_command_line(SyntheticBitwarden::new());
    let installation = engine
        .inspect_installation(VaultwardenInstallationRequest::trusted_path())
        .unwrap();
    let preflight = engine
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            "Independent exact item",
            Option::<String>::None,
            &installation,
            installation.review_hash(),
        ))
        .unwrap();
    let stored = engine
        .store_and_rehearse(VaultwardenStoreRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            &preflight,
            preflight.review_hash(),
        ))
        .unwrap();
    let stored_receipt = stored.receipt().unwrap();

    let rehearsal = engine
        .rehearse(VaultwardenRehearsalRequest::new(
            &bundle,
            stored_receipt.item_identifier().clone(),
            stored_receipt.server_identity_hash(),
            &installation,
            installation.review_hash(),
        ))
        .expect("exact retained item should independently rehearse");
    assert_eq!(
        rehearsal.bundle_identity(),
        stored_receipt.bundle_identity()
    );
    assert_eq!(
        rehearsal.item_identifier(),
        stored_receipt.item_identifier()
    );
    assert!(rehearsal.verified_at_unix_seconds() > 0);

    let loaded = engine
        .load(VaultwardenLoadRequest::new(
            &bundle,
            stored_receipt.item_identifier().clone(),
            stored_receipt.server_identity_hash(),
            &installation,
            installation.review_hash(),
        ))
        .expect("exact retained item should load a redacted in-memory Recovery Method");
    assert_eq!(loaded.bundle_identity(), stored_receipt.bundle_identity());
    assert_eq!(
        loaded.recovery_method_identity(),
        stored_receipt.recovery_method_identity()
    );
    assert_eq!(loaded.item_identifier(), stored_receipt.item_identifier());
    assert!(!format!("{loaded:?}").contains(&"31".repeat(32)));

    let destination = directory.path().join("restored-from-vaultwarden");
    RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            loaded.recovery_secret(),
        ))
        .expect("loaded Vaultwarden Recovery Secret should drive Restore");
    assert_eq!(
        fs::read(destination.join("settings.txt")).unwrap(),
        b"synthetic owner settings for Vaultwarden recovery\n"
    );
    assert_eq!(
        engine
            .command_line()
            .retrieved_identifier
            .lock()
            .unwrap()
            .as_deref(),
        Some(ITEM_IDENTIFIER)
    );
}

#[test]
fn locked_vault_stops_before_remote_creation_and_keeps_master_password_outside_iniza() {
    let directory = TestDirectory::new();
    let (bundle, recovery) = completed_bundle(&directory);
    let locked = BitwardenVaultObservation::locked(
        "https://vaultwarden.example.test",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    )
    .unwrap();
    let engine =
        VaultwardenRecoveryEngine::with_command_line(SyntheticBitwarden::with_vault(locked));
    let installation = engine
        .inspect_installation(VaultwardenInstallationRequest::trusted_path())
        .unwrap();

    let error = engine
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            "Locked vault",
            Option::<String>::None,
            &installation,
            installation.review_hash(),
        ))
        .expect_err("a locked vault must stop before recovery item creation");

    assert_eq!(
        error.to_string(),
        "Unlock the official Bitwarden command-line client outside Iniza, then retry. Iniza never asks for your Vaultwarden master password."
    );
    let command_line = engine.command_line();
    assert!(command_line.created_note.lock().unwrap().is_none());
    assert!(!command_line.synchronized.load(Ordering::SeqCst));
    assert!(command_line.retrieved_identifier.lock().unwrap().is_none());
}

#[test]
fn missing_official_bitwarden_software_returns_safe_installation_guidance() {
    let directory = TestDirectory::new();
    let missing = directory.path().join("not-installed-bw");
    let engine = VaultwardenRecoveryEngine::with_command_line(InstalledBitwarden::system());

    let error = engine
        .inspect_installation(VaultwardenInstallationRequest::explicit(&missing))
        .expect_err("a missing executable must stop at installation inspection");

    assert_eq!(
        error.to_string(),
        "Official Bitwarden command-line software was not found. Install it with `brew install bitwarden-cli`, then inspect it again. Iniza will not use an alternate Vaultwarden protocol."
    );
    assert!(
        !error
            .to_string()
            .contains(&missing.to_string_lossy().into_owned())
    );
    assert!(!error.to_string().contains("password"));
    assert!(!error.to_string().contains("session"));
}

#[cfg(unix)]
#[test]
fn production_installation_inspection_binds_executable_interpreter_and_current_version() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new();
    let executable = directory.path().join("bw");
    fs::write(
        &executable,
        b"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '2026.8.0\\n'; exit 0; fi\nexit 64\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let engine = VaultwardenRecoveryEngine::with_command_line(InstalledBitwarden::system());

    let inspected = engine
        .inspect_installation(VaultwardenInstallationRequest::explicit(&executable))
        .expect("a trusted current executable should produce review evidence");

    assert_eq!(
        inspected.executable_path(),
        fs::canonicalize(&executable).unwrap()
    );
    assert_eq!(inspected.version(), "2026.8.0");
    let human = inspected.human_summary();
    assert!(human.contains(&executable.to_string_lossy().into_owned()));
    assert!(human.contains("2026.8.0"));
    assert!(human.contains("interpreter"));
    let machine: serde_json::Value =
        serde_json::from_str(&inspected.machine_json_result()).unwrap();
    assert_eq!(machine["status"], "review-required");
    assert_eq!(machine["data"]["version"], "2026.8.0");
    assert_eq!(
        machine["data"]["executable_identity"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        machine["data"]["interpreter_identity"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(inspected.review_hash().len(), 64);
}

#[cfg(unix)]
#[test]
fn production_installation_inspection_child_uses_verified_home_in_cleared_environment() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_BITWARDEN_INSPECTION_CHILD") else {
        return;
    };
    let directory = TestDirectory(PathBuf::from(root));
    let executable = directory.path().join("bw");
    let engine = VaultwardenRecoveryEngine::with_command_line(InstalledBitwarden::system());

    engine
        .inspect_installation(VaultwardenInstallationRequest::explicit(&executable))
        .expect("installation inspection should use the verified user home");

    std::mem::forget(directory);
}

#[cfg(unix)]
#[test]
fn production_installation_inspection_does_not_leave_the_client_without_a_home_directory() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new();
    let executable = directory.path().join("bw");
    fs::write(
        &executable,
        b"#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then\n\
  [ -z \"${INIZA_SHOULD_NOT_LEAK+x}\" ] || exit 71\n\
  printf '%s' \"${HOME-unset}\" > version-home\n\
  printf '2026.8.0\\n'\n\
  exit 0\n\
fi\n\
exit 72\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let hostile_home = directory.path().join("hostile-inherited-home");

    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("production_installation_inspection_child_uses_verified_home_in_cleared_environment")
        .arg("--nocapture")
        .current_dir(directory.path())
        .env(
            "INIZA_SYNTHETIC_BITWARDEN_INSPECTION_CHILD",
            directory.path(),
        )
        .env("INIZA_SHOULD_NOT_LEAK", "hostile inherited value")
        .env("HOME", &hostile_home)
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "child failed: {combined}");
    let observed_home = fs::read_to_string(directory.path().join("version-home")).unwrap();
    assert_ne!(observed_home, "unset");
    assert_ne!(Path::new(&observed_home), hostile_home);
    assert!(Path::new(&observed_home).is_absolute());
}

#[cfg(unix)]
#[test]
fn unsupported_bitwarden_version_returns_safe_upgrade_guidance() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new();
    let executable = directory.path().join("bw-old");
    fs::write(
        &executable,
        b"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '2026.7.0\\n'; exit 0; fi\nexit 64\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let engine = VaultwardenRecoveryEngine::with_command_line(InstalledBitwarden::system());

    let error = engine
        .inspect_installation(VaultwardenInstallationRequest::explicit(&executable))
        .expect_err("an unsupported executable must not reach credentialed work");

    assert_eq!(
        error.to_string(),
        "Bitwarden command-line version 2026.8.0 or newer is required. Upgrade the official Homebrew package with `brew upgrade bitwarden-cli`, then inspect it again."
    );
    assert!(
        !error
            .to_string()
            .contains(&executable.to_string_lossy().into_owned())
    );
}

#[cfg(unix)]
#[test]
fn production_status_child_uses_session_only_in_cleared_environment() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_BITWARDEN_STATUS_CHILD") else {
        return;
    };
    let directory = TestDirectory(PathBuf::from(root));
    let executable = directory.path().join("bw");
    let (bundle, recovery) = completed_bundle(&directory);
    let engine = VaultwardenRecoveryEngine::with_command_line(InstalledBitwarden::system());
    let installation = engine
        .inspect_installation(VaultwardenInstallationRequest::explicit(&executable))
        .unwrap();

    let preflight = engine
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            "Production status boundary",
            Option::<String>::None,
            &installation,
            installation.review_hash(),
        ))
        .expect("strict unlocked status should pass preflight");

    assert_eq!(preflight.vault_state(), "unlocked");
    assert_eq!(
        preflight.server_origin(),
        "https://vaultwarden.example.test"
    );
    let visible = format!("{preflight:?}\n{}", preflight.machine_json_result());
    assert!(!visible.contains("c3ludGhldGljLXNlc3Npb24="));
    assert!(!visible.contains("owner@example.test"));
    assert!(!visible.contains("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
}

#[cfg(unix)]
#[test]
fn production_status_is_noninteractive_strict_and_secret_free() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new();
    let executable = directory.path().join("bw");
    fs::write(
        &executable,
        b"#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then printf '2026.8.0\\n'; exit 0; fi\n\
if [ \"$1\" = \"status\" ]; then\n\
  [ \"$2\" = \"--nointeraction\" ] || exit 71\n\
  [ \"$#\" = \"2\" ] || exit 72\n\
  [ -z \"${INIZA_SHOULD_NOT_LEAK+x}\" ] || exit 73\n\
  [ -z \"${BITWARDENCLI_DEBUG+x}\" ] || exit 74\n\
  [ \"$BW_SESSION\" = \"c3ludGhldGljLXNlc3Npb24=\" ] || exit 75\n\
  [ -n \"$HOME\" ] || exit 76\n\
  printf '{\"serverUrl\":\"https://vaultwarden.example.test\",\"lastSync\":null,\"userEmail\":\"owner@example.test\",\"userId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"status\":\"unlocked\"}\\n'\n\
  exit 0\n\
fi\n\
exit 77\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("production_status_child_uses_session_only_in_cleared_environment")
        .arg("--nocapture")
        .env("INIZA_SYNTHETIC_BITWARDEN_STATUS_CHILD", directory.path())
        .env("BW_SESSION", "c3ludGhldGljLXNlc3Npb24=")
        .env("INIZA_SHOULD_NOT_LEAK", "hostile inherited value")
        .env("BITWARDENCLI_DEBUG", "true")
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "child failed: {combined}");
    assert!(!combined.contains("c3ludGhldGljLXNlc3Npb24="));
    assert!(!combined.contains("owner@example.test"));
    assert!(!combined.contains("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
}

#[cfg(unix)]
#[test]
fn production_create_child_writes_one_exact_secure_note_through_standard_input() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_BITWARDEN_CREATE_CHILD") else {
        return;
    };
    let directory = TestDirectory(PathBuf::from(root));
    let executable = directory.path().join("bw");
    let (bundle, recovery) = completed_bundle(&directory);
    let engine = VaultwardenRecoveryEngine::with_command_line(InstalledBitwarden::system());
    let installation = engine
        .inspect_installation(VaultwardenInstallationRequest::explicit(&executable))
        .unwrap();
    let preflight = engine
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            "Production create boundary",
            Some("owner-approved external location"),
            &installation,
            installation.review_hash(),
        ))
        .unwrap();
    let report = engine
        .store_and_rehearse(VaultwardenStoreRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            &preflight,
            preflight.review_hash(),
        ))
        .expect("successful creation should retain the exact item identifier");

    assert_eq!(
        report.state(),
        VaultwardenStoreState::ItemCreatedButUnverified
    );
    assert_eq!(report.item_identifier().unwrap().as_str(), ITEM_IDENTIFIER);
    assert!(report.receipt().is_none());
    assert!(!format!("{report:?}").contains(&"31".repeat(32)));
    std::mem::forget(directory);
}

#[cfg(unix)]
#[test]
fn production_create_uses_exact_secure_note_schema_without_secret_arguments() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new();
    let executable = directory.path().join("bw");
    let captured_note = directory.path().join("captured-note.json");
    let script = format!(
        "#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then printf '2026.8.0\\n'; exit 0; fi\n\
[ -z \"${{INIZA_SHOULD_NOT_LEAK+x}}\" ] || exit 70\n\
[ -n \"$HOME\" ] || exit 72\n\
if [ \"$1\" = \"status\" ]; then\n\
  [ \"$BW_SESSION\" = \"c3ludGhldGljLXNlc3Npb24=\" ] || exit 71\n\
  [ \"$2\" = \"--nointeraction\" ] || exit 73\n\
  [ \"$#\" = \"2\" ] || exit 74\n\
  printf '{{\"serverUrl\":\"https://vaultwarden.example.test\",\"lastSync\":null,\"userEmail\":\"owner@example.test\",\"userId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"status\":\"unlocked\"}}\\n'\n\
  exit 0\n\
fi\n\
if [ \"$1\" = \"encode\" ]; then\n\
  [ -z \"${{BW_SESSION+x}}\" ] || exit 83\n\
  [ \"$2\" = \"--nointeraction\" ] || exit 75\n\
  [ \"$#\" = \"2\" ] || exit 76\n\
  /bin/cat > '{}' || exit 77\n\
  printf 'c3ludGhldGljLWVuY29kZWQ=\\n'\n\
  exit 0\n\
fi\n\
if [ \"$1\" = \"create\" ]; then\n\
  [ \"$BW_SESSION\" = \"c3ludGhldGljLXNlc3Npb24=\" ] || exit 71\n\
  [ \"$2\" = \"item\" ] || exit 78\n\
  [ \"$3\" = \"--nointeraction\" ] || exit 79\n\
  [ \"$#\" = \"3\" ] || exit 80\n\
  [ \"$(/bin/cat)\" = \"c3ludGhldGljLWVuY29kZWQ=\" ] || exit 81\n\
  printf '{{\"id\":\"{}\"}}\\n'\n\
  exit 0\n\
fi\n\
exit 82\n",
        captured_note.display(),
        ITEM_IDENTIFIER,
    );
    fs::write(&executable, script).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("production_create_child_writes_one_exact_secure_note_through_standard_input")
        .arg("--nocapture")
        .env("INIZA_SYNTHETIC_BITWARDEN_CREATE_CHILD", directory.path())
        .env("BW_SESSION", "c3ludGhldGljLXNlc3Npb24=")
        .env("INIZA_SHOULD_NOT_LEAK", "hostile inherited value")
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "child failed: {combined}");
    let note: serde_json::Value =
        serde_json::from_slice(&fs::read(&captured_note).unwrap()).unwrap();
    let object = note.as_object().unwrap();
    assert_eq!(object.len(), 4);
    assert_eq!(note["type"], 2);
    assert_eq!(note["secureNote"], serde_json::json!({ "type": 0 }));
    assert!(
        note["name"]
            .as_str()
            .unwrap()
            .starts_with("Iniza Recovery — Production create boundary — ")
    );
    assert_eq!(
        note["fields"],
        serde_json::json!([
            {
                "name": "iniza_bundle_id",
                "value": note["fields"][0]["value"],
                "type": 0
            },
            { "name": "iniza_format", "value": "IZ2/IZ1", "type": 0 },
            {
                "name": "iniza_secret",
                "value": "3131313131313131313131313131313131313131313131313131313131313131",
                "type": 1
            },
            {
                "name": "iniza_created_at",
                "value": note["fields"][3]["value"],
                "type": 0
            },
            {
                "name": "iniza_location_hint",
                "value": "owner-approved external location",
                "type": 0
            }
        ])
    );
    assert_eq!(note["fields"][0]["value"].as_str().unwrap().len(), 32);
    assert_eq!(note["fields"][3]["value"].as_str().unwrap().len(), 20);
    assert!(!combined.contains("3131313131313131"));
    assert!(!combined.contains("c3ludGhldGljLXNlc3Npb24="));
}

#[cfg(unix)]
#[test]
fn production_rehearsal_child_retrieves_exact_item_and_authenticates_bundle() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_BITWARDEN_REHEARSAL_CHILD") else {
        return;
    };
    let directory = TestDirectory(PathBuf::from(root));
    let executable = directory.path().join("bw");
    let retrieved_item = directory.path().join("retrieved-item.json");
    let (bundle, recovery) = completed_bundle(&directory);
    let engine = VaultwardenRecoveryEngine::with_command_line(InstalledBitwarden::system());
    let installation = engine
        .inspect_installation(VaultwardenInstallationRequest::explicit(&executable))
        .unwrap();
    let preflight = engine
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            "Production retrieval boundary",
            Some("owner-approved external location"),
            &installation,
            installation.review_hash(),
        ))
        .unwrap();
    let preflight_json: serde_json::Value =
        serde_json::from_str(&preflight.machine_json_result()).unwrap();
    let item = serde_json::json!({
        "passwordHistory": null,
        "revisionDate": "2026-09-06T12:30:00.000Z",
        "creationDate": "2026-09-06T12:30:00.000Z",
        "deletedDate": null,
        "object": "item",
        "id": ITEM_IDENTIFIER,
        "organizationId": null,
        "folderId": null,
        "type": 2,
        "reprompt": 0,
        "name": preflight.item_name(),
        "notes": null,
        "favorite": false,
        "fields": [
            {
                "name": "iniza_bundle_id",
                "value": preflight.bundle_identity(),
                "type": 0
            },
            {
                "name": "iniza_format",
                "value": preflight_json["data"]["bundle_format"],
                "type": 0
            },
            {
                "name": "iniza_secret",
                "value": "3131313131313131313131313131313131313131313131313131313131313131",
                "type": 1
            },
            {
                "name": "iniza_created_at",
                "value": preflight_json["data"]["created_at"],
                "type": 0
            },
            {
                "name": "iniza_location_hint",
                "value": "owner-approved external location",
                "type": 0
            }
        ],
        "secureNote": { "type": 0 },
        "collectionIds": []
    });
    fs::write(&retrieved_item, serde_json::to_vec(&item).unwrap()).unwrap();

    let report = engine
        .store_and_rehearse(VaultwardenStoreRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            &preflight,
            preflight.review_hash(),
        ))
        .expect("exact retrieval should complete production rehearsal");

    assert_eq!(report.state(), VaultwardenStoreState::Verified);
    let receipt = report.receipt().unwrap();
    assert_eq!(receipt.bundle_identity(), preflight.bundle_identity());
    assert_eq!(receipt.item_identifier().as_str(), ITEM_IDENTIFIER);
    let visible = format!("{report:?}\n{}", report.machine_json_result());
    assert!(!visible.contains("3131313131313131"));
    assert!(!visible.contains("c3ludGhldGljLXNlc3Npb24="));
    assert!(!visible.contains("owner@example.test"));
    std::mem::forget(directory);
}

#[cfg(unix)]
#[test]
fn production_sync_and_exact_get_complete_bundle_rehearsal() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new();
    let executable = directory.path().join("bw");
    let retrieved_item = directory.path().join("retrieved-item.json");
    let script = format!(
        "#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then printf '2026.8.0\\n'; exit 0; fi\n\
[ -z \"${{INIZA_SHOULD_NOT_LEAK+x}}\" ] || exit 70\n\
[ -n \"$HOME\" ] || exit 71\n\
if [ \"$1\" = \"status\" ]; then\n\
  [ \"$2\" = \"--nointeraction\" ] || exit 72\n\
  [ \"$BW_SESSION\" = \"c3ludGhldGljLXNlc3Npb24=\" ] || exit 73\n\
  printf '{{\"serverUrl\":\"https://vaultwarden.example.test\",\"lastSync\":null,\"userEmail\":\"owner@example.test\",\"userId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"status\":\"unlocked\"}}\\n'\n\
  exit 0\n\
fi\n\
if [ \"$1\" = \"encode\" ]; then\n\
  [ \"$2\" = \"--nointeraction\" ] || exit 74\n\
  [ -z \"${{BW_SESSION+x}}\" ] || exit 75\n\
  /bin/cat >/dev/null || exit 76\n\
  printf 'c3ludGhldGljLWVuY29kZWQ=\\n'\n\
  exit 0\n\
fi\n\
if [ \"$1\" = \"create\" ]; then\n\
  [ \"$2\" = \"item\" ] || exit 77\n\
  [ \"$3\" = \"--nointeraction\" ] || exit 78\n\
  [ \"$#\" = \"3\" ] || exit 79\n\
  [ \"$BW_SESSION\" = \"c3ludGhldGljLXNlc3Npb24=\" ] || exit 80\n\
  [ \"$(/bin/cat)\" = \"c3ludGhldGljLWVuY29kZWQ=\" ] || exit 81\n\
  printf '{{\"id\":\"{}\"}}\\n'\n\
  exit 0\n\
fi\n\
if [ \"$1\" = \"sync\" ]; then\n\
  [ \"$2\" = \"--response\" ] || exit 82\n\
  [ \"$3\" = \"--nointeraction\" ] || exit 83\n\
  [ \"$#\" = \"3\" ] || exit 84\n\
  [ \"$BW_SESSION\" = \"c3ludGhldGljLXNlc3Npb24=\" ] || exit 85\n\
  printf '{{\"success\":true,\"data\":{{\"object\":\"message\",\"title\":\"Syncing complete.\",\"message\":null,\"noColor\":false}}}}\\n'\n\
  exit 0\n\
fi\n\
if [ \"$1\" = \"get\" ]; then\n\
  [ \"$2\" = \"item\" ] || exit 86\n\
  [ \"$3\" = \"{}\" ] || exit 87\n\
  [ \"$4\" = \"--nointeraction\" ] || exit 88\n\
  [ \"$#\" = \"4\" ] || exit 89\n\
  [ \"$BW_SESSION\" = \"c3ludGhldGljLXNlc3Npb24=\" ] || exit 90\n\
  /bin/cat '{}'\n\
  exit 0\n\
fi\n\
exit 91\n",
        ITEM_IDENTIFIER,
        ITEM_IDENTIFIER,
        retrieved_item.display(),
    );
    fs::write(&executable, script).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("production_rehearsal_child_retrieves_exact_item_and_authenticates_bundle")
        .arg("--nocapture")
        .env(
            "INIZA_SYNTHETIC_BITWARDEN_REHEARSAL_CHILD",
            directory.path(),
        )
        .env("BW_SESSION", "c3ludGhldGljLXNlc3Npb24=")
        .env("INIZA_SHOULD_NOT_LEAK", "hostile inherited value")
        .output()
        .unwrap();

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "child failed: {combined}");
    assert!(!combined.contains("3131313131313131"));
    assert!(!combined.contains("c3ludGhldGljLXNlc3Npb24="));
    assert!(!combined.contains("owner@example.test"));
}

#[cfg(unix)]
#[test]
fn hostile_status_child_rejects_external_output_without_disclosure() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_BITWARDEN_HOSTILE_STATUS_CHILD") else {
        return;
    };
    let directory = TestDirectory(PathBuf::from(root));
    let executable = directory.path().join("bw");
    let command_line = InstalledBitwarden::system();
    let installation = command_line
        .inspect_installation(&VaultwardenInstallationRequest::explicit(&executable))
        .unwrap();

    let error = command_line
        .status(&installation)
        .expect_err("hostile status output must fail closed");

    let visible = format!("{error:?}\n{error}");
    assert!(!visible.contains("hostile-output-secret-marker"));
    assert!(!visible.contains("attacker@example.test"));
    assert!(!visible.contains("c3ludGhldGljLXNlc3Npb24="));
}

#[cfg(unix)]
#[test]
fn production_status_rejects_unknown_duplicate_and_oversized_output() {
    use std::os::unix::fs::PermissionsExt;

    let responses = [
        br#"{"serverUrl":"https://vaultwarden.example.test","lastSync":null,"userEmail":"attacker@example.test","userId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","status":"unlocked","unexpected":"hostile-output-secret-marker"}"#.to_vec(),
        br#"{"serverUrl":"https://vaultwarden.example.test","lastSync":null,"userEmail":"attacker@example.test","userId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","status":"unlocked","status":"locked","marker":"hostile-output-secret-marker"}"#.to_vec(),
        vec![b'x'; 1024 * 1024 + 1],
    ];

    for response in responses {
        let directory = TestDirectory::new();
        let executable = directory.path().join("bw");
        let response_path = directory.path().join("status-response");
        fs::write(&response_path, response).unwrap();
        let script = format!(
            "#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then printf '2026.8.0\\n'; exit 0; fi\n\
if [ \"$1\" = \"status\" ]; then\n\
  [ \"$2\" = \"--nointeraction\" ] || exit 70\n\
  /bin/cat '{}'\n\
  exit 0\n\
fi\n\
exit 71\n",
            response_path.display(),
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("hostile_status_child_rejects_external_output_without_disclosure")
            .arg("--nocapture")
            .env(
                "INIZA_SYNTHETIC_BITWARDEN_HOSTILE_STATUS_CHILD",
                directory.path(),
            )
            .env("BW_SESSION", "c3ludGhldGljLXNlc3Npb24=")
            .output()
            .unwrap();
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "child failed: {combined}");
        assert!(!combined.contains("hostile-output-secret-marker"));
        assert!(!combined.contains("attacker@example.test"));
        assert!(!combined.contains("c3ludGhldGljLXNlc3Npb24="));
    }
}

#[cfg(unix)]
#[test]
fn hostile_retrieval_child_rejects_changed_secure_note_without_disclosure() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_BITWARDEN_HOSTILE_GET_CHILD") else {
        return;
    };
    let directory = TestDirectory(PathBuf::from(root));
    let executable = directory.path().join("bw");
    let command_line = InstalledBitwarden::system();
    let installation = command_line
        .inspect_installation(&VaultwardenInstallationRequest::explicit(&executable))
        .unwrap();
    let identifier = VaultwardenItemIdentifier::parse(ITEM_IDENTIFIER).unwrap();

    let error = command_line
        .get_recovery_note(&installation, &identifier)
        .expect_err("a changed Secure Note schema must fail closed");

    assert_eq!(error.to_string(), "Bundle authentication failed");
    let visible = format!("{error:?}\n{error}");
    assert!(!visible.contains("hostile-output-secret-marker"));
    assert!(!visible.contains("3131313131313131"));
    assert!(!visible.contains("c3ludGhldGljLXNlc3Npb24="));
}

#[cfg(unix)]
#[test]
fn production_get_rejects_extra_changed_and_duplicate_iniza_fields() {
    use std::os::unix::fs::PermissionsExt;

    let hostile_items = [
        serde_json::json!({
            "object": "item",
            "id": ITEM_IDENTIFIER,
            "type": 2,
            "name": "Iniza Recovery — Hostile retrieval — 2026-09-07",
            "secureNote": { "type": 0 },
            "fields": [
                { "name": "iniza_bundle_id", "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "type": 0 },
                { "name": "iniza_format", "value": "IZ2/IZ1", "type": 0 },
                { "name": "iniza_secret", "value": "3131313131313131313131313131313131313131313131313131313131313131", "type": 1 },
                { "name": "iniza_created_at", "value": "2026-09-07T00:00:00Z", "type": 0 },
                { "name": "iniza_location_hint", "value": "hostile-output-secret-marker", "type": 0 },
                { "name": "iniza_extra", "value": "hostile-output-secret-marker", "type": 0 }
            ]
        }),
        serde_json::json!({
            "object": "item",
            "id": ITEM_IDENTIFIER,
            "type": 2,
            "name": "Iniza Recovery — Hostile retrieval — 2026-09-07",
            "secureNote": { "type": 0 },
            "fields": [
                { "name": "iniza_bundle_id", "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "type": 0 },
                { "name": "iniza_format", "value": "IZ2/IZ1", "type": 0 },
                { "name": "iniza_secret", "value": "3131313131313131313131313131313131313131313131313131313131313131", "type": 0 },
                { "name": "iniza_created_at", "value": "2026-09-07T00:00:00Z", "type": 0 }
            ]
        }),
        serde_json::json!({
            "object": "item",
            "id": ITEM_IDENTIFIER,
            "type": 2,
            "name": "Iniza Recovery — Hostile retrieval — 2026-09-07",
            "secureNote": { "type": 0 },
            "fields": [
                { "name": "iniza_bundle_id", "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "type": 0 },
                { "name": "iniza_format", "value": "IZ2/IZ1", "type": 0 },
                { "name": "iniza_secret", "value": "3131313131313131313131313131313131313131313131313131313131313131", "type": 1 },
                { "name": "iniza_created_at", "value": "2026-09-07T00:00:00Z", "type": 0 },
                { "name": "iniza_created_at", "value": "hostile-output-secret-marker", "type": 0 }
            ]
        }),
    ];

    for item in hostile_items {
        let directory = TestDirectory::new();
        let executable = directory.path().join("bw");
        let response_path = directory.path().join("get-response.json");
        fs::write(&response_path, serde_json::to_vec(&item).unwrap()).unwrap();
        let script = format!(
            "#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then printf '2026.8.0\\n'; exit 0; fi\n\
if [ \"$1\" = \"get\" ]; then\n\
  [ \"$2\" = \"item\" ] || exit 70\n\
  [ \"$3\" = \"{}\" ] || exit 71\n\
  [ \"$4\" = \"--nointeraction\" ] || exit 72\n\
  [ \"$#\" = \"4\" ] || exit 73\n\
  /bin/cat '{}'\n\
  exit 0\n\
fi\n\
exit 74\n",
            ITEM_IDENTIFIER,
            response_path.display(),
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("hostile_retrieval_child_rejects_changed_secure_note_without_disclosure")
            .arg("--nocapture")
            .env(
                "INIZA_SYNTHETIC_BITWARDEN_HOSTILE_GET_CHILD",
                directory.path(),
            )
            .env("BW_SESSION", "c3ludGhldGljLXNlc3Npb24=")
            .output()
            .unwrap();
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "child failed: {combined}");
        assert!(!combined.contains("hostile-output-secret-marker"));
        assert!(!combined.contains("3131313131313131"));
        assert!(!combined.contains("c3ludGhldGljLXNlc3Npb24="));
    }
}

#[cfg(unix)]
#[test]
fn invalid_session_child_stops_before_credentialed_bitwarden_work() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_BITWARDEN_INVALID_SESSION_CHILD") else {
        return;
    };
    let directory = TestDirectory(PathBuf::from(root));
    let executable = directory.path().join("bw");
    let command_line = InstalledBitwarden::system();
    let installation = command_line
        .inspect_installation(&VaultwardenInstallationRequest::explicit(&executable))
        .unwrap();

    let error = command_line
        .status(&installation)
        .expect_err("an invalid session must stop before credentialed work");

    assert_eq!(
        error.to_string(),
        "BW_SESSION is invalid; unlock the official Bitwarden command-line client again outside Iniza"
    );
    assert!(!format!("{error:?}\n{error}").contains("hostile session value"));
}

#[cfg(unix)]
#[test]
fn non_base64_session_is_rejected_before_bitwarden_receives_it() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new();
    let executable = directory.path().join("bw");
    let invocation_marker = directory.path().join("status-was-invoked");
    let script = format!(
        "#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then printf '2026.8.0\\n'; exit 0; fi\n\
if [ \"$1\" = \"status\" ]; then\n\
  : > '{}'\n\
  printf '{{\"serverUrl\":\"https://vaultwarden.example.test\",\"lastSync\":null,\"userEmail\":\"owner@example.test\",\"userId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"status\":\"unlocked\"}}\\n'\n\
  exit 0\n\
fi\n\
exit 70\n",
        invocation_marker.display(),
    );
    fs::write(&executable, script).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("invalid_session_child_stops_before_credentialed_bitwarden_work")
        .arg("--nocapture")
        .env(
            "INIZA_SYNTHETIC_BITWARDEN_INVALID_SESSION_CHILD",
            directory.path(),
        )
        .env("BW_SESSION", "hostile session value")
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(output.status.success(), "child failed: {combined}");
    assert!(!invocation_marker.exists());
    assert!(!combined.contains("hostile session value"));
}
