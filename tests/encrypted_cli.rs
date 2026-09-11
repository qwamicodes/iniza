use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BundleEngine, InstalledBitwarden, OfflineRecoveryEngine, OfflineRecoveryPersistenceTransition,
    OfflineRecoveryStorage, OfflineRecoveryWriteRequest, PackRecoveryContext, PackRequest,
    PlanEngine, ReadinessEvidenceEngine, ReadinessEvidenceInitializationRequest,
    ReadinessReceiptRecordRequest, RecoveryMethod, RecoverySecret, ScanRequest,
    VaultwardenInstallationRequest, VaultwardenRecoveryEngine, VerifyRequest,
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

fn iniza_with_session(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iniza"))
        .args(arguments)
        .env("BW_SESSION", "c3ludGhldGljLXNlc3Npb24=")
        .output()
        .expect("iniza should run")
}

fn documented_identity_hash(domain: &[u8], value: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    hasher.finalize().to_hex().to_string()
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
fn pack_dry_run_validates_the_complete_request_without_reading_or_writing_protected_state() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("settings.txt"),
        b"synthetic protected settings\n",
    )
    .unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let plan_path = directory.path().join("approved-plan.toml");
    plan.write_to(&plan_path).unwrap();
    let bundle = directory.path().join("migration.iniza");
    let recovery_document = directory.path().join("separate.iniza-recovery");

    let output = iniza(&[
        "--json",
        "pack",
        "--plan",
        plan_path.to_str().unwrap(),
        "--output",
        bundle.to_str().unwrap(),
        "--name",
        "Synthetic command-line migration",
        "--bitwarden",
        "--offline-recovery",
        recovery_document.to_str().unwrap(),
        "--dry-run",
    ]);

    assert!(
        output.status.success(),
        "Pack dry run should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(!bundle.exists());
    assert!(!recovery_document.exists());
    let standard_output = String::from_utf8_lossy(&output.stdout);
    assert_eq!(standard_output.lines().count(), 1);
    assert!(!standard_output.contains("synthetic protected settings"));
    assert!(!standard_output.contains(&source.display().to_string()));
    let result: serde_json::Value = serde_json::from_str(standard_output.trim()).unwrap();
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "pack");
    assert_eq!(result["status"], "success");
    assert_eq!(result["data"]["dry_run"], true);
    assert_eq!(result["data"]["plan_approval"], "approved");
    assert_eq!(result["data"]["recovery_methods"], 2);
    assert_eq!(result["data"]["would_contact_vaultwarden"], false);
    assert_eq!(result["data"]["would_create_artifacts"], false);
}

#[test]
fn machine_pack_refuses_interactive_owner_review_before_creating_artifacts() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("settings.txt"),
        b"synthetic protected settings\n",
    )
    .unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let plan_path = directory.path().join("approved-plan.toml");
    plan.write_to(&plan_path).unwrap();
    let bundle = directory.path().join("migration.iniza");
    let recovery_document = directory.path().join("separate.iniza-recovery");

    let output = iniza(&[
        "--json",
        "pack",
        "--plan",
        plan_path.to_str().unwrap(),
        "--output",
        bundle.to_str().unwrap(),
        "--name",
        "Synthetic command-line migration",
        "--bitwarden",
        "--offline-recovery",
        recovery_document.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(10));
    assert!(output.stderr.is_empty());
    assert!(!bundle.exists());
    assert!(!recovery_document.exists());
    let standard_output = String::from_utf8_lossy(&output.stdout);
    assert_eq!(standard_output.lines().count(), 1);
    assert!(!standard_output.contains("synthetic protected settings"));
    assert!(!standard_output.contains(&source.display().to_string()));
    let result: serde_json::Value = serde_json::from_str(standard_output.trim()).unwrap();
    assert_eq!(result["command"], "pack");
    assert_eq!(result["status"], "error");
    assert_eq!(result["errors"][0]["code"], "INIZA-E010");
    assert!(
        result["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("interactive owner review")
    );
}

#[test]
fn status_revalidates_stored_receipts_and_never_returns_an_erase_decision() {
    let directory = TestDirectory::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic readiness input\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let plan_path = directory.path().join("approved-plan.toml");
    plan.write_to(&plan_path).unwrap();
    let recovery = PackRecoveryContext::from_secrets(
        RecoverySecret::from_bytes(RecoveryMethod::Vaultwarden, Zeroizing::new([0x51; 32])),
        RecoverySecret::from_bytes(RecoveryMethod::Offline, Zeroizing::new([0x62; 32])),
    )
    .unwrap();
    let bundle = directory.path().join("migration.iniza");
    BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle).with_recovery_context(&recovery))
        .unwrap();
    let document = directory.path().join("separate.iniza-recovery");
    let offline = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage);
    offline
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &document,
            recovery.offline_recovery_key(),
        ))
        .unwrap();
    let receipt = offline
        .rehearse(iniza::OfflineRecoveryRehearsalRequest::new(
            &bundle, &document,
        ))
        .unwrap();
    let verification = BundleEngine::local()
        .verify(VerifyRequest::new(&bundle, recovery.offline_recovery_key()))
        .unwrap();
    let receipts = directory.path().join("receipts");
    let evidence = ReadinessEvidenceEngine::local();
    evidence
        .initialize(ReadinessEvidenceInitializationRequest::new(
            &plan, &receipts,
        ))
        .unwrap();
    evidence
        .record_receipt(ReadinessReceiptRecordRequest::bundle_verification(
            &receipts,
            &plan,
            &bundle,
            &verification,
        ))
        .unwrap();
    evidence
        .record_receipt(ReadinessReceiptRecordRequest::offline_recovery(
            &receipts, &plan, &receipt,
        ))
        .unwrap();

    let output = iniza(&[
        "--json",
        "status",
        "--plan",
        plan_path.to_str().unwrap(),
        "--receipts",
        receipts.to_str().unwrap(),
        "--bundle",
        bundle.to_str().unwrap(),
        "--offline-recovery-document",
        document.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let standard_output = String::from_utf8_lossy(&output.stdout);
    assert_eq!(standard_output.lines().count(), 1);
    assert!(!standard_output.contains("synthetic readiness input"));
    assert!(!standard_output.contains(&source.display().to_string()));
    let result: serde_json::Value = serde_json::from_str(standard_output.trim()).unwrap();
    assert_eq!(result["command"], "readiness status");
    assert_eq!(result["status"], "blocking-gaps");
    assert_eq!(result["data"]["bundle_verification"], "current");
    assert_eq!(result["data"]["offline_recovery_method"], "current");
    assert_eq!(
        result["warnings"][0],
        "This is not permission to erase a machine."
    );
    assert!(result["data"].get("safe_to_erase").is_none());
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

#[cfg(unix)]
struct VaultwardenCommandFixture {
    bundle: PathBuf,
    document: PathBuf,
    executable: PathBuf,
    bundle_identity: String,
    server_identity_hash: String,
    installation_review_hash: String,
}

#[cfg(unix)]
fn completed_bundle_with_both_recovery_methods(
    directory: &TestDirectory,
) -> VaultwardenCommandFixture {
    use std::os::unix::fs::PermissionsExt;

    const ITEM_IDENTIFIER: &str = "12345678-1234-4234-8234-123456789abc";
    const SERVER_ORIGIN: &str = "https://vaultwarden.example.test";

    let source = directory.path().join("both-recovery-source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("settings.txt"),
        b"synthetic settings verified through both recovery methods\n",
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
            zeroize::Zeroizing::new([0x31; 32]),
        ),
        RecoverySecret::from_bytes(RecoveryMethod::Offline, zeroize::Zeroizing::new([0x47; 32])),
    )
    .unwrap();
    let bundle = directory.path().join("both-recovery.iniza");
    BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle).with_recovery_context(&recovery))
        .unwrap();
    let bundle_identity = BundleEngine::local()
        .verify(VerifyRequest::new(&bundle, recovery.offline_recovery_key()))
        .unwrap()
        .bundle_identity()
        .to_owned();
    let document = directory.path().join("both-recovery.iniza-recovery");
    OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage)
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &document,
            recovery.offline_recovery_key(),
        ))
        .unwrap();

    let retrieved_item = directory.path().join("retrieved-item.json");
    let item = serde_json::json!({
        "passwordHistory": null,
        "revisionDate": "2026-09-08T12:30:00.000Z",
        "creationDate": "2026-09-08T12:30:00.000Z",
        "deletedDate": null,
        "object": "item",
        "id": ITEM_IDENTIFIER,
        "organizationId": null,
        "folderId": null,
        "type": 2,
        "reprompt": 0,
        "name": "Iniza Recovery — Synthetic command-line verification — 2026-09-08",
        "notes": null,
        "favorite": false,
        "fields": [
            { "name": "iniza_bundle_id", "value": bundle_identity, "type": 0 },
            { "name": "iniza_format", "value": "IZ2/IZ1", "type": 0 },
            {
                "name": "iniza_secret",
                "value": "3131313131313131313131313131313131313131313131313131313131313131",
                "type": 1
            },
            { "name": "iniza_created_at", "value": "2026-09-08T12:30:00Z", "type": 0 }
        ],
        "secureNote": { "type": 0 },
        "collectionIds": []
    });
    fs::write(&retrieved_item, serde_json::to_vec(&item).unwrap()).unwrap();
    let executable = directory.path().join("bw");
    let script = format!(
        "#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then printf '2026.8.0\\n'; exit 0; fi\n\
if [ \"$1\" = \"status\" ]; then\n\
  [ \"$2\" = \"--nointeraction\" ] || exit 71\n\
  [ \"$BW_SESSION\" = \"c3ludGhldGljLXNlc3Npb24=\" ] || exit 72\n\
  printf '{{\"serverUrl\":\"{SERVER_ORIGIN}\",\"lastSync\":null,\"userEmail\":\"owner@example.test\",\"userId\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"status\":\"unlocked\"}}\\n'\n\
  exit 0\n\
fi\n\
if [ \"$1\" = \"sync\" ]; then\n\
  [ \"$2\" = \"--response\" ] || exit 73\n\
  [ \"$3\" = \"--nointeraction\" ] || exit 74\n\
  [ \"$BW_SESSION\" = \"c3ludGhldGljLXNlc3Npb24=\" ] || exit 75\n\
  printf '{{\"success\":true,\"data\":{{\"object\":\"message\",\"title\":\"Syncing complete.\",\"message\":null,\"noColor\":false}}}}\\n'\n\
  exit 0\n\
fi\n\
if [ \"$1\" = \"get\" ]; then\n\
  [ \"$2\" = \"item\" ] || exit 76\n\
  [ \"$3\" = \"{ITEM_IDENTIFIER}\" ] || exit 77\n\
  [ \"$4\" = \"--nointeraction\" ] || exit 78\n\
  [ \"$BW_SESSION\" = \"c3ludGhldGljLXNlc3Npb24=\" ] || exit 79\n\
  /bin/cat '{}'\n\
  exit 0\n\
fi\n\
exit 80\n",
        retrieved_item.display(),
    );
    fs::write(&executable, script).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let installation = VaultwardenRecoveryEngine::with_command_line(InstalledBitwarden::system())
        .inspect_installation(VaultwardenInstallationRequest::explicit(&executable))
        .unwrap();
    let server_identity_hash =
        documented_identity_hash(b"iniza vaultwarden server identity v1", SERVER_ORIGIN);

    VaultwardenCommandFixture {
        bundle,
        document,
        executable,
        bundle_identity,
        server_identity_hash,
        installation_review_hash: installation.review_hash().to_owned(),
    }
}

#[cfg(unix)]
#[test]
fn owner_can_fully_verify_one_bundle_through_both_stored_recovery_methods() {
    const ITEM_IDENTIFIER: &str = "12345678-1234-4234-8234-123456789abc";

    let directory = TestDirectory::new();
    let fixture = completed_bundle_with_both_recovery_methods(&directory);
    let output = iniza_with_session(&[
        "--json",
        "verify",
        "--bundle",
        fixture.bundle.to_str().unwrap(),
        "--recovery",
        "both",
        "--offline-recovery-document",
        fixture.document.to_str().unwrap(),
        "--vaultwarden-item",
        ITEM_IDENTIFIER,
        "--vaultwarden-server-identity-hash",
        &fixture.server_identity_hash,
        "--bitwarden-installation-review-hash",
        &fixture.installation_review_hash,
        "--bitwarden-executable",
        fixture.executable.to_str().unwrap(),
    ]);

    assert!(
        output.status.success(),
        "both Recovery Methods should verify: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let standard_output = String::from_utf8_lossy(&output.stdout);
    assert_eq!(standard_output.lines().count(), 1);
    let result: serde_json::Value = serde_json::from_str(standard_output.trim()).unwrap();
    assert_eq!(result["command"], "verify");
    assert_eq!(result["status"], "success");
    assert_eq!(
        result["data"]["recovery_methods"],
        serde_json::json!(["offline", "vaultwarden"])
    );
    assert_eq!(result["data"]["same_bundle_identity"], true);
    assert_eq!(result["data"]["bundle_identity"], fixture.bundle_identity);
    assert!(!standard_output.contains(&"31".repeat(32)));
    assert!(!standard_output.contains("c3ludGhldGljLXNlc3Npb24="));
    assert!(!standard_output.contains(fixture.bundle.to_str().unwrap()));
    assert!(!standard_output.contains(fixture.document.to_str().unwrap()));
}

#[cfg(unix)]
#[test]
fn encrypted_commands_accept_the_exact_vaultwarden_recovery_locator() {
    const ITEM_IDENTIFIER: &str = "12345678-1234-4234-8234-123456789abc";

    let directory = TestDirectory::new();
    let fixture = completed_bundle_with_both_recovery_methods(&directory);
    let common = [
        "--vaultwarden-item",
        ITEM_IDENTIFIER,
        "--vaultwarden-server-identity-hash",
        fixture.server_identity_hash.as_str(),
        "--bitwarden-installation-review-hash",
        fixture.installation_review_hash.as_str(),
        "--bitwarden-executable",
        fixture.executable.to_str().unwrap(),
    ];

    let mut verify_arguments = vec![
        "--json",
        "verify",
        "--bundle",
        fixture.bundle.to_str().unwrap(),
    ];
    verify_arguments.extend(common);
    let verify = iniza_with_session(&verify_arguments);
    assert!(
        verify.status.success(),
        "Vaultwarden Verify should succeed: {}{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_result: serde_json::Value =
        serde_json::from_slice(&verify.stdout).expect("Verify should emit one result");
    assert_eq!(verify_result["command"], "verify");
    assert_eq!(verify_result["status"], "success");

    let mut inspect_arguments = vec![
        "--json",
        "inspect",
        "--bundle",
        fixture.bundle.to_str().unwrap(),
    ];
    inspect_arguments.extend(common);
    let inspect = iniza_with_session(&inspect_arguments);
    assert!(
        inspect.status.success(),
        "Vaultwarden Inspect should succeed: {}{}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_result: serde_json::Value =
        serde_json::from_slice(&inspect.stdout).expect("Inspect should emit one result");
    assert_eq!(inspect_result["command"], "inspect");
    assert_eq!(inspect_result["status"], "success");

    let copy = directory.path().join("vaultwarden-copy.iniza");
    let mut copy_arguments = vec![
        "--json",
        "copy",
        "--bundle",
        fixture.bundle.to_str().unwrap(),
        "--to",
        copy.to_str().unwrap(),
    ];
    copy_arguments.extend(common);
    let copied = iniza_with_session(&copy_arguments);
    assert!(
        copied.status.success(),
        "Vaultwarden Verified Copy should succeed: {}{}",
        String::from_utf8_lossy(&copied.stdout),
        String::from_utf8_lossy(&copied.stderr)
    );
    let copied_result: serde_json::Value =
        serde_json::from_slice(&copied.stdout).expect("Verified Copy should emit one result");
    assert_eq!(copied_result["command"], "copy");
    assert_eq!(copied_result["status"], "success");
    assert!(copy.exists());

    let restore = directory.path().join("vaultwarden-restore");
    let mut restore_arguments = vec![
        "--json",
        "restore",
        "--bundle",
        fixture.bundle.to_str().unwrap(),
        "--to",
        restore.to_str().unwrap(),
    ];
    restore_arguments.extend(common);
    let restored = iniza_with_session(&restore_arguments);
    assert!(
        restored.status.success(),
        "Vaultwarden Restore should succeed: {}{}",
        String::from_utf8_lossy(&restored.stdout),
        String::from_utf8_lossy(&restored.stderr)
    );
    let restored_result: serde_json::Value =
        serde_json::from_slice(&restored.stdout).expect("Restore should emit one result");
    assert_eq!(restored_result["command"], "restore");
    assert_eq!(restored_result["status"], "success");
    assert_eq!(
        fs::read(restore.join("settings.txt")).unwrap(),
        b"synthetic settings verified through both recovery methods\n"
    );

    let visible = format!(
        "{}{}{}{}{}{}{}{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr),
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr),
        String::from_utf8_lossy(&copied.stdout),
        String::from_utf8_lossy(&copied.stderr),
        String::from_utf8_lossy(&restored.stdout),
        String::from_utf8_lossy(&restored.stderr),
    );
    assert!(!visible.contains(&"31".repeat(32)));
    assert!(!visible.contains("c3ludGhldGljLXNlc3Npb24="));
    assert!(!visible.contains(fixture.bundle.to_str().unwrap()));
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
