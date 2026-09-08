use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BitwardenCommandLine, BitwardenInstallationObservation, BitwardenRecoveryNote,
    BitwardenRetrievedRecoveryNote, BitwardenVaultObservation, BundleEngine, CoreError,
    OfflineRecoveryEngine, OfflineRecoveryLocator, OfflineRecoveryPersistenceTransition,
    OfflineRecoveryStorage, OfflineRecoveryWriteRequest, PackRecoveryContext, PackRequest,
    PlanEngine, RecoveryMethod, RecoverySecret, ScanRequest, StoredRecoveryMethodEngine,
    StoredRecoveryMethodRequest, VaultwardenInstallationRequest, VaultwardenItemIdentifier,
    VaultwardenPreflightRequest, VaultwardenRecoveryEngine, VaultwardenRecoveryLocator,
    VerifyRequest,
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
            "iniza-stored-recovery-method-{}-{unique}-{}",
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

#[derive(Debug, Clone)]
struct SyntheticStoredBitwarden {
    bundle_identity: String,
}

impl SyntheticStoredBitwarden {
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
}

impl BitwardenCommandLine for SyntheticStoredBitwarden {
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
        _note: &BitwardenRecoveryNote<'_>,
    ) -> Result<VaultwardenItemIdentifier, CoreError> {
        Err(CoreError::Vaultwarden(
            "synthetic stored-item adapter does not create notes".to_owned(),
        ))
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
        BitwardenRetrievedRecoveryNote::new(
            item_identifier.clone(),
            "Iniza Recovery — Synthetic stored recovery — 2026-09-08",
            &self.bundle_identity,
            "IZ2/IZ1",
            "2026-09-08T00:00:00Z",
            Option::<String>::None,
            RecoverySecret::from_bytes(RecoveryMethod::Vaultwarden, Zeroizing::new([0x31; 32])),
        )
    }
}

#[test]
fn owner_can_load_a_stored_offline_recovery_key_and_fully_verify_the_bundle() {
    let directory = TestDirectory::new();
    let source = directory.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("settings.txt"), b"synthetic owner settings\n").unwrap();

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();

    let known_offline_key = [0x47; 32];
    let recovery = PackRecoveryContext::from_secrets(
        RecoverySecret::from_bytes(RecoveryMethod::Vaultwarden, Zeroizing::new([0x31; 32])),
        RecoverySecret::from_bytes(RecoveryMethod::Offline, Zeroizing::new(known_offline_key)),
    )
    .unwrap();
    let bundle = directory.path().join("migration.iniza");
    BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle).with_recovery_context(&recovery))
        .unwrap();

    let recovery_document = directory.path().join("separate.iniza-recovery");
    let written = OfflineRecoveryEngine::with_storage(SyntheticRemovableStorage)
        .write(OfflineRecoveryWriteRequest::new(
            &bundle,
            &recovery_document,
            recovery.offline_recovery_key(),
        ))
        .unwrap();
    let expected_bundle_identity = written.bundle_identity().to_owned();
    drop(recovery);

    let loaded = StoredRecoveryMethodEngine::local()
        .load(StoredRecoveryMethodRequest::new(
            &bundle,
            OfflineRecoveryLocator::new(&recovery_document),
        ))
        .unwrap();
    let verification = BundleEngine::local()
        .verify(VerifyRequest::new(&bundle, loaded.recovery_secret()))
        .unwrap();

    assert_eq!(loaded.bundle_identity(), expected_bundle_identity);
    assert_eq!(verification.bundle_identity(), expected_bundle_identity);
    assert_eq!(loaded.recovery_method(), RecoveryMethod::Offline);
    assert!(verification.authenticated_chunks > 0);

    let loaded_debug = format!("{loaded:?}");
    let known_key_hex = known_offline_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(loaded_debug.contains("[REDACTED]"));
    assert!(!loaded_debug.contains(&known_key_hex));
}

#[test]
fn owner_can_load_an_exact_vaultwarden_item_and_fully_verify_the_bundle() {
    let directory = TestDirectory::new();
    let source = directory.path().join("vaultwarden-source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("settings.txt"),
        b"synthetic settings protected by Vaultwarden\n",
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
    let bundle = directory.path().join("vaultwarden-migration.iniza");
    BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle).with_recovery_context(&recovery))
        .unwrap();

    let preparation_engine =
        VaultwardenRecoveryEngine::with_command_line(SyntheticStoredBitwarden {
            bundle_identity: String::new(),
        });
    let installation = preparation_engine
        .inspect_installation(VaultwardenInstallationRequest::trusted_path())
        .unwrap();
    let preflight = preparation_engine
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            recovery.vaultwarden_recovery_secret(),
            "Synthetic stored recovery",
            Option::<String>::None,
            &installation,
            installation.review_hash(),
        ))
        .unwrap();
    let expected_bundle_identity = preflight.bundle_identity().to_owned();
    let expected_server_identity_hash = preflight.server_identity_hash().to_owned();
    let reviewed_installation_hash = installation.review_hash().to_owned();
    drop(recovery);

    let item_identifier =
        VaultwardenItemIdentifier::parse("12345678-1234-4234-8234-123456789abc").unwrap();
    let loaded =
        StoredRecoveryMethodEngine::with_bitwarden_command_line(SyntheticStoredBitwarden {
            bundle_identity: expected_bundle_identity.clone(),
        })
        .load(StoredRecoveryMethodRequest::new(
            &bundle,
            VaultwardenRecoveryLocator::new(
                item_identifier.clone(),
                &expected_server_identity_hash,
                installation,
                &reviewed_installation_hash,
            ),
        ))
        .unwrap();
    let verification = BundleEngine::local()
        .verify(VerifyRequest::new(&bundle, loaded.recovery_secret()))
        .unwrap();

    assert_eq!(loaded.bundle_identity(), expected_bundle_identity);
    assert_eq!(verification.bundle_identity(), expected_bundle_identity);
    assert_eq!(loaded.recovery_method(), RecoveryMethod::Vaultwarden);
    assert_eq!(loaded.item_identifier(), Some(&item_identifier));
    assert_eq!(
        loaded.server_identity_hash(),
        Some(expected_server_identity_hash.as_str())
    );

    let loaded_debug = format!("{loaded:?}");
    assert!(loaded_debug.contains("[REDACTED]"));
    assert!(!loaded_debug.contains(&"31".repeat(32)));
}
