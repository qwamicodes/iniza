use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::json;

use crate::{
    BitwardenCommandLine, BundleEngine, CoreError, MigrationCaptureOwnerReview,
    MigrationCaptureReport, MigrationCaptureRequest, MigrationCaptureState,
    MigrationWorkflowEngine, NotProtectedReport, OfflineRecoveryEngine, OfflineRecoveryLoadRequest,
    OfflineRecoveryStorage, PlanEngine, RestoreCancellation, RestoreEngine, RestoreEvent,
    RestoreEventSink, RestoreReport, RestoreRequest, RestoreState, ScanRequest,
    VaultwardenInstallationRequest, VerifiedCopyPersistence, VerifiedCopyReport,
    VerifiedCopyRequest, VerifiedCopyStorageLocation,
};

const SHELL_SETTINGS: &[u8] = b"synthetic shell settings\n";
const ORDINARY_BINARY: &[u8] = &[0x00, 0x11, 0x7f, 0x80, 0xfe, 0xff];

pub struct SyntheticMigrationRehearsalRequest<'a> {
    root: PathBuf,
    installation: VaultwardenInstallationRequest,
    owner_review: &'a dyn MigrationCaptureOwnerReview,
}

impl<'a> SyntheticMigrationRehearsalRequest<'a> {
    pub fn new(
        root: impl Into<PathBuf>,
        installation: VaultwardenInstallationRequest,
        owner_review: &'a dyn MigrationCaptureOwnerReview,
    ) -> Self {
        Self {
            root: root.into(),
            installation,
            owner_review,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticMigrationRehearsalReport {
    capture: MigrationCaptureReport,
    external_copy: VerifiedCopyReport,
    cloud_copy: VerifiedCopyReport,
    restore: RestoreReport,
    restore_was_resumed: bool,
    exact_comparison_passed: bool,
    not_protected_report: NotProtectedReport,
}

impl SyntheticMigrationRehearsalReport {
    pub fn capture(&self) -> &MigrationCaptureReport {
        &self.capture
    }

    pub fn external_copy(&self) -> &VerifiedCopyReport {
        &self.external_copy
    }

    pub fn cloud_copy(&self) -> &VerifiedCopyReport {
        &self.cloud_copy
    }

    pub fn restore(&self) -> &RestoreReport {
        &self.restore
    }

    pub fn restore_was_resumed(&self) -> bool {
        self.restore_was_resumed
    }

    pub fn exact_comparison_passed(&self) -> bool {
        self.exact_comparison_passed
    }

    pub fn not_protected_report(&self) -> &NotProtectedReport {
        &self.not_protected_report
    }

    pub fn human_summary(&self) -> &'static str {
        "Synthetic migration rehearsal authenticated the Bundle through both Recovery Methods, created two Verified Copies, and completed an interrupted and resumed Restore Rehearsal with exact comparison. This result does not authorize real source capture and does not decide whether this machine is safe to erase."
    }

    pub fn machine_json_result(&self) -> String {
        json!({
            "schema_version": 1,
            "command": "migration rehearse",
            "status": "success",
            "data": {
                "bundle_identity": self.capture.offline_verification().bundle_identity(),
                "recovery_methods_verified": 2,
                "verified_copies": 2,
                "restore_resumed": self.restore_was_resumed,
                "exact_comparison_passed": self.exact_comparison_passed,
                "not_protected_items": self.not_protected_report.entries().len(),
                "must_protect_gaps": self.not_protected_report.must_protect_gap_count(),
                "real_source_capture_authorized": false,
                "safe_to_erase": false,
            },
            "warnings": [
                "synthetic rehearsal evidence is not authorization to read personal source content",
                "synthetic rehearsal evidence is not machine-erasure authorization",
            ],
            "errors": [],
        })
        .to_string()
    }
}

#[derive(Debug)]
pub struct SyntheticMigrationRehearsalEngine<C, S, E, I> {
    bitwarden: C,
    offline_storage: S,
    external_copy_storage: E,
    cloud_copy_storage: I,
}

impl<C, S, E, I> SyntheticMigrationRehearsalEngine<C, S, E, I> {
    pub fn with_boundaries(
        bitwarden: C,
        offline_storage: S,
        external_copy_storage: E,
        cloud_copy_storage: I,
    ) -> Self {
        Self {
            bitwarden,
            offline_storage,
            external_copy_storage,
            cloud_copy_storage,
        }
    }
}

impl<C, S, E, I> SyntheticMigrationRehearsalEngine<C, S, E, I>
where
    C: BitwardenCommandLine + Clone,
    S: OfflineRecoveryStorage + Clone,
    E: VerifiedCopyPersistence,
    I: VerifiedCopyPersistence,
{
    pub fn run(
        &self,
        request: SyntheticMigrationRehearsalRequest<'_>,
    ) -> Result<SyntheticMigrationRehearsalReport, CoreError> {
        create_rehearsal_root(&request.root)?;
        let source = request.root.join("source");
        let developer_configuration = source.join("developer-config");
        create_directory(&source)?;
        create_directory(&developer_configuration)?;
        write_fixture(
            &developer_configuration.join("shell-settings.txt"),
            SHELL_SETTINGS,
        )?;
        write_fixture(&source.join("ordinary-binary.bin"), ORDINARY_BINARY)?;
        write_fixture(&source.join("generated.cache"), b"regenerable cache\n")?;
        write_fixture(
            &source.join("account-synced-app-state"),
            b"optional duplicated account state\n",
        )?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("ordinary-binary.bin", source.join("review-needed-link"))
            .map_err(|source_error| CoreError::Io {
                action: "create synthetic review-required symbolic link",
                path: source.join("review-needed-link"),
                source: source_error,
            })?;
        #[cfg(unix)]
        create_synthetic_unsupported_entry(&source.join("optional-worker.pipe"))?;

        let mut inventory_scan = ScanRequest::for_directory(&source)
            .exclude("generated.cache")
            .mark_optional("generated.cache")
            .mark_optional("account-synced-app-state");
        #[cfg(unix)]
        {
            inventory_scan = inventory_scan
                .mark_optional("review-needed-link")
                .mark_optional("optional-worker.pipe");
        }
        let inventory_plan = PlanEngine::local().scan(inventory_scan)?;
        let not_protected_report = NotProtectedReport::from_plan(&inventory_plan);
        #[cfg(unix)]
        fs::remove_file(source.join("optional-worker.pipe")).map_err(|source_error| {
            CoreError::Io {
                action: "remove disposable unsupported entry before safe capture",
                path: source.join("optional-worker.pipe"),
                source: source_error,
            }
        })?;

        let mut capture_scan = ScanRequest::for_directory(&source)
            .exclude("generated.cache")
            .mark_optional("generated.cache")
            .mark_optional("account-synced-app-state");
        #[cfg(unix)]
        {
            capture_scan = capture_scan
                .mark_optional("review-needed-link")
                .exclude("optional-worker.pipe")
                .mark_optional("optional-worker.pipe");
        }
        let mut plan = PlanEngine::local().scan(capture_scan)?;
        let reviewed_plan_hash = plan.approval_hash()?;
        plan.approve(&reviewed_plan_hash)?;

        let bundle = request.root.join("migration.iniza");
        let offline_document = request.root.join("migration.iniza-recovery");
        let capture_engine = MigrationWorkflowEngine::with_boundaries(
            self.bitwarden.clone(),
            self.offline_storage.clone(),
        );
        let capture = capture_engine.capture(
            MigrationCaptureRequest::new(
                &plan,
                &bundle,
                &offline_document,
                "Complete synthetic migration",
                request.installation,
                request.owner_review,
            )
            .with_location_hint("Disposable synthetic migration rehearsal"),
        )?;
        if capture.state() != MigrationCaptureState::Complete {
            return Err(CoreError::BundleIncomplete(bundle));
        }

        let offline_engine = OfflineRecoveryEngine::with_storage(self.offline_storage.clone());
        let loaded_for_copy =
            offline_engine.load(OfflineRecoveryLoadRequest::new(&bundle, &offline_document))?;
        let external_copy = BundleEngine::local().copy_verified(
            VerifiedCopyRequest::new(
                &bundle,
                request.root.join("external-storage.iniza"),
                loaded_for_copy.recovery_secret(),
            )
            .with_persistence(&self.external_copy_storage),
        )?;
        let cloud_copy = BundleEngine::local().copy_verified(
            VerifiedCopyRequest::new(
                &bundle,
                cloud_copy_path(&request.root),
                loaded_for_copy.recovery_secret(),
            )
            .with_persistence(&self.cloud_copy_storage),
        )?;
        if external_copy.storage_location() != VerifiedCopyStorageLocation::ExternalStorage
            || cloud_copy.storage_location() != VerifiedCopyStorageLocation::ICloudDrive
            || !external_copy.is_verified()
            || !cloud_copy.is_verified()
        {
            return Err(CoreError::BundleInvalid(
                "synthetic rehearsal did not produce both required Verified Copy classes"
                    .to_owned(),
            ));
        }
        drop(loaded_for_copy);

        let restored = request.root.join("restored");
        let loaded_for_interrupted_restore =
            offline_engine.load(OfflineRecoveryLoadRequest::new(&bundle, &offline_document))?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = SharedRestoreCancellation {
            cancelled: Arc::clone(&cancelled),
        };
        let mut cancel_when_staged = CancelWhenStagingValidated { cancelled };
        let paused = RestoreEngine::local().restore(
            RestoreRequest::new(
                cloud_copy_path(&request.root),
                &restored,
                loaded_for_interrupted_restore.recovery_secret(),
            )
            .with_event_sink(&mut cancel_when_staged)
            .with_cancellation(&cancellation),
        )?;
        if paused.state() != RestoreState::Paused {
            return Err(CoreError::BundleInvalid(
                "synthetic Restore did not pause at its durable checkpoint".to_owned(),
            ));
        }
        drop(loaded_for_interrupted_restore);

        let loaded_for_resumed_restore = offline_engine.load(OfflineRecoveryLoadRequest::new(
            cloud_copy_path(&request.root),
            &offline_document,
        ))?;
        let restore = RestoreEngine::local().restore(
            RestoreRequest::new(
                cloud_copy_path(&request.root),
                &restored,
                loaded_for_resumed_restore.recovery_secret(),
            )
            .resume(),
        )?;
        if restore.state() != RestoreState::Complete {
            return Err(CoreError::BundleInvalid(
                "synthetic Restore Resume did not complete".to_owned(),
            ));
        }

        let exact_comparison_passed =
            read_fixture(&restored.join("developer-config/shell-settings.txt"))? == SHELL_SETTINGS
                && read_fixture(&restored.join("ordinary-binary.bin"))? == ORDINARY_BINARY;
        if !exact_comparison_passed {
            return Err(CoreError::BundleInvalid(
                "synthetic Restore comparison did not match the independent fixture".to_owned(),
            ));
        }

        Ok(SyntheticMigrationRehearsalReport {
            capture,
            external_copy,
            cloud_copy,
            restore,
            restore_was_resumed: true,
            exact_comparison_passed,
            not_protected_report,
        })
    }
}

fn cloud_copy_path(root: &Path) -> PathBuf {
    root.join("icloud-drive.iniza")
}

fn create_rehearsal_root(path: &Path) -> Result<(), CoreError> {
    if path.exists() {
        return Err(CoreError::DestinationAlreadyExists(path.to_path_buf()));
    }
    create_directory(path)
}

fn create_directory(path: &Path) -> Result<(), CoreError> {
    fs::create_dir(path).map_err(|source| CoreError::Io {
        action: "create synthetic rehearsal directory",
        path: path.to_path_buf(),
        source,
    })
}

fn write_fixture(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    fs::write(path, bytes).map_err(|source| CoreError::Io {
        action: "write synthetic rehearsal fixture",
        path: path.to_path_buf(),
        source,
    })
}

fn read_fixture(path: &Path) -> Result<Vec<u8>, CoreError> {
    fs::read(path).map_err(|source| CoreError::Io {
        action: "read restored synthetic rehearsal fixture",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn create_synthetic_unsupported_entry(destination: &Path) -> Result<(), CoreError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let encoded = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        CoreError::BundleInvalid("synthetic unsupported-entry path contains a null byte".to_owned())
    })?;
    // SAFETY: `encoded` is a valid, null-terminated path and the mode contains
    // only ordinary permission bits. The created first-in-first-out node is
    // isolated beneath the disposable rehearsal root.
    if unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) } != 0 {
        return Err(CoreError::Io {
            action: "create synthetic unsupported first-in-first-out node",
            path: destination.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

struct CancelWhenStagingValidated {
    cancelled: Arc<AtomicBool>,
}

impl RestoreEventSink for CancelWhenStagingValidated {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::StagingValidated {
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }
}

struct SharedRestoreCancellation {
    cancelled: Arc<AtomicBool>,
}

impl RestoreCancellation for SharedRestoreCancellation {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}
