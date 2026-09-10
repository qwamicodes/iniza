use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::json;

use crate::{
    BitwardenCommandLine, BundleEngine, CoreError, MigrationCaptureOwnerReview,
    MigrationCaptureReport, MigrationCaptureRequest, MigrationCaptureState,
    MigrationWorkflowEngine, NotProtectedReport, OfflineRecoveryEngine, OfflineRecoveryLoadRequest,
    OfflineRecoveryStorage, PlanEngine, ProjectAuditEngine, ProjectAuditRequest,
    ProjectCapsuleCaptureRequest, ProjectCapsuleEngine, ProjectCapsuleIgnoredRecommendation,
    ProjectCapsuleRehearsalRequest, ProjectCapsuleReviewDecision, ProjectCapsuleReviewRequest,
    ProjectHead, ReadinessEvidenceConclusion, ReadinessEvidenceEngine,
    ReadinessEvidenceInitializationRequest, ReadinessEvidenceStatusReport,
    ReadinessEvidenceStatusRequest, ReadinessEvidenceStorage, ReadinessEvidenceStorageTransition,
    ReadinessReceiptRecordRequest, RestoreCancellation, RestoreEngine, RestoreEvent,
    RestoreEventSink, RestoreReport, RestoreRequest, RestoreState, ScanRequest,
    VaultwardenInstallationRequest, VaultwardenLoadRequest, VaultwardenRecoveryEngine,
    VerifiedCopyPersistence, VerifiedCopyReport, VerifiedCopyRequest, VerifiedCopyStorageLocation,
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
    readiness_status: ReadinessEvidenceStatusReport,
    receipt_invalidation_was_detected: bool,
    audited_project_count: usize,
    project_capsule_is_restorable: bool,
    project_state_matrix_passed: bool,
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

    pub fn readiness_status(&self) -> &ReadinessEvidenceStatusReport {
        &self.readiness_status
    }

    pub fn receipt_invalidation_was_detected(&self) -> bool {
        self.receipt_invalidation_was_detected
    }

    pub fn audited_project_count(&self) -> usize {
        self.audited_project_count
    }

    pub fn project_capsule_is_restorable(&self) -> bool {
        self.project_capsule_is_restorable
    }

    pub fn project_state_matrix_passed(&self) -> bool {
        self.project_state_matrix_passed
    }

    pub fn human_summary(&self) -> &'static str {
        "Synthetic migration rehearsal authenticated the Bundle through both Recovery Methods, created two Verified Copies, completed an interrupted and resumed Restore Rehearsal with exact comparison, audited a dirty Project and completed its Project Capsule Restore Rehearsal, appended machine Receipts to append-only Readiness Evidence, and proved that mutation invalidates a Receipt. Owner Attestations remain unconfirmed. This result does not authorize real source capture and does not decide whether this machine is safe to erase."
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
                "audited_projects": self.audited_project_count,
                "project_capsules_restorable": usize::from(self.project_capsule_is_restorable),
                "project_state_matrix_passed": self.project_state_matrix_passed,
                "exact_comparison_passed": self.exact_comparison_passed,
                "not_protected_items": self.not_protected_report.entries().len(),
                "must_protect_gaps": self.not_protected_report.must_protect_gap_count(),
                "receipt_invalidation_detected": self.receipt_invalidation_was_detected,
                "readiness_state": match self.readiness_status.state() {
                    crate::ReadinessEvidenceState::CompleteEvidence => "complete-evidence",
                    crate::ReadinessEvidenceState::BlockingGaps => "blocking-gaps",
                },
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
        let project_root = source.join("project-fixture");
        create_dirty_project_fixture(&project_root)?;
        create_detached_project_fixture(&source.join("project-fixture-detached"))?;
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

        let project_audit =
            ProjectAuditEngine::local().audit(ProjectAuditRequest::from_plan(&plan))?;
        let audited_project_count = project_audit.projects().len();
        let canonical_project_root =
            fs::canonicalize(&project_root).map_err(|source_error| CoreError::Io {
                action: "canonicalize synthetic Project root",
                path: project_root.clone(),
                source: source_error,
            })?;
        let project = project_audit
            .projects()
            .iter()
            .find(|project| project.root() == canonical_project_root)
            .ok_or_else(|| {
                CoreError::BundleInvalid(
                    "synthetic rehearsal did not discover its dirty Project".to_owned(),
                )
            })?;
        if audited_project_count != 2 {
            return Err(CoreError::BundleInvalid(format!(
                "synthetic rehearsal expected two Projects and discovered {audited_project_count}"
            )));
        }
        let local_state = project.local_state();
        let ignored_state_is_present = project
            .ignored_candidates()
            .is_ok_and(|candidates| !candidates.is_empty());
        let mut project_state_matrix_passed = local_state.upstream().is_none()
            && local_state.staged_changes() == 1
            && local_state.unstaged_changes() == 1
            && local_state.untracked_items() == 1
            && local_state.stash_count() == 1
            && local_state
                .local_only_branches()
                .iter()
                .any(|branch| branch == "local-only")
            && local_state
                .local_only_tags()
                .iter()
                .any(|tag| tag == "local-only-tag")
            && ignored_state_is_present
            && project_audit.projects().iter().any(|project| {
                matches!(project.local_state().head(), ProjectHead::Detached(_))
                    && project.local_state().upstream().is_none()
            });
        if !project_state_matrix_passed {
            return Err(CoreError::BundleInvalid(format!(
                "synthetic Project did not expose the reviewed dirty-state matrix: staged={}, unstaged={}, untracked={}, stashes={}, local branches={}, local tags={}, ignored={ignored_state_is_present}",
                local_state.staged_changes(),
                local_state.unstaged_changes(),
                local_state.untracked_items(),
                local_state.stash_count(),
                local_state.local_only_branches().len(),
                local_state.local_only_tags().len(),
            )));
        }
        let capsule_engine = ProjectCapsuleEngine::local();
        let initial_capsule_review =
            capsule_engine.review(ProjectCapsuleReviewRequest::new(&plan, project))?;
        let mut capsule_review_request = ProjectCapsuleReviewRequest::new(&plan, project);
        for ignored in initial_capsule_review.ignored_candidates() {
            let decision = match ignored.recommendation() {
                ProjectCapsuleIgnoredRecommendation::RequiresExplicitDecision => {
                    ProjectCapsuleReviewDecision::include_as_encrypted_reviewed_state(
                        ignored.candidate_id(),
                    )
                }
                ProjectCapsuleIgnoredRecommendation::ExcludeReproducibleGeneratedState => {
                    ProjectCapsuleReviewDecision::exclude_as_reproducible_generated_state(
                        ignored.candidate_id(),
                        "synthetic generated state is reproducible",
                    )
                }
            };
            capsule_review_request = capsule_review_request.with_decision(decision);
        }
        let capsule_review = capsule_engine.review(capsule_review_request)?;
        if !capsule_review.is_complete() {
            return Err(CoreError::BundleInvalid(
                "synthetic Project Capsule review remained incomplete".to_owned(),
            ));
        }
        let project_capsule = request.root.join("project-capsule.iniza");
        let capsule_capture = capsule_engine.capture(ProjectCapsuleCaptureRequest::new(
            &plan,
            project,
            &capsule_review,
            capsule_review.review_hash(),
            &project_capsule,
        ))?;
        let capsule_expectation = capsule_capture
            .expectation()
            .ok_or_else(|| {
                CoreError::BundleInvalid(
                    "verified synthetic Project Capsule has no expectation".to_owned(),
                )
            })?
            .clone();
        let capsule_rehearsal = capsule_engine.rehearse(ProjectCapsuleRehearsalRequest::new(
            &project_capsule,
            &capsule_expectation,
            capsule_capture.offline_recovery_key(),
            request.root.join("project-capsule-restored"),
        ))?;
        let project_capsule_is_restorable = capsule_rehearsal.is_restorable();
        project_state_matrix_passed = project_state_matrix_passed
            && capsule_rehearsal.validation().is_faithful()
            && capsule_rehearsal.validation().has_no_remote()
            && capsule_rehearsal.validation().hooks_are_disabled()
            && capsule_rehearsal
                .validation()
                .reference_object_identifier("refs/heads/local-only")
                .is_some()
            && capsule_rehearsal
                .validation()
                .reference_object_identifier("refs/tags/local-only-tag")
                .is_some();
        if !project_capsule_is_restorable {
            return Err(CoreError::BundleInvalid(
                "synthetic Project Capsule Restore Rehearsal was not Restorable".to_owned(),
            ));
        }

        let bundle = request.root.join("migration.iniza");
        let offline_document = request.root.join("migration.iniza-recovery");
        let capture_engine = MigrationWorkflowEngine::with_boundaries(
            self.bitwarden.clone(),
            self.offline_storage.clone(),
        );
        let installation_request = request.installation.clone();
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
        let first_cloud_copy_path = cloud_copy_path(&request.root);
        let cloud_copy = BundleEngine::local().copy_verified(
            VerifiedCopyRequest::new(
                &bundle,
                &first_cloud_copy_path,
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
            &first_cloud_copy_path,
            &offline_document,
        ))?;
        let restore = RestoreEngine::local().restore(
            RestoreRequest::new(
                &first_cloud_copy_path,
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

        let evidence_directory = request.root.join("readiness-evidence");
        let replacement_cloud_copy_path = request.root.join("icloud-drive-replacement.iniza");
        let readiness = ReadinessEvidenceEngine::with_storage(RehearsalReadinessStorage {
            external_copy: request.root.join("external-storage.iniza"),
            cloud_copies: vec![
                first_cloud_copy_path.clone(),
                replacement_cloud_copy_path.clone(),
            ],
        });
        readiness.initialize(ReadinessEvidenceInitializationRequest::new(
            &plan,
            &evidence_directory,
        ))?;
        readiness.record_receipt(ReadinessReceiptRecordRequest::bundle_verification(
            &evidence_directory,
            &plan,
            &bundle,
            capture.offline_verification(),
        ))?;
        readiness.record_receipt(ReadinessReceiptRecordRequest::offline_recovery(
            &evidence_directory,
            &plan,
            capture.offline_receipt(),
        ))?;
        readiness.record_receipt(ReadinessReceiptRecordRequest::vaultwarden_recovery(
            &evidence_directory,
            &plan,
            capture.vaultwarden_receipt(),
        ))?;
        readiness.record_receipt(ReadinessReceiptRecordRequest::verified_copy(
            &evidence_directory,
            &plan,
            &external_copy,
        ))?;
        readiness.record_receipt(ReadinessReceiptRecordRequest::verified_copy(
            &evidence_directory,
            &plan,
            &cloud_copy,
        ))?;
        readiness.record_receipt(ReadinessReceiptRecordRequest::not_protected_report(
            &evidence_directory,
            &plan,
        ))?;
        readiness.record_receipt(ReadinessReceiptRecordRequest::restore_rehearsal(
            &evidence_directory,
            &plan,
            &restore,
        ))?;
        readiness.record_receipt(ReadinessReceiptRecordRequest::project_capsule_capture(
            &evidence_directory,
            &plan,
            &capsule_capture,
        ))?;
        readiness.record_receipt(ReadinessReceiptRecordRequest::project_capsule_rehearsal(
            &evidence_directory,
            &plan,
            &capsule_rehearsal,
        ))?;

        let vaultwarden = VaultwardenRecoveryEngine::with_command_line(self.bitwarden.clone());
        let installation = vaultwarden.inspect_installation(installation_request)?;
        let reviewed_installation_hash = request
            .owner_review
            .review_bitwarden_installation(&installation)?;
        let loaded_vaultwarden = vaultwarden.load(VaultwardenLoadRequest::new(
            &bundle,
            capture.vaultwarden_receipt().item_identifier().clone(),
            capture.vaultwarden_receipt().server_identity_hash(),
            &installation,
            reviewed_installation_hash,
        ))?;
        let loaded_for_status =
            offline_engine.load(OfflineRecoveryLoadRequest::new(&bundle, &offline_document))?;
        let status_request = |cloud_copy: &Path| {
            ReadinessEvidenceStatusRequest::new(&evidence_directory, &plan)
                .with_bundle(&bundle, loaded_for_status.recovery_secret())
                .with_offline_recovery_document(&offline_document)
                .with_vaultwarden_recovery(&loaded_vaultwarden)
                .with_verified_copy(request.root.join("external-storage.iniza"))
                .with_verified_copy(cloud_copy)
                .with_restore_rehearsal(&restored)
                .with_project_capsule(
                    &project_capsule,
                    &capsule_expectation,
                    capsule_capture.offline_recovery_key(),
                )
                .with_project_publication(project)
        };
        let before_mutation = readiness.status(status_request(&first_cloud_copy_path))?;
        if before_mutation.verified_copy() != ReadinessEvidenceConclusion::Current {
            return Err(CoreError::ReadinessEvidence(
                "synthetic Verified Copy Receipts were not current before mutation".to_owned(),
            ));
        }
        fs::write(&first_cloud_copy_path, b"synthetic changed copy\n").map_err(|source_error| {
            CoreError::Io {
                action: "mutate disposable synthetic Verified Copy",
                path: first_cloud_copy_path.clone(),
                source: source_error,
            }
        })?;
        let invalidated = readiness.status(status_request(&first_cloud_copy_path))?;
        let receipt_invalidation_was_detected =
            invalidated.verified_copy() == ReadinessEvidenceConclusion::Invalidated;
        if !receipt_invalidation_was_detected {
            return Err(CoreError::ReadinessEvidence(
                "synthetic Verified Copy mutation did not invalidate its Receipt".to_owned(),
            ));
        }
        let cloud_copy = BundleEngine::local().copy_verified(
            VerifiedCopyRequest::new(
                &bundle,
                &replacement_cloud_copy_path,
                loaded_for_status.recovery_secret(),
            )
            .with_persistence(&self.cloud_copy_storage),
        )?;
        readiness.record_receipt(ReadinessReceiptRecordRequest::verified_copy(
            &evidence_directory,
            &plan,
            &cloud_copy,
        ))?;
        let readiness_status = readiness.status(status_request(&replacement_cloud_copy_path))?;
        if readiness_status.verified_copy() != ReadinessEvidenceConclusion::Current {
            return Err(CoreError::ReadinessEvidence(
                "replacement synthetic Verified Copy Receipt is not current".to_owned(),
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
            readiness_status,
            receipt_invalidation_was_detected,
            audited_project_count,
            project_capsule_is_restorable,
            project_state_matrix_passed,
        })
    }
}

#[derive(Debug)]
struct RehearsalReadinessStorage {
    external_copy: PathBuf,
    cloud_copies: Vec<PathBuf>,
}

impl ReadinessEvidenceStorage for RehearsalReadinessStorage {
    fn prepare_transition(
        &self,
        _transition: ReadinessEvidenceStorageTransition,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn verified_copy_storage_location(
        &self,
        _source: &Path,
        destination: &Path,
    ) -> std::io::Result<VerifiedCopyStorageLocation> {
        if destination == self.external_copy {
            Ok(VerifiedCopyStorageLocation::ExternalStorage)
        } else if self.cloud_copies.iter().any(|copy| copy == destination) {
            Ok(VerifiedCopyStorageLocation::ICloudDrive)
        } else {
            Ok(VerifiedCopyStorageLocation::Other)
        }
    }
}

fn cloud_copy_path(root: &Path) -> PathBuf {
    root.join("icloud-drive.iniza")
}

fn create_dirty_project_fixture(project: &Path) -> Result<(), CoreError> {
    create_directory(project)?;
    run_git(project, &["init", "-q", "-b", "main"])?;
    write_fixture(&project.join(".gitignore"), b"reviewed-secret.env\n")?;
    write_fixture(&project.join("staged.txt"), b"initial staged value\n")?;
    write_fixture(&project.join("unstaged.txt"), b"initial unstaged value\n")?;
    write_fixture(&project.join("stash.txt"), b"initial stash value\n")?;
    run_git(project, &["add", "."])?;
    run_git(
        project,
        &[
            "-c",
            "user.name=Iniza Synthetic Rehearsal",
            "-c",
            "user.email=iniza@example.invalid",
            "commit",
            "-q",
            "-m",
            "synthetic initial state",
        ],
    )?;
    run_git(project, &["branch", "local-only"])?;
    run_git(project, &["tag", "local-only-tag"])?;
    write_fixture(&project.join("stash.txt"), b"synthetic stashed value\n")?;
    run_git(project, &["stash", "push", "-q", "-m", "synthetic stash"])?;
    write_fixture(&project.join("staged.txt"), b"synthetic staged value\n")?;
    run_git(project, &["add", "staged.txt"])?;
    write_fixture(&project.join("unstaged.txt"), b"synthetic unstaged value\n")?;
    write_fixture(
        &project.join("untracked.txt"),
        b"synthetic untracked value\n",
    )?;
    write_fixture(
        &project.join("reviewed-secret.env"),
        b"SYNTHETIC_VALUE=not-a-secret\n",
    )?;
    run_git(project, &["config", "core.hooksPath", "/dev/null"])?;
    Ok(())
}

fn create_detached_project_fixture(project: &Path) -> Result<(), CoreError> {
    create_directory(project)?;
    run_git(project, &["init", "-q", "-b", "main"])?;
    write_fixture(&project.join("detached.txt"), b"synthetic detached state\n")?;
    run_git(project, &["add", "detached.txt"])?;
    run_git(
        project,
        &[
            "-c",
            "user.name=Iniza Synthetic Rehearsal",
            "-c",
            "user.email=iniza@example.invalid",
            "commit",
            "-q",
            "-m",
            "synthetic detached state",
        ],
    )?;
    run_git(project, &["checkout", "-q", "--detach", "HEAD"])?;
    Ok(())
}

fn run_git(project: &Path, arguments: &[&str]) -> Result<(), CoreError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(arguments)
        .output()
        .map_err(|source| CoreError::Io {
            action: "run Git for synthetic Project rehearsal",
            path: project.to_path_buf(),
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(CoreError::BundleInvalid(format!(
            "synthetic Project Git command failed with status {}",
            output.status
        )))
    }
}

fn create_rehearsal_root(path: &Path) -> Result<(), CoreError> {
    if path.exists() {
        return Err(CoreError::DestinationAlreadyExists(path.to_path_buf()));
    }
    create_directory(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            CoreError::Io {
                action: "secure synthetic rehearsal directory",
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    Ok(())
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
