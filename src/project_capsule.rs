use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

use crate::{
    BundleEngine, BundleVerification, CoreError, Disposition, GitProcess, InstalledGit,
    MigrationItemKind, PackReport, PackRequest, Plan, PlanApprovalState, PlanEngine, ProjectAudit,
    ProjectKind, RecoverySecret, RestoreEngine, RestoreRequest, ScanRequest, VerifyRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectCapsuleRepresentation {
    GitNativeArchiveWithOverlay,
    FullRepositorySnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectCapsuleCaptureState {
    Verified,
    ChangedAndUnverified,
}

pub struct ProjectCapsuleCaptureRequest<'a> {
    plan: &'a Plan,
    project: &'a ProjectAudit,
    destination: PathBuf,
    reviewed_ignored_paths: Vec<PathBuf>,
    reviewed_executables: Vec<PathBuf>,
}

impl<'a> ProjectCapsuleCaptureRequest<'a> {
    pub fn new(plan: &'a Plan, project: &'a ProjectAudit, destination: impl Into<PathBuf>) -> Self {
        Self {
            plan,
            project,
            destination: destination.into(),
            reviewed_ignored_paths: Vec::new(),
            reviewed_executables: Vec::new(),
        }
    }

    pub fn with_reviewed_ignored_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.reviewed_ignored_paths.push(path.into());
        self
    }

    pub fn with_reviewed_executable(mut self, path: impl Into<PathBuf>) -> Self {
        self.reviewed_executables.push(path.into());
        self
    }
}

pub struct ProjectCapsuleCaptureReport {
    state: ProjectCapsuleCaptureState,
    pre_capture_hash: String,
    post_capture_hash: String,
    bundle_bytes: u64,
    verification: BundleVerification,
    pack: PackReport,
}

impl fmt::Debug for ProjectCapsuleCaptureReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectCapsuleCaptureReport")
            .field("state", &self.state)
            .field(
                "representation",
                &ProjectCapsuleRepresentation::FullRepositorySnapshot,
            )
            .field("pre_capture_hash", &self.pre_capture_hash)
            .field("post_capture_hash", &self.post_capture_hash)
            .field("bundle_bytes", &self.bundle_bytes)
            .field("bundle_identity", &self.verification.bundle_identity())
            .field(
                "authenticated_project_bytes",
                &self.verification.authenticated_bytes,
            )
            .field("pack_state", &self.pack.state())
            .finish()
    }
}

impl ProjectCapsuleCaptureReport {
    pub fn state(&self) -> ProjectCapsuleCaptureState {
        self.state
    }

    pub fn is_verified(&self) -> bool {
        self.state == ProjectCapsuleCaptureState::Verified
    }

    pub fn representation(&self) -> ProjectCapsuleRepresentation {
        ProjectCapsuleRepresentation::FullRepositorySnapshot
    }

    pub fn pre_capture_hash(&self) -> &str {
        &self.pre_capture_hash
    }

    pub fn post_capture_hash(&self) -> &str {
        &self.post_capture_hash
    }

    pub fn bundle_bytes(&self) -> u64 {
        self.bundle_bytes
    }

    pub fn verification(&self) -> &BundleVerification {
        &self.verification
    }

    pub fn authenticated_project_bytes(&self) -> u64 {
        self.verification.authenticated_bytes
    }

    pub fn vaultwarden_recovery_secret(&self) -> &RecoverySecret {
        self.pack.vaultwarden_recovery_secret()
    }

    pub fn offline_recovery_key(&self) -> &RecoverySecret {
        self.pack.offline_recovery_key()
    }

    pub fn human_result(&self) -> String {
        format!(
            "Project Capsule capture\n  state: {}\n  representation: full-repository-snapshot\n  encrypted Bundle: {} bytes\n  authenticated Project: {} bytes\n  next action: {}",
            match self.state {
                ProjectCapsuleCaptureState::Verified => "Verified",
                ProjectCapsuleCaptureState::ChangedAndUnverified => "Changed and Unverified",
            },
            self.bundle_bytes,
            self.verification.authenticated_bytes,
            if self.state == ProjectCapsuleCaptureState::Verified {
                "store and rehearse both Recovery Methods, then perform a Restore Rehearsal"
            } else {
                "preserve this Bundle for review and capture again after the Project is stable"
            },
        )
    }

    pub fn machine_json_result(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "command": "project capsule capture",
            "status": match self.state {
                ProjectCapsuleCaptureState::Verified => "success",
                ProjectCapsuleCaptureState::ChangedAndUnverified => "changed-and-unverified",
            },
            "data": {
                "state": match self.state {
                    ProjectCapsuleCaptureState::Verified => "verified",
                    ProjectCapsuleCaptureState::ChangedAndUnverified => "changed-and-unverified",
                },
                "representation": "full-repository-snapshot",
                "bundle_identity": self.verification.bundle_identity(),
                "encrypted_bundle_bytes": self.bundle_bytes,
                "authenticated_project_bytes": self.verification.authenticated_bytes,
                "restore_rehearsal": "not-performed",
                "synchronized": "not-evaluated",
            },
            "warnings": [],
            "errors": [],
        })
        .to_string()
    }
}

pub struct ProjectCapsuleComparisonRequest {
    project_root: PathBuf,
    reviewed_ignored_paths: Vec<PathBuf>,
    reviewed_executables: Vec<PathBuf>,
    workspace: PathBuf,
    git_native_bundle: PathBuf,
    snapshot_bundle: PathBuf,
}

pub struct ProjectCapsuleValidationRequest {
    expected_project: PathBuf,
    restored_project: PathBuf,
    restored_bundle: PathBuf,
    reviewed_ignored_paths: Vec<PathBuf>,
    reviewed_executables: Vec<PathBuf>,
    executable_mode_review_hash: Option<String>,
}

impl ProjectCapsuleValidationRequest {
    pub fn new(
        expected_project: impl Into<PathBuf>,
        restored_project: impl Into<PathBuf>,
        restored_bundle: impl Into<PathBuf>,
        reviewed_ignored_paths: Vec<PathBuf>,
    ) -> Self {
        Self {
            expected_project: expected_project.into(),
            restored_project: restored_project.into(),
            restored_bundle: restored_bundle.into(),
            reviewed_ignored_paths,
            reviewed_executables: Vec::new(),
            executable_mode_review_hash: None,
        }
    }

    pub fn with_reviewed_executable(mut self, path: impl Into<PathBuf>) -> Self {
        self.reviewed_executables.push(path.into());
        self
    }

    pub fn with_executable_mode_review_hash(mut self, hash: impl Into<String>) -> Self {
        self.executable_mode_review_hash = Some(hash.into());
        self
    }
}

impl ProjectCapsuleComparisonRequest {
    pub fn new(
        project_root: impl Into<PathBuf>,
        reviewed_ignored_paths: Vec<PathBuf>,
        workspace: impl Into<PathBuf>,
        git_native_bundle: impl Into<PathBuf>,
        snapshot_bundle: impl Into<PathBuf>,
    ) -> Self {
        Self {
            project_root: project_root.into(),
            reviewed_ignored_paths,
            reviewed_executables: Vec::new(),
            workspace: workspace.into(),
            git_native_bundle: git_native_bundle.into(),
            snapshot_bundle: snapshot_bundle.into(),
        }
    }

    pub fn with_reviewed_executable(mut self, path: impl Into<PathBuf>) -> Self {
        self.reviewed_executables.push(path.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCapsuleValidationReport {
    faithful: bool,
    findings: Vec<String>,
    head_is_attached_to_main: bool,
    current_state_is_detached: bool,
    has_no_remote: bool,
    hooks_are_disabled: bool,
    reviewed_executables_restored: bool,
    required_executable_mode_review_hash: Option<String>,
    executable_mode_review_pending: bool,
    head_object_identifier: String,
    reference_object_identifiers: BTreeMap<String, String>,
}

impl ProjectCapsuleValidationReport {
    pub fn is_faithful(&self) -> bool {
        self.faithful
    }

    pub fn findings(&self) -> &[String] {
        &self.findings
    }

    pub fn head_is_attached_to_main(&self) -> bool {
        self.head_is_attached_to_main
    }

    pub fn current_state_is_detached(&self) -> bool {
        self.current_state_is_detached
    }

    pub fn has_no_remote(&self) -> bool {
        self.has_no_remote
    }

    pub fn hooks_are_disabled(&self) -> bool {
        self.hooks_are_disabled
    }

    pub fn reviewed_executables_restored(&self) -> bool {
        self.reviewed_executables_restored
    }

    pub fn required_executable_mode_review_hash(&self) -> Option<&str> {
        self.required_executable_mode_review_hash.as_deref()
    }

    pub fn executable_mode_review_is_pending(&self) -> bool {
        self.executable_mode_review_pending
    }

    pub fn head_object_identifier(&self) -> &str {
        &self.head_object_identifier
    }

    pub fn reference_object_identifier(&self, reference: &str) -> Option<&str> {
        self.reference_object_identifiers
            .get(reference)
            .map(String::as_str)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCapsuleCandidateReport {
    representation: ProjectCapsuleRepresentation,
    pre_capture_hash: String,
    post_capture_hash: String,
    bundle_bytes: u64,
    restored_bytes: u64,
    portability_findings: Vec<String>,
    maintenance_findings: Vec<String>,
    construction_must_restart: bool,
    validation: ProjectCapsuleValidationReport,
}

impl ProjectCapsuleCandidateReport {
    pub fn representation(&self) -> ProjectCapsuleRepresentation {
        self.representation
    }

    pub fn pre_capture_hash(&self) -> &str {
        &self.pre_capture_hash
    }

    pub fn post_capture_hash(&self) -> &str {
        &self.post_capture_hash
    }

    pub fn bundle_bytes(&self) -> u64 {
        self.bundle_bytes
    }

    pub fn restored_bytes(&self) -> u64 {
        self.restored_bytes
    }

    pub fn bundle_pack_is_resumable(&self) -> bool {
        true
    }

    pub fn construction_must_restart(&self) -> bool {
        self.construction_must_restart
    }

    pub fn portability_findings(&self) -> &[String] {
        &self.portability_findings
    }

    pub fn maintenance_findings(&self) -> &[String] {
        &self.maintenance_findings
    }

    pub fn validation(&self) -> &ProjectCapsuleValidationReport {
        &self.validation
    }

    pub fn restorable(&self) -> bool {
        self.pre_capture_hash == self.post_capture_hash && self.validation.faithful
    }

    pub fn changed_during_capture(&self) -> bool {
        self.pre_capture_hash != self.post_capture_hash
    }

    pub fn eligible_for_recommendation(&self) -> bool {
        self.restorable()
            && self.representation == ProjectCapsuleRepresentation::FullRepositorySnapshot
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCapsuleComparisonReport {
    candidates: BTreeMap<ProjectCapsuleRepresentation, ProjectCapsuleCandidateReport>,
    recommendation: Option<ProjectCapsuleRepresentation>,
}

impl ProjectCapsuleComparisonReport {
    pub fn candidate(
        &self,
        representation: ProjectCapsuleRepresentation,
    ) -> Option<&ProjectCapsuleCandidateReport> {
        self.candidates.get(&representation)
    }

    pub fn recommendation(&self) -> Option<ProjectCapsuleRepresentation> {
        self.recommendation
    }

    pub fn human_result(&self) -> String {
        let mut lines = vec!["Project Capsule comparison".to_owned()];
        for candidate in self.candidates.values() {
            lines.push(format!(
                "  {}: {}; encrypted Bundle {} bytes; restored {} bytes",
                representation_name(candidate.representation),
                if candidate.restorable() {
                    "Restorable"
                } else if candidate.changed_during_capture() {
                    "Changed and Unverified"
                } else {
                    "Not Restorable"
                },
                candidate.bundle_bytes,
                candidate.restored_bytes,
            ));
        }
        lines.push(match self.recommendation {
            Some(representation) => {
                format!("  recommendation: {}", representation_name(representation))
            }
            None => "  recommendation: none".to_owned(),
        });
        lines.join("\n")
    }

    pub fn machine_json_result(&self) -> String {
        let candidates = self
            .candidates
            .values()
            .map(|candidate| {
                serde_json::json!({
                    "representation": representation_name(candidate.representation),
                    "restorable": candidate.restorable(),
                    "eligible_for_recommendation": candidate.eligible_for_recommendation(),
                    "changed_during_capture": candidate.changed_during_capture(),
                    "encrypted_bundle_bytes": candidate.bundle_bytes,
                    "restored_bytes": candidate.restored_bytes,
                    "resumability": {
                        "encrypted_pack": "authenticated-checkpoint",
                        "candidate_construction": if candidate.construction_must_restart {
                            "restart-required"
                        } else {
                            "native-pack"
                        },
                    },
                    "portability_findings": candidate.portability_findings,
                    "maintenance_findings": candidate.maintenance_findings,
                    "validation_findings": candidate.validation.findings,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema_version": 1,
            "command": "project capsule compare",
            "status": if self.recommendation.is_some() { "success" } else { "no-recommendation" },
            "data": {
                "candidates": candidates,
                "recommendation": self.recommendation.map(representation_name),
            },
            "warnings": [],
            "errors": [],
        })
        .to_string()
    }
}

fn representation_name(representation: ProjectCapsuleRepresentation) -> &'static str {
    match representation {
        ProjectCapsuleRepresentation::GitNativeArchiveWithOverlay => {
            "git-native-archive-with-overlay"
        }
        ProjectCapsuleRepresentation::FullRepositorySnapshot => "full-repository-snapshot",
    }
}

#[derive(Debug)]
pub struct ProjectCapsuleEngine<G = InstalledGit> {
    git: G,
}

impl ProjectCapsuleEngine<InstalledGit> {
    pub fn local() -> Self {
        Self {
            git: InstalledGit::default(),
        }
    }
}

impl<G> ProjectCapsuleEngine<G> {
    pub fn with_git_process(git: G) -> Self {
        Self { git }
    }
}

impl<G: GitProcess> ProjectCapsuleEngine<G> {
    pub fn capture(
        &self,
        mut request: ProjectCapsuleCaptureRequest<'_>,
    ) -> Result<ProjectCapsuleCaptureReport, CoreError> {
        validate_capture_request(&self.git, &mut request)?;
        let root = request.project.root();
        let expected = observe_project(&self.git, root, &request.reviewed_ignored_paths)?;
        let excluded_ignored =
            unreviewed_ignored_paths(&self.git, root, &request.reviewed_ignored_paths)?;
        let capsule_plan = approved_capsule_plan(root, &excluded_ignored)?;
        let engine = BundleEngine::local();
        let pack = engine.pack(PackRequest::new(&capsule_plan, &request.destination))?;
        let verification = engine.verify(VerifyRequest::new(
            &request.destination,
            pack.offline_recovery_key(),
        ))?;
        let post_capture_hash =
            observe_project(&self.git, root, &request.reviewed_ignored_paths)?.digest;
        let state = if expected.digest == post_capture_hash {
            ProjectCapsuleCaptureState::Verified
        } else {
            ProjectCapsuleCaptureState::ChangedAndUnverified
        };
        Ok(ProjectCapsuleCaptureReport {
            state,
            pre_capture_hash: expected.digest,
            post_capture_hash,
            bundle_bytes: file_len(&request.destination)?,
            verification,
            pack,
        })
    }

    pub fn validate_restored(
        &self,
        mut request: ProjectCapsuleValidationRequest,
    ) -> Result<ProjectCapsuleValidationReport, CoreError> {
        request.reviewed_ignored_paths.sort();
        request.reviewed_ignored_paths.dedup();
        request.reviewed_executables.sort();
        request.reviewed_executables.dedup();
        validate_reviewed_paths(
            &request.reviewed_ignored_paths,
            &request.reviewed_executables,
        )?;
        let expected = observe_project(
            &self.git,
            &request.expected_project,
            &request.reviewed_ignored_paths,
        )?;
        let required_hash = executable_mode_review_hash(
            &request.expected_project,
            &request.restored_bundle,
            &expected,
            &request.reviewed_executables,
        )?;
        let approved = request.reviewed_executables.is_empty()
            || request.executable_mode_review_hash.as_deref() == Some(required_hash.as_str());
        if approved {
            restore_reviewed_executable_modes(
                &request.expected_project,
                &request.restored_project,
                &request.reviewed_executables,
            )?;
        }
        let mut report = validate_project(
            &self.git,
            &expected,
            &request.restored_project,
            &request.reviewed_ignored_paths,
            &request.reviewed_executables,
        )?;
        report.required_executable_mode_review_hash =
            (!request.reviewed_executables.is_empty()).then_some(required_hash);
        report.executable_mode_review_pending = !approved;
        if !approved
            && !report
                .findings
                .iter()
                .any(|finding| finding == "executable-mode-review")
        {
            report.findings.push("executable-mode-review".to_owned());
            report.faithful = false;
        }
        Ok(report)
    }

    pub fn compare(
        &self,
        mut request: ProjectCapsuleComparisonRequest,
    ) -> Result<ProjectCapsuleComparisonReport, CoreError> {
        validate_request(&mut request)?;
        fs::create_dir(&request.workspace).map_err(|source| CoreError::Io {
            action: "create Project Capsule comparison workspace",
            path: request.workspace.clone(),
            source,
        })?;

        let expected = observe_project(
            &self.git,
            &request.project_root,
            &request.reviewed_ignored_paths,
        )?;
        let mut candidates = BTreeMap::new();

        let git_native = self.round_trip_git_native(&request, &expected)?;
        candidates.insert(
            ProjectCapsuleRepresentation::GitNativeArchiveWithOverlay,
            git_native,
        );

        let snapshot = self.round_trip_snapshot(&request, &expected)?;
        candidates.insert(
            ProjectCapsuleRepresentation::FullRepositorySnapshot,
            snapshot,
        );

        let recommendation = candidates
            .values()
            .filter(|candidate| candidate.eligible_for_recommendation())
            .min_by_key(|candidate| candidate.bundle_bytes)
            .map(|candidate| candidate.representation);
        Ok(ProjectCapsuleComparisonReport {
            candidates,
            recommendation,
        })
    }

    fn round_trip_snapshot(
        &self,
        request: &ProjectCapsuleComparisonRequest,
        expected: &ProjectObservation,
    ) -> Result<ProjectCapsuleCandidateReport, CoreError> {
        let pre_capture_hash = expected.digest.clone();
        let excluded_ignored = unreviewed_ignored_paths(
            &self.git,
            &request.project_root,
            &request.reviewed_ignored_paths,
        )?;
        let plan = approved_capsule_plan(&request.project_root, &excluded_ignored)?;
        let engine = BundleEngine::local();
        let sealed = engine.pack(PackRequest::new(&plan, &request.snapshot_bundle))?;
        let verified = engine.verify(VerifyRequest::new(
            &request.snapshot_bundle,
            sealed.offline_recovery_key(),
        ))?;
        let post_capture_hash = observe_project(
            &self.git,
            &request.project_root,
            &request.reviewed_ignored_paths,
        )?
        .digest;
        let restored = request.workspace.join("snapshot-restored");
        let restore_report = RestoreEngine::local().restore(RestoreRequest::new(
            &request.snapshot_bundle,
            &restored,
            sealed.offline_recovery_key(),
        ))?;
        restore_reviewed_executable_modes(
            &request.project_root,
            &restored,
            &request.reviewed_executables,
        )?;
        let validation = validate_project(
            &self.git,
            expected,
            &restored,
            &request.reviewed_ignored_paths,
            &request.reviewed_executables,
        )?;
        Ok(ProjectCapsuleCandidateReport {
            representation: ProjectCapsuleRepresentation::FullRepositorySnapshot,
            pre_capture_hash,
            post_capture_hash,
            bundle_bytes: file_len(&request.snapshot_bundle)?,
            restored_bytes: restore_report
                .restored_bytes()
                .max(verified.authenticated_bytes),
            portability_findings: vec![
                "depends on compatible Git repository database, symbolic-link, and file-mode semantics"
                    .to_owned(),
            ],
            maintenance_findings: vec![
                "reuses the directory Plan, direct encrypted Pack, full Verify, and safe Restore"
                    .to_owned(),
            ],
            construction_must_restart: false,
            validation,
        })
    }

    fn round_trip_git_native(
        &self,
        request: &ProjectCapsuleComparisonRequest,
        expected: &ProjectObservation,
    ) -> Result<ProjectCapsuleCandidateReport, CoreError> {
        let pre_capture_hash = expected.digest.clone();
        let source = request.workspace.join("git-native-source");
        fs::create_dir(&source).map_err(|error| CoreError::Io {
            action: "create synthetic Git-native Project Capsule source",
            path: source.clone(),
            source: error,
        })?;
        let archive = source.join("repository.bundle");
        run_git_required(
            &self.git,
            &request.project_root,
            &[
                OsString::from("bundle"),
                OsString::from("create"),
                archive.as_os_str().to_owned(),
                OsString::from("--all"),
                OsString::from("HEAD"),
            ],
            "create Git-native Project archive",
        )?;
        let excluded_ignored = unreviewed_ignored_paths(
            &self.git,
            &request.project_root,
            &request.reviewed_ignored_paths,
        )?;
        copy_worktree_overlay(
            &request.project_root,
            &source.join("worktree"),
            &excluded_ignored,
        )?;
        let git_overlay = source.join("git-overlay");
        fs::create_dir_all(git_overlay.join("hooks")).map_err(|error| CoreError::Io {
            action: "create Git metadata overlay",
            path: git_overlay.clone(),
            source: error,
        })?;
        copy_regular_file(
            &request.project_root.join(".git/index"),
            &git_overlay.join("index"),
            0o600,
        )?;
        capture_index_objects(&self.git, &request.project_root, &git_overlay)?;
        let source_hook = request.project_root.join(".git/hooks/pre-commit");
        if source_hook.is_file() {
            copy_regular_file(&source_hook, &git_overlay.join("hooks/pre-commit"), 0o600)?;
        }
        fs::write(
            source.join("head"),
            expected
                .head_symbolic
                .as_deref()
                .unwrap_or(expected.head_oid.as_str()),
        )
        .map_err(|error| CoreError::Io {
            action: "write Project Capsule current state",
            path: source.join("head"),
            source: error,
        })?;

        let plan = approved_capsule_plan(&source, &BTreeSet::new())?;
        let engine = BundleEngine::local();
        let sealed = engine.pack(PackRequest::new(&plan, &request.git_native_bundle))?;
        let verified = engine.verify(VerifyRequest::new(
            &request.git_native_bundle,
            sealed.offline_recovery_key(),
        ))?;
        remove_disposable_directory(&request.workspace, &source)?;
        let post_capture_hash = observe_project(
            &self.git,
            &request.project_root,
            &request.reviewed_ignored_paths,
        )?
        .digest;
        let capsule_restore = request.workspace.join("git-native-restored-capsule");
        let restore_report = RestoreEngine::local().restore(RestoreRequest::new(
            &request.git_native_bundle,
            &capsule_restore,
            sealed.offline_recovery_key(),
        ))?;
        let restored = request.workspace.join("git-native-restored-project");
        self.reconstruct_git_native(&capsule_restore, &restored, expected)?;
        remove_disposable_directory(&request.workspace, &capsule_restore)?;
        restore_reviewed_executable_modes(
            &request.project_root,
            &restored,
            &request.reviewed_executables,
        )?;
        let validation = validate_project(
            &self.git,
            expected,
            &restored,
            &request.reviewed_ignored_paths,
            &request.reviewed_executables,
        )?;
        Ok(ProjectCapsuleCandidateReport {
            representation: ProjectCapsuleRepresentation::GitNativeArchiveWithOverlay,
            pre_capture_hash,
            post_capture_hash,
            bundle_bytes: file_len(&request.git_native_bundle)?,
            restored_bytes: restore_report
                .restored_bytes()
                .max(verified.authenticated_bytes),
            portability_findings: vec![
                "depends on installed Git bundle compatibility, symbolic-link, and file-mode semantics"
                    .to_owned(),
            ],
            maintenance_findings: vec![
                "reconstructs local references, index-only objects, exact index, worktree overlay, and current state"
                    .to_owned(),
            ],
            construction_must_restart: true,
            validation,
        })
    }

    fn reconstruct_git_native(
        &self,
        capsule: &Path,
        restored: &Path,
        expected: &ProjectObservation,
    ) -> Result<(), CoreError> {
        fs::create_dir(restored).map_err(|source| CoreError::Io {
            action: "create restored Project",
            path: restored.to_path_buf(),
            source,
        })?;
        run_git_required(
            &self.git,
            restored,
            &[OsString::from("init"), OsString::from("-q")],
            "initialize restored Project",
        )?;
        quarantine_hooks(restored)?;
        run_git_required(
            &self.git,
            restored,
            &[
                OsString::from("bundle"),
                OsString::from("unbundle"),
                capsule.join("repository.bundle").into_os_string(),
            ],
            "unbundle restored Project objects",
        )?;
        restore_index_objects(
            &self.git,
            restored,
            &capsule.join("git-overlay/index-objects"),
        )?;
        for (reference, object_identifier) in &expected.references {
            run_git_required(
                &self.git,
                restored,
                &[
                    OsString::from("update-ref"),
                    OsString::from(reference),
                    OsString::from(object_identifier),
                ],
                "restore local Project reference",
            )?;
        }
        match &expected.head_symbolic {
            Some(reference) => run_git_required(
                &self.git,
                restored,
                &[
                    OsString::from("symbolic-ref"),
                    OsString::from("HEAD"),
                    OsString::from(reference),
                ],
                "restore attached Project current state",
            )?,
            None => run_git_required(
                &self.git,
                restored,
                &[
                    OsString::from("update-ref"),
                    OsString::from("--no-deref"),
                    OsString::from("HEAD"),
                    OsString::from(&expected.head_oid),
                ],
                "restore detached Project current state",
            )?,
        }
        copy_tree_contents(&capsule.join("worktree"), restored, 0o600)?;
        copy_regular_file(
            &capsule.join("git-overlay/index"),
            &restored.join(".git/index"),
            0o600,
        )?;
        let hook = capsule.join("git-overlay/hooks/pre-commit");
        if hook.is_file() {
            copy_regular_file(&hook, &restored.join(".git/hooks/pre-commit"), 0o600)?;
        }
        quarantine_hooks(restored)?;
        Ok(())
    }
}

fn validate_capture_request(
    git: &impl GitProcess,
    request: &mut ProjectCapsuleCaptureRequest<'_>,
) -> Result<(), CoreError> {
    request.reviewed_ignored_paths.sort();
    request.reviewed_ignored_paths.dedup();
    request.reviewed_executables.sort();
    request.reviewed_executables.dedup();
    validate_reviewed_paths(
        &request.reviewed_ignored_paths,
        &request.reviewed_executables,
    )?;
    if !request.plan.is_directory_plan()
        || request.plan.approval_state()? != PlanApprovalState::Approved
    {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture requires an approved, non-stale directory Plan".to_owned(),
        ));
    }
    if request.project.kind() != ProjectKind::WorkingTree
        || !request.project.local_audit_verified()
        || request.project.changed_during_audit()
    {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture requires one verified, unchanged working-tree Project audit"
                .to_owned(),
        ));
    }
    let root = request.project.root();
    let current_audit_hash =
        crate::project_audit::observe_local_repository_hash(git, root, request.project.kind())
            .ok_or_else(|| {
                CoreError::InvalidPlan(
                    "Project Capsule capture could not revalidate the Project audit".to_owned(),
                )
            })?;
    if request.project.local_state().observation_hash() != Some(current_audit_hash.as_str()) {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture requires a fresh Project audit".to_owned(),
        ));
    }
    if !request
        .plan
        .approved_roots()
        .iter()
        .any(|approved_root| root.starts_with(approved_root))
    {
        return Err(CoreError::InvalidPlan(
            "Project Capsule audit is not bound to the approved Plan scope".to_owned(),
        ));
    }
    if request.destination.exists() {
        return Err(CoreError::DestinationAlreadyExists(
            request.destination.clone(),
        ));
    }
    if !root.join(".git").is_dir() {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture requires one working-tree Project".to_owned(),
        ));
    }
    if repository_has_active_lock(&root.join(".git")).map_err(|_| {
        CoreError::InvalidPlan(
            "Project Capsule capture could not verify repository lock state".to_owned(),
        )
    })? {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture requires an unlocked repository".to_owned(),
        ));
    }
    if !request.project.submodules().is_empty()
        || request.project.git_large_file_storage().configured()
        || root.join(".git/objects/info/alternates").exists()
        || root.join(".git/worktrees").exists()
    {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture found unsupported repository state".to_owned(),
        ));
    }
    let ignored = ignored_paths(git, root)?;
    if request
        .reviewed_ignored_paths
        .iter()
        .any(|path| !ignored.contains(path))
    {
        return Err(CoreError::InvalidPlan(
            "reviewed ignored Project path is not currently ignored".to_owned(),
        ));
    }
    for executable in &request.reviewed_executables {
        let metadata = fs::symlink_metadata(root.join(executable)).map_err(|_| {
            CoreError::InvalidPlan(
                "reviewed Project executable is unavailable or unsafe".to_owned(),
            )
        })?;
        if !metadata.is_file() || !is_executable(&metadata) {
            return Err(CoreError::InvalidPlan(
                "reviewed Project executable is not an executable regular file".to_owned(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ProjectObservation {
    digest: String,
    head_oid: String,
    head_symbolic: Option<String>,
    references: BTreeMap<String, String>,
    index_digest: String,
    worktree: BTreeMap<PathBuf, ObservedPath>,
    has_remote: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObservedPath {
    Directory,
    Regular { digest: String, executable: bool },
    SymbolicLink { target: PathBuf },
}

fn validate_request(request: &mut ProjectCapsuleComparisonRequest) -> Result<(), CoreError> {
    request.reviewed_ignored_paths.sort();
    request.reviewed_ignored_paths.dedup();
    request.reviewed_executables.sort();
    request.reviewed_executables.dedup();
    validate_reviewed_paths(
        &request.reviewed_ignored_paths,
        &request.reviewed_executables,
    )?;
    if request.workspace.exists()
        || request.git_native_bundle.exists()
        || request.snapshot_bundle.exists()
    {
        return Err(CoreError::DestinationAlreadyExists(
            request.workspace.clone(),
        ));
    }
    let metadata = fs::metadata(&request.project_root).map_err(|source| CoreError::Io {
        action: "inspect Project Capsule source",
        path: request.project_root.clone(),
        source,
    })?;
    if !metadata.is_dir() || !request.project_root.join(".git").is_dir() {
        return Err(CoreError::InvalidPlan(
            "Project Capsule comparison requires one working-tree Project".to_owned(),
        ));
    }
    if repository_has_active_lock(&request.project_root.join(".git")).map_err(|_| {
        CoreError::InvalidPlan(
            "Project Capsule comparison could not verify repository lock state".to_owned(),
        )
    })? {
        return Err(CoreError::InvalidPlan(
            "Project Capsule comparison requires an unlocked repository".to_owned(),
        ));
    }
    Ok(())
}

fn repository_has_active_lock(git_directory: &Path) -> io::Result<bool> {
    let mut pending = vec![git_directory.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if entry.file_name().to_string_lossy().ends_with(".lock") {
                return Ok(true);
            }
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                pending.push(entry.path());
            }
        }
    }
    Ok(false)
}

fn validate_reviewed_paths(
    reviewed_ignored_paths: &[PathBuf],
    reviewed_executables: &[PathBuf],
) -> Result<(), CoreError> {
    for path in reviewed_ignored_paths
        .iter()
        .chain(reviewed_executables.iter())
    {
        if !safe_relative(path) {
            return Err(CoreError::InvalidPlan(
                "Project Capsule reviewed paths must be safe relative paths".to_owned(),
            ));
        }
    }
    if reviewed_executables
        .iter()
        .any(|path| path.starts_with(".git/hooks"))
    {
        return Err(CoreError::InvalidPlan(
            "Git hooks cannot receive executable-mode approval".to_owned(),
        ));
    }
    Ok(())
}

fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn approved_capsule_plan(
    root: &Path,
    excluded_paths: &BTreeSet<PathBuf>,
) -> Result<Plan, CoreError> {
    let mut plan = PlanEngine::local().scan(ScanRequest::for_directory(root))?;
    for item in &mut plan.items {
        if excluded_paths.iter().any(|excluded| {
            item.relative_path == *excluded || item.relative_path.starts_with(excluded)
        }) {
            item.disposition = Disposition::Excluded;
        } else if matches!(
            item.kind,
            MigrationItemKind::Directory
                | MigrationItemKind::RegularFile
                | MigrationItemKind::SymbolicLink
        ) {
            item.disposition = Disposition::Included;
        }
    }
    let approval_hash = plan.approval_hash()?;
    plan.approve(&approval_hash)?;
    debug_assert!(matches!(
        plan.approval_state(),
        Ok(PlanApprovalState::Approved)
    ));
    Ok(plan)
}

fn observe_project(
    git: &impl GitProcess,
    root: &Path,
    reviewed_ignored_paths: &[PathBuf],
) -> Result<ProjectObservation, CoreError> {
    let head_oid = git_text(git, root, &["rev-parse", "HEAD"], "read Project HEAD")?;
    let symbolic = git_optional_text(
        git,
        root,
        &["symbolic-ref", "-q", "HEAD"],
        "read Project current branch",
    )?;
    let references_text = git_text(
        git,
        root,
        &["for-each-ref", "--format=%(refname)%00%(objectname)"],
        "read Project references",
    )?;
    let mut references = BTreeMap::new();
    for line in references_text.lines() {
        if let Some((reference, object_identifier)) = line.split_once('\0') {
            references.insert(reference.to_owned(), object_identifier.to_owned());
        }
    }
    let remotes = git_text(git, root, &["remote"], "read Project remotes")?;
    let index = fs::read(root.join(".git/index")).map_err(|source| CoreError::Io {
        action: "read Project index",
        path: root.join(".git/index"),
        source,
    })?;
    let ignored_paths = ignored_paths(git, root)?;
    let worktree = observe_worktree(root, reviewed_ignored_paths, &ignored_paths)?;
    let mut canonical = Vec::new();
    canonical.extend_from_slice(b"INIZA-PROJECT-OBSERVATION-V1\0");
    append_field(&mut canonical, head_oid.as_bytes());
    append_field(&mut canonical, symbolic.as_deref().unwrap_or("").as_bytes());
    for (reference, object_identifier) in &references {
        append_field(&mut canonical, reference.as_bytes());
        append_field(&mut canonical, object_identifier.as_bytes());
    }
    append_field(&mut canonical, blake3::hash(&index).as_bytes());
    for (path, observed) in &worktree {
        append_field(&mut canonical, path.to_string_lossy().as_bytes());
        match observed {
            ObservedPath::Directory => append_field(&mut canonical, b"directory"),
            ObservedPath::Regular { digest, executable } => {
                append_field(&mut canonical, b"regular");
                append_field(&mut canonical, digest.as_bytes());
                append_field(
                    &mut canonical,
                    if *executable { b"executable" } else { b"plain" },
                );
            }
            ObservedPath::SymbolicLink { target } => {
                append_field(&mut canonical, b"symbolic-link");
                append_field(&mut canonical, target.to_string_lossy().as_bytes());
            }
        }
    }
    append_field(
        &mut canonical,
        if remotes.trim().is_empty() {
            b"no-remote"
        } else {
            b"remote"
        },
    );
    Ok(ProjectObservation {
        digest: blake3::hash(&canonical).to_hex().to_string(),
        head_oid,
        head_symbolic: symbolic,
        references,
        index_digest: blake3::hash(&index).to_hex().to_string(),
        worktree,
        has_remote: !remotes.trim().is_empty(),
    })
}

fn observe_worktree(
    root: &Path,
    reviewed_ignored_paths: &[PathBuf],
    ignored_paths: &BTreeSet<PathBuf>,
) -> Result<BTreeMap<PathBuf, ObservedPath>, CoreError> {
    let mut observed = BTreeMap::new();
    observe_directory(
        root,
        root,
        reviewed_ignored_paths,
        ignored_paths,
        &mut observed,
    )?;
    Ok(observed)
}

fn observe_directory(
    root: &Path,
    directory: &Path,
    reviewed_ignored_paths: &[PathBuf],
    ignored_paths: &BTreeSet<PathBuf>,
    observed: &mut BTreeMap<PathBuf, ObservedPath>,
) -> Result<(), CoreError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| CoreError::Io {
            action: "read Project worktree",
            path: directory.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CoreError::Io {
            action: "read Project worktree entry",
            path: directory.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let absolute = entry.path();
        let relative = absolute.strip_prefix(root).map_err(|_| {
            CoreError::InvalidPlan("Project observation escaped its root".to_owned())
        })?;
        if relative == Path::new(".git") {
            continue;
        }
        let metadata = fs::symlink_metadata(&absolute).map_err(|source| CoreError::Io {
            action: "inspect Project worktree item",
            path: absolute.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            observed.insert(
                relative.to_path_buf(),
                ObservedPath::SymbolicLink {
                    target: fs::read_link(&absolute).map_err(|source| CoreError::Io {
                        action: "read Project symbolic link",
                        path: absolute,
                        source,
                    })?,
                },
            );
        } else if metadata.is_dir() {
            observed.insert(relative.to_path_buf(), ObservedPath::Directory);
            if ignored_paths.contains(relative)
                && !reviewed_ignored_paths.contains(&relative.to_path_buf())
            {
                continue;
            }
            observe_directory(
                root,
                &absolute,
                reviewed_ignored_paths,
                ignored_paths,
                observed,
            )?;
        } else if metadata.is_file() {
            if ignored_paths.contains(relative)
                && !reviewed_ignored_paths.contains(&relative.to_path_buf())
            {
                continue;
            }
            let bytes = fs::read(&absolute).map_err(|source| CoreError::Io {
                action: "read Project worktree item",
                path: absolute.clone(),
                source,
            })?;
            observed.insert(
                relative.to_path_buf(),
                ObservedPath::Regular {
                    digest: blake3::hash(&bytes).to_hex().to_string(),
                    executable: is_executable(&metadata),
                },
            );
        }
    }
    Ok(())
}

fn validate_project(
    git: &impl GitProcess,
    expected: &ProjectObservation,
    restored: &Path,
    reviewed_ignored_paths: &[PathBuf],
    reviewed_executables: &[PathBuf],
) -> Result<ProjectCapsuleValidationReport, CoreError> {
    let fsck_ok = run_git(
        git,
        restored,
        &["fsck", "--full", "--strict", "--no-reflogs"],
    )?
    .status_code
        == Some(0);
    let actual = observe_project(git, restored, reviewed_ignored_paths)?;
    let head_is_attached_to_main = actual.head_symbolic.as_deref() == Some("refs/heads/main");
    let current_state_is_detached = actual.head_symbolic.is_none();
    let has_no_remote = !actual.has_remote;
    let hooks_are_disabled = hooks_disabled(restored)?;
    let reviewed_executables_restored = reviewed_executables.iter().all(|path| {
        fs::symlink_metadata(restored.join(path))
            .map(|metadata| is_executable(&metadata))
            .unwrap_or(false)
    });
    let checks = [
        ("git-structure", fsck_ok),
        ("head-object", expected.head_oid == actual.head_oid),
        ("head-state", expected.head_symbolic == actual.head_symbolic),
        ("local-references", expected.references == actual.references),
        ("index", expected.index_digest == actual.index_digest),
        ("worktree", expected.worktree == actual.worktree),
        ("remote-absence", expected.has_remote == actual.has_remote),
        ("hooks-disabled", hooks_are_disabled),
        ("reviewed-executable-modes", reviewed_executables_restored),
    ];
    let findings = checks
        .iter()
        .filter(|(_, passed)| !passed)
        .map(|(name, _)| (*name).to_owned())
        .collect::<Vec<_>>();
    let faithful = findings.is_empty();
    Ok(ProjectCapsuleValidationReport {
        faithful,
        findings,
        head_is_attached_to_main,
        current_state_is_detached,
        has_no_remote,
        hooks_are_disabled,
        reviewed_executables_restored,
        required_executable_mode_review_hash: None,
        executable_mode_review_pending: false,
        head_object_identifier: actual.head_oid,
        reference_object_identifiers: actual.references,
    })
}

fn executable_mode_review_hash(
    source: &Path,
    bundle: &Path,
    expected: &ProjectObservation,
    reviewed_executables: &[PathBuf],
) -> Result<String, CoreError> {
    let mut bundle_file = fs::File::open(bundle).map_err(|source| CoreError::Io {
        action: "open restored Bundle for executable-mode review",
        path: bundle.to_path_buf(),
        source,
    })?;
    let mut bundle_hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = bundle_file
            .read(&mut buffer)
            .map_err(|source| CoreError::Io {
                action: "hash restored Bundle for executable-mode review",
                path: bundle.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        bundle_hasher.update(&buffer[..read]);
    }
    let mut binding = Vec::new();
    binding.extend_from_slice(b"INIZA-PROJECT-MODE-REVIEW-V1\0");
    append_field(&mut binding, expected.digest.as_bytes());
    append_field(&mut binding, bundle_hasher.finalize().as_bytes());
    for relative in reviewed_executables {
        let metadata =
            fs::symlink_metadata(source.join(relative)).map_err(|error| CoreError::Io {
                action: "inspect executable-mode review source",
                path: source.join(relative),
                source: error,
            })?;
        if !metadata.is_file() {
            return Err(CoreError::InvalidPlan(
                "reviewed executable must identify a regular file".to_owned(),
            ));
        }
        append_field(&mut binding, relative.to_string_lossy().as_bytes());
        #[cfg(unix)]
        append_field(
            &mut binding,
            &(metadata.permissions().mode() & 0o777).to_le_bytes(),
        );
    }
    Ok(blake3::hash(&binding).to_hex().to_string())
}

fn restore_reviewed_executable_modes(
    source: &Path,
    restored: &Path,
    reviewed_executables: &[PathBuf],
) -> Result<(), CoreError> {
    for relative in reviewed_executables {
        if relative.starts_with(".git/hooks") {
            return Err(CoreError::InvalidPlan(
                "Git hooks cannot receive executable-mode approval".to_owned(),
            ));
        }
        let source_metadata =
            fs::symlink_metadata(source.join(relative)).map_err(|error| CoreError::Io {
                action: "inspect reviewed executable source",
                path: source.join(relative),
                source: error,
            })?;
        let destination = restored.join(relative);
        let destination_metadata =
            fs::symlink_metadata(&destination).map_err(|error| CoreError::Io {
                action: "inspect reviewed executable Restore",
                path: destination.clone(),
                source: error,
            })?;
        if !source_metadata.is_file() || !destination_metadata.is_file() {
            return Err(CoreError::InvalidPlan(
                "reviewed executable must identify matching regular files".to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            let reviewed_mode = source_metadata.permissions().mode() & 0o777;
            fs::set_permissions(&destination, fs::Permissions::from_mode(reviewed_mode)).map_err(
                |error| CoreError::Io {
                    action: "restore reviewed executable mode",
                    path: destination,
                    source: error,
                },
            )?;
        }
    }
    Ok(())
}

fn hooks_disabled(root: &Path) -> Result<bool, CoreError> {
    let hooks = root.join(".git/hooks");
    if !hooks.exists() {
        return Ok(true);
    }
    let mut pending = vec![hooks];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|source| CoreError::Io {
            action: "inspect restored Git hooks",
            path: directory.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| CoreError::Io {
                action: "inspect restored Git hook",
                path: directory.clone(),
                source,
            })?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|source| CoreError::Io {
                action: "inspect restored Git hook mode",
                path: entry.path(),
                source,
            })?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() && is_executable(&metadata) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn quarantine_hooks(root: &Path) -> Result<(), CoreError> {
    let hooks = root.join(".git/hooks");
    if !hooks.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&hooks).map_err(|source| CoreError::Io {
        action: "inspect Git hooks for quarantine",
        path: hooks.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| CoreError::Io {
            action: "inspect Git hook for quarantine",
            path: hooks.clone(),
            source,
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|source| CoreError::Io {
            action: "inspect Git hook type for quarantine",
            path: entry.path(),
            source,
        })?;
        if metadata.is_file() {
            #[cfg(unix)]
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600)).map_err(
                |source| CoreError::Io {
                    action: "disable restored Git hook",
                    path: entry.path(),
                    source,
                },
            )?;
        }
    }
    Ok(())
}

fn copy_worktree_overlay(
    source: &Path,
    destination: &Path,
    excluded_paths: &BTreeSet<PathBuf>,
) -> Result<(), CoreError> {
    fs::create_dir(destination).map_err(|error| CoreError::Io {
        action: "create Project worktree overlay",
        path: destination.to_path_buf(),
        source: error,
    })?;
    copy_overlay_directory(source, source, destination, excluded_paths)
}

fn copy_overlay_directory(
    root: &Path,
    source: &Path,
    destination: &Path,
    excluded_paths: &BTreeSet<PathBuf>,
) -> Result<(), CoreError> {
    for entry in sorted_entries(source)? {
        if entry.file_name() == ".git" {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| {
                CoreError::InvalidPlan("Project overlay item escaped its root".to_owned())
            })?
            .to_path_buf();
        if excluded_paths
            .iter()
            .any(|excluded| relative == *excluded || relative.starts_with(excluded))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|source| CoreError::Io {
            action: "inspect Project worktree overlay item",
            path: entry.path(),
            source,
        })?;
        let target = destination.join(entry.file_name());
        if metadata.is_dir() {
            fs::create_dir(&target).map_err(|source| CoreError::Io {
                action: "create Project worktree overlay directory",
                path: target.clone(),
                source,
            })?;
            copy_overlay_directory(root, &entry.path(), &target, excluded_paths)?;
        } else {
            copy_path(&entry.path(), &target, 0o600)?;
        }
    }
    Ok(())
}

fn ignored_paths(git: &impl GitProcess, project: &Path) -> Result<BTreeSet<PathBuf>, CoreError> {
    let output = run_git(
        git,
        project,
        &[
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        ],
    )?;
    if output.status_code != Some(0) {
        return Err(CoreError::InvalidPlan(
            "read ignored Project paths failed".to_owned(),
        ));
    }
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| {
            let text = std::str::from_utf8(record).map_err(|_| {
                CoreError::InvalidPlan(
                    "ignored Project path cannot be represented portably".to_owned(),
                )
            })?;
            let path = PathBuf::from(text);
            if !safe_relative(&path) {
                return Err(CoreError::InvalidPlan(
                    "ignored Project path escaped its root".to_owned(),
                ));
            }
            Ok(path)
        })
        .collect()
}

fn unreviewed_ignored_paths(
    git: &impl GitProcess,
    project: &Path,
    reviewed: &[PathBuf],
) -> Result<BTreeSet<PathBuf>, CoreError> {
    Ok(ignored_paths(git, project)?
        .into_iter()
        .filter(|path| {
            !reviewed
                .iter()
                .any(|approved| path == approved || path.starts_with(approved))
        })
        .collect())
}

fn capture_index_objects(
    git: &impl GitProcess,
    project: &Path,
    git_overlay: &Path,
) -> Result<(), CoreError> {
    let output = run_git(git, project, &["ls-files", "--stage", "-z"])?;
    if output.status_code != Some(0) {
        return Err(CoreError::InvalidPlan(
            "read Project index objects failed".to_owned(),
        ));
    }
    let object_identifiers = output
        .stdout
        .split(|byte| *byte == 0)
        .filter_map(|record| {
            let metadata = record.split(|byte| *byte == b'\t').next()?;
            let mut fields = metadata.split(|byte| *byte == b' ');
            let _mode = fields.next()?;
            let object_identifier = fields.next()?;
            Some(String::from_utf8_lossy(object_identifier).into_owned())
        })
        .collect::<BTreeSet<_>>();
    let destination = git_overlay.join("index-objects");
    fs::create_dir(&destination).map_err(|source| CoreError::Io {
        action: "create Project index object overlay",
        path: destination.clone(),
        source,
    })?;
    for object_identifier in object_identifiers {
        let output = run_git(
            git,
            project,
            &["cat-file", "blob", object_identifier.as_str()],
        )?;
        if output.status_code != Some(0) {
            return Err(CoreError::InvalidPlan(
                "read Project index object failed".to_owned(),
            ));
        }
        fs::write(destination.join(&object_identifier), output.stdout).map_err(|source| {
            CoreError::Io {
                action: "write Project index object overlay",
                path: destination.join(&object_identifier),
                source,
            }
        })?;
    }
    Ok(())
}

fn restore_index_objects(
    git: &impl GitProcess,
    project: &Path,
    source: &Path,
) -> Result<(), CoreError> {
    for entry in sorted_entries(source)? {
        let expected_identifier = entry.file_name().to_string_lossy().into_owned();
        let output = git
            .run(
                project,
                &[
                    OsString::from("hash-object"),
                    OsString::from("-w"),
                    entry.path().into_os_string(),
                ],
            )
            .map_err(|source| CoreError::Io {
                action: "restore Project index object",
                path: project.to_path_buf(),
                source,
            })?;
        if output.status_code != Some(0)
            || String::from_utf8_lossy(&output.stdout).trim() != expected_identifier
        {
            return Err(CoreError::InvalidPlan(
                "restored Project index object did not authenticate".to_owned(),
            ));
        }
    }
    Ok(())
}

fn copy_tree_contents(source: &Path, destination: &Path, file_mode: u32) -> Result<(), CoreError> {
    for entry in sorted_entries(source)? {
        copy_path(
            &entry.path(),
            &destination.join(entry.file_name()),
            file_mode,
        )?;
    }
    Ok(())
}

fn copy_path(source: &Path, destination: &Path, file_mode: u32) -> Result<(), CoreError> {
    let metadata = fs::symlink_metadata(source).map_err(|error| CoreError::Io {
        action: "inspect Project Capsule item",
        path: source.to_path_buf(),
        source: error,
    })?;
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(source).map_err(|error| CoreError::Io {
            action: "read Project Capsule symbolic link",
            path: source.to_path_buf(),
            source: error,
        })?;
        #[cfg(unix)]
        symlink(target, destination).map_err(|error| CoreError::Io {
            action: "create Project Capsule symbolic link",
            path: destination.to_path_buf(),
            source: error,
        })?;
    } else if metadata.is_dir() {
        fs::create_dir(destination).map_err(|error| CoreError::Io {
            action: "create Project Capsule directory",
            path: destination.to_path_buf(),
            source: error,
        })?;
        copy_tree_contents(source, destination, file_mode)?;
    } else if metadata.is_file() {
        copy_regular_file(source, destination, file_mode)?;
    }
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path, mode: u32) -> Result<(), CoreError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| CoreError::Io {
            action: "create Project Capsule file parent",
            path: parent.to_path_buf(),
            source: error,
        })?;
    }
    fs::copy(source, destination).map_err(|error| CoreError::Io {
        action: "copy Project Capsule file",
        path: destination.to_path_buf(),
        source: error,
    })?;
    #[cfg(unix)]
    fs::set_permissions(destination, fs::Permissions::from_mode(mode)).map_err(|error| {
        CoreError::Io {
            action: "quarantine Project Capsule file",
            path: destination.to_path_buf(),
            source: error,
        }
    })?;
    Ok(())
}

fn sorted_entries(directory: &Path) -> Result<Vec<fs::DirEntry>, CoreError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| CoreError::Io {
            action: "read Project Capsule directory",
            path: directory.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, io::Error>>()
        .map_err(|source| CoreError::Io {
            action: "read Project Capsule entry",
            path: directory.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

fn file_len(path: &Path) -> Result<u64, CoreError> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|source| CoreError::Io {
            action: "measure encrypted Project Capsule Bundle",
            path: path.to_path_buf(),
            source,
        })
}

fn remove_disposable_directory(workspace: &Path, target: &Path) -> Result<(), CoreError> {
    if target.parent() != Some(workspace) {
        return Err(CoreError::InvalidPlan(
            "Project Capsule cleanup target escaped its disposable workspace".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(target).map_err(|source| CoreError::Io {
        action: "inspect disposable Project Capsule workspace",
        path: target.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CoreError::InvalidPlan(
            "Project Capsule cleanup target is not its expected directory".to_owned(),
        ));
    }
    fs::remove_dir_all(target).map_err(|source| CoreError::Io {
        action: "remove disposable plaintext Project Capsule workspace",
        path: target.to_path_buf(),
        source,
    })
}

fn git_text(
    git: &impl GitProcess,
    repository: &Path,
    arguments: &[&str],
    action: &'static str,
) -> Result<String, CoreError> {
    let output = run_git(git, repository, arguments)?;
    if output.status_code != Some(0) {
        return Err(CoreError::InvalidPlan(format!("{action} failed")));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim_end_matches('\n').to_owned())
        .map_err(|_| CoreError::InvalidPlan(format!("{action} returned invalid text")))
}

fn git_optional_text(
    git: &impl GitProcess,
    repository: &Path,
    arguments: &[&str],
    action: &'static str,
) -> Result<Option<String>, CoreError> {
    let output = run_git(git, repository, arguments)?;
    match output.status_code {
        Some(0) => String::from_utf8(output.stdout)
            .map(|value| Some(value.trim().to_owned()))
            .map_err(|_| CoreError::InvalidPlan(format!("{action} returned invalid text"))),
        Some(1) => Ok(None),
        _ => Err(CoreError::InvalidPlan(format!("{action} failed"))),
    }
}

fn run_git(
    git: &impl GitProcess,
    repository: &Path,
    arguments: &[&str],
) -> Result<crate::GitProcessOutput, CoreError> {
    let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
    git.run(repository, &arguments)
        .map_err(|source| CoreError::Io {
            action: "run bounded Git Project Capsule operation",
            path: repository.to_path_buf(),
            source,
        })
}

fn run_git_required(
    git: &impl GitProcess,
    repository: &Path,
    arguments: &[OsString],
    action: &'static str,
) -> Result<(), CoreError> {
    let output = git
        .run(repository, arguments)
        .map_err(|source| CoreError::Io {
            action,
            path: repository.to_path_buf(),
            source,
        })?;
    if output.status_code != Some(0) {
        return Err(CoreError::InvalidPlan(format!("{action} failed")));
    }
    Ok(())
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}
