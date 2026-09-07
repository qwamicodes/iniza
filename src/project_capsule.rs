use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::{
    BundleEngine, BundleVerification, CoreError, Disposition, GitProcess, IgnoredCandidate,
    IgnoredReview, InstalledGit, MigrationItemKind, PackReport, PackRequest, Plan,
    PlanApprovalState, PlanEngine, ProjectAudit, ProjectHead, ProjectKind, RecoveryMethod,
    RecoverySecret, RestoreEngine, RestoreRequest, ScanRequest, VerifyRequest,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectCapsuleRetryPolicy {
    total_attempts: u8,
}

impl ProjectCapsuleRetryPolicy {
    pub fn new(total_attempts: u8) -> Result<Self, CoreError> {
        if !(1..=3).contains(&total_attempts) {
            return Err(CoreError::InvalidPlan(
                "Project Capsule capture allows one to three total attempts".to_owned(),
            ));
        }
        Ok(Self { total_attempts })
    }
}

impl Default for ProjectCapsuleRetryPolicy {
    fn default() -> Self {
        Self { total_attempts: 1 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectCapsuleSupportedState {
    AttachedCurrentState,
    DetachedCurrentState,
    Stashes,
    LocalOnlyBranches,
    LocalOnlyTags,
    StagedChanges,
    UnstagedChanges,
    UntrackedItems,
    RepositoryWithoutRemote,
    LocallyCompleteGitLargeFileStorage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectCapsuleBlockingFeature {
    Submodules,
    BareRepository,
    LinkedWorktree,
    ObjectAlternates,
    SparseCheckout,
    PartialClone,
    PromisorObjects,
    ActiveGitLocks,
    NonportableFilesystemNames,
    IncompleteGitLargeFileStorage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCapsuleSupportReport {
    supported_states: BTreeSet<ProjectCapsuleSupportedState>,
    blocking_features: BTreeSet<ProjectCapsuleBlockingFeature>,
    git_large_file_storage_objects: Vec<ProjectCapsuleGitLargeFileStorageEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProjectCapsuleGitLargeFileStorageEvidence {
    object_identifier: String,
    size: u64,
}

impl ProjectCapsuleSupportReport {
    pub fn supports(&self, state: ProjectCapsuleSupportedState) -> bool {
        self.supported_states.contains(&state)
    }

    pub fn blocking_features(&self) -> &BTreeSet<ProjectCapsuleBlockingFeature> {
        &self.blocking_features
    }

    pub fn blocks(&self, feature: ProjectCapsuleBlockingFeature) -> bool {
        self.blocking_features.contains(&feature)
    }

    pub fn is_supported_for_capture(&self) -> bool {
        self.blocking_features.is_empty()
    }

    pub fn human_result(&self) -> String {
        format!(
            "Project Capsule support\n  state: {}\n  supported states: {}\n  blocking features: {}\n  local Git Large File Storage objects: {}",
            if self.is_supported_for_capture() {
                "Supported for capture"
            } else {
                "Blocked and Unverified"
            },
            self.supported_states.len(),
            self.blocking_features.len(),
            self.git_large_file_storage_objects.len(),
        )
    }

    pub fn machine_json_result(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "command": "project capsule support",
            "status": if self.is_supported_for_capture() { "supported" } else { "blocked" },
            "data": {
                "supported_for_capture": self.is_supported_for_capture(),
                "supported_states": self.supported_states.iter().map(|state| project_capsule_supported_state_name(*state)).collect::<Vec<_>>(),
                "blocking_features": self.blocking_features.iter().map(|feature| project_capsule_blocking_feature_name(*feature)).collect::<Vec<_>>(),
                "git_large_file_storage_object_count": self.git_large_file_storage_objects.len(),
                "restorable": "not-rehearsed",
                "synchronized": "not-evaluated",
            },
            "warnings": [],
            "errors": [],
        })
        .to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectCapsuleIgnoredRecommendation {
    RequiresExplicitDecision,
    ExcludeReproducibleGeneratedState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectCapsuleReviewDecisionKind {
    IncludeAsEncryptedReviewedState,
    ExcludeAsReproducibleGeneratedState,
    ReplaceLiveDatabaseWithExport,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProjectDatabaseExportReview {
    project_id: String,
    plan_hash: String,
    base_review_hash: String,
    database_candidate_id: String,
    export_item_id: String,
    export_relative_path: PathBuf,
    export_digest: String,
    export_size: u64,
    validation_description: String,
}

impl fmt::Debug for ProjectDatabaseExportReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectDatabaseExportReview")
            .field("project_id", &self.project_id)
            .field("plan_hash", &self.plan_hash)
            .field("base_review_hash", &self.base_review_hash)
            .field("database_candidate_id", &self.database_candidate_id)
            .field("export_item_id", &self.export_item_id)
            .field("export_digest", &self.export_digest)
            .field("export_size", &self.export_size)
            .field("validation", &"stable-export-bytes-only")
            .finish()
    }
}

pub struct ProjectDatabaseExportReviewRequest<'a> {
    plan: &'a Plan,
    project: &'a ProjectAudit,
    initial_review: &'a ProjectCapsuleReview,
    reviewed_hash: String,
    database_candidate_id: String,
    export_item_id: String,
    validation_description: String,
}

impl<'a> ProjectDatabaseExportReviewRequest<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan: &'a Plan,
        project: &'a ProjectAudit,
        initial_review: &'a ProjectCapsuleReview,
        reviewed_hash: impl Into<String>,
        database_candidate_id: impl Into<String>,
        export_item_id: impl Into<String>,
        validation_description: impl Into<String>,
    ) -> Self {
        Self {
            plan,
            project,
            initial_review,
            reviewed_hash: reviewed_hash.into(),
            database_candidate_id: database_candidate_id.into(),
            export_item_id: export_item_id.into(),
            validation_description: validation_description.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCapsuleReviewDecision {
    candidate_id: String,
    kind: ProjectCapsuleReviewDecisionKind,
    owner_reason: Option<String>,
    database_export_review: Option<ProjectDatabaseExportReview>,
}

impl ProjectCapsuleReviewDecision {
    pub fn include_as_encrypted_reviewed_state(candidate_id: impl Into<String>) -> Self {
        Self {
            candidate_id: candidate_id.into(),
            kind: ProjectCapsuleReviewDecisionKind::IncludeAsEncryptedReviewedState,
            owner_reason: None,
            database_export_review: None,
        }
    }

    pub fn exclude_as_reproducible_generated_state(
        candidate_id: impl Into<String>,
        owner_reason: impl Into<String>,
    ) -> Self {
        Self {
            candidate_id: candidate_id.into(),
            kind: ProjectCapsuleReviewDecisionKind::ExcludeAsReproducibleGeneratedState,
            owner_reason: Some(owner_reason.into()),
            database_export_review: None,
        }
    }

    pub fn replace_live_database_with_export(review: ProjectDatabaseExportReview) -> Self {
        Self {
            candidate_id: review.database_candidate_id.clone(),
            kind: ProjectCapsuleReviewDecisionKind::ReplaceLiveDatabaseWithExport,
            owner_reason: None,
            database_export_review: Some(review),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCapsuleIgnoredReview {
    candidate_id: String,
    relative_path: PathBuf,
    recommendation: ProjectCapsuleIgnoredRecommendation,
    decision: Option<ProjectCapsuleReviewDecisionKind>,
    owner_reason: Option<String>,
    database_export_review: Option<ProjectDatabaseExportReview>,
}

impl ProjectCapsuleIgnoredReview {
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    pub fn recommendation(&self) -> ProjectCapsuleIgnoredRecommendation {
        self.recommendation
    }

    pub fn decision(&self) -> Option<ProjectCapsuleReviewDecisionKind> {
        self.decision
    }

    pub fn owner_reason(&self) -> Option<&str> {
        self.owner_reason.as_deref()
    }
}

pub struct ProjectCapsuleReviewRequest<'a> {
    plan: &'a Plan,
    project: &'a ProjectAudit,
    decisions: Vec<ProjectCapsuleReviewDecision>,
}

impl<'a> ProjectCapsuleReviewRequest<'a> {
    pub fn new(plan: &'a Plan, project: &'a ProjectAudit) -> Self {
        Self {
            plan,
            project,
            decisions: Vec::new(),
        }
    }

    pub fn with_decision(mut self, decision: ProjectCapsuleReviewDecision) -> Self {
        self.decisions.push(decision);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCapsuleReview {
    plan_hash: String,
    project_id: String,
    project_observation_hash: String,
    support_report: ProjectCapsuleSupportReport,
    ignored_candidates: Vec<ProjectCapsuleIgnoredReview>,
    review_hash: String,
}

impl ProjectCapsuleReview {
    pub fn support_report(&self) -> &ProjectCapsuleSupportReport {
        &self.support_report
    }

    pub fn ignored_candidates(&self) -> &[ProjectCapsuleIgnoredReview] {
        &self.ignored_candidates
    }

    pub fn ignored_candidate(&self, candidate_id: &str) -> Option<&ProjectCapsuleIgnoredReview> {
        self.ignored_candidates
            .iter()
            .find(|candidate| candidate.candidate_id == candidate_id)
    }

    pub fn review_hash(&self) -> &str {
        &self.review_hash
    }

    pub fn is_complete(&self) -> bool {
        self.support_report.is_supported_for_capture()
            && self
                .ignored_candidates
                .iter()
                .all(|candidate| candidate.decision.is_some())
    }

    pub fn human_result(&self) -> String {
        let decided = self
            .ignored_candidates
            .iter()
            .filter(|candidate| candidate.decision.is_some())
            .count();
        format!(
            "Project Capsule review\n  state: {}\n  Project: {}\n  review hash: {}\n  ignored decisions: {}/{}\n  blocking features: {}\n  next action: {}",
            if self.is_complete() {
                "Complete for capture"
            } else {
                "Blocked and Unverified"
            },
            self.project_id,
            self.review_hash,
            decided,
            self.ignored_candidates.len(),
            self.support_report.blocking_features.len(),
            if self.is_complete() {
                "capture with this exact review hash"
            } else {
                "resolve every decision and blocking feature, then review again"
            },
        )
    }

    pub fn machine_json_result(&self) -> String {
        let decided = self
            .ignored_candidates
            .iter()
            .filter(|candidate| candidate.decision.is_some())
            .count();
        serde_json::json!({
            "schema_version": 1,
            "command": "project capsule review",
            "status": if self.is_complete() { "complete" } else { "blocked" },
            "data": {
                "project_id": self.project_id,
                "plan_hash": self.plan_hash,
                "review_hash": self.review_hash,
                "supported_for_capture": self.support_report.is_supported_for_capture(),
                "supported_state_count": self.support_report.supported_states.len(),
                "blocking_feature_count": self.support_report.blocking_features.len(),
                "ignored_candidate_count": self.ignored_candidates.len(),
                "decided_ignored_candidate_count": decided,
                "database_export_evidence": database_export_evidence_count(self),
                "restorable": "not-rehearsed",
                "synchronized": "not-evaluated",
            },
            "warnings": [],
            "errors": [],
        })
        .to_string()
    }
}

pub struct ProjectCapsuleCaptureRequest<'a> {
    plan: &'a Plan,
    project: &'a ProjectAudit,
    review: &'a ProjectCapsuleReview,
    review_hash: String,
    destination: PathBuf,
    reviewed_executables: Vec<PathBuf>,
    retry_policy: ProjectCapsuleRetryPolicy,
}

impl<'a> ProjectCapsuleCaptureRequest<'a> {
    pub fn new(
        plan: &'a Plan,
        project: &'a ProjectAudit,
        review: &'a ProjectCapsuleReview,
        review_hash: impl Into<String>,
        destination: impl Into<PathBuf>,
    ) -> Self {
        Self {
            plan,
            project,
            review,
            review_hash: review_hash.into(),
            destination: destination.into(),
            reviewed_executables: Vec::new(),
            retry_policy: ProjectCapsuleRetryPolicy::default(),
        }
    }

    pub fn with_reviewed_executable(mut self, path: impl Into<PathBuf>) -> Self {
        self.reviewed_executables.push(path.into());
        self
    }

    pub fn with_retry_policy(mut self, retry_policy: ProjectCapsuleRetryPolicy) -> Self {
        self.retry_policy = retry_policy;
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
    expectation: Option<ProjectCapsuleExpectation>,
    attempts: u8,
    retained_changed_attempts: u8,
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
            .field("attempts", &self.attempts)
            .field("retained_changed_attempts", &self.retained_changed_attempts)
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

    pub fn expectation(&self) -> Option<&ProjectCapsuleExpectation> {
        self.expectation.as_ref()
    }

    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    pub fn retained_changed_attempts(&self) -> u8 {
        self.retained_changed_attempts
    }

    pub fn human_result(&self) -> String {
        format!(
            "Project Capsule capture\n  state: {}\n  representation: full-repository-snapshot\n  attempts: {}\n  retained changed attempts: {}\n  encrypted Bundle: {} bytes\n  authenticated Project: {} bytes\n  next action: {}",
            match self.state {
                ProjectCapsuleCaptureState::Verified => "Verified",
                ProjectCapsuleCaptureState::ChangedAndUnverified => "Changed and Unverified",
            },
            self.attempts,
            self.retained_changed_attempts,
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
                "attempts": self.attempts,
                "retained_changed_attempts": self.retained_changed_attempts,
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

#[derive(Clone)]
pub struct ProjectCapsuleExpectation {
    project_id: String,
    plan_hash: String,
    review_hash: String,
    bundle_identity: String,
    captured_unix_seconds: u64,
    observation: ProjectObservation,
    reviewed_ignored_paths: Vec<PathBuf>,
    reviewed_executable_modes: BTreeMap<PathBuf, u32>,
    required_executable_mode_review_hash: Option<String>,
    git_large_file_storage_objects: Vec<ProjectCapsuleGitLargeFileStorageEvidence>,
    database_export_evidence: usize,
}

impl fmt::Debug for ProjectCapsuleExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectCapsuleExpectation")
            .field("project_id", &self.project_id)
            .field("plan_hash", &self.plan_hash)
            .field("review_hash", &self.review_hash)
            .field("bundle_identity", &self.bundle_identity)
            .field("captured_unix_seconds", &self.captured_unix_seconds)
            .field("reviewed_ignored_count", &self.reviewed_ignored_paths.len())
            .field(
                "reviewed_executable_count",
                &self.reviewed_executable_modes.len(),
            )
            .field(
                "git_large_file_storage_object_count",
                &self.git_large_file_storage_objects.len(),
            )
            .field("database_export_evidence", &self.database_export_evidence)
            .finish()
    }
}

impl ProjectCapsuleExpectation {
    pub fn required_executable_mode_review_hash(&self) -> Option<&str> {
        self.required_executable_mode_review_hash.as_deref()
    }
}

pub struct ProjectCapsuleRehearsalRequest<'a> {
    bundle: PathBuf,
    expectation: &'a ProjectCapsuleExpectation,
    recovery_secret: &'a RecoverySecret,
    destination: PathBuf,
    executable_mode_review_hash: Option<String>,
}

impl<'a> ProjectCapsuleRehearsalRequest<'a> {
    pub fn new(
        bundle: impl Into<PathBuf>,
        expectation: &'a ProjectCapsuleExpectation,
        recovery_secret: &'a RecoverySecret,
        destination: impl Into<PathBuf>,
    ) -> Self {
        Self {
            bundle: bundle.into(),
            expectation,
            recovery_secret,
            destination: destination.into(),
            executable_mode_review_hash: None,
        }
    }

    pub fn with_executable_mode_review_hash(mut self, hash: impl Into<String>) -> Self {
        self.executable_mode_review_hash = Some(hash.into());
        self
    }
}

pub struct ProjectCapsuleRehearsalReceipt {
    restorable: bool,
    recovery_method: RecoveryMethod,
    project_id: String,
    bundle_identity: String,
    database_export_evidence: usize,
    validation: ProjectCapsuleValidationReport,
}

impl fmt::Debug for ProjectCapsuleRehearsalReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectCapsuleRehearsalReceipt")
            .field("restorable", &self.restorable)
            .field("recovery_method", &self.recovery_method)
            .field("project_id", &self.project_id)
            .field("bundle_identity", &self.bundle_identity)
            .field("database_export_evidence", &self.database_export_evidence)
            .field("database_consistency_automatically_verified", &false)
            .field("findings", &self.validation.findings())
            .finish()
    }
}

impl ProjectCapsuleRehearsalReceipt {
    pub fn is_restorable(&self) -> bool {
        self.restorable
    }

    pub fn recovery_method(&self) -> RecoveryMethod {
        self.recovery_method
    }

    pub fn validation(&self) -> &ProjectCapsuleValidationReport {
        &self.validation
    }

    pub fn database_export_evidence(&self) -> usize {
        self.database_export_evidence
    }

    pub fn database_consistency_was_automatically_verified(&self) -> bool {
        false
    }

    pub fn human_result(&self) -> String {
        format!(
            "Project Capsule Restore Rehearsal\n  state: {}\n  Recovery Method: {}\n  Project: {}\n  validation findings: {}\n  database export evidence: {}\n  database consistency: not automatically verified\n  Synchronized: not evaluated",
            if self.restorable {
                "Restorable"
            } else {
                "Unverified"
            },
            match self.recovery_method {
                RecoveryMethod::Vaultwarden => "Vaultwarden Recovery Secret",
                RecoveryMethod::Offline => "Offline Recovery Key",
            },
            self.project_id,
            self.validation.findings().len(),
            self.database_export_evidence,
        )
    }

    pub fn machine_json_result(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "command": "project capsule rehearse",
            "status": if self.restorable { "restorable" } else { "unverified" },
            "data": {
                "project_id": self.project_id,
                "bundle_identity": self.bundle_identity,
                "recovery_method": match self.recovery_method {
                    RecoveryMethod::Vaultwarden => "vaultwarden",
                    RecoveryMethod::Offline => "offline",
                },
                "restorable": self.restorable,
                "synchronized": "not-evaluated",
                "database_export_evidence": self.database_export_evidence,
                "database_consistency_automatically_verified": false,
                "validation_findings": self.validation.findings(),
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

fn project_capsule_supported_state_name(state: ProjectCapsuleSupportedState) -> &'static str {
    match state {
        ProjectCapsuleSupportedState::AttachedCurrentState => "attached-current-state",
        ProjectCapsuleSupportedState::DetachedCurrentState => "detached-current-state",
        ProjectCapsuleSupportedState::Stashes => "stashes",
        ProjectCapsuleSupportedState::LocalOnlyBranches => "local-only-branches",
        ProjectCapsuleSupportedState::LocalOnlyTags => "local-only-tags",
        ProjectCapsuleSupportedState::StagedChanges => "staged-changes",
        ProjectCapsuleSupportedState::UnstagedChanges => "unstaged-changes",
        ProjectCapsuleSupportedState::UntrackedItems => "untracked-items",
        ProjectCapsuleSupportedState::RepositoryWithoutRemote => "repository-without-remote",
        ProjectCapsuleSupportedState::LocallyCompleteGitLargeFileStorage => {
            "locally-complete-git-large-file-storage"
        }
    }
}

fn project_capsule_blocking_feature_name(feature: ProjectCapsuleBlockingFeature) -> &'static str {
    match feature {
        ProjectCapsuleBlockingFeature::Submodules => "submodules",
        ProjectCapsuleBlockingFeature::BareRepository => "bare-repository",
        ProjectCapsuleBlockingFeature::LinkedWorktree => "linked-worktree",
        ProjectCapsuleBlockingFeature::ObjectAlternates => "object-alternates",
        ProjectCapsuleBlockingFeature::SparseCheckout => "sparse-checkout",
        ProjectCapsuleBlockingFeature::PartialClone => "partial-clone",
        ProjectCapsuleBlockingFeature::PromisorObjects => "promisor-objects",
        ProjectCapsuleBlockingFeature::ActiveGitLocks => "active-git-locks",
        ProjectCapsuleBlockingFeature::NonportableFilesystemNames => "nonportable-filesystem-names",
        ProjectCapsuleBlockingFeature::IncompleteGitLargeFileStorage => {
            "incomplete-git-large-file-storage"
        }
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
    pub fn review_database_export(
        &self,
        request: ProjectDatabaseExportReviewRequest<'_>,
    ) -> Result<ProjectDatabaseExportReview, CoreError> {
        validate_review_request(
            &self.git,
            &ProjectCapsuleReviewRequest::new(request.plan, request.project),
        )?;
        if request.reviewed_hash != request.initial_review.review_hash
            || request.initial_review.plan_hash != request.plan.approval_hash()?
            || request.initial_review.project_id != request.project.id()
            || request.initial_review.project_observation_hash
                != request
                    .project
                    .local_state()
                    .observation_hash()
                    .unwrap_or_default()
        {
            return Err(CoreError::InvalidPlan(
                "database export review does not match the initial Project Capsule review"
                    .to_owned(),
            ));
        }
        let database_candidate = complete_ignored_candidates(request.project)?
            .iter()
            .find(|candidate| candidate.id() == request.database_candidate_id)
            .ok_or_else(|| {
                CoreError::InvalidPlan(
                    "database export review does not identify an ignored database candidate"
                        .to_owned(),
                )
            })?;
        if !is_live_database_path(database_candidate.relative_path()) {
            return Err(CoreError::InvalidPlan(
                "database export review requires an ignored live database candidate".to_owned(),
            ));
        }
        let export_item = request
            .plan
            .items()
            .iter()
            .find(|item| item.id == request.export_item_id)
            .ok_or_else(|| {
                CoreError::InvalidPlan(
                    "database export review does not identify a selected Migration Item".to_owned(),
                )
            })?;
        if export_item.kind != MigrationItemKind::RegularFile
            || export_item.disposition != Disposition::Included
            || export_item.relative_path == database_candidate.relative_path()
        {
            return Err(CoreError::InvalidPlan(
                "database export must be a distinct Included regular-file Migration Item"
                    .to_owned(),
            ));
        }
        if request.validation_description.trim().is_empty() {
            return Err(CoreError::InvalidPlan(
                "database export review requires an owner-visible validation description"
                    .to_owned(),
            ));
        }
        let export = request.project.root().join(&export_item.relative_path);
        let first = observe_database_export(&export)?;
        let second = observe_database_export(&export)?;
        if first != second {
            return Err(CoreError::InvalidPlan(
                "database export changed between its two stable-file observations".to_owned(),
            ));
        }
        Ok(ProjectDatabaseExportReview {
            project_id: request.project.id().to_owned(),
            plan_hash: request.plan.approval_hash()?,
            base_review_hash: request.reviewed_hash,
            database_candidate_id: request.database_candidate_id,
            export_item_id: request.export_item_id,
            export_relative_path: export_item.relative_path.clone(),
            export_digest: first.digest,
            export_size: first.size,
            validation_description: request.validation_description,
        })
    }

    pub fn review(
        &self,
        request: ProjectCapsuleReviewRequest<'_>,
    ) -> Result<ProjectCapsuleReview, CoreError> {
        validate_review_request(&self.git, &request)?;
        let local_state = request.project.local_state();
        let mut supported_states = BTreeSet::new();
        if matches!(local_state.head(), ProjectHead::Branch(_)) {
            supported_states.insert(ProjectCapsuleSupportedState::AttachedCurrentState);
        }
        if matches!(local_state.head(), ProjectHead::Detached(_)) {
            supported_states.insert(ProjectCapsuleSupportedState::DetachedCurrentState);
        }
        if local_state.stash_count() > 0 {
            supported_states.insert(ProjectCapsuleSupportedState::Stashes);
        }
        if !local_state.local_only_branches().is_empty() {
            supported_states.insert(ProjectCapsuleSupportedState::LocalOnlyBranches);
        }
        if !local_state.local_only_tags().is_empty() {
            supported_states.insert(ProjectCapsuleSupportedState::LocalOnlyTags);
        }
        if local_state.staged_changes() > 0 {
            supported_states.insert(ProjectCapsuleSupportedState::StagedChanges);
        }
        if local_state.unstaged_changes() > 0 {
            supported_states.insert(ProjectCapsuleSupportedState::UnstagedChanges);
        }
        if local_state.untracked_items() > 0 {
            supported_states.insert(ProjectCapsuleSupportedState::UntrackedItems);
        }
        if request.project.remotes().is_empty() {
            supported_states.insert(ProjectCapsuleSupportedState::RepositoryWithoutRemote);
        }
        let mut blocking_features = BTreeSet::new();
        let mut git_large_file_storage_objects = Vec::new();
        match request.project.kind() {
            ProjectKind::WorkingTree => {}
            ProjectKind::BareRepository => {
                blocking_features.insert(ProjectCapsuleBlockingFeature::BareRepository);
            }
            ProjectKind::Submodule => {
                blocking_features.insert(ProjectCapsuleBlockingFeature::LinkedWorktree);
            }
        }
        if request.project.kind() == ProjectKind::WorkingTree {
            blocking_features.extend(working_tree_blocking_features(
                &self.git,
                request.project.root(),
            )?);
        }
        if !request.project.submodules().is_empty() {
            blocking_features.insert(ProjectCapsuleBlockingFeature::Submodules);
        }
        if request.project.git_large_file_storage().configured() {
            match local_git_large_file_storage_evidence(request.project.root())? {
                Some(objects) => {
                    git_large_file_storage_objects = objects;
                    supported_states
                        .insert(ProjectCapsuleSupportedState::LocallyCompleteGitLargeFileStorage);
                }
                None => {
                    blocking_features
                        .insert(ProjectCapsuleBlockingFeature::IncompleteGitLargeFileStorage);
                }
            }
        }
        let support_report = ProjectCapsuleSupportReport {
            supported_states,
            blocking_features,
            git_large_file_storage_objects,
        };
        let mut decisions = BTreeMap::new();
        for decision in request.decisions {
            if decisions
                .insert(
                    decision.candidate_id,
                    (
                        decision.kind,
                        decision.owner_reason,
                        decision.database_export_review,
                    ),
                )
                .is_some()
            {
                return Err(CoreError::InvalidPlan(
                    "Project Capsule review contains a duplicate ignored-state decision".to_owned(),
                ));
            }
        }
        let mut ignored_candidates = complete_ignored_candidates(request.project)?
            .iter()
            .map(|candidate| {
                let recommendation = match candidate.review() {
                    IgnoredReview::RequiresReview => {
                        ProjectCapsuleIgnoredRecommendation::RequiresExplicitDecision
                    }
                    IgnoredReview::SuggestedExclusion => {
                        ProjectCapsuleIgnoredRecommendation::ExcludeReproducibleGeneratedState
                    }
                };
                let decision = decisions.remove(candidate.id());
                if let Some((kind, owner_reason, _)) = &decision
                    && (*kind
                        == ProjectCapsuleReviewDecisionKind::ExcludeAsReproducibleGeneratedState
                        && (recommendation
                            != ProjectCapsuleIgnoredRecommendation::ExcludeReproducibleGeneratedState
                            || owner_reason
                                .as_deref()
                                .map(str::trim)
                                .unwrap_or_default()
                                .is_empty()))
                {
                    return Err(CoreError::InvalidPlan(
                        "Project Capsule generated-state exclusion requires an audited reproducible candidate and owner-visible reason"
                            .to_owned(),
                    ));
                }
                if let Some((kind, _, database_export_review)) = &decision
                    && *kind == ProjectCapsuleReviewDecisionKind::ReplaceLiveDatabaseWithExport
                {
                    let export_review = database_export_review.as_ref().ok_or_else(|| {
                        CoreError::InvalidPlan(
                            "Project Capsule database replacement requires stable export evidence"
                                .to_owned(),
                        )
                    })?;
                    validate_database_export_binding(
                        request.plan,
                        request.project,
                        candidate.id(),
                        candidate.relative_path(),
                        export_review,
                    )?;
                }
                Ok(ProjectCapsuleIgnoredReview {
                    candidate_id: candidate.id().to_owned(),
                    relative_path: candidate.relative_path().to_path_buf(),
                    recommendation,
                    decision: decision.as_ref().map(|(kind, _, _)| *kind),
                    owner_reason: decision.as_ref().and_then(|(_, reason, _)| reason.clone()),
                    database_export_review: decision.and_then(|(_, _, review)| review),
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        if !decisions.is_empty() {
            return Err(CoreError::InvalidPlan(
                "Project Capsule review decision does not identify an audited ignored candidate"
                    .to_owned(),
            ));
        }
        ignored_candidates.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
        let review_hash = project_capsule_review_hash(
            request.plan,
            request.project,
            &support_report,
            &ignored_candidates,
        )?;
        let plan_hash = request.plan.approval_hash()?;
        let project_observation_hash = request
            .project
            .local_state()
            .observation_hash()
            .unwrap_or_default()
            .to_owned();
        Ok(ProjectCapsuleReview {
            plan_hash,
            project_id: request.project.id().to_owned(),
            project_observation_hash,
            support_report,
            ignored_candidates,
            review_hash,
        })
    }

    pub fn capture(
        &self,
        mut request: ProjectCapsuleCaptureRequest<'_>,
    ) -> Result<ProjectCapsuleCaptureReport, CoreError> {
        validate_capture_request(&self.git, &mut request)?;
        let root = request.project.root();
        let reviewed_ignored_paths = included_reviewed_ignored_paths(request.review);
        let excluded_ignored = unreviewed_ignored_paths(&self.git, root, &reviewed_ignored_paths)?;
        let capsule_plan = approved_capsule_plan(root, &excluded_ignored)?;
        let engine = BundleEngine::local();
        let mut recovery_owner = None::<PackReport>;
        let mut retained_changed_attempts = 0_u8;
        for attempt in 1..=request.retry_policy.total_attempts {
            let attempt_path = project_capsule_attempt_path(&request.destination, attempt)?;
            let retained_path = retained_project_capsule_attempt_path(&attempt_path);
            if attempt_path.exists() || retained_path.exists() {
                return Err(CoreError::DestinationAlreadyExists(
                    if attempt_path.exists() {
                        attempt_path
                    } else {
                        retained_path
                    },
                ));
            }
            let expected = observe_project(&self.git, root, &reviewed_ignored_paths)?;
            let pack = if let Some(owner) = recovery_owner.as_ref() {
                engine.pack(
                    PackRequest::new(&capsule_plan, &attempt_path)
                        .with_recovery_context(owner.recovery_context()),
                )?
            } else {
                engine.pack(PackRequest::new(&capsule_plan, &attempt_path))?
            };
            let verification = engine.verify(VerifyRequest::new(
                &attempt_path,
                pack.offline_recovery_key(),
            ))?;
            let bundle_bytes = file_len(&attempt_path)?;
            let post_capture_hash =
                observe_project(&self.git, root, &reviewed_ignored_paths)?.digest;
            if expected.digest == post_capture_hash {
                publish_project_capsule_attempt(&attempt_path, &request.destination)?;
                let reviewed_executable_modes = reviewed_executable_modes(
                    request.project.root(),
                    &request.reviewed_executables,
                )?;
                let required_executable_mode_review_hash = executable_expectation_review_hash(
                    request.project.id(),
                    &request.review_hash,
                    verification.bundle_identity(),
                    &expected,
                    &reviewed_executable_modes,
                );
                let expectation = ProjectCapsuleExpectation {
                    project_id: request.project.id().to_owned(),
                    plan_hash: request.plan.approval_hash()?,
                    review_hash: request.review_hash.clone(),
                    bundle_identity: verification.bundle_identity().to_owned(),
                    captured_unix_seconds: project_capsule_unix_time_now()?,
                    observation: expected.clone(),
                    reviewed_ignored_paths: reviewed_ignored_paths.clone(),
                    reviewed_executable_modes,
                    required_executable_mode_review_hash,
                    git_large_file_storage_objects: request
                        .review
                        .support_report
                        .git_large_file_storage_objects
                        .clone(),
                    database_export_evidence: database_export_evidence_count(request.review),
                };
                return Ok(ProjectCapsuleCaptureReport {
                    state: ProjectCapsuleCaptureState::Verified,
                    pre_capture_hash: expected.digest,
                    post_capture_hash,
                    bundle_bytes,
                    verification,
                    pack,
                    expectation: Some(expectation),
                    attempts: attempt,
                    retained_changed_attempts,
                });
            }
            retain_changed_project_capsule_attempt(&attempt_path, &retained_path)?;
            retained_changed_attempts = retained_changed_attempts.saturating_add(1);
            if attempt == request.retry_policy.total_attempts {
                return Ok(ProjectCapsuleCaptureReport {
                    state: ProjectCapsuleCaptureState::ChangedAndUnverified,
                    pre_capture_hash: expected.digest,
                    post_capture_hash,
                    bundle_bytes,
                    verification,
                    pack,
                    expectation: None,
                    attempts: attempt,
                    retained_changed_attempts,
                });
            }
            if recovery_owner.is_none() {
                recovery_owner = Some(pack);
            }
        }
        unreachable!("Project Capsule retry policy always permits at least one attempt")
    }

    pub fn rehearse(
        &self,
        request: ProjectCapsuleRehearsalRequest<'_>,
    ) -> Result<ProjectCapsuleRehearsalReceipt, CoreError> {
        let verification = BundleEngine::local()
            .verify(VerifyRequest::new(&request.bundle, request.recovery_secret))?;
        if verification.bundle_identity() != request.expectation.bundle_identity {
            return Err(CoreError::InvalidPlan(
                "Project Capsule expectation does not belong to the selected Bundle".to_owned(),
            ));
        }
        RestoreEngine::local().restore(RestoreRequest::new(
            &request.bundle,
            &request.destination,
            request.recovery_secret,
        ))?;
        let executable_mode_approved = request
            .expectation
            .required_executable_mode_review_hash
            .as_deref()
            .is_none_or(|required| {
                request.executable_mode_review_hash.as_deref() == Some(required)
            });
        if executable_mode_approved {
            restore_expected_executable_modes(
                &request.destination,
                &request.expectation.reviewed_executable_modes,
            )?;
        }
        let reviewed_executables = request
            .expectation
            .reviewed_executable_modes
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut validation = validate_project(
            &self.git,
            &request.expectation.observation,
            &request.destination,
            &request.expectation.reviewed_ignored_paths,
            &reviewed_executables,
        )?;
        validation.required_executable_mode_review_hash = request
            .expectation
            .required_executable_mode_review_hash
            .clone();
        validation.executable_mode_review_pending = !executable_mode_approved;
        if !executable_mode_approved
            && !validation
                .findings
                .iter()
                .any(|finding| finding == "executable-mode-review")
        {
            validation
                .findings
                .push("executable-mode-review".to_owned());
            validation.faithful = false;
        }
        if !request
            .expectation
            .git_large_file_storage_objects
            .is_empty()
            && local_git_large_file_storage_evidence(&request.destination)?
                != Some(request.expectation.git_large_file_storage_objects.clone())
        {
            validation
                .findings
                .push("git-large-file-storage-evidence".to_owned());
            validation.faithful = false;
        }
        Ok(ProjectCapsuleRehearsalReceipt {
            restorable: validation.is_faithful(),
            recovery_method: request.recovery_secret.method(),
            project_id: request.expectation.project_id.clone(),
            bundle_identity: verification.bundle_identity().to_owned(),
            database_export_evidence: request.expectation.database_export_evidence,
            validation,
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

fn validate_review_request(
    git: &impl GitProcess,
    request: &ProjectCapsuleReviewRequest<'_>,
) -> Result<(), CoreError> {
    if !request.plan.is_directory_plan()
        || request.plan.approval_state()? != PlanApprovalState::Approved
    {
        return Err(CoreError::InvalidPlan(
            "Project Capsule review requires an approved, non-stale directory Plan".to_owned(),
        ));
    }
    if !request.project.local_audit_verified() || request.project.changed_during_audit() {
        return Err(CoreError::InvalidPlan(
            "Project Capsule review requires one verified, unchanged Project audit".to_owned(),
        ));
    }
    let current_hash = crate::project_audit::observe_local_repository_hash(
        git,
        request.project.root(),
        request.project.kind(),
    )
    .ok_or_else(|| {
        CoreError::InvalidPlan(
            "Project Capsule review could not revalidate the Project audit".to_owned(),
        )
    })?;
    if request.project.local_state().observation_hash() != Some(current_hash.as_str()) {
        return Err(CoreError::InvalidPlan(
            "Project Capsule review requires a fresh Project audit".to_owned(),
        ));
    }
    if !request
        .plan
        .approved_roots()
        .iter()
        .any(|root| request.project.root().starts_with(root))
    {
        return Err(CoreError::InvalidPlan(
            "Project Capsule review audit is not bound to the approved Plan scope".to_owned(),
        ));
    }
    Ok(())
}

fn project_capsule_review_hash(
    plan: &Plan,
    project: &ProjectAudit,
    support_report: &ProjectCapsuleSupportReport,
    ignored_candidates: &[ProjectCapsuleIgnoredReview],
) -> Result<String, CoreError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza Project Capsule review v1\0");
    for field in [
        plan.approval_hash()?,
        project.id().to_owned(),
        project
            .local_state()
            .observation_hash()
            .unwrap_or_default()
            .to_owned(),
    ] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    for state in &support_report.supported_states {
        let name = format!("{state:?}");
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
    }
    for feature in &support_report.blocking_features {
        let name = format!("{feature:?}");
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
    }
    for object in &support_report.git_large_file_storage_objects {
        hasher.update(&(object.object_identifier.len() as u64).to_le_bytes());
        hasher.update(object.object_identifier.as_bytes());
        hasher.update(&object.size.to_le_bytes());
    }
    for candidate in ignored_candidates {
        hasher.update(&(candidate.candidate_id.len() as u64).to_le_bytes());
        hasher.update(candidate.candidate_id.as_bytes());
        let recommendation = format!("{:?}", candidate.recommendation);
        hasher.update(&(recommendation.len() as u64).to_le_bytes());
        hasher.update(recommendation.as_bytes());
        let decision = format!("{:?}", candidate.decision);
        hasher.update(&(decision.len() as u64).to_le_bytes());
        hasher.update(decision.as_bytes());
        let owner_reason = candidate.owner_reason.as_deref().unwrap_or_default();
        hasher.update(&(owner_reason.len() as u64).to_le_bytes());
        hasher.update(owner_reason.as_bytes());
        if let Some(export) = &candidate.database_export_review {
            for field in [
                export.base_review_hash.as_bytes(),
                export.export_item_id.as_bytes(),
                export.export_digest.as_bytes(),
                export.validation_description.as_bytes(),
            ] {
                hasher.update(&(field.len() as u64).to_le_bytes());
                hasher.update(field);
            }
            hasher.update(&export.export_size.to_le_bytes());
        }
    }
    Ok(format!(
        "project_capsule_review_blake3_{}",
        hasher.finalize().to_hex()
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DatabaseExportObservation {
    digest: String,
    size: u64,
    device_id: u64,
    file_id: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

fn observe_database_export(path: &Path) -> Result<DatabaseExportObservation, CoreError> {
    let before = fs::symlink_metadata(path).map_err(|source| CoreError::Io {
        action: "inspect selected database export",
        path: path.to_path_buf(),
        source,
    })?;
    if !before.is_file() {
        return Err(CoreError::InvalidPlan(
            "selected database export must be a regular file".to_owned(),
        ));
    }
    let mut file = open_regular_file_without_following(path, "open selected database export")?;
    let mut hasher = blake3::Hasher::new();
    let mut captured = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| CoreError::Io {
            action: "hash selected database export",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        captured = captured.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|source| CoreError::Io {
        action: "reinspect selected database export",
        path: path.to_path_buf(),
        source,
    })?;
    if !after.is_file() || captured != before.len() || !same_database_export_file(&before, &after) {
        return Err(CoreError::InvalidPlan(
            "database export changed during its stable-file observation".to_owned(),
        ));
    }
    #[cfg(unix)]
    let observation = DatabaseExportObservation {
        digest: hasher.finalize().to_hex().to_string(),
        size: captured,
        device_id: after.dev(),
        file_id: after.ino(),
        modified_seconds: after.mtime(),
        modified_nanoseconds: after.mtime_nsec(),
    };
    #[cfg(not(unix))]
    let observation = DatabaseExportObservation {
        digest: hasher.finalize().to_hex().to_string(),
        size: captured,
        device_id: 0,
        file_id: 0,
        modified_seconds: 0,
        modified_nanoseconds: 0,
    };
    Ok(observation)
}

fn same_database_export_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
    }
    #[cfg(not(unix))]
    {
        before.len() == after.len() && before.modified().ok() == after.modified().ok()
    }
}

fn is_live_database_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "db" | "sqlite" | "sqlite3"
            )
        })
        .unwrap_or(false)
}

fn validate_database_export_binding(
    plan: &Plan,
    project: &ProjectAudit,
    candidate_id: &str,
    database_path: &Path,
    review: &ProjectDatabaseExportReview,
) -> Result<(), CoreError> {
    let plan_hash = plan.approval_hash()?;
    let export_item = plan
        .items()
        .iter()
        .find(|item| item.id == review.export_item_id)
        .ok_or_else(|| {
            CoreError::InvalidPlan(
                "database export review no longer identifies a selected Migration Item".to_owned(),
            )
        })?;
    if review.project_id != project.id()
        || review.plan_hash != plan_hash
        || review.database_candidate_id != candidate_id
        || !is_live_database_path(database_path)
        || export_item.relative_path != review.export_relative_path
        || export_item.kind != MigrationItemKind::RegularFile
        || export_item.disposition != Disposition::Included
        || export_item.relative_path == database_path
        || review.validation_description.trim().is_empty()
    {
        return Err(CoreError::InvalidPlan(
            "database export review is not bound to the current Plan and Project".to_owned(),
        ));
    }
    let current = observe_database_export(&project.root().join(&review.export_relative_path))?;
    if current.digest != review.export_digest || current.size != review.export_size {
        return Err(CoreError::InvalidPlan(
            "database export changed after its two stable-file observations".to_owned(),
        ));
    }
    Ok(())
}

fn validate_capture_request(
    git: &impl GitProcess,
    request: &mut ProjectCapsuleCaptureRequest<'_>,
) -> Result<(), CoreError> {
    request.reviewed_executables.sort();
    request.reviewed_executables.dedup();
    let reviewed_ignored_paths = included_reviewed_ignored_paths(request.review);
    validate_reviewed_paths(&reviewed_ignored_paths, &request.reviewed_executables)?;
    if !request.plan.is_directory_plan()
        || request.plan.approval_state()? != PlanApprovalState::Approved
    {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture requires an approved, non-stale directory Plan".to_owned(),
        ));
    }
    if request.review_hash != request.review.review_hash {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture review hash does not match the completed review".to_owned(),
        ));
    }
    let plan_hash = request.plan.approval_hash()?;
    if request.review.plan_hash != plan_hash
        || request.review.project_id != request.project.id()
        || request.review.project_observation_hash
            != request
                .project
                .local_state()
                .observation_hash()
                .unwrap_or_default()
    {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture review is not bound to the current Plan and Project audit"
                .to_owned(),
        ));
    }
    if !request.review.is_complete() {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture requires a completed review with no blocking gaps".to_owned(),
        ));
    }
    for candidate in &request.review.ignored_candidates {
        if let Some(database_export_review) = &candidate.database_export_review {
            validate_database_export_binding(
                request.plan,
                request.project,
                &candidate.candidate_id,
                &candidate.relative_path,
                database_export_review,
            )?;
        }
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
    let audited_ignored_paths = complete_ignored_candidates(request.project)?
        .iter()
        .map(|candidate| candidate.relative_path().to_path_buf())
        .collect::<BTreeSet<_>>();
    if ignored_paths(git, root)? != audited_ignored_paths {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture requires a fresh ignored-state review".to_owned(),
        ));
    }
    if !working_tree_blocking_features(git, root)?.is_empty() {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture requires a fresh repository support review".to_owned(),
        ));
    }
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
        || root.join(".git/objects/info/alternates").exists()
        || root.join(".git/worktrees").exists()
    {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture found unsupported repository state".to_owned(),
        ));
    }
    if request.project.git_large_file_storage().configured()
        && local_git_large_file_storage_evidence(root)?
            != Some(
                request
                    .review
                    .support_report
                    .git_large_file_storage_objects
                    .clone(),
            )
    {
        return Err(CoreError::InvalidPlan(
            "Project Capsule capture requires a fresh Git Large File Storage review".to_owned(),
        ));
    }
    let ignored = ignored_paths(git, root)?;
    if reviewed_ignored_paths
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

fn complete_ignored_candidates(project: &ProjectAudit) -> Result<&[IgnoredCandidate], CoreError> {
    project.ignored_candidates().map_err(|_| {
        CoreError::InvalidPlan(
            "Project Capsule operations require a complete ignored-state inventory".to_owned(),
        )
    })
}

fn included_reviewed_ignored_paths(review: &ProjectCapsuleReview) -> Vec<PathBuf> {
    review
        .ignored_candidates
        .iter()
        .filter(|candidate| {
            candidate.decision
                == Some(ProjectCapsuleReviewDecisionKind::IncludeAsEncryptedReviewedState)
        })
        .map(|candidate| candidate.relative_path.clone())
        .collect()
}

fn database_export_evidence_count(review: &ProjectCapsuleReview) -> usize {
    review
        .ignored_candidates
        .iter()
        .filter(|candidate| {
            candidate.decision
                == Some(ProjectCapsuleReviewDecisionKind::ReplaceLiveDatabaseWithExport)
                && candidate.database_export_review.is_some()
        })
        .count()
}

fn local_git_large_file_storage_evidence(
    root: &Path,
) -> Result<Option<Vec<ProjectCapsuleGitLargeFileStorageEvidence>>, CoreError> {
    let mut objects = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|source| CoreError::Io {
            action: "inspect Git Large File Storage pointers",
            path: directory.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| CoreError::Io {
                action: "inspect Git Large File Storage pointer entry",
                path: directory.clone(),
                source,
            })?;
            if entry.path() == root.join(".git") {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|source| CoreError::Io {
                action: "inspect Git Large File Storage pointer type",
                path: entry.path(),
                source,
            })?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                if entry.path() != root && entry.path().join(".git").exists() {
                    continue;
                }
                pending.push(entry.path());
                continue;
            }
            if !metadata.is_file() || metadata.len() > 1024 {
                continue;
            }
            let bytes = read_regular_file_without_following(
                &entry.path(),
                "read Git Large File Storage pointer",
            )?;
            if !bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n") {
                continue;
            }
            let Some((object_identifier, size)) = parse_git_large_file_storage_pointer(&bytes)
            else {
                return Ok(None);
            };
            let object = root
                .join(".git/lfs/objects")
                .join(&object_identifier[..2])
                .join(&object_identifier[2..4])
                .join(&object_identifier);
            let Ok(object_metadata) = fs::symlink_metadata(&object) else {
                return Ok(None);
            };
            if !object_metadata.is_file() || object_metadata.len() != size {
                return Ok(None);
            }
            let mut file = open_regular_file_without_following(
                &object,
                "open local Git Large File Storage object",
            )?;
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer).map_err(|source| CoreError::Io {
                    action: "hash local Git Large File Storage object",
                    path: object.clone(),
                    source,
                })?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            let Some(expected_digest) = decode_sha256_identifier(&object_identifier) else {
                return Ok(None);
            };
            if hasher.finalize()[..] != expected_digest {
                return Ok(None);
            }
            objects.push(ProjectCapsuleGitLargeFileStorageEvidence {
                object_identifier,
                size,
            });
        }
    }
    objects.sort();
    objects.dedup();
    Ok(Some(objects))
}

fn parse_git_large_file_storage_pointer(bytes: &[u8]) -> Option<(String, u64)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "version https://git-lfs.github.com/spec/v1" {
        return None;
    }
    let object_identifier = lines.next()?.strip_prefix("oid sha256:")?;
    if object_identifier.len() != 64
        || !object_identifier
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let size = lines.next()?.strip_prefix("size ")?.parse().ok()?;
    if lines.next().is_some() {
        return None;
    }
    Some((object_identifier.to_owned(), size))
}

fn decode_sha256_identifier(identifier: &str) -> Option<[u8; 32]> {
    if identifier.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in identifier.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)? as u8;
        let low = (pair[1] as char).to_digit(16)? as u8;
        decoded[index] = (high << 4) | low;
    }
    Some(decoded)
}

fn read_regular_file_without_following(
    path: &Path,
    action: &'static str,
) -> Result<Vec<u8>, CoreError> {
    let mut file = open_regular_file_without_following(path, action)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| CoreError::Io {
            action,
            path: path.to_path_buf(),
            source,
        })?;
    Ok(bytes)
}

fn open_regular_file_without_following(
    path: &Path,
    action: &'static str,
) -> Result<fs::File, CoreError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path).map_err(|source| CoreError::Io {
        action,
        path: path.to_path_buf(),
        source,
    })
}

fn reviewed_executable_modes(
    root: &Path,
    reviewed_executables: &[PathBuf],
) -> Result<BTreeMap<PathBuf, u32>, CoreError> {
    let mut modes = BTreeMap::new();
    for relative in reviewed_executables {
        let metadata =
            fs::symlink_metadata(root.join(relative)).map_err(|source| CoreError::Io {
                action: "inspect reviewed Project executable mode",
                path: root.join(relative),
                source,
            })?;
        if !metadata.is_file() || !is_executable(&metadata) {
            return Err(CoreError::InvalidPlan(
                "reviewed Project executable is not an executable regular file".to_owned(),
            ));
        }
        #[cfg(unix)]
        let mode = metadata.permissions().mode() & 0o777;
        #[cfg(not(unix))]
        let mode = 0_u32;
        modes.insert(relative.clone(), mode);
    }
    Ok(modes)
}

fn executable_expectation_review_hash(
    project_id: &str,
    review_hash: &str,
    bundle_identity: &str,
    observation: &ProjectObservation,
    reviewed_executable_modes: &BTreeMap<PathBuf, u32>,
) -> Option<String> {
    if reviewed_executable_modes.is_empty() {
        return None;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza Project Capsule executable expectation v1\0");
    for field in [
        project_id.as_bytes(),
        review_hash.as_bytes(),
        bundle_identity.as_bytes(),
        observation.digest.as_bytes(),
    ] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    for (path, mode) in reviewed_executable_modes {
        let path = path.to_string_lossy();
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(&mode.to_le_bytes());
    }
    Some(format!(
        "project_capsule_mode_review_blake3_{}",
        hasher.finalize().to_hex()
    ))
}

fn restore_expected_executable_modes(
    restored: &Path,
    reviewed_executable_modes: &BTreeMap<PathBuf, u32>,
) -> Result<(), CoreError> {
    for (relative, mode) in reviewed_executable_modes {
        if relative.starts_with(".git/hooks") {
            return Err(CoreError::InvalidPlan(
                "Git hooks cannot receive executable-mode approval".to_owned(),
            ));
        }
        let destination = restored.join(relative);
        let metadata = fs::symlink_metadata(&destination).map_err(|source| CoreError::Io {
            action: "inspect reviewed executable Restore",
            path: destination.clone(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(CoreError::InvalidPlan(
                "reviewed executable Restore is not a regular file".to_owned(),
            ));
        }
        #[cfg(unix)]
        fs::set_permissions(&destination, fs::Permissions::from_mode(*mode)).map_err(|source| {
            CoreError::Io {
                action: "restore expectation-bound executable mode",
                path: destination,
                source,
            }
        })?;
    }
    Ok(())
}

fn project_capsule_unix_time_now() -> Result<u64, CoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoreError::InvalidPlan("system clock is before the Unix epoch".to_owned()))
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

fn working_tree_blocking_features(
    git: &impl GitProcess,
    root: &Path,
) -> Result<BTreeSet<ProjectCapsuleBlockingFeature>, CoreError> {
    let mut features = BTreeSet::new();
    if root.join(".git/objects/info/alternates").exists() {
        features.insert(ProjectCapsuleBlockingFeature::ObjectAlternates);
    }
    if root.join(".git/worktrees").exists() {
        features.insert(ProjectCapsuleBlockingFeature::LinkedWorktree);
    }
    if root.join(".git/info/sparse-checkout").exists()
        || git_optional_text(
            git,
            root,
            &["config", "--local", "--get", "core.sparseCheckout"],
            "inspect sparse-checkout configuration",
        )?
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    {
        features.insert(ProjectCapsuleBlockingFeature::SparseCheckout);
    }
    if git_optional_text(
        git,
        root,
        &["config", "--local", "--get", "extensions.partialClone"],
        "inspect partial-clone configuration",
    )?
    .is_some()
    {
        features.insert(ProjectCapsuleBlockingFeature::PartialClone);
    }
    if git_optional_text(
        git,
        root,
        &[
            "config",
            "--local",
            "--get-regexp",
            "^remote\\..*\\.promisor$",
        ],
        "inspect promisor-object configuration",
    )?
    .is_some()
    {
        features.insert(ProjectCapsuleBlockingFeature::PromisorObjects);
    }
    if repository_has_active_lock(&root.join(".git")).map_err(|_| {
        CoreError::InvalidPlan("Project Capsule could not verify repository lock state".to_owned())
    })? {
        features.insert(ProjectCapsuleBlockingFeature::ActiveGitLocks);
    }
    if repository_has_nonportable_names(root)? {
        features.insert(ProjectCapsuleBlockingFeature::NonportableFilesystemNames);
    }
    Ok(features)
}

fn repository_has_nonportable_names(root: &Path) -> Result<bool, CoreError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut portable_names = BTreeSet::<String>::new();
        for entry in fs::read_dir(&directory).map_err(|source| CoreError::Io {
            action: "inspect Project names for portable capture",
            path: directory.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| CoreError::Io {
                action: "inspect Project name for portable capture",
                path: directory.clone(),
                source,
            })?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Ok(true);
            };
            if !is_portable_project_name(&name)
                || !portable_names
                    .insert(name.nfc().flat_map(char::to_lowercase).collect::<String>())
            {
                return Ok(true);
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|source| CoreError::Io {
                action: "inspect Project entry for portable capture",
                path: entry.path(),
                source,
            })?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                pending.push(entry.path());
            }
        }
    }
    Ok(false)
}

fn is_portable_project_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 255
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|character| character.is_control() || "<>:\"\\|?*".contains(character))
    {
        return false;
    }
    let base = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    !matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
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

fn project_capsule_attempt_path(destination: &Path, attempt: u8) -> Result<PathBuf, CoreError> {
    let file_name = destination.file_name().ok_or_else(|| {
        CoreError::InvalidPlan("Project Capsule destination must have a file name".to_owned())
    })?;
    let mut attempt_name = file_name.to_os_string();
    attempt_name.push(format!(".project-capsule-attempt-{attempt}.iniza"));
    Ok(destination.with_file_name(attempt_name))
}

fn retained_project_capsule_attempt_path(attempt: &Path) -> PathBuf {
    let mut retained = attempt.as_os_str().to_os_string();
    retained.push(".partial");
    PathBuf::from(retained)
}

fn publish_project_capsule_attempt(source: &Path, destination: &Path) -> Result<(), CoreError> {
    fs::hard_link(source, destination).map_err(|source_error| {
        if source_error.kind() == io::ErrorKind::AlreadyExists {
            CoreError::DestinationAlreadyExists(destination.to_path_buf())
        } else {
            CoreError::Io {
                action: "publish verified Project Capsule attempt",
                path: destination.to_path_buf(),
                source: source_error,
            }
        }
    })?;
    fs::remove_file(source).map_err(|source_error| CoreError::Io {
        action: "remove published Project Capsule attempt name",
        path: source.to_path_buf(),
        source: source_error,
    })
}

fn retain_changed_project_capsule_attempt(source: &Path, retained: &Path) -> Result<(), CoreError> {
    fs::hard_link(source, retained).map_err(|source_error| {
        if source_error.kind() == io::ErrorKind::AlreadyExists {
            CoreError::DestinationAlreadyExists(retained.to_path_buf())
        } else {
            CoreError::Io {
                action: "retain changed Project Capsule attempt",
                path: retained.to_path_buf(),
                source: source_error,
            }
        }
    })?;
    fs::remove_file(source).map_err(|source_error| CoreError::Io {
        action: "remove completed changed-attempt Bundle name",
        path: source.to_path_buf(),
        source: source_error,
    })
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
