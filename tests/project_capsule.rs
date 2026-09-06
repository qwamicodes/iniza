use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

use iniza::{
    GitProcess, GitProcessOutput, InstalledGit, PlanEngine, ProjectAuditEngine,
    ProjectAuditRequest, ProjectCapsuleCaptureRequest, ProjectCapsuleCaptureState,
    ProjectCapsuleComparisonRequest, ProjectCapsuleEngine, ProjectCapsuleRepresentation,
    ProjectCapsuleValidationRequest, RestoreEngine, RestoreRequest, ScanRequest,
};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "iniza-project-capsule-{name}-{}-{unique}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("test directory should be created");
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
#[test]
fn both_project_capsule_representations_restore_the_complete_reviewed_dirty_project() {
    let directory = TestDirectory::new("dirty-round-trip");
    let project = directory.path.join("owner-project");
    let workspace = directory.path.join("comparison-workspace");
    let git_native_bundle = directory.path.join("git-native.iniza");
    let snapshot_bundle = directory.path.join("snapshot.iniza");
    let script_sentinel = directory.path.join("script-ran");
    let hook_sentinel = directory.path.join("hook-ran");
    create_dirty_project_fixture(&project, &script_sentinel, &hook_sentinel);

    let request = ProjectCapsuleComparisonRequest::new(
        &project,
        vec![PathBuf::from(".env.local")],
        &workspace,
        &git_native_bundle,
        &snapshot_bundle,
    )
    .with_reviewed_executable("scripts/rebuild.sh");
    let report = ProjectCapsuleEngine::local()
        .compare(request)
        .expect("both synthetic Project Capsule candidates should complete");

    for representation in [
        ProjectCapsuleRepresentation::GitNativeArchiveWithOverlay,
        ProjectCapsuleRepresentation::FullRepositorySnapshot,
    ] {
        let candidate = report
            .candidate(representation)
            .expect("each required representation should be reported");
        assert!(candidate.restorable(), "{candidate:#?}");
        assert_eq!(
            candidate.pre_capture_hash(),
            candidate.post_capture_hash(),
            "an unchanged Project must retain the same bounded observation"
        );
        assert!(candidate.bundle_bytes() > 0);
        assert!(candidate.restored_bytes() > 0);
        assert!(candidate.bundle_pack_is_resumable());
        assert!(!candidate.portability_findings().is_empty());
        assert!(!candidate.maintenance_findings().is_empty());
        assert!(candidate.validation().is_faithful());
        assert!(candidate.validation().head_is_attached_to_main());
        assert!(candidate.validation().has_no_remote());
        assert!(candidate.validation().hooks_are_disabled());
        assert!(candidate.validation().reviewed_executables_restored());
        assert_eq!(
            candidate.validation().head_object_identifier(),
            "4a260c9f844521bf6a53b7f6c0b2cbc4d769b81e"
        );
        assert_eq!(
            candidate
                .validation()
                .reference_object_identifier("refs/heads/feature/local"),
            Some("d5fab99845a315081adb2f64f5a50df4fec18ade")
        );
        assert_eq!(
            candidate
                .validation()
                .reference_object_identifier("refs/heads/main"),
            Some("4a260c9f844521bf6a53b7f6c0b2cbc4d769b81e")
        );
        assert_eq!(
            candidate
                .validation()
                .reference_object_identifier("refs/stash"),
            Some("b52e9e9858a1e2db1386288dae75d549a681ee47")
        );
        assert_eq!(
            candidate
                .validation()
                .reference_object_identifier("refs/tags/owner-snapshot"),
            Some("c03a07a58990d68ea6c78b79a1ba3c27baf5c088")
        );
    }
    assert_eq!(
        report.recommendation(),
        Some(ProjectCapsuleRepresentation::FullRepositorySnapshot),
        "the plaintext Git archive prototype is not production-eligible even when it is smaller"
    );
    assert!(
        report
            .candidate(ProjectCapsuleRepresentation::GitNativeArchiveWithOverlay)
            .expect("Git-native candidate should exist")
            .construction_must_restart()
    );
    assert!(
        !report
            .candidate(ProjectCapsuleRepresentation::FullRepositorySnapshot)
            .expect("snapshot candidate should exist")
            .construction_must_restart()
    );
    for restored in [
        workspace.join("git-native-restored-project"),
        workspace.join("snapshot-restored"),
    ] {
        assert_eq!(
            fs::read(restored.join("staged.txt")).expect("staged worktree file should restore"),
            b"selected staged content\n"
        );
        assert_eq!(
            git_bytes(&restored, &["show", ":staged.txt"]),
            b"selected staged content\n"
        );
        assert_eq!(
            fs::read(restored.join("binary.dat")).expect("binary worktree file should restore"),
            [0_u8, 255, 16, 32, 48, 64, 80, 96]
        );
        assert_eq!(
            git_bytes(&restored, &["show", ":binary.dat"]),
            [0_u8, 1, 2, 3]
        );
        assert_eq!(
            fs::read(restored.join("notes.txt")).expect("untracked file should restore"),
            b"selected untracked content\n"
        );
        assert_eq!(
            fs::read(restored.join(".env.local")).expect("reviewed ignored file should restore"),
            b"SYNTHETIC_ONLY=true\n"
        );
        assert!(
            !restored.join("unreviewed.secret").exists(),
            "an ignored path without explicit review must not enter a Project Capsule"
        );
        assert_eq!(
            fs::read_link(restored.join("current-config")).expect("symbolic link should restore"),
            PathBuf::from("config/development.json")
        );
        assert!(restored.join("uploads/empty").is_dir());
        assert_ne!(
            fs::metadata(restored.join("scripts/rebuild.sh"))
                .expect("reviewed executable should restore")
                .permissions()
                .mode()
                & 0o111,
            0
        );
        assert_eq!(
            fs::metadata(restored.join(".git/hooks/pre-commit"))
                .expect("hook evidence should restore")
                .permissions()
                .mode()
                & 0o111,
            0
        );
        let status = git_stdout(
            &restored,
            &[
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--ignored=matching",
            ],
        );
        assert!(status.contains("?? notes.txt"));
        assert!(status.contains("!! .env.local"));
        assert!(git_stdout(&restored, &["remote"]).trim().is_empty());
    }
    assert!(
        !script_sentinel.exists(),
        "the restored script must never run"
    );
    assert!(
        !hook_sentinel.exists(),
        "the restored Git hook must never run"
    );
    assert!(
        !workspace.join("git-native-source").exists(),
        "the reusable plaintext Git-native source must be removed after verification"
    );
    assert!(
        !workspace.join("git-native-restored-capsule").exists(),
        "the restored plaintext capsule container must be removed after reconstruction"
    );
}

#[cfg(unix)]
#[test]
fn project_change_during_capture_withholds_a_recommendation() {
    let directory = TestDirectory::new("changed-during-capture");
    let project = directory.path.join("owner-project");
    let workspace = directory.path.join("comparison-workspace");
    let script_sentinel = directory.path.join("script-ran");
    let hook_sentinel = directory.path.join("hook-ran");
    create_dirty_project_fixture(&project, &script_sentinel, &hook_sentinel);
    let git = MutatingGit {
        installed: InstalledGit::default(),
        project: project.clone(),
        changed: Mutex::new(false),
    };

    let report = ProjectCapsuleEngine::with_git_process(git)
        .compare(
            ProjectCapsuleComparisonRequest::new(
                &project,
                vec![PathBuf::from(".env.local")],
                &workspace,
                directory.path.join("git-native.iniza"),
                directory.path.join("snapshot.iniza"),
            )
            .with_reviewed_executable("scripts/rebuild.sh"),
        )
        .expect("capture should return bounded evidence when the Project changes");

    let git_native = report
        .candidate(ProjectCapsuleRepresentation::GitNativeArchiveWithOverlay)
        .expect("Git-native result should remain visible");
    assert!(git_native.changed_during_capture());
    assert!(!git_native.restorable());
    assert_eq!(report.recommendation(), None);
}

#[cfg(unix)]
#[test]
fn project_capsule_results_do_not_expose_project_names_paths_or_remote_credentials() {
    let directory = TestDirectory::new("sanitized-results");
    let protected_name = "customer-top-secret";
    let credential = "correct-horse-token";
    let project = directory.path.join(protected_name);
    let script_sentinel = directory.path.join("script-ran");
    let hook_sentinel = directory.path.join("hook-ran");
    create_dirty_project_fixture(&project, &script_sentinel, &hook_sentinel);
    git(
        &project,
        &[
            "remote",
            "add",
            "origin",
            &format!(
                "https://owner:{credential}@example.invalid/private/repository.git?token={credential}"
            ),
        ],
    );

    let report = ProjectCapsuleEngine::local()
        .compare(
            ProjectCapsuleComparisonRequest::new(
                &project,
                vec![PathBuf::from(".env.local")],
                directory.path.join("comparison-workspace"),
                directory.path.join("git-native.iniza"),
                directory.path.join("snapshot.iniza"),
            )
            .with_reviewed_executable("scripts/rebuild.sh"),
        )
        .expect("hostile display data should not prevent bounded comparison evidence");

    for output in [report.human_result(), report.machine_json_result()] {
        assert!(!output.contains(protected_name));
        assert!(!output.contains(credential));
        assert!(!output.contains(&directory.path.to_string_lossy().to_string()));
        assert!(!output.contains("repository.git"));
    }
    let machine: serde_json::Value =
        serde_json::from_str(&report.machine_json_result()).expect("machine result should be JSON");
    assert_eq!(machine["command"], "project capsule compare");
}

#[cfg(unix)]
#[test]
fn both_representations_restore_a_detached_unreferenced_current_commit() {
    let directory = TestDirectory::new("detached-head");
    let project = directory.path.join("owner-project");
    let script_sentinel = directory.path.join("script-ran");
    let hook_sentinel = directory.path.join("hook-ran");
    create_dirty_project_fixture(&project, &script_sentinel, &hook_sentinel);
    git_with_identity(
        &project,
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-q",
            "-m",
            "prepare detached fixture",
            "--",
            "staged.txt",
        ],
        "2026-01-04T00:00:00Z",
    );
    git(&project, &["checkout", "--detach", "-q"]);
    fs::write(
        project.join("detached.txt"),
        "unreferenced current commit\n",
    )
    .expect("detached fixture should be written");
    git(&project, &["add", "detached.txt"]);
    git_with_identity(
        &project,
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-q",
            "-m",
            "detached fixture",
        ],
        "2026-01-05T00:00:00Z",
    );
    fs::write(project.join("staged.txt"), "detached staged content\n")
        .expect("detached staged fixture should be written");
    git(&project, &["add", "staged.txt"]);

    let report = ProjectCapsuleEngine::local()
        .compare(
            ProjectCapsuleComparisonRequest::new(
                &project,
                vec![PathBuf::from(".env.local")],
                directory.path.join("comparison-workspace"),
                directory.path.join("git-native.iniza"),
                directory.path.join("snapshot.iniza"),
            )
            .with_reviewed_executable("scripts/rebuild.sh"),
        )
        .expect("detached Project should complete both synthetic round trips");

    for representation in [
        ProjectCapsuleRepresentation::GitNativeArchiveWithOverlay,
        ProjectCapsuleRepresentation::FullRepositorySnapshot,
    ] {
        let candidate = report
            .candidate(representation)
            .expect("each candidate should be reported");
        assert!(candidate.restorable(), "{candidate:#?}");
        assert!(candidate.validation().current_state_is_detached());
    }
    assert!(!script_sentinel.exists());
    assert!(!hook_sentinel.exists());
}

#[cfg(unix)]
#[test]
fn executable_mode_requires_the_exact_validation_hash_bound_to_the_restored_bundle() {
    let directory = TestDirectory::new("mode-review");
    let project = directory.path.join("owner-project");
    let workspace = directory.path.join("comparison-workspace");
    let snapshot_bundle = directory.path.join("snapshot.iniza");
    let script_sentinel = directory.path.join("script-ran");
    let hook_sentinel = directory.path.join("hook-ran");
    create_dirty_project_fixture(&project, &script_sentinel, &hook_sentinel);
    ProjectCapsuleEngine::local()
        .compare(
            ProjectCapsuleComparisonRequest::new(
                &project,
                vec![PathBuf::from(".env.local")],
                &workspace,
                directory.path.join("git-native.iniza"),
                &snapshot_bundle,
            )
            .with_reviewed_executable("scripts/rebuild.sh"),
        )
        .expect("synthetic comparison should create a verified restored candidate");
    let restored = workspace.join("snapshot-restored");
    fs::set_permissions(
        restored.join("scripts/rebuild.sh"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("test should return the executable to quarantine");

    let pending = ProjectCapsuleEngine::local()
        .validate_restored(
            ProjectCapsuleValidationRequest::new(
                &project,
                &restored,
                &snapshot_bundle,
                vec![PathBuf::from(".env.local")],
            )
            .with_reviewed_executable("scripts/rebuild.sh"),
        )
        .expect("validation without approval should return a bounded pending result");
    assert!(pending.executable_mode_review_is_pending());
    assert_eq!(
        fs::metadata(restored.join("scripts/rebuild.sh"))
            .expect("restored script should exist")
            .permissions()
            .mode()
            & 0o111,
        0,
        "validation must not apply execute bits before exact review"
    );
    let exact_review_hash = pending
        .required_executable_mode_review_hash()
        .expect("pending result should expose a secret-free exact review hash")
        .to_owned();

    let rejected = ProjectCapsuleEngine::local()
        .validate_restored(
            ProjectCapsuleValidationRequest::new(
                &project,
                &restored,
                &snapshot_bundle,
                vec![PathBuf::from(".env.local")],
            )
            .with_reviewed_executable("scripts/rebuild.sh")
            .with_executable_mode_review_hash("wrong-bundle-bound-review-hash"),
        )
        .expect("a mismatched review should remain a bounded pending result");
    assert!(rejected.executable_mode_review_is_pending());
    assert_eq!(
        fs::metadata(restored.join("scripts/rebuild.sh"))
            .expect("restored script should exist")
            .permissions()
            .mode()
            & 0o111,
        0,
        "a mismatched review hash must not apply execute bits"
    );

    let accepted = ProjectCapsuleEngine::local()
        .validate_restored(
            ProjectCapsuleValidationRequest::new(
                &project,
                &restored,
                &snapshot_bundle,
                vec![PathBuf::from(".env.local")],
            )
            .with_reviewed_executable("scripts/rebuild.sh")
            .with_executable_mode_review_hash(exact_review_hash),
        )
        .expect("the exact Bundle-bound review hash should apply reviewed modes");
    assert!(accepted.is_faithful(), "{accepted:#?}");
    assert!(!accepted.executable_mode_review_is_pending());
    assert!(accepted.hooks_are_disabled());
    assert!(!script_sentinel.exists());
    assert!(!hook_sentinel.exists());
}

#[cfg(unix)]
#[test]
fn active_git_lock_blocks_comparison_before_any_output_is_created() {
    let directory = TestDirectory::new("active-lock");
    let project = directory.path.join("owner-project");
    let workspace = directory.path.join("comparison-workspace");
    let git_native_bundle = directory.path.join("git-native.iniza");
    let snapshot_bundle = directory.path.join("snapshot.iniza");
    create_dirty_project_fixture(
        &project,
        &directory.path.join("script-ran"),
        &directory.path.join("hook-ran"),
    );
    fs::write(project.join(".git/index.lock"), "synthetic active lock\n")
        .expect("active lock fixture should be written");

    let error = ProjectCapsuleEngine::local()
        .compare(ProjectCapsuleComparisonRequest::new(
            &project,
            vec![PathBuf::from(".env.local")],
            &workspace,
            &git_native_bundle,
            &snapshot_bundle,
        ))
        .expect_err("active repository locks must block Project Capsule comparison");

    assert_eq!(
        error.to_string(),
        "Project Capsule comparison requires an unlocked repository"
    );
    assert!(!workspace.exists());
    assert!(!git_native_bundle.exists());
    assert!(!snapshot_bundle.exists());
}

#[cfg(unix)]
#[test]
fn approved_verified_project_captures_directly_into_a_fully_verified_snapshot_bundle() {
    let directory = TestDirectory::new("production-capture");
    let project = directory.path.join("owner-project");
    let bundle = directory.path.join("project-capsule.iniza");
    let restore = directory.path.join("restored-project");
    create_dirty_project_fixture(
        &project,
        &directory.path.join("script-ran"),
        &directory.path.join("hook-ran"),
    );
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let reviewed_hash = plan.approval_hash().expect("Project Plan should hash");
    plan.approve(&reviewed_hash)
        .expect("exact reviewed hash should approve the Project Plan");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");

    let report = ProjectCapsuleEngine::local()
        .capture(
            ProjectCapsuleCaptureRequest::new(&plan, project_audit, &bundle)
                .with_reviewed_ignored_path(".env.local")
                .with_reviewed_executable("scripts/rebuild.sh"),
        )
        .expect("approved verified Project should capture");

    assert_eq!(report.state(), ProjectCapsuleCaptureState::Verified);
    assert_eq!(
        report.representation(),
        ProjectCapsuleRepresentation::FullRepositorySnapshot
    );
    assert_eq!(report.pre_capture_hash(), report.post_capture_hash());
    assert!(report.bundle_bytes() > 0);
    assert_eq!(
        report.verification().authenticated_bytes,
        report.authenticated_project_bytes()
    );
    assert!(bundle.is_file());
    assert!(!directory.path.join("project-capsule").exists());
    assert!(
        !report
            .human_result()
            .contains(&project.to_string_lossy().to_string())
    );
    assert!(!report.machine_json_result().contains("owner-project"));
    assert!(!format!("{report:?}").contains("owner-project"));

    RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &restore,
            report.offline_recovery_key(),
        ))
        .expect("captured Project Capsule should restore with one Recovery Method");
    assert_eq!(
        fs::read(restore.join("staged.txt")).expect("reviewed staged content should restore"),
        b"selected staged content\n"
    );
    assert!(
        !restore.join("unreviewed.secret").exists(),
        "unreviewed ignored data must not enter production capture"
    );
    assert_eq!(
        fs::metadata(restore.join(".git/hooks/pre-commit"))
            .expect("hook evidence should restore")
            .permissions()
            .mode()
            & 0o111,
        0,
        "captured Git hooks must restore disabled"
    );
}

#[cfg(unix)]
#[test]
fn production_capture_preserves_but_does_not_rely_on_a_bundle_when_the_project_changes() {
    let directory = TestDirectory::new("production-capture-change");
    let project = directory.path.join("owner-project");
    let bundle = directory.path.join("project-capsule.iniza");
    create_dirty_project_fixture(
        &project,
        &directory.path.join("script-ran"),
        &directory.path.join("hook-ran"),
    );
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let reviewed_hash = plan.approval_hash().expect("Project Plan should hash");
    plan.approve(&reviewed_hash)
        .expect("exact reviewed hash should approve the Project Plan");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    let git = PostPackMutatingGit {
        installed: InstalledGit::default(),
        project: project.clone(),
        head_observations: AtomicUsize::new(0),
    };

    let report = ProjectCapsuleEngine::with_git_process(git)
        .capture(
            ProjectCapsuleCaptureRequest::new(
                &plan,
                audit.projects().first().expect("Project should be audited"),
                &bundle,
            )
            .with_reviewed_ignored_path(".env.local")
            .with_reviewed_executable("scripts/rebuild.sh"),
        )
        .expect("changed capture should return bounded preservation evidence");

    assert_eq!(
        report.state(),
        ProjectCapsuleCaptureState::ChangedAndUnverified
    );
    assert!(!report.is_verified());
    assert_ne!(report.pre_capture_hash(), report.post_capture_hash());
    assert!(
        bundle.is_file(),
        "the encrypted evidence should be preserved"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&report.machine_json_result())
            .expect("capture result should be JSON")["status"],
        "changed-and-unverified"
    );
}

#[cfg(unix)]
#[test]
fn production_capture_rejects_a_project_changed_after_its_verified_audit() {
    let directory = TestDirectory::new("stale-project-audit");
    let project = directory.path.join("owner-project");
    let bundle = directory.path.join("project-capsule.iniza");
    create_dirty_project_fixture(
        &project,
        &directory.path.join("script-ran"),
        &directory.path.join("hook-ran"),
    );
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let reviewed_hash = plan.approval_hash().expect("Project Plan should hash");
    plan.approve(&reviewed_hash)
        .expect("exact reviewed hash should approve the Project Plan");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    fs::write(project.join("created-after-audit.txt"), "stale audit\n")
        .expect("post-audit change should be written");

    let error = ProjectCapsuleEngine::local()
        .capture(
            ProjectCapsuleCaptureRequest::new(
                &plan,
                audit.projects().first().expect("Project should be audited"),
                &bundle,
            )
            .with_reviewed_ignored_path(".env.local")
            .with_reviewed_executable("scripts/rebuild.sh"),
        )
        .expect_err("changed Project must require a fresh audit");

    assert_eq!(
        error.to_string(),
        "Project Capsule capture requires a fresh Project audit"
    );
    assert!(!bundle.exists());
}

struct PostPackMutatingGit {
    installed: InstalledGit,
    project: PathBuf,
    head_observations: AtomicUsize,
}

impl GitProcess for PostPackMutatingGit {
    fn run(
        &self,
        repository: &Path,
        arguments: &[std::ffi::OsString],
    ) -> std::io::Result<GitProcessOutput> {
        let observes_head = arguments.first().and_then(|value| value.to_str()) == Some("rev-parse")
            && arguments.get(1).and_then(|value| value.to_str()) == Some("HEAD");
        if observes_head && self.head_observations.fetch_add(1, Ordering::SeqCst) == 1 {
            fs::write(
                self.project.join("notes.txt"),
                "changed after encrypted Pack\n",
            )?;
        }
        self.installed.run(repository, arguments)
    }
}

struct MutatingGit {
    installed: InstalledGit,
    project: PathBuf,
    changed: Mutex<bool>,
}

impl GitProcess for MutatingGit {
    fn run(
        &self,
        repository: &Path,
        arguments: &[std::ffi::OsString],
    ) -> std::io::Result<GitProcessOutput> {
        let output = self.installed.run(repository, arguments)?;
        let is_bundle_create = arguments.first().and_then(|value| value.to_str()) == Some("bundle")
            && arguments.get(1).and_then(|value| value.to_str()) == Some("create");
        let mut changed = self.changed.lock().expect("mutation guard should lock");
        if is_bundle_create && !*changed {
            fs::write(self.project.join("notes.txt"), "changed during capture\n")?;
            *changed = true;
        }
        Ok(output)
    }
}

#[cfg(unix)]
fn create_dirty_project_fixture(project: &Path, script_sentinel: &Path, hook_sentinel: &Path) {
    assert_eq!(
        script_sentinel.file_name().and_then(|name| name.to_str()),
        Some("script-ran")
    );
    assert_eq!(
        hook_sentinel.file_name().and_then(|name| name.to_str()),
        Some("hook-ran")
    );
    fs::create_dir_all(project.join("scripts")).expect("fixture directories should be created");
    fs::create_dir_all(project.join("config")).expect("configuration directory should be created");
    git(project, &["init", "-q", "--initial-branch=main"]);
    fs::write(project.join(".gitignore"), ".env.local\n")
        .expect("ignore fixture should be written");
    fs::write(project.join("staged.txt"), "committed staged content\n")
        .expect("staged fixture should be written");
    fs::write(project.join("binary.dat"), [0_u8, 1, 2, 3])
        .expect("binary fixture should be written");
    fs::write(project.join("stash.txt"), "committed stash content\n")
        .expect("stash fixture should be written");
    fs::write(
        project.join("config/development.json"),
        "{\"environment\":\"development\"}\n",
    )
    .expect("configuration fixture should be written");
    fs::write(
        project.join("scripts/rebuild.sh"),
        "#!/bin/sh\ntouch ../script-ran\n",
    )
    .expect("executable fixture should be written");
    fs::set_permissions(
        project.join("scripts/rebuild.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("executable fixture mode should be set");
    git(project, &["add", "."]);
    commit(project, "first fixture", "2026-01-01T00:00:00Z");
    let first_commit = git_stdout(project, &["rev-parse", "HEAD"]);

    fs::write(project.join("second.txt"), "second committed content\n")
        .expect("second commit fixture should be written");
    git(project, &["add", "second.txt"]);
    commit(project, "second fixture", "2026-01-02T00:00:00Z");
    git(project, &["branch", "feature/local", first_commit.trim()]);
    git_with_identity(
        project,
        &["tag", "-a", "owner-snapshot", "-m", "owner snapshot"],
        "2026-01-03T00:00:00Z",
    );

    fs::write(project.join("stash.txt"), "synthetic stashed content\n")
        .expect("stash change should be written");
    git_with_identity(
        project,
        &["stash", "push", "-q", "-m", "synthetic stash"],
        "2026-01-03T12:00:00Z",
    );
    fs::write(project.join("staged.txt"), "selected staged content\n")
        .expect("staged change should be written");
    git(project, &["add", "staged.txt"]);
    fs::write(
        project.join("binary.dat"),
        [0_u8, 255, 16, 32, 48, 64, 80, 96],
    )
    .expect("binary worktree change should be written");
    fs::write(project.join("notes.txt"), "selected untracked content\n")
        .expect("untracked fixture should be written");
    fs::write(project.join(".env.local"), "SYNTHETIC_ONLY=true\n")
        .expect("reviewed ignored fixture should be written");
    fs::write(
        project.join(".gitignore"),
        ".env.local\nunreviewed.secret\n",
    )
    .expect("unreviewed ignore rule should be written");
    fs::write(
        project.join("unreviewed.secret"),
        "MUST_NOT_ENTER_CAPSULE\n",
    )
    .expect("unreviewed ignored fixture should be written");
    symlink("config/development.json", project.join("current-config"))
        .expect("symbolic-link fixture should be created");
    fs::create_dir_all(project.join("uploads/empty"))
        .expect("selected empty directory should be created");
    fs::write(
        project.join(".git/hooks/pre-commit"),
        "#!/bin/sh\ntouch ../hook-ran\n",
    )
    .expect("hook fixture should be written");
    fs::set_permissions(
        project.join(".git/hooks/pre-commit"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("hook fixture mode should be set");
}

fn commit(project: &Path, message: &str, date: &str) {
    git_with_identity(project, &["commit", "-q", "-m", message], date);
}

fn git_with_identity(project: &Path, arguments: &[&str], date: &str) {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(arguments)
        .env("GIT_AUTHOR_NAME", "Iniza Test")
        .env("GIT_AUTHOR_EMAIL", "iniza@example.invalid")
        .env("GIT_COMMITTER_NAME", "Iniza Test")
        .env("GIT_COMMITTER_EMAIL", "iniza@example.invalid")
        .env("GIT_AUTHOR_DATE", date)
        .env("GIT_COMMITTER_DATE", date)
        .output()
        .expect("Git fixture command should start");
    assert!(
        output.status.success(),
        "Git fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git(project: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(arguments)
        .output()
        .expect("Git fixture command should start");
    assert!(
        output.status.success(),
        "Git fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_stdout(project: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(arguments)
        .output()
        .expect("Git fixture command should start");
    assert!(
        output.status.success(),
        "Git fixture command should succeed"
    );
    String::from_utf8(output.stdout).expect("Git fixture output should be Unicode")
}

fn git_bytes(project: &Path, arguments: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(arguments)
        .output()
        .expect("Git should read restored fixture bytes");
    assert!(output.status.success(), "Git byte query should succeed");
    output.stdout
}
