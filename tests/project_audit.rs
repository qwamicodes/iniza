use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use iniza::{
    GitProcess, GitProcessOutput, IgnoredReview, InstalledGit, PlanEngine, ProjectAuditEngine,
    ProjectAuditRequest, ProjectHead, ProjectKind, ProtectionRequirement, RemoteCheckOutcome,
    ScanRequest,
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
            "iniza-project-audit-{name}-{}-{unique}-{sequence}",
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

#[test]
fn approved_roots_discover_each_working_bare_nested_and_submodule_project_once() {
    let directory = TestDirectory::new("discovery");
    let approved_root = directory.path.join("approved-projects");
    let submodule_origin = directory.path.join("submodule-origin");
    fs::create_dir(&approved_root).expect("approved root should be created");

    init_repository(&approved_root.join("working"));
    init_bare_repository(&approved_root.join("archive.git"));
    let parent = approved_root.join("parent");
    init_repository(&parent);
    init_repository(&parent.join("tools/nested"));
    init_repository(&submodule_origin);
    fs::write(submodule_origin.join("README.md"), "synthetic submodule\n")
        .expect("submodule fixture should be written");
    git(&submodule_origin, &["add", "README.md"]);
    git(
        &submodule_origin,
        &[
            "-c",
            "user.name=Iniza Test",
            "-c",
            "user.email=iniza@example.invalid",
            "commit",
            "-q",
            "-m",
            "synthetic fixture",
        ],
    );
    let output = Command::new("git")
        .arg("-c")
        .arg("protocol.file.allow=always")
        .arg("-C")
        .arg(&parent)
        .arg("submodule")
        .arg("add")
        .arg("-q")
        .arg(&submodule_origin)
        .arg("vendor/child")
        .output()
        .expect("Git should add the local synthetic submodule");
    assert_command_succeeded(output, "add the local synthetic submodule");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&approved_root))
        .expect("approved project root should scan");
    let canonical_approved_root = fs::canonicalize(&approved_root)
        .expect("approved project root should have a canonical identity");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let engine = ProjectAuditEngine::local();
    let first = engine
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved root should discover Projects");
    let second = engine
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("repeated discovery should remain stable");

    let discovered = first
        .projects()
        .iter()
        .map(|project| {
            (
                project
                    .root()
                    .strip_prefix(&canonical_approved_root)
                    .expect("Project should stay under the approved root")
                    .to_path_buf(),
                project.kind(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        discovered,
        BTreeSet::from([
            (PathBuf::from("archive.git"), ProjectKind::BareRepository),
            (PathBuf::from("parent"), ProjectKind::WorkingTree),
            (
                PathBuf::from("parent/tools/nested"),
                ProjectKind::WorkingTree,
            ),
            (PathBuf::from("parent/vendor/child"), ProjectKind::Submodule,),
            (PathBuf::from("working"), ProjectKind::WorkingTree),
        ])
    );
    assert_eq!(first.projects().len(), 5, "Projects must not be duplicated");
    assert!(first.projects().iter().all(|project| {
        project.id().starts_with("project_")
            && project.protection_requirement() == ProtectionRequirement::MustProtect
    }));
    assert_eq!(
        first
            .projects()
            .iter()
            .map(|project| project.id())
            .collect::<Vec<_>>(),
        second
            .projects()
            .iter()
            .map(|project| project.id())
            .collect::<Vec<_>>(),
        "Project identities and order should be stable",
    );
}

#[test]
fn owner_sees_branch_working_tree_stash_and_local_only_branch_risk_without_a_remote_check() {
    let directory = TestDirectory::new("local-risk");
    let project_root = directory.path.join("required-project");
    let remote = directory.path.join("configured-remote.git");
    init_repository(&project_root);
    git(&project_root, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    init_bare_repository(&remote);
    fs::write(project_root.join("staged.txt"), "initial staged fixture\n")
        .expect("tracked fixture should be written");
    fs::write(
        project_root.join("unstaged.txt"),
        "initial unstaged fixture\n",
    )
    .expect("tracked fixture should be written");
    fs::write(project_root.join("stash.txt"), "initial stash fixture\n")
        .expect("stash fixture should be written");
    git(&project_root, &["add", "."]);
    commit(&project_root, "initial fixture");
    git(
        &project_root,
        &[
            "remote",
            "add",
            "origin",
            remote
                .to_str()
                .expect("remote fixture path should be Unicode"),
        ],
    );
    git(&project_root, &["push", "-q", "-u", "origin", "main"]);

    fs::write(project_root.join("ahead.txt"), "local-only commit\n")
        .expect("ahead fixture should be written");
    git(&project_root, &["add", "ahead.txt"]);
    commit(&project_root, "ahead fixture");
    git(&project_root, &["branch", "local-only"]);
    fs::write(project_root.join("stash.txt"), "stashed change\n")
        .expect("stash change should be written");
    git(
        &project_root,
        &["stash", "push", "-q", "-m", "synthetic stash"],
    );
    fs::write(project_root.join("staged.txt"), "staged change\n")
        .expect("staged change should be written");
    git(&project_root, &["add", "staged.txt"]);
    fs::write(project_root.join("unstaged.txt"), "unstaged change\n")
        .expect("unstaged change should be written");
    fs::write(project_root.join("untracked.txt"), "untracked change\n")
        .expect("untracked fixture should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let report = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("local Project audit should succeed without a remote check");
    let project = report
        .projects()
        .first()
        .expect("required Project should be reported");
    let local = project.local_state();

    assert_eq!(local.head(), &ProjectHead::Branch("main".to_owned()));
    assert_eq!(local.upstream(), Some("origin/main"));
    assert_eq!(local.ahead(), Some(1));
    assert_eq!(local.behind(), Some(0));
    assert_eq!(local.staged_changes(), 1);
    assert_eq!(local.unstaged_changes(), 1);
    assert_eq!(local.untracked_items(), 1);
    assert_eq!(local.stash_count(), 1);
    assert_eq!(local.local_only_branches(), &["local-only"]);
}

#[test]
fn configured_remote_addresses_are_reported_without_credentials_or_sensitive_query_values() {
    let directory = TestDirectory::new("sanitized-remotes");
    let project_root = directory.path.join("private-project");
    init_repository(&project_root);
    git(
        &project_root,
        &[
            "remote",
            "add",
            "origin",
            "https://alice:correct-horse@example.invalid/private/repository.git?token=top-secret&ref=main#credential-fragment",
        ],
    );
    git(
        &project_root,
        &[
            "remote",
            "add",
            "mirror",
            "git@example.invalid:private/mirror.git",
        ],
    );

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("private Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let report = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("configured remotes should audit without network access");
    let remotes = report.projects()[0]
        .remotes()
        .iter()
        .map(|remote| (remote.name(), remote.address()))
        .collect::<Vec<_>>();

    assert_eq!(
        remotes,
        vec![
            ("mirror", "example.invalid:private/mirror.git"),
            ("origin", "https://example.invalid/private/repository.git"),
        ]
    );
    let debug = format!("{report:?}");
    for forbidden in [
        "alice",
        "correct-horse",
        "token",
        "top-secret",
        "credential-fragment",
    ] {
        assert!(
            !debug.contains(forbidden),
            "sanitized Project report must omit {forbidden}",
        );
    }
}

#[test]
fn local_filesystem_remote_locations_are_redacted_from_reports() {
    let directory = TestDirectory::new("local-remote-redaction");
    let project_root = directory.path.join("private-project");
    let local_remote = directory.path.join("private-location/repository.git");
    init_repository(&project_root);
    git(
        &project_root,
        &[
            "remote",
            "add",
            "origin",
            local_remote
                .to_str()
                .expect("local remote fixture path should be Unicode"),
        ],
    );

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("private Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let report = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("local remote should audit without disclosing its path");

    assert_eq!(
        report.projects()[0].remotes()[0].address(),
        "local-path:[redacted]"
    );
    assert!(
        !report
            .machine_json_result()
            .contains(&local_remote.display().to_string())
    );
}

#[test]
fn ignored_content_separates_regenerable_output_from_state_that_requires_review() {
    let directory = TestDirectory::new("ignored-review");
    let project_root = directory.path.join("required-project");
    init_repository(&project_root);
    fs::write(
        project_root.join(".gitignore"),
        "node_modules/\ntarget/\n.env\nlocal.db\nuploads/\ncertificate.pem\nsettings.local.json\nscratch.log\n",
    )
    .expect("ignore rules should be written");
    write_fixture(&project_root.join("node_modules/package/index.js"));
    write_fixture(&project_root.join("target/debug/application"));
    write_fixture(&project_root.join(".env"));
    write_fixture(&project_root.join("local.db"));
    write_fixture(&project_root.join("uploads/avatar.png"));
    write_fixture(&project_root.join("certificate.pem"));
    write_fixture(&project_root.join("settings.local.json"));
    write_fixture(&project_root.join("scratch.log"));

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let report = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("ignored Project content should audit locally");
    let ignored = report.projects()[0]
        .ignored_candidates()
        .iter()
        .map(|candidate| (candidate.relative_path(), candidate.review()))
        .collect::<BTreeSet<_>>();

    assert_eq!(
        ignored,
        BTreeSet::from([
            (Path::new(".env"), IgnoredReview::RequiresReview),
            (Path::new("certificate.pem"), IgnoredReview::RequiresReview,),
            (Path::new("local.db"), IgnoredReview::RequiresReview),
            (
                Path::new("node_modules/package/index.js"),
                IgnoredReview::SuggestedExclusion,
            ),
            (Path::new("scratch.log"), IgnoredReview::RequiresReview),
            (
                Path::new("settings.local.json"),
                IgnoredReview::RequiresReview,
            ),
            (
                Path::new("target/debug/application"),
                IgnoredReview::SuggestedExclusion,
            ),
            (
                Path::new("uploads/avatar.png"),
                IgnoredReview::RequiresReview,
            ),
        ])
    );
}

#[test]
fn project_audit_reports_submodules_and_git_large_file_storage_indicators_without_fetching() {
    let directory = TestDirectory::new("submodule-large-file-storage");
    let project_root = directory.path.join("required-project");
    let submodule_origin = directory.path.join("submodule-origin");
    init_repository(&project_root);
    init_repository(&submodule_origin);
    fs::write(submodule_origin.join("README.md"), "synthetic submodule\n")
        .expect("submodule fixture should be written");
    git(&submodule_origin, &["add", "README.md"]);
    commit(&submodule_origin, "submodule fixture");
    let output = Command::new("git")
        .arg("-c")
        .arg("protocol.file.allow=always")
        .arg("-C")
        .arg(&project_root)
        .arg("submodule")
        .arg("add")
        .arg("-q")
        .arg(&submodule_origin)
        .arg("vendor/child")
        .output()
        .expect("Git should add the local synthetic submodule");
    assert_command_succeeded(output, "add the local synthetic submodule");
    fs::write(
        project_root.join(".gitattributes"),
        "*.bin filter=lfs diff=lfs merge=lfs -text\n",
    )
    .expect("Git Large File Storage attributes should be written");
    fs::write(
        project_root.join("model.bin"),
        "version https://git-lfs.github.com/spec/v1\noid sha256:8c7dd922ad47494fc02c388e12c00eac39d5e14fbbbaa7c65a8bb296951c07c3\nsize 12345\n",
    )
    .expect("Git Large File Storage pointer should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let report = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("submodule and Git Large File Storage indicators should audit locally");
    let canonical_root =
        fs::canonicalize(&project_root).expect("required Project should have a canonical identity");
    let project = report
        .projects()
        .iter()
        .find(|project| project.root() == canonical_root)
        .expect("parent Project should be reported");

    assert_eq!(project.submodules().len(), 1);
    assert_eq!(
        project.submodules()[0].relative_path(),
        Path::new("vendor/child")
    );
    assert!(project.submodules()[0].initialized());
    assert!(project.git_large_file_storage().configured());
    assert_eq!(project.git_large_file_storage().pointer_files(), 1);
}

#[test]
fn explicit_remote_check_identifies_reachable_remote_and_genuinely_local_only_tags() {
    let directory = TestDirectory::new("remote-check");
    let project_root = directory.path.join("required-project");
    init_repository(&project_root);
    fs::write(project_root.join("README.md"), "synthetic Project\n")
        .expect("Project fixture should be written");
    git(&project_root, &["add", "README.md"]);
    commit(&project_root, "Project fixture");
    git(&project_root, &["tag", "published"]);
    git(&project_root, &["tag", "local-only"]);
    git(
        &project_root,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/private/repository.git",
        ],
    );

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let git = ScriptedRemoteGit {
        installed: InstalledGit::default(),
        remote_status: 0,
        remote_stdout: b"0123456789012345678901234567890123456789\trefs/tags/published\n".to_vec(),
        remote_stderr: Vec::new(),
    };

    let report = ProjectAuditEngine::with_git_process(git)
        .audit(ProjectAuditRequest::from_plan(&plan).with_remote_check())
        .expect("explicit remote check should preserve the local Project audit");
    let project = &report.projects()[0];

    assert_eq!(
        project.remotes()[0].check_outcome(),
        &RemoteCheckOutcome::Reachable
    );
    assert_eq!(project.local_state().local_only_tags(), &["local-only"]);
}

#[test]
fn generated_dependency_and_build_trees_do_not_create_accidental_projects() {
    let directory = TestDirectory::new("generated-projects");
    let approved_root = directory.path.join("approved-projects");
    init_repository(&approved_root.join("owner-project"));
    init_repository(&approved_root.join("node_modules/dependency"));
    init_repository(&approved_root.join("target/generated-repository"));

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&approved_root))
        .expect("approved project root should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let report = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("generated trees should be skipped safely");

    assert_eq!(report.projects().len(), 1);
    assert_eq!(
        report.projects()[0]
            .root()
            .file_name()
            .and_then(|value| value.to_str()),
        Some("owner-project")
    );
}

#[test]
fn repository_change_during_audit_is_reported_as_changed_and_unverified() {
    let directory = TestDirectory::new("changing-repository");
    let project_root = directory.path.join("required-project");
    init_repository(&project_root);
    fs::write(project_root.join("README.md"), "synthetic Project\n")
        .expect("Project fixture should be written");
    git(&project_root, &["add", "README.md"]);
    commit(&project_root, "Project fixture");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let changing_git = ChangingStatusGit {
        installed: InstalledGit::default(),
        status_calls: AtomicU64::new(0),
    };

    let report = ProjectAuditEngine::with_git_process(changing_git)
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("changing Project should remain visible in the report");
    let project = &report.projects()[0];

    assert!(project.changed_during_audit());
    assert!(!project.local_audit_verified());
}

#[test]
fn failed_remote_check_keeps_verified_local_evidence_and_discards_hostile_error_text() {
    let directory = TestDirectory::new("failed-remote-check");
    let project_root = directory.path.join("required-project");
    init_repository(&project_root);
    fs::write(project_root.join("tracked.txt"), "initial content\n")
        .expect("Project fixture should be written");
    git(&project_root, &["add", "tracked.txt"]);
    commit(&project_root, "Project fixture");
    fs::write(project_root.join("tracked.txt"), "staged local content\n")
        .expect("staged Project fixture should be written");
    git(&project_root, &["add", "tracked.txt"]);
    git(
        &project_root,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/private/repository.git",
        ],
    );

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let git = ScriptedRemoteGit {
        installed: InstalledGit::default(),
        remote_status: 128,
        remote_stdout: Vec::new(),
        remote_stderr: b"fatal: token=credential-marker-4f91 authentication failed\n".to_vec(),
    };

    let report = ProjectAuditEngine::with_git_process(git)
        .audit(ProjectAuditRequest::from_plan(&plan).with_remote_check())
        .expect("remote failure must not erase the local Project audit");
    let project = &report.projects()[0];

    assert_eq!(
        project.remotes()[0].check_outcome(),
        &RemoteCheckOutcome::Failed {
            code: "remote-check-failed".to_owned(),
        }
    );
    assert!(project.local_audit_verified());
    assert_eq!(project.local_state().staged_changes(), 1);
    assert!(!format!("{report:?}").contains("credential-marker-4f91"));
}

#[cfg(unix)]
#[test]
fn installed_git_adapter_uses_direct_arguments_controlled_prompting_and_a_cleared_environment() {
    let directory = TestDirectory::new("installed-git-safety");
    let executable = directory.path.join("synthetic-git");
    let captured_arguments = directory.path.join("arguments.bin");
    let captured_environment = directory.path.join("environment.txt");
    let shell_marker = directory.path.join("shell-interpolation-must-not-run");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\0' \"$@\" > '{}'\nenv > '{}'\nprintf 'synthetic output'\n",
        captured_arguments.display(),
        captured_environment.display(),
    );
    fs::write(&executable, script).expect("synthetic Git executable should be written");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("synthetic Git executable should become executable");
    let repository = directory.path.join("repository; hostile name");
    fs::create_dir(&repository).expect("hostile-named repository directory should be created");
    let malicious_argument = format!("$(touch {})", shell_marker.display());
    let adapter = InstalledGit::with_executable(&executable);

    let output = adapter
        .run(
            &repository,
            &[
                OsString::from("status"),
                OsString::from(&malicious_argument),
            ],
        )
        .expect("synthetic Git executable should run directly");

    assert_eq!(output.status_code, Some(0));
    assert_eq!(output.stdout, b"synthetic output");
    assert!(
        !shell_marker.exists(),
        "arguments must never be shell-evaluated"
    );
    let arguments = fs::read(&captured_arguments)
        .expect("captured direct arguments should be readable")
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8_lossy(argument).into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        arguments,
        vec![
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "color.ui=false",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.ssh.allow=always",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.git.allow=never",
            "-c",
            "core.sshCommand=/usr/bin/ssh",
            "-C",
            repository.to_str().expect("fixture path should be Unicode"),
            "status",
            &malicious_argument,
        ]
    );
    let environment = fs::read_to_string(&captured_environment)
        .expect("captured controlled environment should be readable");
    for expected in [
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_OPTIONAL_LOCKS=0",
        "GIT_TERMINAL_PROMPT=0",
        "GCM_INTERACTIVE=Never",
        "LC_ALL=C",
    ] {
        assert!(environment.lines().any(|line| line == expected));
    }
    assert!(!environment.lines().any(|line| line.starts_with("HOME=")));
}

#[cfg(unix)]
#[test]
fn installed_git_adapter_rejects_oversized_command_output() {
    let directory = TestDirectory::new("installed-git-output-limit");
    let executable = directory.path.join("synthetic-git");
    fs::write(
        &executable,
        "#!/bin/sh\n/bin/dd if=/dev/zero bs=1048576 count=2 2>/dev/null\n",
    )
    .expect("synthetic Git executable should be written");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("synthetic Git executable should become executable");
    let repository = directory.path.join("repository");
    fs::create_dir(&repository).expect("synthetic repository directory should be created");

    let error = InstalledGit::with_executable(&executable)
        .run(&repository, &[OsString::from("status")])
        .expect_err("oversized Git output must fail closed");

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "Git command output exceeded the safe limit"
    );
}

#[cfg(unix)]
#[test]
fn hostile_git_transport_configuration_cannot_execute_a_local_program() {
    let directory = TestDirectory::new("hostile-transport");
    let project_root = directory.path.join("required-project");
    let malicious_helper = directory.path.join("malicious-remote-helper");
    let execution_marker = directory.path.join("helper-must-not-run");
    init_repository(&project_root);
    fs::write(
        &malicious_helper,
        format!(
            "#!/bin/sh\ntouch '{}'\nexit 1\n",
            execution_marker.display()
        ),
    )
    .expect("malicious helper fixture should be written");
    fs::set_permissions(&malicious_helper, fs::Permissions::from_mode(0o700))
        .expect("malicious helper fixture should become executable");
    git(&project_root, &["config", "protocol.ext.allow", "always"]);
    let hostile_address = format!("ext::{}", malicious_helper.display());
    git(
        &project_root,
        &["remote", "add", "origin", &hostile_address],
    );

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let report = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan).with_remote_check())
        .expect("hostile remote configuration should fail closed inside the report");

    assert!(
        !execution_marker.exists(),
        "external transport helper must not run"
    );
    assert!(matches!(
        report.projects()[0].remotes()[0].check_outcome(),
        RemoteCheckOutcome::Failed { .. }
    ));
}

#[test]
fn human_and_machine_reports_separately_explain_restorable_and_synchronized_gaps() {
    let directory = TestDirectory::new("readiness-gaps");
    let project_root = directory.path.join("private-required-project");
    init_repository(&project_root);
    fs::write(
        project_root.join("private-notes.txt"),
        "protected source marker 5dd982\n",
    )
    .expect("private fixture should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let report = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("required Project should audit locally");
    let human = report.to_human_text();
    let machine = report.machine_json_result();

    assert!(
        human.contains(
            &fs::canonicalize(&project_root)
                .unwrap()
                .display()
                .to_string()
        )
    );
    assert!(human.contains("Restorable gap:"));
    assert!(human.contains("Synchronized gap:"));
    assert_eq!(machine.lines().count(), 1);
    let value: serde_json::Value = serde_json::from_str(&machine)
        .expect("machine report should be valid JavaScript Object Notation");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "projects scan");
    assert_eq!(value["status"], "success-with-gaps");
    assert_eq!(value["data"]["projects"][0]["restorable"]["state"], "gap");
    assert_eq!(value["data"]["projects"][0]["synchronized"]["state"], "gap");
    assert!(value["data"]["projects"][0]["project_id"].is_string());
    assert!(!machine.contains(&project_root.display().to_string()));
    assert!(!machine.contains("private-notes.txt"));
    assert!(!machine.contains("protected source marker 5dd982"));
}

#[test]
fn human_report_neutralizes_terminal_controls_in_repository_and_ignored_names() {
    let directory = TestDirectory::new("hostile-rendering");
    let project_root = directory.path.join("required\u{1b}[31m-project");
    init_repository(&project_root);
    fs::write(project_root.join(".gitignore"), "ignored-*.txt\n")
        .expect("synthetic ignore rule should be written");
    fs::write(
        project_root.join("ignored-\u{1b}[2J.txt"),
        "synthetic ignored content\n",
    )
    .expect("hostile ignored fixture should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("hostile-named Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let human = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("hostile names should remain reportable")
        .to_human_text();

    assert!(!human.contains('\u{1b}'));
    assert!(human.contains("required�[31m-project"));
    assert!(human.contains("ignored-�[2J.txt"));
}

#[test]
fn default_project_audit_never_attempts_a_remote_command() {
    let directory = TestDirectory::new("no-network-default");
    let project_root = directory.path.join("required-project");
    init_repository(&project_root);
    git(
        &project_root,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/private/repository.git",
        ],
    );
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let git = NetworkRejectingGit {
        installed: InstalledGit::default(),
        remote_attempts: AtomicU64::new(0),
    };

    let report = ProjectAuditEngine::with_git_process(git)
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("default local audit should not need a remote");

    assert_eq!(
        report.projects()[0].remotes()[0].check_outcome(),
        &RemoteCheckOutcome::NotRequested
    );
}

struct NetworkRejectingGit {
    installed: InstalledGit,
    remote_attempts: AtomicU64,
}

impl GitProcess for NetworkRejectingGit {
    fn run(&self, repository: &Path, arguments: &[OsString]) -> io::Result<GitProcessOutput> {
        if arguments.first().and_then(|value| value.to_str()) == Some("ls-remote") {
            self.remote_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(io::Error::other("unexpected synthetic network attempt"));
        }
        self.installed.run(repository, arguments)
    }
}

#[test]
fn project_requirement_is_inherited_from_the_reviewed_plan() {
    let directory = TestDirectory::new("project-requirement");
    let approved_root = directory.path.join("approved-projects");
    init_repository(&approved_root.join("must-protect"));
    init_repository(&approved_root.join("optional"));
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&approved_root).mark_optional("optional"))
        .expect("approved project root should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let report = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("Project requirements should audit from the Plan");
    let mut requirements = report
        .projects()
        .iter()
        .map(|project| {
            (
                project
                    .root()
                    .file_name()
                    .and_then(|value| value.to_str())
                    .expect("fixture Project name should be text"),
                project.protection_requirement(),
            )
        })
        .collect::<Vec<_>>();
    requirements.sort_by_key(|(name, _)| *name);

    assert_eq!(
        requirements,
        vec![
            ("must-protect", ProtectionRequirement::MustProtect),
            ("optional", ProtectionRequirement::Optional),
        ]
    );
}

#[test]
fn detached_head_is_reported_without_changing_repository_state() {
    let directory = TestDirectory::new("detached-head");
    let project_root = directory.path.join("required-project");
    init_repository(&project_root);
    fs::write(project_root.join("README.md"), "synthetic Project\n")
        .expect("Project fixture should be written");
    git(&project_root, &["add", "README.md"]);
    commit(&project_root, "Project fixture");
    let commit_id = git_stdout(&project_root, &["rev-parse", "HEAD"]);
    git(&project_root, &["checkout", "-q", "--detach", "HEAD"]);
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let report = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("detached Project should audit without checkout");

    assert_eq!(
        report.projects()[0].local_state().head(),
        &ProjectHead::Detached(commit_id)
    );
    assert_eq!(
        git_stdout(&project_root, &["rev-parse", "--abbrev-ref", "HEAD"]),
        "HEAD"
    );
}

struct ChangingStatusGit {
    installed: InstalledGit,
    status_calls: AtomicU64,
}

impl GitProcess for ChangingStatusGit {
    fn run(&self, repository: &Path, arguments: &[OsString]) -> io::Result<GitProcessOutput> {
        let mut output = self.installed.run(repository, arguments)?;
        if arguments.first().and_then(|value| value.to_str()) == Some("status")
            && self.status_calls.fetch_add(1, Ordering::SeqCst) > 0
        {
            output
                .stdout
                .extend_from_slice(b"?? changed-during-audit\0");
        }
        Ok(output)
    }
}

struct ScriptedRemoteGit {
    installed: InstalledGit,
    remote_status: i32,
    remote_stdout: Vec<u8>,
    remote_stderr: Vec<u8>,
}

impl GitProcess for ScriptedRemoteGit {
    fn run(&self, repository: &Path, arguments: &[OsString]) -> io::Result<GitProcessOutput> {
        if arguments.first().and_then(|value| value.to_str()) == Some("ls-remote") {
            return Ok(GitProcessOutput {
                status_code: Some(self.remote_status),
                stdout: self.remote_stdout.clone(),
                stderr: self.remote_stderr.clone(),
            });
        }
        self.installed.run(repository, arguments)
    }
}

fn init_repository(path: &Path) {
    fs::create_dir_all(path).expect("repository directory should be created");
    git(path, &["init", "-q"]);
}

fn write_fixture(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("fixture parent should be created");
    }
    fs::write(path, "synthetic ignored content\n").expect("ignored fixture should be written");
}

fn init_bare_repository(path: &Path) {
    fs::create_dir_all(path).expect("bare repository directory should be created");
    git(path, &["init", "--bare", "-q"]);
}

fn commit(repository: &Path, message: &str) {
    git(
        repository,
        &[
            "-c",
            "user.name=Iniza Test",
            "-c",
            "user.email=iniza@example.invalid",
            "commit",
            "-q",
            "-m",
            message,
        ],
    );
}

fn git(directory: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .expect("Git fixture command should start");
    assert_command_succeeded(output, &format!("run git {}", arguments.join(" ")));
}

fn git_stdout(directory: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .expect("Git fixture command should start");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert_command_succeeded(output, &format!("run git {}", arguments.join(" ")));
    stdout
}

fn assert_command_succeeded(output: std::process::Output, action: &str) {
    assert!(
        output.status.success(),
        "Git should {action}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
