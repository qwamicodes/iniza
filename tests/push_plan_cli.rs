use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    GitPublicationOperation, GitPublicationOutput, GitPublicationProcess, PlanEngine,
    ProjectAuditEngine, ProjectAuditRequest, PushPlanDraftRequest, PushPlanEngine, ScanRequest,
};

struct TestDirectory(PathBuf);

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-push-plan-cli-{}-{unique}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::SeqCst),
        ));
        fs::create_dir(&path).expect("test directory should be created");
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

#[test]
fn automation_can_approve_the_exact_immutable_push_plan_without_contacting_the_remote() {
    let directory = TestDirectory::new();
    let project = directory.path().join("private-disposable-project");
    let remote = directory.path().join("disposable-remote.git");
    let push_plan = directory.path().join("reviewed.push-plan.toml");
    let approval = directory.path().join("reviewed.push-approval.toml");
    create_ahead_project(&project, &remote);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("disposable Project should scan");
    let directory_plan_hash = plan.approval_hash().expect("Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("disposable Project should audit");
    let project_audit = audit.projects().first().expect("Project should be present");
    let draft = PushPlanEngine::with_git_publication_process(LocalGitPublication)
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &push_plan,
        ))
        .expect("fixture should produce one immutable Push Plan");

    let output = iniza(&[
        "--json",
        "projects",
        "push-plan",
        "approve",
        "--plan",
        push_plan.to_str().expect("Push Plan path should be text"),
        "--reviewed-hash",
        draft.approval_hash(),
        "--output",
        approval.to_str().expect("approval path should be text"),
        "--acknowledge-remote-side-effects",
    ]);

    assert!(
        output.status.success(),
        "exact Push Plan approval should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(approval.is_file(), "approval receipt should be written");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("machine result should be valid JavaScript Object Notation");
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["command"], "projects push-plan approve");
    assert_eq!(result["status"], "success");
    assert_eq!(result["data"]["push_plan_hash"], draft.approval_hash());
    let visible = format!(
        "{}{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(&approval).expect("approval receipt should be readable"),
    );
    assert!(!visible.contains(&project.display().to_string()));
    assert!(!visible.contains(&remote.display().to_string()));
    assert!(!visible.contains("private-disposable-project"));
}

#[test]
fn missing_remote_side_effect_acknowledgement_creates_no_push_plan_approval() {
    let directory = TestDirectory::new();
    let project = directory.path().join("private-disposable-project");
    let remote = directory.path().join("disposable-remote.git");
    let push_plan = directory.path().join("reviewed.push-plan.toml");
    let approval = directory.path().join("must-not-exist.push-approval.toml");
    create_ahead_project(&project, &remote);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("disposable Project should scan");
    let directory_plan_hash = plan.approval_hash().expect("Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("disposable Project should audit");
    let draft = PushPlanEngine::with_git_publication_process(LocalGitPublication)
        .draft(PushPlanDraftRequest::new(
            &plan,
            audit.projects().first().expect("Project should be present"),
            "origin",
            &push_plan,
        ))
        .expect("fixture should produce one immutable Push Plan");

    let output = iniza(&[
        "--json",
        "projects",
        "push-plan",
        "approve",
        "--plan",
        push_plan.to_str().expect("Push Plan path should be text"),
        "--reviewed-hash",
        draft.approval_hash(),
        "--output",
        approval.to_str().expect("approval path should be text"),
    ]);

    assert_eq!(output.status.code(), Some(10));
    assert!(!approval.exists(), "no approval receipt should be created");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("machine error should be valid JavaScript Object Notation");
    assert_eq!(result["command"], "projects push-plan approve");
    assert_eq!(result["status"], "error");
    assert_eq!(result["errors"][0]["code"], "INIZA-E010");
    assert_eq!(
        result["errors"][0]["message"],
        "Push Plan approval requires acknowledgement of remote side effects"
    );
}

#[test]
fn production_draft_command_rejects_local_transport_without_creating_a_push_plan() {
    let directory = TestDirectory::new();
    let project = directory.path().join("private-disposable-project");
    let remote = directory.path().join("disposable-remote.git");
    let directory_plan = directory.path().join("approved-directory-plan.toml");
    let push_plan = directory.path().join("must-not-exist.push-plan.toml");
    create_ahead_project(&project, &remote);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("disposable Project should scan");
    let directory_plan_hash = plan.approval_hash().expect("Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("disposable Project should audit");
    let project_identifier = audit
        .projects()
        .first()
        .expect("Project should be present")
        .id()
        .to_owned();
    plan.write_to(&directory_plan)
        .expect("approved Plan should be written");

    let output = iniza(&[
        "--json",
        "projects",
        "push-plan",
        "draft",
        "--plan",
        directory_plan.to_str().expect("Plan path should be text"),
        "--project",
        &project_identifier,
        "--output",
        push_plan.to_str().expect("Push Plan path should be text"),
    ]);

    assert_eq!(output.status.code(), Some(41));
    assert!(!push_plan.exists(), "no Push Plan should be created");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("machine error should be valid JavaScript Object Notation");
    assert_eq!(result["command"], "projects push-plan draft");
    assert_eq!(result["status"], "error");
    assert_eq!(result["errors"][0]["code"], "INIZA-E041");
    let visible = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!visible.contains(&project.display().to_string()));
    assert!(!visible.contains(&remote.display().to_string()));
    assert!(!visible.contains("private-disposable-project"));
}

fn iniza(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iniza"))
        .args(arguments)
        .output()
        .expect("iniza should run")
}

struct LocalGitPublication;

impl GitPublicationProcess for LocalGitPublication {
    fn run(
        &self,
        repository: &Path,
        operation: GitPublicationOperation<'_>,
    ) -> std::io::Result<GitPublicationOutput> {
        let mut command = Command::new("git");
        command
            .arg("-c")
            .arg("protocol.file.allow=always")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-C")
            .arg(repository);
        match operation {
            GitPublicationOperation::ReadWorkingTreeStatus => {
                command.args([
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                    "--ignore-submodules=all",
                ]);
            }
            GitPublicationOperation::ListLocalReferences => {
                command.args([
                    "for-each-ref",
                    "--format=%(objectname)%00%(refname)",
                    "refs/heads",
                    "refs/tags",
                    "refs/stash",
                ]);
            }
            GitPublicationOperation::ReadLocalReference { reference } => {
                command.args(["rev-parse", "--verify", reference.as_str()]);
            }
            GitPublicationOperation::ReadRemoteReference { remote, reference } => {
                command.args([
                    "ls-remote",
                    "--exit-code",
                    "--refs",
                    "--",
                    remote.as_str(),
                    reference.as_str(),
                ]);
            }
            GitPublicationOperation::CheckAncestor {
                ancestor,
                descendant,
            } => {
                command.args([
                    "merge-base",
                    "--is-ancestor",
                    ancestor.as_str(),
                    descendant.as_str(),
                ]);
            }
            GitPublicationOperation::PushReference { .. } => {
                panic!("approval fixture must not publish")
            }
        }
        let output = command.output()?;
        Ok(GitPublicationOutput {
            status_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

fn create_ahead_project(project: &Path, remote: &Path) {
    fs::create_dir(project).expect("Project directory should be created");
    git(project, &["init", "-q", "--initial-branch=main"]);
    git(
        remote.parent().expect("remote should have a parent"),
        &[
            "init",
            "-q",
            "--bare",
            remote.to_str().expect("remote path should be text"),
        ],
    );
    fs::write(project.join("tracked.txt"), "published base\n")
        .expect("base fixture should be written");
    git(project, &["add", "tracked.txt"]);
    commit(project, "published base", "2026-02-01T00:00:00Z");
    git(
        project,
        &[
            "remote",
            "add",
            "origin",
            remote.to_str().expect("remote path should be text"),
        ],
    );
    git(project, &["push", "-q", "-u", "origin", "main"]);
    fs::write(project.join("tracked.txt"), "approved new commit\n")
        .expect("ahead fixture should be written");
    git(project, &["add", "tracked.txt"]);
    commit(project, "approved new commit", "2026-02-02T00:00:00Z");
}

fn commit(project: &Path, message: &str, date: &str) {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(["commit", "-q", "-m", message])
        .env("GIT_AUTHOR_NAME", "Iniza Test")
        .env("GIT_AUTHOR_EMAIL", "iniza@example.invalid")
        .env("GIT_COMMITTER_NAME", "Iniza Test")
        .env("GIT_COMMITTER_EMAIL", "iniza@example.invalid")
        .env("GIT_AUTHOR_DATE", date)
        .env("GIT_COMMITTER_DATE", date)
        .output()
        .expect("Git commit should start");
    assert!(
        output.status.success(),
        "Git commit failed: {}",
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
