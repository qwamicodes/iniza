use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    GitObjectIdentifier, GitProcess, GitProcessOutput, GitPublicationOperation,
    GitPublicationOutput, GitPublicationProcess, GitReference, GitRemoteName,
    InstalledGitPublication, PlanEngine, ProjectAuditEngine, ProjectAuditRequest,
    PushExecutionState, PushPlanApprovalRequest, PushPlanDraftRequest, PushPlanEngine,
    PushPlanExecutionRequest, ScanRequest,
};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn publication_capabilities_cannot_represent_force_deletion_or_option_injection() {
    assert!(GitReference::parse("+refs/heads/main").is_err());
    assert!(GitReference::parse(":refs/heads/main").is_err());
    assert!(GitReference::parse("refs/heads/*").is_err());
    assert!(GitReference::parse("--force").is_err());
    assert!(GitRemoteName::parse("--upload-pack=hostile").is_err());
    assert!(GitObjectIdentifier::parse("--help").is_err());

    assert_eq!(
        GitReference::parse("refs/heads/main")
            .expect("safe reference should parse")
            .as_str(),
        "refs/heads/main"
    );
}

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
            "iniza-push-plan-{name}-{}-{unique}-{sequence}",
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
fn exact_approved_existing_upstream_action_publishes_without_changing_local_project_state() {
    let directory = TestDirectory::new("existing-upstream");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let push_plan = directory.path.join("publication.push-plan");
    let approval = directory.path.join("publication.push-approval");
    let result_document = directory.path.join("publication.push-result");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);
    let expected_old_remote = git_stdout(&remote, &["rev-parse", "refs/heads/main"]);
    let proposed_new_remote = git_stdout(&project, &["rev-parse", "refs/heads/main"]);
    let status_before = git_bytes(
        &project,
        &["status", "--porcelain=v2", "-z", "--untracked-files=all"],
    );

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");
    let engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);

    let draft = engine
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &push_plan,
        ))
        .expect("existing upstream ahead action should draft");
    assert_eq!(draft.actions().len(), 1);
    let action = &draft.actions()[0];
    assert_eq!(action.local_reference(), "refs/heads/main");
    assert_eq!(action.remote_reference(), "refs/heads/main");
    assert_eq!(
        action.expected_old_remote_object(),
        expected_old_remote.trim()
    );
    assert_eq!(
        action.proposed_new_remote_object(),
        proposed_new_remote.trim()
    );
    assert!(action.is_non_force());
    let document = fs::read_to_string(&push_plan).expect("Push Plan should be reviewable text");
    assert!(document.contains("policy = \"non-force-only\""));
    assert!(!document.contains("force ="));
    assert!(!document.contains("owner-project"));
    assert!(!document.contains("owner-remote"));
    assert!(!document.contains(&project.to_string_lossy().to_string()));
    assert!(!document.contains(&remote.to_string_lossy().to_string()));
    let document_value: toml::Value = toml::from_str(&document).expect("Push Plan should be TOML");
    let created = document_value["created_unix_seconds"]
        .as_integer()
        .expect("Push Plan should record creation time");
    let expires = document_value["expires_unix_seconds"]
        .as_integer()
        .expect("Push Plan should record expiry time");
    assert!(expires > created);
    assert!(expires - created <= 15 * 60);
    assert!(
        draft
            .warning()
            .contains("continuous integration, deployments, and notifications")
    );

    let wrong_hash_receipt = directory.path.join("wrong-hash.push-approval");
    let wrong_hash = engine.approve(
        PushPlanApprovalRequest::new(&push_plan, &directory_plan_hash, &wrong_hash_receipt)
            .acknowledge_remote_side_effects(),
    );
    assert!(
        wrong_hash.is_err(),
        "a directory Plan hash must not approve publication"
    );
    assert!(!wrong_hash_receipt.exists());
    let missing_ack_receipt = directory.path.join("missing-ack.push-approval");
    let missing_ack = engine.approve(PushPlanApprovalRequest::new(
        &push_plan,
        draft.approval_hash(),
        &missing_ack_receipt,
    ));
    assert!(
        missing_ack.is_err(),
        "approval requires an explicit side-effect acknowledgement"
    );
    assert!(!missing_ack_receipt.exists());

    let push_approval = engine
        .approve(
            PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &approval)
                .acknowledge_remote_side_effects(),
        )
        .expect("exact reviewed Push Plan should approve separately");
    assert_eq!(push_approval.push_plan_hash(), draft.approval_hash());
    assert_ne!(push_approval.push_plan_hash(), directory_plan_hash);
    let approval_document =
        fs::read_to_string(&approval).expect("approval receipt should be reviewable text");
    let approval_value: toml::Value =
        toml::from_str(&approval_document).expect("approval receipt should be TOML");
    assert!(
        approval_value["approved_unix_seconds"]
            .as_integer()
            .is_some()
    );
    assert!(
        approval_value["receipt_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("push_receipt_") && id.len() == 45)
    );
    assert!(!approval_document.contains("owner-project"));
    assert!(!approval_document.contains("owner-remote"));
    assert!(!approval_document.contains(&project.to_string_lossy().to_string()));
    assert!(!approval_document.contains(&remote.to_string_lossy().to_string()));

    let execution = engine
        .execute(PushPlanExecutionRequest::new(
            &plan,
            project_audit,
            &push_plan,
            &approval,
            &result_document,
        ))
        .expect("unchanged exact action should publish");
    assert_eq!(execution.state(), PushExecutionState::Complete);
    assert_eq!(execution.succeeded_actions(), 1);
    assert_eq!(execution.failed_actions(), 0);
    assert_eq!(
        git_stdout(&remote, &["rev-parse", "refs/heads/main"]).trim(),
        proposed_new_remote.trim()
    );
    assert_eq!(
        git_bytes(
            &project,
            &["status", "--porcelain=v2", "-z", "--untracked-files=all"],
        ),
        status_before,
        "publication must not change staged, unstaged, or untracked local state"
    );
    assert!(!hook_sentinel.exists(), "the pre-push hook must not run");
    assert!(result_document.is_file());
    let durable_result =
        fs::read_to_string(&result_document).expect("partial result log should be readable");
    assert!(!durable_result.contains("SECRET-RAW-GIT-ERROR"));
    assert!(!durable_result.contains(&project.to_string_lossy().to_string()));
    assert!(!durable_result.contains(&remote.to_string_lossy().to_string()));
    for output in [execution.human_result(), execution.machine_json_result()] {
        assert!(!output.contains(&project.to_string_lossy().to_string()));
        assert!(!output.contains(&remote.to_string_lossy().to_string()));
        assert!(!output.contains("owner-project"));
        assert!(!output.contains("owner-remote"));
    }
}

#[test]
fn remote_change_after_approval_is_contained_as_partial_without_publication_attempt() {
    let directory = TestDirectory::new("stale-remote");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let push_plan = directory.path.join("publication.push-plan");
    let approval = directory.path.join("publication.push-approval");
    let result_document = directory.path.join("publication.push-result");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");
    let engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);

    let draft = engine
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &push_plan,
        ))
        .expect("existing upstream action should draft");
    engine
        .approve(
            PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &approval)
                .acknowledge_remote_side_effects(),
        )
        .expect("Push Plan should approve");

    git(
        &project,
        &[
            "push",
            "--no-verify",
            "origin",
            "refs/heads/main:refs/heads/replacement",
        ],
    );
    let changed_remote_object = git_stdout(&remote, &["rev-parse", "refs/heads/replacement"]);
    git(
        &remote,
        &[
            "update-ref",
            "refs/heads/main",
            changed_remote_object.trim(),
        ],
    );

    let execution = engine
        .execute(PushPlanExecutionRequest::new(
            &plan,
            project_audit,
            &push_plan,
            &approval,
            &result_document,
        ))
        .expect("stale remote state should produce a contained partial result");

    assert_eq!(execution.state(), PushExecutionState::Partial);
    assert_eq!(execution.succeeded_actions(), 0);
    assert_eq!(execution.failed_actions(), 1);
    assert_eq!(
        git_stdout(&remote, &["rev-parse", "refs/heads/main"]).trim(),
        changed_remote_object.trim(),
        "Iniza must not overwrite a changed remote reference"
    );
    assert!(!hook_sentinel.exists(), "no publication attempt should run");
    assert!(
        result_document.is_file(),
        "partial evidence must be durable"
    );
    let durable_result =
        fs::read_to_string(&result_document).expect("partial result should be reviewable text");
    assert!(durable_result.contains("\"outcome_code\":\"remote-reference-changed\""));
    assert!(!durable_result.contains(changed_remote_object.trim()));
    for output in [execution.human_result(), execution.machine_json_result()] {
        assert!(!output.contains(&project.to_string_lossy().to_string()));
        assert!(!output.contains(&remote.to_string_lossy().to_string()));
        assert!(!output.contains("owner-project"));
        assert!(!output.contains("owner-remote"));
        assert!(!output.contains(changed_remote_object.trim()));
    }
}

#[test]
fn rejected_publication_is_recorded_as_sanitized_partial_evidence() {
    let directory = TestDirectory::new("rejected-publication");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let push_plan = directory.path.join("publication.push-plan");
    let approval = directory.path.join("publication.push-approval");
    let result_document = directory.path.join("publication.push-result");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);
    let remote_before = git_stdout(&remote, &["rev-parse", "refs/heads/main"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");
    let local_engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);
    let draft = local_engine
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &push_plan,
        ))
        .expect("existing upstream action should draft");
    local_engine
        .approve(
            PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &approval)
                .acknowledge_remote_side_effects(),
        )
        .expect("Push Plan should approve");

    let execution = PushPlanEngine::with_git_publication_process(RejectingPushGit)
        .execute(PushPlanExecutionRequest::new(
            &plan,
            project_audit,
            &push_plan,
            &approval,
            &result_document,
        ))
        .expect("a rejected push should produce contained partial evidence");

    assert_eq!(execution.state(), PushExecutionState::Partial);
    assert_eq!(execution.succeeded_actions(), 0);
    assert_eq!(execution.failed_actions(), 1);
    assert_eq!(
        git_stdout(&remote, &["rev-parse", "refs/heads/main"]).trim(),
        remote_before.trim()
    );
    assert!(result_document.is_file());
    for output in [execution.human_result(), execution.machine_json_result()] {
        assert!(!output.contains("SECRET-RAW-GIT-ERROR"));
        assert!(!output.contains(&project.to_string_lossy().to_string()));
        assert!(!output.contains(&remote.to_string_lossy().to_string()));
    }
}

#[test]
fn new_remote_branch_requires_exact_item_approval_before_publication() {
    let directory = TestDirectory::new("new-branch");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let push_plan = directory.path.join("publication.push-plan");
    let rejected_approval = directory.path.join("rejected.push-approval");
    let approval = directory.path.join("publication.push-approval");
    let result_document = directory.path.join("publication.push-result");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);
    git(&project, &["branch", "feature/local-only"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan).with_remote_check())
        .expect("approved Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");
    let engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);

    let draft = engine
        .draft(
            PushPlanDraftRequest::new(&plan, project_audit, "origin", &push_plan)
                .include_new_reference("refs/heads/feature/local-only"),
        )
        .expect("selected local-only branch should draft");
    let new_branch = draft
        .actions()
        .iter()
        .find(|action| action.action_class() == "new-remote-branch")
        .expect("new branch should be a distinct action");
    assert!(new_branch.requires_item_approval());
    assert_eq!(new_branch.expected_old_remote_object(), "absent");

    let missing_item_approval = engine.approve(
        PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &rejected_approval)
            .acknowledge_remote_side_effects(),
    );
    assert!(missing_item_approval.is_err());
    assert!(!rejected_approval.exists());

    engine
        .approve(
            PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &approval)
                .approve_action(new_branch.action_id())
                .acknowledge_remote_side_effects(),
        )
        .expect("exact new-branch action approval should be accepted");
    let execution = engine
        .execute(PushPlanExecutionRequest::new(
            &plan,
            project_audit,
            &push_plan,
            &approval,
            &result_document,
        ))
        .expect("approved existing and new branch actions should publish");

    assert_eq!(execution.state(), PushExecutionState::Complete);
    assert_eq!(execution.succeeded_actions(), 2);
    assert_eq!(execution.failed_actions(), 0);
    assert_eq!(
        git_stdout(&remote, &["rev-parse", "refs/heads/feature/local-only"]).trim(),
        git_stdout(&project, &["rev-parse", "refs/heads/feature/local-only"]).trim()
    );
    assert!(!hook_sentinel.exists());
}

#[test]
fn selected_new_branch_can_be_the_only_action_when_current_upstream_is_synchronized() {
    let directory = TestDirectory::new("only-new-branch");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let push_plan = directory.path.join("publication.push-plan");
    let approval = directory.path.join("publication.push-approval");
    let result_document = directory.path.join("publication.push-result");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);
    git(&project, &["push", "--no-verify", "origin", "main"]);
    git(&project, &["branch", "feature/local-only"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("synchronized Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");
    let engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);
    let draft = engine
        .draft(
            PushPlanDraftRequest::new(&plan, project_audit, "origin", &push_plan)
                .include_new_reference("refs/heads/feature/local-only"),
        )
        .expect("selected local-only branch should draft without an upstream action");

    assert_eq!(draft.actions().len(), 1);
    assert_eq!(draft.actions()[0].action_class(), "new-remote-branch");
    engine
        .approve(
            PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &approval)
                .approve_action(draft.actions()[0].action_id())
                .acknowledge_remote_side_effects(),
        )
        .expect("new branch action should approve");
    let execution = engine
        .execute(PushPlanExecutionRequest::new(
            &plan,
            project_audit,
            &push_plan,
            &approval,
            &result_document,
        ))
        .expect("new branch should publish");

    assert_eq!(execution.state(), PushExecutionState::Complete);
    assert_eq!(execution.succeeded_actions(), 1);
    assert!(!hook_sentinel.exists());
}

#[test]
fn each_successful_action_is_synchronized_before_the_next_publication_attempt() {
    let directory = TestDirectory::new("durable-partial-results");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let push_plan = directory.path.join("publication.push-plan");
    let approval = directory.path.join("publication.push-approval");
    let result_document = directory.path.join("publication.push-result");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);
    git(&project, &["branch", "feature/local-only"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");
    let local_engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);
    let draft = local_engine
        .draft(
            PushPlanDraftRequest::new(&plan, project_audit, "origin", &push_plan)
                .include_new_reference("refs/heads/feature/local-only"),
        )
        .expect("two-action Push Plan should draft");
    let new_branch = draft
        .actions()
        .iter()
        .find(|action| action.action_class() == "new-remote-branch")
        .expect("new branch action should exist");
    let first_action_id = draft.actions()[0].action_id().to_owned();
    local_engine
        .approve(
            PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &approval)
                .approve_action(new_branch.action_id())
                .acknowledge_remote_side_effects(),
        )
        .expect("two-action Push Plan should approve");

    let interruption = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = PushPlanEngine::with_git_publication_process(CrashBeforeSecondPushGit {
            push_calls: AtomicU64::new(0),
        })
        .execute(PushPlanExecutionRequest::new(
            &plan,
            project_audit,
            &push_plan,
            &approval,
            &result_document,
        ));
    }));

    assert!(
        interruption.is_err(),
        "fixture should stop before action two"
    );
    let durable_result = fs::read_to_string(&result_document)
        .expect("action one evidence must exist before action two starts");
    assert!(durable_result.contains(&first_action_id));
    assert!(durable_result.contains("\"state\":\"succeeded\""));
    assert_eq!(
        git_stdout(&remote, &["rev-parse", "refs/heads/main"]).trim(),
        git_stdout(&project, &["rev-parse", "refs/heads/main"]).trim()
    );
    let feature_remote = Command::new("git")
        .arg("-C")
        .arg(&remote)
        .args(["rev-parse", "--verify", "refs/heads/feature/local-only"])
        .output()
        .expect("remote verification should start");
    assert!(!feature_remote.status.success());
    assert!(!hook_sentinel.exists());
}

#[test]
fn actions_after_a_rejection_remain_explicitly_pending_and_are_never_attempted() {
    let directory = TestDirectory::new("pending-after-rejection");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let push_plan = directory.path.join("publication.push-plan");
    let approval = directory.path.join("publication.push-approval");
    let result_document = directory.path.join("publication.push-result");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);
    git(&project, &["branch", "feature/first"]);
    git(&project, &["branch", "feature/second"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");
    let local_engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);
    let draft = local_engine
        .draft(
            PushPlanDraftRequest::new(&plan, project_audit, "origin", &push_plan)
                .include_new_reference("refs/heads/feature/first")
                .include_new_reference("refs/heads/feature/second"),
        )
        .expect("three-action Push Plan should draft");
    let mut approval_request =
        PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &approval)
            .acknowledge_remote_side_effects();
    for action in draft
        .actions()
        .iter()
        .filter(|action| action.requires_item_approval())
    {
        approval_request = approval_request.approve_action(action.action_id());
    }
    local_engine
        .approve(approval_request)
        .expect("all selected new actions should approve");

    let execution = PushPlanEngine::with_git_publication_process(RejectSecondPushGit {
        push_calls: AtomicU64::new(0),
    })
    .execute(PushPlanExecutionRequest::new(
        &plan,
        project_audit,
        &push_plan,
        &approval,
        &result_document,
    ))
    .expect("rejection should be contained with pending actions");

    assert_eq!(execution.state(), PushExecutionState::Partial);
    assert_eq!(execution.succeeded_actions(), 1);
    assert_eq!(execution.failed_actions(), 1);
    assert_eq!(execution.pending_actions(), 1);
    let durable_result =
        fs::read_to_string(&result_document).expect("partial result log should exist");
    assert!(durable_result.contains("\"pending_actions\":1"));
    for action in draft.actions() {
        assert!(
            durable_result.contains(action.action_id()),
            "the header should preserve every planned action identity"
        );
    }
    for reference in ["refs/heads/feature/first", "refs/heads/feature/second"] {
        let remote_reference = Command::new("git")
            .arg("-C")
            .arg(&remote)
            .args(["rev-parse", "--verify", reference])
            .output()
            .expect("remote verification should start");
        assert!(!remote_reference.status.success());
    }
    assert!(!hook_sentinel.exists());
}

#[cfg(unix)]
#[test]
fn approval_rejects_a_symbolic_link_instead_of_following_an_immutable_push_plan() {
    let directory = TestDirectory::new("linked-plan");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let real_push_plan = directory.path.join("real.push-plan");
    let linked_push_plan = directory.path.join("linked.push-plan");
    let approval = directory.path.join("publication.push-approval");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");
    let engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);
    let draft = engine
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &real_push_plan,
        ))
        .expect("Push Plan should draft");
    symlink(&real_push_plan, &linked_push_plan).expect("Push Plan link should be created");

    let error = engine
        .approve(
            PushPlanApprovalRequest::new(&linked_push_plan, draft.approval_hash(), &approval)
                .acknowledge_remote_side_effects(),
        )
        .expect_err("approval must not follow a symbolic-link substitution");

    assert!(error.to_string().contains("could not read Push Plan"));
    assert!(!approval.exists());
}

#[test]
fn edited_push_plan_and_existing_result_destination_fail_before_publication() {
    let directory = TestDirectory::new("edited-plan-and-existing-result");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let edited_push_plan = directory.path.join("edited.push-plan");
    let clean_push_plan = directory.path.join("clean.push-plan");
    let edited_approval = directory.path.join("edited.push-approval");
    let clean_approval = directory.path.join("clean.push-approval");
    let result_document = directory.path.join("existing.push-result");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);
    let remote_before = git_stdout(&remote, &["rev-parse", "refs/heads/main"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");
    let engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);
    let edited_draft = engine
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &edited_push_plan,
        ))
        .expect("Push Plan should draft");
    let edited = fs::read_to_string(&edited_push_plan)
        .expect("Push Plan should read")
        .replace("non-force-only", "changed-after-review");
    fs::write(&edited_push_plan, edited).expect("Push Plan fixture should be edited");
    let edited_error = engine.approve(
        PushPlanApprovalRequest::new(
            &edited_push_plan,
            edited_draft.approval_hash(),
            &edited_approval,
        )
        .acknowledge_remote_side_effects(),
    );
    assert!(edited_error.is_err());
    assert!(!edited_approval.exists());

    let clean_draft = engine
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &clean_push_plan,
        ))
        .expect("second Push Plan should draft");
    engine
        .approve(
            PushPlanApprovalRequest::new(
                &clean_push_plan,
                clean_draft.approval_hash(),
                &clean_approval,
            )
            .acknowledge_remote_side_effects(),
        )
        .expect("clean Push Plan should approve");
    fs::write(&result_document, "unrelated existing evidence\n")
        .expect("existing result fixture should be written");
    let execution = engine.execute(PushPlanExecutionRequest::new(
        &plan,
        project_audit,
        &clean_push_plan,
        &clean_approval,
        &result_document,
    ));

    assert!(execution.is_err());
    assert_eq!(
        fs::read_to_string(&result_document).expect("existing result should remain"),
        "unrelated existing evidence\n"
    );
    assert_eq!(
        git_stdout(&remote, &["rev-parse", "refs/heads/main"]).trim(),
        remote_before.trim()
    );
    assert!(!hook_sentinel.exists());
}

#[cfg(unix)]
#[test]
fn production_publication_adapter_rejects_oversized_git_output() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new("oversized-git-output");
    let executable = directory.path.join("hostile-git");
    fs::write(&executable, "#!/bin/sh\nyes x | head -c 1048577\nexit 0\n")
        .expect("hostile Git fixture should be written");
    let mut permissions = fs::metadata(&executable)
        .expect("fixture metadata should be readable")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("fixture should be executable");

    let reference = GitReference::parse("refs/heads/main").expect("safe reference should parse");
    let error = InstalledGitPublication::with_executable(&executable)
        .run(
            &directory.path,
            GitPublicationOperation::ReadLocalReference {
                reference: &reference,
            },
        )
        .expect_err("oversized Git output must fail closed");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("safe limit"));
}

#[test]
fn changed_local_project_observation_after_approval_blocks_publication() {
    let directory = TestDirectory::new("changed-local-observation");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let push_plan = directory.path.join("publication.push-plan");
    let approval = directory.path.join("publication.push-approval");
    let result_document = directory.path.join("publication.push-result");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);
    let remote_before = git_stdout(&remote, &["rev-parse", "refs/heads/main"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("approved Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");
    let engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);
    let draft = engine
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &push_plan,
        ))
        .expect("Push Plan should draft");
    engine
        .approve(
            PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &approval)
                .acknowledge_remote_side_effects(),
        )
        .expect("Push Plan should approve");

    fs::write(
        project.join("added-after-approval.txt"),
        "new local state\n",
    )
    .expect("local state should change");
    let execution = engine
        .execute(PushPlanExecutionRequest::new(
            &plan,
            project_audit,
            &push_plan,
            &approval,
            &result_document,
        ))
        .expect("changed local observation should be contained as Partial");

    assert_eq!(execution.state(), PushExecutionState::Partial);
    assert_eq!(execution.succeeded_actions(), 0);
    assert_eq!(execution.failed_actions(), 1);
    assert_eq!(
        git_stdout(&remote, &["rev-parse", "refs/heads/main"]).trim(),
        remote_before.trim(),
        "local staleness must prevent publication"
    );
    assert!(!hook_sentinel.exists());
    assert!(result_document.is_file());
}

#[test]
fn new_remote_tag_requires_exact_item_approval_before_publication() {
    let directory = TestDirectory::new("new-tag");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let push_plan = directory.path.join("publication.push-plan");
    let approval = directory.path.join("publication.push-approval");
    let result_document = directory.path.join("publication.push-result");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);
    git(&project, &["tag", "release/v1"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::with_git_process(LocalGitAudit)
        .audit(ProjectAuditRequest::from_plan(&plan).with_remote_check())
        .expect("local-only tag should audit against the disposable remote");
    let project_audit = audit.projects().first().expect("Project should be audited");
    assert_eq!(
        project_audit.local_state().local_only_tags(),
        &["release/v1"]
    );
    let engine = PushPlanEngine::with_git_publication_process(LocalGitPublication);
    let draft = engine
        .draft(
            PushPlanDraftRequest::new(&plan, project_audit, "origin", &push_plan)
                .include_new_reference("refs/tags/release/v1"),
        )
        .expect("selected local-only tag should draft");
    let tag = draft
        .actions()
        .iter()
        .find(|action| action.action_class() == "tag")
        .expect("tag should be a distinct action");
    assert!(tag.requires_item_approval());
    engine
        .approve(
            PushPlanApprovalRequest::new(&push_plan, draft.approval_hash(), &approval)
                .approve_action(tag.action_id())
                .acknowledge_remote_side_effects(),
        )
        .expect("exact tag action approval should be accepted");
    let execution = engine
        .execute(PushPlanExecutionRequest::new(
            &plan,
            project_audit,
            &push_plan,
            &approval,
            &result_document,
        ))
        .expect("approved existing branch and tag should publish");

    assert_eq!(execution.state(), PushExecutionState::Complete);
    assert_eq!(execution.succeeded_actions(), 2);
    assert_eq!(
        git_stdout(&remote, &["rev-parse", "refs/tags/release/v1"]).trim(),
        git_stdout(&project, &["rev-parse", "refs/tags/release/v1"]).trim()
    );
    assert!(!hook_sentinel.exists());
}

#[test]
fn divergent_remote_branch_requires_manual_reconciliation_without_creating_a_push_plan() {
    let directory = TestDirectory::new("diverged");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let competitor = directory.path.join("competitor");
    let push_plan = directory.path.join("publication.push-plan");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);
    let clone = Command::new("git")
        .args(["clone", "-q", "--branch", "main"])
        .arg(&remote)
        .arg(&competitor)
        .output()
        .expect("competing clone should start");
    assert!(clone.status.success(), "competing clone should succeed");
    fs::write(competitor.join("competing.txt"), "remote-only commit\n")
        .expect("competing change should be written");
    git(&competitor, &["add", "competing.txt"]);
    commit(
        &competitor,
        "competing remote commit",
        "2026-02-03T00:00:00Z",
    );
    git(&competitor, &["push", "-q", "origin", "main"]);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("local Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");

    let error = PushPlanEngine::with_git_publication_process(LocalGitPublication)
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &push_plan,
        ))
        .expect_err("divergence must not produce an executable Push Plan");

    assert!(error.to_string().contains("manual reconciliation"));
    assert!(!push_plan.exists());
    assert!(!hook_sentinel.exists());
}

#[test]
fn mismatched_remote_advertisement_is_rejected_instead_of_authorizing_another_reference() {
    let directory = TestDirectory::new("mismatched-advertisement");
    let project = directory.path.join("owner-project");
    let remote = directory.path.join("owner-remote.git");
    let push_plan = directory.path.join("publication.push-plan");
    let hook_sentinel = directory.path.join("pre-push-ran");
    create_ahead_project(&project, &remote, &hook_sentinel);

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project))
        .expect("Project Plan should scan");
    let directory_plan_hash = plan.approval_hash().expect("directory Plan should hash");
    plan.approve(&directory_plan_hash)
        .expect("exact directory Plan hash should approve");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("local Project should audit");
    let project_audit = audit.projects().first().expect("Project should be audited");

    let error = PushPlanEngine::with_git_publication_process(MismatchedAdvertisementGit)
        .draft(PushPlanDraftRequest::new(
            &plan,
            project_audit,
            "origin",
            &push_plan,
        ))
        .expect_err("another reference advertisement must not authorize publication");

    assert!(error.to_string().contains("exact remote Git reference"));
    assert!(!push_plan.exists());
}

#[cfg(unix)]
#[test]
fn production_publication_adapter_uses_exact_non_force_arguments_and_a_clean_environment() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new("production-policy");
    let executable = directory.path.join("recording-git");
    fs::write(
        &executable,
        "#!/bin/sh\nprintf 'argument=%s\\n' \"$@\"\nprintf 'home=%s\\n' \"${HOME-unset}\"\nprintf 'prompt=%s\\n' \"${GIT_TERMINAL_PROMPT-unset}\"\nprintf 'interactive=%s\\n' \"${GCM_INTERACTIVE-unset}\"\n",
    )
    .expect("recording Git fixture should be written");
    let mut permissions = fs::metadata(&executable)
        .expect("fixture metadata should be readable")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("fixture should be executable");

    let remote = GitRemoteName::parse("origin").expect("safe remote should parse");
    let local_reference =
        GitReference::parse("refs/heads/main").expect("safe local reference should parse");
    let remote_reference =
        GitReference::parse("refs/heads/main").expect("safe remote reference should parse");
    let output = InstalledGitPublication::with_executable(&executable)
        .run(
            &directory.path,
            GitPublicationOperation::PushReference {
                remote: &remote,
                local_reference: &local_reference,
                remote_reference: &remote_reference,
            },
        )
        .expect("recording Git fixture should run");
    let observed = String::from_utf8(output.stdout).expect("fixture output should be text");

    assert!(observed.contains("argument=protocol.file.allow=never"));
    assert!(observed.contains("argument=core.hooksPath=/dev/null"));
    assert!(observed.contains("argument=--no-verify"));
    assert!(observed.contains("argument=--no-follow-tags"));
    assert!(observed.contains("argument=refs/heads/main:refs/heads/main"));
    assert!(!observed.contains("--force"));
    assert!(observed.contains("home=unset"));
    assert!(observed.contains("prompt=0"));
    assert!(observed.contains("interactive=Never"));
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
            .arg("-c")
            .arg("credential.helper=")
            .arg("-C")
            .arg(repository)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "Never");
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
            GitPublicationOperation::PushReference {
                remote,
                local_reference,
                remote_reference,
            } => {
                command.args([
                    "push",
                    "--porcelain",
                    "--no-verify",
                    "--no-follow-tags",
                    "--",
                    remote.as_str(),
                    &format!("{}:{}", local_reference.as_str(), remote_reference.as_str()),
                ]);
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

struct LocalGitAudit;

impl GitProcess for LocalGitAudit {
    fn run(&self, repository: &Path, arguments: &[OsString]) -> std::io::Result<GitProcessOutput> {
        let output = Command::new("git")
            .arg("-c")
            .arg("protocol.file.allow=always")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()?;
        Ok(GitProcessOutput {
            status_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

struct RejectingPushGit;

impl GitPublicationProcess for RejectingPushGit {
    fn run(
        &self,
        repository: &Path,
        operation: GitPublicationOperation<'_>,
    ) -> std::io::Result<GitPublicationOutput> {
        if matches!(&operation, GitPublicationOperation::PushReference { .. }) {
            return Ok(GitPublicationOutput {
                status_code: Some(1),
                stdout: Vec::new(),
                stderr: b"SECRET-RAW-GIT-ERROR".to_vec(),
            });
        }
        LocalGitPublication.run(repository, operation)
    }
}

struct MismatchedAdvertisementGit;

impl GitPublicationProcess for MismatchedAdvertisementGit {
    fn run(
        &self,
        repository: &Path,
        operation: GitPublicationOperation<'_>,
    ) -> std::io::Result<GitPublicationOutput> {
        let is_remote_read = matches!(
            &operation,
            GitPublicationOperation::ReadRemoteReference { .. }
        );
        let mut output = LocalGitPublication.run(repository, operation)?;
        if is_remote_read && output.status_code == Some(0) {
            let object = output
                .stdout
                .split(|byte| byte.is_ascii_whitespace())
                .next()
                .unwrap_or_default();
            output.stdout = [object, b"\trefs/heads/unrelated\n"].concat();
        }
        Ok(output)
    }
}

struct CrashBeforeSecondPushGit {
    push_calls: AtomicU64,
}

struct RejectSecondPushGit {
    push_calls: AtomicU64,
}

impl GitPublicationProcess for RejectSecondPushGit {
    fn run(
        &self,
        repository: &Path,
        operation: GitPublicationOperation<'_>,
    ) -> std::io::Result<GitPublicationOutput> {
        if matches!(&operation, GitPublicationOperation::PushReference { .. })
            && self.push_calls.fetch_add(1, Ordering::SeqCst) == 1
        {
            return Ok(GitPublicationOutput {
                status_code: Some(1),
                stdout: Vec::new(),
                stderr: b"synthetic rejection".to_vec(),
            });
        }
        LocalGitPublication.run(repository, operation)
    }
}

impl GitPublicationProcess for CrashBeforeSecondPushGit {
    fn run(
        &self,
        repository: &Path,
        operation: GitPublicationOperation<'_>,
    ) -> std::io::Result<GitPublicationOutput> {
        if matches!(&operation, GitPublicationOperation::PushReference { .. })
            && self.push_calls.fetch_add(1, Ordering::SeqCst) == 1
        {
            panic!("synthetic interruption before second publication action");
        }
        LocalGitPublication.run(repository, operation)
    }
}

fn create_ahead_project(project: &Path, remote: &Path, hook_sentinel: &Path) {
    fs::create_dir(project).expect("Project directory should be created");
    git(project, &["init", "-q", "--initial-branch=main"]);
    git(
        remote.parent().expect("remote should have a parent"),
        &[
            "init",
            "-q",
            "--bare",
            remote
                .to_str()
                .expect("fixture remote path should be Unicode"),
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
            remote.to_str().expect("remote path should be Unicode"),
        ],
    );
    git(project, &["push", "-q", "-u", "origin", "main"]);
    fs::write(project.join("tracked.txt"), "approved new commit\n")
        .expect("ahead fixture should be written");
    git(project, &["add", "tracked.txt"]);
    commit(project, "approved new commit", "2026-02-02T00:00:00Z");
    fs::write(project.join("unstaged.txt"), "local dirty state\n")
        .expect("dirty fixture should be written");
    fs::write(
        project.join(".git/hooks/pre-push"),
        format!("#!/bin/sh\ntouch '{}'\n", hook_sentinel.display()),
    )
    .expect("pre-push hook fixture should be written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let hook = project.join(".git/hooks/pre-push");
        let mut permissions = fs::metadata(&hook)
            .expect("pre-push hook metadata should be readable")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(hook, permissions).expect("pre-push hook should be executable");
    }
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

fn git_stdout(project: &Path, arguments: &[&str]) -> String {
    String::from_utf8(git_bytes(project, arguments)).expect("Git output should be Unicode")
}

fn git_bytes(project: &Path, arguments: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .arg("-C")
        .arg(project)
        .args(arguments)
        .output()
        .expect("Git query should start");
    assert!(
        output.status.success(),
        "Git query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
