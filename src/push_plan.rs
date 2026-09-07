use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{CoreError, Plan, PlanApprovalState, ProjectAudit, ProjectHead, ProjectKind};

const PUSH_PLAN_SCHEMA_VERSION: u32 = 1;
const PUSH_APPROVAL_SCHEMA_VERSION: u32 = 1;
const PUSH_RESULT_SCHEMA_VERSION: u32 = 1;
const PUBLICATION_WARNING: &str = "Publishing can trigger continuous integration, deployments, and notifications on the remote service.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPublicationOutput {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitRemoteName(String);

impl GitRemoteName {
    pub fn parse(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_remote_name(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitReference(String);

impl GitReference {
    pub fn parse(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        validate_reference(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitObjectIdentifier(String);

impl GitObjectIdentifier {
    pub fn parse(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        Ok(Self(parse_object_identifier(value.as_bytes())?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitPublicationOperation<'a> {
    ReadWorkingTreeStatus,
    ListLocalReferences,
    ReadLocalReference {
        reference: &'a GitReference,
    },
    ReadRemoteReference {
        remote: &'a GitRemoteName,
        reference: &'a GitReference,
    },
    CheckAncestor {
        ancestor: &'a GitObjectIdentifier,
        descendant: &'a GitObjectIdentifier,
    },
    PushReference {
        remote: &'a GitRemoteName,
        local_reference: &'a GitReference,
        remote_reference: &'a GitReference,
    },
}

pub trait GitPublicationProcess {
    fn run(
        &self,
        repository: &Path,
        operation: GitPublicationOperation<'_>,
    ) -> io::Result<GitPublicationOutput>;
}

#[derive(Debug, Clone)]
pub struct InstalledGitPublication {
    executable: PathBuf,
}

impl Default for InstalledGitPublication {
    fn default() -> Self {
        let system_git = PathBuf::from("/usr/bin/git");
        Self {
            executable: if system_git.is_file() {
                system_git
            } else {
                PathBuf::from("git")
            },
        }
    }
}

impl InstalledGitPublication {
    pub fn with_executable(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }
}

impl GitPublicationProcess for InstalledGitPublication {
    fn run(
        &self,
        repository: &Path,
        operation: GitPublicationOperation<'_>,
    ) -> io::Result<GitPublicationOutput> {
        let mut command = Command::new(&self.executable);
        command
            .arg("--no-optional-locks")
            .args(["-c", "core.fsmonitor=false"])
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(["-c", "credential.helper="])
            .args(["-c", "protocol.allow=never"])
            .args(["-c", "protocol.https.allow=always"])
            .args(["-c", "protocol.ssh.allow=always"])
            .args(["-c", "protocol.file.allow=never"])
            .args(["-c", "protocol.ext.allow=never"])
            .args(["-c", "protocol.git.allow=never"])
            .args(["-c", "core.sshCommand=/usr/bin/ssh"])
            .arg("-C")
            .arg(repository)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env(
                "PATH",
                "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
            )
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "Never")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
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
        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("Git standard output was not captured"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("Git standard error was not captured"))?;
        let stdout_reader = thread::spawn(move || capture_publication_stream(stdout));
        let stderr_reader = thread::spawn(move || capture_publication_stream(stderr));
        let status = child.wait()?;
        let (stdout, stdout_oversized) = join_publication_stream(stdout_reader)?;
        let (stderr, stderr_oversized) = join_publication_stream(stderr_reader)?;
        if stdout_oversized || stderr_oversized {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Git command output exceeded the safe limit",
            ));
        }
        Ok(GitPublicationOutput {
            status_code: status.code(),
            stdout,
            stderr,
        })
    }
}

const MAX_GIT_PUBLICATION_STREAM_BYTES: usize = 1024 * 1024;

fn capture_publication_stream(mut stream: impl Read) -> io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::new();
    let mut oversized = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_GIT_PUBLICATION_STREAM_BYTES.saturating_sub(captured.len());
        let retained = remaining.min(read);
        captured.extend_from_slice(&buffer[..retained]);
        oversized |= retained < read;
    }
    Ok((captured, oversized))
}

fn join_publication_stream(
    reader: thread::JoinHandle<io::Result<(Vec<u8>, bool)>>,
) -> io::Result<(Vec<u8>, bool)> {
    reader
        .join()
        .map_err(|_| io::Error::other("Git output reader stopped unexpectedly"))?
}

#[derive(Debug, Clone)]
pub struct PushPlanDraftRequest<'a> {
    plan: &'a Plan,
    project: &'a ProjectAudit,
    remote: String,
    destination: PathBuf,
    selected_new_references: Vec<String>,
}

impl<'a> PushPlanDraftRequest<'a> {
    pub fn new(
        plan: &'a Plan,
        project: &'a ProjectAudit,
        remote: impl Into<String>,
        destination: impl Into<PathBuf>,
    ) -> Self {
        Self {
            plan,
            project,
            remote: remote.into(),
            destination: destination.into(),
            selected_new_references: Vec::new(),
        }
    }

    pub fn include_new_reference(mut self, reference: impl Into<String>) -> Self {
        self.selected_new_references.push(reference.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct PushPlanApprovalRequest {
    push_plan: PathBuf,
    reviewed_hash: String,
    destination: PathBuf,
    acknowledged_remote_side_effects: bool,
    approved_action_ids: Vec<String>,
}

impl PushPlanApprovalRequest {
    pub fn new(
        push_plan: impl Into<PathBuf>,
        reviewed_hash: impl Into<String>,
        destination: impl Into<PathBuf>,
    ) -> Self {
        Self {
            push_plan: push_plan.into(),
            reviewed_hash: reviewed_hash.into(),
            destination: destination.into(),
            acknowledged_remote_side_effects: false,
            approved_action_ids: Vec::new(),
        }
    }

    pub fn acknowledge_remote_side_effects(mut self) -> Self {
        self.acknowledged_remote_side_effects = true;
        self
    }

    pub fn approve_action(mut self, action_id: impl Into<String>) -> Self {
        self.approved_action_ids.push(action_id.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct PushPlanExecutionRequest<'a> {
    plan: &'a Plan,
    project: &'a ProjectAudit,
    push_plan: PathBuf,
    approval: PathBuf,
    result: PathBuf,
}

impl<'a> PushPlanExecutionRequest<'a> {
    pub fn new(
        plan: &'a Plan,
        project: &'a ProjectAudit,
        push_plan: impl Into<PathBuf>,
        approval: impl Into<PathBuf>,
        result: impl Into<PathBuf>,
    ) -> Self {
        Self {
            plan,
            project,
            push_plan: push_plan.into(),
            approval: approval.into(),
            result: result.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PushPlanDocument {
    schema_version: u32,
    document_kind: String,
    project_id: String,
    remote: String,
    created_unix_seconds: u64,
    expires_unix_seconds: u64,
    policy: String,
    warning: String,
    actions: Vec<PushAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushAction {
    action_id: String,
    action_class: String,
    local_reference: String,
    remote_reference: String,
    expected_old_remote_object: String,
    proposed_new_remote_object: String,
    requires_item_approval: bool,
}

impl PushAction {
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    pub fn action_class(&self) -> &str {
        &self.action_class
    }

    pub fn local_reference(&self) -> &str {
        &self.local_reference
    }

    pub fn remote_reference(&self) -> &str {
        &self.remote_reference
    }

    pub fn expected_old_remote_object(&self) -> &str {
        &self.expected_old_remote_object
    }

    pub fn proposed_new_remote_object(&self) -> &str {
        &self.proposed_new_remote_object
    }

    pub fn is_non_force(&self) -> bool {
        true
    }

    pub fn requires_item_approval(&self) -> bool {
        self.requires_item_approval
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushPlanDocumentReport {
    document: PushPlanDocument,
    approval_hash: String,
}

impl PushPlanDocumentReport {
    pub fn actions(&self) -> &[PushAction] {
        &self.document.actions
    }

    pub fn approval_hash(&self) -> &str {
        &self.approval_hash
    }

    pub fn warning(&self) -> &str {
        &self.document.warning
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PushApprovalDocument {
    schema_version: u32,
    document_kind: String,
    receipt_id: String,
    approved_unix_seconds: u64,
    push_plan_hash: String,
    remote_side_effects_acknowledgement: String,
    approved_action_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushPlanApprovalReceipt {
    document: PushApprovalDocument,
}

impl PushPlanApprovalReceipt {
    pub fn push_plan_hash(&self) -> &str {
        &self.document.push_plan_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PushExecutionState {
    Complete,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushExecutionReport {
    state: PushExecutionState,
    succeeded_actions: usize,
    failed_actions: usize,
    pending_actions: usize,
    plan_hash: String,
    project_identity: String,
    push_plan_hash: String,
    remote: String,
    publication_proofs: Vec<PushPublicationProof>,
    occurred_at_unix_seconds: u64,
    human_result: String,
    machine_json_result: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PushPublicationProof {
    pub(crate) local_reference: String,
    pub(crate) remote_reference: String,
    pub(crate) proposed_new_remote_object: String,
}

impl PushExecutionReport {
    pub fn state(&self) -> PushExecutionState {
        self.state
    }

    pub fn succeeded_actions(&self) -> usize {
        self.succeeded_actions
    }

    pub fn failed_actions(&self) -> usize {
        self.failed_actions
    }

    pub fn pending_actions(&self) -> usize {
        self.pending_actions
    }

    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    pub fn project_identity(&self) -> &str {
        &self.project_identity
    }

    pub fn push_plan_hash(&self) -> &str {
        &self.push_plan_hash
    }

    pub fn occurred_at_unix_seconds(&self) -> u64 {
        self.occurred_at_unix_seconds
    }

    pub(crate) fn remote(&self) -> &str {
        &self.remote
    }

    pub(crate) fn publication_proofs(&self) -> &[PushPublicationProof] {
        &self.publication_proofs
    }

    pub fn human_result(&self) -> &str {
        &self.human_result
    }

    pub fn machine_json_result(&self) -> &str {
        &self.machine_json_result
    }
}

#[derive(Debug)]
pub struct PushPlanEngine<G = InstalledGitPublication> {
    git: G,
}

impl PushPlanEngine<InstalledGitPublication> {
    pub fn local() -> Self {
        Self {
            git: InstalledGitPublication::default(),
        }
    }
}

impl<G> PushPlanEngine<G> {
    pub fn with_git_publication_process(git: G) -> Self {
        Self { git }
    }
}

impl<G: GitPublicationProcess> PushPlanEngine<G> {
    pub fn draft(
        &self,
        request: PushPlanDraftRequest<'_>,
    ) -> Result<PushPlanDocumentReport, CoreError> {
        validate_plan_and_project(request.plan, request.project)?;
        ensure_project_observation_current(&self.git, request.project)?;
        validate_remote_name(&request.remote)?;
        if !request
            .project
            .remotes()
            .iter()
            .any(|remote| remote.name() == request.remote)
        {
            return invalid("Push Plan remote is not configured for the Project");
        }
        let branch = match request.project.local_state().head() {
            ProjectHead::Branch(branch) => branch,
            _ => return invalid("Push Plan requires an attached existing branch"),
        };
        let upstream = request.project.local_state().upstream().ok_or_else(|| {
            CoreError::InvalidPlan("Push Plan requires an upstream branch".to_owned())
        })?;
        let (upstream_remote, upstream_branch) = upstream.split_once('/').ok_or_else(|| {
            CoreError::InvalidPlan("Project upstream is not a remote branch".to_owned())
        })?;
        if upstream_remote != request.remote {
            return invalid("Push Plan remote does not match the current upstream");
        }
        if request.project.local_state().behind().unwrap_or(0) != 0 {
            return invalid("behind or diverged Projects require manual reconciliation");
        }
        let mut actions = Vec::new();
        if request.project.local_state().ahead().unwrap_or(0) > 0 {
            let local_reference = format!("refs/heads/{branch}");
            let remote_reference = format!("refs/heads/{upstream_branch}");
            validate_reference(&local_reference)?;
            validate_reference(&remote_reference)?;
            let proposed_new_remote_object =
                read_local_object(&self.git, request.project.root(), &local_reference)?;
            let expected_old_remote_object = read_remote_object(
                &self.git,
                request.project.root(),
                &request.remote,
                &remote_reference,
            )?;
            ensure_ancestor(
                &self.git,
                request.project.root(),
                &expected_old_remote_object,
                &proposed_new_remote_object,
            )?;
            let existing_action_id = action_id(
                request.project.id(),
                &local_reference,
                &remote_reference,
                &expected_old_remote_object,
                &proposed_new_remote_object,
            );
            actions.push(PushAction {
                action_id: existing_action_id,
                action_class: "existing-upstream-branch".to_owned(),
                local_reference,
                remote_reference,
                expected_old_remote_object,
                proposed_new_remote_object,
                requires_item_approval: false,
            });
        } else if request.selected_new_references.is_empty() {
            return invalid("Project has no selected publication actions");
        }
        let created_unix_seconds = unix_time_now()?;
        let document = PushPlanDocument {
            schema_version: PUSH_PLAN_SCHEMA_VERSION,
            document_kind: "push-plan".to_owned(),
            project_id: request.project.id().to_owned(),
            remote: request.remote,
            created_unix_seconds,
            expires_unix_seconds: created_unix_seconds + 15 * 60,
            policy: "non-force-only".to_owned(),
            warning: PUBLICATION_WARNING.to_owned(),
            actions,
        };
        let mut document = document;
        let mut selected_new_references = request.selected_new_references;
        selected_new_references.sort();
        if selected_new_references
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return invalid("Push Plan contains duplicate selected references");
        }
        for reference in selected_new_references {
            validate_reference(&reference)?;
            let (action_class, short_name) =
                if let Some(name) = reference.strip_prefix("refs/heads/") {
                    ("new-remote-branch", name)
                } else if let Some(name) = reference.strip_prefix("refs/tags/") {
                    ("tag", name)
                } else {
                    return invalid(
                        "only local-only branches and tags can be selected for publication",
                    );
                };
            let is_audited_local_only = match action_class {
                "new-remote-branch" => request
                    .project
                    .local_state()
                    .local_only_branches()
                    .iter()
                    .any(|name| name == short_name),
                "tag" => request
                    .project
                    .local_state()
                    .local_only_tags()
                    .iter()
                    .any(|name| name == short_name),
                _ => false,
            };
            if !is_audited_local_only {
                return invalid(
                    "selected new reference was not proven local-only by the Project audit",
                );
            }
            let proposed = read_local_object(&self.git, request.project.root(), &reference)?;
            if read_remote_object_optional(
                &self.git,
                request.project.root(),
                &document.remote,
                &reference,
            )?
            .is_some()
            {
                return invalid("selected new reference already exists on the remote");
            }
            document.actions.push(PushAction {
                action_id: action_id(
                    request.project.id(),
                    &reference,
                    &reference,
                    "absent",
                    &proposed,
                ),
                action_class: action_class.to_owned(),
                local_reference: reference.clone(),
                remote_reference: reference,
                expected_old_remote_object: "absent".to_owned(),
                proposed_new_remote_object: proposed,
                requires_item_approval: true,
            });
        }
        let text = encode_push_plan(&document)?;
        write_exclusive_synced(&request.destination, text.as_bytes(), "write Push Plan")?;
        let approval_hash = push_plan_hash(text.as_bytes());
        Ok(PushPlanDocumentReport {
            document,
            approval_hash,
        })
    }

    pub fn approve(
        &self,
        request: PushPlanApprovalRequest,
    ) -> Result<PushPlanApprovalReceipt, CoreError> {
        if !request.acknowledged_remote_side_effects {
            return invalid("Push Plan approval requires acknowledgement of remote side effects");
        }
        let (document, bytes) = read_canonical_push_plan(&request.push_plan)?;
        if unix_time_now()? > document.expires_unix_seconds {
            return invalid("Push Plan expired before approval");
        }
        let current_hash = push_plan_hash(&bytes);
        if request.reviewed_hash != current_hash {
            return invalid("reviewed Push Plan hash does not match the immutable document");
        }
        if document.actions.is_empty() {
            return invalid("Push Plan contains no publication actions");
        }
        let mut required_action_ids = document
            .actions
            .iter()
            .filter(|action| action.requires_item_approval)
            .map(|action| action.action_id.clone())
            .collect::<Vec<_>>();
        required_action_ids.sort();
        let mut approved_action_ids = request.approved_action_ids;
        approved_action_ids.sort();
        if approved_action_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
            || approved_action_ids != required_action_ids
        {
            return invalid("every new branch and tag requires exact item-by-item approval");
        }
        let receipt_document = PushApprovalDocument {
            schema_version: PUSH_APPROVAL_SCHEMA_VERSION,
            document_kind: "push-plan-approval".to_owned(),
            receipt_id: random_receipt_id()?,
            approved_unix_seconds: unix_time_now()?,
            push_plan_hash: current_hash,
            remote_side_effects_acknowledgement: "remote-side-effects-v1".to_owned(),
            approved_action_ids,
        };
        let text = encode_approval(&receipt_document)?;
        write_exclusive_synced(
            &request.destination,
            text.as_bytes(),
            "write Push Plan approval",
        )?;
        Ok(PushPlanApprovalReceipt {
            document: receipt_document,
        })
    }

    pub fn execute(
        &self,
        request: PushPlanExecutionRequest<'_>,
    ) -> Result<PushExecutionReport, CoreError> {
        validate_plan_and_project(request.plan, request.project)?;
        let (document, plan_bytes) = read_canonical_push_plan(&request.push_plan)?;
        if document.project_id != request.project.id() {
            return invalid("Push Plan does not belong to the selected Project");
        }
        let receipt = read_canonical_approval(&request.approval)?;
        let current_hash = push_plan_hash(&plan_bytes);
        if receipt.push_plan_hash != current_hash {
            return invalid("Push Plan approval does not match the immutable Push Plan");
        }
        if receipt.remote_side_effects_acknowledgement != "remote-side-effects-v1" {
            return invalid("Push Plan approval lacks the required side-effect acknowledgement");
        }
        let mut required_action_ids = document
            .actions
            .iter()
            .filter(|action| action.requires_item_approval)
            .map(|action| action.action_id.clone())
            .collect::<Vec<_>>();
        required_action_ids.sort();
        if receipt.approved_action_ids != required_action_ids {
            return invalid("Push Plan approval does not authorize every selected new reference");
        }
        let planned_action_ids = document
            .actions
            .iter()
            .map(|action| action.action_id.as_str())
            .collect::<Vec<_>>();
        let publication_proofs = document
            .actions
            .iter()
            .map(|action| PushPublicationProof {
                local_reference: action.local_reference.clone(),
                remote_reference: action.remote_reference.clone(),
                proposed_new_remote_object: action.proposed_new_remote_object.clone(),
            })
            .collect();
        let mut result_log = PushResultLog::create(
            &request.result,
            &current_hash,
            &request.plan.approval_hash()?,
            request.project.id(),
            &document.remote,
            publication_proofs,
            &planned_action_ids,
        )?;
        if unix_time_now()? > document.expires_unix_seconds {
            return result_log.finish(PushExecutionState::Partial, 0, 1, "push-plan-expired", None);
        }
        if ensure_project_observation_current(&self.git, request.project).is_err() {
            return result_log.finish(
                PushExecutionState::Partial,
                0,
                1,
                "local-project-changed",
                None,
            );
        }

        let mut succeeded = 0;
        for action in &document.actions {
            validate_reference(&action.local_reference)?;
            validate_reference(&action.remote_reference)?;
            let local_object =
                match read_local_object(&self.git, request.project.root(), &action.local_reference)
                {
                    Ok(object) => object,
                    Err(_) => {
                        return result_log.finish(
                            PushExecutionState::Partial,
                            succeeded,
                            1,
                            "local-reference-observation-failed",
                            Some(&action.action_id),
                        );
                    }
                };
            if local_object != action.proposed_new_remote_object {
                return result_log.finish(
                    PushExecutionState::Partial,
                    succeeded,
                    1,
                    "local-reference-changed",
                    Some(&action.action_id),
                );
            }
            let remote_object = match read_remote_object_optional(
                &self.git,
                request.project.root(),
                &document.remote,
                &action.remote_reference,
            ) {
                Ok(object) => object,
                Err(_) => {
                    return result_log.finish(
                        PushExecutionState::Partial,
                        succeeded,
                        1,
                        "remote-reference-observation-failed",
                        Some(&action.action_id),
                    );
                }
            };
            let expected_remote = if action.expected_old_remote_object == "absent" {
                None
            } else {
                Some(action.expected_old_remote_object.as_str())
            };
            if remote_object.as_deref() != expected_remote {
                return result_log.finish(
                    PushExecutionState::Partial,
                    succeeded,
                    1,
                    "remote-reference-changed",
                    Some(&action.action_id),
                );
            }
            if let Some(remote_object) = &remote_object
                && ensure_ancestor(
                    &self.git,
                    request.project.root(),
                    remote_object,
                    &local_object,
                )
                .is_err()
            {
                return result_log.finish(
                    PushExecutionState::Partial,
                    succeeded,
                    1,
                    "reference-ancestry-changed",
                    Some(&action.action_id),
                );
            }
            let publication_remote = GitRemoteName::parse(document.remote.clone())?;
            let publication_local_reference = GitReference::parse(action.local_reference.clone())?;
            let publication_remote_reference =
                GitReference::parse(action.remote_reference.clone())?;
            let push = match self.git.run(
                request.project.root(),
                GitPublicationOperation::PushReference {
                    remote: &publication_remote,
                    local_reference: &publication_local_reference,
                    remote_reference: &publication_remote_reference,
                },
            ) {
                Ok(output) => output,
                Err(_) => {
                    return result_log.finish(
                        PushExecutionState::Partial,
                        succeeded,
                        1,
                        "publication-process-failed",
                        Some(&action.action_id),
                    );
                }
            };
            if push.status_code != Some(0) {
                return result_log.finish(
                    PushExecutionState::Partial,
                    succeeded,
                    1,
                    "publication-rejected",
                    Some(&action.action_id),
                );
            }
            let published = match read_remote_object(
                &self.git,
                request.project.root(),
                &document.remote,
                &action.remote_reference,
            ) {
                Ok(object) => object,
                Err(_) => {
                    return result_log.finish(
                        PushExecutionState::Partial,
                        succeeded,
                        1,
                        "publication-proof-failed",
                        Some(&action.action_id),
                    );
                }
            };
            if published != action.proposed_new_remote_object {
                return result_log.finish(
                    PushExecutionState::Partial,
                    succeeded,
                    1,
                    "publication-unproven",
                    Some(&action.action_id),
                );
            }
            result_log.append_action(&action.action_id, "succeeded", "published")?;
            succeeded += 1;
        }

        result_log.finish(PushExecutionState::Complete, succeeded, 0, "complete", None)
    }
}

struct PushResultLog {
    file: File,
    path: PathBuf,
    push_plan_hash: String,
    plan_hash: String,
    project_identity: String,
    remote: String,
    publication_proofs: Vec<PushPublicationProof>,
    total_actions: usize,
}

impl PushResultLog {
    fn create(
        path: &Path,
        push_plan_hash: &str,
        plan_hash: &str,
        project_identity: &str,
        remote: &str,
        publication_proofs: Vec<PushPublicationProof>,
        planned_action_ids: &[&str],
    ) -> Result<Self, CoreError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path).map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                CoreError::DestinationAlreadyExists(path.to_path_buf())
            } else {
                CoreError::Io {
                    action: "create Push Plan result log",
                    path: path.to_path_buf(),
                    source,
                }
            }
        })?;
        let mut log = Self {
            file,
            path: path.to_path_buf(),
            push_plan_hash: push_plan_hash.to_owned(),
            plan_hash: plan_hash.to_owned(),
            project_identity: project_identity.to_owned(),
            remote: remote.to_owned(),
            publication_proofs,
            total_actions: planned_action_ids.len(),
        };
        log.append_json(&serde_json::json!({
            "schema_version": PUSH_RESULT_SCHEMA_VERSION,
            "record_type": "push-result-header",
            "push_plan_hash": push_plan_hash,
            "planned_action_ids": planned_action_ids,
        }))?;
        sync_parent(path, "synchronize Push Plan result directory")?;
        Ok(log)
    }

    fn append_action(
        &mut self,
        action_id: &str,
        state: &str,
        outcome_code: &str,
    ) -> Result<(), CoreError> {
        self.append_json(&serde_json::json!({
            "schema_version": PUSH_RESULT_SCHEMA_VERSION,
            "record_type": "push-action-result",
            "action_id": action_id,
            "state": state,
            "outcome_code": outcome_code,
        }))
    }

    fn finish(
        &mut self,
        state: PushExecutionState,
        succeeded_actions: usize,
        failed_actions: usize,
        outcome_code: &str,
        failed_action_id: Option<&str>,
    ) -> Result<PushExecutionReport, CoreError> {
        let pending_actions = self
            .total_actions
            .saturating_sub(succeeded_actions.saturating_add(failed_actions));
        if let Some(action_id) = failed_action_id {
            self.append_action(action_id, "failed", outcome_code)?;
        }
        self.append_json(&serde_json::json!({
            "schema_version": PUSH_RESULT_SCHEMA_VERSION,
            "record_type": "push-result-summary",
            "state": match state {
                PushExecutionState::Complete => "complete",
                PushExecutionState::Partial => "partial",
            },
            "succeeded_actions": succeeded_actions,
            "failed_actions": failed_actions,
            "pending_actions": pending_actions,
            "outcome_code": outcome_code,
        }))?;
        build_execution_report(
            PushExecutionBinding {
                push_plan_hash: &self.push_plan_hash,
                plan_hash: &self.plan_hash,
                project_identity: &self.project_identity,
                remote: &self.remote,
                publication_proofs: &self.publication_proofs[..succeeded_actions],
            },
            state,
            succeeded_actions,
            failed_actions,
            pending_actions,
            outcome_code,
        )
    }

    fn append_json(&mut self, value: &serde_json::Value) -> Result<(), CoreError> {
        let mut line =
            serde_json::to_vec(value).map_err(|error| CoreError::InvalidPlan(error.to_string()))?;
        line.push(b'\n');
        self.file.write_all(&line).map_err(|source| CoreError::Io {
            action: "append Push Plan result record",
            path: self.path.clone(),
            source,
        })?;
        self.file.sync_all().map_err(|source| CoreError::Io {
            action: "synchronize Push Plan result record",
            path: self.path.clone(),
            source,
        })
    }
}

struct PushExecutionBinding<'a> {
    push_plan_hash: &'a str,
    plan_hash: &'a str,
    project_identity: &'a str,
    remote: &'a str,
    publication_proofs: &'a [PushPublicationProof],
}

fn build_execution_report(
    binding: PushExecutionBinding<'_>,
    state: PushExecutionState,
    succeeded_actions: usize,
    failed_actions: usize,
    pending_actions: usize,
    outcome_code: &str,
) -> Result<PushExecutionReport, CoreError> {
    let PushExecutionBinding {
        push_plan_hash,
        plan_hash,
        project_identity,
        remote,
        publication_proofs,
    } = binding;
    let human_result = match state {
        PushExecutionState::Complete => format!(
            "Push Plan complete: {succeeded_actions} approved publication action(s) proven."
        ),
        PushExecutionState::Partial => format!(
            "Push Plan partial: {succeeded_actions} publication action(s) proven, {failed_actions} failed, and {pending_actions} pending."
        ),
    };
    let machine_json_result = serde_json::json!({
        "schema_version": PUSH_RESULT_SCHEMA_VERSION,
        "command": "projects push-plan execute",
        "status": match state {
            PushExecutionState::Complete => "complete",
            PushExecutionState::Partial => "partial",
        },
        "data": {
            "succeeded_actions": succeeded_actions,
            "failed_actions": failed_actions,
            "pending_actions": pending_actions,
            "push_plan_hash": push_plan_hash,
            "outcome_code": outcome_code,
        },
        "warnings": [],
        "errors": [],
    })
    .to_string();
    Ok(PushExecutionReport {
        state,
        succeeded_actions,
        failed_actions,
        pending_actions,
        plan_hash: plan_hash.to_owned(),
        project_identity: project_identity.to_owned(),
        push_plan_hash: push_plan_hash.to_owned(),
        remote: remote.to_owned(),
        publication_proofs: publication_proofs.to_vec(),
        occurred_at_unix_seconds: unix_time_now()?,
        human_result,
        machine_json_result,
    })
}

fn sync_parent(path: &Path, action: &'static str) -> Result<(), CoreError> {
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| CoreError::Io {
                action,
                path: parent.to_path_buf(),
                source,
            })?;
    }
    Ok(())
}

fn validate_plan_and_project(plan: &Plan, project: &ProjectAudit) -> Result<(), CoreError> {
    if !plan.is_directory_plan() || plan.approval_state()? != PlanApprovalState::Approved {
        return invalid("Push Plan requires an approved, non-stale directory Plan");
    }
    if !project.local_audit_verified() || project.changed_during_audit() {
        return invalid("Push Plan requires a verified, unchanged Project audit");
    }
    if !plan
        .approved_roots()
        .iter()
        .any(|root| project.root().starts_with(root))
    {
        return invalid("Project escaped the approved directory Plan roots");
    }
    Ok(())
}

fn ensure_project_observation_current(
    git: &impl GitPublicationProcess,
    project: &ProjectAudit,
) -> Result<(), CoreError> {
    let expected = project.local_state().observation_hash().ok_or_else(|| {
        CoreError::InvalidPlan("Project audit has no verified local observation".to_owned())
    })?;
    let status = if project.kind() == ProjectKind::BareRepository {
        Vec::new()
    } else {
        run_publication_observation(
            git,
            project.root(),
            GitPublicationOperation::ReadWorkingTreeStatus,
        )?
    };
    let references = run_publication_observation(
        git,
        project.root(),
        GitPublicationOperation::ListLocalReferences,
    )?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza project audit observation v1\0");
    hasher.update(&(status.len() as u64).to_le_bytes());
    hasher.update(&status);
    hasher.update(&(references.len() as u64).to_le_bytes());
    hasher.update(&references);
    if hasher.finalize().to_hex().as_str() != expected {
        return invalid("Project changed after its verified local audit");
    }
    Ok(())
}

pub(crate) fn revalidate_synchronized_project(
    git: &impl GitPublicationProcess,
    project: &ProjectAudit,
    remote: &str,
    proofs: &[PushPublicationProof],
) -> Result<(), CoreError> {
    if proofs.is_empty() {
        return invalid("Push Plan execution has no proven publication actions");
    }
    ensure_project_observation_current(git, project)?;
    for proof in proofs {
        let local = read_local_object(git, project.root(), &proof.local_reference)?;
        let remote_object =
            read_remote_object(git, project.root(), remote, &proof.remote_reference)?;
        if local != proof.proposed_new_remote_object
            || remote_object != proof.proposed_new_remote_object
        {
            return invalid("published Git reference is no longer synchronized");
        }
    }
    Ok(())
}

pub(crate) fn revalidate_already_synchronized_project(
    git: &impl GitPublicationProcess,
    project: &ProjectAudit,
) -> Result<(), CoreError> {
    if !project.local_state().verified()
        || project.local_state().changed_during_audit()
        || project.local_state().ahead() != Some(0)
        || project.local_state().behind() != Some(0)
    {
        return invalid("Project has unpublished or unverified local Git state");
    }
    let upstream = project.local_state().upstream().ok_or_else(|| {
        CoreError::InvalidPlan("Project has no reviewed upstream branch".to_owned())
    })?;
    let (remote, upstream_branch) = upstream.split_once('/').ok_or_else(|| {
        CoreError::InvalidPlan("Project upstream is not a remote branch".to_owned())
    })?;
    validate_remote_name(remote)?;
    if !project
        .remotes()
        .iter()
        .any(|candidate| candidate.name() == remote)
    {
        return invalid("Project upstream remote is not configured");
    }
    let branch = match project.local_state().head() {
        ProjectHead::Branch(branch) => branch,
        _ => return invalid("Project does not have an attached branch to synchronize"),
    };
    let local_reference = format!("refs/heads/{branch}");
    let remote_reference = format!("refs/heads/{upstream_branch}");
    validate_reference(&local_reference)?;
    validate_reference(&remote_reference)?;
    ensure_project_observation_current(git, project)?;
    let local = read_local_object(git, project.root(), &local_reference)?;
    let remote_object = read_remote_object(git, project.root(), remote, &remote_reference)?;
    if local != remote_object {
        return invalid("Project upstream changed after its verified local audit");
    }
    Ok(())
}

fn run_publication_observation(
    git: &impl GitPublicationProcess,
    repository: &Path,
    operation: GitPublicationOperation<'_>,
) -> Result<Vec<u8>, CoreError> {
    let output = git
        .run(repository, operation)
        .map_err(|source| CoreError::Io {
            action: "revalidate local Project observation",
            path: repository.to_path_buf(),
            source,
        })?;
    if output.status_code != Some(0) {
        return invalid("local Project observation could not be revalidated");
    }
    Ok(output.stdout)
}

fn validate_remote_name(remote: &str) -> Result<(), CoreError> {
    if remote.is_empty()
        || remote.starts_with('-')
        || !remote
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return invalid("Push Plan remote name is unsafe");
    }
    Ok(())
}

fn validate_reference(reference: &str) -> Result<(), CoreError> {
    let unsafe_character = reference.bytes().any(|byte| {
        byte.is_ascii_control()
            || byte == b' '
            || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
    });
    if !reference.starts_with("refs/")
        || reference.starts_with('-')
        || reference.contains("..")
        || reference.contains("@{")
        || reference.contains("//")
        || reference.ends_with('/')
        || reference.ends_with('.')
        || reference.ends_with(".lock")
        || unsafe_character
    {
        return invalid("Push Plan contains an unsafe Git reference");
    }
    Ok(())
}

fn read_local_object(
    git: &impl GitPublicationProcess,
    repository: &Path,
    reference: &str,
) -> Result<String, CoreError> {
    let reference = GitReference::parse(reference)?;
    let output = git
        .run(
            repository,
            GitPublicationOperation::ReadLocalReference {
                reference: &reference,
            },
        )
        .map_err(|source| CoreError::Io {
            action: "observe local Git reference",
            path: repository.to_path_buf(),
            source,
        })?;
    if output.status_code != Some(0) {
        return invalid("local Git reference could not be observed");
    }
    parse_object_identifier(&output.stdout)
}

fn read_remote_object(
    git: &impl GitPublicationProcess,
    repository: &Path,
    remote: &str,
    reference: &str,
) -> Result<String, CoreError> {
    read_remote_object_optional(git, repository, remote, reference)?.ok_or_else(|| {
        CoreError::InvalidPlan("remote Git reference could not be observed".to_owned())
    })
}

fn read_remote_object_optional(
    git: &impl GitPublicationProcess,
    repository: &Path,
    remote: &str,
    reference: &str,
) -> Result<Option<String>, CoreError> {
    let remote_name = GitRemoteName::parse(remote)?;
    let parsed_reference = GitReference::parse(reference)?;
    let output = git
        .run(
            repository,
            GitPublicationOperation::ReadRemoteReference {
                remote: &remote_name,
                reference: &parsed_reference,
            },
        )
        .map_err(|source| CoreError::Io {
            action: "observe remote Git reference",
            path: repository.to_path_buf(),
            source,
        })?;
    if output.status_code == Some(2) && output.stdout.is_empty() {
        return Ok(None);
    }
    if output.status_code != Some(0) {
        return invalid("remote Git reference could not be observed");
    }
    let mut fields = output
        .stdout
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let object = fields.next().unwrap_or_default();
    let advertised_reference = fields.next().unwrap_or_default();
    if advertised_reference != reference.as_bytes() || fields.next().is_some() {
        return invalid("Git did not advertise the exact remote Git reference");
    }
    parse_object_identifier(object).map(Some)
}

fn parse_object_identifier(bytes: &[u8]) -> Result<String, CoreError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CoreError::InvalidPlan("Git object identifier was not Unicode".to_owned()))?
        .trim();
    if !(text.len() == 40 || text.len() == 64) || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return invalid("Git returned an invalid object identifier");
    }
    Ok(text.to_ascii_lowercase())
}

fn ensure_ancestor(
    git: &impl GitPublicationProcess,
    repository: &Path,
    ancestor: &str,
    descendant: &str,
) -> Result<(), CoreError> {
    let ancestor = GitObjectIdentifier::parse(ancestor)?;
    let descendant = GitObjectIdentifier::parse(descendant)?;
    let output = git
        .run(
            repository,
            GitPublicationOperation::CheckAncestor {
                ancestor: &ancestor,
                descendant: &descendant,
            },
        )
        .map_err(|source| CoreError::Io {
            action: "check Git publication ancestry",
            path: repository.to_path_buf(),
            source,
        })?;
    if output.status_code != Some(0) {
        return invalid("behind or diverged Git references require manual reconciliation");
    }
    Ok(())
}

fn action_id(
    project_id: &str,
    local_reference: &str,
    remote_reference: &str,
    old_object: &str,
    new_object: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza push action v1\0");
    for field in [
        project_id,
        local_reference,
        remote_reference,
        old_object,
        new_object,
    ] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    format!("push_action_{}", &hasher.finalize().to_hex()[..24])
}

fn push_plan_hash(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza immutable Push Plan v1\0");
    hasher.update(bytes);
    format!("push_plan_blake3_{}", hasher.finalize().to_hex())
}

fn encode_push_plan(document: &PushPlanDocument) -> Result<String, CoreError> {
    toml::to_string_pretty(document).map_err(|error| CoreError::InvalidPlan(error.to_string()))
}

fn encode_approval(document: &PushApprovalDocument) -> Result<String, CoreError> {
    toml::to_string_pretty(document).map_err(|error| CoreError::InvalidPlan(error.to_string()))
}

fn read_canonical_push_plan(path: &Path) -> Result<(PushPlanDocument, Vec<u8>), CoreError> {
    let bytes = read_bounded(path, "read Push Plan")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CoreError::InvalidPlan("Push Plan is not Unicode".to_owned()))?;
    let document: PushPlanDocument =
        toml::from_str(text).map_err(|error| CoreError::InvalidPlan(error.to_string()))?;
    validate_push_plan_document(&document)?;
    if encode_push_plan(&document)?.as_bytes() != bytes {
        return invalid("Push Plan is not in canonical form");
    }
    Ok((document, bytes))
}

fn validate_push_plan_document(document: &PushPlanDocument) -> Result<(), CoreError> {
    if document.schema_version != PUSH_PLAN_SCHEMA_VERSION
        || document.document_kind != "push-plan"
        || document.policy != "non-force-only"
        || document.warning != PUBLICATION_WARNING
        || document.actions.is_empty()
        || document.expires_unix_seconds <= document.created_unix_seconds
        || document.expires_unix_seconds - document.created_unix_seconds > 15 * 60
    {
        return invalid("Push Plan document contract is invalid");
    }
    validate_remote_name(&document.remote)?;
    for action in &document.actions {
        validate_reference(&action.local_reference)?;
        validate_reference(&action.remote_reference)?;
        let action_contract_valid = match action.action_class.as_str() {
            "existing-upstream-branch" => {
                !action.requires_item_approval
                    && parse_object_identifier(action.expected_old_remote_object.as_bytes()).is_ok()
            }
            "new-remote-branch" | "tag" => {
                action.requires_item_approval && action.expected_old_remote_object == "absent"
            }
            _ => false,
        };
        if !action_contract_valid
            || parse_object_identifier(action.proposed_new_remote_object.as_bytes()).is_err()
        {
            return invalid("Push Plan action contract is invalid");
        }
        let expected_id = action_id(
            &document.project_id,
            &action.local_reference,
            &action.remote_reference,
            &action.expected_old_remote_object,
            &action.proposed_new_remote_object,
        );
        if action.action_id != expected_id {
            return invalid("Push Plan action identity is invalid");
        }
    }
    Ok(())
}

fn unix_time_now() -> Result<u64, CoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CoreError::InvalidPlan("system clock is before the Unix epoch".to_owned()))
}

fn random_receipt_id() -> Result<String, CoreError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| CoreError::InvalidPlan("operating-system entropy failed".to_owned()))?;
    let mut id = String::from("push_receipt_");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut id, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(id)
}

fn valid_receipt_id(receipt_id: &str) -> bool {
    receipt_id
        .strip_prefix("push_receipt_")
        .is_some_and(|suffix| {
            suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn read_canonical_approval(path: &Path) -> Result<PushApprovalDocument, CoreError> {
    let bytes = read_bounded(path, "read Push Plan approval")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CoreError::InvalidPlan("Push Plan approval is not Unicode".to_owned()))?;
    let document: PushApprovalDocument =
        toml::from_str(text).map_err(|error| CoreError::InvalidPlan(error.to_string()))?;
    if document.schema_version != PUSH_APPROVAL_SCHEMA_VERSION
        || document.document_kind != "push-plan-approval"
        || document.remote_side_effects_acknowledgement != "remote-side-effects-v1"
        || !document.push_plan_hash.starts_with("push_plan_blake3_")
        || !valid_receipt_id(&document.receipt_id)
        || document.approved_unix_seconds == 0
        || document
            .approved_action_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return invalid("Push Plan approval contract is invalid");
    }
    if encode_approval(&document)?.as_bytes() != bytes {
        return invalid("Push Plan approval is not in canonical form");
    }
    Ok(document)
}

fn read_bounded(path: &Path, action: &'static str) -> Result<Vec<u8>, CoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|source| CoreError::Io {
        action,
        path: path.to_path_buf(),
        source,
    })?;
    if !file
        .metadata()
        .map_err(|source| CoreError::Io {
            action,
            path: path.to_path_buf(),
            source,
        })?
        .is_file()
    {
        return invalid("publication document must be a regular file");
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CoreError::Io {
            action,
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() > 1024 * 1024 {
        return invalid("publication document exceeds the one-megabyte limit");
    }
    Ok(bytes)
}

fn write_exclusive_synced(
    path: &Path,
    bytes: &[u8],
    action: &'static str,
) -> Result<(), CoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                CoreError::DestinationAlreadyExists(path.to_path_buf())
            } else {
                CoreError::Io {
                    action,
                    path: path.to_path_buf(),
                    source,
                }
            }
        })?;
    file.write_all(bytes).map_err(|source| CoreError::Io {
        action,
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| CoreError::Io {
        action,
        path: path.to_path_buf(),
        source,
    })?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| CoreError::Io {
                action,
                path: parent.to_path_buf(),
                source,
            })?;
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T, CoreError> {
    Err(CoreError::InvalidPlan(message.to_owned()))
}
