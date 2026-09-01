use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use crate::{CoreError, Plan, PlanApprovalState, ProtectionRequirement};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectKind {
    WorkingTree,
    BareRepository,
    Submodule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectHead {
    Branch(String),
    Detached(String),
    Unborn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectLocalState {
    head: ProjectHead,
    upstream: Option<String>,
    ahead: Option<u64>,
    behind: Option<u64>,
    staged_changes: u64,
    unstaged_changes: u64,
    untracked_items: u64,
    stash_count: u64,
    local_only_branches: Vec<String>,
    local_only_tags: Vec<String>,
    changed_during_audit: bool,
    verified: bool,
}

impl ProjectLocalState {
    pub fn head(&self) -> &ProjectHead {
        &self.head
    }

    pub fn upstream(&self) -> Option<&str> {
        self.upstream.as_deref()
    }

    pub fn ahead(&self) -> Option<u64> {
        self.ahead
    }

    pub fn behind(&self) -> Option<u64> {
        self.behind
    }

    pub fn staged_changes(&self) -> u64 {
        self.staged_changes
    }

    pub fn unstaged_changes(&self) -> u64 {
        self.unstaged_changes
    }

    pub fn untracked_items(&self) -> u64 {
        self.untracked_items
    }

    pub fn stash_count(&self) -> u64 {
        self.stash_count
    }

    pub fn local_only_branches(&self) -> &[String] {
        &self.local_only_branches
    }

    pub fn local_only_tags(&self) -> &[String] {
        &self.local_only_tags
    }

    pub fn changed_during_audit(&self) -> bool {
        self.changed_during_audit
    }

    pub fn verified(&self) -> bool {
        self.verified
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectAudit {
    id: String,
    root: PathBuf,
    kind: ProjectKind,
    protection_requirement: ProtectionRequirement,
    local_state: ProjectLocalState,
    remotes: Vec<SanitizedRemote>,
    ignored_candidates: Vec<IgnoredCandidate>,
    submodules: Vec<ProjectSubmodule>,
    git_large_file_storage: GitLargeFileStorageAudit,
}

impl ProjectAudit {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn kind(&self) -> ProjectKind {
        self.kind
    }

    pub fn protection_requirement(&self) -> ProtectionRequirement {
        self.protection_requirement
    }

    pub fn local_state(&self) -> &ProjectLocalState {
        &self.local_state
    }

    pub fn remotes(&self) -> &[SanitizedRemote] {
        &self.remotes
    }

    pub fn ignored_candidates(&self) -> &[IgnoredCandidate] {
        &self.ignored_candidates
    }

    pub fn submodules(&self) -> &[ProjectSubmodule] {
        &self.submodules
    }

    pub fn git_large_file_storage(&self) -> &GitLargeFileStorageAudit {
        &self.git_large_file_storage
    }

    pub fn changed_during_audit(&self) -> bool {
        self.local_state.changed_during_audit()
    }

    pub fn local_audit_verified(&self) -> bool {
        self.local_state.verified()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSubmodule {
    relative_path: PathBuf,
    initialized: bool,
}

impl ProjectSubmodule {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn initialized(&self) -> bool {
        self.initialized
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GitLargeFileStorageAudit {
    configured: bool,
    pointer_files: u64,
}

impl GitLargeFileStorageAudit {
    pub fn configured(&self) -> bool {
        self.configured
    }

    pub fn pointer_files(&self) -> u64 {
        self.pointer_files
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IgnoredReview {
    SuggestedExclusion,
    RequiresReview,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoredCandidate {
    id: String,
    relative_path: PathBuf,
    review: IgnoredReview,
    explanation: String,
}

impl IgnoredCandidate {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn review(&self) -> IgnoredReview {
        self.review
    }

    pub fn explanation(&self) -> &str {
        &self.explanation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedRemote {
    name: String,
    address: String,
    check_outcome: RemoteCheckOutcome,
}

impl SanitizedRemote {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn check_outcome(&self) -> &RemoteCheckOutcome {
        &self.check_outcome
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCheckOutcome {
    NotRequested,
    Reachable,
    Failed { code: String },
}

pub struct ProjectAuditRequest<'a> {
    plan: &'a Plan,
    remote_check: bool,
}

impl<'a> ProjectAuditRequest<'a> {
    pub fn from_plan(plan: &'a Plan) -> Self {
        Self {
            plan,
            remote_check: false,
        }
    }

    pub fn with_remote_check(mut self) -> Self {
        self.remote_check = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectAuditReport {
    projects: Vec<ProjectAudit>,
}

impl ProjectAuditReport {
    pub fn projects(&self) -> &[ProjectAudit] {
        &self.projects
    }

    pub fn to_human_text(&self) -> String {
        let mut lines = vec![format!("Projects audited: {}", self.projects.len())];
        for project in &self.projects {
            lines.push(String::new());
            lines.push(format!(
                "{}  {}",
                project.id,
                safe_path_display(&project.root)
            ));
            lines.push(format!("  kind: {}", project_kind_name(project.kind)));
            lines.push(format!(
                "  requirement: {}",
                protection_requirement_name(project.protection_requirement)
            ));
            lines.push(format!("  head: {}", human_head(&project.local_state.head)));
            lines.push(format!(
                "  working tree: {} staged, {} unstaged, {} untracked",
                project.local_state.staged_changes,
                project.local_state.unstaged_changes,
                project.local_state.untracked_items,
            ));
            for remote in &project.remotes {
                lines.push(format!(
                    "  remote: {} {} ({})",
                    remote.name,
                    remote.address,
                    remote_check_name(&remote.check_outcome),
                ));
            }
            for candidate in &project.ignored_candidates {
                lines.push(format!(
                    "  ignored review: {} — {}",
                    safe_path_display(&candidate.relative_path),
                    ignored_review_name(candidate.review),
                ));
            }
            for gap in project.restorable_gaps() {
                lines.push(format!("  Restorable gap: {gap}"));
            }
            for gap in project.synchronized_gaps() {
                lines.push(format!("  Synchronized gap: {gap}"));
            }
        }
        lines.join("\n")
    }

    pub fn machine_json_result(&self) -> String {
        let projects = self
            .projects
            .iter()
            .map(|project| {
                let ignored_candidates = project
                    .ignored_candidates
                    .iter()
                    .map(|candidate| {
                        serde_json::json!({
                            "item_id": candidate.id,
                            "review": ignored_review_name(candidate.review),
                        })
                    })
                    .collect::<Vec<_>>();
                let remote_checks = project
                    .remotes
                    .iter()
                    .map(|remote| {
                        serde_json::json!({
                            "name": remote.name,
                            "address": remote.address,
                            "check": remote_check_name(&remote.check_outcome),
                        })
                    })
                    .collect::<Vec<_>>();
                serde_json::json!({
                    "project_id": project.id,
                    "kind": project_kind_name(project.kind),
                    "protection_requirement": protection_requirement_name(project.protection_requirement),
                    "local_audit": {
                        "verified": project.local_state.verified,
                        "changed": project.local_state.changed_during_audit,
                        "head_state": machine_head_name(&project.local_state.head),
                        "upstream_configured": project.local_state.upstream.is_some(),
                        "ahead": project.local_state.ahead,
                        "behind": project.local_state.behind,
                        "staged_changes": project.local_state.staged_changes,
                        "unstaged_changes": project.local_state.unstaged_changes,
                        "untracked_items": project.local_state.untracked_items,
                        "stash_count": project.local_state.stash_count,
                        "local_only_branch_count": project.local_state.local_only_branches.len(),
                        "local_only_tag_count": project.local_state.local_only_tags.len(),
                    },
                    "remote_checks": remote_checks,
                    "ignored_candidates": ignored_candidates,
                    "submodule_count": project.submodules.len(),
                    "git_large_file_storage": {
                        "configured": project.git_large_file_storage.configured,
                        "pointer_files": project.git_large_file_storage.pointer_files,
                    },
                    "restorable": {
                        "state": "gap",
                        "reasons": project.restorable_gaps(),
                    },
                    "synchronized": {
                        "state": "gap",
                        "reasons": project.synchronized_gaps(),
                    },
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema_version": 1,
            "command": "projects scan",
            "status": "success-with-gaps",
            "data": {
                "project_count": projects.len(),
                "projects": projects,
            },
            "warnings": [],
            "errors": [],
        })
        .to_string()
    }
}

impl ProjectAudit {
    fn restorable_gaps(&self) -> Vec<&'static str> {
        let mut gaps = vec!["a verified Project Capsule and Restore Rehearsal do not exist yet"];
        if !self.local_state.verified {
            gaps.push("the local Project audit is unverified");
        }
        gaps
    }

    fn synchronized_gaps(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        if self.remotes.is_empty() {
            gaps.push("no configured remote was found");
        }
        if self
            .remotes
            .iter()
            .any(|remote| remote.check_outcome == RemoteCheckOutcome::NotRequested)
        {
            gaps.push("remote reachability was not requested");
        }
        if self
            .remotes
            .iter()
            .any(|remote| matches!(remote.check_outcome, RemoteCheckOutcome::Failed { .. }))
        {
            gaps.push("a requested remote check failed");
        }
        if self.local_state.upstream.is_none() {
            gaps.push("the current branch has no upstream");
        }
        if self.local_state.behind.is_some_and(|count| count > 0) {
            gaps.push("the current branch is behind its locally known upstream");
        }
        if self.local_state.ahead.is_some_and(|count| count > 0) {
            gaps.push("ahead commits require a separately reviewed Push Plan");
        }
        if !self.local_state.local_only_branches.is_empty()
            || !self.local_state.local_only_tags.is_empty()
        {
            gaps.push("local-only references require capsule protection or a publication decision");
        }
        if gaps.is_empty() {
            gaps.push("remote synchronization evidence is not yet bound to a Receipt");
        }
        gaps
    }
}

fn project_kind_name(kind: ProjectKind) -> &'static str {
    match kind {
        ProjectKind::WorkingTree => "working-tree",
        ProjectKind::BareRepository => "bare-repository",
        ProjectKind::Submodule => "submodule",
    }
}

fn protection_requirement_name(requirement: ProtectionRequirement) -> &'static str {
    match requirement {
        ProtectionRequirement::MustProtect => "must-protect",
        ProtectionRequirement::Optional => "optional",
    }
}

fn human_head(head: &ProjectHead) -> String {
    match head {
        ProjectHead::Branch(branch) => format!("branch {branch}"),
        ProjectHead::Detached(commit) => format!("detached at {commit}"),
        ProjectHead::Unborn => "unborn".to_owned(),
    }
}

fn machine_head_name(head: &ProjectHead) -> &'static str {
    match head {
        ProjectHead::Branch(_) => "branch",
        ProjectHead::Detached(_) => "detached",
        ProjectHead::Unborn => "unborn",
    }
}

fn ignored_review_name(review: IgnoredReview) -> &'static str {
    match review {
        IgnoredReview::SuggestedExclusion => "suggested-exclusion",
        IgnoredReview::RequiresReview => "requires-review",
    }
}

fn remote_check_name(outcome: &RemoteCheckOutcome) -> &'static str {
    match outcome {
        RemoteCheckOutcome::NotRequested => "not-requested",
        RemoteCheckOutcome::Reachable => "reachable",
        RemoteCheckOutcome::Failed { .. } => "failed",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitProcessOutput {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait GitProcess {
    fn run(&self, repository: &Path, arguments: &[OsString]) -> io::Result<GitProcessOutput>;
}

#[derive(Debug, Clone)]
pub struct InstalledGit {
    executable: PathBuf,
}

impl Default for InstalledGit {
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

impl InstalledGit {
    pub fn with_executable(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
        }
    }
}

impl GitProcess for InstalledGit {
    fn run(&self, repository: &Path, arguments: &[OsString]) -> io::Result<GitProcessOutput> {
        let mut command = Command::new(&self.executable);
        command
            .arg("--no-optional-locks")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("color.ui=false")
            .arg("-c")
            .arg("credential.helper=")
            .arg("-c")
            .arg("protocol.allow=never")
            .arg("-c")
            .arg("protocol.https.allow=always")
            .arg("-c")
            .arg("protocol.ssh.allow=always")
            .arg("-c")
            .arg("protocol.ext.allow=never")
            .arg("-c")
            .arg("protocol.file.allow=never")
            .arg("-c")
            .arg("protocol.git.allow=never")
            .arg("-c")
            .arg("core.sshCommand=/usr/bin/ssh")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "Never")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env(
                "PATH",
                "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("Git standard output was not captured"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("Git standard error was not captured"))?;
        let stdout_reader = thread::spawn(move || capture_git_stream(stdout));
        let stderr_reader = thread::spawn(move || capture_git_stream(stderr));
        let status = child.wait()?;
        let (stdout, stdout_oversized) = join_git_stream(stdout_reader)?;
        let (stderr, stderr_oversized) = join_git_stream(stderr_reader)?;
        if stdout_oversized || stderr_oversized {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Git command output exceeded the safe limit",
            ));
        }
        Ok(GitProcessOutput {
            status_code: status.code(),
            stdout,
            stderr,
        })
    }
}

const MAX_GIT_STREAM_BYTES: usize = 1024 * 1024;

fn capture_git_stream(mut stream: impl Read) -> io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::new();
    let mut oversized = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_GIT_STREAM_BYTES.saturating_sub(captured.len());
        let retained = remaining.min(read);
        captured.extend_from_slice(&buffer[..retained]);
        oversized |= retained < read;
    }
    Ok((captured, oversized))
}

fn join_git_stream(
    reader: thread::JoinHandle<io::Result<(Vec<u8>, bool)>>,
) -> io::Result<(Vec<u8>, bool)> {
    reader
        .join()
        .map_err(|_| io::Error::other("Git output reader stopped unexpectedly"))?
}

#[derive(Debug)]
pub struct ProjectAuditEngine<G = InstalledGit> {
    git: G,
}

impl ProjectAuditEngine<InstalledGit> {
    pub fn local() -> Self {
        Self {
            git: InstalledGit::default(),
        }
    }
}

impl<G> ProjectAuditEngine<G> {
    pub fn with_git_process(git: G) -> Self {
        Self { git }
    }
}

impl<G: GitProcess> ProjectAuditEngine<G> {
    pub fn audit(&self, request: ProjectAuditRequest<'_>) -> Result<ProjectAuditReport, CoreError> {
        if !request.plan.is_directory_plan()
            || request.plan.approval_state()? != PlanApprovalState::Approved
        {
            return Err(CoreError::InvalidPlan(
                "Project audit requires an approved, non-stale directory Plan".to_owned(),
            ));
        }

        let mut discovered = BTreeMap::<PathBuf, ProjectKind>::new();
        for approved_root in request.plan.approved_roots() {
            discover_projects(approved_root, approved_root, &mut discovered)?;
        }

        let mut projects = Vec::with_capacity(discovered.len());
        for (root, kind) in discovered {
            let plan_root = request
                .plan
                .approved_roots()
                .iter()
                .find(|approved_root| root.starts_with(approved_root))
                .ok_or_else(|| {
                    CoreError::InvalidPlan("discovered Project escaped approved roots".to_owned())
                })?;
            let relative = root.strip_prefix(plan_root).map_err(|_| {
                CoreError::InvalidPlan("discovered Project escaped approved roots".to_owned())
            })?;
            let relative = if relative.as_os_str().is_empty() {
                Path::new(".")
            } else {
                relative
            };
            let item = request
                .plan
                .items()
                .iter()
                .find(|item| item.relative_path == relative)
                .ok_or_else(|| {
                    CoreError::InvalidPlan(
                        "discovered Project has no matching Migration Item".to_owned(),
                    )
                })?;
            let id = stable_project_id(&item.id);
            let remote_audit = audit_remotes(&self.git, &root, request.remote_check);
            let local_state =
                audit_local_state(&self.git, &root, kind, remote_audit.published_tags.as_ref());
            let remotes = remote_audit.remotes;
            let ignored_candidates = audit_ignored_candidates(&self.git, &root, kind, &id);
            let submodules = audit_submodules(&self.git, &root, kind);
            let git_large_file_storage = audit_git_large_file_storage(&root, kind);
            projects.push(ProjectAudit {
                id,
                root,
                kind,
                protection_requirement: item.protection_requirement,
                local_state,
                remotes,
                ignored_candidates,
                submodules,
                git_large_file_storage,
            });
        }

        Ok(ProjectAuditReport { projects })
    }
}

fn audit_submodules(
    git: &impl GitProcess,
    root: &Path,
    kind: ProjectKind,
) -> Vec<ProjectSubmodule> {
    if kind == ProjectKind::BareRepository || !root.join(".gitmodules").is_file() {
        return Vec::new();
    }
    let Some(output) = run_optional_bytes(
        git,
        root,
        &[
            "config",
            "--null",
            "--file",
            ".gitmodules",
            "--get-regexp",
            "^submodule\\..*\\.path$",
        ],
    ) else {
        return Vec::new();
    };
    let mut submodules = output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .filter_map(|record| {
            let separator = record.iter().position(|byte| *byte == b'\n')?;
            let relative_path =
                PathBuf::from(String::from_utf8_lossy(&record[separator + 1..]).into_owned());
            if !is_safe_relative_path(&relative_path) {
                return None;
            }
            let dot_git = root.join(&relative_path).join(".git");
            Some(ProjectSubmodule {
                relative_path,
                initialized: dot_git.is_file() || dot_git.is_dir(),
            })
        })
        .collect::<Vec<_>>();
    submodules.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    submodules.dedup_by(|left, right| left.relative_path == right.relative_path);
    submodules
}

fn audit_git_large_file_storage(root: &Path, kind: ProjectKind) -> GitLargeFileStorageAudit {
    if kind == ProjectKind::BareRepository {
        return GitLargeFileStorageAudit::default();
    }
    let mut audit = GitLargeFileStorageAudit::default();
    scan_large_file_storage_indicators(root, root, &mut audit);
    audit
}

fn scan_large_file_storage_indicators(
    project_root: &Path,
    directory: &Path,
    audit: &mut GitLargeFileStorageAudit,
) {
    if directory != project_root && directory.join(".git").exists() {
        return;
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name() == ".git" {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_dir() && !is_generated_tree_name(&entry.file_name()) {
            scan_large_file_storage_indicators(project_root, &path, audit);
        } else if metadata.file_type().is_file()
            && ((entry.file_name() == ".gitattributes" && metadata.len() <= 1024 * 1024)
                || metadata.len() <= 1024)
        {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            if entry.file_name() == ".gitattributes"
                && bytes
                    .windows(b"filter=lfs".len())
                    .any(|window| window == b"filter=lfs")
            {
                audit.configured = true;
            }
            if metadata.len() <= 1024
                && bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n")
                && bytes
                    .windows(b"\noid sha256:".len())
                    .any(|window| window == b"\noid sha256:")
                && bytes
                    .windows(b"\nsize ".len())
                    .any(|window| window == b"\nsize ")
            {
                audit.pointer_files = audit.pointer_files.saturating_add(1);
            }
        }
    }
}

fn audit_ignored_candidates(
    git: &impl GitProcess,
    root: &Path,
    kind: ProjectKind,
    project_id: &str,
) -> Vec<IgnoredCandidate> {
    if kind == ProjectKind::BareRepository {
        return Vec::new();
    }
    let Some(output) = run_optional_bytes(
        git,
        root,
        &[
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        ],
    ) else {
        return Vec::new();
    };
    let mut candidates = output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .filter_map(|record| {
            let relative_path = PathBuf::from(String::from_utf8_lossy(record).into_owned());
            if !is_safe_relative_path(&relative_path) {
                return None;
            }
            let generated = relative_path.components().any(|component| {
                matches!(
                    component,
                    Component::Normal(name)
                        if name == "node_modules"
                            || name == "target"
                            || name == "dist"
                            || name == "build"
                            || name == ".next"
                )
            });
            let (review, explanation) = if generated {
                (
                    IgnoredReview::SuggestedExclusion,
                    "known regenerable dependency or build output",
                )
            } else {
                (
                    IgnoredReview::RequiresReview,
                    ignored_review_explanation(&relative_path),
                )
            };
            Some(IgnoredCandidate {
                id: stable_ignored_id(project_id, &relative_path),
                relative_path,
                review,
                explanation: explanation.to_owned(),
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    candidates
}

fn ignored_review_explanation(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name == ".env" || name.starts_with(".env.") {
        "likely secret or local configuration"
    } else if matches!(
        extension.as_str(),
        "pem" | "key" | "crt" | "cer" | "p12" | "pfx"
    ) {
        "certificate or private-key material"
    } else if matches!(extension.as_str(), "db" | "sqlite" | "sqlite3") {
        "database content requires a consistent export decision"
    } else if path
        .components()
        .any(|component| matches!(component, Component::Normal(value) if value == "uploads"))
    {
        "potentially irreplaceable uploaded content"
    } else if name.contains(".local") || name.contains("config") || name.contains("settings") {
        "local configuration requires review"
    } else {
        "ignored content is not proven regenerable"
    }
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn stable_ignored_id(project_id: &str, relative_path: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza ignored candidate v1\0");
    hasher.update(project_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(relative_path.to_string_lossy().as_bytes());
    format!("ignored_{}", &hasher.finalize().to_hex()[..24])
}

struct RemoteAudit {
    remotes: Vec<SanitizedRemote>,
    published_tags: Option<std::collections::BTreeSet<String>>,
}

fn audit_remotes(git: &impl GitProcess, root: &Path, remote_check: bool) -> RemoteAudit {
    let Some(output) = run_optional_bytes(
        git,
        root,
        &["config", "--null", "--get-regexp", "^remote\\..*\\.url$"],
    ) else {
        return RemoteAudit {
            remotes: Vec::new(),
            published_tags: Some(std::collections::BTreeSet::new()),
        };
    };
    let configured = output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .filter_map(|record| {
            let separator = record.iter().position(|byte| *byte == b'\n')?;
            let key = String::from_utf8_lossy(&record[..separator]);
            let name = key.strip_prefix("remote.")?.strip_suffix(".url")?;
            let address = String::from_utf8_lossy(&record[separator + 1..]);
            Some((
                name.to_owned(),
                SanitizedRemote {
                    name: safe_text(name),
                    address: sanitize_remote_address(&address),
                    check_outcome: RemoteCheckOutcome::NotRequested,
                },
            ))
        })
        .collect::<Vec<_>>();
    let mut all_reachable = remote_check;
    let mut published_tags = std::collections::BTreeSet::new();
    let mut remotes = configured
        .into_iter()
        .map(|(raw_name, mut remote)| {
            if remote_check {
                let arguments = [
                    OsString::from("ls-remote"),
                    OsString::from("--heads"),
                    OsString::from("--tags"),
                    OsString::from("--"),
                    OsString::from(raw_name),
                ];
                match git.run(root, &arguments) {
                    Ok(output) if output.status_code == Some(0) => {
                        remote.check_outcome = RemoteCheckOutcome::Reachable;
                        published_tags.extend(parse_advertised_tags(&output.stdout));
                    }
                    _ => {
                        remote.check_outcome = RemoteCheckOutcome::Failed {
                            code: "remote-check-failed".to_owned(),
                        };
                        all_reachable = false;
                    }
                }
            }
            remote
        })
        .collect::<Vec<_>>();
    remotes.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.address.cmp(&right.address))
    });
    RemoteAudit {
        remotes,
        published_tags: all_reachable.then_some(published_tags),
    }
}

fn parse_advertised_tags(bytes: &[u8]) -> std::collections::BTreeSet<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| line.split_once('\t').map(|(_, reference)| reference))
        .filter_map(|reference| reference.strip_prefix("refs/tags/"))
        .map(|tag| tag.strip_suffix("^{}").unwrap_or(tag))
        .map(safe_text)
        .filter(|tag| !tag.is_empty())
        .collect()
}

fn sanitize_remote_address(address: &str) -> String {
    let without_fragment = address.split('#').next().unwrap_or_default();
    let without_query = without_fragment.split('?').next().unwrap_or_default();
    let lower = without_query.to_ascii_lowercase();
    let sanitized = if lower.starts_with("file://") || lower.starts_with("ext::") {
        "local-path:[redacted]".to_owned()
    } else if let Some((scheme, remainder)) = without_query.split_once("://") {
        let (authority, path) = remainder
            .split_once('/')
            .map_or((remainder, ""), |(authority, path)| (authority, path));
        let authority = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        if path.is_empty() {
            format!("{scheme}://{authority}")
        } else {
            format!("{scheme}://{authority}/{path}")
        }
    } else if let Some((userinfo, remainder)) = without_query.split_once('@') {
        if userinfo.contains('/') || !remainder.contains(':') {
            "local-path:[redacted]".to_owned()
        } else {
            remainder.to_owned()
        }
    } else if without_query
        .split_once(':')
        .is_some_and(|(host, path)| !host.is_empty() && !host.contains('/') && !path.is_empty())
    {
        without_query.to_owned()
    } else {
        "local-path:[redacted]".to_owned()
    };
    safe_text(&sanitized)
}

fn safe_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn safe_path_display(path: &Path) -> String {
    safe_text(&path.to_string_lossy())
}

fn audit_local_state(
    git: &impl GitProcess,
    root: &Path,
    kind: ProjectKind,
    published_tags: Option<&std::collections::BTreeSet<String>>,
) -> ProjectLocalState {
    let before = observe_local_repository(git, root, kind);
    let branch = run_optional(git, root, &["symbolic-ref", "--quiet", "--short", "HEAD"]);
    let head = if let Some(branch) = branch {
        ProjectHead::Branch(safe_text(branch.trim()))
    } else if let Some(commit) = run_optional(git, root, &["rev-parse", "--verify", "HEAD"]) {
        ProjectHead::Detached(safe_text(commit.trim()))
    } else {
        ProjectHead::Unborn
    };
    let upstream = run_optional(
        git,
        root,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    )
    .map(|value| safe_text(value.trim()));
    let (behind, ahead) = if upstream.is_some() {
        run_optional(
            git,
            root,
            &["rev-list", "--left-right", "--count", "@{upstream}...HEAD"],
        )
        .and_then(|value| {
            let mut values = value.split_whitespace();
            Some((values.next()?.parse().ok()?, values.next()?.parse().ok()?))
        })
        .map_or((None, None), |(behind, ahead)| (Some(behind), Some(ahead)))
    } else {
        (None, None)
    };
    let (staged_changes, unstaged_changes, untracked_items) =
        before.as_ref().map_or((0, 0, 0), |observation| {
            parse_working_tree_counts(&observation.status)
        });
    let stash_count = run_optional(git, root, &["stash", "list", "--format=%H"])
        .map_or(0, |value| value.lines().count() as u64);
    let local_only_branches = run_optional(
        git,
        root,
        &[
            "for-each-ref",
            "--format=%(refname:short)%09%(upstream:short)",
            "refs/heads",
        ],
    )
    .map_or_else(Vec::new, |value| {
        value
            .lines()
            .filter_map(|line| {
                let (branch, upstream) = line.split_once('\t')?;
                upstream.is_empty().then(|| safe_text(branch))
            })
            .collect()
    });
    let local_only_tags = published_tags.map_or_else(Vec::new, |published| {
        run_optional(
            git,
            root,
            &["for-each-ref", "--format=%(refname:short)", "refs/tags"],
        )
        .map_or_else(Vec::new, |value| {
            value
                .lines()
                .map(safe_text)
                .filter(|tag| !tag.is_empty() && !published.contains(tag))
                .collect()
        })
    });
    let after = observe_local_repository(git, root, kind);
    let changed_during_audit =
        matches!((&before, &after), (Some(before), Some(after)) if before != after);
    let verified = matches!((&before, &after), (Some(before), Some(after)) if before == after);

    ProjectLocalState {
        head,
        upstream,
        ahead,
        behind,
        staged_changes,
        unstaged_changes,
        untracked_items,
        stash_count,
        local_only_branches,
        local_only_tags,
        changed_during_audit,
        verified,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LocalRepositoryObservation {
    status: Vec<u8>,
    references: Vec<u8>,
}

fn observe_local_repository(
    git: &impl GitProcess,
    root: &Path,
    kind: ProjectKind,
) -> Option<LocalRepositoryObservation> {
    let status = if kind == ProjectKind::BareRepository {
        Vec::new()
    } else {
        run_optional_bytes(
            git,
            root,
            &[
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=all",
            ],
        )?
    };
    let references = run_optional_bytes(
        git,
        root,
        &[
            "for-each-ref",
            "--format=%(objectname)%00%(refname)",
            "refs/heads",
            "refs/tags",
            "refs/stash",
        ],
    )?;
    Some(LocalRepositoryObservation { status, references })
}

fn run_optional(git: &impl GitProcess, root: &Path, arguments: &[&str]) -> Option<String> {
    let output = run_optional_bytes(git, root, arguments)?;
    Some(String::from_utf8_lossy(&output).into_owned())
}

fn run_optional_bytes(git: &impl GitProcess, root: &Path, arguments: &[&str]) -> Option<Vec<u8>> {
    let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
    let output = git.run(root, &arguments).ok()?;
    (output.status_code == Some(0)).then_some(output.stdout)
}

fn parse_working_tree_counts(bytes: &[u8]) -> (u64, u64, u64) {
    let mut staged = 0;
    let mut unstaged = 0;
    let mut untracked = 0;
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| record.len() >= 3)
    {
        match &record[..2] {
            b"??" => untracked += 1,
            b"!!" => {}
            status => {
                if status[0] != b' ' {
                    staged += 1;
                }
                if status[1] != b' ' {
                    unstaged += 1;
                }
            }
        }
    }
    (staged, unstaged, untracked)
}

fn discover_projects(
    approved_root: &Path,
    directory: &Path,
    discovered: &mut BTreeMap<PathBuf, ProjectKind>,
) -> Result<(), CoreError> {
    let canonical = fs::canonicalize(directory).map_err(|source| CoreError::Io {
        action: "resolve Project discovery path",
        path: directory.to_path_buf(),
        source,
    })?;
    if !canonical.starts_with(approved_root) {
        return Err(CoreError::InvalidPlan(
            "Project discovery escaped an approved root".to_owned(),
        ));
    }

    if let Some(kind) = project_kind(&canonical)? {
        discovered.insert(canonical.clone(), kind);
    }

    let entries = fs::read_dir(&canonical).map_err(|source| CoreError::Io {
        action: "read Project discovery directory",
        path: canonical.clone(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| CoreError::Io {
            action: "read Project discovery entry",
            path: canonical.clone(),
            source,
        })?;
        if entry.file_name() == ".git" || is_generated_tree_name(&entry.file_name()) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|source| CoreError::Io {
            action: "inspect Project discovery entry",
            path: entry.path(),
            source,
        })?;
        if metadata.file_type().is_dir() {
            discover_projects(approved_root, &entry.path(), discovered)?;
        }
    }
    Ok(())
}

fn is_generated_tree_name(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_str(),
        Some("node_modules" | "target" | "dist" | "build" | ".next")
    )
}

fn project_kind(directory: &Path) -> Result<Option<ProjectKind>, CoreError> {
    let dot_git = directory.join(".git");
    match fs::symlink_metadata(&dot_git) {
        Ok(metadata) if metadata.file_type().is_dir() => return Ok(Some(ProjectKind::WorkingTree)),
        Ok(metadata) if metadata.file_type().is_file() => return Ok(Some(ProjectKind::Submodule)),
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(CoreError::Io {
                action: "inspect Project metadata",
                path: dot_git,
                source,
            });
        }
    }
    if directory.join("HEAD").is_file()
        && directory.join("objects").is_dir()
        && directory.join("refs").is_dir()
    {
        Ok(Some(ProjectKind::BareRepository))
    } else {
        Ok(None)
    }
}

fn stable_project_id(migration_item_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza Project v1\0");
    hasher.update(migration_item_id.as_bytes());
    format!("project_{}", &hasher.finalize().to_hex()[..24])
}
