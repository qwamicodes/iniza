use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{PlanEngine, ProjectAuditEngine, ProjectAuditRequest, ScanRequest};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-project-audit-cli-{name}-{}-{unique}",
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
fn owner_and_automation_receive_the_same_project_gaps_without_machine_path_leaks() {
    let directory = TestDirectory::new("reports");
    let project_root = directory.path.join("private-project");
    let plan_path = directory.path.join("iniza.toml");
    init_repository(&project_root);
    fs::write(
        project_root.join("private-source.txt"),
        "private Project marker 74f3d9\n",
    )
    .expect("private Project fixture should be written");
    fs::write(project_root.join(".gitignore"), "private-settings.local\n")
        .expect("synthetic ignore rule should be written");
    fs::write(
        project_root.join("private-settings.local"),
        "synthetic local setting\n",
    )
    .expect("synthetic ignored setting should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("required Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    plan.write_to(&plan_path)
        .expect("approved Plan should be written");

    let human = iniza(&[
        "projects",
        "scan",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
    ]);
    assert_eq!(human.status.code(), Some(1));
    let human_text = String::from_utf8_lossy(&human.stdout);
    assert!(human_text.contains("Restorable gap:"));
    assert!(human_text.contains("Synchronized gap:"));
    assert!(human_text.contains("ignored state: complete (1 pending, 0 excluded by Plan)"));
    assert!(human_text.contains("private-settings.local"));
    assert!(
        human_text.contains(
            &fs::canonicalize(&project_root)
                .unwrap()
                .display()
                .to_string()
        )
    );

    let machine = iniza(&[
        "--json",
        "--json-events",
        "projects",
        "scan",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
    ]);
    assert_eq!(machine.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&machine.stdout).lines().count(), 1);
    let value: serde_json::Value = serde_json::from_slice(&machine.stdout)
        .expect("machine Project audit should be valid JavaScript Object Notation");
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["command"], "projects scan");
    assert_eq!(value["status"], "success-with-gaps");
    assert_eq!(
        value["data"]["projects"][0]["ignored_state"]["state"],
        "complete"
    );
    assert_eq!(
        value["data"]["projects"][0]["ignored_state"]["candidate_count"],
        1
    );
    let events = String::from_utf8_lossy(&machine.stderr)
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("progress event should be valid JavaScript Object Notation Lines")
        })
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event"], "project-audit-started");
    assert_eq!(events[1]["event"], "project-audit-completed");
    assert_eq!(events[1]["project_count"], 1);
    let machine_text = format!(
        "{}{}",
        String::from_utf8_lossy(&machine.stdout),
        String::from_utf8_lossy(&machine.stderr)
    );
    assert!(!machine_text.contains(&project_root.display().to_string()));
    assert!(!machine_text.contains("private-source.txt"));
    assert!(!machine_text.contains("private-settings.local"));
    assert!(!machine_text.contains("private Project marker 74f3d9"));
}

#[test]
fn ineligible_remote_overlay_decision_never_writes_a_revised_plan() {
    let directory = TestDirectory::new("ineligible-overlay");
    let project_root = directory.path.join("private-project");
    let plan_path = directory.path.join("approved.toml");
    let revised_path = directory.path.join("revised.toml");
    init_repository(&project_root);
    git(&project_root, &["config", "user.name", "Synthetic Owner"]);
    git(
        &project_root,
        &["config", "user.email", "synthetic@example.invalid"],
    );
    fs::write(
        project_root.join("tracked.txt"),
        "synthetic tracked state\n",
    )
    .expect("tracked fixture should be written");
    fs::write(project_root.join(".gitignore"), ".env\n").expect("ignore fixture should be written");
    git(&project_root, &["add", "tracked.txt", ".gitignore"]);
    git(&project_root, &["commit", "-q", "-m", "synthetic fixture"]);
    fs::write(project_root.join(".env"), "SYNTHETIC_ONLY=value\n")
        .expect("ignored fixture should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&project_root))
        .expect("Project should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    plan.write_to(&plan_path)
        .expect("approved Plan should be written");
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .expect("local Project audit should succeed");
    let project = &audit.projects()[0];
    let candidate = &project
        .ignored_candidates()
        .expect("ignored inventory should be complete")[0];
    let selection = format!("{}:project_protection_blake3_stale", project.id());
    let ignored = format!("{}:{}", project.id(), candidate.id());

    let result = iniza(&[
        "projects",
        "scan",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
        "--remote-check",
        "--remote-overlay",
        &selection,
        "--include-ignored",
        &ignored,
        "--output-plan",
        revised_path
            .to_str()
            .expect("revised Plan path should be text"),
    ]);

    assert!(!result.status.success());
    assert!(!revised_path.exists());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("stale or is not eligible for remote reconstruction")
    );
}

fn iniza(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iniza"))
        .args(arguments)
        .output()
        .expect("iniza should run")
}

fn init_repository(path: &Path) {
    fs::create_dir_all(path).expect("repository directory should be created");
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["init", "-q"])
        .output()
        .expect("Git fixture command should start");
    assert!(
        output.status.success(),
        "Git repository should initialize: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git(path: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(arguments)
        .output()
        .expect("Git fixture command should start");
    assert!(
        output.status.success(),
        "Git fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
