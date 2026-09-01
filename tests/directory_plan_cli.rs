use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::Plan;

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
            "iniza-directory-cli-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("test directory should be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn iniza(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iniza"))
        .args(arguments)
        .output()
        .expect("iniza should run")
}

#[test]
fn owner_and_automation_can_review_the_same_directory_plan_coverage() {
    let directory = TestDirectory::new("plan-show");
    let root = directory.path().join("developer-state");
    let plan_path = directory.path().join("iniza.toml");
    fs::create_dir_all(root.join("nested")).expect("approved root should be created");
    fs::write(
        root.join("settings.txt"),
        b"protected machine output marker",
    )
    .expect("settings fixture should be written");
    fs::write(root.join("nested/tool.txt"), b"tool").expect("tool fixture should be written");

    let scan = iniza(&[
        "scan",
        root.to_str().expect("root path should be text"),
        "--output-plan",
        plan_path.to_str().expect("Plan path should be text"),
    ]);
    assert!(
        scan.status.success(),
        "directory scan should succeed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    assert!(
        fs::read_to_string(&plan_path)
            .expect("Plan should be readable")
            .contains("plan_kind = \"directory\"")
    );

    let human = iniza(&[
        "plan",
        "show",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
    ]);
    assert!(human.status.success());
    let human_output = String::from_utf8_lossy(&human.stdout);
    assert!(human_output.contains("Coverage"));
    assert!(human_output.contains("Included: 4"));
    assert!(human_output.contains("Must-Protect blockers: 0"));
    assert!(human_output.contains("settings.txt"));
    assert!(!human_output.contains("protected machine output marker"));

    let machine = iniza(&[
        "--json",
        "plan",
        "show",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
    ]);
    assert!(machine.status.success());
    assert!(machine.stderr.is_empty());
    assert_eq!(String::from_utf8_lossy(&machine.stdout).lines().count(), 1);
    let value: serde_json::Value =
        serde_json::from_slice(&machine.stdout).expect("machine output should be valid JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "plan show");
    assert_eq!(value["status"], "success");
    assert_eq!(value["data"]["coverage"]["included"], 4);
    assert_eq!(value["data"]["coverage"]["must_protect_blocking"], 0);
    assert_eq!(
        value["data"]["items"]
            .as_array()
            .expect("items should be an array")
            .len(),
        4
    );
    let machine_text = String::from_utf8_lossy(&machine.stdout);
    assert!(!machine_text.contains(&root.display().to_string()));
    assert!(!machine_text.contains("protected machine output marker"));
}

#[test]
fn owner_approval_requires_the_reviewed_hash_and_stale_approval_blocks_validation() {
    let directory = TestDirectory::new("plan-approval");
    let root = directory.path().join("developer-state");
    let plan_path = directory.path().join("iniza.toml");
    fs::create_dir(&root).expect("approved root should be created");
    fs::write(root.join("settings.txt"), b"synthetic settings")
        .expect("settings fixture should be written");
    assert!(
        iniza(&[
            "scan",
            root.to_str().expect("root path should be text"),
            "--output-plan",
            plan_path.to_str().expect("Plan path should be text"),
        ])
        .status
        .success()
    );

    let initial_validation = iniza(&[
        "plan",
        "validate",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
    ]);
    assert!(initial_validation.status.success());
    let initial_output = String::from_utf8_lossy(&initial_validation.stdout);
    let reviewed_hash = initial_output
        .lines()
        .find_map(|line| line.strip_prefix("Approval hash: "))
        .expect("validation should display the approval hash")
        .to_owned();
    assert!(reviewed_hash.starts_with("plan_blake3_"));
    assert!(initial_output.contains("Approval: Unapproved"));

    let wrong_approval = iniza(&[
        "plan",
        "approve",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
        "--approved-hash",
        "plan_blake3_wrong",
    ]);
    assert_eq!(wrong_approval.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&wrong_approval.stderr).contains("does not match"));

    let approval = iniza(&[
        "plan",
        "approve",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
        "--approved-hash",
        &reviewed_hash,
    ]);
    assert!(approval.status.success());
    assert_eq!(
        String::from_utf8_lossy(&approval.stdout),
        format!("Plan approved: {reviewed_hash}\n")
    );
    let approved_validation = iniza(&[
        "plan",
        "validate",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
    ]);
    assert!(approved_validation.status.success());
    assert!(String::from_utf8_lossy(&approved_validation.stdout).contains("Approval: Approved"));

    let approved_text = fs::read_to_string(&plan_path).expect("approved Plan should be readable");
    let edited = approved_text.replace(
        "publication_policy = \"protect-locally-only\"",
        "publication_policy = \"review-separately\"",
    );
    assert_ne!(edited, approved_text);
    fs::write(&plan_path, edited).expect("approval-relevant edit should be written");
    let stale_validation = iniza(&[
        "plan",
        "validate",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
    ]);
    assert_eq!(stale_validation.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&stale_validation.stderr).contains("approval is stale"));
}

#[test]
fn plan_diff_explains_changes_for_people_and_automation() {
    let directory = TestDirectory::new("plan-diff");
    let root = directory.path().join("developer-state");
    let original_path = directory.path().join("original.toml");
    let revised_path = directory.path().join("revised.toml");
    fs::create_dir(&root).expect("approved root should be created");
    fs::write(root.join("settings.txt"), b"private diff output marker")
        .expect("settings fixture should be written");
    assert!(
        iniza(&[
            "scan",
            root.to_str().expect("root path should be text"),
            "--output-plan",
            original_path.to_str().expect("Plan path should be text"),
        ])
        .status
        .success()
    );
    let original_text =
        fs::read_to_string(&original_path).expect("original Plan should be readable");
    fs::write(
        &revised_path,
        original_text.replace(
            "publication_policy = \"protect-locally-only\"",
            "publication_policy = \"review-separately\"",
        ),
    )
    .expect("revised Plan should be written");

    let human = iniza(&[
        "plan",
        "diff",
        original_path.to_str().expect("Plan path should be text"),
        revised_path.to_str().expect("Plan path should be text"),
    ]);
    assert!(human.status.success());
    let human_text = String::from_utf8_lossy(&human.stdout);
    assert!(human_text.contains("publication policy changed"));
    assert!(!human_text.contains("private diff output marker"));

    let machine = iniza(&[
        "--json",
        "plan",
        "diff",
        original_path.to_str().expect("Plan path should be text"),
        revised_path.to_str().expect("Plan path should be text"),
    ]);
    assert!(machine.status.success());
    assert!(machine.stderr.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&machine.stdout).expect("machine diff should be valid JSON");
    assert_eq!(value["command"], "plan diff");
    assert_eq!(value["data"]["changed"], true);
    assert_eq!(
        value["data"]["changes"]
            .as_array()
            .expect("changes should be an array")
            .len(),
        1
    );
    let machine_text = String::from_utf8_lossy(&machine.stdout);
    assert!(!machine_text.contains(&root.display().to_string()));
    assert!(!machine_text.contains("private diff output marker"));
}

#[test]
fn machine_plan_diff_identifies_changed_items_without_paths_or_content() {
    let directory = TestDirectory::new("machine-item-diff");
    let root = directory.path().join("developer-state");
    let original_path = directory.path().join("original.toml");
    let revised_path = directory.path().join("revised.toml");
    fs::create_dir(&root).expect("approved root should be created");
    fs::write(
        root.join("private-settings.txt"),
        b"private machine diff content marker",
    )
    .expect("settings fixture should be written");

    assert!(
        iniza(&[
            "scan",
            root.to_str().expect("root path should be text"),
            "--output-plan",
            original_path.to_str().expect("Plan path should be text"),
        ])
        .status
        .success()
    );
    let original = Plan::read_from(&original_path).expect("original Plan should be valid");
    let changed_item = original
        .items()
        .iter()
        .find(|item| item.relative_path == Path::new("private-settings.txt"))
        .expect("private settings item should be present");
    let changed_item_id = changed_item.id.clone();
    let original_text =
        fs::read_to_string(&original_path).expect("original Plan should be readable");
    let revised_text = original_text.replacen(
        &format!(
            "id = \"{}\"\nrelative_path = \"private-settings.txt\"\nkind = \"regular-file\"\nestimated_size = 35\ndisposition = \"included\"",
            changed_item_id
        ),
        &format!(
            "id = \"{}\"\nrelative_path = \"private-settings.txt\"\nkind = \"regular-file\"\nestimated_size = 35\ndisposition = \"requires-review\"",
            changed_item_id
        ),
        1,
    );
    assert_ne!(
        revised_text, original_text,
        "fixture edit should take effect"
    );
    fs::write(&revised_path, revised_text).expect("revised Plan should be written");

    let output = iniza(&[
        "--json",
        "plan",
        "diff",
        original_path.to_str().expect("Plan path should be text"),
        revised_path.to_str().expect("Plan path should be text"),
    ]);

    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("machine diff should be valid JSON");
    assert_eq!(value["data"]["changes"][0]["item_id"], changed_item_id);
    assert_eq!(value["data"]["changes"][0]["kind"], "disposition-changed");
    let machine_text = String::from_utf8_lossy(&output.stdout);
    assert!(!machine_text.contains("private-settings.txt"));
    assert!(!machine_text.contains("private machine diff content marker"));
    assert!(!machine_text.contains(&root.display().to_string()));
}

#[test]
fn automation_can_request_versioned_scan_events_without_prompts_paths_or_content() {
    let directory = TestDirectory::new("scan-events");
    let root = directory.path().join("developer-state");
    let plan_path = directory.path().join("iniza.toml");
    fs::create_dir(&root).expect("approved root should be created");
    fs::write(root.join("settings.txt"), b"private event stream marker")
        .expect("settings fixture should be written");

    let output = iniza(&[
        "--json",
        "--json-events",
        "scan",
        root.to_str().expect("root path should be text"),
        "--output-plan",
        plan_path.to_str().expect("Plan path should be text"),
    ]);

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).lines().count(), 1);
    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("result should be valid JSON");
    assert_eq!(result["command"], "scan");
    assert_eq!(result["status"], "success");
    let event_lines = String::from_utf8_lossy(&output.stderr)
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("event should be JSON"))
        .collect::<Vec<_>>();
    assert_eq!(event_lines.len(), 2);
    assert_eq!(event_lines[0]["schema_version"], 1);
    assert_eq!(event_lines[0]["event"], "scan-started");
    assert_eq!(event_lines[1]["event"], "scan-completed");
    assert_eq!(event_lines[1]["item_count"], 2);
    let all_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all_output.contains(&root.display().to_string()));
    assert!(!all_output.contains("private event stream marker"));
}

#[test]
fn scan_command_records_reviewed_scope_destination_and_publication_policy() {
    let directory = TestDirectory::new("scan-policy");
    let root = directory.path().join("developer-state");
    let plan_path = directory.path().join("iniza.toml");
    let destination = directory.path().join("migration.iniza");
    fs::create_dir(&root).expect("approved root should be created");
    fs::write(root.join("settings.txt"), b"settings").expect("settings fixture should be written");
    fs::write(root.join("regenerable.cache"), b"cache").expect("cache fixture should be written");

    let scan = iniza(&[
        "scan",
        root.to_str().expect("root path should be text"),
        "--output-plan",
        plan_path.to_str().expect("Plan path should be text"),
        "--exclude",
        "regenerable.cache",
        "--recipe",
        "shell",
        "--destination",
        destination
            .to_str()
            .expect("destination path should be text"),
        "--publication-policy",
        "review-separately",
    ]);
    assert!(
        scan.status.success(),
        "reviewed scan policy should succeed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let text = fs::read_to_string(&plan_path).expect("Plan should be readable");
    assert!(text.contains("recipes = [\"shell\"]"));
    assert!(text.contains("exclusions = [\"regenerable.cache\"]"));
    assert!(text.contains(&format!(
        "destination_preference = \"{}\"",
        destination.display()
    )));
    assert!(text.contains("publication_policy = \"review-separately\""));

    let show = iniza(&[
        "--json",
        "plan",
        "show",
        "--plan",
        plan_path.to_str().expect("Plan path should be text"),
    ]);
    let value: serde_json::Value =
        serde_json::from_slice(&show.stdout).expect("machine output should be valid JSON");
    assert_eq!(value["data"]["coverage"]["excluded"], 1);
    assert_eq!(value["data"]["coverage"]["must_protect_blocking"], 1);
}
