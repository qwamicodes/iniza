use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDirectory(PathBuf);

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-protection-candidates-cli-{}-{unique}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
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

fn iniza(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_iniza"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn owner_and_automation_can_list_macos_protection_candidates_without_reading_content() {
    let directory = TestDirectory::new();
    let home = directory.path().join("owner-home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(
        home.join(".ssh/config"),
        b"do not print this content marker",
    )
    .unwrap();

    let human = iniza(&[
        "scan",
        home.to_str().unwrap(),
        "--list-protection-candidates",
    ]);
    assert!(human.status.success());
    let human_text = String::from_utf8_lossy(&human.stdout);
    assert!(human_text.contains("Protection Candidates"));
    assert!(human_text.contains("secure-shell-configuration"));
    assert!(human_text.contains("visual-studio-code-settings"));
    assert!(!human_text.contains("do not print this content marker"));

    let machine = iniza(&[
        "--json",
        "scan",
        home.to_str().unwrap(),
        "--list-protection-candidates",
    ]);
    assert!(machine.status.success());
    assert!(machine.stderr.is_empty());
    assert_eq!(String::from_utf8_lossy(&machine.stdout).lines().count(), 1);
    let value: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "candidates scan");
    let machine_text = String::from_utf8_lossy(&machine.stdout);
    assert!(!machine_text.contains(&home.display().to_string()));
    assert!(!machine_text.contains("do not print this content marker"));
}

#[test]
fn owner_can_write_a_narrow_plan_from_explicit_candidate_choices() {
    let directory = TestDirectory::new();
    let home = directory.path().join("owner-home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/config"), b"selected content").unwrap();
    let code_user = home.join("Library/Application Support/Code/User");
    fs::create_dir_all(&code_user).unwrap();
    fs::write(code_user.join("settings.json"), b"selected editor content").unwrap();
    fs::create_dir_all(home.join("Documents/unselected")).unwrap();
    fs::write(
        home.join("Documents/unselected/private.txt"),
        b"unselected marker",
    )
    .unwrap();
    let plan_path = directory.path().join("iniza.toml");

    let result = iniza(&[
        "scan",
        home.to_str().unwrap(),
        "--candidate",
        "secure-shell-configuration",
        "--candidate",
        "visual-studio-code-settings",
        "--output-plan",
        plan_path.to_str().unwrap(),
    ]);

    assert!(
        result.status.success(),
        "candidate Plan scan failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let plan = iniza::Plan::read_from(&plan_path).unwrap();
    let paths = plan
        .items()
        .iter()
        .map(|item| item.relative_path.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec![
            PathBuf::from("."),
            PathBuf::from(".ssh"),
            PathBuf::from(".ssh/config"),
            PathBuf::from("Library"),
            PathBuf::from("Library/Application Support"),
            PathBuf::from("Library/Application Support/Code"),
            PathBuf::from("Library/Application Support/Code/User"),
            PathBuf::from("Library/Application Support/Code/User/settings.json"),
        ]
    );
    assert!(paths.iter().all(|path| !path.starts_with("Documents")));
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.contains("selected content"));
    assert!(!output.contains("selected editor content"));
    assert!(!output.contains("unselected marker"));
}
