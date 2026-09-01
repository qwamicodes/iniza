use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("iniza-{name}-{}-{unique}", std::process::id()));
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

fn assert_machine_success(output: &Output, expected_command: &str) {
    assert!(
        output.status.success(),
        "machine command should succeed; standard error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "machine mode should not emit progress or prompts"
    );
    let standard_output = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        standard_output.lines().count(),
        1,
        "machine mode should emit exactly one result object"
    );
    assert!(standard_output.starts_with("{\"schema_version\":1,"));
    assert!(standard_output.contains(&format!("\"command\":\"{expected_command}\"")));
    assert!(standard_output.contains("\"status\":\"success\""));
    assert!(standard_output.contains("\"data\":"));
    assert!(standard_output.contains("\"warnings\":[]"));
    assert!(standard_output.ends_with("\"errors\":[]}\n"));
}

#[test]
fn owner_can_create_a_reviewable_plan_for_one_explicit_file() {
    let directory = TestDirectory::new("scan-one-file");
    let source = directory.path().join("hello.txt");
    let plan = directory.path().join("iniza.toml");
    fs::write(&source, b"synthetic source content\n").expect("source fixture should be written");

    let output = iniza(&[
        "scan",
        source.to_str().expect("source path should be valid text"),
        "--output-plan",
        plan.to_str().expect("plan path should be valid text"),
    ]);

    assert!(
        output.status.success(),
        "scan should succeed; standard error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(plan.exists(), "scan should write the requested Plan");

    let plan_text = fs::read_to_string(plan).expect("Plan should be readable text");
    assert!(plan_text.contains("schema_version = 1"));
    assert!(plan_text.contains("disposition = \"included\""));
    assert!(plan_text.contains("protection_requirement = \"must-protect\""));
    assert!(plan_text.contains("source_name = \"hello.txt\""));
    assert!(plan_text.contains("logical_size = 25"));
    assert!(
        !plan_text.contains("synthetic source content"),
        "Plan must not contain source content"
    );
}

#[test]
fn owner_can_validate_the_generated_plan() {
    let directory = TestDirectory::new("validate-plan");
    let source = directory.path().join("hello.txt");
    let plan = directory.path().join("iniza.toml");
    fs::write(&source, b"synthetic source content\n").expect("source fixture should be written");

    let scan = iniza(&[
        "scan",
        source.to_str().expect("source path should be valid text"),
        "--output-plan",
        plan.to_str().expect("plan path should be valid text"),
    ]);
    assert!(scan.status.success(), "scan should create the Plan");

    let validation = iniza(&[
        "plan",
        "validate",
        "--plan",
        plan.to_str().expect("plan path should be valid text"),
    ]);

    assert!(
        validation.status.success(),
        "Plan validation should succeed; standard error: {}",
        String::from_utf8_lossy(&validation.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&validation.stdout),
        format!("Plan valid: {}\n", plan.display())
    );
}

#[test]
fn owner_can_pack_a_structurally_distinct_test_only_fixture_container() {
    let directory = TestDirectory::new("pack-fixture");
    let source = directory.path().join("hello.txt");
    let plan = directory.path().join("iniza.toml");
    let fixture = directory.path().join("hello.iniza-fixture");
    fs::write(&source, b"synthetic source content\n").expect("source fixture should be written");

    assert!(
        iniza(&[
            "scan",
            source.to_str().expect("source path should be valid text"),
            "--output-plan",
            plan.to_str().expect("plan path should be valid text"),
        ])
        .status
        .success()
    );

    let pack = iniza(&[
        "fixture",
        "pack",
        "--plan",
        plan.to_str().expect("plan path should be valid text"),
        "--output",
        fixture.to_str().expect("fixture path should be valid text"),
    ]);

    assert!(
        pack.status.success(),
        "fixture packing should succeed; standard error: {}",
        String::from_utf8_lossy(&pack.stderr)
    );
    assert!(
        fixture.exists(),
        "packing should write the fixture container"
    );
    assert!(
        String::from_utf8_lossy(&pack.stdout).contains("TEST-ONLY UNENCRYPTED"),
        "human output should never imply real protection"
    );
    let bytes = fs::read(fixture).expect("fixture container should be readable");
    assert!(
        bytes.starts_with(b"INIZA-TEST-FIXTURE-V0\0"),
        "fixture container should use an unmistakable test-only header"
    );
}

#[test]
fn owner_can_inspect_safe_fixture_metadata_without_source_content() {
    let directory = TestDirectory::new("inspect-fixture");
    let source = directory.path().join("private-name.txt");
    let plan = directory.path().join("iniza.toml");
    let fixture = directory.path().join("private-name.iniza-fixture");
    fs::write(&source, b"do not print this synthetic secret\n")
        .expect("source fixture should be written");

    assert!(
        iniza(&[
            "scan",
            source.to_str().expect("source path should be valid text"),
            "--output-plan",
            plan.to_str().expect("plan path should be valid text"),
        ])
        .status
        .success()
    );
    assert!(
        iniza(&[
            "fixture",
            "pack",
            "--plan",
            plan.to_str().expect("plan path should be valid text"),
            "--output",
            fixture.to_str().expect("fixture path should be valid text"),
        ])
        .status
        .success()
    );

    let inspection = iniza(&[
        "fixture",
        "inspect",
        fixture.to_str().expect("fixture path should be valid text"),
    ]);

    assert!(
        inspection.status.success(),
        "fixture inspection should succeed; standard error: {}",
        String::from_utf8_lossy(&inspection.stderr)
    );
    let standard_output = String::from_utf8_lossy(&inspection.stdout);
    assert!(standard_output.contains("TEST-ONLY UNENCRYPTED fixture"));
    assert!(standard_output.contains("source name: private-name.txt"));
    assert!(standard_output.contains("logical size: 35 bytes"));
    assert!(!standard_output.contains("do not print this synthetic secret"));
    assert!(!standard_output.contains(&directory.path().display().to_string()));
}

#[test]
fn owner_can_restore_exact_bytes_only_to_a_new_destination() {
    let directory = TestDirectory::new("restore-fixture");
    let source = directory.path().join("exact-bytes.bin");
    let plan = directory.path().join("iniza.toml");
    let fixture = directory.path().join("exact-bytes.iniza-fixture");
    let destination = directory.path().join("restored");
    let source_bytes = b"\0synthetic\xffbinary\r\nbytes";
    fs::write(&source, source_bytes).expect("source fixture should be written");

    assert!(
        iniza(&[
            "scan",
            source.to_str().expect("source path should be valid text"),
            "--output-plan",
            plan.to_str().expect("plan path should be valid text"),
        ])
        .status
        .success()
    );
    assert!(
        iniza(&[
            "fixture",
            "pack",
            "--plan",
            plan.to_str().expect("plan path should be valid text"),
            "--output",
            fixture.to_str().expect("fixture path should be valid text"),
        ])
        .status
        .success()
    );

    let restore = iniza(&[
        "fixture",
        "restore",
        fixture.to_str().expect("fixture path should be valid text"),
        "--to",
        destination
            .to_str()
            .expect("destination path should be valid text"),
    ]);

    assert!(
        restore.status.success(),
        "fixture Restore should succeed; standard error: {}",
        String::from_utf8_lossy(&restore.stderr)
    );
    let restored_file = destination.join("exact-bytes.bin");
    assert_eq!(
        fs::read(&restored_file).expect("restored file should be readable"),
        source_bytes,
        "Restore must preserve every source byte"
    );

    let restore_again = iniza(&[
        "fixture",
        "restore",
        fixture.to_str().expect("fixture path should be valid text"),
        "--to",
        destination
            .to_str()
            .expect("destination path should be valid text"),
    ]);

    assert_eq!(
        restore_again.status.code(),
        Some(50),
        "an existing destination should use the documented conflict exit code"
    );
    assert!(String::from_utf8_lossy(&restore_again.stderr).contains("destination already exists"));
    assert_eq!(
        fs::read(restored_file).expect("first restored file should remain readable"),
        source_bytes,
        "a refused Restore must not alter the existing destination"
    );
}

#[test]
fn automation_can_round_trip_with_one_machine_result_and_no_prompts() {
    let directory = TestDirectory::new("machine-round-trip");
    let source = directory.path().join("machine.txt");
    let plan = directory.path().join("iniza.toml");
    let fixture = directory.path().join("machine.iniza-fixture");
    let destination = directory.path().join("restored");
    fs::write(&source, b"machine-safe synthetic content\n")
        .expect("source fixture should be written");

    let scan = iniza(&[
        "--json",
        "scan",
        source.to_str().expect("source path should be valid text"),
        "--output-plan",
        plan.to_str().expect("plan path should be valid text"),
    ]);
    assert_machine_success(&scan, "scan");

    let validation = iniza(&[
        "--json",
        "plan",
        "validate",
        "--plan",
        plan.to_str().expect("plan path should be valid text"),
    ]);
    assert_machine_success(&validation, "plan validate");

    let pack = iniza(&[
        "--json",
        "fixture",
        "pack",
        "--plan",
        plan.to_str().expect("plan path should be valid text"),
        "--output",
        fixture.to_str().expect("fixture path should be valid text"),
    ]);
    assert_machine_success(&pack, "fixture pack");

    let inspection = iniza(&[
        "--json",
        "fixture",
        "inspect",
        fixture.to_str().expect("fixture path should be valid text"),
    ]);
    assert_machine_success(&inspection, "fixture inspect");
    let inspection_output = String::from_utf8_lossy(&inspection.stdout);
    assert!(inspection_output.contains("\"fixture_kind\":\"test_only_unencrypted\""));
    assert!(inspection_output.contains("\"source_name\":\"machine.txt\""));
    assert!(inspection_output.contains("\"logical_size\":31"));
    assert!(!inspection_output.contains("machine-safe synthetic content"));

    let restore = iniza(&[
        "--json",
        "fixture",
        "restore",
        fixture.to_str().expect("fixture path should be valid text"),
        "--to",
        destination
            .to_str()
            .expect("destination path should be valid text"),
    ]);
    assert_machine_success(&restore, "fixture restore");
    assert_eq!(
        fs::read(destination.join("machine.txt")).expect("restored file should be readable"),
        b"machine-safe synthetic content\n"
    );
}

#[test]
fn normal_bundle_commands_reject_test_only_fixture_containers() {
    let directory = TestDirectory::new("reject-fixture-as-bundle");
    let source = directory.path().join("not-a-bundle.txt");
    let plan = directory.path().join("iniza.toml");
    let fixture = directory.path().join("not-a-bundle.iniza-fixture");
    fs::write(&source, b"never expose this synthetic payload\n")
        .expect("source fixture should be written");

    assert!(
        iniza(&[
            "scan",
            source.to_str().expect("source path should be valid text"),
            "--output-plan",
            plan.to_str().expect("plan path should be valid text"),
        ])
        .status
        .success()
    );
    assert!(
        iniza(&[
            "fixture",
            "pack",
            "--plan",
            plan.to_str().expect("plan path should be valid text"),
            "--output",
            fixture.to_str().expect("fixture path should be valid text"),
        ])
        .status
        .success()
    );

    let inspection = iniza(&[
        "inspect",
        fixture.to_str().expect("fixture path should be valid text"),
    ]);

    assert_eq!(inspection.status.code(), Some(20));
    let standard_error = String::from_utf8_lossy(&inspection.stderr);
    assert!(standard_error.contains("test-only fixture"));
    assert!(standard_error.contains("not an encrypted Bundle"));
    assert!(!standard_error.contains("never expose this synthetic payload"));
    assert!(inspection.stdout.is_empty());
}
