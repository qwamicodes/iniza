use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::fs::symlink;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use iniza::{
    BundleEngine, BundleSource, BundleSourceObservation, DestinationCapacity, PackRequest, Plan,
    PlanEngine, RecoveryMethod, RecoverySecret, RestoreCancellation, RestoreEngine, RestoreEvent,
    RestoreEventSink, RestoreRequest, RestoreState, ScanRequest, SourceFilesystem,
    SourceObservation,
};
use zeroize::Zeroizing;

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
            "iniza-restore-{name}-{}-{unique}",
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

fn review_plan_item_as_included(plan: &Plan, path: &Path, relative_path: &str) -> Plan {
    plan.write_to(path)
        .expect("unapproved Plan fixture should be written");
    let text = fs::read_to_string(path).expect("Plan fixture should be readable");
    let mut document: toml::Value = toml::from_str(&text).expect("Plan fixture should be TOML");
    let item = document
        .get_mut("items")
        .and_then(toml::Value::as_array_mut)
        .and_then(|items| {
            items.iter_mut().find(|item| {
                item.get("relative_path").and_then(toml::Value::as_str) == Some(relative_path)
            })
        })
        .expect("reviewed Migration Item should exist in the Plan");
    item["disposition"] = toml::Value::String("included".to_owned());
    fs::write(
        path,
        toml::to_string_pretty(&document).expect("reviewed Plan should encode"),
    )
    .expect("reviewed Plan fixture should be written");
    Plan::read_from(path).expect("reviewed Plan fixture should remain valid")
}

#[derive(Clone)]
struct VirtualCollisionSource {
    root: PathBuf,
    files: BTreeMap<PathBuf, Vec<u8>>,
}

impl VirtualCollisionSource {
    fn new(names: &[&str]) -> Self {
        let root = PathBuf::from("/synthetic/iniza-collision-source");
        let files = names
            .iter()
            .map(|name| {
                (
                    root.join(name),
                    format!("content for {name}\n").into_bytes(),
                )
            })
            .collect();
        Self { root, files }
    }
}

impl SourceFilesystem for VirtualCollisionSource {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        Ok(path.to_path_buf())
    }

    fn observe(&self, path: &Path) -> io::Result<SourceObservation> {
        if path == self.root {
            return Ok(SourceObservation::directory(7, 1));
        }
        self.files
            .get(path)
            .map(|content| SourceObservation::regular_file(content.len() as u64, 7, 1))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown virtual path"))
    }

    fn read_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        if path == self.root {
            return Ok(self.files.keys().cloned().collect());
        }
        Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "virtual file is not a directory",
        ))
    }
}

impl BundleSource for VirtualCollisionSource {
    fn observe(&self, path: &Path) -> io::Result<BundleSourceObservation> {
        self.files
            .get(path)
            .map(|content| BundleSourceObservation::new(content.len() as u64, 7, 1))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown virtual path"))
    }

    fn open(&self, path: &Path) -> io::Result<Box<dyn Read>> {
        self.files
            .get(path)
            .cloned()
            .map(|content| Box::new(Cursor::new(content)) as Box<dyn Read>)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown virtual path"))
    }
}

#[derive(Clone)]
struct VirtualModeSource {
    root: PathBuf,
    file: PathBuf,
    content: Vec<u8>,
    mode: u32,
}

impl VirtualModeSource {
    fn new(mode: u32) -> Self {
        let root = PathBuf::from("/synthetic/iniza-mode-source");
        Self {
            file: root.join("group-readable.txt"),
            root,
            content: b"authenticated group-readable content\n".to_vec(),
            mode,
        }
    }
}

impl SourceFilesystem for VirtualModeSource {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        Ok(path.to_path_buf())
    }

    fn observe(&self, path: &Path) -> io::Result<SourceObservation> {
        if path == self.root {
            Ok(SourceObservation::directory(7, 1))
        } else if path == self.file {
            Ok(SourceObservation::regular_file(
                self.content.len() as u64,
                7,
                1,
            ))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown virtual path",
            ))
        }
    }

    fn read_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        if path == self.root {
            Ok(vec![self.file.clone()])
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "virtual path is not a directory",
            ))
        }
    }
}

impl BundleSource for VirtualModeSource {
    fn observe(&self, path: &Path) -> io::Result<BundleSourceObservation> {
        if path == self.file {
            Ok(
                BundleSourceObservation::new(self.content.len() as u64, 7, 1)
                    .with_posix_mode(self.mode),
            )
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown virtual path",
            ))
        }
    }

    fn open(&self, path: &Path) -> io::Result<Box<dyn Read>> {
        if path == self.file {
            Ok(Box::new(Cursor::new(self.content.clone())))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown virtual path",
            ))
        }
    }

    fn posix_mode(&self, path: &Path) -> io::Result<Option<u32>> {
        if path == self.file {
            Ok(Some(self.mode))
        } else if path == self.root {
            Ok(Some(0o700))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown virtual path",
            ))
        }
    }
}

#[derive(Clone)]
struct VirtualSpecialSource {
    root: PathBuf,
    special: PathBuf,
}

impl VirtualSpecialSource {
    fn new() -> Self {
        let root = PathBuf::from("/synthetic/iniza-special-source");
        let special = root.join("agent.sock");
        Self { root, special }
    }
}

impl SourceFilesystem for VirtualSpecialSource {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        Ok(path.to_path_buf())
    }

    fn observe(&self, path: &Path) -> io::Result<SourceObservation> {
        if path == self.root {
            Ok(SourceObservation::directory(7, 1))
        } else if path == self.special {
            Ok(SourceObservation::special(7, 1))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown virtual path",
            ))
        }
    }

    fn read_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        if path == self.root {
            Ok(vec![self.special.clone()])
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "virtual special entry is not a directory",
            ))
        }
    }
}

impl BundleSource for VirtualSpecialSource {
    fn observe(&self, _path: &Path) -> io::Result<BundleSourceObservation> {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "special entries cannot be opened as regular files",
        ))
    }

    fn open(&self, _path: &Path) -> io::Result<Box<dyn Read>> {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "special entries cannot be opened as regular files",
        ))
    }
}

#[test]
fn restore_event_has_deterministic_path_free_machine_output() {
    assert_eq!(
        RestoreEvent::DestinationIdentityRecorded.machine_json_line(),
        r#"{"event":"destination-identity-recorded","schema_version":1}"#
    );
    assert_eq!(
        RestoreEvent::StagingValidated.machine_json_line(),
        r#"{"event":"staging-validated","schema_version":1}"#
    );
    assert_eq!(
        RestoreEvent::MaterializationPrepared.machine_json_line(),
        r#"{"event":"materialization-prepared","schema_version":1}"#
    );
    assert_eq!(
        RestoreEvent::PublicationAdvanced {
            completed_top_level_entries: 3,
        }
        .machine_json_line(),
        r#"{"completed_top_level_entries":3,"event":"publication-advanced","schema_version":1}"#
    );
    assert_eq!(
        RestoreEvent::PublicationCandidateMoved {
            candidate_top_level_entry: 3,
        }
        .machine_json_line(),
        r#"{"candidate_top_level_entry":3,"event":"publication-candidate-moved","schema_version":1}"#
    );
    assert_eq!(
        RestoreEvent::RollbackPrepared {
            remaining_top_level_entries: 2,
        }
        .machine_json_line(),
        r#"{"event":"rollback-prepared","remaining_top_level_entries":2,"schema_version":1}"#
    );
}

#[test]
fn owner_can_restore_authenticated_regular_files_into_a_new_destination() {
    let directory = TestDirectory::new("authenticated-regular-files");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir_all(source.join("nested")).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("settings fixture should be written");
    fs::write(source.join("nested/empty.txt"), []).expect("empty fixture should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    let report = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("authenticated Bundle should restore");

    assert_eq!(report.state(), RestoreState::Complete);
    assert_eq!(report.restored_items(), 4);
    assert_eq!(report.restored_bytes(), 19);
    assert_eq!(
        fs::read(destination.join("settings.txt")).expect("settings should be restored"),
        b"synthetic settings\n"
    );
    assert_eq!(
        fs::read(destination.join("nested/empty.txt")).expect("empty file should be restored"),
        b""
    );
    assert!(
        !destination.join(".iniza-restore").exists(),
        "a completed Restore Rehearsal should remove transaction-control artifacts"
    );
    let human = report.human_result();
    assert!(human.contains("Restore completed"));
    assert!(human.contains("restored items          4"));
    let machine: serde_json::Value =
        serde_json::from_str(&report.machine_json_result()).expect("result should be JSON");
    assert_eq!(machine["schema_version"], 1);
    assert_eq!(machine["command"], "restore");
    assert_eq!(machine["status"], "success");
    assert_eq!(machine["data"]["state"], "complete");
    assert_eq!(machine["data"]["restored_items"], 4);
    assert_eq!(machine["data"]["restored_bytes"], 19);
    assert!(
        !report.machine_json_result().contains("settings.txt"),
        "machine output must not disclose authenticated paths"
    );
}

#[test]
fn owner_can_restore_into_an_existing_empty_destination() {
    let directory = TestDirectory::new("empty-destination");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("settings fixture should be written");
    fs::create_dir(&destination).expect("empty destination should be created");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    let report = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("authenticated Bundle should restore into an empty destination");

    assert_eq!(report.state(), RestoreState::Complete);
    assert_eq!(
        fs::read(destination.join("settings.txt")).expect("settings should be restored"),
        b"synthetic settings\n"
    );
}

#[cfg(unix)]
#[test]
fn restore_handles_more_planned_items_than_the_open_file_limit() {
    const CHILD_ENVIRONMENT: &str = "INIZA_LOW_OPEN_FILE_LIMIT_CHILD";

    if std::env::var_os(CHILD_ENVIRONMENT).is_none() {
        let mut command = Command::new(
            std::env::current_exe().expect("the Restore test executable should be available"),
        );
        command
            .arg("restore_handles_more_planned_items_than_the_open_file_limit")
            .arg("--exact")
            .arg("--nocapture")
            .env(CHILD_ENVIRONMENT, "1");

        // SAFETY: this closure only changes the child process resource limit before exec.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 64,
                    rlim_max: 64,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }

        let output = command
            .output()
            .expect("the low-open-file-limit child test should run");
        assert!(
            output.status.success(),
            "Restore should use a bounded descriptor window under a low open-file limit.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let directory = TestDirectory::new("low-open-file-limit");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    for index in 0..96 {
        fs::write(
            source.join(format!("protected-{index:03}.txt")),
            format!("synthetic protected content {index}\n"),
        )
        .expect("protected fixture should be written");
    }

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan below the low open-file limit");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal below the low open-file limit");

    let report = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("Restore should not retain one open descriptor per planned item");

    assert_eq!(report.state(), RestoreState::Complete);
    assert_eq!(report.restored_items(), 97);
    assert_eq!(
        fs::read(destination.join("protected-095.txt"))
            .expect("the final protected fixture should be restored"),
        b"synthetic protected content 95\n"
    );
}

#[test]
fn restore_reports_an_existing_nonempty_destination_as_a_conflict() {
    let directory = TestDirectory::new("nonempty-destination-conflict");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("settings fixture should be written");
    fs::create_dir(&destination).expect("destination should be created");
    fs::write(destination.join("unrelated.txt"), b"unrelated bytes\n")
        .expect("unrelated destination fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    let error = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect_err("an existing nonempty destination must be a Restore conflict");

    assert!(matches!(
        error,
        iniza::CoreError::DestinationAlreadyExists(path) if path == destination
    ));
    assert_eq!(
        fs::read(destination.join("unrelated.txt"))
            .expect("unrelated destination fixture should remain readable"),
        b"unrelated bytes\n"
    );
}

#[cfg(unix)]
#[test]
fn restore_preserves_reviewed_posix_modes_without_executing_content() {
    let directory = TestDirectory::new("posix-mode");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    let executable = source.join("reviewed-mode");
    fs::write(&executable, b"reviewed non-executable content\n")
        .expect("mode fixture should be written");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o640))
        .expect("fixture mode should be set");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("authenticated Bundle should restore");

    let restored_mode = fs::metadata(destination.join("reviewed-mode"))
        .expect("restored mode metadata should be readable")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(restored_mode, 0o640);
}

#[cfg(unix)]
#[test]
fn restore_preserves_a_reviewed_mode_that_the_destination_owner_cannot_read() {
    let directory = TestDirectory::new("owner-unreadable-mode");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    let source = VirtualModeSource::new(0o004);
    let mut plan = PlanEngine::with_source(source.clone())
        .scan(ScanRequest::for_directory(&source.root))
        .expect("virtual mode source should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::with_source(source)
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("a valid owner-unreadable mode should not prevent Restore validation");

    let restored_mode = fs::metadata(destination.join("group-readable.txt"))
        .expect("restored mode metadata should be readable")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(restored_mode, 0o004);
}

#[cfg(unix)]
#[test]
fn restore_quarantines_other_executable_content_without_running_it() {
    let directory = TestDirectory::new("quarantined-executable");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    let execution_marker = directory.path().join("executable-ran");
    fs::create_dir(&source).expect("source directory should be created");
    let executable = source.join("reviewed-tool");
    fs::write(
        &executable,
        format!("#!/bin/sh\ntouch '{}'\n", execution_marker.display()),
    )
    .expect("executable fixture should be written");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
        .expect("fixture mode should be set");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    let report = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("authenticated Bundle should restore executable content in quarantine");

    let restored_mode = fs::metadata(destination.join("reviewed-tool"))
        .expect("restored executable metadata should be readable")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(restored_mode, 0o644);
    assert_eq!(report.quarantined_executables(), 1);
    assert!(!execution_marker.exists());
}

struct PublishRace {
    conflicting_path: PathBuf,
}

#[cfg(unix)]
struct ReplaceStagedDirectoryWithSymlink {
    staged_directory: PathBuf,
    displaced_directory: PathBuf,
    outside_directory: PathBuf,
}

struct ReplaceStagedBytesWithoutChangingSize {
    staged_file: PathBuf,
}

struct InjectUnplannedStagedEntry {
    destination: PathBuf,
}

struct InjectOverdeepStagedTree {
    staging: PathBuf,
}

impl RestoreEventSink for InjectUnplannedStagedEntry {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::StagingValidated {
            fs::write(
                self.destination
                    .join(".iniza-restore/staging/unplanned-secret.txt"),
                b"not authenticated by the Bundle\n",
            )
            .expect("unplanned staged fixture should be injected");
        }
    }
}

impl RestoreEventSink for InjectOverdeepStagedTree {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::StagingValidated {
            for entry in fs::read_dir(&self.staging).expect("staging should be readable") {
                let path = entry.expect("staged entry should be readable").path();
                if path.is_dir() {
                    fs::remove_dir_all(path).expect("staged directory should be removable");
                } else {
                    fs::remove_file(path).expect("staged file should be removable");
                }
            }
            let overdeep = (0..129).fold(self.staging.clone(), |path, _| path.join("d"));
            fs::create_dir_all(overdeep).expect("overdeep staged fixture should be created");
        }
    }
}

#[test]
fn restore_rejects_an_unplanned_item_injected_into_staging() {
    let directory = TestDirectory::new("unplanned-staged-item");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let mut injection = InjectUnplannedStagedEntry {
        destination: destination.clone(),
    };

    let error = RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut injection),
        )
        .expect_err("an unplanned staged item must fail closed");

    assert!(error.to_string().contains("entry limit"));
    assert!(!destination.join("settings.txt").exists());
    assert!(!destination.join("unplanned-secret.txt").exists());
}

#[test]
fn restore_stops_enumerating_a_staged_tree_beyond_the_path_depth_limit() {
    let directory = TestDirectory::new("overdeep-staged-tree");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    for index in 0..129 {
        fs::write(
            source.join(format!("planned-{index}.txt")),
            b"protected settings\n",
        )
        .expect("settings fixture should be written");
    }
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let mut injection = InjectOverdeepStagedTree {
        staging: destination.join(".iniza-restore/staging"),
    };

    let error = RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut injection),
        )
        .expect_err("an overdeep staged tree must fail closed");

    assert!(error.to_string().contains("depth limit"));
    assert!(!destination.join("planned-0.txt").exists());
}

impl RestoreEventSink for ReplaceStagedBytesWithoutChangingSize {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::StagingValidated {
            fs::write(&self.staged_file, b"malicious settings\n")
                .expect("staged bytes should be replaced for the fault");
        }
    }
}

#[test]
fn staged_content_substitution_with_the_same_size_is_rejected_before_publication() {
    let directory = TestDirectory::new("staged-content-substitution");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let mut substitution = ReplaceStagedBytesWithoutChangingSize {
        staged_file: destination.join(".iniza-restore/staging/settings.txt"),
    };

    RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut substitution),
        )
        .expect_err("same-size staged content substitution must fail closed");

    assert!(!destination.join("settings.txt").exists());
}

#[cfg(unix)]
impl RestoreEventSink for ReplaceStagedDirectoryWithSymlink {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::StagingValidated {
            fs::rename(&self.staged_directory, &self.displaced_directory)
                .expect("authenticated staged directory should be displaced for the fault");
            symlink(&self.outside_directory, &self.staged_directory)
                .expect("staged directory should be replaced with a symbolic link");
        }
    }
}

#[cfg(unix)]
#[test]
fn staged_directory_substitution_is_rejected_without_changing_outside_metadata() {
    let directory = TestDirectory::new("staged-directory-substitution");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    let outside_directory = directory.path().join("outside-destination");
    let displaced_directory = directory.path().join("displaced-authenticated-staging");
    fs::create_dir_all(source.join("nested")).expect("source directory should be created");
    fs::write(source.join("nested/settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    fs::set_permissions(source.join("nested"), fs::Permissions::from_mode(0o710))
        .expect("source directory mode should be set");
    fs::create_dir(&outside_directory).expect("outside directory should be created");
    fs::set_permissions(&outside_directory, fs::Permissions::from_mode(0o777))
        .expect("outside directory mode should be set");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let mut substitution = ReplaceStagedDirectoryWithSymlink {
        staged_directory: destination.join(".iniza-restore/staging/nested"),
        displaced_directory,
        outside_directory: outside_directory.clone(),
    };

    RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut substitution),
        )
        .expect_err("substituted staged content must fail closed");

    assert_eq!(
        fs::metadata(&outside_directory)
            .expect("outside directory should remain readable")
            .permissions()
            .mode()
            & 0o7777,
        0o777,
        "Restore must never apply authenticated metadata through a substituted symbolic link"
    );
    assert!(!destination.join("nested").exists());
}

impl RestoreEventSink for PublishRace {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::StagingValidated {
            fs::write(&self.conflicting_path, b"unrelated competing bytes\n")
                .expect("competing file should be created at the publication boundary");
        }
    }
}

struct ReplacePublishedCandidate {
    target: PathBuf,
}

struct ReplaceCheckpointedCandidate {
    target: PathBuf,
}

impl RestoreEventSink for ReplaceCheckpointedCandidate {
    fn emit(&mut self, event: RestoreEvent) {
        if matches!(
            event,
            RestoreEvent::PublicationAdvanced {
                completed_top_level_entries: 1
            }
        ) {
            fs::remove_file(&self.target).expect("checkpointed candidate should be removable");
            fs::write(&self.target, b"unrelated replacement\n")
                .expect("post-checkpoint replacement should be written");
            #[cfg(unix)]
            fs::set_permissions(&self.target, fs::Permissions::from_mode(0o600))
                .expect("post-checkpoint replacement should use the validation mode");
        }
    }
}

impl RestoreEventSink for ReplacePublishedCandidate {
    fn emit(&mut self, event: RestoreEvent) {
        if matches!(
            event,
            RestoreEvent::PublicationCandidateMoved {
                candidate_top_level_entry: 1
            }
        ) {
            fs::remove_file(&self.target).expect("published candidate should be removable");
            fs::write(&self.target, b"unrelated replacement\n")
                .expect("replacement candidate should be written");
            #[cfg(unix)]
            fs::set_permissions(&self.target, fs::Permissions::from_mode(0o600))
                .expect("replacement candidate should retain the validation mode");
        }
    }
}

#[cfg(unix)]
struct MakePublishedCandidateExecutable {
    target: PathBuf,
}

#[cfg(unix)]
impl RestoreEventSink for MakePublishedCandidateExecutable {
    fn emit(&mut self, event: RestoreEvent) {
        if matches!(
            event,
            RestoreEvent::PublicationCandidateMoved {
                candidate_top_level_entry: 1
            }
        ) {
            fs::set_permissions(&self.target, fs::Permissions::from_mode(0o755))
                .expect("published candidate mode should be replaceable");
        }
    }
}

#[test]
fn restore_reauthenticates_each_publication_candidate_before_checkpointing_it() {
    let directory = TestDirectory::new("publication-candidate-race");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let target = destination.join("settings.txt");
    let mut replacement = ReplacePublishedCandidate {
        target: target.clone(),
    };

    RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut replacement),
        )
        .expect_err("replaced publication candidate must fail authentication");

    assert_eq!(
        fs::read(&target).expect("unrelated replacement should remain untouched"),
        b"unrelated replacement\n"
    );
    assert!(destination.join(".iniza-restore/journal.json").is_file());
}

#[test]
fn restore_rejects_a_publication_candidate_replaced_after_its_checkpoint() {
    let directory = TestDirectory::new("post-checkpoint-candidate-race");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let target = destination.join("settings.txt");
    let mut replacement = ReplaceCheckpointedCandidate {
        target: target.clone(),
    };

    RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut replacement),
        )
        .expect_err("a post-checkpoint replacement must fail final binding validation");

    assert_eq!(
        fs::read(&target).expect("unrelated replacement should remain untouched"),
        b"unrelated replacement\n"
    );
    assert!(destination.join(".iniza-restore/journal.json").is_file());
}

#[cfg(unix)]
#[test]
fn owner_can_resume_when_interrupted_final_mode_application_made_a_file_unreadable() {
    let directory = TestDirectory::new("resume-final-mode-application");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    let source = VirtualModeSource::new(0o004);
    let mut plan = PlanEngine::with_source(source.clone())
        .scan(ScanRequest::for_directory(&source.root))
        .expect("virtual mode source should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::with_source(source)
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let target = destination.join("group-readable.txt");
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut cancel_after_publication = CancelAfterFirstPublication {
        cancelled: Arc::clone(&cancelled),
    };
    let cancellation = SharedCancellation { cancelled };

    let paused = RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut cancel_after_publication)
                .with_cancellation(&cancellation),
        )
        .expect("Restore should pause after its durable publication checkpoint");
    assert_eq!(paused.state(), RestoreState::Paused);
    assert!(destination.join(".iniza-restore/journal.json").is_file());
    fs::set_permissions(&target, fs::Permissions::from_mode(0o004))
        .expect("authenticated final mode should simulate interrupted finalization");

    RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect("authenticated Resume should normalize, revalidate, and restore the final mode");

    let restored_mode = fs::metadata(&target)
        .expect("restored mode metadata should be readable")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(restored_mode, 0o004);
    assert!(!destination.join(".iniza-restore").exists());
}

#[cfg(unix)]
#[test]
fn restore_rejects_a_publication_candidate_made_executable_before_checkpointing_it() {
    let directory = TestDirectory::new("publication-candidate-executable-race");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    let executable = source.join("reviewed-tool");
    fs::write(&executable, b"authenticated tool bytes\n")
        .expect("executable fixture should be written");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
        .expect("fixture should start executable");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let target = destination.join("reviewed-tool");
    let mut replacement = MakePublishedCandidateExecutable {
        target: target.clone(),
    };

    RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut replacement),
        )
        .expect_err("an executable publication candidate must fail authentication");

    let published_mode = fs::metadata(&target)
        .expect("published candidate should remain available for recovery")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(published_mode, 0o755);
    assert!(destination.join(".iniza-restore/journal.json").is_file());
}

#[test]
fn restore_never_overwrites_a_file_created_during_publication() {
    let directory = TestDirectory::new("publication-race");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let conflicting_path = destination.join("settings.txt");
    let mut race = PublishRace {
        conflicting_path: conflicting_path.clone(),
    };

    let error = RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut race),
        )
        .expect_err("Restore must fail rather than replace a competing path");

    assert!(matches!(
        error,
        iniza::CoreError::DestinationAlreadyExists(path) if path == conflicting_path
    ));
    assert_eq!(
        fs::read(destination.join("settings.txt")).expect("competing file should remain readable"),
        b"unrelated competing bytes\n"
    );
    assert!(
        !destination.join(".iniza-restore").exists(),
        "failed Restore should remove only its own transaction-control artifacts"
    );
}

#[cfg(unix)]
#[test]
fn restore_disables_repository_hooks_and_never_executes_them() {
    let directory = TestDirectory::new("disabled-hooks");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    let execution_marker = directory.path().join("hook-executed");
    let hook = source.join("project/.git/hooks/pre-commit");
    fs::create_dir_all(hook.parent().expect("hook should have a parent"))
        .expect("hook directory should be created");
    fs::write(
        &hook,
        format!("#!/bin/sh\ntouch '{}'\n", execution_marker.display()),
    )
    .expect("hook fixture should be written");
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755))
        .expect("hook fixture should be executable");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    let report = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("authenticated Bundle should restore with its hooks disabled");

    let restored_hook = destination.join("project/.git/hooks/pre-commit");
    let mode = fs::metadata(&restored_hook)
        .expect("restored hook metadata should be readable")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode & 0o111, 0, "restored hook must not be executable");
    assert_eq!(report.disabled_hooks(), 1);
    assert!(
        !execution_marker.exists(),
        "Restore must never execute authenticated content"
    );
}

#[cfg(unix)]
#[test]
fn restore_recreates_an_authenticated_symbolic_link_that_stays_inside_the_destination() {
    let directory = TestDirectory::new("safe-symbolic-link");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    symlink("settings.txt", source.join("current-settings"))
        .expect("symbolic-link fixture should be created");

    let plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let mut plan = review_plan_item_as_included(
        &plan,
        &directory.path().join("safe-symbolic-link-plan.toml"),
        "current-settings",
    );
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("authenticated safe symbolic link should restore");

    assert_eq!(
        fs::read_link(destination.join("current-settings"))
            .expect("symbolic link should be restored"),
        PathBuf::from("settings.txt")
    );
    assert_eq!(
        fs::read_to_string(destination.join("current-settings"))
            .expect("restored symbolic link should resolve inside the destination"),
        "protected settings\n"
    );
}

#[cfg(unix)]
#[test]
fn restore_preserves_reviewed_directory_modes() {
    let directory = TestDirectory::new("directory-mode");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    let protected_directory = source.join("private-settings");
    fs::create_dir_all(&protected_directory).expect("source directory should be created");
    fs::set_permissions(&protected_directory, fs::Permissions::from_mode(0o750))
        .expect("fixture directory mode should be set");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("authenticated Bundle should restore");

    let restored_mode = fs::metadata(destination.join("private-settings"))
        .expect("restored directory metadata should be readable")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(restored_mode, 0o750);
}

struct CancelWhenStaged {
    cancelled: Arc<AtomicBool>,
}

impl RestoreEventSink for CancelWhenStaged {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::StagingValidated {
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }
}

struct SharedCancellation {
    cancelled: Arc<AtomicBool>,
}

struct CancelAfterFirstPublication {
    cancelled: Arc<AtomicBool>,
}

struct PanicWhenRollbackPrepared;

impl RestoreEventSink for PanicWhenRollbackPrepared {
    fn emit(&mut self, event: RestoreEvent) {
        if matches!(event, RestoreEvent::RollbackPrepared { .. }) {
            panic!("synthetic interruption after durable rollback intent");
        }
    }
}

impl RestoreEventSink for CancelAfterFirstPublication {
    fn emit(&mut self, event: RestoreEvent) {
        if event
            == (RestoreEvent::PublicationAdvanced {
                completed_top_level_entries: 1,
            })
        {
            self.cancelled.store(true, Ordering::SeqCst);
        }
    }
}

#[test]
fn owner_can_resume_a_restore_paused_during_publication() {
    let directory = TestDirectory::new("publication-resume");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("alpha.txt"), b"alpha protected state\n")
        .expect("first fixture should be written");
    fs::write(source.join("omega.txt"), b"omega protected state\n")
        .expect("second fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut cancel_after_first_publication = CancelAfterFirstPublication {
        cancelled: Arc::clone(&cancelled),
    };
    let cancellation = SharedCancellation { cancelled };

    let paused = RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut cancel_after_first_publication)
                .with_cancellation(&cancellation),
        )
        .expect("publication cancellation should pause at a durable checkpoint");

    assert_eq!(paused.state(), RestoreState::Paused);
    assert!(destination.join("alpha.txt").is_file());
    assert!(!destination.join("omega.txt").exists());
    assert!(destination.join(".iniza-restore/journal.json").is_file());

    fs::write(destination.join("alpha.txt"), b"unrelated replacement\n")
        .expect("published target substitution should be injected");
    let replacement_error = RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect_err("resume must reject a replaced published target");
    assert!(
        replacement_error
            .to_string()
            .contains("changed after authentication"),
        "unexpected replacement rejection: {replacement_error}"
    );
    assert_eq!(
        fs::read(destination.join("alpha.txt")).expect("replacement should remain untouched"),
        b"unrelated replacement\n"
    );
    fs::write(destination.join("alpha.txt"), b"alpha protected state\n")
        .expect("authenticated publication fixture should be restored");

    let mut panic_when_rollback_prepared = PanicWhenRollbackPrepared;
    let rollback_interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = RestoreEngine::local().restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut panic_when_rollback_prepared)
                .resume(),
        );
    }));
    assert!(
        rollback_interrupted.is_err(),
        "synthetic rollback interruption should occur"
    );
    assert!(destination.join("alpha.txt").is_file());
    assert!(destination.join(".iniza-restore/journal.json").is_file());

    let completed = RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect("matching authenticated publication should resume");

    assert_eq!(completed.state(), RestoreState::Complete);
    assert_eq!(
        fs::read(destination.join("alpha.txt")).expect("first item should be restored"),
        b"alpha protected state\n"
    );
    assert_eq!(
        fs::read(destination.join("omega.txt")).expect("second item should be restored"),
        b"omega protected state\n"
    );
    assert!(!destination.join(".iniza-restore").exists());
}

struct PanicAfterFirstPublication;

impl RestoreEventSink for PanicAfterFirstPublication {
    fn emit(&mut self, event: RestoreEvent) {
        if matches!(
            event,
            RestoreEvent::PublicationAdvanced {
                completed_top_level_entries: 1
            }
        ) {
            panic!("synthetic process interruption after durable publication");
        }
    }
}

struct PanicAfterMaterializationCheckpoint;

impl RestoreEventSink for PanicAfterMaterializationCheckpoint {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::MaterializationPrepared {
            panic!("synthetic interruption after durable materialization checkpoint");
        }
    }
}

#[test]
fn owner_can_resume_after_an_abrupt_materialization_interruption() {
    let directory = TestDirectory::new("abrupt materialization resume");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let mut panic_after_checkpoint = PanicAfterMaterializationCheckpoint;

    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = RestoreEngine::local().restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut panic_after_checkpoint),
        );
    }));
    assert!(interrupted.is_err(), "synthetic interruption should occur");
    assert!(destination.join(".iniza-restore/journal.json").is_file());
    assert!(!destination.join("settings.txt").exists());

    let completed = RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect("durably checkpointed materialization should resume after interruption");

    assert_eq!(completed.state(), RestoreState::Complete);
    assert_eq!(
        fs::read(destination.join("settings.txt")).expect("item should be restored"),
        b"protected settings\n"
    );
    assert!(!destination.join(".iniza-restore").exists());
}

#[test]
fn owner_can_resume_after_an_abrupt_publication_interruption() {
    let directory = TestDirectory::new("abrupt-publication-resume");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let mut panic_after_first_publication = PanicAfterFirstPublication;

    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = RestoreEngine::local().restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut panic_after_first_publication),
        );
    }));
    assert!(interrupted.is_err(), "synthetic interruption should occur");
    assert!(destination.join("settings.txt").is_file());
    assert!(destination.join(".iniza-restore/journal.json").is_file());

    let completed = RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect("durably checkpointed publication should resume after interruption");

    assert_eq!(completed.state(), RestoreState::Complete);
    assert_eq!(
        fs::read(destination.join("settings.txt")).expect("item should be restored"),
        b"protected settings\n"
    );
    assert!(!destination.join(".iniza-restore").exists());
}

impl RestoreCancellation for SharedCancellation {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[test]
fn owner_can_resume_only_the_matching_authenticated_paused_restore() {
    let directory = TestDirectory::new("authenticated-resume");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut cancel_when_staged = CancelWhenStaged {
        cancelled: Arc::clone(&cancelled),
    };
    let cancellation = SharedCancellation { cancelled };

    let paused = RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut cancel_when_staged)
                .with_cancellation(&cancellation),
        )
        .expect("cancellation at a journaled boundary should pause safely");

    assert_eq!(paused.state(), RestoreState::Paused);
    assert!(!destination.join("settings.txt").exists());
    assert!(destination.join(".iniza-restore/staging").is_dir());
    assert!(destination.join(".iniza-restore/journal.json").is_file());

    let unrelated = destination.join("unrelated.txt");
    fs::write(&unrelated, b"must remain unrelated\n")
        .expect("unrelated destination fixture should be written");
    let unrelated_error = RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect_err("resume must reject unrelated destination entries");
    assert!(
        unrelated_error.to_string().contains("entry limit")
            || unrelated_error.to_string().contains("unrelated entries")
    );
    fs::remove_file(&unrelated).expect("unrelated fixture should be removed");

    let journal_path = destination.join(".iniza-restore/journal.json");
    let authentic_journal = fs::read(&journal_path).expect("journal should be readable");
    let mut noncanonical_journal = Vec::with_capacity(authentic_journal.len() + 1);
    noncanonical_journal.push(b' ');
    noncanonical_journal.extend_from_slice(&authentic_journal);
    fs::write(&journal_path, noncanonical_journal)
        .expect("non-canonical journal fixture should be written");
    let canonical_error = RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect_err("resume must reject a non-canonical journal representation");
    assert!(canonical_error.to_string().contains("not canonical"));
    fs::write(&journal_path, &authentic_journal).expect("authentic journal should be restored");

    let authentic_journal_text =
        String::from_utf8(authentic_journal.clone()).expect("journal should be UTF-8 JSON");
    let tampered_journal =
        authentic_journal_text.replace("\"staged_bytes\":19", "\"staged_bytes\":20");
    assert_ne!(tampered_journal, authentic_journal_text);
    fs::write(&journal_path, tampered_journal).expect("tampered journal fixture should be written");
    let journal_error = RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect_err("resume must reject a journal with an invalid authentication tag");
    assert!(journal_error.to_string().contains("does not authenticate"));
    fs::write(&journal_path, authentic_journal).expect("authentic journal should be restored");
    fs::write(
        destination.join(".iniza-restore/journal.json.partial"),
        b"interrupted replacement bytes",
    )
    .expect("interrupted partial journal should be created");

    let completed = RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect("matching Bundle, Recovery Secret, journal, and staging should resume");

    assert_eq!(completed.state(), RestoreState::Complete);
    assert_eq!(
        fs::read(destination.join("settings.txt")).expect("settings should be restored"),
        b"protected settings\n"
    );
    assert!(!destination.join(".iniza-restore").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn restore_round_trips_supported_extended_attributes_and_access_control_metadata() {
    let directory = TestDirectory::new("macos-metadata");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    let protected = source.join("settings.txt");
    fs::write(&protected, b"protected settings\n").expect("fixture should be written");
    let xattr = Command::new("/usr/bin/xattr")
        .args(["-w", "com.iniza.synthetic", "reviewed-value"])
        .arg(&protected)
        .output()
        .expect("xattr fixture command should run");
    assert!(xattr.status.success(), "xattr fixture should be applied");
    let acl = Command::new("/bin/chmod")
        .args(["+a", "everyone deny delete"])
        .arg(&protected)
        .output()
        .expect("access-control fixture command should run");
    assert!(
        acl.status.success(),
        "access-control fixture should be applied"
    );

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    let report = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("supported metadata should restore");

    let restored = destination.join("settings.txt");
    let restored_xattr = Command::new("/usr/bin/xattr")
        .args(["-p", "com.iniza.synthetic"])
        .arg(&restored)
        .output()
        .expect("restored xattr command should run");
    assert!(restored_xattr.status.success());
    assert_eq!(restored_xattr.stdout, b"reviewed-value\n");
    let restored_acl = Command::new("/bin/ls")
        .arg("-lde")
        .arg(&restored)
        .output()
        .expect("restored access-control command should run");
    assert!(restored_acl.status.success());
    assert!(
        String::from_utf8_lossy(&restored_acl.stdout).contains("deny delete"),
        "restored access-control metadata should contain the reviewed entry"
    );
    assert_eq!(report.unapplied_metadata(), 0);
}

#[test]
fn restore_rejects_case_and_unicode_normalization_collisions_before_creating_a_destination() {
    let scenarios = [
        ("case", vec!["Readme", "README"]),
        ("unicode", vec!["café.txt", "cafe\u{301}.txt"]),
    ];
    for (name, names) in scenarios {
        let directory = TestDirectory::new(name);
        let bundle = directory.path().join(format!("{name}.iniza"));
        let destination = directory.path().join("restored-state");
        let source = VirtualCollisionSource::new(&names);
        let mut plan = PlanEngine::with_source(source.clone())
            .scan(ScanRequest::for_directory(&source.root))
            .expect("virtual collision source should scan");
        let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
        plan.approve(&reviewed_hash)
            .expect("matching reviewed hash should approve the Plan");
        let sealed = BundleEngine::with_source(source)
            .pack(PackRequest::new(&plan, &bundle))
            .expect("approved virtual Plan should seal");

        let error = RestoreEngine::local()
            .restore(RestoreRequest::new(
                &bundle,
                &destination,
                sealed.offline_recovery_key(),
            ))
            .expect_err("colliding authenticated paths must fail before Restore starts");

        assert!(error.to_string().contains("collision"));
        assert!(
            !destination.exists(),
            "collision validation must precede destination creation"
        );
    }
}

#[derive(Debug)]
struct NoRestoreCapacity;

impl DestinationCapacity for NoRestoreCapacity {
    fn available_bytes(&self, _destination: &Path) -> io::Result<u64> {
        Ok(0)
    }
}

#[test]
fn insufficient_capacity_rejects_restore_before_destination_creation() {
    let directory = TestDirectory::new("insufficient-capacity");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    let error = RestoreEngine::with_capacity(NoRestoreCapacity)
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect_err("insufficient capacity must reject Restore");

    assert!(matches!(
        error,
        iniza::CoreError::InsufficientSpace { path, available: 0, .. } if path == destination
    ));
    assert!(!destination.exists());
}

#[test]
fn wrong_recovery_secret_is_rejected_before_destination_creation() {
    let directory = TestDirectory::new("wrong-secret");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let wrong_secret =
        RecoverySecret::from_bytes(RecoveryMethod::Offline, Zeroizing::new([0x5a; 32]));

    let error = RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, &wrong_secret))
        .expect_err("wrong Recovery Secret must fail closed");

    assert!(matches!(error, iniza::CoreError::AuthenticationFailed));
    assert!(!destination.exists());
}

#[cfg(unix)]
#[test]
fn escaping_symbolic_link_is_rejected_before_destination_creation() {
    let directory = TestDirectory::new("escaping-symbolic-link");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    symlink("../../outside-restore", source.join("escape"))
        .expect("escaping symbolic-link fixture should be created");
    let plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let mut plan = review_plan_item_as_included(
        &plan,
        &directory.path().join("escaping-symbolic-link-plan.toml"),
        "escape",
    );
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    let error = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect_err("escaping symbolic link must fail closed");

    assert!(
        error
            .to_string()
            .contains("escapes the Restore destination")
    );
    assert!(!destination.exists());
}

struct MutatingRestoreCapacity {
    bundle: PathBuf,
}

impl DestinationCapacity for MutatingRestoreCapacity {
    fn available_bytes(&self, _destination: &Path) -> io::Result<u64> {
        let mut bytes = fs::read(&self.bundle)?;
        let last = bytes
            .last_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Bundle is empty"))?;
        *last ^= 0x01;
        fs::write(&self.bundle, bytes)?;
        Ok(u64::MAX)
    }
}

#[test]
fn restore_stays_bound_to_the_opened_bundle_when_its_source_name_is_replaced() {
    let directory = TestDirectory::new("bundle-path-replacement");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let opened_bundle = directory.path().join("opened-developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"authenticated settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    let report = RestoreEngine::with_capacity(ReplacingBundlePath {
        bundle: bundle.clone(),
        opened_bundle: opened_bundle.clone(),
    })
    .restore(RestoreRequest::new(
        &bundle,
        &destination,
        sealed.offline_recovery_key(),
    ))
    .expect("Restore should remain bound to the Bundle it authenticated and opened");

    assert_eq!(report.state(), RestoreState::Complete);
    assert_eq!(
        fs::read(destination.join("settings.txt")).expect("settings should be restored"),
        b"authenticated settings\n"
    );
    assert_eq!(
        fs::read(&bundle).expect("replacement source name should remain readable"),
        b"untrusted replacement Bundle bytes"
    );
    assert!(opened_bundle.is_file());
}

struct ReplacingBundlePath {
    bundle: PathBuf,
    opened_bundle: PathBuf,
}

impl DestinationCapacity for ReplacingBundlePath {
    fn available_bytes(&self, _destination: &Path) -> io::Result<u64> {
        fs::rename(&self.bundle, &self.opened_bundle)?;
        fs::write(&self.bundle, b"untrusted replacement Bundle bytes")?;
        Ok(u64::MAX)
    }
}

#[test]
fn bundle_change_after_authenticated_preflight_never_publishes_content() {
    let directory = TestDirectory::new("bundle-change");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");

    RestoreEngine::with_capacity(MutatingRestoreCapacity {
        bundle: bundle.clone(),
    })
    .restore(RestoreRequest::new(
        &bundle,
        &destination,
        sealed.offline_recovery_key(),
    ))
    .expect_err("Bundle change between passes must fail closed");

    assert!(
        destination.is_dir(),
        "failed Restore cleanup must retain the outer destination so a pathname substitution cannot make cleanup delete unrelated data"
    );
    assert!(
        fs::read_dir(&destination)
            .expect("retained destination should remain readable")
            .next()
            .is_none(),
        "failed Restore cleanup should remove only its transaction artifacts"
    );
}

#[cfg(unix)]
struct RemoveDestinationWritePermission {
    destination: PathBuf,
}

#[cfg(unix)]
impl RestoreEventSink for RemoveDestinationWritePermission {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::StagingValidated {
            fs::set_permissions(&self.destination, fs::Permissions::from_mode(0o500))
                .expect("destination permission fault should be injected");
        }
    }
}

#[cfg(unix)]
#[test]
fn permission_loss_at_publication_preserves_resumable_state_without_exposing_content() {
    let directory = TestDirectory::new("permission-loss");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let mut permission_fault = RemoveDestinationWritePermission {
        destination: destination.clone(),
    };

    RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut permission_fault),
        )
        .expect_err("permission loss must prevent publication");
    if destination.exists() {
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
            .expect("destination permissions should be restored for recovery");
    }

    assert!(!destination.join("settings.txt").exists());
    assert!(destination.join(".iniza-restore/journal.json").is_file());
    RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect("Restore should resume after permissions recover");
    assert_eq!(
        fs::read(destination.join("settings.txt")).expect("settings should be restored"),
        b"protected settings\n"
    );
}

#[cfg(unix)]
#[test]
fn restore_rejects_authenticated_device_or_socket_entries_before_destination_creation() {
    let directory = TestDirectory::new("special-entry");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    let source = VirtualSpecialSource::new();
    let mut plan = PlanEngine::with_source(source.clone())
        .scan(ScanRequest::for_directory(&source.root))
        .expect("virtual special source should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::with_source(source)
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal its unsupported-item evidence");

    let error = RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect_err("socket entry must block Restore");

    assert!(error.to_string().contains("device or socket"));
    assert!(!destination.exists());
}

#[cfg(unix)]
struct SwapRestoreDestination {
    destination: PathBuf,
    moved_destination: PathBuf,
}

#[cfg(unix)]
struct SwapAfterDestinationSecured {
    destination: PathBuf,
    moved_destination: PathBuf,
    substituted_destination: PathBuf,
    observed_decrypted_escape: Arc<AtomicBool>,
}

#[cfg(unix)]
struct SwapAfterDestinationIdentityRecorded {
    destination: PathBuf,
    moved_destination: PathBuf,
    substituted_destination: PathBuf,
}

#[cfg(unix)]
impl RestoreEventSink for SwapAfterDestinationIdentityRecorded {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::DestinationIdentityRecorded {
            fs::rename(&self.destination, &self.moved_destination)
                .expect("identified destination should be movable for the fault");
            fs::create_dir(&self.substituted_destination)
                .expect("substituted destination should be created");
            symlink(&self.substituted_destination, &self.destination)
                .expect("destination should be substituted before capability open");
        }
    }
}

#[cfg(unix)]
#[test]
fn destination_substitution_between_identity_and_open_is_rejected_before_staging() {
    let directory = TestDirectory::new("destination-open-race");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    let moved_destination = directory.path().join("moved-restored-state");
    let substituted_destination = directory.path().join("substituted-restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let mut swap = SwapAfterDestinationIdentityRecorded {
        destination: destination.clone(),
        moved_destination,
        substituted_destination: substituted_destination.clone(),
    };

    RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut swap),
        )
        .expect_err("opened destination must match the recorded identity");

    assert!(!substituted_destination.join(".iniza-restore").exists());
    assert!(!substituted_destination.join("settings.txt").exists());
}

#[cfg(unix)]
impl RestoreEventSink for SwapAfterDestinationSecured {
    fn emit(&mut self, event: RestoreEvent) {
        match event {
            RestoreEvent::DestinationIdentityRecorded => {}
            RestoreEvent::DestinationSecured => {
                fs::rename(&self.destination, &self.moved_destination)
                    .expect("secured destination should be movable for the fault");
                fs::create_dir(&self.substituted_destination)
                    .expect("substituted destination should be created");
                fs::create_dir(self.substituted_destination.join(".iniza-restore"))
                    .expect("unrelated control-shaped directory should be created");
                fs::write(
                    self.substituted_destination
                        .join(".iniza-restore/unrelated.txt"),
                    b"must remain unrelated\n",
                )
                .expect("unrelated sentinel should be written");
                symlink(&self.substituted_destination, &self.destination)
                    .expect("destination should be substituted by a symbolic link");
            }
            RestoreEvent::MaterializationPrepared => {}
            RestoreEvent::StagingValidated => {
                if self
                    .substituted_destination
                    .join(".iniza-restore/staging/settings.txt")
                    .is_file()
                {
                    self.observed_decrypted_escape.store(true, Ordering::SeqCst);
                }
            }
            RestoreEvent::PublicationAdvanced { .. } => {}
            RestoreEvent::PublicationCandidateMoved { .. } => {}
            RestoreEvent::RollbackPrepared { .. } => {}
        }
    }
}

#[cfg(unix)]
#[test]
fn destination_substitution_never_redirects_decrypted_staging_content() {
    let directory = TestDirectory::new("descriptor-relative-staging");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    let moved_destination = directory.path().join("moved-restored-state");
    let substituted_destination = directory.path().join("substituted-restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let observed_decrypted_escape = Arc::new(AtomicBool::new(false));
    let mut swap = SwapAfterDestinationSecured {
        destination: destination.clone(),
        moved_destination: moved_destination.clone(),
        substituted_destination: substituted_destination.clone(),
        observed_decrypted_escape: Arc::clone(&observed_decrypted_escape),
    };

    RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut swap),
        )
        .expect_err("destination substitution must stop Restore publication");

    assert!(
        !observed_decrypted_escape.load(Ordering::SeqCst),
        "decrypted staging bytes must stay within the secured destination descriptor"
    );
    assert!(!substituted_destination.join("settings.txt").exists());
    assert_eq!(
        fs::read(substituted_destination.join(".iniza-restore/unrelated.txt"))
            .expect("cleanup must not follow the substituted destination"),
        b"must remain unrelated\n"
    );
}

#[cfg(unix)]
impl RestoreEventSink for SwapRestoreDestination {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::StagingValidated {
            fs::rename(&self.destination, &self.moved_destination)
                .expect("Restore destination should be moved for the fault");
            symlink(&self.moved_destination, &self.destination)
                .expect("Restore destination should be replaced by a symbolic link");
        }
    }
}

#[cfg(unix)]
#[test]
fn destination_identity_change_is_rejected_before_publication() {
    let directory = TestDirectory::new("destination-swap");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let destination = directory.path().join("restored-state");
    let moved_destination = directory.path().join("moved-restored-state");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"protected settings\n")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    let sealed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved Plan should seal");
    let mut swap = SwapRestoreDestination {
        destination: destination.clone(),
        moved_destination: moved_destination.clone(),
    };

    let error = RestoreEngine::local()
        .restore(
            RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key())
                .with_event_sink(&mut swap),
        )
        .expect_err("destination identity change must prevent publication");

    assert!(error.to_string().contains("identity changed"));
    assert!(!moved_destination.join("settings.txt").exists());
}
