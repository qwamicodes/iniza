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

use iniza::{
    BundleEngine, BundleSource, BundleSourceObservation, DestinationCapacity, PackRequest,
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
        RestoreEvent::StagingValidated.machine_json_line(),
        r#"{"event":"staging-validated","schema_version":1}"#
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

impl RestoreEventSink for PublishRace {
    fn emit(&mut self, event: RestoreEvent) {
        if event == RestoreEvent::StagingValidated {
            fs::write(&self.conflicting_path, b"unrelated competing bytes\n")
                .expect("competing file should be created at the publication boundary");
        }
    }
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
    assert!(unrelated_error.to_string().contains("unrelated entries"));
    fs::remove_file(&unrelated).expect("unrelated fixture should be removed");

    let journal_path = destination.join(".iniza-restore/journal.json");
    let authentic_journal = fs::read(&journal_path).expect("journal should be readable");
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&authentic_journal).expect("journal should be JSON");
    tampered["staged_bytes"] = serde_json::json!(20);
    fs::write(
        &journal_path,
        serde_json::to_vec(&tampered).expect("tampered journal should encode"),
    )
    .expect("tampered journal fixture should be written");
    let journal_error = RestoreEngine::local()
        .restore(RestoreRequest::new(&bundle, &destination, sealed.offline_recovery_key()).resume())
        .expect_err("resume must reject a journal with an invalid authentication tag");
    assert!(journal_error.to_string().contains("does not authenticate"));
    fs::write(&journal_path, authentic_journal).expect("authentic journal should be restored");

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

    assert!(!destination.exists());
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
fn permission_loss_at_publication_rolls_back_without_exposing_content() {
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
    if destination.exists() {
        assert_eq!(
            fs::read_dir(&destination)
                .expect("rolled-back destination should remain readable")
                .count(),
            0
        );
    }
    RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            sealed.offline_recovery_key(),
        ))
        .expect("Restore should restart after permissions recover");
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
