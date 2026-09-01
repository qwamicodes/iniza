use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io, sync::Mutex};

#[cfg(unix)]
use std::os::unix::fs::symlink;

use iniza::{
    CoreError, Disposition, MigrationItemKind, Plan, PlanApprovalState, PlanEngine,
    ProtectionRequirement, PublicationPolicy, ScanRequest, SourceEntryKind, SourceFilesystem,
    SourceObservation,
};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let temporary_root = if cfg!(unix) {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let path =
            temporary_root.join(format!("iniza-plan-{name}-{}-{unique}", std::process::id()));
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

#[test]
fn owner_receives_one_stable_classification_for_every_item_under_an_approved_root() {
    let directory = TestDirectory::new("stable-classification");
    let root = directory.path().join("developer-state");
    fs::create_dir_all(root.join("nested")).expect("nested directory should be created");
    fs::write(root.join("notes.txt"), b"seven!!").expect("text fixture should be written");
    fs::write(root.join("nested/config.bin"), [0_u8, 1, 2])
        .expect("binary fixture should be written");

    let first = PlanEngine::local()
        .scan(ScanRequest::for_directory(&root))
        .expect("approved directory should scan");
    let second = PlanEngine::local()
        .scan(ScanRequest::for_directory(&root))
        .expect("unchanged approved directory should scan deterministically");

    assert_eq!(
        first.approved_roots(),
        [fs::canonicalize(&root).expect("root should canonicalize")]
    );
    assert_eq!(first.items().len(), 4);
    assert_eq!(first.estimated_logical_size(), 10);
    assert_eq!(
        first
            .items()
            .iter()
            .map(|item| (
                item.relative_path.clone(),
                item.kind,
                item.disposition,
                item.protection_requirement,
                item.explanation.as_str(),
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                PathBuf::from("."),
                MigrationItemKind::Directory,
                Disposition::Included,
                ProtectionRequirement::MustProtect,
                "explicitly approved directory",
            ),
            (
                PathBuf::from("nested"),
                MigrationItemKind::Directory,
                Disposition::Included,
                ProtectionRequirement::MustProtect,
                "discovered beneath an explicitly approved root",
            ),
            (
                PathBuf::from("nested/config.bin"),
                MigrationItemKind::RegularFile,
                Disposition::Included,
                ProtectionRequirement::MustProtect,
                "discovered beneath an explicitly approved root",
            ),
            (
                PathBuf::from("notes.txt"),
                MigrationItemKind::RegularFile,
                Disposition::Included,
                ProtectionRequirement::MustProtect,
                "discovered beneath an explicitly approved root",
            ),
        ]
    );
    assert_eq!(
        first
            .items()
            .iter()
            .map(|item| (&item.relative_path, &item.id))
            .collect::<Vec<_>>(),
        second
            .items()
            .iter()
            .map(|item| (&item.relative_path, &item.id))
            .collect::<Vec<_>>()
    );
}

#[cfg(unix)]
#[test]
fn escaping_symbolic_links_are_visible_blocking_gaps_and_never_followed() {
    let directory = TestDirectory::new("unsafe-source-items");
    let root = directory.path().join("approved");
    let outside = directory.path().join("outside");
    fs::create_dir(&root).expect("approved root should be created");
    fs::create_dir(&outside).expect("outside directory should be created");
    fs::write(root.join("inside.txt"), b"inside").expect("inside fixture should be written");
    fs::write(outside.join("must-not-be-discovered.txt"), b"outside")
        .expect("outside fixture should be written");
    symlink(&outside, root.join("escaping-link")).expect("escaping link should be created");

    let plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&root))
        .expect("unsafe source entries should be reported rather than followed");

    assert_eq!(
        plan.items()
            .iter()
            .map(|item| item.relative_path.clone())
            .collect::<Vec<_>>(),
        vec![
            PathBuf::from("."),
            PathBuf::from("escaping-link"),
            PathBuf::from("inside.txt"),
        ]
    );
    let link = plan
        .items()
        .iter()
        .find(|item| item.relative_path == Path::new("escaping-link"))
        .expect("escaping link should remain visible");
    assert_eq!(link.kind, MigrationItemKind::SymbolicLink);
    assert_eq!(link.disposition, Disposition::RequiresReview);
    assert_eq!(
        link.protection_requirement,
        ProtectionRequirement::MustProtect
    );
    let summary = plan.coverage_summary();
    assert_eq!(summary.included, 2);
    assert_eq!(summary.requires_review, 1);
    assert_eq!(summary.unsupported, 0);
    assert_eq!(summary.must_protect_blocking, 1);
    assert_eq!(summary.optional_warnings, 0);
}

#[test]
fn external_filesystem_risks_are_classified_without_hiding_or_crossing_them() {
    let plan = PlanEngine::with_source(RiskSource::default())
        .scan(ScanRequest::for_directory("/synthetic/approved").mark_optional("worker.sock"))
        .expect("filesystem risks should become reviewable Plan evidence");

    let items = plan
        .items()
        .iter()
        .map(|item| {
            (
                item.relative_path.clone(),
                item.kind,
                item.disposition,
                item.protection_requirement,
                item.explanation.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        items,
        vec![
            (
                PathBuf::from("."),
                MigrationItemKind::Directory,
                Disposition::Included,
                ProtectionRequirement::MustProtect,
                "explicitly approved directory".to_owned(),
            ),
            (
                PathBuf::from("changing.txt"),
                MigrationItemKind::RegularFile,
                Disposition::RequiresReview,
                ProtectionRequirement::MustProtect,
                "source metadata changed during discovery".to_owned(),
            ),
            (
                PathBuf::from("mounted"),
                MigrationItemKind::Directory,
                Disposition::RequiresReview,
                ProtectionRequirement::MustProtect,
                "mount boundary not crossed without approval".to_owned(),
            ),
            (
                PathBuf::from("private.txt"),
                MigrationItemKind::RegularFile,
                Disposition::Unavailable,
                ProtectionRequirement::MustProtect,
                "source item is not readable".to_owned(),
            ),
            (
                PathBuf::from("worker.sock"),
                MigrationItemKind::Special,
                Disposition::Unsupported,
                ProtectionRequirement::Optional,
                "special filesystem item is not captured".to_owned(),
            ),
        ]
    );
    let summary = plan.coverage_summary();
    assert_eq!(summary.included, 1);
    assert_eq!(summary.requires_review, 2);
    assert_eq!(summary.unavailable, 1);
    assert_eq!(summary.unsupported, 1);
    assert_eq!(summary.must_protect_blocking, 3);
    assert_eq!(summary.optional_warnings, 1);
}

#[test]
fn reviewed_scope_policy_is_recorded_and_changes_coverage_without_hiding_items() {
    let directory = TestDirectory::new("reviewed-policy");
    let root = directory.path().join("developer-state");
    let destination = directory.path().join("owner-selected.iniza");
    fs::create_dir(&root).expect("approved root should be created");
    fs::write(root.join("required.txt"), b"required").expect("required fixture should be written");
    fs::write(root.join("optional.txt"), b"optional").expect("optional fixture should be written");
    fs::write(root.join("excluded.cache"), b"regenerable")
        .expect("excluded fixture should be written");

    let plan = PlanEngine::local()
        .scan(
            ScanRequest::for_directory(&root)
                .exclude("excluded.cache")
                .mark_optional("optional.txt")
                .with_recipe("shell")
                .with_destination_preference(&destination)
                .with_publication_policy(PublicationPolicy::ReviewSeparately),
        )
        .expect("reviewed scope policy should produce a Plan");

    assert_eq!(plan.recipes(), ["shell"]);
    assert_eq!(plan.exclusions(), [PathBuf::from("excluded.cache")]);
    assert_eq!(plan.destination_preference(), Some(destination.as_path()));
    assert_eq!(
        plan.publication_policy(),
        PublicationPolicy::ReviewSeparately
    );
    let excluded = plan
        .items()
        .iter()
        .find(|item| item.relative_path == Path::new("excluded.cache"))
        .expect("excluded item should remain visible");
    assert_eq!(excluded.disposition, Disposition::Excluded);
    assert_eq!(
        excluded.protection_requirement,
        ProtectionRequirement::MustProtect
    );
    assert_eq!(excluded.explanation, "excluded by reviewed Plan request");
    let optional = plan
        .items()
        .iter()
        .find(|item| item.relative_path == Path::new("optional.txt"))
        .expect("optional item should remain visible");
    assert_eq!(optional.disposition, Disposition::Included);
    assert_eq!(
        optional.protection_requirement,
        ProtectionRequirement::Optional
    );
    let summary = plan.coverage_summary();
    assert_eq!(summary.included, 3);
    assert_eq!(summary.excluded, 1);
    assert_eq!(summary.must_protect_blocking, 1);
}

#[test]
fn canonical_plan_approval_is_repeatable_and_becomes_stale_after_a_relevant_edit() {
    let directory = TestDirectory::new("canonical-approval");
    let root = directory.path().join("approved");
    let first_path = directory.path().join("first.iniza.toml");
    let second_path = directory.path().join("second.iniza.toml");
    fs::create_dir(&root).expect("approved root should be created");
    fs::write(root.join("private.txt"), b"protected source content marker")
        .expect("source fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(
            ScanRequest::for_directory(&root)
                .with_recipe("shell")
                .with_destination_preference(directory.path().join("migration.iniza")),
        )
        .expect("approved directory should scan");

    let reviewed_hash = plan
        .approval_hash()
        .expect("Plan should have a canonical approval hash");
    assert_eq!(
        reviewed_hash,
        plan.approval_hash()
            .expect("unchanged Plan hash should repeat")
    );
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    assert_eq!(
        plan.approval_state()
            .expect("approval state should be calculable"),
        PlanApprovalState::Approved
    );
    plan.write_to(&first_path)
        .expect("approved Plan should serialize");
    plan.write_to(&second_path)
        .expect("approved Plan should serialize repeatedly");
    assert_eq!(
        fs::read(&first_path).expect("first Plan should be readable"),
        fs::read(&second_path).expect("second Plan should be readable")
    );
    let text = fs::read_to_string(&first_path).expect("Plan should be readable text");
    assert!(text.contains("plan_kind = \"directory\""));
    assert!(text.contains(&format!("reviewed_hash = \"{reviewed_hash}\"")));
    assert!(!text.contains("protected source content marker"));
    assert!(!text.contains("recovery_secret"));
    assert_eq!(
        Plan::read_from(&first_path)
            .expect("serialized Plan should parse")
            .approval_state()
            .expect("reloaded approval state should be calculable"),
        PlanApprovalState::Approved
    );

    let edited = text.replace(
        "publication_policy = \"protect-locally-only\"",
        "publication_policy = \"review-separately\"",
    );
    assert_ne!(edited, text, "fixture must edit an approval-relevant field");
    fs::write(&first_path, edited).expect("edited Plan should be written");
    let edited_plan = Plan::read_from(&first_path).expect("edited Plan should remain parseable");
    assert_eq!(
        edited_plan
            .approval_state()
            .expect("edited approval state should be calculable"),
        PlanApprovalState::Stale
    );
    assert_ne!(
        edited_plan
            .approval_hash()
            .expect("edited Plan should have a new hash"),
        reviewed_hash
    );
}

#[test]
fn plan_comparison_explains_approval_relevant_changes_without_source_content() {
    let directory = TestDirectory::new("plan-comparison");
    let root = directory.path().join("approved");
    fs::create_dir(&root).expect("approved root should be created");
    fs::write(root.join("settings.txt"), b"private comparison marker")
        .expect("source fixture should be written");
    let original = PlanEngine::local()
        .scan(ScanRequest::for_directory(&root))
        .expect("original Plan should scan");
    let revised = PlanEngine::local()
        .scan(
            ScanRequest::for_directory(&root)
                .exclude("settings.txt")
                .mark_optional("settings.txt")
                .with_recipe("shell")
                .with_publication_policy(PublicationPolicy::ReviewSeparately),
        )
        .expect("revised Plan should scan");

    let comparison = original.compare(&revised);

    assert!(!comparison.is_empty());
    let explanation = comparison.to_human_text();
    assert!(explanation.contains("publication policy changed"));
    assert!(explanation.contains("recipe added: shell"));
    assert!(explanation.contains("settings.txt"));
    assert!(explanation.contains("Disposition changed from Included to Excluded"));
    assert!(explanation.contains("Protection Requirement changed from MustProtect to Optional"));
    assert!(!explanation.contains("private comparison marker"));
}

#[test]
fn unsafe_requested_or_discovered_paths_are_rejected_before_they_enter_a_plan() {
    let directory = TestDirectory::new("unsafe-plan-paths");
    let root = directory.path().join("approved");
    fs::create_dir(&root).expect("approved root should be created");
    let unsafe_request = PlanEngine::local()
        .scan(ScanRequest::for_directory(&root).exclude("../outside"))
        .expect_err("parent traversal must not enter a Plan");
    assert!(matches!(
        unsafe_request,
        CoreError::InvalidPlan(message) if message == "Plan exclusion must be a safe relative path"
    ));

    let unsafe_discovery = PlanEngine::with_source(EscapingSource)
        .scan(ScanRequest::for_directory("/synthetic/approved"))
        .expect_err("filesystem entries outside the approved root must be rejected");
    assert!(matches!(
        unsafe_discovery,
        CoreError::InvalidPlan(message) if message == "Migration Item escaped its approved root"
    ));

    let broad_root = PlanEngine::with_source(EscapingSource)
        .scan(ScanRequest::for_directory("/"))
        .expect_err("a filesystem root must be rejected as an unsafe scan scope");
    assert!(matches!(
        broad_root,
        CoreError::InvalidPlan(message) if message == "approved Plan root is too broad"
    ));
}

#[test]
fn crossing_a_mount_boundary_requires_and_records_explicit_plan_policy() {
    let default_plan = PlanEngine::with_source(RiskSource::default())
        .scan(ScanRequest::for_directory("/synthetic/approved"))
        .expect("default scan should stop at the mount boundary");
    assert!(!default_plan.cross_mounts());
    assert!(
        default_plan
            .items()
            .iter()
            .all(|item| item.relative_path != Path::new("mounted/must-not-cross.txt"))
    );

    let approved_plan = PlanEngine::with_source(RiskSource::default())
        .scan(ScanRequest::for_directory("/synthetic/approved").with_cross_mounts(true))
        .expect("explicit cross-mount policy should traverse the mounted directory");
    assert!(approved_plan.cross_mounts());
    assert!(
        approved_plan
            .items()
            .iter()
            .any(|item| item.relative_path == Path::new("mounted/must-not-cross.txt"))
    );
    let default_hash = default_plan
        .approval_hash()
        .expect("default Plan should have an approval hash");
    assert_ne!(
        approved_plan
            .approval_hash()
            .expect("cross-mount Plan should have an approval hash"),
        default_hash
    );
}

#[test]
fn every_approval_relevant_plan_category_changes_the_canonical_hash() {
    let directory = TestDirectory::new("approval-fields");
    let root = directory.path().join("first-root");
    let second_root = directory.path().join("second-root");
    fs::create_dir(&root).expect("first root should be created");
    fs::create_dir(&second_root).expect("second root should be created");
    fs::write(root.join("settings.txt"), b"one").expect("first fixture should be written");
    fs::write(second_root.join("settings.txt"), b"one").expect("second fixture should be written");

    let requests = [
        ScanRequest::for_directory(&root),
        ScanRequest::for_directory(&root).with_recipe("shell"),
        ScanRequest::for_directory(&root).exclude("settings.txt"),
        ScanRequest::for_directory(&root).mark_optional("settings.txt"),
        ScanRequest::for_directory(&root)
            .with_destination_preference(directory.path().join("migration.iniza")),
        ScanRequest::for_directory(&root)
            .with_publication_policy(PublicationPolicy::ReviewSeparately),
        ScanRequest::for_directory(&root).with_cross_mounts(true),
        ScanRequest::for_directory(&second_root),
    ];
    let mut hashes = requests
        .into_iter()
        .map(|request| {
            PlanEngine::local()
                .scan(request)
                .expect("Plan variant should scan")
                .approval_hash()
                .expect("Plan variant should hash")
        })
        .collect::<BTreeSet<_>>();
    fs::write(root.join("settings.txt"), b"changed size").expect("fixture metadata should change");
    hashes.insert(
        PlanEngine::local()
            .scan(ScanRequest::for_directory(&root))
            .expect("changed source should rescan")
            .approval_hash()
            .expect("changed source Plan should hash"),
    );

    assert_eq!(hashes.len(), 9);
}

#[test]
fn unreadable_approved_root_is_a_visible_must_protect_blocker() {
    let plan = PlanEngine::with_source(UnreadableRootSource)
        .scan(ScanRequest::for_directory("/synthetic/approved"))
        .expect("an unreadable approved root should remain reviewable");

    assert_eq!(plan.items().len(), 1);
    assert_eq!(plan.items()[0].relative_path, Path::new("."));
    assert_eq!(plan.items()[0].disposition, Disposition::Unavailable);
    assert_eq!(
        plan.items()[0].protection_requirement,
        ProtectionRequirement::MustProtect
    );
    assert_eq!(plan.coverage_summary().must_protect_blocking, 1);
}

#[derive(Default)]
struct RiskSource {
    changing_observations: Mutex<u64>,
}

impl SourceFilesystem for RiskSource {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        Ok(path.to_path_buf())
    }

    fn observe(&self, path: &Path) -> io::Result<SourceObservation> {
        let name = path.file_name().and_then(|value| value.to_str());
        Ok(match name {
            Some("approved") => SourceObservation::directory(1, 10),
            Some("changing.txt") => {
                let mut observations = self
                    .changing_observations
                    .lock()
                    .expect("observation counter should lock");
                *observations += 1;
                SourceObservation::regular_file(7, 1, *observations)
            }
            Some("mounted") => SourceObservation::directory(2, 20),
            Some("private.txt") => SourceObservation {
                kind: SourceEntryKind::RegularFile,
                estimated_size: 11,
                device_id: 1,
                change_token: 30,
                readable: false,
            },
            Some("worker.sock") => SourceObservation::special(1, 40),
            _ => return Err(io::Error::new(io::ErrorKind::NotFound, "unknown fixture")),
        })
    }

    fn read_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        if path == Path::new("/synthetic/approved") {
            Ok(["changing.txt", "mounted", "private.txt", "worker.sock"]
                .into_iter()
                .map(|name| path.join(name))
                .collect())
        } else if path == Path::new("/synthetic/approved/mounted") {
            Ok(vec![path.join("must-not-cross.txt")])
        } else {
            Ok(Vec::new())
        }
    }
}

struct EscapingSource;

struct UnreadableRootSource;

impl SourceFilesystem for UnreadableRootSource {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        Ok(path.to_path_buf())
    }

    fn observe(&self, _path: &Path) -> io::Result<SourceObservation> {
        Ok(SourceObservation::directory(1, 1))
    }

    fn read_directory(&self, _path: &Path) -> io::Result<Vec<PathBuf>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic unreadable root",
        ))
    }
}

impl SourceFilesystem for EscapingSource {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        Ok(path.to_path_buf())
    }

    fn observe(&self, _path: &Path) -> io::Result<SourceObservation> {
        Ok(SourceObservation::directory(1, 1))
    }

    fn read_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        if path == Path::new("/synthetic/approved") {
            Ok(vec![PathBuf::from("/synthetic/outside")])
        } else {
            Ok(Vec::new())
        }
    }
}
