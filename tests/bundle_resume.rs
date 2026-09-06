use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BundleEngine, BundleEvent, BundleEventSink, DestinationCapacity, InspectRequest,
    LocalBundleSource, PackCancellation, PackCheckpointPromotionStep, PackPersistence,
    PackPersistenceTransition, PackRecoveryAdvice, PackRecoveryContext, PackRequest, PackState,
    PackStopAction, Plan, PlanEngine, RecoveryMethod, RecoverySecret, RestoreEngine,
    RestoreRequest, ScanRequest, VerifyRequest,
};
use zeroize::Zeroizing;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-pack-resume-{}-{unique}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::SeqCst)
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

fn approved_plan(directory: &TestDirectory) -> Plan {
    let source = directory.path().join("synthetic-source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("first.txt"), b"first protected item\n").unwrap();
    fs::write(source.join("second.txt"), b"second protected item\n").unwrap();
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .unwrap();
    let hash = plan.approval_hash().unwrap();
    plan.approve(&hash).unwrap();
    plan
}

struct StopAfterCapture<'a> {
    cancellation: &'a PackCancellation,
    events: Vec<BundleEvent>,
}

impl BundleEventSink for StopAfterCapture<'_> {
    fn emit(&mut self, event: BundleEvent) {
        if matches!(&event, BundleEvent::ItemCaptured { bytes, .. } if *bytes > 0) {
            self.cancellation.request_stop();
        }
        self.events.push(event);
    }
}

#[test]
fn repeated_interrupt_escalates_from_checkpoint_stop_to_immediate_termination() {
    let cancellation = PackCancellation::default();

    assert_eq!(
        cancellation.request_stop(),
        PackStopAction::FinishCurrentItem
    );
    assert_eq!(
        cancellation.request_stop(),
        PackStopAction::TerminateImmediately
    );
    assert_eq!(
        cancellation.request_stop(),
        PackStopAction::TerminateImmediately
    );
}

struct TerminateOnRepeatedInterrupt<'a> {
    cancellation: &'a PackCancellation,
}

impl BundleEventSink for TerminateOnRepeatedInterrupt<'_> {
    fn emit(&mut self, event: BundleEvent) {
        if matches!(event, BundleEvent::ItemCaptured { bytes, .. } if bytes > 0) {
            assert_eq!(
                self.cancellation.request_stop(),
                PackStopAction::FinishCurrentItem
            );
            if self.cancellation.request_stop() == PackStopAction::TerminateImmediately {
                std::process::exit(73);
            }
        }
    }
}

#[test]
fn repeated_interrupt_termination_child() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_REPEATED_INTERRUPT_CHILD") else {
        return;
    };
    let root = PathBuf::from(root);
    let plan = Plan::read_from(&root.join("reviewed-plan.toml")).unwrap();
    let cancellation = PackCancellation::default();
    let mut events = TerminateOnRepeatedInterrupt {
        cancellation: &cancellation,
    };
    BundleEngine::local()
        .pack(
            PackRequest::new(&plan, root.join("migration.iniza"))
                .with_recovery_context(&synthetic_recovery_context())
                .with_cancellation(&cancellation)
                .with_event_sink(&mut events),
        )
        .unwrap();
    panic!("Pack did not terminate at the repeated interrupt");
}

#[test]
fn repeated_interrupt_can_terminate_immediately_while_output_remains_partial() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    plan.write_to(&directory.path().join("reviewed-plan.toml"))
        .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "repeated_interrupt_termination_child",
            "--nocapture",
        ])
        .env("INIZA_SYNTHETIC_REPEATED_INTERRUPT_CHILD", directory.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    let destination = directory.path().join("migration.iniza");
    let partial = directory.path().join("migration.iniza.partial");
    assert!(!destination.exists());
    assert!(partial.is_file());
    assert!(
        !directory
            .path()
            .join("migration.iniza.partial.checkpoint")
            .exists()
    );
    let context = synthetic_recovery_context();
    assert!(
        BundleEngine::local()
            .verify(VerifyRequest::new(&partial, context.offline_recovery_key(),))
            .is_err()
    );
    assert!(
        BundleEngine::local()
            .pack(PackRequest::resume(&plan, &destination, &context))
            .unwrap_err()
            .to_string()
            .contains("restart required")
    );
}

struct FailPackPersistenceOnce {
    target: PackPersistenceTransition,
    kind: io::ErrorKind,
    failed: AtomicBool,
}

impl PackPersistence for FailPackPersistenceOnce {
    fn prepare_transition(&self, transition: PackPersistenceTransition) -> io::Result<()> {
        if transition == self.target && !self.failed.swap(true, Ordering::SeqCst) {
            Err(io::Error::new(self.kind, "injected destination failure"))
        } else {
            Ok(())
        }
    }
}

fn assert_promotion_failure_is_resumable(
    target: PackPersistenceTransition,
    kind: io::ErrorKind,
    saved_pair_must_be_unchanged: bool,
) {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let partial = directory.path().join("migration.iniza.partial");
    let checkpoint = directory.path().join("migration.iniza.partial.checkpoint");
    let context = synthetic_recovery_context();
    let cancellation = PackCancellation::default();
    let mut stop = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    BundleEngine::local()
        .pack(
            PackRequest::new(&plan, &destination)
                .with_recovery_context(&context)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut stop),
        )
        .unwrap();
    let saved_partial = fs::read(&partial).unwrap();
    let saved_checkpoint = fs::read(&checkpoint).unwrap();
    let second_cancellation = PackCancellation::default();
    let mut second_stop = StopAfterCapture {
        cancellation: &second_cancellation,
        events: Vec::new(),
    };
    let persistence = FailPackPersistenceOnce {
        target,
        kind,
        failed: AtomicBool::new(false),
    };

    BundleEngine::local()
        .pack(
            PackRequest::resume(&plan, &destination, &context)
                .with_cancellation(&second_cancellation)
                .with_event_sink(&mut second_stop)
                .with_persistence(&persistence),
        )
        .expect_err("destination failure must stop checkpoint promotion");

    assert!(persistence.failed.load(Ordering::SeqCst));
    assert!(!destination.exists());
    if saved_pair_must_be_unchanged {
        assert_eq!(fs::read(&partial).unwrap(), saved_partial);
        assert_eq!(fs::read(&checkpoint).unwrap(), saved_checkpoint);
    }
    let completed = BundleEngine::local()
        .pack(PackRequest::resume(&plan, &destination, &context))
        .expect("authenticated progress must remain resumable after a destination failure");
    assert_eq!(completed.state(), PackState::Complete);
    assert_eq!(
        BundleEngine::local()
            .verify(VerifyRequest::new(
                &destination,
                context.offline_recovery_key(),
            ))
            .unwrap()
            .authenticated_bytes,
        43
    );
}

#[test]
fn journal_creation_failure_preserves_authenticated_progress_for_resume() {
    for kind in [io::ErrorKind::StorageFull, io::ErrorKind::PermissionDenied] {
        assert_promotion_failure_is_resumable(
            PackPersistenceTransition::CreatePromotionJournal,
            kind,
            true,
        );
    }
}

#[test]
fn journal_write_failure_preserves_authenticated_progress_for_resume() {
    for kind in [io::ErrorKind::StorageFull, io::ErrorKind::PermissionDenied] {
        assert_promotion_failure_is_resumable(
            PackPersistenceTransition::WritePromotionJournal,
            kind,
            true,
        );
    }
}

macro_rules! promotion_failure_recovery_test {
    ($name:ident, $transition:expr) => {
        #[test]
        fn $name() {
            for kind in [io::ErrorKind::StorageFull, io::ErrorKind::PermissionDenied] {
                assert_promotion_failure_is_resumable($transition, kind, false);
            }
        }
    };
}

promotion_failure_recovery_test!(
    journal_sync_failure_preserves_resumable_progress,
    PackPersistenceTransition::SynchronizePromotionJournal
);
promotion_failure_recovery_test!(
    journal_directory_sync_failure_preserves_resumable_progress,
    PackPersistenceTransition::SynchronizePromotionJournalDirectory
);
promotion_failure_recovery_test!(
    journal_publication_failure_preserves_resumable_progress,
    PackPersistenceTransition::PublishPromotionJournal
);
promotion_failure_recovery_test!(
    published_journal_sync_failure_preserves_resumable_progress,
    PackPersistenceTransition::SynchronizePublishedPromotionJournal
);
promotion_failure_recovery_test!(
    saved_partial_move_failure_preserves_resumable_progress,
    PackPersistenceTransition::MoveSavedPartial
);
promotion_failure_recovery_test!(
    saved_partial_move_sync_failure_preserves_resumable_progress,
    PackPersistenceTransition::SynchronizeSavedPartialMove
);
promotion_failure_recovery_test!(
    saved_checkpoint_move_failure_preserves_resumable_progress,
    PackPersistenceTransition::MoveSavedCheckpoint
);
promotion_failure_recovery_test!(
    saved_checkpoint_move_sync_failure_preserves_resumable_progress,
    PackPersistenceTransition::SynchronizeSavedCheckpointMove
);
promotion_failure_recovery_test!(
    resumed_partial_move_failure_preserves_resumable_progress,
    PackPersistenceTransition::MoveResumedPartial
);
promotion_failure_recovery_test!(
    resumed_partial_move_sync_failure_preserves_resumable_progress,
    PackPersistenceTransition::SynchronizeResumedPartialMove
);
promotion_failure_recovery_test!(
    resumed_checkpoint_move_failure_preserves_resumable_progress,
    PackPersistenceTransition::MoveResumedCheckpoint
);
promotion_failure_recovery_test!(
    resumed_checkpoint_move_sync_failure_preserves_resumable_progress,
    PackPersistenceTransition::SynchronizeResumedCheckpointMove
);
promotion_failure_recovery_test!(
    superseded_partial_removal_failure_preserves_resumable_progress,
    PackPersistenceTransition::RemoveSupersededPartial
);
promotion_failure_recovery_test!(
    superseded_partial_removal_sync_failure_preserves_resumable_progress,
    PackPersistenceTransition::SynchronizeSupersededPartialRemoval
);
promotion_failure_recovery_test!(
    superseded_checkpoint_removal_failure_preserves_resumable_progress,
    PackPersistenceTransition::RemoveSupersededCheckpoint
);
promotion_failure_recovery_test!(
    superseded_checkpoint_removal_sync_failure_preserves_resumable_progress,
    PackPersistenceTransition::SynchronizeSupersededCheckpointRemoval
);
promotion_failure_recovery_test!(
    promotion_journal_removal_failure_preserves_resumable_progress,
    PackPersistenceTransition::RemovePromotionJournal
);
promotion_failure_recovery_test!(
    promotion_journal_removal_sync_failure_preserves_resumable_progress,
    PackPersistenceTransition::SynchronizePromotionJournalRemoval
);

fn assert_prepublication_failure_is_contained(
    target: PackPersistenceTransition,
    kind: io::ErrorKind,
    request_checkpoint: bool,
) {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let context = synthetic_recovery_context();
    let cancellation = PackCancellation::default();
    if request_checkpoint {
        assert_eq!(
            cancellation.request_stop(),
            PackStopAction::FinishCurrentItem
        );
    }
    let persistence = FailPackPersistenceOnce {
        target,
        kind,
        failed: AtomicBool::new(false),
    };

    BundleEngine::local()
        .pack(
            PackRequest::new(&plan, &destination)
                .with_recovery_context(&context)
                .with_cancellation(&cancellation)
                .with_persistence(&persistence),
        )
        .expect_err("injected prepublication failure must stop Pack");

    assert!(persistence.failed.load(Ordering::SeqCst));
    assert!(!destination.exists());
    let retry_destination = directory.path().join("retry.iniza");
    let completed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &retry_destination).with_recovery_context(&context))
        .expect("a clean restart at a new destination must remain available");
    assert_eq!(completed.state(), PackState::Complete);
    assert_eq!(
        BundleEngine::local()
            .verify(VerifyRequest::new(
                &retry_destination,
                context.offline_recovery_key(),
            ))
            .unwrap()
            .authenticated_bytes,
        43
    );
}

macro_rules! prepublication_failure_containment_test {
    ($name:ident, $transition:expr, $request_checkpoint:expr) => {
        #[test]
        fn $name() {
            for kind in [io::ErrorKind::StorageFull, io::ErrorKind::PermissionDenied] {
                assert_prepublication_failure_is_contained($transition, kind, $request_checkpoint);
            }
        }
    };
}

prepublication_failure_containment_test!(
    partial_creation_failure_never_publishes,
    PackPersistenceTransition::CreatePartialBundle,
    false
);
prepublication_failure_containment_test!(
    partial_write_failure_never_publishes,
    PackPersistenceTransition::WritePartialBundle,
    false
);
prepublication_failure_containment_test!(
    migration_item_stage_creation_failure_never_publishes,
    PackPersistenceTransition::CreateMigrationItemStage,
    false
);
prepublication_failure_containment_test!(
    migration_item_stage_write_failure_never_publishes,
    PackPersistenceTransition::WriteMigrationItemStage,
    false
);
prepublication_failure_containment_test!(
    migration_item_stage_flush_failure_never_publishes,
    PackPersistenceTransition::FlushMigrationItemStage,
    false
);
prepublication_failure_containment_test!(
    migration_item_stage_removal_failure_never_publishes,
    PackPersistenceTransition::RemoveMigrationItemStage,
    false
);
prepublication_failure_containment_test!(
    partial_checkpoint_sync_failure_never_publishes,
    PackPersistenceTransition::SynchronizePartialBeforeCheckpoint,
    true
);
prepublication_failure_containment_test!(
    checkpoint_creation_failure_never_publishes,
    PackPersistenceTransition::CreateCheckpoint,
    true
);
prepublication_failure_containment_test!(
    checkpoint_write_failure_never_publishes,
    PackPersistenceTransition::WriteCheckpoint,
    true
);
prepublication_failure_containment_test!(
    checkpoint_sync_failure_never_publishes,
    PackPersistenceTransition::SynchronizeCheckpoint,
    true
);
prepublication_failure_containment_test!(
    checkpoint_directory_sync_failure_never_publishes,
    PackPersistenceTransition::SynchronizeCheckpointDirectory,
    true
);
prepublication_failure_containment_test!(
    completed_partial_sync_failure_never_publishes,
    PackPersistenceTransition::SynchronizeCompletedPartial,
    false
);
prepublication_failure_containment_test!(
    completed_bundle_publication_failure_never_publishes,
    PackPersistenceTransition::PublishCompletedBundle,
    false
);

#[test]
fn completed_bundle_directory_sync_failure_returns_an_error_but_keeps_verifiable_output() {
    for kind in [io::ErrorKind::StorageFull, io::ErrorKind::PermissionDenied] {
        let directory = TestDirectory::new();
        let plan = approved_plan(&directory);
        let destination = directory.path().join("migration.iniza");
        let context = synthetic_recovery_context();
        let persistence = FailPackPersistenceOnce {
            target: PackPersistenceTransition::SynchronizeCompletedBundleDirectory,
            kind,
            failed: AtomicBool::new(false),
        };

        BundleEngine::local()
            .pack(
                PackRequest::new(&plan, &destination)
                    .with_recovery_context(&context)
                    .with_persistence(&persistence),
            )
            .expect_err("directory synchronization failure must not report Pack success");

        assert!(persistence.failed.load(Ordering::SeqCst));
        assert_eq!(
            BundleEngine::local()
                .verify(VerifyRequest::new(
                    &destination,
                    context.offline_recovery_key(),
                ))
                .unwrap()
                .authenticated_bytes,
            43
        );
    }
}

#[test]
fn completed_bundle_publication_atomically_removes_the_partial_name() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let partial = directory.path().join("migration.iniza.partial");
    let context = synthetic_recovery_context();

    let completed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &destination).with_recovery_context(&context))
        .unwrap();

    assert_eq!(completed.state(), PackState::Complete);
    assert!(destination.is_file());
    assert!(!partial.exists());
    assert_eq!(
        BundleEngine::local()
            .verify(VerifyRequest::new(
                &destination,
                context.offline_recovery_key(),
            ))
            .unwrap()
            .authenticated_bytes,
        43
    );
}

struct TerminatePackPersistence {
    target: PackPersistenceTransition,
}

impl PackPersistence for TerminatePackPersistence {
    fn prepare_transition(&self, transition: PackPersistenceTransition) -> io::Result<()> {
        if transition == self.target {
            std::process::exit(73);
        }
        Ok(())
    }
}

fn pack_persistence_transition_from_name(name: &str) -> PackPersistenceTransition {
    match name {
        "create-partial" => PackPersistenceTransition::CreatePartialBundle,
        "write-partial" => PackPersistenceTransition::WritePartialBundle,
        "create-item-stage" => PackPersistenceTransition::CreateMigrationItemStage,
        "write-item-stage" => PackPersistenceTransition::WriteMigrationItemStage,
        "flush-item-stage" => PackPersistenceTransition::FlushMigrationItemStage,
        "remove-item-stage" => PackPersistenceTransition::RemoveMigrationItemStage,
        "sync-partial-checkpoint" => PackPersistenceTransition::SynchronizePartialBeforeCheckpoint,
        "create-checkpoint" => PackPersistenceTransition::CreateCheckpoint,
        "write-checkpoint" => PackPersistenceTransition::WriteCheckpoint,
        "sync-checkpoint" => PackPersistenceTransition::SynchronizeCheckpoint,
        "sync-checkpoint-directory" => PackPersistenceTransition::SynchronizeCheckpointDirectory,
        "sync-completed-partial" => PackPersistenceTransition::SynchronizeCompletedPartial,
        "publish-completed" => PackPersistenceTransition::PublishCompletedBundle,
        "sync-completed-directory" => {
            PackPersistenceTransition::SynchronizeCompletedBundleDirectory
        }
        unexpected => panic!("unexpected Pack persistence transition {unexpected}"),
    }
}

#[test]
fn pack_persistence_termination_child() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_PERSISTENCE_CHILD") else {
        return;
    };
    let root = PathBuf::from(root);
    let plan = Plan::read_from(&root.join("reviewed-plan.toml")).unwrap();
    let transition = pack_persistence_transition_from_name(
        &std::env::var("INIZA_SYNTHETIC_PERSISTENCE_TRANSITION").unwrap(),
    );
    let persistence = TerminatePackPersistence { target: transition };
    let cancellation = PackCancellation::default();
    if std::env::var_os("INIZA_SYNTHETIC_PERSISTENCE_CHECKPOINT").is_some() {
        assert_eq!(
            cancellation.request_stop(),
            PackStopAction::FinishCurrentItem
        );
    }
    BundleEngine::local()
        .pack(
            PackRequest::new(&plan, root.join("migration.iniza"))
                .with_recovery_context(&synthetic_recovery_context())
                .with_cancellation(&cancellation)
                .with_persistence(&persistence),
        )
        .unwrap();
    panic!("Pack did not terminate at the requested persistence transition");
}

#[test]
fn process_termination_at_every_pack_write_transition_never_creates_false_completion() {
    for (name, request_checkpoint, final_is_visible) in [
        ("create-partial", false, false),
        ("write-partial", false, false),
        ("create-item-stage", false, false),
        ("write-item-stage", false, false),
        ("flush-item-stage", false, false),
        ("remove-item-stage", false, false),
        ("sync-partial-checkpoint", true, false),
        ("create-checkpoint", true, false),
        ("write-checkpoint", true, false),
        ("sync-checkpoint", true, false),
        ("sync-checkpoint-directory", true, false),
        ("sync-completed-partial", false, false),
        ("publish-completed", false, false),
        ("sync-completed-directory", false, true),
    ] {
        let directory = TestDirectory::new();
        let plan = approved_plan(&directory);
        plan.write_to(&directory.path().join("reviewed-plan.toml"))
            .unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "pack_persistence_termination_child",
                "--nocapture",
            ])
            .env("INIZA_SYNTHETIC_PERSISTENCE_CHILD", directory.path())
            .env("INIZA_SYNTHETIC_PERSISTENCE_TRANSITION", name);
        if request_checkpoint {
            command.env("INIZA_SYNTHETIC_PERSISTENCE_CHECKPOINT", "1");
        }
        let status = command.status().unwrap();
        assert_eq!(status.code(), Some(73), "{name} child failed unexpectedly");
        let destination = directory.path().join("migration.iniza");
        let context = synthetic_recovery_context();
        if final_is_visible {
            assert_eq!(
                BundleEngine::local()
                    .verify(VerifyRequest::new(
                        &destination,
                        context.offline_recovery_key(),
                    ))
                    .unwrap()
                    .authenticated_bytes,
                43,
                "{name} left a final name that did not fully authenticate"
            );
        } else {
            assert!(!destination.exists(), "{name} published false completion");
            let restarted = directory.path().join("restarted.iniza");
            let report = BundleEngine::local()
                .pack(PackRequest::new(&plan, &restarted).with_recovery_context(&context))
                .unwrap_or_else(|error| panic!("clean restart after {name} failed: {error}"));
            assert_eq!(report.state(), PackState::Complete);
            assert_eq!(
                BundleEngine::local()
                    .verify(VerifyRequest::new(
                        &restarted,
                        context.offline_recovery_key(),
                    ))
                    .unwrap()
                    .authenticated_bytes,
                43
            );
        }
        assert_eq!(
            fs::read(directory.path().join("synthetic-source/first.txt")).unwrap(),
            b"first protected item\n"
        );
        assert_eq!(
            fs::read(directory.path().join("synthetic-source/second.txt")).unwrap(),
            b"second protected item\n"
        );
    }
}

fn assert_recovery_advice_contract(advice: PackRecoveryAdvice, action: &str) {
    assert!(advice.human_summary().contains(action));
    let machine: serde_json::Value = serde_json::from_str(&advice.machine_json_result()).unwrap();
    assert_eq!(machine["schema_version"], 1);
    assert_eq!(machine["command"], "pack recovery advice");
    assert_eq!(machine["data"]["next_action"], action);
    let output = format!("{}\n{}", advice.human_summary(), machine);
    assert!(!output.contains("31313131"));
    assert!(!output.contains("47474747"));
}

#[test]
fn failed_pack_guidance_distinguishes_retry_resume_restart_and_verify() {
    let retry_directory = TestDirectory::new();
    let retry_plan = approved_plan(&retry_directory);
    let retry_destination = retry_directory.path().join("migration.iniza");
    let context = synthetic_recovery_context();
    let retry_failure = FailPackPersistenceOnce {
        target: PackPersistenceTransition::CreatePartialBundle,
        kind: io::ErrorKind::PermissionDenied,
        failed: AtomicBool::new(false),
    };
    BundleEngine::local()
        .pack(
            PackRequest::new(&retry_plan, &retry_destination)
                .with_recovery_context(&context)
                .with_persistence(&retry_failure),
        )
        .unwrap_err();
    assert_recovery_advice_contract(
        BundleEngine::local().advise_failed_pack(&retry_plan, &retry_destination, &context),
        "retry",
    );

    let resume_directory = TestDirectory::new();
    let resume_plan = approved_plan(&resume_directory);
    let resume_destination = resume_directory.path().join("migration.iniza");
    let cancellation = PackCancellation::default();
    let mut stop = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    BundleEngine::local()
        .pack(
            PackRequest::new(&resume_plan, &resume_destination)
                .with_recovery_context(&context)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut stop),
        )
        .unwrap();
    assert_recovery_advice_contract(
        BundleEngine::local().advise_failed_pack(&resume_plan, &resume_destination, &context),
        "resume-after-revalidation",
    );

    let restart_directory = TestDirectory::new();
    let restart_plan = approved_plan(&restart_directory);
    restart_plan
        .write_to(&restart_directory.path().join("reviewed-plan.toml"))
        .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "pack_termination_child", "--nocapture"])
        .env("INIZA_SYNTHETIC_PACK_CHILD", restart_directory.path())
        .env("INIZA_SYNTHETIC_PACK_PHASE", "captured")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    assert_recovery_advice_contract(
        BundleEngine::local().advise_failed_pack(
            &restart_plan,
            &restart_directory.path().join("migration.iniza"),
            &context,
        ),
        "restart-at-new-destination",
    );

    let verify_directory = TestDirectory::new();
    let verify_plan = approved_plan(&verify_directory);
    let verify_destination = verify_directory.path().join("migration.iniza");
    let verify_failure = FailPackPersistenceOnce {
        target: PackPersistenceTransition::SynchronizeCompletedBundleDirectory,
        kind: io::ErrorKind::StorageFull,
        failed: AtomicBool::new(false),
    };
    BundleEngine::local()
        .pack(
            PackRequest::new(&verify_plan, &verify_destination)
                .with_recovery_context(&context)
                .with_persistence(&verify_failure),
        )
        .unwrap_err();
    assert_recovery_advice_contract(
        BundleEngine::local().advise_failed_pack(&verify_plan, &verify_destination, &context),
        "verify-published-bundle",
    );
}

#[test]
fn owner_can_interrupt_pack_at_a_checkpoint_without_publishing_a_bundle() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let partial = directory.path().join("migration.iniza.partial");
    let cancellation = PackCancellation::default();
    let mut events = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    let engine = BundleEngine::local();

    let report = engine
        .pack(
            PackRequest::new(&plan, &destination)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut events),
        )
        .expect("a clean interruption should return a paused Pack report");

    assert_eq!(report.state(), PackState::Paused);
    assert!(
        !destination.exists(),
        "partial work must never receive a completed Bundle name"
    );
    assert!(partial.is_file());
    assert!(
        events
            .events
            .iter()
            .any(|event| matches!(event, BundleEvent::CheckpointWritten { .. }))
    );
    assert!(
        !events
            .events
            .iter()
            .any(|event| matches!(event, BundleEvent::PackCompleted { .. }))
    );
    assert!(
        engine
            .inspect(InspectRequest::new(&partial, report.offline_recovery_key()))
            .is_err()
    );
    assert!(
        engine
            .verify(VerifyRequest::new(&partial, report.offline_recovery_key()))
            .is_err()
    );
    let restored = directory.path().join("restored");
    assert!(
        RestoreEngine::local()
            .restore(RestoreRequest::new(
                &partial,
                &restored,
                report.offline_recovery_key(),
            ))
            .is_err()
    );
    assert!(!restored.exists());
}

#[test]
fn owner_can_resume_a_paused_bundle_and_restore_every_protected_item() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let cancellation = PackCancellation::default();
    let mut events = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    let engine = BundleEngine::local();
    let paused = engine
        .pack(
            PackRequest::new(&plan, &destination)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut events),
        )
        .unwrap();

    let completed = engine
        .pack(PackRequest::resume(
            &plan,
            &destination,
            paused.recovery_context(),
        ))
        .expect("an authenticated paused Bundle should resume to completion");

    assert_eq!(completed.state(), PackState::Complete);
    for secret in [
        paused.vaultwarden_recovery_secret(),
        paused.offline_recovery_key(),
    ] {
        let verified = engine
            .verify(VerifyRequest::new(&destination, secret))
            .unwrap();
        assert_eq!(verified.authenticated_chunks, 2);
        assert_eq!(verified.authenticated_bytes, 43);
        assert_eq!(verified.summary.included_items, 3);
    }
    let restored = directory.path().join("restored");
    RestoreEngine::local()
        .restore(RestoreRequest::new(
            &destination,
            &restored,
            completed.offline_recovery_key(),
        ))
        .unwrap();
    assert_eq!(
        fs::read(restored.join("first.txt")).unwrap(),
        b"first protected item\n"
    );
    assert_eq!(
        fs::read(restored.join("second.txt")).unwrap(),
        b"second protected item\n"
    );
    assert!(!directory.path().join("migration.iniza.partial").exists());
}

#[test]
fn resume_rejects_a_changed_source_identity_without_modifying_saved_progress() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let partial = directory.path().join("migration.iniza.partial");
    let cancellation = PackCancellation::default();
    let mut events = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    let engine = BundleEngine::local();
    let paused = engine
        .pack(
            PackRequest::new(&plan, &destination)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut events),
        )
        .unwrap();
    let saved = fs::read(&partial).unwrap();
    let original = directory.path().join("synthetic-source/first.txt");
    fs::rename(&original, directory.path().join("saved-first.txt")).unwrap();
    fs::write(&original, b"first protected item\n").unwrap();

    let error = engine
        .pack(PackRequest::resume(
            &plan,
            &destination,
            paused.recovery_context(),
        ))
        .expect_err("a different source identity must require a fresh Plan and restart");

    assert!(error.to_string().contains("source"));
    assert!(!destination.exists());
    assert_eq!(fs::read(&partial).unwrap(), saved);
}

#[test]
fn owner_can_pause_resumed_pack_and_resume_again() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let cancellation = PackCancellation::default();
    let mut events = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    let engine = BundleEngine::local();
    let first = engine
        .pack(
            PackRequest::new(&plan, &destination)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut events),
        )
        .unwrap();
    let second_cancellation = PackCancellation::default();
    let mut second_events = StopAfterCapture {
        cancellation: &second_cancellation,
        events: Vec::new(),
    };
    let second = engine
        .pack(
            PackRequest::resume(&plan, &destination, first.recovery_context())
                .with_cancellation(&second_cancellation)
                .with_event_sink(&mut second_events),
        )
        .unwrap();
    assert_eq!(second.state(), PackState::Paused);
    assert!(!destination.exists());

    let complete = engine
        .pack(PackRequest::resume(
            &plan,
            &destination,
            second.recovery_context(),
        ))
        .expect("the latest authenticated checkpoint should support another Resume");

    assert_eq!(complete.state(), PackState::Complete);
    assert_eq!(
        engine
            .verify(VerifyRequest::new(
                &destination,
                first.offline_recovery_key()
            ))
            .unwrap()
            .authenticated_bytes,
        43
    );
    assert_eq!(
        fs::read_dir(directory.path()).unwrap().count(),
        2,
        "completed Pack should leave only the source and sealed Bundle"
    );
}

#[test]
fn paused_pack_explains_authenticated_resume_without_disclosing_protected_state() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let cancellation = PackCancellation::default();
    cancellation.request_stop();
    let report = BundleEngine::local()
        .pack(PackRequest::new(&plan, &destination).with_cancellation(&cancellation))
        .unwrap();

    let machine = report.machine_json_result();
    let value: serde_json::Value = serde_json::from_str(&machine).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "pack");
    assert_eq!(value["status"], "interrupted");
    assert_eq!(value["data"]["state"], "paused");
    assert_eq!(value["data"]["next_action"], "resume-after-revalidation");
    assert_eq!(report.exit_code(), 70);
    let human = report.human_summary();
    assert!(human.contains("authenticated checkpoint"));
    assert!(human.contains("Resume"));
    for output in [machine, human, format!("{report:?}")] {
        assert!(!output.contains(&directory.path().display().to_string()));
        assert!(!output.contains("first.txt"));
        assert!(!output.contains("first protected item"));
    }
}

struct CompetingPartial(PathBuf);

impl BundleEventSink for CompetingPartial {
    fn emit(&mut self, event: BundleEvent) {
        if event == BundleEvent::PackStarted {
            fs::write(&self.0, b"unrelated partial content\n").unwrap();
        }
    }
}

#[test]
fn pack_failure_never_removes_an_unrelated_partial_created_after_preflight() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let partial = directory.path().join("migration.iniza.partial");
    let mut conflict = CompetingPartial(partial.clone());

    BundleEngine::local()
        .pack(PackRequest::new(&plan, &destination).with_event_sink(&mut conflict))
        .expect_err("a competing partial must not be overwritten");

    assert!(!destination.exists());
    assert_eq!(
        fs::read(&partial).expect("cleanup must not delete unrelated partial content"),
        b"unrelated partial content\n"
    );
}

#[test]
fn resume_rejects_untrusted_inputs_without_changing_saved_progress() {
    for fault in [
        "checkpoint",
        "content",
        "format",
        "plan",
        "recovery",
        "destination",
    ] {
        let directory = TestDirectory::new();
        let mut plan = approved_plan(&directory);
        let destination = directory.path().join("migration.iniza");
        let partial = directory.path().join("migration.iniza.partial");
        let checkpoint = directory.path().join("migration.iniza.partial.checkpoint");
        let cancellation = PackCancellation::default();
        let mut events = StopAfterCapture {
            cancellation: &cancellation,
            events: Vec::new(),
        };
        let engine = BundleEngine::local();
        let paused = engine
            .pack(
                PackRequest::new(&plan, &destination)
                    .with_cancellation(&cancellation)
                    .with_event_sink(&mut events),
            )
            .unwrap();
        let mut other = None;
        match fault {
            "checkpoint" | "content" | "format" => {
                let path = if fault == "checkpoint" {
                    &checkpoint
                } else {
                    &partial
                };
                let mut bytes = fs::read(path).unwrap();
                let index = if fault == "format" {
                    9
                } else {
                    bytes.len() - 1
                };
                bytes[index] ^= 0xff;
                fs::write(path, bytes).unwrap();
            }
            "plan" => {
                fs::write(
                    directory.path().join("synthetic-source/new.txt"),
                    b"newly selected\n",
                )
                .unwrap();
                plan = PlanEngine::local()
                    .scan(ScanRequest::for_directory(
                        directory.path().join("synthetic-source"),
                    ))
                    .unwrap();
                plan.approve(&plan.approval_hash().unwrap()).unwrap();
            }
            "recovery" => {
                other = Some(
                    engine
                        .pack(PackRequest::new(
                            &plan,
                            directory.path().join("other.iniza"),
                        ))
                        .unwrap(),
                );
            }
            "destination" => fs::write(&destination, b"unrelated final content\n").unwrap(),
            _ => unreachable!(),
        }
        let before_partial = fs::read(&partial).unwrap();
        let before_checkpoint = fs::read(&checkpoint).unwrap();
        let context = other.as_ref().unwrap_or(&paused).recovery_context();

        assert!(
            engine
                .pack(PackRequest::resume(&plan, &destination, context))
                .is_err(),
            "{fault} must prevent Resume"
        );

        assert_eq!(
            fs::read(&partial).unwrap(),
            before_partial,
            "{fault} changed saved content"
        );
        assert_eq!(
            fs::read(&checkpoint).unwrap(),
            before_checkpoint,
            "{fault} changed saved checkpoint"
        );
        if fault == "destination" {
            assert_eq!(
                fs::read(&destination).unwrap(),
                b"unrelated final content\n"
            );
        } else {
            assert!(!destination.exists(), "{fault} published final output");
        }
    }
}

#[test]
fn caller_can_hold_recovery_methods_before_pack_writes_any_output() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    // Known, non-secret test material; this is not a production recovery transport.
    let context = PackRecoveryContext::from_secrets(
        RecoverySecret::from_bytes(RecoveryMethod::Vaultwarden, Zeroizing::new([0x31; 32])),
        RecoverySecret::from_bytes(RecoveryMethod::Offline, Zeroizing::new([0x47; 32])),
    )
    .unwrap();

    let report = BundleEngine::local()
        .pack(PackRequest::new(&plan, &destination).with_recovery_context(&context))
        .unwrap();

    assert_eq!(report.state(), PackState::Complete);
    for secret in [
        context.vaultwarden_recovery_secret(),
        context.offline_recovery_key(),
    ] {
        assert_eq!(
            BundleEngine::local()
                .verify(VerifyRequest::new(&destination, secret))
                .unwrap()
                .authenticated_bytes,
            43
        );
    }
}

fn synthetic_recovery_context() -> PackRecoveryContext {
    // Public fixture constants, never a mechanism for transporting real secrets.
    PackRecoveryContext::from_secrets(
        RecoverySecret::from_bytes(RecoveryMethod::Vaultwarden, Zeroizing::new([0x31; 32])),
        RecoverySecret::from_bytes(RecoveryMethod::Offline, Zeroizing::new([0x47; 32])),
    )
    .unwrap()
}

struct TerminatePack<'a> {
    phase: String,
    cancellation: &'a PackCancellation,
}

impl BundleEventSink for TerminatePack<'_> {
    fn emit(&mut self, event: BundleEvent) {
        let phase = match event {
            BundleEvent::PackStarted => "started",
            BundleEvent::ItemCaptured { bytes, .. } if bytes > 0 => {
                if self.phase == "checkpoint" {
                    self.cancellation.request_stop();
                }
                "captured"
            }
            BundleEvent::CheckpointWritten { .. } => "checkpoint",
            BundleEvent::PackCompleted { .. } => "complete",
            _ => return,
        };
        if self.phase == phase {
            // Deliberately bypass unwinding and destructors in this disposable child.
            std::process::exit(73);
        }
    }
}

#[test]
fn pack_termination_child() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_PACK_CHILD") else {
        return;
    };
    let root = PathBuf::from(root);
    let plan = Plan::read_from(&root.join("reviewed-plan.toml")).unwrap();
    let cancellation = PackCancellation::default();
    let mut events = TerminatePack {
        phase: std::env::var("INIZA_SYNTHETIC_PACK_PHASE").unwrap(),
        cancellation: &cancellation,
    };
    let context = synthetic_recovery_context();
    BundleEngine::local()
        .pack(
            PackRequest::new(&plan, root.join("migration.iniza"))
                .with_recovery_context(&context)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut events),
        )
        .unwrap();
    panic!("the specified termination boundary was not reached");
}

#[test]
fn process_termination_preserves_only_authenticated_resumable_progress() {
    for phase in ["started", "captured", "checkpoint", "complete"] {
        let directory = TestDirectory::new();
        let plan = approved_plan(&directory);
        plan.write_to(&directory.path().join("reviewed-plan.toml"))
            .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "pack_termination_child", "--nocapture"])
            .env("INIZA_SYNTHETIC_PACK_CHILD", directory.path())
            .env("INIZA_SYNTHETIC_PACK_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73), "{phase} child failed unexpectedly");
        let destination = directory.path().join("migration.iniza");
        let partial = directory.path().join("migration.iniza.partial");
        let context = synthetic_recovery_context();
        let engine = BundleEngine::local();
        if phase == "complete" {
            assert_eq!(
                engine
                    .verify(VerifyRequest::new(
                        &destination,
                        context.offline_recovery_key()
                    ))
                    .unwrap()
                    .authenticated_bytes,
                43
            );
        } else {
            assert!(!destination.exists());
            if phase == "started" {
                assert!(!partial.exists());
                engine
                    .pack(PackRequest::new(&plan, &destination).with_recovery_context(&context))
                    .unwrap();
            } else {
                assert!(
                    engine
                        .inspect(InspectRequest::new(
                            &partial,
                            context.offline_recovery_key()
                        ))
                        .is_err()
                );
                assert!(
                    engine
                        .verify(VerifyRequest::new(&partial, context.offline_recovery_key()))
                        .is_err()
                );
                let restored = directory.path().join("rejected-restore");
                assert!(
                    RestoreEngine::local()
                        .restore(RestoreRequest::new(
                            &partial,
                            &restored,
                            context.offline_recovery_key()
                        ))
                        .is_err()
                );
                assert!(!restored.exists());
                let saved = fs::read(&partial).unwrap();
                let resumed = engine.pack(PackRequest::resume(&plan, &destination, &context));
                if phase == "captured" {
                    let error = resumed.expect_err("uncheckpointed output cannot resume");
                    assert!(error.to_string().contains("restart required"), "{error}");
                    assert_eq!(fs::read(&partial).unwrap(), saved);
                    assert!(!destination.exists());
                } else {
                    assert_eq!(resumed.unwrap().state(), PackState::Complete);
                    assert_eq!(
                        engine
                            .verify(VerifyRequest::new(
                                &destination,
                                context.offline_recovery_key()
                            ))
                            .unwrap()
                            .authenticated_bytes,
                        43
                    );
                }
            }
        }
        assert_eq!(
            fs::read(directory.path().join("synthetic-source/first.txt")).unwrap(),
            b"first protected item\n"
        );
        assert_eq!(
            fs::read(directory.path().join("synthetic-source/second.txt")).unwrap(),
            b"second protected item\n"
        );
    }
}

#[test]
fn every_partial_artifact_name_is_rejected_even_with_complete_bundle_bytes() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let engine = BundleEngine::local();
    let complete = engine.pack(PackRequest::new(&plan, &destination)).unwrap();
    for suffix in [
        "partial",
        "partial.resume",
        "partial.previous",
        "partial.checkpoint",
        "partial.resume.checkpoint",
    ] {
        let partial = directory.path().join(format!("migration.iniza.{suffix}"));
        fs::copy(&destination, &partial).unwrap();
        assert!(
            engine
                .inspect(InspectRequest::new(
                    &partial,
                    complete.offline_recovery_key()
                ))
                .is_err(),
            "Inspect accepted {suffix}"
        );
        assert!(
            engine
                .verify(VerifyRequest::new(
                    &partial,
                    complete.offline_recovery_key()
                ))
                .is_err(),
            "Verify accepted {suffix}"
        );
        let restored = directory.path().join("must-not-be-created");
        assert!(
            RestoreEngine::local()
                .restore(RestoreRequest::new(
                    &partial,
                    &restored,
                    complete.offline_recovery_key()
                ))
                .is_err(),
            "Restore accepted {suffix}"
        );
        assert!(!restored.exists());
    }
}

struct CheckpointCapacity(Arc<AtomicBool>);

impl DestinationCapacity for CheckpointCapacity {
    fn available_bytes(&self, _destination: &Path) -> std::io::Result<u64> {
        Ok(if self.0.load(Ordering::SeqCst) {
            0
        } else {
            u64::MAX
        })
    }
}

struct LoseCapacityAtPause<'a> {
    exhausted: Arc<AtomicBool>,
    cancellation: &'a PackCancellation,
}

impl BundleEventSink for LoseCapacityAtPause<'_> {
    fn emit(&mut self, event: BundleEvent) {
        if matches!(event, BundleEvent::ItemCaptured { bytes, .. } if bytes > 0) {
            self.exhausted.store(true, Ordering::SeqCst);
            self.cancellation.request_stop();
        }
    }
}

#[test]
fn checkpoint_capacity_failure_preserves_previous_resumable_progress() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let partial = directory.path().join("migration.iniza.partial");
    let checkpoint = directory.path().join("migration.iniza.partial.checkpoint");
    let cancellation = PackCancellation::default();
    let mut stop = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    let paused = BundleEngine::local()
        .pack(
            PackRequest::new(&plan, &destination)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut stop),
        )
        .unwrap();
    let saved_partial = fs::read(&partial).unwrap();
    let saved_checkpoint = fs::read(&checkpoint).unwrap();
    let exhausted = Arc::new(AtomicBool::new(false));
    let second_cancellation = PackCancellation::default();
    let mut failure = LoseCapacityAtPause {
        exhausted: Arc::clone(&exhausted),
        cancellation: &second_cancellation,
    };
    let engine = BundleEngine::with_adapters(LocalBundleSource, CheckpointCapacity(exhausted));

    let error = engine
        .pack(
            PackRequest::resume(&plan, &destination, paused.recovery_context())
                .with_cancellation(&second_cancellation)
                .with_event_sink(&mut failure),
        )
        .expect_err("a checkpoint must not claim success when destination capacity is exhausted");

    assert!(error.to_string().contains("insufficient destination space"));
    assert!(!destination.exists());
    assert_eq!(fs::read(&partial).unwrap(), saved_partial);
    assert_eq!(fs::read(&checkpoint).unwrap(), saved_checkpoint);
    assert!(
        !directory
            .path()
            .join("migration.iniza.partial.resume")
            .exists()
    );
    let complete = BundleEngine::local()
        .pack(PackRequest::resume(
            &plan,
            &destination,
            paused.recovery_context(),
        ))
        .unwrap();
    assert_eq!(complete.state(), PackState::Complete);
    assert_eq!(
        BundleEngine::local()
            .verify(VerifyRequest::new(
                &destination,
                complete.offline_recovery_key()
            ))
            .unwrap()
            .authenticated_bytes,
        43
    );
}

struct ReplacePartialAfterCapture<'a> {
    partial: PathBuf,
    cancellation: Option<&'a PackCancellation>,
    replaced: bool,
}

impl BundleEventSink for ReplacePartialAfterCapture<'_> {
    fn emit(&mut self, event: BundleEvent) {
        if !self.replaced && matches!(event, BundleEvent::ItemCaptured { bytes, .. } if bytes > 0) {
            fs::rename(&self.partial, self.partial.with_extension("displaced")).unwrap();
            fs::write(
                &self.partial,
                b"unrelated replacement must remain untouched\n",
            )
            .unwrap();
            self.replaced = true;
            if let Some(cancellation) = self.cancellation {
                cancellation.request_stop();
            }
        }
    }
}

#[test]
fn pack_rejects_a_replaced_partial_before_checkpoint_or_publication() {
    for pause in [false, true] {
        let directory = TestDirectory::new();
        let plan = approved_plan(&directory);
        let destination = directory.path().join("migration.iniza");
        let partial = directory.path().join("migration.iniza.partial");
        let cancellation = PackCancellation::default();
        let mut replacement = ReplacePartialAfterCapture {
            partial: partial.clone(),
            cancellation: pause.then_some(&cancellation),
            replaced: false,
        };

        BundleEngine::local()
            .pack(
                PackRequest::new(&plan, &destination)
                    .with_cancellation(&cancellation)
                    .with_event_sink(&mut replacement),
            )
            .expect_err("a substituted partial cannot become a checkpoint or completed Bundle");

        assert!(!destination.exists());
        assert!(
            !directory
                .path()
                .join("migration.iniza.partial.checkpoint")
                .exists()
        );
        assert_eq!(
            fs::read(&partial).unwrap(),
            b"unrelated replacement must remain untouched\n"
        );
    }
}

struct ReplaceSavedPartialOnResume {
    partial: PathBuf,
}

impl BundleEventSink for ReplaceSavedPartialOnResume {
    fn emit(&mut self, event: BundleEvent) {
        if event == BundleEvent::PackStarted {
            fs::rename(
                &self.partial,
                self.partial.with_extension("authenticated-saved"),
            )
            .unwrap();
            fs::write(
                &self.partial,
                b"unrelated saved-path replacement must remain untouched\n",
            )
            .unwrap();
        }
    }
}

#[test]
fn completed_resume_never_removes_an_unrelated_saved_path_replacement() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let partial = directory.path().join("migration.iniza.partial");
    let cancellation = PackCancellation::default();
    let mut stop = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    let paused = BundleEngine::local()
        .pack(
            PackRequest::new(&plan, &destination)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut stop),
        )
        .unwrap();
    let mut replacement = ReplaceSavedPartialOnResume {
        partial: partial.clone(),
    };

    let completed = BundleEngine::local()
        .pack(
            PackRequest::resume(&plan, &destination, paused.recovery_context())
                .with_event_sink(&mut replacement),
        )
        .expect("Resume remains bound to the authenticated opened progress");

    assert_eq!(completed.state(), PackState::Complete);
    assert_eq!(
        fs::read(&partial).expect("cleanup must preserve an unrelated replacement"),
        b"unrelated saved-path replacement must remain untouched\n"
    );
    assert_eq!(
        BundleEngine::local()
            .verify(VerifyRequest::new(
                &destination,
                completed.offline_recovery_key(),
            ))
            .unwrap()
            .authenticated_bytes,
        43
    );
}

struct ReplaceSavedCheckpointOnResume {
    checkpoint: PathBuf,
}

impl BundleEventSink for ReplaceSavedCheckpointOnResume {
    fn emit(&mut self, event: BundleEvent) {
        if event == BundleEvent::PackStarted {
            fs::rename(
                &self.checkpoint,
                self.checkpoint.with_extension("authenticated-saved"),
            )
            .unwrap();
            fs::write(
                &self.checkpoint,
                b"unrelated checkpoint-path replacement must remain untouched\n",
            )
            .unwrap();
        }
    }
}

#[test]
fn completed_resume_never_removes_an_unrelated_checkpoint_path_replacement() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let checkpoint = directory.path().join("migration.iniza.partial.checkpoint");
    let cancellation = PackCancellation::default();
    let mut stop = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    let paused = BundleEngine::local()
        .pack(
            PackRequest::new(&plan, &destination)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut stop),
        )
        .unwrap();
    let mut replacement = ReplaceSavedCheckpointOnResume {
        checkpoint: checkpoint.clone(),
    };

    let completed = BundleEngine::local()
        .pack(
            PackRequest::resume(&plan, &destination, paused.recovery_context())
                .with_event_sink(&mut replacement),
        )
        .expect("Resume remains bound to the authenticated checkpoint bytes");

    assert_eq!(completed.state(), PackState::Complete);
    assert_eq!(
        fs::read(&checkpoint).expect("cleanup must preserve an unrelated replacement"),
        b"unrelated checkpoint-path replacement must remain untouched\n"
    );
    assert_eq!(
        BundleEngine::local()
            .verify(VerifyRequest::new(
                &destination,
                completed.offline_recovery_key(),
            ))
            .unwrap()
            .authenticated_bytes,
        43
    );
}

struct ReplaceSavedPartialAndPause<'a> {
    partial: PathBuf,
    cancellation: &'a PackCancellation,
}

impl BundleEventSink for ReplaceSavedPartialAndPause<'_> {
    fn emit(&mut self, event: BundleEvent) {
        match event {
            BundleEvent::PackStarted => {
                fs::rename(
                    &self.partial,
                    self.partial.with_extension("authenticated-saved"),
                )
                .unwrap();
                fs::write(
                    &self.partial,
                    b"unrelated saved path must survive failed promotion\n",
                )
                .unwrap();
            }
            BundleEvent::ItemCaptured { bytes, .. } if bytes > 0 => {
                self.cancellation.request_stop();
            }
            _ => {}
        }
    }
}

#[test]
fn paused_resume_never_promotes_through_a_replaced_saved_partial() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let partial = directory.path().join("migration.iniza.partial");
    let cancellation = PackCancellation::default();
    let mut stop = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    let paused = BundleEngine::local()
        .pack(
            PackRequest::new(&plan, &destination)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut stop),
        )
        .unwrap();
    let second_cancellation = PackCancellation::default();
    let mut replacement = ReplaceSavedPartialAndPause {
        partial: partial.clone(),
        cancellation: &second_cancellation,
    };

    let error = BundleEngine::local()
        .pack(
            PackRequest::resume(&plan, &destination, paused.recovery_context())
                .with_cancellation(&second_cancellation)
                .with_event_sink(&mut replacement),
        )
        .expect_err("changed saved progress paths must prevent checkpoint promotion");

    assert!(error.to_string().contains("identity changed"));
    assert!(!destination.exists());
    assert_eq!(
        fs::read(&partial).unwrap(),
        b"unrelated saved path must survive failed promotion\n"
    );
    assert!(
        directory
            .path()
            .join("migration.iniza.partial.resume")
            .is_file()
    );
    assert!(
        directory
            .path()
            .join("migration.iniza.partial.resume.checkpoint")
            .is_file()
    );
}

struct ReplaceSavedCheckpointAndPause<'a> {
    checkpoint: PathBuf,
    cancellation: &'a PackCancellation,
}

impl BundleEventSink for ReplaceSavedCheckpointAndPause<'_> {
    fn emit(&mut self, event: BundleEvent) {
        match event {
            BundleEvent::PackStarted => {
                fs::rename(
                    &self.checkpoint,
                    self.checkpoint.with_extension("authenticated-saved"),
                )
                .unwrap();
                fs::write(
                    &self.checkpoint,
                    b"unrelated checkpoint path must survive failed promotion\n",
                )
                .unwrap();
            }
            BundleEvent::ItemCaptured { bytes, .. } if bytes > 0 => {
                self.cancellation.request_stop();
            }
            _ => {}
        }
    }
}

#[test]
fn paused_resume_never_promotes_through_a_replaced_saved_checkpoint() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    let destination = directory.path().join("migration.iniza");
    let checkpoint = directory.path().join("migration.iniza.partial.checkpoint");
    let cancellation = PackCancellation::default();
    let mut stop = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    let paused = BundleEngine::local()
        .pack(
            PackRequest::new(&plan, &destination)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut stop),
        )
        .unwrap();
    let second_cancellation = PackCancellation::default();
    let mut replacement = ReplaceSavedCheckpointAndPause {
        checkpoint: checkpoint.clone(),
        cancellation: &second_cancellation,
    };

    let error = BundleEngine::local()
        .pack(
            PackRequest::resume(&plan, &destination, paused.recovery_context())
                .with_cancellation(&second_cancellation)
                .with_event_sink(&mut replacement),
        )
        .expect_err("changed saved checkpoint paths must prevent promotion");

    assert!(error.to_string().contains("identity changed"));
    assert!(!destination.exists());
    assert_eq!(
        fs::read(&checkpoint).unwrap(),
        b"unrelated checkpoint path must survive failed promotion\n"
    );
    assert!(
        directory
            .path()
            .join("migration.iniza.partial.resume")
            .is_file()
    );
    assert!(
        directory
            .path()
            .join("migration.iniza.partial.resume.checkpoint")
            .is_file()
    );
}

#[test]
fn resumed_pack_checkpoint_termination_child() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_RESUMED_PACK_CHILD") else {
        return;
    };
    let root = PathBuf::from(root);
    let plan = Plan::read_from(&root.join("reviewed-plan.toml")).unwrap();
    let cancellation = PackCancellation::default();
    let mut events = TerminatePack {
        phase: "checkpoint".to_owned(),
        cancellation: &cancellation,
    };
    let context = synthetic_recovery_context();
    BundleEngine::local()
        .pack(
            PackRequest::resume(&plan, root.join("migration.iniza"), &context)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut events),
        )
        .unwrap();
    panic!("resumed Pack did not reach its durable checkpoint");
}

#[test]
fn owner_can_resume_after_termination_at_a_resumed_pack_checkpoint() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    plan.write_to(&directory.path().join("reviewed-plan.toml"))
        .unwrap();
    let destination = directory.path().join("migration.iniza");
    let context = synthetic_recovery_context();
    let cancellation = PackCancellation::default();
    let mut stop = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    BundleEngine::local()
        .pack(
            PackRequest::new(&plan, &destination)
                .with_recovery_context(&context)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut stop),
        )
        .unwrap();

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "resumed_pack_checkpoint_termination_child",
            "--nocapture",
        ])
        .env("INIZA_SYNTHETIC_RESUMED_PACK_CHILD", directory.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    assert!(!destination.exists());
    assert!(directory.path().join("migration.iniza.partial").is_file());
    assert!(
        directory
            .path()
            .join("migration.iniza.partial.resume")
            .is_file()
    );

    let complete = BundleEngine::local()
        .pack(PackRequest::resume(&plan, &destination, &context))
        .expect("the latest authenticated checkpoint should remain resumable");

    assert_eq!(complete.state(), PackState::Complete);
    assert_eq!(
        BundleEngine::local()
            .verify(VerifyRequest::new(
                &destination,
                context.offline_recovery_key(),
            ))
            .unwrap()
            .authenticated_bytes,
        43
    );
    assert_eq!(
        fs::read(directory.path().join("synthetic-source/first.txt")).unwrap(),
        b"first protected item\n"
    );
    assert_eq!(
        fs::read(directory.path().join("synthetic-source/second.txt")).unwrap(),
        b"second protected item\n"
    );
}

#[test]
fn corrupted_interrupted_resume_never_displaces_older_authenticated_progress() {
    let directory = TestDirectory::new();
    let plan = approved_plan(&directory);
    plan.write_to(&directory.path().join("reviewed-plan.toml"))
        .unwrap();
    let destination = directory.path().join("migration.iniza");
    let partial = directory.path().join("migration.iniza.partial");
    let checkpoint = directory.path().join("migration.iniza.partial.checkpoint");
    let resumed_partial = directory.path().join("migration.iniza.partial.resume");
    let context = synthetic_recovery_context();
    let cancellation = PackCancellation::default();
    let mut stop = StopAfterCapture {
        cancellation: &cancellation,
        events: Vec::new(),
    };
    BundleEngine::local()
        .pack(
            PackRequest::new(&plan, &destination)
                .with_recovery_context(&context)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut stop),
        )
        .unwrap();
    let saved_partial = fs::read(&partial).unwrap();
    let saved_checkpoint = fs::read(&checkpoint).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "resumed_pack_checkpoint_termination_child",
            "--nocapture",
        ])
        .env("INIZA_SYNTHETIC_RESUMED_PACK_CHILD", directory.path())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    let mut corrupted = fs::read(&resumed_partial).unwrap();
    *corrupted.last_mut().unwrap() ^= 0xff;
    fs::write(&resumed_partial, corrupted).unwrap();

    BundleEngine::local()
        .pack(PackRequest::resume(&plan, &destination, &context))
        .expect_err("corrupted newer progress must not displace authenticated saved progress");

    assert!(!destination.exists());
    assert_eq!(fs::read(&partial).unwrap(), saved_partial);
    assert_eq!(fs::read(&checkpoint).unwrap(), saved_checkpoint);
}

struct TerminateCheckpointPromotion<'a> {
    step: PackCheckpointPromotionStep,
    cancellation: &'a PackCancellation,
}

impl BundleEventSink for TerminateCheckpointPromotion<'_> {
    fn emit(&mut self, event: BundleEvent) {
        match event {
            BundleEvent::ItemCaptured { bytes, .. } if bytes > 0 => {
                self.cancellation.request_stop();
            }
            BundleEvent::CheckpointPromotionAdvanced { step } if step == self.step => {
                // Deliberately bypass unwinding and destructors in this disposable child.
                std::process::exit(73);
            }
            _ => {}
        }
    }
}

#[test]
fn pack_checkpoint_promotion_termination_child() {
    let Some(root) = std::env::var_os("INIZA_SYNTHETIC_PROMOTION_CHILD") else {
        return;
    };
    let step = match std::env::var("INIZA_SYNTHETIC_PROMOTION_STEP")
        .unwrap()
        .as_str()
    {
        "promotion-journal-written" => PackCheckpointPromotionStep::PromotionJournalWritten,
        "saved-partial-retained" => PackCheckpointPromotionStep::SavedPartialRetained,
        "saved-checkpoint-retained" => PackCheckpointPromotionStep::SavedCheckpointRetained,
        "resumed-partial-activated" => PackCheckpointPromotionStep::ResumedPartialActivated,
        "resumed-checkpoint-activated" => PackCheckpointPromotionStep::ResumedCheckpointActivated,
        "superseded-partial-removed" => PackCheckpointPromotionStep::SupersededPartialRemoved,
        "superseded-checkpoint-removed" => PackCheckpointPromotionStep::SupersededCheckpointRemoved,
        "promotion-journal-removed" => PackCheckpointPromotionStep::PromotionJournalRemoved,
        unexpected => panic!("unexpected promotion step {unexpected}"),
    };
    let root = PathBuf::from(root);
    let plan = Plan::read_from(&root.join("reviewed-plan.toml")).unwrap();
    let context = synthetic_recovery_context();
    let cancellation = PackCancellation::default();
    let mut events = TerminateCheckpointPromotion {
        step,
        cancellation: &cancellation,
    };
    BundleEngine::local()
        .pack(
            PackRequest::resume(&plan, root.join("migration.iniza"), &context)
                .with_cancellation(&cancellation)
                .with_event_sink(&mut events),
        )
        .unwrap();
    panic!("resumed Pack did not reach the requested durable promotion step");
}

#[test]
fn owner_can_resume_after_termination_at_every_checkpoint_promotion_step() {
    for step in [
        "promotion-journal-written",
        "promotion-journal-removed",
        "superseded-partial-removed",
        "superseded-checkpoint-removed",
        "saved-partial-retained",
        "saved-checkpoint-retained",
        "resumed-partial-activated",
        "resumed-checkpoint-activated",
    ] {
        let directory = TestDirectory::new();
        let plan = approved_plan(&directory);
        plan.write_to(&directory.path().join("reviewed-plan.toml"))
            .unwrap();
        let destination = directory.path().join("migration.iniza");
        let context = synthetic_recovery_context();
        let cancellation = PackCancellation::default();
        let mut stop = StopAfterCapture {
            cancellation: &cancellation,
            events: Vec::new(),
        };
        BundleEngine::local()
            .pack(
                PackRequest::new(&plan, &destination)
                    .with_recovery_context(&context)
                    .with_cancellation(&cancellation)
                    .with_event_sink(&mut stop),
            )
            .unwrap();

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pack_checkpoint_promotion_termination_child",
                "--nocapture",
            ])
            .env("INIZA_SYNTHETIC_PROMOTION_CHILD", directory.path())
            .env("INIZA_SYNTHETIC_PROMOTION_STEP", step)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73), "{step} child failed unexpectedly");
        assert!(!destination.exists());

        let completed = BundleEngine::local()
            .pack(PackRequest::resume(&plan, &destination, &context))
            .unwrap_or_else(|error| panic!("Resume after {step} failed: {error}"));

        assert_eq!(completed.state(), PackState::Complete);
        assert_eq!(
            BundleEngine::local()
                .verify(VerifyRequest::new(
                    &destination,
                    context.offline_recovery_key(),
                ))
                .unwrap()
                .authenticated_bytes,
            43
        );
        assert_eq!(
            fs::read(directory.path().join("synthetic-source/first.txt")).unwrap(),
            b"first protected item\n"
        );
        assert_eq!(
            fs::read(directory.path().join("synthetic-source/second.txt")).unwrap(),
            b"second protected item\n"
        );
    }
}
