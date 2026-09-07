use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AuthenticatedBundleSummary, CoreError, Disposition, ExtendedAttribute, MigrationItemKind, Plan,
    PlanApprovalState, RecoveryMethod, RecoverySecret, SealedBundle,
};

const MAGIC: &[u8; 8] = b"INIZAIZ2";
const FORMAT_VERSION: u16 = 2;
const SUITE_ID: u16 = 1;
const SLOT_COUNT: u8 = 2;
const SLOT_LENGTH: usize = 106;
const FIXED_HEADER_LENGTH: usize = 84;
const HEADER_LENGTH: usize = FIXED_HEADER_LENGTH + SLOT_LENGTH * SLOT_COUNT as usize;
const RECORD_HEADER_LENGTH: usize = 28;
const ARGON2_MEMORY_KIBIBYTES: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const MAX_PLAINTEXT_CHUNK: usize = 1024 * 1024;
const MAX_MANIFEST_PLAINTEXT: usize = 16 * 1024 * 1024;
const MAX_INDEX_PLAINTEXT: usize = 64 * 1024 * 1024;
const MAX_COMPLETION_PLAINTEXT: usize = 64;
const MAX_PACK_CHECKPOINT: u64 = 128 * 1024 * 1024;
const MAX_PACK_PROMOTION_JOURNAL: u64 = 4096;

const RECORD_CONTENT: u8 = 1;
const RECORD_MANIFEST: u8 = 2;
const RECORD_INDEX: u8 = 3;
const RECORD_COMPLETION: u8 = 255;

#[derive(Debug, Default)]
pub struct PackCancellation(AtomicU8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackStopAction {
    FinishCurrentItem,
    TerminateImmediately,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackRecoveryAdvice {
    Retry,
    ResumeAfterRevalidation,
    RestartAtNewDestination,
    VerifyPublishedBundle,
}

impl PackRecoveryAdvice {
    fn next_action(self) -> &'static str {
        match self {
            Self::Retry => "retry",
            Self::ResumeAfterRevalidation => "resume-after-revalidation",
            Self::RestartAtNewDestination => "restart-at-new-destination",
            Self::VerifyPublishedBundle => "verify-published-bundle",
        }
    }

    pub fn human_summary(self) -> &'static str {
        match self {
            Self::Retry => {
                "Next action: retry. No Pack output artifact is visible at the requested destination."
            }
            Self::ResumeAfterRevalidation => {
                "Next action: resume-after-revalidation. Resume must authenticate the Plan, Recovery Methods, sources, checkpoint, and destination state before writing."
            }
            Self::RestartAtNewDestination => {
                "Next action: restart-at-new-destination while preserving every existing partial artifact for review."
            }
            Self::VerifyPublishedBundle => {
                "Next action: verify-published-bundle. A completed name is visible, but it must pass full verification before reliance."
            }
        }
    }

    pub fn machine_json_result(self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "command": "pack recovery advice",
            "status": "guidance",
            "data": { "next_action": self.next_action() },
            "warnings": [],
            "errors": [],
        })
        .to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackPersistenceTransition {
    CreatePartialBundle,
    WritePartialBundle,
    CreateMigrationItemStage,
    WriteMigrationItemStage,
    FlushMigrationItemStage,
    RemoveMigrationItemStage,
    SynchronizePartialBeforeCheckpoint,
    CreateCheckpoint,
    WriteCheckpoint,
    SynchronizeCheckpoint,
    SynchronizeCheckpointDirectory,
    SynchronizeCompletedPartial,
    PublishCompletedBundle,
    SynchronizeCompletedBundleDirectory,
    CreatePromotionJournal,
    WritePromotionJournal,
    SynchronizePromotionJournal,
    SynchronizePromotionJournalDirectory,
    PublishPromotionJournal,
    SynchronizePublishedPromotionJournal,
    MoveSavedPartial,
    SynchronizeSavedPartialMove,
    MoveSavedCheckpoint,
    SynchronizeSavedCheckpointMove,
    MoveResumedPartial,
    SynchronizeResumedPartialMove,
    MoveResumedCheckpoint,
    SynchronizeResumedCheckpointMove,
    RemoveSupersededPartial,
    SynchronizeSupersededPartialRemoval,
    RemoveSupersededCheckpoint,
    SynchronizeSupersededCheckpointRemoval,
    RemovePromotionJournal,
    SynchronizePromotionJournalRemoval,
}

pub trait PackPersistence: Send + Sync {
    fn prepare_transition(&self, transition: PackPersistenceTransition) -> io::Result<()>;
}

#[derive(Debug, Default)]
pub struct LocalPackPersistence;

impl PackPersistence for LocalPackPersistence {
    fn prepare_transition(&self, _transition: PackPersistenceTransition) -> io::Result<()> {
        Ok(())
    }
}

static LOCAL_PACK_PERSISTENCE: LocalPackPersistence = LocalPackPersistence;

impl PackCancellation {
    pub fn request_stop(&self) -> PackStopAction {
        if self
            .0
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            PackStopAction::FinishCurrentItem
        } else {
            self.0.store(2, Ordering::SeqCst);
            PackStopAction::TerminateImmediately
        }
    }

    fn is_requested(&self) -> bool {
        self.0.load(Ordering::SeqCst) > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackState {
    Complete,
    Paused,
}

#[derive(Debug)]
pub struct PackRecoveryContext(SealedBundle);

impl PackRecoveryContext {
    pub fn from_secrets(
        vaultwarden: RecoverySecret,
        offline: RecoverySecret,
    ) -> Result<Self, CoreError> {
        if vaultwarden.method() != RecoveryMethod::Vaultwarden
            || offline.method() != RecoveryMethod::Offline
            || vaultwarden.bytes == offline.bytes
        {
            return Err(invalid_bundle(
                "Pack requires two distinct, correctly identified Recovery Methods",
            ));
        }
        Ok(Self(SealedBundle {
            vaultwarden_recovery_secret: vaultwarden,
            offline_recovery_key: offline,
        }))
    }

    pub fn vaultwarden_recovery_secret(&self) -> &RecoverySecret {
        self.0.vaultwarden_recovery_secret()
    }

    pub fn offline_recovery_key(&self) -> &RecoverySecret {
        self.0.offline_recovery_key()
    }
}

#[derive(Debug)]
pub struct PackReport {
    state: PackState,
    recovery: PackRecoveryContext,
}

impl PackReport {
    pub fn state(&self) -> PackState {
        self.state
    }

    pub fn vaultwarden_recovery_secret(&self) -> &RecoverySecret {
        self.recovery.0.vaultwarden_recovery_secret()
    }

    pub fn offline_recovery_key(&self) -> &RecoverySecret {
        self.recovery.0.offline_recovery_key()
    }

    pub fn recovery_context(&self) -> &PackRecoveryContext {
        &self.recovery
    }

    pub fn exit_code(&self) -> u8 {
        match self.state {
            PackState::Complete => 0,
            PackState::Paused => 70,
        }
    }

    pub fn human_summary(&self) -> String {
        match self.state {
            PackState::Complete => "Pack completed. Fully verify the Bundle before relying on it.",
            PackState::Paused => "Pack paused at an authenticated checkpoint. Resume requires the matching Plan, Recovery Methods, unchanged sources, and revalidated saved progress.",
        }.to_owned()
    }

    pub fn machine_json_result(&self) -> String {
        let (status, state, next_action) = match self.state {
            PackState::Complete => ("success", "complete", "verify"),
            PackState::Paused => ("interrupted", "paused", "resume-after-revalidation"),
        };
        serde_json::json!({
            "schema_version": 1, "command": "pack", "status": status,
            "data": { "state": state, "next_action": next_action },
            "warnings": [], "errors": [],
        })
        .to_string()
    }
}

pub struct PackRequest<'a> {
    plan: &'a Plan,
    destination: PathBuf,
    event_sink: Option<&'a mut dyn BundleEventSink>,
    cancellation: Option<&'a PackCancellation>,
    resume: Option<&'a PackRecoveryContext>,
    recovery: Option<&'a PackRecoveryContext>,
    persistence: &'a dyn PackPersistence,
}

impl<'a> PackRequest<'a> {
    pub fn new(plan: &'a Plan, destination: impl Into<PathBuf>) -> Self {
        Self {
            plan,
            destination: destination.into(),
            event_sink: None,
            cancellation: None,
            resume: None,
            recovery: None,
            persistence: &LOCAL_PACK_PERSISTENCE,
        }
    }

    pub fn resume(
        plan: &'a Plan,
        destination: impl Into<PathBuf>,
        recovery: &'a PackRecoveryContext,
    ) -> Self {
        Self {
            resume: Some(recovery),
            ..Self::new(plan, destination)
        }
    }

    pub fn with_event_sink(mut self, event_sink: &'a mut dyn BundleEventSink) -> Self {
        self.event_sink = Some(event_sink);
        self
    }

    pub fn with_cancellation(mut self, cancellation: &'a PackCancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub fn with_persistence(mut self, persistence: &'a dyn PackPersistence) -> Self {
        self.persistence = persistence;
        self
    }

    pub fn with_recovery_context(mut self, recovery: &'a PackRecoveryContext) -> Self {
        self.recovery = Some(recovery);
        self
    }
}

#[derive(Debug)]
pub struct InspectRequest<'a> {
    source: PathBuf,
    recovery_secret: &'a RecoverySecret,
}

impl<'a> InspectRequest<'a> {
    pub fn new(source: impl Into<PathBuf>, recovery_secret: &'a RecoverySecret) -> Self {
        Self {
            source: source.into(),
            recovery_secret,
        }
    }
}

pub struct VerifyRequest<'a> {
    source: PathBuf,
    recovery_secret: &'a RecoverySecret,
    event_sink: Option<&'a mut dyn BundleEventSink>,
}

pub struct VerifiedCopyRequest<'a> {
    source: PathBuf,
    destination: PathBuf,
    recovery_secret: &'a RecoverySecret,
    replace_matching_partial: bool,
    cancellation: Option<&'a VerifiedCopyCancellation>,
    event_sink: Option<&'a mut dyn VerifiedCopyEventSink>,
    persistence: &'a dyn VerifiedCopyPersistence,
}

impl<'a> VerifiedCopyRequest<'a> {
    pub fn new(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        recovery_secret: &'a RecoverySecret,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            recovery_secret,
            replace_matching_partial: false,
            cancellation: None,
            event_sink: None,
            persistence: &LOCAL_VERIFIED_COPY_PERSISTENCE,
        }
    }

    pub fn replace_matching_partial(mut self) -> Self {
        self.replace_matching_partial = true;
        self
    }

    pub fn with_cancellation(mut self, cancellation: &'a VerifiedCopyCancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub fn with_event_sink(mut self, event_sink: &'a mut dyn VerifiedCopyEventSink) -> Self {
        self.event_sink = Some(event_sink);
        self
    }

    pub fn with_persistence(mut self, persistence: &'a dyn VerifiedCopyPersistence) -> Self {
        self.persistence = persistence;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedCopyDurability {
    Durable,
    Weaker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedCopyPersistenceTransition {
    ReadSource,
    CreatePartial,
    WritePartial,
    SynchronizePartial,
    AuthenticatePartial,
    PublishCompleted,
    SynchronizeDirectory,
    ReopenCompleted,
}

pub trait VerifiedCopyPersistence: Send + Sync {
    fn prepare_transition(&self, transition: VerifiedCopyPersistenceTransition) -> io::Result<()>;

    fn durability(&self) -> VerifiedCopyDurability {
        VerifiedCopyDurability::Durable
    }
}

#[derive(Debug, Default)]
pub struct LocalVerifiedCopyPersistence;

impl VerifiedCopyPersistence for LocalVerifiedCopyPersistence {
    fn prepare_transition(&self, _transition: VerifiedCopyPersistenceTransition) -> io::Result<()> {
        Ok(())
    }
}

static LOCAL_VERIFIED_COPY_PERSISTENCE: LocalVerifiedCopyPersistence = LocalVerifiedCopyPersistence;

#[derive(Debug, Default)]
pub struct VerifiedCopyCancellation(AtomicBool);

impl VerifiedCopyCancellation {
    pub fn request_stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn is_requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedCopyEvent {
    CopyStarted,
    BytesCopied { copied_bytes: u64 },
    CopyPaused { copied_bytes: u64 },
    CopyCompleted { copied_bytes: u64 },
}

pub trait VerifiedCopyEventSink {
    fn emit(&mut self, event: VerifiedCopyEvent);
}

impl<'a> VerifyRequest<'a> {
    pub fn new(source: impl Into<PathBuf>, recovery_secret: &'a RecoverySecret) -> Self {
        Self {
            source: source.into(),
            recovery_secret,
            event_sink: None,
        }
    }

    pub fn with_event_sink(mut self, event_sink: &'a mut dyn BundleEventSink) -> Self {
        self.event_sink = Some(event_sink);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleVerification {
    pub summary: AuthenticatedBundleSummary,
    pub authenticated_chunks: u64,
    pub authenticated_bytes: u64,
    bundle_identity: String,
}

impl BundleVerification {
    pub fn bundle_identity(&self) -> &str {
        &self.bundle_identity
    }

    pub fn machine_json_result(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "command": "verify",
            "status": "success",
            "data": {
                "format_version": self.summary.format_version,
                "cryptographic_suite": self.summary.cryptographic_suite,
                "logical_size": self.summary.logical_size,
                "included_items": self.summary.included_items,
                "changed_items": self.summary.changed_items,
                "unsupported_items": self.summary.unsupported_items,
                "unverified_items": self.summary.unverified_items,
                "authenticated_chunks": self.authenticated_chunks,
                "authenticated_bytes": self.authenticated_bytes,
            },
            "warnings": [],
            "errors": [],
        })
        .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCopyReport {
    source_digest: String,
    destination_digest: String,
    source_bundle_identity: String,
    destination_bundle_identity: String,
    receipt: VerifiedCopyReceipt,
    durability: VerifiedCopyDurability,
    warnings: Vec<String>,
}

impl VerifiedCopyReport {
    pub fn is_verified(&self) -> bool {
        self.source_digest == self.destination_digest
            && self.source_bundle_identity == self.destination_bundle_identity
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub fn destination_digest(&self) -> &str {
        &self.destination_digest
    }

    pub fn source_bundle_identity(&self) -> &str {
        &self.source_bundle_identity
    }

    pub fn destination_bundle_identity(&self) -> &str {
        &self.destination_bundle_identity
    }

    pub fn receipt(&self) -> &VerifiedCopyReceipt {
        &self.receipt
    }

    pub fn durability(&self) -> VerifiedCopyDurability {
        self.durability
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn human_summary(&self) -> &'static str {
        "Verified Copy created."
    }

    pub fn machine_json_result(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "command": "copy",
            "status": "success",
            "data": {
                "verified": self.is_verified(),
                "source_bundle_identity": self.source_bundle_identity,
                "destination_bundle_identity": self.destination_bundle_identity,
                "whole_file_digest": self.destination_digest,
                "verified_at_unix_seconds": self.receipt.verified_at_unix_seconds,
                "durability": match self.durability {
                    VerifiedCopyDurability::Durable => "durable",
                    VerifiedCopyDurability::Weaker => "weaker",
                },
            },
            "warnings": self.warnings,
            "errors": [],
        })
        .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCopyReceipt {
    source_bundle_identity: String,
    destination_bundle_identity: String,
    whole_file_digest: String,
    destination_evidence_identity: String,
    durability: VerifiedCopyDurability,
    verified_at_unix_seconds: u64,
}

impl VerifiedCopyReceipt {
    pub fn schema_version(&self) -> u32 {
        1
    }

    pub fn operation(&self) -> &'static str {
        "verified-copy"
    }

    pub fn result(&self) -> &'static str {
        "verified"
    }

    pub fn source_bundle_identity(&self) -> &str {
        &self.source_bundle_identity
    }

    pub fn destination_bundle_identity(&self) -> &str {
        &self.destination_bundle_identity
    }

    pub fn whole_file_digest(&self) -> &str {
        &self.whole_file_digest
    }

    pub fn destination_evidence_identity(&self) -> &str {
        &self.destination_evidence_identity
    }

    pub fn durability(&self) -> VerifiedCopyDurability {
        self.durability
    }

    pub fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }

    pub fn machine_json_result(&self) -> String {
        serde_json::json!({
            "schema_version": self.schema_version(),
            "operation": self.operation(),
            "result": self.result(),
            "source_bundle_identity": self.source_bundle_identity,
            "destination_bundle_identity": self.destination_bundle_identity,
            "whole_file_digest": self.whole_file_digest,
            "destination_evidence_identity": self.destination_evidence_identity,
            "durability": verified_copy_durability_name(self.durability),
            "verified_at_unix_seconds": self.verified_at_unix_seconds,
        })
        .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum BundleEvent {
    PackStarted,
    CheckpointWritten {
        captured_items: u64,
        captured_bytes: u64,
    },
    CheckpointPromotionAdvanced {
        step: PackCheckpointPromotionStep,
    },
    ItemCaptured {
        item_id: String,
        bytes: u64,
        outcome: String,
    },
    PackCompleted {
        included_items: u64,
        changed_items: u64,
        unsupported_items: u64,
        unverified_items: u64,
    },
    VerificationStarted,
    ChunkVerified {
        sequence: u64,
        bytes: u64,
    },
    VerificationCompleted {
        authenticated_chunks: u64,
        authenticated_bytes: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackCheckpointPromotionStep {
    PromotionJournalWritten,
    SavedPartialRetained,
    SavedCheckpointRetained,
    ResumedPartialActivated,
    ResumedCheckpointActivated,
    SupersededPartialRemoved,
    SupersededCheckpointRemoved,
    PromotionJournalRemoved,
}

impl BundleEvent {
    pub fn machine_json_line(&self) -> String {
        let mut value =
            serde_json::to_value(self).expect("BundleEvent serialization is infallible");
        value
            .as_object_mut()
            .expect("BundleEvent serializes as an object")
            .insert("schema_version".to_owned(), serde_json::json!(1));
        value.to_string()
    }
}

pub trait BundleEventSink {
    fn emit(&mut self, event: BundleEvent);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSourceObservation {
    pub length: u64,
    pub identity: u64,
    pub change_token: u64,
    pub posix_mode: Option<u32>,
}

impl BundleSourceObservation {
    pub fn new(length: u64, identity: u64, change_token: u64) -> Self {
        Self {
            length,
            identity,
            change_token,
            posix_mode: None,
        }
    }

    pub fn with_posix_mode(mut self, posix_mode: u32) -> Self {
        self.posix_mode = Some(posix_mode & 0o7777);
        self
    }
}

pub trait BundleSource {
    fn observe(&self, path: &Path) -> io::Result<BundleSourceObservation>;
    fn open(&self, path: &Path) -> io::Result<Box<dyn Read>>;
    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        fs::read_link(path)
    }
    fn posix_mode(&self, path: &Path) -> io::Result<Option<u32>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Ok(Some(
                fs::symlink_metadata(path)?.permissions().mode() & 0o7777,
            ))
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(None)
        }
    }
    fn extended_attributes(
        &self,
        path: &Path,
        no_follow: bool,
    ) -> io::Result<Vec<ExtendedAttribute>> {
        crate::platform_metadata::read_extended_attributes(path, no_follow)
    }
    fn access_control(&self, path: &Path, no_follow: bool) -> io::Result<Option<String>> {
        crate::platform_metadata::read_access_control(path, no_follow)
    }
}

#[derive(Debug, Default)]
pub struct LocalBundleSource;

impl BundleSource for LocalBundleSource {
    fn observe(&self, path: &Path) -> io::Result<BundleSourceObservation> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "selected Migration Item is no longer a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let identity = metadata.dev().rotate_left(17) ^ metadata.ino();
            let change_token = (metadata.mtime() as u64).rotate_left(29)
                ^ metadata.mtime_nsec() as u64
                ^ metadata.len();
            use std::os::unix::fs::PermissionsExt;
            Ok(
                BundleSourceObservation::new(metadata.len(), identity, change_token)
                    .with_posix_mode(metadata.permissions().mode()),
            )
        }
        #[cfg(not(unix))]
        {
            use std::time::UNIX_EPOCH;
            let change_token = metadata
                .modified()?
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            Ok(BundleSourceObservation::new(
                metadata.len(),
                metadata.len(),
                change_token,
            ))
        }
    }

    fn open(&self, path: &Path) -> io::Result<Box<dyn Read>> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            Ok(Box::new(file))
        }
        #[cfg(not(unix))]
        {
            Ok(Box::new(fs::File::open(path)?))
        }
    }
}

pub trait DestinationCapacity {
    fn available_bytes(&self, destination: &Path) -> io::Result<u64>;
}

#[derive(Debug, Default)]
pub struct LocalDestinationCapacity;

impl DestinationCapacity for LocalDestinationCapacity {
    fn available_bytes(&self, destination: &Path) -> io::Result<u64> {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::mem::MaybeUninit;
            use std::os::unix::ffi::OsStrExt;

            let directory = destination.parent().unwrap_or_else(|| Path::new("."));
            let path = CString::new(directory.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "destination path contains a null byte",
                )
            })?;
            let mut statistics = MaybeUninit::<libc::statvfs>::uninit();
            // SAFETY: `path` is a live null-terminated string and `statistics` points to
            // writable storage for one `statvfs` value. A zero return initializes it.
            if unsafe { libc::statvfs(path.as_ptr(), statistics.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the successful `statvfs` call above initialized the value.
            let statistics = unsafe { statistics.assume_init() };
            (statistics.f_bavail as u64)
                .checked_mul(statistics.f_frsize)
                .ok_or_else(|| io::Error::other("available destination capacity overflowed"))
        }
        #[cfg(not(unix))]
        {
            let _ = destination;
            Ok(u64::MAX)
        }
    }
}

#[derive(Debug)]
pub struct BundleEngine<S = LocalBundleSource, C = LocalDestinationCapacity> {
    source: S,
    capacity: C,
}

impl BundleEngine<LocalBundleSource, LocalDestinationCapacity> {
    pub fn local() -> Self {
        Self {
            source: LocalBundleSource,
            capacity: LocalDestinationCapacity,
        }
    }
}

impl<S> BundleEngine<S, LocalDestinationCapacity> {
    pub fn with_source(source: S) -> Self {
        Self {
            source,
            capacity: LocalDestinationCapacity,
        }
    }
}

impl<S, C> BundleEngine<S, C> {
    pub fn with_adapters(source: S, capacity: C) -> Self {
        Self { source, capacity }
    }
}

impl<S: BundleSource, C: DestinationCapacity> BundleEngine<S, C> {
    pub fn pack(&self, mut request: PackRequest<'_>) -> Result<PackReport, CoreError> {
        validate_pack_request(&request)?;
        let mut event_sink = request.event_sink.take();
        let persistence = request.persistence;
        let plan = request.plan;
        let destination = request.destination;
        let partial = partial_path(&destination);
        let resumed_partial = resumed_partial_path(&partial);
        if let Some(recovery) = request.resume {
            reconcile_interrupted_pack_promotion(
                plan,
                &partial,
                recovery,
                &self.source,
                persistence,
                &mut event_sink,
            )?;
        }
        if let Some(recovery) = request.resume
            && resumed_partial.exists()
        {
            let saved = authenticate_pack_checkpoint(plan, &partial, recovery, &self.source)?;
            let advanced =
                authenticate_pack_checkpoint(plan, &resumed_partial, recovery, &self.source)?;
            if advanced.checkpoint.captured_items < saved.checkpoint.captured_items {
                return Err(invalid_bundle(
                    "interrupted resumed checkpoint is older than saved progress; restart required while preserving all artifacts",
                ));
            }
            let saved_identity = pack_progress_identity(&saved, &partial)?;
            let advanced_identity = pack_progress_identity(&advanced, &resumed_partial)?;
            let journal_identity = write_pack_promotion_journal(
                plan,
                &partial,
                saved_identity,
                advanced_identity,
                &advanced,
                persistence,
                &mut event_sink,
            )?;
            promote_paused_pack(
                &partial,
                &resumed_partial,
                &saved_identity,
                &advanced_identity,
                journal_identity,
                persistence,
                &mut event_sink,
            )?;
        }
        let resume = request
            .resume
            .map(|recovery| authenticate_pack_checkpoint(plan, &partial, recovery, &self.source))
            .transpose()?;
        let resumed_partial_identity = resume
            .as_ref()
            .map(|progress| {
                progress.file.metadata().map_err(|source| CoreError::Io {
                    action: "identify authenticated partial Bundle",
                    path: partial.clone(),
                    source,
                })
            })
            .transpose()?;
        let resumed_checkpoint_identity = resume
            .as_ref()
            .map(|progress| progress.checkpoint_identity.clone());
        if resume.is_none() && partial.exists() {
            return Err(CoreError::DestinationAlreadyExists(partial));
        }
        let output_partial = if resume.is_some() {
            resumed_partial
        } else {
            partial.clone()
        };
        if output_partial.exists() {
            return Err(CoreError::DestinationAlreadyExists(output_partial));
        }

        let data_encryption_key = random_secret()?;
        let recovery_context = request.resume.or(request.recovery);
        let vaultwarden_secret = RecoverySecret {
            method: RecoveryMethod::Vaultwarden,
            bytes: match recovery_context {
                Some(recovery) => Zeroizing::new(*recovery.0.vaultwarden_recovery_secret().bytes),
                None => random_secret()?,
            },
        };
        let offline_secret = RecoverySecret {
            method: RecoveryMethod::Offline,
            bytes: match recovery_context {
                Some(recovery) => Zeroizing::new(*recovery.0.offline_recovery_key().bytes),
                None => random_secret()?,
            },
        };
        let bundle_identifier = random_array()?;
        let hkdf_salt = random_array()?;
        let nonce_prefix = random_array()?;
        let header = encode_header(
            &data_encryption_key,
            [&vaultwarden_secret, &offline_secret],
            &bundle_identifier,
            &hkdf_salt,
            &nonce_prefix,
        )?;
        let keys = derive_bundle_keys(&data_encryption_key, &hkdf_salt, &bundle_identifier)?;
        let context = RecordContext {
            header_hash: *blake3::hash(&header).as_bytes(),
            bundle_identifier,
            nonce_prefix,
        };

        let mut created_partial = None;
        let write_result = write_bundle(
            plan,
            &self.source,
            &self.capacity,
            &output_partial,
            &destination,
            &header,
            &keys,
            &context,
            &mut event_sink,
            request.cancellation,
            resume,
            &mut created_partial,
            persistence,
        );
        if write_result.is_err()
            && created_partial.as_ref().is_some_and(|created| {
                fs::symlink_metadata(&output_partial)
                    .ok()
                    .is_some_and(|current| same_pack_file(created, &current))
            })
        {
            let _ = fs::remove_file(&output_partial);
        }
        let state = write_result?;
        if let (Some(recovery), PackState::Paused) = (request.resume, state) {
            let advanced =
                authenticate_pack_checkpoint(plan, &output_partial, recovery, &self.source)?;
            let saved_identity = PackProgressIdentity {
                partial: pack_file_identity(
                    resumed_partial_identity
                        .as_ref()
                        .expect("Resume authenticated partial identity"),
                )?,
                checkpoint: pack_file_identity(
                    resumed_checkpoint_identity
                        .as_ref()
                        .expect("Resume authenticated checkpoint identity"),
                )?,
            };
            let advanced_identity = pack_progress_identity(&advanced, &output_partial)?;
            let journal_identity = write_pack_promotion_journal(
                plan,
                &partial,
                saved_identity,
                advanced_identity,
                &advanced,
                persistence,
                &mut event_sink,
            )?;
            promote_paused_pack(
                &partial,
                &output_partial,
                &saved_identity,
                &advanced_identity,
                journal_identity,
                persistence,
                &mut event_sink,
            )?;
        }
        if request.resume.is_some() && state == PackState::Complete {
            if resumed_partial_identity.as_ref().is_some_and(|expected| {
                fs::symlink_metadata(&partial)
                    .ok()
                    .is_some_and(|current| same_pack_file(expected, &current))
            }) {
                let _ = fs::remove_file(&partial);
            }
            let checkpoint = pack_checkpoint_path(&partial);
            if resumed_checkpoint_identity
                .as_ref()
                .is_some_and(|expected| {
                    fs::symlink_metadata(&checkpoint)
                        .ok()
                        .is_some_and(|current| same_pack_file(expected, &current))
                })
            {
                let _ = fs::remove_file(checkpoint);
            }
        }

        Ok(PackReport {
            state,
            recovery: PackRecoveryContext(SealedBundle {
                vaultwarden_recovery_secret: vaultwarden_secret,
                offline_recovery_key: offline_secret,
            }),
        })
    }

    pub fn inspect(
        &self,
        request: InspectRequest<'_>,
    ) -> Result<AuthenticatedBundleSummary, CoreError> {
        let mut event_sink = None;
        let mut content_sink = None;
        Ok(open_bundle(
            &request.source,
            request.recovery_secret,
            false,
            &mut event_sink,
            &mut content_sink,
        )?
        .summary)
    }

    pub fn verify(&self, mut request: VerifyRequest<'_>) -> Result<BundleVerification, CoreError> {
        let mut event_sink = request.event_sink.take();
        let mut content_sink = None;
        let opened = open_bundle(
            &request.source,
            request.recovery_secret,
            true,
            &mut event_sink,
            &mut content_sink,
        )?;
        Ok(BundleVerification {
            summary: opened.summary,
            authenticated_chunks: opened.authenticated_chunks,
            authenticated_bytes: opened.authenticated_bytes,
            bundle_identity: bundle_identity_hex(&opened.bundle_identifier),
        })
    }

    pub fn copy_verified(
        &self,
        mut request: VerifiedCopyRequest<'_>,
    ) -> Result<VerifiedCopyReport, CoreError> {
        if request
            .destination
            .extension()
            .and_then(|value| value.to_str())
            != Some("iniza")
        {
            return Err(invalid_bundle(
                "Verified Copy destination must end with .iniza",
            ));
        }
        let mut event_sink = request.event_sink.take();
        prepare_verified_copy_transition(
            request.persistence,
            VerifiedCopyPersistenceTransition::ReadSource,
            "read or materialize source Bundle for Verified Copy",
            &request.source,
        )?;
        let mut source_file = open_bundle_file(&request.source)?;
        let mut events = None;
        let mut content_sink = None;
        let source = open_bundle_from(
            &mut source_file,
            &request.source,
            request.recovery_secret,
            true,
            &mut events,
            &mut content_sink,
            false,
        )?;
        if request.destination.exists() {
            return Err(CoreError::DestinationAlreadyExists(request.destination));
        }
        let partial = partial_path(&request.destination);
        let replaced_partial_identity = if partial.exists() {
            if !request.replace_matching_partial {
                return Err(CoreError::DestinationAlreadyExists(partial));
            }
            Some(require_matching_copy_prefix(
                &mut source_file,
                &request.source,
                &partial,
            )?)
        } else {
            None
        };
        let output_partial = if replaced_partial_identity.is_some() {
            resumed_partial_path(&partial)
        } else {
            partial.clone()
        };
        if output_partial.exists() {
            return Err(CoreError::DestinationAlreadyExists(output_partial));
        }
        emit_verified_copy_event(&mut event_sink, VerifiedCopyEvent::CopyStarted);
        source_file
            .seek(SeekFrom::Start(0))
            .map_err(|source_error| CoreError::Io {
                action: "rewind authenticated source Bundle for Verified Copy",
                path: request.source.clone(),
                source: source_error,
            })?;
        prepare_verified_copy_transition(
            request.persistence,
            VerifiedCopyPersistenceTransition::CreatePartial,
            "create partial Verified Copy",
            &output_partial,
        )?;
        let mut output =
            create_private_pack_file(&output_partial).map_err(|source_error| CoreError::Io {
                action: "create partial Verified Copy",
                path: output_partial.clone(),
                source: source_error,
            })?;
        let mut buffer = [0_u8; 64 * 1024];
        let mut copied_bytes = 0_u64;
        loop {
            let read = source_file
                .read(&mut buffer)
                .map_err(|source_error| CoreError::Io {
                    action: "read authenticated source Bundle for Verified Copy",
                    path: request.source.clone(),
                    source: source_error,
                })?;
            if read == 0 {
                break;
            }
            prepare_verified_copy_transition(
                request.persistence,
                VerifiedCopyPersistenceTransition::WritePartial,
                "write partial Verified Copy",
                &output_partial,
            )?;
            output
                .write_all(&buffer[..read])
                .map_err(|source_error| CoreError::Io {
                    action: "write partial Verified Copy",
                    path: output_partial.clone(),
                    source: source_error,
                })?;
            copied_bytes = copied_bytes
                .checked_add(read as u64)
                .ok_or_else(|| invalid_bundle("Verified Copy byte count overflowed"))?;
            emit_verified_copy_event(
                &mut event_sink,
                VerifiedCopyEvent::BytesCopied { copied_bytes },
            );
            if request
                .cancellation
                .is_some_and(VerifiedCopyCancellation::is_requested)
            {
                prepare_verified_copy_transition(
                    request.persistence,
                    VerifiedCopyPersistenceTransition::SynchronizePartial,
                    "synchronize interrupted partial Verified Copy",
                    &output_partial,
                )?;
                output.sync_all().map_err(|source_error| CoreError::Io {
                    action: "synchronize interrupted partial Verified Copy",
                    path: output_partial.clone(),
                    source: source_error,
                })?;
                emit_verified_copy_event(
                    &mut event_sink,
                    VerifiedCopyEvent::CopyPaused { copied_bytes },
                );
                return Err(CoreError::CopyInterrupted(output_partial));
            }
        }
        prepare_verified_copy_transition(
            request.persistence,
            VerifiedCopyPersistenceTransition::SynchronizePartial,
            "synchronize partial Verified Copy",
            &output_partial,
        )?;
        output.sync_all().map_err(|source_error| CoreError::Io {
            action: "synchronize partial Verified Copy",
            path: output_partial.clone(),
            source: source_error,
        })?;
        drop(output);

        prepare_verified_copy_transition(
            request.persistence,
            VerifiedCopyPersistenceTransition::AuthenticatePartial,
            "authenticate partial Verified Copy",
            &output_partial,
        )?;
        let mut copied_file = open_bundle_file(&output_partial)?;
        let copied = open_bundle_from(
            &mut copied_file,
            &output_partial,
            request.recovery_secret,
            true,
            &mut events,
            &mut content_sink,
            true,
        )?;
        require_matching_verified_copy(&source, &copied)?;

        let parent = request
            .destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory =
            crate::restore_fs::RestoreDirectory::open_ambient(parent).map_err(|source_error| {
                CoreError::Io {
                    action: "open Verified Copy destination directory",
                    path: parent.to_path_buf(),
                    source: source_error,
                }
            })?;
        prepare_verified_copy_transition(
            request.persistence,
            VerifiedCopyPersistenceTransition::PublishCompleted,
            "publish Verified Copy without overwrite",
            &request.destination,
        )?;
        directory
            .exclusive_rename(
                Path::new(
                    output_partial
                        .file_name()
                        .expect("partial Verified Copy name"),
                ),
                &directory,
                Path::new(
                    request
                        .destination
                        .file_name()
                        .expect("completed Verified Copy name"),
                ),
            )
            .map_err(|source_error| {
                if source_error.kind() == io::ErrorKind::AlreadyExists {
                    CoreError::DestinationAlreadyExists(request.destination.clone())
                } else {
                    CoreError::Io {
                        action: "publish Verified Copy without overwrite",
                        path: request.destination.clone(),
                        source: source_error,
                    }
                }
            })?;
        prepare_verified_copy_transition(
            request.persistence,
            VerifiedCopyPersistenceTransition::SynchronizeDirectory,
            "synchronize Verified Copy destination directory",
            parent,
        )?;
        directory.sync().map_err(|source_error| CoreError::Io {
            action: "synchronize Verified Copy destination directory",
            path: parent.to_path_buf(),
            source: source_error,
        })?;

        prepare_verified_copy_transition(
            request.persistence,
            VerifiedCopyPersistenceTransition::ReopenCompleted,
            "reopen completed Verified Copy",
            &request.destination,
        )?;
        let mut destination_file = open_bundle_file(&request.destination)?;
        let destination = open_bundle_from(
            &mut destination_file,
            &request.destination,
            request.recovery_secret,
            true,
            &mut events,
            &mut content_sink,
            false,
        )?;
        require_matching_verified_copy(&source, &destination)?;
        if replaced_partial_identity.as_ref().is_some_and(|expected| {
            fs::symlink_metadata(&partial)
                .ok()
                .is_some_and(|current| same_pack_file(expected, &current))
        }) {
            let _ = directory.remove_file(Path::new(
                partial
                    .file_name()
                    .expect("saved partial Verified Copy name"),
            ));
            let _ = directory.sync();
        }
        let source_digest = bundle_hash_hex(&source.bundle_hash);
        let destination_digest = bundle_hash_hex(&destination.bundle_hash);
        let source_bundle_identity = bundle_identity_hex(&source.bundle_identifier);
        let destination_bundle_identity = bundle_identity_hex(&destination.bundle_identifier);
        let durability = request.persistence.durability();
        let receipt = VerifiedCopyReceipt {
            source_bundle_identity: source_bundle_identity.clone(),
            destination_bundle_identity: destination_bundle_identity.clone(),
            whole_file_digest: destination_digest.clone(),
            destination_evidence_identity: verified_copy_destination_evidence_identity(
                &request.destination,
            )?,
            durability,
            verified_at_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| invalid_bundle("system clock is before the Unix epoch"))?
                .as_secs(),
        };
        let warnings = match durability {
            VerifiedCopyDurability::Durable => Vec::new(),
            VerifiedCopyDurability::Weaker => vec![
                "Verified Copy completed with weaker filesystem durability guarantees".to_owned(),
            ],
        };
        emit_verified_copy_event(
            &mut event_sink,
            VerifiedCopyEvent::CopyCompleted { copied_bytes },
        );
        Ok(VerifiedCopyReport {
            source_digest,
            destination_digest,
            source_bundle_identity,
            destination_bundle_identity,
            receipt,
            durability,
            warnings,
        })
    }

    pub fn advise_failed_pack(
        &self,
        plan: &Plan,
        destination: &Path,
        recovery: &PackRecoveryContext,
    ) -> PackRecoveryAdvice {
        if destination.exists()
            && self
                .verify(VerifyRequest::new(
                    destination,
                    recovery.offline_recovery_key(),
                ))
                .is_ok()
        {
            return PackRecoveryAdvice::VerifyPublishedBundle;
        }
        let partial = partial_path(destination);
        if authenticate_pack_checkpoint(plan, &partial, recovery, &self.source).is_ok() {
            return PackRecoveryAdvice::ResumeAfterRevalidation;
        }
        let resumed = resumed_partial_path(&partial);
        let previous = previous_partial_path(&partial);
        let promotion_artifact_exists = [
            pack_promotion_journal_path(&partial),
            previous.clone(),
            pack_checkpoint_path(&previous),
        ]
        .iter()
        .any(|path| pack_artifact_exists(path).unwrap_or(true));
        if promotion_artifact_exists {
            return PackRecoveryAdvice::ResumeAfterRevalidation;
        }
        let incomplete_artifact_exists = [
            partial.clone(),
            pack_checkpoint_path(&partial),
            resumed.clone(),
            pack_checkpoint_path(&resumed),
        ]
        .iter()
        .any(|path| pack_artifact_exists(path).unwrap_or(true));
        if incomplete_artifact_exists || destination.exists() {
            PackRecoveryAdvice::RestartAtNewDestination
        } else {
            PackRecoveryAdvice::Retry
        }
    }
}

fn validate_pack_request(request: &PackRequest<'_>) -> Result<(), CoreError> {
    if request.resume.is_some() && request.recovery.is_some() {
        return Err(invalid_bundle(
            "Pack Resume already specifies its recovery context",
        ));
    }
    if !request.plan.is_directory_plan() {
        return Err(CoreError::InvalidPlan(
            "Bundle Pack requires a directory Plan".to_owned(),
        ));
    }
    if request.plan.approval_state()? != PlanApprovalState::Approved {
        return Err(CoreError::InvalidPlan(
            "Bundle Pack requires an approved, non-stale Plan".to_owned(),
        ));
    }
    if request
        .destination
        .extension()
        .and_then(|value| value.to_str())
        != Some("iniza")
    {
        return Err(invalid_bundle("Bundle output must end with .iniza"));
    }
    if request.destination.exists() {
        return Err(CoreError::DestinationAlreadyExists(
            request.destination.clone(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_bundle(
    plan: &Plan,
    source_adapter: &impl BundleSource,
    capacity: &impl DestinationCapacity,
    partial: &Path,
    destination: &Path,
    header: &[u8],
    keys: &BundleKeys,
    context: &RecordContext,
    events: &mut Option<&mut dyn BundleEventSink>,
    cancellation: Option<&PackCancellation>,
    resume: Option<AuthenticatedPackCheckpoint>,
    created_partial: &mut Option<fs::Metadata>,
    persistence: &dyn PackPersistence,
) -> Result<PackState, CoreError> {
    emit_event(events, BundleEvent::PackStarted);
    let estimated_required = plan
        .estimated_logical_size()
        .checked_add(HEADER_LENGTH as u64)
        .and_then(|size| size.checked_add((plan.items().len() as u64).saturating_mul(512)))
        .and_then(|size| size.checked_add(MAX_PLAINTEXT_CHUNK as u64))
        .ok_or_else(|| invalid_bundle("Bundle capacity estimate overflowed"))?;
    ensure_capacity(capacity, destination, estimated_required)?;
    persistence
        .prepare_transition(PackPersistenceTransition::CreatePartialBundle)
        .map_err(|source| CoreError::Io {
            action: "prepare partial Bundle creation",
            path: partial.to_path_buf(),
            source,
        })?;
    let output = create_private_pack_file(partial).map_err(|source| CoreError::Io {
        action: "create partial Bundle",
        path: partial.to_path_buf(),
        source,
    })?;
    *created_partial = Some(output.metadata().map_err(|source| CoreError::Io {
        action: "identify created partial Bundle",
        path: partial.to_path_buf(),
        source,
    })?);
    let mut writer = StreamWriter::new(
        output,
        capacity,
        destination,
        persistence,
        PackPersistenceTransition::WritePartialBundle,
    );
    writer.write_hashed(header, partial)?;
    let root = plan
        .approved_roots()
        .first()
        .ok_or_else(|| CoreError::InvalidPlan("Plan has no approved root".to_owned()))?;
    let mut sequence = 0_u64;
    let mut index = Vec::new();
    let mut manifest_items = Vec::with_capacity(plan.items().len());
    let mut logical_size = 0_u64;
    let mut included_items = 0_u64;
    let mut changed_items = 0_u64;
    let mut unsupported_items = 0_u64;
    let mut unverified_items = 0_u64;
    let mut source_observations = BTreeMap::new();

    if let Some(resume) = resume {
        let checkpoint = rekey_pack_prefix(resume, &mut writer, partial, keys, context)?;
        sequence = checkpoint.index.len() as u64;
        index = checkpoint.index;
        manifest_items = checkpoint.manifest_items;
        logical_size = checkpoint.captured_bytes;
        included_items = checkpoint.included_items;
        changed_items = checkpoint.changed_items;
        unsupported_items = checkpoint.unsupported_items;
        unverified_items = checkpoint.unverified_items;
        source_observations = checkpoint.source_observations;
    }

    let first_uncaptured_item = manifest_items.len();
    for (item_ordinal, item) in plan.items().iter().enumerate().skip(first_uncaptured_item) {
        let item_ordinal = u32::try_from(item_ordinal)
            .map_err(|_| invalid_bundle("Bundle contains too many Migration Items"))?;
        let mut chunk_sequences = Vec::new();
        let mut content_hash = None;
        let mut posix_mode = None;
        let mut symlink_target = None;
        if item.kind == MigrationItemKind::Directory && item.disposition == Disposition::Included {
            posix_mode = source_adapter
                .posix_mode(&root.join(&item.relative_path))
                .ok()
                .flatten();
        }
        let outcome = if item.kind == MigrationItemKind::Special {
            unsupported_items += 1;
            CaptureOutcome::Unsupported
        } else if item.disposition == Disposition::Included {
            included_items += 1;
            match item.kind {
                MigrationItemKind::Directory => CaptureOutcome::Included,
                MigrationItemKind::SymbolicLink => {
                    match capture_symbolic_link(source_adapter, &root.join(&item.relative_path)) {
                        Some(target) => {
                            symlink_target = Some(target.to_string_lossy().into_owned());
                            CaptureOutcome::Included
                        }
                        None => {
                            included_items -= 1;
                            unverified_items += 1;
                            CaptureOutcome::Unverified
                        }
                    }
                }
                MigrationItemKind::RegularFile => {
                    let captured = capture_regular_file(
                        source_adapter,
                        &root.join(&item.relative_path),
                        item_ordinal,
                        &mut sequence,
                        &mut writer,
                        partial,
                        keys,
                        context,
                        &mut index,
                    )?;
                    source_observations.insert(item_ordinal, captured.observation);
                    if captured.changed {
                        changed_items += 1;
                    }
                    if captured.verified {
                        logical_size = logical_size
                            .checked_add(captured.logical_size)
                            .ok_or_else(|| invalid_bundle("Bundle logical size overflowed"))?;
                        chunk_sequences = captured.chunk_sequences;
                        content_hash = captured.content_hash;
                        posix_mode = captured.posix_mode;
                        if captured.changed {
                            CaptureOutcome::Changed
                        } else {
                            CaptureOutcome::Included
                        }
                    } else {
                        unverified_items += 1;
                        CaptureOutcome::Unverified
                    }
                }
                MigrationItemKind::Special => unreachable!("handled above"),
                MigrationItemKind::Unknown => {
                    included_items -= 1;
                    unsupported_items += 1;
                    CaptureOutcome::Unsupported
                }
            }
        } else {
            match item.disposition {
                Disposition::Unsupported => {
                    unsupported_items += 1;
                    CaptureOutcome::Unsupported
                }
                Disposition::RequiresReview | Disposition::Unavailable => {
                    unverified_items += 1;
                    CaptureOutcome::Unverified
                }
                Disposition::Excluded => CaptureOutcome::Excluded,
                Disposition::Included => unreachable!("handled above"),
            }
        };
        let (extended_attributes, access_control_captured, access_control) =
            if matches!(outcome, CaptureOutcome::Included | CaptureOutcome::Changed) {
                capture_platform_metadata(
                    source_adapter,
                    &root.join(&item.relative_path),
                    item.kind == MigrationItemKind::SymbolicLink,
                )
            } else {
                (None, None, None)
            };
        manifest_items.push(ManifestItem {
            id: item.id.clone(),
            relative_path: item.relative_path.to_string_lossy().into_owned(),
            kind: format!("{:?}", item.kind),
            estimated_size: item.estimated_size,
            outcome,
            chunk_sequences,
            content_hash,
            posix_mode,
            symlink_target,
            extended_attributes,
            access_control_captured,
            access_control,
        });
        emit_event(
            events,
            BundleEvent::ItemCaptured {
                item_id: item.id.clone(),
                bytes: manifest_items
                    .last()
                    .map(|manifest_item| manifest_item.estimated_size)
                    .unwrap_or(0),
                outcome: capture_outcome_name(outcome).to_owned(),
            },
        );
        if cancellation.is_some_and(PackCancellation::is_requested) {
            write_pack_checkpoint(
                plan,
                &writer,
                partial,
                keys,
                context,
                sequence,
                manifest_items.len() as u64,
                logical_size,
                &manifest_items,
                &index,
                [
                    included_items,
                    changed_items,
                    unsupported_items,
                    unverified_items,
                ],
                source_adapter,
                &source_observations,
                persistence,
            )?;
            emit_event(
                events,
                BundleEvent::CheckpointWritten {
                    captured_items: manifest_items.len() as u64,
                    captured_bytes: logical_size,
                },
            );
            return Ok(PackState::Paused);
        }
    }

    let manifest = Manifest {
        marker: "MNF2".to_owned(),
        schema_version: 2,
        source_name: plan.source_name.clone(),
        plan_hash: plan.approval_hash()?,
        logical_size,
        included_items,
        changed_items,
        unsupported_items,
        unverified_items,
        items: manifest_items,
    };
    let manifest_plaintext = serde_json::to_vec(&manifest)
        .map_err(|error| invalid_bundle(format!("could not encode Bundle manifest: {error}")))?;
    if manifest_plaintext.len() > MAX_MANIFEST_PLAINTEXT {
        return Err(invalid_bundle("Bundle manifest exceeds its size limit"));
    }
    let manifest_sequence = sequence;
    writer.write_record(
        RECORD_MANIFEST,
        sequence,
        u32::MAX,
        u32::MAX,
        &keys.manifest,
        context,
        &manifest_plaintext,
        partial,
    )?;
    sequence = sequence
        .checked_add(1)
        .ok_or_else(|| invalid_bundle("Bundle record sequence overflowed"))?;

    let index_plaintext = encode_index(&index)?;
    let index_sequence = sequence;
    writer.write_record(
        RECORD_INDEX,
        sequence,
        u32::MAX,
        u32::MAX,
        &keys.index,
        context,
        &index_plaintext,
        partial,
    )?;
    sequence = sequence
        .checked_add(1)
        .ok_or_else(|| invalid_bundle("Bundle record sequence overflowed"))?;

    let prefix_hash = *writer.hasher.finalize().as_bytes();
    let completion = encode_completion(
        &prefix_hash,
        writer.record_count,
        manifest_sequence,
        index_sequence,
    );
    writer.write_record(
        RECORD_COMPLETION,
        sequence,
        u32::MAX,
        u32::MAX,
        &keys.completion,
        context,
        &completion,
        partial,
    )?;
    persistence
        .prepare_transition(PackPersistenceTransition::SynchronizeCompletedPartial)
        .map_err(|source| CoreError::Io {
            action: "prepare completed partial Bundle synchronization",
            path: partial.to_path_buf(),
            source,
        })?;
    writer.file.sync_all().map_err(|source| CoreError::Io {
        action: "synchronize completed partial Bundle",
        path: partial.to_path_buf(),
        source,
    })?;
    require_pack_file_identity(&writer.file, partial)?;
    persistence
        .prepare_transition(PackPersistenceTransition::PublishCompletedBundle)
        .map_err(|source| CoreError::Io {
            action: "prepare completed Bundle publication",
            path: destination.to_path_buf(),
            source,
        })?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory =
        crate::restore_fs::RestoreDirectory::open_ambient(parent).map_err(|source| {
            CoreError::Io {
                action: "open completed Bundle destination directory",
                path: parent.to_path_buf(),
                source,
            }
        })?;
    directory
        .exclusive_rename(
            Path::new(partial.file_name().expect("partial Bundle name")),
            &directory,
            Path::new(destination.file_name().expect("completed Bundle name")),
        )
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                CoreError::DestinationAlreadyExists(destination.to_path_buf())
            } else {
                CoreError::Io {
                    action: "publish completed Bundle without overwrite",
                    path: destination.to_path_buf(),
                    source,
                }
            }
        })?;
    persistence
        .prepare_transition(PackPersistenceTransition::SynchronizeCompletedBundleDirectory)
        .map_err(|source| CoreError::Io {
            action: "prepare completed Bundle directory synchronization",
            path: parent.to_path_buf(),
            source,
        })?;
    directory.sync().map_err(|source| CoreError::Io {
        action: "synchronize completed Bundle directory",
        path: parent.to_path_buf(),
        source,
    })?;
    emit_event(
        events,
        BundleEvent::PackCompleted {
            included_items,
            changed_items,
            unsupported_items,
            unverified_items,
        },
    );
    Ok(PackState::Complete)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackCheckpoint {
    schema_version: u32,
    plan_hash: String,
    partial_hash: String,
    partial_length: u64,
    next_sequence: u64,
    captured_items: u64,
    captured_bytes: u64,
    manifest_items: Vec<ManifestItem>,
    index: Vec<IndexEntry>,
    included_items: u64,
    changed_items: u64,
    unsupported_items: u64,
    unverified_items: u64,
    source_observations: BTreeMap<u32, Option<BundleSourceObservation>>,
}

struct AuthenticatedPackCheckpoint {
    file: fs::File,
    checkpoint_identity: fs::Metadata,
    checkpoint: PackCheckpoint,
    keys: BundleKeys,
    context: RecordContext,
    header: [u8; HEADER_LENGTH],
}

fn authenticate_pack_checkpoint(
    plan: &Plan,
    partial: &Path,
    recovery: &PackRecoveryContext,
    source_adapter: &impl BundleSource,
) -> Result<AuthenticatedPackCheckpoint, CoreError> {
    authenticate_pack_checkpoint_at(
        plan,
        partial,
        &pack_checkpoint_path(partial),
        recovery,
        source_adapter,
    )
}

fn authenticate_pack_checkpoint_at(
    plan: &Plan,
    partial: &Path,
    checkpoint_path: &Path,
    recovery: &PackRecoveryContext,
    source_adapter: &impl BundleSource,
) -> Result<AuthenticatedPackCheckpoint, CoreError> {
    let mut file = open_bundle_file(partial)?;
    let metadata = file.metadata().map_err(|source| CoreError::Io {
        action: "inspect partial Bundle for Resume",
        path: partial.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(invalid_bundle(
            "Pack Resume requires a regular partial Bundle",
        ));
    }
    let mut header = [0_u8; HEADER_LENGTH];
    file.read_exact(&mut header)
        .map_err(|_| invalid_bundle("partial Bundle header is truncated"))?;
    let opened = decode_header(&header, recovery.0.offline_recovery_key())?;
    let other = decode_header(&header, recovery.0.vaultwarden_recovery_secret())?;
    if opened.data_encryption_key != other.data_encryption_key {
        return Err(CoreError::AuthenticationFailed);
    }
    let keys = derive_bundle_keys(
        &opened.data_encryption_key,
        &opened.hkdf_salt,
        &opened.bundle_identifier,
    )?;
    let context = RecordContext {
        header_hash: *blake3::hash(&header).as_bytes(),
        bundle_identifier: opened.bundle_identifier,
        nonce_prefix: opened.nonce_prefix,
    };
    let mut bytes = Vec::new();
    let checkpoint_file = open_bundle_file(checkpoint_path)
        .map_err(|error| match error {
            CoreError::Io { ref source, .. } if source.kind() == io::ErrorKind::NotFound => {
                invalid_bundle("Pack checkpoint is missing; restart required at a new destination, preserving partial output")
            }
            other => other,
        })?;
    let checkpoint_identity = checkpoint_file.metadata().map_err(|source| CoreError::Io {
        action: "identify authenticated Pack checkpoint",
        path: checkpoint_path.to_path_buf(),
        source,
    })?;
    checkpoint_file
        .take(MAX_PACK_CHECKPOINT + 49)
        .read_to_end(&mut bytes)
        .map_err(|source| CoreError::Io {
            action: "read authenticated Pack checkpoint",
            path: checkpoint_path.to_path_buf(),
            source,
        })?;
    if bytes.len() < 48
        || bytes.len() as u64 > MAX_PACK_CHECKPOINT + 48
        || &bytes[..8] != b"IZ2PAUS1"
    {
        return Err(invalid_bundle(
            "Pack checkpoint is missing, oversized, or incompatible; restart required",
        ));
    }
    let nonce: [u8; 24] = bytes[8..32].try_into().expect("bounded checkpoint nonce");
    let plaintext = Zeroizing::new(decrypt(
        &keys.checkpoint,
        &nonce,
        &context.header_hash,
        &bytes[32..],
    )?);
    let checkpoint: PackCheckpoint = serde_json::from_slice(&plaintext)
        .map_err(|_| invalid_bundle("Pack checkpoint encoding is invalid"))?;
    let canonical = Zeroizing::new(
        serde_json::to_vec(&checkpoint)
            .map_err(|_| invalid_bundle("Pack checkpoint cannot be canonicalized"))?,
    );
    if *canonical != *plaintext
        || checkpoint.schema_version != 1
        || checkpoint.plan_hash != plan.approval_hash()?
        || checkpoint.partial_length != metadata.len()
        || checkpoint.captured_items != checkpoint.manifest_items.len() as u64
        || checkpoint.manifest_items.len() > plan.items().len()
    {
        return Err(invalid_bundle(
            "Pack checkpoint does not match the approved Plan or partial Bundle; restart required",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| CoreError::Io {
            action: "rewind authenticated partial Bundle",
            path: partial.to_path_buf(),
            source,
        })?;
    let mut prefix_hasher = blake3::Hasher::new();
    let mut remaining = checkpoint.partial_length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded partial Bundle hash buffer");
        let read = file
            .read(&mut buffer[..requested])
            .map_err(|source| CoreError::Io {
                action: "hash authenticated partial Bundle",
                path: partial.to_path_buf(),
                source,
            })?;
        if read == 0 {
            return Err(invalid_bundle(
                "Pack checkpoint partial Bundle is truncated; restart required",
            ));
        }
        prefix_hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    if prefix_hasher.finalize().to_hex().as_str() != checkpoint.partial_hash {
        return Err(invalid_bundle(
            "Pack checkpoint partial Bundle changed; restart required while preserving older progress",
        ));
    }
    file.seek(SeekFrom::Start(HEADER_LENGTH as u64))
        .map_err(|source| CoreError::Io {
            action: "position authenticated partial Bundle content",
            path: partial.to_path_buf(),
            source,
        })?;
    encode_index(&checkpoint.index)?;
    for (captured, planned) in checkpoint.manifest_items.iter().zip(plan.items()) {
        if captured.id != planned.id
            || captured.relative_path != planned.relative_path.to_string_lossy()
            || captured.kind != format!("{:?}", planned.kind)
        {
            return Err(invalid_bundle(
                "Pack checkpoint Migration Items do not match the approved Plan",
            ));
        }
    }
    let root = plan
        .approved_roots()
        .first()
        .ok_or_else(|| invalid_bundle("Pack Resume Plan has no root"))?;
    for (ordinal, item) in plan.items().iter().enumerate().filter(|(_, item)| {
        item.disposition == Disposition::Included && item.kind == MigrationItemKind::RegularFile
    }) {
        let expected = checkpoint
            .source_observations
            .get(&(ordinal as u32))
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                invalid_bundle("Pack Resume source identity was not verified; restart required")
            })?;
        if source_adapter
            .observe(&root.join(&item.relative_path))
            .ok()
            .as_ref()
            != Some(expected)
        {
            return Err(invalid_bundle(
                "Pack Resume source changed; review a fresh Plan and restart",
            ));
        }
    }
    Ok(AuthenticatedPackCheckpoint {
        file,
        checkpoint_identity,
        checkpoint,
        keys,
        context,
        header,
    })
}

fn rekey_pack_prefix(
    mut resume: AuthenticatedPackCheckpoint,
    writer: &mut StreamWriter<'_>,
    partial: &Path,
    keys: &BundleKeys,
    context: &RecordContext,
) -> Result<PackCheckpoint, CoreError> {
    let mut prefix_hasher = blake3::Hasher::new();
    prefix_hasher.update(&resume.header);
    let mut offset = HEADER_LENGTH as u64;
    let mut previous_sequence = None;
    let mut content_hashers = BTreeMap::<u32, blake3::Hasher>::new();
    let mut authenticated_bytes = 0_u64;
    let mut new_index = Vec::new();
    for (sequence, entry) in resume.checkpoint.index.iter().enumerate() {
        if entry.offset != offset {
            return Err(invalid_bundle("Pack checkpoint chunk offset is invalid"));
        }
        let mut raw_header = [0_u8; RECORD_HEADER_LENGTH];
        resume
            .file
            .read_exact(&mut raw_header)
            .map_err(|_| invalid_bundle("checkpointed Bundle chunk is truncated"))?;
        let record = decode_record_header(&raw_header)?;
        validate_record_limit(&record)?;
        if record.kind != RECORD_CONTENT
            || record.sequence != entry.sequence
            || record.item_ordinal != entry.item_ordinal
            || record.chunk_ordinal != entry.chunk_ordinal
            || record.plaintext_length != entry.plaintext_length
            || record.ciphertext_length != entry.ciphertext_length
            || previous_sequence.is_some_and(|previous| record.sequence <= previous)
            || record.sequence >= resume.checkpoint.next_sequence
        {
            return Err(invalid_bundle(
                "Pack checkpoint does not match its authenticated chunk",
            ));
        }
        previous_sequence = Some(record.sequence);
        let item = resume
            .checkpoint
            .manifest_items
            .get_mut(entry.item_ordinal as usize)
            .ok_or_else(|| {
                invalid_bundle("Pack checkpoint references an unknown Migration Item")
            })?;
        let expected_sequence = item
            .chunk_sequences
            .get_mut(entry.chunk_ordinal as usize)
            .ok_or_else(|| invalid_bundle("Pack checkpoint chunk order is invalid"))?;
        if *expected_sequence != record.sequence {
            return Err(invalid_bundle("Pack checkpoint chunk mapping is invalid"));
        }
        let mut ciphertext = vec![0_u8; record.ciphertext_length as usize];
        resume
            .file
            .read_exact(&mut ciphertext)
            .map_err(|_| invalid_bundle("checkpointed Bundle ciphertext is truncated"))?;
        let plaintext = decrypt_record(
            &record,
            &raw_header,
            &ciphertext,
            &resume.keys.content,
            &resume.context,
        )?;
        prefix_hasher.update(&raw_header);
        prefix_hasher.update(&ciphertext);
        offset += RECORD_HEADER_LENGTH as u64 + ciphertext.len() as u64;
        authenticated_bytes = authenticated_bytes
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| invalid_bundle("Pack checkpoint byte count overflowed"))?;
        content_hashers
            .entry(entry.item_ordinal)
            .or_default()
            .update(&plaintext);
        let new_offset = writer.offset;
        writer.write_record(
            RECORD_CONTENT,
            sequence as u64,
            entry.item_ordinal,
            entry.chunk_ordinal,
            &keys.content,
            context,
            &plaintext,
            partial,
        )?;
        *expected_sequence = sequence as u64;
        new_index.push(IndexEntry {
            sequence: sequence as u64,
            offset: new_offset,
            ..entry.clone()
        });
    }
    if offset != resume.checkpoint.partial_length
        || prefix_hasher.finalize().to_hex().as_str() != resume.checkpoint.partial_hash
        || authenticated_bytes != resume.checkpoint.captured_bytes
    {
        return Err(invalid_bundle(
            "checkpointed Bundle content changed; restart required",
        ));
    }
    for (ordinal, item) in resume.checkpoint.manifest_items.iter().enumerate() {
        if let Some(expected) = &item.content_hash {
            let actual = content_hashers
                .remove(&(ordinal as u32))
                .ok_or_else(|| invalid_bundle("Pack checkpoint is missing protected content"))?;
            if actual.finalize().to_hex().as_str() != expected {
                return Err(invalid_bundle(
                    "Pack checkpoint protected content does not authenticate",
                ));
            }
        }
    }
    resume.checkpoint.index = new_index;
    Ok(resume.checkpoint)
}

fn create_private_pack_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn same_pack_file(expected: &fs::Metadata, current: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        current.is_file() && expected.dev() == current.dev() && expected.ino() == current.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (expected, current);
        false
    }
}

fn require_pack_file_identity(file: &fs::File, path: &Path) -> Result<(), CoreError> {
    let expected = file.metadata().map_err(|source| CoreError::Io {
        action: "identify opened partial Bundle",
        path: path.to_path_buf(),
        source,
    })?;
    let current = fs::symlink_metadata(path).map_err(|source| CoreError::Io {
        action: "revalidate partial Bundle identity",
        path: path.to_path_buf(),
        source,
    })?;
    if !same_pack_file(&expected, &current) {
        return Err(invalid_bundle(
            "partial Bundle identity changed; restart required at a new destination, preserving existing artifacts",
        ));
    }
    Ok(())
}

fn pack_checkpoint_path(partial: &Path) -> PathBuf {
    let mut path = partial.as_os_str().to_os_string();
    path.push(".checkpoint");
    PathBuf::from(path)
}

fn resumed_partial_path(partial: &Path) -> PathBuf {
    let mut path = partial.as_os_str().to_os_string();
    path.push(".resume");
    PathBuf::from(path)
}

fn previous_partial_path(partial: &Path) -> PathBuf {
    let mut path = partial.as_os_str().to_os_string();
    path.push(".previous");
    PathBuf::from(path)
}

fn pack_promotion_journal_path(partial: &Path) -> PathBuf {
    let mut path = partial.as_os_str().to_os_string();
    path.push(".promotion");
    PathBuf::from(path)
}

fn pack_promotion_journal_staging_path(partial: &Path, nonce: &[u8; 24]) -> PathBuf {
    let mut path = partial.as_os_str().to_os_string();
    path.push(".promotion.pending-");
    path.push(blake3::hash(nonce).to_hex().as_str());
    PathBuf::from(path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackFileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackProgressIdentity {
    partial: PackFileIdentity,
    checkpoint: PackFileIdentity,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackPromotionJournal {
    schema_version: u32,
    plan_hash: String,
    saved: PackProgressIdentity,
    advanced: PackProgressIdentity,
}

fn pack_promotion_journal_aad(context: &RecordContext) -> Vec<u8> {
    let mut aad = b"INIZA-PACK-PROMOTION-V1".to_vec();
    aad.extend_from_slice(&context.header_hash);
    aad
}

fn write_pack_promotion_journal(
    plan: &Plan,
    partial: &Path,
    saved: PackProgressIdentity,
    advanced: PackProgressIdentity,
    advanced_progress: &AuthenticatedPackCheckpoint,
    persistence: &dyn PackPersistence,
    events: &mut Option<&mut dyn BundleEventSink>,
) -> Result<PackFileIdentity, CoreError> {
    let journal = PackPromotionJournal {
        schema_version: 1,
        plan_hash: plan.approval_hash()?,
        saved,
        advanced,
    };
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&journal)
            .map_err(|_| invalid_bundle("Pack promotion journal cannot be encoded"))?,
    );
    if plaintext.len() as u64 > MAX_PACK_PROMOTION_JOURNAL {
        return Err(invalid_bundle(
            "Pack promotion journal exceeds its size limit",
        ));
    }
    let nonce = random_array::<24>()?;
    let ciphertext = encrypt(
        &advanced_progress.keys.checkpoint,
        &nonce,
        &pack_promotion_journal_aad(&advanced_progress.context),
        &plaintext,
    )?;
    let path = pack_promotion_journal_path(partial);
    let staging = pack_promotion_journal_staging_path(partial, &nonce);
    persistence
        .prepare_transition(PackPersistenceTransition::CreatePromotionJournal)
        .map_err(|source| CoreError::Io {
            action: "prepare authenticated Pack promotion journal creation",
            path: staging.clone(),
            source,
        })?;
    let mut output = create_private_pack_file(&staging).map_err(|source| CoreError::Io {
        action: "create authenticated Pack promotion journal",
        path: staging.clone(),
        source,
    })?;
    persistence
        .prepare_transition(PackPersistenceTransition::WritePromotionJournal)
        .map_err(|source| CoreError::Io {
            action: "prepare authenticated Pack promotion journal write",
            path: staging.clone(),
            source,
        })?;
    output
        .write_all(b"IZ2PROM1")
        .and_then(|()| output.write_all(&nonce))
        .and_then(|()| output.write_all(&ciphertext))
        .map_err(|source| CoreError::Io {
            action: "write authenticated Pack promotion journal",
            path: staging.clone(),
            source,
        })?;
    persistence
        .prepare_transition(PackPersistenceTransition::SynchronizePromotionJournal)
        .map_err(|source| CoreError::Io {
            action: "prepare authenticated Pack promotion journal synchronization",
            path: staging.clone(),
            source,
        })?;
    output.sync_all().map_err(|source| CoreError::Io {
        action: "synchronize authenticated Pack promotion journal",
        path: staging.clone(),
        source,
    })?;
    let identity = pack_file_identity(&output.metadata().map_err(|source| CoreError::Io {
        action: "identify authenticated Pack promotion journal",
        path: staging.clone(),
        source,
    })?)?;
    let parent = partial
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    persistence
        .prepare_transition(PackPersistenceTransition::SynchronizePromotionJournalDirectory)
        .map_err(|source| CoreError::Io {
            action: "prepare Pack promotion journal directory synchronization",
            path: parent.to_path_buf(),
            source,
        })?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| CoreError::Io {
            action: "synchronize Pack promotion journal directory",
            path: parent.to_path_buf(),
            source,
        })?;
    let directory =
        crate::restore_fs::RestoreDirectory::open_ambient(parent).map_err(|source| {
            CoreError::Io {
                action: "open Pack promotion journal directory",
                path: parent.to_path_buf(),
                source,
            }
        })?;
    persistence
        .prepare_transition(PackPersistenceTransition::PublishPromotionJournal)
        .map_err(|source| CoreError::Io {
            action: "prepare authenticated Pack promotion journal publication",
            path: path.clone(),
            source,
        })?;
    directory
        .exclusive_rename(
            Path::new(staging.file_name().expect("Pack journal staging name")),
            &directory,
            Path::new(path.file_name().expect("Pack promotion journal name")),
        )
        .map_err(|source| CoreError::Io {
            action: "publish authenticated Pack promotion journal without overwrite",
            path: path.clone(),
            source,
        })?;
    persistence
        .prepare_transition(PackPersistenceTransition::SynchronizePublishedPromotionJournal)
        .map_err(|source| CoreError::Io {
            action: "prepare published Pack promotion journal synchronization",
            path: parent.to_path_buf(),
            source,
        })?;
    directory.sync().map_err(|source| CoreError::Io {
        action: "synchronize published Pack promotion journal",
        path: parent.to_path_buf(),
        source,
    })?;
    emit_event(
        events,
        BundleEvent::CheckpointPromotionAdvanced {
            step: PackCheckpointPromotionStep::PromotionJournalWritten,
        },
    );
    Ok(identity)
}

fn read_pack_promotion_journal(
    plan: &Plan,
    partial: &Path,
    advanced_progress: &AuthenticatedPackCheckpoint,
) -> Result<(PackPromotionJournal, PackFileIdentity), CoreError> {
    let path = pack_promotion_journal_path(partial);
    let file = open_bundle_file(&path)?;
    let identity = pack_file_identity(&file.metadata().map_err(|source| CoreError::Io {
        action: "identify authenticated Pack promotion journal",
        path: path.clone(),
        source,
    })?)?;
    let mut bytes = Vec::new();
    file.take(MAX_PACK_PROMOTION_JOURNAL + 49)
        .read_to_end(&mut bytes)
        .map_err(|source| CoreError::Io {
            action: "read authenticated Pack promotion journal",
            path: path.clone(),
            source,
        })?;
    if bytes.len() < 48
        || bytes.len() as u64 > MAX_PACK_PROMOTION_JOURNAL + 48
        || &bytes[..8] != b"IZ2PROM1"
    {
        return Err(invalid_bundle(
            "Pack promotion journal is missing, oversized, or incompatible",
        ));
    }
    let nonce: [u8; 24] = bytes[8..32].try_into().expect("bounded journal nonce");
    let plaintext = Zeroizing::new(decrypt(
        &advanced_progress.keys.checkpoint,
        &nonce,
        &pack_promotion_journal_aad(&advanced_progress.context),
        &bytes[32..],
    )?);
    let journal: PackPromotionJournal = serde_json::from_slice(&plaintext)
        .map_err(|_| invalid_bundle("Pack promotion journal encoding is invalid"))?;
    let canonical = Zeroizing::new(
        serde_json::to_vec(&journal)
            .map_err(|_| invalid_bundle("Pack promotion journal cannot be canonicalized"))?,
    );
    if *canonical != *plaintext
        || journal.schema_version != 1
        || journal.plan_hash != plan.approval_hash()?
    {
        return Err(invalid_bundle(
            "Pack promotion journal does not match the approved Plan",
        ));
    }
    Ok((journal, identity))
}

fn pack_progress_identity(
    progress: &AuthenticatedPackCheckpoint,
    partial: &Path,
) -> Result<PackProgressIdentity, CoreError> {
    Ok(PackProgressIdentity {
        partial: pack_file_identity(&progress.file.metadata().map_err(|source| {
            CoreError::Io {
                action: "identify authenticated partial Bundle",
                path: partial.to_path_buf(),
                source,
            }
        })?)?,
        checkpoint: pack_file_identity(&progress.checkpoint_identity)?,
    })
}

fn pack_file_identity(metadata: &fs::Metadata) -> Result<PackFileIdentity, CoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(PackFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(invalid_bundle(
            "Pack checkpoint promotion requires stable file identities on this platform",
        ))
    }
}

fn same_pack_identity(expected: PackFileIdentity, current: &fs::Metadata) -> bool {
    current.is_file()
        && pack_file_identity(current)
            .map(|identity| identity == expected)
            .unwrap_or(false)
}

fn pack_artifact_exists(path: &Path) -> Result<bool, CoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(CoreError::Io {
            action: "inspect interrupted Pack checkpoint promotion",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn reconcile_interrupted_pack_promotion(
    plan: &Plan,
    partial: &Path,
    recovery: &PackRecoveryContext,
    source_adapter: &impl BundleSource,
    persistence: &dyn PackPersistence,
    events: &mut Option<&mut dyn BundleEventSink>,
) -> Result<(), CoreError> {
    let checkpoint = pack_checkpoint_path(partial);
    let resumed = resumed_partial_path(partial);
    let resumed_checkpoint = pack_checkpoint_path(&resumed);
    let previous = previous_partial_path(partial);
    let previous_checkpoint = pack_checkpoint_path(&previous);
    let journal_path = pack_promotion_journal_path(partial);
    let state = [
        pack_artifact_exists(partial)?,
        pack_artifact_exists(&checkpoint)?,
        pack_artifact_exists(&resumed)?,
        pack_artifact_exists(&resumed_checkpoint)?,
        pack_artifact_exists(&previous)?,
        pack_artifact_exists(&previous_checkpoint)?,
        pack_artifact_exists(&journal_path)?,
    ];
    if !state[4] && !state[5] && !state[6] {
        return Ok(());
    }

    let (saved_paths, advanced_paths, completed_steps) = match state {
        [true, true, true, true, false, false, true] => (
            Some((partial, checkpoint.as_path())),
            (resumed.as_path(), resumed_checkpoint.as_path()),
            0,
        ),
        [false, true, true, true, true, false, _] => (
            Some((previous.as_path(), checkpoint.as_path())),
            (resumed.as_path(), resumed_checkpoint.as_path()),
            1,
        ),
        [false, false, true, true, true, true, _] => (
            Some((previous.as_path(), previous_checkpoint.as_path())),
            (resumed.as_path(), resumed_checkpoint.as_path()),
            2,
        ),
        [true, false, false, true, true, true, _] => (
            Some((previous.as_path(), previous_checkpoint.as_path())),
            (partial, resumed_checkpoint.as_path()),
            3,
        ),
        [true, true, false, false, true, true, _] => (
            Some((previous.as_path(), previous_checkpoint.as_path())),
            (partial, checkpoint.as_path()),
            4,
        ),
        [true, true, false, false, false, true, true] => (None, (partial, checkpoint.as_path()), 5),
        [true, true, false, false, false, false, true] => {
            (None, (partial, checkpoint.as_path()), 6)
        }
        _ => {
            return Err(invalid_bundle(
                "interrupted Pack checkpoint promotion is ambiguous; restart at a new destination while preserving all artifacts",
            ));
        }
    };
    let advanced = authenticate_pack_checkpoint_at(
        plan,
        advanced_paths.0,
        advanced_paths.1,
        recovery,
        source_adapter,
    )?;
    let advanced_identity = pack_progress_identity(&advanced, advanced_paths.0)?;
    let saved = saved_paths
        .map(|paths| {
            authenticate_pack_checkpoint_at(plan, paths.0, paths.1, recovery, source_adapter)
                .map(|progress| (progress, paths.0))
        })
        .transpose()?;
    let saved_identity = saved
        .as_ref()
        .map(|(progress, path)| pack_progress_identity(progress, path))
        .transpose()?;
    if saved.as_ref().is_some_and(|(progress, _)| {
        advanced.checkpoint.captured_items < progress.checkpoint.captured_items
    }) {
        return Err(invalid_bundle(
            "interrupted resumed checkpoint is older than saved progress; restart required while preserving all artifacts",
        ));
    }
    let (journal, journal_identity) = if state[6] {
        read_pack_promotion_journal(plan, partial, &advanced)?
    } else {
        let saved_identity = saved_identity.ok_or_else(|| {
            invalid_bundle(
                "interrupted Pack checkpoint cleanup has no authenticated promotion journal; restart at a new destination while preserving all artifacts",
            )
        })?;
        let journal_identity = write_pack_promotion_journal(
            plan,
            partial,
            saved_identity,
            advanced_identity,
            &advanced,
            persistence,
            events,
        )?;
        (
            PackPromotionJournal {
                schema_version: 1,
                plan_hash: plan.approval_hash()?,
                saved: saved_identity,
                advanced: advanced_identity,
            },
            journal_identity,
        )
    };
    if journal.advanced != advanced_identity
        || saved_identity.is_some_and(|identity| identity != journal.saved)
    {
        return Err(invalid_bundle(
            "Pack promotion journal does not identify the authenticated progress artifacts",
        ));
    }
    continue_pack_checkpoint_promotion(
        PackPromotionTransaction {
            partial,
            resumed: &resumed,
            saved: &journal.saved,
            advanced: &journal.advanced,
            journal_identity,
            persistence,
        },
        completed_steps,
        events,
    )
}

fn promote_paused_pack(
    partial: &Path,
    resumed: &Path,
    saved: &PackProgressIdentity,
    advanced: &PackProgressIdentity,
    journal_identity: PackFileIdentity,
    persistence: &dyn PackPersistence,
    events: &mut Option<&mut dyn BundleEventSink>,
) -> Result<(), CoreError> {
    continue_pack_checkpoint_promotion(
        PackPromotionTransaction {
            partial,
            resumed,
            saved,
            advanced,
            journal_identity,
            persistence,
        },
        0,
        events,
    )
}

struct PackPromotionTransaction<'a> {
    partial: &'a Path,
    resumed: &'a Path,
    saved: &'a PackProgressIdentity,
    advanced: &'a PackProgressIdentity,
    journal_identity: PackFileIdentity,
    persistence: &'a dyn PackPersistence,
}

fn continue_pack_checkpoint_promotion(
    transaction: PackPromotionTransaction<'_>,
    completed_steps: usize,
    events: &mut Option<&mut dyn BundleEventSink>,
) -> Result<(), CoreError> {
    let PackPromotionTransaction {
        partial,
        resumed,
        saved,
        advanced,
        journal_identity,
        persistence,
    } = transaction;
    let parent = partial
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory =
        crate::restore_fs::RestoreDirectory::open_ambient(parent).map_err(|source| {
            CoreError::Io {
                action: "open Pack checkpoint directory",
                path: parent.to_path_buf(),
                source,
            }
        })?;
    let original_checkpoint = pack_checkpoint_path(partial);
    let previous = previous_partial_path(partial);
    let previous_checkpoint = pack_checkpoint_path(&previous);
    if completed_steps == 0 {
        for path in [&previous, &previous_checkpoint] {
            match directory
                .symlink_metadata(Path::new(path.file_name().expect("Pack artifact name")))
            {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => return Err(CoreError::DestinationAlreadyExists(path.to_path_buf())),
                Err(source) => {
                    return Err(CoreError::Io {
                        action: "inspect previous Pack checkpoint",
                        path: path.to_path_buf(),
                        source,
                    });
                }
            }
        }
    }
    let resumed_checkpoint = pack_checkpoint_path(resumed);
    let transitions = [
        (
            partial,
            previous.as_path(),
            &saved.partial,
            PackCheckpointPromotionStep::SavedPartialRetained,
            PackPersistenceTransition::MoveSavedPartial,
            PackPersistenceTransition::SynchronizeSavedPartialMove,
        ),
        (
            original_checkpoint.as_path(),
            previous_checkpoint.as_path(),
            &saved.checkpoint,
            PackCheckpointPromotionStep::SavedCheckpointRetained,
            PackPersistenceTransition::MoveSavedCheckpoint,
            PackPersistenceTransition::SynchronizeSavedCheckpointMove,
        ),
        (
            resumed,
            partial,
            &advanced.partial,
            PackCheckpointPromotionStep::ResumedPartialActivated,
            PackPersistenceTransition::MoveResumedPartial,
            PackPersistenceTransition::SynchronizeResumedPartialMove,
        ),
        (
            resumed_checkpoint.as_path(),
            original_checkpoint.as_path(),
            &advanced.checkpoint,
            PackCheckpointPromotionStep::ResumedCheckpointActivated,
            PackPersistenceTransition::MoveResumedCheckpoint,
            PackPersistenceTransition::SynchronizeResumedCheckpointMove,
        ),
    ];
    for (from, to, expected, step, move_transition, sync_transition) in
        transitions.into_iter().skip(completed_steps)
    {
        let current = fs::symlink_metadata(from).map_err(|source| CoreError::Io {
            action: "revalidate Pack progress before promotion",
            path: from.to_path_buf(),
            source,
        })?;
        if !same_pack_identity(*expected, &current) {
            return Err(invalid_bundle(
                "saved Pack progress identity changed; restart required while preserving all artifacts",
            ));
        }
        persistence
            .prepare_transition(move_transition)
            .map_err(|source| CoreError::Io {
                action: "prepare authenticated Pack checkpoint move",
                path: to.to_path_buf(),
                source,
            })?;
        directory
            .exclusive_rename(
                Path::new(from.file_name().expect("Pack artifact name")),
                &directory,
                Path::new(to.file_name().expect("Pack artifact name")),
            )
            .map_err(|source| CoreError::Io {
                action: "advance authenticated Pack checkpoint without overwrite",
                path: to.to_path_buf(),
                source,
            })?;
        persistence
            .prepare_transition(sync_transition)
            .map_err(|source| CoreError::Io {
                action: "prepare authenticated Pack checkpoint directory synchronization",
                path: parent.to_path_buf(),
                source,
            })?;
        directory.sync().map_err(|source| CoreError::Io {
            action: "synchronize authenticated Pack checkpoint move",
            path: parent.to_path_buf(),
            source,
        })?;
        emit_event(events, BundleEvent::CheckpointPromotionAdvanced { step });
    }
    for (path, expected, step, remove_transition, sync_transition) in [
        (
            &previous,
            &saved.partial,
            PackCheckpointPromotionStep::SupersededPartialRemoved,
            PackPersistenceTransition::RemoveSupersededPartial,
            PackPersistenceTransition::SynchronizeSupersededPartialRemoval,
        ),
        (
            &previous_checkpoint,
            &saved.checkpoint,
            PackCheckpointPromotionStep::SupersededCheckpointRemoved,
            PackPersistenceTransition::RemoveSupersededCheckpoint,
            PackPersistenceTransition::SynchronizeSupersededCheckpointRemoval,
        ),
    ]
    .into_iter()
    .skip(completed_steps.saturating_sub(4))
    {
        let current = fs::symlink_metadata(path).map_err(|source| CoreError::Io {
            action: "revalidate superseded Pack progress before cleanup",
            path: path.to_path_buf(),
            source,
        })?;
        if !same_pack_identity(*expected, &current) {
            return Err(invalid_bundle(
                "superseded Pack progress identity changed; cleanup stopped while preserving all artifacts",
            ));
        }
        persistence
            .prepare_transition(remove_transition)
            .map_err(|source| CoreError::Io {
                action: "prepare superseded Pack checkpoint cleanup",
                path: path.to_path_buf(),
                source,
            })?;
        directory
            .remove_file(Path::new(path.file_name().expect("Pack artifact name")))
            .map_err(|source| CoreError::Io {
                action: "remove superseded Pack checkpoint",
                path: path.to_path_buf(),
                source,
            })?;
        persistence
            .prepare_transition(sync_transition)
            .map_err(|source| CoreError::Io {
                action: "prepare superseded Pack checkpoint cleanup synchronization",
                path: parent.to_path_buf(),
                source,
            })?;
        directory.sync().map_err(|source| CoreError::Io {
            action: "synchronize superseded Pack checkpoint cleanup",
            path: parent.to_path_buf(),
            source,
        })?;
        emit_event(events, BundleEvent::CheckpointPromotionAdvanced { step });
    }
    let journal = pack_promotion_journal_path(partial);
    let current = fs::symlink_metadata(&journal).map_err(|source| CoreError::Io {
        action: "revalidate Pack promotion journal before cleanup",
        path: journal.clone(),
        source,
    })?;
    if !same_pack_identity(journal_identity, &current) {
        return Err(invalid_bundle(
            "Pack promotion journal identity changed; cleanup stopped while preserving all artifacts",
        ));
    }
    persistence
        .prepare_transition(PackPersistenceTransition::RemovePromotionJournal)
        .map_err(|source| CoreError::Io {
            action: "prepare completed Pack promotion journal cleanup",
            path: journal.clone(),
            source,
        })?;
    directory
        .remove_file(Path::new(
            journal.file_name().expect("Pack promotion journal name"),
        ))
        .map_err(|source| CoreError::Io {
            action: "remove completed Pack promotion journal",
            path: journal.clone(),
            source,
        })?;
    persistence
        .prepare_transition(PackPersistenceTransition::SynchronizePromotionJournalRemoval)
        .map_err(|source| CoreError::Io {
            action: "prepare Pack promotion journal cleanup synchronization",
            path: parent.to_path_buf(),
            source,
        })?;
    directory.sync().map_err(|source| CoreError::Io {
        action: "synchronize Pack promotion journal cleanup",
        path: parent.to_path_buf(),
        source,
    })?;
    emit_event(
        events,
        BundleEvent::CheckpointPromotionAdvanced {
            step: PackCheckpointPromotionStep::PromotionJournalRemoved,
        },
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_pack_checkpoint(
    plan: &Plan,
    writer: &StreamWriter<'_>,
    partial: &Path,
    keys: &BundleKeys,
    context: &RecordContext,
    next_sequence: u64,
    captured_items: u64,
    captured_bytes: u64,
    manifest_items: &[ManifestItem],
    index: &[IndexEntry],
    counts: [u64; 4],
    source_adapter: &impl BundleSource,
    captured_observations: &BTreeMap<u32, Option<BundleSourceObservation>>,
    persistence: &dyn PackPersistence,
) -> Result<(), CoreError> {
    require_pack_file_identity(&writer.file, partial)?;
    persistence
        .prepare_transition(PackPersistenceTransition::SynchronizePartialBeforeCheckpoint)
        .map_err(|source| CoreError::Io {
            action: "prepare partial Bundle synchronization before checkpoint",
            path: partial.to_path_buf(),
            source,
        })?;
    writer.file.sync_all().map_err(|source| CoreError::Io {
        action: "synchronize partial Bundle before checkpoint",
        path: partial.to_path_buf(),
        source,
    })?;
    let root = plan
        .approved_roots()
        .first()
        .ok_or_else(|| invalid_bundle("Pack Plan has no root"))?;
    let mut source_observations = captured_observations.clone();
    for (ordinal, item) in plan.items().iter().enumerate().filter(|(_, item)| {
        item.disposition == Disposition::Included && item.kind == MigrationItemKind::RegularFile
    }) {
        source_observations
            .entry(ordinal as u32)
            .or_insert_with(|| source_adapter.observe(&root.join(&item.relative_path)).ok());
    }
    let checkpoint = PackCheckpoint {
        schema_version: 1,
        plan_hash: plan.approval_hash()?,
        partial_hash: writer.hasher.finalize().to_hex().to_string(),
        partial_length: writer.offset,
        next_sequence,
        captured_items,
        captured_bytes,
        manifest_items: manifest_items.to_vec(),
        index: index.to_vec(),
        included_items: counts[0],
        changed_items: counts[1],
        unsupported_items: counts[2],
        unverified_items: counts[3],
        source_observations,
    };
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&checkpoint)
            .map_err(|_| invalid_bundle("Pack checkpoint cannot be encoded"))?,
    );
    if plaintext.len() as u64 > MAX_PACK_CHECKPOINT {
        return Err(invalid_bundle("Pack checkpoint exceeds its size limit"));
    }
    let nonce = random_array::<24>()?;
    let ciphertext = encrypt(&keys.checkpoint, &nonce, &context.header_hash, &plaintext)?;
    ensure_capacity(
        writer.capacity,
        writer.capacity_destination,
        32 + ciphertext.len() as u64,
    )?;
    let path = pack_checkpoint_path(partial);
    persistence
        .prepare_transition(PackPersistenceTransition::CreateCheckpoint)
        .map_err(|source| CoreError::Io {
            action: "prepare authenticated Pack checkpoint creation",
            path: path.clone(),
            source,
        })?;
    let mut output = create_private_pack_file(&path).map_err(|source| CoreError::Io {
        action: "create authenticated Pack checkpoint",
        path: path.clone(),
        source,
    })?;
    persistence
        .prepare_transition(PackPersistenceTransition::WriteCheckpoint)
        .map_err(|source| CoreError::Io {
            action: "prepare authenticated Pack checkpoint write",
            path: path.clone(),
            source,
        })?;
    output
        .write_all(b"IZ2PAUS1")
        .and_then(|()| output.write_all(&nonce))
        .and_then(|()| output.write_all(&ciphertext))
        .map_err(|source| CoreError::Io {
            action: "write authenticated Pack checkpoint",
            path: path.clone(),
            source,
        })?;
    persistence
        .prepare_transition(PackPersistenceTransition::SynchronizeCheckpoint)
        .map_err(|source| CoreError::Io {
            action: "prepare authenticated Pack checkpoint synchronization",
            path: path.clone(),
            source,
        })?;
    output.sync_all().map_err(|source| CoreError::Io {
        action: "synchronize authenticated Pack checkpoint",
        path: path.clone(),
        source,
    })?;
    let parent = partial
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    persistence
        .prepare_transition(PackPersistenceTransition::SynchronizeCheckpointDirectory)
        .map_err(|source| CoreError::Io {
            action: "prepare Pack checkpoint directory synchronization",
            path: parent.to_path_buf(),
            source,
        })?;
    fs::File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|source| CoreError::Io {
            action: "synchronize Pack checkpoint directory",
            path: parent.to_path_buf(),
            source,
        })?;
    Ok(())
}

fn emit_event(events: &mut Option<&mut dyn BundleEventSink>, event: BundleEvent) {
    if let Some(sink) = events.as_deref_mut() {
        sink.emit(event);
    }
}

fn capture_outcome_name(outcome: CaptureOutcome) -> &'static str {
    match outcome {
        CaptureOutcome::Included => "included",
        CaptureOutcome::Excluded => "excluded",
        CaptureOutcome::Changed => "changed",
        CaptureOutcome::Unsupported => "unsupported",
        CaptureOutcome::Unverified => "unverified",
    }
}

fn ensure_capacity(
    capacity: &dyn DestinationCapacity,
    destination: &Path,
    required: u64,
) -> Result<(), CoreError> {
    let available = capacity
        .available_bytes(destination)
        .map_err(|source| CoreError::Io {
            action: "inspect destination capacity",
            path: destination.to_path_buf(),
            source,
        })?;
    if available < required {
        return Err(CoreError::InsufficientSpace {
            path: destination.to_path_buf(),
            required,
            available,
        });
    }
    Ok(())
}

struct CapturedFile {
    logical_size: u64,
    chunk_sequences: Vec<u64>,
    content_hash: Option<String>,
    posix_mode: Option<u32>,
    changed: bool,
    verified: bool,
    observation: Option<BundleSourceObservation>,
}

fn capture_symbolic_link(source_adapter: &impl BundleSource, source: &Path) -> Option<PathBuf> {
    for _ in 0..3 {
        let before = source_adapter.read_link(source).ok()?;
        let after = source_adapter.read_link(source).ok()?;
        if before == after {
            return Some(before);
        }
    }
    None
}

fn capture_platform_metadata(
    source_adapter: &impl BundleSource,
    source: &Path,
    no_follow: bool,
) -> (Option<Vec<ExtendedAttribute>>, Option<bool>, Option<String>) {
    let extended_attributes = match (
        source_adapter.extended_attributes(source, no_follow),
        source_adapter.extended_attributes(source, no_follow),
    ) {
        (Ok(before), Ok(after)) if before == after => Some(before),
        _ => None,
    };
    let (access_control_captured, access_control) = match (
        source_adapter.access_control(source, no_follow),
        source_adapter.access_control(source, no_follow),
    ) {
        (Ok(before), Ok(after)) if before == after => (Some(true), before),
        _ => (Some(false), None),
    };
    (extended_attributes, access_control_captured, access_control)
}

#[allow(clippy::too_many_arguments)]
fn capture_regular_file(
    source_adapter: &impl BundleSource,
    source: &Path,
    item_ordinal: u32,
    sequence: &mut u64,
    writer: &mut StreamWriter<'_>,
    partial: &Path,
    keys: &BundleKeys,
    context: &RecordContext,
    index: &mut Vec<IndexEntry>,
) -> Result<CapturedFile, CoreError> {
    const CAPTURE_ATTEMPTS: u32 = 3;
    let mut changed = false;
    for attempt in 0..CAPTURE_ATTEMPTS {
        let before = match source_adapter.observe(source) {
            Ok(observation) => observation,
            Err(_) => continue,
        };
        let mut input = match source_adapter.open(source) {
            Ok(input) => input,
            Err(_) => continue,
        };
        let stage_path = item_stage_path(partial, item_ordinal, attempt);
        writer
            .persistence
            .prepare_transition(PackPersistenceTransition::CreateMigrationItemStage)
            .map_err(|source_error| CoreError::Io {
                action: "prepare encrypted Migration Item staging output creation",
                path: stage_path.clone(),
                source: source_error,
            })?;
        let stage_file = fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&stage_path)
            .map_err(|source_error| CoreError::Io {
                action: "create encrypted Migration Item staging output",
                path: stage_path.clone(),
                source: source_error,
            })?;
        let mut stage = StreamWriter::new(
            stage_file,
            writer.capacity,
            writer.capacity_destination,
            writer.persistence,
            PackPersistenceTransition::WriteMigrationItemStage,
        );
        let mut stage_index = Vec::new();
        let mut chunk_sequences = Vec::new();
        let mut content_hasher = blake3::Hasher::new();
        let mut logical_size = 0_u64;
        let mut chunk_ordinal = 0_u32;
        let capture_result = (|| -> Result<(), CoreError> {
            let mut buffer = Zeroizing::new(vec![0_u8; MAX_PLAINTEXT_CHUNK]);
            loop {
                let read = input
                    .read(&mut buffer)
                    .map_err(|source_error| CoreError::Io {
                        action: "read selected Migration Item",
                        path: source.to_path_buf(),
                        source: source_error,
                    })?;
                if read == 0 && chunk_ordinal > 0 {
                    break;
                }
                let record_offset = stage.offset;
                let ciphertext_length = stage.write_record(
                    RECORD_CONTENT,
                    *sequence,
                    item_ordinal,
                    chunk_ordinal,
                    &keys.content,
                    context,
                    &buffer[..read],
                    &stage_path,
                )?;
                stage_index.push(IndexEntry {
                    sequence: *sequence,
                    item_ordinal,
                    chunk_ordinal,
                    offset: record_offset,
                    plaintext_length: read as u32,
                    ciphertext_length,
                });
                content_hasher.update(&buffer[..read]);
                logical_size = logical_size
                    .checked_add(read as u64)
                    .ok_or_else(|| invalid_bundle("Migration Item size overflowed"))?;
                chunk_sequences.push(*sequence);
                *sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid_bundle("Bundle record sequence overflowed"))?;
                chunk_ordinal = chunk_ordinal
                    .checked_add(1)
                    .ok_or_else(|| invalid_bundle("Migration Item chunk count overflowed"))?;
                if read == 0 {
                    break;
                }
            }
            Ok(())
        })();
        if let Err(error) = capture_result {
            drop(stage);
            let _ = fs::remove_file(&stage_path);
            return Err(error);
        }
        let after = source_adapter.observe(source).ok();
        if after == Some(before) && logical_size == before.length {
            let base_offset = writer.offset;
            writer
                .persistence
                .prepare_transition(PackPersistenceTransition::FlushMigrationItemStage)
                .map_err(|source_error| CoreError::Io {
                    action: "prepare encrypted Migration Item staging output flush",
                    path: stage_path.clone(),
                    source: source_error,
                })?;
            stage.file.flush().map_err(|source_error| CoreError::Io {
                action: "flush encrypted Migration Item staging output",
                path: stage_path.clone(),
                source: source_error,
            })?;
            stage
                .file
                .seek(SeekFrom::Start(0))
                .map_err(|source_error| CoreError::Io {
                    action: "rewind encrypted Migration Item staging output",
                    path: stage_path.clone(),
                    source: source_error,
                })?;
            copy_stage(&mut stage.file, writer, partial)?;
            writer.record_count = writer
                .record_count
                .checked_add(stage.record_count)
                .ok_or_else(|| invalid_bundle("Bundle record count overflowed"))?;
            for mut entry in stage_index {
                entry.offset = entry
                    .offset
                    .checked_add(base_offset)
                    .ok_or_else(|| invalid_bundle("Bundle chunk offset overflowed"))?;
                index.push(entry);
            }
            drop(stage);
            writer
                .persistence
                .prepare_transition(PackPersistenceTransition::RemoveMigrationItemStage)
                .map_err(|source_error| CoreError::Io {
                    action: "prepare encrypted Migration Item staging output cleanup",
                    path: stage_path.clone(),
                    source: source_error,
                })?;
            fs::remove_file(&stage_path).map_err(|source_error| CoreError::Io {
                action: "remove encrypted Migration Item staging output",
                path: stage_path,
                source: source_error,
            })?;
            return Ok(CapturedFile {
                logical_size,
                chunk_sequences,
                content_hash: Some(content_hasher.finalize().to_hex().to_string()),
                posix_mode: before.posix_mode,
                changed,
                verified: true,
                observation: Some(before),
            });
        }
        changed = true;
        drop(stage);
        let _ = fs::remove_file(&stage_path);
    }
    Ok(CapturedFile {
        logical_size: 0,
        chunk_sequences: Vec::new(),
        content_hash: None,
        posix_mode: None,
        changed,
        verified: false,
        observation: None,
    })
}

fn item_stage_path(partial: &Path, item_ordinal: u32, attempt: u32) -> PathBuf {
    let mut value = partial.as_os_str().to_os_string();
    value.push(format!(".item-{item_ordinal}-{attempt}"));
    PathBuf::from(value)
}

fn copy_stage(
    source: &mut fs::File,
    destination: &mut StreamWriter<'_>,
    destination_path: &Path,
) -> Result<(), CoreError> {
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|source_error| CoreError::Io {
                action: "read encrypted Migration Item staging output",
                path: destination_path.to_path_buf(),
                source: source_error,
            })?;
        if read == 0 {
            return Ok(());
        }
        destination.write_hashed(&buffer[..read], destination_path)?;
    }
}

struct StreamWriter<'a> {
    file: fs::File,
    hasher: blake3::Hasher,
    offset: u64,
    record_count: u64,
    capacity: &'a dyn DestinationCapacity,
    capacity_destination: &'a Path,
    persistence: &'a dyn PackPersistence,
    write_transition: PackPersistenceTransition,
}

impl<'a> StreamWriter<'a> {
    fn new(
        file: fs::File,
        capacity: &'a dyn DestinationCapacity,
        capacity_destination: &'a Path,
        persistence: &'a dyn PackPersistence,
        write_transition: PackPersistenceTransition,
    ) -> Self {
        Self {
            file,
            hasher: blake3::Hasher::new(),
            offset: 0,
            record_count: 0,
            capacity,
            capacity_destination,
            persistence,
            write_transition,
        }
    }

    fn write_hashed(&mut self, bytes: &[u8], path: &Path) -> Result<(), CoreError> {
        ensure_capacity(self.capacity, self.capacity_destination, bytes.len() as u64)?;
        self.persistence
            .prepare_transition(self.write_transition)
            .map_err(|source| CoreError::Io {
                action: "prepare encrypted Bundle data write",
                path: path.to_path_buf(),
                source,
            })?;
        self.file.write_all(bytes).map_err(|source| CoreError::Io {
            action: "write partial Bundle",
            path: path.to_path_buf(),
            source,
        })?;
        self.hasher.update(bytes);
        self.offset = self
            .offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid_bundle("Bundle output size overflowed"))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn write_record(
        &mut self,
        kind: u8,
        sequence: u64,
        item_ordinal: u32,
        chunk_ordinal: u32,
        key: &[u8; 32],
        context: &RecordContext,
        plaintext: &[u8],
        path: &Path,
    ) -> Result<u32, CoreError> {
        let plaintext_length = u32::try_from(plaintext.len())
            .map_err(|_| invalid_bundle("Bundle record plaintext is too large"))?;
        let ciphertext_length = plaintext_length
            .checked_add(16)
            .ok_or_else(|| invalid_bundle("Bundle record ciphertext length overflowed"))?;
        let record_header = encode_record_header(
            kind,
            sequence,
            item_ordinal,
            chunk_ordinal,
            plaintext_length,
            ciphertext_length,
        );
        let aad = record_aad(context, &record_header);
        let nonce = record_nonce(&context.nonce_prefix, sequence);
        let ciphertext = encrypt(key, &nonce, &aad, plaintext)?;
        self.write_hashed(&record_header, path)?;
        self.write_hashed(&ciphertext, path)?;
        self.record_count += 1;
        Ok(ciphertext_length)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    marker: String,
    schema_version: u32,
    source_name: String,
    plan_hash: String,
    logical_size: u64,
    included_items: u64,
    changed_items: u64,
    unsupported_items: u64,
    unverified_items: u64,
    items: Vec<ManifestItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestItem {
    id: String,
    relative_path: String,
    kind: String,
    estimated_size: u64,
    outcome: CaptureOutcome,
    chunk_sequences: Vec<u64>,
    content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    posix_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    symlink_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extended_attributes: Option<Vec<ExtendedAttribute>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_control_captured: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_control: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CaptureOutcome {
    Included,
    Excluded,
    Changed,
    Unsupported,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexEntry {
    sequence: u64,
    item_ordinal: u32,
    chunk_ordinal: u32,
    offset: u64,
    plaintext_length: u32,
    ciphertext_length: u32,
}

fn encode_index(entries: &[IndexEntry]) -> Result<Vec<u8>, CoreError> {
    let count = u32::try_from(entries.len())
        .map_err(|_| invalid_bundle("Bundle chunk index has too many entries"))?;
    let length = 8_usize
        .checked_add(
            entries
                .len()
                .checked_mul(32)
                .ok_or_else(|| invalid_bundle("Bundle chunk index length overflowed"))?,
        )
        .ok_or_else(|| invalid_bundle("Bundle chunk index length overflowed"))?;
    if length > MAX_INDEX_PLAINTEXT {
        return Err(invalid_bundle("Bundle chunk index exceeds its size limit"));
    }
    let mut output = Vec::with_capacity(length);
    output.extend_from_slice(b"IDX2");
    output.extend_from_slice(&count.to_be_bytes());
    for entry in entries {
        output.extend_from_slice(&entry.sequence.to_be_bytes());
        output.extend_from_slice(&entry.item_ordinal.to_be_bytes());
        output.extend_from_slice(&entry.chunk_ordinal.to_be_bytes());
        output.extend_from_slice(&entry.offset.to_be_bytes());
        output.extend_from_slice(&entry.plaintext_length.to_be_bytes());
        output.extend_from_slice(&entry.ciphertext_length.to_be_bytes());
    }
    Ok(output)
}

fn decode_index(bytes: &[u8]) -> Result<Vec<IndexEntry>, CoreError> {
    if bytes.len() < 8 || &bytes[..4] != b"IDX2" {
        return Err(invalid_bundle("Bundle chunk index marker is invalid"));
    }
    let count = u32::from_be_bytes(bytes[4..8].try_into().expect("fixed slice")) as usize;
    let expected = 8_usize
        .checked_add(
            count
                .checked_mul(32)
                .ok_or_else(|| invalid_bundle("Bundle chunk index count overflowed"))?,
        )
        .ok_or_else(|| invalid_bundle("Bundle chunk index size overflowed"))?;
    if expected > MAX_INDEX_PLAINTEXT || bytes.len() != expected {
        return Err(invalid_bundle("Bundle chunk index length is invalid"));
    }
    let mut entries = Vec::with_capacity(count);
    for chunk in bytes[8..].chunks_exact(32) {
        entries.push(IndexEntry {
            sequence: u64::from_be_bytes(chunk[0..8].try_into().expect("fixed slice")),
            item_ordinal: u32::from_be_bytes(chunk[8..12].try_into().expect("fixed slice")),
            chunk_ordinal: u32::from_be_bytes(chunk[12..16].try_into().expect("fixed slice")),
            offset: u64::from_be_bytes(chunk[16..24].try_into().expect("fixed slice")),
            plaintext_length: u32::from_be_bytes(chunk[24..28].try_into().expect("fixed slice")),
            ciphertext_length: u32::from_be_bytes(chunk[28..32].try_into().expect("fixed slice")),
        });
    }
    Ok(entries)
}

struct OpenedBundle {
    summary: AuthenticatedBundleSummary,
    authenticated_chunks: u64,
    authenticated_bytes: u64,
    restore_plan: AuthenticatedRestorePlan,
    bundle_hash: [u8; 32],
    bundle_identifier: [u8; 16],
}

#[derive(Debug)]
pub(crate) struct AuthenticatedRestorePlan {
    pub(crate) items: Vec<AuthenticatedRestoreItem>,
    pub(crate) bundle_hash: [u8; 32],
    pub(crate) bundle_identity: String,
}

#[derive(Debug)]
pub(crate) struct AuthenticatedRestoreItem {
    pub(crate) ordinal: u32,
    pub(crate) relative_path: String,
    pub(crate) kind: AuthenticatedRestoreKind,
    pub(crate) estimated_size: u64,
    pub(crate) content_hash: Option<String>,
    pub(crate) selected: bool,
    pub(crate) posix_mode: Option<u32>,
    pub(crate) symlink_target: Option<String>,
    pub(crate) extended_attributes: Option<Vec<ExtendedAttribute>>,
    pub(crate) access_control_captured: Option<bool>,
    pub(crate) access_control: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticatedRestoreKind {
    Directory,
    RegularFile,
    SymbolicLink,
    Special,
    Unknown,
}

fn authenticated_restore_kind(value: &str) -> Result<AuthenticatedRestoreKind, CoreError> {
    match value {
        "Directory" => Ok(AuthenticatedRestoreKind::Directory),
        "RegularFile" => Ok(AuthenticatedRestoreKind::RegularFile),
        "SymbolicLink" => Ok(AuthenticatedRestoreKind::SymbolicLink),
        "Special" => Ok(AuthenticatedRestoreKind::Special),
        "Unknown" => Ok(AuthenticatedRestoreKind::Unknown),
        _ => Err(invalid_bundle(
            "Bundle manifest contains an unknown Migration Item kind",
        )),
    }
}

pub(crate) trait AuthenticatedContentSink {
    fn write_chunk(
        &mut self,
        item_ordinal: u32,
        chunk_ordinal: u32,
        content: &[u8],
    ) -> Result<(), CoreError>;
}

pub(crate) struct RestoreBundleReader {
    source: PathBuf,
    input: fs::File,
}

pub(crate) struct AuthenticatedRestoreContent {
    pub(crate) authenticated_bytes: u64,
    pub(crate) bundle_hash: [u8; 32],
}

impl RestoreBundleReader {
    pub(crate) fn open(source: &Path) -> Result<Self, CoreError> {
        Ok(Self {
            source: source.to_path_buf(),
            input: open_bundle_file(source)?,
        })
    }

    pub(crate) fn authenticate_plan(
        &mut self,
        recovery_secret: &RecoverySecret,
    ) -> Result<AuthenticatedRestorePlan, CoreError> {
        let mut events = None;
        let mut content_sink = None;
        let opened = open_bundle_from(
            &mut self.input,
            &self.source,
            recovery_secret,
            false,
            &mut events,
            &mut content_sink,
            false,
        )?;
        Ok(opened.restore_plan)
    }

    pub(crate) fn stream_authenticated_content(
        &mut self,
        recovery_secret: &RecoverySecret,
        sink: &mut dyn AuthenticatedContentSink,
    ) -> Result<AuthenticatedRestoreContent, CoreError> {
        let mut events = None;
        let mut content_sink = Some(sink);
        let opened = open_bundle_from(
            &mut self.input,
            &self.source,
            recovery_secret,
            true,
            &mut events,
            &mut content_sink,
            false,
        )?;
        Ok(AuthenticatedRestoreContent {
            authenticated_bytes: opened.authenticated_bytes,
            bundle_hash: opened.bundle_hash,
        })
    }
}

fn open_bundle(
    source: &Path,
    recovery_secret: &RecoverySecret,
    verify_content: bool,
    events: &mut Option<&mut dyn BundleEventSink>,
    content_sink: &mut Option<&mut dyn AuthenticatedContentSink>,
) -> Result<OpenedBundle, CoreError> {
    let mut input = open_bundle_file(source)?;
    open_bundle_from(
        &mut input,
        source,
        recovery_secret,
        verify_content,
        events,
        content_sink,
        false,
    )
}

fn open_bundle_file(source: &Path) -> Result<fs::File, CoreError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(source).map_err(|source_error| CoreError::Io {
        action: "open Bundle",
        path: source.to_path_buf(),
        source: source_error,
    })
}

fn open_bundle_from(
    input: &mut fs::File,
    source: &Path,
    recovery_secret: &RecoverySecret,
    verify_content: bool,
    events: &mut Option<&mut dyn BundleEventSink>,
    content_sink: &mut Option<&mut dyn AuthenticatedContentSink>,
    allow_partial: bool,
) -> Result<OpenedBundle, CoreError> {
    if verify_content {
        emit_event(events, BundleEvent::VerificationStarted);
    }
    if !allow_partial {
        reject_partial_path(source)?;
    }
    input
        .seek(SeekFrom::Start(0))
        .map_err(|source_error| CoreError::Io {
            action: "rewind opened Bundle",
            path: source.to_path_buf(),
            source: source_error,
        })?;
    let file_length = input
        .metadata()
        .map_err(|source_error| CoreError::Io {
            action: "inspect Bundle length",
            path: source.to_path_buf(),
            source: source_error,
        })?
        .len();
    if file_length < (HEADER_LENGTH + RECORD_HEADER_LENGTH) as u64 {
        return Err(invalid_bundle("Bundle is truncated"));
    }
    let mut header = [0_u8; HEADER_LENGTH];
    input
        .read_exact(&mut header)
        .map_err(|_| invalid_bundle("Bundle header is truncated"))?;
    let opened_header = decode_header(&header, recovery_secret)?;
    let keys = derive_bundle_keys(
        &opened_header.data_encryption_key,
        &opened_header.hkdf_salt,
        &opened_header.bundle_identifier,
    )?;
    let context = RecordContext {
        header_hash: *blake3::hash(&header).as_bytes(),
        bundle_identifier: opened_header.bundle_identifier,
        nonce_prefix: opened_header.nonce_prefix,
    };
    let mut prefix_hasher = blake3::Hasher::new();
    prefix_hasher.update(&header);
    let mut bundle_hasher = blake3::Hasher::new();
    bundle_hasher.update(&header);
    let mut previous_sequence = None;
    let mut record_count = 0_u64;
    let mut content_entries = Vec::new();
    let mut manifest = None;
    let mut index = None;
    let mut manifest_sequence = None;
    let mut index_sequence = None;
    let mut authenticated_chunks = 0_u64;
    let mut authenticated_bytes = 0_u64;
    let mut verified_content_hashers = BTreeMap::<u32, blake3::Hasher>::new();
    let mut saw_completion = false;

    loop {
        let record_offset = input
            .stream_position()
            .map_err(|source_error| CoreError::Io {
                action: "read Bundle position",
                path: source.to_path_buf(),
                source: source_error,
            })?;
        if record_offset == file_length {
            break;
        }
        let mut raw_header = [0_u8; RECORD_HEADER_LENGTH];
        input
            .read_exact(&mut raw_header)
            .map_err(|_| invalid_bundle("Bundle record is truncated"))?;
        let record = decode_record_header(&raw_header)?;
        if previous_sequence.is_some_and(|previous| record.sequence <= previous) {
            return Err(invalid_bundle("Bundle record order is invalid"));
        }
        previous_sequence = Some(record.sequence);
        validate_record_limit(&record)?;
        let mut ciphertext = vec![0_u8; record.ciphertext_length as usize];
        input
            .read_exact(&mut ciphertext)
            .map_err(|_| invalid_bundle("Bundle record ciphertext is truncated"))?;
        bundle_hasher.update(&raw_header);
        bundle_hasher.update(&ciphertext);

        if record.kind == RECORD_COMPLETION {
            if saw_completion {
                return Err(invalid_bundle(
                    "Bundle contains duplicate completion records",
                ));
            }
            let completion = decrypt_record(
                &record,
                &raw_header,
                &ciphertext,
                &keys.completion,
                &context,
            )?;
            let prefix_hash = *prefix_hasher.finalize().as_bytes();
            decode_completion(
                &completion,
                &prefix_hash,
                record_count,
                manifest_sequence,
                index_sequence,
            )?;
            saw_completion = true;
            if input
                .stream_position()
                .map_err(|source_error| CoreError::Io {
                    action: "read Bundle completion position",
                    path: source.to_path_buf(),
                    source: source_error,
                })?
                != file_length
            {
                return Err(invalid_bundle(
                    "Bundle contains trailing bytes after completion",
                ));
            }
            break;
        }

        prefix_hasher.update(&raw_header);
        prefix_hasher.update(&ciphertext);
        match record.kind {
            RECORD_CONTENT => {
                if manifest.is_some() {
                    return Err(invalid_bundle("Bundle content appears after its manifest"));
                }
                content_entries.push(IndexEntry {
                    sequence: record.sequence,
                    item_ordinal: record.item_ordinal,
                    chunk_ordinal: record.chunk_ordinal,
                    offset: record_offset,
                    plaintext_length: record.plaintext_length,
                    ciphertext_length: record.ciphertext_length,
                });
                if verify_content {
                    let plaintext =
                        decrypt_record(&record, &raw_header, &ciphertext, &keys.content, &context)?;
                    authenticated_chunks += 1;
                    authenticated_bytes =
                        authenticated_bytes
                            .checked_add(plaintext.len() as u64)
                            .ok_or_else(|| invalid_bundle("verified byte count overflowed"))?;
                    verified_content_hashers
                        .entry(record.item_ordinal)
                        .or_default()
                        .update(&plaintext);
                    if let Some(sink) = content_sink.as_deref_mut() {
                        sink.write_chunk(record.item_ordinal, record.chunk_ordinal, &plaintext)?;
                    }
                    emit_event(
                        events,
                        BundleEvent::ChunkVerified {
                            sequence: record.sequence,
                            bytes: plaintext.len() as u64,
                        },
                    );
                }
            }
            RECORD_MANIFEST => {
                if manifest.is_some() || index.is_some() {
                    return Err(invalid_bundle("Bundle manifest order is invalid"));
                }
                let plaintext =
                    decrypt_record(&record, &raw_header, &ciphertext, &keys.manifest, &context)?;
                manifest_sequence = Some(record.sequence);
                manifest = Some(decode_manifest(&plaintext)?);
            }
            RECORD_INDEX => {
                if manifest.is_none() || index.is_some() {
                    return Err(invalid_bundle("Bundle chunk index order is invalid"));
                }
                let plaintext =
                    decrypt_record(&record, &raw_header, &ciphertext, &keys.index, &context)?;
                index_sequence = Some(record.sequence);
                index = Some(decode_index(&plaintext)?);
            }
            _ => return Err(invalid_bundle("Bundle contains an unknown critical record")),
        }
        record_count += 1;
    }
    if !saw_completion {
        return Err(CoreError::BundleIncomplete(source.to_path_buf()));
    }
    let manifest = manifest.ok_or_else(|| invalid_bundle("Bundle manifest is missing"))?;
    let index = index.ok_or_else(|| invalid_bundle("Bundle chunk index is missing"))?;
    if index != content_entries {
        return Err(invalid_bundle(
            "Bundle chunk index does not match its records",
        ));
    }
    validate_manifest(&manifest, &index)?;
    if verify_content {
        validate_content_hashes(&manifest, verified_content_hashers)?;
    }
    if verify_content && authenticated_bytes != manifest.logical_size {
        return Err(invalid_bundle(
            "verified content size does not match the manifest",
        ));
    }
    if verify_content {
        emit_event(
            events,
            BundleEvent::VerificationCompleted {
                authenticated_chunks,
                authenticated_bytes,
            },
        );
    }
    let restore_plan = AuthenticatedRestorePlan {
        items: manifest
            .items
            .iter()
            .enumerate()
            .map(|(ordinal, item)| {
                Ok(AuthenticatedRestoreItem {
                    ordinal: u32::try_from(ordinal)
                        .map_err(|_| invalid_bundle("Bundle contains too many Migration Items"))?,
                    relative_path: item.relative_path.clone(),
                    kind: authenticated_restore_kind(&item.kind)?,
                    estimated_size: item.estimated_size,
                    content_hash: item.content_hash.clone(),
                    selected: matches!(
                        item.outcome,
                        CaptureOutcome::Included | CaptureOutcome::Changed
                    ),
                    posix_mode: item.posix_mode,
                    symlink_target: item.symlink_target.clone(),
                    extended_attributes: item.extended_attributes.clone(),
                    access_control_captured: item.access_control_captured,
                    access_control: item.access_control.clone(),
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()?,
        bundle_hash: *bundle_hasher.finalize().as_bytes(),
        bundle_identity: bundle_identity_hex(&opened_header.bundle_identifier),
    };
    Ok(OpenedBundle {
        summary: AuthenticatedBundleSummary {
            source_name: manifest.source_name,
            logical_size: manifest.logical_size,
            format_version: FORMAT_VERSION,
            cryptographic_suite: "IZ1",
            included_items: manifest.included_items,
            changed_items: manifest.changed_items,
            unsupported_items: manifest.unsupported_items,
            unverified_items: manifest.unverified_items,
        },
        authenticated_chunks,
        authenticated_bytes,
        restore_plan,
        bundle_hash: *bundle_hasher.finalize().as_bytes(),
        bundle_identifier: opened_header.bundle_identifier,
    })
}

fn require_matching_verified_copy(
    source: &OpenedBundle,
    destination: &OpenedBundle,
) -> Result<(), CoreError> {
    if source.bundle_hash != destination.bundle_hash
        || source.bundle_identifier != destination.bundle_identifier
    {
        return Err(invalid_bundle(
            "Verified Copy bytes or authenticated Bundle identity do not match the source",
        ));
    }
    Ok(())
}

fn emit_verified_copy_event(
    sink: &mut Option<&mut dyn VerifiedCopyEventSink>,
    event: VerifiedCopyEvent,
) {
    if let Some(sink) = sink.as_deref_mut() {
        sink.emit(event);
    }
}

fn prepare_verified_copy_transition(
    persistence: &dyn VerifiedCopyPersistence,
    transition: VerifiedCopyPersistenceTransition,
    action: &'static str,
    path: &Path,
) -> Result<(), CoreError> {
    persistence
        .prepare_transition(transition)
        .map_err(|source| CoreError::Io {
            action,
            path: path.to_path_buf(),
            source,
        })
}

fn require_matching_copy_prefix(
    source: &mut fs::File,
    source_path: &Path,
    partial_path: &Path,
) -> Result<fs::Metadata, CoreError> {
    let mut partial = open_bundle_file(partial_path)?;
    let partial_metadata = partial.metadata().map_err(|source_error| CoreError::Io {
        action: "identify existing partial Verified Copy",
        path: partial_path.to_path_buf(),
        source: source_error,
    })?;
    let source_length = source
        .metadata()
        .map_err(|source_error| CoreError::Io {
            action: "identify authenticated source Bundle",
            path: source_path.to_path_buf(),
            source: source_error,
        })?
        .len();
    if partial_metadata.len() == 0 || partial_metadata.len() > source_length {
        return Err(invalid_bundle(
            "existing partial Verified Copy does not match the authenticated source Bundle",
        ));
    }
    source
        .seek(SeekFrom::Start(0))
        .map_err(|source_error| CoreError::Io {
            action: "rewind authenticated source Bundle for partial comparison",
            path: source_path.to_path_buf(),
            source: source_error,
        })?;
    let mut remaining = partial_metadata.len();
    let mut source_buffer = [0_u8; 64 * 1024];
    let mut partial_buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(source_buffer.len() as u64))
            .expect("bounded Verified Copy prefix buffer");
        source
            .read_exact(&mut source_buffer[..requested])
            .map_err(|source_error| CoreError::Io {
                action: "read authenticated source Bundle for partial comparison",
                path: source_path.to_path_buf(),
                source: source_error,
            })?;
        partial
            .read_exact(&mut partial_buffer[..requested])
            .map_err(|source_error| CoreError::Io {
                action: "read existing partial Verified Copy",
                path: partial_path.to_path_buf(),
                source: source_error,
            })?;
        if source_buffer[..requested] != partial_buffer[..requested] {
            return Err(invalid_bundle(
                "existing partial Verified Copy does not match the authenticated source Bundle",
            ));
        }
        remaining -= requested as u64;
    }
    Ok(partial_metadata)
}

fn bundle_hash_hex(bundle_hash: &[u8; 32]) -> String {
    blake3::Hash::from_bytes(*bundle_hash).to_hex().to_string()
}

fn bundle_identity_hex(bundle_identifier: &[u8; 16]) -> String {
    bundle_identifier
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_manifest(manifest: &Manifest, index: &[IndexEntry]) -> Result<(), CoreError> {
    if manifest.marker != "MNF2" || !matches!(manifest.schema_version, 1 | 2) {
        return Err(invalid_bundle("Bundle manifest version is unsupported"));
    }
    if manifest.source_name.is_empty() || manifest.source_name.len() > 4096 {
        return Err(invalid_bundle("Bundle manifest source name is invalid"));
    }
    let indexed_sequences = index.iter().map(|entry| entry.sequence).collect::<Vec<_>>();
    let manifest_sequences = manifest
        .items
        .iter()
        .flat_map(|item| item.chunk_sequences.iter().copied())
        .collect::<Vec<_>>();
    if manifest_sequences != indexed_sequences {
        return Err(invalid_bundle("Bundle manifest chunk mapping is invalid"));
    }
    let mut expected_chunks = BTreeMap::<u32, u32>::new();
    for entry in index {
        if entry.item_ordinal as usize >= manifest.items.len() {
            return Err(invalid_bundle(
                "Bundle chunk index references an unknown Migration Item",
            ));
        }
        let expected = expected_chunks.entry(entry.item_ordinal).or_default();
        if entry.chunk_ordinal != *expected {
            return Err(invalid_bundle(
                "Bundle Migration Item chunk order is invalid",
            ));
        }
        *expected = expected
            .checked_add(1)
            .ok_or_else(|| invalid_bundle("Bundle Migration Item chunk count overflowed"))?;
    }
    Ok(())
}

fn validate_content_hashes(
    manifest: &Manifest,
    hashers: BTreeMap<u32, blake3::Hasher>,
) -> Result<(), CoreError> {
    for (item_ordinal, item) in manifest.items.iter().enumerate() {
        if item.chunk_sequences.is_empty() {
            if item.content_hash.is_some() {
                return Err(invalid_bundle(
                    "Bundle manifest has a digest without selected chunks",
                ));
            }
            continue;
        }
        let actual = hashers
            .get(&(item_ordinal as u32))
            .ok_or_else(|| invalid_bundle("Bundle verification missed selected chunks"))?
            .finalize()
            .to_hex()
            .to_string();
        if item.content_hash.as_deref() != Some(actual.as_str()) {
            return Err(invalid_bundle(
                "Bundle content does not match its authenticated manifest",
            ));
        }
    }
    Ok(())
}

struct OpenedHeader {
    data_encryption_key: Zeroizing<[u8; 32]>,
    bundle_identifier: [u8; 16],
    hkdf_salt: [u8; 32],
    nonce_prefix: [u8; 16],
}

fn encode_header(
    data_encryption_key: &[u8; 32],
    recovery_secrets: [&RecoverySecret; 2],
    bundle_identifier: &[u8; 16],
    hkdf_salt: &[u8; 32],
    nonce_prefix: &[u8; 16],
) -> Result<Vec<u8>, CoreError> {
    let mut header = Vec::with_capacity(HEADER_LENGTH);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    header.extend_from_slice(&SUITE_ID.to_be_bytes());
    header.extend_from_slice(&(HEADER_LENGTH as u32).to_be_bytes());
    header.extend_from_slice(bundle_identifier);
    header.extend_from_slice(hkdf_salt);
    header.extend_from_slice(nonce_prefix);
    header.push(SLOT_COUNT);
    header.extend_from_slice(&[0; 3]);
    for recovery_secret in recovery_secrets {
        let salt = random_array()?;
        let nonce = random_array()?;
        let prefix = encode_slot_prefix(recovery_secret.method, &salt, &nonce);
        let aad = slot_aad(bundle_identifier, hkdf_salt, nonce_prefix, &prefix);
        let wrapping_key = derive_wrapping_key(&recovery_secret.bytes, &salt)?;
        let wrapped = encrypt(&wrapping_key, &nonce, &aad, data_encryption_key)?;
        header.extend_from_slice(&prefix);
        header.extend_from_slice(&wrapped);
    }
    if header.len() != HEADER_LENGTH {
        return Err(invalid_bundle("internal IZ2 header length mismatch"));
    }
    Ok(header)
}

fn decode_header(
    header: &[u8; HEADER_LENGTH],
    recovery_secret: &RecoverySecret,
) -> Result<OpenedHeader, CoreError> {
    let mut cursor = SliceCursor::new(header);
    if cursor.take(8)? != MAGIC {
        return Err(invalid_bundle("Bundle magic is invalid"));
    }
    if cursor.u16()? != FORMAT_VERSION {
        return Err(invalid_bundle("Bundle format version is unsupported"));
    }
    if cursor.u16()? != SUITE_ID {
        return Err(invalid_bundle("Bundle cryptographic suite is unsupported"));
    }
    if cursor.u32()? as usize != HEADER_LENGTH {
        return Err(invalid_bundle("Bundle public header length is invalid"));
    }
    let bundle_identifier = cursor.array()?;
    let hkdf_salt = cursor.array()?;
    let nonce_prefix = cursor.array()?;
    if cursor.u8()? != SLOT_COUNT || cursor.take(3)? != [0; 3] {
        return Err(invalid_bundle(
            "Bundle Recovery Method directory is invalid",
        ));
    }
    let mut selected = None;
    for _ in 0..SLOT_COUNT {
        let start = cursor.position;
        let method = RecoveryMethod::from_slot_id(cursor.u8()?)?;
        if cursor.u8()? != method.slot_id() || cursor.u8()? != 0x13 || cursor.u8()? != 0 {
            return Err(invalid_bundle("Bundle Recovery Method slot is invalid"));
        }
        if cursor.u32()? != ARGON2_MEMORY_KIBIBYTES
            || cursor.u32()? != ARGON2_ITERATIONS
            || cursor.u32()? != ARGON2_PARALLELISM
        {
            return Err(invalid_bundle("Bundle Argon2id parameters are unsupported"));
        }
        let salt = cursor.array()?;
        let nonce = cursor.array()?;
        if cursor.u16()? != 48 {
            return Err(invalid_bundle("Bundle wrapped key length is invalid"));
        }
        let prefix_end = cursor.position;
        let wrapped_key: [u8; 48] = cursor.array()?;
        if method == recovery_secret.method {
            selected = Some((salt, nonce, wrapped_key, header[start..prefix_end].to_vec()));
        }
    }
    if cursor.position != HEADER_LENGTH {
        return Err(invalid_bundle("Bundle public header is not canonical"));
    }
    let (salt, nonce, wrapped_key, prefix) =
        selected.ok_or_else(|| invalid_bundle("requested Recovery Method is unavailable"))?;
    let wrapping_key = derive_wrapping_key(&recovery_secret.bytes, &salt)?;
    let aad = slot_aad(&bundle_identifier, &hkdf_salt, &nonce_prefix, &prefix);
    let mut data_encryption_key = decrypt(&wrapping_key, &nonce, &aad, &wrapped_key)?;
    if data_encryption_key.len() != 32 {
        data_encryption_key.zeroize();
        return Err(invalid_bundle(
            "unwrapped data-encryption key length is invalid",
        ));
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&data_encryption_key);
    data_encryption_key.zeroize();
    Ok(OpenedHeader {
        data_encryption_key: key,
        bundle_identifier,
        hkdf_salt,
        nonce_prefix,
    })
}

struct BundleKeys {
    content: Zeroizing<[u8; 32]>,
    manifest: Zeroizing<[u8; 32]>,
    index: Zeroizing<[u8; 32]>,
    completion: Zeroizing<[u8; 32]>,
    checkpoint: Zeroizing<[u8; 32]>,
}

struct RecordContext {
    header_hash: [u8; 32],
    bundle_identifier: [u8; 16],
    nonce_prefix: [u8; 16],
}

fn derive_bundle_keys(
    data_encryption_key: &[u8; 32],
    salt: &[u8; 32],
    bundle_identifier: &[u8; 16],
) -> Result<BundleKeys, CoreError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), data_encryption_key);
    Ok(BundleKeys {
        content: expand_key(&hkdf, b"iniza IZ1 content key", bundle_identifier)?,
        manifest: expand_key(&hkdf, b"iniza IZ1 manifest key", bundle_identifier)?,
        index: expand_key(&hkdf, b"iniza IZ1 index key", bundle_identifier)?,
        completion: expand_key(&hkdf, b"iniza IZ1 completion key", bundle_identifier)?,
        checkpoint: expand_key(
            &hkdf,
            b"iniza IZ2 pack checkpoint key v1",
            bundle_identifier,
        )?,
    })
}

fn expand_key(
    hkdf: &Hkdf<Sha256>,
    label: &[u8],
    bundle_identifier: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let mut info = Vec::with_capacity(label.len() + bundle_identifier.len());
    info.extend_from_slice(label);
    info.extend_from_slice(bundle_identifier);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| invalid_bundle("IZ2 subkey derivation failed"))?;
    Ok(output)
}

fn derive_wrapping_key(
    recovery_secret: &[u8; 32],
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let params = Params::new(
        ARGON2_MEMORY_KIBIBYTES,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|_| invalid_bundle("IZ2 Argon2id parameters are invalid"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(recovery_secret, salt, output.as_mut())
        .map_err(|_| invalid_bundle("Argon2id key derivation failed"))?;
    Ok(output)
}

fn random_secret() -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut())
        .map_err(|_| invalid_bundle("operating-system entropy failed"))?;
    Ok(bytes)
}

fn random_array<const N: usize>() -> Result<[u8; N], CoreError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| invalid_bundle("operating-system entropy failed"))?;
    Ok(bytes)
}

fn encode_slot_prefix(method: RecoveryMethod, salt: &[u8; 16], nonce: &[u8; 24]) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(SLOT_LENGTH - 48);
    prefix.push(method.slot_id());
    prefix.push(method.slot_id());
    prefix.push(0x13);
    prefix.push(0);
    prefix.extend_from_slice(&ARGON2_MEMORY_KIBIBYTES.to_be_bytes());
    prefix.extend_from_slice(&ARGON2_ITERATIONS.to_be_bytes());
    prefix.extend_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
    prefix.extend_from_slice(salt);
    prefix.extend_from_slice(nonce);
    prefix.extend_from_slice(&48_u16.to_be_bytes());
    prefix
}

fn slot_aad(
    bundle_identifier: &[u8; 16],
    hkdf_salt: &[u8; 32],
    nonce_prefix: &[u8; 16],
    slot_prefix: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&SUITE_ID.to_be_bytes());
    aad.extend_from_slice(bundle_identifier);
    aad.extend_from_slice(hkdf_salt);
    aad.extend_from_slice(nonce_prefix);
    aad.extend_from_slice(slot_prefix);
    aad
}

struct RecordHeader {
    kind: u8,
    sequence: u64,
    item_ordinal: u32,
    chunk_ordinal: u32,
    plaintext_length: u32,
    ciphertext_length: u32,
}

fn encode_record_header(
    kind: u8,
    sequence: u64,
    item_ordinal: u32,
    chunk_ordinal: u32,
    plaintext_length: u32,
    ciphertext_length: u32,
) -> [u8; RECORD_HEADER_LENGTH] {
    let mut bytes = [0_u8; RECORD_HEADER_LENGTH];
    bytes[0] = kind;
    bytes[4..12].copy_from_slice(&sequence.to_be_bytes());
    bytes[12..16].copy_from_slice(&item_ordinal.to_be_bytes());
    bytes[16..20].copy_from_slice(&chunk_ordinal.to_be_bytes());
    bytes[20..24].copy_from_slice(&plaintext_length.to_be_bytes());
    bytes[24..28].copy_from_slice(&ciphertext_length.to_be_bytes());
    bytes
}

fn decode_record_header(bytes: &[u8; RECORD_HEADER_LENGTH]) -> Result<RecordHeader, CoreError> {
    if bytes[1..4] != [0; 3] {
        return Err(invalid_bundle(
            "Bundle record contains unknown critical flags",
        ));
    }
    let plaintext_length = u32::from_be_bytes(bytes[20..24].try_into().expect("fixed slice"));
    let ciphertext_length = u32::from_be_bytes(bytes[24..28].try_into().expect("fixed slice"));
    if ciphertext_length != plaintext_length.checked_add(16).unwrap_or(0) {
        return Err(invalid_bundle("Bundle record length is invalid"));
    }
    Ok(RecordHeader {
        kind: bytes[0],
        sequence: u64::from_be_bytes(bytes[4..12].try_into().expect("fixed slice")),
        item_ordinal: u32::from_be_bytes(bytes[12..16].try_into().expect("fixed slice")),
        chunk_ordinal: u32::from_be_bytes(bytes[16..20].try_into().expect("fixed slice")),
        plaintext_length,
        ciphertext_length,
    })
}

fn validate_record_limit(record: &RecordHeader) -> Result<(), CoreError> {
    let maximum = match record.kind {
        RECORD_CONTENT => MAX_PLAINTEXT_CHUNK,
        RECORD_MANIFEST => MAX_MANIFEST_PLAINTEXT,
        RECORD_INDEX => MAX_INDEX_PLAINTEXT,
        RECORD_COMPLETION => MAX_COMPLETION_PLAINTEXT,
        _ => return Err(invalid_bundle("Bundle contains an unknown critical record")),
    };
    if record.plaintext_length as usize > maximum {
        return Err(invalid_bundle("Bundle record exceeds its parser limit"));
    }
    Ok(())
}

fn record_aad(context: &RecordContext, record_header: &[u8; RECORD_HEADER_LENGTH]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 8 + 2 + 2 + 16 + RECORD_HEADER_LENGTH);
    aad.extend_from_slice(&context.header_hash);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&SUITE_ID.to_be_bytes());
    aad.extend_from_slice(&context.bundle_identifier);
    aad.extend_from_slice(record_header);
    aad
}

fn record_nonce(prefix: &[u8; 16], sequence: u64) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid_bundle("IZ2 encryption key length is invalid"))?;
    cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| invalid_bundle("IZ2 encryption failed"))
}

fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid_bundle("IZ2 decryption key length is invalid"))?;
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CoreError::AuthenticationFailed)
}

fn decrypt_record(
    record: &RecordHeader,
    raw_header: &[u8; RECORD_HEADER_LENGTH],
    ciphertext: &[u8],
    key: &[u8; 32],
    context: &RecordContext,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let aad = record_aad(context, raw_header);
    let nonce = record_nonce(&context.nonce_prefix, record.sequence);
    decrypt(key, &nonce, &aad, ciphertext).map(Zeroizing::new)
}

fn encode_completion(
    prefix_hash: &[u8; 32],
    record_count: u64,
    manifest_sequence: u64,
    index_sequence: u64,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(61);
    output.extend_from_slice(b"END2");
    output.extend_from_slice(prefix_hash);
    output.extend_from_slice(&record_count.to_be_bytes());
    output.extend_from_slice(&manifest_sequence.to_be_bytes());
    output.extend_from_slice(&index_sequence.to_be_bytes());
    output.push(1);
    output
}

fn decode_completion(
    bytes: &[u8],
    prefix_hash: &[u8; 32],
    record_count: u64,
    manifest_sequence: Option<u64>,
    index_sequence: Option<u64>,
) -> Result<(), CoreError> {
    if bytes.len() != 61 || &bytes[..4] != b"END2" || bytes[60] != 1 {
        return Err(invalid_bundle("Bundle completion record is invalid"));
    }
    if &bytes[4..36] != prefix_hash {
        return Err(invalid_bundle("Bundle completion prefix digest is invalid"));
    }
    if u64::from_be_bytes(bytes[36..44].try_into().expect("fixed slice")) != record_count
        || Some(u64::from_be_bytes(
            bytes[44..52].try_into().expect("fixed slice"),
        )) != manifest_sequence
        || Some(u64::from_be_bytes(
            bytes[52..60].try_into().expect("fixed slice"),
        )) != index_sequence
    {
        return Err(invalid_bundle("Bundle completion locations are invalid"));
    }
    Ok(())
}

fn decode_manifest(bytes: &[u8]) -> Result<Manifest, CoreError> {
    if bytes.len() > MAX_MANIFEST_PLAINTEXT {
        return Err(invalid_bundle("Bundle manifest exceeds its parser limit"));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| invalid_bundle("Bundle manifest is not canonical supported JSON"))
}

fn verified_copy_durability_name(durability: VerifiedCopyDurability) -> &'static str {
    match durability {
        VerifiedCopyDurability::Durable => "durable",
        VerifiedCopyDurability::Weaker => "weaker",
    }
}

pub(crate) fn verified_copy_destination_evidence_identity(
    destination: &Path,
) -> Result<String, CoreError> {
    let metadata = fs::symlink_metadata(destination).map_err(|source| CoreError::Io {
        action: "inspect Verified Copy destination identity",
        path: destination.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(invalid_bundle(
            "Verified Copy destination identity is not a regular file",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza verified copy destination evidence v1\0");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        hasher.update(&metadata.dev().to_be_bytes());
        hasher.update(&metadata.ino().to_be_bytes());
    }
    #[cfg(not(unix))]
    hasher.update(
        fs::canonicalize(destination)
            .map_err(|source| CoreError::Io {
                action: "resolve Verified Copy destination identity",
                path: destination.to_path_buf(),
                source,
            })?
            .to_string_lossy()
            .as_bytes(),
    );
    Ok(hasher.finalize().to_hex().to_string())
}

fn partial_path(destination: &Path) -> PathBuf {
    let mut value = destination.as_os_str().to_os_string();
    value.push(".partial");
    PathBuf::from(value)
}

fn reject_partial_path(source: &Path) -> Result<(), CoreError> {
    if source.file_name().is_some_and(|name| {
        let name = name.to_string_lossy();
        [
            ".iniza.partial",
            ".iniza.partial.resume",
            ".iniza.partial.previous",
            ".iniza.partial.checkpoint",
            ".iniza.partial.resume.checkpoint",
            ".iniza.partial.previous.checkpoint",
        ]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    }) {
        return Err(CoreError::BundleIncomplete(source.to_path_buf()));
    }
    Ok(())
}

fn invalid_bundle(message: impl Into<String>) -> CoreError {
    CoreError::BundleInvalid(message.into())
}

struct SliceCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SliceCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CoreError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| invalid_bundle("Bundle parser offset overflowed"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid_bundle("Bundle header is truncated"))?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid_bundle("Bundle fixed field is truncated"))
    }

    fn u8(&mut self) -> Result<u8, CoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CoreError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CoreError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}
