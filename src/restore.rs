use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use cap_std::fs::{MetadataExt as CapMetadataExt, PermissionsExt as CapPermissionsExt};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as StdMetadataExt, PermissionsExt};

use crate::bundle::{
    AuthenticatedContentSink, AuthenticatedRestoreItem, AuthenticatedRestoreKind,
    RestoreBundleReader,
};
use crate::restore_fs::RestoreDirectory;
use crate::{
    CoreError, DestinationCapacity, ExtendedAttribute, LocalDestinationCapacity, RecoveryMethod,
    RecoverySecret,
};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

const CONTROL_DIRECTORY: &str = ".iniza-restore";
const MAX_RESTORE_ITEMS: usize = 100_000;
const MAX_RESTORE_PATH_BYTES: usize = 4_096;
const MAX_RESTORE_PATH_DEPTH: usize = 128;
const MAX_RESTORE_LOGICAL_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;

pub struct RestoreRequest<'a> {
    source: PathBuf,
    destination: PathBuf,
    recovery_secret: &'a RecoverySecret,
    event_sink: Option<&'a mut dyn RestoreEventSink>,
    cancellation: Option<&'a dyn RestoreCancellation>,
    resume: bool,
}

impl<'a> RestoreRequest<'a> {
    pub fn new(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        recovery_secret: &'a RecoverySecret,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            recovery_secret,
            event_sink: None,
            cancellation: None,
            resume: false,
        }
    }

    pub fn with_event_sink(mut self, event_sink: &'a mut dyn RestoreEventSink) -> Self {
        self.event_sink = Some(event_sink);
        self
    }

    pub fn with_cancellation(mut self, cancellation: &'a dyn RestoreCancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub fn resume(mut self) -> Self {
        self.resume = true;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum RestoreEvent {
    DestinationIdentityRecorded,
    DestinationSecured,
    MaterializationPrepared,
    StagingValidated,
    PublicationCandidateMoved { candidate_top_level_entry: u64 },
    PublicationAdvanced { completed_top_level_entries: u64 },
    RollbackPrepared { remaining_top_level_entries: u64 },
}

impl RestoreEvent {
    pub fn machine_json_line(&self) -> String {
        let mut value =
            serde_json::to_value(self).expect("RestoreEvent serialization is infallible");
        value
            .as_object_mut()
            .expect("RestoreEvent serializes as an object")
            .insert("schema_version".to_owned(), serde_json::json!(1));
        value.to_string()
    }
}

pub trait RestoreEventSink {
    fn emit(&mut self, event: RestoreEvent);
}

pub trait RestoreCancellation {
    fn is_cancelled(&self) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreState {
    Complete,
    Paused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    state: RestoreState,
    restored_items: u64,
    restored_bytes: u64,
    disabled_hooks: u64,
    quarantined_executables: u64,
    unapplied_metadata: u64,
    bundle_identity: String,
    destination_evidence_identity: String,
    recovery_method: RecoveryMethod,
    occurred_at_unix_seconds: u64,
}

impl RestoreReport {
    pub fn state(&self) -> RestoreState {
        self.state
    }

    pub fn restored_items(&self) -> u64 {
        self.restored_items
    }

    pub fn restored_bytes(&self) -> u64 {
        self.restored_bytes
    }

    pub fn disabled_hooks(&self) -> u64 {
        self.disabled_hooks
    }

    pub fn unapplied_metadata(&self) -> u64 {
        self.unapplied_metadata
    }

    pub fn quarantined_executables(&self) -> u64 {
        self.quarantined_executables
    }

    pub fn bundle_identity(&self) -> &str {
        &self.bundle_identity
    }

    pub fn destination_evidence_identity(&self) -> &str {
        &self.destination_evidence_identity
    }

    pub fn recovery_method(&self) -> RecoveryMethod {
        self.recovery_method
    }

    pub fn occurred_at_unix_seconds(&self) -> u64 {
        self.occurred_at_unix_seconds
    }

    pub fn human_result(&self) -> String {
        let heading = match self.state {
            RestoreState::Complete => "Restore completed",
            RestoreState::Paused => "Restore paused safely",
        };
        format!(
            "{heading}\n  restored items          {}\n  restored bytes          {}\n  disabled hooks          {}\n  quarantined executables {}\n  unapplied metadata      {}",
            self.restored_items,
            self.restored_bytes,
            self.disabled_hooks,
            self.quarantined_executables,
            self.unapplied_metadata,
        )
    }

    pub fn machine_json_result(&self) -> String {
        let state = match self.state {
            RestoreState::Complete => "complete",
            RestoreState::Paused => "paused",
        };
        serde_json::json!({
            "schema_version": 1,
            "command": "restore",
            "status": if self.state == RestoreState::Complete { "success" } else { "paused" },
            "data": {
                "state": state,
                "restored_items": self.restored_items,
                "restored_bytes": self.restored_bytes,
                "disabled_hooks": self.disabled_hooks,
                "quarantined_executables": self.quarantined_executables,
                "unapplied_metadata": self.unapplied_metadata,
            },
            "warnings": [],
            "errors": [],
        })
        .to_string()
    }
}

#[derive(Debug)]
pub struct RestoreEngine<C = LocalDestinationCapacity> {
    capacity: C,
}

impl RestoreEngine<LocalDestinationCapacity> {
    pub fn local() -> Self {
        Self {
            capacity: LocalDestinationCapacity,
        }
    }
}

impl<C> RestoreEngine<C> {
    pub fn with_capacity(capacity: C) -> Self {
        Self { capacity }
    }
}

impl<C: DestinationCapacity> RestoreEngine<C> {
    pub fn restore(&self, mut request: RestoreRequest<'_>) -> Result<RestoreReport, CoreError> {
        let mut bundle = RestoreBundleReader::open(&request.source)?;
        let authenticated = bundle.authenticate_plan(request.recovery_secret)?;
        let planned = validate_restore_items(&authenticated.items)?;
        ensure_restore_capacity(&self.capacity, &request.destination, &planned)?;
        if !request.resume {
            prepare_destination(&request.destination)?;
        }
        let destination_identity = destination_identity(&request.destination)?;
        let destination_evidence_identity = destination_evidence_identity(&destination_identity);
        if let Some(sink) = request.event_sink.as_deref_mut() {
            sink.emit(RestoreEvent::DestinationIdentityRecorded);
        }
        let destination_directory =
            RestoreDirectory::open_ambient(&request.destination).map_err(|source| {
                CoreError::Io {
                    action: "open secured Restore destination",
                    path: request.destination.clone(),
                    source,
                }
            })?;
        if destination_directory_identity(&destination_directory, &request.destination)?
            != destination_identity
        {
            return Err(invalid_restore(
                "opened Restore destination does not match its secured identity",
            ));
        }
        if let Some(sink) = request.event_sink.as_deref_mut() {
            sink.emit(RestoreEvent::DestinationSecured);
        }
        let resume_journal = if request.resume {
            Some(validate_resume_destination(
                &request,
                &planned,
                &authenticated.bundle_hash,
                &destination_directory,
            )?)
        } else {
            None
        };

        let mut preserve_recovery_state = false;
        let recovery_method = request.recovery_secret.method();
        let result = restore_transaction(
            &mut request,
            &mut bundle,
            RestoreTransactionContext {
                planned: &planned,
                destination_identity: &destination_identity,
                destination_directory: &destination_directory,
                expected_bundle_hash: &authenticated.bundle_hash,
                bundle_identity: &authenticated.bundle_identity,
                destination_evidence_identity: &destination_evidence_identity,
                recovery_method,
                resume_journal: resume_journal.as_ref(),
            },
            &mut preserve_recovery_state,
        );
        match result {
            Ok(report) => Ok(report),
            Err(error) => {
                if !request.resume && !preserve_recovery_state {
                    cleanup_failed_restore(&request.destination, &destination_directory)?;
                }
                Err(error)
            }
        }
    }
}

fn cleanup_failed_restore(
    destination: &Path,
    destination_directory: &RestoreDirectory,
) -> Result<(), CoreError> {
    match destination_directory.symlink_metadata(Path::new(CONTROL_DIRECTORY)) {
        Ok(metadata) if metadata.is_dir() => destination_directory
            .remove_dir_all(Path::new(CONTROL_DIRECTORY))
            .map_err(|source| CoreError::Io {
                action: "remove failed Restore transaction control",
                path: destination.join(CONTROL_DIRECTORY),
                source,
            })?,
        Ok(_) => {
            return Err(invalid_restore(
                "failed Restore transaction control changed to an unsafe filesystem item",
            ));
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(CoreError::Io {
                action: "inspect failed Restore transaction control",
                path: destination.join(CONTROL_DIRECTORY),
                source,
            });
        }
    }
    destination_directory
        .sync()
        .map_err(|source| CoreError::Io {
            action: "synchronize failed Restore cleanup",
            path: destination.to_path_buf(),
            source,
        })?;

    Ok(())
}

fn ensure_restore_capacity(
    capacity: &dyn DestinationCapacity,
    destination: &Path,
    planned: &[PlannedItem],
) -> Result<(), CoreError> {
    let required = planned
        .iter()
        .filter(|item| item.kind == PlannedKind::RegularFile)
        .try_fold(0_u64, |total, item| total.checked_add(item.estimated_size))
        .ok_or_else(|| invalid_restore("Restore capacity estimate overflowed"))?;
    let available = capacity
        .available_bytes(destination)
        .map_err(|source| CoreError::Io {
            action: "inspect Restore destination capacity",
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

#[derive(Debug)]
struct PlannedItem {
    ordinal: u32,
    relative_path: PathBuf,
    kind: PlannedKind,
    estimated_size: u64,
    content_hash: Option<String>,
    posix_mode: Option<u32>,
    repository_hook: bool,
    executable_content: bool,
    symlink_target: Option<PathBuf>,
    extended_attributes: Option<Vec<ExtendedAttribute>>,
    access_control_captured: Option<bool>,
    access_control: Option<String>,
}

impl PlannedItem {
    fn restored_regular_file_mode(&self) -> Option<u32> {
        self.posix_mode.map(|mode| {
            if self.executable_content {
                mode & !0o111
            } else {
                mode
            }
        })
    }

    fn validation_regular_file_mode(&self) -> u32 {
        0o600
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlannedKind {
    Directory,
    RegularFile,
    SymbolicLink,
}

#[derive(Debug)]
struct ValidatedRestoreItem {
    relative_path: PathBuf,
    kind: PlannedKind,
    final_mode: Option<u32>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DestinationIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    canonical_path: PathBuf,
}

fn destination_identity(destination: &Path) -> Result<DestinationIdentity, CoreError> {
    let metadata = fs::symlink_metadata(destination).map_err(|source| CoreError::Io {
        action: "inspect Restore destination identity",
        path: destination.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(invalid_restore(
            "Restore destination identity changed to an unsafe filesystem item",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(DestinationIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(DestinationIdentity {
            canonical_path: fs::canonicalize(destination).map_err(|source| CoreError::Io {
                action: "resolve Restore destination identity",
                path: destination.to_path_buf(),
                source,
            })?,
        })
    }
}

fn destination_evidence_identity(identity: &DestinationIdentity) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza restore destination evidence v1\0");
    #[cfg(unix)]
    {
        hasher.update(&identity.device.to_be_bytes());
        hasher.update(&identity.inode.to_be_bytes());
    }
    #[cfg(not(unix))]
    hasher.update(identity.canonical_path.to_string_lossy().as_bytes());
    hasher.finalize().to_hex().to_string()
}

pub(crate) fn current_restore_destination_evidence_identity(
    destination: &Path,
) -> Result<String, CoreError> {
    destination_identity(destination).map(|identity| destination_evidence_identity(&identity))
}

fn restore_time() -> Result<u64, CoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| invalid_restore("system clock precedes Unix epoch"))
}

fn require_destination_identity(
    destination: &Path,
    expected: &DestinationIdentity,
) -> Result<(), CoreError> {
    if &destination_identity(destination)? != expected {
        return Err(invalid_restore(
            "Restore destination identity changed before publication",
        ));
    }
    Ok(())
}

fn destination_directory_identity(
    directory: &RestoreDirectory,
    display_path: &Path,
) -> Result<DestinationIdentity, CoreError> {
    let metadata = directory.metadata().map_err(|source| CoreError::Io {
        action: "inspect opened Restore destination identity",
        path: display_path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(DestinationIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(DestinationIdentity {
            canonical_path: fs::canonicalize(display_path).map_err(|source| CoreError::Io {
                action: "resolve opened Restore destination identity",
                path: display_path.to_path_buf(),
                source,
            })?,
        })
    }
}

fn validate_restore_items(
    items: &[AuthenticatedRestoreItem],
) -> Result<Vec<PlannedItem>, CoreError> {
    if items.len() > MAX_RESTORE_ITEMS {
        return Err(invalid_restore(
            "Bundle exceeds the Restore item-count limit",
        ));
    }
    if items.iter().any(|item| {
        matches!(
            item.kind,
            AuthenticatedRestoreKind::Special | AuthenticatedRestoreKind::Unknown
        )
    }) {
        return Err(invalid_restore(
            "Bundle contains an unsafe device or socket Migration Item",
        ));
    }
    let mut paths = BTreeSet::new();
    let mut collision_keys = BTreeSet::new();
    let mut planned = Vec::new();
    let mut logical_bytes = 0_u64;
    for item in items.iter().filter(|item| item.selected) {
        let relative_path = validate_relative_path(&item.relative_path)?;
        if item.relative_path.len() > MAX_RESTORE_PATH_BYTES
            || relative_path.components().count() > MAX_RESTORE_PATH_DEPTH
        {
            return Err(invalid_restore("Bundle exceeds a Restore path limit"));
        }
        if !paths.insert(relative_path.clone()) {
            return Err(invalid_restore(
                "Bundle manifest contains duplicate restore paths",
            ));
        }
        if !collision_keys.insert(portable_collision_key(&item.relative_path)) {
            return Err(invalid_restore(
                "Bundle manifest contains a case or Unicode normalization collision",
            ));
        }
        let kind = match item.kind {
            AuthenticatedRestoreKind::Directory => PlannedKind::Directory,
            AuthenticatedRestoreKind::RegularFile => PlannedKind::RegularFile,
            AuthenticatedRestoreKind::SymbolicLink => PlannedKind::SymbolicLink,
            AuthenticatedRestoreKind::Special | AuthenticatedRestoreKind::Unknown => {
                return Err(invalid_restore(
                    "Bundle manifest selects an unsupported Migration Item kind",
                ));
            }
        };
        let symlink_target = if kind == PlannedKind::SymbolicLink {
            let target = item.symlink_target.as_deref().ok_or_else(|| {
                invalid_restore("selected symbolic link has no authenticated target")
            })?;
            Some(validate_symlink_target(&relative_path, target)?)
        } else {
            if item.symlink_target.is_some() {
                return Err(invalid_restore(
                    "non-symbolic Migration Item has a symbolic-link target",
                ));
            }
            None
        };
        let repository_hook =
            kind == PlannedKind::RegularFile && is_repository_hook(&relative_path);
        let executable_content = kind == PlannedKind::RegularFile
            && item.posix_mode.is_some_and(|mode| mode & 0o111 != 0);
        if kind == PlannedKind::RegularFile {
            logical_bytes = logical_bytes
                .checked_add(item.estimated_size)
                .ok_or_else(|| invalid_restore("Restore logical size overflowed"))?;
            if logical_bytes > MAX_RESTORE_LOGICAL_BYTES {
                return Err(invalid_restore(
                    "Bundle exceeds the Restore logical-size limit",
                ));
            }
        }
        planned.push(PlannedItem {
            ordinal: item.ordinal,
            relative_path,
            kind,
            estimated_size: item.estimated_size,
            content_hash: item.content_hash.clone(),
            posix_mode: item.posix_mode,
            repository_hook,
            executable_content,
            symlink_target,
            extended_attributes: item.extended_attributes.clone(),
            access_control_captured: item.access_control_captured,
            access_control: item.access_control.clone(),
        });
    }
    Ok(planned)
}

fn portable_collision_key(value: &str) -> String {
    value.nfc().flat_map(char::to_lowercase).collect::<String>()
}

fn validate_symlink_target(link_path: &Path, value: &str) -> Result<PathBuf, CoreError> {
    let target = Path::new(value);
    if value.is_empty() || target.is_absolute() {
        return Err(invalid_restore(
            "Bundle manifest contains an unsafe symbolic-link target",
        ));
    }
    let mut resolved = link_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for component in target.components() {
        match component {
            Component::Normal(value) => resolved.push(value.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if resolved.pop().is_none() {
                    return Err(invalid_restore(
                        "Bundle symbolic link escapes the Restore destination",
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_restore(
                    "Bundle manifest contains an unsafe symbolic-link target",
                ));
            }
        }
    }
    if resolved
        .first()
        .is_some_and(|component| component == CONTROL_DIRECTORY)
    {
        return Err(invalid_restore(
            "Bundle symbolic link targets Restore transaction control",
        ));
    }
    Ok(target.to_path_buf())
}

fn validate_relative_path(value: &str) -> Result<PathBuf, CoreError> {
    if value == "." {
        return Ok(PathBuf::new());
    }
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid_restore(
            "Bundle manifest contains an unsafe restore path",
        ));
    }
    if path
        .components()
        .next()
        .is_some_and(|component| component.as_os_str() == CONTROL_DIRECTORY)
    {
        return Err(invalid_restore(
            "Bundle manifest path conflicts with Restore transaction control",
        ));
    }
    Ok(path.to_path_buf())
}

fn is_repository_hook(path: &Path) -> bool {
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    components
        .windows(3)
        .any(|window| window[0] == ".git" && window[1] == "hooks")
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreJournal {
    schema_version: u32,
    bundle_hash: String,
    staged_items: u64,
    staged_bytes: u64,
    phase: RestoreJournalPhase,
    published_top_level_entries: u64,
    publication_intent: Option<u64>,
    authentication_tag: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RestoreJournalPhase {
    Materializing,
    Staged,
    Publishing,
    RollingBack,
}

#[derive(Debug, Clone, Copy)]
struct JournalCheckpoint {
    staged_bytes: u64,
    staged_items: u64,
    phase: RestoreJournalPhase,
    published_top_level_entries: u64,
    publication_intent: Option<u64>,
}

fn validate_resume_destination(
    request: &RestoreRequest<'_>,
    planned: &[PlannedItem],
    expected_bundle_hash: &[u8; 32],
    destination_directory: &RestoreDirectory,
) -> Result<RestoreJournal, CoreError> {
    let control = request.destination.join(CONTROL_DIRECTORY);
    let control_metadata = destination_directory
        .symlink_metadata(Path::new(CONTROL_DIRECTORY))
        .map_err(|source| CoreError::Io {
            action: "inspect Restore transaction control for resume",
            path: control.clone(),
            source,
        })?;
    if !control_metadata.is_dir() {
        return Err(invalid_restore(
            "Restore transaction control is not a directory",
        ));
    }
    let control_directory = destination_directory
        .open_dir(Path::new(CONTROL_DIRECTORY))
        .map_err(|source| CoreError::Io {
            action: "open Restore transaction control for resume",
            path: control.clone(),
            source,
        })?;
    let control_entries = control_directory
        .entry_names(3)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::InvalidData {
                invalid_restore("Restore transaction state contains unrelated entries")
            } else {
                CoreError::Io {
                    action: "inspect Restore transaction entry for resume",
                    path: control.clone(),
                    source,
                }
            }
        })?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expected = ["journal.json".into(), "staging".into()]
        .into_iter()
        .collect::<BTreeSet<std::ffi::OsString>>();
    let mut allowed_control_entries = expected.clone();
    allowed_control_entries.insert("journal.json.partial".into());
    if !expected.is_subset(&control_entries) || !control_entries.is_subset(&allowed_control_entries)
    {
        return Err(invalid_restore(
            "Restore transaction state contains unrelated entries",
        ));
    }
    let staging = control.join("staging");
    if !control_directory
        .symlink_metadata(Path::new("staging"))
        .map_err(|source| CoreError::Io {
            action: "inspect Restore staging for resume",
            path: staging.clone(),
            source,
        })?
        .is_dir()
    {
        return Err(invalid_restore("Restore staging is not a directory"));
    }
    let journal_path = control.join("journal.json");
    let journal_file = control_directory
        .open_file(Path::new("journal.json"))
        .map_err(|source| CoreError::Io {
            action: "open Restore journal for resume",
            path: journal_path.clone(),
            source,
        })?;
    let mut bytes = Vec::new();
    journal_file
        .take((16 * 1024 + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CoreError::Io {
            action: "read Restore journal for resume",
            path: journal_path.clone(),
            source,
        })?;
    if bytes.len() > 16 * 1024 {
        return Err(invalid_restore("Restore journal exceeds its size limit"));
    }
    let journal: RestoreJournal = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_restore("Restore journal is invalid"))?;
    let canonical_journal = serde_json::to_vec(&journal)
        .map_err(|_| invalid_restore("Restore journal cannot be canonicalized"))?;
    if bytes != canonical_journal {
        return Err(invalid_restore("Restore journal is not canonical"));
    }
    let expected_staged_bytes = planned
        .iter()
        .filter(|item| item.kind == PlannedKind::RegularFile)
        .try_fold(0_u64, |total, item| total.checked_add(item.estimated_size))
        .ok_or_else(|| invalid_restore("Restore staged byte count overflowed"))?;
    if journal.schema_version != 2
        || journal.bundle_hash != bundle_hash_hex(expected_bundle_hash)
        || journal.staged_items != planned.len() as u64
        || journal.staged_bytes != expected_staged_bytes
        || journal.authentication_tag
            != journal_authentication_tag(
                request.recovery_secret,
                &journal.bundle_hash,
                journal.staged_items,
                journal.staged_bytes,
                journal.phase,
                journal.published_top_level_entries,
                journal.publication_intent,
            )
    {
        return Err(invalid_restore(
            "Restore journal does not authenticate for this Bundle and Recovery Secret",
        ));
    }
    let top_level = top_level_entry_names(planned)?;
    let published = usize::try_from(journal.published_top_level_entries)
        .map_err(|_| invalid_restore("Restore journal publication count is invalid"))?;
    let state_is_valid = match journal.phase {
        RestoreJournalPhase::Materializing | RestoreJournalPhase::Staged => {
            published == 0 && journal.publication_intent.is_none()
        }
        RestoreJournalPhase::Publishing => {
            published <= top_level.len()
                && journal.publication_intent.is_none_or(|intent| {
                    intent == journal.published_top_level_entries
                        && (intent as usize) < top_level.len()
                })
        }
        RestoreJournalPhase::RollingBack => {
            published > 0
                && published <= top_level.len()
                && journal.publication_intent.is_some_and(|intent| {
                    intent.checked_add(1) == Some(journal.published_top_level_entries)
                })
        }
    };
    if !state_is_valid {
        return Err(invalid_restore(
            "Restore journal publication state is invalid",
        ));
    }
    let (required_published, allowed_published) = match journal.phase {
        RestoreJournalPhase::RollingBack => (published - 1, published),
        RestoreJournalPhase::Publishing if journal.publication_intent.is_some() => {
            (published, published + 1)
        }
        _ => (published, published),
    };
    let mut allowed = BTreeSet::from([CONTROL_DIRECTORY.into()]);
    allowed.extend(top_level.iter().take(allowed_published).cloned());
    let actual = destination_directory
        .entry_names(allowed.len())
        .map_err(|source| {
            if source.kind() == io::ErrorKind::InvalidData {
                invalid_restore("Restore resume destination contains unrelated entries")
            } else {
                CoreError::Io {
                    action: "inspect Restore destination for resume",
                    path: request.destination.clone(),
                    source,
                }
            }
        })?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if !actual.is_subset(&allowed)
        || !top_level
            .iter()
            .take(required_published)
            .all(|name| actual.contains(name))
    {
        return Err(invalid_restore(
            "Restore resume destination contains unrelated entries",
        ));
    }
    let visible_names = actual
        .iter()
        .filter(|name| name.as_os_str() != std::ffi::OsStr::new(CONTROL_DIRECTORY))
        .cloned()
        .collect::<BTreeSet<_>>();
    normalize_resume_modes(planned, destination_directory, &visible_names)?;
    validate_published_entries(planned, destination_directory, &visible_names)?;
    if control_entries.contains(std::ffi::OsStr::new("journal.json.partial")) {
        control_directory
            .remove_file(Path::new("journal.json.partial"))
            .map_err(|source| CoreError::Io {
                action: "discard interrupted partial Restore journal",
                path: control.join("journal.json.partial"),
                source,
            })?;
        control_directory.sync().map_err(|source| CoreError::Io {
            action: "synchronize partial Restore journal cleanup",
            path: control,
            source,
        })?;
    }
    Ok(journal)
}

fn top_level_entry_names(planned: &[PlannedItem]) -> Result<Vec<std::ffi::OsString>, CoreError> {
    let mut names = BTreeSet::new();
    for item in planned {
        let Some(component) = item.relative_path.components().next() else {
            continue;
        };
        let Component::Normal(name) = component else {
            return Err(invalid_restore("Restore item path is not relative"));
        };
        names.insert(name.to_os_string());
    }
    Ok(names.into_iter().collect())
}

fn write_authenticated_journal(
    request: &RestoreRequest<'_>,
    control_directory: &RestoreDirectory,
    bundle_hash: &[u8; 32],
    checkpoint: JournalCheckpoint,
) -> Result<(), CoreError> {
    let control = request.destination.join(CONTROL_DIRECTORY);
    let journal_path = control.join("journal.json");
    let partial = control.join("journal.json.partial");
    let bundle_hash = bundle_hash_hex(bundle_hash);
    let journal = RestoreJournal {
        schema_version: 2,
        authentication_tag: journal_authentication_tag(
            request.recovery_secret,
            &bundle_hash,
            checkpoint.staged_items,
            checkpoint.staged_bytes,
            checkpoint.phase,
            checkpoint.published_top_level_entries,
            checkpoint.publication_intent,
        ),
        bundle_hash,
        staged_items: checkpoint.staged_items,
        staged_bytes: checkpoint.staged_bytes,
        phase: checkpoint.phase,
        published_top_level_entries: checkpoint.published_top_level_entries,
        publication_intent: checkpoint.publication_intent,
    };
    let bytes = serde_json::to_vec(&journal)
        .map_err(|error| invalid_restore(format!("could not encode Restore journal: {error}")))?;
    let mut output = control_directory
        .create_restricted_file(Path::new("journal.json.partial"))
        .map_err(|source| CoreError::Io {
            action: "create partial Restore journal",
            path: partial.clone(),
            source,
        })?;
    output.write_all(&bytes).map_err(|source| CoreError::Io {
        action: "write partial Restore journal",
        path: partial.clone(),
        source,
    })?;
    output.sync_all().map_err(|source| CoreError::Io {
        action: "synchronize partial Restore journal",
        path: partial.clone(),
        source,
    })?;
    control_directory
        .rename(
            Path::new("journal.json.partial"),
            control_directory,
            Path::new("journal.json"),
        )
        .map_err(|source| CoreError::Io {
            action: "publish authenticated Restore journal",
            path: journal_path,
            source,
        })?;
    control_directory.sync().map_err(|source| CoreError::Io {
        action: "synchronize authenticated Restore journal directory",
        path: control,
        source,
    })?;
    Ok(())
}

fn journal_authentication_tag(
    recovery_secret: &RecoverySecret,
    bundle_hash: &str,
    staged_items: u64,
    staged_bytes: u64,
    phase: RestoreJournalPhase,
    published_top_level_entries: u64,
    publication_intent: Option<u64>,
) -> String {
    let key = blake3::derive_key(
        "iniza Restore journal authentication version 2",
        recovery_secret.bytes.as_ref(),
    );
    let phase = match phase {
        RestoreJournalPhase::Materializing => "materializing",
        RestoreJournalPhase::Staged => "staged",
        RestoreJournalPhase::Publishing => "publishing",
        RestoreJournalPhase::RollingBack => "rolling-back",
    };
    let intent = publication_intent
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned());
    let payload = format!(
        "2\n{bundle_hash}\n{staged_items}\n{staged_bytes}\n{phase}\n{published_top_level_entries}\n{intent}\n"
    );
    blake3::keyed_hash(&key, payload.as_bytes())
        .to_hex()
        .to_string()
}

fn bundle_hash_hex(bundle_hash: &[u8; 32]) -> String {
    blake3::Hash::from_bytes(*bundle_hash).to_hex().to_string()
}

fn prepare_destination(destination: &Path) -> Result<(), CoreError> {
    let parent_path = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination
        .file_name()
        .ok_or_else(|| invalid_restore("Restore destination must have a final path component"))?;
    let parent = RestoreDirectory::open_ambient(parent_path).map_err(|source| CoreError::Io {
        action: "open Restore destination parent",
        path: parent_path.to_path_buf(),
        source,
    })?;
    match parent.create_restrictive_dir(Path::new(name)) {
        Ok(()) => {
            parent.sync().map_err(|source| CoreError::Io {
                action: "synchronize Restore destination parent",
                path: parent_path.to_path_buf(),
                source,
            })?;
            Ok(())
        }
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata =
                parent
                    .symlink_metadata(Path::new(name))
                    .map_err(|source| CoreError::Io {
                        action: "inspect existing Restore destination",
                        path: destination.to_path_buf(),
                        source,
                    })?;
            if !metadata.is_dir() {
                return Err(CoreError::DestinationAlreadyExists(
                    destination.to_path_buf(),
                ));
            }
            let existing = parent
                .open_dir(Path::new(name))
                .map_err(|source| CoreError::Io {
                    action: "inspect existing Restore destination",
                    path: destination.to_path_buf(),
                    source,
                })?;
            if !existing.is_empty().map_err(|source| CoreError::Io {
                action: "inspect existing Restore destination",
                path: destination.to_path_buf(),
                source,
            })? {
                return Err(CoreError::DestinationAlreadyExists(
                    destination.to_path_buf(),
                ));
            }
            Ok(())
        }
        Err(source) => Err(CoreError::Io {
            action: "create Restore destination",
            path: destination.to_path_buf(),
            source,
        }),
    }
}

struct RestoreTransactionContext<'a> {
    planned: &'a [PlannedItem],
    destination_identity: &'a DestinationIdentity,
    destination_directory: &'a RestoreDirectory,
    expected_bundle_hash: &'a [u8; 32],
    bundle_identity: &'a str,
    destination_evidence_identity: &'a str,
    recovery_method: RecoveryMethod,
    resume_journal: Option<&'a RestoreJournal>,
}

fn restore_transaction(
    request: &mut RestoreRequest<'_>,
    bundle: &mut RestoreBundleReader,
    context: RestoreTransactionContext<'_>,
    preserve_recovery_state: &mut bool,
) -> Result<RestoreReport, CoreError> {
    let RestoreTransactionContext {
        planned,
        destination_identity,
        destination_directory,
        expected_bundle_hash,
        bundle_identity,
        destination_evidence_identity,
        recovery_method,
        resume_journal,
    } = context;
    let control = request.destination.join(CONTROL_DIRECTORY);
    let staging = control.join("staging");
    let control_directory = if request.resume {
        let control_directory = destination_directory
            .open_dir(Path::new(CONTROL_DIRECTORY))
            .map_err(|source| CoreError::Io {
                action: "open Restore transaction control",
                path: control.clone(),
                source,
            })?;
        let destination_path = request.destination.clone();
        reconcile_interrupted_publication(
            request,
            planned,
            destination_directory,
            &control_directory,
            resume_journal.ok_or_else(|| invalid_restore("Restore resume journal is missing"))?,
            &destination_path,
            expected_bundle_hash,
        )?;
        control_directory
            .remove_dir_all(Path::new("staging"))
            .map_err(|source| CoreError::Io {
                action: "reset authenticated Restore staging for resume",
                path: staging.clone(),
                source,
            })?;
        control_directory.sync().map_err(|source| CoreError::Io {
            action: "synchronize reset Restore transaction control",
            path: control.clone(),
            source,
        })?;
        control_directory
    } else {
        destination_directory
            .create_restrictive_dir(Path::new(CONTROL_DIRECTORY))
            .map_err(|source| CoreError::Io {
                action: "create Restore transaction control",
                path: control.clone(),
                source,
            })?;
        destination_directory
            .open_dir(Path::new(CONTROL_DIRECTORY))
            .map_err(|source| CoreError::Io {
                action: "open Restore transaction control",
                path: control.clone(),
                source,
            })?
    };
    destination_directory
        .sync()
        .map_err(|source| CoreError::Io {
            action: "synchronize Restore destination control",
            path: request.destination.clone(),
            source,
        })?;
    control_directory
        .create_restrictive_dir(Path::new("staging"))
        .map_err(|source| CoreError::Io {
            action: "create Restore staging directory",
            path: staging.clone(),
            source,
        })?;
    let staging_directory = control_directory
        .open_dir(Path::new("staging"))
        .map_err(|source| CoreError::Io {
            action: "open Restore staging directory",
            path: staging.clone(),
            source,
        })?;
    control_directory.sync().map_err(|source| CoreError::Io {
        action: "synchronize Restore staging directory",
        path: control.clone(),
        source,
    })?;
    let expected_staged_bytes = planned
        .iter()
        .filter(|item| item.kind == PlannedKind::RegularFile)
        .try_fold(0_u64, |total, item| total.checked_add(item.estimated_size))
        .ok_or_else(|| invalid_restore("Restore staged byte count overflowed"))?;
    write_authenticated_journal(
        request,
        &control_directory,
        expected_bundle_hash,
        JournalCheckpoint {
            staged_bytes: expected_staged_bytes,
            staged_items: planned.len() as u64,
            phase: RestoreJournalPhase::Materializing,
            published_top_level_entries: 0,
            publication_intent: None,
        },
    )?;
    if let Some(sink) = request.event_sink.as_deref_mut() {
        sink.emit(RestoreEvent::MaterializationPrepared);
    }

    let mut directories = planned
        .iter()
        .filter(|item| item.kind == PlannedKind::Directory)
        .collect::<Vec<_>>();
    directories.sort_by_key(|item| item.relative_path.components().count());
    for item in directories {
        if !item.relative_path.as_os_str().is_empty() {
            staging_directory
                .create_restrictive_dir_all(&item.relative_path)
                .map_err(|source| CoreError::Io {
                    action: "create restrictive staged directory",
                    path: staging.join(&item.relative_path),
                    source,
                })?;
        }
    }

    let mut sink = StagedFileSink::new(&staging_directory);
    for item in planned
        .iter()
        .filter(|item| item.kind == PlannedKind::RegularFile)
    {
        let path = staging.join(&item.relative_path);
        let file = staging_directory
            .create_restricted_file(&item.relative_path)
            .map_err(|source| CoreError::Io {
                action: "create restricted staged Migration Item",
                path: path.clone(),
                source,
            })?;
        sink.add(
            item.ordinal,
            item.relative_path.clone(),
            path,
            &file,
            item.estimated_size,
        )?;
    }
    for item in planned
        .iter()
        .filter(|item| item.kind == PlannedKind::SymbolicLink)
    {
        let target = item
            .symlink_target
            .as_deref()
            .ok_or_else(|| invalid_restore("selected symbolic link has no target"))?;
        let path = staging.join(&item.relative_path);
        #[cfg(unix)]
        staging_directory
            .create_symlink(target, &item.relative_path)
            .map_err(|source| CoreError::Io {
                action: "create staged symbolic link",
                path: path.clone(),
                source,
            })?;
        #[cfg(not(unix))]
        return Err(invalid_restore(
            "symbolic-link Restore is unsupported on this platform",
        ));
    }

    let authenticated_content =
        bundle.stream_authenticated_content(request.recovery_secret, &mut sink)?;
    sink.finish()?;
    if authenticated_content.bundle_hash != *expected_bundle_hash {
        return Err(invalid_restore(
            "Bundle changed between Restore authentication passes",
        ));
    }
    let restored_bytes = authenticated_content.authenticated_bytes;
    validate_staged_items(planned, &staging_directory)?;
    write_authenticated_journal(
        request,
        &control_directory,
        expected_bundle_hash,
        JournalCheckpoint {
            staged_bytes: restored_bytes,
            staged_items: planned.len() as u64,
            phase: RestoreJournalPhase::Staged,
            published_top_level_entries: 0,
            publication_intent: None,
        },
    )?;
    if let Some(sink) = request.event_sink.as_deref_mut() {
        sink.emit(RestoreEvent::StagingValidated);
    }
    validate_staged_items(planned, &staging_directory)?;
    if request
        .cancellation
        .is_some_and(RestoreCancellation::is_cancelled)
    {
        return Ok(RestoreReport {
            state: RestoreState::Paused,
            restored_items: 0,
            restored_bytes,
            disabled_hooks: planned.iter().filter(|item| item.repository_hook).count() as u64,
            quarantined_executables: planned
                .iter()
                .filter(|item| item.executable_content)
                .count() as u64,
            unapplied_metadata: 0,
            bundle_identity: bundle_identity.to_owned(),
            destination_evidence_identity: destination_evidence_identity.to_owned(),
            recovery_method,
            occurred_at_unix_seconds: restore_time()?,
        });
    }
    require_destination_identity(&request.destination, destination_identity)?;
    let destination_path = request.destination.clone();
    let publication = publish_staged_entries(
        request,
        &staging_directory,
        destination_directory,
        PublicationContext {
            control: &control_directory,
            destination_path: &destination_path,
            bundle_hash: expected_bundle_hash,
            staged_bytes: restored_bytes,
            staged_items: planned.len() as u64,
            planned,
        },
        preserve_recovery_state,
    )?;
    let validated_items = match publication {
        PublicationOutcome::Paused => {
            return Ok(RestoreReport {
                state: RestoreState::Paused,
                restored_items: 0,
                restored_bytes,
                disabled_hooks: planned.iter().filter(|item| item.repository_hook).count() as u64,
                quarantined_executables: planned
                    .iter()
                    .filter(|item| item.executable_content)
                    .count() as u64,
                unapplied_metadata: 0,
                bundle_identity: bundle_identity.to_owned(),
                destination_evidence_identity: destination_evidence_identity.to_owned(),
                recovery_method,
                occurred_at_unix_seconds: restore_time()?,
            });
        }
        PublicationOutcome::Complete(validated_items) => validated_items,
    };
    let item_unapplied_metadata =
        finalize_validated_items(planned, destination_directory, &validated_items)?;
    validate_finalized_items(planned, destination_directory, &validated_items)?;
    apply_directory_modes(destination_directory, &validated_items)?;
    control_directory
        .remove_dir(Path::new("staging"))
        .map_err(|source| CoreError::Io {
            action: "remove empty Restore staging directory",
            path: staging.clone(),
            source,
        })?;
    control_directory.sync().map_err(|source| CoreError::Io {
        action: "synchronize completed Restore staging removal",
        path: control.clone(),
        source,
    })?;
    let journal = control.join("journal.json");
    control_directory
        .remove_file(Path::new("journal.json"))
        .map_err(|source| CoreError::Io {
            action: "remove completed Restore journal",
            path: journal,
            source,
        })?;
    control_directory.sync().map_err(|source| CoreError::Io {
        action: "synchronize completed Restore journal removal",
        path: control.clone(),
        source,
    })?;
    destination_directory
        .remove_dir(Path::new(CONTROL_DIRECTORY))
        .map_err(|source| CoreError::Io {
            action: "remove completed Restore transaction control",
            path: control,
            source,
        })?;
    destination_directory
        .sync()
        .map_err(|source| CoreError::Io {
            action: "synchronize completed Restore transaction removal",
            path: request.destination.clone(),
            source,
        })?;
    let unapplied_metadata = item_unapplied_metadata
        .saturating_add(apply_root_directory_mode(planned, destination_directory))
        .saturating_add(apply_root_platform_metadata(planned, destination_directory));

    Ok(RestoreReport {
        state: RestoreState::Complete,
        restored_items: planned.len() as u64,
        restored_bytes,
        disabled_hooks: planned.iter().filter(|item| item.repository_hook).count() as u64,
        quarantined_executables: planned
            .iter()
            .filter(|item| item.executable_content)
            .count() as u64,
        unapplied_metadata,
        bundle_identity: bundle_identity.to_owned(),
        destination_evidence_identity: destination_evidence_identity.to_owned(),
        recovery_method,
        occurred_at_unix_seconds: restore_time()?,
    })
}

fn validate_staged_items(
    planned: &[PlannedItem],
    staging: &RestoreDirectory,
) -> Result<(), CoreError> {
    let expected_entries = planned
        .iter()
        .filter(|item| !item.relative_path.as_os_str().is_empty())
        .map(|item| item.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let actual_entries = staging
        .relative_entries(expected_entries.len(), MAX_RESTORE_PATH_DEPTH)
        .map_err(|source| {
            restore_enumeration_error(
                "enumerate staged Migration Items",
                PathBuf::from(CONTROL_DIRECTORY).join("staging"),
                source,
            )
        })?;
    if actual_entries != expected_entries {
        return Err(invalid_restore(
            "Restore staging contains an unplanned or missing Migration Item",
        ));
    }
    validate_planned_items(&planned.iter().collect::<Vec<_>>(), staging).map(|_| ())
}

fn validate_planned_items(
    planned: &[&PlannedItem],
    directory: &RestoreDirectory,
) -> Result<BTreeMap<PathBuf, ValidatedRestoreItem>, CoreError> {
    let mut validated = BTreeMap::new();
    for item in planned {
        if item.relative_path.as_os_str().is_empty() {
            continue;
        }
        let metadata = directory
            .symlink_metadata(&item.relative_path)
            .map_err(|source| CoreError::Io {
                action: "revalidate staged Migration Item",
                path: item.relative_path.clone(),
                source,
            })?;
        let kind_matches = match item.kind {
            PlannedKind::Directory => metadata.is_dir(),
            PlannedKind::RegularFile => metadata.is_file() && metadata.len() == item.estimated_size,
            PlannedKind::SymbolicLink => metadata.file_type().is_symlink(),
        };
        if !kind_matches {
            return Err(invalid_restore(
                "staged Migration Item changed after authentication",
            ));
        }
        if item.kind == PlannedKind::SymbolicLink {
            let expected = item
                .symlink_target
                .as_deref()
                .ok_or_else(|| invalid_restore("selected symbolic link has no target"))?;
            let actual =
                directory
                    .read_link(&item.relative_path)
                    .map_err(|source| CoreError::Io {
                        action: "revalidate staged symbolic link",
                        path: item.relative_path.clone(),
                        source,
                    })?;
            if actual != expected {
                return Err(invalid_restore(
                    "staged symbolic link changed after authentication",
                ));
            }
        }
        if item.kind == PlannedKind::RegularFile {
            let expected = item
                .content_hash
                .as_deref()
                .ok_or_else(|| invalid_restore("selected regular file has no content hash"))?;
            let mut file =
                directory
                    .open_file(&item.relative_path)
                    .map_err(|source| CoreError::Io {
                        action: "revalidate staged regular file",
                        path: item.relative_path.clone(),
                        source,
                    })?;
            let opened_metadata = file.metadata().map_err(|source| CoreError::Io {
                action: "inspect opened staged regular file",
                path: item.relative_path.clone(),
                source,
            })?;
            if !opened_metadata.is_file() || opened_metadata.len() != item.estimated_size {
                return Err(invalid_restore(
                    "opened staged regular file changed after authentication",
                ));
            }
            #[cfg(unix)]
            if opened_metadata.permissions().mode() & 0o7777 != item.validation_regular_file_mode()
            {
                return Err(invalid_restore(
                    "staged regular file mode changed after authentication",
                ));
            }
            let mut hasher = blake3::Hasher::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer).map_err(|source| CoreError::Io {
                    action: "revalidate staged regular file",
                    path: item.relative_path.clone(),
                    source,
                })?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            if hasher.finalize().to_hex().as_str() != expected {
                return Err(invalid_restore(
                    "staged regular file changed after authentication",
                ));
            }
            validated.insert(
                item.relative_path.clone(),
                ValidatedRestoreItem {
                    relative_path: item.relative_path.clone(),
                    kind: item.kind,
                    final_mode: item.restored_regular_file_mode(),
                    #[cfg(unix)]
                    device: opened_metadata.dev(),
                    #[cfg(unix)]
                    inode: opened_metadata.ino(),
                },
            );
        }
        if item.kind == PlannedKind::Directory {
            let file = directory
                .metadata_file(&item.relative_path)
                .map_err(|source| CoreError::Io {
                    action: "open validated staged directory",
                    path: item.relative_path.clone(),
                    source,
                })?;
            let opened_metadata = file.metadata().map_err(|source| CoreError::Io {
                action: "inspect opened staged directory",
                path: item.relative_path.clone(),
                source,
            })?;
            if !opened_metadata.is_dir() {
                return Err(invalid_restore(
                    "opened staged directory changed after authentication",
                ));
            }
            validated.insert(
                item.relative_path.clone(),
                ValidatedRestoreItem {
                    relative_path: item.relative_path.clone(),
                    kind: item.kind,
                    final_mode: item.posix_mode,
                    #[cfg(unix)]
                    device: opened_metadata.dev(),
                    #[cfg(unix)]
                    inode: opened_metadata.ino(),
                },
            );
        }
    }
    Ok(validated)
}

fn validate_published_entries(
    planned: &[PlannedItem],
    destination: &RestoreDirectory,
    visible_names: &BTreeSet<std::ffi::OsString>,
) -> Result<BTreeMap<PathBuf, ValidatedRestoreItem>, CoreError> {
    let selected = planned
        .iter()
        .filter(|item| {
            item.relative_path
                .components()
                .next()
                .is_some_and(|component| visible_names.contains(component.as_os_str()))
        })
        .collect::<Vec<_>>();
    let expected = selected
        .iter()
        .map(|item| item.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for name in visible_names {
        let name_path = Path::new(name);
        let metadata = destination
            .symlink_metadata(name_path)
            .map_err(|source| CoreError::Io {
                action: "inspect published Restore entry",
                path: name_path.to_path_buf(),
                source,
            })?;
        actual.insert(name_path.to_path_buf());
        if metadata.is_dir() {
            let child = destination
                .open_dir(name_path)
                .map_err(|source| CoreError::Io {
                    action: "open published Restore directory",
                    path: name_path.to_path_buf(),
                    source,
                })?;
            let remaining = expected.len().saturating_sub(actual.len());
            actual.extend(
                child
                    .relative_entries(remaining, MAX_RESTORE_PATH_DEPTH.saturating_sub(1))
                    .map_err(|source| {
                        restore_enumeration_error(
                            "enumerate published Restore directory",
                            name_path.to_path_buf(),
                            source,
                        )
                    })?
                    .into_iter()
                    .map(|relative| name_path.join(relative)),
            );
        }
    }
    if actual != expected {
        return Err(invalid_restore(
            "published Restore entries do not match authenticated staging",
        ));
    }
    validate_planned_items(&selected, destination)
}

fn normalize_resume_modes(
    planned: &[PlannedItem],
    destination: &RestoreDirectory,
    visible_names: &BTreeSet<std::ffi::OsString>,
) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        let is_visible = |item: &&PlannedItem| {
            item.relative_path
                .components()
                .next()
                .is_some_and(|component| visible_names.contains(component.as_os_str()))
        };
        let mut directories = planned
            .iter()
            .filter(|item| item.kind == PlannedKind::Directory)
            .filter(is_visible)
            .collect::<Vec<_>>();
        directories.sort_by_key(|item| item.relative_path.components().count());
        for item in directories {
            normalize_resume_item_mode(item, destination, 0o700, item.posix_mode)?;
        }
        for item in planned
            .iter()
            .filter(|item| item.kind == PlannedKind::RegularFile)
            .filter(is_visible)
        {
            normalize_resume_item_mode(
                item,
                destination,
                item.validation_regular_file_mode(),
                item.restored_regular_file_mode(),
            )?;
        }
    }
    #[cfg(not(unix))]
    let _ = (planned, destination, visible_names);
    Ok(())
}

#[cfg(unix)]
fn normalize_resume_item_mode(
    item: &PlannedItem,
    destination: &RestoreDirectory,
    validation_mode: u32,
    final_mode: Option<u32>,
) -> Result<(), CoreError> {
    let metadata = destination
        .symlink_metadata(&item.relative_path)
        .map_err(|source| CoreError::Io {
            action: "inspect published Restore mode for resume",
            path: item.relative_path.clone(),
            source,
        })?;
    let actual_mode = metadata.permissions().mode() & 0o7777;
    if actual_mode == validation_mode {
        return Ok(());
    }
    if final_mode.map(|mode| mode & 0o7777) != Some(actual_mode) {
        return Err(invalid_restore(
            "published Restore mode does not match authenticated recovery state",
        ));
    }
    destination
        .set_mode_nofollow(&item.relative_path, validation_mode)
        .map_err(|source| CoreError::Io {
            action: "normalize published Restore mode for resume",
            path: item.relative_path.clone(),
            source,
        })?;
    let normalized = destination
        .symlink_metadata(&item.relative_path)
        .map_err(|source| CoreError::Io {
            action: "reinspect normalized Restore mode",
            path: item.relative_path.clone(),
            source,
        })?;
    let kind_matches = match item.kind {
        PlannedKind::Directory => normalized.is_dir(),
        PlannedKind::RegularFile => normalized.is_file(),
        PlannedKind::SymbolicLink => false,
    };
    if !kind_matches || normalized.permissions().mode() & 0o7777 != validation_mode {
        return Err(invalid_restore(
            "published Restore mode changed while preparing authenticated resume",
        ));
    }
    Ok(())
}

fn apply_item_platform_metadata(item: &PlannedItem, file: Option<&File>) -> u64 {
    let mut unapplied = 0_u64;
    match &item.extended_attributes {
        Some(attributes) => {
            if file
                .ok_or_else(|| io::Error::other("metadata item has no safe descriptor"))
                .and_then(|file| {
                    crate::platform_metadata::write_extended_attributes_file(file, attributes)
                })
                .is_err()
            {
                unapplied = unapplied.saturating_add(1);
            }
        }
        None => unapplied = unapplied.saturating_add(1),
    }
    match item.access_control_captured {
        Some(true) => {
            if let Some(access_control) = &item.access_control
                && file
                    .ok_or_else(|| io::Error::other("metadata item has no safe descriptor"))
                    .and_then(|file| {
                        crate::platform_metadata::write_access_control_file(file, access_control)
                    })
                    .is_err()
            {
                unapplied = unapplied.saturating_add(1);
            }
        }
        Some(false) | None => unapplied = unapplied.saturating_add(1),
    }
    unapplied
}

fn apply_root_platform_metadata(planned: &[PlannedItem], destination: &RestoreDirectory) -> u64 {
    let Some(root) = planned
        .iter()
        .find(|item| item.relative_path.as_os_str().is_empty())
    else {
        return 0;
    };
    let file = destination.metadata_file(Path::new("")).ok();
    apply_item_platform_metadata(root, file.as_ref())
}

fn finalize_validated_items(
    planned: &[PlannedItem],
    destination: &RestoreDirectory,
    validated: &BTreeMap<PathBuf, ValidatedRestoreItem>,
) -> Result<u64, CoreError> {
    let mut unapplied_metadata = 0_u64;
    for item in planned
        .iter()
        .filter(|item| !item.relative_path.as_os_str().is_empty())
    {
        if item.kind == PlannedKind::SymbolicLink {
            unapplied_metadata =
                unapplied_metadata.saturating_add(apply_item_platform_metadata(item, None));
            continue;
        }
        let identity = validated
            .get(&item.relative_path)
            .ok_or_else(|| invalid_restore("finalized Restore item lost its validated identity"))?;
        let mut file = destination
            .metadata_file(&item.relative_path)
            .map_err(|source| CoreError::Io {
                action: "open validated Restore item for finalization",
                path: item.relative_path.clone(),
                source,
            })?;
        let metadata = file.metadata().map_err(|source| CoreError::Io {
            action: "inspect validated Restore item for finalization",
            path: item.relative_path.clone(),
            source,
        })?;
        if !validated_identity_matches(identity, &metadata) {
            return Err(invalid_restore(
                "finalized Restore item no longer matches its validated identity",
            ));
        }
        match item.kind {
            PlannedKind::RegularFile => {
                if !metadata.is_file() || metadata.len() != item.estimated_size {
                    return Err(invalid_restore(
                        "finalized regular file changed after authentication",
                    ));
                }
                #[cfg(unix)]
                if metadata.permissions().mode() & 0o7777 != item.validation_regular_file_mode() {
                    return Err(invalid_restore(
                        "finalized regular file mode changed after authentication",
                    ));
                }
                let expected_hash = item
                    .content_hash
                    .as_deref()
                    .ok_or_else(|| invalid_restore("selected regular file has no content hash"))?;
                file.seek(SeekFrom::Start(0))
                    .map_err(|source| CoreError::Io {
                        action: "rewind validated Restore item for finalization",
                        path: item.relative_path.clone(),
                        source,
                    })?;
                let mut hasher = blake3::Hasher::new();
                let mut buffer = [0_u8; 64 * 1024];
                loop {
                    let read = file.read(&mut buffer).map_err(|source| CoreError::Io {
                        action: "reauthenticate Restore item for finalization",
                        path: item.relative_path.clone(),
                        source,
                    })?;
                    if read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..read]);
                }
                if hasher.finalize().to_hex().as_str() != expected_hash {
                    return Err(invalid_restore(
                        "finalized regular file changed after authentication",
                    ));
                }
                #[cfg(unix)]
                if let Some(mode) = identity.final_mode {
                    file.set_permissions(fs::Permissions::from_mode(mode & 0o7777))
                        .map_err(|source| CoreError::Io {
                            action: "apply restored Migration Item permissions",
                            path: item.relative_path.clone(),
                            source,
                        })?;
                }
            }
            PlannedKind::Directory => {
                if !metadata.is_dir() {
                    return Err(invalid_restore(
                        "finalized directory changed after authentication",
                    ));
                }
            }
            PlannedKind::SymbolicLink => unreachable!("symbolic links are handled above"),
        }
        unapplied_metadata =
            unapplied_metadata.saturating_add(apply_item_platform_metadata(item, Some(&file)));
        file.sync_all().map_err(|source| CoreError::Io {
            action: "synchronize finalized Restore item",
            path: item.relative_path.clone(),
            source,
        })?;
    }
    Ok(unapplied_metadata)
}

fn validated_identity_matches(
    validated: &ValidatedRestoreItem,
    metadata: &std::fs::Metadata,
) -> bool {
    #[cfg(unix)]
    {
        metadata.dev() == validated.device && metadata.ino() == validated.inode
    }
    #[cfg(not(unix))]
    {
        let _ = (validated, metadata);
        true
    }
}

fn validate_finalized_items(
    planned: &[PlannedItem],
    destination: &RestoreDirectory,
    validated: &BTreeMap<PathBuf, ValidatedRestoreItem>,
) -> Result<(), CoreError> {
    let expected_entries = planned
        .iter()
        .filter(|item| !item.relative_path.as_os_str().is_empty())
        .map(|item| item.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let top_level = top_level_entry_names(planned)?;
    let mut expected_root = top_level.iter().cloned().collect::<BTreeSet<_>>();
    expected_root.insert(CONTROL_DIRECTORY.into());
    let actual_root = destination
        .entry_names(expected_root.len())
        .map_err(|source| {
            restore_enumeration_error(
                "enumerate finalized Restore root entries",
                PathBuf::new(),
                source,
            )
        })?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual_root != expected_root {
        return Err(invalid_restore(
            "finalized Restore root entries changed after authentication",
        ));
    }
    let mut actual_entries = BTreeSet::new();
    for name in top_level {
        let path = Path::new(&name);
        actual_entries.insert(path.to_path_buf());
        if destination
            .symlink_metadata(path)
            .map_err(|source| CoreError::Io {
                action: "inspect finalized Restore root entry",
                path: path.to_path_buf(),
                source,
            })?
            .is_dir()
        {
            let child = destination.open_dir(path).map_err(|source| CoreError::Io {
                action: "open finalized Restore directory",
                path: path.to_path_buf(),
                source,
            })?;
            let remaining = expected_entries.len().saturating_sub(actual_entries.len());
            actual_entries.extend(
                child
                    .relative_entries(remaining, MAX_RESTORE_PATH_DEPTH.saturating_sub(1))
                    .map_err(|source| {
                        restore_enumeration_error(
                            "enumerate finalized Restore directory",
                            path.to_path_buf(),
                            source,
                        )
                    })?
                    .into_iter()
                    .map(|relative| path.join(relative)),
            );
        }
    }
    if actual_entries != expected_entries {
        return Err(invalid_restore(
            "finalized Restore entries changed after authentication",
        ));
    }

    for item in planned
        .iter()
        .filter(|item| !item.relative_path.as_os_str().is_empty())
    {
        if item.kind == PlannedKind::SymbolicLink {
            let actual = destination
                .read_link(&item.relative_path)
                .map_err(|source| CoreError::Io {
                    action: "revalidate finalized symbolic link",
                    path: item.relative_path.clone(),
                    source,
                })?;
            if item.symlink_target.as_deref() != Some(actual.as_path()) {
                return Err(invalid_restore(
                    "finalized symbolic link changed after authentication",
                ));
            }
            continue;
        }

        let identity = validated
            .get(&item.relative_path)
            .ok_or_else(|| invalid_restore("finalized Restore item lost its validated identity"))?;
        let path_metadata =
            destination
                .symlink_metadata(&item.relative_path)
                .map_err(|source| CoreError::Io {
                    action: "inspect finalized Restore binding",
                    path: item.relative_path.clone(),
                    source,
                })?;
        #[cfg(unix)]
        if path_metadata.dev() != identity.device || path_metadata.ino() != identity.inode {
            return Err(invalid_restore(
                "finalized Restore item no longer matches its validated identity",
            ));
        }
    }
    Ok(())
}

fn apply_directory_modes(
    destination: &RestoreDirectory,
    validated: &BTreeMap<PathBuf, ValidatedRestoreItem>,
) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        let mut directories = validated
            .values()
            .filter(|item| item.kind == PlannedKind::Directory && item.final_mode.is_some())
            .collect::<Vec<_>>();
        directories.sort_by_key(|item| std::cmp::Reverse(item.relative_path.components().count()));
        for item in directories {
            let file = destination
                .metadata_file(&item.relative_path)
                .map_err(|source| CoreError::Io {
                    action: "open validated directory before applying permissions",
                    path: item.relative_path.clone(),
                    source,
                })?;
            let metadata = file.metadata().map_err(|source| CoreError::Io {
                action: "inspect validated directory before applying permissions",
                path: item.relative_path.clone(),
                source,
            })?;
            if !metadata.is_dir() || !validated_identity_matches(item, &metadata) {
                return Err(invalid_restore(
                    "restored directory no longer matches its validated identity",
                ));
            }
            file.set_permissions(fs::Permissions::from_mode(
                item.final_mode.expect("filtered mode") & 0o7777,
            ))
            .and_then(|()| file.sync_all())
            .map_err(|source| CoreError::Io {
                action: "apply restored directory permissions",
                path: item.relative_path.clone(),
                source,
            })?;
        }
    }
    #[cfg(not(unix))]
    let _ = validated;
    Ok(())
}

fn apply_root_directory_mode(planned: &[PlannedItem], destination: &RestoreDirectory) -> u64 {
    let root = planned.iter().find(|item| {
        item.kind == PlannedKind::Directory && item.relative_path.as_os_str().is_empty()
    });
    let Some(mode) = root.and_then(|item| item.posix_mode) else {
        return 0;
    };
    #[cfg(unix)]
    {
        if destination
            .metadata_file(Path::new(""))
            .and_then(|file| file.set_permissions(fs::Permissions::from_mode(mode & 0o7777)))
            .is_err()
        {
            return 1;
        }
        0
    }
    #[cfg(not(unix))]
    {
        let _ = (mode, destination);
        1
    }
}

struct StagedFile {
    relative_path: PathBuf,
    path: PathBuf,
    expected_size: u64,
    written: u64,
    next_chunk: u32,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

struct ActiveStagedFile {
    ordinal: u32,
    file: File,
}

struct StagedFileSink<'a> {
    staging_directory: &'a RestoreDirectory,
    files: BTreeMap<u32, StagedFile>,
    active: Option<ActiveStagedFile>,
}

impl<'a> StagedFileSink<'a> {
    fn new(staging_directory: &'a RestoreDirectory) -> Self {
        Self {
            staging_directory,
            files: BTreeMap::new(),
            active: None,
        }
    }

    fn add(
        &mut self,
        ordinal: u32,
        relative_path: PathBuf,
        path: PathBuf,
        file: &File,
        expected_size: u64,
    ) -> Result<(), CoreError> {
        let metadata = file.metadata().map_err(|source| CoreError::Io {
            action: "inspect restricted staged Migration Item",
            path: path.clone(),
            source,
        })?;
        self.files.insert(
            ordinal,
            StagedFile {
                relative_path,
                path,
                expected_size,
                written: 0,
                next_chunk: 0,
                #[cfg(unix)]
                device: metadata.dev(),
                #[cfg(unix)]
                inode: metadata.ino(),
            },
        );
        Ok(())
    }

    fn open_for_chunk(&mut self, item_ordinal: u32) -> Result<(), CoreError> {
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.ordinal == item_ordinal)
        {
            return Ok(());
        }
        self.active = None;
        let staged = self.files.get(&item_ordinal).ok_or_else(|| {
            invalid_restore("Bundle content targets an unselected Migration Item")
        })?;
        let mut file = self
            .staging_directory
            .open_file_for_write(&staged.relative_path)
            .map_err(|source| CoreError::Io {
                action: "open restricted staged Migration Item",
                path: staged.path.clone(),
                source,
            })?;
        #[cfg(unix)]
        {
            let metadata = file.metadata().map_err(|source| CoreError::Io {
                action: "inspect opened staged Migration Item",
                path: staged.path.clone(),
                source,
            })?;
            if metadata.dev() != staged.device || metadata.ino() != staged.inode {
                return Err(invalid_restore(
                    "staged Migration Item identity changed during materialization",
                ));
            }
        }
        file.seek(SeekFrom::Start(staged.written))
            .map_err(|source| CoreError::Io {
                action: "seek staged Migration Item",
                path: staged.path.clone(),
                source,
            })?;
        self.active = Some(ActiveStagedFile {
            ordinal: item_ordinal,
            file,
        });
        Ok(())
    }

    fn finish(mut self) -> Result<(), CoreError> {
        self.active = None;
        for staged in self.files.into_values() {
            if staged.written != staged.expected_size {
                return Err(invalid_restore(
                    "restored Migration Item size does not match its authenticated manifest",
                ));
            }
            self.staging_directory
                .metadata_file(&staged.relative_path)
                .and_then(|file| file.sync_all())
                .map_err(|source| CoreError::Io {
                    action: "synchronize staged Migration Item",
                    path: staged.path,
                    source,
                })?;
        }
        Ok(())
    }
}

impl AuthenticatedContentSink for StagedFileSink<'_> {
    fn write_chunk(
        &mut self,
        item_ordinal: u32,
        chunk_ordinal: u32,
        content: &[u8],
    ) -> Result<(), CoreError> {
        self.open_for_chunk(item_ordinal)?;
        let staged = self.files.get_mut(&item_ordinal).ok_or_else(|| {
            invalid_restore("Bundle content targets an unselected Migration Item")
        })?;
        if chunk_ordinal != staged.next_chunk {
            return Err(invalid_restore(
                "Bundle content chunk order is invalid during Restore",
            ));
        }
        self.active
            .as_mut()
            .expect("active staged file should match an authenticated item")
            .file
            .write_all(content)
            .map_err(|source| CoreError::Io {
                action: "write staged Migration Item",
                path: staged.path.clone(),
                source,
            })?;
        staged.written = staged
            .written
            .checked_add(content.len() as u64)
            .ok_or_else(|| invalid_restore("restored Migration Item size overflowed"))?;
        if staged.written > staged.expected_size {
            return Err(invalid_restore(
                "restored Migration Item exceeds its authenticated size",
            ));
        }
        staged.next_chunk = staged
            .next_chunk
            .checked_add(1)
            .ok_or_else(|| invalid_restore("restored Migration Item chunk count overflowed"))?;
        Ok(())
    }
}

fn reconcile_interrupted_publication(
    request: &mut RestoreRequest<'_>,
    planned: &[PlannedItem],
    destination: &RestoreDirectory,
    control: &RestoreDirectory,
    journal: &RestoreJournal,
    destination_path: &Path,
    expected_bundle_hash: &[u8; 32],
) -> Result<(), CoreError> {
    let staging = control
        .open_dir(Path::new("staging"))
        .map_err(|source| CoreError::Io {
            action: "open interrupted Restore staging",
            path: destination_path.join(CONTROL_DIRECTORY).join("staging"),
            source,
        })?;
    let names = top_level_entry_names(planned)?;
    let mut published = usize::try_from(journal.published_top_level_entries)
        .map_err(|_| invalid_restore("Restore journal publication count is invalid"))?;
    if journal.phase == RestoreJournalPhase::RollingBack {
        let intent = journal
            .publication_intent
            .ok_or_else(|| invalid_restore("Restore rollback intent is missing"))?;
        let intent = usize::try_from(intent)
            .map_err(|_| invalid_restore("Restore rollback intent is invalid"))?;
        let name = Path::new(&names[intent]);
        match (
            directory_entry_exists(destination, name)?,
            directory_entry_exists(&staging, name)?,
        ) {
            (true, false) => {}
            (false, true) => published -= 1,
            _ => {
                return Err(invalid_restore(
                    "interrupted Restore rollback cannot be reconciled safely",
                ));
            }
        }
        write_authenticated_journal(
            request,
            control,
            expected_bundle_hash,
            JournalCheckpoint {
                staged_bytes: journal.staged_bytes,
                staged_items: journal.staged_items,
                phase: RestoreJournalPhase::Publishing,
                published_top_level_entries: published as u64,
                publication_intent: None,
            },
        )?;
    } else if let Some(intent) = journal.publication_intent {
        let intent = usize::try_from(intent)
            .map_err(|_| invalid_restore("Restore journal publication intent is invalid"))?;
        if intent != published || intent >= names.len() {
            return Err(invalid_restore(
                "Restore journal publication intent is invalid",
            ));
        }
        let name = Path::new(&names[intent]);
        match (
            directory_entry_exists(destination, name)?,
            directory_entry_exists(&staging, name)?,
        ) {
            (true, false) => published += 1,
            (false, true) => {}
            _ => {
                return Err(invalid_restore(
                    "interrupted Restore publication cannot be reconciled safely",
                ));
            }
        }
        write_authenticated_journal(
            request,
            control,
            expected_bundle_hash,
            JournalCheckpoint {
                staged_bytes: journal.staged_bytes,
                staged_items: journal.staged_items,
                phase: RestoreJournalPhase::Publishing,
                published_top_level_entries: published as u64,
                publication_intent: None,
            },
        )?;
    }
    for index in (0..published).rev() {
        let name = Path::new(&names[index]);
        if directory_entry_exists(&staging, name)? || !directory_entry_exists(destination, name)? {
            return Err(invalid_restore(
                "interrupted Restore publication changed before recovery",
            ));
        }
        write_authenticated_journal(
            request,
            control,
            expected_bundle_hash,
            JournalCheckpoint {
                staged_bytes: journal.staged_bytes,
                staged_items: journal.staged_items,
                phase: RestoreJournalPhase::RollingBack,
                published_top_level_entries: (index + 1) as u64,
                publication_intent: Some(index as u64),
            },
        )?;
        if let Some(sink) = request.event_sink.as_deref_mut() {
            sink.emit(RestoreEvent::RollbackPrepared {
                remaining_top_level_entries: (index + 1) as u64,
            });
        }
        destination
            .exclusive_rename(name, &staging, name)
            .map_err(|source| publication_error(&destination_path.join(name), source))?;
        destination.sync().map_err(|source| CoreError::Io {
            action: "synchronize interrupted Restore destination",
            path: destination_path.to_path_buf(),
            source,
        })?;
        staging.sync().map_err(|source| CoreError::Io {
            action: "synchronize interrupted Restore staging",
            path: destination_path.join(CONTROL_DIRECTORY).join("staging"),
            source,
        })?;
        write_authenticated_journal(
            request,
            control,
            expected_bundle_hash,
            JournalCheckpoint {
                staged_bytes: journal.staged_bytes,
                staged_items: journal.staged_items,
                phase: RestoreJournalPhase::Publishing,
                published_top_level_entries: index as u64,
                publication_intent: None,
            },
        )?;
    }
    Ok(())
}

fn directory_entry_exists(directory: &RestoreDirectory, name: &Path) -> Result<bool, CoreError> {
    match directory.symlink_metadata(name) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(CoreError::Io {
            action: "inspect Restore transaction entry",
            path: name.to_path_buf(),
            source,
        }),
    }
}

#[derive(Debug)]
enum PublicationOutcome {
    Complete(BTreeMap<PathBuf, ValidatedRestoreItem>),
    Paused,
}

struct PublicationContext<'a> {
    control: &'a RestoreDirectory,
    destination_path: &'a Path,
    bundle_hash: &'a [u8; 32],
    staged_bytes: u64,
    staged_items: u64,
    planned: &'a [PlannedItem],
}

fn publish_staged_entries(
    request: &mut RestoreRequest<'_>,
    staging: &RestoreDirectory,
    destination: &RestoreDirectory,
    context: PublicationContext<'_>,
    preserve_recovery_state: &mut bool,
) -> Result<PublicationOutcome, CoreError> {
    let PublicationContext {
        control,
        destination_path,
        bundle_hash,
        staged_bytes,
        staged_items,
        planned,
    } = context;
    let expected_top_level = top_level_entry_names(planned)?;
    let mut entries = staging
        .entry_names(expected_top_level.len())
        .map_err(|source| {
            restore_enumeration_error(
                "read completed Restore staging directory",
                destination_path.join(CONTROL_DIRECTORY).join("staging"),
                source,
            )
        })?;
    entries.sort();
    if entries != expected_top_level {
        return Err(invalid_restore(
            "Restore staging top level changed before publication",
        ));
    }
    for name in &entries {
        let target = destination_path.join(name);
        match destination.symlink_metadata(Path::new(name)) {
            Ok(_) => return Err(CoreError::DestinationAlreadyExists(target.clone())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CoreError::Io {
                    action: "inspect Restore publication target",
                    path: target.clone(),
                    source,
                });
            }
        }
    }
    let mut validated_items = BTreeMap::new();
    for (index, name) in entries.into_iter().enumerate() {
        let target = destination_path.join(&name);
        write_authenticated_journal(
            request,
            control,
            bundle_hash,
            JournalCheckpoint {
                staged_bytes,
                staged_items,
                phase: RestoreJournalPhase::Publishing,
                published_top_level_entries: index as u64,
                publication_intent: Some(index as u64),
            },
        )?;
        *preserve_recovery_state = true;
        staging
            .exclusive_rename(Path::new(&name), destination, Path::new(&name))
            .map_err(|source| publication_error(&target, source))?;
        if let Some(sink) = request.event_sink.as_deref_mut() {
            sink.emit(RestoreEvent::PublicationCandidateMoved {
                candidate_top_level_entry: (index + 1) as u64,
            });
        }
        validated_items.extend(validate_published_entries(
            planned,
            destination,
            &BTreeSet::from([name.clone()]),
        )?);
        staging.sync().map_err(|source| CoreError::Io {
            action: "synchronize Restore staging publication",
            path: destination_path.join(CONTROL_DIRECTORY).join("staging"),
            source,
        })?;
        destination.sync().map_err(|source| CoreError::Io {
            action: "synchronize Restore destination publication",
            path: destination_path.to_path_buf(),
            source,
        })?;
        let completed = (index + 1) as u64;
        write_authenticated_journal(
            request,
            control,
            bundle_hash,
            JournalCheckpoint {
                staged_bytes,
                staged_items,
                phase: RestoreJournalPhase::Publishing,
                published_top_level_entries: completed,
                publication_intent: None,
            },
        )?;
        if let Some(sink) = request.event_sink.as_deref_mut() {
            sink.emit(RestoreEvent::PublicationAdvanced {
                completed_top_level_entries: completed,
            });
        }
        if request
            .cancellation
            .is_some_and(RestoreCancellation::is_cancelled)
        {
            return Ok(PublicationOutcome::Paused);
        }
    }
    Ok(PublicationOutcome::Complete(validated_items))
}

fn publication_error(target: &Path, source: io::Error) -> CoreError {
    if source.kind() == io::ErrorKind::AlreadyExists
        || source
            .raw_os_error()
            .is_some_and(|code| code == libc::EEXIST || code == libc::ENOTEMPTY)
    {
        CoreError::DestinationAlreadyExists(target.to_path_buf())
    } else {
        CoreError::Io {
            action: "publish restored Migration Item without overwrite",
            path: target.to_path_buf(),
            source,
        }
    }
}

fn invalid_restore(message: impl Into<String>) -> CoreError {
    CoreError::BundleInvalid(message.into())
}

fn restore_enumeration_error(action: &'static str, path: PathBuf, source: io::Error) -> CoreError {
    if source.kind() == io::ErrorKind::InvalidData {
        invalid_restore(source.to_string())
    } else {
        CoreError::Io {
            action,
            path,
            source,
        }
    }
}
