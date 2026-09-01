use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

use crate::bundle::{
    AuthenticatedContentSink, AuthenticatedRestoreItem, authenticate_restore_plan,
    stream_authenticated_content,
};
use crate::{
    CoreError, DestinationCapacity, ExtendedAttribute, LocalDestinationCapacity, RecoverySecret,
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
    StagingValidated,
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
        let authenticated = authenticate_restore_plan(&request.source, request.recovery_secret)?;
        let planned = validate_restore_items(&authenticated.items)?;
        ensure_restore_capacity(&self.capacity, &request.destination, &planned)?;
        let destination_state = if request.resume {
            validate_resume_destination(&request, planned.len() as u64)?;
            None
        } else {
            Some(prepare_destination(&request.destination)?)
        };
        let destination_identity = destination_identity(&request.destination)?;

        let result = restore_transaction(&mut request, &planned, &destination_identity);
        if result.is_err() {
            if !request.resume {
                if destination_state == Some(DestinationState::Created) {
                    let _ = set_directory_mode(&request.destination);
                }
                let _ = fs::remove_dir_all(request.destination.join(CONTROL_DIRECTORY));
            }
            if destination_state == Some(DestinationState::Created) {
                let _ = fs::remove_dir(&request.destination);
            }
        }
        result
    }
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
    posix_mode: Option<u32>,
    repository_hook: bool,
    executable_content: bool,
    symlink_target: Option<PathBuf>,
    extended_attributes: Option<Vec<ExtendedAttribute>>,
    access_control_captured: Option<bool>,
    access_control: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlannedKind {
    Directory,
    RegularFile,
    SymbolicLink,
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

fn validate_restore_items(
    items: &[AuthenticatedRestoreItem],
) -> Result<Vec<PlannedItem>, CoreError> {
    if items.len() > MAX_RESTORE_ITEMS {
        return Err(invalid_restore(
            "Bundle exceeds the Restore item-count limit",
        ));
    }
    if items
        .iter()
        .any(|item| matches!(item.kind.as_str(), "Special" | "Unknown"))
    {
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
        let kind = match item.kind.as_str() {
            "Directory" => PlannedKind::Directory,
            "RegularFile" => PlannedKind::RegularFile,
            "SymbolicLink" => PlannedKind::SymbolicLink,
            _ => {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestinationState {
    Created,
    ExistingEmpty,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreJournal {
    schema_version: u32,
    bundle_hash: String,
    staged_items: u64,
    staged_bytes: u64,
    authentication_tag: String,
}

fn validate_resume_destination(
    request: &RestoreRequest<'_>,
    expected_items: u64,
) -> Result<(), CoreError> {
    let entries = fs::read_dir(&request.destination).map_err(|source| CoreError::Io {
        action: "inspect Restore destination for resume",
        path: request.destination.clone(),
        source,
    })?;
    let names = entries
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|source| CoreError::Io {
                    action: "inspect Restore destination entry for resume",
                    path: request.destination.clone(),
                    source,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if names.len() != 1 || names[0] != CONTROL_DIRECTORY {
        return Err(invalid_restore(
            "Restore resume destination contains unrelated entries",
        ));
    }
    let control = request.destination.join(CONTROL_DIRECTORY);
    if !fs::symlink_metadata(&control)
        .map_err(|source| CoreError::Io {
            action: "inspect Restore transaction control for resume",
            path: control.clone(),
            source,
        })?
        .file_type()
        .is_dir()
    {
        return Err(invalid_restore(
            "Restore transaction control is not a directory",
        ));
    }
    let control_entries = fs::read_dir(&control)
        .map_err(|source| CoreError::Io {
            action: "inspect Restore transaction state for resume",
            path: control.clone(),
            source,
        })?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|source| CoreError::Io {
            action: "inspect Restore transaction entry for resume",
            path: control.clone(),
            source,
        })?;
    let expected = ["journal.json".into(), "staging".into()]
        .into_iter()
        .collect::<BTreeSet<std::ffi::OsString>>();
    if control_entries != expected {
        return Err(invalid_restore(
            "Restore transaction state contains unrelated entries",
        ));
    }
    let staging = control.join("staging");
    if !fs::symlink_metadata(&staging)
        .map_err(|source| CoreError::Io {
            action: "inspect Restore staging for resume",
            path: staging.clone(),
            source,
        })?
        .file_type()
        .is_dir()
    {
        return Err(invalid_restore("Restore staging is not a directory"));
    }
    let journal_path = control.join("journal.json");
    let bytes = fs::read(&journal_path).map_err(|source| CoreError::Io {
        action: "read Restore journal for resume",
        path: journal_path.clone(),
        source,
    })?;
    if bytes.len() > 16 * 1024 {
        return Err(invalid_restore("Restore journal exceeds its size limit"));
    }
    let journal: RestoreJournal = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_restore("Restore journal is invalid"))?;
    let bundle_hash = hash_file(&request.source)?;
    if journal.schema_version != 1
        || journal.bundle_hash != bundle_hash
        || journal.staged_items != expected_items
        || journal.authentication_tag
            != journal_authentication_tag(
                request.recovery_secret,
                &journal.bundle_hash,
                journal.staged_items,
                journal.staged_bytes,
            )
    {
        return Err(invalid_restore(
            "Restore journal does not authenticate for this Bundle and Recovery Secret",
        ));
    }
    Ok(())
}

fn write_authenticated_journal(
    request: &RestoreRequest<'_>,
    staged_bytes: u64,
    staged_items: u64,
) -> Result<(), CoreError> {
    let control = request.destination.join(CONTROL_DIRECTORY);
    let journal_path = control.join("journal.json");
    let partial = control.join("journal.json.partial");
    let bundle_hash = hash_file(&request.source)?;
    let journal = RestoreJournal {
        schema_version: 1,
        authentication_tag: journal_authentication_tag(
            request.recovery_secret,
            &bundle_hash,
            staged_items,
            staged_bytes,
        ),
        bundle_hash,
        staged_items,
        staged_bytes,
    };
    let bytes = serde_json::to_vec(&journal)
        .map_err(|error| invalid_restore(format!("could not encode Restore journal: {error}")))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let mut output = options.open(&partial).map_err(|source| CoreError::Io {
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
    fs::rename(&partial, &journal_path).map_err(|source| CoreError::Io {
        action: "publish authenticated Restore journal",
        path: journal_path,
        source,
    })?;
    Ok(())
}

fn journal_authentication_tag(
    recovery_secret: &RecoverySecret,
    bundle_hash: &str,
    staged_items: u64,
    staged_bytes: u64,
) -> String {
    let key = blake3::derive_key(
        "iniza Restore journal authentication version 1",
        recovery_secret.bytes.as_ref(),
    );
    let payload = format!("1\n{bundle_hash}\n{staged_items}\n{staged_bytes}\n");
    blake3::keyed_hash(&key, payload.as_bytes())
        .to_hex()
        .to_string()
}

fn hash_file(path: &Path) -> Result<String, CoreError> {
    let mut input = File::open(path).map_err(|source| CoreError::Io {
        action: "open Bundle for Restore transaction binding",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(|source| CoreError::Io {
            action: "hash Bundle for Restore transaction binding",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn prepare_destination(destination: &Path) -> Result<DestinationState, CoreError> {
    match fs::create_dir(destination) {
        Ok(()) => {
            set_directory_mode(destination)?;
            Ok(DestinationState::Created)
        }
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut entries = fs::read_dir(destination).map_err(|source| CoreError::Io {
                action: "inspect existing Restore destination",
                path: destination.to_path_buf(),
                source,
            })?;
            if entries.next().is_some() {
                return Err(CoreError::DestinationAlreadyExists(
                    destination.to_path_buf(),
                ));
            }
            Ok(DestinationState::ExistingEmpty)
        }
        Err(source) => Err(CoreError::Io {
            action: "create Restore destination",
            path: destination.to_path_buf(),
            source,
        }),
    }
}

fn restore_transaction(
    request: &mut RestoreRequest<'_>,
    planned: &[PlannedItem],
    destination_identity: &DestinationIdentity,
) -> Result<RestoreReport, CoreError> {
    let control = request.destination.join(CONTROL_DIRECTORY);
    let staging = control.join("staging");
    if request.resume {
        fs::remove_dir_all(&staging).map_err(|source| CoreError::Io {
            action: "reset authenticated Restore staging for resume",
            path: staging.clone(),
            source,
        })?;
        create_restrictive_directory(&staging)?;
    } else {
        create_restrictive_directory(&control)?;
        create_restrictive_directory(&staging)?;
    }

    let mut directories = planned
        .iter()
        .filter(|item| item.kind == PlannedKind::Directory)
        .collect::<Vec<_>>();
    directories.sort_by_key(|item| item.relative_path.components().count());
    for item in directories {
        if !item.relative_path.as_os_str().is_empty() {
            create_restrictive_directory(&staging.join(&item.relative_path))?;
        }
    }

    let mut sink = StagedFileSink::new();
    for item in planned
        .iter()
        .filter(|item| item.kind == PlannedKind::RegularFile)
    {
        let path = staging.join(&item.relative_path);
        let parent = path
            .parent()
            .ok_or_else(|| invalid_restore("Restore staging path has no parent"))?;
        if !parent.is_dir() {
            return Err(invalid_restore(
                "Bundle manifest file parent is not a selected directory",
            ));
        }
        sink.add(
            item.ordinal,
            path,
            item.estimated_size,
            item.posix_mode.map(|mode| {
                if item.executable_content {
                    mode & !0o111
                } else {
                    mode
                }
            }),
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
        symlink(target, &path).map_err(|source| CoreError::Io {
            action: "create staged symbolic link",
            path: path.clone(),
            source,
        })?;
        #[cfg(not(unix))]
        return Err(invalid_restore(
            "symbolic-link Restore is unsupported on this platform",
        ));
    }

    let restored_bytes =
        stream_authenticated_content(&request.source, request.recovery_secret, &mut sink)?;
    sink.finish()?;
    write_authenticated_journal(request, restored_bytes, planned.len() as u64)?;
    if let Some(sink) = request.event_sink.as_deref_mut() {
        sink.emit(RestoreEvent::StagingValidated);
    }
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
        });
    }
    require_destination_identity(&request.destination, destination_identity)?;
    publish_staged_entries(&staging, &request.destination)?;
    fs::remove_dir(&staging).map_err(|source| CoreError::Io {
        action: "remove empty Restore staging directory",
        path: staging.clone(),
        source,
    })?;
    let journal = control.join("journal.json");
    fs::remove_file(&journal).map_err(|source| CoreError::Io {
        action: "remove completed Restore journal",
        path: journal,
        source,
    })?;
    fs::remove_dir(&control).map_err(|source| CoreError::Io {
        action: "remove completed Restore transaction control",
        path: control,
        source,
    })?;
    let unapplied_metadata = apply_platform_metadata(planned, &request.destination);
    apply_directory_modes(planned, &request.destination)?;

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
    })
}

fn apply_platform_metadata(planned: &[PlannedItem], destination: &Path) -> u64 {
    let mut unapplied = 0_u64;
    for item in planned {
        let path = destination.join(&item.relative_path);
        let no_follow = item.kind == PlannedKind::SymbolicLink;
        match &item.extended_attributes {
            Some(attributes) => {
                if crate::platform_metadata::write_extended_attributes(&path, no_follow, attributes)
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
                    && crate::platform_metadata::write_access_control(
                        &path,
                        no_follow,
                        access_control,
                    )
                    .is_err()
                {
                    unapplied = unapplied.saturating_add(1);
                }
            }
            Some(false) | None => unapplied = unapplied.saturating_add(1),
        }
    }
    unapplied
}

fn apply_directory_modes(planned: &[PlannedItem], destination: &Path) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        let mut directories = planned
            .iter()
            .filter(|item| item.kind == PlannedKind::Directory && item.posix_mode.is_some())
            .collect::<Vec<_>>();
        directories.sort_by_key(|item| std::cmp::Reverse(item.relative_path.components().count()));
        for item in directories {
            let path = destination.join(&item.relative_path);
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(item.posix_mode.expect("filtered mode") & 0o7777),
            )
            .map_err(|source| CoreError::Io {
                action: "apply restored directory permissions",
                path,
                source,
            })?;
        }
    }
    Ok(())
}

fn create_restrictive_directory(path: &Path) -> Result<(), CoreError> {
    fs::create_dir(path).map_err(|source| CoreError::Io {
        action: "create Restore staging directory",
        path: path.to_path_buf(),
        source,
    })?;
    set_directory_mode(path)
}

fn set_directory_mode(path: &Path) -> Result<(), CoreError> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        CoreError::Io {
            action: "restrict Restore directory permissions",
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

struct StagedFile {
    path: PathBuf,
    file: File,
    expected_size: u64,
    posix_mode: Option<u32>,
    written: u64,
    next_chunk: u32,
}

#[derive(Default)]
struct StagedFileSink {
    files: BTreeMap<u32, StagedFile>,
}

impl StagedFileSink {
    fn new() -> Self {
        Self::default()
    }

    fn add(
        &mut self,
        ordinal: u32,
        path: PathBuf,
        expected_size: u64,
        posix_mode: Option<u32>,
    ) -> Result<(), CoreError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(&path).map_err(|source| CoreError::Io {
            action: "create restricted staged Migration Item",
            path: path.clone(),
            source,
        })?;
        self.files.insert(
            ordinal,
            StagedFile {
                path,
                file,
                expected_size,
                posix_mode,
                written: 0,
                next_chunk: 0,
            },
        );
        Ok(())
    }

    fn finish(self) -> Result<(), CoreError> {
        for staged in self.files.into_values() {
            if staged.written != staged.expected_size {
                return Err(invalid_restore(
                    "restored Migration Item size does not match its authenticated manifest",
                ));
            }
            #[cfg(unix)]
            if let Some(mode) = staged.posix_mode {
                staged
                    .file
                    .set_permissions(fs::Permissions::from_mode(mode & 0o7777))
                    .map_err(|source| CoreError::Io {
                        action: "apply restored Migration Item permissions",
                        path: staged.path.clone(),
                        source,
                    })?;
            }
            staged.file.sync_all().map_err(|source| CoreError::Io {
                action: "synchronize staged Migration Item",
                path: staged.path,
                source,
            })?;
        }
        Ok(())
    }
}

impl AuthenticatedContentSink for StagedFileSink {
    fn write_chunk(
        &mut self,
        item_ordinal: u32,
        chunk_ordinal: u32,
        content: &[u8],
    ) -> Result<(), CoreError> {
        let staged = self.files.get_mut(&item_ordinal).ok_or_else(|| {
            invalid_restore("Bundle content targets an unselected Migration Item")
        })?;
        if chunk_ordinal != staged.next_chunk {
            return Err(invalid_restore(
                "Bundle content chunk order is invalid during Restore",
            ));
        }
        staged
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

fn publish_staged_entries(staging: &Path, destination: &Path) -> Result<(), CoreError> {
    let entries = fs::read_dir(staging)
        .map_err(|source| CoreError::Io {
            action: "read completed Restore staging directory",
            path: staging.to_path_buf(),
            source,
        })?
        .map(|entry| {
            entry
                .map(|entry| (entry.path(), destination.join(entry.file_name())))
                .map_err(|source| CoreError::Io {
                    action: "read completed Restore staging entry",
                    path: staging.to_path_buf(),
                    source,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut entries = entries;
    entries.sort_by(|left, right| left.1.cmp(&right.1));
    for (_, target) in &entries {
        match fs::symlink_metadata(target) {
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
    let mut published = Vec::new();
    for (source, target) in entries {
        if let Err(error) = exclusive_rename(&source, &target) {
            for (published_target, original_source) in published.into_iter().rev() {
                let _ = fs::rename(published_target, original_source);
            }
            return Err(error);
        }
        published.push((target, source));
    }
    Ok(())
}

fn exclusive_rename(source: &Path, target: &Path) -> Result<(), CoreError> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let source_c = CString::new(source.as_os_str().as_bytes())
            .map_err(|_| invalid_restore("Restore staging path contains a null byte"))?;
        let target_c = CString::new(target.as_os_str().as_bytes())
            .map_err(|_| invalid_restore("Restore target path contains a null byte"))?;
        // SAFETY: both paths are live null-terminated strings. `RENAME_EXCL`
        // requests one atomic same-filesystem rename that never replaces a name.
        if unsafe { libc::renamex_np(source_c.as_ptr(), target_c.as_ptr(), libc::RENAME_EXCL) } == 0
        {
            return Ok(());
        }
        Err(publication_error(target, io::Error::last_os_error()))
    }
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let source_c = CString::new(source.as_os_str().as_bytes())
            .map_err(|_| invalid_restore("Restore staging path contains a null byte"))?;
        let target_c = CString::new(target.as_os_str().as_bytes())
            .map_err(|_| invalid_restore("Restore target path contains a null byte"))?;
        // SAFETY: both paths are live null-terminated strings. `RENAME_NOREPLACE`
        // requests one atomic same-filesystem rename that never replaces a name.
        if unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source_c.as_ptr(),
                libc::AT_FDCWD,
                target_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0
        {
            return Ok(());
        }
        return Err(publication_error(target, io::Error::last_os_error()));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        if target.exists() {
            return Err(CoreError::DestinationAlreadyExists(target.to_path_buf()));
        }
        fs::rename(source, target).map_err(|source_error| publication_error(target, source_error))
    }
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
