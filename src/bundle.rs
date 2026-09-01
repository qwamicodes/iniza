use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AuthenticatedBundleSummary, CoreError, Disposition, MigrationItemKind, Plan, PlanApprovalState,
    RecoveryMethod, RecoverySecret, SealedBundle,
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

const RECORD_CONTENT: u8 = 1;
const RECORD_MANIFEST: u8 = 2;
const RECORD_INDEX: u8 = 3;
const RECORD_COMPLETION: u8 = 255;

pub struct PackRequest<'a> {
    plan: &'a Plan,
    destination: PathBuf,
    event_sink: Option<&'a mut dyn BundleEventSink>,
}

impl<'a> PackRequest<'a> {
    pub fn new(plan: &'a Plan, destination: impl Into<PathBuf>) -> Self {
        Self {
            plan,
            destination: destination.into(),
            event_sink: None,
        }
    }

    pub fn with_event_sink(mut self, event_sink: &'a mut dyn BundleEventSink) -> Self {
        self.event_sink = Some(event_sink);
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
}

impl BundleVerification {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum BundleEvent {
    PackStarted,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleSourceObservation {
    pub length: u64,
    pub identity: u64,
    pub change_token: u64,
}

impl BundleSourceObservation {
    pub fn new(length: u64, identity: u64, change_token: u64) -> Self {
        Self {
            length,
            identity,
            change_token,
        }
    }
}

pub trait BundleSource {
    fn observe(&self, path: &Path) -> io::Result<BundleSourceObservation>;
    fn open(&self, path: &Path) -> io::Result<Box<dyn Read>>;
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
            Ok(BundleSourceObservation::new(
                metadata.len(),
                identity,
                change_token,
            ))
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
    pub fn pack(&self, mut request: PackRequest<'_>) -> Result<SealedBundle, CoreError> {
        validate_pack_request(&request)?;
        let mut event_sink = request.event_sink.take();
        let plan = request.plan;
        let destination = request.destination;
        let partial = partial_path(&destination);
        if partial.exists() {
            return Err(CoreError::DestinationAlreadyExists(partial));
        }

        let data_encryption_key = random_secret()?;
        let vaultwarden_secret = RecoverySecret {
            method: RecoveryMethod::Vaultwarden,
            bytes: random_secret()?,
        };
        let offline_secret = RecoverySecret {
            method: RecoveryMethod::Offline,
            bytes: random_secret()?,
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

        let write_result = write_bundle(
            plan,
            &self.source,
            &self.capacity,
            &partial,
            &destination,
            &header,
            &keys,
            &context,
            &mut event_sink,
        );
        if write_result.is_err() {
            let _ = fs::remove_file(&partial);
        }
        write_result?;

        Ok(SealedBundle {
            vaultwarden_recovery_secret: vaultwarden_secret,
            offline_recovery_key: offline_secret,
        })
    }

    pub fn inspect(
        &self,
        request: InspectRequest<'_>,
    ) -> Result<AuthenticatedBundleSummary, CoreError> {
        let mut event_sink = None;
        Ok(open_bundle(
            &request.source,
            request.recovery_secret,
            false,
            &mut event_sink,
        )?
        .summary)
    }

    pub fn verify(&self, mut request: VerifyRequest<'_>) -> Result<BundleVerification, CoreError> {
        let mut event_sink = request.event_sink.take();
        let opened = open_bundle(
            &request.source,
            request.recovery_secret,
            true,
            &mut event_sink,
        )?;
        Ok(BundleVerification {
            summary: opened.summary,
            authenticated_chunks: opened.authenticated_chunks,
            authenticated_bytes: opened.authenticated_bytes,
        })
    }
}

fn validate_pack_request(request: &PackRequest<'_>) -> Result<(), CoreError> {
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
) -> Result<(), CoreError> {
    emit_event(events, BundleEvent::PackStarted);
    let estimated_required = plan
        .estimated_logical_size()
        .checked_add(HEADER_LENGTH as u64)
        .and_then(|size| size.checked_add((plan.items().len() as u64).saturating_mul(512)))
        .and_then(|size| size.checked_add(MAX_PLAINTEXT_CHUNK as u64))
        .ok_or_else(|| invalid_bundle("Bundle capacity estimate overflowed"))?;
    ensure_capacity(capacity, destination, estimated_required)?;
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(partial)
        .map_err(|source| CoreError::Io {
            action: "create partial Bundle",
            path: partial.to_path_buf(),
            source,
        })?;
    let mut writer = StreamWriter::new(output, capacity, destination);
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

    for (item_ordinal, item) in plan.items().iter().enumerate() {
        let item_ordinal = u32::try_from(item_ordinal)
            .map_err(|_| invalid_bundle("Bundle contains too many Migration Items"))?;
        let mut chunk_sequences = Vec::new();
        let mut content_hash = None;
        let outcome = if matches!(
            item.kind,
            MigrationItemKind::SymbolicLink | MigrationItemKind::Special
        ) {
            unsupported_items += 1;
            CaptureOutcome::Unsupported
        } else if item.disposition == Disposition::Included {
            included_items += 1;
            match item.kind {
                MigrationItemKind::Directory => CaptureOutcome::Included,
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
                    if captured.changed {
                        changed_items += 1;
                    }
                    if captured.verified {
                        logical_size = logical_size
                            .checked_add(captured.logical_size)
                            .ok_or_else(|| invalid_bundle("Bundle logical size overflowed"))?;
                        chunk_sequences = captured.chunk_sequences;
                        content_hash = captured.content_hash;
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
                _ => {
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
        manifest_items.push(ManifestItem {
            id: item.id.clone(),
            relative_path: item.relative_path.to_string_lossy().into_owned(),
            kind: format!("{:?}", item.kind),
            estimated_size: item.estimated_size,
            outcome,
            chunk_sequences,
            content_hash,
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
    }

    let manifest = Manifest {
        marker: "MNF2".to_owned(),
        schema_version: 1,
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
    writer.file.sync_all().map_err(|source| CoreError::Io {
        action: "synchronize completed partial Bundle",
        path: partial.to_path_buf(),
        source,
    })?;
    fs::hard_link(partial, destination).map_err(|source| {
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
    // Publication has already succeeded. A cleanup failure must not report the
    // operation as failed when the authenticated final Bundle is now visible.
    // A later housekeeping pass may remove the redundant hard-link name.
    let _ = fs::remove_file(partial);
    emit_event(
        events,
        BundleEvent::PackCompleted {
            included_items,
            changed_items,
            unsupported_items,
            unverified_items,
        },
    );
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
    changed: bool,
    verified: bool,
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
        let mut stage = StreamWriter::new(stage_file, writer.capacity, writer.capacity_destination);
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
            fs::remove_file(&stage_path).map_err(|source_error| CoreError::Io {
                action: "remove encrypted Migration Item staging output",
                path: stage_path,
                source: source_error,
            })?;
            return Ok(CapturedFile {
                logical_size,
                chunk_sequences,
                content_hash: Some(content_hasher.finalize().to_hex().to_string()),
                changed,
                verified: true,
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
        changed,
        verified: false,
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
}

impl<'a> StreamWriter<'a> {
    fn new(
        file: fs::File,
        capacity: &'a dyn DestinationCapacity,
        capacity_destination: &'a Path,
    ) -> Self {
        Self {
            file,
            hasher: blake3::Hasher::new(),
            offset: 0,
            record_count: 0,
            capacity,
            capacity_destination,
        }
    }

    fn write_hashed(&mut self, bytes: &[u8], path: &Path) -> Result<(), CoreError> {
        ensure_capacity(self.capacity, self.capacity_destination, bytes.len() as u64)?;
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestItem {
    id: String,
    relative_path: String,
    kind: String,
    estimated_size: u64,
    outcome: CaptureOutcome,
    chunk_sequences: Vec<u64>,
    content_hash: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
}

fn open_bundle(
    source: &Path,
    recovery_secret: &RecoverySecret,
    verify_content: bool,
    events: &mut Option<&mut dyn BundleEventSink>,
) -> Result<OpenedBundle, CoreError> {
    if verify_content {
        emit_event(events, BundleEvent::VerificationStarted);
    }
    reject_partial_path(source)?;
    let mut input = fs::File::open(source).map_err(|source_error| CoreError::Io {
        action: "open Bundle",
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
    })
}

fn validate_manifest(manifest: &Manifest, index: &[IndexEntry]) -> Result<(), CoreError> {
    if manifest.marker != "MNF2" || manifest.schema_version != 1 {
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

fn partial_path(destination: &Path) -> PathBuf {
    let mut value = destination.as_os_str().to_os_string();
    value.push(".partial");
    PathBuf::from(value)
}

fn reject_partial_path(source: &Path) -> Result<(), CoreError> {
    if source
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.ends_with(".iniza.partial"))
    {
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
