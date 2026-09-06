use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::{BundleEngine, CoreError, RecoveryMethod, RecoverySecret, VerifyRequest};

const DOCUMENT_HEADER: &str = "INIZA OFFLINE RECOVERY KEY";
const DOCUMENT_SCHEMA_VERSION: &str = "1";
const DOCUMENT_BUNDLE_FORMAT: &str = "IZ2";
const DOCUMENT_RECOVERY_METHOD: &str = "offline";
const DOCUMENT_INSTRUCTIONS: &str = "Use Iniza offline recovery rehearsal or Restore with this document; keep it separate from every Bundle copy.";
const MAX_DOCUMENT_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineRecoveryPersistenceTransition {
    AuthenticateCompletedBundle,
    CreateDocument,
    RestrictDocument,
    WriteDocument,
    SynchronizeDocument,
    SynchronizeDirectory,
    ReadDocument,
    AuthenticateRehearsal,
}

pub trait OfflineRecoveryStorage: Send + Sync {
    fn validate_separate_removable_target(&self, document: &Path) -> io::Result<()>;

    fn prepare_transition(
        &self,
        transition: OfflineRecoveryPersistenceTransition,
    ) -> io::Result<()>;
}

#[derive(Debug, Default)]
pub struct LocalOfflineRecoveryStorage;

impl OfflineRecoveryStorage for LocalOfflineRecoveryStorage {
    fn validate_separate_removable_target(&self, document: &Path) -> io::Result<()> {
        let parent = document.parent().unwrap_or_else(|| Path::new("."));
        let parent = fs::canonicalize(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let root_device = fs::metadata("/")?.dev();
            let target_device = fs::metadata(&parent)?.dev();
            if root_device == target_device {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Offline Recovery Key target must be separate mounted storage",
                ));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = parent;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "removable-storage validation is unsupported on this platform",
            ))
        }
    }

    fn prepare_transition(
        &self,
        _transition: OfflineRecoveryPersistenceTransition,
    ) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct OfflineRecoveryWriteRequest<'a> {
    bundle: PathBuf,
    document: PathBuf,
    recovery_secret: &'a RecoverySecret,
}

impl<'a> OfflineRecoveryWriteRequest<'a> {
    pub fn new(
        bundle: impl Into<PathBuf>,
        document: impl Into<PathBuf>,
        recovery_secret: &'a RecoverySecret,
    ) -> Self {
        Self {
            bundle: bundle.into(),
            document: document.into(),
            recovery_secret,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineRecoveryRehearsalRequest {
    bundle: PathBuf,
    document: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineRecoveryLoadRequest {
    bundle: PathBuf,
    document: PathBuf,
}

impl OfflineRecoveryLoadRequest {
    pub fn new(bundle: impl Into<PathBuf>, document: impl Into<PathBuf>) -> Self {
        Self {
            bundle: bundle.into(),
            document: document.into(),
        }
    }
}

pub struct LoadedOfflineRecoveryKey {
    bundle_identity: String,
    recovery_method_identity: String,
    recovery_secret: RecoverySecret,
}

impl LoadedOfflineRecoveryKey {
    pub fn bundle_identity(&self) -> &str {
        &self.bundle_identity
    }

    pub fn recovery_method_identity(&self) -> &str {
        &self.recovery_method_identity
    }

    pub fn recovery_secret(&self) -> &RecoverySecret {
        &self.recovery_secret
    }
}

impl fmt::Debug for LoadedOfflineRecoveryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedOfflineRecoveryKey")
            .field("bundle_identity", &self.bundle_identity)
            .field("recovery_method_identity", &self.recovery_method_identity)
            .field("recovery_secret", &"[REDACTED]")
            .finish()
    }
}

impl OfflineRecoveryRehearsalRequest {
    pub fn new(bundle: impl Into<PathBuf>, document: impl Into<PathBuf>) -> Self {
        Self {
            bundle: bundle.into(),
            document: document.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineRecoveryDocumentReport {
    bundle_identity: String,
    recovery_method_identity: String,
}

impl OfflineRecoveryDocumentReport {
    pub fn bundle_identity(&self) -> &str {
        &self.bundle_identity
    }

    pub fn recovery_method_identity(&self) -> &str {
        &self.recovery_method_identity
    }

    pub fn human_summary(&self) -> &'static str {
        "Offline Recovery Key written. Rehearse it independently before relying on it."
    }

    pub fn machine_json_result(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "command": "recovery offline write",
            "status": "success",
            "data": {
                "bundle_identity": self.bundle_identity,
                "recovery_method_identity": self.recovery_method_identity,
            },
            "warnings": ["independent unlock rehearsal is still required"],
            "errors": [],
        })
        .to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineRecoveryRehearsalReceipt {
    bundle_identity: String,
    recovery_method_identity: String,
    verified_at_unix_seconds: u64,
}

impl OfflineRecoveryRehearsalReceipt {
    pub fn bundle_identity(&self) -> &str {
        &self.bundle_identity
    }

    pub fn recovery_method_identity(&self) -> &str {
        &self.recovery_method_identity
    }

    pub fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }

    pub fn human_summary(&self) -> &'static str {
        "Offline Recovery Key independently unlocked and authenticated the completed Bundle."
    }

    pub fn machine_json_result(&self) -> String {
        serde_json::json!({
            "schema_version": 1,
            "command": "recovery offline rehearse",
            "status": "success",
            "data": {
                "bundle_identity": self.bundle_identity,
                "recovery_method_identity": self.recovery_method_identity,
                "verified_at_unix_seconds": self.verified_at_unix_seconds,
            },
            "warnings": [],
            "errors": [],
        })
        .to_string()
    }
}

#[derive(Debug)]
pub struct OfflineRecoveryEngine<S = LocalOfflineRecoveryStorage> {
    storage: S,
}

impl OfflineRecoveryEngine<LocalOfflineRecoveryStorage> {
    pub fn local() -> Self {
        Self {
            storage: LocalOfflineRecoveryStorage,
        }
    }
}

impl<S> OfflineRecoveryEngine<S> {
    pub fn with_storage(storage: S) -> Self {
        Self { storage }
    }
}

impl<S: OfflineRecoveryStorage> OfflineRecoveryEngine<S> {
    pub fn write(
        &self,
        request: OfflineRecoveryWriteRequest<'_>,
    ) -> Result<OfflineRecoveryDocumentReport, CoreError> {
        if request.recovery_secret.method() != RecoveryMethod::Offline {
            return Err(CoreError::AuthenticationFailed);
        }
        require_document_name(&request.document)?;
        self.storage
            .validate_separate_removable_target(&request.document)
            .map_err(|source| {
                recovery_io(
                    "validate separate recovery storage",
                    &request.document,
                    source,
                )
            })?;
        prepare(
            &self.storage,
            OfflineRecoveryPersistenceTransition::AuthenticateCompletedBundle,
            "authenticate completed Bundle for offline recovery",
            &request.bundle,
        )?;
        let verified = BundleEngine::local()
            .verify(VerifyRequest::new(&request.bundle, request.recovery_secret))?;
        let bundle_identity = verified.bundle_identity().to_owned();
        let recovery_method_identity = recovery_method_identity(&bundle_identity);
        let document = encode_document(
            &bundle_identity,
            &recovery_method_identity,
            request.recovery_secret,
        );

        prepare(
            &self.storage,
            OfflineRecoveryPersistenceTransition::CreateDocument,
            "create Offline Recovery Key document",
            &request.document,
        )?;
        let mut file = create_restricted_document(&request.document)?;
        let created_identity = recovery_document_identity(&file, &request.document)?;
        let persisted = (|| {
            prepare(
                &self.storage,
                OfflineRecoveryPersistenceTransition::RestrictDocument,
                "restrict Offline Recovery Key document",
                &request.document,
            )?;
            restrict_document(&file, &request.document)?;
            prepare(
                &self.storage,
                OfflineRecoveryPersistenceTransition::WriteDocument,
                "write Offline Recovery Key document",
                &request.document,
            )?;
            file.write_all(document.as_bytes()).map_err(|source| {
                recovery_io(
                    "write Offline Recovery Key document",
                    &request.document,
                    source,
                )
            })?;
            prepare(
                &self.storage,
                OfflineRecoveryPersistenceTransition::SynchronizeDocument,
                "synchronize Offline Recovery Key document",
                &request.document,
            )?;
            file.sync_all().map_err(|source| {
                recovery_io(
                    "synchronize Offline Recovery Key document",
                    &request.document,
                    source,
                )
            })
        })();
        drop(file);
        if let Err(error) = persisted {
            remove_owned_failed_document(&request.document, &created_identity);
            return Err(error);
        }
        prepare(
            &self.storage,
            OfflineRecoveryPersistenceTransition::SynchronizeDirectory,
            "synchronize Offline Recovery Key directory",
            &request.document,
        )?;
        synchronize_parent(&request.document)?;

        Ok(OfflineRecoveryDocumentReport {
            bundle_identity,
            recovery_method_identity,
        })
    }

    pub fn rehearse(
        &self,
        request: OfflineRecoveryRehearsalRequest,
    ) -> Result<OfflineRecoveryRehearsalReceipt, CoreError> {
        let loaded = self.load(OfflineRecoveryLoadRequest {
            bundle: request.bundle,
            document: request.document,
        })?;
        let verified_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CoreError::BundleInvalid("system clock precedes Unix epoch".to_owned()))?
            .as_secs();
        Ok(OfflineRecoveryRehearsalReceipt {
            bundle_identity: loaded.bundle_identity,
            recovery_method_identity: loaded.recovery_method_identity,
            verified_at_unix_seconds,
        })
    }

    pub fn load(
        &self,
        request: OfflineRecoveryLoadRequest,
    ) -> Result<LoadedOfflineRecoveryKey, CoreError> {
        prepare(
            &self.storage,
            OfflineRecoveryPersistenceTransition::ReadDocument,
            "read Offline Recovery Key document",
            &request.document,
        )?;
        let decoded = decode_document(&request.document)?;
        prepare(
            &self.storage,
            OfflineRecoveryPersistenceTransition::AuthenticateRehearsal,
            "authenticate Bundle with Offline Recovery Key",
            &request.bundle,
        )?;
        let verified = BundleEngine::local()
            .verify(VerifyRequest::new(
                &request.bundle,
                &decoded.recovery_secret,
            ))
            .map_err(|_| CoreError::AuthenticationFailed)?;
        if verified.bundle_identity() != decoded.bundle_identity
            || recovery_method_identity(verified.bundle_identity())
                != decoded.recovery_method_identity
        {
            return Err(CoreError::AuthenticationFailed);
        }
        Ok(LoadedOfflineRecoveryKey {
            bundle_identity: decoded.bundle_identity,
            recovery_method_identity: decoded.recovery_method_identity,
            recovery_secret: decoded.recovery_secret,
        })
    }

    pub fn lost_document_guidance(&self) -> &'static str {
        "Iniza has no backdoor and cannot reconstruct a lost Offline Recovery Key. Use the independently rehearsed Vaultwarden Recovery Secret, or recover the separately stored document."
    }
}

struct DecodedDocument {
    bundle_identity: String,
    recovery_method_identity: String,
    recovery_secret: RecoverySecret,
}

fn require_document_name(path: &Path) -> Result<(), CoreError> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("iniza-recovery") {
        return Err(CoreError::BundleInvalid(
            "Offline Recovery Key document must end with .iniza-recovery".to_owned(),
        ));
    }
    Ok(())
}

fn recovery_method_identity(bundle_identity: &str) -> String {
    format!("offline:{bundle_identity}:slot-2")
}

fn encode_document(
    bundle_identity: &str,
    recovery_method_identity: &str,
    recovery_secret: &RecoverySecret,
) -> Zeroizing<String> {
    let mut document = Zeroizing::new(format!(
        "{DOCUMENT_HEADER}\nschema_version: {DOCUMENT_SCHEMA_VERSION}\nbundle_identity: {bundle_identity}\nbundle_format: {DOCUMENT_BUNDLE_FORMAT}\nrecovery_method: {DOCUMENT_RECOVERY_METHOD}\nrecovery_method_identity: {recovery_method_identity}\nrecovery_secret_hex: "
    ));
    for byte in recovery_secret.bytes.iter() {
        use std::fmt::Write as _;
        write!(&mut *document, "{byte:02x}").expect("writing to a String cannot fail");
    }
    document.push_str("\ninstructions: ");
    document.push_str(DOCUMENT_INSTRUCTIONS);
    document.push('\n');
    document
}

fn decode_document(path: &Path) -> Result<DecodedDocument, CoreError> {
    require_document_name(path).map_err(|_| CoreError::AuthenticationFailed)?;
    let file = open_document(path).map_err(|_| CoreError::AuthenticationFailed)?;
    let metadata = file
        .metadata()
        .map_err(|_| CoreError::AuthenticationFailed)?;
    if !metadata.is_file() || metadata.len() > MAX_DOCUMENT_BYTES {
        return Err(CoreError::AuthenticationFailed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CoreError::AuthenticationFailed);
        }
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CoreError::AuthenticationFailed)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| CoreError::AuthenticationFailed)?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != 8 || lines[0] != DOCUMENT_HEADER {
        return Err(CoreError::AuthenticationFailed);
    }
    let schema = field(lines[1], "schema_version")?;
    let bundle_identity = field(lines[2], "bundle_identity")?;
    let bundle_format = field(lines[3], "bundle_format")?;
    let recovery_method = field(lines[4], "recovery_method")?;
    let method_identity = field(lines[5], "recovery_method_identity")?;
    let secret_hex = field(lines[6], "recovery_secret_hex")?;
    let instructions = field(lines[7], "instructions")?;
    if schema != DOCUMENT_SCHEMA_VERSION
        || bundle_format != DOCUMENT_BUNDLE_FORMAT
        || recovery_method != DOCUMENT_RECOVERY_METHOD
        || instructions != DOCUMENT_INSTRUCTIONS
        || !valid_lower_hex(bundle_identity, 32)
        || method_identity != recovery_method_identity(bundle_identity)
        || !valid_lower_hex(secret_hex, 64)
    {
        return Err(CoreError::AuthenticationFailed);
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&secret_hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| CoreError::AuthenticationFailed)?;
    }
    Ok(DecodedDocument {
        bundle_identity: bundle_identity.to_owned(),
        recovery_method_identity: method_identity.to_owned(),
        recovery_secret: RecoverySecret::from_bytes(RecoveryMethod::Offline, secret),
    })
}

fn field<'a>(line: &'a str, expected: &str) -> Result<&'a str, CoreError> {
    line.strip_prefix(expected)
        .and_then(|value| value.strip_prefix(": "))
        .ok_or(CoreError::AuthenticationFailed)
}

fn valid_lower_hex(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn prepare(
    storage: &dyn OfflineRecoveryStorage,
    transition: OfflineRecoveryPersistenceTransition,
    action: &'static str,
    path: &Path,
) -> Result<(), CoreError> {
    storage
        .prepare_transition(transition)
        .map_err(|source| recovery_io(action, path, source))
}

fn recovery_io(action: &'static str, path: &Path, source: io::Error) -> CoreError {
    CoreError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

fn create_restricted_document(path: &Path) -> Result<File, CoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path).map_err(|source| match source.kind() {
        io::ErrorKind::AlreadyExists => CoreError::DestinationAlreadyExists(path.to_path_buf()),
        _ => recovery_io("create Offline Recovery Key document", path, source),
    })
}

#[cfg(unix)]
struct RecoveryDocumentIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(unix))]
struct RecoveryDocumentIdentity;

fn recovery_document_identity(
    file: &File,
    path: &Path,
) -> Result<RecoveryDocumentIdentity, CoreError> {
    let metadata = file
        .metadata()
        .map_err(|source| recovery_io("identify Offline Recovery Key document", path, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(RecoveryDocumentIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(RecoveryDocumentIdentity)
    }
}

fn restrict_document(file: &File, path: &Path) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| recovery_io("restrict Offline Recovery Key document", path, source))
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
        Ok(())
    }
}

fn remove_owned_failed_document(path: &Path, expected: &RecoveryDocumentIdentity) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fs::symlink_metadata(path).ok().is_some_and(|metadata| {
            metadata.is_file()
                && metadata.dev() == expected.device
                && metadata.ino() == expected.inode
        }) {
            let _ = fs::remove_file(path);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, expected);
    }
}

fn open_document(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

fn synchronize_parent(path: &Path) -> Result<(), CoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| recovery_io("synchronize Offline Recovery Key directory", parent, source))
}
