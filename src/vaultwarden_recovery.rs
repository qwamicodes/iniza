use std::ffi::CStr;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::{BundleEngine, CoreError, RecoveryMethod, RecoverySecret, VerifyRequest};

const MINIMUM_BITWARDEN_VERSION: (u32, u32, u32) = (2026, 8, 0);
const MAX_TEXT_BYTES: usize = 256;
const DIGEST_HEX_BYTES: usize = 64;
const MAX_BITWARDEN_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_BITWARDEN_SESSION_BYTES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultwardenInstallationRequest {
    TrustedPath,
    Explicit(PathBuf),
}

impl VaultwardenInstallationRequest {
    pub fn trusted_path() -> Self {
        Self::TrustedPath
    }

    pub fn explicit(path: impl Into<PathBuf>) -> Self {
        Self::Explicit(path.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenInstallationObservation {
    executable_path: PathBuf,
    version: String,
    executable_digest: String,
    interpreter_path: Option<PathBuf>,
    interpreter_digest: Option<String>,
}

impl BitwardenInstallationObservation {
    pub fn new(
        executable_path: impl Into<PathBuf>,
        version: impl Into<String>,
        executable_digest: impl Into<String>,
        interpreter_path: Option<impl Into<PathBuf>>,
        interpreter_digest: Option<impl Into<String>>,
    ) -> Result<Self, CoreError> {
        let executable_path = executable_path.into();
        let version = version.into();
        let executable_digest = executable_digest.into();
        let interpreter_path = interpreter_path.map(Into::into);
        let interpreter_digest = interpreter_digest.map(Into::into);
        if !executable_path.is_absolute() {
            return Err(vaultwarden_error(
                "Bitwarden executable path must be absolute",
            ));
        }
        require_supported_version(&version)?;
        require_digest(&executable_digest, "Bitwarden executable identity")?;
        if interpreter_path.is_some() != interpreter_digest.is_some() {
            return Err(vaultwarden_error(
                "Bitwarden interpreter path and identity must appear together",
            ));
        }
        if let Some(path) = &interpreter_path
            && !path.is_absolute()
        {
            return Err(vaultwarden_error(
                "Bitwarden interpreter path must be absolute",
            ));
        }
        if let Some(digest) = &interpreter_digest {
            require_digest(digest, "Bitwarden interpreter identity")?;
        }
        Ok(Self {
            executable_path,
            version,
            executable_digest,
            interpreter_path,
            interpreter_digest,
        })
    }

    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn executable_digest(&self) -> &str {
        &self.executable_digest
    }

    pub fn interpreter_path(&self) -> Option<&Path> {
        self.interpreter_path.as_deref()
    }

    pub fn interpreter_digest(&self) -> Option<&str> {
        self.interpreter_digest.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitwardenVaultState {
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenVaultObservation {
    server_origin: String,
    account_identifier: String,
    state: BitwardenVaultState,
}

impl BitwardenVaultObservation {
    pub fn locked(
        server_origin: impl Into<String>,
        account_identifier: impl Into<String>,
    ) -> Result<Self, CoreError> {
        Self::with_state(
            server_origin.into(),
            account_identifier.into(),
            BitwardenVaultState::Locked,
        )
    }

    pub fn unlocked(
        server_origin: impl Into<String>,
        account_identifier: impl Into<String>,
    ) -> Result<Self, CoreError> {
        Self::with_state(
            server_origin.into(),
            account_identifier.into(),
            BitwardenVaultState::Unlocked,
        )
    }

    fn with_state(
        server_origin: String,
        account_identifier: String,
        state: BitwardenVaultState,
    ) -> Result<Self, CoreError> {
        require_server_origin(&server_origin)?;
        require_uuid(&account_identifier, "Bitwarden account identifier")?;
        Ok(Self {
            server_origin,
            account_identifier,
            state,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VaultwardenItemIdentifier(String);

impl VaultwardenItemIdentifier {
    pub fn parse(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        require_uuid(&value, "Vaultwarden item identifier")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VaultwardenItemIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VaultwardenItemIdentifier")
            .field(&self.0)
            .finish()
    }
}

pub struct BitwardenRecoveryNote<'a> {
    item_name: &'a str,
    bundle_identity: &'a str,
    bundle_format: &'a str,
    created_at: &'a str,
    location_hint: Option<&'a str>,
    recovery_secret: &'a RecoverySecret,
}

impl BitwardenRecoveryNote<'_> {
    pub fn item_name(&self) -> &str {
        self.item_name
    }

    pub fn bundle_identity(&self) -> &str {
        self.bundle_identity
    }

    pub fn bundle_format(&self) -> &str {
        self.bundle_format
    }

    pub fn created_at(&self) -> &str {
        self.created_at
    }

    pub fn location_hint(&self) -> Option<&str> {
        self.location_hint
    }

    pub fn recovery_method(&self) -> RecoveryMethod {
        self.recovery_secret.method()
    }

    /// Encodes the Recovery Secret only for a reviewed external storage adapter.
    ///
    /// The returned allocation is zeroized when dropped. Human and machine
    /// output must never include this value.
    pub fn recovery_secret_hex_for_storage(&self) -> Zeroizing<String> {
        recovery_secret_hex(self.recovery_secret)
    }
}

impl fmt::Debug for BitwardenRecoveryNote<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitwardenRecoveryNote")
            .field("item_name", &self.item_name)
            .field("bundle_identity", &self.bundle_identity)
            .field("bundle_format", &self.bundle_format)
            .field("created_at", &self.created_at)
            .field("location_hint", &self.location_hint)
            .field("recovery_secret", &"[REDACTED]")
            .finish()
    }
}

pub struct BitwardenRetrievedRecoveryNote {
    item_identifier: VaultwardenItemIdentifier,
    item_name: String,
    bundle_identity: String,
    bundle_format: String,
    created_at: String,
    location_hint: Option<String>,
    recovery_secret: RecoverySecret,
}

impl BitwardenRetrievedRecoveryNote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        item_identifier: VaultwardenItemIdentifier,
        item_name: impl Into<String>,
        bundle_identity: impl Into<String>,
        bundle_format: impl Into<String>,
        created_at: impl Into<String>,
        location_hint: Option<impl Into<String>>,
        recovery_secret: RecoverySecret,
    ) -> Result<Self, CoreError> {
        if recovery_secret.method() != RecoveryMethod::Vaultwarden {
            return Err(CoreError::AuthenticationFailed);
        }
        let item_name = item_name.into();
        let bundle_identity = bundle_identity.into();
        let bundle_format = bundle_format.into();
        let created_at = created_at.into();
        let location_hint = location_hint.map(Into::into);
        require_item_name(&item_name)?;
        require_bundle_identity(&bundle_identity)?;
        if bundle_format != "IZ2/IZ1" {
            return Err(vaultwarden_error(
                "Vaultwarden recovery item Bundle format is unsupported",
            ));
        }
        require_timestamp(&created_at)?;
        if let Some(location_hint) = &location_hint {
            require_review_text(location_hint, "Vaultwarden location hint")?;
        }
        Ok(Self {
            item_identifier,
            item_name,
            bundle_identity,
            bundle_format,
            created_at,
            location_hint,
            recovery_secret,
        })
    }
}

impl fmt::Debug for BitwardenRetrievedRecoveryNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitwardenRetrievedRecoveryNote")
            .field("item_identifier", &self.item_identifier)
            .field("item_name", &self.item_name)
            .field("bundle_identity", &self.bundle_identity)
            .field("bundle_format", &self.bundle_format)
            .field("created_at", &self.created_at)
            .field("location_hint", &self.location_hint)
            .field("recovery_secret", &"[REDACTED]")
            .finish()
    }
}

pub trait BitwardenCommandLine: Send + Sync {
    fn inspect_installation(
        &self,
        request: &VaultwardenInstallationRequest,
    ) -> Result<BitwardenInstallationObservation, CoreError>;

    fn status(
        &self,
        installation: &BitwardenInstallationObservation,
    ) -> Result<BitwardenVaultObservation, CoreError>;

    fn create_recovery_note(
        &self,
        installation: &BitwardenInstallationObservation,
        note: &BitwardenRecoveryNote<'_>,
    ) -> Result<VaultwardenItemIdentifier, CoreError>;

    fn synchronize(&self, installation: &BitwardenInstallationObservation)
    -> Result<(), CoreError>;

    fn get_recovery_note(
        &self,
        installation: &BitwardenInstallationObservation,
        item_identifier: &VaultwardenItemIdentifier,
    ) -> Result<BitwardenRetrievedRecoveryNote, CoreError>;
}

#[derive(Debug, Default)]
pub struct InstalledBitwarden;

impl InstalledBitwarden {
    pub fn system() -> Self {
        Self
    }
}

impl BitwardenCommandLine for InstalledBitwarden {
    fn inspect_installation(
        &self,
        request: &VaultwardenInstallationRequest,
    ) -> Result<BitwardenInstallationObservation, CoreError> {
        let selected = match request {
            VaultwardenInstallationRequest::Explicit(path) => fs::canonicalize(path).ok(),
            VaultwardenInstallationRequest::TrustedPath => [
                Path::new("/opt/homebrew/bin/bw"),
                Path::new("/usr/local/bin/bw"),
            ]
            .into_iter()
            .find_map(|path| fs::canonicalize(path).ok()),
        };
        let Some(selected) = selected else {
            return Err(missing_bitwarden_guidance());
        };
        inspect_installed_bitwarden(&selected)
    }

    fn status(
        &self,
        installation: &BitwardenInstallationObservation,
    ) -> Result<BitwardenVaultObservation, CoreError> {
        let current = inspect_installed_bitwarden(installation.executable_path())?;
        if current != *installation {
            return Err(vaultwarden_error(
                "Bitwarden installation changed after review",
            ));
        }
        let home = trusted_user_home()?;
        let session = bitwarden_session_from_environment()?;
        let output = run_bitwarden_status(&current, &home, session.as_deref().map(String::as_str))?;
        let status: StrictBitwardenStatus = serde_json::from_slice(&output).map_err(|_| {
            vaultwarden_error(
                "Bitwarden status response was rejected without exposing external output",
            )
        })?;
        status.into_observation(session.is_some())
    }

    fn create_recovery_note(
        &self,
        installation: &BitwardenInstallationObservation,
        note: &BitwardenRecoveryNote<'_>,
    ) -> Result<VaultwardenItemIdentifier, CoreError> {
        if note.recovery_secret.method() != RecoveryMethod::Vaultwarden {
            return Err(CoreError::AuthenticationFailed);
        }
        let home = trusted_user_home()?;
        let session = bitwarden_session_from_environment()?.ok_or_else(|| {
            vaultwarden_error(
                "Unlock the official Bitwarden command-line client outside Iniza, then retry. Iniza never asks for your Vaultwarden master password.",
            )
        })?;
        let secret_hex = note.recovery_secret_hex_for_storage();
        let mut fields = vec![
            ExactBitwardenField::text("iniza_bundle_id", note.bundle_identity),
            ExactBitwardenField::text("iniza_format", note.bundle_format),
            ExactBitwardenField::hidden("iniza_secret", &secret_hex),
            ExactBitwardenField::text("iniza_created_at", note.created_at),
        ];
        if let Some(location_hint) = note.location_hint {
            fields.push(ExactBitwardenField::text(
                "iniza_location_hint",
                location_hint,
            ));
        }
        let secure_note = ExactBitwardenSecureNote {
            item_type: 2,
            name: note.item_name,
            secure_note: ExactBitwardenSecureNoteSubtype { note_type: 0 },
            fields,
        };
        let mut note_json = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *note_json, &secure_note).map_err(|_| {
            vaultwarden_error("Vaultwarden recovery item could not be encoded safely")
        })?;
        let mut encoded = run_bitwarden_command(
            installation,
            &home,
            None,
            &["encode", "--nointeraction"],
            Some(&note_json),
            "encoding",
        )?;
        trim_single_line(&mut encoded);
        if encoded.is_empty()
            || encoded.len() > 64 * 1024
            || !encoded
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(vaultwarden_error(
                "Bitwarden encoding response was rejected without exposing external output",
            ));
        }
        let created = run_bitwarden_command(
            installation,
            &home,
            Some(session.as_str()),
            &["create", "item", "--nointeraction"],
            Some(&encoded),
            "recovery item creation",
        )?;
        let created: BitwardenCreatedItem = serde_json::from_slice(&created).map_err(|_| {
            vaultwarden_error(
                "Bitwarden recovery item creation response was rejected without exposing external output",
            )
        })?;
        VaultwardenItemIdentifier::parse(created.id)
    }

    fn synchronize(
        &self,
        installation: &BitwardenInstallationObservation,
    ) -> Result<(), CoreError> {
        let home = trusted_user_home()?;
        let session = bitwarden_session_from_environment()?.ok_or_else(|| {
            vaultwarden_error(
                "Unlock the official Bitwarden command-line client outside Iniza, then retry. Iniza never asks for your Vaultwarden master password.",
            )
        })?;
        let output = run_bitwarden_command(
            installation,
            &home,
            Some(session.as_str()),
            &["sync", "--response", "--nointeraction"],
            None,
            "synchronization",
        )?;
        let response: StrictBitwardenSynchronization = serde_json::from_slice(&output).map_err(|_| {
            vaultwarden_error(
                "Bitwarden synchronization response was rejected without exposing external output",
            )
        })?;
        if !response.success
            || response.data.object != "message"
            || response.data.title != "Syncing complete."
            || response.data.message.is_some()
            || response.data.no_color
        {
            return Err(vaultwarden_error(
                "Bitwarden synchronization response was rejected without exposing external output",
            ));
        }
        Ok(())
    }

    fn get_recovery_note(
        &self,
        installation: &BitwardenInstallationObservation,
        item_identifier: &VaultwardenItemIdentifier,
    ) -> Result<BitwardenRetrievedRecoveryNote, CoreError> {
        let home = trusted_user_home()?;
        let session = bitwarden_session_from_environment()?.ok_or_else(|| {
            vaultwarden_error(
                "Unlock the official Bitwarden command-line client outside Iniza, then retry. Iniza never asks for your Vaultwarden master password.",
            )
        })?;
        let output = run_bitwarden_command(
            installation,
            &home,
            Some(session.as_str()),
            &["get", "item", item_identifier.as_str(), "--nointeraction"],
            None,
            "recovery item retrieval",
        )?;
        parse_retrieved_recovery_note(&output, item_identifier)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultwardenInstallationReport {
    request: VaultwardenInstallationRequest,
    observation: BitwardenInstallationObservation,
    review_hash: String,
}

impl VaultwardenInstallationReport {
    pub fn executable_path(&self) -> &Path {
        self.observation.executable_path()
    }

    pub fn version(&self) -> &str {
        self.observation.version()
    }

    pub fn review_hash(&self) -> &str {
        &self.review_hash
    }

    pub fn human_summary(&self) -> String {
        let interpreter = self
            .observation
            .interpreter_path()
            .map(|path| format!("; interpreter {}", path.display()))
            .unwrap_or_default();
        format!(
            "Bitwarden executable {} version {}{interpreter}; review hash {}",
            self.observation.executable_path().display(),
            self.observation.version(),
            self.review_hash
        )
    }

    pub fn machine_json_result(&self) -> String {
        json!({
            "schema_version": 1,
            "command": "recovery vaultwarden inspect-installation",
            "status": "review-required",
            "data": {
                "executable_path": self.observation.executable_path,
                "version": self.observation.version,
                "executable_identity": self.observation.executable_digest,
                "interpreter_path": self.observation.interpreter_path,
                "interpreter_identity": self.observation.interpreter_digest,
                "review_hash": self.review_hash,
            },
            "warnings": ["review the selected executable and version before credentialed work"],
            "errors": [],
        })
        .to_string()
    }
}

pub struct VaultwardenPreflightRequest<'a> {
    bundle: PathBuf,
    recovery_secret: &'a RecoverySecret,
    friendly_bundle_name: String,
    location_hint: Option<String>,
    installation: &'a VaultwardenInstallationReport,
    reviewed_installation_hash: String,
}

impl<'a> VaultwardenPreflightRequest<'a> {
    pub fn new(
        bundle: impl Into<PathBuf>,
        recovery_secret: &'a RecoverySecret,
        friendly_bundle_name: impl Into<String>,
        location_hint: Option<impl Into<String>>,
        installation: &'a VaultwardenInstallationReport,
        reviewed_installation_hash: impl Into<String>,
    ) -> Self {
        Self {
            bundle: bundle.into(),
            recovery_secret,
            friendly_bundle_name: friendly_bundle_name.into(),
            location_hint: location_hint.map(Into::into),
            installation,
            reviewed_installation_hash: reviewed_installation_hash.into(),
        }
    }
}

impl fmt::Debug for VaultwardenPreflightRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultwardenPreflightRequest")
            .field("bundle", &"[REDACTED PATH]")
            .field("recovery_secret", &"[REDACTED]")
            .field("friendly_bundle_name", &self.friendly_bundle_name)
            .field("location_hint", &self.location_hint)
            .field(
                "reviewed_installation_hash",
                &self.reviewed_installation_hash,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultwardenPreflightReport {
    installation_request: VaultwardenInstallationRequest,
    installation: BitwardenInstallationObservation,
    installation_review_hash: String,
    server_origin: String,
    server_identity_hash: String,
    account_identity_hash: String,
    vault_state: &'static str,
    bundle_identity: String,
    bundle_format: String,
    item_name: String,
    created_at: String,
    location_hint: Option<String>,
    review_hash: String,
}

impl VaultwardenPreflightReport {
    pub fn vault_state(&self) -> &str {
        self.vault_state
    }

    pub fn server_origin(&self) -> &str {
        &self.server_origin
    }

    pub fn server_identity_hash(&self) -> &str {
        &self.server_identity_hash
    }

    pub fn bundle_identity(&self) -> &str {
        &self.bundle_identity
    }

    pub fn item_name(&self) -> &str {
        &self.item_name
    }

    pub fn review_hash(&self) -> &str {
        &self.review_hash
    }

    pub fn machine_json_result(&self) -> String {
        json!({
            "schema_version": 1,
            "command": "recovery vaultwarden preflight",
            "status": "review-required",
            "data": {
                "server_origin": self.server_origin,
                "server_identity_hash": self.server_identity_hash,
                "vault_state": self.vault_state,
                "bundle_identity": self.bundle_identity,
                "bundle_format": self.bundle_format,
                "item_name": self.item_name,
                "created_at": self.created_at,
                "location_hint": self.location_hint,
                "review_hash": self.review_hash,
            },
            "warnings": ["creating a Vaultwarden recovery item changes an external service"],
            "errors": [],
        })
        .to_string()
    }
}

pub struct VaultwardenStoreRequest<'a> {
    bundle: PathBuf,
    recovery_secret: &'a RecoverySecret,
    preflight: &'a VaultwardenPreflightReport,
    reviewed_preflight_hash: String,
}

pub struct VaultwardenLoadRequest<'a> {
    bundle: PathBuf,
    item_identifier: VaultwardenItemIdentifier,
    expected_server_identity_hash: String,
    installation: &'a VaultwardenInstallationReport,
    reviewed_installation_hash: String,
}

impl<'a> VaultwardenLoadRequest<'a> {
    pub fn new(
        bundle: impl Into<PathBuf>,
        item_identifier: VaultwardenItemIdentifier,
        expected_server_identity_hash: impl Into<String>,
        installation: &'a VaultwardenInstallationReport,
        reviewed_installation_hash: impl Into<String>,
    ) -> Self {
        Self {
            bundle: bundle.into(),
            item_identifier,
            expected_server_identity_hash: expected_server_identity_hash.into(),
            installation,
            reviewed_installation_hash: reviewed_installation_hash.into(),
        }
    }
}

impl fmt::Debug for VaultwardenLoadRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultwardenLoadRequest")
            .field("bundle", &"[REDACTED PATH]")
            .field("item_identifier", &self.item_identifier)
            .field(
                "expected_server_identity_hash",
                &self.expected_server_identity_hash,
            )
            .field(
                "reviewed_installation_hash",
                &self.reviewed_installation_hash,
            )
            .finish_non_exhaustive()
    }
}

pub struct VaultwardenRehearsalRequest<'a>(VaultwardenLoadRequest<'a>);

impl<'a> VaultwardenRehearsalRequest<'a> {
    pub fn new(
        bundle: impl Into<PathBuf>,
        item_identifier: VaultwardenItemIdentifier,
        expected_server_identity_hash: impl Into<String>,
        installation: &'a VaultwardenInstallationReport,
        reviewed_installation_hash: impl Into<String>,
    ) -> Self {
        Self(VaultwardenLoadRequest::new(
            bundle,
            item_identifier,
            expected_server_identity_hash,
            installation,
            reviewed_installation_hash,
        ))
    }
}

impl fmt::Debug for VaultwardenRehearsalRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VaultwardenRehearsalRequest")
            .field(&self.0)
            .finish()
    }
}

impl<'a> VaultwardenStoreRequest<'a> {
    pub fn new(
        bundle: impl Into<PathBuf>,
        recovery_secret: &'a RecoverySecret,
        preflight: &'a VaultwardenPreflightReport,
        reviewed_preflight_hash: impl Into<String>,
    ) -> Self {
        Self {
            bundle: bundle.into(),
            recovery_secret,
            preflight,
            reviewed_preflight_hash: reviewed_preflight_hash.into(),
        }
    }
}

impl fmt::Debug for VaultwardenStoreRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultwardenStoreRequest")
            .field("bundle", &"[REDACTED PATH]")
            .field("recovery_secret", &"[REDACTED]")
            .field("reviewed_preflight_hash", &self.reviewed_preflight_hash)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultwardenStoreState {
    Verified,
    ItemCreatedButUnverified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultwardenRecoveryReceipt {
    bundle_identity: String,
    recovery_method_identity: String,
    item_identifier: VaultwardenItemIdentifier,
    server_identity_hash: String,
    verified_at_unix_seconds: u64,
}

impl VaultwardenRecoveryReceipt {
    pub fn bundle_identity(&self) -> &str {
        &self.bundle_identity
    }

    pub fn recovery_method_identity(&self) -> &str {
        &self.recovery_method_identity
    }

    pub fn item_identifier(&self) -> &VaultwardenItemIdentifier {
        &self.item_identifier
    }

    pub fn server_identity_hash(&self) -> &str {
        &self.server_identity_hash
    }

    pub fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }
}

pub struct LoadedVaultwardenRecoverySecret {
    bundle_identity: String,
    recovery_method_identity: String,
    item_identifier: VaultwardenItemIdentifier,
    server_identity_hash: String,
    recovery_secret: RecoverySecret,
}

impl LoadedVaultwardenRecoverySecret {
    pub fn bundle_identity(&self) -> &str {
        &self.bundle_identity
    }

    pub fn recovery_method_identity(&self) -> &str {
        &self.recovery_method_identity
    }

    pub fn item_identifier(&self) -> &VaultwardenItemIdentifier {
        &self.item_identifier
    }

    pub fn server_identity_hash(&self) -> &str {
        &self.server_identity_hash
    }

    pub fn recovery_secret(&self) -> &RecoverySecret {
        &self.recovery_secret
    }
}

impl fmt::Debug for LoadedVaultwardenRecoverySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedVaultwardenRecoverySecret")
            .field("bundle_identity", &self.bundle_identity)
            .field("recovery_method_identity", &self.recovery_method_identity)
            .field("item_identifier", &self.item_identifier)
            .field("server_identity_hash", &self.server_identity_hash)
            .field("recovery_secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultwardenStoreReport {
    state: VaultwardenStoreState,
    item_identifier: Option<VaultwardenItemIdentifier>,
    receipt: Option<VaultwardenRecoveryReceipt>,
}

impl VaultwardenStoreReport {
    pub fn state(&self) -> VaultwardenStoreState {
        self.state
    }

    pub fn item_identifier(&self) -> Option<&VaultwardenItemIdentifier> {
        self.item_identifier.as_ref()
    }

    pub fn receipt(&self) -> Option<&VaultwardenRecoveryReceipt> {
        self.receipt.as_ref()
    }

    pub fn human_summary(&self) -> &'static str {
        match self.state {
            VaultwardenStoreState::Verified => {
                "Vaultwarden Recovery Secret independently unlocked and authenticated the completed Bundle."
            }
            VaultwardenStoreState::ItemCreatedButUnverified => {
                "The exact Vaultwarden recovery item was retained and is not yet verified. Retry rehearsal by its item identifier; the independent Offline Recovery Key remains usable."
            }
        }
    }

    pub fn machine_json_result(&self) -> String {
        let (status, state, warnings, errors) = match self.state {
            VaultwardenStoreState::Verified => (
                "success",
                "verified",
                Vec::<&str>::new(),
                Vec::<&str>::new(),
            ),
            VaultwardenStoreState::ItemCreatedButUnverified => (
                "partial",
                "item-created-but-unverified",
                vec![
                    "the exact item was retained; retry rehearsal by its item identifier",
                    "the independent Offline Recovery Key remains usable",
                ],
                vec!["Vaultwarden recovery verification did not complete"],
            ),
        };
        let receipt = self.receipt.as_ref().map(|receipt| {
            json!({
                "bundle_identity": receipt.bundle_identity,
                "recovery_method_identity": receipt.recovery_method_identity,
                "item_identifier": receipt.item_identifier.as_str(),
                "server_identity_hash": receipt.server_identity_hash,
                "verified_at_unix_seconds": receipt.verified_at_unix_seconds,
            })
        });
        json!({
            "schema_version": 1,
            "command": "recovery vaultwarden store-and-rehearse",
            "status": status,
            "data": {
                "state": state,
                "item_identifier": self.item_identifier.as_ref().map(VaultwardenItemIdentifier::as_str),
                "receipt": receipt,
            },
            "warnings": warnings,
            "errors": errors,
        })
        .to_string()
    }
}

#[derive(Debug)]
pub struct VaultwardenRecoveryEngine<C> {
    command_line: C,
}

impl<C> VaultwardenRecoveryEngine<C> {
    pub fn with_command_line(command_line: C) -> Self {
        Self { command_line }
    }

    pub fn command_line(&self) -> &C {
        &self.command_line
    }
}

impl<C: BitwardenCommandLine> VaultwardenRecoveryEngine<C> {
    pub fn inspect_installation(
        &self,
        request: VaultwardenInstallationRequest,
    ) -> Result<VaultwardenInstallationReport, CoreError> {
        let observation = self.command_line.inspect_installation(&request)?;
        let review_hash = installation_review_hash(&observation);
        Ok(VaultwardenInstallationReport {
            request,
            observation,
            review_hash,
        })
    }

    pub fn preflight(
        &self,
        request: VaultwardenPreflightRequest<'_>,
    ) -> Result<VaultwardenPreflightReport, CoreError> {
        require_review_hash(
            &request.reviewed_installation_hash,
            request.installation.review_hash(),
            "Bitwarden installation review hash does not match",
        )?;
        if request.recovery_secret.method() != RecoveryMethod::Vaultwarden {
            return Err(CoreError::AuthenticationFailed);
        }
        require_review_text(&request.friendly_bundle_name, "friendly Bundle name")?;
        if let Some(location_hint) = &request.location_hint {
            require_review_text(location_hint, "Vaultwarden location hint")?;
        }
        let current = self
            .command_line
            .inspect_installation(&request.installation.request)?;
        if current != request.installation.observation {
            return Err(vaultwarden_error(
                "Bitwarden installation changed after review",
            ));
        }
        let vault = self.command_line.status(&current)?;
        if vault.state != BitwardenVaultState::Unlocked {
            return Err(vaultwarden_error(
                "Unlock the official Bitwarden command-line client outside Iniza, then retry. Iniza never asks for your Vaultwarden master password.",
            ));
        }
        let verified = BundleEngine::local()
            .verify(VerifyRequest::new(&request.bundle, request.recovery_secret))?;
        let bundle_identity = verified.bundle_identity().to_owned();
        let bundle_format = format!(
            "IZ{}/{}",
            verified.summary.format_version, verified.summary.cryptographic_suite
        );
        let now = unix_time()?;
        let created_at = format_utc_timestamp(now);
        let item_name = format!(
            "Iniza Recovery — {} — {}",
            request.friendly_bundle_name,
            &created_at[..10]
        );
        let server_identity_hash = identity_hash(
            b"iniza vaultwarden server identity v1",
            &vault.server_origin,
        );
        let account_identity_hash = identity_hash(
            b"iniza vaultwarden account identity v1",
            &vault.account_identifier,
        );
        let review_hash = preflight_review_hash(
            request.installation.review_hash(),
            &server_identity_hash,
            &account_identity_hash,
            &bundle_identity,
            &bundle_format,
            &item_name,
            &created_at,
            request.location_hint.as_deref(),
        );
        Ok(VaultwardenPreflightReport {
            installation_request: request.installation.request.clone(),
            installation: current,
            installation_review_hash: request.installation.review_hash.clone(),
            server_origin: vault.server_origin,
            server_identity_hash,
            account_identity_hash,
            vault_state: "unlocked",
            bundle_identity,
            bundle_format,
            item_name,
            created_at,
            location_hint: request.location_hint,
            review_hash,
        })
    }

    pub fn store_and_rehearse(
        &self,
        request: VaultwardenStoreRequest<'_>,
    ) -> Result<VaultwardenStoreReport, CoreError> {
        require_review_hash(
            &request.reviewed_preflight_hash,
            request.preflight.review_hash(),
            "Vaultwarden preflight review hash does not match",
        )?;
        if request.recovery_secret.method() != RecoveryMethod::Vaultwarden {
            return Err(CoreError::AuthenticationFailed);
        }
        let current = self
            .command_line
            .inspect_installation(&request.preflight.installation_request)?;
        if current != request.preflight.installation
            || installation_review_hash(&current) != request.preflight.installation_review_hash
        {
            return Err(vaultwarden_error(
                "Bitwarden installation changed after preflight review",
            ));
        }
        let vault = self.command_line.status(&current)?;
        let server_identity_hash = identity_hash(
            b"iniza vaultwarden server identity v1",
            &vault.server_origin,
        );
        let account_identity_hash = identity_hash(
            b"iniza vaultwarden account identity v1",
            &vault.account_identifier,
        );
        if vault.state != BitwardenVaultState::Unlocked
            || server_identity_hash != request.preflight.server_identity_hash
            || account_identity_hash != request.preflight.account_identity_hash
        {
            return Err(vaultwarden_error(
                "Bitwarden server, account, or vault state changed after preflight review",
            ));
        }
        let verified = BundleEngine::local()
            .verify(VerifyRequest::new(&request.bundle, request.recovery_secret))?;
        let bundle_format = format!(
            "IZ{}/{}",
            verified.summary.format_version, verified.summary.cryptographic_suite
        );
        if verified.bundle_identity() != request.preflight.bundle_identity
            || bundle_format != request.preflight.bundle_format
        {
            return Err(CoreError::AuthenticationFailed);
        }
        let note = BitwardenRecoveryNote {
            item_name: &request.preflight.item_name,
            bundle_identity: &request.preflight.bundle_identity,
            bundle_format: &request.preflight.bundle_format,
            created_at: &request.preflight.created_at,
            location_hint: request.preflight.location_hint.as_deref(),
            recovery_secret: request.recovery_secret,
        };
        let item_identifier = self.command_line.create_recovery_note(&current, &note)?;
        let receipt = (|| {
            self.command_line.synchronize(&current)?;
            let retrieved = self
                .command_line
                .get_recovery_note(&current, &item_identifier)?;
            if retrieved.item_identifier != item_identifier
                || retrieved.item_name != request.preflight.item_name
                || retrieved.bundle_identity != request.preflight.bundle_identity
                || retrieved.bundle_format != request.preflight.bundle_format
                || retrieved.created_at != request.preflight.created_at
                || retrieved.location_hint != request.preflight.location_hint
            {
                return Err(CoreError::AuthenticationFailed);
            }
            let rehearsed = BundleEngine::local()
                .verify(VerifyRequest::new(
                    &request.bundle,
                    &retrieved.recovery_secret,
                ))
                .map_err(|_| CoreError::AuthenticationFailed)?;
            if rehearsed.bundle_identity() != request.preflight.bundle_identity {
                return Err(CoreError::AuthenticationFailed);
            }
            Ok(VaultwardenRecoveryReceipt {
                bundle_identity: request.preflight.bundle_identity.clone(),
                recovery_method_identity: format!(
                    "vaultwarden:{}:slot-1",
                    request.preflight.bundle_identity
                ),
                item_identifier: item_identifier.clone(),
                server_identity_hash: request.preflight.server_identity_hash.clone(),
                verified_at_unix_seconds: unix_time()?,
            })
        })();
        match receipt {
            Ok(receipt) => Ok(VaultwardenStoreReport {
                state: VaultwardenStoreState::Verified,
                item_identifier: Some(item_identifier),
                receipt: Some(receipt),
            }),
            Err(_) => Ok(VaultwardenStoreReport {
                state: VaultwardenStoreState::ItemCreatedButUnverified,
                item_identifier: Some(item_identifier),
                receipt: None,
            }),
        }
    }

    pub fn rehearse(
        &self,
        request: VaultwardenRehearsalRequest<'_>,
    ) -> Result<VaultwardenRecoveryReceipt, CoreError> {
        let loaded = self.load(request.0)?;
        Ok(VaultwardenRecoveryReceipt {
            bundle_identity: loaded.bundle_identity,
            recovery_method_identity: loaded.recovery_method_identity,
            item_identifier: loaded.item_identifier,
            server_identity_hash: loaded.server_identity_hash,
            verified_at_unix_seconds: unix_time()?,
        })
    }

    pub fn load(
        &self,
        request: VaultwardenLoadRequest<'_>,
    ) -> Result<LoadedVaultwardenRecoverySecret, CoreError> {
        require_digest(
            &request.expected_server_identity_hash,
            "Vaultwarden server identity hash",
        )?;
        require_review_hash(
            &request.reviewed_installation_hash,
            request.installation.review_hash(),
            "Bitwarden installation review hash does not match",
        )?;
        let current = self
            .command_line
            .inspect_installation(&request.installation.request)?;
        if current != request.installation.observation
            || installation_review_hash(&current) != request.installation.review_hash
        {
            return Err(vaultwarden_error(
                "Bitwarden installation changed after review",
            ));
        }
        let vault = self.command_line.status(&current)?;
        let server_identity_hash = identity_hash(
            b"iniza vaultwarden server identity v1",
            &vault.server_origin,
        );
        if vault.state != BitwardenVaultState::Unlocked
            || server_identity_hash != request.expected_server_identity_hash
        {
            return Err(vaultwarden_error(
                "Bitwarden server or vault state does not match the reviewed recovery item",
            ));
        }
        self.command_line.synchronize(&current)?;
        let retrieved = self
            .command_line
            .get_recovery_note(&current, &request.item_identifier)?;
        if retrieved.item_identifier != request.item_identifier {
            return Err(CoreError::AuthenticationFailed);
        }
        let verified = BundleEngine::local()
            .verify(VerifyRequest::new(
                &request.bundle,
                &retrieved.recovery_secret,
            ))
            .map_err(|_| CoreError::AuthenticationFailed)?;
        let bundle_format = format!(
            "IZ{}/{}",
            verified.summary.format_version, verified.summary.cryptographic_suite
        );
        if verified.bundle_identity() != retrieved.bundle_identity
            || bundle_format != retrieved.bundle_format
        {
            return Err(CoreError::AuthenticationFailed);
        }
        let bundle_identity = retrieved.bundle_identity;
        Ok(LoadedVaultwardenRecoverySecret {
            recovery_method_identity: format!("vaultwarden:{bundle_identity}:slot-1"),
            bundle_identity,
            item_identifier: retrieved.item_identifier,
            server_identity_hash,
            recovery_secret: retrieved.recovery_secret,
        })
    }
}

fn vaultwarden_error(message: impl Into<String>) -> CoreError {
    CoreError::Vaultwarden(message.into())
}

fn missing_bitwarden_guidance() -> CoreError {
    vaultwarden_error(
        "Official Bitwarden command-line software was not found. Install it with `brew install bitwarden-cli`, then inspect it again. Iniza will not use an alternate Vaultwarden protocol.",
    )
}

#[derive(Serialize)]
struct ExactBitwardenSecureNote<'a> {
    #[serde(rename = "type")]
    item_type: u8,
    name: &'a str,
    #[serde(rename = "secureNote")]
    secure_note: ExactBitwardenSecureNoteSubtype,
    fields: Vec<ExactBitwardenField<'a>>,
}

#[derive(Serialize)]
struct ExactBitwardenSecureNoteSubtype {
    #[serde(rename = "type")]
    note_type: u8,
}

#[derive(Serialize)]
struct ExactBitwardenField<'a> {
    name: &'a str,
    value: &'a str,
    #[serde(rename = "type")]
    field_type: u8,
}

impl<'a> ExactBitwardenField<'a> {
    fn text(name: &'a str, value: &'a str) -> Self {
        Self {
            name,
            value,
            field_type: 0,
        }
    }

    fn hidden(name: &'a str, value: &'a str) -> Self {
        Self {
            name,
            value,
            field_type: 1,
        }
    }
}

#[derive(Deserialize)]
struct BitwardenCreatedItem {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictBitwardenSynchronization {
    success: bool,
    data: StrictBitwardenSynchronizationMessage,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictBitwardenSynchronizationMessage {
    object: String,
    title: String,
    message: Option<String>,
    #[serde(rename = "noColor")]
    no_color: bool,
}

struct SensitiveExternalText(Zeroizing<String>);

impl SensitiveExternalText {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for SensitiveExternalText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SensitiveTextVisitor;

        impl serde::de::Visitor<'_> for SensitiveTextVisitor {
            type Value = SensitiveExternalText;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded text value")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SensitiveExternalText(Zeroizing::new(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SensitiveExternalText(Zeroizing::new(value)))
            }
        }

        deserializer.deserialize_string(SensitiveTextVisitor)
    }
}

#[derive(Deserialize)]
struct StrictBitwardenRetrievedItem {
    object: String,
    id: String,
    #[serde(rename = "type")]
    item_type: u8,
    name: SensitiveExternalText,
    fields: Vec<StrictBitwardenRetrievedField>,
    #[serde(rename = "secureNote")]
    secure_note: StrictBitwardenSecureNoteSubtype,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictBitwardenRetrievedField {
    name: String,
    value: SensitiveExternalText,
    #[serde(rename = "type")]
    field_type: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictBitwardenSecureNoteSubtype {
    #[serde(rename = "type")]
    note_type: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictBitwardenStatus {
    #[serde(rename = "serverUrl")]
    server_url: Option<String>,
    #[serde(rename = "lastSync")]
    last_sync: Option<String>,
    #[serde(rename = "userEmail")]
    user_email: Option<String>,
    #[serde(rename = "userId")]
    user_identifier: Option<String>,
    status: String,
}

impl StrictBitwardenStatus {
    fn into_observation(
        self,
        session_was_available: bool,
    ) -> Result<BitwardenVaultObservation, CoreError> {
        if let Some(last_sync) = &self.last_sync {
            require_external_text(last_sync, "Bitwarden last synchronization time")?;
        }
        if let Some(user_email) = &self.user_email
            && (user_email.len() > 320
                || user_email.is_empty()
                || user_email.chars().any(char::is_control))
        {
            return Err(vaultwarden_error(
                "Bitwarden status response was rejected without exposing external output",
            ));
        }
        let server_origin = self.server_url.ok_or_else(|| {
            vaultwarden_error(
                "Bitwarden status response does not identify the reviewed Vaultwarden server",
            )
        })?;
        let account_identifier = self.user_identifier.ok_or_else(|| {
            vaultwarden_error(
                "Bitwarden status response does not identify the reviewed Vaultwarden account",
            )
        })?;
        match self.status.as_str() {
            "unlocked" if session_was_available => {
                BitwardenVaultObservation::unlocked(server_origin, account_identifier)
            }
            "unlocked" => Err(vaultwarden_error(
                "Bitwarden reported an unlocked vault without a short-lived BW_SESSION value",
            )),
            "locked" => BitwardenVaultObservation::locked(server_origin, account_identifier),
            _ => Err(vaultwarden_error(
                "Bitwarden status response contains an unsupported vault state",
            )),
        }
    }
}

fn parse_retrieved_recovery_note(
    output: &[u8],
    expected_identifier: &VaultwardenItemIdentifier,
) -> Result<BitwardenRetrievedRecoveryNote, CoreError> {
    let item: StrictBitwardenRetrievedItem =
        serde_json::from_slice(output).map_err(|_| CoreError::AuthenticationFailed)?;
    if item.object != "item"
        || item.id != expected_identifier.as_str()
        || item.item_type != 2
        || item.secure_note.note_type != 0
        || !(item.fields.len() == 4 || item.fields.len() == 5)
    {
        return Err(CoreError::AuthenticationFailed);
    }

    let mut bundle_identity = None;
    let mut bundle_format = None;
    let mut recovery_secret_hex = None;
    let mut created_at = None;
    let mut location_hint = None;
    for field in &item.fields {
        let slot = match field.name.as_str() {
            "iniza_bundle_id" if field.field_type == 0 => &mut bundle_identity,
            "iniza_format" if field.field_type == 0 => &mut bundle_format,
            "iniza_secret" if field.field_type == 1 => &mut recovery_secret_hex,
            "iniza_created_at" if field.field_type == 0 => &mut created_at,
            "iniza_location_hint" if field.field_type == 0 => &mut location_hint,
            _ => return Err(CoreError::AuthenticationFailed),
        };
        if slot.replace(field.value.as_str()).is_some() {
            return Err(CoreError::AuthenticationFailed);
        }
    }
    let bundle_identity = bundle_identity.ok_or(CoreError::AuthenticationFailed)?;
    let bundle_format = bundle_format.ok_or(CoreError::AuthenticationFailed)?;
    let recovery_secret_hex = recovery_secret_hex.ok_or(CoreError::AuthenticationFailed)?;
    let created_at = created_at.ok_or(CoreError::AuthenticationFailed)?;
    let recovery_secret = decode_vaultwarden_recovery_secret(recovery_secret_hex)?;

    BitwardenRetrievedRecoveryNote::new(
        expected_identifier.clone(),
        item.name.as_str(),
        bundle_identity,
        bundle_format,
        created_at,
        location_hint,
        recovery_secret,
    )
}

fn decode_vaultwarden_recovery_secret(value: &str) -> Result<RecoverySecret, CoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CoreError::AuthenticationFailed);
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| CoreError::AuthenticationFailed)?;
    }
    Ok(RecoverySecret::from_bytes(
        RecoveryMethod::Vaultwarden,
        bytes,
    ))
}

fn bitwarden_session_from_environment() -> Result<Option<Zeroizing<String>>, CoreError> {
    let session = match std::env::var("BW_SESSION") {
        Ok(session) => session,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(vaultwarden_error(
                "BW_SESSION must be valid text supplied by the official Bitwarden command-line client",
            ));
        }
    };
    if session.is_empty()
        || session.len() > MAX_BITWARDEN_SESSION_BYTES
        || !session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(vaultwarden_error(
            "BW_SESSION is invalid; unlock the official Bitwarden command-line client again outside Iniza",
        ));
    }
    Ok(Some(Zeroizing::new(session)))
}

fn run_bitwarden_status(
    installation: &BitwardenInstallationObservation,
    home: &Path,
    session: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    run_bitwarden_command(
        installation,
        home,
        session,
        &["status", "--nointeraction"],
        None,
        "status",
    )
}

fn run_bitwarden_command(
    installation: &BitwardenInstallationObservation,
    home: &Path,
    session: Option<&str>,
    arguments: &[&str],
    standard_input: Option<&[u8]>,
    operation: &'static str,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    revalidate_installation_identity(installation)?;
    let mut command = reviewed_bitwarden_command(installation);
    command
        .args(arguments)
        .env_clear()
        .env("HOME", home)
        .stdin(if standard_input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(session) = session {
        command.env("BW_SESSION", session);
    }
    let mut child = command.spawn().map_err(|_| {
        vaultwarden_error(format!(
            "Bitwarden {operation} failed without exposing external output or credential material"
        ))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        vaultwarden_error(format!(
            "Bitwarden {operation} failed without exposing external output or credential material"
        ))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        vaultwarden_error(format!(
            "Bitwarden {operation} failed without exposing external output or credential material"
        ))
    })?;
    let stdout_reader = thread::spawn(move || read_bounded_output(stdout));
    let stderr_reader = thread::spawn(move || read_bounded_output(stderr));
    if let Some(standard_input) = standard_input {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            vaultwarden_error(format!(
                "Bitwarden {operation} failed without exposing external output or credential material"
            ))
        })?;
        stdin.write_all(standard_input).map_err(|_| {
            vaultwarden_error(format!(
                "Bitwarden {operation} failed without exposing external output or credential material"
            ))
        })?;
    }
    let status = child.wait().map_err(|_| {
        vaultwarden_error(format!(
            "Bitwarden {operation} failed without exposing external output or credential material"
        ))
    })?;
    let stdout = stdout_reader.join().ok().and_then(Result::ok);
    let stderr = stderr_reader.join().ok().and_then(Result::ok);
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        return Err(vaultwarden_error(
            "Bitwarden output exceeded the accepted boundary or could not be read",
        ));
    };
    if !status.success() || stdout.is_empty() || !stderr.is_empty() {
        return Err(vaultwarden_error(format!(
            "Bitwarden {operation} failed without exposing external output or credential material"
        )));
    }
    Ok(stdout)
}

fn revalidate_installation_identity(
    installation: &BitwardenInstallationObservation,
) -> Result<(), CoreError> {
    let executable_digest = validate_trusted_executable(installation.executable_path())?;
    let interpreter_path = read_absolute_shebang(installation.executable_path())?;
    let interpreter_digest = interpreter_path
        .as_deref()
        .map(validate_trusted_executable)
        .transpose()?;
    if executable_digest != installation.executable_digest
        || interpreter_path != installation.interpreter_path
        || interpreter_digest != installation.interpreter_digest
    {
        return Err(vaultwarden_error(
            "Bitwarden installation changed after review",
        ));
    }
    Ok(())
}

fn reviewed_bitwarden_command(installation: &BitwardenInstallationObservation) -> Command {
    if let Some(interpreter) = installation.interpreter_path() {
        let mut command = Command::new(interpreter);
        command.arg(installation.executable_path());
        command
    } else {
        Command::new(installation.executable_path())
    }
}

fn recovery_secret_hex(recovery_secret: &RecoverySecret) -> Zeroizing<String> {
    let mut encoded = Zeroizing::new(String::with_capacity(64));
    for byte in recovery_secret.bytes.iter() {
        use std::fmt::Write as _;
        write!(&mut *encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn trim_single_line(value: &mut Vec<u8>) {
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        value.pop();
    }
}

fn read_bounded_output(mut reader: impl Read) -> Result<Zeroizing<Vec<u8>>, ()> {
    let mut output = Zeroizing::new(Vec::new());
    let mut buffer = [0_u8; 16 * 1024];
    let mut exceeded = false;
    loop {
        let read = reader.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > MAX_BITWARDEN_OUTPUT_BYTES {
            exceeded = true;
        } else if !exceeded {
            output.extend_from_slice(&buffer[..read]);
        }
    }
    if exceeded { Err(()) } else { Ok(output) }
}

#[cfg(unix)]
fn trusted_user_home() -> Result<PathBuf, CoreError> {
    use std::mem::MaybeUninit;
    use std::os::unix::fs::MetadataExt;

    let effective_user = unsafe { libc::geteuid() };
    let suggested_size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let buffer_size = if suggested_size < 0 {
        16 * 1024
    } else {
        usize::try_from(suggested_size)
            .unwrap_or(16 * 1024)
            .clamp(1024, 64 * 1024)
    };
    let mut buffer = vec![0_u8; buffer_size];
    let mut password_entry = MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let lookup = unsafe {
        libc::getpwuid_r(
            effective_user,
            password_entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if lookup != 0 || result.is_null() {
        return Err(vaultwarden_error(
            "The trusted user home directory could not be determined",
        ));
    }
    let password_entry = unsafe { password_entry.assume_init() };
    if password_entry.pw_dir.is_null() {
        return Err(vaultwarden_error(
            "The trusted user home directory could not be determined",
        ));
    }
    let home = PathBuf::from(std::ffi::OsString::from_vec(
        unsafe { CStr::from_ptr(password_entry.pw_dir) }
            .to_bytes()
            .to_vec(),
    ));
    let canonical = fs::canonicalize(&home)
        .map_err(|_| vaultwarden_error("The trusted user home directory could not be verified"))?;
    let metadata = fs::metadata(&canonical)
        .map_err(|_| vaultwarden_error("The trusted user home directory could not be verified"))?;
    if !canonical.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != effective_user
        || metadata.mode() & 0o022 != 0
    {
        return Err(vaultwarden_error(
            "The trusted user home directory could not be verified",
        ));
    }
    Ok(canonical)
}

#[cfg(not(unix))]
fn trusted_user_home() -> Result<PathBuf, CoreError> {
    Err(vaultwarden_error(
        "The production Bitwarden command-line adapter is supported on Unix systems only",
    ))
}

fn require_external_text(value: &str, label: &str) -> Result<(), CoreError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(vaultwarden_error(format!("{label} is invalid")));
    }
    Ok(())
}

fn inspect_installed_bitwarden(path: &Path) -> Result<BitwardenInstallationObservation, CoreError> {
    let executable_digest = validate_trusted_executable(path)?;
    let interpreter_path = read_absolute_shebang(path)?;
    let interpreter_digest = interpreter_path
        .as_deref()
        .map(validate_trusted_executable)
        .transpose()?;
    let home = trusted_user_home()?;
    let mut version_command = if let Some(interpreter) = &interpreter_path {
        let mut command = Command::new(interpreter);
        command.arg(path);
        command
    } else {
        Command::new(path)
    };
    let mut child = version_command
        .arg("--version")
        .env_clear()
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            vaultwarden_error(
                "Official Bitwarden command-line version inspection failed without exposing external output",
            )
        })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        vaultwarden_error(
            "Official Bitwarden command-line version inspection failed without exposing external output",
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        vaultwarden_error(
            "Official Bitwarden command-line version inspection failed without exposing external output",
        )
    })?;
    let stdout_reader = thread::spawn(move || read_bounded_output(stdout));
    let stderr_reader = thread::spawn(move || read_bounded_output(stderr));
    let status = child.wait().map_err(|_| {
        vaultwarden_error(
            "Official Bitwarden command-line version inspection failed without exposing external output",
        )
    })?;
    let stdout = stdout_reader.join().ok().and_then(Result::ok);
    let stderr = stderr_reader.join().ok().and_then(Result::ok);
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        return Err(vaultwarden_error(
            "Official Bitwarden command-line version inspection failed without exposing external output",
        ));
    };
    if !status.success() || stdout.is_empty() || stdout.len() > 128 || !stderr.is_empty() {
        return Err(vaultwarden_error(
            "Official Bitwarden command-line version inspection failed without exposing external output",
        ));
    }
    let version = std::str::from_utf8(&stdout)
        .map_err(|_| vaultwarden_error("Bitwarden command-line version response is invalid"))?
        .trim_end_matches(['\r', '\n']);
    if version.is_empty() || version.chars().any(char::is_whitespace) {
        return Err(vaultwarden_error(
            "Bitwarden command-line version response is invalid",
        ));
    }
    BitwardenInstallationObservation::new(
        path,
        version,
        executable_digest,
        interpreter_path,
        interpreter_digest,
    )
}

fn validate_trusted_executable(path: &Path) -> Result<String, CoreError> {
    let metadata = fs::metadata(path)
        .map_err(|_| vaultwarden_error("Bitwarden executable identity could not be verified"))?;
    if !metadata.is_file() {
        return Err(vaultwarden_error(
            "Bitwarden executable must resolve to a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let owner = metadata.uid();
        let effective_user = unsafe { libc::geteuid() };
        if owner != 0 && owner != effective_user {
            return Err(vaultwarden_error(
                "Bitwarden executable owner is not trusted",
            ));
        }
        if metadata.mode() & 0o111 == 0 || metadata.mode() & 0o022 != 0 {
            return Err(vaultwarden_error(
                "Bitwarden executable permissions are not trusted",
            ));
        }
        let mut ancestor = path.parent();
        while let Some(directory) = ancestor {
            let directory_metadata = fs::metadata(directory).map_err(|_| {
                vaultwarden_error("Bitwarden executable parent identity could not be verified")
            })?;
            let owner = directory_metadata.uid();
            if !directory_metadata.is_dir()
                || (owner != 0 && owner != effective_user)
                || directory_metadata.mode() & 0o022 != 0
            {
                return Err(vaultwarden_error(
                    "Bitwarden executable parent permissions are not trusted",
                ));
            }
            ancestor = directory.parent();
        }
    }
    let mut file = File::open(path)
        .map_err(|_| vaultwarden_error("Bitwarden executable identity could not be verified"))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| {
            vaultwarden_error("Bitwarden executable identity could not be verified")
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn read_absolute_shebang(path: &Path) -> Result<Option<PathBuf>, CoreError> {
    let mut file = File::open(path)
        .map_err(|_| vaultwarden_error("Bitwarden executable identity could not be verified"))?;
    let mut prefix = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut prefix)
        .map_err(|_| vaultwarden_error("Bitwarden executable identity could not be verified"))?;
    if !prefix.starts_with(b"#!") {
        return Ok(None);
    }
    let newline = prefix
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| vaultwarden_error("Bitwarden executable shebang is invalid"))?;
    if newline > 4096 {
        return Err(vaultwarden_error("Bitwarden executable shebang is invalid"));
    }
    let shebang = std::str::from_utf8(&prefix[2..newline])
        .map_err(|_| vaultwarden_error("Bitwarden executable shebang is invalid"))?
        .trim_end_matches('\r');
    if shebang.is_empty()
        || shebang.chars().any(char::is_whitespace)
        || !Path::new(shebang).is_absolute()
        || shebang == "/usr/bin/env"
    {
        return Err(vaultwarden_error(
            "Bitwarden executable must use one trusted absolute interpreter without options",
        ));
    }
    let interpreter = fs::canonicalize(shebang).map_err(|_| {
        vaultwarden_error("Bitwarden executable interpreter identity could not be verified")
    })?;
    Ok(Some(interpreter))
}

fn require_supported_version(version: &str) -> Result<(), CoreError> {
    if version.len() > 32 {
        return Err(vaultwarden_error(
            "Bitwarden command-line version is unsupported",
        ));
    }
    let mut fields = version.split('.');
    let major = parse_version_field(fields.next())?;
    let minor = parse_version_field(fields.next())?;
    let patch = parse_version_field(fields.next())?;
    if fields.next().is_some() {
        return Err(vaultwarden_error(
            "Bitwarden command-line version 2026.8.0 or newer is required",
        ));
    }
    if (major, minor, patch) < MINIMUM_BITWARDEN_VERSION {
        return Err(vaultwarden_error(
            "Bitwarden command-line version 2026.8.0 or newer is required. Upgrade the official Homebrew package with `brew upgrade bitwarden-cli`, then inspect it again.",
        ));
    }
    Ok(())
}

fn parse_version_field(field: Option<&str>) -> Result<u32, CoreError> {
    let field = field.ok_or_else(|| {
        vaultwarden_error("Bitwarden command-line version 2026.8.0 or newer is required")
    })?;
    if field.is_empty() || field.len() > 8 || !field.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(vaultwarden_error(
            "Bitwarden command-line version 2026.8.0 or newer is required",
        ));
    }
    field.parse().map_err(|_| {
        vaultwarden_error("Bitwarden command-line version 2026.8.0 or newer is required")
    })
}

fn require_digest(value: &str, label: &str) -> Result<(), CoreError> {
    if value.len() != DIGEST_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(vaultwarden_error(format!("{label} is invalid")));
    }
    Ok(())
}

fn require_uuid(value: &str, label: &str) -> Result<(), CoreError> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
    {
        return Err(vaultwarden_error(format!("{label} is invalid")));
    }
    Ok(())
}

fn require_server_origin(value: &str) -> Result<(), CoreError> {
    if value.len() > MAX_TEXT_BYTES
        || !value.starts_with("https://")
        || value[8..].is_empty()
        || value[8..].contains(['/', '?', '#', '@'])
        || value.chars().any(char::is_control)
    {
        return Err(vaultwarden_error(
            "Vaultwarden server must be an external Hypertext Transfer Protocol Secure origin",
        ));
    }
    Ok(())
}

fn require_review_text(value: &str, label: &str) -> Result<(), CoreError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err(vaultwarden_error(format!("{label} is invalid")));
    }
    Ok(())
}

fn require_item_name(value: &str) -> Result<(), CoreError> {
    require_review_text(value, "Vaultwarden recovery item name")?;
    let Some((friendly_name, date)) = value
        .strip_prefix("Iniza Recovery — ")
        .and_then(|rest| rest.rsplit_once(" — "))
    else {
        return Err(vaultwarden_error(
            "Vaultwarden recovery item name is invalid",
        ));
    };
    require_review_text(friendly_name, "friendly Bundle name")?;
    if date.len() != 10
        || !date.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        })
    {
        return Err(vaultwarden_error(
            "Vaultwarden recovery item name is invalid",
        ));
    }
    Ok(())
}

fn require_bundle_identity(value: &str) -> Result<(), CoreError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(vaultwarden_error(
            "Vaultwarden recovery item Bundle identity is invalid",
        ));
    }
    Ok(())
}

fn require_timestamp(value: &str) -> Result<(), CoreError> {
    if value.len() != 20
        || !value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            10 => byte == b'T',
            13 | 16 => byte == b':',
            19 => byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
    {
        return Err(vaultwarden_error(
            "Vaultwarden recovery item creation time is invalid",
        ));
    }
    Ok(())
}

fn require_review_hash(actual: &str, expected: &str, message: &str) -> Result<(), CoreError> {
    require_digest(actual, "review hash")?;
    if actual != expected {
        return Err(vaultwarden_error(message));
    }
    Ok(())
}

fn installation_review_hash(observation: &BitwardenInstallationObservation) -> String {
    hash_fields(
        b"iniza bitwarden installation review v1",
        &[
            observation.executable_path.to_string_lossy().as_bytes(),
            observation.version.as_bytes(),
            observation.executable_digest.as_bytes(),
            observation
                .interpreter_path
                .as_ref()
                .map(|path| path.to_string_lossy())
                .as_deref()
                .map(str::as_bytes)
                .unwrap_or_default(),
            observation
                .interpreter_digest
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn preflight_review_hash(
    installation_hash: &str,
    server_hash: &str,
    account_hash: &str,
    bundle_identity: &str,
    bundle_format: &str,
    item_name: &str,
    created_at: &str,
    location_hint: Option<&str>,
) -> String {
    hash_fields(
        b"iniza vaultwarden preflight review v1",
        &[
            installation_hash.as_bytes(),
            server_hash.as_bytes(),
            account_hash.as_bytes(),
            bundle_identity.as_bytes(),
            bundle_format.as_bytes(),
            item_name.as_bytes(),
            created_at.as_bytes(),
            location_hint.unwrap_or_default().as_bytes(),
        ],
    )
}

fn identity_hash(domain: &[u8], value: &str) -> String {
    hash_fields(domain, &[value.as_bytes()])
}

fn hash_fields(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().to_hex().to_string()
}

fn unix_time() -> Result<u64, CoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| vaultwarden_error("system clock precedes Unix epoch"))
}

fn format_utc_timestamp(unix_seconds: u64) -> String {
    let days = i64::try_from(unix_seconds / 86_400).unwrap_or(i64::MAX);
    let seconds = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i64, i64, i64) {
    let days = days_since_unix_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}
