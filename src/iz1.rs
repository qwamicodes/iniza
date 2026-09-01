use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{CoreError, is_safe_file_name};

const MAGIC: &[u8; 8] = b"INIZAIZ1";
const FORMAT_VERSION: u16 = 1;
const SUITE_ID: u16 = 1;
const SLOT_COUNT: u8 = 2;
const SLOT_LENGTH: usize = 106;
const FIXED_HEADER_LENGTH: usize = 84;
const HEADER_LENGTH: usize = FIXED_HEADER_LENGTH + SLOT_LENGTH * SLOT_COUNT as usize;
const ARGON2_MEMORY_KIBIBYTES: u32 = 65_536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const MAX_PLAINTEXT_CHUNK: usize = 1024 * 1024;
const MAX_MANIFEST_PLAINTEXT: usize = 16 * 1024 * 1024;
const MAX_INDEX_PLAINTEXT: usize = 64 * 1024 * 1024;
const MAX_BUNDLE_LENGTH: u64 = 96 * 1024 * 1024;

const RECORD_CONTENT: u8 = 1;
const RECORD_MANIFEST: u8 = 2;
const RECORD_INDEX: u8 = 3;
const RECORD_COMPLETION: u8 = 255;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMethod {
    Vaultwarden,
    Offline,
}

impl RecoveryMethod {
    pub(crate) fn slot_id(self) -> u8 {
        match self {
            Self::Vaultwarden => 1,
            Self::Offline => 2,
        }
    }

    pub(crate) fn from_slot_id(value: u8) -> Result<Self, CoreError> {
        match value {
            1 => Ok(Self::Vaultwarden),
            2 => Ok(Self::Offline),
            _ => Err(invalid_bundle("Bundle contains an unknown Recovery Method")),
        }
    }
}

pub struct RecoverySecret {
    pub(crate) method: RecoveryMethod,
    pub(crate) bytes: Zeroizing<[u8; 32]>,
}

impl RecoverySecret {
    pub fn from_bytes(method: RecoveryMethod, bytes: Zeroizing<[u8; 32]>) -> Self {
        Self { method, bytes }
    }

    pub fn method(&self) -> RecoveryMethod {
        self.method
    }
}

impl fmt::Debug for RecoverySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverySecret")
            .field("method", &self.method)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedBundleSummary {
    pub source_name: String,
    pub logical_size: u64,
    pub format_version: u16,
    pub cryptographic_suite: &'static str,
    pub included_items: u64,
    pub changed_items: u64,
    pub unsupported_items: u64,
    pub unverified_items: u64,
}

pub struct SealedBundle {
    pub(crate) vaultwarden_recovery_secret: RecoverySecret,
    pub(crate) offline_recovery_key: RecoverySecret,
}

impl SealedBundle {
    pub fn vaultwarden_recovery_secret(&self) -> &RecoverySecret {
        &self.vaultwarden_recovery_secret
    }

    pub fn offline_recovery_key(&self) -> &RecoverySecret {
        &self.offline_recovery_key
    }
}

impl fmt::Debug for SealedBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedBundle")
            .field("vaultwarden_recovery_secret", &"[REDACTED]")
            .field("offline_recovery_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct Iz1Prototype;

impl Iz1Prototype {
    pub fn seal_one_file(
        &self,
        source: &Path,
        destination: &Path,
    ) -> Result<SealedBundle, CoreError> {
        if destination.extension().and_then(|value| value.to_str()) != Some("iniza") {
            return Err(invalid_bundle("Bundle output must end with .iniza"));
        }
        if destination.exists() {
            return Err(CoreError::DestinationAlreadyExists(
                destination.to_path_buf(),
            ));
        }

        let metadata = fs::metadata(source).map_err(|error| CoreError::Io {
            action: "read Bundle source metadata",
            path: source.to_path_buf(),
            source: error,
        })?;
        if !metadata.is_file() {
            return Err(CoreError::SourceIsNotARegularFile(source.to_path_buf()));
        }
        if metadata.len() > MAX_PLAINTEXT_CHUNK as u64 {
            return Err(invalid_bundle(
                "IZ1 one-file prototype source exceeds the 1 MiB chunk limit",
            ));
        }
        let source_name = source
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| CoreError::SourceHasNoFileName(source.to_path_buf()))?
            .to_owned();
        let content = Zeroizing::new(fs::read(source).map_err(|error| CoreError::Io {
            action: "read Bundle source",
            path: source.to_path_buf(),
            source: error,
        })?);

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

        let mut header = Vec::with_capacity(HEADER_LENGTH);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        header.extend_from_slice(&SUITE_ID.to_be_bytes());
        header.extend_from_slice(&(HEADER_LENGTH as u32).to_be_bytes());
        header.extend_from_slice(&bundle_identifier);
        header.extend_from_slice(&hkdf_salt);
        header.extend_from_slice(&nonce_prefix);
        header.push(SLOT_COUNT);
        header.extend_from_slice(&[0; 3]);

        for recovery_secret in [&vaultwarden_secret, &offline_secret] {
            let salt: [u8; 16] = random_array()?;
            let nonce: [u8; 24] = random_array()?;
            let slot_prefix = encode_slot_prefix(recovery_secret.method, &salt, &nonce);
            let aad =
                slot_associated_data(&bundle_identifier, &hkdf_salt, &nonce_prefix, &slot_prefix);
            let wrapping_key = derive_wrapping_key(&recovery_secret.bytes, &salt)?;
            let wrapped_key = encrypt(&wrapping_key, &nonce, &aad, data_encryption_key.as_slice())?;
            if wrapped_key.len() != 48 {
                return Err(invalid_bundle(
                    "wrapped data-encryption key has invalid length",
                ));
            }
            header.extend_from_slice(&slot_prefix);
            header.extend_from_slice(&wrapped_key);
        }
        if header.len() != HEADER_LENGTH {
            return Err(invalid_bundle("internal IZ1 header length mismatch"));
        }

        let keys = derive_bundle_keys(&data_encryption_key, &hkdf_salt, &bundle_identifier)?;
        let header_hash = *blake3::hash(&header).as_bytes();
        let mut bundle_bytes = header;
        let record_context = RecordContext {
            nonce_prefix: &nonce_prefix,
            header_hash: &header_hash,
            bundle_identifier: &bundle_identifier,
        };

        append_encrypted_record(
            &mut bundle_bytes,
            RECORD_CONTENT,
            0,
            &keys.content,
            &record_context,
            &content,
        )?;

        let content_hash = blake3::hash(&content);
        let manifest =
            encode_manifest(&source_name, content.len() as u64, content_hash.as_bytes())?;
        append_encrypted_record(
            &mut bundle_bytes,
            RECORD_MANIFEST,
            1,
            &keys.manifest,
            &record_context,
            &manifest,
        )?;

        let index = encode_index();
        append_encrypted_record(
            &mut bundle_bytes,
            RECORD_INDEX,
            2,
            &keys.index,
            &record_context,
            &index,
        )?;

        let prefix_hash = *blake3::hash(&bundle_bytes).as_bytes();
        let completion = encode_completion(&prefix_hash);
        append_encrypted_record(
            &mut bundle_bytes,
            RECORD_COMPLETION,
            3,
            &keys.completion,
            &record_context,
            &completion,
        )?;

        let partial_path = partial_path(destination);
        let write_result = write_completed_bundle(&partial_path, destination, &bundle_bytes);
        if write_result.is_err() {
            let _ = fs::remove_file(&partial_path);
        }
        write_result?;

        Ok(SealedBundle {
            vaultwarden_recovery_secret: vaultwarden_secret,
            offline_recovery_key: offline_secret,
        })
    }

    pub fn inspect(
        &self,
        source: &Path,
        recovery_secret: &RecoverySecret,
    ) -> Result<AuthenticatedBundleSummary, CoreError> {
        reject_partial_path(source)?;
        let bundle = read_bounded_bundle(source)?;
        Ok(open_bundle_bytes(&bundle, recovery_secret)?.summary)
    }

    pub fn restore(
        &self,
        source: &Path,
        recovery_secret: &RecoverySecret,
        destination: &Path,
    ) -> Result<PathBuf, CoreError> {
        reject_partial_path(source)?;
        let bundle = read_bounded_bundle(source)?;
        let opened = open_bundle_bytes(&bundle, recovery_secret)?;
        if !is_safe_file_name(&opened.summary.source_name) {
            return Err(invalid_bundle(
                "authenticated Bundle source name is not a safe file name",
            ));
        }

        fs::create_dir(destination).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CoreError::DestinationAlreadyExists(destination.to_path_buf())
            } else {
                CoreError::Io {
                    action: "create Bundle Restore destination",
                    path: destination.to_path_buf(),
                    source: error,
                }
            }
        })?;
        let restored_file = destination.join(&opened.summary.source_name);
        let result = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&restored_file)
            .and_then(|mut output| output.write_all(&opened.content));
        if let Err(error) = result {
            let _ = fs::remove_file(&restored_file);
            let _ = fs::remove_dir(destination);
            return Err(CoreError::Io {
                action: "write restored Bundle content",
                path: restored_file,
                source: error,
            });
        }
        Ok(restored_file)
    }
}

struct BundleKeys {
    content: Zeroizing<[u8; 32]>,
    manifest: Zeroizing<[u8; 32]>,
    index: Zeroizing<[u8; 32]>,
    completion: Zeroizing<[u8; 32]>,
}

struct RecordContext<'a> {
    nonce_prefix: &'a [u8; 16],
    header_hash: &'a [u8; 32],
    bundle_identifier: &'a [u8; 16],
}

struct Slot {
    method: RecoveryMethod,
    salt: [u8; 16],
    nonce: [u8; 24],
    wrapped_key: [u8; 48],
    prefix: Vec<u8>,
}

struct Record<'a> {
    kind: u8,
    sequence: u64,
    plaintext_length: u32,
    ciphertext: &'a [u8],
}

struct OpenedBundle {
    summary: AuthenticatedBundleSummary,
    content: Zeroizing<Vec<u8>>,
}

fn open_bundle_bytes(
    bundle: &[u8],
    recovery_secret: &RecoverySecret,
) -> Result<OpenedBundle, CoreError> {
    let mut cursor = Cursor::new(bundle);
    if cursor.take(8)? != MAGIC {
        return Err(invalid_bundle("Bundle magic is invalid"));
    }
    let format_version = cursor.u16()?;
    if format_version != FORMAT_VERSION {
        return Err(invalid_bundle("Bundle format version is unsupported"));
    }
    if cursor.u16()? != SUITE_ID {
        return Err(invalid_bundle("Bundle cryptographic suite is unsupported"));
    }
    if cursor.u32()? as usize != HEADER_LENGTH {
        return Err(invalid_bundle("Bundle public header length is invalid"));
    }
    let bundle_identifier = cursor.array::<16>()?;
    let hkdf_salt = cursor.array::<32>()?;
    let nonce_prefix = cursor.array::<16>()?;
    if cursor.u8()? != SLOT_COUNT || cursor.take(3)? != [0; 3] {
        return Err(invalid_bundle(
            "Bundle Recovery Method directory is invalid",
        ));
    }

    let mut slots = Vec::with_capacity(SLOT_COUNT as usize);
    for _ in 0..SLOT_COUNT {
        let start = cursor.position();
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
        let salt = cursor.array::<16>()?;
        let nonce = cursor.array::<24>()?;
        if cursor.u16()? != 48 {
            return Err(invalid_bundle("Bundle wrapped key length is invalid"));
        }
        let prefix_end = cursor.position();
        let wrapped_key = cursor.array::<48>()?;
        slots.push(Slot {
            method,
            salt,
            nonce,
            wrapped_key,
            prefix: bundle[start..prefix_end].to_vec(),
        });
    }
    if cursor.position() != HEADER_LENGTH {
        return Err(invalid_bundle("Bundle public header is not canonical"));
    }

    let slot = slots
        .iter()
        .find(|slot| slot.method == recovery_secret.method)
        .ok_or_else(|| invalid_bundle("requested Recovery Method is unavailable"))?;
    let wrapping_key = derive_wrapping_key(&recovery_secret.bytes, &slot.salt)?;
    let slot_aad =
        slot_associated_data(&bundle_identifier, &hkdf_salt, &nonce_prefix, &slot.prefix);
    let mut data_encryption_key = decrypt(
        &wrapping_key,
        &slot.nonce,
        &slot_aad,
        &slot.wrapped_key,
        "Recovery Secret did not unlock the Bundle",
    )?;
    if data_encryption_key.len() != 32 {
        data_encryption_key.zeroize();
        return Err(invalid_bundle(
            "unwrapped data-encryption key length is invalid",
        ));
    }
    let mut data_encryption_key_array = Zeroizing::new([0u8; 32]);
    data_encryption_key_array.copy_from_slice(&data_encryption_key);
    data_encryption_key.zeroize();
    let keys = derive_bundle_keys(&data_encryption_key_array, &hkdf_salt, &bundle_identifier)?;
    let header_hash = *blake3::hash(&bundle[..HEADER_LENGTH]).as_bytes();
    let record_context = RecordContext {
        nonce_prefix: &nonce_prefix,
        header_hash: &header_hash,
        bundle_identifier: &bundle_identifier,
    };

    let content_record = cursor.record(MAX_PLAINTEXT_CHUNK)?;
    require_record(&content_record, RECORD_CONTENT, 0)?;
    let content = decrypt_record(&content_record, &keys.content, &record_context)?;

    let manifest_record = cursor.record(MAX_MANIFEST_PLAINTEXT)?;
    require_record(&manifest_record, RECORD_MANIFEST, 1)?;
    let manifest = decrypt_record(&manifest_record, &keys.manifest, &record_context)?;
    let summary = decode_manifest(&manifest, &content, format_version)?;

    let index_record = cursor.record(MAX_INDEX_PLAINTEXT)?;
    require_record(&index_record, RECORD_INDEX, 2)?;
    let index = decrypt_record(&index_record, &keys.index, &record_context)?;
    decode_index(&index)?;

    let completion_offset = cursor.position();
    let completion_record = cursor.record(64)?;
    require_record(&completion_record, RECORD_COMPLETION, 3)?;
    let completion = decrypt_record(&completion_record, &keys.completion, &record_context)?;
    decode_completion(&completion, &bundle[..completion_offset])?;
    if !cursor.is_finished() {
        return Err(invalid_bundle(
            "Bundle contains trailing bytes after completion",
        ));
    }

    Ok(OpenedBundle { summary, content })
}

fn random_secret() -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut())
        .map_err(|_| invalid_bundle("operating-system entropy failed"))?;
    Ok(bytes)
}

fn random_array<const N: usize>() -> Result<[u8; N], CoreError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| invalid_bundle("operating-system entropy failed"))?;
    Ok(bytes)
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
    .map_err(|_| invalid_bundle("IZ1 Argon2id parameters are invalid"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(recovery_secret, salt, output.as_mut())
        .map_err(|_| invalid_bundle("Argon2id key derivation failed"))?;
    Ok(output)
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
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, output.as_mut())
        .map_err(|_| invalid_bundle("IZ1 subkey derivation failed"))?;
    Ok(output)
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
    prefix.extend_from_slice(&48u16.to_be_bytes());
    prefix
}

fn slot_associated_data(
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

fn append_encrypted_record(
    bundle: &mut Vec<u8>,
    kind: u8,
    sequence: u64,
    key: &[u8; 32],
    context: &RecordContext<'_>,
    plaintext: &[u8],
) -> Result<(), CoreError> {
    let plaintext_length = u32::try_from(plaintext.len())
        .map_err(|_| invalid_bundle("IZ1 record plaintext is too large"))?;
    let ciphertext_length = plaintext_length
        .checked_add(16)
        .ok_or_else(|| invalid_bundle("IZ1 record ciphertext length overflowed"))?;
    let aad = record_associated_data(
        kind,
        sequence,
        plaintext_length,
        ciphertext_length,
        context.header_hash,
        context.bundle_identifier,
    );
    let nonce = record_nonce(context.nonce_prefix, sequence);
    let ciphertext = encrypt(key, &nonce, &aad, plaintext)?;
    bundle.push(kind);
    bundle.push(0);
    bundle.extend_from_slice(&0u16.to_be_bytes());
    bundle.extend_from_slice(&sequence.to_be_bytes());
    bundle.extend_from_slice(&plaintext_length.to_be_bytes());
    bundle.extend_from_slice(&ciphertext_length.to_be_bytes());
    bundle.extend_from_slice(&ciphertext);
    Ok(())
}

fn decrypt_record(
    record: &Record<'_>,
    key: &[u8; 32],
    context: &RecordContext<'_>,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let ciphertext_length = u32::try_from(record.ciphertext.len())
        .map_err(|_| invalid_bundle("Bundle record ciphertext is too large"))?;
    let aad = record_associated_data(
        record.kind,
        record.sequence,
        record.plaintext_length,
        ciphertext_length,
        context.header_hash,
        context.bundle_identifier,
    );
    let nonce = record_nonce(context.nonce_prefix, record.sequence);
    decrypt(
        key,
        &nonce,
        &aad,
        record.ciphertext,
        "Bundle record authentication failed",
    )
    .map(Zeroizing::new)
}

fn record_associated_data(
    kind: u8,
    sequence: u64,
    plaintext_length: u32,
    ciphertext_length: u32,
    header_hash: &[u8; 32],
    bundle_identifier: &[u8; 16],
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(header_hash);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&SUITE_ID.to_be_bytes());
    aad.extend_from_slice(bundle_identifier);
    aad.push(kind);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(&plaintext_length.to_be_bytes());
    aad.extend_from_slice(&ciphertext_length.to_be_bytes());
    aad
}

fn record_nonce(prefix: &[u8; 16], sequence: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
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
        .map_err(|_| invalid_bundle("IZ1 encryption key length is invalid"))?;
    cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| invalid_bundle("IZ1 encryption failed"))
}

fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
    _message: &'static str,
) -> Result<Vec<u8>, CoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| invalid_bundle("IZ1 decryption key length is invalid"))?;
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

fn encode_manifest(
    source_name: &str,
    logical_size: u64,
    content_hash: &[u8; 32],
) -> Result<Vec<u8>, CoreError> {
    let name_length = u16::try_from(source_name.len())
        .map_err(|_| invalid_bundle("Bundle source name is too long"))?;
    let mut manifest = Vec::new();
    manifest.extend_from_slice(b"MNF1");
    manifest.extend_from_slice(&name_length.to_be_bytes());
    manifest.extend_from_slice(source_name.as_bytes());
    manifest.extend_from_slice(&logical_size.to_be_bytes());
    manifest.extend_from_slice(content_hash);
    manifest.extend_from_slice(&0u64.to_be_bytes());
    Ok(manifest)
}

fn decode_manifest(
    manifest: &[u8],
    content: &[u8],
    format_version: u16,
) -> Result<AuthenticatedBundleSummary, CoreError> {
    let mut cursor = Cursor::new(manifest);
    if cursor.take(4)? != b"MNF1" {
        return Err(invalid_bundle("Bundle manifest marker is invalid"));
    }
    let name_length = cursor.u16()? as usize;
    if name_length == 0 || name_length > 4096 {
        return Err(invalid_bundle(
            "Bundle manifest source name length is invalid",
        ));
    }
    let source_name = std::str::from_utf8(cursor.take(name_length)?)
        .map_err(|_| invalid_bundle("Bundle manifest source name is not valid text"))?
        .to_owned();
    let logical_size = cursor.u64()?;
    let content_hash = cursor.array::<32>()?;
    if cursor.u64()? != 0 || !cursor.is_finished() {
        return Err(invalid_bundle("Bundle manifest is not canonical"));
    }
    if logical_size != content.len() as u64 || content_hash != *blake3::hash(content).as_bytes() {
        return Err(invalid_bundle(
            "Bundle content does not match its authenticated manifest",
        ));
    }
    Ok(AuthenticatedBundleSummary {
        source_name,
        logical_size,
        format_version,
        cryptographic_suite: "IZ1",
        included_items: 1,
        changed_items: 0,
        unsupported_items: 0,
        unverified_items: 0,
    })
}

fn encode_index() -> Vec<u8> {
    let mut index = Vec::new();
    index.extend_from_slice(b"IDX1");
    index.extend_from_slice(&1u32.to_be_bytes());
    index.extend_from_slice(&0u64.to_be_bytes());
    index
}

fn decode_index(index: &[u8]) -> Result<(), CoreError> {
    if index != b"IDX1\0\0\0\x01\0\0\0\0\0\0\0\0" {
        return Err(invalid_bundle("Bundle index is invalid"));
    }
    Ok(())
}

fn encode_completion(prefix_hash: &[u8; 32]) -> Vec<u8> {
    let mut completion = Vec::new();
    completion.extend_from_slice(b"END1");
    completion.extend_from_slice(prefix_hash);
    completion.extend_from_slice(&3u32.to_be_bytes());
    completion.extend_from_slice(&1u64.to_be_bytes());
    completion.extend_from_slice(&2u64.to_be_bytes());
    completion.push(1);
    completion
}

fn decode_completion(completion: &[u8], prefix: &[u8]) -> Result<(), CoreError> {
    let mut cursor = Cursor::new(completion);
    if cursor.take(4)? != b"END1" {
        return Err(invalid_bundle("Bundle completion marker is invalid"));
    }
    if cursor.array::<32>()? != *blake3::hash(prefix).as_bytes()
        || cursor.u32()? != 3
        || cursor.u64()? != 1
        || cursor.u64()? != 2
        || cursor.u8()? != 1
        || !cursor.is_finished()
    {
        return Err(invalid_bundle("Bundle completion record is invalid"));
    }
    Ok(())
}

fn require_record(record: &Record<'_>, kind: u8, sequence: u64) -> Result<(), CoreError> {
    if record.kind != kind || record.sequence != sequence {
        return Err(invalid_bundle("Bundle record order is invalid"));
    }
    Ok(())
}

fn read_bounded_bundle(source: &Path) -> Result<Vec<u8>, CoreError> {
    let input = fs::File::open(source).map_err(|error| CoreError::Io {
        action: "open Bundle",
        path: source.to_path_buf(),
        source: error,
    })?;
    let metadata = input.metadata().map_err(|error| CoreError::Io {
        action: "read Bundle metadata",
        path: source.to_path_buf(),
        source: error,
    })?;
    if metadata.len() > MAX_BUNDLE_LENGTH {
        return Err(invalid_bundle(
            "Bundle exceeds the IZ1 prototype size limit",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    input
        .take(MAX_BUNDLE_LENGTH + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CoreError::Io {
            action: "read Bundle",
            path: source.to_path_buf(),
            source: error,
        })?;
    if bytes.len() as u64 > MAX_BUNDLE_LENGTH {
        return Err(invalid_bundle(
            "Bundle exceeds the IZ1 prototype size limit",
        ));
    }
    Ok(bytes)
}

fn reject_partial_path(source: &Path) -> Result<(), CoreError> {
    if source
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.ends_with(".iniza.partial"))
    {
        return Err(CoreError::BundleIncomplete(source.to_path_buf()));
    }
    Ok(())
}

fn write_completed_bundle(
    partial_path: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), CoreError> {
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(partial_path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CoreError::DestinationAlreadyExists(partial_path.to_path_buf())
            } else {
                CoreError::Io {
                    action: "create partial Bundle",
                    path: partial_path.to_path_buf(),
                    source: error,
                }
            }
        })?;
    output.write_all(bytes).map_err(|error| CoreError::Io {
        action: "write partial Bundle",
        path: partial_path.to_path_buf(),
        source: error,
    })?;
    output.sync_all().map_err(|error| CoreError::Io {
        action: "flush partial Bundle",
        path: partial_path.to_path_buf(),
        source: error,
    })?;
    drop(output);
    fs::hard_link(partial_path, destination).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            CoreError::DestinationAlreadyExists(destination.to_path_buf())
        } else {
            CoreError::Io {
                action: "seal completed Bundle without overwrite",
                path: destination.to_path_buf(),
                source: error,
            }
        }
    })?;
    fs::remove_file(partial_path).map_err(|error| CoreError::Io {
        action: "remove completed partial Bundle name",
        path: partial_path.to_path_buf(),
        source: error,
    })
}

fn partial_path(destination: &Path) -> PathBuf {
    let mut name: OsString = destination.as_os_str().to_owned();
    name.push(".partial");
    PathBuf::from(name)
}

fn invalid_bundle(message: impl Into<String>) -> CoreError {
    CoreError::BundleInvalid(message.into())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CoreError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| invalid_bundle("Bundle length overflowed"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid_bundle("Bundle is truncated"))?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid_bundle("Bundle fixed-width field is invalid"))
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

    fn u64(&mut self) -> Result<u64, CoreError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn record(&mut self, maximum_plaintext_length: usize) -> Result<Record<'a>, CoreError> {
        let kind = self.u8()?;
        if self.u8()? != 0 || self.u16()? != 0 {
            return Err(invalid_bundle("Bundle record flags are unsupported"));
        }
        let sequence = self.u64()?;
        let plaintext_length = self.u32()?;
        let ciphertext_length = self.u32()?;
        if plaintext_length as usize > maximum_plaintext_length
            || ciphertext_length != plaintext_length.saturating_add(16)
        {
            return Err(invalid_bundle("Bundle record length is invalid"));
        }
        let ciphertext = self.take(ciphertext_length as usize)?;
        Ok(Record {
            kind,
            sequence,
            plaintext_length,
            ciphertext,
        })
    }
}
