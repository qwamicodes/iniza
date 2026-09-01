use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{CoreError, InizaCore, Iz1Prototype, RecoveryMethod};

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("iniza-iz1-{name}-{}-{unique}", std::process::id()));
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
fn owner_can_unlock_one_sealed_bundle_through_each_independent_recovery_method() {
    let directory = TestDirectory::new("independent-recovery");
    let source = directory.path().join("synthetic.txt");
    let bundle = directory.path().join("synthetic.iniza");
    fs::write(&source, b"non-secret synthetic Bundle content\n")
        .expect("synthetic source should be written");

    let sealed = Iz1Prototype
        .seal_one_file(&source, &bundle)
        .expect("one synthetic file should seal");

    assert_eq!(
        sealed.vaultwarden_recovery_secret().method(),
        RecoveryMethod::Vaultwarden
    );
    assert_eq!(
        sealed.offline_recovery_key().method(),
        RecoveryMethod::Offline
    );

    for recovery_secret in [
        sealed.vaultwarden_recovery_secret(),
        sealed.offline_recovery_key(),
    ] {
        let summary = Iz1Prototype
            .inspect(&bundle, recovery_secret)
            .expect("either Recovery Method should unlock the same Bundle");
        assert_eq!(summary.source_name, "synthetic.txt");
        assert_eq!(summary.logical_size, 36);
        assert_eq!(summary.format_version, 1);
        assert_eq!(summary.cryptographic_suite, "IZ1");
    }
}

#[test]
fn owner_can_restore_exact_bytes_from_a_sealed_bundle_into_a_new_destination() {
    let directory = TestDirectory::new("exact-byte-restore");
    let source = directory.path().join("exact.bin");
    let bundle = directory.path().join("exact.iniza");
    let destination = directory.path().join("restored");
    let expected = b"\0synthetic encrypted\xffBundle bytes\r\n";
    fs::write(&source, expected).expect("synthetic source should be written");
    let sealed = Iz1Prototype
        .seal_one_file(&source, &bundle)
        .expect("one synthetic file should seal");

    let restored = Iz1Prototype
        .restore(&bundle, sealed.offline_recovery_key(), &destination)
        .expect("authenticated Bundle should Restore into a new destination");

    assert_eq!(restored, destination.join("exact.bin"));
    assert_eq!(
        fs::read(restored).expect("restored file should be readable"),
        expected
    );
}

#[test]
fn restore_refuses_to_overwrite_an_existing_destination() {
    let directory = TestDirectory::new("restore-non-overwrite");
    let source = directory.path().join("source.txt");
    let bundle = directory.path().join("source.iniza");
    let destination = directory.path().join("existing-destination");
    let sentinel = destination.join("keep.txt");
    fs::write(&source, b"synthetic restore source\n").expect("source should be written");
    fs::create_dir(&destination).expect("existing destination should be created");
    fs::write(&sentinel, b"do not replace\n").expect("sentinel should be written");
    let sealed = Iz1Prototype
        .seal_one_file(&source, &bundle)
        .expect("Bundle should seal");

    let error = Iz1Prototype
        .restore(&bundle, sealed.offline_recovery_key(), &destination)
        .expect_err("Restore must not write into an existing destination");

    assert!(matches!(
        error,
        CoreError::DestinationAlreadyExists(path) if path == destination
    ));
    assert_eq!(
        fs::read(sentinel).expect("sentinel should remain readable"),
        b"do not replace\n"
    );
    assert!(!destination.join("source.txt").exists());
}

#[test]
fn wrong_recovery_secret_fails_with_a_secret_free_authentication_error() {
    let directory = TestDirectory::new("wrong-recovery-secret");
    let first_source = directory.path().join("first.txt");
    let second_source = directory.path().join("second.txt");
    let first_bundle = directory.path().join("first.iniza");
    let second_bundle = directory.path().join("second.iniza");
    fs::write(&first_source, b"first synthetic content\n").expect("first source should be written");
    fs::write(&second_source, b"second synthetic content\n")
        .expect("second source should be written");
    let first = Iz1Prototype
        .seal_one_file(&first_source, &first_bundle)
        .expect("first Bundle should seal");
    let second = Iz1Prototype
        .seal_one_file(&second_source, &second_bundle)
        .expect("second Bundle should seal");

    let error = Iz1Prototype
        .inspect(&first_bundle, second.offline_recovery_key())
        .expect_err("a Recovery Secret from another Bundle must fail closed");

    assert!(matches!(error, CoreError::AuthenticationFailed));
    assert_eq!(error.to_string(), "Bundle authentication failed");
    assert!(!format!("{error:?}").contains("RecoverySecret"));
    assert_eq!(
        Iz1Prototype
            .inspect(&first_bundle, first.offline_recovery_key())
            .expect("the matching Recovery Secret should remain valid")
            .source_name,
        "first.txt"
    );
}

#[test]
fn incomplete_output_is_never_accepted_as_a_sealed_bundle() {
    let directory = TestDirectory::new("incomplete-output");
    let source = directory.path().join("source.txt");
    let bundle = directory.path().join("source.iniza");
    let partial = directory.path().join("source.iniza.partial");
    fs::write(&source, b"synthetic completion state\n").expect("source should be written");
    let sealed = Iz1Prototype
        .seal_one_file(&source, &bundle)
        .expect("Bundle should seal");
    assert!(bundle.exists(), "sealed Bundle should use its final path");
    assert!(
        !partial.exists(),
        "successful sealing should leave no partial output"
    );

    fs::copy(&bundle, &partial).expect("complete bytes should be copied under a partial name");
    let error = Iz1Prototype
        .inspect(&partial, sealed.vaultwarden_recovery_secret())
        .expect_err("a partial path must never be treated as a sealed Bundle");

    assert!(matches!(error, CoreError::BundleIncomplete(path) if path == partial));
}

#[test]
fn modified_reordered_truncated_or_falsely_completed_bundle_fails_closed() {
    const HEADER_LENGTH: usize = 296;

    let directory = TestDirectory::new("tamper-detection");
    let source = directory.path().join("source.txt");
    let bundle = directory.path().join("source.iniza");
    fs::write(&source, b"synthetic authenticated content\n").expect("source should be written");
    let sealed = Iz1Prototype
        .seal_one_file(&source, &bundle)
        .expect("Bundle should seal");
    let original = fs::read(&bundle).expect("Bundle should be readable");

    let mut modified_ciphertext = original.clone();
    modified_ciphertext[HEADER_LENGTH + 20] ^= 0x01;
    let modified_path = directory.path().join("modified.iniza");
    fs::write(&modified_path, modified_ciphertext).expect("modified Bundle should be written");
    assert!(matches!(
        Iz1Prototype.inspect(&modified_path, sealed.offline_recovery_key()),
        Err(CoreError::AuthenticationFailed)
    ));

    let first_end = record_end(&original, HEADER_LENGTH);
    let second_end = record_end(&original, first_end);
    let mut reordered = Vec::with_capacity(original.len());
    reordered.extend_from_slice(&original[..HEADER_LENGTH]);
    reordered.extend_from_slice(&original[first_end..second_end]);
    reordered.extend_from_slice(&original[HEADER_LENGTH..first_end]);
    reordered.extend_from_slice(&original[second_end..]);
    let reordered_path = directory.path().join("reordered.iniza");
    fs::write(&reordered_path, reordered).expect("reordered Bundle should be written");
    assert!(matches!(
        Iz1Prototype.inspect(&reordered_path, sealed.offline_recovery_key()),
        Err(CoreError::BundleInvalid(message)) if message.contains("record order")
    ));

    let mut truncated = original.clone();
    truncated.pop();
    let truncated_path = directory.path().join("truncated.iniza");
    fs::write(&truncated_path, truncated).expect("truncated Bundle should be written");
    assert!(
        Iz1Prototype
            .inspect(&truncated_path, sealed.offline_recovery_key())
            .is_err()
    );

    let mut forged_completion = original;
    let final_byte = forged_completion
        .last_mut()
        .expect("Bundle should contain a completion record");
    *final_byte ^= 0x01;
    let forged_path = directory.path().join("forged-completion.iniza");
    fs::write(&forged_path, forged_completion).expect("forged Bundle should be written");
    assert!(matches!(
        Iz1Prototype.inspect(&forged_path, sealed.offline_recovery_key()),
        Err(CoreError::AuthenticationFailed)
    ));

    let mut trailing = fs::read(&bundle).expect("Bundle should remain readable");
    trailing.push(0);
    let trailing_path = directory.path().join("trailing.iniza");
    fs::write(&trailing_path, trailing).expect("Bundle with trailing bytes should be written");
    assert!(matches!(
        Iz1Prototype.inspect(&trailing_path, sealed.offline_recovery_key()),
        Err(CoreError::BundleInvalid(message)) if message.contains("trailing bytes")
    ));
}

#[test]
fn unsupported_public_header_values_are_rejected_without_unsafe_fallbacks() {
    const FORMAT_VERSION_OFFSET: usize = 8;
    const SUITE_OFFSET: usize = 10;
    const HEADER_LENGTH_OFFSET: usize = 12;
    const FIRST_SLOT_MEMORY_COST_OFFSET: usize = 88;

    let directory = TestDirectory::new("header-bounds");
    let source = directory.path().join("source.txt");
    let bundle = directory.path().join("source.iniza");
    fs::write(&source, b"synthetic parser boundary content\n").expect("source should be written");
    let sealed = Iz1Prototype
        .seal_one_file(&source, &bundle)
        .expect("Bundle should seal");
    let original = fs::read(&bundle).expect("Bundle should be readable");

    let cases = [
        (
            "unsupported-version.iniza",
            FORMAT_VERSION_OFFSET,
            2_u16.to_be_bytes().to_vec(),
            "format version",
        ),
        (
            "unsupported-suite.iniza",
            SUITE_OFFSET,
            2_u16.to_be_bytes().to_vec(),
            "cryptographic suite",
        ),
        (
            "oversized-header.iniza",
            HEADER_LENGTH_OFFSET,
            u32::MAX.to_be_bytes().to_vec(),
            "header length",
        ),
        (
            "unsupported-argon-memory.iniza",
            FIRST_SLOT_MEMORY_COST_OFFSET,
            u32::MAX.to_be_bytes().to_vec(),
            "Argon2id parameters",
        ),
    ];

    for (name, offset, replacement, expected_message) in cases {
        let mut malformed = original.clone();
        malformed[offset..offset + replacement.len()].copy_from_slice(&replacement);
        let path = directory.path().join(name);
        fs::write(&path, malformed).expect("malformed Bundle should be written");

        let error = Iz1Prototype
            .inspect(&path, sealed.vaultwarden_recovery_secret())
            .expect_err("unsupported public header value must fail closed");

        assert!(
            matches!(error, CoreError::BundleInvalid(message) if message.contains(expected_message)),
            "{name} should report its rejected field"
        );
    }
}

#[test]
fn prototype_enforces_declared_source_and_bundle_size_limits() {
    const ONE_MEBIBYTE: u64 = 1024 * 1024;
    const NINETY_SIX_MEBIBYTES: u64 = 96 * ONE_MEBIBYTE;

    let directory = TestDirectory::new("size-limits");
    let small_source = directory.path().join("small.txt");
    let valid_bundle = directory.path().join("small.iniza");
    fs::write(&small_source, b"small synthetic content\n").expect("small source should be written");
    let sealed = Iz1Prototype
        .seal_one_file(&small_source, &valid_bundle)
        .expect("small source should seal");

    let oversized_source = directory.path().join("oversized-source.bin");
    fs::File::create(&oversized_source)
        .and_then(|file| file.set_len(ONE_MEBIBYTE + 1))
        .expect("oversized sparse source should be created");
    let source_error = Iz1Prototype
        .seal_one_file(
            &oversized_source,
            &directory.path().join("oversized-source.iniza"),
        )
        .expect_err("source over the prototype chunk limit must be rejected");
    assert!(matches!(
        source_error,
        CoreError::BundleInvalid(message) if message.contains("1 MiB chunk limit")
    ));

    let oversized_bundle = directory.path().join("oversized-bundle.iniza");
    fs::File::create(&oversized_bundle)
        .and_then(|file| file.set_len(NINETY_SIX_MEBIBYTES + 1))
        .expect("oversized sparse Bundle should be created");
    let bundle_error = Iz1Prototype
        .inspect(&oversized_bundle, sealed.offline_recovery_key())
        .expect_err("Bundle over the parser limit must be rejected");
    assert!(matches!(
        bundle_error,
        CoreError::BundleInvalid(message) if message.contains("size limit")
    ));
}

#[test]
fn sealed_bundle_plan_and_debug_output_do_not_disclose_protected_content_or_recovery_secrets() {
    let directory = TestDirectory::new("secret-containment");
    let source = directory.path().join("private-source-name-17f482.txt");
    let plan = directory.path().join("plan.toml");
    let bundle = directory.path().join("private.iniza");
    let protected_content = b"protected synthetic content marker 6d9c3114";
    fs::write(&source, protected_content).expect("synthetic source should be written");

    InizaCore
        .scan_explicit_file(&source)
        .expect("synthetic source should scan")
        .write_to(&plan)
        .expect("Plan should be written");
    let sealed = Iz1Prototype
        .seal_one_file(&source, &bundle)
        .expect("synthetic source should seal");

    let bundle_bytes = fs::read(&bundle).expect("Bundle should be readable");
    assert!(!contains_bytes(&bundle_bytes, protected_content));
    assert!(!contains_bytes(
        &bundle_bytes,
        b"private-source-name-17f482.txt"
    ));

    let plan_text = fs::read_to_string(plan).expect("Plan should be readable");
    assert!(!plan_text.contains("recovery_secret"));
    assert!(!plan_text.contains("offline_recovery_key"));
    assert_eq!(
        format!("{:?}", sealed.offline_recovery_key()),
        "RecoverySecret { method: Offline, secret: \"[REDACTED]\" }"
    );
    assert_eq!(
        format!("{sealed:?}"),
        "SealedBundle { vaultwarden_recovery_secret: \"[REDACTED]\", offline_recovery_key: \"[REDACTED]\" }"
    );
}

fn record_end(bundle: &[u8], offset: usize) -> usize {
    let ciphertext_length = u32::from_be_bytes(
        bundle[offset + 16..offset + 20]
            .try_into()
            .expect("record length should have four bytes"),
    ) as usize;
    offset + 20 + ciphertext_length
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}
