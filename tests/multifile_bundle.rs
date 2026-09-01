use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

use iniza::{
    BundleEngine, BundleEvent, BundleEventSink, BundleSource, BundleSourceObservation,
    DestinationCapacity, InspectRequest, LocalBundleSource, PackRequest, PlanEngine,
    RecoveryMethod, RecoverySecret, ScanRequest, VerifyRequest,
};
use zeroize::Zeroizing;

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-multifile-{name}-{}-{unique}",
            std::process::id()
        ));
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
fn owner_can_pack_inspect_and_fully_verify_an_approved_multifile_plan() {
    let directory = TestDirectory::new("first-tracer");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("empty.txt"), []).expect("empty fixture should be written");
    fs::write(source.join("settings.txt"), b"synthetic settings\n")
        .expect("settings fixture should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let engine = BundleEngine::local();
    let sealed = engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect("approved multi-file Plan should seal");

    let inspected = engine
        .inspect(InspectRequest::new(
            &bundle,
            sealed.vaultwarden_recovery_secret(),
        ))
        .expect("Vaultwarden Recovery Method should authenticate safe metadata");
    assert_eq!(inspected.source_name, "developer-state");
    assert_eq!(inspected.logical_size, 19);
    assert_eq!(inspected.format_version, 2);
    assert_eq!(inspected.cryptographic_suite, "IZ1");
    assert_eq!(inspected.included_items, 3);
    assert_eq!(inspected.changed_items, 0);
    assert_eq!(inspected.unsupported_items, 0);
    assert_eq!(inspected.unverified_items, 0);

    let verified = engine
        .verify(VerifyRequest::new(&bundle, sealed.offline_recovery_key()))
        .expect("Offline Recovery Method should authenticate every selected chunk");
    assert_eq!(verified.summary, inspected);
    assert_eq!(verified.authenticated_chunks, 2);
    assert_eq!(verified.authenticated_bytes, 19);
    assert_eq!(
        fs::read_dir(directory.path())
            .expect("test directory should remain readable")
            .count(),
        2,
        "inspection and verification must not extract content",
    );
}

#[cfg(unix)]
#[test]
fn mixed_synthetic_directory_streams_without_plaintext_reaching_bundle_storage() {
    let directory = TestDirectory::new("mixed-streaming");
    let source = directory.path().join("mixed-state");
    let bundle = directory.path().join("mixed-state.iniza");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("empty.txt"), []).expect("empty fixture should be written");
    fs::write(
        source.join("notes.txt"),
        b"protected plaintext marker 7b91e274\n",
    )
    .expect("text fixture should be written");
    fs::write(source.join("binary.bin"), [0_u8, 255, 17, 128])
        .expect("binary fixture should be written");
    let large = vec![0x5a_u8; 2 * 1024 * 1024 + 17];
    fs::write(source.join("large.bin"), &large).expect("large fixture should be written");
    fs::write(source.join("設定-🧪.txt"), b"unicode fixture\n")
        .expect("Unicode-named fixture should be written");
    let permission_sensitive = source.join("owner-only.txt");
    fs::write(&permission_sensitive, b"permission-sensitive\n")
        .expect("permission-sensitive fixture should be written");
    fs::set_permissions(&permission_sensitive, fs::Permissions::from_mode(0o600))
        .expect("permission-sensitive mode should be applied");
    symlink("notes.txt", source.join("notes-link"))
        .expect("symbolic-link fixture should be created");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("mixed synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let engine = BundleEngine::local();
    let sealed = engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect("mixed synthetic Plan should stream into a Bundle");
    let verified = engine
        .verify(VerifyRequest::new(&bundle, sealed.offline_recovery_key()))
        .expect("every selected chunk should authenticate");

    assert_eq!(verified.summary.included_items, 8);
    assert_eq!(verified.summary.changed_items, 0);
    assert_eq!(verified.summary.unsupported_items, 0);
    assert_eq!(verified.summary.unverified_items, 0);
    assert_eq!(verified.authenticated_chunks, 8);
    assert_eq!(
        verified.authenticated_bytes,
        large.len() as u64 + 36 + 4 + 16 + 21,
    );
    let bytes = fs::read(&bundle).expect("Bundle should be readable for leak inspection");
    assert!(!contains_bytes(
        &bytes,
        b"protected plaintext marker 7b91e274"
    ));
    assert!(!contains_bytes(&bytes, "設定-🧪.txt".as_bytes()));
    assert!(!contains_bytes(&bytes, b"permission-sensitive"));
}

#[cfg(unix)]
#[test]
fn a_regular_file_swapped_for_a_symbolic_link_never_escapes_the_reviewed_root() {
    let directory = TestDirectory::new("symbolic-link-swap");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    let outside = directory.path().join("outside-reviewed-root.txt");
    let selected = source.join("selected.txt");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(&selected, b"original synthetic bytes").expect("selected fixture should be written");
    fs::write(&outside, b"outside secret marker 81f2f2")
        .expect("outside fixture should be written");

    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");
    fs::remove_file(&selected).expect("selected fixture should be replaceable");
    symlink(&outside, &selected).expect("symbolic-link swap should be created");

    let engine = BundleEngine::local();
    let sealed = engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect("a swapped source should be contained and reported");
    let verified = engine
        .verify(VerifyRequest::new(&bundle, sealed.offline_recovery_key()))
        .expect("the contained Bundle should remain verifiable");

    assert_eq!(verified.summary.unverified_items, 1);
    assert_eq!(verified.authenticated_chunks, 0);
    assert_eq!(verified.authenticated_bytes, 0);
    let bytes = fs::read(&bundle).expect("Bundle should be readable for leak inspection");
    assert!(!contains_bytes(&bytes, b"outside secret marker 81f2f2"));
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn changing_sources_are_retried_within_the_bound_then_reported_honestly() {
    let directory = TestDirectory::new("changing-sources");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settles.txt"), b"settled synthetic bytes")
        .expect("settling fixture should be written");
    fs::write(
        source.join("never-settles.txt"),
        b"unstable synthetic bytes",
    )
    .expect("unstable fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let observations = Arc::new(Mutex::new(BTreeMap::new()));
    let scripted = ChangingSource {
        observations: Arc::clone(&observations),
    };
    let engine = BundleEngine::with_source(scripted);
    let sealed = engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect("source instability should remain visible without preventing sealing");
    let verified = engine
        .verify(VerifyRequest::new(&bundle, sealed.offline_recovery_key()))
        .expect("stable captured chunks should authenticate");

    assert_eq!(verified.summary.included_items, 3);
    assert_eq!(verified.summary.changed_items, 2);
    assert_eq!(verified.summary.unverified_items, 1);
    assert_eq!(verified.authenticated_chunks, 1);
    assert_eq!(verified.authenticated_bytes, 23);
    assert_eq!(
        observations
            .lock()
            .expect("observation counts should lock")
            .get("never-settles.txt")
            .copied(),
        Some(6),
        "three attempts must each perform one before and one after observation",
    );
}

#[derive(Clone)]
struct ChangingSource {
    observations: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl BundleSource for ChangingSource {
    fn observe(&self, path: &Path) -> io::Result<BundleSourceObservation> {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "fixture name missing"))?;
        let mut observations = self
            .observations
            .lock()
            .expect("observation counts should lock");
        let count = observations.entry(name.to_owned()).or_default();
        *count += 1;
        let change_token = match name {
            "settles.txt" if *count <= 2 => *count,
            "settles.txt" => 3,
            "never-settles.txt" => *count,
            _ => return Err(io::Error::new(io::ErrorKind::NotFound, "unknown fixture")),
        };
        Ok(BundleSourceObservation::new(23, 7, change_token))
    }

    fn open(&self, path: &Path) -> io::Result<Box<dyn Read>> {
        match path.file_name().and_then(|value| value.to_str()) {
            Some("settles.txt") => Ok(Box::new(Cursor::new(b"settled synthetic bytes".to_vec()))),
            Some("never-settles.txt") => {
                Ok(Box::new(Cursor::new(b"unstable synthetic bytes".to_vec())))
            }
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "unknown fixture")),
        }
    }
}

#[test]
fn insufficient_preflight_capacity_rejects_pack_before_output_creation() {
    let directory = TestDirectory::new("capacity-preflight");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let engine = BundleEngine::with_adapters(LocalBundleSource, NoCapacity);
    let error = engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect_err("insufficient preflight capacity must reject Bundle creation");

    assert!(error.to_string().contains("insufficient destination space"));
    assert!(!bundle.exists());
    assert!(
        !directory
            .path()
            .join("developer-state.iniza.partial")
            .exists()
    );
}

struct NoCapacity;

impl DestinationCapacity for NoCapacity {
    fn available_bytes(&self, _destination: &Path) -> io::Result<u64> {
        Ok(0)
    }
}

#[test]
fn capacity_loss_during_writing_never_publishes_a_completed_bundle() {
    let directory = TestDirectory::new("capacity-during-write");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(source.join("settings.txt"), b"synthetic settings")
        .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let engine = BundleEngine::with_adapters(
        LocalBundleSource,
        CapacityDisappearsAfterPreflight::default(),
    );
    let error = engine
        .pack(PackRequest::new(&plan, &bundle))
        .expect_err("capacity loss during writing must fail Bundle creation");

    assert!(error.to_string().contains("insufficient destination space"));
    assert!(
        !bundle.exists(),
        "a failed write must not publish final output"
    );
    assert!(
        !directory
            .path()
            .join("developer-state.iniza.partial")
            .exists()
    );
}

#[derive(Default)]
struct CapacityDisappearsAfterPreflight {
    checks: AtomicUsize,
}

impl DestinationCapacity for CapacityDisappearsAfterPreflight {
    fn available_bytes(&self, _destination: &Path) -> io::Result<u64> {
        if self.checks.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(u64::MAX)
        } else {
            Ok(0)
        }
    }
}

#[test]
fn recovery_adapters_can_reconstruct_a_redacted_in_memory_secret() {
    let marker = [0x6d_u8; 32];
    let secret = RecoverySecret::from_bytes(RecoveryMethod::Offline, Zeroizing::new(marker));

    assert_eq!(secret.method(), RecoveryMethod::Offline);
    let debug = format!("{secret:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("6d6d6d6d"));
}

#[test]
fn checked_in_golden_bundle_and_hostile_mutations_fail_closed() {
    const HEADER_LENGTH: usize = 296;
    let directory = TestDirectory::new("golden-mutations");
    let golden_path = directory.path().join("golden.iniza");
    let golden = decode_base64(include_str!("fixtures/iz2-golden.b64"));
    fs::write(&golden_path, &golden).expect("golden Bundle should be written");
    let secret = RecoverySecret::from_bytes(
        RecoveryMethod::Offline,
        Zeroizing::new([
            0xb3, 0xd9, 0x02, 0x2a, 0x5b, 0xbf, 0x3c, 0x92, 0x5f, 0x24, 0xc0, 0xb9, 0x56, 0x4e,
            0xe0, 0x04, 0x20, 0xb5, 0x02, 0x48, 0x03, 0x7d, 0xa4, 0x2a, 0xc3, 0x6d, 0xbd, 0x7b,
            0xf2, 0x9d, 0x6e, 0x06,
        ]),
    );
    let engine = BundleEngine::local();
    let verified = engine
        .verify(VerifyRequest::new(&golden_path, &secret))
        .expect("checked-in IZ2 golden Bundle should remain compatible");
    assert_eq!(verified.summary.source_name, "golden-source");
    assert_eq!(verified.summary.format_version, 2);
    assert_eq!(verified.summary.included_items, 2);
    assert_eq!(verified.authenticated_chunks, 1);
    assert_eq!(verified.authenticated_bytes, 0);

    let first_end = iz2_record_end(&golden, HEADER_LENGTH);
    let second_end = iz2_record_end(&golden, first_end);
    let cases = [
        ("truncated", golden[..golden.len() - 1].to_vec()),
        {
            let mut reordered = Vec::with_capacity(golden.len());
            reordered.extend_from_slice(&golden[..HEADER_LENGTH]);
            reordered.extend_from_slice(&golden[first_end..second_end]);
            reordered.extend_from_slice(&golden[HEADER_LENGTH..first_end]);
            reordered.extend_from_slice(&golden[second_end..]);
            ("reordered", reordered)
        },
        {
            let mut duplicated = Vec::with_capacity(golden.len() + first_end - HEADER_LENGTH);
            duplicated.extend_from_slice(&golden[..first_end]);
            duplicated.extend_from_slice(&golden[HEADER_LENGTH..first_end]);
            duplicated.extend_from_slice(&golden[first_end..]);
            ("duplicated", duplicated)
        },
        {
            let mut oversized = golden.clone();
            oversized[HEADER_LENGTH + 20..HEADER_LENGTH + 24]
                .copy_from_slice(&(1024_u32 * 1024 + 1).to_be_bytes());
            oversized[HEADER_LENGTH + 24..HEADER_LENGTH + 28]
                .copy_from_slice(&(1024_u32 * 1024 + 17).to_be_bytes());
            ("oversized", oversized)
        },
        {
            let mut unknown_critical = golden.clone();
            unknown_critical[HEADER_LENGTH] = 99;
            ("unknown-critical", unknown_critical)
        },
        {
            let mut unknown_flags = golden.clone();
            unknown_flags[HEADER_LENGTH + 1] = 1;
            ("unknown-flags", unknown_flags)
        },
    ];

    for (name, bytes) in cases {
        let path = directory.path().join(format!("{name}.iniza"));
        fs::write(&path, bytes).expect("mutated Bundle should be written");
        assert!(
            engine.inspect(InspectRequest::new(&path, &secret)).is_err(),
            "{name} mutation must fail closed",
        );
    }
}

fn iz2_record_end(bytes: &[u8], start: usize) -> usize {
    let ciphertext_length = u32::from_be_bytes(
        bytes[start + 24..start + 28]
            .try_into()
            .expect("record length should be present"),
    ) as usize;
    start + 28 + ciphertext_length
}

fn decode_base64(text: &str) -> Vec<u8> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let symbols = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    assert_eq!(symbols.len() % 4, 0, "base64 fixture should be complete");
    let mut output = Vec::new();
    for group in symbols.chunks_exact(4) {
        let a = value(group[0]).expect("base64 symbol should be valid") as u32;
        let b = value(group[1]).expect("base64 symbol should be valid") as u32;
        let c = if group[2] == b'=' {
            0
        } else {
            value(group[2]).expect("base64 symbol should be valid") as u32
        };
        let d = if group[3] == b'=' {
            0
        } else {
            value(group[3]).expect("base64 symbol should be valid") as u32
        };
        let combined = (a << 18) | (b << 12) | (c << 6) | d;
        output.push((combined >> 16) as u8);
        if group[2] != b'=' {
            output.push((combined >> 8) as u8);
        }
        if group[3] != b'=' {
            output.push(combined as u8);
        }
    }
    output
}

#[test]
fn automation_receives_versioned_secret_free_result_and_progress_lines() {
    let directory = TestDirectory::new("automation-output");
    let source = directory.path().join("developer-state");
    let bundle = directory.path().join("developer-state.iniza");
    fs::create_dir(&source).expect("source directory should be created");
    fs::write(
        source.join("private-settings.txt"),
        b"private automation marker 94919b",
    )
    .expect("settings fixture should be written");
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .expect("synthetic directory should scan");
    let reviewed_hash = plan.approval_hash().expect("Plan should have a hash");
    plan.approve(&reviewed_hash)
        .expect("matching reviewed hash should approve the Plan");

    let engine = BundleEngine::local();
    let mut pack_events = CollectedEvents::default();
    let sealed = engine
        .pack(PackRequest::new(&plan, &bundle).with_event_sink(&mut pack_events))
        .expect("Bundle should pack with progress events");
    let mut verify_events = CollectedEvents::default();
    let verified = engine
        .verify(
            VerifyRequest::new(&bundle, sealed.offline_recovery_key())
                .with_event_sink(&mut verify_events),
        )
        .expect("Bundle should verify with progress events");

    let event_lines = pack_events
        .0
        .iter()
        .chain(&verify_events.0)
        .map(BundleEvent::machine_json_line)
        .collect::<Vec<_>>();
    assert!(!event_lines.is_empty());
    for line in &event_lines {
        assert_eq!(line.lines().count(), 1);
        let value: serde_json::Value =
            serde_json::from_str(line).expect("event should be valid JSON Lines output");
        assert_eq!(value["schema_version"], 1);
        assert!(value["event"].is_string());
    }
    let result = verified.machine_json_result();
    assert_eq!(result.lines().count(), 1);
    let value: serde_json::Value =
        serde_json::from_str(&result).expect("result should be valid JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "verify");
    assert_eq!(value["status"], "success");
    assert_eq!(value["data"]["authenticated_chunks"], 1);
    let all_output = format!("{}\n{result}", event_lines.join("\n"));
    assert!(!all_output.contains(&source.display().to_string()));
    assert!(!all_output.contains("private-settings.txt"));
    assert!(!all_output.contains("private automation marker 94919b"));
    assert!(!all_output.contains("RecoverySecret"));
}

#[derive(Default)]
struct CollectedEvents(Vec<BundleEvent>);

impl BundleEventSink for CollectedEvents {
    fn emit(&mut self, event: BundleEvent) {
        self.0.push(event);
    }
}
