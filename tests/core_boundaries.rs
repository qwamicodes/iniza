use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{CoreError, FIXTURE_MAGIC, InizaCore};

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
            std::env::temp_dir().join(format!("iniza-core-{name}-{}-{unique}", std::process::id()));
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
fn core_returns_a_typed_error_for_a_fixture_at_the_bundle_boundary() {
    let directory = TestDirectory::new("fixture-is-not-bundle");
    let fixture = directory.path().join("sample.iniza-fixture");
    fs::write(&fixture, FIXTURE_MAGIC).expect("fixture marker should be written");

    let error = InizaCore
        .inspect_bundle(&fixture)
        .expect_err("normal Bundle inspection must reject a test-only fixture");

    assert!(matches!(error, CoreError::TestFixtureIsNotBundle(path) if path == fixture));
}
