use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BundleEngine, CandidatePortability, CandidateSensitivity, CandidateSourceKind,
    CandidateValidation, Disposition, PackRequest, PlanEngine, ProtectionCandidateEngine,
    ProtectionCandidateRequest, ProtectionRequirement, RestoreEngine, RestoreRequest,
    VerifyRequest,
};

struct TestDirectory(PathBuf);

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-protection-candidates-{}-{unique}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn macos_catalog_offers_developer_defaults_and_unselected_account_synced_settings() {
    let directory = TestDirectory::new();
    let home = directory.path().join("owner-home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/config"), b"sensitive host marker\n").unwrap();
    fs::write(home.join(".gitconfig"), b"private git marker\n").unwrap();
    fs::write(home.join(".bashrc"), b"private bash marker\n").unwrap();
    fs::write(home.join(".zshrc"), b"private zsh marker\n").unwrap();
    let code_user = home.join("Library/Application Support/Code/User");
    fs::create_dir_all(code_user.join("snippets")).unwrap();
    fs::write(code_user.join("settings.json"), b"private setting marker\n").unwrap();
    fs::write(
        code_user.join("keybindings.json"),
        b"private binding marker\n",
    )
    .unwrap();

    let report = ProtectionCandidateEngine::macos()
        .discover(ProtectionCandidateRequest::for_home(&home))
        .unwrap();

    for id in [
        "secure-shell-configuration",
        "git-configuration",
        "bash-configuration",
        "zsh-configuration",
    ] {
        let candidate = report
            .candidate(id)
            .expect("developer default should be offered");
        assert_eq!(candidate.proposed_disposition(), Disposition::Included);
        assert_eq!(
            candidate.protection_requirement(),
            ProtectionRequirement::MustProtect
        );
        assert_ne!(candidate.sensitivity(), CandidateSensitivity::Public);
        assert_ne!(candidate.portability(), CandidatePortability::NotPortable);
        assert_eq!(
            candidate.validation(),
            CandidateValidation::ExactFilesystemState
        );
        assert!(!candidate.account_sync_claimed());
    }

    for id in [
        "visual-studio-code-settings",
        "visual-studio-code-keybindings",
        "visual-studio-code-snippets",
        "visual-studio-code-extension-inventory",
    ] {
        let candidate = report
            .candidate(id)
            .expect("Visual Studio Code candidate should be offered");
        assert_eq!(
            candidate.proposed_disposition(),
            Disposition::RequiresReview
        );
        assert_eq!(
            candidate.protection_requirement(),
            ProtectionRequirement::Optional
        );
        assert!(candidate.account_sync_claimed());
        assert!(!candidate.account_sync_verified());
    }

    let machine = report.machine_json_result();
    assert_eq!(machine.lines().count(), 1);
    assert!(!machine.contains(&home.display().to_string()));
    assert!(!machine.contains("sensitive host marker"));
    assert!(!machine.contains("private git marker"));
    assert!(!machine.contains("private setting marker"));
}

#[test]
fn catalog_offers_non_executing_inventories_and_suggests_regenerable_exclusions() {
    let directory = TestDirectory::new();
    let home = directory.path().join("owner-home");
    fs::create_dir(&home).unwrap();

    let report = ProtectionCandidateEngine::macos()
        .discover(ProtectionCandidateRequest::for_home(&home))
        .unwrap();

    let homebrew = report.candidate("homebrew-package-inventory").unwrap();
    assert_eq!(
        homebrew.source_kind(),
        CandidateSourceKind::InventoryCommand
    );
    assert_eq!(homebrew.validation(), CandidateValidation::InventoryOnly);
    assert_eq!(homebrew.proposed_disposition(), Disposition::Included);
    assert!(
        homebrew
            .inventory_commands()
            .iter()
            .all(|command| !command.executes_or_installs_payloads())
    );
    assert!(
        homebrew
            .inventory_commands()
            .iter()
            .any(|command| command.program() == "brew")
    );

    let languages = report.candidate("language-tool-version-inventory").unwrap();
    assert_eq!(languages.validation(), CandidateValidation::InventoryOnly);
    assert_eq!(languages.proposed_disposition(), Disposition::Included);
    assert!(
        languages
            .inventory_commands()
            .iter()
            .all(|command| !command.executes_or_installs_payloads())
    );

    for id in [
        "downloadable-caches",
        "build-outputs",
        "package-registries",
        "installed-toolchain-payloads",
        "homebrew-caches",
    ] {
        let candidate = report.candidate(id).expect("exclusion should be visible");
        assert_eq!(
            candidate.source_kind(),
            CandidateSourceKind::SuggestedExclusion
        );
        assert_eq!(candidate.proposed_disposition(), Disposition::Excluded);
        assert_eq!(
            candidate.protection_requirement(),
            ProtectionRequirement::Optional
        );
    }
}

#[test]
fn owner_can_offer_a_raw_application_folder_with_unsupported_restore_semantics_visible() {
    let directory = TestDirectory::new();
    let home = directory.path().join("owner-home");
    let relative = Path::new("Library/Application Support/Synthetic App");
    let application_folder = home.join(relative);
    fs::create_dir_all(&application_folder).unwrap();
    fs::write(
        application_folder.join("state.db"),
        b"synthetic application state",
    )
    .unwrap();

    let report = ProtectionCandidateEngine::macos()
        .discover(ProtectionCandidateRequest::for_home(&home).with_raw_application_folder(relative))
        .unwrap();
    let candidate = report
        .candidates()
        .iter()
        .find(|candidate| candidate.sources() == [fs::canonicalize(&application_folder).unwrap()])
        .expect("raw application folder should be offered");

    assert_eq!(candidate.source_kind(), CandidateSourceKind::Filesystem);
    assert_eq!(
        candidate.proposed_disposition(),
        Disposition::RequiresReview
    );
    assert_eq!(
        candidate.protection_requirement(),
        ProtectionRequirement::Optional
    );
    assert_eq!(
        candidate.validation(),
        CandidateValidation::UnsupportedRestore
    );
    assert_eq!(candidate.portability(), CandidatePortability::Partial);
    assert!(candidate.available());
}

#[test]
fn owner_selection_creates_a_narrow_plan_without_scanning_unselected_home_state() {
    let directory = TestDirectory::new();
    let home = directory.path().join("owner-home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/config"), b"selected secure shell content").unwrap();
    let code_user = home.join("Library/Application Support/Code/User");
    fs::create_dir_all(&code_user).unwrap();
    fs::write(code_user.join("settings.json"), b"selected editor content").unwrap();
    fs::create_dir_all(home.join("Documents/private-unselected")).unwrap();
    fs::write(
        home.join("Documents/private-unselected/never-scan.txt"),
        b"unselected content marker",
    )
    .unwrap();
    let report = ProtectionCandidateEngine::macos()
        .discover(ProtectionCandidateRequest::for_home(&home))
        .unwrap();

    let request = report
        .plan_request(&["secure-shell-configuration", "visual-studio-code-settings"])
        .unwrap();
    let plan = PlanEngine::local().scan(request).unwrap();
    let paths = plan
        .items()
        .iter()
        .map(|item| item.relative_path.clone())
        .collect::<Vec<_>>();

    assert_eq!(
        paths,
        vec![
            PathBuf::from("."),
            PathBuf::from(".ssh"),
            PathBuf::from(".ssh/config"),
            PathBuf::from("Library"),
            PathBuf::from("Library/Application Support"),
            PathBuf::from("Library/Application Support/Code"),
            PathBuf::from("Library/Application Support/Code/User"),
            PathBuf::from("Library/Application Support/Code/User/settings.json"),
        ]
    );
    assert!(paths.iter().all(|path| !path.starts_with("Documents")));
    let secure_shell = plan
        .items()
        .iter()
        .find(|item| item.relative_path == Path::new(".ssh/config"))
        .unwrap();
    assert_eq!(
        secure_shell.protection_requirement,
        ProtectionRequirement::MustProtect
    );
    let editor = plan
        .items()
        .iter()
        .find(|item| item.relative_path.ends_with("settings.json"))
        .unwrap();
    assert_eq!(
        editor.protection_requirement,
        ProtectionRequirement::Optional
    );
    assert_eq!(editor.disposition, Disposition::Included);
    assert!(plan.recipes().contains(
        &"protection-candidate:secure-shell-configuration:exact-filesystem-state".to_owned()
    ));
    assert!(plan.recipes().contains(
        &"protection-candidate:visual-studio-code-settings:exact-filesystem-state".to_owned()
    ));
}

#[test]
fn candidate_review_output_is_deterministic_path_free_for_automation_and_content_free() {
    let directory = TestDirectory::new();
    let home = directory.path().join("owner-home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/config"), b"never print candidate content").unwrap();
    let raw_relative = Path::new("Library/Application Support/Synthetic App");
    fs::create_dir_all(home.join(raw_relative)).unwrap();
    fs::write(
        home.join(raw_relative).join("state.db"),
        b"never print raw state",
    )
    .unwrap();
    let request =
        || ProtectionCandidateRequest::for_home(&home).with_raw_application_folder(raw_relative);

    let first = ProtectionCandidateEngine::macos()
        .discover(request())
        .unwrap();
    let second = ProtectionCandidateEngine::macos()
        .discover(request())
        .unwrap();
    let human = first.to_human_text();
    let machine = first.machine_json_result();

    assert!(human.contains(".ssh"));
    assert!(human.contains("source kind: Filesystem"));
    assert!(human.contains("protection requirement: MustProtect"));
    assert!(human.contains("available: yes"));
    assert!(human.contains("account sync claim: unverified"));
    assert!(human.contains("unsupported Restore semantics"));
    assert!(!human.contains("never print candidate content"));
    assert!(!human.contains("never print raw state"));
    assert_eq!(machine, second.machine_json_result());
    assert_eq!(machine.lines().count(), 1);
    assert!(!machine.contains(&home.display().to_string()));
    assert!(!machine.contains("never print candidate content"));
    assert!(!machine.contains("never print raw state"));
    let value: serde_json::Value = serde_json::from_str(&machine).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "candidates scan");
    let candidates = value["data"]["candidates"].as_array().unwrap();
    let ids = candidates
        .iter()
        .map(|candidate| candidate["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    let homebrew = candidates
        .iter()
        .find(|candidate| candidate["id"] == "homebrew-package-inventory")
        .unwrap();
    assert_eq!(homebrew["inventory_commands"][0]["program"], "brew");
}

#[test]
fn selected_candidate_plan_round_trips_without_unselected_home_content() {
    let directory = TestDirectory::new();
    let home = directory.path().join("owner-home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/config"), b"selected secure shell content").unwrap();
    let code_user = home.join("Library/Application Support/Code/User");
    fs::create_dir_all(&code_user).unwrap();
    fs::write(code_user.join("settings.json"), b"selected editor content").unwrap();
    fs::create_dir_all(home.join("Documents/unselected")).unwrap();
    fs::write(
        home.join("Documents/unselected/private.txt"),
        b"must never enter the Bundle",
    )
    .unwrap();
    let report = ProtectionCandidateEngine::macos()
        .discover(ProtectionCandidateRequest::for_home(&home))
        .unwrap();
    let mut plan = PlanEngine::local()
        .scan(
            report
                .plan_request(&["secure-shell-configuration", "visual-studio-code-settings"])
                .unwrap(),
        )
        .unwrap();
    let reviewed_hash = plan.approval_hash().unwrap();
    plan.approve(&reviewed_hash).unwrap();
    let bundle = directory.path().join("selected-state.iniza");
    let packed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .unwrap();

    let verified = BundleEngine::local()
        .verify(VerifyRequest::new(&bundle, packed.offline_recovery_key()))
        .unwrap();
    assert_eq!(verified.authenticated_bytes, 52);
    let destination = directory.path().join("restored");
    RestoreEngine::local()
        .restore(RestoreRequest::new(
            &bundle,
            &destination,
            packed.vaultwarden_recovery_secret(),
        ))
        .unwrap();
    assert_eq!(
        fs::read(destination.join(".ssh/config")).unwrap(),
        b"selected secure shell content"
    );
    assert_eq!(
        fs::read(destination.join("Library/Application Support/Code/User/settings.json")).unwrap(),
        b"selected editor content"
    );
    assert!(!destination.join("Documents").exists());
}

#[test]
fn selected_unavailable_must_protect_candidate_remains_visible_in_the_plan() {
    let directory = TestDirectory::new();
    let home = directory.path().join("owner-home");
    fs::create_dir(&home).unwrap();
    let report = ProtectionCandidateEngine::macos()
        .discover(ProtectionCandidateRequest::for_home(&home))
        .unwrap();

    let secure_shell = report.candidate("secure-shell-configuration").unwrap();
    assert!(!secure_shell.available());
    let plan = PlanEngine::local()
        .scan(
            report
                .plan_request(&["secure-shell-configuration"])
                .unwrap(),
        )
        .unwrap();
    let unavailable = plan
        .items()
        .iter()
        .find(|item| item.relative_path == Path::new(".ssh"))
        .expect("selected unavailable state must remain reviewable");
    assert_eq!(unavailable.disposition, Disposition::Unavailable);
    assert_eq!(
        unavailable.protection_requirement,
        ProtectionRequirement::MustProtect
    );
}

#[test]
fn raw_application_folder_must_stay_beneath_the_reviewed_home() {
    let directory = TestDirectory::new();
    let home = directory.path().join("owner-home");
    fs::create_dir(&home).unwrap();

    for unsafe_path in [Path::new("../outside"), Path::new("/absolute/outside")] {
        let error = ProtectionCandidateEngine::macos()
            .discover(
                ProtectionCandidateRequest::for_home(&home)
                    .with_raw_application_folder(unsafe_path),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must be a safe home-relative path")
        );
    }
}
