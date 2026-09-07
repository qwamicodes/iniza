use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use iniza::{
    BundleEngine, InstalledBitwarden, PackRequest, PackState, PlanEngine, ScanRequest,
    VaultwardenInstallationRequest, VaultwardenPreflightRequest, VaultwardenRecoveryEngine,
    VaultwardenStoreRequest, VaultwardenStoreState,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let installation_request = parse_installation_request()?;
    let command_line = InstalledBitwarden::system();
    let engine = VaultwardenRecoveryEngine::with_command_line(command_line);
    let installation = engine
        .inspect_installation(installation_request)
        .map_err(|error| error.to_string())?;

    println!("{}", installation.human_summary());
    println!(
        "This inspection does not prove vendor provenance. Confirm that you installed the official Bitwarden command-line package through your trusted channel."
    );
    confirm_exact(
        "Type the complete installation review hash to approve credentialed work",
        installation.review_hash(),
    )?;

    let rehearsal = RehearsalDirectory::create()?;
    let source = rehearsal.path().join("synthetic-source");
    fs::create_dir(&source).map_err(|_| "could not create synthetic source".to_owned())?;
    fs::write(
        source.join("owner-rehearsal.txt"),
        b"Disposable synthetic content for the COKS-36 owner rehearsal.\n",
    )
    .map_err(|_| "could not write synthetic rehearsal content".to_owned())?;
    let mut plan = PlanEngine::local()
        .scan(ScanRequest::for_directory(&source))
        .map_err(|error| error.to_string())?;
    let plan_hash = plan.approval_hash().map_err(|error| error.to_string())?;
    plan.approve(&plan_hash)
        .map_err(|error| error.to_string())?;
    let bundle = rehearsal.path().join("vaultwarden-owner-rehearsal.iniza");
    let packed = BundleEngine::local()
        .pack(PackRequest::new(&plan, &bundle))
        .map_err(|error| error.to_string())?;
    if packed.state() != PackState::Complete {
        return Err("the disposable synthetic Bundle did not complete".to_owned());
    }

    let preflight = engine
        .preflight(VaultwardenPreflightRequest::new(
            &bundle,
            packed.vaultwarden_recovery_secret(),
            "Owner Vaultwarden rehearsal",
            Some("Disposable COKS-36 rehearsal; retain only until owner review completes"),
            &installation,
            installation.review_hash(),
        ))
        .map_err(|error| error.to_string())?;
    println!("{}", preflight.machine_json_result());
    confirm_exact(
        "Type the complete preflight review hash to authorize creating one real Secure Note",
        preflight.review_hash(),
    )?;

    let stored = engine
        .store_and_rehearse(VaultwardenStoreRequest::new(
            &bundle,
            packed.vaultwarden_recovery_secret(),
            &preflight,
            preflight.review_hash(),
        ))
        .map_err(|error| error.to_string())?;
    println!("{}", stored.human_summary());
    println!("{}", stored.machine_json_result());
    if stored.state() == VaultwardenStoreState::ItemCreatedButUnverified {
        let item_identifier = stored
            .item_identifier()
            .map(|identifier| identifier.as_str())
            .unwrap_or("unavailable");
        return Err(format!(
            "The real item was retained but did not complete rehearsal. Record item identifier {item_identifier}. The disposable Bundle remains at {} for an exact-identifier retry. Do not delete the Vaultwarden item automatically.",
            rehearsal.keep().display()
        ));
    }

    let receipt = stored
        .receipt()
        .ok_or_else(|| "verified storage did not produce a rehearsal Receipt".to_owned())?;
    println!(
        "Verified item identifier: {}",
        receipt.item_identifier().as_str()
    );
    println!("Verified Bundle identity: {}", receipt.bundle_identity());
    println!(
        "Vaultwarden server identity hash: {}",
        receipt.server_identity_hash()
    );
    println!(
        "Verified at Unix seconds: {}",
        receipt.verified_at_unix_seconds()
    );
    println!(
        "Now use a fresh device or equivalent isolated environment. Sign in to the reviewed external Vaultwarden service and locate this exact item identifier without giving Iniza any credential."
    );
    confirm_phrase(
        "After verifying external hosting, type: external service confirmed",
        "external service confirmed",
    )?;
    confirm_phrase(
        "After completing fresh-device sign-in, type: fresh device confirmed",
        "fresh device confirmed",
    )?;
    confirm_phrase(
        "After exercising the independent multi-factor recovery path, type: independent multi-factor recovery confirmed",
        "independent multi-factor recovery confirmed",
    )?;
    let attested_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes Unix epoch".to_owned())?
        .as_secs();
    println!(
        "Owner Attestation recorded at Unix seconds {attested_at}: external service confirmed; fresh device confirmed; independent multi-factor recovery confirmed."
    );
    println!(
        "The disposable local rehearsal Bundle and source were removed. The verified Vaultwarden Secure Note remains because Iniza never deletes recovery items automatically."
    );
    Ok(())
}

fn parse_installation_request() -> Result<VaultwardenInstallationRequest, String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => Ok(VaultwardenInstallationRequest::trusted_path()),
        [flag, path] if flag == "--bitwarden-executable" => {
            Ok(VaultwardenInstallationRequest::explicit(path))
        }
        _ => Err(
            "usage: cargo run --example coks_36_owner_rehearsal -- [--bitwarden-executable <ABSOLUTE_PATH_TO_BW>]"
                .to_owned(),
        ),
    }
}

fn confirm_exact(prompt: &str, expected: &str) -> Result<(), String> {
    let actual = read_confirmation(prompt)?;
    if actual != expected {
        return Err(
            "review hash confirmation did not match; no later operation was authorized".to_owned(),
        );
    }
    Ok(())
}

fn confirm_phrase(prompt: &str, expected: &str) -> Result<(), String> {
    let actual = read_confirmation(prompt)?;
    if actual != expected {
        return Err("Owner Attestation phrase did not match".to_owned());
    }
    Ok(())
}

fn read_confirmation(prompt: &str) -> Result<String, String> {
    print!("{prompt}: ");
    io::stdout()
        .flush()
        .map_err(|_| "could not display the confirmation prompt".to_owned())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|_| "could not read the confirmation".to_owned())?;
    Ok(input.trim_end_matches(['\r', '\n']).to_owned())
}

struct RehearsalDirectory {
    path: PathBuf,
    remove_on_drop: bool,
}

impl RehearsalDirectory {
    fn create() -> Result<Self, String> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock precedes Unix epoch".to_owned())?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "iniza-coks-36-owner-rehearsal-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .map_err(|_| "could not create the isolated rehearsal directory".to_owned())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|_| "could not restrict the rehearsal directory".to_owned())?;
        }
        Ok(Self {
            path,
            remove_on_drop: true,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn keep(mut self) -> PathBuf {
        self.remove_on_drop = false;
        self.path.clone()
    }
}

impl Drop for RehearsalDirectory {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
