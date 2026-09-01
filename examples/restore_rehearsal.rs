use std::error::Error;
use std::fs;
use std::path::PathBuf;

use iniza::{BundleEngine, PackRequest, PlanEngine, RestoreEngine, RestoreRequest, ScanRequest};

fn main() -> Result<(), Box<dyn Error>> {
    let workspace = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: cargo run --example restore_rehearsal -- <ABSENT_SYNTHETIC_DIRECTORY>")?;
    if workspace.exists() {
        return Err(format!(
            "refusing existing rehearsal directory: {}",
            workspace.display()
        )
        .into());
    }

    let source = workspace.join("synthetic-source");
    let bundle = workspace.join("synthetic.iniza");
    let destination = workspace.join("restored");
    fs::create_dir_all(source.join("nested"))?;
    fs::write(source.join("settings.txt"), b"synthetic settings\n")?;
    fs::write(source.join("nested/empty.txt"), [])?;

    let mut plan = PlanEngine::local().scan(ScanRequest::for_directory(&source))?;
    let reviewed_hash = plan.approval_hash()?;
    plan.approve(&reviewed_hash)?;
    let sealed = BundleEngine::local().pack(PackRequest::new(&plan, &bundle))?;
    let report = RestoreEngine::local().restore(RestoreRequest::new(
        &bundle,
        &destination,
        sealed.offline_recovery_key(),
    ))?;

    println!("{}", report.human_result());
    println!("Synthetic rehearsal retained at {}", workspace.display());
    Ok(())
}
