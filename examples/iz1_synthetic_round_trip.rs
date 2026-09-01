use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use iniza::Iz1Prototype;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let work_directory = one_work_directory_argument()?;
    fs::create_dir(&work_directory)?;

    let source = work_directory.join("synthetic.txt");
    let bundle = work_directory.join("synthetic.iniza");
    let restore_destination = work_directory.join("restored");
    let expected = b"non-secret synthetic IZ1 manual quality-assurance content\n";
    fs::write(&source, expected)?;

    let sealed = Iz1Prototype.seal_one_file(&source, &bundle)?;
    let vaultwarden = Iz1Prototype.inspect(&bundle, sealed.vaultwarden_recovery_secret())?;
    let offline = Iz1Prototype.inspect(&bundle, sealed.offline_recovery_key())?;
    let restored =
        Iz1Prototype.restore(&bundle, sealed.offline_recovery_key(), &restore_destination)?;

    println!("sealed=true");
    println!(
        "vaultwarden_unlock={}:{}",
        vaultwarden.source_name, vaultwarden.logical_size
    );
    println!(
        "offline_unlock={}:{}",
        offline.source_name, offline.logical_size
    );
    println!("restore_matches={}", fs::read(restored)? == expected);
    println!("bundle={}", bundle.display());
    Ok(())
}

fn one_work_directory_argument() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments
        .next()
        .ok_or("usage: cargo run --example iz1_synthetic_round_trip -- <absent-work-directory>")?;
    if arguments.next().is_some() {
        return Err(
            "usage: cargo run --example iz1_synthetic_round_trip -- <absent-work-directory>".into(),
        );
    }
    if path == OsString::new() {
        return Err("work directory must not be empty".into());
    }
    Ok(PathBuf::from(path))
}
