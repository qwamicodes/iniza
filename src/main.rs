use std::path::PathBuf;
use std::process::ExitCode;

use iniza::{CoreError, InizaCore};

fn main() -> ExitCode {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let machine_output = arguments.first().is_some_and(|value| value == "--json");
    if machine_output {
        arguments.remove(0);
    }
    let command_name = machine_command_name(&arguments);

    match run(arguments, machine_output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if machine_output {
                print_machine_error(&command_name, &error);
            } else {
                eprintln!("{error}");
            }
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(arguments: Vec<String>, machine_output: bool) -> Result<(), CliError> {
    match arguments.as_slice() {
        [command, source, output_flag, plan]
            if command == "scan" && output_flag == "--output-plan" =>
        {
            let source = PathBuf::from(source);
            let plan_path = PathBuf::from(plan);
            print_progress(machine_output, &format!("Scanning {}", source.display()));
            let plan = InizaCore
                .scan_explicit_file(&source)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            plan.write_to(&plan_path)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            if machine_output {
                print_machine_success(
                    "scan",
                    &format!(
                        "{{\"plan_path\":{},\"source_name\":{},\"logical_size\":{}}}",
                        json_string(&plan_path.to_string_lossy()),
                        json_string(&plan.source_name),
                        plan.logical_size
                    ),
                );
            } else {
                println!("Plan created: {}", plan_path.display());
            }
            Ok(())
        }
        [command, subcommand, plan_flag, plan]
            if command == "plan" && subcommand == "validate" && plan_flag == "--plan" =>
        {
            let plan_path = PathBuf::from(plan);
            print_progress(
                machine_output,
                &format!("Validating {}", plan_path.display()),
            );
            InizaCore
                .validate_plan(&plan_path)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            if machine_output {
                print_machine_success(
                    "plan validate",
                    &format!(
                        "{{\"plan_path\":{}}}",
                        json_string(&plan_path.to_string_lossy())
                    ),
                );
            } else {
                println!("Plan valid: {}", plan_path.display());
            }
            Ok(())
        }
        [namespace, command, plan_flag, plan, output_flag, output]
            if namespace == "fixture"
                && command == "pack"
                && plan_flag == "--plan"
                && output_flag == "--output" =>
        {
            let plan_path = PathBuf::from(plan);
            let output_path = PathBuf::from(output);
            print_progress(
                machine_output,
                &format!("Packing test-only fixture from {}", plan_path.display()),
            );
            let summary = InizaCore
                .pack_fixture(&plan_path, &output_path)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            if machine_output {
                print_machine_success(
                    "fixture pack",
                    &format!(
                        "{{\"fixture_path\":{},\"fixture_kind\":\"test_only_unencrypted\",\"source_name\":{},\"logical_size\":{}}}",
                        json_string(&output_path.to_string_lossy()),
                        json_string(&summary.source_name),
                        summary.logical_size
                    ),
                );
            } else {
                println!(
                    "TEST-ONLY UNENCRYPTED fixture created: {} ({} bytes, {})",
                    output_path.display(),
                    summary.logical_size,
                    summary.source_name
                );
            }
            Ok(())
        }
        [namespace, command, fixture] if namespace == "fixture" && command == "inspect" => {
            let fixture_path = PathBuf::from(fixture);
            print_progress(
                machine_output,
                &format!("Inspecting test-only fixture {}", fixture_path.display()),
            );
            let summary = InizaCore
                .inspect_fixture(&fixture_path)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            if machine_output {
                print_machine_success(
                    "fixture inspect",
                    &format!(
                        "{{\"fixture_kind\":\"test_only_unencrypted\",\"source_name\":{},\"logical_size\":{}}}",
                        json_string(&summary.source_name),
                        summary.logical_size
                    ),
                );
            } else {
                println!(
                    "TEST-ONLY UNENCRYPTED fixture\nsource name: {}\nlogical size: {} bytes",
                    summary.source_name, summary.logical_size
                );
            }
            Ok(())
        }
        [namespace, command, fixture, destination_flag, destination]
            if namespace == "fixture"
                && command == "restore"
                && destination_flag == "--to" =>
        {
            let fixture_path = PathBuf::from(fixture);
            let destination_path = PathBuf::from(destination);
            print_progress(
                machine_output,
                &format!(
                    "Restoring test-only fixture {} to {}",
                    fixture_path.display(),
                    destination_path.display()
                ),
            );
            let restored_file = InizaCore
                .restore_fixture(&fixture_path, &destination_path)
                .map_err(map_restore_error)?;
            if machine_output {
                print_machine_success(
                    "fixture restore",
                    &format!(
                        "{{\"fixture_kind\":\"test_only_unencrypted\",\"restored_file\":{}}}",
                        json_string(&restored_file.to_string_lossy())
                    ),
                );
            } else {
                println!(
                    "TEST-ONLY UNENCRYPTED fixture restored: {}",
                    restored_file.display()
                );
            }
            Ok(())
        }
        [command, bundle] if command == "inspect" => {
            let bundle_path = PathBuf::from(bundle);
            print_progress(
                machine_output,
                &format!("Inspecting encrypted Bundle {}", bundle_path.display()),
            );
            InizaCore
                .inspect_bundle(&bundle_path)
                .map_err(|error| CliError::BundleInvalid(error.to_string()))?;
            unreachable!("encrypted Bundle inspection is not implemented")
        }
        _ => Err(CliError::Usage(
            "usage: iniza scan <SOURCE> --output-plan <PLAN> | iniza plan validate --plan <PLAN> | iniza inspect <BUNDLE> | iniza fixture pack --plan <PLAN> --output <PATH.iniza-fixture> | iniza fixture inspect <PATH.iniza-fixture> | iniza fixture restore <PATH.iniza-fixture> --to <NEW_DESTINATION>"
                .to_owned(),
        )),
    }
}

fn print_progress(machine_output: bool, message: &str) {
    if !machine_output {
        eprintln!("{message}");
    }
}

fn print_machine_success(command: &str, data: &str) {
    println!(
        "{{\"schema_version\":1,\"command\":{},\"status\":\"success\",\"data\":{},\"warnings\":[],\"errors\":[]}}",
        json_string(command),
        data
    );
}

fn print_machine_error(command: &str, error: &CliError) {
    println!(
        "{{\"schema_version\":1,\"command\":{},\"status\":\"error\",\"data\":{{}},\"warnings\":[],\"errors\":[{{\"code\":{},\"message\":{}}}]}}",
        json_string(command),
        json_string(error.machine_code()),
        json_string(&error.to_string())
    );
}

fn machine_command_name(arguments: &[String]) -> String {
    match arguments {
        [namespace, command, ..] if namespace == "plan" || namespace == "fixture" => {
            format!("{namespace} {command}")
        }
        [command, ..] => command.clone(),
        [] => "unknown".to_owned(),
    }
}

fn json_string(value: &str) -> String {
    let mut encoded = String::from("\"");
    for character in value.chars() {
        match character {
            '\"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            character if character.is_control() => {
                encoded.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => encoded.push(character),
        }
    }
    encoded.push('\"');
    encoded
}

fn map_restore_error(error: CoreError) -> CliError {
    match error {
        CoreError::DestinationAlreadyExists(_) => CliError::Conflict(error.to_string()),
        _ => CliError::Operation(error.to_string()),
    }
}

#[derive(Debug)]
enum CliError {
    BundleInvalid(String),
    Conflict(String),
    Usage(String),
    Operation(String),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::BundleInvalid(_) => 20,
            Self::Conflict(_) => 50,
            Self::Usage(_) => 2,
            Self::Operation(_) => 11,
        }
    }

    fn machine_code(&self) -> &'static str {
        match self {
            Self::BundleInvalid(_) => "INIZA-E020",
            Self::Conflict(_) => "INIZA-E050",
            Self::Usage(_) => "INIZA-E002",
            Self::Operation(_) => "INIZA-E011",
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BundleInvalid(message)
            | Self::Conflict(message)
            | Self::Usage(message)
            | Self::Operation(message) => formatter.write_str(message),
        }
    }
}
