use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use iniza::{
    BundleEngine, CoreError, InizaCore, InspectRequest, InstalledBitwarden,
    MigrationCaptureOwnerReview, MigrationCaptureRequest, MigrationCaptureState,
    MigrationWorkflowEngine, OfflineRecoveryEngine, OfflineRecoveryLocator,
    OfflineRecoveryRehearsalRequest, Plan, PlanApprovalState, PlanEngine, ProjectAuditEngine,
    ProjectAuditRequest, ProtectionCandidateEngine, ProtectionCandidateRequest, PublicationPolicy,
    PushExecutionState, PushPlanApprovalRequest, PushPlanDraftRequest, PushPlanEngine,
    PushPlanExecutionRequest, ReadinessEvidenceEngine, ReadinessEvidenceStatusRequest,
    RestoreEngine, RestoreRequest, ScanRequest, StoredRecoveryMethodEngine,
    StoredRecoveryMethodRequest, VaultwardenInstallationReport, VaultwardenInstallationRequest,
    VaultwardenItemIdentifier, VaultwardenPreflightReport, VaultwardenRecoveryEngine,
    VaultwardenRecoveryLocator, VerifiedCopyRequest, VerifyRequest,
};

fn main() -> ExitCode {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let machine_output = remove_global_flag(&mut arguments, "--json");
    let json_events = remove_global_flag(&mut arguments, "--json-events");
    let non_interactive = remove_global_flag(&mut arguments, "--non-interactive");
    remove_global_flag(&mut arguments, "--no-color");
    let command_name = machine_command_name(&arguments);

    match run(arguments, machine_output, json_events, non_interactive) {
        Ok(exit_code) => exit_code,
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

fn run(
    arguments: Vec<String>,
    machine_output: bool,
    json_events: bool,
    non_interactive: bool,
) -> Result<ExitCode, CliError> {
    match arguments.as_slice() {
        [command, scan_arguments @ ..] if command == "scan" => {
            run_scan(scan_arguments, machine_output, json_events)
        }
        [namespace, command, project_arguments @ ..]
            if namespace == "projects" && command == "scan" =>
        {
            run_project_audit(project_arguments, machine_output, json_events)
        }
        [
            namespace,
            command,
            action,
            plan_flag,
            plan_path,
            project_flag,
            project_identifier,
            output_flag,
            push_plan,
        ] if namespace == "projects"
            && command == "push-plan"
            && action == "draft"
            && plan_flag == "--plan"
            && project_flag == "--project"
            && output_flag == "--output" =>
        {
            let plan = Plan::read_from(&PathBuf::from(plan_path))
                .map_err(|error| CliError::GitPublication(error.to_string()))?;
            let audit = ProjectAuditEngine::local()
                .audit(ProjectAuditRequest::from_plan(&plan))
                .map_err(|error| CliError::GitPublication(error.to_string()))?;
            let project = audit
                .projects()
                .iter()
                .find(|project| project.id() == project_identifier)
                .ok_or_else(|| {
                    CliError::GitPublication(
                        "Push Plan Project is not present in the approved Plan".to_owned(),
                    )
                })?;
            let remote = project
                .local_state()
                .upstream()
                .and_then(|upstream| upstream.split_once('/'))
                .map(|(remote, _)| remote)
                .ok_or_else(|| {
                    CliError::GitPublication(
                        "Push Plan requires an existing upstream branch".to_owned(),
                    )
                })?;
            let draft = PushPlanEngine::local()
                .draft(PushPlanDraftRequest::new(
                    &plan, project, remote, push_plan,
                ))
                .map_err(|error| CliError::GitPublication(error.to_string()))?;
            let actions = draft
                .actions()
                .iter()
                .map(|action| {
                    serde_json::json!({
                        "action_id": action.action_id(),
                        "action_class": action.action_class(),
                        "local_reference": action.local_reference(),
                        "remote_reference": action.remote_reference(),
                        "expected_old_remote_object": action.expected_old_remote_object(),
                        "proposed_new_remote_object": action.proposed_new_remote_object(),
                        "non_force": action.is_non_force(),
                        "requires_item_approval": action.requires_item_approval(),
                    })
                })
                .collect::<Vec<_>>();
            if machine_output {
                print_machine_value(
                    "projects push-plan draft",
                    serde_json::json!({
                        "approval_hash": draft.approval_hash(),
                        "warning": draft.warning(),
                        "actions": actions,
                    }),
                );
            } else {
                println!("Push Plan review hash: {}", draft.approval_hash());
                println!("Warning: {}", draft.warning());
                for action in draft.actions() {
                    println!(
                        "{}: {} {} -> {} (expected {}, proposed {}, non-force)",
                        action.action_id(),
                        action.action_class(),
                        action.local_reference(),
                        action.remote_reference(),
                        action.expected_old_remote_object(),
                        action.proposed_new_remote_object(),
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        [namespace, command, action, approval_arguments @ ..]
            if namespace == "projects" && command == "push-plan" && action == "approve" =>
        {
            run_push_plan_approval(approval_arguments, machine_output)
        }
        [namespace, command, action, execution_arguments @ ..]
            if namespace == "projects" && command == "push-plan" && action == "execute" =>
        {
            run_push_plan_execution(execution_arguments, machine_output)
        }
        [namespace, method, command, bundle_flag, bundle, document_flag, document]
            if namespace == "recovery"
                && method == "offline"
                && command == "rehearse"
                && bundle_flag == "--bundle"
                && document_flag == "--document" =>
        {
            let receipt = OfflineRecoveryEngine::local()
                .rehearse(OfflineRecoveryRehearsalRequest::new(bundle, document))
                .map_err(|error| match error {
                    CoreError::AuthenticationFailed
                    | CoreError::BundleIncomplete(_)
                    | CoreError::BundleInvalid(_) => CliError::BundleInvalid(error.to_string()),
                    _ => CliError::Operation(error.to_string()),
                })?;
            if machine_output {
                println!("{}", receipt.machine_json_result());
            } else {
                println!("{}", receipt.human_summary());
                println!("Bundle identity: {}", receipt.bundle_identity());
                println!(
                    "Recovery Method identity: {}",
                    receipt.recovery_method_identity()
                );
                println!("Verified at: {}", receipt.verified_at_unix_seconds());
            }
            Ok(ExitCode::SUCCESS)
        }
        [command, subcommand, plan_flag, plan]
            if command == "plan" && subcommand == "show" && plan_flag == "--plan" =>
        {
            let plan_path = PathBuf::from(plan);
            print_progress(machine_output, &format!("Reviewing {}", plan_path.display()));
            let plan = Plan::read_from(&plan_path)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            if machine_output {
                print_machine_value("plan show", plan_review_value(&plan));
            } else {
                print_plan_review(&plan)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        [command, subcommand, original, revised]
            if command == "plan" && subcommand == "diff" =>
        {
            let original = Plan::read_from(&PathBuf::from(original))
                .map_err(|error| CliError::Operation(error.to_string()))?;
            let revised = Plan::read_from(&PathBuf::from(revised))
                .map_err(|error| CliError::Operation(error.to_string()))?;
            let comparison = original.compare(&revised);
            if machine_output {
                let changes = comparison
                    .changes()
                    .iter()
                    .map(|change| {
                        serde_json::json!({
                            "kind": change.kind().as_str(),
                            "item_id": change.item_id(),
                        })
                    })
                    .collect::<Vec<_>>();
                print_machine_value(
                    "plan diff",
                    serde_json::json!({
                        "changed": !comparison.is_empty(),
                        "changes": changes,
                    }),
                );
            } else {
                println!("{}", comparison.to_human_text());
            }
            Ok(ExitCode::SUCCESS)
        }
        [command, subcommand, plan_flag, plan]
            if command == "plan" && subcommand == "validate" && plan_flag == "--plan" =>
        {
            let plan_path = PathBuf::from(plan);
            print_progress(
                machine_output,
                &format!("Validating {}", plan_path.display()),
            );
            let plan = InizaCore
                .validate_plan(&plan_path)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            if plan.is_directory_plan()
                && plan
                    .approval_state()
                    .map_err(|error| CliError::Operation(error.to_string()))?
                    == PlanApprovalState::Stale
            {
                return Err(CliError::Approval(
                    "Plan approval is stale because approval-relevant content changed".to_owned(),
                ));
            }
            if machine_output {
                if plan.is_directory_plan() {
                    print_machine_value(
                        "plan validate",
                        serde_json::json!({
                            "approval_hash": plan.approval_hash().map_err(|error| CliError::Operation(error.to_string()))?,
                            "approval_state": format!("{:?}", plan.approval_state().map_err(|error| CliError::Operation(error.to_string()))?).to_ascii_lowercase(),
                        }),
                    );
                } else {
                    print_machine_success(
                        "plan validate",
                        &format!(
                            "{{\"plan_path\":{}}}",
                            json_string(&plan_path.to_string_lossy())
                        ),
                    );
                }
            } else {
                println!("Plan valid: {}", plan_path.display());
                if plan.is_directory_plan() {
                    println!(
                        "Approval hash: {}",
                        plan.approval_hash()
                            .map_err(|error| CliError::Operation(error.to_string()))?
                    );
                    println!(
                        "Approval: {:?}",
                        plan.approval_state()
                            .map_err(|error| CliError::Operation(error.to_string()))?
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        [command, subcommand, plan_flag, plan, hash_flag, approved_hash]
            if command == "plan"
                && subcommand == "approve"
                && plan_flag == "--plan"
                && hash_flag == "--approved-hash" =>
        {
            let plan_path = PathBuf::from(plan);
            let mut plan = Plan::read_from(&plan_path)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            plan.approve(approved_hash)
                .map_err(|error| CliError::Approval(error.to_string()))?;
            plan.write_to(&plan_path)
                .map_err(|error| CliError::Operation(error.to_string()))?;
            if machine_output {
                print_machine_value(
                    "plan approve",
                    serde_json::json!({"approved_hash": approved_hash}),
                );
            } else {
                println!("Plan approved: {approved_hash}");
            }
            Ok(ExitCode::SUCCESS)
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
            Ok(ExitCode::SUCCESS)
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
            Ok(ExitCode::SUCCESS)
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
            Ok(ExitCode::SUCCESS)
        }
        [command, pack_arguments @ ..] if command == "pack" => {
            run_pack(pack_arguments, machine_output, non_interactive)
        }
        [command, encrypted_arguments @ ..] if command == "verify" => {
            run_verify(encrypted_arguments, machine_output)
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
            unreachable!("encrypted Bundle inspection requires a stored Recovery Method")
        }
        [command, encrypted_arguments @ ..] if command == "inspect" => {
            run_inspect(encrypted_arguments, machine_output)
        }
        [command, encrypted_arguments @ ..] if command == "copy" => {
            run_copy(encrypted_arguments, machine_output)
        }
        [command, encrypted_arguments @ ..] if command == "restore" => {
            run_restore(encrypted_arguments, machine_output)
        }
        [
            command,
            plan_flag,
            plan_path,
            receipts_flag,
            receipts,
            bundle_flag,
            bundle,
            recovery_flag,
            recovery_document,
        ] if command == "status"
            && plan_flag == "--plan"
            && receipts_flag == "--receipts"
            && bundle_flag == "--bundle"
            && recovery_flag == "--offline-recovery-document" =>
        {
            print_progress(machine_output, "Revalidating append-only Readiness Evidence");
            let plan = Plan::read_from(&PathBuf::from(plan_path))
                .map_err(|error| CliError::Approval(error.to_string()))?;
            let loaded = StoredRecoveryMethodEngine::local()
                .load(StoredRecoveryMethodRequest::new(
                    bundle,
                    OfflineRecoveryLocator::new(recovery_document),
                ))
                .map_err(map_bundle_error)?;
            let report = ReadinessEvidenceEngine::local()
                .status(
                    ReadinessEvidenceStatusRequest::new(receipts, &plan)
                        .with_bundle(bundle, loaded.recovery_secret())
                        .with_offline_recovery_document(recovery_document),
                )
                .map_err(|error| CliError::Operation(error.to_string()))?;
            if machine_output {
                println!("{}", report.machine_json_result());
            } else {
                println!("{}", report.human_result());
                for gap in report.blocking_gaps() {
                    println!("Blocking gap: {} ({})", gap.code(), gap.count());
                }
            }
            Ok(ExitCode::from(report.exit_code()))
        }
        _ => Err(CliError::Usage(
            "usage: iniza scan <SOURCE> (--list-protection-candidates | --candidate <IDENTIFIER>... --output-plan <PLAN> | --output-plan <PLAN>) [SCAN OPTIONS] | iniza projects scan --plan <APPROVED_PLAN> [--remote-check] | iniza recovery offline rehearse --bundle <BUNDLE> --document <RECOVERY_DOCUMENT> | iniza pack [PACK OPTIONS] | iniza verify [ENCRYPTED OPTIONS] | iniza inspect [ENCRYPTED OPTIONS] | iniza copy [ENCRYPTED OPTIONS] | iniza restore [ENCRYPTED OPTIONS] | iniza status --plan <PLAN> --receipts <EVIDENCE_DIRECTORY> --bundle <BUNDLE> --offline-recovery-document <RECOVERY_DOCUMENT> | iniza plan show --plan <PLAN> | iniza plan validate --plan <PLAN> | iniza plan approve --plan <PLAN> --approved-hash <HASH> | iniza plan diff <OLD> <NEW> | iniza fixture pack --plan <PLAN> --output <PATH.iniza-fixture> | iniza fixture inspect <PATH.iniza-fixture> | iniza fixture restore <PATH.iniza-fixture> --to <NEW_DESTINATION>"
                .to_owned(),
        )),
    }
}

#[derive(Default)]
struct EncryptedCommandArguments<'a> {
    bundle: Option<&'a str>,
    destination: Option<&'a str>,
    recovery: Option<&'a str>,
    offline_document: Option<&'a str>,
    vaultwarden_item: Option<&'a str>,
    vaultwarden_server_identity_hash: Option<&'a str>,
    bitwarden_installation_review_hash: Option<&'a str>,
    bitwarden_executable: Option<&'a str>,
}

struct VaultwardenCommandLocator<'a> {
    item_identifier: &'a str,
    server_identity_hash: &'a str,
    installation_review_hash: &'a str,
    executable: Option<&'a str>,
}

impl<'a> EncryptedCommandArguments<'a> {
    fn parse(command: &str, arguments: &'a [String]) -> Result<Self, CliError> {
        let mut parsed = Self::default();
        let mut index = 0;
        while index < arguments.len() {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| encrypted_command_usage(command))?;
            let destination = match arguments[index].as_str() {
                "--bundle" if parsed.bundle.is_none() => &mut parsed.bundle,
                "--to" if parsed.destination.is_none() => &mut parsed.destination,
                "--recovery" if parsed.recovery.is_none() => &mut parsed.recovery,
                "--offline-recovery-document" if parsed.offline_document.is_none() => {
                    &mut parsed.offline_document
                }
                "--vaultwarden-item" if parsed.vaultwarden_item.is_none() => {
                    &mut parsed.vaultwarden_item
                }
                "--vaultwarden-server-identity-hash"
                    if parsed.vaultwarden_server_identity_hash.is_none() =>
                {
                    &mut parsed.vaultwarden_server_identity_hash
                }
                "--bitwarden-installation-review-hash"
                    if parsed.bitwarden_installation_review_hash.is_none() =>
                {
                    &mut parsed.bitwarden_installation_review_hash
                }
                "--bitwarden-executable" if parsed.bitwarden_executable.is_none() => {
                    &mut parsed.bitwarden_executable
                }
                _ => return Err(encrypted_command_usage(command)),
            };
            *destination = Some(value.as_str());
            index += 2;
        }
        Ok(parsed)
    }

    fn bundle(&self, command: &str) -> Result<&'a str, CliError> {
        self.bundle.ok_or_else(|| encrypted_command_usage(command))
    }

    fn destination(&self, command: &str) -> Result<&'a str, CliError> {
        self.destination
            .ok_or_else(|| encrypted_command_usage(command))
    }

    fn vaultwarden_locator(
        &self,
        command: &str,
    ) -> Result<Option<VaultwardenCommandLocator<'a>>, CliError> {
        let has_any = self.vaultwarden_item.is_some()
            || self.vaultwarden_server_identity_hash.is_some()
            || self.bitwarden_installation_review_hash.is_some()
            || self.bitwarden_executable.is_some();
        if !has_any {
            return Ok(None);
        }
        let item = self
            .vaultwarden_item
            .ok_or_else(|| encrypted_command_usage(command))?;
        let server = self
            .vaultwarden_server_identity_hash
            .ok_or_else(|| encrypted_command_usage(command))?;
        let review = self
            .bitwarden_installation_review_hash
            .ok_or_else(|| encrypted_command_usage(command))?;
        Ok(Some(VaultwardenCommandLocator {
            item_identifier: item,
            server_identity_hash: server,
            installation_review_hash: review,
            executable: self.bitwarden_executable,
        }))
    }
}

fn run_verify(arguments: &[String], machine_output: bool) -> Result<ExitCode, CliError> {
    let parsed = EncryptedCommandArguments::parse("verify", arguments)?;
    let bundle = parsed.bundle("verify")?;
    if parsed.destination.is_some() {
        return Err(encrypted_command_usage("verify"));
    }

    if parsed.recovery == Some("both") {
        let document = parsed
            .offline_document
            .ok_or_else(|| encrypted_command_usage("verify"))?;
        let vaultwarden_locator = parsed
            .vaultwarden_locator("verify")?
            .ok_or_else(|| encrypted_command_usage("verify"))?;
        print_progress(
            machine_output,
            "Fully verifying encrypted Bundle through both Recovery Methods",
        );
        let offline = load_offline_recovery(bundle, document)?;
        let vaultwarden = load_vaultwarden_recovery(
            bundle,
            vaultwarden_locator.item_identifier,
            vaultwarden_locator.server_identity_hash,
            vaultwarden_locator.installation_review_hash,
            vaultwarden_locator.executable,
        )?;
        let offline_verification = BundleEngine::local()
            .verify(VerifyRequest::new(bundle, offline.recovery_secret()))
            .map_err(map_bundle_error)?;
        let vaultwarden_verification = BundleEngine::local()
            .verify(VerifyRequest::new(bundle, vaultwarden.recovery_secret()))
            .map_err(map_bundle_error)?;
        if offline_verification.bundle_identity() != vaultwarden_verification.bundle_identity() {
            return Err(CliError::Recovery(
                "the two Recovery Methods did not authenticate the same Bundle identity".to_owned(),
            ));
        }
        if machine_output {
            print_machine_value(
                "verify",
                serde_json::json!({
                    "bundle_identity": offline_verification.bundle_identity(),
                    "recovery_methods": ["offline", "vaultwarden"],
                    "same_bundle_identity": true,
                    "format_version": offline_verification.summary.format_version,
                    "cryptographic_suite": offline_verification.summary.cryptographic_suite,
                    "authenticated_chunks": offline_verification.authenticated_chunks,
                    "authenticated_bytes": offline_verification.authenticated_bytes,
                }),
            );
        } else {
            println!("Bundle fully verified through both Recovery Methods");
            println!(
                "Bundle identity: {}",
                offline_verification.bundle_identity()
            );
            println!("Offline Recovery Key: verified");
            println!("Vaultwarden Recovery Secret: verified");
            println!("Both Recovery Methods authenticated the same Bundle: yes");
        }
        return Ok(ExitCode::SUCCESS);
    }
    if parsed.recovery.is_some() {
        return Err(encrypted_command_usage("verify"));
    }

    print_progress(machine_output, "Fully verifying encrypted Bundle");
    let loaded = load_single_recovery("verify", bundle, &parsed)?;
    let verification = BundleEngine::local()
        .verify(VerifyRequest::new(bundle, loaded.recovery_secret()))
        .map_err(map_bundle_error)?;
    if machine_output {
        println!("{}", verification.machine_json_result());
    } else {
        println!("Bundle fully verified");
        println!("Recovery Method: {:?}", loaded.recovery_method());
        println!(
            "Bundle format: IZ{}/{}",
            verification.summary.format_version, verification.summary.cryptographic_suite
        );
        println!(
            "Authenticated chunks: {}",
            verification.authenticated_chunks
        );
        println!("Authenticated bytes: {}", verification.authenticated_bytes);
        println!(
            "Included Migration Items: {}",
            verification.summary.included_items
        );
        println!(
            "Changed Migration Items: {}",
            verification.summary.changed_items
        );
        println!(
            "Unsupported Migration Items: {}",
            verification.summary.unsupported_items
        );
        println!(
            "Unverified Migration Items: {}",
            verification.summary.unverified_items
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn run_inspect(arguments: &[String], machine_output: bool) -> Result<ExitCode, CliError> {
    let parsed = EncryptedCommandArguments::parse("inspect", arguments)?;
    let bundle = parsed.bundle("inspect")?;
    if parsed.destination.is_some() || parsed.recovery.is_some() {
        return Err(encrypted_command_usage("inspect"));
    }
    print_progress(machine_output, "Inspecting authenticated encrypted Bundle");
    let loaded = load_single_recovery("inspect", bundle, &parsed)?;
    let summary = BundleEngine::local()
        .inspect(InspectRequest::new(bundle, loaded.recovery_secret()))
        .map_err(map_bundle_error)?;
    if machine_output {
        print_machine_value(
            "inspect",
            serde_json::json!({
                "format_version": summary.format_version,
                "cryptographic_suite": summary.cryptographic_suite,
                "source_name": summary.source_name,
                "logical_size": summary.logical_size,
                "included_items": summary.included_items,
                "changed_items": summary.changed_items,
                "unsupported_items": summary.unsupported_items,
                "unverified_items": summary.unverified_items,
            }),
        );
    } else {
        println!("Authenticated Bundle inspection");
        println!("Recovery Method: {:?}", loaded.recovery_method());
        println!(
            "Bundle format: IZ{}/{}",
            summary.format_version, summary.cryptographic_suite
        );
        println!("Source name: {}", summary.source_name);
        println!("Logical size: {} bytes", summary.logical_size);
        println!("Included Migration Items: {}", summary.included_items);
        println!("Changed Migration Items: {}", summary.changed_items);
        println!("Unsupported Migration Items: {}", summary.unsupported_items);
        println!("Unverified Migration Items: {}", summary.unverified_items);
    }
    Ok(ExitCode::SUCCESS)
}

fn run_copy(arguments: &[String], machine_output: bool) -> Result<ExitCode, CliError> {
    let parsed = EncryptedCommandArguments::parse("copy", arguments)?;
    let bundle = parsed.bundle("copy")?;
    let destination = parsed.destination("copy")?;
    if parsed.recovery.is_some() {
        return Err(encrypted_command_usage("copy"));
    }
    print_progress(machine_output, "Creating and authenticating Verified Copy");
    let loaded = load_single_recovery("copy", bundle, &parsed)?;
    let report = BundleEngine::local()
        .copy_verified(VerifiedCopyRequest::new(
            bundle,
            destination,
            loaded.recovery_secret(),
        ))
        .map_err(map_verified_copy_error)?;
    if machine_output {
        println!("{}", report.machine_json_result());
    } else {
        println!("{}", report.human_summary());
        println!("Recovery Method: {:?}", loaded.recovery_method());
        println!("Verified: {}", report.is_verified());
        println!("Storage location: {:?}", report.storage_location());
        println!("Durability: {:?}", report.durability());
        for warning in report.warnings() {
            println!("Warning: {warning}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_restore(arguments: &[String], machine_output: bool) -> Result<ExitCode, CliError> {
    let parsed = EncryptedCommandArguments::parse("restore", arguments)?;
    let bundle = parsed.bundle("restore")?;
    let destination = parsed.destination("restore")?;
    if parsed.recovery.is_some() {
        return Err(encrypted_command_usage("restore"));
    }
    print_progress(machine_output, "Restoring authenticated encrypted Bundle");
    let loaded = load_single_recovery("restore", bundle, &parsed)?;
    let report = RestoreEngine::local()
        .restore(RestoreRequest::new(
            bundle,
            destination,
            loaded.recovery_secret(),
        ))
        .map_err(map_encrypted_restore_error)?;
    if machine_output {
        println!("{}", report.machine_json_result());
    } else {
        println!("{}", report.human_result());
        println!("Recovery Method: {:?}", report.recovery_method());
    }
    Ok(ExitCode::SUCCESS)
}

fn load_single_recovery(
    command: &str,
    bundle: &str,
    parsed: &EncryptedCommandArguments<'_>,
) -> Result<iniza::LoadedRecoveryMethod, CliError> {
    match (
        parsed.offline_document,
        parsed.vaultwarden_locator(command)?,
    ) {
        (Some(document), None) => load_offline_recovery(bundle, document),
        (None, Some(locator)) => load_vaultwarden_recovery(
            bundle,
            locator.item_identifier,
            locator.server_identity_hash,
            locator.installation_review_hash,
            locator.executable,
        ),
        _ => Err(CliError::Approval(
            "select exactly one stored Recovery Method for this command".to_owned(),
        )),
    }
}

fn load_offline_recovery(
    bundle: &str,
    document: &str,
) -> Result<iniza::LoadedRecoveryMethod, CliError> {
    StoredRecoveryMethodEngine::local()
        .load(StoredRecoveryMethodRequest::new(
            bundle,
            OfflineRecoveryLocator::new(document),
        ))
        .map_err(map_bundle_error)
}

fn encrypted_command_usage(command: &str) -> CliError {
    let destination = if matches!(command, "copy" | "restore") {
        " --to <NEW_DESTINATION>"
    } else {
        ""
    };
    let both = if command == "verify" {
        " | --recovery both --offline-recovery-document <DOCUMENT> <VAULTWARDEN_LOCATOR>"
    } else {
        ""
    };
    CliError::Usage(format!(
        "usage: iniza {command} --bundle <BUNDLE>{destination} (--offline-recovery-document <DOCUMENT> | <VAULTWARDEN_LOCATOR>{both}); VAULTWARDEN_LOCATOR is --vaultwarden-item <IDENTIFIER> --vaultwarden-server-identity-hash <HASH> --bitwarden-installation-review-hash <HASH> [--bitwarden-executable <PATH>]"
    ))
}

fn load_vaultwarden_recovery(
    bundle: &str,
    item_identifier: &str,
    server_identity_hash: &str,
    installation_review_hash: &str,
    bitwarden_executable: Option<&str>,
) -> Result<iniza::LoadedRecoveryMethod, CliError> {
    let installation_request = bitwarden_executable
        .map(|path| VaultwardenInstallationRequest::explicit(PathBuf::from(path)))
        .unwrap_or_else(VaultwardenInstallationRequest::trusted_path);
    let vaultwarden = VaultwardenRecoveryEngine::with_command_line(InstalledBitwarden::system());
    let installation = vaultwarden
        .inspect_installation(installation_request)
        .map_err(map_vaultwarden_recovery_error)?;
    let item_identifier = VaultwardenItemIdentifier::parse(item_identifier.to_owned())
        .map_err(map_vaultwarden_recovery_error)?;
    StoredRecoveryMethodEngine::local()
        .load(StoredRecoveryMethodRequest::new(
            bundle,
            VaultwardenRecoveryLocator::new(
                item_identifier,
                server_identity_hash,
                installation,
                installation_review_hash,
            ),
        ))
        .map_err(map_vaultwarden_recovery_error)
}

fn map_vaultwarden_recovery_error(error: CoreError) -> CliError {
    match error {
        CoreError::AuthenticationFailed => CliError::Recovery(error.to_string()),
        CoreError::BundleIncomplete(_)
        | CoreError::BundleInvalid(_)
        | CoreError::TestFixtureIsNotBundle(_) => CliError::BundleInvalid(error.to_string()),
        CoreError::Vaultwarden(_) => CliError::Vaultwarden(error.to_string()),
        _ => CliError::Operation(error.to_string()),
    }
}

fn run_pack(
    arguments: &[String],
    machine_output: bool,
    non_interactive: bool,
) -> Result<ExitCode, CliError> {
    let mut plan_path = None;
    let mut output = None;
    let mut friendly_name = None;
    let mut offline_recovery = None;
    let mut bitwarden_executable = None;
    let mut bitwarden = false;
    let mut dry_run = false;
    let mut resume = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--plan" if plan_path.is_none() => {
                plan_path = Some(arguments.get(index + 1).ok_or_else(pack_usage)?);
                index += 2;
            }
            "--output" if output.is_none() => {
                output = Some(arguments.get(index + 1).ok_or_else(pack_usage)?);
                index += 2;
            }
            "--name" if friendly_name.is_none() => {
                friendly_name = Some(arguments.get(index + 1).ok_or_else(pack_usage)?);
                index += 2;
            }
            "--offline-recovery" if offline_recovery.is_none() => {
                offline_recovery = Some(arguments.get(index + 1).ok_or_else(pack_usage)?);
                index += 2;
            }
            "--bitwarden" if !bitwarden => {
                bitwarden = true;
                index += 1;
            }
            "--bitwarden-executable" if bitwarden_executable.is_none() => {
                bitwarden_executable = Some(arguments.get(index + 1).ok_or_else(pack_usage)?);
                index += 2;
            }
            "--resume" if !resume => {
                resume = true;
                index += 1;
            }
            "--dry-run" if !dry_run => {
                dry_run = true;
                index += 1;
            }
            _ => return Err(pack_usage()),
        }
    }

    let plan_path = PathBuf::from(plan_path.ok_or_else(pack_usage)?);
    let output = PathBuf::from(output.ok_or_else(pack_usage)?);
    let friendly_name = friendly_name.ok_or_else(pack_usage)?;
    let offline_recovery = PathBuf::from(offline_recovery.ok_or_else(pack_usage)?);
    if !bitwarden {
        return Err(CliError::Approval(
            "Pack requires the Vaultwarden Recovery Method".to_owned(),
        ));
    }
    if friendly_name.trim().is_empty() {
        return Err(pack_usage());
    }
    if resume {
        return Err(CliError::Interrupted(
            "Pack Resume is available only inside the same live migration capture; a fresh command cannot reconstruct secret live state"
                .to_owned(),
        ));
    }
    if output.extension().and_then(|value| value.to_str()) != Some("iniza") {
        return Err(CliError::Usage(
            "Pack output must end with .iniza".to_owned(),
        ));
    }
    if !offline_recovery
        .to_string_lossy()
        .ends_with(".iniza-recovery")
    {
        return Err(CliError::Usage(
            "Offline Recovery Key document must end with .iniza-recovery".to_owned(),
        ));
    }

    let plan =
        Plan::read_from(&plan_path).map_err(|error| CliError::Approval(error.to_string()))?;
    if plan
        .approval_state()
        .map_err(|error| CliError::Approval(error.to_string()))?
        != PlanApprovalState::Approved
    {
        return Err(CliError::Approval(
            "Pack requires an approved, non-stale Plan".to_owned(),
        ));
    }
    let coverage = plan.coverage_summary();
    if coverage.must_protect_blocking > 0 {
        return Err(CliError::Approval(format!(
            "Pack is blocked by {} unresolved Must-Protect Item(s)",
            coverage.must_protect_blocking
        )));
    }
    if output.exists() || offline_recovery.exists() {
        return Err(CliError::Conflict(
            "Pack never overwrites an existing Bundle or Offline Recovery Key document".to_owned(),
        ));
    }

    if (machine_output || non_interactive) && !dry_run {
        return Err(CliError::Approval(
            "Pack requires interactive owner review of the Bitwarden installation and Vaultwarden preflight; --json never prompts"
                .to_owned(),
        ));
    }
    if dry_run && machine_output {
        print_machine_value(
            "pack",
            serde_json::json!({
                "dry_run": true,
                "plan_approval": "approved",
                "estimated_logical_bytes": plan.estimated_logical_size(),
                "included_items": coverage.included,
                "optional_warnings": coverage.optional_warnings,
                "recovery_methods": 2,
                "would_contact_vaultwarden": false,
                "would_create_artifacts": false,
            }),
        );
        return Ok(ExitCode::SUCCESS);
    } else if dry_run {
        println!(
            "Pack dry run passed. Plan is approved; {} included Migration Item(s), {} estimated logical bytes, and both Recovery Methods are selected. No Bundle, Recovery Method, or external-service change was made.",
            coverage.included,
            plan.estimated_logical_size(),
        );
        return Ok(ExitCode::SUCCESS);
    } else if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(CliError::Approval(
            "interactive Pack requires a controlling terminal for exact owner review".to_owned(),
        ));
    }

    let installation = bitwarden_executable
        .map(|path| VaultwardenInstallationRequest::explicit(PathBuf::from(path)))
        .unwrap_or_else(VaultwardenInstallationRequest::trusted_path);
    let owner_review = TerminalMigrationCaptureOwnerReview;
    eprintln!(
        "Packing the approved Plan, writing the Offline Recovery Key document to the reviewed separate device, and then reviewing Vaultwarden. This creates protected artifacts and may create one external Secure Note."
    );
    let report = MigrationWorkflowEngine::local()
        .capture(MigrationCaptureRequest::new(
            &plan,
            &output,
            &offline_recovery,
            friendly_name,
            installation,
            &owner_review,
        ))
        .map_err(map_migration_capture_error)?;
    if report.state() != MigrationCaptureState::Complete {
        return Err(CliError::Interrupted(report.human_summary().to_owned()));
    }
    println!("{}", report.human_summary());
    println!(
        "Bundle identity: {}",
        report.offline_verification().bundle_identity()
    );
    println!(
        "Offline Recovery Method identity: {}",
        report.offline_receipt().recovery_method_identity()
    );
    println!(
        "Vaultwarden item identifier: {}",
        report.vaultwarden_receipt().item_identifier().as_str()
    );
    println!(
        "Vaultwarden server identity hash: {}",
        report.vaultwarden_receipt().server_identity_hash()
    );
    println!(
        "Bitwarden installation review hash: {}",
        report.installation_review_hash()
    );
    println!(
        "Vaultwarden preflight review hash: {}",
        report.preflight_review_hash()
    );
    println!("Safe to erase this machine: no");
    Ok(ExitCode::SUCCESS)
}

fn pack_usage() -> CliError {
    CliError::Usage(
        "usage: iniza pack --plan <APPROVED_PLAN> --output <PATH.iniza> --name <FRIENDLY_NAME> --bitwarden [--bitwarden-executable <PATH>] --offline-recovery <PATH.iniza-recovery> [--resume] [--dry-run]"
            .to_owned(),
    )
}

struct TerminalMigrationCaptureOwnerReview;

impl MigrationCaptureOwnerReview for TerminalMigrationCaptureOwnerReview {
    fn review_bitwarden_installation(
        &self,
        report: &VaultwardenInstallationReport,
    ) -> Result<String, CoreError> {
        eprintln!("{}", report.human_summary());
        eprintln!(
            "This inspection does not prove vendor provenance. Confirm that you installed the official Bitwarden command-line package through your trusted channel."
        );
        prompt_for_complete_review_hash(
            "Type the complete installation review hash to approve credentialed work: ",
        )
    }

    fn review_vaultwarden_preflight(
        &self,
        report: &VaultwardenPreflightReport,
    ) -> Result<String, CoreError> {
        eprintln!("{}", report.human_summary());
        prompt_for_complete_review_hash(
            "Type the complete preflight review hash to authorize creating one real Secure Note: ",
        )
    }
}

fn prompt_for_complete_review_hash(prompt: &str) -> Result<String, CoreError> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(|error| {
        CoreError::Vaultwarden(format!(
            "could not present the owner review prompt: {error}"
        ))
    })?;
    let mut reviewed_hash = String::new();
    io::stdin().read_line(&mut reviewed_hash).map_err(|error| {
        CoreError::Vaultwarden(format!("could not read the owner review decision: {error}"))
    })?;
    Ok(reviewed_hash.trim().to_owned())
}

fn run_push_plan_approval(
    arguments: &[String],
    machine_output: bool,
) -> Result<ExitCode, CliError> {
    let mut push_plan = None;
    let mut reviewed_hash = None;
    let mut approval = None;
    let mut acknowledged_remote_side_effects = false;
    let mut approved_action_ids = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--plan" if push_plan.is_none() => {
                push_plan = Some(
                    arguments
                        .get(index + 1)
                        .ok_or_else(push_plan_approval_usage)?,
                );
                index += 2;
            }
            "--reviewed-hash" if reviewed_hash.is_none() => {
                reviewed_hash = Some(
                    arguments
                        .get(index + 1)
                        .ok_or_else(push_plan_approval_usage)?,
                );
                index += 2;
            }
            "--output" if approval.is_none() => {
                approval = Some(
                    arguments
                        .get(index + 1)
                        .ok_or_else(push_plan_approval_usage)?,
                );
                index += 2;
            }
            "--acknowledge-remote-side-effects" if !acknowledged_remote_side_effects => {
                acknowledged_remote_side_effects = true;
                index += 1;
            }
            "--approve-action" => {
                approved_action_ids.push(
                    arguments
                        .get(index + 1)
                        .ok_or_else(push_plan_approval_usage)?,
                );
                index += 2;
            }
            _ => return Err(push_plan_approval_usage()),
        }
    }
    let mut request = PushPlanApprovalRequest::new(
        push_plan.ok_or_else(push_plan_approval_usage)?,
        reviewed_hash.ok_or_else(push_plan_approval_usage)?,
        approval.ok_or_else(push_plan_approval_usage)?,
    );
    if acknowledged_remote_side_effects {
        request = request.acknowledge_remote_side_effects();
    }
    for action_id in approved_action_ids {
        request = request.approve_action(action_id);
    }
    let receipt = PushPlanEngine::local()
        .approve(request)
        .map_err(|error| CliError::Approval(error.to_string()))?;
    if machine_output {
        print_machine_value(
            "projects push-plan approve",
            serde_json::json!({"push_plan_hash": receipt.push_plan_hash()}),
        );
    } else {
        println!("Push Plan approved: {}", receipt.push_plan_hash());
    }
    Ok(ExitCode::SUCCESS)
}

fn push_plan_approval_usage() -> CliError {
    CliError::Usage(
        "usage: iniza projects push-plan approve --plan <PUSH_PLAN> --reviewed-hash <HASH> --output <APPROVAL_RECEIPT> --acknowledge-remote-side-effects [--approve-action <ACTION_IDENTIFIER>]..."
            .to_owned(),
    )
}

fn run_push_plan_execution(
    arguments: &[String],
    machine_output: bool,
) -> Result<ExitCode, CliError> {
    let mut directory_plan = None;
    let mut project_identifier = None;
    let mut push_plan = None;
    let mut approval = None;
    let mut result_log = None;
    let mut index = 0;
    while index < arguments.len() {
        let destination = match arguments[index].as_str() {
            "--directory-plan" if directory_plan.is_none() => &mut directory_plan,
            "--project" if project_identifier.is_none() => &mut project_identifier,
            "--push-plan" if push_plan.is_none() => &mut push_plan,
            "--approval" if approval.is_none() => &mut approval,
            "--result" if result_log.is_none() => &mut result_log,
            _ => return Err(push_plan_execution_usage()),
        };
        *destination = Some(
            arguments
                .get(index + 1)
                .ok_or_else(push_plan_execution_usage)?,
        );
        index += 2;
    }
    let plan = Plan::read_from(&PathBuf::from(
        directory_plan.ok_or_else(push_plan_execution_usage)?,
    ))
    .map_err(|error| CliError::GitPublication(error.to_string()))?;
    let audit = ProjectAuditEngine::local()
        .audit(ProjectAuditRequest::from_plan(&plan))
        .map_err(|error| CliError::GitPublication(error.to_string()))?;
    let project_identifier = project_identifier.ok_or_else(push_plan_execution_usage)?;
    let project = audit
        .projects()
        .iter()
        .find(|project| project.id() == *project_identifier)
        .ok_or_else(|| {
            CliError::GitPublication(
                "Push Plan Project is not present in the approved Plan".to_owned(),
            )
        })?;
    let report = PushPlanEngine::local()
        .execute(PushPlanExecutionRequest::new(
            &plan,
            project,
            push_plan.ok_or_else(push_plan_execution_usage)?,
            approval.ok_or_else(push_plan_execution_usage)?,
            result_log.ok_or_else(push_plan_execution_usage)?,
        ))
        .map_err(|error| match error {
            CoreError::DestinationAlreadyExists(_) => CliError::Conflict(error.to_string()),
            _ => CliError::GitPublication(error.to_string()),
        })?;
    if machine_output {
        println!("{}", report.machine_json_result());
    } else {
        println!("{}", report.human_result());
    }
    Ok(match report.state() {
        PushExecutionState::Complete => ExitCode::SUCCESS,
        PushExecutionState::Partial => ExitCode::from(41),
    })
}

fn push_plan_execution_usage() -> CliError {
    CliError::Usage(
        "usage: iniza projects push-plan execute --directory-plan <DIRECTORY_PLAN> --project <PROJECT_IDENTIFIER> --push-plan <PUSH_PLAN> --approval <APPROVAL_RECEIPT> --result <RESULT_LOG>"
            .to_owned(),
    )
}

fn run_scan(
    arguments: &[String],
    machine_output: bool,
    json_events: bool,
) -> Result<ExitCode, CliError> {
    let source = arguments
        .first()
        .map(PathBuf::from)
        .ok_or_else(scan_usage)?;
    let mut output_plan = None;
    let mut exclusions = Vec::new();
    let mut optional_items = Vec::new();
    let mut reviewed_inclusions = Vec::new();
    let mut recipes = Vec::new();
    let mut destination = None;
    let mut publication_policy = PublicationPolicy::ProtectLocallyOnly;
    let mut cross_mounts = false;
    let mut list_protection_candidates = false;
    let mut raw_application_folders = Vec::new();
    let mut selected_candidates = Vec::new();
    let mut index = 1;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--output-plan" => {
                output_plan = Some(PathBuf::from(
                    arguments.get(index + 1).ok_or_else(scan_usage)?,
                ));
                index += 2;
            }
            "--exclude" => {
                exclusions.push(PathBuf::from(
                    arguments.get(index + 1).ok_or_else(scan_usage)?,
                ));
                index += 2;
            }
            "--optional" => {
                optional_items.push(PathBuf::from(
                    arguments.get(index + 1).ok_or_else(scan_usage)?,
                ));
                index += 2;
            }
            "--include-reviewed" => {
                reviewed_inclusions.push(PathBuf::from(
                    arguments.get(index + 1).ok_or_else(scan_usage)?,
                ));
                index += 2;
            }
            "--recipe" => {
                recipes.push(arguments.get(index + 1).ok_or_else(scan_usage)?.clone());
                index += 2;
            }
            "--destination" => {
                destination = Some(PathBuf::from(
                    arguments.get(index + 1).ok_or_else(scan_usage)?,
                ));
                index += 2;
            }
            "--publication-policy" => {
                publication_policy = match arguments.get(index + 1).map(String::as_str) {
                    Some("protect-locally-only") => PublicationPolicy::ProtectLocallyOnly,
                    Some("review-separately") => PublicationPolicy::ReviewSeparately,
                    _ => return Err(scan_usage()),
                };
                index += 2;
            }
            "--cross-mounts" => {
                cross_mounts = true;
                index += 1;
            }
            "--list-protection-candidates" => {
                list_protection_candidates = true;
                index += 1;
            }
            "--raw-application-folder" => {
                raw_application_folders.push(PathBuf::from(
                    arguments.get(index + 1).ok_or_else(scan_usage)?,
                ));
                index += 2;
            }
            "--candidate" => {
                selected_candidates.push(arguments.get(index + 1).ok_or_else(scan_usage)?.clone());
                index += 2;
            }
            _ => return Err(scan_usage()),
        }
    }
    if list_protection_candidates {
        let mut request = ProtectionCandidateRequest::for_home(&source);
        for folder in raw_application_folders {
            request = request.with_raw_application_folder(folder);
        }
        let report = ProtectionCandidateEngine::macos()
            .discover(request)
            .map_err(|error| CliError::Operation(error.to_string()))?;
        if machine_output {
            println!("{}", report.machine_json_result());
        } else {
            print!("{}", report.to_human_text());
        }
        return Ok(ExitCode::SUCCESS);
    }
    let plan_path = output_plan.ok_or_else(scan_usage)?;
    print_progress(
        machine_output || json_events,
        &format!("Scanning {}", source.display()),
    );
    if json_events {
        print_json_event("scan-started", serde_json::json!({}));
    }
    let plan = if !selected_candidates.is_empty() {
        let mut candidate_request = ProtectionCandidateRequest::for_home(&source);
        for folder in raw_application_folders {
            candidate_request = candidate_request.with_raw_application_folder(folder);
        }
        let report = ProtectionCandidateEngine::macos()
            .discover(candidate_request)
            .map_err(|error| CliError::Operation(error.to_string()))?;
        let selected = selected_candidates
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let mut request = report
            .plan_request(&selected)
            .map_err(|error| CliError::Operation(error.to_string()))?
            .with_cross_mounts(cross_mounts)
            .with_publication_policy(publication_policy);
        for exclusion in exclusions {
            request = request.exclude(exclusion);
        }
        for optional_item in optional_items {
            request = request.mark_optional(optional_item);
        }
        for reviewed_inclusion in reviewed_inclusions {
            request = request.include_reviewed(reviewed_inclusion);
        }
        for recipe in recipes {
            request = request.with_recipe(recipe);
        }
        if let Some(destination) = destination {
            request = request.with_destination_preference(destination);
        }
        PlanEngine::local()
            .scan(request)
            .map_err(|error| CliError::Operation(error.to_string()))?
    } else {
        if !raw_application_folders.is_empty() {
            return Err(scan_usage());
        }
        let metadata = std::fs::symlink_metadata(&source).map_err(|error| {
            CliError::Operation(format!(
                "could not inspect approved source at {}: {error}",
                source.display()
            ))
        })?;
        if metadata.is_dir() {
            let mut request = ScanRequest::for_directory(&source)
                .with_cross_mounts(cross_mounts)
                .with_publication_policy(publication_policy);
            for exclusion in exclusions {
                request = request.exclude(exclusion);
            }
            for optional_item in optional_items {
                request = request.mark_optional(optional_item);
            }
            for reviewed_inclusion in reviewed_inclusions {
                request = request.include_reviewed(reviewed_inclusion);
            }
            for recipe in recipes {
                request = request.with_recipe(recipe);
            }
            if let Some(destination) = destination {
                request = request.with_destination_preference(destination);
            }
            PlanEngine::local()
                .scan(request)
                .map_err(|error| CliError::Operation(error.to_string()))?
        } else {
            if !exclusions.is_empty()
                || !optional_items.is_empty()
                || !reviewed_inclusions.is_empty()
                || !recipes.is_empty()
                || destination.is_some()
                || publication_policy != PublicationPolicy::ProtectLocallyOnly
                || cross_mounts
            {
                return Err(CliError::Usage(
                    "directory scan options require a directory source".to_owned(),
                ));
            }
            InizaCore
                .scan_explicit_file(&source)
                .map_err(|error| CliError::Operation(error.to_string()))?
        }
    };
    plan.write_to(&plan_path)
        .map_err(|error| CliError::Operation(error.to_string()))?;
    if json_events {
        print_json_event(
            "scan-completed",
            serde_json::json!({"item_count": plan.items().len()}),
        );
    }
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
    Ok(ExitCode::SUCCESS)
}

fn run_project_audit(
    arguments: &[String],
    machine_output: bool,
    json_events: bool,
) -> Result<ExitCode, CliError> {
    let mut plan_path = None;
    let mut remote_check = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--plan" => {
                plan_path = Some(PathBuf::from(
                    arguments.get(index + 1).ok_or_else(project_audit_usage)?,
                ));
                index += 2;
            }
            "--remote-check" => {
                remote_check = true;
                index += 1;
            }
            _ => return Err(project_audit_usage()),
        }
    }
    let plan_path = plan_path.ok_or_else(project_audit_usage)?;
    let plan =
        Plan::read_from(&plan_path).map_err(|error| CliError::Approval(error.to_string()))?;
    print_progress(
        machine_output || json_events,
        &format!("Auditing Projects from {}", plan_path.display()),
    );
    if json_events {
        print_json_event("project-audit-started", serde_json::json!({}));
    }
    let mut request = ProjectAuditRequest::from_plan(&plan);
    if remote_check {
        request = request.with_remote_check();
    }
    let report = ProjectAuditEngine::local()
        .audit(request)
        .map_err(|error| match error {
            error @ CoreError::InvalidPlan(_) => CliError::Approval(error.to_string()),
            error => CliError::GitAudit(error.to_string()),
        })?;
    if json_events {
        print_json_event(
            "project-audit-completed",
            serde_json::json!({"project_count": report.projects().len()}),
        );
    }
    if machine_output {
        println!("{}", report.machine_json_result());
    } else {
        println!("{}", report.to_human_text());
    }
    Ok(ExitCode::from(1))
}

fn project_audit_usage() -> CliError {
    CliError::Usage("usage: iniza projects scan --plan <APPROVED_PLAN> [--remote-check]".to_owned())
}

fn scan_usage() -> CliError {
    CliError::Usage(
        "usage: iniza scan <SOURCE> (--list-protection-candidates [--raw-application-folder <HOME_RELATIVE_PATH>] | --candidate <ID>... --output-plan <PLAN> [--raw-application-folder <HOME_RELATIVE_PATH>] | --output-plan <PLAN> [--exclude <RELATIVE_PATH>] [--optional <RELATIVE_PATH>] [--include-reviewed <RELATIVE_PATH>] [--recipe <NAME>] [--destination <BUNDLE_PATH>] [--publication-policy <protect-locally-only|review-separately>] [--cross-mounts])"
            .to_owned(),
    )
}

fn print_progress(machine_output: bool, message: &str) {
    if !machine_output {
        eprintln!("{message}");
    }
}

fn print_json_event(event: &str, fields: serde_json::Value) {
    let mut value = serde_json::json!({
        "schema_version": 1,
        "event": event,
    });
    if let (Some(target), Some(fields)) = (value.as_object_mut(), fields.as_object()) {
        for (key, value) in fields {
            target.insert(key.clone(), value.clone());
        }
    }
    eprintln!("{value}");
}

fn remove_global_flag(arguments: &mut Vec<String>, flag: &str) -> bool {
    if let Some(position) = arguments.iter().position(|argument| argument == flag) {
        arguments.remove(position);
        true
    } else {
        false
    }
}

fn print_machine_success(command: &str, data: &str) {
    println!(
        "{{\"schema_version\":1,\"command\":{},\"status\":\"success\",\"data\":{},\"warnings\":[],\"errors\":[]}}",
        json_string(command),
        data
    );
}

fn print_machine_value(command: &str, data: serde_json::Value) {
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "command": command,
            "status": "success",
            "data": data,
            "warnings": [],
            "errors": [],
        })
    );
}

fn plan_review_value(plan: &Plan) -> serde_json::Value {
    let coverage = plan.coverage_summary();
    serde_json::json!({
        "approval_hash": plan.approval_hash().ok(),
        "approval_state": plan.approval_state().ok().map(|state| format!("{state:?}").to_ascii_lowercase()),
        "coverage": {
            "included": coverage.included,
            "excluded": coverage.excluded,
            "requires_review": coverage.requires_review,
            "unsupported": coverage.unsupported,
            "unavailable": coverage.unavailable,
            "must_protect_blocking": coverage.must_protect_blocking,
            "optional_warnings": coverage.optional_warnings,
        },
        "items": plan.items().iter().map(|item| serde_json::json!({
            "id": item.id,
            "kind": item.kind,
            "estimated_size": item.estimated_size,
            "disposition": item.disposition,
            "protection_requirement": item.protection_requirement,
            "explanation": item.explanation,
        })).collect::<Vec<_>>(),
    })
}

fn print_plan_review(plan: &Plan) -> Result<(), CliError> {
    let coverage = plan.coverage_summary();
    let approval_hash = plan
        .approval_hash()
        .map_err(|error| CliError::Operation(error.to_string()))?;
    let approval_state = plan
        .approval_state()
        .map_err(|error| CliError::Operation(error.to_string()))?;
    println!("Plan approval hash: {approval_hash}");
    println!("Approval: {approval_state:?}");
    println!("Coverage");
    println!("  Included: {}", coverage.included);
    println!("  Excluded: {}", coverage.excluded);
    println!("  Requires Review: {}", coverage.requires_review);
    println!("  Unsupported: {}", coverage.unsupported);
    println!("  Unavailable: {}", coverage.unavailable);
    println!(
        "  Must-Protect blockers: {}",
        coverage.must_protect_blocking
    );
    println!("  Optional warnings: {}", coverage.optional_warnings);
    println!("Migration Items");
    for item in plan.items() {
        println!(
            "  {}  {:?}  {:?}  {:?}  {}",
            item.relative_path.display(),
            item.kind,
            item.disposition,
            item.protection_requirement,
            item.explanation
        );
    }
    Ok(())
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
        [namespace, method, command, ..] if namespace == "recovery" => {
            format!("{namespace} {method} {command}")
        }
        [namespace, command, action, ..] if namespace == "projects" && command == "push-plan" => {
            format!("{namespace} {command} {action}")
        }
        [namespace, command, ..]
            if namespace == "plan" || namespace == "fixture" || namespace == "projects" =>
        {
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

fn map_bundle_error(error: CoreError) -> CliError {
    match error {
        CoreError::AuthenticationFailed
        | CoreError::BundleIncomplete(_)
        | CoreError::BundleInvalid(_)
        | CoreError::TestFixtureIsNotBundle(_) => CliError::BundleInvalid(error.to_string()),
        _ => CliError::Operation(error.to_string()),
    }
}

fn map_encrypted_restore_error(error: CoreError) -> CliError {
    match error {
        CoreError::DestinationAlreadyExists(_) => CliError::Conflict(error.to_string()),
        CoreError::AuthenticationFailed
        | CoreError::BundleIncomplete(_)
        | CoreError::BundleInvalid(_)
        | CoreError::TestFixtureIsNotBundle(_) => CliError::BundleInvalid(error.to_string()),
        _ => CliError::Operation(error.to_string()),
    }
}

fn map_verified_copy_error(error: CoreError) -> CliError {
    match error {
        CoreError::DestinationAlreadyExists(_) => CliError::Conflict(error.to_string()),
        CoreError::AuthenticationFailed
        | CoreError::BundleIncomplete(_)
        | CoreError::BundleInvalid(_)
        | CoreError::TestFixtureIsNotBundle(_) => CliError::BundleInvalid(error.to_string()),
        _ => CliError::Operation(error.to_string()),
    }
}

fn map_migration_capture_error(error: CoreError) -> CliError {
    match error {
        CoreError::AuthenticationFailed => CliError::Recovery(error.to_string()),
        CoreError::BundleIncomplete(_)
        | CoreError::BundleInvalid(_)
        | CoreError::TestFixtureIsNotBundle(_) => CliError::BundleInvalid(error.to_string()),
        CoreError::DestinationAlreadyExists(_) => CliError::Conflict(error.to_string()),
        CoreError::InsufficientSpace { .. } | CoreError::Io { .. } => {
            CliError::Storage(error.to_string())
        }
        CoreError::Vaultwarden(_) => CliError::Vaultwarden(error.to_string()),
        _ => CliError::Operation(error.to_string()),
    }
}

#[derive(Debug)]
enum CliError {
    Approval(String),
    BundleInvalid(String),
    Conflict(String),
    GitAudit(String),
    GitPublication(String),
    Interrupted(String),
    Recovery(String),
    Storage(String),
    Usage(String),
    Vaultwarden(String),
    Operation(String),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Approval(_) => 10,
            Self::BundleInvalid(_) => 20,
            Self::Conflict(_) => 50,
            Self::GitAudit(_) => 40,
            Self::GitPublication(_) => 41,
            Self::Interrupted(_) => 70,
            Self::Recovery(_) => 21,
            Self::Storage(_) => 22,
            Self::Usage(_) => 2,
            Self::Vaultwarden(_) => 31,
            Self::Operation(_) => 11,
        }
    }

    fn machine_code(&self) -> &'static str {
        match self {
            Self::Approval(_) => "INIZA-E010",
            Self::BundleInvalid(_) => "INIZA-E020",
            Self::Conflict(_) => "INIZA-E050",
            Self::GitAudit(_) => "INIZA-E040",
            Self::GitPublication(_) => "INIZA-E041",
            Self::Interrupted(_) => "INIZA-E070",
            Self::Recovery(_) => "INIZA-E021",
            Self::Storage(_) => "INIZA-E022",
            Self::Usage(_) => "INIZA-E002",
            Self::Vaultwarden(_) => "INIZA-E031",
            Self::Operation(_) => "INIZA-E011",
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approval(message)
            | Self::BundleInvalid(message)
            | Self::Conflict(message)
            | Self::GitAudit(message)
            | Self::GitPublication(message)
            | Self::Interrupted(message)
            | Self::Recovery(message)
            | Self::Storage(message)
            | Self::Usage(message)
            | Self::Vaultwarden(message)
            | Self::Operation(message) => formatter.write_str(message),
        }
    }
}
