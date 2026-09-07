use std::path::PathBuf;
use std::process::ExitCode;

use iniza::{
    CoreError, InizaCore, OfflineRecoveryEngine, OfflineRecoveryRehearsalRequest, Plan,
    PlanApprovalState, PlanEngine, ProjectAuditEngine, ProjectAuditRequest,
    ProtectionCandidateEngine, ProtectionCandidateRequest, PublicationPolicy, PushExecutionState,
    PushPlanApprovalRequest, PushPlanDraftRequest, PushPlanEngine, PushPlanExecutionRequest,
    ScanRequest,
};

fn main() -> ExitCode {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let machine_output = remove_global_flag(&mut arguments, "--json");
    let json_events = remove_global_flag(&mut arguments, "--json-events");
    let command_name = machine_command_name(&arguments);

    match run(arguments, machine_output, json_events) {
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
            "usage: iniza scan <SOURCE> (--list-protection-candidates | --candidate <ID>... --output-plan <PLAN> | --output-plan <PLAN>) [SCAN OPTIONS] | iniza projects scan --plan <APPROVED_PLAN> [--remote-check] | iniza recovery offline rehearse --bundle <BUNDLE> --document <RECOVERY_DOCUMENT> | iniza plan show --plan <PLAN> | iniza plan validate --plan <PLAN> | iniza plan approve --plan <PLAN> --approved-hash <HASH> | iniza plan diff <OLD> <NEW> | iniza inspect <BUNDLE> | iniza fixture pack --plan <PLAN> --output <PATH.iniza-fixture> | iniza fixture inspect <PATH.iniza-fixture> | iniza fixture restore <PATH.iniza-fixture> --to <NEW_DESTINATION>"
                .to_owned(),
        )),
    }
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

#[derive(Debug)]
enum CliError {
    Approval(String),
    BundleInvalid(String),
    Conflict(String),
    GitAudit(String),
    GitPublication(String),
    Usage(String),
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
            Self::Usage(_) => 2,
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
            Self::Usage(_) => "INIZA-E002",
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
            | Self::Usage(message)
            | Self::Operation(message) => formatter.write_str(message),
        }
    }
}
