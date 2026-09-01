use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::plan_engine::stable_item_id;
use crate::{
    CoreError, Disposition, MigrationItem, MigrationItemKind, Plan, PlanKind,
    ProtectionRequirement, PublicationPolicy,
};

const DIRECTORY_PLAN_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryPlanDocument {
    schema_version: u32,
    plan_kind: String,
    selected_roots: Vec<String>,
    recipes: Vec<String>,
    exclusions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination_preference: Option<String>,
    publication_policy: PublicationPolicy,
    cross_mounts: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval: Option<ApprovalDocument>,
    items: Vec<ItemDocument>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDocument {
    reviewed_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemDocument {
    id: String,
    relative_path: String,
    kind: MigrationItemKind,
    estimated_size: u64,
    disposition: Disposition,
    protection_requirement: ProtectionRequirement,
    explanation: String,
}

pub(crate) fn write(plan: &Plan, destination: &Path) -> Result<(), CoreError> {
    let text = encode(plan, true)?;
    fs::write(destination, text).map_err(|source| CoreError::Io {
        action: "write Plan",
        path: destination.to_path_buf(),
        source,
    })
}

pub(crate) fn approval_hash(plan: &Plan) -> Result<String, CoreError> {
    if plan.kind != PlanKind::Directory {
        return Err(CoreError::InvalidPlan(
            "test-only fixture Plans do not support Migration Plan approval".to_owned(),
        ));
    }
    let text = encode(plan, false)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza directory Plan approval v2\0");
    hasher.update(text.as_bytes());
    Ok(format!("plan_blake3_{}", hasher.finalize().to_hex()))
}

pub(crate) fn decode(text: &str) -> Result<Plan, CoreError> {
    let document: DirectoryPlanDocument =
        toml::from_str(text).map_err(|error| CoreError::InvalidPlan(error.to_string()))?;
    if document.schema_version != DIRECTORY_PLAN_SCHEMA_VERSION {
        return Err(CoreError::InvalidPlan(format!(
            "unsupported directory Plan schema version: {}",
            document.schema_version
        )));
    }
    if document.plan_kind != "directory" {
        return Err(CoreError::InvalidPlan(
            "directory Plan kind is invalid".to_owned(),
        ));
    }
    if document.selected_roots.len() != 1 {
        return Err(CoreError::InvalidPlan(
            "directory Plan must contain exactly one approved root".to_owned(),
        ));
    }
    let root = PathBuf::from(&document.selected_roots[0]);
    if !root.is_absolute() {
        return Err(CoreError::InvalidPlan(
            "approved Plan root must be absolute".to_owned(),
        ));
    }

    let mut seen_ids = BTreeSet::new();
    let mut seen_paths = BTreeSet::new();
    let mut items = Vec::with_capacity(document.items.len());
    for item in document.items {
        let relative_path = PathBuf::from(&item.relative_path);
        if !is_safe_relative_path(&relative_path) {
            return Err(CoreError::InvalidPlan(
                "Migration Item contains an unsafe relative path".to_owned(),
            ));
        }
        if !seen_ids.insert(item.id.clone()) || !seen_paths.insert(relative_path.clone()) {
            return Err(CoreError::InvalidPlan(
                "directory Plan contains duplicate Migration Items".to_owned(),
            ));
        }
        let expected_id = stable_item_id(&root, &relative_path, kind_name(item.kind));
        if item.id != expected_id {
            return Err(CoreError::InvalidPlan(
                "Migration Item stable identity does not match its source identity".to_owned(),
            ));
        }
        items.push(MigrationItem {
            id: item.id,
            relative_path,
            kind: item.kind,
            estimated_size: item.estimated_size,
            disposition: item.disposition,
            protection_requirement: item.protection_requirement,
            explanation: item.explanation,
        });
    }
    items.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if items.is_empty() || items[0].relative_path != Path::new(".") {
        return Err(CoreError::InvalidPlan(
            "directory Plan is missing its approved root Migration Item".to_owned(),
        ));
    }

    let mut exclusions = document
        .exclusions
        .into_iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if exclusions.iter().any(|path| !is_safe_relative_path(path)) {
        return Err(CoreError::InvalidPlan(
            "Plan exclusion contains an unsafe relative path".to_owned(),
        ));
    }
    exclusions.sort();
    exclusions.dedup();
    let mut recipes = document.recipes;
    recipes.sort();
    recipes.dedup();
    let logical_size = items
        .iter()
        .filter(|item| item.kind == MigrationItemKind::RegularFile)
        .map(|item| item.estimated_size)
        .sum();
    let source_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("approved-root")
        .to_owned();

    Ok(Plan {
        schema_version: DIRECTORY_PLAN_SCHEMA_VERSION,
        kind: PlanKind::Directory,
        source_path: root.clone(),
        source_name,
        logical_size,
        approved_roots: vec![root],
        items,
        recipes,
        exclusions,
        destination_preference: document.destination_preference.map(PathBuf::from),
        publication_policy: document.publication_policy,
        cross_mounts: document.cross_mounts,
        approved_hash: document.approval.map(|approval| approval.reviewed_hash),
    })
}

fn encode(plan: &Plan, include_approval: bool) -> Result<String, CoreError> {
    let mut selected_roots = plan
        .approved_roots
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    selected_roots.sort();
    let mut recipes = plan.recipes.clone();
    recipes.sort();
    recipes.dedup();
    let mut exclusions = plan
        .exclusions
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    exclusions.sort();
    exclusions.dedup();
    let mut items = plan
        .items
        .iter()
        .map(|item| ItemDocument {
            id: item.id.clone(),
            relative_path: item.relative_path.to_string_lossy().into_owned(),
            kind: item.kind,
            estimated_size: item.estimated_size,
            disposition: item.disposition,
            protection_requirement: item.protection_requirement,
            explanation: item.explanation.clone(),
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let document = DirectoryPlanDocument {
        schema_version: plan.schema_version,
        plan_kind: "directory".to_owned(),
        selected_roots,
        recipes,
        exclusions,
        destination_preference: plan
            .destination_preference
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        publication_policy: plan.publication_policy,
        cross_mounts: plan.cross_mounts,
        approval: include_approval
            .then(|| {
                plan.approved_hash
                    .as_ref()
                    .map(|reviewed_hash| ApprovalDocument {
                        reviewed_hash: reviewed_hash.clone(),
                    })
            })
            .flatten(),
        items,
    };
    toml::to_string_pretty(&document)
        .map_err(|error| CoreError::InvalidPlan(format!("could not serialize Plan: {error}")))
}

fn is_safe_relative_path(path: &Path) -> bool {
    if path == Path::new(".") {
        return true;
    }
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn kind_name(kind: MigrationItemKind) -> &'static str {
    match kind {
        MigrationItemKind::Directory => "directory",
        MigrationItemKind::RegularFile => "regular-file",
        MigrationItemKind::SymbolicLink => "symbolic-link",
        MigrationItemKind::Special => "special",
        MigrationItemKind::Unknown => "unknown",
    }
}
