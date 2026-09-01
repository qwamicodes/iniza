use std::collections::{BTreeMap, BTreeSet};

use crate::{MigrationItem, Plan};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanComparison {
    changes: Vec<PlanChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanChangeKind {
    SelectedRootsChanged,
    DestinationPreferenceChanged,
    PublicationPolicyChanged,
    MountCrossingPolicyChanged,
    RecipeAdded,
    RecipeRemoved,
    ExclusionAdded,
    ExclusionRemoved,
    ItemAdded,
    ItemRemoved,
    DispositionChanged,
    ProtectionRequirementChanged,
    EstimatedSizeChanged,
    CoverageExplanationChanged,
}

impl PlanChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelectedRootsChanged => "selected-roots-changed",
            Self::DestinationPreferenceChanged => "destination-preference-changed",
            Self::PublicationPolicyChanged => "publication-policy-changed",
            Self::MountCrossingPolicyChanged => "mount-crossing-policy-changed",
            Self::RecipeAdded => "recipe-added",
            Self::RecipeRemoved => "recipe-removed",
            Self::ExclusionAdded => "exclusion-added",
            Self::ExclusionRemoved => "exclusion-removed",
            Self::ItemAdded => "item-added",
            Self::ItemRemoved => "item-removed",
            Self::DispositionChanged => "disposition-changed",
            Self::ProtectionRequirementChanged => "protection-requirement-changed",
            Self::EstimatedSizeChanged => "estimated-size-changed",
            Self::CoverageExplanationChanged => "coverage-explanation-changed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanChange {
    kind: PlanChangeKind,
    item_id: Option<String>,
    human_message: String,
}

impl PlanChange {
    pub fn kind(&self) -> PlanChangeKind {
        self.kind
    }

    pub fn item_id(&self) -> Option<&str> {
        self.item_id.as_deref()
    }

    pub fn human_message(&self) -> &str {
        &self.human_message
    }
}

impl PlanComparison {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn changes(&self) -> &[PlanChange] {
        &self.changes
    }

    pub fn to_human_text(&self) -> String {
        if self.changes.is_empty() {
            "No approval-relevant Plan changes".to_owned()
        } else {
            self.changes
                .iter()
                .map(PlanChange::human_message)
                .collect::<Vec<_>>()
                .join("\n")
        }
    }
}

fn plan_change(kind: PlanChangeKind, human_message: String) -> PlanChange {
    PlanChange {
        kind,
        item_id: None,
        human_message,
    }
}

fn item_change(kind: PlanChangeKind, item_id: &str, human_message: String) -> PlanChange {
    PlanChange {
        kind,
        item_id: Some(item_id.to_owned()),
        human_message,
    }
}

pub(crate) fn compare(before: &Plan, after: &Plan) -> PlanComparison {
    let mut changes = Vec::new();
    if before.approved_roots != after.approved_roots {
        changes.push(plan_change(
            PlanChangeKind::SelectedRootsChanged,
            "selected approved roots changed".to_owned(),
        ));
    }
    if before.destination_preference != after.destination_preference {
        changes.push(plan_change(
            PlanChangeKind::DestinationPreferenceChanged,
            "destination preference changed".to_owned(),
        ));
    }
    if before.publication_policy != after.publication_policy {
        changes.push(plan_change(
            PlanChangeKind::PublicationPolicyChanged,
            format!(
                "publication policy changed from {:?} to {:?}",
                before.publication_policy, after.publication_policy
            ),
        ));
    }
    if before.cross_mounts != after.cross_mounts {
        changes.push(plan_change(
            PlanChangeKind::MountCrossingPolicyChanged,
            format!(
                "mount-crossing policy changed from {} to {}",
                before.cross_mounts, after.cross_mounts
            ),
        ));
    }
    compare_string_sets("recipe", &before.recipes, &after.recipes, &mut changes);
    compare_path_sets(
        "exclusion",
        &before.exclusions,
        &after.exclusions,
        &mut changes,
    );

    let before_items = before
        .items
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let after_items = after
        .items
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    for id in before_items
        .keys()
        .chain(after_items.keys())
        .copied()
        .collect::<BTreeSet<_>>()
    {
        match (before_items.get(id), after_items.get(id)) {
            (None, Some(item)) => changes.push(item_change(
                PlanChangeKind::ItemAdded,
                &item.id,
                format!(
                    "Migration Item added: {} ({})",
                    item.relative_path.display(),
                    item.id
                ),
            )),
            (Some(item), None) => changes.push(item_change(
                PlanChangeKind::ItemRemoved,
                &item.id,
                format!(
                    "Migration Item removed: {} ({})",
                    item.relative_path.display(),
                    item.id
                ),
            )),
            (Some(before_item), Some(after_item)) => {
                compare_item(before_item, after_item, &mut changes)
            }
            (None, None) => unreachable!("identifier came from at least one Plan"),
        }
    }
    PlanComparison { changes }
}

fn compare_item(before: &MigrationItem, after: &MigrationItem, changes: &mut Vec<PlanChange>) {
    let subject = format!("Migration Item {}", before.relative_path.display());
    if before.disposition != after.disposition {
        changes.push(item_change(
            PlanChangeKind::DispositionChanged,
            &before.id,
            format!(
                "{subject} Disposition changed from {:?} to {:?}",
                before.disposition, after.disposition
            ),
        ));
    }
    if before.protection_requirement != after.protection_requirement {
        changes.push(item_change(
            PlanChangeKind::ProtectionRequirementChanged,
            &before.id,
            format!(
                "{subject} Protection Requirement changed from {:?} to {:?}",
                before.protection_requirement, after.protection_requirement
            ),
        ));
    }
    if before.estimated_size != after.estimated_size {
        changes.push(item_change(
            PlanChangeKind::EstimatedSizeChanged,
            &before.id,
            format!(
                "{subject} estimated size changed from {} to {} bytes",
                before.estimated_size, after.estimated_size
            ),
        ));
    }
    if before.explanation != after.explanation {
        changes.push(item_change(
            PlanChangeKind::CoverageExplanationChanged,
            &before.id,
            format!("{subject} coverage explanation changed"),
        ));
    }
}

fn compare_string_sets(
    label: &str,
    before: &[String],
    after: &[String],
    changes: &mut Vec<PlanChange>,
) {
    let before = before.iter().collect::<BTreeSet<_>>();
    let after = after.iter().collect::<BTreeSet<_>>();
    for removed in before.difference(&after) {
        changes.push(plan_change(
            PlanChangeKind::RecipeRemoved,
            format!("{label} removed: {removed}"),
        ));
    }
    for added in after.difference(&before) {
        changes.push(plan_change(
            PlanChangeKind::RecipeAdded,
            format!("{label} added: {added}"),
        ));
    }
}

fn compare_path_sets(
    label: &str,
    before: &[std::path::PathBuf],
    after: &[std::path::PathBuf],
    changes: &mut Vec<PlanChange>,
) {
    let before = before.iter().collect::<BTreeSet<_>>();
    let after = after.iter().collect::<BTreeSet<_>>();
    for removed in before.difference(&after) {
        changes.push(plan_change(
            PlanChangeKind::ExclusionRemoved,
            format!("{label} removed: {}", removed.display()),
        ));
    }
    for added in after.difference(&before) {
        changes.push(plan_change(
            PlanChangeKind::ExclusionAdded,
            format!("{label} added: {}", added.display()),
        ));
    }
}
