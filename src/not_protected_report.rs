use std::path::Path;

use serde_json::json;

use crate::{Disposition, MigrationItem, Plan, ProtectionRequirement};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotProtectedEntry {
    item_id: String,
    relative_path: std::path::PathBuf,
    disposition: Disposition,
    protection_requirement: ProtectionRequirement,
    explanation: String,
}

impl NotProtectedEntry {
    pub fn item_id(&self) -> &str {
        &self.item_id
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn disposition(&self) -> Disposition {
        self.disposition
    }

    pub fn protection_requirement(&self) -> ProtectionRequirement {
        self.protection_requirement
    }

    pub fn explanation(&self) -> &str {
        &self.explanation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotProtectedReport {
    entries: Vec<NotProtectedEntry>,
    report_identity: String,
}

impl NotProtectedReport {
    pub fn from_plan(plan: &Plan) -> Self {
        let entries = plan
            .items()
            .iter()
            .filter(|item| item.disposition != Disposition::Included)
            .map(NotProtectedEntry::from)
            .collect::<Vec<_>>();
        let report_identity = report_identity(&entries);
        Self {
            entries,
            report_identity,
        }
    }

    pub fn entries(&self) -> &[NotProtectedEntry] {
        &self.entries
    }

    pub fn has_must_protect_gap(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.protection_requirement == ProtectionRequirement::MustProtect)
    }

    pub fn must_protect_gap_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.protection_requirement == ProtectionRequirement::MustProtect)
            .count()
    }

    pub fn report_identity(&self) -> &str {
        &self.report_identity
    }

    pub fn human_summary(&self) -> String {
        if self.entries.is_empty() {
            return "Not Protected Report: no Plan exclusions, review-required items, unsupported items, or unavailable items.".to_owned();
        }
        let mut output = format!("Not Protected Report: {} item(s).", self.entries.len());
        for entry in &self.entries {
            output.push_str(&format!(
                "\n  {} — {:?} — {:?}: {}",
                entry.relative_path.display(),
                entry.disposition,
                entry.protection_requirement,
                entry.explanation,
            ));
        }
        output
    }

    pub fn machine_json_result(&self) -> String {
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                json!({
                    "item_id": entry.item_id,
                    "disposition": disposition_label(entry.disposition),
                    "protection_requirement": protection_label(entry.protection_requirement),
                    "explanation": entry.explanation,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "schema_version": 1,
            "command": "not-protected report",
            "status": if self.has_must_protect_gap() { "blocking" } else { "success" },
            "data": {
                "report_identity": self.report_identity,
                "item_count": self.entries.len(),
                "must_protect_gaps": self.must_protect_gap_count(),
                "items": entries,
            },
            "warnings": if self.entries.is_empty() {
                Vec::<&str>::new()
            } else {
                vec!["review every item that is not protected by the Bundle"]
            },
            "errors": [],
        })
        .to_string()
    }
}

impl From<&MigrationItem> for NotProtectedEntry {
    fn from(item: &MigrationItem) -> Self {
        Self {
            item_id: item.id.clone(),
            relative_path: item.relative_path.clone(),
            disposition: item.disposition,
            protection_requirement: item.protection_requirement,
            explanation: item.explanation.clone(),
        }
    }
}

fn report_identity(entries: &[NotProtectedEntry]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iniza not protected report v1\0");
    for entry in entries {
        hasher.update(entry.item_id.as_bytes());
        hasher.update(&[0]);
        hasher.update(disposition_label(entry.disposition).as_bytes());
        hasher.update(&[0]);
        hasher.update(protection_label(entry.protection_requirement).as_bytes());
        hasher.update(&[0]);
        hasher.update(entry.explanation.as_bytes());
        hasher.update(&[0]);
    }
    format!("not_protected_blake3_{}", hasher.finalize().to_hex())
}

fn disposition_label(disposition: Disposition) -> &'static str {
    match disposition {
        Disposition::Included => "included",
        Disposition::Excluded => "excluded",
        Disposition::RequiresReview => "requires-review",
        Disposition::Unsupported => "unsupported",
        Disposition::Unavailable => "unavailable",
    }
}

fn protection_label(requirement: ProtectionRequirement) -> &'static str {
    match requirement {
        ProtectionRequirement::MustProtect => "must-protect",
        ProtectionRequirement::Optional => "optional",
    }
}
