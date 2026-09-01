use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::{CoreError, Plan};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    Included,
    Excluded,
    RequiresReview,
    Unsupported,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionRequirement {
    MustProtect,
    Optional,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicationPolicy {
    #[default]
    ProtectLocallyOnly,
    ReviewSeparately,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationItemKind {
    Directory,
    RegularFile,
    SymbolicLink,
    Special,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationItem {
    pub id: String,
    pub relative_path: PathBuf,
    pub kind: MigrationItemKind,
    pub estimated_size: u64,
    pub disposition: Disposition,
    pub protection_requirement: ProtectionRequirement,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverageSummary {
    pub included: u64,
    pub excluded: u64,
    pub requires_review: u64,
    pub unsupported: u64,
    pub unavailable: u64,
    pub must_protect_blocking: u64,
    pub optional_warnings: u64,
}

impl CoverageSummary {
    pub(crate) fn from_items(items: &[MigrationItem]) -> Self {
        let mut summary = Self::default();
        for item in items {
            match item.disposition {
                Disposition::Included => summary.included += 1,
                Disposition::Excluded => summary.excluded += 1,
                Disposition::RequiresReview => summary.requires_review += 1,
                Disposition::Unsupported => summary.unsupported += 1,
                Disposition::Unavailable => summary.unavailable += 1,
            }
            if item.protection_requirement == ProtectionRequirement::MustProtect
                && item.disposition != Disposition::Included
            {
                summary.must_protect_blocking += 1;
            } else if item.protection_requirement == ProtectionRequirement::Optional
                && matches!(
                    item.disposition,
                    Disposition::RequiresReview
                        | Disposition::Unsupported
                        | Disposition::Unavailable
                )
            {
                summary.optional_warnings += 1;
            }
        }
        summary
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceEntryKind {
    Directory,
    RegularFile,
    SymbolicLink,
    Special,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceObservation {
    pub kind: SourceEntryKind,
    pub estimated_size: u64,
    pub device_id: u64,
    pub change_token: u64,
    pub readable: bool,
}

impl SourceObservation {
    pub fn directory(device_id: u64, change_token: u64) -> Self {
        Self {
            kind: SourceEntryKind::Directory,
            estimated_size: 0,
            device_id,
            change_token,
            readable: true,
        }
    }

    pub fn regular_file(estimated_size: u64, device_id: u64, change_token: u64) -> Self {
        Self {
            kind: SourceEntryKind::RegularFile,
            estimated_size,
            device_id,
            change_token,
            readable: true,
        }
    }

    pub fn special(device_id: u64, change_token: u64) -> Self {
        Self {
            kind: SourceEntryKind::Special,
            estimated_size: 0,
            device_id,
            change_token,
            readable: false,
        }
    }
}

pub trait SourceFilesystem {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
    fn observe(&self, path: &Path) -> io::Result<SourceObservation>;
    fn read_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LocalSourceFilesystem;

impl SourceFilesystem for LocalSourceFilesystem {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        fs::canonicalize(path)
    }

    fn observe(&self, path: &Path) -> io::Result<SourceObservation> {
        let metadata = fs::symlink_metadata(path)?;
        let kind = if metadata.is_dir() {
            SourceEntryKind::Directory
        } else if metadata.is_file() {
            SourceEntryKind::RegularFile
        } else if metadata.file_type().is_symlink() {
            SourceEntryKind::SymbolicLink
        } else {
            SourceEntryKind::Special
        };
        let readable = match kind {
            SourceEntryKind::RegularFile => fs::File::open(path).is_ok(),
            SourceEntryKind::Directory | SourceEntryKind::SymbolicLink => true,
            SourceEntryKind::Special => false,
        };
        Ok(SourceObservation {
            kind,
            estimated_size: if metadata.is_file() {
                metadata.len()
            } else {
                0
            },
            device_id: metadata_device_id(&metadata),
            change_token: metadata_change_token(&metadata),
            readable,
        })
    }

    fn read_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    approved_root: PathBuf,
    cross_mounts: bool,
    exclusions: Vec<PathBuf>,
    optional_items: Vec<PathBuf>,
    recipes: Vec<String>,
    destination_preference: Option<PathBuf>,
    publication_policy: PublicationPolicy,
}

impl ScanRequest {
    pub fn for_directory(root: impl Into<PathBuf>) -> Self {
        Self {
            approved_root: root.into(),
            cross_mounts: false,
            exclusions: Vec::new(),
            optional_items: Vec::new(),
            recipes: Vec::new(),
            destination_preference: None,
            publication_policy: PublicationPolicy::ProtectLocallyOnly,
        }
    }

    pub fn with_cross_mounts(mut self, cross_mounts: bool) -> Self {
        self.cross_mounts = cross_mounts;
        self
    }

    pub fn exclude(mut self, relative_path: impl Into<PathBuf>) -> Self {
        self.exclusions.push(relative_path.into());
        self
    }

    pub fn mark_optional(mut self, relative_path: impl Into<PathBuf>) -> Self {
        self.optional_items.push(relative_path.into());
        self
    }

    pub fn with_recipe(mut self, recipe: impl Into<String>) -> Self {
        self.recipes.push(recipe.into());
        self
    }

    pub fn with_destination_preference(mut self, destination: impl Into<PathBuf>) -> Self {
        self.destination_preference = Some(destination.into());
        self
    }

    pub fn with_publication_policy(mut self, policy: PublicationPolicy) -> Self {
        self.publication_policy = policy;
        self
    }
}

#[derive(Debug)]
pub struct PlanEngine<F = LocalSourceFilesystem> {
    source: F,
}

impl PlanEngine<LocalSourceFilesystem> {
    pub fn local() -> Self {
        Self {
            source: LocalSourceFilesystem,
        }
    }
}

impl<F: SourceFilesystem> PlanEngine<F> {
    pub fn with_source(source: F) -> Self {
        Self { source }
    }

    pub fn scan(&self, request: ScanRequest) -> Result<Plan, CoreError> {
        if request
            .exclusions
            .iter()
            .any(|path| !is_safe_relative_request_path(path))
        {
            return Err(CoreError::InvalidPlan(
                "Plan exclusion must be a safe relative path".to_owned(),
            ));
        }
        if request
            .optional_items
            .iter()
            .any(|path| !is_safe_relative_request_path(path))
        {
            return Err(CoreError::InvalidPlan(
                "optional Migration Item must be a safe relative path".to_owned(),
            ));
        }
        let root = self
            .source
            .canonicalize(&request.approved_root)
            .map_err(|source| CoreError::Io {
                action: "resolve approved Plan root",
                path: request.approved_root.clone(),
                source,
            })?;
        if root.parent().is_none() {
            return Err(CoreError::InvalidPlan(
                "approved Plan root is too broad".to_owned(),
            ));
        }
        let root_observation = self.source.observe(&root).map_err(|source| CoreError::Io {
            action: "inspect approved Plan root",
            path: root.clone(),
            source,
        })?;
        if root_observation.kind != SourceEntryKind::Directory {
            return Err(CoreError::InvalidPlan(format!(
                "approved Plan root is not a directory: {}",
                root.display()
            )));
        }

        let mut items = vec![item_from_observation(
            &root,
            PathBuf::from("."),
            root_observation,
            "explicitly approved directory",
        )];
        let root_was_readable = discover_children(
            &self.source,
            &root,
            &root,
            root_observation.device_id,
            request.cross_mounts,
            &mut items,
        )?;
        if !root_was_readable {
            mark_unavailable(&mut items[0], "source directory is not readable");
        }
        if let Some(root_item) = items.first_mut()
            && self.source.observe(&root).ok() != Some(root_observation)
        {
            mark_changed(root_item);
        }
        apply_request_policy(&mut items, &request.exclusions, &request.optional_items);
        items.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

        let mut recipes = request.recipes;
        recipes.sort();
        recipes.dedup();
        let mut exclusions = request.exclusions;
        exclusions.sort();
        exclusions.dedup();

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
            schema_version: 2,
            kind: crate::PlanKind::Directory,
            source_path: root.clone(),
            source_name,
            logical_size,
            approved_roots: vec![root],
            items,
            recipes,
            exclusions,
            destination_preference: request.destination_preference,
            publication_policy: request.publication_policy,
            cross_mounts: request.cross_mounts,
            approved_hash: None,
        })
    }
}

fn is_safe_relative_request_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn apply_request_policy(
    items: &mut [MigrationItem],
    exclusions: &[PathBuf],
    optional_items: &[PathBuf],
) {
    for item in items {
        if optional_items
            .iter()
            .any(|path| item.relative_path == *path || item.relative_path.starts_with(path))
        {
            item.protection_requirement = ProtectionRequirement::Optional;
        }
        if exclusions
            .iter()
            .any(|path| item.relative_path == *path || item.relative_path.starts_with(path))
        {
            item.disposition = Disposition::Excluded;
            item.explanation = "excluded by reviewed Plan request".to_owned();
        }
    }
}

fn discover_children<F: SourceFilesystem>(
    source: &F,
    root: &Path,
    directory: &Path,
    root_device_id: u64,
    cross_mounts: bool,
    items: &mut Vec<MigrationItem>,
) -> Result<bool, CoreError> {
    let mut paths = match source.read_directory(directory) {
        Ok(paths) => paths,
        Err(_) => return Ok(false),
    };
    paths.sort();

    for path in paths {
        let relative_path = path
            .strip_prefix(root)
            .map_err(|_| {
                CoreError::InvalidPlan("Migration Item escaped its approved root".to_owned())
            })?
            .to_path_buf();
        let first = match source.observe(&path) {
            Ok(observation) => observation,
            Err(_) => {
                items.push(unavailable_unknown_item(root, relative_path));
                continue;
            }
        };
        let mut item = item_from_observation(
            root,
            relative_path,
            first,
            "discovered beneath an explicitly approved root",
        );

        let crosses_mount = first.device_id != root_device_id;
        if crosses_mount && !cross_mounts {
            item.disposition = Disposition::RequiresReview;
            item.explanation = "mount boundary not crossed without approval".to_owned();
        } else if first.kind == SourceEntryKind::Directory
            && !discover_children(source, root, &path, root_device_id, cross_mounts, items)?
        {
            mark_unavailable(&mut item, "source directory is not readable");
        }

        if !first.readable && first.kind == SourceEntryKind::RegularFile {
            mark_unavailable(&mut item, "source item is not readable");
        } else if source.observe(&path).ok() != Some(first)
            && matches!(item.disposition, Disposition::Included)
        {
            mark_changed(&mut item);
        }
        items.push(item);
    }
    Ok(true)
}

fn item_from_observation(
    root: &Path,
    relative_path: PathBuf,
    observation: SourceObservation,
    explanation: &str,
) -> MigrationItem {
    let kind = match observation.kind {
        SourceEntryKind::Directory => MigrationItemKind::Directory,
        SourceEntryKind::RegularFile => MigrationItemKind::RegularFile,
        SourceEntryKind::SymbolicLink => MigrationItemKind::SymbolicLink,
        SourceEntryKind::Special => MigrationItemKind::Special,
    };
    let (disposition, explanation) = match kind {
        MigrationItemKind::Directory | MigrationItemKind::RegularFile => {
            (Disposition::Included, explanation.to_owned())
        }
        MigrationItemKind::SymbolicLink => (
            Disposition::RequiresReview,
            "symbolic link recorded without following its target".to_owned(),
        ),
        MigrationItemKind::Special => (
            Disposition::Unsupported,
            "special filesystem item is not captured".to_owned(),
        ),
        MigrationItemKind::Unknown => unreachable!("observations always have a known kind"),
    };
    MigrationItem {
        id: stable_item_id(root, &relative_path, kind_name(kind)),
        relative_path,
        kind,
        estimated_size: observation.estimated_size,
        disposition,
        protection_requirement: ProtectionRequirement::MustProtect,
        explanation,
    }
}

fn unavailable_unknown_item(root: &Path, relative_path: PathBuf) -> MigrationItem {
    MigrationItem {
        id: stable_item_id(root, &relative_path, "unknown"),
        relative_path,
        kind: MigrationItemKind::Unknown,
        estimated_size: 0,
        disposition: Disposition::Unavailable,
        protection_requirement: ProtectionRequirement::MustProtect,
        explanation: "source item metadata is unavailable".to_owned(),
    }
}

fn mark_unavailable(item: &mut MigrationItem, explanation: &str) {
    item.disposition = Disposition::Unavailable;
    item.explanation = explanation.to_owned();
}

fn mark_changed(item: &mut MigrationItem) {
    item.disposition = Disposition::RequiresReview;
    item.explanation = "source metadata changed during discovery".to_owned();
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

pub(crate) fn stable_item_id(root: &Path, relative_path: &Path, kind: &str) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(b"iniza migration item v1\0");
    input.extend_from_slice(root.to_string_lossy().as_bytes());
    input.push(0);
    input.extend_from_slice(relative_path.to_string_lossy().as_bytes());
    input.push(0);
    input.extend_from_slice(kind.as_bytes());
    format!("item_{}", &blake3::hash(&input).to_hex()[..24])
}

#[cfg(unix)]
fn metadata_device_id(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.dev()
}

#[cfg(not(unix))]
fn metadata_device_id(_metadata: &fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn metadata_change_token(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&metadata.ino().to_be_bytes());
    hasher.update(&metadata.len().to_be_bytes());
    hasher.update(&metadata.mtime().to_be_bytes());
    hasher.update(&metadata.mtime_nsec().to_be_bytes());
    let bytes = hasher.finalize();
    u64::from_be_bytes(
        bytes.as_bytes()[..8]
            .try_into()
            .expect("digest has eight bytes"),
    )
}

#[cfg(not(unix))]
fn metadata_change_token(metadata: &fs::Metadata) -> u64 {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos() as u64);
    metadata.len() ^ modified
}
