use std::fmt;
use std::path::PathBuf;

use crate::{
    BitwardenCommandLine, CoreError, InstalledBitwarden, LoadedOfflineRecoveryKey,
    LoadedVaultwardenRecoverySecret, OfflineRecoveryEngine, OfflineRecoveryLoadRequest,
    RecoveryMethod, RecoverySecret, VaultwardenInstallationReport, VaultwardenItemIdentifier,
    VaultwardenLoadRequest, VaultwardenRecoveryEngine,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineRecoveryLocator {
    document: PathBuf,
}

impl OfflineRecoveryLocator {
    pub fn new(document: impl Into<PathBuf>) -> Self {
        Self {
            document: document.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultwardenRecoveryLocator {
    item_identifier: VaultwardenItemIdentifier,
    expected_server_identity_hash: String,
    installation: VaultwardenInstallationReport,
    reviewed_installation_hash: String,
}

impl VaultwardenRecoveryLocator {
    pub fn new(
        item_identifier: VaultwardenItemIdentifier,
        expected_server_identity_hash: impl Into<String>,
        installation: VaultwardenInstallationReport,
        reviewed_installation_hash: impl Into<String>,
    ) -> Self {
        Self {
            item_identifier,
            expected_server_identity_hash: expected_server_identity_hash.into(),
            installation,
            reviewed_installation_hash: reviewed_installation_hash.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredRecoveryMethodLocator {
    Offline(OfflineRecoveryLocator),
    Vaultwarden(VaultwardenRecoveryLocator),
}

impl From<OfflineRecoveryLocator> for StoredRecoveryMethodLocator {
    fn from(locator: OfflineRecoveryLocator) -> Self {
        Self::Offline(locator)
    }
}

impl From<VaultwardenRecoveryLocator> for StoredRecoveryMethodLocator {
    fn from(locator: VaultwardenRecoveryLocator) -> Self {
        Self::Vaultwarden(locator)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecoveryMethodRequest {
    bundle: PathBuf,
    locator: StoredRecoveryMethodLocator,
}

impl StoredRecoveryMethodRequest {
    pub fn new(
        bundle: impl Into<PathBuf>,
        locator: impl Into<StoredRecoveryMethodLocator>,
    ) -> Self {
        Self {
            bundle: bundle.into(),
            locator: locator.into(),
        }
    }
}

enum LoadedRecoveryMethodInner {
    Offline(LoadedOfflineRecoveryKey),
    Vaultwarden(LoadedVaultwardenRecoverySecret),
}

pub struct LoadedRecoveryMethod {
    inner: LoadedRecoveryMethodInner,
}

impl LoadedRecoveryMethod {
    pub fn bundle_identity(&self) -> &str {
        match &self.inner {
            LoadedRecoveryMethodInner::Offline(loaded) => loaded.bundle_identity(),
            LoadedRecoveryMethodInner::Vaultwarden(loaded) => loaded.bundle_identity(),
        }
    }

    pub fn recovery_method_identity(&self) -> &str {
        match &self.inner {
            LoadedRecoveryMethodInner::Offline(loaded) => loaded.recovery_method_identity(),
            LoadedRecoveryMethodInner::Vaultwarden(loaded) => loaded.recovery_method_identity(),
        }
    }

    pub fn recovery_method(&self) -> RecoveryMethod {
        self.recovery_secret().method()
    }

    pub fn recovery_secret(&self) -> &RecoverySecret {
        match &self.inner {
            LoadedRecoveryMethodInner::Offline(loaded) => loaded.recovery_secret(),
            LoadedRecoveryMethodInner::Vaultwarden(loaded) => loaded.recovery_secret(),
        }
    }

    pub fn item_identifier(&self) -> Option<&VaultwardenItemIdentifier> {
        match &self.inner {
            LoadedRecoveryMethodInner::Offline(_) => None,
            LoadedRecoveryMethodInner::Vaultwarden(loaded) => Some(loaded.item_identifier()),
        }
    }

    pub fn server_identity_hash(&self) -> Option<&str> {
        match &self.inner {
            LoadedRecoveryMethodInner::Offline(_) => None,
            LoadedRecoveryMethodInner::Vaultwarden(loaded) => Some(loaded.server_identity_hash()),
        }
    }
}

impl fmt::Debug for LoadedRecoveryMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedRecoveryMethod")
            .field("bundle_identity", &self.bundle_identity())
            .field("recovery_method_identity", &self.recovery_method_identity())
            .field("recovery_method", &self.recovery_method())
            .field("item_identifier", &self.item_identifier())
            .field("server_identity_hash", &self.server_identity_hash())
            .field("recovery_secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub struct StoredRecoveryMethodEngine<C = InstalledBitwarden> {
    vaultwarden: VaultwardenRecoveryEngine<C>,
}

impl StoredRecoveryMethodEngine<InstalledBitwarden> {
    pub fn local() -> Self {
        Self {
            vaultwarden: VaultwardenRecoveryEngine::with_command_line(InstalledBitwarden::system()),
        }
    }
}

impl<C> StoredRecoveryMethodEngine<C> {
    pub fn with_bitwarden_command_line(command_line: C) -> Self {
        Self {
            vaultwarden: VaultwardenRecoveryEngine::with_command_line(command_line),
        }
    }
}

impl<C: BitwardenCommandLine> StoredRecoveryMethodEngine<C> {
    pub fn load(
        &self,
        request: StoredRecoveryMethodRequest,
    ) -> Result<LoadedRecoveryMethod, CoreError> {
        match request.locator {
            StoredRecoveryMethodLocator::Offline(locator) => {
                let loaded = OfflineRecoveryEngine::local().load(
                    OfflineRecoveryLoadRequest::new(request.bundle, locator.document),
                )?;
                Ok(LoadedRecoveryMethod {
                    inner: LoadedRecoveryMethodInner::Offline(loaded),
                })
            }
            StoredRecoveryMethodLocator::Vaultwarden(locator) => {
                let loaded = self.vaultwarden.load(VaultwardenLoadRequest::new(
                    request.bundle,
                    locator.item_identifier,
                    locator.expected_server_identity_hash,
                    &locator.installation,
                    locator.reviewed_installation_hash,
                ))?;
                Ok(LoadedRecoveryMethod {
                    inner: LoadedRecoveryMethodInner::Vaultwarden(loaded),
                })
            }
        }
    }
}
