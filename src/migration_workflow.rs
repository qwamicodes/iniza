use std::fmt;
use std::path::PathBuf;

use serde_json::json;

use crate::{
    BitwardenCommandLine, BundleEngine, BundleVerification, CoreError, InstalledBitwarden,
    LocalOfflineRecoveryStorage, OfflineRecoveryEngine, OfflineRecoveryLoadRequest,
    OfflineRecoveryRehearsalReceipt, OfflineRecoveryRehearsalRequest, OfflineRecoveryStorage,
    OfflineRecoveryWriteRequest, PackRequest, PackState, Plan, VaultwardenInstallationReport,
    VaultwardenInstallationRequest, VaultwardenLoadRequest, VaultwardenPreflightReport,
    VaultwardenPreflightRequest, VaultwardenRecoveryEngine, VaultwardenRecoveryReceipt,
    VaultwardenStoreRequest, VaultwardenStoreState, VerifyRequest,
};

pub trait MigrationCaptureOwnerReview {
    fn review_bitwarden_installation(
        &self,
        report: &VaultwardenInstallationReport,
    ) -> Result<String, CoreError>;

    fn review_vaultwarden_preflight(
        &self,
        report: &VaultwardenPreflightReport,
    ) -> Result<String, CoreError>;
}

pub struct MigrationCaptureRequest<'a> {
    plan: &'a Plan,
    bundle: PathBuf,
    offline_recovery_document: PathBuf,
    friendly_bundle_name: String,
    location_hint: Option<String>,
    installation: VaultwardenInstallationRequest,
    owner_review: &'a dyn MigrationCaptureOwnerReview,
}

impl<'a> MigrationCaptureRequest<'a> {
    pub fn new(
        plan: &'a Plan,
        bundle: impl Into<PathBuf>,
        offline_recovery_document: impl Into<PathBuf>,
        friendly_bundle_name: impl Into<String>,
        installation: VaultwardenInstallationRequest,
        owner_review: &'a dyn MigrationCaptureOwnerReview,
    ) -> Self {
        Self {
            plan,
            bundle: bundle.into(),
            offline_recovery_document: offline_recovery_document.into(),
            friendly_bundle_name: friendly_bundle_name.into(),
            location_hint: None,
            installation,
            owner_review,
        }
    }

    pub fn with_location_hint(mut self, location_hint: impl Into<String>) -> Self {
        self.location_hint = Some(location_hint.into());
        self
    }
}

impl fmt::Debug for MigrationCaptureRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MigrationCaptureRequest")
            .field("plan", &"[REDACTED PLAN]")
            .field("bundle", &"[REDACTED PATH]")
            .field("offline_recovery_document", &"[REDACTED PATH]")
            .field("friendly_bundle_name", &self.friendly_bundle_name)
            .field("location_hint", &self.location_hint)
            .field("installation", &self.installation)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationCaptureState {
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCaptureReport {
    state: MigrationCaptureState,
    offline_receipt: OfflineRecoveryRehearsalReceipt,
    vaultwarden_receipt: VaultwardenRecoveryReceipt,
    offline_verification: BundleVerification,
    vaultwarden_verification: BundleVerification,
    installation_review_hash: String,
    preflight_review_hash: String,
}

impl MigrationCaptureReport {
    pub fn state(&self) -> MigrationCaptureState {
        self.state
    }

    pub fn offline_receipt(&self) -> &OfflineRecoveryRehearsalReceipt {
        &self.offline_receipt
    }

    pub fn vaultwarden_receipt(&self) -> &VaultwardenRecoveryReceipt {
        &self.vaultwarden_receipt
    }

    pub fn offline_verification(&self) -> &BundleVerification {
        &self.offline_verification
    }

    pub fn vaultwarden_verification(&self) -> &BundleVerification {
        &self.vaultwarden_verification
    }

    pub fn installation_review_hash(&self) -> &str {
        &self.installation_review_hash
    }

    pub fn preflight_review_hash(&self) -> &str {
        &self.preflight_review_hash
    }

    pub fn human_summary(&self) -> &'static str {
        "Bundle capture completed and both Recovery Methods independently authenticated the completed Bundle. This evidence does not decide whether this machine is safe to erase."
    }

    pub fn machine_json_result(&self) -> String {
        json!({
            "schema_version": 1,
            "command": "migration capture",
            "status": "success",
            "data": {
                "state": "complete",
                "bundle_identity": self.offline_verification.bundle_identity(),
                "offline_recovery_verified": true,
                "vaultwarden_recovery_verified": true,
                "vaultwarden_item_identifier": self.vaultwarden_receipt.item_identifier().as_str(),
                "installation_review_hash": self.installation_review_hash,
                "preflight_review_hash": self.preflight_review_hash,
                "safe_to_erase": false,
            },
            "warnings": ["migration capture evidence is not machine-erasure authorization"],
            "errors": [],
        })
        .to_string()
    }
}

#[derive(Debug)]
pub struct MigrationWorkflowEngine<C = InstalledBitwarden, S = LocalOfflineRecoveryStorage> {
    vaultwarden: VaultwardenRecoveryEngine<C>,
    offline: OfflineRecoveryEngine<S>,
}

impl MigrationWorkflowEngine<InstalledBitwarden, LocalOfflineRecoveryStorage> {
    pub fn local() -> Self {
        Self::with_boundaries(InstalledBitwarden::system(), LocalOfflineRecoveryStorage)
    }
}

impl<C, S> MigrationWorkflowEngine<C, S> {
    pub fn with_boundaries(command_line: C, offline_storage: S) -> Self {
        Self {
            vaultwarden: VaultwardenRecoveryEngine::with_command_line(command_line),
            offline: OfflineRecoveryEngine::with_storage(offline_storage),
        }
    }
}

impl<C: BitwardenCommandLine, S: OfflineRecoveryStorage> MigrationWorkflowEngine<C, S> {
    pub fn capture(
        &self,
        request: MigrationCaptureRequest<'_>,
    ) -> Result<MigrationCaptureReport, CoreError> {
        let packed = BundleEngine::local().pack(PackRequest::new(request.plan, &request.bundle))?;
        if packed.state() != PackState::Complete {
            return Err(CoreError::BundleIncomplete(request.bundle));
        }

        self.offline.write(OfflineRecoveryWriteRequest::new(
            &request.bundle,
            &request.offline_recovery_document,
            packed.offline_recovery_key(),
        ))?;
        let offline_receipt = self.offline.rehearse(OfflineRecoveryRehearsalRequest::new(
            &request.bundle,
            &request.offline_recovery_document,
        ))?;

        let installation = self
            .vaultwarden
            .inspect_installation(request.installation)?;
        let installation_review_hash = request
            .owner_review
            .review_bitwarden_installation(&installation)?;
        let preflight = self
            .vaultwarden
            .preflight(VaultwardenPreflightRequest::new(
                &request.bundle,
                packed.vaultwarden_recovery_secret(),
                request.friendly_bundle_name,
                request.location_hint,
                &installation,
                &installation_review_hash,
            ))?;
        let preflight_review_hash = request
            .owner_review
            .review_vaultwarden_preflight(&preflight)?;
        let stored = self
            .vaultwarden
            .store_and_rehearse(VaultwardenStoreRequest::new(
                &request.bundle,
                packed.vaultwarden_recovery_secret(),
                &preflight,
                &preflight_review_hash,
            ))?;
        if stored.state() != VaultwardenStoreState::Verified {
            return Err(CoreError::Vaultwarden(
                "the Vaultwarden recovery item was created but independent verification did not complete"
                    .to_owned(),
            ));
        }
        let vaultwarden_receipt = stored.receipt().cloned().ok_or_else(|| {
            CoreError::Vaultwarden(
                "the verified Vaultwarden recovery receipt is unavailable".to_owned(),
            )
        })?;

        let offline = self.offline.load(OfflineRecoveryLoadRequest::new(
            &request.bundle,
            &request.offline_recovery_document,
        ))?;
        let offline_verification = BundleEngine::local().verify(VerifyRequest::new(
            &request.bundle,
            offline.recovery_secret(),
        ))?;

        let vaultwarden = self.vaultwarden.load(VaultwardenLoadRequest::new(
            &request.bundle,
            vaultwarden_receipt.item_identifier().clone(),
            vaultwarden_receipt.server_identity_hash(),
            &installation,
            &installation_review_hash,
        ))?;
        let vaultwarden_verification = BundleEngine::local().verify(VerifyRequest::new(
            &request.bundle,
            vaultwarden.recovery_secret(),
        ))?;

        let identity = offline_verification.bundle_identity();
        if vaultwarden_verification.bundle_identity() != identity
            || offline_receipt.bundle_identity() != identity
            || vaultwarden_receipt.bundle_identity() != identity
        {
            return Err(CoreError::AuthenticationFailed);
        }

        Ok(MigrationCaptureReport {
            state: MigrationCaptureState::Complete,
            offline_receipt,
            vaultwarden_receipt,
            offline_verification,
            vaultwarden_verification,
            installation_review_hash,
            preflight_review_hash,
        })
    }
}
