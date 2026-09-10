use std::fmt;
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::json;

use crate::{
    BitwardenCommandLine, BundleEngine, BundleEventSink, BundleVerification, CoreError,
    InstalledBitwarden, LocalOfflineRecoveryStorage, OfflineRecoveryEngine,
    OfflineRecoveryLoadRequest, OfflineRecoveryRehearsalReceipt, OfflineRecoveryRehearsalRequest,
    OfflineRecoveryStorage, OfflineRecoveryWriteRequest, PackCancellation, PackReport, PackRequest,
    PackState, Plan, VaultwardenInstallationReport, VaultwardenInstallationRequest,
    VaultwardenLoadRequest, VaultwardenPreflightReport, VaultwardenPreflightRequest,
    VaultwardenRecoveryEngine, VaultwardenRecoveryReceipt, VaultwardenStoreRequest,
    VaultwardenStoreState, VerifyRequest,
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
    pack_cancellation: Option<&'a PackCancellation>,
    pack_event_sink: Option<&'a mut dyn BundleEventSink>,
    resume_paused_pack: bool,
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
            pack_cancellation: None,
            pack_event_sink: None,
            resume_paused_pack: false,
        }
    }

    pub fn with_location_hint(mut self, location_hint: impl Into<String>) -> Self {
        self.location_hint = Some(location_hint.into());
        self
    }

    pub fn with_pack_cancellation(mut self, cancellation: &'a PackCancellation) -> Self {
        self.pack_cancellation = Some(cancellation);
        self
    }

    pub fn with_pack_event_sink(mut self, event_sink: &'a mut dyn BundleEventSink) -> Self {
        self.pack_event_sink = Some(event_sink);
        self
    }

    pub fn resume_paused_pack(mut self) -> Self {
        self.resume_paused_pack = true;
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
    Paused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCaptureReport {
    state: MigrationCaptureState,
    offline_receipt: Option<OfflineRecoveryRehearsalReceipt>,
    vaultwarden_receipt: Option<VaultwardenRecoveryReceipt>,
    offline_verification: Option<BundleVerification>,
    vaultwarden_verification: Option<BundleVerification>,
    installation_review_hash: Option<String>,
    preflight_review_hash: Option<String>,
}

impl MigrationCaptureReport {
    pub fn state(&self) -> MigrationCaptureState {
        self.state
    }

    pub fn offline_receipt(&self) -> &OfflineRecoveryRehearsalReceipt {
        self.offline_receipt
            .as_ref()
            .expect("Complete migration capture has an Offline Recovery receipt")
    }

    pub fn vaultwarden_receipt(&self) -> &VaultwardenRecoveryReceipt {
        self.vaultwarden_receipt
            .as_ref()
            .expect("Complete migration capture has a Vaultwarden receipt")
    }

    pub fn offline_verification(&self) -> &BundleVerification {
        self.offline_verification
            .as_ref()
            .expect("Complete migration capture has an Offline Recovery verification")
    }

    pub fn vaultwarden_verification(&self) -> &BundleVerification {
        self.vaultwarden_verification
            .as_ref()
            .expect("Complete migration capture has a Vaultwarden verification")
    }

    pub fn installation_review_hash(&self) -> &str {
        self.installation_review_hash
            .as_deref()
            .expect("Complete migration capture has an installation review hash")
    }

    pub fn preflight_review_hash(&self) -> &str {
        self.preflight_review_hash
            .as_deref()
            .expect("Complete migration capture has a preflight review hash")
    }

    pub fn human_summary(&self) -> &'static str {
        match self.state {
            MigrationCaptureState::Complete => {
                "Bundle capture completed and both Recovery Methods independently authenticated the completed Bundle. This evidence does not decide whether this machine is safe to erase."
            }
            MigrationCaptureState::Paused => {
                "Pack paused at an authenticated checkpoint. Resume in the same live process; no Recovery Method has been stored and this machine is not safe to erase."
            }
        }
    }

    pub fn machine_json_result(&self) -> String {
        let (status, state, offline_verified, vaultwarden_verified) = match self.state {
            MigrationCaptureState::Complete => ("success", "complete", true, true),
            MigrationCaptureState::Paused => ("paused", "paused", false, false),
        };
        json!({
            "schema_version": 1,
            "command": "migration capture",
            "status": status,
            "data": {
                "state": state,
                "bundle_identity": self.offline_verification.as_ref().map(BundleVerification::bundle_identity),
                "offline_recovery_verified": offline_verified,
                "vaultwarden_recovery_verified": vaultwarden_verified,
                "vaultwarden_item_identifier": self.vaultwarden_receipt.as_ref().map(|receipt| receipt.item_identifier().as_str()),
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
    paused_pack: Mutex<Option<PackReport>>,
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
            paused_pack: Mutex::new(None),
        }
    }
}

impl<C: BitwardenCommandLine, S: OfflineRecoveryStorage> MigrationWorkflowEngine<C, S> {
    pub fn capture(
        &self,
        mut request: MigrationCaptureRequest<'_>,
    ) -> Result<MigrationCaptureReport, CoreError> {
        let mut paused_pack = self.paused_pack.lock().map_err(|_| {
            CoreError::BundleInvalid("live migration capture state is unavailable".to_owned())
        })?;
        let previous = if request.resume_paused_pack {
            Some(paused_pack.take().ok_or_else(|| {
                CoreError::BundleInvalid(
                    "no paused Pack is available in this live migration capture".to_owned(),
                )
            })?)
        } else {
            if paused_pack.is_some() {
                return Err(CoreError::BundleInvalid(
                    "resume the paused Pack in this live migration capture before starting another"
                        .to_owned(),
                ));
            }
            None
        };

        let mut pack_request = match previous.as_ref() {
            Some(previous) => {
                PackRequest::resume(request.plan, &request.bundle, previous.recovery_context())
            }
            None => PackRequest::new(request.plan, &request.bundle),
        };
        if let Some(cancellation) = request.pack_cancellation {
            pack_request = pack_request.with_cancellation(cancellation);
        }
        if let Some(event_sink) = request.pack_event_sink.take() {
            pack_request = pack_request.with_event_sink(event_sink);
        }
        let packed = match BundleEngine::local().pack(pack_request) {
            Ok(packed) => packed,
            Err(error) => {
                if let Some(previous) = previous {
                    *paused_pack = Some(previous);
                }
                return Err(error);
            }
        };
        if packed.state() == PackState::Paused {
            *paused_pack = Some(packed);
            return Ok(MigrationCaptureReport {
                state: MigrationCaptureState::Paused,
                offline_receipt: None,
                vaultwarden_receipt: None,
                offline_verification: None,
                vaultwarden_verification: None,
                installation_review_hash: None,
                preflight_review_hash: None,
            });
        }
        drop(paused_pack);

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
            offline_receipt: Some(offline_receipt),
            vaultwarden_receipt: Some(vaultwarden_receipt),
            offline_verification: Some(offline_verification),
            vaultwarden_verification: Some(vaultwarden_verification),
            installation_review_hash: Some(installation_review_hash),
            preflight_review_hash: Some(preflight_review_hash),
        })
    }
}
