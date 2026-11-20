//! Vault sync for the app: the sync events delegate, the setup, the join with
//! a recovery kit, the disable, the report, pairing on both Macs, the kit
//! import, the key state, and the missing and moved vaults.
//!
//! No sync key or `ManagedKey` crosses uniffi. A `SyncSetup` stays in a
//! [`SyncSetupHandle`]. The pairing of the new Mac and its key are moved into
//! the sync manager, and [`PairingHandle`] holds only the shown code. A kit
//! import checks the kit again in the call that imports, so the recovered key
//! never leaves the call.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use axo_pass_core::core::auth::AuthContext;
use axo_pass_core::secrets::vaults::storage::txn::{Disabled, Target, Unlock};
use axo_pass_core::secrets::vaults::sync::join_sync::JoinInto;
use axo_pass_core::secrets::vaults::sync::load::{SignatureFailure, SyncLoad};
use axo_pass_core::secrets::vaults::sync::manager::{LogEvents, SyncEvents};
use axo_pass_core::secrets::vaults::sync::model::ItemId;
use axo_pass_core::secrets::vaults::sync::pairing::grant::GrantOutcome;
use axo_pass_core::secrets::vaults::sync::pairing::prompt::PairingPrompt;
use axo_pass_core::secrets::vaults::sync::pairing::request::PairingRequest;
use axo_pass_core::secrets::vaults::sync::pairing::{PairedVault, PairingCode};
use axo_pass_core::secrets::vaults::sync::recovery::RecoveryKit;
use axo_pass_core::secrets::vaults::sync::recovery::import::{RecoveryCheck, RecoveryImport};
use axo_pass_core::secrets::vaults::sync::repair::SyncOverride;
use axo_pass_core::secrets::vaults::sync::report::{KnownMac, QuarantinedEntry, SyncReport};
use axo_pass_core::secrets::vaults::sync::setup::{SetupStart, SyncSetup};
use axo_pass_core::secrets::vaults::sync::status::{PausedCause, StopCause, SyncStatus};
use axo_pass_core::secrets::vaults::sync::transport::TransportRoot;
use axo_pass_core::secrets::vaults::sync::transport::s3::credentials::default_credential_store;
use axo_pass_core::secrets::vaults::sync::transport::s3::{S3Config, test_connection};
use axo_pass_core::secrets::vaults::{
    Error as VaultError, KeyState, MissingVault, MovedVault, Resigned, ShortId, SyncedVault,
    VaultCatalog, VaultsManager,
};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::vault::parse_id;
use crate::*;

/// Implemented by the app to receive the events of the sync manager. Called
/// on the manager thread, so each method returns immediately and posts to
/// the main actor. Vault ids are short ids.
#[uniffi::export(with_foreign)]
pub trait SyncEventsDelegate: Send + Sync {
    /// A transaction joined a peer change of the vault. Reload it.
    fn vault_synced(&self, vault_id: String);
    /// A peer change of the vault waits for the next unlock.
    fn peer_changed(&self, vault_id: String);
    /// `count` pairing requests under `root` prompt. A count of zero clears
    /// the prompt.
    fn pairing_requests(&self, root: SyncRootInfo, count: u32);
    /// The new Mac received the sync key of the vault by pairing.
    fn vault_paired(&self, vault_id: String);
    /// The import of the vault waits for a state file of the Mac that paired.
    fn import_waiting(&self, vault_id: String);
    /// The pairing import built or joined the vault `vault_key`.
    fn vault_imported(&self, vault_id: String, vault_key: String);
    /// The pairing import of the vault failed. The user pairs again.
    fn import_failed(&self, vault_id: String, message: String);
}

/// Sync events of the process (D12). The sync manager holds them from its
/// start. They are logged as `LogEvents` logs them, and forwarded to the
/// delegate once [`set_sync_events`] sets it.
pub(crate) struct ForwardEvents {
    log: LogEvents,
    delegate: OnceLock<Arc<dyn SyncEventsDelegate>>,
    /// Last pairing count of each root that is not zero. A delegate set
    /// after the start scan receives them. The delegate is set, and each
    /// count is forwarded, under this mutex, so the delegate receives the
    /// counts in the order the manager reported them.
    counts: Mutex<HashMap<TransportRoot, usize>>,
}

static FORWARD_EVENTS: LazyLock<Arc<ForwardEvents>> = LazyLock::new(|| {
    Arc::new(ForwardEvents {
        log: LogEvents,
        delegate: OnceLock::new(),
        counts: Mutex::new(HashMap::new()),
    })
});

impl ForwardEvents {
    /// Events of the process, for the sync manager.
    pub(crate) fn shared() -> Arc<Self> {
        Arc::clone(&FORWARD_EVENTS)
    }

    /// Set `delegate` and send it the held pairing counts. Only the first
    /// delegate of the process is set. A later one is logged and ignored.
    fn set(&self, delegate: Arc<dyn SyncEventsDelegate>) {
        let counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if self.delegate.set(Arc::clone(&delegate)).is_err() {
            log::warn!("Sync events delegate is already set, the new one is ignored");
            return;
        }
        for (root, count) in counts.iter() {
            delegate.pairing_requests(root.into(), Self::count(*count));
        }
    }

    /// Call `f` with the delegate, if one is set.
    fn forward(&self, f: impl FnOnce(&dyn SyncEventsDelegate)) {
        if let Some(delegate) = self.delegate.get() {
            f(delegate.as_ref());
        }
    }

    fn count(count: usize) -> u32 {
        u32::try_from(count).unwrap_or(u32::MAX)
    }
}

impl SyncEvents for ForwardEvents {
    fn vault_synced(&self, vault_id: Uuid) {
        self.log.vault_synced(vault_id);
        self.forward(|d| d.vault_synced(ShortId::encode_uuid(vault_id)));
    }

    fn peer_changed(&self, vault_id: Uuid) {
        self.log.peer_changed(vault_id);
        self.forward(|d| d.peer_changed(ShortId::encode_uuid(vault_id)));
    }

    fn pairing_requests(&self, root: &TransportRoot, count: usize) {
        self.log.pairing_requests(root, count);
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if count == 0 {
            counts.remove(root);
        } else {
            counts.insert(root.clone(), count);
        }
        self.forward(|d| d.pairing_requests(root.into(), Self::count(count)));
    }

    fn paired(&self, vault: &PairedVault) {
        self.log.paired(vault);
        self.forward(|d| d.vault_paired(ShortId::encode_uuid(vault.vault_id)));
    }

    fn import_waiting(&self, vault_id: Uuid) {
        self.log.import_waiting(vault_id);
        self.forward(|d| d.import_waiting(ShortId::encode_uuid(vault_id)));
    }

    fn vault_imported(&self, vault_id: Uuid, vault_key: &str) {
        self.log.vault_imported(vault_id, vault_key);
        self.forward(|d| d.vault_imported(ShortId::encode_uuid(vault_id), vault_key.to_string()));
    }

    fn import_failed(&self, vault_id: Uuid, error: &VaultError) {
        self.log.import_failed(vault_id, error);
        self.forward(|d| d.import_failed(ShortId::encode_uuid(vault_id), error.to_string()));
    }
}

/// Set the sync events delegate of the process and send it the last pairing
/// count of each root (D12). Call once at launch. Only the first call sets a
/// delegate. A later call is logged and ignored. Events sent before the call
/// are only logged, except the pairing counts.
#[uniffi::export]
pub fn set_sync_events(delegate: Arc<dyn SyncEventsDelegate>) {
    FORWARD_EVENTS.set(delegate);
}

/// Whether the iCloud synced folder can be chosen. False until the iCloud
/// transport is built (D2).
#[uniffi::export]
pub fn sync_icloud_available() -> bool {
    false
}

/// Synced folder of a vault.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum SyncRootInfo {
    /// Folder the user picked.
    Folder { path: String },
    /// `Vaults` in the iCloud container of the app. Not available yet.
    ICloud,
    /// S3 location saved under `name` in the credential store.
    S3 { name: String },
}

impl From<&TransportRoot> for SyncRootInfo {
    fn from(root: &TransportRoot) -> Self {
        match root {
            TransportRoot::ICloud {} => Self::ICloud,
            TransportRoot::Folder { path } => Self::Folder {
                path: path.display().to_string(),
            },
            TransportRoot::S3 { name } => Self::S3 { name: name.clone() },
        }
    }
}

impl From<SyncRootInfo> for TransportRoot {
    fn from(root: SyncRootInfo) -> Self {
        match root {
            SyncRootInfo::ICloud => Self::ICloud {},
            SyncRootInfo::Folder { path } => Self::Folder {
                path: PathBuf::from(path),
            },
            SyncRootInfo::S3 { name } => Self::S3 { name },
        }
    }
}

/// Settings of an S3 location, with its secret access key.
#[derive(uniffi::Record)]
pub struct S3SettingsInput {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Key prefix of every object. Empty for the root of the bucket.
    pub prefix: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl S3SettingsInput {
    fn config(&self) -> Result<S3Config, FfiError> {
        Ok(S3Config::new(
            &self.access_key_id,
            SecretString::from(self.secret_access_key.clone()),
            &self.endpoint,
            &self.region,
            &self.bucket,
            &self.prefix,
        )?)
    }
}

/// Saved settings of an S3 location. Does not hold the secret access key.
#[derive(uniffi::Record)]
pub struct S3SettingsInfo {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub access_key_id: String,
}

/// Outcome of a passed S3 connection test.
#[derive(uniffi::Record)]
pub struct S3TestInfo {
    /// Reads of the listing until it showed the probe object. One means the
    /// listing was consistent with the write.
    pub list_attempts: u32,
}

/// Sync status of a synced vault. Mirrors the core `SyncStatus`.
#[derive(uniffi::Enum)]
pub enum SyncStatusInfo {
    Active,
    /// Local edits are recorded, and the causes block some files or the
    /// publish.
    Paused {
        causes: Vec<PausedCauseInfo>,
    },
    /// No edit is recorded and nothing is published.
    Stopped {
        cause: StopCauseInfo,
    },
}

impl From<SyncStatus> for SyncStatusInfo {
    fn from(status: SyncStatus) -> Self {
        match status {
            SyncStatus::Active => Self::Active,
            SyncStatus::Paused(causes) => Self::Paused {
                causes: causes.into_iter().map(PausedCauseInfo::from).collect(),
            },
            SyncStatus::Stopped(cause) => Self::Stopped {
                cause: cause.into(),
            },
        }
    }
}

/// Cause of a paused sync. Mirrors the core `PausedCause`.
#[derive(uniffi::Enum)]
pub enum PausedCauseInfo {
    /// The synced folder, or a replica directory in it, cannot be listed.
    Unreachable { error: String },
    /// The staged file failed to copy to the synced folder.
    PublishFailed { error: String },
    /// Listed state files are quarantined.
    Quarantined { files: u32 },
    /// Listed state files are of a newer format.
    VersionSkew { files: u32 },
    /// The view of the sync state failed to apply to the vault.
    ApplyFailed { error: String },
    /// The vault failed to diff against the view.
    DiffFailed { error: String },
    /// The sync state is under a key id this Mac lacks.
    KeyMissing { key_id: u32 },
    /// Another Mac enabled sync for the vault separately.
    SeparateKey { replicas: u32 },
}

impl From<PausedCause> for PausedCauseInfo {
    fn from(cause: PausedCause) -> Self {
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        match cause {
            PausedCause::Unreachable { error } => Self::Unreachable { error },
            PausedCause::PublishFailed { error } => Self::PublishFailed { error },
            PausedCause::Quarantined { files } => Self::Quarantined {
                files: count(files),
            },
            PausedCause::VersionSkew { files } => Self::VersionSkew {
                files: count(files),
            },
            PausedCause::ApplyFailed { error } => Self::ApplyFailed { error },
            PausedCause::DiffFailed { error } => Self::DiffFailed { error },
            PausedCause::KeyMissing { key_id } => Self::KeyMissing { key_id },
            PausedCause::SeparateKey { replicas } => Self::SeparateKey {
                replicas: count(replicas),
            },
        }
    }
}

/// Cause of a stopped sync. Mirrors the core `StopCause`.
#[derive(uniffi::Enum)]
pub enum StopCauseInfo {
    /// Edits were found on build `build`. The override resumes sync if
    /// `override_offered` holds.
    Drift {
        build: String,
        override_offered: bool,
    },
    /// The sync state is not trusted.
    SignatureFailed { reason: SignatureFailureInfo },
    /// The vault holds a replica id, and no sync state exists.
    StateMissing,
}

impl From<StopCause> for StopCauseInfo {
    fn from(cause: StopCause) -> Self {
        match cause {
            StopCause::Drift {
                build,
                override_offered,
            } => Self::Drift {
                build,
                override_offered,
            },
            StopCause::SignatureFailed(reason) => Self::SignatureFailed {
                reason: reason.into(),
            },
            StopCause::StateMissing => Self::StateMissing,
        }
    }
}

/// Reason a sync state is not trusted. Mirrors the core `SignatureFailure`.
#[derive(uniffi::Enum)]
pub enum SignatureFailureInfo {
    Envelope,
    Signature,
    Malformed,
    Keyring,
    Body,
    OwnKey,
}

impl From<SignatureFailure> for SignatureFailureInfo {
    fn from(reason: SignatureFailure) -> Self {
        match reason {
            SignatureFailure::Envelope => Self::Envelope,
            SignatureFailure::Signature => Self::Signature,
            SignatureFailure::Malformed => Self::Malformed,
            SignatureFailure::Keyring => Self::Keyring,
            SignatureFailure::Body => Self::Body,
            SignatureFailure::OwnKey => Self::OwnKey,
        }
    }
}

/// Quarantined state file, with the display name of its Mac.
#[derive(uniffi::Record)]
pub struct QuarantinedFileInfo {
    pub replica_id: String,
    /// `None` if the sync state holds no name for the Mac.
    pub mac_name: Option<String>,
    /// File name in the replica directory.
    pub name: String,
    pub reason: String,
}

impl From<QuarantinedEntry> for QuarantinedFileInfo {
    fn from(entry: QuarantinedEntry) -> Self {
        Self {
            replica_id: ShortId::encode_uuid(entry.replica.0),
            mac_name: entry.mac_name,
            name: entry.name,
            reason: entry.reason,
        }
    }
}

/// Mac that the sync state knows by display name.
#[derive(uniffi::Record)]
pub struct KnownMacInfo {
    pub replica_id: String,
    pub name: String,
    pub this_mac: bool,
    /// The Mac turned sync off.
    pub left: bool,
    /// Last active time on the clock of that Mac, as a Unix timestamp in
    /// seconds.
    pub last_active: Option<i64>,
}

impl From<KnownMac> for KnownMacInfo {
    fn from(mac: KnownMac) -> Self {
        Self {
            replica_id: ShortId::encode_uuid(mac.replica.0),
            name: mac.name,
            this_mac: mac.this_mac,
            left: mac.left,
            last_active: mac.last_active,
        }
    }
}

/// Sync report of one vault. Mirrors the core `SyncReport`.
#[derive(uniffi::Record)]
pub struct SyncReportInfo {
    /// `None` for a vault that is not synced, is being disabled, or whose
    /// sync state is from a newer format.
    pub status: Option<SyncStatusInfo>,
    /// An earlier turn-off waits for the synced folder.
    pub disable_in_progress: bool,
    /// Number of values shown as conflicts.
    pub conflicts: u32,
    pub quarantined: Vec<QuarantinedFileInfo>,
    pub known_macs: Vec<KnownMacInfo>,
    /// No recovery kit opens the current sync key.
    pub recovery_kit_missing: bool,
    /// Number of differences the override would show as conflicts, if the
    /// override is offered.
    pub override_preview: Option<u32>,
    pub root: Option<SyncRootInfo>,
    /// The vault syncs with no folder. The user chooses the folder again.
    pub needs_folder: bool,
}

impl From<SyncReport> for SyncReportInfo {
    fn from(report: SyncReport) -> Self {
        let needs_folder = report.needs_folder();
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        Self {
            disable_in_progress: matches!(
                report.case,
                SyncLoad::DisableInProgress | SyncLoad::Leaving
            ),
            status: report.status.map(SyncStatusInfo::from),
            conflicts: count(report.conflicts),
            quarantined: report
                .quarantined
                .into_iter()
                .map(QuarantinedFileInfo::from)
                .collect(),
            known_macs: report
                .known_macs
                .into_iter()
                .map(KnownMacInfo::from)
                .collect(),
            recovery_kit_missing: report.recovery_kit_missing,
            override_preview: report.override_preview.map(count),
            root: report.root.as_ref().map(SyncRootInfo::from),
            needs_folder,
        }
    }
}

/// Start of a sync setup. Mirrors the core `SetupStart`.
#[derive(uniffi::Enum)]
pub enum SyncStartInfo {
    /// The user saves the kit of `setup`, then the app calls
    /// `sync_confirm`.
    Kit { setup: Arc<SyncSetupHandle> },
    /// The synced folder already holds the vault. The app offers the join by
    /// pairing or with a recovery kit.
    Join { root: SyncRootInfo },
}

/// Sync setup of one vault, from its kit until the confirmation. Holds the
/// sync key in Rust memory. Dropping the handle writes nothing.
#[derive(uniffi::Object)]
pub struct SyncSetupHandle {
    setup: SyncSetup,
    vault_key: String,
}

#[uniffi::export]
impl SyncSetupHandle {
    /// Kit text to save and print. Holds the age identity of the kit.
    pub fn kit_text(&self) -> String {
        self.setup.kit().text().to_string()
    }

    /// Key of the vault the setup is for.
    pub fn vault_key(&self) -> String {
        self.vault_key.clone()
    }
}

/// Outcome of a disable. Mirrors the core `Disabled`.
#[derive(uniffi::Enum)]
pub enum DisabledInfo {
    /// The final file reached the synced folder.
    Left,
    /// The final file waits until the synced folder can be reached.
    Waiting,
    /// No final file could be written. Other Macs see this Mac as inactive.
    Deleted,
    /// The own directory of a separate enable was deleted.
    DirectoryDeleted,
}

impl From<Disabled> for DisabledInfo {
    fn from(disabled: Disabled) -> Self {
        match disabled {
            Disabled::Left => Self::Left,
            Disabled::Waiting => Self::Waiting,
            Disabled::Deleted => Self::Deleted,
            Disabled::DirectoryDeleted => Self::DirectoryDeleted,
        }
    }
}

/// Key state of this Mac. Mirrors the core `KeyState`.
#[derive(uniffi::Enum)]
pub enum KeyStateInfo {
    Normal,
    NoVaultFiles,
    /// The re-sign confirmation is offered.
    SigningKeyLost,
    /// The synced vaults can be imported by pairing or with a recovery kit.
    NewHardware,
    KeychainError {
        message: String,
    },
}

impl From<KeyState> for KeyStateInfo {
    fn from(state: KeyState) -> Self {
        match state {
            KeyState::Normal => Self::Normal,
            KeyState::NoVaultFiles => Self::NoVaultFiles,
            KeyState::SigningKeyLost => Self::SigningKeyLost,
            KeyState::NewHardware => Self::NewHardware,
            KeyState::KeychainError(message) => Self::KeychainError { message },
        }
    }
}

/// Synced vault of a local sync state, read without verifying it.
#[derive(uniffi::Record)]
pub struct SyncedVaultInfo {
    pub vault_id: String,
    pub replica_id: String,
}

impl From<SyncedVault> for SyncedVaultInfo {
    fn from(vault: SyncedVault) -> Self {
        Self {
            vault_id: ShortId::encode_uuid(vault.vault_id),
            replica_id: ShortId::encode_uuid(vault.replica_id.0),
        }
    }
}

/// Vault file moved to `unreadable/` on new hardware. It opens only on the
/// Mac that made it.
#[derive(uniffi::Record)]
pub struct MovedVaultInfo {
    pub vault_id: String,
    pub key: String,
    /// Unverified vault name.
    pub name: Option<String>,
    pub path: String,
    /// Directory of the move.
    pub dir: String,
}

impl From<MovedVault> for MovedVaultInfo {
    fn from(moved: MovedVault) -> Self {
        Self {
            vault_id: ShortId::encode_uuid(moved.vault_id),
            key: moved.key,
            name: moved.name,
            path: moved.path.display().to_string(),
            dir: moved.dir.display().to_string(),
        }
    }
}

/// Local sync state with no vault file. It can be rebuilt or disabled.
#[derive(uniffi::Record)]
pub struct MissingVaultInfo {
    pub vault_id: String,
    /// Path of the sync state file.
    pub path: String,
}

impl From<&MissingVault> for MissingVaultInfo {
    fn from(missing: &MissingVault) -> Self {
        Self {
            vault_id: ShortId::encode_uuid(missing.id),
            path: missing.path.display().to_string(),
        }
    }
}

/// Result of the re-sign after signing key loss.
#[derive(uniffi::Record)]
pub struct ResignedInfo {
    /// Number of vault files and retained versions signed again.
    pub signed: u32,
    /// Files left unchanged.
    pub skipped: Vec<String>,
}

impl From<Resigned> for ResignedInfo {
    fn from(resigned: Resigned) -> Self {
        Self {
            signed: u32::try_from(resigned.signed).unwrap_or(u32::MAX),
            skipped: resigned
                .skipped
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
        }
    }
}

/// Mac whose files a kit import still waits for.
#[derive(uniffi::Record)]
pub struct WaitingMacInfo {
    pub replica_id: String,
    /// `None` is shown as "another Mac".
    pub name: Option<String>,
}

/// Result of a kit check. Mirrors the core `RecoveryCheck`, with no key.
#[derive(uniffi::Enum)]
pub enum RecoveryCheckInfo {
    /// The kit opens the key, and the import can run.
    Recovered,
    /// Files of these Macs are downloading. Check again in 5 seconds.
    Waiting { macs: Vec<WaitingMacInfo> },
    /// A newer sync key exists. The kit is outdated.
    KitOutdated { kit: u32, highest: u32 },
    /// No file of the folder opens the key of the kit.
    NoKey,
}

impl RecoveryCheckInfo {
    /// Check of `kit` against the synced folder `root` of `store`.
    /// Returns the core check, which holds the key if recovered.
    fn check(
        store: &VaultCatalog,
        kit: &RecoveryKit,
        root: &TransportRoot,
    ) -> Result<RecoveryCheck, FfiError> {
        let transport = SyncSetup::transport(store.files(), root)?;
        Ok(RecoveryImport::check(kit, &*transport)?)
    }
}

impl From<RecoveryCheck> for RecoveryCheckInfo {
    fn from(check: RecoveryCheck) -> Self {
        match check {
            RecoveryCheck::Recovered(_) => Self::Recovered,
            RecoveryCheck::Waiting(waiting) => Self::Waiting {
                macs: waiting
                    .into_iter()
                    .map(|mac| WaitingMacInfo {
                        replica_id: ShortId::encode_uuid(mac.replica.0),
                        name: mac.name,
                    })
                    .collect(),
            },
            RecoveryCheck::KitOutdated { kit, highest } => Self::KitOutdated {
                kit: kit.0,
                highest: highest.0,
            },
            RecoveryCheck::NoKey => Self::NoKey,
        }
    }
}

/// Result of a kit import or a join with a kit.
#[derive(uniffi::Enum)]
pub enum RecoveryImportInfo {
    /// The key was joined into the vault `vault_key`. `deduplicated` holds
    /// the ids of the items whose later duplicate websites were removed.
    Imported {
        vault_key: String,
        deduplicated: Vec<String>,
    },
    /// The kit check did not recover the key. Nothing was written.
    NotImported { check: RecoveryCheckInfo },
}

impl RecoveryImportInfo {
    /// Check `kit` against `root` again, and join the recovered key into
    /// `into` as the Mac named `name`. The join reads
    /// `vault-encryption-key` on the shared context
    /// (`VaultCatalog::import_recovered`). The manager holds the saved copy,
    /// and the sync manager finds the vault.
    fn import(
        manager: &Mutex<VaultsManager>,
        kit: &RecoveryKit,
        root: &TransportRoot,
        name: &str,
        into: JoinInto,
    ) -> Result<Self, FfiError> {
        let store = VaultsManager::lock(manager).store().clone();
        let key = match RecoveryCheckInfo::check(&store, kit, root)? {
            RecoveryCheck::Recovered(key) => key,
            other => {
                return Ok(Self::NotImported {
                    check: other.into(),
                });
            },
        };
        let committed =
            store.import_recovered(key, root, name, into, AuthContext::SharedThreadLocal)?;
        let vault_key = committed.vault.key.clone();
        let deduplicated = VaultsManager::lock(manager).install(committed);
        AxoPass::refresh_sync();
        Ok(Self::Imported {
            vault_key,
            deduplicated: item_ids(deduplicated),
        })
    }
}

/// Vault of this Mac that a pairing request can be granted for.
#[derive(uniffi::Record)]
pub struct PairingVaultInfo {
    pub vault_id: String,
    pub vault_key: String,
    pub name: Option<String>,
}

/// Outcome of the grant of one vault. Mirrors the core `GrantOutcome`.
#[derive(uniffi::Enum)]
pub enum GrantOutcomeInfo {
    Granted,
    /// The new Mac is known in the vault with other keys. Nothing was
    /// written.
    Conflict,
    /// The vault does not sync. Nothing was written.
    NotTrusted {
        reason: String,
    },
    Failed {
        message: String,
    },
}

impl From<GrantOutcome> for GrantOutcomeInfo {
    fn from(outcome: GrantOutcome) -> Self {
        match outcome {
            GrantOutcome::Granted(_) => Self::Granted,
            GrantOutcome::Conflict => Self::Conflict,
            GrantOutcome::NotTrusted(reason) => Self::NotTrusted { reason },
            GrantOutcome::Failed(e) => Self::Failed {
                message: e.to_string(),
            },
        }
    }
}

/// Grant outcome of one picked vault.
#[derive(uniffi::Record)]
pub struct PairingGrantInfo {
    pub vault_id: String,
    pub outcome: GrantOutcomeInfo,
}

/// Count of the pairings started by this process. A [`PairingHandle`]
/// finishes the pairing only while it is the newest one.
static PAIRING_RUNS: AtomicU64 = AtomicU64::new(0);

/// Pairing of this Mac as the new Mac. The pairing and
/// `vault-encryption-key` are held by the sync manager, which reports each
/// vault through the delegate. The handle holds the shown code.
#[derive(uniffi::Object)]
pub struct PairingHandle {
    code: SecretString,
    vault_ids: Vec<String>,
    run: u64,
}

#[uniffi::export]
impl PairingHandle {
    /// Code to type on the unlocked Mac, as `XXXX-XXXX-XXXX-XXXX`.
    pub fn code(&self) -> String {
        self.code.expose_secret().to_string()
    }

    /// Vaults of the request.
    pub fn vault_ids(&self) -> Vec<String> {
        self.vault_ids.clone()
    }

    /// Delete the request and forget the code. Import waits of vaults whose
    /// key arrived continue. Does nothing if a later pairing started.
    pub fn finish(&self) -> Result<(), FfiError> {
        if PAIRING_RUNS.load(Ordering::SeqCst) == self.run {
            AxoPass::sync_manager()?.finish_pairing();
        }
        Ok(())
    }
}

/// Short ids of `ids`.
fn item_ids(ids: Vec<ItemId>) -> Vec<String> {
    ids.into_iter().map(ShortId::encode_uuid).collect()
}

impl AxoPass {
    /// Run `f` on a blocking thread.
    async fn run_blocking<R: Send + 'static>(
        f: impl FnOnce() -> Result<R, FfiError> + Send + 'static,
    ) -> Result<R, FfiError> {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Target of vault `vault_key`, loaded from its file.
    fn target_of(store: &VaultCatalog, vault_key: &str) -> Result<Target, FfiError> {
        Ok(Target::of(&store.load(vault_key)?))
    }

    /// Target and vault name of the listed vault with id `vault_id`, if the
    /// manager lists one.
    fn listed(manager: &Mutex<VaultsManager>, vault_id: Uuid) -> Option<(Target, Option<String>)> {
        VaultsManager::lock(manager)
            .iter_vaults()
            .find(|(_, vh)| vh.peek_vault_id().is_ok_and(|id| id == vault_id))
            .map(|(_, vh)| (Target::of(vh), vh.vault_name().map(str::to_string)))
    }

    /// Pairing request listed under `root` whose MAC verifies under `code`.
    /// `None` if the code is malformed or matches no request.
    fn match_pairing(
        store: &VaultCatalog,
        root: &TransportRoot,
        code: &str,
    ) -> Result<Option<(PairingRequest, PairingCode)>, FfiError> {
        let Some(code) = PairingCode::parse(code) else {
            return Ok(None);
        };
        let transport = SyncSetup::transport(store.files(), root)?;
        Ok(PairingPrompt::match_code(&*transport, &code)?.map(|request| (request, code)))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Start the sync setup of vault `vault_key` with the synced folder
    /// `root`, as the Mac named `name`. Writes nothing. Gives the kit, or
    /// the join offer if the folder already holds the vault.
    pub async fn sync_prepare(
        &self,
        vault_key: String,
        root: SyncRootInfo,
        name: String,
    ) -> Result<SyncStartInfo, FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || {
            let target = Self::target_of(&store, &vault_key)?;
            Ok(
                match SyncSetup::prepare(store.files(), &target, root.into(), &name)? {
                    SetupStart::Join(root) => SyncStartInfo::Join {
                        root: (&root).into(),
                    },
                    SetupStart::Kit(setup) => SyncStartInfo::Kit {
                        setup: Arc::new(SyncSetupHandle { setup, vault_key }),
                    },
                },
            )
        })
        .await
    }

    /// Enable sync with `setup`, after the user confirmed that the kit is
    /// saved. Needs the app unlocked. Returns the ids of the items whose
    /// later duplicate websites were removed, for a notice. A setup that
    /// failed can be confirmed again.
    pub async fn sync_confirm(&self, setup: Arc<SyncSetupHandle>) -> Result<Vec<String>, FfiError> {
        let manager = Arc::clone(&self.manager);
        let ids = Self::run_blocking(move || {
            Ok(VaultsManager::transact(
                &manager,
                &setup.vault_key,
                |store, target| setup.setup.confirm(store.files(), target, Unlock::App),
            )?)
        })
        .await?;
        Self::refresh_sync();
        Ok(item_ids(ids))
    }

    /// Join vault `vault_key` to the synced folder `root` with the key of
    /// the recovery kit `kit_text`, as the Mac named `name`. For the join
    /// offer and the re-link. The kit is checked again first. Nothing is
    /// written unless the key is recovered.
    pub async fn sync_join_with_kit(
        &self,
        vault_key: String,
        root: SyncRootInfo,
        kit_text: String,
        name: String,
    ) -> Result<RecoveryImportInfo, FfiError> {
        let kit = RecoveryKit::parse(&kit_text)?;
        let manager = Arc::clone(&self.manager);
        Self::run_blocking(move || {
            let store = VaultsManager::lock(&manager).store().clone();
            let vh = store.load(&vault_key)?;
            let target = Target::of(&vh);
            if kit.vault_id != vh.peek_vault_id()? {
                return Err(FfiError::InvalidInput(
                    "the recovery kit is for another vault".into(),
                ));
            }
            RecoveryImportInfo::import(
                &manager,
                &kit,
                &root.into(),
                &name,
                JoinInto::Existing(target),
            )
        })
        .await
    }

    /// Turn off sync of vault `vault_key` on this Mac. Needs the app
    /// unlocked.
    pub async fn sync_disable(&self, vault_key: String) -> Result<DisabledInfo, FfiError> {
        let manager = Arc::clone(&self.manager);
        let disabled =
            Self::run_blocking(move || Ok(VaultsManager::disable_sync(&manager, &vault_key)?))
                .await?;
        Self::refresh_sync();
        Ok(disabled.into())
    }

    /// Sync report of vault `vault_key`. Writes nothing. Needs the app
    /// unlocked.
    pub async fn sync_report(&self, vault_key: String) -> Result<SyncReportInfo, FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || Ok(store.sync_report(&vault_key, Unlock::App)?.into())).await
    }

    /// Number of differences the override of vault `vault_key` would show as
    /// conflicts. Writes nothing. Needs the app unlocked.
    pub async fn sync_override_preview(&self, vault_key: String) -> Result<u32, FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || {
            let target = Self::target_of(&store, &vault_key)?;
            let count = SyncOverride::new(store.files(), &target).preview(Unlock::App)?;
            Ok(u32::try_from(count).unwrap_or(u32::MAX))
        })
        .await
    }

    /// Resume the sync of vault `vault_key` stopped by drift, and show the
    /// differences as conflicts. Needs the app unlocked.
    pub async fn sync_override_confirm(&self, vault_key: String) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        Self::run_blocking(move || {
            Ok(VaultsManager::transact(
                &manager,
                &vault_key,
                |store, target| SyncOverride::new(store.files(), target).confirm(Unlock::App),
            )?)
        })
        .await
    }

    /// Set the synced folder of vault `vault_key`, chosen again. The folder
    /// must hold the vault. Reads no key.
    pub async fn sync_set_root(
        &self,
        vault_key: String,
        root: SyncRootInfo,
    ) -> Result<(), FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || Ok(store.set_sync_root(&vault_key, &root.into())?)).await?;
        Self::refresh_sync();
        Ok(())
    }

    /// Test the S3 bucket of `settings`. Writes, lists, reads, and deletes a
    /// probe object. Saves nothing.
    pub async fn s3_test(&self, settings: S3SettingsInput) -> Result<S3TestInfo, FfiError> {
        Self::run_blocking(move || {
            let report = test_connection(&settings.config()?)?;
            Ok(S3TestInfo {
                list_attempts: report.list_attempts,
            })
        })
        .await
    }

    /// Save `settings` as the S3 location `name`, replacing an earlier one.
    /// Does not test the connection. Fails if the platform has no credential
    /// store.
    pub async fn s3_save(&self, name: String, settings: S3SettingsInput) -> Result<(), FfiError> {
        Self::run_blocking(move || {
            let config = settings.config()?;
            let store = default_credential_store().ok_or_else(|| {
                FfiError::Internal("this platform has no S3 credential store".into())
            })?;
            Ok(store.save(&name, &config)?)
        })
        .await
    }

    /// Saved settings of the S3 location `name`, without the secret. `None`
    /// if none is saved.
    pub async fn s3_load(&self, name: String) -> Result<Option<S3SettingsInfo>, FfiError> {
        Self::run_blocking(move || {
            let Some(store) = default_credential_store() else {
                return Ok(None);
            };
            Ok(store.load(&name)?.map(|config| S3SettingsInfo {
                endpoint: config.endpoint.to_string(),
                region: config.region,
                bucket: config.bucket,
                prefix: config.prefix,
                access_key_id: config.access_key_id,
            }))
        })
        .await
    }

    /// Start pairing this Mac as the new Mac with the synced folder `root`,
    /// as the Mac named `name`. Reads `vault-encryption-key` once on the
    /// shared context, and creates the keys if missing. On new hardware
    /// every vault file moves to `unreadable/` first. The sync manager
    /// imports each paired vault and reports it through the delegate. A
    /// pairing already running is finished.
    pub async fn pairing_start(
        &self,
        root: SyncRootInfo,
        name: String,
    ) -> Result<Arc<PairingHandle>, FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || {
            let root: TransportRoot = root.into();
            let sync = Self::sync_manager()?;
            let (pending, key) =
                store.start_pairing(&root, &name, AuthContext::SharedThreadLocal)?;
            let import = store.pairing_import(&pending, &root, &name);
            let transport = SyncSetup::transport(store.files(), &root)?;
            let handle = PairingHandle {
                code: SecretString::from(pending.code().shown().to_string()),
                vault_ids: pending
                    .request()
                    .replicas
                    .keys()
                    .copied()
                    .map(ShortId::encode_uuid)
                    .collect(),
                run: PAIRING_RUNS.fetch_add(1, Ordering::SeqCst) + 1,
            };
            sync.pair(pending, transport, Box::new(key), Some(import));
            Ok(Arc::new(handle))
        })
        .await
    }

    /// Computer name of the pairing request under `root` that `code`
    /// matches. `None` if no request matches, and no name is shown.
    pub async fn pairing_match_code(
        &self,
        root: SyncRootInfo,
        code: String,
    ) -> Result<Option<String>, FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || {
            let matched = Self::match_pairing(&store, &root.into(), &code)?;
            Ok(matched.map(|(request, _)| request.name))
        })
        .await
    }

    /// Synced vaults of this Mac that the request matched by `code` can be
    /// granted for. Empty if no request matches.
    pub async fn pairing_vaults(
        &self,
        root: SyncRootInfo,
        code: String,
    ) -> Result<Vec<PairingVaultInfo>, FfiError> {
        let store = self.store()?;
        let manager = Arc::clone(&self.manager);
        Self::run_blocking(move || {
            let root: TransportRoot = root.into();
            let Some((request, _)) = Self::match_pairing(&store, &root, &code)? else {
                return Ok(Vec::new());
            };
            Ok(PairingPrompt::vaults(store.files().root(), &root, &request)
                .into_iter()
                .filter_map(|vault_id| {
                    let (target, name) = Self::listed(&manager, vault_id)?;
                    Some(PairingVaultInfo {
                        vault_id: ShortId::encode_uuid(vault_id),
                        vault_key: target.key,
                        name,
                    })
                })
                .collect())
        })
        .await
    }

    /// Add the new Mac of the request matched by `code` to the vaults
    /// `vault_ids`, one transaction each. Needs the app unlocked. Fails if
    /// no request matches.
    pub async fn pairing_grant(
        &self,
        root: SyncRootInfo,
        code: String,
        vault_ids: Vec<String>,
    ) -> Result<Vec<PairingGrantInfo>, FfiError> {
        let store = self.store()?;
        let manager = Arc::clone(&self.manager);
        Self::run_blocking(move || {
            let root: TransportRoot = root.into();
            let (request, code) = Self::match_pairing(&store, &root, &code)?.ok_or_else(|| {
                FfiError::InvalidInput("the code matches no pairing request".into())
            })?;
            let picks = vault_ids
                .iter()
                .map(|id| {
                    let vault_id = parse_id(id)?;
                    let (target, _) = Self::listed(&manager, vault_id)
                        .ok_or_else(|| FfiError::NotFound(format!("Vault {id}")))?;
                    Ok((vault_id, target))
                })
                .collect::<Result<Vec<_>, FfiError>>()?;
            Ok(store
                .files()
                .grant_pairings(&picks, |_| Unlock::App, &request, &code, &root)
                .into_iter()
                .map(|(vault_id, outcome)| PairingGrantInfo {
                    vault_id: ShortId::encode_uuid(vault_id),
                    outcome: outcome.into(),
                })
                .collect())
        })
        .await
    }

    /// Dismiss the current pairing requests under `root`. Only a request
    /// with a new id prompts again. The app clears its count.
    pub async fn pairing_dismiss(&self, root: SyncRootInfo) -> Result<(), FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || {
            let root: TransportRoot = root.into();
            let transport = SyncSetup::transport(store.files(), &root)?;
            Ok(PairingPrompt::dismiss(
                &*transport,
                &root,
                store.files().root(),
            )?)
        })
        .await
    }

    /// Check the recovery kit `kit_text` against the synced folder `root`.
    /// Writes nothing other than download requests. The app checks again
    /// every 5 seconds while it waits.
    pub async fn recovery_check(
        &self,
        root: SyncRootInfo,
        kit_text: String,
    ) -> Result<RecoveryCheckInfo, FfiError> {
        let kit = RecoveryKit::parse(&kit_text)?;
        let store = self.store()?;
        Self::run_blocking(move || Ok(RecoveryCheckInfo::check(&store, &kit, &root.into())?.into()))
            .await
    }

    /// Import the vault of the recovery kit `kit_text` from the synced
    /// folder `root`, as the Mac named `name`. A vault of this Mac with the
    /// vault id is joined, and otherwise a new vault is built. The kit is
    /// checked again first, and nothing is written unless the key is
    /// recovered. Creates the keys if missing. On new hardware every vault
    /// file moves to `unreadable/` first.
    pub async fn recovery_import(
        &self,
        root: SyncRootInfo,
        kit_text: String,
        name: String,
    ) -> Result<RecoveryImportInfo, FfiError> {
        let kit = RecoveryKit::parse(&kit_text)?;
        let manager = Arc::clone(&self.manager);
        Self::run_blocking(move || {
            let into = match Self::listed(&manager, kit.vault_id) {
                Some((target, _)) => JoinInto::Existing(target),
                None => JoinInto::New,
            };
            RecoveryImportInfo::import(&manager, &kit, &root.into(), &name, into)
        })
        .await
    }

    /// New recovery kit text for the current sync key of vault `vault_key`.
    /// Writes nothing. The app calls `recovery_kit_confirm` after the user
    /// saves it. Needs the app unlocked.
    pub async fn recovery_kit_create(&self, vault_key: String) -> Result<String, FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || {
            Ok(store
                .create_kit(&vault_key, Unlock::App)?
                .text()
                .to_string())
        })
        .await
    }

    /// Add the recipient of the kit `kit_text` to vault `vault_key`, after
    /// the user confirmed that the kit is saved. Needs the app unlocked.
    pub async fn recovery_kit_confirm(
        &self,
        vault_key: String,
        kit_text: String,
    ) -> Result<(), FfiError> {
        let kit = RecoveryKit::parse(&kit_text)?;
        let manager = Arc::clone(&self.manager);
        Self::run_blocking(move || {
            Ok(VaultsManager::transact(
                &manager,
                &vault_key,
                |store, target| kit.confirm_saved(store.files(), target, Unlock::App),
            )?)
        })
        .await
    }

    /// Key state of this Mac, probed without a prompt.
    pub async fn key_state(&self) -> Result<KeyStateInfo, FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || Ok(store.key_state().into())).await
    }

    /// Synced vaults of the local sync states, read without verifying them,
    /// for the new hardware notice.
    pub async fn new_hardware_synced_vaults(&self) -> Result<Vec<SyncedVaultInfo>, FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || {
            Ok(store
                .unverified_synced_vaults()
                .into_iter()
                .map(SyncedVaultInfo::from)
                .collect())
        })
        .await
    }

    /// Vault files moved to `unreadable/` on new hardware.
    pub async fn moved_vaults(&self) -> Result<Vec<MovedVaultInfo>, FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || {
            Ok(store
                .moved_vaults()
                .into_iter()
                .map(MovedVaultInfo::from)
                .collect())
        })
        .await
    }

    /// Re-sign every vault file and retained version after the signing key
    /// was lost, after the user confirmed. Creates `device-signing-key`.
    pub async fn resign(&self) -> Result<ResignedInfo, FfiError> {
        let store = self.store()?;
        Self::run_blocking(move || Ok(store.resign()?.into())).await
    }

    /// Local sync states with no vault file, found when this object was
    /// created and not rebuilt or disabled since.
    pub fn list_missing_vaults(&self) -> Result<Vec<MissingVaultInfo>, FfiError> {
        let manager = self.manager.lock().map_err(|_| FfiError::Poisoned)?;
        Ok(manager
            .missing()
            .iter()
            .map(MissingVaultInfo::from)
            .collect())
    }

    /// Rebuild the missing vault `vault_id` from its sync state. Needs the
    /// app unlocked. Returns the key of the rebuilt vault.
    pub async fn rebuild_missing_vault(&self, vault_id: String) -> Result<String, FfiError> {
        let id = parse_id(&vault_id)?;
        let manager = Arc::clone(&self.manager);
        let key =
            Self::run_blocking(move || Ok(VaultsManager::rebuild_vault(&manager, id)?)).await?;
        Self::refresh_sync();
        Ok(key)
    }

    /// Turn off sync of the missing vault `vault_id`. Needs the app
    /// unlocked.
    pub async fn disable_missing_vault(&self, vault_id: String) -> Result<DisabledInfo, FfiError> {
        let id = parse_id(&vault_id)?;
        let manager = Arc::clone(&self.manager);
        let disabled =
            Self::run_blocking(move || Ok(VaultsManager::disable_missing_vault(&manager, id)?))
                .await?;
        Self::refresh_sync();
        Ok(disabled.into())
    }
}
