//! Sync report of one vault, for the sync status in the UI ("Sync status is
//! visible").
//!
//! [`SyncReport::read`] reads the vault, its local sync state, and its
//! sidecar under the vault locks, and writes nothing. It builds no `SyncTxn`,
//! so no save can run. The trusted sync state is used only in the cases on
//! which a transaction builds its `SyncTxn` ([`SyncLoad::builds_txn`]). The
//! status of those cases is the status of the sync state and the sidecar as
//! the last transaction left them. Every other case of a synced vault gives
//! the status a transaction finds for it, and no conflicts, known Macs, or
//! names. A vault that is not synced, is being disabled, or has a sync state
//! of a newer format has no status.
//!
//! The file blobs of a trusted sync state are reported as waiting for upload,
//! as missing on this Mac, and as unreferenced in the synced folder. The
//! folder is listed once, and a listing failure gives no unreferenced count
//! and does not fail the report. A blob missing on this Mac does not pause
//! sync, since the file is fetched when it is read.
//!
//! A synced vault whose sidecar has no root has no folder to sync with, and
//! is shown as needing its folder chosen again, not as active (P28 of doc
//! 16, D18 of doc 18).

use std::collections::BTreeSet;

use uuid::Uuid;

use super::blobs;
use super::crdt::ReplicaId;
use super::keys::SyncKeyring;
use super::load::{SyncLoad, TrustedState};
use super::local_state::PinSource;
use super::model::{KeyId, PublicKey, ReplicaKeys, SyncState};
use super::recovery::RecoveryRecipients;
use super::repair::Repair;
use super::rotation::{RotationPrompt, Rotations};
use super::sidecar::{Notice, Sidecar};
use super::status::SyncStatus;
use super::transport::{SyncTransport, TransportRoot};
use super::view::{Entity, VaultView};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::FileHash;
use crate::secrets::vaults::files::store::BlobStore;
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::storage::txn::{LockedRead, Target, Unlock, VaultWriter};

/// Sync report of one vault.
#[derive(Debug, PartialEq)]
pub struct SyncReport {
    /// Case of the vault against its local sync state.
    pub case: SyncLoad,
    /// Sync status. `None` for a vault that is not synced, is being
    /// disabled, or whose sync state is from a newer format.
    pub status: Option<SyncStatus>,
    /// Number of Ask registers of the view with more than one value.
    pub conflicts: usize,
    /// Quarantined state files of the sidecar, in its order.
    pub quarantined: Vec<QuarantinedEntry>,
    /// Macs of the `replica_names` view, by replica id.
    pub known_macs: Vec<KnownMac>,
    /// Whether the `recovery` map holds no recipient of the current key, the
    /// degraded state (D18 of doc 16).
    pub recovery_kit_missing: bool,
    /// Saved recovery kits of the `recovery` map, oldest first. Empty unless
    /// the sync state is trusted.
    pub recovery_kits: Vec<RecoveryKitEntry>,
    /// Number of differences the user override would show as conflicts, if
    /// the override is offered.
    pub override_preview: Option<usize>,
    /// File blobs waiting for upload, missing on this Mac, and unreferenced
    /// in the folder. Zero or `None` unless the sync state is trusted.
    pub blobs: BlobStatus,
    /// Root of the synced folder in the sidecar. `None` for a synced vault
    /// whose sidecar has no root, and for a vault that is not synced.
    pub root: Option<TransportRoot>,
    /// Verified rotations from other Macs that wait for the answer of the
    /// user. Empty unless the sync state is trusted.
    pub rotations: Vec<RotationPrompt>,
    /// Changes from other Macs that the user has not dismissed, oldest
    /// first.
    pub notices: Vec<Notice>,
    /// Live entries shown with a suffixed key. Empty unless the sync state is
    /// trusted.
    pub suffixed_keys: Vec<Entity>,
}

/// File blobs of a synced vault in the sync report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobStatus {
    /// Blobs that the joined state references, that the local blob store
    /// holds, and that the folder does not list. The next transaction with a
    /// transport uploads them. Zero if the folder cannot be listed.
    pub uploads_pending: usize,
    /// Blobs that the vault references, including trash and history, and
    /// that the local blob store lacks. Each is fetched when its file is
    /// read. It does not pause sync.
    pub missing_locally: usize,
    /// Blobs in the folder that the joined state does not reference. `None`
    /// if the folder cannot be listed. They are never deleted.
    pub unreferenced: Option<UnreferencedBlobs>,
}

/// Blobs in the synced folder that no record of the joined state references.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnreferencedBlobs {
    pub count: usize,
    /// Total size of the blobs in bytes, as the folder reports it.
    pub bytes: u64,
}

impl BlobStatus {
    /// Status of `vault`, with the local blob store `store`, the joined sync
    /// state `state`, and the folder `transport`, if the vault has one.
    /// Decrypts every value of the vault. A listing failure is logged and
    /// gives no unreferenced count.
    fn of(
        vault_id: Uuid,
        vault: &Vault,
        store: &BlobStore,
        state: &SyncState,
        transport: Option<&dyn SyncTransport>,
    ) -> Result<Self, Error> {
        let local: BTreeSet<FileHash> = store.list()?.into_iter().collect();
        let missing_locally = vault.file_blobs()?.difference(&local).count();
        let mut status = Self {
            missing_locally,
            ..Self::default()
        };
        let Some(transport) = transport else {
            return Ok(status);
        };
        let listed = match transport.list_blob_sizes(vault_id) {
            Ok(listed) => listed,
            Err(e) => {
                log::warn!("Failed to list the file blobs of vault {vault_id}: {e}");
                return Ok(status);
            },
        };
        let referenced = blobs::referenced(state);
        let is_listed = |blob: &FileHash| listed.iter().any(|(name, _)| name == blob);
        status.uploads_pending = referenced
            .iter()
            .filter(|blob| local.contains(blob) && !is_listed(blob))
            .count();
        let (count, bytes) = blobs::unreferenced(&listed, &referenced);
        status.unreferenced = Some(UnreferencedBlobs { count, bytes });
        Ok(status)
    }
}

/// Quarantined state file, with the display name of its Mac.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedEntry {
    pub replica: ReplicaId,
    /// Display name of the replica in the view. `None` if the view holds no
    /// name, or if the sync state is not trusted.
    pub mac_name: Option<String>,
    /// File name in the replica directory.
    pub name: String,
    pub reason: String,
}

/// Saved recovery kit, read from its register in the `recovery` map. The
/// label, key id, time, and writer are those of the newest value, by counter
/// and then by write id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryKitEntry {
    /// Age recipient of the kit, the key of the map.
    pub recipient: String,
    /// Key id the kit was made for.
    pub key_id: KeyId,
    /// Whether any value of the register holds the current key id and the
    /// fingerprint of the current key. The rule of
    /// [`RecoveryRecipients::current`], so a concurrent value cannot hide a
    /// kit that opens the current key.
    pub current: bool,
    pub label: Option<String>,
    /// Time of the write, in Unix seconds on the clock of the writer.
    pub written_at: i64,
    /// Display name of the replica that wrote the value. `None` if the state
    /// does not name it, as after a cleanup of that replica.
    pub added_by: Option<String>,
}

impl RecoveryKitEntry {
    /// Kits of the `recovery` map of `trusted`, oldest first, then by
    /// recipient. A writer is named through the `actors` of the state and the
    /// `replica_names` of `view`. A kit counts as current if `keyring` holds
    /// the current key and a value of its register matches it.
    fn of(trusted: &TrustedState, view: &VaultView, keyring: Option<&SyncKeyring>) -> Vec<Self> {
        let state = &trusted.state;
        let key_id = trusted.local.key_id;
        let fingerprint = keyring
            .and_then(|keyring| keyring.get(key_id))
            .map(|key| key.fingerprint());
        let mut entries: Vec<Self> = state
            .store
            .recovery
            .iter()
            .filter_map(|(recipient, register)| {
                let values = register.ordered();
                let (order, newest) = values.last()?;
                let current = fingerprint.is_some_and(|fingerprint| {
                    values.iter().any(|(_, v)| {
                        v.value.key_id == key_id && v.value.key_fingerprint == fingerprint.0
                    })
                });
                let added_by = state
                    .actors
                    .get(&order.write_id.actor)
                    .and_then(|actor| view.replica_names.get(&actor.replica))
                    .cloned();
                Some(Self {
                    recipient: recipient.clone(),
                    key_id: newest.value.key_id,
                    current,
                    label: newest.value.label.clone(),
                    written_at: newest.written_at,
                    added_by,
                })
            })
            .collect();
        entries.sort_by(|a, b| (a.written_at, &a.recipient).cmp(&(b.written_at, &b.recipient)));
        entries
    }
}

/// Mac that the sync state knows by display name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownMac {
    pub replica: ReplicaId,
    pub name: String,
    /// Whether this Mac is the replica of the sync state.
    pub this_mac: bool,
    /// Whether the Mac disabled sync, the shown value of its `left` register.
    pub left: bool,
    /// Newest `started_at` of the actors of the replica in the state, shown
    /// as its last active time (D17 of doc 18). The clock of that Mac.
    /// `None` if the state holds no actor of the replica.
    pub last_active: Option<i64>,
    /// Time that a state file of the Mac last changed the state of this Mac.
    /// The clock of this Mac. `None` for this Mac, and if no file of the Mac
    /// changed the state since this Mac recorded it.
    pub received_at: Option<i64>,
    /// How this Mac pinned the keys of the Mac. `None` for this Mac and for
    /// a Mac with no pin. Remove Mac preselects a Mac pinned at first use.
    pub pin: Option<PinSource>,
    /// Pinned signing key of the Mac, or the own signing key for this Mac.
    /// Remove Mac finds the Mac in each vault by it.
    pub signing: Option<PublicKey>,
    /// Whether a rotation removed the Mac.
    pub removed: bool,
    /// Whether the `replica_keys` register of the Mac holds more than one
    /// value, or a value other than the pinned keys. The pinned keys are
    /// used.
    pub keys_flagged: bool,
}

impl KnownMac {
    /// Whether Remove Mac preselects the Mac: its keys were pinned at first
    /// use, and it is not this Mac and not removed.
    pub fn preselected(&self) -> bool {
        self.pin == Some(PinSource::FirstUse) && !self.this_mac && !self.removed
    }
}

impl SyncReport {
    /// Report of the vault `target`, read under the vault locks of `writer`.
    /// Writes nothing. The keys are unwrapped with `unlock` before the locks,
    /// with no second unlock for a key id the keyring lacks, so that case is
    /// reported as `KeyMissing`. Fails as a transaction fails to load the
    /// vault, its sync state, or its sidecar.
    pub fn read(writer: &VaultWriter, target: &Target, unlock: Unlock<'_>) -> Result<Self, Error> {
        writer.read_locked(target, unlock, |read| Self::of(writer, read))
    }

    /// Whether the vault syncs with no folder, as its sidecar has no root.
    /// The UI shows it as needing its folder chosen again.
    pub fn needs_folder(&self) -> bool {
        self.case.builds_txn() && self.root.is_none()
    }

    /// Report of `read`, the vault file at `vault_path`, under the vault
    /// locks of `writer`.
    fn of(writer: &VaultWriter, read: LockedRead) -> Result<Self, Error> {
        let LockedRead {
            id,
            file_key,
            vault,
            case,
            trusted,
            keyring,
        } = read;
        let sidecar = match vault.replica_id {
            Some(_) => Sidecar::read(writer.root(), id)?,
            None => Sidecar::default(),
        };
        let trusted = trusted.filter(|_| case.builds_txn());
        let view = trusted
            .as_ref()
            .map(|trusted| VaultView::of(&trusted.state));
        let mac_name = |replica: &ReplicaId| {
            view.as_ref()
                .and_then(|view| view.replica_names.get(replica).cloned())
        };
        let quarantined = sidecar
            .quarantined
            .iter()
            .map(|file| QuarantinedEntry {
                replica: file.replica,
                mac_name: mac_name(&file.replica),
                name: file.name.clone(),
                reason: file.reason.clone(),
            })
            .collect();

        let mut report = Self {
            status: SyncStatus::of_case(&case),
            conflicts: 0,
            quarantined,
            known_macs: Vec::new(),
            recovery_kit_missing: false,
            recovery_kits: Vec::new(),
            override_preview: None,
            blobs: BlobStatus::default(),
            root: sidecar.transport.clone(),
            rotations: Vec::new(),
            notices: sidecar.notices.clone(),
            suffixed_keys: Vec::new(),
            case,
        };
        let (Some(trusted), Some(view)) = (&trusted, &view) else {
            return Ok(report);
        };
        let local = &trusted.local;
        report.status = Some(SyncStatus::of_trusted(
            local.stopped_build.as_deref(),
            local.override_build.as_deref(),
            sidecar.paused(),
        ));
        report.conflicts = view.conflicts().len();
        report.known_macs = Self::known_macs(trusted, view, &sidecar, writer.signer().as_ref());
        report.rotations = Rotations::prompts(local);
        report.suffixed_keys = view.suffixed_keys();
        report.recovery_kit_missing = keyring.as_ref().is_none_or(|keyring| {
            RecoveryRecipients::of_key(&trusted.state.store, local.key_id, keyring).is_empty()
        });
        report.recovery_kits = RecoveryKitEntry::of(trusted, view, keyring.as_ref());
        let vault = Vault::from_unlocked_key(&file_key, vault)?;
        let transport = writer
            .transport_of(sidecar.transport.as_ref())
            .inspect_err(|e| log::warn!("Failed to resolve the transport of vault {id}: {e}"))
            .ok()
            .flatten();
        report.blobs = BlobStatus::of(
            id,
            &vault,
            &writer.blob_store(id),
            &trusted.state.store,
            transport.as_deref(),
        )?;
        if let Some(trusted) = Repair::override_state(&report.case, Some(trusted)) {
            report.override_preview = match Repair::preview(trusted, &vault) {
                Ok(count) => Some(count),
                Err(e) => {
                    log::warn!("Vault {id} offers no override, its diff failed: {e}");
                    None
                },
            };
        }
        Ok(report)
    }

    /// Macs of the `replica_names` view `view` of `trusted`, with their
    /// `left` value, the newest start time of their actors, their receive
    /// time in `sidecar`, and their pin. `signer` gives the signing key of
    /// this Mac.
    fn known_macs(
        trusted: &TrustedState,
        view: &VaultView,
        sidecar: &Sidecar,
        signer: &dyn VaultSigner,
    ) -> Vec<KnownMac> {
        let local = &trusted.local;
        let store = &trusted.state.store;
        let own_signing = signer
            .verifying_key()
            .ok()
            .map(|key| PublicKey(key.to_encoded_point(false).as_bytes().to_vec()));
        view.replica_names
            .iter()
            .map(|(replica, name)| {
                let this_mac = *replica == local.replica_id;
                let pin = local.pinned_keys.get(replica);
                let values: Vec<&ReplicaKeys> = store
                    .replica_keys
                    .get(replica)
                    .map(|register| register.values().map(|(_, v)| &v.value).collect())
                    .unwrap_or_default();
                let keys_flagged = values.len() > 1
                    || pin.is_some_and(|pin| {
                        values.iter().any(|keys| {
                            keys.encryption != pin.encryption || keys.signing != pin.signing
                        })
                    });
                KnownMac {
                    replica: *replica,
                    name: name.clone(),
                    this_mac,
                    left: view.left.get(replica).copied().unwrap_or(false),
                    last_active: trusted
                        .state
                        .actors
                        .values()
                        .filter(|actor| actor.replica == *replica)
                        .map(|actor| actor.started_at)
                        .max(),
                    received_at: sidecar.received_at.get(replica).copied(),
                    pin: pin.map(|pin| pin.source),
                    signing: match pin {
                        Some(pin) => Some(pin.signing.clone()),
                        None if this_mac => own_signing.clone(),
                        None => None,
                    },
                    removed: store.removed.get(replica).is_some(),
                    keys_flagged,
                }
            })
            .collect()
    }

    /// Mac of this report whose signing key is `signing`, for Remove Mac in
    /// each vault. This Mac and removed Macs are not returned.
    pub fn mac_with_signing(&self, signing: &PublicKey) -> Option<&KnownMac> {
        self.known_macs
            .iter()
            .find(|mac| !mac.this_mac && !mac.removed && mac.signing.as_ref() == Some(signing))
    }
}
