//! Sync setup of one vault ("Enable sync").
//!
//! The setup runs in two phases (D4). [`SyncSetup::prepare`] checks the vault
//! and the synced folder, then generates the sync key, the replica id, and
//! the recovery kit in memory. It writes nothing. [`SyncSetup::confirm`] runs
//! after the user confirms that the kit is saved. It writes `meta.json`, then
//! the first sync state, the vault, and `key.json` in one transaction under
//! the vault locks (`VaultWriter::enable_sync`). A dropped setup writes
//! nothing.
//!
//! A synced folder holds a vault if the vault directory has a `meta.json`,
//! local or not. A directory with no `meta.json`, such as one with only a
//! conflict copy of it, holds no vault. A folder that holds the vault is
//! offered for the join in place of the kit (`sync/join_sync.rs`).

use std::path::Path;
use std::sync::Arc;

use uuid::Uuid;

use super::crdt::ReplicaId;
use super::keys::{SyncKey, SyncKeyring};
use super::load::SyncLoad;
use super::local_state::{LocalStateError, LocalSyncState};
use super::meta::MetaFile;
use super::model::{ItemId, KeyId};
use super::recovery::RecoveryKit;
use super::transport::{ReadResult, SyncTransport, TransportRoot};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VerifiedVault};
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};

/// Key id of the sync key of a setup.
pub(crate) const FIRST_KEY_ID: KeyId = KeyId(1);

/// Start of a sync setup.
#[derive(Debug)]
pub enum SetupStart {
    /// The synced folder already holds the vault. The UI offers the join.
    Join(TransportRoot),
    /// Setup whose kit the user saves before it is confirmed.
    Kit(SyncSetup),
}

/// Sync setup of one vault, from its kit until the confirmation. Holds the
/// sync key in memory.
#[derive(Debug)]
pub struct SyncSetup {
    vault_id: Uuid,
    replica_id: ReplicaId,
    key: SyncKey,
    kit: RecoveryKit,
    root: TransportRoot,
    /// Display name of this Mac.
    name: String,
}

impl SyncSetup {
    /// Start the setup of the vault `target` with the synced folder `root`,
    /// as the Mac named `name`. Writes nothing.
    ///
    /// The vault is verified under the key of `writer`. A vault that syncs is
    /// refused ([`Self::check_not_synced`]). A folder that holds the vault
    /// gives [`SetupStart::Join`]. Otherwise the sync key, the replica id,
    /// and the kit are generated. Fails if the folder cannot be reached, or
    /// if its `meta.json` of the vault fails to parse.
    pub fn prepare(
        writer: &VaultWriter,
        target: &Target,
        root: TransportRoot,
        name: &str,
    ) -> Result<SetupStart, Error> {
        let signer = &**writer.signer();
        let vault = EncryptedVault::load(&target.path, signer)?;
        Self::check_not_synced(writer.root(), &vault, signer)?;
        let vault_id = vault.id;
        let transport = Self::transport(writer, &root)?;
        if Self::folder_holds(&*transport, vault_id)? {
            log::info!("Synced folder {root} holds vault {vault_id}, offering the join");
            return Ok(SetupStart::Join(root));
        }
        let key = SyncKey::generate();
        let kit = RecoveryKit::create(vault_id, FIRST_KEY_ID, &key);
        Ok(SetupStart::Kit(Self {
            vault_id,
            replica_id: ReplicaId::generate(),
            key,
            kit,
            root,
            name: name.to_string(),
        }))
    }

    /// Kit to show the user before the confirmation.
    pub fn kit(&self) -> &RecoveryKit {
        &self.kit
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    /// Synced folder of the setup.
    pub fn root(&self) -> &TransportRoot {
        &self.root
    }

    pub(crate) fn replica_id(&self) -> ReplicaId {
        self.replica_id
    }

    pub(crate) fn key(&self) -> &SyncKey {
        &self.key
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Enable sync of the vault `target`, after the user confirms that the
    /// kit is saved (`VaultWriter::enable_sync`). Returns the ids of the
    /// items whose later duplicate websites were removed, for a notice. A
    /// setup that failed can be confirmed again with the same kit. The caller
    /// then calls `SyncManager::refresh`, so the vault is watched.
    pub fn confirm(
        &self,
        writer: &VaultWriter,
        target: &Target,
        unlock: Unlock<'_>,
    ) -> Result<Committed<Vec<ItemId>>, Error> {
        writer.enable_sync(target, unlock, self)
    }

    /// Refuse the verified vault `vault` if it has a local sync state under
    /// the app data directory `root`, or holds a replica id. A `leaving` sync
    /// state fails with `SyncDisableInProgress` (D13), and any other sync
    /// state, valid or not, with `SyncAlreadyEnabled`.
    pub(crate) fn check_not_synced(
        root: &Path,
        vault: &VerifiedVault,
        signer: &dyn VaultSigner,
    ) -> Result<(), Error> {
        match LocalSyncState::load(root, vault.id, signer) {
            Err(LocalStateError::Missing) => {},
            Err(LocalStateError::Read(e)) => return Err(Error::SyncStateReadError(e)),
            Err(LocalStateError::SigningKey(e)) => return Err(e),
            Ok(local) if local.leaving => return Err(Error::SyncDisableInProgress),
            _ => return Err(Error::SyncAlreadyEnabled),
        }
        if vault.replica_id.is_some() {
            return Err(Error::SyncAlreadyEnabled);
        }
        Ok(())
    }

    /// Refuse a join of vault `vault_id` while its local sync state under the
    /// app data directory `root` syncs. `vault` is the verified vault file of
    /// a join into an existing vault, and `None` for a new vault. `keyring`
    /// opens the sync state of `vault` for the trust check.
    ///
    /// A `leaving` sync state fails with `SyncDisableInProgress` (D13), and
    /// one of a newer format with `SyncStateVersionSkew`. For an existing
    /// vault, a trusted sync state fails with `SyncAlreadyEnabled`, as does a
    /// sync state under a key id that `keyring` lacks, or of another vault or
    /// replica. A sync state that is missing or fails its signature is the
    /// re-link case, and the join replaces it. So is a sync state left by a
    /// disable of a vault that holds no replica id. For a new vault, a sync
    /// state that verifies is one of a vault file that is missing, and fails
    /// with `SyncAlreadyEnabled`.
    pub(crate) fn check_joinable(
        root: &Path,
        vault_id: Uuid,
        vault: Option<&VerifiedVault>,
        keyring: Option<&SyncKeyring>,
        signer: &dyn VaultSigner,
    ) -> Result<(), Error> {
        let local = match LocalSyncState::load(root, vault_id, signer) {
            Err(LocalStateError::Read(e)) => return Err(Error::SyncStateReadError(e)),
            Err(LocalStateError::SigningKey(e)) => return Err(e),
            Err(LocalStateError::VersionSkew(message)) => {
                return Err(Error::SyncStateVersionSkew(message));
            },
            Ok(local) if local.leaving => return Err(Error::SyncDisableInProgress),
            local => local,
        };
        let Some(vault) = vault else {
            return match local {
                Ok(_) => Err(Error::SyncAlreadyEnabled),
                Err(_) => Ok(()),
            };
        };
        if vault.replica_id.is_none() {
            return Ok(());
        }
        match SyncLoad::classify_trusted(vault, local, keyring, signer)?.0 {
            SyncLoad::StateMissing | SyncLoad::SignatureFailed(_) => Ok(()),
            SyncLoad::VersionSkew(message) => Err(Error::SyncStateVersionSkew(message)),
            _ => Err(Error::SyncAlreadyEnabled),
        }
    }

    /// Check that the synced folder of `transport` holds vault `vault_id`,
    /// for a join. A missing `meta.json` fails with `SyncFolderLacksVault`,
    /// and one that fails to parse, such as one of a newer version or of
    /// another vault, with `SyncMetaFileError`. A `meta.json` that is not
    /// local yet is requested, and the check fails with `SyncTransportError`.
    /// The transport never reads a conflict copy of `meta.json`.
    pub(crate) fn check_folder(transport: &dyn SyncTransport, vault_id: Uuid) -> Result<(), Error> {
        match transport.read_meta(vault_id)? {
            ReadResult::Missing => Err(Error::SyncFolderLacksVault),
            ReadResult::Remote => {
                if let Err(e) = transport.request_download(vault_id) {
                    log::warn!("Failed to request the download of vault {vault_id}: {e}");
                }
                Err(Error::SyncTransportError(format!(
                    "meta.json of vault {vault_id} is not downloaded yet"
                )))
            },
            ReadResult::Local(bytes) => MetaFile::parse(&bytes, vault_id)
                .map(|_| ())
                .map_err(Error::SyncMetaFileError),
        }
    }

    /// Transport of the synced folder `root`. Fails if the folder cannot be
    /// reached.
    pub fn transport(
        writer: &VaultWriter,
        root: &TransportRoot,
    ) -> Result<Arc<dyn SyncTransport>, Error> {
        writer
            .transport_of(Some(root))?
            .ok_or_else(|| Error::SyncTransportError(format!("no transport for {root}")))
    }

    /// Whether the synced folder of `transport` holds vault `vault_id`. The
    /// transport never reads a conflict copy of `meta.json`. Fails if the
    /// folder cannot be read, or if a local `meta.json` fails to parse.
    pub(crate) fn folder_holds(
        transport: &dyn SyncTransport,
        vault_id: Uuid,
    ) -> Result<bool, Error> {
        match transport.read_meta(vault_id)? {
            ReadResult::Missing => Ok(false),
            ReadResult::Remote => Ok(true),
            ReadResult::Local(bytes) => {
                MetaFile::parse(&bytes, vault_id)
                    .map_err(|e| Error::SyncTransportError(e.to_string()))?;
                Ok(true)
            },
        }
    }
}
