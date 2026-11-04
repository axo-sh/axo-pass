//! Pairing grant on the unlocked Mac (Device pairing steps 6 and 7).
//!
//! The user picks the vaults of the matched request. The app unlocks once,
//! and each picked vault runs one transaction with `Unlock::App` on that
//! context (C32). The transaction loads and trusts the sync state, runs the
//! guard, and joins as any transaction does. Under the vault locks it then:
//!
//! 1. Refuses the vault if its sync state is not trusted, if sync does not run,
//!    if its sidecar root is not the root of the request, or if the request map
//!    lacks it. Nothing is written.
//! 2. Pins the new Mac's keys for its replica id of the vault with `pairing`
//!    (D14), before the first-use pins of the joins. A pin of that replica id
//!    with other keys, or a revoked pin, refuses the vault and writes nothing.
//!    It then wraps the key of `LocalSyncState::key_id` to the new Mac's
//!    encryption key and seals the wrapping with the pairing MAC. The wrap
//!    makes no keychain call.
//! 3. Saves the sync state, before the vault if the transaction saves the
//!    vault. A changed pin alone saves the header at `s`.
//! 4. Reads its own `key.json`, replaces any `Device` wrapping to the same
//!    replica id and key id with the new one, and writes it with `write_own`.
//!    The other wrappings are written back unchanged.
//! 5. Publishes the staged file and saves the sidecar, as any transaction does.
//!
//! A failed save in step 3 writes no wrapping. A failed write in step 4
//! leaves the saved pin, and a later grant of the same request finds it
//! `Unchanged` and writes the wrapping.

use uuid::Uuid;

use super::request::PairingRequest;
use super::{PairKey, PairingCode};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::pins::PairedPin;
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport, TransportRoot};
use crate::secrets::vaults::sync::txn::SyncTxn;
use crate::secrets::vaults::sync::wrapping::{DeviceWrapping, KeyFile, KeyFileError, Wrapping};

/// Result of the grant of one picked vault.
#[derive(Debug)]
pub enum GrantOutcome {
    /// Wrapping written, with the result of the pin.
    Granted(PairedPin),
    /// The replica id of the new Mac is pinned with other keys, or its pin
    /// is revoked (D14). Nothing was written.
    Conflict,
    /// The sync state is not trusted, or sync does not run: stopped by
    /// drift, paused by a failed diff or apply, or being disabled. Holds the
    /// reason. Nothing was written.
    NotTrusted(String),
    /// Failed with an error. If the wrapping write failed, the pin was
    /// saved.
    Failed(Error),
}

/// Grant of one pairing request in the transaction of one vault.
pub(crate) struct PairingGrant<'a> {
    request: &'a PairingRequest,
    key: PairKey,
    root: &'a TransportRoot,
    /// Result of the pin, set under the locks.
    pin: Option<PairedPin>,
    /// Sealed wrapping, built under the locks before the saves.
    wrapping: Option<DeviceWrapping>,
    /// Result of the `key.json` write, set after the saves.
    written: Option<Result<(), Error>>,
}

impl<'a> PairingGrant<'a> {
    /// Grant of `request`, matched with `code`, through the transport of
    /// `root`.
    fn new(request: &'a PairingRequest, code: &PairingCode, root: &'a TransportRoot) -> Self {
        Self {
            request,
            key: code.pair_key(),
            root,
            pin: None,
            wrapping: None,
            written: None,
        }
    }

    /// Replica id of the new Mac in vault `vault_id`. Fails if the request
    /// map lacks the vault.
    fn to_replica(&self, vault_id: Uuid) -> Result<ReplicaId, Error> {
        self.request
            .replicas
            .get(&vault_id)
            .copied()
            .ok_or_else(|| {
                Error::PairingVaultNotOffered(format!("request map lacks vault {vault_id}"))
            })
    }

    /// Refuse the vault before any join if its sync state is not trusted,
    /// in the case `case`, if its sidecar root is not the root of the
    /// request, or if the request map lacks it.
    pub(crate) fn check(&self, case: &SyncLoad, sync: Option<&SyncTxn>) -> Result<(), Error> {
        let Some(sync) = sync else {
            return Err(Error::PairingSyncNotTrusted(case.to_string()));
        };
        if sync.transport_root() != Some(self.root) {
            return Err(Error::PairingVaultNotOffered(format!(
                "sidecar root is not {}",
                self.root
            )));
        }
        self.to_replica(sync.vault_id()).map(|_| ())
    }

    /// Pin the keys of the new Mac and build the sealed wrapping, after the
    /// joins and the apply of the joined state and before the first-use
    /// pins. `transport` is the transport of the transaction and `signer`
    /// the signer of this Mac. Refuses the vault if sync does not run, if
    /// it has no transport, or if the pin is a `Conflict`. Nothing is saved
    /// yet.
    pub(crate) fn prepare(
        &mut self,
        sync: &mut SyncTxn,
        transport: Option<&dyn SyncTransport>,
        signer: &dyn VaultSigner,
    ) -> Result<(), Error> {
        if !sync.syncs() {
            return Err(Error::PairingSyncNotTrusted(
                "sync is stopped or paused".to_string(),
            ));
        }
        if sync.is_leaving() {
            return Err(Error::PairingSyncNotTrusted(
                "sync is being disabled".to_string(),
            ));
        }
        if transport.is_none() {
            return Err(Error::SyncTransportError(format!(
                "{} cannot be reached",
                self.root
            )));
        }
        let vault_id = sync.vault_id();
        let to_replica = self.to_replica(vault_id)?;
        let from = sync.own_keys(signer)?.ok_or_else(|| {
            Error::PairingSyncNotTrusted("own keys are not in the sync state".to_string())
        })?;
        let keys = self.request.keys();
        let pin = sync.pin_paired(to_replica, &keys);
        log::info!(
            "Vault {vault_id} pairing pin of replica {}: {pin:?}",
            to_replica.0
        );
        if pin == PairedPin::Conflict {
            return Err(Error::PairingPinConflict(to_replica.0.to_string()));
        }
        let (key_id, key) = sync.current_key().ok_or_else(|| {
            Error::PairingSyncNotTrusted("keyring lacks the key of the body".to_string())
        })?;
        let mut wrapping = DeviceWrapping::wrap(key_id, key, to_replica, &keys.encryption, &from)?;
        self.key
            .seal_wrapping(&mut wrapping, vault_id, sync.replica(), &keys);
        self.pin = Some(pin);
        self.wrapping = Some(wrapping);
        Ok(())
    }

    /// Write the wrapping into the own `key.json` of the vault of `sync`
    /// through `transport`, after the saves. The result is kept for the
    /// outcome.
    pub(crate) fn write(&mut self, sync: &SyncTxn, transport: &dyn SyncTransport) {
        let result = self.write_key_file(sync, transport);
        if let Err(e) = &result {
            let vault_id = sync.vault_id();
            log::warn!("Failed to write the pairing wrapping of vault {vault_id}: {e}");
        }
        self.written = Some(result);
    }

    /// Read the own `key.json`, replace any `Device` wrapping to the same
    /// replica id and key id with the sealed wrapping, and write it. A
    /// missing file, or one that fails to parse, is read as empty. A file
    /// that is `Remote` or of another version fails, so no wrapping of it is
    /// lost.
    fn write_key_file(
        &mut self,
        sync: &SyncTxn,
        transport: &dyn SyncTransport,
    ) -> Result<(), Error> {
        let wrapping = self.wrapping.take().ok_or_else(|| {
            Error::SyncStateEncodeError("pairing wrapping was not built".to_string())
        })?;
        let vault_id = sync.vault_id();
        let own = sync.replica();
        let mut file = match transport.read(vault_id, own, FileName::Key)? {
            ReadResult::Missing => KeyFile::default(),
            ReadResult::Remote => {
                return Err(Error::SyncTransportError(
                    "own key.json is not local".to_string(),
                ));
            },
            ReadResult::Local(bytes) => match KeyFile::parse(&bytes) {
                Ok(file) => file,
                Err(KeyFileError::VersionSkew(message)) => {
                    return Err(Error::SyncStateVersionSkew(message));
                },
                Err(e) => {
                    log::warn!("Own key.json of vault {vault_id} is read as empty: {e}");
                    KeyFile::default()
                },
            },
        };
        file.wrappings.retain(|existing| {
            !matches!(existing, Wrapping::Device(device)
                if device.to_replica == wrapping.to_replica && device.key_id == wrapping.key_id)
        });
        file.wrappings.push(Wrapping::Device(wrapping));
        transport.write_own(vault_id, own, FileName::Key, &file.to_bytes())
    }

    /// Outcome of the transaction `result`.
    fn outcome(self, result: Result<Committed<()>, Error>) -> GrantOutcome {
        match result {
            Ok(_) => match (self.written, self.pin) {
                (Some(Ok(())), Some(pin)) => GrantOutcome::Granted(pin),
                (Some(Err(e)), _) => GrantOutcome::Failed(e),
                _ => GrantOutcome::Failed(Error::SyncStateEncodeError(
                    "pairing wrapping was not written".to_string(),
                )),
            },
            Err(Error::PairingPinConflict(_)) => GrantOutcome::Conflict,
            Err(Error::PairingSyncNotTrusted(reason)) => GrantOutcome::NotTrusted(reason),
            Err(e) => GrantOutcome::Failed(e),
        }
    }
}

impl VaultWriter {
    /// Add the new Mac of `request` to the vault `target`, in one
    /// transaction unlocked with `unlock`. `code` is the code the request
    /// matched, and `root` the transport root the request was found under.
    /// See the module comment for the order of the steps.
    pub fn grant_pairing(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        request: &PairingRequest,
        code: &PairingCode,
        root: &TransportRoot,
    ) -> GrantOutcome {
        let mut grant = PairingGrant::new(request, code, root);
        let result = self.write_granting(target, unlock, &mut grant);
        let outcome = grant.outcome(result);
        log::info!(
            "Pairing request {} for vault {}: {outcome:?}",
            request.request_id,
            target.key
        );
        outcome
    }

    /// [`Self::grant_pairing`] for each picked vault of `picks`, by vault id,
    /// in order. Each vault runs its own transaction with the unlock that
    /// `unlock` returns for its target, `Unlock::App` in the app, so the user
    /// sees the one prompt of the app unlock. A vault that fails does not
    /// stop the others.
    pub fn grant_pairings<'u>(
        &self,
        picks: &[(Uuid, Target)],
        unlock: impl Fn(&Target) -> Unlock<'u>,
        request: &PairingRequest,
        code: &PairingCode,
        root: &TransportRoot,
    ) -> Vec<(Uuid, GrantOutcome)> {
        picks
            .iter()
            .map(|(vault_id, target)| {
                let outcome = self.grant_pairing(target, unlock(target), request, code, root);
                (*vault_id, outcome)
            })
            .collect()
    }
}
