//! Device pairing on the new Mac (Device pairing steps 1 to 3 and 8).
//!
//! The new Mac shows a one-time code, writes a pairing request with a new
//! replica id for each vault directory under the root that it does not sync,
//! and polls the `key.json` files of those vaults for `Device` wrappings to
//! its replica ids. Only the user moves the code between the Macs, so the
//! MAC of the request authenticates the new Mac's keys to the unlocked Mac,
//! and the MAC of a wrapping authenticates the key and the sender keys to
//! the new Mac.
//!
//! The pairing watcher, and the deletion of the request when the app quits
//! or after 15 minutes, are milestone 9. The import of a [`PairedVault`] is
//! milestone 10.

pub mod request;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use self::request::PairingRequest;
use super::crdt::ReplicaId;
use super::keys::SyncKey;
use super::local_state::{PinSource, PinnedKeys};
use super::model::{KeyId, ReplicaKeys};
use super::transport::{FileName, MAX_PAIRING_SIZE, ReadResult, RequestId, SyncTransport};
use super::wrapping::base32::Crockford;
use super::wrapping::{DeviceUnwrap, DeviceWrapping, KeyFile, PairingMac};
use crate::core::auth::AuthContext;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::device_keys::{
    DeviceKeys, KeyState, OnNewHardware, VaultFiles, ensure_device_keys,
};

/// HKDF info of the pairing key.
const PAIRING_INFO: &[u8] = b"ap-pairing-v1";

/// One-time pairing code: 10 random bytes (80 bits), shown as 16 Crockford
/// base32 characters. Held in memory only. It has no serde form, is zeroized
/// on drop, and `Debug` shows no bytes.
pub struct PairingCode(Zeroizing<[u8; 10]>);

impl PairingCode {
    /// Characters of the shown form, without hyphens.
    const CHARS: usize = 16;

    /// New random code.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 10]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; 10]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Code of the text the user typed. Read as Crockford base32, so case,
    /// hyphens, spaces, and the confusable letters do not matter. Fails
    /// unless the text holds 16 characters other than hyphens and spaces.
    pub fn parse(text: &str) -> Option<Self> {
        let chars = text.chars().filter(|c| !matches!(c, '-' | ' ')).count();
        if chars != Self::CHARS {
            return None;
        }
        let decoded = Zeroizing::new(Crockford::decode(text)?);
        let mut bytes = Zeroizing::new([0u8; 10]);
        if decoded.len() != bytes.len() {
            return None;
        }
        bytes.copy_from_slice(&decoded);
        Some(Self(bytes))
    }

    /// Shown form, `XXXX-XXXX-XXXX-XXXX`.
    pub fn shown(&self) -> Zeroizing<String> {
        Zeroizing::new(Crockford::encode_grouped(self.0.as_ref(), 4))
    }

    /// `HKDF-SHA-256(code bytes, info = "ap-pairing-v1")`, 32 bytes. No salt.
    pub fn pair_key(&self) -> PairKey {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, self.0.as_ref())
            .expand(PAIRING_INFO, key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA-256 output length");
        PairKey(key)
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(..)")
    }
}

/// The only field is `Zeroizing`, which zeroizes the bytes on drop.
impl ZeroizeOnDrop for PairingCode {}

/// HMAC key of one pairing, derived from the code. Zeroized on drop.
pub struct PairKey(Zeroizing<[u8; 32]>);

impl PairKey {
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// HMAC-SHA-256 of `input`.
    pub fn mac(&self, input: &[u8]) -> PairingMac {
        let mut hmac = self.hmac();
        hmac.update(input);
        PairingMac(hmac.finalize().into_bytes().into())
    }

    /// Whether `mac` is the HMAC-SHA-256 of `input`. The comparison takes
    /// constant time.
    pub fn verify(&self, input: &[u8], mac: &PairingMac) -> bool {
        let mut hmac = self.hmac();
        hmac.update(input);
        hmac.verify_slice(&mac.0).is_ok()
    }

    /// Set the pairing MAC of `wrapping`, written by `from_replica` in vault
    /// `vault_id` for the new Mac with the keys `to`.
    pub fn seal_wrapping(
        &self,
        wrapping: &mut DeviceWrapping,
        vault_id: Uuid,
        from_replica: ReplicaId,
        to: &ReplicaKeys,
    ) {
        wrapping.pairing_mac = Some(self.mac(&wrapping.pairing_input(vault_id, from_replica, to)));
    }

    /// Whether the pairing MAC of `wrapping` verifies, for a wrapping in the
    /// `key.json` of `from_replica` in vault `vault_id` to the new Mac with
    /// the keys `to`. A wrapping with no pairing MAC fails.
    pub fn verify_wrapping(
        &self,
        wrapping: &DeviceWrapping,
        vault_id: Uuid,
        from_replica: ReplicaId,
        to: &ReplicaKeys,
    ) -> bool {
        wrapping.pairing_mac.as_ref().is_some_and(|mac| {
            self.verify(&wrapping.pairing_input(vault_id, from_replica, to), mac)
        })
    }

    fn hmac(&self) -> Hmac<Sha256> {
        <Hmac<Sha256> as Mac>::new_from_slice(self.0.as_ref())
            .expect("HMAC takes a key of any length")
    }
}

impl fmt::Debug for PairKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairKey(..)")
    }
}

/// The only field is `Zeroizing`, which zeroizes the bytes on drop.
impl ZeroizeOnDrop for PairKey {}

/// Vault whose sync key the new Mac received by pairing.
#[derive(Debug)]
pub struct PairedVault {
    pub vault_id: Uuid,
    /// Replica id of the new Mac in the vault, from the request.
    pub replica_id: ReplicaId,
    pub key_id: KeyId,
    pub key: SyncKey,
    /// Replica of the Mac that wrote the wrapping.
    pub peer: ReplicaId,
    /// `pairing` pin of the keys of `peer`, from the wrapping.
    pub pin: PinnedKeys,
}

/// Pairing of this Mac as the new Mac, from its request until the user
/// finishes. The code is dropped with it.
#[derive(Debug)]
pub struct PendingPairing {
    code: PairingCode,
    key: PairKey,
    request: PairingRequest,
    /// Vaults whose key was accepted.
    accepted: BTreeSet<Uuid>,
}

impl PendingPairing {
    /// Start a pairing through `transport`, as the Mac named `name`.
    ///
    /// Lists the vault directories first, so a folder that cannot be listed
    /// creates no key. The request map leaves out the vaults in `synced`,
    /// the vaults this Mac syncs (D13). On new hardware the sync states move
    /// to `unreadable/`, so `synced` is not used. Fails with
    /// `PairingNoVaults` if no vault is left. Then creates the missing keys
    /// with `OnNewHardware::MoveFiles`, reads the public keys on `context`,
    /// which can prompt, generates a replica id for each vault and the code,
    /// and writes the request.
    #[allow(dead_code, reason = "the pairing UI of milestone 10 calls it")]
    pub(crate) fn start(
        transport: &dyn SyncTransport,
        synced: &BTreeSet<Uuid>,
        keys: &dyn DeviceKeys,
        files: &VaultFiles,
        context: AuthContext,
        name: &str,
    ) -> Result<Self, Error> {
        let vaults = transport.list_vaults()?;
        let new_hardware = KeyState::probe(keys, files) == KeyState::NewHardware;
        let replicas: BTreeMap<Uuid, ReplicaId> = vaults
            .into_iter()
            .filter(|vault_id| new_hardware || !synced.contains(vault_id))
            .map(|vault_id| (vault_id, ReplicaId::generate()))
            .collect();
        if replicas.is_empty() {
            return Err(Error::PairingNoVaults);
        }
        ensure_device_keys(keys, files, context.clone(), OnNewHardware::MoveFiles)?;
        let public = keys.public_keys(context)?;
        let code = PairingCode::generate();
        let key = code.pair_key();
        let request = PairingRequest::new(
            RequestId::generate(),
            replicas,
            &public,
            name.to_string(),
            &key,
        );
        let bytes = request.to_bytes();
        if bytes.len() as u64 > MAX_PAIRING_SIZE {
            return Err(Error::PairingRequestTooLarge(bytes.len()));
        }
        transport.write_pairing(request.request_id, &bytes)?;
        log::info!(
            "Pairing request {} written for {} vaults",
            request.request_id,
            request.replicas.len()
        );
        Ok(Self {
            code,
            key,
            request,
            accepted: BTreeSet::new(),
        })
    }

    /// Code to show to the user.
    pub fn code(&self) -> &PairingCode {
        &self.code
    }

    pub fn request(&self) -> &PairingRequest {
        &self.request
    }

    /// Vaults whose key arrived since the last poll.
    ///
    /// Reads the `key.json` of every replica directory of each vault in the
    /// request map that has no accepted key. A `Remote` or missing file, and
    /// a file or directory that fails to read, is read again in the next
    /// poll. A `Device` wrapping is accepted only if its `to_replica` is the
    /// replica id of its vault in the map and its pairing MAC verifies under
    /// the code. The MAC is checked before the unwrap, so a wrapping that
    /// fails it draws no prompt. `unwrap` holds `vault-encryption-key`, read
    /// once on one context for every vault. A key that is not 32 bytes, or
    /// whose fingerprint differs from `key_fingerprint`, is refused. The
    /// first accepted wrapping of a vault gives its [`PairedVault`].
    pub fn poll(
        &mut self,
        transport: &dyn SyncTransport,
        unwrap: &impl DeviceUnwrap,
    ) -> Vec<PairedVault> {
        let mut paired = Vec::new();
        for (&vault_id, &replica_id) in &self.request.replicas {
            if self.accepted.contains(&vault_id) {
                continue;
            }
            if let Some(vault) = self.poll_vault(transport, unwrap, vault_id, replica_id) {
                self.accepted.insert(vault_id);
                paired.push(vault);
            }
        }
        paired
    }

    /// Delete the request and drop the code. The code is dropped even if the
    /// delete fails.
    pub fn finish(self, transport: &dyn SyncTransport) -> Result<(), Error> {
        transport.delete_pairing(self.request.request_id)
    }

    /// First accepted wrapping to `replica_id` in vault `vault_id`.
    fn poll_vault(
        &self,
        transport: &dyn SyncTransport,
        unwrap: &impl DeviceUnwrap,
        vault_id: Uuid,
        replica_id: ReplicaId,
    ) -> Option<PairedVault> {
        let replicas = transport
            .list_replicas(vault_id)
            .inspect_err(|e| log::warn!("Pairing failed to list the replicas of {vault_id}: {e}"))
            .ok()?;
        let keys = self.request.keys();
        for from_replica in replicas {
            if from_replica == replica_id {
                continue;
            }
            let bytes = match transport.read(vault_id, from_replica, FileName::Key) {
                Ok(ReadResult::Local(bytes)) => bytes,
                Ok(ReadResult::Missing | ReadResult::Remote) => continue,
                Err(e) => {
                    log::warn!("Pairing failed to read a key file of {vault_id}: {e}");
                    continue;
                },
            };
            let file = match KeyFile::parse(&bytes) {
                Ok(file) => file,
                Err(e) => {
                    log::debug!("Pairing skips a key file of {vault_id}: {e}");
                    continue;
                },
            };
            for wrapping in file.devices() {
                if wrapping.to_replica != replica_id
                    || !self
                        .key
                        .verify_wrapping(wrapping, vault_id, from_replica, &keys)
                {
                    continue;
                }
                match wrapping.unwrap(unwrap) {
                    Ok(key) => {
                        log::info!(
                            "Pairing received sync key {} of {vault_id}",
                            wrapping.key_id.0
                        );
                        return Some(PairedVault {
                            vault_id,
                            replica_id,
                            key_id: wrapping.key_id,
                            key,
                            peer: from_replica,
                            pin: PinnedKeys {
                                source: PinSource::Pairing,
                                encryption: wrapping.from_encryption.clone(),
                                signing: wrapping.from_signing.clone(),
                                revoked: false,
                            },
                        });
                    },
                    Err(e) => log::warn!("Pairing refused a wrapping of {vault_id}: {e}"),
                }
            }
        }
        None
    }
}
