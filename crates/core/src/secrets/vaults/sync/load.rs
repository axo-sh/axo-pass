//! Load classification: a verified vault file against its local sync state.
//!
//! Every load path verifies the vault file, classifies it with
//! [`SyncLoad::classify`], and builds the `Vault` only if
//! [`SyncLoad::check`] passes. The check is read-only and writes nothing. A
//! missing or failed sync state is a stop found again at each load
//! (`sync/status.rs`).

use std::fmt;
use std::path::Path;

use p256::ecdsa::VerifyingKey;
use uuid::Uuid;

use super::crdt::{CausalState, ReplicaId};
use super::keys::{SyncKeyWrapper, SyncKeyring};
use super::local_state::{LocalStateError, LocalSyncState};
use super::model::{KeyId, SyncState};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::VerifiedVault;
use crate::secrets::vaults::format::signing::VaultSigner;

/// Case of a vault file against its local sync state.
#[derive(Debug, PartialEq)]
pub enum SyncLoad {
    /// Vault names no replica id, and no sync state exists.
    NotSynced,
    /// `v == s`.
    Current,
    /// `v < s`. A crash between the sync state save and the vault save, or a
    /// restored vault.
    OlderVault { vault: u64, state: u64 },
    /// `v < s` while sync is stopped by drift. The sync state holds none of
    /// the edits saved while stopped, so the vault loads as it is, with the
    /// "Older vault file" notice, and is not rebuilt.
    StoppedOlderVault { vault: u64, state: u64 },
    /// `v > s`. A sync state restored from a backup.
    NewerVault { vault: u64, state: u64 },
    /// Sync state names another vault id or replica id than the vault.
    Mismatch(Mismatch),
    /// Vault names a replica id, and no sync state exists.
    StateMissing,
    /// Sync state is not trusted.
    SignatureFailed(SignatureFailure),
    /// Sync state body is under a key id the keyring lacks.
    KeyMissing(KeyId),
    /// Sync state is from a newer format.
    VersionSkew(String),
    /// Vault names no replica id, and a sync state exists.
    DisableInProgress,
}

/// Sync state field that differs from the vault.
#[derive(Debug, PartialEq)]
pub enum Mismatch {
    /// Vault id of the sync state.
    VaultId(Uuid),
    /// Replica id of the sync state.
    ReplicaId(ReplicaId),
}

/// Reason a sync state is not trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureFailure {
    /// Envelope fails to parse, so the signature cannot be checked.
    Envelope,
    /// Signature does not verify.
    Signature,
    /// Signed state fails to parse.
    Malformed,
    /// Signed keyring fails to unwrap.
    Keyring,
    /// Signed body fails to decrypt or to decode.
    Body,
    /// Own `replica_keys` entry does not hold the current
    /// `device-signing-key`.
    OwnKey,
}

/// Local sync state whose signature, keyring, body, and own key check all
/// pass, with its decrypted body.
pub(crate) struct TrustedState {
    pub(crate) local: LocalSyncState,
    pub(crate) state: CausalState<SyncState>,
}

impl fmt::Display for SyncLoad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSynced => f.write_str("vault is not synced"),
            Self::Current => f.write_str("vault matches its sync state"),
            Self::OlderVault { vault, state } => {
                write!(
                    f,
                    "vault generation {vault} is older than sync state generation {state}"
                )
            },
            Self::StoppedOlderVault { vault, state } => {
                write!(
                    f,
                    "vault generation {vault} is older than sync state generation {state}, and \
                     sync is stopped by drift"
                )
            },
            Self::NewerVault { vault, state } => {
                write!(
                    f,
                    "vault generation {vault} is newer than sync state generation {state}"
                )
            },
            Self::Mismatch(Mismatch::VaultId(id)) => {
                write!(f, "sync state belongs to vault {id}")
            },
            Self::Mismatch(Mismatch::ReplicaId(id)) => {
                write!(f, "sync state belongs to replica {}", id.0)
            },
            Self::StateMissing => f.write_str("sync state missing"),
            Self::SignatureFailed(reason) => write!(f, "sync state signature failed: {reason:?}"),
            Self::KeyMissing(key_id) => write!(f, "keyring lacks sync key {}", key_id.0),
            Self::VersionSkew(message) => write!(f, "sync state is from a newer format: {message}"),
            Self::DisableInProgress => f.write_str("disable sync in progress"),
        }
    }
}

impl SyncLoad {
    /// Case of the verified vault `vault` against `local`, the result of
    /// loading its local sync state under the key of `signer`. The body is
    /// decrypted with `keyring` for the own key check. `keyring` is `None` if
    /// the keyring of the sync state failed to unwrap, which is a failed
    /// signature.
    ///
    /// A failure to read the file or the signing key is an error, not a case.
    pub fn classify(
        vault: &VerifiedVault,
        local: Result<LocalSyncState, LocalStateError>,
        keyring: Option<&SyncKeyring>,
        signer: &dyn VaultSigner,
    ) -> Result<Self, Error> {
        Ok(Self::classify_trusted(vault, local, keyring, signer)?.0)
    }

    /// [`Self::classify`], with the trusted sync state if the case compares
    /// the vault with one: `Current`, `OlderVault`, `StoppedOlderVault`,
    /// `NewerVault`, and `Mismatch`.
    pub(crate) fn classify_trusted(
        vault: &VerifiedVault,
        local: Result<LocalSyncState, LocalStateError>,
        keyring: Option<&SyncKeyring>,
        signer: &dyn VaultSigner,
    ) -> Result<(Self, Option<TrustedState>), Error> {
        let Some(replica_id) = vault.replica_id else {
            // Any sync state file of a vault that is not synced is left from
            // a disable, whether or not it verifies.
            return Ok((
                match local {
                    Err(LocalStateError::Missing) => Self::NotSynced,
                    _ => Self::DisableInProgress,
                },
                None,
            ));
        };
        let trusted = match Self::trust(local, keyring, signer)? {
            Ok(trusted) => trusted,
            Err(case) => return Ok((case, None)),
        };
        let local = &trusted.local;
        let case = if local.vault_id != vault.id {
            Self::Mismatch(Mismatch::VaultId(local.vault_id))
        } else if local.replica_id.0 != replica_id {
            Self::Mismatch(Mismatch::ReplicaId(local.replica_id))
        } else {
            let (vault, state) = (vault.generation, local.generation);
            match vault.cmp(&state) {
                std::cmp::Ordering::Equal => Self::Current,
                std::cmp::Ordering::Less if local.stopped_build.is_some() => {
                    Self::StoppedOlderVault { vault, state }
                },
                std::cmp::Ordering::Less => Self::OlderVault { vault, state },
                std::cmp::Ordering::Greater => Self::NewerVault { vault, state },
            }
        };
        Ok((case, Some(trusted)))
    }

    /// Trusted state of `local`, the result of loading a local sync state
    /// under the key of `signer`, with its body decrypted with `keyring`.
    /// `keyring` is `None` if it failed to unwrap. Otherwise the case of a
    /// synced vault whose sync state is not trusted.
    pub(crate) fn trust(
        local: Result<LocalSyncState, LocalStateError>,
        keyring: Option<&SyncKeyring>,
        signer: &dyn VaultSigner,
    ) -> Result<Result<TrustedState, Self>, Error> {
        let local = match local {
            Ok(local) => local,
            Err(e) => return Self::of_error(e).map(Err),
        };
        let Some(keyring) = keyring else {
            return Ok(Err(Self::SignatureFailed(SignatureFailure::Keyring)));
        };
        let state = match local.open(keyring) {
            Ok(state) => state,
            Err(e) => return Self::of_error(e).map(Err),
        };
        if !Self::holds_own_key(&state.store, local.replica_id, signer)? {
            return Ok(Err(Self::SignatureFailed(SignatureFailure::OwnKey)));
        }
        Ok(Ok(TrustedState { local, state }))
    }

    /// Case of a synced vault whose sync state fails to load or to open.
    fn of_error(e: LocalStateError) -> Result<Self, Error> {
        Ok(match e {
            LocalStateError::Missing => Self::StateMissing,
            LocalStateError::Read(e) => return Err(Error::SyncStateReadError(e)),
            LocalStateError::SigningKey(e) => return Err(e),
            LocalStateError::Envelope(_) => Self::SignatureFailed(SignatureFailure::Envelope),
            LocalStateError::SignatureInvalid => Self::SignatureFailed(SignatureFailure::Signature),
            LocalStateError::Malformed(_) => Self::SignatureFailed(SignatureFailure::Malformed),
            LocalStateError::VersionSkew(message) => Self::VersionSkew(message),
            LocalStateError::KeyMissing(key_id) => Self::KeyMissing(key_id),
            LocalStateError::Decryption
            | LocalStateError::Padding(_)
            | LocalStateError::Body(_) => Self::SignatureFailed(SignatureFailure::Body),
        })
    }

    /// Whether the `replica_keys` entry of `replica_id` in `state` holds the
    /// current key of `signer`. Any one value of the register may hold it.
    fn holds_own_key(
        state: &SyncState,
        replica_id: ReplicaId,
        signer: &dyn VaultSigner,
    ) -> Result<bool, Error> {
        let current = signer.verifying_key()?;
        let Some(register) = state.replica_keys.get(&replica_id) else {
            return Ok(false);
        };
        Ok(register.values().any(|(_, keys)| {
            VerifyingKey::from_sec1_bytes(&keys.value.signing.0).is_ok_and(|key| key == current)
        }))
    }

    /// Fail if a load path must not serve the vault in this case. Every case
    /// that needs a repair fails with `SyncRepairNeeded`, and a newer sync
    /// state format with `SyncStateVersionSkew`. The vault loads in every
    /// other case.
    pub fn check(&self) -> Result<(), Error> {
        match self {
            Self::NotSynced
            | Self::Current
            | Self::StoppedOlderVault { .. }
            | Self::StateMissing
            | Self::SignatureFailed(_)
            | Self::KeyMissing(_)
            | Self::DisableInProgress => Ok(()),
            Self::OlderVault { .. } | Self::NewerVault { .. } | Self::Mismatch(_) => {
                Err(Error::SyncRepairNeeded(self.to_string()))
            },
            Self::VersionSkew(message) => Err(Error::SyncStateVersionSkew(message.clone())),
        }
    }

    /// Keyring of the local sync state of `vault` under the app data
    /// directory `root`, unwrapped by `wrapper`. Empty if the vault is not
    /// synced or the sync state fails to load. `None` if the keyring fails to
    /// unwrap.
    pub(crate) fn keyring(
        root: &Path,
        vault: &VerifiedVault,
        signer: &dyn VaultSigner,
        wrapper: &impl SyncKeyWrapper,
    ) -> Option<SyncKeyring> {
        if vault.replica_id.is_none() {
            return Some(SyncKeyring::default());
        }
        Self::keyring_of(root, vault.id, signer, wrapper)
    }

    /// Keyring of the local sync state of vault `vault_id` under the app data
    /// directory `root`, unwrapped by `wrapper`, for a vault with no vault
    /// file that verifies. Empty if the sync state fails to load. `None` if
    /// the keyring fails to unwrap.
    pub(crate) fn keyring_of(
        root: &Path,
        vault_id: Uuid,
        signer: &dyn VaultSigner,
        wrapper: &impl SyncKeyWrapper,
    ) -> Option<SyncKeyring> {
        Self::unwrap_keyring(&LocalSyncState::load(root, vault_id, signer), wrapper)
    }

    /// Keyring of `local` unwrapped by `wrapper`. Empty if `local` failed to
    /// load. `None` if the keyring fails to unwrap.
    fn unwrap_keyring(
        local: &Result<LocalSyncState, LocalStateError>,
        wrapper: &impl SyncKeyWrapper,
    ) -> Option<SyncKeyring> {
        match local {
            Ok(local) => SyncKeyring::unwrap(&local.sync_keys, wrapper).ok(),
            Err(_) => Some(SyncKeyring::default()),
        }
    }

    /// Load the local sync state of `vault` under the app data directory
    /// `root`, unwrap its keyring with `wrapper`, and classify the vault.
    /// Returns the case and the keyring the vault holds, as
    /// [`Self::with_keyring`] gives it.
    pub(crate) fn load(
        root: &Path,
        vault: &VerifiedVault,
        signer: &dyn VaultSigner,
        wrapper: &impl SyncKeyWrapper,
    ) -> Result<(Self, SyncKeyring), Error> {
        let local = LocalSyncState::load(root, vault.id, signer);
        let keyring = match vault.replica_id {
            Some(_) => Self::unwrap_keyring(&local, wrapper),
            None => Some(SyncKeyring::default()),
        };
        let case = Self::classify(vault, local, keyring.as_ref(), signer)?;
        Ok(case.with_keyring(keyring))
    }

    /// This case with `keyring` if the case is `Current` or
    /// `StoppedOlderVault`, or else with an empty keyring. Only a sync state
    /// the vault loads with as it is is trusted.
    pub(crate) fn with_keyring(self, keyring: Option<SyncKeyring>) -> (Self, SyncKeyring) {
        match self {
            Self::Current | Self::StoppedOlderVault { .. } => (self, keyring.unwrap_or_default()),
            _ => (self, SyncKeyring::default()),
        }
    }
}
