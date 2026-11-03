//! Rebuild of a vault from its trusted local sync state.
//!
//! The view of the sync state is applied to an empty vault. The rebuilt vault
//! is saved with the next generation, `s + 1`. The sync state is saved first
//! with that generation and its body sealed again, then the vault. A crash
//! between the two saves leaves `v < s`, which the next transaction rebuilds
//! again.

use std::path::Path;

use super::keys::SyncKeyring;
use super::load::TrustedState;
use super::local_state::LocalSyncState;
use super::view::VaultView;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::model::{UnlockedKey, Vault};

/// Rebuild of one vault: the sync state to save at the next generation, and
/// the view to apply.
pub(crate) struct Rebuild {
    /// Sync state at the next generation, with its body sealed again.
    local: LocalSyncState,
    view: VaultView,
}

impl Rebuild {
    /// Rebuild from `trusted`. The body is sealed again under the next
    /// generation with the key of `keyring` that opened it.
    pub(crate) fn new(trusted: TrustedState, keyring: &SyncKeyring) -> Result<Self, Error> {
        let TrustedState { mut local, state } = trusted;
        let padded = local
            .open_padded(keyring)
            .map_err(|e| Error::SyncStateEncodeError(e.to_string()))?;
        local.generation += 1;
        local.seal(&padded, keyring)?;
        Ok(Self {
            local,
            view: VaultView::of(&state),
        })
    }

    /// Vault name of the view.
    pub(crate) fn name(&self) -> Option<&str> {
        self.view.name.as_deref()
    }

    /// Vault with key `key` and file key `file_key`, holding the view, at the
    /// next generation and the replica id of the sync state. Fails if the
    /// file key is for another vault id than the sync state.
    pub(crate) fn vault(&self, key: String, file_key: &UnlockedKey) -> Result<Vault, Error> {
        if file_key.vault_id() != self.local.vault_id {
            return Err(Error::VaultFileKeyChanged);
        }
        let mut vault = Vault::with_unlocked_key(key, file_key);
        self.view.apply(&mut vault)?;
        vault.set_sync(self.local.generation, Some(self.local.replica_id.0));
        Ok(vault)
    }

    /// Save the sync state, signed by `signer`, under the app data directory
    /// `root`. Runs before the vault is saved.
    pub(crate) fn save_state(&self, root: &Path, signer: &dyn VaultSigner) -> Result<(), Error> {
        self.local.save(root, signer)
    }
}
