use std::collections::HashMap;

use uuid::Uuid;

use crate::core::auth::AuthContext;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::vault::{UnlockedKey, Vault};
use crate::secrets::vaults::{Unlocker, VaultHandle};

/// Unlock with file keys by vault id instead of the keychain. A vault without
/// a key fails to unlock.
#[derive(Default)]
pub(crate) struct KeyUnlocker(pub(crate) HashMap<Uuid, UnlockedKey>);

impl Unlocker for KeyUnlocker {
    fn unlock(&self, vw: &mut VaultHandle, _context: AuthContext) -> Result<(), Error> {
        let enc_vault = EncryptedVault::load(&vw.path)?;
        let key = self
            .0
            .get(&enc_vault.id)
            .ok_or(Error::VaultFileKeyDecryptionError)?;
        vw.replace_vault(Vault::from_unlocked_key(key, enc_vault)?);
        Ok(())
    }
}
