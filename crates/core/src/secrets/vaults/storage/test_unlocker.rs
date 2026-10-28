use std::collections::HashMap;

use uuid::Uuid;

use crate::core::auth::AuthContext;
use crate::secrets::vaults::bundle::FileKeyWrapper;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultFileKey};
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::{UnlockedKey, Vault};
use crate::secrets::vaults::{Unlocker, VaultHandle};

/// Unlock with file keys by vault id instead of the keychain. A stored raw
/// file key written by [`Self::file_key_wrapper`] takes precedence over the
/// map. Vaults with neither fail to unlock. Files are verified under the test
/// device key.
#[derive(Default)]
pub(crate) struct KeyUnlocker(pub(crate) HashMap<Uuid, UnlockedKey>);

impl KeyUnlocker {
    /// Prefix of a stored file key that holds the raw key after it.
    const RAW_KEY_PREFIX: &[u8] = b"test-raw-file-key:";
}

impl Unlocker for KeyUnlocker {
    fn unlock(&self, vw: &mut VaultHandle, _context: AuthContext) -> Result<(), Error> {
        let enc_vault = EncryptedVault::load(&vw.path, &TestSigner::device())?;
        let stored;
        let raw = enc_vault
            .file_key
            .as_bytes()
            .strip_prefix(Self::RAW_KEY_PREFIX);
        let key = match raw {
            Some(raw) => {
                let cipher = VaultCipher::new_with_bytes(raw, enc_vault.id);
                stored = UnlockedKey::for_test(enc_vault.file_key.clone(), cipher);
                &stored
            },
            None => self
                .0
                .get(&enc_vault.id)
                .ok_or(Error::VaultFileKeyDecryptionError)?,
        };
        vw.replace_vault(Vault::from_unlocked_key(key, enc_vault)?);
        Ok(())
    }

    /// Store each raw file key after [`Self::RAW_KEY_PREFIX`].
    fn file_key_wrapper(&self, _context: AuthContext) -> Result<FileKeyWrapper, Error> {
        Ok(Box::new(|raw: &[u8]| {
            Ok(VaultFileKey::new([Self::RAW_KEY_PREFIX, raw].concat()))
        }))
    }
}
