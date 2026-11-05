use std::collections::HashMap;
use std::path::Path;

use uuid::Uuid;

use crate::core::auth::AuthContext;
use crate::secrets::vaults::bundle::FileKeyWrapper;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultFileKey};
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::{UnlockedKey, Vault};
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::keys::TestKeyWrapper;
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::{Unlocker, VaultHandle};

/// Unlock with file keys by vault id instead of the keychain. A stored raw
/// file key written by [`Self::file_key_wrapper`] takes precedence over the
/// map. Vaults with neither fail to unlock. Files and sync states are
/// verified under the test device key, and sync keyrings are unwrapped with
/// [`TestKeyWrapper`].
#[derive(Default)]
pub(crate) struct KeyUnlocker(pub(crate) HashMap<Uuid, UnlockedKey>);

impl KeyUnlocker {
    /// Prefix of a stored file key that holds the raw key after it.
    const RAW_KEY_PREFIX: &[u8] = b"test-raw-file-key:";

    /// File key of the vault file `enc_vault`: the stored raw key, or else
    /// the key in the map. Fails with `VaultFileKeyDecryptionError` if there
    /// is neither.
    pub(crate) fn file_key(&self, enc_vault: &EncryptedVault) -> Result<UnlockedKey, Error> {
        let raw = enc_vault
            .file_key
            .as_bytes()
            .strip_prefix(Self::RAW_KEY_PREFIX);
        match raw {
            Some(raw) => {
                let cipher = VaultCipher::new_with_bytes(raw, enc_vault.id);
                Ok(UnlockedKey::for_test(enc_vault.file_key.clone(), cipher))
            },
            None => self
                .0
                .get(&enc_vault.id)
                .map(UnlockedKey::duplicate_for_test)
                .ok_or(Error::VaultFileKeyDecryptionError),
        }
    }
}

impl Unlocker for KeyUnlocker {
    fn unlock(
        &self,
        vw: &mut VaultHandle,
        root: &Path,
        _context: AuthContext,
    ) -> Result<(), Error> {
        let signer = TestSigner::device();
        let enc_vault = EncryptedVault::load(&vw.path, &signer)?;
        let key = self.file_key(&enc_vault)?;
        let (case, keyring) = SyncLoad::load(root, &enc_vault, &signer, &TestKeyWrapper)?;
        case.check()?;
        let mut vault = Vault::from_unlocked_key(&key, enc_vault)?;
        vault.set_key(vw.key.clone());
        vw.set_unlocked(vault, keyring);
        Ok(())
    }

    /// Transaction with `Unlock::Test` and the file key of [`Self::file_key`].
    fn read_transaction(
        &self,
        files: &VaultWriter,
        target: &Target,
        _context: AuthContext,
    ) -> Result<Committed<()>, Error> {
        let enc_vault = EncryptedVault::load(&target.path, &TestSigner::device())?;
        let key = self.file_key(&enc_vault)?;
        let unlock = || key.duplicate_for_test();
        files.write(target, Unlock::Test(&unlock), |_| Ok(()))
    }

    /// Store each raw file key after [`Self::RAW_KEY_PREFIX`].
    fn file_key_wrapper(&self, _context: AuthContext) -> Result<FileKeyWrapper, Error> {
        Ok(Box::new(|raw: &[u8]| {
            Ok(VaultFileKey::new([Self::RAW_KEY_PREFIX, raw].concat()))
        }))
    }

    /// Empty vault with the fixed test file key. The name is not kept.
    fn new_vault(
        &self,
        _name: Option<String>,
        key: String,
        _context: AuthContext,
    ) -> Result<Vault, Error> {
        let mut vault = Vault::new_for_test();
        vault.set_key(key);
        Ok(vault)
    }
}
