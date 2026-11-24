//! Device keys in software, for simulator builds.
//!
//! The simulator has no Secure Enclave, so the keys are P-256 keys in files of
//! the data directory. They give the same public key and ciphertext forms as
//! the Secure Enclave keys. The auth context is ignored, since nothing gates
//! a software key.

use super::{DeviceKeys, KeyProbe, KeychainKeys};
use crate::core::auth::AuthContext;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::keychain::software_keys::SoftwareKeys;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::{KeychainSigner, VaultSigner};
use crate::secrets::vaults::sync::model::{PublicKey, ReplicaKeys};

/// Label of the vault encryption key.
const VAULT_ENCRYPTION_KEY_LABEL: &str = "vault-encryption-key";

/// `vault-encryption-key` as a managed key, or `None` if it does not exist.
fn load_encryption_key() -> Result<Option<ManagedKey>, KeychainError> {
    SoftwareKeys::load(VAULT_ENCRYPTION_KEY_LABEL)?
        .map(|secret| {
            ManagedKey::from_secret(Some(VAULT_ENCRYPTION_KEY_LABEL.to_string()), &secret)
        })
        .transpose()
}

/// Look for the vault encryption key. No software key is gated by
/// authentication.
pub(in crate::secrets::vaults::storage) fn probe_vault_encryption_key()
-> Result<Result<Option<ManagedKey>, KeychainError>, KeychainError> {
    Ok(load_encryption_key())
}

impl DeviceKeys for KeychainKeys {
    fn probe_encryption_key(&self) -> KeyProbe {
        KeyProbe::of(load_encryption_key())
    }

    fn probe_signing_key(&self) -> KeyProbe {
        KeyProbe::of(KeychainSigner::probe_key())
    }

    fn read_encryption_key(&self, _context: AuthContext) -> Result<Option<ManagedKey>, Error> {
        load_encryption_key().map_err(Error::KeyRetrievalFailed)
    }

    fn create_keys(&self, _context: AuthContext) -> Result<(), Error> {
        if self.probe_encryption_key().is_missing()? {
            log::debug!("Vault encryption key not found, creating a software key");
            SoftwareKeys::create(VAULT_ENCRYPTION_KEY_LABEL).map_err(Error::KeyCreationFailed)?;
        }
        if self.probe_signing_key().is_missing()? {
            KeychainSigner::create_key()?;
        }
        Ok(())
    }

    fn create_signing_key(&self) -> Result<(), Error> {
        KeychainSigner::create_key()
    }

    fn public_keys(&self, context: AuthContext) -> Result<ReplicaKeys, Error> {
        let encryption = self
            .read_encryption_key(context)?
            .ok_or(Error::VaultEncryptionKeyMissing)?
            .public_key_sec1()
            .map_err(Error::KeyRetrievalFailed)?;
        let signing = KeychainSigner.verifying_key()?.to_encoded_point(false);
        Ok(ReplicaKeys {
            encryption: PublicKey(encryption),
            signing: PublicKey(signing.as_bytes().to_vec()),
        })
    }
}
