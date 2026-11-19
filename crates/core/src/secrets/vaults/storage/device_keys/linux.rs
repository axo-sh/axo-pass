//! Linux stub of the device keys. Probes report an error and every operation
//! fails with `Unsupported`.

use super::{DeviceKeys, KeyProbe, KeychainKeys};
use crate::core::auth::AuthContext;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::KeychainSigner;
use crate::secrets::vaults::sync::model::ReplicaKeys;

/// Fails with `Unsupported`.
pub(in crate::secrets::vaults::storage) fn probe_vault_encryption_key()
-> Result<Result<Option<ManagedKey>, KeychainError>, KeychainError> {
    Err(KeychainError::Unsupported)
}

impl DeviceKeys for KeychainKeys {
    fn probe_encryption_key(&self) -> KeyProbe {
        match probe_vault_encryption_key() {
            Ok(result) => KeyProbe::of(result),
            Err(e) => KeyProbe::Error(e.to_string()),
        }
    }

    fn probe_signing_key(&self) -> KeyProbe {
        KeyProbe::of(KeychainSigner::probe_key())
    }

    fn read_encryption_key(&self, _context: AuthContext) -> Result<Option<ManagedKey>, Error> {
        Err(Error::KeyRetrievalFailed(KeychainError::Unsupported))
    }

    fn create_keys(&self, _context: AuthContext) -> Result<(), Error> {
        Err(Error::KeyCreationFailed(KeychainError::Unsupported))
    }

    fn create_signing_key(&self) -> Result<(), Error> {
        KeychainSigner::create_key()
    }

    fn public_keys(&self, _context: AuthContext) -> Result<ReplicaKeys, Error> {
        Err(Error::KeyRetrievalFailed(KeychainError::Unsupported))
    }
}
