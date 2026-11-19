//! Device keys in the macOS keychain.

use super::{DeviceKeys, KeyProbe, KeychainKeys, VAULT_ENCRYPTION_KEY_LABEL};
use crate::core::auth::{AuthContext, AuthMethod, probe_shared_context, run_on_auth_thread};
use crate::core::provenance::Provenance;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::keychain_query::KeychainQuery;
use crate::secrets::keychain::managed_key::{KeyClass, KeyPolicy, ManagedKey, ManagedKeyQuery};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::{KeychainSigner, VaultSigner};
use crate::secrets::vaults::sync::model::{PublicKey, ReplicaKeys};

/// Query the vault encryption key on the shared context with interaction not
/// allowed. A key gated by authentication fails the inner result with
/// `ItemNotAccessible`.
pub(in crate::secrets::vaults::storage) fn probe_vault_encryption_key()
-> Result<Result<Option<ManagedKey>, KeychainError>, KeychainError> {
    probe_shared_context(|la_context| {
        ManagedKeyQuery::build()
            .with_label(VAULT_ENCRYPTION_KEY_LABEL)
            .with_key_class(KeyClass::Private)
            .one_with_retry(la_context, false)
    })
}

impl DeviceKeys for KeychainKeys {
    /// Same probe as `check_vault_auth_still_valid`.
    fn probe_encryption_key(&self) -> KeyProbe {
        match probe_vault_encryption_key() {
            Ok(result) => KeyProbe::of(result),
            Err(e) => KeyProbe::Error(e.to_string()),
        }
    }

    fn probe_signing_key(&self) -> KeyProbe {
        KeyProbe::of(KeychainSigner::probe_key())
    }

    /// Read the key, drawing the prompt wherever `context` draws it.
    ///
    /// A foreign context arrives already authenticated by the process that
    /// owns it, so nothing is evaluated here. A second evaluation of the same
    /// context would put a second prompt in front of the user for one request.
    fn read_encryption_key(&self, context: AuthContext) -> Result<Option<ManagedKey>, Error> {
        let reason = match Provenance::resolve_current_parent()
            .inspect(|provenance| log::debug!("read_encryption_key: {provenance:#?}"))
            .and_then(|p| p.caller())
        {
            Some(parent) => format!("unlock the vault for {parent}"),
            None => "unlock the vault".to_string(),
        };
        let auth_method = match context {
            AuthContext::Foreign(_) => AuthMethod::None,
            _ => AuthMethod::Policy { reason },
        };
        run_on_auth_thread(context, auth_method, move |la_context| {
            ManagedKeyQuery::build()
                .with_label(VAULT_ENCRYPTION_KEY_LABEL)
                .with_key_class(KeyClass::Private)
                .one(la_context)
        })
        .map_err(Error::KeyRetrievalFailed)?
        .map_err(Error::KeyRetrievalFailed)
    }

    /// Create both keys without a prompt. `vault-encryption-key` is created on
    /// `context` with no evaluation. The read of the key that follows draws the
    /// only prompt.
    fn create_keys(&self, context: AuthContext) -> Result<(), Error> {
        if self.probe_encryption_key().is_missing()? {
            log::debug!("Vault encryption key not found, creating it");
            run_on_auth_thread(context, AuthMethod::None, move |la_context| {
                ManagedKey::create_with_context(
                    VAULT_ENCRYPTION_KEY_LABEL,
                    KeyPolicy::AlwaysRequireAuth,
                    Some(la_context),
                )
            })
            .map_err(Error::KeyCreationFailed)?
            .map_err(Error::KeyCreationFailed)?;
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
