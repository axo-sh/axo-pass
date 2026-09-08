use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::{fs, io};

use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{SecretBox, SecretString};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::core::auth::{AuthContext, AuthMethod, probe_shared_context, run_on_auth_thread};
use crate::core::provenance::Provenance;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::keychain_query::KeychainQuery;
use crate::secrets::keychain::managed_key::{KeyClass, ManagedKey, ManagedKeyQuery};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::vault::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::vault::{Vault, VaultItemCredentialOverview, VaultItemOverview};
use crate::secrets::vaults::vault_export::ExportMode;
use crate::secrets::vaults::vault_export::exported_bundle::{BUNDLE_VERSION, ExportedBundle};

pub const DEFAULT_VAULT: &str = "default";

const VAULT_ENCRYPTION_KEY_LABEL: &str = "vault-encryption-key";

enum VaultState {
    Locked { name: Option<String> },
    Unlocked { vault: Box<Vault> },
}

// in-memory representation of a vault
pub struct VaultWrapper {
    pub key: String,
    pub path: PathBuf,
    state: VaultState,
}

fn vault_file_path(vault_dir: &Path, vault_key: &str) -> Result<PathBuf, Error> {
    let vault_key =
        normalized_key(vault_key).ok_or_else(|| Error::InvalidVaultKey(vault_key.to_string()))?;
    Ok(vault_dir.join(format!("{vault_key}.json")))
}

impl VaultWrapper {
    pub fn new_vault(
        name: Option<String>,
        vault_dir: &Path,
        vault_key: &str,
        user_encryption_key: ManagedKey,
    ) -> Result<Self, Error> {
        log::debug!("Creating new vault...");
        let vault_key = normalized_key(vault_key)
            .ok_or_else(|| Error::InvalidVaultKey(vault_key.to_string()))?;

        let vault_path = vault_file_path(vault_dir, &vault_key)?;
        let vault_overview = Vault::new(name, user_encryption_key)?;
        let vault_wrapper = Self {
            key: vault_key.to_string(),
            path: vault_path,
            state: VaultState::Unlocked {
                vault: Box::new(vault_overview),
            },
        };
        vault_wrapper.save()?;
        Ok(vault_wrapper)
    }

    pub fn load(vault_dir: &Path, vault_key: Option<String>) -> Result<Self, Error> {
        let vault_key = vault_key.unwrap_or(DEFAULT_VAULT.to_string());
        let vault_path = vault_file_path(vault_dir, &vault_key)?;
        Self::load_from_path(Some(vault_key), &vault_path)
    }

    pub fn load_from_path(vault_key: Option<String>, vault_path: &Path) -> Result<Self, Error> {
        let vault = EncryptedVault::load(vault_path)?;

        // todo: decide what to do for key for external vaults, some options:
        // 1. use file name as key
        // 2. use the vault.id as the key
        // 3. use the vault.name
        // 4. add a key field to the vault file and use that
        let vault_key = vault_key.unwrap_or_else(|| vault.id.to_string());
        if !validate_key(&vault_key) {
            return Err(Error::InvalidVaultKey(vault_key.to_string()));
        }

        Ok(Self {
            key: vault_key,
            path: vault_path.to_path_buf(),
            state: VaultState::Locked {
                name: vault.name.clone(),
            },
        })
    }

    pub fn unlock(&mut self) -> Result<(), Error> {
        self.unlock_on(AuthContext::SharedThreadLocal)
    }

    /// Unlock on a specific [`AuthContext`]. The app broker passes
    /// [`AuthContext::Foreign`] so the app that owns the context draws the
    /// prompt for a lapsed authentication.
    pub fn unlock_on(&mut self, auth_context: AuthContext) -> Result<(), Error> {
        // note: does not check if the LAContext is still valid
        let encrypted_vault = EncryptedVault::load(&self.path)?;
        let managed_key = get_vault_encryption_key_on(auth_context)?;
        let vault = Vault::from_encrypted(managed_key, encrypted_vault)
            .inspect_err(|e| log::debug!("failed to build vault: {e}"))
            .map_err(|_| Error::VaultFileKeyDecryptionError)?;
        self.state = VaultState::Unlocked {
            vault: Box::new(vault),
        };
        Ok(())
    }

    /// Drop the decrypted vault from memory, keeping only the name shown in the
    /// vault list. Reading items again requires `unlock`, and so a fresh
    /// authentication.
    pub fn lock(&mut self) {
        if let VaultState::Unlocked { vault } = &self.state {
            self.state = VaultState::Locked {
                name: vault.name.clone(),
            };
        }
    }

    fn get_unlocked_vault(&self) -> Result<&Vault, Error> {
        match &self.state {
            VaultState::Unlocked { vault } => Ok(vault),
            VaultState::Locked { .. } => Err(Error::VaultLocked),
        }
    }

    fn get_unlocked_vault_mut(&mut self) -> Result<&mut Vault, Error> {
        match &mut self.state {
            VaultState::Unlocked { vault } => Ok(vault),
            VaultState::Locked { .. } => Err(Error::VaultLocked),
        }
    }

    pub fn save(&self) -> Result<(), Error> {
        let Some(vault_dir) = self.path.parent() else {
            return Err(Error::VaultDirCreateError(io::Error::new(
                io::ErrorKind::NotFound,
                "Vault directory not found",
            )));
        };

        let vault = self.get_unlocked_vault()?;
        let encrypted_vault = vault.to_encrypted()?;
        let vault_data = serde_json::to_string_pretty(&encrypted_vault)
            .map_err(Error::VaultSerializationError)?;

        fs::create_dir_all(vault_dir).map_err(Error::VaultDirCreateError)?;
        fs::write(self.path.clone(), vault_data).map_err(Error::VaultWriteError)?;
        Ok(())
    }

    pub fn set_vault_key(&mut self, new_vault_key: String) -> Result<(), Error> {
        if !validate_key(&new_vault_key) {
            return Err(Error::InvalidVaultKey(new_vault_key));
        }

        let vault_dir = self
            .path
            .parent()
            .expect("Vault path has no parent directory");
        let new_path = vault_file_path(vault_dir, &new_vault_key)?;

        if let Err(err) = std::fs::rename(&self.path, &new_path) {
            return Err(Error::VaultKeyUpdateFailed(err));
        }

        self.key = new_vault_key;
        self.path = new_path;
        self.save()?;
        Ok(())
    }

    pub fn vault_name(&self) -> Option<&str> {
        match &self.state {
            VaultState::Locked { name } => name.as_deref(),
            VaultState::Unlocked { vault, .. } => vault.name.as_deref(),
        }
    }

    pub fn set_vault_name(&mut self, new_name: String) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.name = Some(new_name);
        Ok(())
    }

    pub fn list_items(&self) -> Result<Vec<&VaultItemOverview>, Error> {
        let vault = self.get_unlocked_vault()?;
        Ok(vault.list_items())
    }

    pub fn get_item_overview(&self, item_key: &str) -> Result<Option<&VaultItemOverview>, Error> {
        let vault = self.get_unlocked_vault()?;
        match vault.get_item(item_key) {
            Ok(item) => Ok(Some(item)),
            Err(Error::InvalidItemKey(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get or create an item by key. When the item already exists the
    /// item_title is ignored (consistent with how add_credential callers pass
    /// an empty title for existing items).
    pub fn add_item(
        &mut self,
        item_key: &str,
        item_title: &str,
    ) -> Result<&VaultItemOverview, Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.add_or_update_item(item_key, item_title)
    }

    pub fn delete_item(&mut self, item_key: &str) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.delete_item(item_key)
    }

    pub fn add_secret(
        &mut self,
        item_key: &str,
        cred_key: &str,
        cred_title: &str,
        cred_value: SecretString,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.add_or_update_item_credential(item_key, cred_key, cred_title, cred_value)?;
        Ok(())
    }

    pub fn get_secret(
        &self,
        item_key: &str,
        cred_key: &str,
    ) -> Result<Option<SecretBox<String>>, Error> {
        let vault = self.get_unlocked_vault()?;
        vault.get_item_credential_secret(item_key, cred_key)
    }

    pub fn get_secret_by_url(&self, url: Url) -> Result<Option<SecretBox<String>>, Error> {
        let mut segments = url
            .path_segments()
            .ok_or(Error::InvalidVaultItemReference("invalid url".to_string()))?;
        let item_key = segments.next().ok_or(Error::InvalidVaultItemReference(
            "missing item key".to_string(),
        ))?;
        let credential_key = segments.next().ok_or(Error::InvalidVaultItemReference(
            "missing credential key".to_string(),
        ))?;
        log::debug!("Parsed reference {item_key}/{credential_key}");
        self.get_secret(item_key, credential_key)
    }

    pub fn get_secret_overview(
        &self,
        item_key: &str,
        credential_key: &str,
    ) -> Result<Option<&VaultItemCredentialOverview>, Error> {
        let vault = self.get_unlocked_vault()?;
        match vault.get_item_credential(item_key, credential_key) {
            Ok(cred) => Ok(Some(cred)),
            Err(Error::InvalidCredentialKey(_)) | Err(Error::InvalidItemKey(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn delete_item_credential(&mut self, item_key: &str, cred_key: &str) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.delete_item_credential(item_key, cred_key)
    }
}

/// Export one or more unlocked vaults into a single bundle file. A random
/// bundle key is generated, each vault's file key is wrapped with it, and the
/// bundle key itself is protected once with `export_mode`. Every vault must be
/// unlocked.
pub fn export_bundle(
    vaults: &[&VaultWrapper],
    path: &Path,
    export_mode: ExportMode,
) -> Result<(), Error> {
    if vaults.is_empty() {
        return Err(Error::VaultExportError("No vaults to export".to_string()));
    }

    let bundle_id = Uuid::new_v4();
    let bundle_key = Aes256Gcm::generate_key(OsRng);
    let bundle_cipher = Aes256Gcm::new(&bundle_key);

    let mut bundled_vaults = Vec::with_capacity(vaults.len());
    for vw in vaults {
        let vault = vw.get_unlocked_vault()?;
        let key = (vw.key != DEFAULT_VAULT).then(|| vw.key.clone());
        bundled_vaults.push(vault.to_bundled_vault(key, bundle_id, &bundle_cipher)?);
    }

    let age_bundle_key = export_mode.encrypt(bundle_key.as_slice())?;

    let bundle = ExportedBundle {
        version: BUNDLE_VERSION,
        id: bundle_id,
        exported_at: OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc()),
        age_bundle_key,
        vaults: bundled_vaults,
    };

    let json = serde_json::to_string_pretty(&bundle).map_err(Error::VaultSerializationError)?;
    fs::write(path, json).map_err(Error::VaultWriteError)?;
    Ok(())
}

static WHITESPACE_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\s+").unwrap());

static VAULT_KEY_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z][a-z0-9-_]+[a-z0-9]$").unwrap());

pub fn validate_key(key: &str) -> bool {
    VAULT_KEY_REGEX.is_match(key)
}

pub fn normalized_key(key: &str) -> Option<String> {
    let normalized = WHITESPACE_REGEX
        .replace_all(&key.trim().to_lowercase(), "-")
        .to_string();
    if validate_key(&normalized) {
        Some(normalized)
    } else {
        None
    }
}

/// Check whether the shared authentication still covers the vault encryption
/// key, without prompting for it.
///
/// Being able to read the key authentication is still valid. A key that is
/// present but blocked means auth has lapsed. A key that is absent is not an
/// auth failure at all: it has yet to be created, and
/// `get_vault_encryption_key` will make one on the next unlock.
pub fn check_vault_auth_still_valid() -> Result<(), Error> {
    let result = probe_shared_context(|la_context| {
        ManagedKeyQuery::build()
            .with_label(VAULT_ENCRYPTION_KEY_LABEL)
            .with_key_class(KeyClass::Private)
            .one_with_retry(la_context, false)
    })
    .map_err(Error::VaultInvalidAuth)?;

    match result {
        Ok(_) => Ok(()),
        Err(KeychainError::ItemNotAccessible) => {
            log::debug!("Vault encryption key is gated; authentication has lapsed");
            Err(Error::VaultInvalidAuth(
                KeychainError::AuthenticationExpired,
            ))
        },
        Err(e) => Err(Error::VaultInvalidAuth(e)),
    }
}

pub fn get_vault_encryption_key() -> Result<ManagedKey, Error> {
    get_vault_encryption_key_on(AuthContext::SharedThreadLocal)
}

/// Read the vault encryption key on a specific [`AuthContext`], creating it if
/// it does not exist yet. Key creation runs on the same context, so the Secure
/// Enclave biometric prompt is drawn wherever the caller's context draws it.
///
/// A foreign context arrives already authenticated by the process that owns it,
/// so nothing is evaluated here: a second evaluation of the same context would
/// put a second prompt in front of the user for one request.
pub fn get_vault_encryption_key_on(auth_context: AuthContext) -> Result<ManagedKey, Error> {
    let reason = match Provenance::resolve_current_parent()
        .inspect(|provenance| log::debug!("get_vault_encryption_key: {provenance:#?}"))
        .and_then(|p| p.caller())
    {
        Some(parent) => format!("unlock the vault for {parent}"),
        None => "unlock the vault".to_string(),
    };
    let auth_method = match auth_context {
        AuthContext::Foreign(_) => AuthMethod::None,
        _ => AuthMethod::Policy { reason },
    };
    let key_result = run_on_auth_thread(auth_context.clone(), auth_method, move |la_context| {
        ManagedKeyQuery::build()
            .with_label(VAULT_ENCRYPTION_KEY_LABEL)
            .with_key_class(KeyClass::Private)
            .one(la_context)
    })
    .map_err(Error::KeyRetrievalFailed)?;

    match key_result {
        Ok(Some(user_encryption_key)) => Ok(user_encryption_key),
        Ok(None) => {
            log::debug!("Vault encryption key not found, initializing new key...");
            run_on_auth_thread(auth_context, AuthMethod::None, move |la_context| {
                ManagedKey::create_with_context(VAULT_ENCRYPTION_KEY_LABEL, Some(la_context))
            })
            .map_err(Error::KeyCreationFailed)?
            .map_err(Error::KeyCreationFailed)
        },
        Err(e) => Err(Error::KeyRetrievalFailed(e)),
    }
}
