use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use jiff::tz::TimeZone;
use secrecy::{SecretBox, SecretString};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::{self, Action, AuditEvent, Outcome, Subject, SubjectIds, SubjectKind};
use crate::core::auth::{AuthContext, AuthMethod, probe_shared_context, run_on_auth_thread};
use crate::core::provenance::Provenance;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::keychain_query::KeychainQuery;
use crate::secrets::keychain::managed_key::{KeyClass, KeyPolicy, ManagedKey, ManagedKeyQuery};
use crate::secrets::vaults::autofill::item::ItemAutofill;
use crate::secrets::vaults::bundle::ExportMode;
use crate::secrets::vaults::bundle::exported_bundle::{BUNDLE_VERSION, ExportedBundle};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultHeader};
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::model::{
    CredentialPlacement, CredentialUpdate, DeletedCredentialEntry, DeletedItemOverview,
    HistoryOverview, UnlockedKey, Vault, VaultFolder, VaultItemCredentialOverview,
    VaultItemOverview, VaultItemSection,
};
use crate::secrets::vaults::passkey::signals::{self, SignalStore};
use crate::secrets::vaults::storage::txn::VaultLocks;

pub const DEFAULT_VAULT: &str = "default";

/// Progress events emitted during [`export_bundle`]. The key derivation step is
/// a single opaque scrypt call with no sub-progress, so it is reported as one
/// event before it starts.
#[derive(Clone, Copy, Debug)]
pub enum ExportProgress {
    /// Collecting and wrapping vault `index` of `total` (1-based).
    Vault { index: usize, total: usize },
    /// Deriving the passphrase key. This is the slow step for a passphrase
    /// export.
    DerivingKey,
    /// Writing the bundle file.
    Writing,
}

const VAULT_ENCRYPTION_KEY_LABEL: &str = "vault-encryption-key";

enum VaultState {
    Locked { name: Option<String> },
    Unlocked { vault: Box<Vault> },
}

// in-memory representation of a vault
pub struct VaultHandle {
    pub key: String,
    pub path: PathBuf,
    state: VaultState,
}

fn vault_file_path(vault_dir: &Path, vault_key: &str) -> Result<PathBuf, Error> {
    let vault_key =
        normalized_key(vault_key).ok_or_else(|| Error::InvalidVaultKey(vault_key.to_string()))?;
    Ok(vault_dir.join(format!("{vault_key}.json")))
}

impl VaultHandle {
    /// A new, unlocked vault that is not written yet. Write it with
    /// [`super::txn::VaultWriter::create`].
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
        Ok(Self::unlocked(vault_key, vault_path, vault_overview))
    }

    pub(crate) fn unlocked(key: String, path: PathBuf, vault: Vault) -> Self {
        Self {
            key,
            path,
            state: VaultState::Unlocked {
                vault: Box::new(vault),
            },
        }
    }

    /// An unlocked, empty vault that is never written to disk.
    #[cfg(test)]
    pub(crate) fn new_for_test(vault_key: &str) -> Self {
        Self::new_for_test_at(PathBuf::from(format!("/nonexistent/{vault_key}.json")))
    }

    /// An unlocked, empty vault at `path`, not yet written.
    #[cfg(test)]
    pub(crate) fn new_for_test_at(path: PathBuf) -> Self {
        let key = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        Self::unlocked(key, path, Vault::new_for_test())
    }

    pub fn load(
        vault_dir: &Path,
        vault_key: Option<String>,
        locks: &VaultLocks,
    ) -> Result<Self, Error> {
        let vault_key = vault_key.unwrap_or(DEFAULT_VAULT.to_string());
        let vault_path = vault_file_path(vault_dir, &vault_key)?;
        Self::load_from_path(Some(vault_key), &vault_path, locks)
    }

    /// Load a locked vault and record its path in `locks`.
    pub fn load_from_path(
        vault_key: Option<String>,
        vault_path: &Path,
        locks: &VaultLocks,
    ) -> Result<Self, Error> {
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
        locks.track(vault.id, vault_path);

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

    /// Contents of the vault file for the unlocked vault.
    pub(crate) fn file_contents(&self) -> Result<String, Error> {
        let vault = self.get_unlocked_vault()?;
        let encrypted_vault = vault.to_encrypted(true)?;
        serde_json::to_string_pretty(&encrypted_vault).map_err(Error::VaultSerializationError)
    }

    /// File key of the unlocked vault, for a transaction that reloads it.
    pub(crate) fn unlocked_key(&self) -> Result<UnlockedKey, Error> {
        Ok(self.get_unlocked_vault()?.unlocked_key())
    }

    /// Replace the unlocked vault, as when a retained version is restored.
    pub(crate) fn replace_vault(&mut self, vault: Vault) {
        self.state = VaultState::Unlocked {
            vault: Box::new(vault),
        };
    }

    /// Change the vault key, and so the file name. The transaction that runs
    /// this moves the file when it saves.
    pub fn set_vault_key(&mut self, new_vault_key: String) -> Result<(), Error> {
        if !validate_key(&new_vault_key) {
            return Err(Error::InvalidVaultKey(new_vault_key));
        }

        let vault_dir = self
            .path
            .parent()
            .ok_or_else(|| Error::VaultNotFound(self.path.display().to_string()))?;
        self.path = vault_file_path(vault_dir, &new_vault_key)?;
        self.key = new_vault_key;
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

    pub fn list_deleted_items(&self) -> Result<Vec<DeletedItemOverview<'_>>, Error> {
        let vault = self.get_unlocked_vault()?;
        Ok(vault.list_deleted_items())
    }

    pub fn restore_item(&mut self, item_id: Uuid, new_key: Option<String>) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.restore_item(item_id, new_key)?;
        Ok(())
    }

    pub fn purge_item(&mut self, item_id: Uuid) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.purge_item(item_id)
    }

    /// Purge every deleted item deleted before `older_than`, a Unix timestamp
    /// in seconds.
    pub fn purge_deleted_items(&mut self, older_than: i64) -> Result<usize, Error> {
        let vault = self.get_unlocked_vault_mut()?;
        Ok(vault.purge_deleted_items(older_than))
    }

    pub fn add_secret(
        &mut self,
        item_key: &str,
        cred_key: &str,
        cred_title: &str,
        cred_kind: FieldKind,
        cred_value: SecretString,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault
            .add_or_update_item_credential(item_key, cred_key, cred_title, cred_kind, cred_value)?;
        Ok(())
    }

    /// Add a credential. Fails if the key is already taken in the item.
    pub fn add_new_secret(
        &mut self,
        item_key: &str,
        cred_key: &str,
        cred_title: &str,
        cred_kind: FieldKind,
        cred_value: SecretString,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.add_item_credential(item_key, cred_key, cred_title, cred_kind, cred_value)?;
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

    /// Previous values of a credential, most recently replaced first.
    pub fn list_history(
        &self,
        item_key: &str,
        cred_key: &str,
    ) -> Result<Vec<HistoryOverview>, Error> {
        let vault = self.get_unlocked_vault()?;
        vault.list_history(item_key, cred_key)
    }

    pub fn get_history_value(
        &self,
        item_key: &str,
        cred_key: &str,
        history_id: Uuid,
    ) -> Result<SecretBox<String>, Error> {
        let vault = self.get_unlocked_vault()?;
        vault.get_history_value(item_key, cred_key, history_id)
    }

    /// Make a previous value the current value.
    pub fn restore_history_value(
        &mut self,
        item_key: &str,
        cred_key: &str,
        history_id: Uuid,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.restore_history_value(item_key, cred_key, history_id)
    }

    /// Delete a previous value permanently.
    pub fn purge_history(
        &mut self,
        item_key: &str,
        cred_key: &str,
        history_id: Uuid,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.purge_history(item_key, cred_key, history_id)
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

    /// Change the key, title, or kind of a credential. The value is unchanged.
    pub fn update_credential(
        &mut self,
        item_key: &str,
        cred_key: &str,
        update: CredentialUpdate,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.update_item_credential(item_key, cred_key, update)?;
        Ok(())
    }

    /// Record a use of a credential at `at`, in the system time zone. See
    /// [`Self::mark_credential_used_in`].
    pub fn mark_credential_used(
        &mut self,
        item_key: &str,
        cred_key: &str,
        at: i64,
    ) -> Result<bool, Error> {
        self.mark_credential_used_in(item_key, cred_key, at, &TimeZone::system())
    }

    /// Record a use of a credential at `at`. Writes only if no use is stored,
    /// or if the stored use falls on an earlier date in `zone`. The value is
    /// unchanged. Returns whether the time was written.
    pub fn mark_credential_used_in(
        &mut self,
        item_key: &str,
        cred_key: &str,
        at: i64,
        zone: &TimeZone,
    ) -> Result<bool, Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.mark_credential_used(item_key, cred_key, at, zone)
    }

    pub fn delete_item_credential(&mut self, item_key: &str, cred_key: &str) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.delete_item_credential(item_key, cred_key)
    }

    /// Deleted credentials of all live items, most recently deleted first.
    pub fn list_all_deleted(&self) -> Result<Vec<DeletedCredentialEntry<'_>>, Error> {
        let vault = self.get_unlocked_vault()?;
        Ok(vault.list_all_deleted())
    }

    /// Secret of a deleted credential, or of a credential in a deleted item.
    pub fn get_deleted_secret(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
    ) -> Result<SecretBox<String>, Error> {
        let vault = self.get_unlocked_vault()?;
        vault.get_deleted_credential_secret(item_id, cred_id)
    }

    pub fn restore_item_credential(
        &mut self,
        item_key: &str,
        cred_id: Uuid,
        new_key: Option<String>,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.restore_item_credential(item_key, cred_id, new_key)?;
        Ok(())
    }

    pub fn purge_item_credential(&mut self, item_key: &str, cred_id: Uuid) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.purge_item_credential(item_key, cred_id)
    }

    /// Purge every deleted credential deleted before
    /// `older_than`, a Unix timestamp in seconds.
    pub fn purge_deleted(&mut self, older_than: i64) -> Result<usize, Error> {
        let vault = self.get_unlocked_vault_mut()?;
        Ok(vault.purge_deleted(older_than))
    }

    pub fn set_item_category(
        &mut self,
        item_key: &str,
        category: Option<String>,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.set_item_category(item_key, category)
    }

    pub fn set_item_autofill(
        &mut self,
        item_key: &str,
        autofill: ItemAutofill,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.set_item_autofill(item_key, autofill)
    }

    pub fn get_item_overview_by_id(
        &self,
        item_id: Uuid,
    ) -> Result<Option<&VaultItemOverview>, Error> {
        let vault = self.get_unlocked_vault()?;
        match vault.get_item_by_id(item_id) {
            Ok(item) => Ok(Some(item)),
            Err(Error::InvalidItemKey(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_secret_by_id(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
    ) -> Result<Option<SecretBox<String>>, Error> {
        let vault = self.get_unlocked_vault()?;
        match vault.get_item_credential_secret_by_id(item_id, cred_id) {
            Ok(secret) => Ok(secret),
            Err(Error::InvalidCredentialKey(_)) | Err(Error::InvalidItemKey(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// This vault's id, the first segment of a record identifier.
    pub fn vault_id(&self) -> Result<Uuid, Error> {
        Ok(self.get_unlocked_vault()?.id())
    }

    /// This vault's id. A locked vault is read from its file header, without
    /// verifying it.
    pub fn peek_vault_id(&self) -> Result<Uuid, Error> {
        match self.vault_id() {
            Err(Error::VaultLocked) => Ok(VaultHeader::peek(&self.path)?.id),
            other => other,
        }
    }

    /// Audit ids of this vault and of item `item_key`. The item id is `None` if
    /// there is no such item.
    pub fn item_ids(&self, item_key: &str) -> Result<SubjectIds, Error> {
        let vault_id = self.vault_id()?;
        Ok(match self.get_item_overview(item_key)? {
            Some(item) => SubjectIds::item(vault_id, item.id),
            None => SubjectIds::vault(vault_id),
        })
    }

    /// Audit ids of this vault, item `item_key`, and its credential
    /// `cred_key`. Ids of entities that do not exist are `None`.
    pub fn credential_ids(&self, item_key: &str, cred_key: &str) -> Result<SubjectIds, Error> {
        let ids = self.item_ids(item_key)?;
        Ok(SubjectIds {
            credential_id: self.get_secret_overview(item_key, cred_key)?.map(|c| c.id),
            ..ids
        })
    }

    /// Reorder an item's credentials, keeping each in its current section.
    pub fn reorder_credentials(
        &mut self,
        item_key: &str,
        ordered_cred_keys: &[String],
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        let placements = ordered_cred_keys
            .iter()
            .map(|key| {
                let section = match vault.get_item_credential(item_key, key) {
                    Ok(cred) => cred.section,
                    // Unknown keys are reported by reorder_item_credentials.
                    Err(_) => None,
                };
                CredentialPlacement {
                    key: key.clone(),
                    section,
                }
            })
            .collect::<Vec<_>>();
        vault.reorder_item_credentials(item_key, &placements)
    }

    /// Reorder an item's credentials and set each one's section.
    pub fn arrange_credentials(
        &mut self,
        item_key: &str,
        placements: &[CredentialPlacement],
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.reorder_item_credentials(item_key, placements)
    }

    pub fn move_credential(
        &mut self,
        item_key: &str,
        cred_key: &str,
        section_id: Option<Uuid>,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.move_item_credential(item_key, cred_key, section_id)
    }

    /// Move a credential to another item, with its value and previous values.
    /// See [`Vault::transfer_item_credential`].
    pub fn transfer_credential(
        &mut self,
        item_key: &str,
        cred_key: &str,
        dest_item_key: &str,
        new_key: &str,
        section_id: Option<Uuid>,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.transfer_item_credential(item_key, cred_key, dest_item_key, new_key, section_id)?;
        Ok(())
    }

    pub fn list_folders(&self) -> Result<Vec<&VaultFolder>, Error> {
        let vault = self.get_unlocked_vault()?;
        Ok(vault.list_folders())
    }

    /// Site reports about the passkeys in this vault, combined with the reports
    /// not yet written into the vaults.
    pub fn passkey_signals(&self) -> Result<SignalStore, Error> {
        let vault = self.get_unlocked_vault()?;
        Ok(signals::effective(vault.passkey_signals()))
    }

    /// Change the site reports stored in this vault. The caller saves.
    pub fn update_passkey_signals<R>(
        &mut self,
        change: impl FnOnce(&mut SignalStore) -> R,
    ) -> Result<R, Error> {
        let vault = self.get_unlocked_vault_mut()?;
        Ok(vault.update_passkey_signals(change))
    }

    pub fn create_folder(&mut self, title: &str) -> Result<&VaultFolder, Error> {
        let vault = self.get_unlocked_vault_mut()?;
        Ok(vault.create_folder(title))
    }

    pub fn rename_folder(&mut self, folder_id: Uuid, title: &str) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.rename_folder(folder_id, title)
    }

    pub fn delete_folder(&mut self, folder_id: Uuid) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.delete_folder(folder_id)
    }

    pub fn reorder_folders(&mut self, ordered_folder_ids: &[Uuid]) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.reorder_folders(ordered_folder_ids)
    }

    pub fn move_item(&mut self, item_key: &str, folder_id: Option<Uuid>) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.move_item(item_key, folder_id)
    }

    pub fn create_item_section(
        &mut self,
        item_key: &str,
        title: &str,
    ) -> Result<&VaultItemSection, Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.create_item_section(item_key, title)
    }

    pub fn rename_item_section(
        &mut self,
        item_key: &str,
        section_id: Uuid,
        title: &str,
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.rename_item_section(item_key, section_id, title)
    }

    pub fn delete_item_section(&mut self, item_key: &str, section_id: Uuid) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.delete_item_section(item_key, section_id)
    }

    pub fn reorder_item_sections(
        &mut self,
        item_key: &str,
        ordered_section_ids: &[Uuid],
    ) -> Result<(), Error> {
        let vault = self.get_unlocked_vault_mut()?;
        vault.reorder_item_sections(item_key, ordered_section_ids)
    }
}

/// Export one or more unlocked vaults into a single bundle file. A random
/// bundle key is generated, each vault's file key is wrapped with it, and the
/// bundle key itself is protected once with `export_mode`. Every vault must be
/// unlocked. Passkeys are left out of the bundle unless `include_passkeys` is
/// set.
pub fn export_bundle(
    vaults: &[&VaultHandle],
    path: &Path,
    export_mode: ExportMode,
    include_passkeys: bool,
    mut progress: impl FnMut(ExportProgress),
) -> Result<(), Error> {
    if vaults.is_empty() {
        return Err(Error::VaultExportError("No vaults to export".to_string()));
    }

    let bundle_id = Uuid::new_v4();
    let bundle_key = Aes256Gcm::generate_key(OsRng);
    let bundle_cipher = Aes256Gcm::new(&bundle_key);

    let total = vaults.len();
    let mut bundled_vaults = Vec::with_capacity(total);
    for (i, vw) in vaults.iter().enumerate() {
        progress(ExportProgress::Vault {
            index: i + 1,
            total,
        });
        let vault = vw.get_unlocked_vault()?;
        let key = (vw.key != DEFAULT_VAULT).then(|| vw.key.clone());
        bundled_vaults.push(vault.to_bundled_vault(
            key,
            bundle_id,
            &bundle_cipher,
            include_passkeys,
        )?);
    }

    progress(ExportProgress::DerivingKey);
    let age_bundle_key = export_mode.encrypt(bundle_key.as_slice())?;

    progress(ExportProgress::Writing);

    let bundle = ExportedBundle {
        version: BUNDLE_VERSION,
        id: bundle_id,
        exported_at: OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc()),
        age_bundle_key,
        vaults: bundled_vaults,
    };

    let json = serde_json::to_string_pretty(&bundle).map_err(Error::VaultSerializationError)?;
    fs::write(path, json).map_err(Error::VaultWriteError)?;

    let bundle_id = bundle_id.to_string();
    for vw in vaults {
        audit::record(
            AuditEvent::new(
                audit::process_source(),
                Action::VaultExported,
                Outcome::Succeeded,
            )
            .subject(
                Subject::new(SubjectKind::Vault, vw.key.clone())
                    .maybe_label(vw.vault_name().map(str::to_string)),
            )
            .subject_ids(SubjectIds {
                vault_id: vw.vault_id().ok(),
                ..SubjectIds::default()
            })
            .detail("bundle", bundle_id.clone())
            .detail("vault_count", total.to_string()),
        );
    }
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
                ManagedKey::create_with_context(
                    VAULT_ENCRYPTION_KEY_LABEL,
                    KeyPolicy::AlwaysRequireAuth,
                    Some(la_context),
                )
            })
            .map_err(Error::KeyCreationFailed)?
            .map_err(Error::KeyCreationFailed)
        },
        Err(e) => Err(Error::KeyRetrievalFailed(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_ids_name_the_vault_item_and_credential_that_exist() {
        let mut vw = VaultHandle::new_for_test("personal");
        vw.add_item("item", "Item").unwrap();
        vw.add_secret(
            "item",
            "cred",
            "Cred",
            FieldKind::default(),
            SecretString::from("value".to_string()),
        )
        .unwrap();
        let vault_id = vw.vault_id().unwrap();
        let item_id = vw.get_item_overview("item").unwrap().unwrap().id;
        let cred_id = vw.get_secret_overview("item", "cred").unwrap().unwrap().id;

        assert_eq!(
            vw.credential_ids("item", "cred").unwrap(),
            SubjectIds::credential(vault_id, item_id, cred_id)
        );
        assert_eq!(
            vw.credential_ids("item", "missing").unwrap(),
            SubjectIds::item(vault_id, item_id)
        );
        assert_eq!(vw.item_ids("missing").unwrap(), SubjectIds::vault(vault_id));
    }
}
