mod export_mode;
mod exported_vault;
mod import_identity;

#[cfg(test)]
mod tests;

use std::fs;
use std::io::{self};
use std::path::Path;

use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::vault::encrypted_vault::{EncryptedVault, VaultFileKey};
pub use crate::secrets::vaults::vault_export::export_mode::ExportMode;
pub use crate::secrets::vaults::vault_export::exported_vault::ExportedVault;
pub use crate::secrets::vaults::vault_export::import_identity::ImportIdentity;
use crate::secrets::vaults::vault_wrapper::{
    VaultWrapper, get_vault_encryption_key, normalized_key,
};

/// Import a vault from an export file. Decrypts the age-wrapped file key,
/// re-wraps it with the local Secure Enclave key, and saves it in the usual
/// vault directory as a normal vault.
pub fn import_vault<P: AsRef<Path>, Q: AsRef<Path>>(
    import_path: P,
    identity: ImportIdentity,
    vault_dir: Q,
    vault_key: Option<String>,
) -> Result<VaultWrapper, Error> {
    let import_path = import_path.as_ref();
    let vault_dir = vault_dir.as_ref();

    // read and parse the exported vault
    let data = fs::read_to_string(import_path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Error::VaultNotFound(import_path.display().to_string())
        } else {
            Error::VaultReadError(e)
        }
    })?;

    let exported: ExportedVault =
        serde_json::from_str(&data).map_err(Error::VaultDeserializationError)?;

    // resolve vault key from provided key or default
    let vault_key = vault_key
        .or_else(|| exported.default_key.clone())
        .ok_or_else(|| {
            Error::InvalidVaultKey(
                "No vault key provided and export file has no default key".to_string(),
            )
            .into()
        })?;

    // normalize and validate the key
    let vault_key = normalized_key(&vault_key).ok_or_else(|| Error::InvalidVaultKey(vault_key))?;

    // decrypt the age-wrapped file key
    let raw_key = identity.unwrap_file_key(&exported.age_file_key)?;

    // re-wrap with the local Secure Enclave key
    let managed_key = get_vault_encryption_key()?;
    let enc_file_key = VaultFileKey::Personal(
        managed_key
            .encrypt(&raw_key)
            .ok_or(Error::VaultFileKeyEncryptionError)?
            .into_bytes(),
    );

    // build a normal EncryptedVault and save it
    let encrypted_vault = EncryptedVault {
        id: exported.id,
        name: exported.name,
        file_key: enc_file_key,
        items: exported.items,
    };

    let vault_path = vault_dir.join(format!("{vault_key}.json"));
    let json =
        serde_json::to_string_pretty(&encrypted_vault).map_err(Error::VaultSerializationError)?;

    fs::create_dir_all(vault_dir).map_err(Error::VaultDirCreateError)?;
    fs::write(&vault_path, json).map_err(Error::VaultWriteError)?;

    VaultWrapper::load_from_path(Some(vault_key), &vault_path)
}
