use std::path::PathBuf;

use clap::{Parser, ValueHint};
use color_print::cprintln;

use crate::age::recipients::resolve_identity;
use crate::cli::commands::vault::utils::{prompt_passphrase, read_age_identity_file};
use crate::secrets::vaults::VaultsManager;
use crate::secrets::vaults::vault_export::ImportIdentity;

#[derive(Parser, Debug)]
pub struct VaultImportCommand {
    /// Path to the export file to import
    #[arg(value_hint = ValueHint::FilePath)]
    import_path: PathBuf,

    /// Key to assign to the imported vault (overrides key in export file)
    vault_key: Option<String>,

    #[command(flatten)]
    import_encryption: ImportIdentityFlags,
}

impl VaultImportCommand {
    pub fn execute(&self) -> Result<(), String> {
        let import_identity = (&self.import_encryption).try_into()?;

        let mut vm = VaultsManager::new();
        let vw = vm
            .import_vault(&self.import_path, import_identity, self.vault_key.clone())
            .map_err(|e| format!("Failed to import vault: {e}"))?;

        cprintln!("Imported vault as <blue>{}</blue>", vw.key);
        Ok(())
    }
}

#[derive(Parser, Debug, Default)]
#[group(required = false, multiple = false)]
struct ImportIdentityFlags {
    /// Decrypt with a passphrase (prompted if not given)
    #[arg(long)]
    passphrase: Option<String>,

    /// Decrypt with an age identity from the keychain
    #[arg(long)]
    identity: Option<String>,

    /// Decrypt with an age identity from a file (containing
    /// "AGE-SECRET-KEY-1...")
    #[arg(long)]
    identity_file: Option<String>,
}

impl TryInto<ImportIdentity> for &ImportIdentityFlags {
    type Error = String;

    fn try_into(self) -> Result<ImportIdentity, Self::Error> {
        if let Some(recipient_name) = &self.identity {
            let age_identity = resolve_identity(recipient_name)
                .map_err(|e| format!("Failed to resolve identity '{recipient_name}': {e}"))?;
            return Ok(ImportIdentity::Identity(age_identity));
        }
        if let Some(age_identity_file_path) = &self.identity_file {
            let age_identity = read_age_identity_file(age_identity_file_path)?;
            return Ok(ImportIdentity::Identity(age_identity));
        }
        if let Some(pass) = &self.passphrase {
            return Ok(ImportIdentity::Passphrase(pass.clone().into()));
        }
        let passphrase = prompt_passphrase("Enter import passphrase:")?;
        Ok(ImportIdentity::Passphrase(passphrase))
    }
}
