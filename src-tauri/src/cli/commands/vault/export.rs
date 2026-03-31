use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::{Parser, ValueHint};
use color_print::cprintln;
use inquire::Select;

use crate::age::recipients::resolve_recipient;
use crate::cli::commands::vault::utils::prompt_passphrase;
use crate::secrets::vaults::VaultsManager;
use crate::secrets::vaults::vault_export::ExportMode;

const VAULT_EXTENSION: &str = "axovault";

#[derive(Parser, Debug)]
pub struct VaultExportCommand {
    /// Vault key of vault to export (default vault if not given)
    #[arg(long)]
    vault: Option<String>,

    /// Path to write the export file to (default: <vault_key>.axovault)
    #[arg(long, value_hint = ValueHint::FilePath)]
    #[arg(value_hint = ValueHint::FilePath)]
    export_path: Option<PathBuf>,

    #[command(flatten)]
    export_encryption: ExportModeFlags,
}

impl VaultExportCommand {
    pub fn execute(&self) -> Result<(), String> {
        let mut vm = VaultsManager::new();
        let vault_key = match self.vault {
            Some(ref k) => k.to_string(),
            None => select_vault(vm.vault_labels())?,
        };

        let vw = vm
            .get_vault_mut(&vault_key)
            .ok_or_else(|| format!("Vault not found: {vault_key}"))?;

        vw.unlock()
            .map_err(|e| format!("Failed to unlock vault: {e}"))?;

        let export_path = self
            .export_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("{vault_key}.{VAULT_EXTENSION}")));

        let output_path = PathBuf::from(&export_path);
        if output_path.exists() {
            return Err(format!(
                "File already exists: {}. Choose a different path or remove it first.",
                export_path.display()
            ));
        }
        let export_mode = (&self.export_encryption).try_into()?;
        vw.export(&output_path, export_mode)
            .map_err(|e| format!("Failed to export vault: {e}"))?;

        cprintln!(
            "Exported vault <blue>{vault_key}</blue> to <blue>{}</blue>",
            export_path.display()
        );
        Ok(())
    }
}

#[derive(Parser, Debug, Default)]
#[group(required = false, multiple = false)]
struct ExportModeFlags {
    /// Encrypt with a passphrase
    #[arg(long)]
    passphrase: Option<String>,

    /// Encrypt to a managed age recipient stored in the keychain (by name)
    #[arg(long)]
    recipient: Option<String>,

    /// Encrypt to an age recipient ("age1...")
    #[arg(long)]
    recipient_key: Option<String>,
}

impl TryInto<ExportMode> for &ExportModeFlags {
    type Error = String;

    fn try_into(self) -> Result<ExportMode, String> {
        if let Some(recipient_name) = &self.recipient {
            // Resolve a managed age recipient from the keychain by name
            let age_recipient = resolve_recipient(recipient_name)
                .map_err(|e| format!("Failed to resolve recipient '{recipient_name}': {e}"))?;
            return Ok(ExportMode::Recipient(age_recipient.to_string()));
        }
        if let Some(pubkey) = &self.recipient_key {
            return Ok(ExportMode::Recipient(pubkey.to_string()));
        }
        if let Some(pass) = &self.passphrase {
            return Ok(ExportMode::Passphrase(pass.clone().into()));
        }
        let passphrase = prompt_passphrase("Enter export passphrase:")
            .map_err(|e| format!("Failed to read passphrase: {e}"))?;
        Ok(ExportMode::Passphrase(passphrase))
    }
}

fn select_vault(vault_labels: BTreeMap<String, String>) -> Result<String, String> {
    if vault_labels.is_empty() {
        return Err("No vaults found".to_string());
    }
    let labels = vault_labels.keys().cloned().collect::<Vec<_>>();
    let selected = Select::new("Select a vault:", labels)
        .prompt()
        .map_err(|e| format!("Vault selection cancelled: {e}"))?
        .to_string();

    vault_labels
        .get(&selected)
        .cloned()
        .ok_or_else(|| "Failed to resolve selected vault".to_string())
}
