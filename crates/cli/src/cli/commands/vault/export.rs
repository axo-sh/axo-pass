use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use axo_pass_core::age::recipients::resolve_recipient;
use axo_pass_core::core::app_broker::{self, BrokerError, WireExportMode};
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::secrets::vaults::vault_export::{ExportMode, WorkFactor};
use axo_pass_core::secrets::vaults::{ExportProgress, VaultsManager};
use clap::{Parser, ValueHint};
use clml::cprintln;
use inquire::MultiSelect;
use secrecy::ExposeSecret;

use crate::cli::commands::vault::utils::prompt_passphrase;

const VAULT_EXTENSION: &str = "axovault";

#[derive(Parser, Debug)]
pub struct VaultExportCommand {
    /// Vault key to export. Repeatable. Prompts to choose if not given.
    #[arg(long = "vault")]
    vault: Vec<String>,

    /// Path to write the export file to (default: <vault_key>.axovault for one
    /// vault, vaults.axovault for more)
    #[arg(long, value_hint = ValueHint::FilePath)]
    export_path: Option<PathBuf>,

    #[command(flatten)]
    export_encryption: ExportModeFlags,

    /// Passphrase key-derivation cost: a preset (fast, balanced, secure,
    /// paranoid) or a scrypt log_n number (18-24). Default: secure. Ignored
    /// for recipient encryption.
    #[arg(long, default_value = "secure")]
    work_factor: String,
}

impl VaultExportCommand {
    pub fn execute(&self) -> Result<(), String> {
        let mut vm = VaultsManager::new();

        let mut vault_keys = if self.vault.is_empty() {
            select_vaults(vm.vault_labels())?
        } else {
            self.vault.clone()
        };
        // a repeated key would bundle the same vault id twice, which import
        // rejects
        let mut seen = HashSet::new();
        vault_keys.retain(|key| seen.insert(key.clone()));
        if vault_keys.is_empty() {
            return Err("No vaults selected".to_string());
        }

        let export_path = self.export_path.clone().unwrap_or_else(|| {
            if vault_keys.len() == 1 {
                PathBuf::from(format!("{}.{VAULT_EXTENSION}", vault_keys[0]))
            } else {
                PathBuf::from(format!("vaults.{VAULT_EXTENSION}"))
            }
        });

        if export_path.exists() {
            return Err(format!(
                "File already exists: {}. Choose a different path or remove it first.",
                export_path.display()
            ));
        }

        let work_factor = WorkFactor::parse(&self.work_factor)?;
        let export_mode = self.export_encryption.resolve(work_factor)?;
        if let ExportMode::Passphrase { work_factor, .. } = &export_mode {
            let hint = work_factor.cost_hint();
            cprintln!("<dim>Key derivation cost: {hint}</dim>");
        }

        let caller = Provenance::resolve_current_parent().and_then(|p| p.caller());
        // The app serves the request from its own working directory, so the
        // path it writes to must be absolute.
        let export_path_str = std::path::absolute(&export_path)
            .unwrap_or_else(|_| export_path.clone())
            .to_string_lossy()
            .to_string();

        match app_broker::request_export_vaults(
            &vault_keys,
            &export_path_str,
            wire_export_mode(&export_mode),
            caller.as_deref(),
        ) {
            Ok(_) => {},
            Err(BrokerError::Unavailable) => {
                Self::export_locally(&mut vm, &vault_keys, &export_path, export_mode)?
            },
            Err(e) => return Err(format!("Failed to export vaults: {e}")),
        }

        let count = vault_keys.len();
        let noun = if count == 1 { "vault" } else { "vaults" };
        let path = export_path.display();
        cprintln!("Exported <blue>{count}</blue> {noun} to <blue>{path}</blue>");
        Ok(())
    }

    fn export_locally(
        vm: &mut VaultsManager,
        vault_keys: &[String],
        export_path: &Path,
        export_mode: ExportMode,
    ) -> Result<(), String> {
        vm.export_bundle(vault_keys, export_path, export_mode, |p| match p {
            ExportProgress::Vault { index, total } => {
                cprintln!("<dim>Collecting vault {index}/{total}</dim>");
            },
            ExportProgress::DerivingKey => {
                cprintln!("<dim>Deriving key</dim>");
            },
            ExportProgress::Writing => {
                cprintln!("<dim>Writing bundle</dim>");
            },
        })
        .map_err(|e| format!("Failed to export vaults: {e}"))
    }
}

/// Resolve a managed age recipient by name to its `age1...` public string.
/// `ap` holds no keychain entitlements, so the recipient list comes from the
/// app; this raises no prompt, as only the public half is read. A build with no
/// broker to reach resolves from the keychain directly.
fn resolve_managed_recipient(name: &str) -> Result<String, String> {
    let caller = Provenance::resolve_current_parent().and_then(|p| p.caller());
    match app_broker::request_age_keys(caller.as_deref()) {
        Ok(keys) => keys
            .into_iter()
            .find(|k| k.name == name)
            .map(|k| k.recipient)
            .ok_or_else(|| format!("No age key named {name}")),
        Err(BrokerError::Unavailable) => resolve_recipient(name)
            .map(|r| r.to_string())
            .map_err(|e| format!("Failed to resolve recipient '{name}': {e}")),
        Err(e) => Err(format!("Failed to resolve recipient '{name}': {e}")),
    }
}

/// Split a resolved [`ExportMode`] into the form that crosses the broker
/// socket. The passphrase work factor travels as its resolved scrypt `log_n`.
fn wire_export_mode(mode: &ExportMode) -> WireExportMode {
    match mode {
        ExportMode::Passphrase {
            passphrase,
            work_factor,
        } => WireExportMode::Passphrase {
            passphrase: passphrase.expose_secret().to_string(),
            work_factor: work_factor.log_n(),
        },
        ExportMode::Recipient(recipient) => WireExportMode::Recipient {
            recipient: recipient.clone(),
        },
    }
}

#[derive(Parser, Debug, Default)]
#[group(required = false, multiple = false)]
struct ExportModeFlags {
    /// Encrypt with a passphrase
    #[arg(long)]
    passphrase: Option<String>,

    /// Encrypt to a managed age recipient stored by Axo Pass (by name)
    #[arg(long)]
    recipient: Option<String>,

    /// Encrypt to an age recipient ("age1...")
    #[arg(long)]
    recipient_key: Option<String>,
}

impl ExportModeFlags {
    fn resolve(&self, work_factor: WorkFactor) -> Result<ExportMode, String> {
        if let Some(recipient_name) = &self.recipient {
            return Ok(ExportMode::Recipient(resolve_managed_recipient(
                recipient_name,
            )?));
        }
        if let Some(pubkey) = &self.recipient_key {
            return Ok(ExportMode::Recipient(pubkey.to_string()));
        }
        let passphrase = if let Some(pass) = &self.passphrase {
            pass.clone().into()
        } else {
            prompt_passphrase("Enter passphrase to encrypt the exported vaults:")
                .map_err(|e| format!("Failed to read passphrase: {e}"))?
        };
        Ok(ExportMode::Passphrase {
            passphrase,
            work_factor,
        })
    }
}

fn select_vaults(vault_labels: BTreeMap<String, String>) -> Result<Vec<String>, String> {
    if vault_labels.is_empty() {
        return Err("No vaults found".to_string());
    }
    let labels = vault_labels.keys().cloned().collect::<Vec<_>>();
    let selected = MultiSelect::new("Select vaults to export:", labels)
        .prompt()
        .map_err(|e| format!("Vault selection cancelled: {e}"))?;

    selected
        .into_iter()
        .map(|label| {
            vault_labels
                .get(&label)
                .cloned()
                .ok_or_else(|| format!("Failed to resolve selected vault '{label}'"))
        })
        .collect()
}
