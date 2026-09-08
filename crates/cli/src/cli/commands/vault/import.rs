use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use axo_pass_core::age::recipients::resolve_identity;
use axo_pass_core::secrets::vaults::VaultsManager;
use axo_pass_core::secrets::vaults::vault_export::{BundleVaultInfo, ImportIdentity};
use clap::{Parser, ValueHint};
use clml::cprintln;
use inquire::MultiSelect;
use uuid::Uuid;

use crate::cli::commands::vault::utils::{prompt_passphrase, read_age_identity_file};

#[derive(Parser, Debug)]
pub struct VaultImportCommand {
    /// Path to the export file to import
    #[arg(value_hint = ValueHint::FilePath)]
    import_path: PathBuf,

    /// Import only vaults matching this selector (its key, name, or id).
    /// Repeatable. Imports every vault if not given.
    #[arg(long = "vault")]
    select: Vec<String>,

    /// Rename a vault on import: --key <old>=<new>, where <old> is a selector
    /// (key, name, or id). Repeatable.
    #[arg(long = "key", value_parser = parse_key_override)]
    key_overrides: Vec<(String, String)>,

    /// Key to assign to the imported vault. Only allowed when the selection
    /// resolves to a single vault.
    vault_key: Option<String>,

    #[command(flatten)]
    import_encryption: ImportIdentityFlags,
}

impl VaultImportCommand {
    pub fn execute(&self) -> Result<(), String> {
        let import_identity = (&self.import_encryption).try_into()?;

        let mut vm = VaultsManager::new();
        let bundle = vm
            .open_bundle(&self.import_path, import_identity)
            .map_err(|e| format!("Failed to open bundle: {e}"))?;

        let infos = bundle.vaults();
        if infos.is_empty() {
            return Err("Bundle contains no vaults".to_string());
        }

        let selected: Vec<&BundleVaultInfo> = if !self.select.is_empty() {
            self.select
                .iter()
                .map(|sel| {
                    match_vault(&infos, sel)
                        .ok_or_else(|| format!("No vault in bundle matches '{sel}'"))
                })
                .collect::<Result<_, _>>()?
        } else if infos.len() == 1 {
            vec![&infos[0]]
        } else {
            select_vaults(&infos)?
        };

        if self.vault_key.is_some() && selected.len() != 1 {
            return Err(
                "A positional vault key is only allowed when importing a single vault; \
                 use --key <old>=<new>"
                    .to_string(),
            );
        }

        let mut selection: BTreeMap<Uuid, String> = BTreeMap::new();
        for info in &selected {
            let key = self.resolve_target_key(info);
            selection.insert(info.id, key);
        }

        let keys = vm
            .import_bundle(bundle, &selection)
            .map_err(|e| format!("Failed to import bundle: {e}"))?;

        for key in keys {
            cprintln!("Imported vault as <blue>{key}</blue>");
        }
        Ok(())
    }

    fn resolve_target_key(&self, info: &BundleVaultInfo) -> String {
        for (old, new) in &self.key_overrides {
            if vault_matches(info, old) {
                return new.clone();
            }
        }
        if let Some(key) = &self.vault_key {
            return key.clone();
        }
        if let Some(key) = &info.default_key {
            return key.clone();
        }
        format!("imported-{}", &Uuid::new_v4().simple().to_string()[..8])
    }
}

fn vault_matches(info: &BundleVaultInfo, selector: &str) -> bool {
    info.default_key.as_deref() == Some(selector)
        || info.name.as_deref() == Some(selector)
        || info.id.to_string() == selector
        || info.id.simple().to_string() == selector
}

fn match_vault<'a>(infos: &'a [BundleVaultInfo], selector: &str) -> Option<&'a BundleVaultInfo> {
    infos.iter().find(|info| vault_matches(info, selector))
}

fn bundle_label(info: &BundleVaultInfo) -> String {
    match (&info.name, &info.default_key) {
        (Some(name), Some(key)) => format!("{name} ({key})"),
        (Some(name), None) => format!("{name} [{}]", info.id.simple()),
        (None, Some(key)) => key.clone(),
        (None, None) => info.id.to_string(),
    }
}

fn select_vaults(infos: &[BundleVaultInfo]) -> Result<Vec<&BundleVaultInfo>, String> {
    let labels: Vec<String> = infos.iter().map(bundle_label).collect();
    let chosen: HashSet<String> = MultiSelect::new("Select vaults to import:", labels.clone())
        .prompt()
        .map_err(|e| format!("Selection cancelled: {e}"))?
        .into_iter()
        .collect();

    let picked: Vec<&BundleVaultInfo> = infos
        .iter()
        .zip(labels.iter())
        .filter(|(_, label)| chosen.contains(*label))
        .map(|(info, _)| info)
        .collect();

    if picked.is_empty() {
        return Err("No vaults selected".to_string());
    }
    Ok(picked)
}

fn parse_key_override(raw: &str) -> Result<(String, String), String> {
    let (old, new) = raw
        .split_once('=')
        .ok_or_else(|| format!("Expected <old>=<new>, got '{raw}'"))?;
    if old.is_empty() || new.is_empty() {
        return Err(format!("Both sides of '{raw}' must be non-empty"));
    }
    Ok((old.to_string(), new.to_string()))
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
