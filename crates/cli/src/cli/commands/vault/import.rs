use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use axo_pass_core::age::recipients::resolve_identity;
use axo_pass_core::core::app_broker::{self, BrokerError, WireImportIdentity};
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::secrets::vaults::VaultsManager;
use axo_pass_core::secrets::vaults::vault_export::{BundleVaultInfo, ImportIdentity};
use clap::{Parser, ValueHint};
use clml::cprintln;
use inquire::MultiSelect;
use secrecy::ExposeSecret;
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
        // Built once: sent over the broker socket, and converted locally to
        // open the bundle for the interactive selection.
        let wire_identity = self.import_encryption.wire_identity()?;
        let import_identity = ImportIdentity::try_from(wire_identity.clone())?;

        let mut vm = VaultsManager::new();
        let bundle = vm
            .open_bundle(&self.import_path, import_identity)
            .map_err(|e| format!("Failed to open bundle: {e}"))?;

        let infos = bundle.vaults();
        if infos.is_empty() {
            return Err("Bundle contains no vaults".to_string());
        }

        let mut selected: Vec<&BundleVaultInfo> = if !self.select.is_empty() {
            self.select
                .iter()
                .map(|sel| match_vault(&infos, sel))
                .collect::<Result<_, _>>()?
        } else if infos.len() == 1 {
            vec![&infos[0]]
        } else {
            select_vaults(&infos)?
        };

        // a selector repeated on the command line resolves to the same vault
        let mut seen_ids = HashSet::new();
        selected.retain(|info| seen_ids.insert(info.id));

        for (old, _) in &self.key_overrides {
            if !selected.iter().any(|info| vault_matches(info, old)) {
                return Err(format!("--key '{old}=...' matches no vault being imported"));
            }
        }

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

        let wire_selection: Vec<(String, String)> = selection
            .iter()
            .map(|(id, key)| (id.to_string(), key.clone()))
            .collect();

        let caller = Provenance::resolve_current_parent().and_then(|p| p.caller());
        // The app serves the request from its own working directory, so it
        // needs an absolute path to the bundle.
        let import_path_str = self
            .import_path
            .canonicalize()
            .unwrap_or_else(|_| self.import_path.clone())
            .to_string_lossy()
            .to_string();

        let keys = match app_broker::request_import_vaults(
            &import_path_str,
            wire_identity,
            &wire_selection,
            caller.as_deref(),
        ) {
            Ok(keys) => keys,
            Err(BrokerError::Unavailable) => vm
                .import_bundle(bundle, &selection)
                .map_err(|e| format!("Failed to import bundle: {e}"))?,
            Err(e) => return Err(format!("Failed to import bundle: {e}")),
        };

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

/// Resolve a selector to exactly one vault. Names and default keys are not
/// unique within a bundle, so an ambiguous selector is an error rather than a
/// silent pick of the first match.
fn match_vault<'a>(
    infos: &'a [BundleVaultInfo],
    selector: &str,
) -> Result<&'a BundleVaultInfo, String> {
    let mut matches = infos.iter().filter(|info| vault_matches(info, selector));
    let first = matches
        .next()
        .ok_or_else(|| format!("No vault in bundle matches '{selector}'"))?;
    if matches.next().is_some() {
        return Err(format!(
            "'{selector}' matches more than one vault in the bundle; select it by id"
        ));
    }
    Ok(first)
}

fn bundle_label(info: &BundleVaultInfo) -> String {
    match (&info.name, &info.default_key) {
        (Some(name), Some(key)) => format!("{name} ({key})"),
        (Some(name), None) => format!("{name} [{}]", info.id.simple()),
        (None, Some(key)) => key.clone(),
        (None, None) => info.id.to_string(),
    }
}

/// Labels for the picker. A bundle can hold two vaults with the same name and
/// key, so duplicates get their id appended. Without that, picking one would
/// match both.
fn unique_labels(infos: &[BundleVaultInfo]) -> Vec<String> {
    let base: Vec<String> = infos.iter().map(bundle_label).collect();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for label in &base {
        *counts.entry(label.as_str()).or_default() += 1;
    }
    base.iter()
        .zip(infos)
        .map(|(label, info)| {
            if counts[label.as_str()] > 1 {
                let id = info.id.simple();
                format!("{label} [{id}]")
            } else {
                label.clone()
            }
        })
        .collect()
}

fn select_vaults(infos: &[BundleVaultInfo]) -> Result<Vec<&BundleVaultInfo>, String> {
    let labels = unique_labels(infos);
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

    /// Decrypt with an age identity stored by Axo Pass (by name)
    #[arg(long)]
    identity: Option<String>,

    /// Decrypt with an age identity from a file (containing
    /// "AGE-SECRET-KEY-1...")
    #[arg(long)]
    identity_file: Option<String>,
}

impl ImportIdentityFlags {
    /// Resolve the flags into the identity form that crosses the broker socket.
    /// An age secret key travels as its `AGE-SECRET-KEY-1...` string, a
    /// passphrase as plain text.
    fn wire_identity(&self) -> Result<WireImportIdentity, String> {
        if let Some(name) = &self.identity {
            return Ok(WireImportIdentity::Identity {
                identity: resolve_managed_identity(name)?,
            });
        }
        if let Some(age_identity_file_path) = &self.identity_file {
            let age_identity = read_age_identity_file(age_identity_file_path)?;
            return Ok(WireImportIdentity::Identity {
                identity: age_identity.to_string().expose_secret().to_string(),
            });
        }
        if let Some(pass) = &self.passphrase {
            return Ok(WireImportIdentity::Passphrase {
                passphrase: pass.clone(),
            });
        }
        let passphrase = prompt_passphrase("Enter import passphrase:")?;
        Ok(WireImportIdentity::Passphrase {
            passphrase: passphrase.expose_secret().to_string(),
        })
    }
}

/// Unlock a managed age identity by name, returning its `AGE-SECRET-KEY-1...`
/// string. `ap` holds no keychain entitlements, so the app unlocks it behind a
/// biometric prompt. A build with no broker to reach unlocks from the keychain
/// directly.
fn resolve_managed_identity(name: &str) -> Result<String, String> {
    let caller = Provenance::resolve_current_parent().and_then(|p| p.caller());
    match app_broker::request_age_identity(name, caller.as_deref()) {
        Ok(secret) => Ok(secret.expose_secret().to_string()),
        Err(BrokerError::Failed(m)) if m.starts_with("No age key named") => {
            Err(format!("No age key named {name}"))
        },
        Err(BrokerError::Unavailable) => resolve_identity(name)
            .map(|id| id.to_string().expose_secret().to_string())
            .map_err(|e| format!("Failed to resolve identity '{name}': {e}")),
        Err(e) => Err(format!("Failed to resolve identity '{name}': {e}")),
    }
}
