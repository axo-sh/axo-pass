use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use axo_pass_core::core::app_broker::{self, BrokerError, WireImportIdentity, WireImportSelection};
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::secrets::vaults::bundle::{
    BundleVaultInfo, ImportAction, ImportIdentity, ImportableBundle,
};
use axo_pass_core::secrets::vaults::{ShortId, VaultCatalog};
use clap::{Parser, ValueEnum, ValueHint};
use clml::cprintln;
use inquire::{MultiSelect, Select};
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::cli::commands::vault::import_1password::{OnePasswordImport, is_item_export};
use crate::cli::commands::vault::utils::{prompt_passphrase, read_age_identity_file};

#[derive(Parser, Debug)]
pub struct VaultImportCommand {
    /// Path to the export file to import. A 1Password `.1pif` export or an
    /// Apple Passwords `.csv` export is detected and imported as items.
    #[arg(value_hint = ValueHint::AnyPath)]
    import_path: PathBuf,

    /// Import only vaults matching this selector (its key, name, or id).
    /// Repeatable. Imports every vault if not given.
    #[arg(long = "vault")]
    select: Vec<String>,

    /// Item export only: name of the new vault. Defaults to "1Password" or
    /// "Apple Passwords".
    #[arg(long, conflicts_with = "into")]
    name: Option<String>,

    /// Item export only: key of an existing vault to import into. Creates
    /// no vault.
    #[arg(long)]
    into: Option<String>,

    /// Item export only: import items that 1Password marked as trashed.
    #[arg(long)]
    include_trashed: bool,

    /// Item export only: show the summary and write nothing, as if the
    /// confirmation were answered no.
    #[arg(long)]
    dry_run: bool,

    /// Item export only: import without asking for confirmation.
    #[arg(short, long)]
    yes: bool,

    /// Item export only: show the full report, with the data that is not
    /// imported, instead of the summary.
    #[arg(short, long)]
    verbose: bool,

    /// Rename a vault on import: --key <old>=<new>, where <old> is a selector
    /// (key, name, or id). Repeatable.
    #[arg(long = "key", value_parser = parse_key_override)]
    key_overrides: Vec<(String, String)>,

    /// Key to assign to the imported vault. Only allowed when the selection
    /// resolves to a single vault.
    vault_key: Option<String>,

    /// What to do with each selected vault whose id already exists on this
    /// Mac. Asks for each such vault if not given.
    #[arg(long, value_enum)]
    existing: Option<ExistingChoice>,

    #[command(flatten)]
    import_encryption: ImportIdentityFlags,
}

impl VaultImportCommand {
    /// The 1Password import this command describes, or `None` if the path is
    /// a vault bundle. Options of the other kind of import are an error.
    pub(super) fn one_password(&self) -> Result<Option<OnePasswordImport>, String> {
        if !is_item_export(&self.import_path) {
            if self.name.is_some()
                || self.into.is_some()
                || self.include_trashed
                || self.dry_run
                || self.yes
                || self.verbose
            {
                return Err(
                    "--name, --into, --include-trashed, --dry-run, --yes, and --verbose apply \
                     only to a 1Password .1pif export or an Apple Passwords .csv export"
                        .to_string(),
                );
            }
            return Ok(None);
        }
        if !self.select.is_empty()
            || !self.key_overrides.is_empty()
            || self.vault_key.is_some()
            || self.existing.is_some()
            || self.import_encryption.is_set()
        {
            return Err(
                "--vault, --key, a vault key, --existing, and the decryption options do not \
                 apply to a 1Password .1pif or Apple Passwords .csv export. Use --into to import into an existing vault."
                    .to_string(),
            );
        }
        Ok(Some(OnePasswordImport {
            path: self.import_path.clone(),
            name: self.name.clone(),
            vault: self.into.clone(),
            include_trashed: self.include_trashed,
            dry_run: self.dry_run,
            yes: self.yes,
            verbose: self.verbose,
        }))
    }

    pub fn execute(&self) -> Result<(), String> {
        if let Some(import) = self.one_password()? {
            return import.execute();
        }

        // Built once: sent over the broker socket, and converted locally to
        // open the bundle for the interactive selection.
        let wire_identity = self.import_encryption.wire_identity()?;
        let import_identity = ImportIdentity::try_from(wire_identity.clone())?;

        let bundle = ImportableBundle::open(&self.import_path, import_identity)
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

        // A vault whose id a vault file on this Mac holds cannot be imported
        // under its id. Each one is imported as a copy or left out.
        let catalog = VaultCatalog::app();
        let existing = catalog.existing_ids(selected.iter().map(|info| info.id));
        let mut selection: Vec<WireImportSelection> = Vec::with_capacity(selected.len());
        for info in &selected {
            let mut key = self.resolve_target_key(info);
            let mut action = ImportAction::Default;
            if info.missing_files > 0 {
                let label = bundle_label(info);
                let (missing, files) = (info.missing_files, info.files);
                cprintln!(
                    "<yellow>{label}: {missing} of {files} files are not in the bundle. \
                     Their records are imported and the files read as missing.</yellow>"
                );
            }
            if existing.contains(&info.id) {
                // The blobs of a file are bound to the vault id, so a copy
                // cannot read them. Core refuses the copy as well.
                if info.files > 0 {
                    if self.existing == Some(ExistingChoice::Skip) {
                        continue;
                    }
                    let label = bundle_label(info);
                    let files = info.files;
                    return Err(format!(
                        "{label} holds {files} files and its id exists on this Mac, so it cannot \
                         be imported as a copy. Leave it out with --existing skip, or remove \
                         the vault on this Mac first."
                    ));
                }
                if self.existing_choice(info)? == ExistingChoice::Skip {
                    continue;
                }
                action = ImportAction::Copy;
                if !self.key_given(info) {
                    let taken: Vec<&String> = selection.iter().map(|s| &s.key).collect();
                    key = copy_key(&catalog, &key, &taken);
                }
            }
            selection.push(WireImportSelection {
                id: ShortId::encode_uuid(info.id),
                key,
                action,
            });
        }
        if selection.is_empty() {
            cprintln!("Nothing to import, every selected vault was skipped");
            return Ok(());
        }

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
            selection,
            caller.as_deref(),
        ) {
            Ok(keys) => keys,
            Err(e) => return Err(format!("Failed to import bundle: {e}")),
        };

        for key in keys {
            cprintln!("Imported vault as <blue>{key}</blue>");
        }
        Ok(())
    }

    /// Choice for a selected vault whose id exists on this Mac. Read from
    /// `--existing`, or asked for if it is not given.
    fn existing_choice(&self, info: &BundleVaultInfo) -> Result<ExistingChoice, String> {
        if let Some(existing) = self.existing {
            return Ok(existing);
        }
        let label = bundle_label(info);
        let options = vec![EXISTING_COPY, EXISTING_SKIP];
        let answer = Select::new(
            &format!("A vault with the id of {label} is already on this Mac:"),
            options,
        )
        .prompt()
        .map_err(|e| format!("Selection cancelled: {e}"))?;
        Ok(if answer == EXISTING_COPY {
            ExistingChoice::Copy
        } else {
            ExistingChoice::Skip
        })
    }

    /// Whether the target key of `info` was given on the command line.
    fn key_given(&self, info: &BundleVaultInfo) -> bool {
        self.vault_key.is_some()
            || self
                .key_overrides
                .iter()
                .any(|(old, _)| vault_matches(info, old))
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

const EXISTING_COPY: &str = "Import as a copy with a new id";
const EXISTING_SKIP: &str = "Skip";

/// What to do with a selected vault whose id already exists on this Mac.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ExistingChoice {
    /// Import it under a new id.
    Copy,
    /// Leave it out.
    Skip,
}

/// Key for a copy of a vault that would be imported as `key`. The bundle key
/// is usually the key of the vault the copy was made from, so the copy takes
/// `{key}-copy`, or `{key}-copy-{n}` if a vault file or another vault of this
/// import claims that key.
fn copy_key(catalog: &VaultCatalog, key: &str, taken: &[&String]) -> String {
    let base = format!("{key}-copy");
    (1..)
        .map(|n| {
            if n == 1 {
                base.clone()
            } else {
                format!("{base}-{n}")
            }
        })
        .find_map(|candidate| {
            catalog
                .unclaimed_key(&candidate, None)
                .ok()
                .filter(|key| !taken.contains(&key))
        })
        .unwrap_or(base)
}

/// Whether `selector` is the default key, the name, or the id of the vault. An
/// id selector is a short id or a 32 or 36 character hex id.
fn vault_matches(info: &BundleVaultInfo, selector: &str) -> bool {
    info.default_key.as_deref() == Some(selector)
        || info.name.as_deref() == Some(selector)
        || ShortId::parse_uuid(selector).is_ok_and(|id| id == info.id)
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
        (Some(name), None) => format!("{name} [{}]", ShortId::new(info.id)),
        (None, Some(key)) => key.clone(),
        (None, None) => ShortId::encode_uuid(info.id),
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
                let id = ShortId::new(info.id);
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
    /// Whether any decryption flag is given.
    fn is_set(&self) -> bool {
        self.passphrase.is_some() || self.identity.is_some() || self.identity_file.is_some()
    }

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
/// biometric prompt.
fn resolve_managed_identity(name: &str) -> Result<String, String> {
    let caller = Provenance::resolve_current_parent().and_then(|p| p.caller());
    match app_broker::request_age_identity(name, caller.as_deref()) {
        Ok(secret) => Ok(secret.expose_secret().to_string()),
        Err(BrokerError::Failed(m)) if m.starts_with("No age key named") => {
            Err(format!("No age key named {name}"))
        },
        Err(e) => Err(format!("Failed to resolve identity '{name}': {e}")),
    }
}
