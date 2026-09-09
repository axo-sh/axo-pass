use std::io::{IsTerminal, Read, Write};
use std::str::FromStr;

use axo_pass_core::core::app_broker::{self, BrokerError, ResolvePurpose, VaultRef};
use axo_pass_core::core::dirs::vaults_dir;
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::secrets::vaults::{DEFAULT_VAULT, FieldKind, VaultWrapper};
use clap::{Parser, Subcommand};
use clml::{cformat, cprintln};
use inquire::Password;
use regex::Regex;
use secrecy::{ExposeSecret, SecretString};

/// Resolves backslash escapes in a user-supplied delimiter so shells that
/// cannot type control characters literally can still pass one. Handles `\n`,
/// `\t`, `\r`, `\0`, `\\`, and `\xHH` for an arbitrary byte (`\x1f` is the
/// ASCII unit separator). An unrecognized escape is left as written.
fn unescape_delimiter(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            result.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => result.push('\n'),
            Some('t') => result.push('\t'),
            Some('r') => result.push('\r'),
            Some('0') => result.push('\0'),
            Some('\\') => result.push('\\'),
            Some('x') => {
                let hex: String = chars.by_ref().take(2).collect();
                match u8::from_str_radix(&hex, 16) {
                    Ok(byte) => result.push(byte as char),
                    Err(_) => {
                        result.push_str("\\x");
                        result.push_str(&hex);
                    },
                }
            },
            Some(other) => {
                result.push('\\');
                result.push(other);
            },
            None => result.push('\\'),
        }
    }
    result
}

#[derive(Parser, Debug)]
#[command(flatten_help = true, help_template = "{usage-heading} {usage}")]
pub struct ItemCommand {
    #[command(subcommand)]
    subcommand: ItemSubcommand,

    #[arg(long, global = true)]
    vault: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ItemReference {
    pub vault: Option<String>,
    pub item: String,
    pub credential: Option<String>,
}

impl FromStr for ItemReference {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let axo_url_re =
        Regex::new(r"^(?:axo://(?P<vault>[a-zA-Z0-9-_]+)/)?(?P<item>[a-zA-Z0-9-_]+)(?:/(?P<credential>[a-zA-Z0-9-_]+)?)").unwrap();
        if let Some(captures) = axo_url_re.captures(s) {
            let vault = captures.name("vault").map(|m| m.as_str().to_string());
            let item = captures
                .name("item")
                .ok_or_else(|| format!("Missing item in reference: {}", s))?
                .as_str()
                .to_string();
            let credential = captures.name("credential").map(|m| m.as_str().to_string());
            Ok(ItemReference {
                vault,
                item,
                credential,
            })
        } else {
            Err(format!("Invalid item reference: {s}"))
        }
    }
}

#[derive(Subcommand, Debug)]
enum ItemSubcommand {
    /// List items in the vault
    List,

    /// Get item by reference, item_key or {item_key}/{credential_key}
    Get { item_reference: ItemReference },

    /// Read secret value(s) by reference or {item_key}/{credential_key}
    Read {
        #[arg(required = true)]
        item_reference: Vec<ItemReference>,

        /// String to print between values (supports \n, \t, \r, \0, \xHH
        /// escapes)
        #[arg(long, short = 'd', default_value = "\\n")]
        delimiter: String,
    },

    /// Set secret value by reference or {item_key}/{credential_key}
    Set {
        item_reference: ItemReference,
        secret_value: Option<SecretString>,
    },
}

impl ItemCommand {
    pub async fn execute(&self) {
        let result = match &self.subcommand {
            ItemSubcommand::Get { item_reference } => self.cmd_get_item(item_reference),
            ItemSubcommand::Read {
                item_reference,
                delimiter,
            } => self.cmd_read_item(item_reference, delimiter),
            ItemSubcommand::List => self.cmd_list_items(),
            ItemSubcommand::Set {
                item_reference,
                secret_value,
            } => self.cmd_set_item(item_reference, secret_value.clone()),
        };
        // A dismissed prompt and a vault that will not open are both ordinary
        // outcomes, so they exit with a message rather than a panic.
        if let Err(e) = result {
            cprintln!("<red>{e}</red>");
            std::process::exit(1);
        }
    }

    fn unlock_vault(vault_key: Option<String>) -> Result<VaultWrapper, String> {
        let mut vw = VaultWrapper::load(&vaults_dir(), vault_key)
            .map_err(|e| format!("Failed to load vault: {e}"))?;
        vw.unlock()
            .map_err(|e| format!("Failed to unlock vault: {e}"))?;
        Ok(vw)
    }

    /// Show one item's overview through the app broker, never a secret value.
    /// `ap` holds no keychain entitlements, so the app unlocks the vault and
    /// returns the listing, which is filtered here to the one item. A build
    /// that is not staged in an app bundle has no broker to reach and unlocks
    /// locally.
    fn cmd_get_item(&self, item_reference: &ItemReference) -> Result<(), String> {
        let item_reference = item_reference.clone();
        let vault_key = item_reference
            .vault
            .or_else(|| self.vault.clone())
            .unwrap_or_else(|| DEFAULT_VAULT.to_string());
        let item_key = item_reference.item;
        let credential_key = item_reference.credential;

        let caller = Provenance::resolve_current_parent()
            .inspect(|provenance| log::debug!("item get caller: {provenance:#?}"))
            .and_then(|provenance| provenance.caller());

        match app_broker::request_vault_items(&vault_key, caller.as_deref()) {
            Ok(items) => {
                let Some(item) = items.into_iter().find(|item| item.key == item_key) else {
                    return Err(cformat!(
                        "<blue>{item_key}</blue> not found in vault <blue>{vault_key}</blue>",
                    ));
                };
                let credentials: Vec<(String, String)> = item
                    .credentials
                    .into_iter()
                    .map(|c| (c.key, c.title))
                    .collect();
                Self::print_item(&vault_key, &item_key, credential_key.as_deref(), &credentials)
            },
            Err(BrokerError::Unavailable) => {
                self.get_item_locally(&vault_key, &item_key, credential_key.as_deref())
            },
            Err(e) => Err(format!("Failed to get item: {e}")),
        }
    }

    fn get_item_locally(
        &self,
        vault_key: &str,
        item_key: &str,
        credential_key: Option<&str>,
    ) -> Result<(), String> {
        let vw = Self::unlock_vault(Some(vault_key.to_string()))?;
        let Some(item) = vw
            .get_item_overview(item_key)
            .map_err(|e| format!("Failed to get item: {e}"))?
        else {
            return Err(cformat!(
                "<blue>{item_key}</blue> not found in vault <blue>{vault_key}</blue>",
            ));
        };
        let credentials: Vec<(String, String)> = item
            .credentials
            .values()
            .map(|cred| (cred.key.clone(), cred.title.clone()))
            .collect();
        Self::print_item(vault_key, item_key, credential_key, &credentials)
    }

    /// Render an item overview: every credential, or the detail for one named
    /// credential. `credentials` is `(key, title)` pairs.
    fn print_item(
        vault_key: &str,
        item_key: &str,
        credential_key: Option<&str>,
        credentials: &[(String, String)],
    ) -> Result<(), String> {
        match credential_key {
            None => {
                if credentials.is_empty() {
                    cprintln!("<dim><<no credentials>></dim>");
                }
                for (cred_key, title) in credentials {
                    cprintln!(
                        "{title} {cred_key} <dim>axo://{vault_key}/{item_key}/{cred_key}</dim>",
                    );
                }
            },
            Some(credential_key) => {
                let Some((_, title)) =
                    credentials.iter().find(|(key, _)| key == credential_key)
                else {
                    return Err(cformat!(
                        "<blue>{item_key}/{credential_key}</blue> not found in vault <blue>{vault_key}</blue>",
                    ));
                };
                cprintln!("<green>Credential</green>: {credential_key}");
                cprintln!("<green>Title</green>: {title}");
                cprintln!(
                    "<green>Reference</green>: axo://{vault_key}/{item_key}/{credential_key}"
                );
            },
        }
        Ok(())
    }

    fn cmd_read_item(
        &self,
        item_references: &[ItemReference],
        delimiter: &str,
    ) -> Result<(), String> {
        Self::cmd_read(item_references, self.vault.clone(), delimiter)
    }

    /// Read one or more secrets through the app broker. `ap` holds no
    /// keychain entitlements, so the app unlocks the vault and returns the
    /// value. A build that is not staged in an app bundle has no broker to
    /// reach and unlocks locally. Values are printed joined by `delimiter`.
    ///
    /// Every reference is resolved in one broker request, so a multi-reference
    /// read raises a single prompt rather than one per reference.
    pub fn cmd_read(
        item_references: &[ItemReference],
        vault: Option<String>,
        delimiter: &str,
    ) -> Result<(), String> {
        let delimiter = unescape_delimiter(delimiter);

        // (vault, item, credential) per reference, defaults applied.
        let mut triples = Vec::with_capacity(item_references.len());
        for item_reference in item_references {
            let item_reference = item_reference.clone();
            let Some(credential_key) = item_reference.credential else {
                return Err("Credential key must be specified".to_string());
            };
            let vault_key = item_reference
                .vault
                .or_else(|| vault.clone())
                .unwrap_or_else(|| DEFAULT_VAULT.to_string());
            triples.push((vault_key, item_reference.item, credential_key));
        }

        let caller = Provenance::resolve_current_parent()
            .inspect(|provenance| log::debug!("read caller: {provenance:#?}"))
            .and_then(|provenance| provenance.caller());

        let wire: Vec<VaultRef> = triples
            .iter()
            .map(|(v, i, c)| VaultRef {
                vault_key: v.clone(),
                item_key: i.clone(),
                credential_key: c.clone(),
            })
            .collect();

        let values = match app_broker::request_resolve_secrets(
            &wire,
            ResolvePurpose::Read,
            caller.as_deref(),
        ) {
            Ok(values) => values,
            Err(BrokerError::Unavailable) => triples
                .iter()
                .map(|(v, i, c)| Self::read_locally(v, i, c).map(Some))
                .collect::<Result<Vec<_>, _>>()?,
            Err(e) => return Err(format!("Failed to read secret: {e}")),
        };

        let mut resolved = Vec::with_capacity(triples.len());
        for ((vault_key, item_key, credential_key), value) in triples.iter().zip(values) {
            let Some(value) = value else {
                return Err(cformat!(
                    "<blue>{item_key}/{credential_key}</blue> not found in vault <blue>{vault_key}</blue>",
                ));
            };
            resolved.push(value);
        }

        let rendered: Vec<&str> = resolved.iter().map(|v| v.expose_secret()).collect();

        // With multiple secrets the delimiter separates values on output. A
        // secret that contains the delimiter would make the output ambiguous,
        // so refuse rather than emit something the caller cannot split.
        if rendered.len() > 1 && !delimiter.is_empty() {
            for ((vault_key, item_key, credential_key), value) in triples.iter().zip(&rendered) {
                if value.contains(&delimiter) {
                    return Err(cformat!(
                        "<blue>{item_key}/{credential_key}</blue> in vault <blue>{vault_key}</blue> contains the delimiter; choose a different delimiter",
                    ));
                }
            }
        }

        let output = rendered.join(&delimiter);
        if std::io::stdout().is_terminal() {
            println!("{output}");
        } else {
            print!("{output}");
            std::io::stdout()
                .flush()
                .map_err(|e| format!("Failed to write to stdout: {e}"))?;
        }
        Ok(())
    }

    fn read_locally(
        vault_key: &str,
        item_key: &str,
        credential_key: &str,
    ) -> Result<SecretString, String> {
        let vw = Self::unlock_vault(Some(vault_key.to_string()))?;
        match vw.get_secret(item_key, credential_key) {
            Ok(Some(secret)) => Ok(SecretString::from(secret.expose_secret().to_owned())),
            Ok(None) => Err(cformat!(
                "<blue>{item_key}/{credential_key}</blue> not found in vault <blue>{vault_key}</blue>",
            )),
            Err(e) => Err(format!("Failed to get secret: {e}")),
        }
    }

    /// List items through the app broker. `ap` holds no keychain entitlements,
    /// so the app unlocks the vault and returns the overview. A build that is
    /// not staged in an app bundle has no broker to reach and unlocks locally.
    fn cmd_list_items(&self) -> Result<(), String> {
        let vault_key = self
            .vault
            .clone()
            .unwrap_or_else(|| DEFAULT_VAULT.to_string());
        let caller = Provenance::resolve_current_parent()
            .inspect(|provenance| log::debug!("item list caller: {provenance:#?}"))
            .and_then(|provenance| provenance.caller());

        let items = match app_broker::request_vault_items(&vault_key, caller.as_deref()) {
            Ok(items) => items,
            Err(BrokerError::Unavailable) => return self.list_items_locally(),
            Err(e) => return Err(format!("Failed to list items: {e}")),
        };

        cprintln!("<green>Vault</green>: <blue>{vault_key}</blue>");
        // Counted per credential, not per item: an item with no credentials
        // prints nothing, so it must not suppress the empty notice.
        let mut has_items = false;
        for item in &items {
            for cred in &item.credentials {
                cprintln!(
                    "  {} <dim>axo://{vault_key}/{}/{}</dim>",
                    cred.title,
                    item.key,
                    cred.key
                );
                has_items = true;
            }
        }
        if !has_items {
            println!("<no items>");
        }

        Ok(())
    }

    fn list_items_locally(&self) -> Result<(), String> {
        let vw = Self::unlock_vault(self.vault.clone())?;
        let vault_key = vw.key.clone();
        cprintln!("<green>Vault</green>: <blue>{vault_key}</blue>");

        let mut items = vw
            .list_items()
            .map_err(|e| format!("Failed to list items: {e}"))?;
        items.sort_by_key(|item| item.title.to_lowercase());

        let mut has_items = false;
        for item in &items {
            for cred in item.credentials.values() {
                cprintln!(
                    "  {} <dim>axo://{vault_key}/{}/{}</dim>",
                    cred.title,
                    item.key,
                    cred.key
                );
                has_items = true;
            }
        }
        if !has_items {
            println!("<no items>");
        }

        Ok(())
    }

    /// Write one credential's secret value through the app broker. `ap` holds
    /// no keychain entitlements, so the app unlocks the vault, writes the
    /// value and saves. A build that is not staged in an app bundle has no
    /// broker to reach and writes locally.
    fn cmd_set_item(
        &self,
        item_reference: &ItemReference,
        secret_value: Option<SecretString>,
    ) -> Result<(), String> {
        let item_reference = item_reference.clone();
        let vault_key = item_reference
            .vault
            .or_else(|| self.vault.clone())
            .unwrap_or_else(|| DEFAULT_VAULT.to_string());

        let item_key = item_reference.item;
        let Some(credential_key) = item_reference.credential else {
            return Err("Credential key must be specified".to_string());
        };

        let secret = match secret_value {
            Some(value) => value,
            None if std::io::stdin().is_terminal() => Password::new("Enter secret value:")
                .prompt()
                .map_err(|e| format!("Failed to read secret value: {e}"))?
                .trim()
                .into(),

            None => {
                let mut buffer = String::new();
                std::io::stdin()
                    .read_to_string(&mut buffer)
                    .map_err(|e| format!("Failed to read from stdin: {e}"))?;
                buffer.trim().to_string().into()
            },
        };

        let caller = Provenance::resolve_current_parent()
            .inspect(|provenance| log::debug!("item set caller: {provenance:#?}"))
            .and_then(|provenance| provenance.caller());

        match app_broker::request_write_vault_secret(
            &vault_key,
            &item_key,
            &credential_key,
            &credential_key,
            &secret,
            caller.as_deref(),
        ) {
            Ok(_) => {},
            Err(BrokerError::Unavailable) => {
                Self::set_item_locally(&vault_key, &item_key, &credential_key, secret)?
            },
            Err(e) => return Err(format!("Failed to set secret: {e}")),
        }

        println!("Added item: axo://{vault_key}/{item_key}/{credential_key}");
        Ok(())
    }

    fn set_item_locally(
        vault_key: &str,
        item_key: &str,
        credential_key: &str,
        secret: SecretString,
    ) -> Result<(), String> {
        let mut vw = Self::unlock_vault(Some(vault_key.to_string()))?;
        vw.add_secret(
            item_key,
            credential_key,
            credential_key,
            FieldKind::default(),
            secret,
        )
        .map_err(|e| format!("Failed to add secret: {e}"))?;
        vw.save().map_err(|e| format!("Failed to save vault: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_item_reference_from_str() {
        let test_cases = vec![
            (
                "axo://my_vault/my_item/my_credential",
                ItemReference {
                    vault: Some("my_vault".to_string()),
                    item: "my_item".to_string(),
                    credential: Some("my_credential".to_string()),
                },
            ),
            (
                "item456/cred789",
                ItemReference {
                    vault: None,
                    item: "item456".to_string(),
                    credential: Some("cred789".to_string()),
                },
            ),
        ];

        for (reference_str, expected) in test_cases {
            let item_ref =
                ItemReference::from_str(reference_str).expect("Failed to parse item reference");
            assert_eq!(
                item_ref, expected,
                "Failed parsing reference: {reference_str}",
            );
        }
    }
}
