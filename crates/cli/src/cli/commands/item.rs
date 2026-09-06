use std::io::{IsTerminal, Read};
use std::str::FromStr;

use axo_pass_core::core::app_broker::{self, BrokerError};
use axo_pass_core::core::dirs::vaults_dir;
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::secrets::vaults::{DEFAULT_VAULT, VaultWrapper};
use clap::{Parser, Subcommand};
use color_print::{cformat, cprintln};
use inquire::Password;
use regex::Regex;
use secrecy::{ExposeSecret, SecretString};

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

    /// Read secret value by reference or {item_key}/{credential_key}
    Read { item_reference: ItemReference },

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
            ItemSubcommand::Read { item_reference } => self.cmd_read_item(item_reference),
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

    fn cmd_get_item(&self, item_reference: &ItemReference) -> Result<(), String> {
        let item_reference = item_reference.clone();
        let vw = Self::unlock_vault(item_reference.vault.or_else(|| self.vault.clone()))?;
        let vault_key = vw.key.clone();
        let item_key = item_reference.item;
        let Some(item) = vw
            .get_item_overview(&item_key)
            .map_err(|e| format!("Failed to get item: {e}"))?
        else {
            return Err(cformat!(
                "<blue>{item_key}</blue> not found in vault <blue>{vault_key}</blue>",
            ));
        };
        match item_reference.credential {
            None => {
                if item.credentials.is_empty() {
                    cprintln!("<dim><<no credentials>></dim>");
                }
                for (cred_key, cred) in &item.credentials {
                    cprintln!(
                        "{} {cred_key} <dim>axo://{vault_key}/{item_key}/{cred_key}</dim>",
                        cred.title,
                    );
                }
            },
            Some(credential_key) => {
                let Some(credential) = vw
                    .get_secret_overview(&item_key, &credential_key)
                    .map_err(|e| format!("Failed to get credential: {e}"))?
                else {
                    return Err(cformat!(
                        "<blue>{item_key}/{credential_key}</blue> not found in vault <blue>{vault_key}</blue>",
                    ));
                };
                cprintln!("<green>Credential</green>: {}", credential_key);
                cprintln!("<green>Title</green>: {}", credential.title);
                cprintln!(
                    "<green>Reference</green>: axo://{vault_key}/{item_key}/{credential_key}"
                );
            },
        }
        Ok(())
    }

    fn cmd_read_item(&self, item_reference: &ItemReference) -> Result<(), String> {
        Self::cmd_read(item_reference, self.vault.clone())
    }

    /// Read a secret through the app broker. `ap` holds no keychain
    /// entitlements, so the app unlocks the vault and returns the value. A
    /// build that is not staged in an app bundle has no broker to reach and
    /// unlocks locally.
    pub fn cmd_read(item_reference: &ItemReference, vault: Option<String>) -> Result<(), String> {
        let item_reference = item_reference.clone();
        let item_key = item_reference.item;
        let Some(credential_key) = item_reference.credential else {
            return Err("Credential key must be specified".to_string());
        };
        let vault_key = item_reference
            .vault
            .or(vault)
            .unwrap_or_else(|| DEFAULT_VAULT.to_string());
        let caller = Provenance::resolve_current_parent()
            .inspect(|provenance| log::debug!("read caller: {provenance:#?}"))
            .and_then(|provenance| provenance.caller());

        let value = match app_broker::request_vault_secret(
            &vault_key,
            &item_key,
            &credential_key,
            caller.as_deref(),
        ) {
            Ok(value) => value,
            Err(BrokerError::Unavailable) => {
                return Self::read_locally(&vault_key, &item_key, &credential_key);
            },
            Err(e) => return Err(format!("Failed to read secret: {e}")),
        };

        let Some(value) = value else {
            return Err(cformat!(
                "<blue>{item_key}/{credential_key}</blue> not found in vault <blue>{vault_key}</blue>",
            ));
        };
        println!("{}", value.expose_secret());
        Ok(())
    }

    fn read_locally(vault_key: &str, item_key: &str, credential_key: &str) -> Result<(), String> {
        let vw = Self::unlock_vault(Some(vault_key.to_string()))?;
        match vw.get_secret(item_key, credential_key) {
            Ok(Some(secret)) => {
                println!("{}", secret.expose_secret());
                Ok(())
            },
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

    fn cmd_set_item(
        &self,
        item_reference: &ItemReference,
        secret_value: Option<SecretString>,
    ) -> Result<(), String> {
        let item_reference = item_reference.clone();
        let mut vw = Self::unlock_vault(item_reference.vault.or_else(|| self.vault.clone()))?;

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

        vw.add_secret(&item_key, &credential_key, &credential_key, secret)
            .expect("Failed to add secret");

        vw.save().expect("Failed to save vault");

        println!(
            "Added item: axo://{}/{}/{}",
            vw.key, item_key, credential_key
        );

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
