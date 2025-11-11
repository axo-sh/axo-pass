use std::io::{IsTerminal, Read};

use clap::{Parser, Subcommand};
use inquire::Password;
use secrecy::SecretString;

use crate::core::dirs::vaults_dir;
use crate::secrets::vault_wrapper::{DEFAULT_VAULT, VaultWrapper};

#[derive(Parser, Debug)]
pub struct VaultCommand {
    #[command(subcommand)]
    subcommand: VaultSubcommand,

    #[arg(long)]
    vault: Option<String>,
}

#[derive(Subcommand, Debug)]
enum VaultSubcommand {
    GetItem {
        get_item_url: String,
    },
    ListItems,
    SetItem {
        item_key: String,
        credential_key: String,
        secret_value: Option<SecretString>,
    },
}

impl VaultCommand {
    pub async fn execute(&self) {
        match &self.subcommand {
            VaultSubcommand::GetItem { get_item_url } => {
                self.cmd_get_item_by_url(get_item_url.clone())
                    .expect("Failed to get item");
            },
            VaultSubcommand::ListItems => {
                self.cmd_list_items().expect("Failed to list items");
            },
            VaultSubcommand::SetItem {
                item_key,
                credential_key,
                secret_value,
            } => {
                self.cmd_set_item(item_key, credential_key, secret_value.clone())
                    .expect("Failed to set item");
            },
        }
    }

    fn load_vault(&self, vault_key: Option<&str>) -> Result<VaultWrapper, String> {
        let mut vw = VaultWrapper::load(&vaults_dir(), vault_key.or(self.vault.as_deref()))
            .map_err(|e| format!("Failed to load vault: {e}"))?;
        vw.unlock()
            .map_err(|e| format!("Failed to unlock vault: {e}"))?;
        Ok(vw)
    }

    fn cmd_get_item_by_url(&self, get_item_url: String) -> Result<(), String> {
        let u = url::Url::parse(&get_item_url)
            .map_err(|e| format!("Invalid URL '{get_item_url}': {e}"))?;
        if u.scheme() != "axo" {
            panic!("Unsupported URL scheme: {}", u.scheme())
        }
        let vault_key = u
            .host_str()
            .ok_or_else(|| format!("URL missing host: {}", get_item_url))?;

        let vw = self.load_vault(Some(vault_key))?;
        let res = vw.get_secret_by_url(u).expect("Failed to get item by URL");
        println!("{}", res.unwrap_or_else(|| "<not found>".to_string()));
        Ok(())
    }

    fn cmd_list_items(&self) -> Result<(), String> {
        let vw = self.load_vault(None)?;

        println!("Vault: {} (default vault)", vw.key);
        let items = vw.list_items();
        let mut has_items = false;
        for (item_key, item_value) in items {
            for (cred_key, _cred_value) in item_value.credentials.iter() {
                println!("axo://{}/{}/{}", DEFAULT_VAULT, item_key, cred_key);
            }
            has_items = true;
        }
        if !has_items {
            println!("<no items>");
        }

        Ok(())
    }

    fn cmd_set_item(
        &self,
        item_key: &str,
        credential_key: &str,
        secret_value: Option<SecretString>,
    ) -> Result<(), String> {
        let mut vw = self.load_vault(None)?;

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

        vw.add_secret(item_key, item_key, credential_key, credential_key, secret)
            .expect("Failed to add secret");

        vw.save().expect("Failed to save vault");

        println!(
            "Added item: axo://{}/{}/{}",
            vw.key, item_key, credential_key
        );

        Ok(())
    }
}
