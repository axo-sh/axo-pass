use anyhow::anyhow;
use color_print::cprintln;

use crate::secrets::keychain::keychain_query::KeyChainQuery;
use crate::secrets::keychain::managed_key::{self, ManagedKeyQuery, ManagedSshKey};

pub async fn cmd_list_managed_keys() {
    let keys = ManagedKeyQuery::build()
        .with_key_class(managed_key::KeyClass::Public)
        .list()
        .unwrap();

    if keys.is_empty() {
        println!("No managed keys found");
        return;
    }

    for (i, key) in keys.iter().enumerate() {
        cprintln!(
            "<green>Label:</green> {}",
            key.label.as_deref().unwrap_or("<unknown>")
        );
        match key.public_key() {
            Ok(public_key) => cprintln!(
                "<green>Public Key:</green> {}",
                public_key.fingerprint(ssh_key::HashAlg::Sha256)
            ),
            Err(e) => cprintln!("<red>Failed to get public key:</red> {e}"),
        }
        if i < keys.len() - 1 {
            println!();
        };
    }
}

pub async fn cmd_delete_managed_key(label: &str) {
    // Find the key by label (need to query private keys to be able to delete)
    if let Err(e) = ManagedSshKey::find(label)
        .and_then(|ssh_key| ssh_key.ok_or(anyhow!("Key not found")))
        .and_then(|ssh_key| ssh_key.delete())
    {
        cprintln!("<red>Failed to delete key:</red> {e}");
        std::process::exit(1);
    } else {
        cprintln!("<green>Deleted managed key:</green> {label}");
    }
}
