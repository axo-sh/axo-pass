use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use color_print::cprintln;

use crate::secrets::keychain::keychain_query::KeyChainQuery;
use crate::secrets::keychain::managed_key::{self, ManagedKeyQuery};

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
        if std::env::var("FRITTATA_DEBUG").is_ok() {
            // https://developer.apple.com/documentation/security/ksecattrapplicationlabel
            cprintln!(
                "<green>kSecAttrApplicationLabel:</green> {}",
                key.app_label().as_deref().unwrap_or("<none>")
            );
        }
        if let Some(pub_key) = key.public_key() {
            cprintln!("<green>Public Key:</green>\n{}", b64.encode(pub_key));
        }
        if i < keys.len() - 1 {
            println!();
        };
    }
}
