use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;

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
        println!("Label: {}", key.label.as_deref().unwrap_or("<unknown>"));
        if std::env::var("FRITTATA_DEBUG").is_ok() {
            // https://developer.apple.com/documentation/security/ksecattrapplicationlabel
            println!(
                "kSecAttrApplicationLabel: {}",
                key.app_label().as_deref().unwrap_or("<none>")
            );
        }
        if let Some(pub_key) = key.public_key() {
            println!("Public Key:\n{}", b64.encode(pub_key));
        }
        if i < keys.len() - 1 {
            println!("---");
        };
    }
}
