use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;

use crate::secrets::keychain::keychain_query::KeyChainQuery;
use crate::secrets::keychain::managed_key::{self, ManagedKeyQuery};

pub async fn cmd_list_managed_keys() {
    let keys = ManagedKeyQuery::build()
        .with_key_class(managed_key::KeyClass::Public)
        .list()
        .unwrap();
    for key in keys {
        if let Some(pub_key) = key.public_key() {
            println!("Found key: {:?} pub={}", key, b64.encode(pub_key));
        } else {
            println!("Found key: {:?}", key);
        }
    }
}
