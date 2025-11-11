use std::collections::BTreeMap;

use serde::Serialize;
use typeshare::typeshare;

use crate::secrets::vault::VaultItem;
use crate::secrets::vault_wrapper::VaultWrapper;

#[derive(Serialize, Debug, Clone)]
#[typeshare]
pub struct VaultSchema {
    pub key: String,
    pub title: Option<String>,
    #[typeshare(serialized_as = "HashMap<String, VaultItemSchema>")]
    pub data: BTreeMap<String, VaultItemSchema>,
}

impl From<&VaultWrapper> for VaultSchema {
    fn from(vw: &VaultWrapper) -> Self {
        VaultSchema {
            key: vw.key.clone(),
            title: vw.vault.name.clone(),
            data: vw
                .vault
                .data
                .iter()
                .map(|(key, item)| (key.clone(), item.into()))
                .collect(),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
#[typeshare]
pub struct VaultItemSchema {
    #[typeshare(serialized_as = "string")]
    id: uuid::Uuid,
    title: String,
    #[typeshare(serialized_as = "HashMap<String, VaultItemCredentialSchema>")]
    credentials: BTreeMap<String, VaultItemCredentialSchema>,
}

impl From<&VaultItem> for VaultItemSchema {
    fn from(item: &VaultItem) -> Self {
        VaultItemSchema {
            id: item.id,
            title: item.title.clone(),
            credentials: item
                .credentials
                .iter()
                .map(|(cred_key, cred)| {
                    (
                        cred_key.clone(),
                        VaultItemCredentialSchema {
                            id: cred.id,
                            title: cred.title.clone(),
                        },
                    )
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
#[typeshare]
pub struct VaultItemCredentialSchema {
    #[typeshare(serialized_as = "String")]
    id: uuid::Uuid,
    title: Option<String>,
}
