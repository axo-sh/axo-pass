use std::collections::BTreeMap;

use serde::Serialize;
use typeshare::typeshare;

use crate::secrets::vault::VaultItem;
use crate::secrets::vault_wrapper::VaultWrapper;

#[derive(Serialize, Debug, Clone)]
#[typeshare]
pub struct VaultSchema {
    pub key: String,
    pub name: Option<String>,
    pub path: String,
    #[typeshare(serialized_as = "HashMap<String, VaultItemSchema>")]
    pub data: BTreeMap<String, VaultItemSchema>,
}

impl From<&VaultWrapper> for VaultSchema {
    fn from(vw: &VaultWrapper) -> Self {
        VaultSchema {
            key: vw.key.clone(),
            name: vw.vault.name.clone(),
            path: vw.path.to_string_lossy().to_string(),
            data: vw
                .vault
                .items
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
