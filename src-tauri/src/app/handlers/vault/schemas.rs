use std::collections::BTreeMap;

use serde::Serialize;
use typeshare::typeshare;

use crate::secrets::vaults::{Error, VaultItemCredentialOverview, VaultItemOverview, VaultWrapper};

// VaultSchema is the serialized form of VaultWrapper, with decrypted item
// titles and credential titles, but without credential values. Used for sending
// vault data to the frontend.
#[derive(Serialize, Debug, Clone)]
#[typeshare]
pub struct VaultSchema {
    pub key: String,
    pub name: Option<String>,
    pub path: String,
    #[typeshare(serialized_as = "HashMap<String, VaultItemSchema>")]
    pub data: BTreeMap<String, VaultItemSchema>,
}

impl VaultWrapper {
    pub fn to_schema(&self) -> Result<VaultSchema, Error> {
        let items = self.list_items()?;
        Ok(VaultSchema {
            key: self.key.clone(),
            name: self.vault_name().map(|s| s.to_string()),
            path: self.path.to_string_lossy().to_string(),
            data: items
                .into_iter()
                .map(|item| (item.key.clone(), item.into()))
                .collect(),
        })
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

impl From<&VaultItemOverview> for VaultItemSchema {
    fn from(item: &VaultItemOverview) -> Self {
        Self {
            id: item.id,
            title: item.title.clone(),
            credentials: item
                .credentials
                .values()
                .map(|cred| (cred.key.clone(), cred.into()))
                .collect(),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
#[typeshare]
pub struct VaultItemCredentialSchema {
    #[typeshare(serialized_as = "String")]
    id: uuid::Uuid,
    title: String,
}

impl From<&VaultItemCredentialOverview> for VaultItemCredentialSchema {
    fn from(cred: &VaultItemCredentialOverview) -> Self {
        Self {
            id: cred.id,
            title: cred.title.clone(),
        }
    }
}
