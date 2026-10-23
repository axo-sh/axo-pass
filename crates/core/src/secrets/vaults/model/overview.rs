//! Vault folder, item, and credential overviews, and the metadata blobs they
//! are stored as.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use super::ItemId;
use crate::secrets::vaults::autofill::item::{ItemAutofill, Role};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::passkey::signals::SignalStore;
use crate::secrets::vaults::storage::handle::normalized_key;

/// Sort key for folders, sections, and credentials. Entries with a position
/// come first, ordered by position, then the rest by title.
pub fn display_order(position: Option<u32>, title: &str) -> (u32, &str) {
    (position.unwrap_or(u32::MAX), title)
}

#[derive(Clone)]
pub struct VaultFolder {
    pub id: Uuid,
    pub title: String,
    /// User-defined order among folders. `None` until folders are reordered.
    pub position: Option<u32>,
}

impl VaultFolder {
    pub fn new(title: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.trim().to_string(),
            position: None,
        }
    }

    pub(super) fn from_metadata(metadata: &VaultFolderMetadata) -> Self {
        Self {
            id: metadata.id,
            title: metadata.title.clone(),
            position: metadata.position,
        }
    }

    pub fn to_metadata(&self) -> VaultFolderMetadata {
        VaultFolderMetadata {
            id: self.id,
            title: self.title.clone(),
            position: self.position,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultItemSection {
    pub id: Uuid,
    pub title: String,
    /// User-defined order among the item's sections. `None` until the
    /// sections are reordered.
    pub position: Option<u32>,
}

impl VaultItemSection {
    pub fn new(title: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.trim().to_string(),
            position: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultItemOverview {
    pub id: Uuid,
    pub title: String,
    pub key: String,
    /// Folder the item is filed in. `None` for an unfiled item.
    pub folder: Option<Uuid>,
    pub sections: BTreeMap<Uuid, VaultItemSection>,
    /// Display hint, such as `login`. Nothing branches on it.
    pub category: Option<String>,
    pub autofill: ItemAutofill,
    pub credentials: BTreeMap<Uuid, VaultItemCredentialOverview>,
}

impl VaultItemOverview {
    pub fn try_new(title: &str, key: &str) -> Result<Self, Error> {
        let item_key = normalized_key(key).ok_or_else(|| Error::InvalidItemKey(key.to_string()))?;
        Ok(Self {
            id: Uuid::new_v4(),
            title: title.to_string(),
            key: item_key,
            folder: None,
            sections: BTreeMap::new(),
            category: None,
            autofill: ItemAutofill::default(),
            credentials: BTreeMap::new(),
        })
    }

    pub(super) fn from_metadata(id: Uuid, metadata: &VaultItemMetadata) -> Self {
        let sections = metadata
            .sections
            .iter()
            .map(|s| {
                let section = VaultItemSection {
                    id: s.id,
                    title: s.title.clone(),
                    position: s.position,
                };
                (s.id, section)
            })
            .collect();
        Self {
            id,
            title: metadata.title.clone(),
            key: metadata.key.clone(),
            folder: metadata.folder,
            sections,
            category: metadata.category.clone(),
            autofill: ItemAutofill::default(),
            credentials: BTreeMap::new(),
        }
    }

    pub fn to_metadata(&self) -> VaultItemMetadata {
        VaultItemMetadata {
            title: self.title.clone(),
            key: self.key.clone(),
            folder: self.folder,
            sections: self
                .sections
                .values()
                .map(|s| VaultSectionMetadata {
                    id: s.id,
                    title: s.title.clone(),
                    position: s.position,
                })
                .collect(),
            category: self.category.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultItemCredentialOverview {
    pub id: Uuid,
    pub title: String,
    pub key: String,
    pub kind: FieldKind,
    /// User-defined order within the item's section. `None` until the item is
    /// reordered.
    pub position: Option<u32>,
    /// Section of the item the credential is shown in. `None` for a
    /// credential outside any section.
    pub section: Option<Uuid>,
    /// Unix seconds of the first use on the most recent day of use, for
    /// credentials whose use is recorded. Only passkey sign-ins set it. It
    /// names the day of last use, not the time.
    pub last_used_day_at: Option<i64>,
}

impl VaultItemCredentialOverview {
    pub fn try_new(title: &str, key: &str, kind: FieldKind) -> Result<Self, Error> {
        let cred_key =
            normalized_key(key).ok_or_else(|| Error::InvalidCredentialKey(key.to_string()))?;
        Ok(Self {
            id: Uuid::new_v4(),
            title: title.to_string(),
            key: cred_key,
            kind,
            position: None,
            section: None,
            last_used_day_at: None,
        })
    }

    pub(super) fn from_metadata(id: Uuid, metadata: &VaultCredentialMetadata) -> Self {
        Self {
            id,
            title: metadata.title.clone(),
            key: metadata.key.clone(),
            kind: metadata.kind.clone(),
            position: metadata.position,
            section: metadata.section,
            last_used_day_at: metadata.last_used_day_at,
        }
    }

    pub fn to_metadata(&self) -> VaultCredentialMetadata {
        VaultCredentialMetadata {
            title: self.title.clone(),
            key: self.key.clone(),
            kind: self.kind.clone(),
            position: self.position,
            section: self.section,
            last_used_day_at: self.last_used_day_at,
        }
    }
}

/// A deleted credential as shown in the Recently Deleted list.
#[derive(Clone, Debug)]
pub struct DeletedCredentialOverview {
    pub item_id: ItemId,
    /// The credential as it was when deleted. It is also the entry id.
    pub credential: VaultItemCredentialOverview,
    /// Unix timestamp in seconds.
    pub deleted_at: i64,
}

/// A deleted item as shown in the Recently Deleted list.
pub struct DeletedItemOverview<'a> {
    /// The item as it was when deleted, with its credentials.
    pub item: &'a VaultItemOverview,
    /// Unix timestamp in seconds.
    pub deleted_at: i64,
    /// Credentials of the item that were deleted before the item.
    pub deleted_credentials: Vec<&'a VaultItemCredentialOverview>,
}

/// A deleted credential with the live item it was deleted from.
pub struct DeletedCredentialEntry<'a> {
    pub item: &'a VaultItemOverview,
    pub credential: &'a DeletedCredentialOverview,
}

/// A previous value of a credential, without the value.
#[derive(Clone, Debug)]
pub struct HistoryOverview {
    pub id: Uuid,
    /// Unix timestamp in seconds.
    pub replaced_at: i64,
}

/// Details of a previous value, stored as one encrypted blob.
#[derive(Serialize, Deserialize, Zeroize)]
pub struct HistoryInfo {
    pub replaced_at: i64,
}

/// Details of a deleted credential or item, stored as one encrypted blob.
#[derive(Serialize, Deserialize, Zeroize)]
pub struct DeletedInfo {
    pub deleted_at: i64,
    /// Autofill role the credential had when deleted. Restoring the credential
    /// gives the role back if no other credential took it. Always `None` for an
    /// item, which keeps its own autofill data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub role: Option<Role>,
}

/// Vault-level metadata, stored as one encrypted blob.
#[derive(Default, Serialize, Deserialize, Zeroize)]
pub struct VaultMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<VaultFolderMetadata>,
    /// Site reports about the passkeys in this vault.
    #[serde(default, skip_serializing_if = "SignalStore::is_empty")]
    #[zeroize(skip)]
    pub passkey_signals: SignalStore,
}

impl VaultMetadata {
    pub fn is_empty(&self) -> bool {
        self.folders.is_empty() && self.passkey_signals.is_empty()
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
pub struct VaultFolderMetadata {
    #[zeroize(skip)]
    pub id: Uuid,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
}

#[derive(Serialize, Deserialize, Zeroize)]
pub struct VaultItemMetadata {
    pub title: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub folder: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<VaultSectionMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

#[derive(Serialize, Deserialize, Zeroize)]
pub struct VaultSectionMetadata {
    #[zeroize(skip)]
    pub id: Uuid,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
}

#[derive(Serialize, Deserialize, Zeroize)]
pub struct VaultCredentialMetadata {
    pub title: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "FieldKind::is_default")]
    pub kind: FieldKind,
    /// User-defined order of a credential within its section. Absent on
    /// legacy vaults and until the first reorder; unset credentials sort
    /// after set ones, by title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub section: Option<Uuid>,
    /// Unix seconds of the first use on the most recent day of use. Absent
    /// until the first recorded use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_day_at: Option<i64>,
}
