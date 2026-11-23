//! Sync model of one vault: the registers and maps that replicas join, and
//! their value types.
//!
//! The sync state is `CausalState<SyncState>`. Values are plain structs. They
//! are stored only inside the encrypted sync state.
//!
//! Each register names its conflict policy as a type parameter, so a register
//! without a policy does not compile:
//!
//! ```compile_fail
//! use axo_pass_core::secrets::vaults::sync::crdt::MvRegister;
//!
//! struct NotAPolicy;
//!
//! let register = MvRegister::<String, NotAPolicy>::default();
//! ```
//!
//! The same register with a policy compiles:
//!
//! ```
//! use axo_pass_core::secrets::vaults::sync::crdt::{Ask, MvRegister};
//!
//! let register = MvRegister::<String, Ask>::default();
//! ```

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use uuid::Uuid;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::crdt::{
    Ask, CausalContext, CausalStore, Merge, MvRegister, OrMap, Order, Own, ReplicaId, Rotation,
    Stop, Trash, WriteId,
};
use crate::secrets::vaults::autofill::item::{MatchKind, Role};
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::model::history::HistoryKind;
use crate::secrets::vaults::passkey::signals::SignalEntry;

#[cfg(test)]
mod schema_tests;

/// Version of the serde forms of the value types, and of the state file body.
pub const SYNC_FORMAT_VERSION: u32 = 1;

pub type FolderId = Uuid;
pub type ItemId = Uuid;
pub type SectionId = Uuid;
pub type CredentialId = Uuid;
pub type HistoryId = Uuid;

/// Synced registers of one vault.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncState {
    pub name: MvRegister<Option<String>, Ask>,
    /// Display name of each replica. Each replica writes only its own.
    /// Cleanup removes the entry of a retired, departed, or removed replica.
    pub replica_names: OrMap<ReplicaId, MvRegister<String, Own>>,
    /// Secure Enclave public keys of each replica. Each replica writes only
    /// its own. Cleanup removes the entry. The local pins and revocations are
    /// kept.
    pub replica_keys: OrMap<ReplicaId, MvRegister<ReplicaKeys, Stop>>,
    /// Replicas removed by a key rotation. An entry is removed only by a Mac
    /// that replaces a losing concurrent rotation, if only that rotation
    /// removed the replica. Cleanup keeps it.
    pub removed: OrMap<ReplicaId, MvRegister<Removal, Rotation>>,
    /// Replicas that disabled sync. Each replica writes only its own. Cleanup
    /// removes the entry.
    pub left: OrMap<ReplicaId, MvRegister<bool, Own>>,
    /// Age recipients of saved recovery kits, keyed by recipient.
    pub recovery: OrMap<String, MvRegister<RecoveryRecipient, Order>>,
    pub folders: OrMap<FolderId, MvRegister<FolderValue, Order>>,
    /// Keyed by [`SignalEntry::key`].
    pub(crate) signals: OrMap<String, MvRegister<SignalEntry, Merge>>,
    pub items: OrMap<ItemId, SyncItem>,
    /// Vault level, so moving a credential between items writes one register.
    pub credentials: OrMap<CredentialId, SyncCredential>,
}

/// Synced registers of one item.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncItem {
    pub title: MvRegister<String, Ask>,
    pub category: MvRegister<Option<String>, Ask>,
    /// Stored as written. The view makes keys unique.
    pub key: MvRegister<String, Ask>,
    pub folder: MvRegister<Option<FolderId>, Order>,
    pub sections: OrMap<SectionId, MvRegister<SectionValue, Order>>,
    /// Keyed by URL.
    pub websites: OrMap<String, MvRegister<WebsiteValue, Order>>,
    /// Role slots. One register per slot, so changes to different slots do
    /// not conflict.
    pub username: MvRegister<Option<CredentialId>, Ask>,
    pub password: MvRegister<Option<CredentialId>, Ask>,
    pub totp: MvRegister<Option<CredentialId>, Ask>,
    /// Creation time as Unix seconds.
    pub created_at: MvRegister<i64, Order>,
    pub trashed: MvRegister<Option<TrashValue>, Trash>,
}

/// Synced registers of one credential.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncCredential {
    pub item: MvRegister<ItemId, Order>,
    pub title: MvRegister<String, Ask>,
    pub kind: MvRegister<FieldKind, Ask>,
    /// Stored as written. The view makes keys unique.
    pub key: MvRegister<String, Ask>,
    pub placement: MvRegister<Placement, Order>,
    pub value: MvRegister<SecretText, Ask>,
    /// Written once per entry by each writer.
    pub history: OrMap<HistoryId, MvRegister<HistoryValue, Order>>,
    /// Passkey last used day, as Unix seconds. One register per replica. Each
    /// replica writes only its own. Cleanup removes the entry of a cleaned
    /// replica after folding its time into the cleaning replica's own.
    pub last_used_day_at: OrMap<ReplicaId, MvRegister<i64, Own>>,
    /// Creation time as Unix seconds.
    pub created_at: MvRegister<i64, Order>,
    pub trashed: MvRegister<Option<TrashValue>, Trash>,
}

/// Implement [`CausalStore`] for a struct of stores, field by field.
///
/// Each method destructures `Self` without `..`, so a field left out of the
/// list fails to compile.
macro_rules! causal_store {
    ($name:ident { $first:ident $(, $rest:ident)* $(,)? }) => {
        impl CausalStore for $name {
            fn is_empty(&self) -> bool {
                let Self { $first, $($rest),* } = self;
                $first.is_empty() $(&& $rest.is_empty())*
            }

            fn each_value(&self, f: &mut dyn FnMut(WriteId, u64)) {
                let Self { $first, $($rest),* } = self;
                $first.each_value(f);
                $($rest.each_value(f);)*
            }

            fn find_duplicate_write_id(&self, other: &Self) -> Option<WriteId> {
                let Self { $first, $($rest),* } = self;
                $first
                    .find_duplicate_write_id(&other.$first)
                    $(.or_else(|| $rest.find_duplicate_write_id(&other.$rest)))*
            }

            fn join(&mut self, ctx: &CausalContext, other: Self, other_ctx: &CausalContext) {
                let Self { $first, $($rest),* } = other;
                self.$first.join(ctx, $first, other_ctx);
                $(self.$rest.join(ctx, $rest, other_ctx);)*
            }
        }
    };
}

causal_store!(SyncState {
    name,
    replica_names,
    replica_keys,
    removed,
    left,
    recovery,
    folders,
    signals,
    items,
    credentials,
});

causal_store!(SyncItem {
    title,
    category,
    key,
    folder,
    sections,
    websites,
    username,
    password,
    totp,
    created_at,
    trashed,
});

causal_store!(SyncCredential {
    item,
    title,
    kind,
    key,
    placement,
    value,
    history,
    last_used_day_at,
    created_at,
    trashed,
});

/// Folder title and position.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderValue {
    pub title: String,
    /// Order among folders. `None` until folders are reordered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
}

/// Item section title and position.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionValue {
    pub title: String,
    /// Order among the sections of the item. `None` until sections are
    /// reordered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
}

/// Website match kind and position. The URL is the map key. The match kind
/// has the field name and default of `Website`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebsiteValue {
    #[serde(
        default,
        skip_serializing_if = "MatchKind::is_default",
        rename = "match"
    )]
    pub match_kind: MatchKind,
    /// Order among the websites of the item.
    pub position: u32,
}

/// Credential section and position.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    /// `None` for the default section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<SectionId>,
    /// Order among the credentials of the section. `None` until credentials
    /// are reordered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
}

/// History entry of a credential. Mapped field by field from
/// `HistoryMetadata` and the entry value.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryValue {
    /// Unix seconds.
    pub at: i64,
    pub kind: HistoryKind,
    /// Value the entry holds, as its kind states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<SecretText>,
}

/// Trash details of an item or credential. Mapped field by field from
/// `DeletedInfo`, with its serde form.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrashValue {
    /// Unix seconds.
    pub deleted_at: i64,
    /// Autofill role the credential had when trashed. Always `None` for an
    /// item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
}

/// Secret string. Zeroized on drop. `Debug` shows no value. The serde form is
/// a plain string.
#[derive(Clone, Default, PartialEq)]
pub struct SecretText(pub Zeroizing<String>);

impl SecretText {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(..)")
    }
}

/// The only field is `Zeroizing`, which zeroizes the string on drop.
impl ZeroizeOnDrop for SecretText {}

impl Serialize for SecretText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Secure Enclave public keys of one replica.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaKeys {
    /// Vault encryption key.
    pub encryption: PublicKey,
    /// Device signing key.
    pub signing: PublicKey,
}

/// Removal of a replica by a key rotation.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Removal {
    /// First key id the removed replica does not hold.
    pub key_id: KeyId,
}

/// Recovery kit recipient.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecipient {
    /// Key id the kit was made for.
    pub key_id: KeyId,
    /// Fingerprint of that key, as printed in the kit.
    #[serde(with = "ByteString")]
    pub key_fingerprint: [u8; 16],
}

/// Id of a sync key. The serde form is the number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(pub u32);

/// SEC1 bytes of a P-256 public key. Not parsed or checked here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey(#[serde(with = "ByteString")] pub Vec<u8>);

/// Serde form of bytes. A byte string in a binary format such as CBOR, and
/// standard base64 in a readable format such as JSON.
pub(crate) struct ByteString;

impl ByteString {
    pub(crate) fn serialize<S: Serializer>(
        bytes: &impl AsRef<[u8]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&B64.encode(bytes))
        } else {
            serializer.serialize_bytes(bytes.as_ref())
        }
    }

    pub(crate) fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<Vec<u8>>,
    {
        let bytes = if deserializer.is_human_readable() {
            deserializer.deserialize_str(ByteStringVisitor)?
        } else {
            deserializer.deserialize_bytes(ByteStringVisitor)?
        };
        let length = bytes.len();
        T::try_from(bytes)
            .map_err(|_| de::Error::invalid_length(length, &"bytes of the expected length"))
    }
}

/// Visitor of [`ByteString`]. Takes a base64 string or a byte string.
struct ByteStringVisitor;

impl de::Visitor<'_> for ByteStringVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a byte string or a base64 string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        B64.decode(value).map_err(E::custom)
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(value.to_vec())
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(value)
    }
}
