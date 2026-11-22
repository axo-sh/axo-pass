//! Write ids that edits from the UI carry, and the conflict resolution UI
//! (milestone 12).
//!
//! `list_items` gives each item the write ids of the Ask registers of the item
//! and its credentials, as `RegisterRead` records. An edit passes them back,
//! and the transaction refuses it with `EditRefused` if a register it writes
//! changed since the read, holds a conflict, or was not read. A vault that is
//! not synced has no reads and refuses no edit.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use axo_pass_core::secrets::vaults::sync::crdt::{ActorId, WriteId};
use axo_pass_core::secrets::vaults::sync::edit_check::{
    ConflictDetail, ReadSet, RefusalReason, ResolvePick, SyncReads,
};
use axo_pass_core::secrets::vaults::sync::resolve::Choice;
use axo_pass_core::secrets::vaults::sync::view::{AskRegister, Conflict, Entity};
use axo_pass_core::secrets::vaults::{
    FieldKind, ShortId, VaultHandle, VaultsManager, files, passkey,
};
use uuid::Uuid;

use crate::vault::{ensure_unlocked, parse_id};
use crate::*;

/// Write ids that the UI read for one Ask register.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct RegisterRead {
    /// `vault`, `item`, or `credential`.
    pub entity_kind: String,
    /// Short id of the item or credential. Empty for the vault.
    pub entity_id: String,
    /// `name`, `title`, `category`, `key`, `username`, `password`, `totp`,
    /// `kind`, or `value`.
    pub register: String,
    /// Write ids of the register values, opaque to the app.
    pub write_ids: String,
    /// The register holds a conflict, which is resolved before an edit.
    pub conflicted: bool,
}

/// One value of a conflict, with the Mac that wrote it.
#[derive(uniffi::Record, Clone, Debug)]
pub struct ConflictValueInfo {
    /// Write id of the value, opaque to the app. Passed to `resolve_conflict`.
    pub write_id: String,
    /// Value as text. A role slot is shown by the title of the field it
    /// names. A passkey is shown by its account name, and a file by its name.
    pub text: String,
    /// The value is a secret, shown only on request.
    pub concealed: bool,
    /// Name of the Mac that wrote the value. `None` if it is unknown.
    pub mac_name: Option<String>,
    /// This Mac wrote the value.
    pub this_mac: bool,
    /// Unix seconds by the clock of the Mac that wrote it.
    pub written_at: i64,
    /// The vault shows this value until the conflict is resolved.
    pub shown: bool,
}

/// Ask register with more than one value, for the conflict resolution UI.
#[derive(uniffi::Record, Clone, Debug)]
pub struct ConflictInfo {
    /// `vault`, `item`, or `credential`.
    pub entity_kind: String,
    /// Short id of the item or credential. Empty for the vault.
    pub entity_id: String,
    pub register: String,
    /// Key and title of the item that holds the register. `None` for the
    /// vault name.
    pub item_key: Option<String>,
    pub item_title: Option<String>,
    /// Key and title of the credential that holds the register. `None` for
    /// an item or vault register.
    pub credential_key: Option<String>,
    pub credential_title: Option<String>,
    /// Write ids of every value, opaque to the app. Passed to
    /// `resolve_conflict`.
    pub read: String,
    /// Shown value first, then the others in order of their writes, newest
    /// first.
    pub values: Vec<ConflictValueInfo>,
}

/// Write ids as the app holds them: `{actor}:{seq}`, joined by commas.
fn encode_write_ids<'a>(ids: impl IntoIterator<Item = &'a WriteId>) -> String {
    ids.into_iter()
        .map(encode_write_id)
        .collect::<Vec<_>>()
        .join(",")
}

fn encode_write_id(id: &WriteId) -> String {
    format!("{}:{}", id.actor.0.simple(), id.seq)
}

fn parse_write_id(text: &str) -> Result<WriteId, FfiError> {
    let invalid = || FfiError::InvalidInput(format!("Invalid write id: {text}"));
    let (actor, seq) = text.split_once(':').ok_or_else(invalid)?;
    Ok(WriteId {
        actor: ActorId(Uuid::parse_str(actor).map_err(|_| invalid())?),
        seq: seq.parse().map_err(|_| invalid())?,
    })
}

fn parse_write_ids(text: &str) -> Result<BTreeSet<WriteId>, FfiError> {
    text.split(',')
        .filter(|id| !id.is_empty())
        .map(parse_write_id)
        .collect()
}

fn entity_parts(entity: Entity) -> (String, String) {
    match entity {
        Entity::Vault => ("vault".to_string(), String::new()),
        Entity::Item(id) => ("item".to_string(), ShortId::encode_uuid(id)),
        Entity::Credential(id) => ("credential".to_string(), ShortId::encode_uuid(id)),
    }
}

fn parse_register(kind: &str, id: &str, register: &str) -> Result<Conflict, FfiError> {
    let entity = match kind {
        "vault" => Entity::Vault,
        "item" => Entity::Item(parse_id(id)?),
        "credential" => Entity::Credential(parse_id(id)?),
        other => return Err(FfiError::InvalidInput(format!("Unknown entity {other:?}"))),
    };
    let register = AskRegister::parse(register)
        .ok_or_else(|| FfiError::InvalidInput(format!("Unknown register {register:?}")))?;
    Ok(Conflict { entity, register })
}

/// Read set of the registers that `reads` name.
pub(crate) fn read_set(reads: &[RegisterRead]) -> Result<ReadSet, FfiError> {
    let mut set = ReadSet::default();
    for read in reads {
        let register = parse_register(&read.entity_kind, &read.entity_id, &read.register)?;
        set.insert(register, parse_write_ids(&read.write_ids)?);
    }
    Ok(set)
}

/// Reads of `reads` as the app holds them, by the id of the entity that
/// holds each register. The vault name is under the nil id.
pub(crate) fn register_reads(reads: &SyncReads) -> HashMap<Uuid, Vec<RegisterRead>> {
    let mut by_entity: HashMap<Uuid, Vec<RegisterRead>> = HashMap::new();
    for (register, ids) in reads.reads.iter() {
        let id = match register.entity {
            Entity::Vault => Uuid::nil(),
            Entity::Item(id) | Entity::Credential(id) => id,
        };
        let (entity_kind, entity_id) = entity_parts(register.entity);
        by_entity.entry(id).or_default().push(RegisterRead {
            entity_kind,
            entity_id,
            register: register.register.name().to_string(),
            write_ids: encode_write_ids(ids),
            conflicted: reads.conflicts.contains(register),
        });
    }
    by_entity
}

/// Reads of item `item_id` and of `credentials`, its credential ids.
pub(crate) fn item_reads(
    by_entity: &HashMap<Uuid, Vec<RegisterRead>>,
    item_id: Uuid,
    credentials: impl IntoIterator<Item = Uuid>,
) -> Vec<RegisterRead> {
    std::iter::once(item_id)
        .chain(credentials)
        .filter_map(|id| by_entity.get(&id))
        .flatten()
        .cloned()
        .collect()
}

/// Fields of [`FfiError::EditRefused`] for `reason`.
pub(crate) fn refusal_reason(reason: RefusalReason) -> &'static str {
    match reason {
        RefusalReason::Changed => "changed",
        RefusalReason::Conflicted => "conflicted",
        RefusalReason::NotCarried => "not_read",
    }
}

pub(crate) fn refusal_parts(register: Conflict) -> (String, String, String) {
    let (kind, id) = entity_parts(register.entity);
    (kind, id, register.register.name().to_string())
}

/// Item and credential of the unlocked vault `vault` that hold `register`, by
/// key and title.
struct Holder {
    item: Option<(String, String)>,
    credential: Option<(String, String, FieldKind)>,
}

impl Holder {
    fn of(vault: &VaultHandle, entity: Entity) -> Self {
        let items = vault.list_items().unwrap_or_default();
        match entity {
            Entity::Vault => Self {
                item: None,
                credential: None,
            },
            Entity::Item(id) => Self {
                item: items
                    .iter()
                    .find(|i| i.id == id)
                    .map(|i| (i.key.clone(), i.title.clone())),
                credential: None,
            },
            Entity::Credential(id) => {
                let found = items.iter().find_map(|item| {
                    item.credentials.values().find(|c| c.id == id).map(|c| {
                        (
                            (item.key.clone(), item.title.clone()),
                            (c.key.clone(), c.title.clone(), c.kind.clone()),
                        )
                    })
                });
                Self {
                    item: found.as_ref().map(|(item, _)| item.clone()),
                    credential: found.map(|(_, credential)| credential),
                }
            },
        }
    }
}

/// Text of a conflict value, and whether it is concealed. `vault` names the
/// fields of a role slot, and `kind` is the kind of the credential of a value.
fn value_text(vault: &VaultHandle, choice: &Choice, kind: Option<&FieldKind>) -> (String, bool) {
    let field = |id: &Option<Uuid>| match id {
        None => "None".to_string(),
        Some(id) => vault
            .list_items()
            .unwrap_or_default()
            .iter()
            .find_map(|item| item.credentials.values().find(|c| c.id == *id))
            .map(|c| c.title.clone())
            .unwrap_or_else(|| "Deleted field".to_string()),
    };
    match choice {
        Choice::Name(name) => (name.clone().unwrap_or_default(), false),
        Choice::ItemTitle(_, text)
        | Choice::ItemKey(_, text)
        | Choice::CredentialTitle(_, text)
        | Choice::CredentialKey(_, text) => (text.clone(), false),
        Choice::Category(_, category) => (
            category.clone().unwrap_or_else(|| "None".to_string()),
            false,
        ),
        Choice::Username(_, slot) | Choice::Password(_, slot) | Choice::Totp(_, slot) => {
            (field(slot), false)
        },
        Choice::Kind(_, kind) => (FieldKindInfo::from(kind).kind, false),
        Choice::Value(_, value) => {
            let value = value.0.as_str();
            match kind {
                Some(FieldKind::Passkey) => {
                    let name = passkey::summary(value)
                        .and_then(|s| s.username.or(s.user_display_name).or(Some(s.rp_id)));
                    (name.unwrap_or_else(|| "Passkey".to_string()), false)
                },
                Some(FieldKind::File) => {
                    let name = files::summary(value).map(|s| s.name);
                    (name.unwrap_or_else(|| "File".to_string()), false)
                },
                _ => (value.to_string(), true),
            }
        },
    }
}

fn conflict_info(vault: &VaultHandle, detail: ConflictDetail) -> ConflictInfo {
    let this_mac = vault.replica_id().ok().flatten();
    let holder = Holder::of(vault, detail.register.entity);
    let kind = holder.credential.as_ref().map(|(_, _, kind)| kind);
    let values = detail
        .values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let (text, concealed) = value_text(vault, &value.value, kind);
            ConflictValueInfo {
                write_id: encode_write_id(&value.write_id),
                text,
                concealed,
                mac_name: value.replica_name.clone(),
                this_mac: value.replica.is_some_and(|r| Some(r.0) == this_mac),
                written_at: value.written_at,
                shown: index == 0,
            }
        })
        .collect();
    let (entity_kind, entity_id) = entity_parts(detail.register.entity);
    let (item_key, item_title) = holder.item.unzip();
    let (credential_key, credential_title) = holder
        .credential
        .map(|(key, title, _)| (key, title))
        .unzip();
    ConflictInfo {
        entity_kind,
        entity_id,
        register: detail.register.register.name().to_string(),
        item_key,
        item_title,
        credential_key,
        credential_title,
        read: encode_write_ids(&detail.read),
        values,
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Write ids of the vault name, for `update_vault`. Empty for a vault
    /// that is not synced. Unlocks the vault as `list_items` does.
    pub async fn vault_reads(&self, vault_key: String) -> Result<Vec<RegisterRead>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let files = m.store().files().clone();
            let vault = m.get_or_create_vault_mut(&vault_key)?;
            let reads = files.sync_reads(vault)?;
            Ok(reads
                .map(|reads| {
                    register_reads(&reads)
                        .remove(&Uuid::nil())
                        .unwrap_or_default()
                })
                .unwrap_or_default())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Conflicts of a synced vault, each with its values, the name of the Mac
    /// that wrote each value, and its write time. Empty for a vault that is
    /// not synced. Unlocks the vault as `list_items` does.
    pub async fn list_conflicts(&self, vault_key: String) -> Result<Vec<ConflictInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let files = m.store().files().clone();
            let vault = m.get_or_create_vault_mut(&vault_key)?;
            let details = files.conflicts(vault)?;
            Ok(details
                .into_iter()
                .map(|detail| conflict_info(vault, detail))
                .collect())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Resolve a conflict of `list_conflicts` with the value `chosen_write_id`.
    /// The chosen value supersedes every value on every Mac. Each field value
    /// not chosen goes to its previous values. Fails with `EditRefused` and
    /// reason `changed` if the register changed since `read`, and the app
    /// lists the conflicts again.
    pub async fn resolve_conflict(
        &self,
        vault_key: String,
        entity_kind: String,
        entity_id: String,
        register: String,
        read: String,
        chosen_write_id: String,
    ) -> Result<(), FfiError> {
        let pick = ResolvePick {
            register: parse_register(&entity_kind, &entity_id, &register)?,
            read: parse_write_ids(&read)?,
            chosen: parse_write_id(&chosen_write_id)?,
        };
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            VaultsManager::resolve_conflict(&manager, &vault_key, pick).map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_ids_round_trip() {
        let ids: BTreeSet<WriteId> = [
            WriteId {
                actor: ActorId(Uuid::from_u128(1)),
                seq: 3,
            },
            WriteId {
                actor: ActorId(Uuid::from_u128(2)),
                seq: 40,
            },
        ]
        .into();
        assert_eq!(parse_write_ids(&encode_write_ids(&ids)).unwrap(), ids);
        assert!(parse_write_ids("").unwrap().is_empty());
        assert!(parse_write_id("nope").is_err());
    }

    #[test]
    fn register_reads_round_trip_through_read_set() {
        let (item, credential) = (Uuid::from_u128(10), Uuid::from_u128(11));
        let write_id = |seq| WriteId {
            actor: ActorId(Uuid::from_u128(1)),
            seq,
        };
        let name = Conflict {
            entity: Entity::Vault,
            register: AskRegister::Name,
        };
        let title = Conflict {
            entity: Entity::Item(item),
            register: AskRegister::Title,
        };
        let value = Conflict {
            entity: Entity::Credential(credential),
            register: AskRegister::Value,
        };
        let mut reads = SyncReads::default();
        reads.reads.insert(name, [write_id(1)].into());
        reads.reads.insert(title, [write_id(2)].into());
        reads.reads.insert(value, [write_id(3), write_id(4)].into());
        reads.conflicts.insert(value);

        let by_entity = register_reads(&reads);
        let vault = &by_entity[&Uuid::nil()];
        assert_eq!(vault.len(), 1);
        assert_eq!(vault[0].entity_kind, "vault");
        assert_eq!(vault[0].entity_id, "");

        let item_reads = item_reads(&by_entity, item, [credential]);
        assert_eq!(item_reads.len(), 2);
        let conflicted: Vec<&str> = item_reads
            .iter()
            .filter(|read| read.conflicted)
            .map(|read| read.register.as_str())
            .collect();
        assert_eq!(conflicted, ["value"]);

        let set = read_set(&item_reads).unwrap();
        assert_eq!(set.get(&title), reads.reads.get(&title));
        assert_eq!(set.get(&value), reads.reads.get(&value));
        assert_eq!(set.get(&name), None);
    }

    #[test]
    fn unknown_register_refused() {
        assert!(parse_register("vault", "", "websites").is_err());
        assert!(parse_register("folder", "", "name").is_err());
    }
}
