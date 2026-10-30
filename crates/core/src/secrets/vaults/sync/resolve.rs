//! History ids, resolve requests, and "Keep `{key}-{suffix}`".
//!
//! A history entry for a replaced credential value takes an id derived from
//! the credential id and the write id of the replaced value. Macs that replace
//! the same value, or resolve the same conflict, therefore write one entry.
//!
//! A resolve request writes the chosen value into an Ask register under the
//! write id of the transaction, whatever the diff finds, so it supersedes every
//! value of the register. "Keep `{key}-{suffix}`" writes the shown key into the
//! key register the same way.

use std::collections::BTreeSet;

use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::crdt::{Ask, CausalState, MvRegister, ReplicaId, Versioned, WriteId};
use super::diff::{CredentialWrite, Edit, ItemWrite, LocalEdits};
use super::model::{CredentialId, HistoryId, HistoryValue, ItemId, SecretText, SyncState};
use super::view::{AskRegister, Conflict, Entity, VaultView};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;

/// Derived ids of history entries.
pub struct HistoryIds;

impl HistoryIds {
    const PREFIX: &[u8] = b"ap-history-id-v1:";

    /// Id of the history entry of the value that `write_id` wrote into the
    /// value register of `credential`.
    ///
    /// The first 16 bytes of SHA-256 over the prefix, the credential id, the
    /// actor id, and the sequence number as 8 bytes big-endian. No version
    /// bits are set.
    pub fn derive(credential: CredentialId, write_id: WriteId) -> HistoryId {
        let mut hash = Sha256::new();
        hash.update(Self::PREFIX);
        hash.update(credential.as_bytes());
        hash.update(write_id.actor.0.as_bytes());
        hash.update(write_id.seq.to_be_bytes());
        let digest = hash.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Uuid::from_bytes(bytes)
    }

    /// Give each history entry that the requested change added to `vault`
    /// the id derived from the write id of the value it replaced.
    ///
    /// Runs after the requested change and before the diff. An added entry is
    /// one that the sync state lacks. The value it replaced is the shown
    /// value of the credential, so the first added entry that holds the shown
    /// value takes the derived id. Other added entries keep their random ids,
    /// as do the entries of a credential whose value register holds no value,
    /// and an entry whose derived id the credential already holds.
    pub fn rewrite(state: &CausalState<SyncState>, vault: &mut Vault) -> Result<(), Error> {
        let mut renames = Vec::new();
        for entry in &vault.sync_entries()?.credentials {
            let id = entry.overview.id;
            let Some(credential) = state.store.credentials.get(&id) else {
                continue;
            };
            let Some((key, shown)) = credential.value.ordered().pop() else {
                continue;
            };
            let derived = Self::derive(id, key.write_id);
            if entry.history.iter().any(|h| h.id == derived) {
                continue;
            }
            let added = entry.history.iter().find(|h| {
                let known = credential
                    .history
                    .get(&h.id)
                    .is_some_and(|r| r.shown().is_some());
                !known && h.value.expose_secret().as_str() == shown.value.0.as_str()
            });
            if let Some(added) = added {
                renames.push((id, added.id, derived));
            }
        }

        let mut writer = vault.sync_writer();
        for (credential, from, to) in renames {
            writer.set_history_id(credential, from, to)?;
        }
        Ok(())
    }
}

/// Request to resolve an Ask register with a chosen value.
#[derive(Clone, Debug, PartialEq)]
pub struct Resolve {
    pub choice: Choice,
    /// Write ids of the register values the request read.
    pub read: BTreeSet<WriteId>,
}

/// Ask register and the value chosen for it. The value can equal a value of
/// the register or be a new one.
#[derive(Clone, Debug, PartialEq)]
pub enum Choice {
    Name(Option<String>),
    ItemTitle(ItemId, String),
    Category(ItemId, Option<String>),
    ItemKey(ItemId, String),
    Username(ItemId, Option<CredentialId>),
    Password(ItemId, Option<CredentialId>),
    Totp(ItemId, Option<CredentialId>),
    CredentialTitle(CredentialId, String),
    Kind(CredentialId, FieldKind),
    CredentialKey(CredentialId, String),
    Value(CredentialId, SecretText),
}

/// What a resolve request replaced, for `sync.conflict_resolved`.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolveReport {
    /// Resolved register and its entity.
    pub register: Conflict,
    /// Register values that differ from the chosen value, in order key order.
    pub not_chosen: Vec<NotChosen>,
}

/// Register value that a resolve request did not choose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotChosen {
    pub write_id: WriteId,
    /// Mac that wrote the value. `None` if the state holds no info on the
    /// actor.
    pub replica: Option<ReplicaId>,
    /// Unix seconds by the writer's clock.
    pub written_at: i64,
}

/// Refusal of a resolve or keep request.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ResolveError {
    #[error("{0:?} is not in the sync state")]
    Missing(Entity),
    /// The register holds other values than the request read.
    #[error("{0:?} changed since it was read")]
    Changed(Conflict),
}

impl Choice {
    fn register(&self) -> Conflict {
        let (entity, register) = match self {
            Self::Name(_) => (Entity::Vault, AskRegister::Name),
            Self::ItemTitle(id, _) => (Entity::Item(*id), AskRegister::Title),
            Self::Category(id, _) => (Entity::Item(*id), AskRegister::Category),
            Self::ItemKey(id, _) => (Entity::Item(*id), AskRegister::Key),
            Self::Username(id, _) => (Entity::Item(*id), AskRegister::Username),
            Self::Password(id, _) => (Entity::Item(*id), AskRegister::Password),
            Self::Totp(id, _) => (Entity::Item(*id), AskRegister::Totp),
            Self::CredentialTitle(id, _) => (Entity::Credential(*id), AskRegister::Title),
            Self::Kind(id, _) => (Entity::Credential(*id), AskRegister::Kind),
            Self::CredentialKey(id, _) => (Entity::Credential(*id), AskRegister::Key),
            Self::Value(id, _) => (Entity::Credential(*id), AskRegister::Value),
        };
        Conflict { entity, register }
    }

    /// Write of the chosen value.
    fn edit(self) -> Edit {
        match self {
            Self::Name(name) => Edit::Name(name),
            Self::ItemTitle(id, title) => Edit::Item(id, ItemWrite::Title(title)),
            Self::Category(id, category) => Edit::Item(id, ItemWrite::Category(category)),
            Self::ItemKey(id, key) => Edit::Item(id, ItemWrite::Key(key)),
            Self::Username(id, slot) => Edit::Item(id, ItemWrite::Username(slot)),
            Self::Password(id, slot) => Edit::Item(id, ItemWrite::Password(slot)),
            Self::Totp(id, slot) => Edit::Item(id, ItemWrite::Totp(slot)),
            Self::CredentialTitle(id, title) => Edit::Credential(id, CredentialWrite::Title(title)),
            Self::Kind(id, kind) => Edit::Credential(id, CredentialWrite::Kind(kind)),
            Self::CredentialKey(id, key) => Edit::Credential(id, CredentialWrite::Key(key)),
            Self::Value(id, value) => Edit::Credential(id, CredentialWrite::Value(value)),
        }
    }
}

impl Edit {
    /// Ask register that this edit writes, if any.
    fn ask_register(&self) -> Option<Conflict> {
        let (entity, register) = match self {
            Self::Name(_) => (Entity::Vault, AskRegister::Name),
            Self::Item(id, write) => {
                let register = match write {
                    ItemWrite::Title(_) => AskRegister::Title,
                    ItemWrite::Category(_) => AskRegister::Category,
                    ItemWrite::Key(_) => AskRegister::Key,
                    ItemWrite::Username(_) => AskRegister::Username,
                    ItemWrite::Password(_) => AskRegister::Password,
                    ItemWrite::Totp(_) => AskRegister::Totp,
                    ItemWrite::Folder(_) | ItemWrite::Trashed(_) => return None,
                };
                (Entity::Item(*id), register)
            },
            Self::Credential(id, write) => {
                let register = match write {
                    CredentialWrite::Title(_) => AskRegister::Title,
                    CredentialWrite::Kind(_) => AskRegister::Kind,
                    CredentialWrite::Key(_) => AskRegister::Key,
                    CredentialWrite::Value(_) => AskRegister::Value,
                    CredentialWrite::Item(_)
                    | CredentialWrite::Placement(_)
                    | CredentialWrite::Trashed(_) => return None,
                };
                (Entity::Credential(*id), register)
            },
            _ => return None,
        };
        Some(Conflict { entity, register })
    }
}

impl LocalEdits {
    /// Add a resolve request to these edits, with `now` in Unix seconds as
    /// the time of each history entry it writes.
    ///
    /// The chosen value is written whatever the diff found, and replaces any
    /// edit of the diff to the same register. For a credential value, each
    /// value that is not chosen and not empty is written to `history` under
    /// its derived id. Fails if the register holds other write ids than the
    /// request read, or if the entity is missing.
    pub fn resolve(
        &mut self,
        state: &CausalState<SyncState>,
        request: Resolve,
        now: i64,
    ) -> Result<ResolveReport, ResolveError> {
        let Resolve { choice, read } = request;
        let register = choice.register();
        let store = &state.store;
        let item = |id: &ItemId| {
            store
                .items
                .get(id)
                .ok_or(ResolveError::Missing(Entity::Item(*id)))
        };
        let credential = |id: &CredentialId| {
            store
                .credentials
                .get(id)
                .ok_or(ResolveError::Missing(Entity::Credential(*id)))
        };

        let mut history = Vec::new();
        let not_chosen = match &choice {
            Choice::Name(name) => {
                Self::times(Self::not_chosen(&store.name, &read, name, register)?)
            },
            Choice::ItemTitle(id, title) => {
                Self::times(Self::not_chosen(&item(id)?.title, &read, title, register)?)
            },
            Choice::Category(id, category) => Self::times(Self::not_chosen(
                &item(id)?.category,
                &read,
                category,
                register,
            )?),
            Choice::ItemKey(id, key) => {
                Self::times(Self::not_chosen(&item(id)?.key, &read, key, register)?)
            },
            Choice::Username(id, slot) => Self::times(Self::not_chosen(
                &item(id)?.username,
                &read,
                slot,
                register,
            )?),
            Choice::Password(id, slot) => Self::times(Self::not_chosen(
                &item(id)?.password,
                &read,
                slot,
                register,
            )?),
            Choice::Totp(id, slot) => {
                Self::times(Self::not_chosen(&item(id)?.totp, &read, slot, register)?)
            },
            Choice::CredentialTitle(id, title) => Self::times(Self::not_chosen(
                &credential(id)?.title,
                &read,
                title,
                register,
            )?),
            Choice::Kind(id, kind) => Self::times(Self::not_chosen(
                &credential(id)?.kind,
                &read,
                kind,
                register,
            )?),
            Choice::CredentialKey(id, key) => Self::times(Self::not_chosen(
                &credential(id)?.key,
                &read,
                key,
                register,
            )?),
            Choice::Value(id, value) => {
                let values = Self::not_chosen(&credential(id)?.value, &read, value, register)?;
                for (write_id, versioned) in &values {
                    if versioned.value.0.is_empty() {
                        continue;
                    }
                    let entry = HistoryValue {
                        value: versioned.value.clone(),
                        replaced_at: now,
                    };
                    history.push(Edit::History(
                        *id,
                        HistoryIds::derive(*id, *write_id),
                        entry,
                    ));
                }
                Self::times(values)
            },
        };

        self.write_request(register, choice.edit());
        self.edits.extend(history);
        let not_chosen = not_chosen
            .into_iter()
            .map(|(write_id, written_at)| NotChosen {
                write_id,
                replica: state.actors.get(&write_id.actor).map(|a| a.replica),
                written_at,
            })
            .collect();
        Ok(ResolveReport {
            register,
            not_chosen,
        })
    }

    /// Add a write of the shown key of `entity` into its key register, for
    /// "Keep `{key}-{suffix}`". Fails if `view` lacks the entity, or if it is
    /// the vault.
    pub fn keep_key(&mut self, view: &VaultView, entity: Entity) -> Result<(), ResolveError> {
        let missing = ResolveError::Missing(entity);
        let edit = match entity {
            Entity::Item(id) => {
                let key = view.items.get(&id).ok_or(missing)?.key.clone();
                Edit::Item(id, ItemWrite::Key(key))
            },
            Entity::Credential(id) => {
                let key = view.credentials.get(&id).ok_or(missing)?.key.clone();
                Edit::Credential(id, CredentialWrite::Key(key))
            },
            Entity::Vault => return Err(missing),
        };
        let register = Conflict {
            entity,
            register: AskRegister::Key,
        };
        self.write_request(register, edit);
        Ok(())
    }

    /// Replace the edits to `register` with `edit`.
    fn write_request(&mut self, register: Conflict, edit: Edit) {
        self.edits.retain(|e| e.ask_register() != Some(register));
        self.edits.push(edit);
    }

    /// Values of `values` that differ from `chosen`, in order key order.
    /// Fails if the write ids of `values` differ from `read`.
    fn not_chosen<'a, T: PartialEq>(
        values: &'a MvRegister<T, Ask>,
        read: &BTreeSet<WriteId>,
        chosen: &T,
        register: Conflict,
    ) -> Result<Vec<(WriteId, &'a Versioned<T>)>, ResolveError> {
        let held: BTreeSet<WriteId> = values.values().map(|(id, _)| id).collect();
        if held != *read {
            return Err(ResolveError::Changed(register));
        }
        Ok(values
            .ordered()
            .into_iter()
            .filter(|(_, v)| v.value != *chosen)
            .map(|(key, v)| (key.write_id, v))
            .collect())
    }

    /// Write id and write time of each value.
    fn times<T>(values: Vec<(WriteId, &Versioned<T>)>) -> Vec<(WriteId, i64)> {
        values
            .into_iter()
            .map(|(id, v)| (id, v.written_at))
            .collect()
    }
}
