//! Edit checks against the Ask registers that a change writes (milestone 12).
//!
//! An edit from the UI carries the write ids of the Ask registers it read. The
//! transaction refuses the edit if a register it writes holds other write ids
//! than it read, if that register holds a conflict, or if it writes an Ask
//! register whose write ids it did not carry. A register it requests to write
//! and holds a conflict refuses it too, even if the written value equals the
//! shown value.
//!
//! A writer outside the UI never fails on a conflict. It reads the write ids
//! inside the transaction, and each write supersedes every value of its
//! register. A register it requests to write that holds a conflict is written
//! with the shown value if the change left it unchanged, so the conflict is
//! resolved whatever the value.
//!
//! A change that declares neither is refused if it writes an Ask register of an
//! entry the sync state holds. A new entry carries no write ids. Trash, move,
//! and restore change role slots only as stored, not as resolved, so the diff
//! finds no write to the slot and none of them needs its write ids.
//!
//! The check runs after the joins of the transaction and before the mint. A
//! refused edit saves the join, as a transaction with no requested change.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::crdt::{CausalState, MvRegister, Policy, ReplicaId, WriteId};
use super::diff::LocalEdits;
use super::model::SyncState;
use super::resolve::{Choice, Resolve};
use super::view::{AskRegister, Conflict, Entity, VaultView};
use crate::secrets::vaults::format::short_id::ShortId;

/// Write ids of Ask registers, by register.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadSet {
    registers: BTreeMap<Conflict, BTreeSet<WriteId>>,
}

impl ReadSet {
    /// Record that `register` held `write_ids` when it was read.
    pub fn insert(&mut self, register: Conflict, write_ids: BTreeSet<WriteId>) {
        self.registers.insert(register, write_ids);
    }

    /// Write ids that `register` held when it was read.
    pub fn get(&self, register: &Conflict) -> Option<&BTreeSet<WriteId>> {
        self.registers.get(register)
    }

    /// Registers and their write ids, in register order.
    pub fn iter(&self) -> impl Iterator<Item = (&Conflict, &BTreeSet<WriteId>)> {
        self.registers.iter()
    }

    /// Add every register of `other`, replacing the write ids of a register
    /// both hold.
    pub fn extend(&mut self, other: ReadSet) {
        self.registers.extend(other.registers);
    }
}

/// How the Ask registers that a change writes are checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum EditMode {
    /// Change that declared no read. A write to an Ask register of an entry
    /// the sync state holds is refused.
    #[default]
    Undeclared,
    /// Edit from the UI, with the write ids it read.
    Ui(ReadSet),
    /// Writer outside the UI, such as the broker, autofill, a passkey save, or
    /// `ap`.
    Writer,
}

/// Edit check of one transaction, declared on the vault handle by the
/// requested change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EditRequest {
    pub mode: EditMode,
    /// Ask registers the change requests to write, whether or not the value
    /// changes.
    pub requested: BTreeSet<Conflict>,
}

/// Reason an edit is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    /// The register holds other write ids than the edit read.
    Changed,
    /// The register holds a conflict. It is resolved before any edit.
    Conflicted,
    /// The edit wrote the register and did not carry its write ids.
    NotCarried,
}

/// Refusal of an edit, with the register that refused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EditRefusal {
    pub register: Conflict,
    pub reason: RefusalReason,
}

impl fmt::Display for EditRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let register = self.register.register.name();
        let entity = match self.register.entity {
            Entity::Vault => "the vault".to_string(),
            Entity::Item(id) => format!("item {}", ShortId::encode_uuid(id)),
            Entity::Credential(id) => format!("field {}", ShortId::encode_uuid(id)),
        };
        match self.reason {
            RefusalReason::Changed => {
                write!(f, "The {register} of {entity} changed since it was read")
            },
            RefusalReason::Conflicted => write!(
                f,
                "The {register} of {entity} has a conflict to resolve before it is edited"
            ),
            RefusalReason::NotCarried => write!(
                f,
                "The {register} of {entity} was changed by a request that did not read it"
            ),
        }
    }
}

impl std::error::Error for EditRefusal {}

impl AskRegister {
    /// Register name, as the FFI and error messages give it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Title => "title",
            Self::Category => "category",
            Self::Key => "key",
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Kind => "kind",
            Self::Value => "value",
        }
    }

    /// Register named `name` by [`Self::name`].
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "name" => Self::Name,
            "title" => Self::Title,
            "category" => Self::Category,
            "key" => Self::Key,
            "username" => Self::Username,
            "password" => Self::Password,
            "totp" => Self::Totp,
            "kind" => Self::Kind,
            "value" => Self::Value,
            _ => return None,
        })
    }
}

/// Write ids of `register` in `state`. `None` if the state lacks the entity
/// or the entity has no such register.
pub fn write_ids(state: &CausalState<SyncState>, register: Conflict) -> Option<BTreeSet<WriteId>> {
    fn ids<T, P: Policy>(values: &MvRegister<T, P>) -> BTreeSet<WriteId> {
        values.values().map(|(id, _)| id).collect()
    }
    let store = &state.store;
    Some(match (register.entity, register.register) {
        (Entity::Vault, AskRegister::Name) => ids(&store.name),
        (Entity::Item(id), kind) => {
            let item = store.items.get(&id)?;
            match kind {
                AskRegister::Title => ids(&item.title),
                AskRegister::Category => ids(&item.category),
                AskRegister::Key => ids(&item.key),
                AskRegister::Username => ids(&item.username),
                AskRegister::Password => ids(&item.password),
                AskRegister::Totp => ids(&item.totp),
                _ => return None,
            }
        },
        (Entity::Credential(id), kind) => {
            let credential = store.credentials.get(&id)?;
            match kind {
                AskRegister::Title => ids(&credential.title),
                AskRegister::Kind => ids(&credential.kind),
                AskRegister::Key => ids(&credential.key),
                AskRegister::Value => ids(&credential.value),
                _ => return None,
            }
        },
        _ => return None,
    })
}

/// Write ids of every Ask register of a sync state, and the registers its
/// view shows as conflicts, for edits from the UI.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReads {
    pub reads: ReadSet,
    pub conflicts: BTreeSet<Conflict>,
}

impl SyncReads {
    const ITEM_REGISTERS: [AskRegister; 6] = [
        AskRegister::Title,
        AskRegister::Category,
        AskRegister::Key,
        AskRegister::Username,
        AskRegister::Password,
        AskRegister::Totp,
    ];
    const CREDENTIAL_REGISTERS: [AskRegister; 4] = [
        AskRegister::Title,
        AskRegister::Kind,
        AskRegister::Key,
        AskRegister::Value,
    ];

    /// Reads of `state`. A register that holds no value is read with no
    /// write ids.
    pub fn of(state: &CausalState<SyncState>) -> Self {
        let store = &state.store;
        let entities = std::iter::once((Entity::Vault, &[AskRegister::Name][..]))
            .chain(
                store
                    .items
                    .iter()
                    .map(|(id, _)| (Entity::Item(*id), &Self::ITEM_REGISTERS[..])),
            )
            .chain(
                store
                    .credentials
                    .iter()
                    .map(|(id, _)| (Entity::Credential(*id), &Self::CREDENTIAL_REGISTERS[..])),
            );
        let mut reads = ReadSet::default();
        for (entity, registers) in entities {
            for register in registers {
                let register = Conflict {
                    entity,
                    register: *register,
                };
                if let Some(ids) = write_ids(state, register) {
                    reads.insert(register, ids);
                }
            }
        }
        let conflicts = VaultView::of(state).conflicts().iter().copied().collect();
        Self { reads, conflicts }
    }
}

/// Request to resolve a conflict by choosing one value of its register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvePick {
    pub register: Conflict,
    /// Write ids of the register values the request read.
    pub read: BTreeSet<WriteId>,
    /// Write id of the chosen value.
    pub chosen: WriteId,
}

impl ResolvePick {
    /// Resolve request that writes the value at `chosen`. `None` if the
    /// register no longer holds it.
    pub(crate) fn resolve(&self, state: &CausalState<SyncState>) -> Option<Resolve> {
        Some(Resolve {
            choice: Choice::of(state, self.register, Some(self.chosen))?,
            read: self.read.clone(),
        })
    }
}

/// Value of a conflict, with the Mac that wrote it, for the conflict UI.
#[derive(Clone, Debug, PartialEq)]
pub struct ConflictValue {
    pub write_id: WriteId,
    pub value: Choice,
    /// Mac that wrote the value. `None` if the state holds no info on the
    /// actor.
    pub replica: Option<ReplicaId>,
    /// Display name of that Mac.
    pub replica_name: Option<String>,
    /// Unix seconds by the writer's clock.
    pub written_at: i64,
}

/// Conflict with its values, shown value first.
#[derive(Clone, Debug, PartialEq)]
pub struct ConflictDetail {
    pub register: Conflict,
    /// Write ids of every value, for a resolve request.
    pub read: BTreeSet<WriteId>,
    pub values: Vec<ConflictValue>,
}

impl ConflictDetail {
    /// Conflicts of the view of `state`, each with its values.
    pub fn of(state: &CausalState<SyncState>) -> Vec<Self> {
        let view = VaultView::of(state);
        view.conflicts()
            .iter()
            .filter_map(|register| Self::of_register(state, &view, *register))
            .collect()
    }

    fn of_register(
        state: &CausalState<SyncState>,
        view: &VaultView,
        register: Conflict,
    ) -> Option<Self> {
        let read = write_ids(state, register)?;
        let mut values: Vec<ConflictValue> = Choice::ordered(state, register)?
            .into_iter()
            .map(|(write_id, written_at, value)| {
                let replica = state.actors.get(&write_id.actor).map(|a| a.replica);
                ConflictValue {
                    write_id,
                    value,
                    replica,
                    replica_name: replica.and_then(|r| view.replica_names.get(&r).cloned()),
                    written_at,
                }
            })
            .collect();
        values.reverse();
        Some(Self {
            register,
            read,
            values,
        })
    }
}

impl EditRequest {
    /// Check `edits`, the local edits of the change, against `state`, the
    /// joined state, by the mode of the request.
    ///
    /// For a writer outside the UI, each requested register that holds a
    /// conflict and that `edits` leave unwritten is added as a write of its
    /// shown value. A writer is never refused.
    pub(crate) fn check(
        &self,
        state: &CausalState<SyncState>,
        edits: &mut LocalEdits,
    ) -> Result<(), EditRefusal> {
        let exists = |register: &Conflict| match register.entity {
            Entity::Vault => true,
            Entity::Item(id) => state.store.items.get(&id).is_some(),
            Entity::Credential(id) => state.store.credentials.get(&id).is_some(),
        };
        let written: BTreeSet<Conflict> = edits
            .edits
            .iter()
            .filter_map(|edit| edit.ask_register())
            .filter(exists)
            .collect();
        let requested: BTreeSet<Conflict> = self.requested.iter().copied().filter(exists).collect();
        let refuse = |register, reason| Err(EditRefusal { register, reason });

        match &self.mode {
            EditMode::Undeclared => match written.first() {
                Some(register) => refuse(*register, RefusalReason::NotCarried),
                None => Ok(()),
            },
            EditMode::Ui(reads) => {
                let conflicts: BTreeSet<Conflict> =
                    VaultView::of(state).conflicts().iter().copied().collect();
                for register in &written {
                    let Some(read) = reads.get(register) else {
                        return refuse(*register, RefusalReason::NotCarried);
                    };
                    if write_ids(state, *register).as_ref() != Some(read) {
                        return refuse(*register, RefusalReason::Changed);
                    }
                }
                match written.union(&requested).find(|r| conflicts.contains(r)) {
                    Some(register) => refuse(*register, RefusalReason::Conflicted),
                    None => Ok(()),
                }
            },
            EditMode::Writer => {
                let view = VaultView::of(state);
                for register in requested.difference(&written) {
                    if !view.conflicts().contains(register) {
                        continue;
                    }
                    if let Some(choice) = Choice::of(state, *register, None) {
                        edits.edits.push(choice.edit());
                    }
                }
                Ok(())
            },
        }
    }
}
