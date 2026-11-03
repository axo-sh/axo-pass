//! Apply step: writes the view of a sync state into a vault.
//!
//! The vault is compared with the view by id, as the diff does, and each
//! difference is written through [`Vault::sync_writer`]. Values are written as
//! the view shows them, positions included, so the next diff finds no edits.
//! Keys are written in one bulk update after every other change. Signals are
//! assigned as a whole store, never merged or recorded, so no list is
//! trimmed.

use std::collections::{BTreeMap, BTreeSet};

use secrecy::ExposeSecret;

use super::model::{
    CredentialId, FolderId, FolderValue, HistoryId, HistoryValue, ItemId, SecretText, TrashValue,
};
use super::view::{CredentialView, Entity, ItemView, VaultView};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::autofill::item::{ItemAutofill, Website};
use crate::secrets::vaults::model::{
    DeletedInfo, PreviousValue, SyncWriter, Vault, VaultItemCredentialOverview, VaultItemOverview,
};
use crate::secrets::vaults::passkey::signals::{SignalEntry, SignalStore};

/// What [`VaultView::apply`] changed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ApplyReport {
    /// Entries whose key changed without a local edit, in id order. Items
    /// first.
    pub key_changes: Vec<KeyChange>,
    /// Entries whose key was written or that were added, and whose stored key
    /// is marked for a key notice.
    pub key_notices: Vec<Entity>,
    /// Every entity changed. Folders and signals count as the vault. Sections
    /// and websites count as their item, and history as its credential.
    pub changed: BTreeSet<Entity>,
}

/// Key of an entry before and after the apply step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyChange {
    pub entity: Entity,
    pub from: String,
    pub to: String,
}

impl VaultView {
    /// Write this view into `vault`.
    ///
    /// Entries the view lacks are purged, and entries the vault lacks are
    /// added with their ids. Fails if a vault mutation fails. The vault may
    /// then hold part of the view.
    pub fn apply(&self, vault: &mut Vault) -> Result<ApplyReport, Error> {
        Apply::new(self, vault)?.run()
    }

    /// [`Self::apply`], failing as a vault mutation fails at the first item
    /// for which `fault` holds, after the folders and the items before it
    /// are written.
    #[cfg(test)]
    pub(crate) fn apply_with_fault(
        &self,
        vault: &mut Vault,
        fault: ApplyFault,
    ) -> Result<ApplyReport, Error> {
        let mut apply = Apply::new(self, vault)?;
        apply.fault = Some(fault);
        apply.run()
    }
}

/// Item view whose apply fails, for tests of a view that a build cannot
/// apply.
#[cfg(test)]
pub(crate) type ApplyFault = fn(&ItemView) -> bool;

/// Signal entries by report key.
fn signals_by_key(store: &SignalStore) -> BTreeMap<String, SignalEntry> {
    store.entries().map(|entry| (entry.key(), entry)).collect()
}

/// Vault entries as they were before the apply step, live and trashed.
struct Stored {
    folders: BTreeMap<FolderId, FolderValue>,
    items: BTreeMap<ItemId, StoredItem>,
    credentials: BTreeMap<CredentialId, StoredCredential>,
}

struct StoredItem {
    /// Its `credentials` is not read.
    overview: VaultItemOverview,
    trashed: Option<TrashValue>,
}

struct StoredCredential {
    item: ItemId,
    overview: VaultItemCredentialOverview,
    trashed: Option<TrashValue>,
    /// Empty if the credential has no value.
    value: SecretText,
    history: BTreeMap<HistoryId, HistoryValue>,
}

impl Stored {
    fn of(vault: &Vault) -> Result<Self, Error> {
        let entries = vault.sync_entries()?;
        let folders = entries
            .folders
            .values()
            .map(|f| {
                let value = FolderValue {
                    title: f.title.clone(),
                    position: f.position,
                };
                (f.id, value)
            })
            .collect();
        let items = entries
            .items
            .iter()
            .map(|entry| {
                let item = StoredItem {
                    overview: entry.overview.clone(),
                    trashed: entry.trashed.as_ref().map(TrashValue::of),
                };
                (entry.overview.id, item)
            })
            .collect();
        let credentials = entries
            .credentials
            .iter()
            .map(|entry| {
                let history = entry
                    .history
                    .iter()
                    .map(|h| {
                        let value = HistoryValue {
                            value: SecretText::new(h.value.expose_secret().as_str()),
                            replaced_at: h.replaced_at,
                        };
                        (h.id, value)
                    })
                    .collect();
                let credential = StoredCredential {
                    item: entry.item,
                    overview: entry.overview.clone(),
                    trashed: entry.trashed.as_ref().map(TrashValue::of),
                    value: SecretText::new(entry.value.expose_secret().as_str()),
                    history,
                };
                (entry.overview.id, credential)
            })
            .collect();
        Ok(Self {
            folders,
            items,
            credentials,
        })
    }
}

/// One run of the apply step.
struct Apply<'a, 'v> {
    view: &'a VaultView,
    stored: Stored,
    writer: SyncWriter<'v>,
    report: ApplyReport,
    /// Keys for the bulk update.
    item_keys: BTreeMap<ItemId, String>,
    credential_keys: BTreeMap<CredentialId, String>,
    /// Entries the vault lacked.
    added: BTreeSet<Entity>,
    #[cfg(test)]
    fault: Option<ApplyFault>,
}

impl<'a, 'v> Apply<'a, 'v> {
    /// Apply step of `view` into `vault`, with the vault name and the signals
    /// written.
    fn new(view: &'a VaultView, vault: &'v mut Vault) -> Result<Self, Error> {
        let stored = Stored::of(vault)?;
        let mut report = ApplyReport::default();

        if vault.name != view.name {
            vault.name = view.name.clone();
            report.changed.insert(Entity::Vault);
        }
        if signals_by_key(vault.passkey_signals()) != signals_by_key(&view.signals) {
            vault.update_passkey_signals(|signals| *signals = view.signals.clone());
            report.changed.insert(Entity::Vault);
        }

        Ok(Self {
            view,
            stored,
            writer: vault.sync_writer(),
            report,
            item_keys: BTreeMap::new(),
            credential_keys: BTreeMap::new(),
            added: BTreeSet::new(),
            #[cfg(test)]
            fault: None,
        })
    }

    fn run(mut self) -> Result<ApplyReport, Error> {
        self.folders()?;
        self.items()?;
        self.credentials()?;
        self.credential_trash()?;
        self.item_trash()?;
        self.purge_items()?;
        self.slots()?;
        self.keys()?;
        Ok(self.report)
    }
}

impl Apply<'_, '_> {
    fn changed(&mut self, entity: Entity) {
        self.report.changed.insert(entity);
    }

    /// Folders the view lacks are purged after the others are written.
    fn folders(&mut self) -> Result<(), Error> {
        let view = self.view;
        for folder in &view.folders {
            let value = FolderValue {
                title: folder.title.clone(),
                position: folder.position,
            };
            if self.stored.folders.get(&folder.id) != Some(&value) {
                self.writer
                    .set_folder(folder.id, &folder.title, folder.position);
                self.changed(Entity::Vault);
            }
        }
        let shown: BTreeSet<FolderId> = view.folders.iter().map(|f| f.id).collect();
        let purged: Vec<FolderId> = self
            .stored
            .folders
            .keys()
            .filter(|id| !shown.contains(id))
            .copied()
            .collect();
        for id in purged {
            self.writer.purge_folder(id)?;
            self.changed(Entity::Vault);
        }
        Ok(())
    }

    /// Item registers, sections, and websites. Trash state and role slots
    /// are written once the credentials are in place.
    fn items(&mut self) -> Result<(), Error> {
        let view = self.view;
        for (id, shown) in &view.items {
            if !self.stored.items.contains_key(id) {
                self.writer.add_item(*id, &shown.title, &shown.key)?;
                self.added.insert(Entity::Item(*id));
                self.changed(Entity::Item(*id));
                let added = StoredItem {
                    overview: VaultItemOverview {
                        id: *id,
                        title: shown.title.clone(),
                        key: shown.key.clone(),
                        folder: None,
                        sections: BTreeMap::new(),
                        category: None,
                        autofill: ItemAutofill::default(),
                        credentials: BTreeMap::new(),
                    },
                    trashed: None,
                };
                self.stored.items.insert(*id, added);
            }
            self.item(shown)?;
        }
        Ok(())
    }

    fn item(&mut self, shown: &ItemView) -> Result<(), Error> {
        let id = shown.id;
        #[cfg(test)]
        if self.fault.is_some_and(|fault| fault(shown)) {
            return Err(Error::InvalidItemKey(id.to_string()));
        }
        let entity = Entity::Item(id);
        let stored = &self.stored.items[&id].overview;
        let mut changed = false;

        if stored.title != shown.title {
            self.writer.set_item_title(id, &shown.title)?;
            changed = true;
        }
        if stored.category != shown.category {
            self.writer.set_item_category(id, shown.category.clone())?;
            changed = true;
        }
        if stored.folder != shown.folder {
            self.writer.set_item_folder(id, shown.folder)?;
            changed = true;
        }
        if stored.key != shown.key {
            self.item_keys.insert(id, shown.key.clone());
            self.report.key_changes.push(KeyChange {
                entity,
                from: stored.key.clone(),
                to: shown.key.clone(),
            });
        }

        for section in &shown.sections {
            let same = stored
                .sections
                .get(&section.id)
                .is_some_and(|s| s.title == section.title && s.position == section.position);
            if !same {
                self.writer
                    .set_section(id, section.id, &section.title, section.position)?;
                changed = true;
            }
        }
        let purged: Vec<_> = stored
            .sections
            .keys()
            .filter(|s| !shown.sections.iter().any(|v| v.id == **s))
            .copied()
            .collect();
        for section in purged {
            self.writer.purge_section(id, section)?;
            changed = true;
        }

        let websites: Vec<Website> = shown
            .websites
            .iter()
            .map(|w| Website::new(w.url.clone(), w.match_kind))
            .collect();
        if stored.autofill.websites != websites {
            self.writer.set_websites(id, websites)?;
            changed = true;
        }

        if changed {
            self.changed(entity);
        }
        Ok(())
    }

    /// Credential registers and history. Trash state is written after.
    fn credentials(&mut self) -> Result<(), Error> {
        let view = self.view;
        let purged: Vec<CredentialId> = self
            .stored
            .credentials
            .keys()
            .filter(|id| !view.credentials.contains_key(id))
            .copied()
            .collect();
        for id in purged {
            self.writer.purge_credential(id)?;
            self.changed(Entity::Credential(id));
        }

        for (id, shown) in &view.credentials {
            if !self.stored.credentials.contains_key(id) {
                self.writer.add_credential(
                    shown.item,
                    *id,
                    &shown.title,
                    &shown.key,
                    shown.kind.clone(),
                    shown.value.0.as_str(),
                )?;
                self.added.insert(Entity::Credential(*id));
                self.changed(Entity::Credential(*id));
                let added = StoredCredential {
                    item: shown.item,
                    overview: VaultItemCredentialOverview {
                        id: *id,
                        title: shown.title.clone(),
                        key: shown.key.clone(),
                        kind: shown.kind.clone(),
                        position: None,
                        section: None,
                        last_used_day_at: None,
                    },
                    trashed: None,
                    value: shown.value.clone(),
                    history: BTreeMap::new(),
                };
                self.stored.credentials.insert(*id, added);
            }
            self.credential(shown)?;
        }
        Ok(())
    }

    fn credential(&mut self, shown: &CredentialView) -> Result<(), Error> {
        let id = shown.id;
        let entity = Entity::Credential(id);
        let stored = &self.stored.credentials[&id];
        let overview = &stored.overview;
        let mut changed = false;

        if stored.item != shown.item {
            self.writer.move_credential(id, shown.item)?;
            changed = true;
        }
        if overview.title != shown.title {
            self.writer.set_credential_title(id, &shown.title)?;
            changed = true;
        }
        if overview.kind != shown.kind {
            self.writer.set_credential_kind(id, shown.kind.clone())?;
            changed = true;
        }
        if overview.key != shown.key {
            self.credential_keys.insert(id, shown.key.clone());
            self.report.key_changes.push(KeyChange {
                entity,
                from: overview.key.clone(),
                to: shown.key.clone(),
            });
        }
        if (overview.section, overview.position) != (shown.section, shown.position) {
            self.writer
                .set_placement(id, shown.section, shown.position)?;
            changed = true;
        }
        if overview.last_used_day_at != shown.last_used_day_at {
            self.writer.set_last_used(id, shown.last_used_day_at)?;
            changed = true;
        }
        if stored.value != shown.value {
            self.writer.set_value(id, shown.value.0.as_str())?;
            changed = true;
        }

        let history: BTreeMap<HistoryId, HistoryValue> = shown
            .history
            .iter()
            .map(|h| {
                let value = HistoryValue {
                    value: h.value.clone(),
                    replaced_at: h.replaced_at,
                };
                (h.id, value)
            })
            .collect();
        if stored.history != history {
            let entries: Vec<PreviousValue<'_>> = shown
                .history
                .iter()
                .map(|h| PreviousValue {
                    id: h.id,
                    value: h.value.0.as_str(),
                    replaced_at: h.replaced_at,
                })
                .collect();
            self.writer.set_history(id, &entries)?;
            changed = true;
        }

        if changed {
            self.changed(entity);
        }
        Ok(())
    }

    fn credential_trash(&mut self) -> Result<(), Error> {
        for (id, shown) in &self.view.credentials {
            let stored = &self.stored.credentials[id];
            if stored.trashed != shown.trashed {
                let info = shown.trashed.as_ref().map(TrashValue::to_info);
                self.writer.set_credential_trashed(*id, info.as_ref())?;
                self.changed(Entity::Credential(*id));
            }
        }
        Ok(())
    }

    fn item_trash(&mut self) -> Result<(), Error> {
        for (id, shown) in &self.view.items {
            let stored = &self.stored.items[id];
            if stored.trashed != shown.trashed {
                let info = shown.trashed.as_ref().map(TrashValue::to_info);
                self.writer.set_item_trashed(*id, info.as_ref())?;
                self.changed(Entity::Item(*id));
            }
        }
        Ok(())
    }

    /// Purge the items the view lacks, once the credentials the view moved out
    /// of them are in their new items.
    fn purge_items(&mut self) -> Result<(), Error> {
        let view = self.view;
        let purged: Vec<ItemId> = self
            .stored
            .items
            .keys()
            .filter(|id| !view.items.contains_key(id))
            .copied()
            .collect();
        for id in purged {
            self.writer.purge_item(id)?;
            self.changed(Entity::Item(id));
        }
        Ok(())
    }

    /// Role slots, once every credential is in its item and trash state.
    fn slots(&mut self) -> Result<(), Error> {
        for (id, shown) in &self.view.items {
            let autofill = &self.stored.items[id].overview.autofill;
            let stored = (autofill.username, autofill.password, autofill.totp);
            let slots = (shown.username, shown.password, shown.totp);
            if stored != slots {
                self.writer
                    .set_slots(*id, shown.username, shown.password, shown.totp)?;
                self.changed(Entity::Item(*id));
            }
        }
        Ok(())
    }

    /// One bulk key update, and the key notices of the entries whose key was
    /// written or that were added. The update runs even without key writes,
    /// because it builds the key indexes again. Adding and trashing items
    /// leaves index entries missing if live items share a key meanwhile.
    fn keys(&mut self) -> Result<(), Error> {
        self.writer
            .set_keys(&self.item_keys, &self.credential_keys)?;
        let written: BTreeSet<Entity> = self
            .item_keys
            .keys()
            .map(|id| Entity::Item(*id))
            .chain(
                self.credential_keys
                    .keys()
                    .map(|id| Entity::Credential(*id)),
            )
            .collect();
        self.report.changed.extend(written.iter().copied());
        self.report.key_notices = self
            .view
            .key_notices()
            .into_iter()
            .filter(|entity| written.contains(entity) || self.added.contains(entity))
            .collect();
        Ok(())
    }
}

impl TrashValue {
    /// `DeletedInfo` of a trash value, field by field.
    fn to_info(&self) -> DeletedInfo {
        let Self { deleted_at, role } = self;
        DeletedInfo {
            deleted_at: *deleted_at,
            role: *role,
        }
    }
}
