//! Repair writes, the `v > s` repair, the recovery merge, recovery on a new
//! build, and the user override.

use std::fs;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};

use super::guard::{add, drift, published_vault, stopped};
use super::join::PEER;
use super::load::{Fixture, GENERATION, REPLICA, body, device_key};
use super::rebuild::refuse;
use super::state_file::{WRITER, keyring};
use super::transport::FakeTransport;
use super::txn::{
    add_item_counting, new_write_ids, saved, saved_vault, state_file, synced, two_keys, under_key_2,
};
use super::view::{State, edited};
use super::{NOW, id};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock};
use crate::secrets::vaults::sync::crdt::{CausalStore, Session};
use crate::secrets::vaults::sync::diff::{CredentialWrite, Edit, ItemWrite, LocalEdits};
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::model::SecretText;
use crate::secrets::vaults::sync::repair::SyncOverride;
use crate::secrets::vaults::sync::status::{BUILD_ID, StopCause, SyncStatus};
use crate::secrets::vaults::sync::view::{AskRegister, Conflict, Entity, VaultView};
use crate::secrets::vaults::{Error, VaultHandle};

/// Build id of an earlier build of the app.
const OLDER_BUILD: &str = "0.0.1+older";

/// Change the header of the sync state of `fx` with `change`, and save it
/// signed by the device key.
fn set_header(fx: &Fixture, change: impl FnOnce(&mut LocalSyncState)) {
    let mut local = saved(fx).0;
    change(&mut local);
    local.save(&fx.root, &TestSigner::device()).unwrap();
}

/// Mark the sync state of `fx` as stopped on an earlier build, as the next
/// transaction on a new build finds it.
fn on_new_build(fx: &Fixture) {
    set_header(fx, |local| {
        local.stopped_build = Some(OLDER_BUILD.to_string())
    });
}

/// Set the title of item `key` in the vault file of `fx` to `title` outside a
/// transaction, at the same generation.
fn drift_to(fx: &Fixture, key: &str, title: &str) {
    let mut vault = saved_vault(fx);
    vault.add_or_update_item(key, title).unwrap();
    write_vault(fx, vault);
}

/// Write `vault` as the vault file of `fx`, signed by the device key.
fn write_vault(fx: &Fixture, vault: Vault) {
    let vh = VaultHandle::unlocked(fx.vault.path.clone(), vault);
    let contents = vh.file_contents(&TestSigner::device()).unwrap();
    fs::write(&fx.vault.path, contents).unwrap();
}

/// Synced vault with item `item` published, and sync stopped by drift of its
/// title on this build.
fn stopped_by_drift(transport: &Arc<FakeTransport>) -> Fixture {
    let fx = published_vault(transport);
    drift(&fx, "item");
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, stopped());
    fx
}

fn preview(fx: &Fixture) -> Result<usize, Error> {
    let key = || fx.vault.unlocked_key().unwrap();
    let target = Target::of(&fx.vault);
    SyncOverride::new(fx.catalog.files(), &target).preview(Unlock::Test(&key))
}

fn confirm(fx: &Fixture) -> Result<Committed<()>, Error> {
    let key = || fx.vault.unlocked_key().unwrap();
    let target = Target::of(&fx.vault);
    SyncOverride::new(fx.catalog.files(), &target).confirm(Unlock::Test(&key))
}

/// Conflict in the Ask register `register` of item `key` of the vault of
/// `fx`.
fn item_conflict(fx: &Fixture, key: &str, register: AskRegister) -> Conflict {
    Conflict {
        entity: Entity::Item(saved_vault(fx).get_item(key).unwrap().id),
        register,
    }
}

/// Contents of the newest retained version of `fx`.
fn newest_version(fx: &Fixture) -> String {
    let versions = fx.catalog.files().list_versions(fx.id()).unwrap();
    let path = fx
        .root
        .join("versions")
        .join(ShortId::encode_uuid(fx.id()))
        .join(&versions[0].name);
    fs::read_to_string(path).unwrap()
}

fn assert_no_edits(fx: &Fixture) {
    let (_, state) = saved(fx);
    let edits = LocalEdits::find(&state, &saved_vault(fx), REPLICA).unwrap();
    assert!(edits.is_empty(), "{:?}", edits.edits());
}

/// Merge that adds vault values the sync state does not record.
#[derive(Clone, Copy, Debug)]
enum Merge {
    /// The `v > s` repair.
    NewerVault,
    /// The recovery merge on a new build.
    NewBuild,
}

impl Merge {
    const ALL: [Self; 2] = [Self::NewerVault, Self::NewBuild];

    /// Save `edits` in a transaction whose edits the sync state does not
    /// hold afterwards, then run the transaction that merges them, which
    /// must leave sync active.
    ///
    /// For `v > s`, the edits are recorded while the synced folder is
    /// unreachable, and the sync state from before them is put back. For the
    /// recovery merge, they are saved while sync is stopped on this build,
    /// and the merge runs as on a new build.
    fn run(
        self,
        fx: &Fixture,
        transport: &FakeTransport,
        edits: impl FnOnce(&mut VaultHandle) -> Result<(), Error>,
    ) -> Committed<()> {
        match self {
            Self::NewerVault => {
                let backup = fs::read_to_string(fx.state_path()).unwrap();
                transport.set_unavailable(true);
                fx.write(edits).unwrap();
                transport.set_unavailable(false);
                fx.put_text(&backup);
                assert!(matches!(fx.write_case(), SyncLoad::NewerVault { .. }));
            },
            Self::NewBuild => {
                set_header(fx, |local| local.stopped_build = Some(BUILD_ID.to_string()));
                assert_eq!(fx.write(edits).unwrap().sync_status, stopped());
                on_new_build(fx);
            },
        }
        let committed = fx.write(|_| Ok(())).unwrap();
        assert_eq!(committed.sync_status, Some(SyncStatus::Active), "{self:?}");
        assert_eq!(saved(fx).0.stopped_build, None, "{self:?}");
        committed
    }
}

#[test]
fn v_greater_than_s_row_of_generation_table_takes_stated_action() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    fx.write(|_| Ok(())).unwrap();
    let backup = fs::read_to_string(fx.state_path()).unwrap();
    let (backup_local, at_backup) = saved(&fx);
    // An edit that an own file holds, and one that no file holds.
    add(&fx, "published").unwrap();
    let (_, published) = saved(&fx);
    transport.set_unavailable(true);
    add(&fx, "unpublished").unwrap();
    transport.set_unavailable(false);
    let (_, lost) = saved(&fx);
    let unpublished = new_write_ids(&published, &lost);
    assert_eq!(unpublished.len(), 1);
    let newer = fs::read_to_string(&fx.vault.path).unwrap();
    let v = saved_vault(&fx).generation();

    // The sync state is restored from a backup.
    fx.put_text(&backup);
    let case = SyncLoad::NewerVault {
        vault: v,
        state: backup_local.generation,
    };
    assert_eq!(fx.read_case(), case);
    assert_eq!(fx.write_case(), case);
    assert!(matches!(fx.read(), Err(Error::SyncRepairNeeded(_))));

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    // The vault file is retained.
    assert_eq!(newest_version(&fx), newer);
    // The own file is joined, and the unpublished edit is added under one
    // new write id.
    let (local, state) = saved(&fx);
    for write in new_write_ids(&at_backup, &published) {
        assert!(state.context.covers(write));
    }
    assert!(!state.context.covers(unpublished[0]));
    assert_eq!(new_write_ids(&published, &state).len(), 1);
    let view = VaultView::of(&state);
    assert!(view.items.values().any(|item| item.key == "unpublished"));
    // The vault is saved from the view, both at `v + 1`.
    let vault = saved_vault(&fx);
    assert_eq!(local.generation, v + 1);
    assert_eq!(vault.generation(), v + 1);
    for key in ["item", "published", "unpublished"] {
        assert!(vault.get_item(key).is_ok(), "{key}");
    }
    assert_no_edits(&fx);
    assert_eq!(fx.read_case(), SyncLoad::Current);
    fx.read().unwrap();
}

#[test]
fn at_v_greater_than_s_unpublished_edit_is_conflict_and_peer_change_after_backup_is_not() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.write(|vh| {
        vh.add_item("item", "Item")?;
        vh.add_item("other", "Other").map(|_| ())
    })
    .unwrap();
    fx.write(|_| Ok(())).unwrap();
    let backup = fs::read_to_string(fx.state_path()).unwrap();
    let (_, at_backup) = saved(&fx);
    let mut peer_vault = saved_vault(&fx);

    // An unpublished local edit of `item`.
    transport.set_unavailable(true);
    fx.write(|vh| vh.add_item("item", "Local").map(|_| ()))
        .unwrap();
    transport.set_unavailable(false);
    // A peer changes `other` after the backup.
    peer_vault.add_or_update_item("other", "Peer").unwrap();
    let mut peer = at_backup.clone();
    let edits = LocalEdits::find(&peer, &peer_vault, PEER).unwrap();
    edits
        .record(&mut peer, &mut Session::new(PEER), NOW)
        .unwrap();
    transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &peer));
    fx.put_text(&backup);

    fx.write(|_| Ok(())).unwrap();

    let (_, state) = saved(&fx);
    let view = VaultView::of(&state);
    let vault = saved_vault(&fx);
    let item = vault.get_item("item").unwrap().id;
    let other = vault.get_item("other").unwrap().id;
    // The local edit is a conflict in its Ask register. The joined value is
    // shown, and no value is superseded.
    assert_eq!(
        view.conflicts(),
        [item_conflict(&fx, "item", AskRegister::Title)]
    );
    assert_eq!(view.items[&item].title, "Item");
    assert_eq!(vault.get_item("item").unwrap().title, "Item");
    let titles = &state.store.items.get(&item).unwrap().title;
    let joined = &at_backup.store.items.get(&item).unwrap().title;
    for (write, value) in joined.values() {
        assert_eq!(titles.get(write), Some(value));
    }
    let values: Vec<&str> = titles
        .ordered()
        .into_iter()
        .map(|(_, v)| v.value.as_str())
        .collect();
    assert_eq!(values, ["Local", "Item"]);
    // The peer value is joined after the repair, so it causes no conflict.
    assert_eq!(view.items[&other].title, "Peer");
    assert_eq!(
        state
            .store
            .items
            .get(&other)
            .unwrap()
            .title
            .values()
            .count(),
        1
    );
    assert_eq!(vault.get_item("other").unwrap().title, "Peer");
    assert_no_edits(&fx);
}

#[test]
fn order_register_keeps_joined_value_and_trash_is_added_while_restore_is_not() {
    for merge in Merge::ALL {
        let transport = Arc::new(FakeTransport::default());
        let fx = synced(&transport);
        fx.write(|vh| {
            vh.add_item("kept", "Kept")?;
            vh.add_item("gone", "Gone")?;
            vh.create_folder("Folder").map(|_| ())
        })
        .unwrap();
        fx.write(|vh| vh.delete_item("gone")).unwrap();
        fx.write(|_| Ok(())).unwrap();
        let before = saved_vault(&fx);
        let folder = before.list_folders()[0].id;
        let kept = before.get_item("kept").unwrap().id;
        let gone = before.list_deleted_items()[0].item.id;

        merge.run(&fx, &transport, |vh| {
            vh.rename_folder(folder, "Renamed")?;
            vh.delete_item("kept")?;
            vh.restore_item(gone, None)
        });

        let (_, state) = saved(&fx);
        let view = VaultView::of(&state);
        let vault = saved_vault(&fx);
        // The Order register keeps the joined value.
        assert_eq!(view.folders[0].title, "Folder", "{merge:?}");
        let register = state.store.folders.get(&folder).unwrap();
        assert_eq!(register.values().count(), 1, "{merge:?}");
        assert_eq!(vault.list_folders()[0].title, "Folder", "{merge:?}");
        // The trash in the vault is added.
        assert!(view.items[&kept].trashed.is_some(), "{merge:?}");
        assert!(vault.get_item("kept").is_err(), "{merge:?}");
        // The restore in the vault is not added.
        assert!(view.items[&gone].trashed.is_some(), "{merge:?}");
        assert!(vault.get_item("gone").is_err(), "{merge:?}");
        assert_eq!(vault.list_deleted_items().len(), 2, "{merge:?}");
        assert!(view.conflicts().is_empty(), "{merge:?}");
        assert_no_edits(&fx);
    }
}

#[test]
fn vault_value_added_to_ask_register_orders_below_joined_value_which_view_shows_and_fills() {
    for merge in Merge::ALL {
        let transport = Arc::new(FakeTransport::default());
        let fx = synced(&transport);
        let set = |vh: &mut VaultHandle, value: &str| {
            let value = SecretString::from(value.to_string());
            vh.add_secret("item", "password", "Password", FieldKind::default(), value)
        };
        fx.write(|vh| {
            vh.add_item("item", "Item")?;
            set(vh, "joined")
        })
        .unwrap();
        fx.write(|_| Ok(())).unwrap();

        merge.run(&fx, &transport, |vh| set(vh, "local"));

        let (_, state) = saved(&fx);
        let view = VaultView::of(&state);
        let vault = saved_vault(&fx);
        let credential = vault.get_item_credential("item", "password").unwrap().id;
        let register = &state.store.credentials.get(&credential).unwrap().value;
        let ordered = register.ordered();
        assert_eq!(ordered.len(), 2, "{merge:?}");
        let ((repair_key, repair), (joined_key, joined)) = (ordered[0], ordered[1]);
        assert_eq!(repair.value.0.as_str(), "local", "{merge:?}");
        assert_eq!(joined.value.0.as_str(), "joined", "{merge:?}");
        assert!(repair_key.counter < joined_key.counter, "{merge:?}");
        // The view shows the joined value, and the vault fills it.
        assert_eq!(view.credentials[&credential].value.0.as_str(), "joined");
        let filled = vault
            .get_item_credential_secret("item", "password")
            .unwrap()
            .unwrap();
        assert_eq!(filled.expose_secret(), "joined", "{merge:?}");
        // The conflict is listed.
        let conflict = Conflict {
            entity: Entity::Credential(credential),
            register: AskRegister::Value,
        };
        assert_eq!(view.conflicts(), [conflict], "{merge:?}");
        assert_no_edits(&fx);
    }
}

#[test]
fn after_guard_stops_sync_it_stays_stopped_on_same_build_and_new_build_merges_and_resumes() {
    let transport = Arc::new(FakeTransport::default());
    let fx = stopped_by_drift(&transport);
    assert_eq!(add(&fx, "second").unwrap().sync_status, stopped());
    let (_, before) = saved(&fx);

    // The same build stays stopped.
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, stopped());
    assert_eq!(saved(&fx).1, before);
    let writes = transport.writes();

    on_new_build(&fx);
    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let (local, state) = saved(&fx);
    assert_eq!(local.stopped_build, None);
    assert_eq!(local.override_build, None);
    // Each difference is added as a concurrent value under one write id.
    assert_eq!(new_write_ids(&before, &state).len(), 1);
    let view = VaultView::of(&state);
    assert_eq!(
        view.conflicts(),
        [item_conflict(&fx, "item", AskRegister::Title)]
    );
    assert!(view.items.values().any(|item| item.key == "second"));
    let vault = saved_vault(&fx);
    assert_eq!(vault.get_item("item").unwrap().title, "Item");
    assert!(vault.get_item("second").is_ok());
    assert_no_edits(&fx);
    // Sync resumes, so the merge is published.
    assert_eq!(transport.writes(), writes + 1);
    let committed = add(&fx, "third").unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(new_write_ids(&state, &saved(&fx).1).len(), 1);
}

#[test]
fn user_override_runs_recovery_merge_after_confirmation_with_number_of_differences() {
    let transport = Arc::new(FakeTransport::default());
    let fx = stopped_by_drift(&transport);
    add(&fx, "second").unwrap();
    let (_, before) = saved(&fx);
    let on_disk = fx.on_disk();

    let differences = preview(&fx).unwrap();
    assert!(differences > 1);
    assert_eq!(fx.on_disk(), on_disk);

    let committed = confirm(&fx).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let (local, state) = saved(&fx);
    assert_eq!(local.stopped_build, None);
    assert_eq!(local.override_build.as_deref(), Some(BUILD_ID));
    // The merge adds as many values as the confirmation stated, under one
    // write id.
    let minted = new_write_ids(&before, &state);
    assert_eq!(minted.len(), 1);
    let mut added = 0;
    state.store.each_value(&mut |write, _| {
        if write == minted[0] {
            added += 1;
        }
    });
    assert_eq!(added, differences);
    let view = VaultView::of(&state);
    assert_eq!(
        view.conflicts(),
        [item_conflict(&fx, "item", AskRegister::Title)]
    );
    assert!(view.items.values().any(|item| item.key == "second"));
    assert_no_edits(&fx);
}

#[test]
fn override_is_not_offered_again_on_build_of_override_build_and_is_offered_on_new_build() {
    let transport = Arc::new(FakeTransport::default());
    let fx = stopped_by_drift(&transport);
    confirm(&fx).unwrap();

    // The guard stops sync again on the build of the override.
    drift_to(&fx, "item", "Drifted again");
    let committed = fx.write(|_| Ok(())).unwrap();

    let not_offered = SyncStatus::Stopped(StopCause::Drift {
        build: BUILD_ID.to_string(),
        override_offered: false,
    });
    assert_eq!(committed.sync_status, Some(not_offered));
    let on_disk = fx.on_disk();
    assert!(matches!(preview(&fx), Err(Error::SyncOverrideNotOffered)));
    assert!(matches!(confirm(&fx), Err(Error::SyncOverrideNotOffered)));
    assert_eq!(fx.on_disk(), on_disk);
    assert_eq!(saved(&fx).0.stopped_build.as_deref(), Some(BUILD_ID));

    // A stop on a build after the one that recorded the override offers it
    // again.
    set_header(&fx, |local| {
        local.override_build = Some(OLDER_BUILD.to_string());
    });
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, stopped());
    assert_eq!(preview(&fx).unwrap(), 1);
    let committed = confirm(&fx).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(saved(&fx).0.override_build.as_deref(), Some(BUILD_ID));
}

#[test]
fn without_confirmation_override_does_nothing_and_sync_stays_stopped() {
    let transport = Arc::new(FakeTransport::default());
    let fx = stopped_by_drift(&transport);
    let on_disk = fx.on_disk();
    let writes = transport.writes();

    assert_eq!(preview(&fx).unwrap(), 1);
    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, stopped());
    assert_eq!(fx.on_disk(), on_disk);
    assert_eq!(transport.writes(), writes);

    // Sync that is not stopped offers no override.
    let active = published_vault(&transport);
    let on_disk = active.on_disk();
    assert!(matches!(
        preview(&active),
        Err(Error::SyncOverrideNotOffered)
    ));
    assert!(matches!(
        confirm(&active),
        Err(Error::SyncOverrideNotOffered)
    ));
    assert_eq!(active.on_disk(), on_disk);
}

#[test]
fn purged_entry_that_vault_still_holds_reappears_after_recovery_merge() {
    let transport = Arc::new(FakeTransport::default());
    let fx = published_vault(&transport);
    let held = saved_vault(&fx);
    fx.write(|vh| vh.delete_item("item")).unwrap();
    fx.write(|vh| {
        let id = vh.list_deleted_items()?[0].item.id;
        vh.purge_item(id)
    })
    .unwrap();
    let (local, purged) = saved(&fx);
    assert!(VaultView::of(&purged).items.is_empty());
    // The vault file that still holds the item is put back at the current
    // generation, so sync stops by drift.
    let mut held = held;
    held.set_sync(local.generation, Some(REPLICA.0));
    write_vault(&fx, held);
    assert_eq!(fx.write(|_| Ok(())).unwrap().sync_status, stopped());

    on_new_build(&fx);
    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let view = VaultView::of(&saved(&fx).1);
    let item = view.items.values().find(|item| item.key == "item").unwrap();
    assert_eq!(item.title, "Item");
    assert_eq!(item.trashed, None);
    assert!(saved_vault(&fx).get_item("item").is_ok());
    assert_no_edits(&fx);
}

#[test]
fn repair_adds_no_value_equal_to_shown_value_or_to_value_its_register_holds() {
    let mut vault = Vault::new_for_test();
    vault.add_or_update_item("item", "Item").unwrap();
    let field = vault
        .add_or_update_item_credential(
            "item",
            "field",
            "Field",
            FieldKind::default(),
            SecretString::from("shown".to_string()),
        )
        .unwrap()
        .id;
    let mut state = State::default();
    let edits = LocalEdits::find(&state, &vault, WRITER).unwrap();
    edits.record(&mut state, &mut Session::new(WRITER), NOW);

    // A vault equal to the view adds nothing.
    let repair = LocalEdits::find_repair(&state, &vault, WRITER).unwrap();
    assert!(repair.is_empty(), "{:?}", repair.edits());

    // A value the register already holds, below the shown value, adds
    // nothing.
    let state = edited(&state, 2, |s, m| {
        let value = SecretText::new("older");
        s.credentials.entry(field).value.write_repair(m, value);
    });
    let older = SecretString::from("older".to_string());
    vault
        .add_or_update_item_credential("item", "field", "Field", FieldKind::default(), older)
        .unwrap();
    let edits = LocalEdits::find(&state, &vault, WRITER).unwrap();
    let write = Edit::Credential(field, CredentialWrite::Value(SecretText::new("older")));
    assert!(edits.edits().contains(&write));
    let repair = LocalEdits::find_repair(&state, &vault, WRITER).unwrap();
    assert!(!repair.edits().contains(&write));
}

#[test]
fn repair_adds_no_suffixed_key_of_duplicate_key_group() {
    let mut vault = Vault::new_for_test();
    let a = vault.add_or_update_item("mail", "A").unwrap().id;
    let mut state = State::default();
    let edits = LocalEdits::find(&state, &vault, WRITER).unwrap();
    edits.record(&mut state, &mut Session::new(WRITER), NOW);
    // Another Mac creates `mail` after it joined `a`, so its item is shown
    // suffixed.
    let b = id(0xb);
    let state = edited(&state, 2, |s, m| {
        let item = s.items.entry(b);
        item.title.write(m, "B".to_string());
        item.key.write(m, "mail".to_string());
    });
    let view = VaultView::of(&state);
    let suffixed = view.items[&b].key.clone();
    assert!(suffixed.starts_with("mail-"));
    let mut vault = Vault::new_for_test();
    view.apply(&mut vault).unwrap();
    assert_eq!(vault.get_item(&suffixed).unwrap().id, b);
    let repair = LocalEdits::find_repair(&state, &vault, WRITER).unwrap();
    assert!(repair.is_empty(), "{:?}", repair.edits());

    // `a` is purged, so the view shows `b` with the bare key while the vault
    // still shows the suffixed key.
    let mut purged = state.clone();
    purged.store.items.remove(&a);
    assert_eq!(VaultView::of(&purged).items[&b].key, "mail");
    let key = Edit::Item(b, ItemWrite::Key(suffixed));
    assert!(
        LocalEdits::find(&purged, &vault, WRITER)
            .unwrap()
            .edits()
            .contains(&key)
    );
    let repair = LocalEdits::find_repair(&purged, &vault, WRITER).unwrap();
    assert!(!repair.edits().contains(&key));
    // `a`, which the view lacks, is added.
    assert!(
        repair
            .edits()
            .iter()
            .any(|edit| matches!(edit, Edit::Item(item, _) if *item == a))
    );
}

#[test]
fn restoring_retained_version_of_synced_vault_records_differences_and_trashes_entries_it_lacks() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    add(&fx, "second").unwrap();
    let second = saved_vault(&fx).get_item("second").unwrap().id;
    // Newest first. The first holds `item` and lacks `second`.
    let versions = fx.catalog.files().list_versions(fx.id()).unwrap();
    let (_, before) = saved(&fx);

    let committed = fx.restore(&versions[0].name).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let (_, state) = saved(&fx);
    assert_eq!(new_write_ids(&before, &state).len(), 1);
    // `second` is moved to the trash, not purged.
    let view = VaultView::of(&state);
    assert!(view.items[&second].trashed.is_some());
    assert!(
        view.items
            .values()
            .any(|i| i.key == "item" && i.trashed.is_none())
    );
    let vault = saved_vault(&fx);
    assert!(vault.get_item("second").is_err());
    assert_eq!(vault.list_deleted_items()[0].item.id, second);
    assert_no_edits(&fx);
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn second_miss_of_sync_state_key_is_added_by_v_greater_than_s_repair_once_key_arrives() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let own = body(REPLICA, &[device_key()]);
    fx.put_text(&under_key_2(&fx, &own, &keyring()));
    add_item_counting(&fx, |_| {});

    // The keyring of the sync state gains key id 2.
    fx.put_text(&under_key_2(&fx, &own, &two_keys()));
    let case = SyncLoad::NewerVault {
        vault: GENERATION + 1,
        state: GENERATION,
    };
    assert_eq!(fx.write_case(), case);

    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let local = LocalSyncState::load(&fx.root, fx.id(), &TestSigner::device()).unwrap();
    assert_eq!(local.generation, GENERATION + 2);
    let state = local.open(&two_keys()).unwrap();
    assert_eq!(new_write_ids(&own, &state).len(), 1);
    assert!(
        VaultView::of(&state)
            .items
            .values()
            .any(|item| item.key == "item")
    );
    let vault = saved_vault(&fx);
    assert_eq!(vault.generation(), GENERATION + 2);
    let edits = LocalEdits::find(&state, &vault, REPLICA).unwrap();
    assert!(edits.is_empty(), "{:?}", edits.edits());
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn restore_over_refused_file_of_synced_version_records_differences_and_next_transaction_finds_no_drift()
 {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    fx.add_item().unwrap();
    add(&fx, "second").unwrap();
    // Newest first. The first holds `item` and lacks `second`.
    let versions = fx.catalog.files().list_versions(fx.id()).unwrap();
    let second = saved_vault(&fx).get_item("second").unwrap().id;
    refuse(&fx.vault.path);

    let key = || fx.vault.unlocked_key().unwrap();
    fx.catalog
        .files()
        .restore_refused(
            &Target::of(&fx.vault),
            Unlock::Test(&key),
            &versions[0].name,
        )
        .unwrap();

    let (local, state) = saved(&fx);
    assert_eq!(local.generation, GENERATION + 3);
    let view = VaultView::of(&state);
    assert!(view.items[&second].trashed.is_some());
    let vault = saved_vault(&fx);
    assert_eq!(vault.generation(), GENERATION + 3);
    assert!(vault.get_item("item").is_ok());
    assert!(vault.get_item("second").is_err());
    assert_no_edits(&fx);
    assert_eq!(fx.read_case(), SyncLoad::Current);

    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
}
