//! Sync state in the write transaction: own files first, the session, the
//! diff, and the saves.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use secrecy::SecretString;

use super::NOW;
use super::load::{Fixture, GENERATION, REPLICA, body, device_key};
use super::state_file::{key, keyring};
use super::transport::FakeTransport;
use super::view::State;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::passkey::signals::{Report, SignalStore};
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock};
use crate::secrets::vaults::sync::crdt::{ActorId, CausalStore, ReplicaId, Session, WriteId};
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::keys::{SyncKey, SyncKeyring, TestKeyWrapper};
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::padded::PaddedBody;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::view::VaultView;
use crate::secrets::vaults::{Error, VaultHandle};

/// Synced vault at [`GENERATION`] with a valid sync state at the same
/// generation, and own state files read through `transport`.
pub(super) fn synced(transport: &Arc<FakeTransport>) -> Fixture {
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    fx.put_state(GENERATION);
    fx
}

/// Sync state of `fx` as saved, and its body.
pub(super) fn saved(fx: &Fixture) -> (LocalSyncState, State) {
    let local = LocalSyncState::load(&fx.root, fx.id(), &TestSigner::device()).unwrap();
    let state = local.open(&keyring()).unwrap();
    (local, state)
}

/// Vault file of `fx` as saved, verified.
pub(super) fn saved_vault(fx: &Fixture) -> Vault {
    let file = EncryptedVault::load(&fx.vault.path, &TestSigner::device()).unwrap();
    Vault::from_unlocked_key(&fx.vault.unlocked_key().unwrap(), file).unwrap()
}

/// Actors of `state` that `before` lacks.
pub(super) fn new_actors(before: &State, state: &State) -> Vec<ActorId> {
    state
        .actors
        .keys()
        .filter(|actor| !before.actors.contains_key(actor))
        .copied()
        .collect()
}

/// Write ids that the context of `state` holds and the context of `before`
/// does not.
pub(super) fn new_write_ids(before: &State, state: &State) -> Vec<WriteId> {
    state
        .context
        .iter()
        .flat_map(|(actor, seq)| {
            (before.context.get(actor) + 1..=seq).map(move |seq| WriteId { actor, seq })
        })
        .collect()
}

/// State of an earlier session of [`REPLICA`]: the saved sync state of `fx`
/// with the entries of `vault` recorded by `session`.
pub(super) fn own_state(fx: &Fixture, vault: &Vault, session: &mut Session) -> State {
    let mut own = saved(fx).1;
    let edits = LocalEdits::find(&own, vault, REPLICA).unwrap();
    assert!(edits.record(&mut own, session, NOW).is_some());
    own
}

/// State file of `state` written by [`REPLICA`] for vault `fx`.
pub(super) fn own_file(fx: &Fixture, state: &State) -> Vec<u8> {
    state_file(fx, REPLICA, state)
}

/// State file of `state` written by `replica` for vault `fx`.
pub(super) fn state_file(fx: &Fixture, replica: ReplicaId, state: &State) -> Vec<u8> {
    let padded = PaddedBody::of(state).unwrap();
    StateFile::encode(&padded, fx.id(), replica, KeyId(1), &key()).unwrap()
}

/// Vault with item `joined` only.
pub(super) fn joined_vault() -> Vault {
    let mut vault = Vault::new_for_test();
    vault.add_or_update_item("joined", "Joined").unwrap();
    vault
}

fn set_mode(dir: &Path, mode: u32) {
    fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn transaction_with_no_requested_change_and_no_join_saves_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    // The next transaction moves the staged context of the publish.
    fx.write(|_| Ok(())).unwrap();
    let before = fx.on_disk();
    let sidecar = fs::read_to_string(Sidecar::path(&fx.root, fx.id())).unwrap();
    let versions = fx.catalog.files().list_versions(fx.id()).unwrap();

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(!committed.changed);
    assert_eq!(fx.on_disk(), before);
    assert_eq!(fx.catalog.files().list_versions(fx.id()).unwrap(), versions);
    assert_eq!(
        fs::read_to_string(Sidecar::path(&fx.root, fx.id())).unwrap(),
        sidecar
    );
}

#[test]
fn save_at_v_equal_to_s_records_edit_and_advances_s() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let (_, before) = saved(&fx);

    fx.add_item().unwrap();

    let (local, state) = saved(&fx);
    assert_eq!(local.generation, GENERATION + 1);
    let vault = saved_vault(&fx);
    assert_eq!(vault.generation(), GENERATION + 1);
    assert_eq!(new_write_ids(&before, &state).len(), 1);
    assert!(
        VaultView::of(&state)
            .items
            .values()
            .any(|item| item.key == "item")
    );
    assert!(
        LocalEdits::find(&state, &vault, REPLICA)
            .unwrap()
            .is_empty()
    );
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn vault_key_rename_advances_s_and_saves_sync_state_first() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    let (_, before) = saved(&fx);
    let vault_before = fs::read_to_string(&fx.vault.path).unwrap();

    // The vault save fails after the sync state save.
    set_mode(&fx.vaults_dir, 0o555);
    let result = fx.write(|vh| vh.set_vault_key("renamed".to_string()));
    set_mode(&fx.vaults_dir, 0o755);

    assert!(matches!(result, Err(Error::VaultWriteError(_))));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), vault_before);
    let (local, state) = saved(&fx);
    assert_eq!(local.generation, GENERATION + 2);
    // The vault key is not in the sync state, so no write id is minted.
    assert_eq!(state, before);
    let case = SyncLoad::OlderVault {
        vault: GENERATION + 1,
        state: GENERATION + 2,
    };
    assert_eq!(fx.read_case(), case);

    let fx = synced(&transport);
    fx.add_item().unwrap();
    let (_, before) = saved(&fx);

    let renamed = fx
        .write(|vh| vh.set_vault_key("renamed".to_string()))
        .unwrap();

    assert!(renamed.changed);
    let (local, state) = saved(&fx);
    assert_eq!(local.generation, GENERATION + 2);
    assert_eq!(state, before);
    let file = EncryptedVault::load(&fx.vault.path, &TestSigner::device()).unwrap();
    assert_eq!(file.key, "renamed");
    assert_eq!(file.generation, GENERATION + 2);
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn own_files_joined_before_any_write_id_minted() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let mut earlier = Session::new(REPLICA);
    let own = own_state(&fx, &joined_vault(), &mut earlier);
    let hash = transport.put_state(fx.id(), REPLICA, &own_file(&fx, &own));

    fx.add_item().unwrap();

    let (local, state) = saved(&fx);
    assert_eq!(local.generation, GENERATION + 1);
    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_ok());
    assert!(vault.get_item("item").is_ok());
    assert!(
        LocalEdits::find(&state, &vault, REPLICA)
            .unwrap()
            .is_empty()
    );

    // The edit is minted by a new actor after the join, and orders after
    // every value it joined. The joined item is not removed.
    let minted = new_write_ids(&own, &state);
    assert_eq!(minted.len(), 1);
    assert_ne!(Some(minted[0].actor), earlier.actor());
    assert_eq!(new_actors(&own, &state), vec![minted[0].actor]);
    let (_, counter) = state
        .store
        .find_value(&mut |id, _| id == minted[0])
        .unwrap();
    assert!(counter > own.store.highest_counter());
    assert!(state.context.covers(earlier.last_write().unwrap()));
    assert!(Sidecar::load(&fx.root, fx.id()).is_joined(REPLICA, hash));
}

#[test]
fn transaction_that_only_joins_applies_view_and_saves_with_next_generation() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let own = own_state(&fx, &joined_vault(), &mut Session::new(REPLICA));
    transport.put_state(fx.id(), REPLICA, &own_file(&fx, &own));

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(committed.changed);
    let (local, state) = saved(&fx);
    assert_eq!(local.generation, GENERATION + 1);
    // The view is applied without a diff, so nothing is minted.
    assert_eq!(state, own);
    let vault = saved_vault(&fx);
    assert_eq!(vault.generation(), GENERATION + 1);
    assert!(vault.get_item("joined").is_ok());
    assert!(
        committed
            .vault
            .get_item_overview("joined")
            .unwrap()
            .is_some()
    );
    assert!(
        LocalEdits::find(&state, &vault, REPLICA)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn own_file_joined_once_and_sidecar_that_fails_to_parse_causes_extra_join_only() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let own = own_state(&fx, &joined_vault(), &mut Session::new(REPLICA));
    let hash = transport.put_state(fx.id(), REPLICA, &own_file(&fx, &own));
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(transport.reads(), 1);
    // The publish deletes the joined own file. The next transaction moves
    // the staged context.
    let published = Sidecar::load(&fx.root, fx.id()).last_publish.unwrap();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(transport.reads(), 1);

    let before = fx.on_disk();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(transport.reads(), 1);
    assert_eq!(fx.on_disk(), before);

    fs::write(Sidecar::path(&fx.root, fx.id()), "not json").unwrap();
    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(transport.reads(), 2);
    assert!(!committed.changed);
    assert_eq!(fx.on_disk(), before);
    assert!(Sidecar::load(&fx.root, fx.id()).is_joined(REPLICA, published));
    let name = StateFile::name(fx.id(), hash);
    assert!(!transport.names(fx.id(), REPLICA).contains(&name));
}

#[test]
fn own_file_that_is_remote_damaged_or_unreachable_not_joined_and_edit_saved() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let own = own_state(&fx, &joined_vault(), &mut Session::new(REPLICA));
    let bytes = own_file(&fx, &own);
    let remote = StateHash::of(&bytes);
    transport.put_remote(fx.id(), REPLICA, &StateFile::name(fx.id(), remote));
    let mut torn = own_file(&fx, &own);
    torn.truncate(torn.len() - 1);
    // Named by the hash of the full file, so the bytes do not match it.
    let damaged = StateHash::of(&own_file(&fx, &own));
    let damaged_name = StateFile::name(fx.id(), damaged);
    transport.put(fx.id(), REPLICA, &damaged_name, &torn);

    fx.add_item().unwrap();

    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_err());
    assert!(vault.get_item("item").is_ok());
    let sidecar = Sidecar::load(&fx.root, fx.id());
    assert!(!sidecar.is_joined(REPLICA, remote));
    assert!(sidecar.is_quarantined(REPLICA, &damaged_name, StateHash::of(&torn)));
    assert_eq!(sidecar.quarantined.len(), 1);

    // An unreachable folder joins nothing, and the edit is still recorded.
    transport.set_unavailable(true);
    let (_, before) = saved(&fx);
    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();
    let (_, state) = saved(&fx);
    assert_eq!(new_write_ids(&before, &state).len(), 1);
    assert!(saved_vault(&fx).get_item("second").is_ok());
}

#[test]
fn two_transactions_in_one_process_continue_one_actor() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let (_, before) = saved(&fx);

    fx.add_item().unwrap();
    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();

    let (local, state) = saved(&fx);
    let actors = new_actors(&before, &state);
    assert_eq!(actors.len(), 1);
    assert_eq!(state.context.get(actors[0]), 2);
    assert_eq!(local.generation, GENERATION + 2);
}

#[test]
fn replaced_state_file_starts_new_actor() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let (_, before) = saved(&fx);
    fx.add_item().unwrap();
    let (mut local, first) = saved(&fx);
    let first_actor = new_actors(&before, &first)[0];

    // The same state, sealed again, gives a file with other bytes.
    local.reseal(local.generation, &keyring()).unwrap();
    local.save(&fx.root, &TestSigner::device()).unwrap();
    assert_eq!(saved(&fx).1, first);
    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();

    let (_, state) = saved(&fx);
    let minted = new_write_ids(&first, &state);
    assert_eq!(minted.len(), 1);
    assert_ne!(minted[0].actor, first_actor);
    assert_eq!(minted[0].seq, 1);
    assert_eq!(state.context.get(first_actor), 1);
}

/// Item with a credential that has one previous value and a passkey site
/// report, saved in a transaction.
pub(super) fn add_entries(fx: &Fixture) {
    fx.write(|vh| {
        vh.add_item("item", "Item")?;
        for value in ["one", "two"] {
            let value = SecretString::from(value.to_string());
            vh.add_secret("item", "field", "Field", FieldKind::default(), value)?;
        }
        vh.update_passkey_signals(|signals| signals.record(report(), 1_700_000_000))
    })
    .unwrap();
}

pub(super) fn report() -> Report {
    Report::Unknown {
        rp_id: "example.com".to_string(),
        credential_id: vec![1, 2, 3],
    }
}

/// Change that only removes entries.
pub(super) type Removal = Box<dyn Fn(&mut VaultHandle) -> Result<(), Error>>;

/// Changes that only remove entries of [`add_entries`], in the order they
/// run. The purge needs the item in the trash first.
pub(super) fn removals() -> [(&'static str, Removal); 3] {
    let history_purge = |vh: &mut VaultHandle| {
        let history = vh.list_history("item", "field")?;
        vh.purge_history("item", "field", history[0].id)
    };
    let signal_trim = |vh: &mut VaultHandle| {
        let mut trimmed = SignalStore::new();
        trimmed.record(report(), 1_700_000_000);
        vh.update_passkey_signals(|signals| signals.remove(&trimmed))
    };
    let purge = |vh: &mut VaultHandle| {
        let id = vh.list_deleted_items()?[0].item.id;
        vh.purge_item(id)
    };
    [
        ("history purge", Box::new(history_purge)),
        ("signal trim", Box::new(signal_trim)),
        ("purge", Box::new(purge)),
    ]
}

#[test]
fn purge_or_trim_only_edit_mints_context_only_write_id() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    add_entries(&fx);

    for (name, removal) in removals() {
        // An item is purged from the trash.
        if name == "purge" {
            fx.write(|vh| vh.delete_item("item")).unwrap();
        }
        let (_, before) = saved(&fx);

        let committed = fx.write(|vh| removal(vh)).unwrap();

        assert!(committed.changed, "{name}");
        let (_, state) = saved(&fx);
        let minted = new_write_ids(&before, &state);
        assert_eq!(minted.len(), 1, "{name}");
        assert!(state.context.covers(minted[0]), "{name}");
        let found = state.store.find_value(&mut |id, _| id == minted[0]);
        assert_eq!(found, None, "{name}");
        let vault = saved_vault(&fx);
        assert!(
            LocalEdits::find(&state, &vault, REPLICA)
                .unwrap()
                .is_empty(),
            "{name}"
        );
    }
    let view = VaultView::of(&saved(&fx).1);
    assert!(view.items.is_empty());
    assert!(view.credentials.is_empty());
    assert_eq!(view.signals.entries().count(), 0);
}

/// Keyring of key ids 1 and 2.
pub(super) fn two_keys() -> SyncKeyring {
    SyncKeyring::new(vec![
        (KeyId(1), key()),
        (KeyId(2), SyncKey::from_bytes([3; 32])),
    ])
    .unwrap()
}

/// Sync state of `fx` at [`GENERATION`] with the body `state` under key id
/// 2, and with the keys of `sync_keys` in its keyring.
pub(super) fn under_key_2(fx: &Fixture, state: &State, sync_keys: &SyncKeyring) -> String {
    let padded = PaddedBody::of(state).unwrap();
    let mut local = LocalSyncState::new(fx.id(), REPLICA, KeyId(2));
    local.generation = GENERATION;
    local.sync_keys = sync_keys.wrap(&TestKeyWrapper).unwrap();
    local.seal(&padded, &two_keys()).unwrap();
    local.to_file_contents(&TestSigner::device()).unwrap()
}

/// Add an item in a transaction whose unlock calls `on_unlock` with the
/// number of the unlock, from 0, after the keyring is read.
pub(super) fn add_item_counting(fx: &Fixture, on_unlock: impl Fn(usize) + Sync) -> Committed<()> {
    let unlocks = AtomicUsize::new(0);
    let key = || {
        on_unlock(unlocks.fetch_add(1, Ordering::SeqCst));
        fx.vault.unlocked_key().unwrap()
    };
    let result =
        fx.catalog
            .files()
            .write::<_, Error>(&Target::of(&fx.vault), Unlock::Test(&key), |vh| {
                vh.add_item("item", "Item").map(|_| ())
            });
    assert_eq!(unlocks.load(Ordering::SeqCst), 2);
    result.unwrap()
}

#[test]
fn sync_state_under_key_unlock_did_not_unwrap_makes_transaction_unlock_once_more_and_retry() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    // A rotation accepted between the keyring read and the locks.
    let before = body(REPLICA, &[device_key()]);
    let rotated = under_key_2(&fx, &before, &two_keys());

    add_item_counting(&fx, |unlock| {
        if unlock == 0 {
            fx.put_text(&rotated);
        }
    });

    let local = LocalSyncState::load(&fx.root, fx.id(), &TestSigner::device()).unwrap();
    assert_eq!(local.key_id, KeyId(2));
    assert_eq!(local.generation, GENERATION + 1);
    let state = local.open(&two_keys()).unwrap();
    assert_eq!(new_write_ids(&before, &state).len(), 1);
    assert!(saved_vault(&fx).get_item("item").is_ok());
}

#[test]
fn second_miss_of_sync_state_key_completes_as_local_save() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let own = body(REPLICA, &[device_key()]);
    fx.put_text(&under_key_2(&fx, &own, &keyring()));
    let state_before = fs::read_to_string(fx.state_path()).unwrap();

    let committed = add_item_counting(&fx, |_| {});

    assert!(committed.changed);
    assert_eq!(fs::read_to_string(fx.state_path()).unwrap(), state_before);
    let vault = saved_vault(&fx);
    assert!(vault.get_item("item").is_ok());
    // The vault takes the next generation, so the next load with the key is
    // `v > s` (6c.3).
    assert_eq!(vault.generation(), GENERATION + 1);
    assert_eq!(fx.read_case(), SyncLoad::KeyMissing(KeyId(2)));
}

#[test]
fn many_joins_keep_versions_per_time_policy() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let mut earlier = Session::new(REPLICA);
    let mut vault = Vault::new_for_test();
    let mut own = saved(&fx).1;
    for n in 0..101 {
        vault
            .add_or_update_item(&format!("item-{n}"), "Item")
            .unwrap();
        let edits = LocalEdits::find(&own, &vault, REPLICA).unwrap();
        edits.record(&mut own, &mut earlier, NOW);
        transport.put_state(fx.id(), REPLICA, &own_file(&fx, &own));

        assert!(fx.write(|_| Ok(())).unwrap().changed, "join {n}");
    }

    // Every version from the last hour is kept, up to 100.
    let versions = fx.catalog.files().list_versions(fx.id()).unwrap();
    assert_eq!(versions.len(), 100);
    assert_eq!(saved(&fx).1, own);
    assert_eq!(saved_vault(&fx).list_items().len(), 101);
}

/// Each case where the transaction leaves the sync state as it is: a
/// missing or failed sync state saves the vault without a generation check.
#[test]
fn untrusted_sync_state_saves_locally_same_generation() {
    let transport = Arc::new(FakeTransport::default());
    for name in ["missing", "signed by another key"] {
        let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
        if name != "missing" {
            fx.put_foreign_state();
        }
        let state_before = fx.on_disk().1;

        fx.add_item().unwrap();

        assert_eq!(fx.on_disk().1, state_before, "{name}");
        assert_eq!(saved_vault(&fx).generation(), GENERATION, "{name}");
    }
}
