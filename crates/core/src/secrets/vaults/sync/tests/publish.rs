//! Staged file and publish: the publish condition, the save order, the move
//! of `staged_context`, and the delete rule for own files.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use super::load::{Fixture, REPLICA};
use super::state_file::keyring;
use super::transport::FakeTransport;
use super::txn::{
    add_entries, joined_vault, new_actors, new_write_ids, own_file, own_state, removals, saved,
    saved_vault, synced,
};
use super::view::State;
use crate::secrets::vaults::sync::crdt::Session;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash, StateSource};
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport};
use crate::secrets::vaults::sync::view::VaultView;

fn staged_path(fx: &Fixture) -> PathBuf {
    LocalSyncState::staged_path(&fx.root, fx.id())
}

/// Bytes of the staged file of `fx`, if it exists.
fn staged_bytes(fx: &Fixture) -> Option<Vec<u8>> {
    fs::read(staged_path(fx)).ok()
}

/// Hash of the last publish recorded in the sidecar of `fx`.
pub(super) fn last_publish(fx: &Fixture) -> Option<StateHash> {
    Sidecar::load(&fx.root, fx.id()).last_publish
}

/// Own state files of `fx` in the synced folder.
pub(super) fn published(transport: &FakeTransport, fx: &Fixture) -> Vec<StateHash> {
    transport.list_states(fx.id(), REPLICA).unwrap()
}

/// State of the own state file `hash` of `fx` in the synced folder.
pub(super) fn decode(transport: &FakeTransport, fx: &Fixture, hash: StateHash) -> State {
    let ReadResult::Local(bytes) = transport
        .read(fx.id(), REPLICA, FileName::State(hash))
        .unwrap()
    else {
        panic!("state file {hash} is not local");
    };
    let source = StateSource {
        vault_id: fx.id(),
        replica_id: REPLICA,
        hash,
    };
    StateFile::decode(&bytes, &source, &keyring()).unwrap().1
}

#[test]
fn only_edit_that_is_purge_history_purge_or_signal_trim_publishes() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    add_entries(&fx);

    for (name, removal) in removals() {
        if name == "purge" {
            fx.write(|vh| vh.delete_item("item")).unwrap();
        }
        let (_, before) = saved(&fx);
        let earlier = last_publish(&fx);

        fx.write(|vh| removal(vh)).unwrap();

        let (_, state) = saved(&fx);
        let minted = new_write_ids(&before, &state);
        assert_eq!(minted.len(), 1, "{name}");
        let hash = last_publish(&fx).unwrap();
        assert_ne!(Some(hash), earlier, "{name}");
        // The older own file was joined, so the publish deletes it.
        assert_eq!(published(&transport, &fx), vec![hash], "{name}");
        let file = decode(&transport, &fx, hash);
        assert!(file.context.covers(minted[0]), "{name}");
        assert_eq!(file, state, "{name}");
    }
}

#[test]
fn directory_that_lacks_file_of_last_publish_republishes_and_remote_own_file_counts_as_present() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    let first = last_publish(&fx).unwrap();
    transport
        .delete_own(fx.id(), REPLICA, FileName::State(first))
        .unwrap();

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(!committed.changed);
    let second = last_publish(&fx).unwrap();
    assert_ne!(second, first);
    assert_eq!(published(&transport, &fx), vec![second]);
    let (_, state) = saved(&fx);
    assert_eq!(decode(&transport, &fx, second), state);

    // The next transaction moves the staged context. A `Remote` own file
    // then counts as present.
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(saved(&fx).0.staged_hash, None);
    let name = StateFile::name(fx.id(), second);
    transport.put_remote(fx.id(), REPLICA, &name);
    let writes = transport.writes();
    let before = fx.on_disk();

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(transport.writes(), writes);
    assert_eq!(transport.names(fx.id(), REPLICA), vec![name]);
    assert_eq!(last_publish(&fx), Some(second));
    assert_eq!(fx.on_disk(), before);
}

#[test]
fn local_edits_while_synced_folder_is_missing_are_published_with_no_conflicts_when_it_returns() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let (_, before) = saved(&fx);
    transport.set_unavailable(true);

    fx.add_item().unwrap();
    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();

    transport.set_unavailable(false);
    assert!(transport.names(fx.id(), REPLICA).is_empty());
    let (local, state) = saved(&fx);
    assert_eq!(new_write_ids(&before, &state).len(), 2);
    assert_eq!(local.staged_context.as_ref(), Some(&state.context));
    let staged = staged_bytes(&fx).unwrap();
    assert_eq!(local.staged_hash, Some(StateHash::of(&staged)));

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(!committed.changed);
    let hash = last_publish(&fx).unwrap();
    assert_eq!(hash, StateHash::of(&staged));
    assert_eq!(published(&transport, &fx), vec![hash]);
    let file = decode(&transport, &fx, hash);
    assert_eq!(file, state);
    assert!(VaultView::of(&file).conflicts().is_empty());
}

/// Vault file, sync state, sidecar, and staged file of a vault, as a backup
/// of the app data holds them.
struct Backup {
    files: Vec<(PathBuf, Vec<u8>)>,
}

impl Backup {
    fn take(fx: &Fixture) -> Self {
        let paths = [
            fx.vault.path.clone(),
            fx.state_path(),
            Sidecar::path(&fx.root, fx.id()),
            staged_path(fx),
        ];
        let files = paths
            .into_iter()
            .map(|path| {
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        Self { files }
    }

    fn restore(&self) {
        for (path, bytes) in &self.files {
            fs::write(path, bytes).unwrap();
        }
    }
}

#[test]
fn vault_and_sync_state_restored_from_same_backup_recover_lost_writes_from_own_files() {
    for reachable in [true, false] {
        let transport = Arc::new(FakeTransport::default());
        let fx = synced(&transport);
        fx.add_item().unwrap();
        let backup = Backup::take(&fx);
        let (_, at_backup) = saved(&fx);
        fx.write(|vh| vh.add_item("after", "After").map(|_| ()))
            .unwrap();
        let (_, lost) = saved(&fx);

        backup.restore();
        if reachable {
            // A transaction that only joins recovers the lost writes.
            let committed = fx.write(|_| Ok(())).unwrap();

            assert!(committed.changed);
            assert_eq!(saved(&fx).1, lost);
        } else {
            // The first edit mints under a new actor, whose write ids cover
            // none of the lost writes.
            transport.set_unavailable(true);
            fx.write(|vh| vh.add_item("offline", "Offline").map(|_| ()))
                .unwrap();
            let (_, offline) = saved(&fx);
            let minted = new_write_ids(&at_backup, &offline);
            assert_eq!(minted.len(), 1);
            assert_eq!(new_actors(&at_backup, &offline), vec![minted[0].actor]);
            assert!(!lost.actors.contains_key(&minted[0].actor));
            assert!(saved_vault(&fx).get_item("after").is_err());

            transport.set_unavailable(false);
            fx.write(|_| Ok(())).unwrap();

            let (_, state) = saved(&fx);
            assert!(new_write_ids(&state, &lost).is_empty());
            assert!(saved_vault(&fx).get_item("offline").is_ok());
        }
        let vault = saved_vault(&fx);
        assert!(vault.get_item("after").is_ok(), "reachable {reachable}");
        assert_eq!(vault.replica_id(), Some(REPLICA.0), "reachable {reachable}");
    }
}

#[test]
fn older_staged_file_put_in_place_of_current_one_does_not_move_published_context() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    let older = staged_bytes(&fx).unwrap();
    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();
    let (local, state) = saved(&fx);
    let current = staged_bytes(&fx).unwrap();
    assert_eq!(last_publish(&fx), Some(StateHash::of(&current)));
    let published_context = local.published_context.clone();
    assert_ne!(published_context, state.context);

    fs::write(staged_path(&fx), &older).unwrap();
    fx.write(|_| Ok(())).unwrap();

    let (local, _) = saved(&fx);
    assert_eq!(local.published_context, published_context);
    let rewritten = staged_bytes(&fx).unwrap();
    assert_ne!(rewritten, older);
    assert_ne!(rewritten, current);
    assert_eq!(local.staged_hash, Some(StateHash::of(&rewritten)));
    assert_eq!(local.staged_context, Some(state.context));
}

#[test]
fn transaction_that_copies_staged_file_saves_no_sync_state_after_vault() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);

    fx.add_item().unwrap();

    // The sync state was saved before the copy, so it still names the
    // staged file.
    let (local, state) = saved(&fx);
    let staged = staged_bytes(&fx).unwrap();
    let hash = StateHash::of(&staged);
    assert_eq!(local.staged_hash, Some(hash));
    assert_eq!(local.staged_context.as_ref(), Some(&state.context));
    assert_eq!(local.generation, saved_vault(&fx).generation());
    assert_eq!(last_publish(&fx), Some(hash));
    let copy = transport
        .read(fx.id(), REPLICA, FileName::State(hash))
        .unwrap();
    assert_eq!(copy, ReadResult::Local(staged));

    // A crash after the copy leaves this state. The next transaction moves
    // the staged context once and does not publish again.
    let writes = transport.writes();
    fx.write(|_| Ok(())).unwrap();

    let (local, _) = saved(&fx);
    assert_eq!(local.published_context, state.context);
    assert_eq!(local.staged_context, None);
    assert_eq!(local.staged_hash, None);
    assert_eq!(transport.writes(), writes);

    let before = fx.on_disk();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(fx.on_disk(), before);
    assert_eq!(transport.writes(), writes);
    assert_eq!(published(&transport, &fx), vec![hash]);
}

#[test]
fn failed_sync_state_save_after_staged_file_write_deletes_staged_file_and_ends_actor() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let (_, before) = saved(&fx);
    fx.add_item().unwrap();
    let (_, first) = saved(&fx);
    let first_actor = new_actors(&before, &first)[0];
    let state_path = fx.state_path();
    let contents = fs::read(&state_path).unwrap();
    let (vault_before, _) = fx.on_disk();
    let names = transport.names(fx.id(), REPLICA);

    let result = fx.write(|vh| {
        // A directory at the sync state path fails its save after the staged
        // file write.
        fs::remove_file(&state_path).unwrap();
        fs::create_dir(&state_path).unwrap();
        vh.add_item("second", "Second").map(|_| ())
    });

    assert!(result.is_err());
    assert!(staged_bytes(&fx).is_none());
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), vault_before);
    assert_eq!(transport.names(fx.id(), REPLICA), names);

    // The same sync state file is put back, so the session continues. Its
    // actor ended, so the next write id comes from a new actor.
    fs::remove_dir(&state_path).unwrap();
    fs::write(&state_path, &contents).unwrap();
    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();

    let (_, state) = saved(&fx);
    let minted = new_write_ids(&first, &state);
    assert_eq!(minted.len(), 1);
    assert_ne!(minted[0].actor, first_actor);
    assert_eq!(minted[0].seq, 1);
    assert_eq!(state.context.get(first_actor), 1);
    for hash in published(&transport, &fx) {
        let file = decode(&transport, &fx, hash);
        assert_eq!(file.context.get(first_actor), 1);
    }
}

#[test]
fn publish_never_overwrites_file_and_deletes_only_older_own_files_that_were_joined() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let own = own_state(&fx, &joined_vault(), &mut Session::new(REPLICA));
    let joined = transport.put_state(fx.id(), REPLICA, &own_file(&fx, &own));
    let remote = StateFile::name(fx.id(), StateHash::of(b"remote"));
    transport.put_remote(fx.id(), REPLICA, &remote);
    let damaged = StateFile::name(fx.id(), StateHash::of(b"damaged"));
    transport.put(fx.id(), REPLICA, &damaged, b"torn");

    fx.add_item().unwrap();

    let hash = last_publish(&fx).unwrap();
    let mut names = vec![StateFile::name(fx.id(), hash), remote, damaged];
    names.sort();
    assert_eq!(transport.names(fx.id(), REPLICA), names);
    assert!(!names.contains(&StateFile::name(fx.id(), joined)));

    // With the sidecar lost, the next transaction joins the file it just
    // published, and copies the same staged file. The file is listed under
    // its hash, so it is not written again and not deleted.
    fs::remove_file(Sidecar::path(&fx.root, fx.id())).unwrap();
    let writes = transport.writes();

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(transport.writes(), writes);
    assert_eq!(transport.names(fx.id(), REPLICA), names);
    assert_eq!(last_publish(&fx), Some(hash));
    assert_eq!(saved(&fx).0.staged_hash, Some(hash));
}

#[test]
fn failed_publish_does_not_fail_save_and_next_transaction_copies_staged_file() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    transport.set_failing_writes(true);

    let committed = fx.add_item().unwrap();

    assert!(committed.changed);
    assert!(saved_vault(&fx).get_item("item").is_ok());
    let (local, state) = saved(&fx);
    let staged = staged_bytes(&fx).unwrap();
    let hash = StateHash::of(&staged);
    // The failed publish is recorded as a staged file that the sidecar does
    // not record as published.
    assert_eq!(local.staged_hash, Some(hash));
    assert_eq!(local.staged_context, Some(state.context));
    assert!(transport.names(fx.id(), REPLICA).is_empty());
    assert_eq!(last_publish(&fx), None);

    transport.set_failing_writes(false);
    let before = fx.on_disk();
    fx.write(|_| Ok(())).unwrap();

    // The staged file is copied as it is, with no sync state save.
    assert_eq!(fx.on_disk(), before);
    assert_eq!(staged_bytes(&fx), Some(staged));
    assert_eq!(published(&transport, &fx), vec![hash]);
    assert_eq!(last_publish(&fx), Some(hash));
}
