//! Peer joins of local state files: the checks of each file, quarantine,
//! refusal, ignored files, and the publish after a join.

use std::sync::Arc;

use uuid::Uuid;

use super::NOW;
use super::load::{Fixture, REPLICA};
use super::publish::{decode, last_publish, published};
use super::state_file::key;
use super::transport::FakeTransport;
use super::txn::{new_actors, new_write_ids, saved, saved_vault, state_file, synced};
use super::view::State;
use crate::secrets::vaults::sync::crdt::{CausalStore, ReplicaId, Session, WriteId};
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::keys::SyncKey;
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::padded::PaddedBody;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::transport::{FileName, SyncTransport};

/// Replica of another Mac.
const PEER: ReplicaId = ReplicaId(Uuid::from_u128(2));

/// Replica of a third Mac.
const OTHER_PEER: ReplicaId = ReplicaId(Uuid::from_u128(3));

/// State of a new session of `replica`: the saved sync state of `fx` with
/// item `item_key` added.
fn peer_state(fx: &Fixture, replica: ReplicaId, item_key: &str) -> State {
    let mut state = saved(fx).1;
    let mut vault = saved_vault(fx);
    vault.add_or_update_item(item_key, "Joined").unwrap();
    let edits = LocalEdits::find(&state, &vault, replica).unwrap();
    assert!(
        edits
            .record(&mut state, &mut Session::new(replica), NOW)
            .is_some()
    );
    state
}

/// State file `bytes` with the header `format_version` set to `version`.
fn with_format_version(bytes: &[u8], version: u32) -> Vec<u8> {
    let from = b"\"format_version\":1";
    let to = format!("\"format_version\":{version}");
    let at = bytes
        .windows(from.len())
        .position(|window| window == from)
        .unwrap();
    [&bytes[..at], to.as_bytes(), &bytes[at + from.len()..]].concat()
}

fn sidecar(fx: &Fixture) -> Sidecar {
    Sidecar::load(&fx.root, fx.id())
}

#[test]
fn transaction_that_only_joins_publishes_if_join_advanced_local_context_past_published_context() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    // The next transaction moves the staged context of the publish.
    fx.write(|_| Ok(())).unwrap();
    let first = last_publish(&fx).unwrap();
    let peer = peer_state(&fx, PEER, "joined");
    let peer_hash = transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &peer));
    let writes = transport.writes();

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(committed.changed);
    let (_, state) = saved(&fx);
    assert!(new_write_ids(&state, &peer).is_empty());
    assert!(saved_vault(&fx).get_item("joined").is_ok());
    let second = last_publish(&fx).unwrap();
    assert_ne!(second, first);
    assert_eq!(transport.writes(), writes + 1);
    assert_eq!(published(&transport, &fx), vec![second]);
    assert_eq!(decode(&transport, &fx, second), state);
    // Peer files are never deleted by this replica.
    assert_eq!(
        transport.list_states(fx.id(), PEER).unwrap(),
        vec![peer_hash]
    );

    // A peer file that the local context covers causes no publish and no
    // sync state save.
    fx.write(|_| Ok(())).unwrap();
    let covered = transport.put_state(fx.id(), OTHER_PEER, &state_file(&fx, OTHER_PEER, &state));
    let before = fx.on_disk();
    let reads = transport.reads();

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(!committed.changed);
    assert_eq!(transport.reads(), reads + 1);
    assert_eq!(fx.on_disk(), before);
    assert_eq!(transport.writes(), writes + 1);
    assert_eq!(last_publish(&fx), Some(second));
    assert!(sidecar(&fx).is_joined(OTHER_PEER, covered));
}

#[test]
fn edit_saved_in_transaction_that_also_joins_local_peer_file_orders_after_every_value_it_joined() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let peer = peer_state(&fx, PEER, "joined");
    let hash = transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &peer));

    fx.add_item().unwrap();

    let (_, state) = saved(&fx);
    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_ok());
    assert!(vault.get_item("item").is_ok());
    assert!(
        LocalEdits::find(&state, &vault, REPLICA)
            .unwrap()
            .is_empty()
    );
    let minted = new_write_ids(&peer, &state);
    assert_eq!(minted.len(), 1);
    assert_eq!(new_actors(&peer, &state), vec![minted[0].actor]);
    let (_, counter) = state
        .store
        .find_value(&mut |id, _| id == minted[0])
        .unwrap();
    assert!(counter > peer.store.highest_counter());
    assert!(new_write_ids(&state, &peer).is_empty());
    assert!(sidecar(&fx).is_joined(PEER, hash));
}

#[test]
fn file_that_fails_hash_or_decryption_or_names_another_vault_or_replica_is_quarantined() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let peer = peer_state(&fx, PEER, "joined");
    let good = state_file(&fx, PEER, &peer);
    let mut undecryptable = good.clone();
    *undecryptable.last_mut().unwrap() ^= 1;
    let padded = PaddedBody::of(&peer).unwrap();
    let other_vault =
        StateFile::encode(&padded, Uuid::from_u128(0x200), PEER, KeyId(1), &key()).unwrap();
    let other_replica = state_file(&fx, OTHER_PEER, &peer);
    let mismatch = StateFile::name(fx.id(), StateHash::of(b"other bytes"));
    let mut planted = vec![(mismatch, good.clone())];
    for bytes in [undecryptable, other_vault, other_replica] {
        planted.push((StateFile::name(fx.id(), StateHash::of(&bytes)), bytes));
    }
    for (name, bytes) in &planted {
        transport.put(fx.id(), PEER, name, bytes);
    }

    fx.add_item().unwrap();

    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_err());
    assert!(vault.get_item("item").is_ok());
    let quarantined = sidecar(&fx).quarantined;
    assert_eq!(quarantined.len(), 4);
    for (name, bytes) in &planted {
        assert!(
            sidecar(&fx).is_quarantined(PEER, name, StateHash::of(bytes)),
            "{name}"
        );
    }

    // A later file of the same replica is read and joined.
    let hash = transport.put_state(fx.id(), PEER, &good);
    let reads = transport.reads();

    fx.write(|_| Ok(())).unwrap();

    assert!(saved_vault(&fx).get_item("joined").is_ok());
    assert!(sidecar(&fx).is_joined(PEER, hash));
    assert_eq!(sidecar(&fx).quarantined, quarantined);
    // A quarantined file is read again for its content hash.
    assert_eq!(transport.reads(), reads + 5);
}

#[test]
fn torn_peer_file_is_quarantined_and_good_later_file_joins() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let good = state_file(&fx, PEER, &peer_state(&fx, PEER, "joined"));
    let hash = StateHash::of(&good);
    let name = StateFile::name(fx.id(), hash);
    let torn = &good[..good.len() / 2];
    transport.put(fx.id(), PEER, &name, torn);

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(!committed.changed);
    assert!(sidecar(&fx).is_quarantined(PEER, &name, StateHash::of(torn)));
    assert!(!sidecar(&fx).is_joined(PEER, hash));

    // The write of the file completes.
    transport.put(fx.id(), PEER, &name, &good);

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(committed.changed);
    assert!(saved_vault(&fx).get_item("joined").is_ok());
    assert!(sidecar(&fx).is_joined(PEER, hash));
}

#[test]
fn refused_state_is_retried_in_next_transaction_and_quarantined_state_is_not() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let (_, before) = saved(&fx);
    fx.add_item().unwrap();
    let actor = new_actors(&before, &saved(&fx).1)[0];
    // A state that claims a later write of the session's actor.
    let mut claim = peer_state(&fx, PEER, "joined");
    claim.context.record(WriteId { actor, seq: 5 });
    let claim_hash = transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &claim));
    // A state with actor info that differs from the local info.
    let mut forged = peer_state(&fx, OTHER_PEER, "forged");
    forged.actors.get_mut(&actor).unwrap().started_at += 1;
    let forged_bytes = state_file(&fx, OTHER_PEER, &forged);
    let forged_hash = transport.put_state(fx.id(), OTHER_PEER, &forged_bytes);
    let forged_name = StateFile::name(fx.id(), forged_hash);

    fx.write(|_| Ok(())).unwrap();

    let first = sidecar(&fx);
    assert!(!first.is_joined(PEER, claim_hash));
    assert!(first.quarantined.iter().all(|file| file.replica != PEER));
    assert!(first.is_quarantined(OTHER_PEER, &forged_name, forged_hash));
    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_err());
    assert!(vault.get_item("forged").is_err());

    // The claim ended the actor, so the next transaction joins the refused
    // state. The quarantined state is not joined.
    fx.write(|_| Ok(())).unwrap();

    let second = sidecar(&fx);
    assert!(second.is_joined(PEER, claim_hash));
    assert!(!second.is_joined(OTHER_PEER, forged_hash));
    assert_eq!(second.quarantined, first.quarantined);
    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_ok());
    assert!(vault.get_item("forged").is_err());
    assert_eq!(saved(&fx).1.context.get(actor), 5);
}

#[test]
fn file_under_other_fingerprint_or_of_newer_format_is_left_and_other_peer_joins() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let peer = peer_state(&fx, PEER, "joined");
    let padded = PaddedBody::of(&peer).unwrap();
    let other_key = SyncKey::from_bytes([9; 32]);
    let ignored = StateFile::encode(&padded, fx.id(), PEER, KeyId(1), &other_key).unwrap();
    let newer = with_format_version(&state_file(&fx, PEER, &peer), 2);
    let left = [
        transport.put_state(fx.id(), PEER, &ignored),
        transport.put_state(fx.id(), PEER, &newer),
    ];
    let other = peer_state(&fx, OTHER_PEER, "other");
    let other_hash = transport.put_state(fx.id(), OTHER_PEER, &state_file(&fx, OTHER_PEER, &other));

    fx.add_item().unwrap();

    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_err());
    assert!(vault.get_item("other").is_ok());
    assert!(vault.get_item("item").is_ok());
    let first = sidecar(&fx);
    assert!(first.quarantined.is_empty());
    assert!(left.iter().all(|hash| !first.is_joined(PEER, *hash)));
    assert!(first.is_joined(OTHER_PEER, other_hash));
    // The local edit is published.
    let hash = last_publish(&fx).unwrap();
    assert_eq!(published(&transport, &fx), vec![hash]);

    // Both files are read again in each transaction.
    let reads = transport.reads();

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(transport.reads(), reads + 2);
    assert!(sidecar(&fx).quarantined.is_empty());
}

#[test]
fn remote_peer_file_is_not_joined_and_not_quarantined() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let bytes = state_file(&fx, PEER, &peer_state(&fx, PEER, "joined"));
    let hash = StateHash::of(&bytes);
    let name = StateFile::name(fx.id(), hash);
    transport.put_remote(fx.id(), PEER, &name);

    fx.add_item().unwrap();

    assert_eq!(transport.reads(), 0);
    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_err());
    assert!(vault.get_item("item").is_ok());
    let sidecar = sidecar(&fx);
    assert!(!sidecar.is_joined(PEER, hash));
    assert!(sidecar.quarantined.is_empty());
    assert_eq!(transport.names(fx.id(), PEER), vec![name]);
}

#[test]
fn every_local_peer_file_is_read_and_each_joined_file_is_read_once() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    // Two concurrent files of one peer. Neither covers the other.
    let hashes = ["first", "second"].map(|item_key| {
        let state = peer_state(&fx, PEER, item_key);
        transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &state))
    });

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(transport.reads(), 2);
    let vault = saved_vault(&fx);
    assert!(vault.get_item("first").is_ok());
    assert!(vault.get_item("second").is_ok());
    assert!(
        hashes
            .iter()
            .all(|hash| sidecar(&fx).is_joined(PEER, *hash))
    );

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(transport.reads(), 2);
}

#[test]
fn folder_or_peer_directory_that_cannot_be_listed_stops_no_other_peer_and_edit_is_saved() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let peer = transport.put_state(
        fx.id(),
        PEER,
        &state_file(&fx, PEER, &peer_state(&fx, PEER, "joined")),
    );
    let other = transport.put_state(
        fx.id(),
        OTHER_PEER,
        &state_file(&fx, OTHER_PEER, &peer_state(&fx, OTHER_PEER, "other")),
    );

    transport.set_unlistable(PEER, true);
    fx.add_item().unwrap();

    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_err());
    assert!(vault.get_item("other").is_ok());
    assert!(vault.get_item("item").is_ok());

    // The joined hashes of a directory that cannot be listed are kept.
    transport.set_unlistable(PEER, false);
    transport.set_unlistable(OTHER_PEER, true);
    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();

    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_ok());
    assert!(vault.get_item("second").is_ok());
    assert!(sidecar(&fx).is_joined(OTHER_PEER, other));

    // With the replica directories unlisted, own files still join.
    transport.set_unlistable(OTHER_PEER, false);
    transport.set_unlistable_replicas(true);
    let own = peer_state(&fx, REPLICA, "own");
    transport.put_state(fx.id(), REPLICA, &state_file(&fx, REPLICA, &own));
    fx.write(|vh| vh.add_item("third", "Third").map(|_| ()))
        .unwrap();

    let vault = saved_vault(&fx);
    assert!(vault.get_item("own").is_ok());
    assert!(vault.get_item("third").is_ok());
    let sidecar = sidecar(&fx);
    assert!(sidecar.is_joined(PEER, peer));
    assert!(sidecar.is_joined(OTHER_PEER, other));
}

#[test]
fn joined_hashes_of_peer_whose_directory_is_gone_are_dropped() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let hash = transport.put_state(
        fx.id(),
        PEER,
        &state_file(&fx, PEER, &peer_state(&fx, PEER, "joined")),
    );
    fx.write(|_| Ok(())).unwrap();
    assert!(sidecar(&fx).is_joined(PEER, hash));

    transport
        .delete_own(fx.id(), PEER, FileName::State(hash))
        .unwrap();
    fx.write(|_| Ok(())).unwrap();

    let sidecar = sidecar(&fx);
    assert!(!sidecar.joined.contains_key(&PEER));
    assert!(sidecar.joined.contains_key(&REPLICA));
    assert!(saved_vault(&fx).get_item("joined").is_ok());
}
