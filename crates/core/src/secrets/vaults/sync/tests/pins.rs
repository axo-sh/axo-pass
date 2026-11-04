//! Pins at first use, the revocation mark, pairing pins, and pin saves.

use std::sync::Arc;

use uuid::Uuid;

use super::join::PEER;
use super::load::{Fixture, GENERATION, REPLICA, body, device_key, state_of};
use super::local_state::{contents, parse, raw_state, replaced, signed};
use super::transport::FakeTransport;
use super::txn::{saved, state_file, synced};
use super::view::State;
use super::{NOW, id};
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::sync::crdt::{ReplicaId, Session};
use crate::secrets::vaults::sync::local_state::{
    LocalStateError, LocalSyncState, PinSource, PinnedKeys,
};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::pins::{PairedPin, Pins};
use crate::secrets::vaults::sync::status::BUILD_ID;

/// Replica of a third Mac.
const OTHER_PEER: ReplicaId = ReplicaId(Uuid::from_u128(3));

/// Public keys numbered `n`.
fn keys(n: u8) -> ReplicaKeys {
    ReplicaKeys {
        encryption: PublicKey(vec![4, n]),
        signing: PublicKey(vec![4, n, n]),
    }
}

/// Unrevoked pin of `keys` with `source`.
fn pin(source: PinSource, keys: &ReplicaKeys) -> PinnedKeys {
    PinnedKeys {
        source,
        encryption: keys.encryption.clone(),
        signing: keys.signing.clone(),
        revoked: false,
    }
}

/// `state` with `keys` written to the `replica_keys` register of `replica`
/// by a new session of `writer`.
fn with_keys(mut state: State, replica: ReplicaId, writer: ReplicaId, keys: ReplicaKeys) -> State {
    let mut session = Session::new(writer);
    let m = session.mint(&mut state, NOW);
    state.store.replica_keys.entry(replica).write(&m, keys);
    state
}

/// Put `state` as a state file of `replica` for vault `fx`.
fn put(transport: &FakeTransport, fx: &Fixture, replica: ReplicaId, state: &State) {
    transport.put_state(fx.id(), replica, &state_file(fx, replica, state));
}

/// Pins of the saved sync state of `fx`.
fn pins(fx: &Fixture) -> Vec<(ReplicaId, PinnedKeys)> {
    saved(fx).0.pinned_keys.into_iter().collect()
}

#[test]
fn first_join_of_peer_file_pins_keys_of_its_writer_with_first_use() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let first = with_keys(saved(&fx).1, PEER, PEER, keys(1));
    put(&transport, &fx, PEER, &first);

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(pins(&fx), vec![(PEER, pin(PinSource::FirstUse, &keys(1)))]);

    // A later value of the peer replaces the first in the register, and
    // the pin is unchanged.
    let later = with_keys(first, PEER, PEER, keys(2));
    put(&transport, &fx, PEER, &later);

    fx.write(|_| Ok(())).unwrap();

    let (local, state) = saved(&fx);
    let register = state.store.replica_keys.get(&PEER).unwrap();
    let values: Vec<_> = register.values().map(|(_, v)| v.value.clone()).collect();
    assert_eq!(values, vec![keys(2)]);
    let pinned: Vec<_> = local.pinned_keys.into_iter().collect();
    assert_eq!(pinned, vec![(PEER, pin(PinSource::FirstUse, &keys(1)))]);
}

#[test]
fn value_written_by_another_replica_actor_is_not_pinned_for_register_owner() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let base = saved(&fx).1;
    let planted = with_keys(base.clone(), PEER, OTHER_PEER, keys(9));
    put(&transport, &fx, OTHER_PEER, &planted);

    fx.write(|_| Ok(())).unwrap();

    let (_, state) = saved(&fx);
    assert!(state.store.replica_keys.get(&PEER).is_some());
    assert_eq!(pins(&fx), vec![]);

    // The owner writes concurrently with the planted value, so the register
    // holds both, and the one value of the owner is pinned.
    let own = with_keys(base, PEER, PEER, keys(1));
    put(&transport, &fx, PEER, &own);

    fx.write(|_| Ok(())).unwrap();

    let (_, state) = saved(&fx);
    assert_eq!(
        state
            .store
            .replica_keys
            .get(&PEER)
            .unwrap()
            .values()
            .count(),
        2
    );
    assert_eq!(pins(&fx), vec![(PEER, pin(PinSource::FirstUse, &keys(1)))]);
}

#[test]
fn register_with_two_values_of_its_owner_pins_nothing_until_one_remains() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let base = saved(&fx).1;
    let mut two = with_keys(base.clone(), PEER, PEER, keys(1));
    two.join(with_keys(base, PEER, PEER, keys(2)));
    put(&transport, &fx, PEER, &two);

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(pins(&fx), vec![]);

    let one = with_keys(two, PEER, PEER, keys(3));
    put(&transport, &fx, PEER, &one);

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(pins(&fx), vec![(PEER, pin(PinSource::FirstUse, &keys(3)))]);
}

#[test]
fn this_replica_is_never_pinned() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    // The own register holds the device key, written by an actor of this
    // replica.
    let (_, state) = saved(&fx);
    assert!(state.store.replica_keys.get(&REPLICA).is_some());
    put(
        &transport,
        &fx,
        PEER,
        &with_keys(state, PEER, PEER, keys(2)),
    );

    fx.add_item().unwrap();

    assert_eq!(pins(&fx), vec![(PEER, pin(PinSource::FirstUse, &keys(2)))]);
}

#[test]
fn save_that_only_adds_pin_leaves_s_and_body_ciphertext_unchanged() {
    let fx = Fixture::synced();
    let body = with_keys(body(REPLICA, &[device_key()]), PEER, PEER, keys(1));
    let mut loaded = state_of(fx.id(), REPLICA, GENERATION, &body);
    // The state is published, so the transaction does not publish.
    loaded.published_context = body.context.clone();
    fx.put(&loaded, &TestSigner::device());
    let (vault_before, _) = fx.on_disk();

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(!committed.changed);
    let (vault_after, _) = fx.on_disk();
    assert_eq!(vault_after, vault_before);
    let (local, state) = saved(&fx);
    assert_eq!(local.generation, GENERATION);
    assert_eq!(state, body);
    let json = |local: &LocalSyncState| serde_json::to_value(local).unwrap();
    assert_eq!(json(&local)["body"], json(&loaded)["body"]);
    assert_eq!(json(&local)["nonce"], json(&loaded)["nonce"]);
    let mut unpinned = local.clone();
    unpinned.pinned_keys.clear();
    assert_eq!(unpinned, loaded);
    assert_eq!(pins(&fx), vec![(PEER, pin(PinSource::FirstUse, &keys(1)))]);

    // The next transaction finds the pin and saves nothing.
    let before = fx.on_disk();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(fx.on_disk(), before);
}

#[test]
fn stopped_transaction_pins_nothing() {
    let fx = Fixture::synced();
    let body = with_keys(body(REPLICA, &[device_key()]), PEER, PEER, keys(1));
    let mut loaded = state_of(fx.id(), REPLICA, GENERATION, &body);
    loaded.stopped_build = Some(BUILD_ID.to_string());
    fx.put(&loaded, &TestSigner::device());
    let before = fx.on_disk();

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(fx.on_disk(), before);
    assert_eq!(pins(&fx), vec![]);
}

#[test]
fn repair_at_v_greater_than_s_pins_peer_of_its_joins() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    fx.put_state(GENERATION - 1);
    let peer = with_keys(saved(&fx).1, PEER, PEER, keys(1));
    put(&transport, &fx, PEER, &peer);

    fx.write(|_| Ok(())).unwrap();

    let (local, _) = saved(&fx);
    assert_eq!(local.generation, GENERATION + 1);
    assert_eq!(pins(&fx), vec![(PEER, pin(PinSource::FirstUse, &keys(1)))]);
}

#[test]
fn changed_revoked_mark_fails_verification() {
    let contents = contents();
    assert!(contents.contains("\"revoked\": false"));
    let changed = replaced(&contents, "\"revoked\": false", "\"revoked\": true");

    assert!(matches!(
        parse(&changed),
        Err(LocalStateError::SignatureInvalid)
    ));
    let resigned = parse(&signed(&raw_state(&changed))).unwrap();
    assert!(resigned.pinned_keys[&ReplicaId(id(2))].revoked);
}

#[test]
fn local_state_without_revoked_field_parses_as_not_revoked() {
    let mut state: serde_json::Value = serde_json::from_str(&raw_state(&contents())).unwrap();
    let pinned = state["pinned_keys"].as_object_mut().unwrap();
    for pin in pinned.values_mut() {
        assert!(pin.as_object_mut().unwrap().remove("revoked").is_some());
    }
    let state_json = serde_json::to_string(&state).unwrap();
    assert!(!state_json.contains("revoked"));

    let local = parse(&signed(&state_json)).unwrap();

    assert!(!local.pinned_keys[&ReplicaId(id(2))].revoked);
}

#[test]
fn pin_paired_adds_upgrades_or_refuses_pin() {
    let mut local = LocalSyncState::new(id(1), REPLICA, KeyId(1));

    assert_eq!(Pins::pin_paired(&mut local, PEER, &keys(1)), PairedPin::New);
    assert_eq!(local.pinned_keys[&PEER], pin(PinSource::Pairing, &keys(1)));
    assert_eq!(
        Pins::pin_paired(&mut local, PEER, &keys(1)),
        PairedPin::Unchanged
    );

    local
        .pinned_keys
        .insert(OTHER_PEER, pin(PinSource::FirstUse, &keys(2)));
    assert_eq!(
        Pins::pin_paired(&mut local, OTHER_PEER, &keys(2)),
        PairedPin::Upgraded
    );
    assert_eq!(
        local.pinned_keys[&OTHER_PEER],
        pin(PinSource::Pairing, &keys(2))
    );
}

#[test]
fn pin_paired_over_pin_with_other_keys_or_revoked_pin_is_conflict_and_changes_nothing() {
    let mut local = LocalSyncState::new(id(1), REPLICA, KeyId(1));
    local
        .pinned_keys
        .insert(PEER, pin(PinSource::FirstUse, &keys(1)));
    let mut revoked = pin(PinSource::FirstUse, &keys(2));
    revoked.revoked = true;
    local.pinned_keys.insert(OTHER_PEER, revoked);
    let before = local.clone();

    let other_signing = ReplicaKeys {
        encryption: keys(1).encryption,
        signing: keys(9).signing,
    };
    for (replica, keys) in [
        (PEER, keys(9)),
        (PEER, other_signing),
        (OTHER_PEER, keys(2)),
    ] {
        assert_eq!(
            Pins::pin_paired(&mut local, replica, &keys),
            PairedPin::Conflict
        );
    }
    assert_eq!(local, before);
}

#[test]
fn only_new_and_upgraded_pairing_pins_change_local_state() {
    let changed: Vec<bool> = [
        PairedPin::New,
        PairedPin::Upgraded,
        PairedPin::Unchanged,
        PairedPin::Conflict,
    ]
    .into_iter()
    .map(PairedPin::changed)
    .collect();

    assert_eq!(changed, [true, true, false, false]);
}
