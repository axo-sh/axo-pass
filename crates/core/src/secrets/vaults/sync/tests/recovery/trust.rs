use std::sync::Arc;

use uuid::Uuid;

use super::super::NOW;
use super::super::load::{Fixture, GENERATION, REPLICA, body, device_key};
use super::super::state_file::key;
use super::super::transport::FakeTransport;
use super::super::txn::{saved, synced, two_keys, under_key_2};
use super::super::view::State;
use super::{Macs, ages, key_file, kit_of, put_key_file, recovered, replica, state_file_under};
use crate::secrets::vaults::sync::crdt::{ReplicaId, Session};
use crate::secrets::vaults::sync::keys::SyncKey;
use crate::secrets::vaults::sync::model::{KeyId, RecoveryRecipient};
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::recovery::import::{RecoveryCheck, RecoveryImport};
use crate::secrets::vaults::sync::state_file::StateFile;
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::sync::wrapping::{AgeWrapping, Wrapping};

/// Replica of a removed Mac that still holds the sync key.
const REMOVED: ReplicaId = ReplicaId(Uuid::from_u128(99));

/// `state` with `value` written into the `recovery` register of
/// `recipient` by a new session of `replica`.
fn with_recipient(
    mut state: State,
    replica: ReplicaId,
    recipient: &str,
    value: RecoveryRecipient,
) -> State {
    let mut session = Session::new(replica);
    let m = session.mint(&mut state, NOW);
    state
        .store
        .recovery
        .entry(recipient.to_string())
        .write(&m, value);
    state
}

#[test]
fn recipient_with_current_key_id_and_another_fingerprint_receives_no_wrapping_and_does_not_clear_degraded_state()
 {
    let macs = Macs::new(2);
    let planted = age::x25519::Identity::generate().to_public().to_string();
    let value = RecoveryRecipient {
        key_id: KeyId(1),
        key_fingerprint: SyncKey::from_bytes([9; 32]).fingerprint().0,
    };
    // A removed Mac adds the recipient for the key id it predicts.
    let state = with_recipient(macs.macs[0].state(), REMOVED, &planted, value);
    let bytes = state_file_under(macs.vault_id, REMOVED, &state, KeyId(1), &key());
    macs.transport.put_state(macs.vault_id, REMOVED, &bytes);

    for mac in &macs.macs {
        assert!(mac.sync().recovery_kit_missing);
        assert!(mac.state().store.recovery.get(&planted).is_some());
        assert_eq!(key_file(&macs.transport, macs.vault_id, mac.replica), None);
    }
}

#[test]
fn recipient_for_older_key_id_receives_no_wrapping() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    let current = two_keys().get(KeyId(2)).unwrap().clone();
    let older = age::x25519::Identity::generate().to_public().to_string();
    let newer = age::x25519::Identity::generate().to_public().to_string();
    let state = body(REPLICA, &[device_key()]);
    let state = with_recipient(
        state,
        REPLICA,
        &older,
        RecoveryRecipient {
            key_id: KeyId(1),
            key_fingerprint: key().fingerprint().0,
        },
    );
    let state = with_recipient(
        state,
        REPLICA,
        &newer,
        RecoveryRecipient {
            key_id: KeyId(2),
            key_fingerprint: current.fingerprint().0,
        },
    );
    fx.put_text(&under_key_2(&fx, &state, &two_keys()));

    let committed = fx.write(|_| Ok(())).unwrap();
    assert!(!committed.recovery_kit_missing);
    assert_eq!(ages(&transport, fx.id(), REPLICA), [(newer, KeyId(2))]);
}

#[test]
fn age_wrapping_with_planted_fingerprint_rejected() {
    let vault_id = Uuid::from_u128(0x100);
    let kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    let transport = FakeTransport::default();
    let mut planted =
        AgeWrapping::wrap(KeyId(1), &SyncKey::from_bytes([9; 32]), &kit.recipient()).unwrap();
    planted.key_fingerprint = kit.fingerprint;
    put_key_file(
        &transport,
        vault_id,
        replica(1),
        vec![Wrapping::Age(planted)],
    );

    assert!(matches!(
        RecoveryImport::check(&kit, &transport).unwrap(),
        RecoveryCheck::NoKey
    ));

    // The real wrapping in a later directory still opens.
    let real = AgeWrapping::wrap(KeyId(1), &key(), &kit.recipient()).unwrap();
    put_key_file(&transport, vault_id, replica(2), vec![Wrapping::Age(real)]);
    let opened = recovered(RecoveryImport::check(&kit, &transport).unwrap());
    assert_eq!(opened.as_bytes(), key().as_bytes());
}

#[test]
fn key_with_partial_fingerprint_match_rejected() {
    let vault_id = Uuid::from_u128(0x100);
    let mut kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    kit.fingerprint.0[15] ^= 1;
    assert_eq!(kit.fingerprint.0[..8], key().fingerprint().0[..8]);
    assert!(!kit.opens(&key()));

    let transport = FakeTransport::default();
    let wrapping = AgeWrapping::wrap(KeyId(1), &key(), &kit.recipient()).unwrap();
    put_key_file(
        &transport,
        vault_id,
        replica(1),
        vec![Wrapping::Age(wrapping)],
    );
    assert!(matches!(
        RecoveryImport::check(&kit, &transport).unwrap(),
        RecoveryCheck::NoKey
    ));
}

#[test]
fn kit_below_peer_header_key_id_refused() {
    let vault_id = Uuid::from_u128(0x100);
    let kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    let transport = FakeTransport::default();
    let wrapping = AgeWrapping::wrap(KeyId(1), &key(), &kit.recipient()).unwrap();
    put_key_file(
        &transport,
        vault_id,
        replica(1),
        vec![Wrapping::Age(wrapping)],
    );
    let state = body(replica(1), &[device_key()]);
    let old = state_file_under(vault_id, replica(1), &state, KeyId(1), &key());
    transport.put_state(vault_id, replica(1), &old);
    let rotated = state_file_under(
        vault_id,
        replica(2),
        &state,
        KeyId(2),
        &SyncKey::from_bytes([3; 32]),
    );
    transport.put_state(vault_id, replica(2), &rotated);

    match RecoveryImport::check(&kit, &transport).unwrap() {
        RecoveryCheck::KitOutdated { kit, highest } => {
            assert_eq!((kit, highest), (KeyId(1), KeyId(2)));
        },
        other => panic!("kit was not refused: {other:?}"),
    }
}

#[test]
fn planted_header_with_higher_key_id_refuses_kit_and_no_state_accepted_from_it() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kit = kit_of(&fx);
    let wrapping = AgeWrapping::wrap(KeyId(1), &key(), &kit.recipient()).unwrap();
    put_key_file(&transport, fx.id(), REMOVED, vec![Wrapping::Age(wrapping)]);
    let header = br#"{"key_id":9}"#;
    let planted = [
        b"APST".as_slice(),
        &(header.len() as u32).to_be_bytes(),
        header,
        &[0xee; 64],
    ]
    .concat();
    transport.put_state(fx.id(), REMOVED, &planted);

    match RecoveryImport::check(&kit, &*transport).unwrap() {
        RecoveryCheck::KitOutdated { highest, .. } => assert_eq!(highest, KeyId(9)),
        other => panic!("kit was not refused: {other:?}"),
    }

    // A transaction quarantines the planted file and joins nothing from it.
    let before = saved(&fx).1;
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(
        committed.sync_status,
        Some(SyncStatus::Paused(vec![PausedCause::Quarantined {
            files: 1
        }]))
    );
    assert_eq!(saved(&fx).1.store, before.store);
}

#[test]
fn state_file_key_id_read_from_header_without_decryption() {
    let state = body(REPLICA, &[device_key()]);
    let bytes = state_file_under(Uuid::from_u128(0x100), REPLICA, &state, KeyId(4), &key());
    assert_eq!(StateFile::peek_key_id(&bytes).unwrap(), KeyId(4));
    assert!(StateFile::peek_key_id(b"APST").is_err());
    assert!(StateFile::peek_key_id(b"NOPE\0\0\0\x02{}").is_err());
}
