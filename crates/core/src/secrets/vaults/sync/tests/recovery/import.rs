use uuid::Uuid;

use super::super::load::{body, device_key};
use super::super::state_file::key;
use super::super::transport::FakeTransport;
use super::{Macs, ages, put_key_file, recovered, replica, state_file_under, with_name};
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::recovery::import::{
    RecoveryCheck, RecoveryImport, WaitingReplica,
};
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::transport::SyncTransport;
use crate::secrets::vaults::sync::wrapping::{AgeWrapping, Wrapping};

#[test]
fn every_replica_writes_age_wrapping_for_each_recipient_of_current_key_and_kit_opens_after_kit_maker_directory_deleted()
 {
    let macs = Macs::new(3);
    let kit = macs.kit();
    macs.macs[0].confirm(&kit);
    for mac in &macs.macs[1..] {
        mac.sync();
    }

    for mac in &macs.macs {
        assert_eq!(
            ages(&macs.transport, macs.vault_id, mac.replica),
            [(kit.recipient(), KeyId(1))],
            "replica {} holds no age wrapping",
            mac.replica.0
        );
    }

    // Cleanup of the Mac that made the kit is milestone 13, and is a
    // deletion of its directory here.
    macs.transport
        .delete_replica(macs.vault_id, macs.macs[0].replica)
        .unwrap();
    let opened = recovered(RecoveryImport::check(&kit, &*macs.transport).unwrap());
    assert_eq!(opened.as_bytes(), key().as_bytes());
}

#[test]
fn import_waits_for_remote_peer_state_files() {
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
    // The local file of Mac 1 names Mac 2. Mac 3 is named by no local file.
    let state = with_name(body(replica(1), &[device_key()]), replica(2), "Mac 2");
    let local = state_file_under(vault_id, replica(1), &state, KeyId(1), &key());
    transport.put_state(vault_id, replica(1), &local);
    for n in [2, 3] {
        let bytes = state_file_under(vault_id, replica(n), &state, KeyId(1), &key());
        let hash = StateHash::of(&bytes);
        transport.put_remote_with(
            vault_id,
            replica(n),
            &StateFile::name(vault_id, hash),
            &bytes,
        );
    }

    let waiting = vec![
        WaitingReplica {
            replica: replica(2),
            name: Some("Mac 2".to_string()),
        },
        WaitingReplica {
            replica: replica(3),
            name: None,
        },
    ];
    // Each check waits until the files are local. The user cancels by not
    // checking again.
    for _ in 0..2 {
        match RecoveryImport::check(&kit, &transport).unwrap() {
            RecoveryCheck::Waiting(replicas) => assert_eq!(replicas, waiting),
            other => panic!("import did not wait: {other:?}"),
        }
    }
    assert_eq!(transport.download_requests(), [vault_id, vault_id]);

    assert_eq!(transport.complete_downloads(vault_id), 2);
    let opened = recovered(RecoveryImport::check(&kit, &transport).unwrap());
    assert_eq!(opened.as_bytes(), key().as_bytes());
}

#[test]
fn remote_state_file_requested_for_download() {
    let vault_id = Uuid::from_u128(0x100);
    let kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    let transport = FakeTransport::default();
    let state = body(replica(1), &[device_key()]);
    let bytes = state_file_under(vault_id, replica(1), &state, KeyId(1), &key());
    let hash = StateHash::of(&bytes);
    transport.put_remote(vault_id, replica(1), &StateFile::name(vault_id, hash));

    assert!(matches!(
        RecoveryImport::check(&kit, &transport).unwrap(),
        RecoveryCheck::Waiting(_)
    ));
    assert_eq!(transport.download_requests(), [vault_id]);
}

#[test]
fn each_import_takes_new_replica_id() {
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

    let replica_id = |check| match check {
        RecoveryCheck::Recovered(recovered) => {
            assert_eq!(recovered.vault_id, vault_id);
            assert_eq!(recovered.key_id, KeyId(1));
            recovered.replica_id
        },
        other => panic!("kit did not open a key: {other:?}"),
    };
    let first = replica_id(RecoveryImport::check(&kit, &transport).unwrap());
    let second = replica_id(RecoveryImport::check(&kit, &transport).unwrap());
    assert_ne!(first, second);
    assert_ne!(first, replica(1));
}
