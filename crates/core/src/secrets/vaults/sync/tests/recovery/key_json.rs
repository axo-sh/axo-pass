use std::path::PathBuf;
use std::sync::Arc;

use super::super::guard::{drift, stopped};
use super::super::load::{REPLICA, device_key};
use super::super::state_file::key;
use super::super::transport::FakeTransport;
use super::super::txn::synced;
use super::{ages, confirm, key_file, kit_of, recovered, replica};
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::txn::{Target, Unlock};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::pairing::PairingCode;
use crate::secrets::vaults::sync::pairing::grant::GrantOutcome;
use crate::secrets::vaults::sync::pairing::request::PairingRequest;
use crate::secrets::vaults::sync::recovery::import::RecoveryImport;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::sync::transport::{RequestId, TransportRoot};
use crate::secrets::vaults::sync::wrapping::{DeviceWrapping, Wrapping};

#[test]
fn deleted_own_key_json_written_again_with_device_wrappings_lost_and_age_wrappings_back() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kit = kit_of(&fx);
    confirm(&fx, &kit).unwrap();
    let mut file = key_file(&transport, fx.id(), REPLICA).unwrap();
    file.wrappings.push(Wrapping::Device(DeviceWrapping {
        key_id: KeyId(1),
        key_fingerprint: key().fingerprint(),
        to_replica: replica(5),
        from_encryption: PublicKey(vec![4, 1]),
        from_signing: PublicKey(device_key()),
        wrapped: vec![1, 2, 3],
        pairing_mac: None,
        signature: None,
        removed: None,
        remaining: None,
    }));
    transport.put(fx.id(), REPLICA, "key.json", &file.to_bytes());

    // An unchanged file with its wanted wrapping is not written again.
    let writes = transport.writes();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(transport.writes(), writes);

    transport.remove(fx.id(), REPLICA, "key.json");
    fx.write(|_| Ok(())).unwrap();
    let file = key_file(&transport, fx.id(), REPLICA).unwrap();
    assert_eq!(file.devices().count(), 0);
    assert_eq!(
        ages(&transport, fx.id(), REPLICA),
        [(kit.recipient(), KeyId(1))]
    );
    let opened = recovered(RecoveryImport::check(&kit, &*transport).unwrap());
    assert_eq!(opened.as_bytes(), key().as_bytes());
}

#[test]
fn pairing_grant_and_age_wrappings_written_in_one_key_json_write() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let root = TransportRoot::Folder {
        path: PathBuf::from("/recovery/Vaults"),
    };
    let sidecar = Sidecar {
        transport: Some(root.clone()),
        ..Sidecar::default()
    };
    sidecar.save(&fx.root, fx.id()).unwrap();
    let kit = kit_of(&fx);
    confirm(&fx, &kit).unwrap();
    transport.remove(fx.id(), REPLICA, "key.json");

    let software = ManagedKey::create_software_for_test().unwrap();
    let keys = ReplicaKeys {
        encryption: PublicKey(software.public_key_sec1().unwrap()),
        signing: PublicKey(vec![0x51; 65]),
    };
    let code = PairingCode::generate();
    let to_replica = ReplicaId::generate();
    let request = PairingRequest::new(
        RequestId::generate(),
        [(fx.id(), to_replica)].into_iter().collect(),
        &keys,
        "New Mac".to_string(),
        &code.pair_key(),
    );
    let unlock = || fx.vault.unlocked_key().unwrap();
    let outcome = fx.catalog.files().grant_pairing(
        &Target::of(&fx.vault),
        Unlock::Test(&unlock),
        &request,
        &code,
        &root,
    );
    assert!(matches!(outcome, GrantOutcome::Granted(_)), "{outcome:?}");

    let file = key_file(&transport, fx.id(), REPLICA).unwrap();
    let devices: Vec<ReplicaId> = file.devices().map(|device| device.to_replica).collect();
    assert_eq!(devices, [to_replica]);
    assert_eq!(
        ages(&transport, fx.id(), REPLICA),
        [(kit.recipient(), KeyId(1))]
    );
}

#[test]
fn failed_key_json_write_pauses_sync_with_publish_failed_and_next_transaction_writes_it() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kit = kit_of(&fx);
    confirm(&fx, &kit).unwrap();
    transport.remove(fx.id(), REPLICA, "key.json");

    transport.set_failing_writes(true);
    let committed = fx.write(|_| Ok(())).unwrap();
    assert!(matches!(
        committed.sync_status,
        Some(SyncStatus::Paused(ref causes))
            if matches!(causes[..], [PausedCause::PublishFailed { .. }])
    ));
    assert_eq!(key_file(&transport, fx.id(), REPLICA), None);

    transport.set_failing_writes(false);
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(
        ages(&transport, fx.id(), REPLICA),
        [(kit.recipient(), KeyId(1))]
    );
}

#[test]
fn stopped_transaction_writes_no_key_json_and_confirmation_while_stopped_writes_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kit = kit_of(&fx);
    confirm(&fx, &kit).unwrap();
    transport.remove(fx.id(), REPLICA, "key.json");
    drift(&fx, "item");

    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, stopped());
    assert_eq!(key_file(&transport, fx.id(), REPLICA), None);

    let other = kit_of(&fx);
    let on_disk = fx.on_disk();
    let writes = transport.writes();
    assert!(matches!(
        confirm(&fx, &other),
        Err(Error::RecoveryKitNotAdded(_))
    ));
    assert_eq!(fx.on_disk(), on_disk);
    assert_eq!(transport.writes(), writes);
}
