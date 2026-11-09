use std::collections::BTreeSet;
use std::fs;

use uuid::Uuid;

use super::{NAME, NewMac, folder, typed_key, vault};
use crate::audit::test_support::test_dir;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::device_keys::{DeviceKeys, KeyProbe};
use crate::secrets::vaults::storage::test_keys::TestKeys;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::model::PublicKey;
use crate::secrets::vaults::sync::pairing::PairingCode;
use crate::secrets::vaults::sync::pairing::request::PairingRequest;
use crate::secrets::vaults::sync::transport::SyncTransport;

#[test]
fn start_writes_verifiable_request() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1), vault(2)]);
    let pending = mac.start(&transport, &[]).unwrap();
    let request = pending.request();
    let bytes = transport.pairing(request.request_id).unwrap();
    let written = PairingRequest::parse(&bytes).unwrap();
    assert_eq!(&written, request);
    assert!(written.verify(&typed_key(&pending)));
    assert!(!written.verify(&PairingCode::generate().pair_key()));
    assert_eq!(written.name, NAME);
    assert_eq!(written.encryption, PublicKey(vec![0xe1; 65]));
    assert_eq!(written.signing, PublicKey(vec![0x51; 65]));
    assert_eq!(mac.keys.created(), 0);
}

#[test]
fn start_without_keys_creates_both_keys() {
    let mut mac = NewMac::new();
    mac.keys = TestKeys::neither();
    let transport = folder(&[vault(1)]);
    let pending = mac.start(&transport, &[]).unwrap();
    assert_eq!(mac.keys.created(), 2);
    assert_eq!(mac.keys.probe_encryption_key(), KeyProbe::Present);
    assert!(transport.pairing(pending.request().request_id).is_some());
}

#[test]
fn new_hardware_start_moves_files_first() {
    let _audit = test_dir();
    let mut mac = NewMac::new();
    mac.keys = TestKeys::neither();
    let vaults = mac.root().join("vaults");
    fs::create_dir_all(&vaults).unwrap();
    fs::write(vaults.join("personal.json"), b"{}").unwrap();
    let transport = folder(&[vault(1), vault(2)]);
    let pending = mac.start(&transport, &[vault(1)]).unwrap();
    assert!(!vaults.join("personal.json").exists());
    assert_eq!(mac.keys.created(), 2);
    let listed: Vec<Uuid> = pending.request().replicas.keys().copied().collect();
    assert_eq!(listed, vec![vault(1), vault(2)]);
}

#[test]
fn start_with_signing_key_lost_fails_and_writes_no_request() {
    let mut mac = NewMac::new();
    mac.keys = TestKeys::new(KeyProbe::Present, KeyProbe::Missing);
    let vaults = mac.root().join("vaults");
    fs::create_dir_all(&vaults).unwrap();
    fs::write(vaults.join("personal.json"), b"{}").unwrap();
    let transport = folder(&[vault(1)]);
    assert!(matches!(
        mac.start(&transport, &[]),
        Err(Error::SigningKeyNotFound)
    ));
    assert_eq!(mac.keys.created(), 0);
    assert!(transport.list_pairings().unwrap().is_empty());
}

#[test]
fn vault_this_mac_syncs_not_in_request_map() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1), vault(2), vault(3)]);
    let pending = mac.start(&transport, &[vault(2)]).unwrap();
    let listed: Vec<Uuid> = pending.request().replicas.keys().copied().collect();
    assert_eq!(listed, vec![vault(1), vault(3)]);
}

#[test]
fn start_with_no_vault_to_pair_fails_and_creates_no_key_or_request() {
    let mut mac = NewMac::new();
    mac.keys = TestKeys::neither();
    for (vaults, synced) in [(vec![], vec![]), (vec![vault(1)], vec![vault(1)])] {
        let transport = folder(&vaults);
        assert!(matches!(
            mac.start(&transport, &synced),
            Err(Error::PairingNoVaults)
        ));
        assert!(transport.list_pairings().unwrap().is_empty());
    }
    assert_eq!(mac.keys.created(), 0);

    let transport = folder(&[vault(1)]);
    transport.set_unavailable(true);
    assert!(matches!(
        mac.start(&transport, &[]),
        Err(Error::SyncTransportError(_))
    ));
    assert_eq!(mac.keys.created(), 0);
}

#[test]
fn request_holds_one_new_replica_id_per_vault_and_two_requests_hold_different_ids() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1), vault(2), vault(3)]);
    let first = mac.start(&transport, &[]).unwrap();
    let second = mac.start(&transport, &[]).unwrap();
    assert_ne!(first.request().request_id, second.request().request_id);
    let first_ids: BTreeSet<ReplicaId> = first.request().replicas.values().copied().collect();
    let second_ids: BTreeSet<ReplicaId> = second.request().replicas.values().copied().collect();
    assert_eq!(first_ids.len(), 3);
    assert_eq!(second_ids.len(), 3);
    assert!(first_ids.is_disjoint(&second_ids));
    assert_ne!(first.code().shown(), second.code().shown());
    assert_eq!(transport.list_pairings().unwrap().len(), 2);
}

#[test]
fn finish_deletes_request() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1)]);
    let pending = mac.start(&transport, &[]).unwrap();
    let request_id = pending.request().request_id;
    assert!(transport.pairing(request_id).is_some());
    pending.finish(&transport).unwrap();
    assert!(transport.pairing(request_id).is_none());
    assert!(transport.list_pairings().unwrap().is_empty());
}
