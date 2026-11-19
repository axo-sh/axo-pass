// Tests that need a software `ManagedKey` run on macOS only.
#![cfg_attr(not(target_os = "macos"), allow(unused_imports, dead_code))]

use std::cell::Cell;
use std::collections::BTreeMap;

use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    NAME, NewMac, folder, granted, key_file, peer, put_key_file, sender_keys, typed_key, vault,
    vector_code, wrapping,
};
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::SyncKey;
use crate::secrets::vaults::sync::local_state::{PinSource, PinnedKeys};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::pairing::PairingCode;
use crate::secrets::vaults::sync::pairing::request::PairingRequest;
use crate::secrets::vaults::sync::transport::RequestId;
use crate::secrets::vaults::sync::wrapping::{DeviceUnwrap, DeviceWrapping, PairingMac};

/// Unwrap that returns fixed bytes and counts its calls.
struct FixedUnwrap {
    raw: Vec<u8>,
    calls: Cell<usize>,
}

impl FixedUnwrap {
    fn new(key: &SyncKey) -> Self {
        Self {
            raw: key.as_bytes().to_vec(),
            calls: Cell::new(0),
        }
    }
}

impl DeviceUnwrap for FixedUnwrap {
    fn unwrap_sync_key(&self, _wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.calls.set(self.calls.get() + 1);
        Some(Zeroizing::new(self.raw.clone()))
    }
}

#[test]
fn planted_keys_without_hmac_rejected() {
    let key = vector_code().pair_key();
    let request = PairingRequest::new(
        RequestId(Uuid::from_u128(1)),
        BTreeMap::from([(vault(1), ReplicaId(Uuid::from_u128(2)))]),
        &sender_keys(),
        NAME.to_string(),
        &key,
    );
    let mut planted = request.clone();
    planted.encryption = PublicKey(vec![0x66; 65]);
    assert!(!planted.verify(&key));
    let mut planted = request.clone();
    planted.signing = PublicKey(vec![0x66; 65]);
    assert!(!planted.verify(&key));
    let other_code = PairingCode::from_bytes([9; 10]).pair_key();
    assert!(!request.verify(&other_code));

    let mac = NewMac::new();
    let transport = folder(&[vault(1)]);
    let mut pending = mac.start(&transport, &[]).unwrap();
    let sync_key = SyncKey::generate();
    let to_replica = pending.request().replicas[&vault(1)];
    let keys = pending.request().keys();
    let no_mac = wrapping(&sync_key, to_replica);
    let mut other_mac = wrapping(&sync_key, to_replica);
    other_code.seal_wrapping(&mut other_mac, vault(1), peer(1), &keys);
    let mut zero_mac = wrapping(&sync_key, to_replica);
    zero_mac.pairing_mac = Some(PairingMac([0; 32]));
    let mut planted_key = wrapping(&sync_key, to_replica);
    let planted_keys = ReplicaKeys {
        encryption: PublicKey(vec![0x66; 65]),
        signing: keys.signing.clone(),
    };
    typed_key(&pending).seal_wrapping(&mut planted_key, vault(1), peer(1), &planted_keys);
    put_key_file(
        &transport,
        vault(1),
        peer(1),
        vec![no_mac, other_mac, zero_mac, planted_key],
    );
    let unwrap = FixedUnwrap::new(&sync_key);
    assert!(pending.poll(&transport, &unwrap).is_empty());
    assert_eq!(
        unwrap.calls.get(),
        0,
        "no wrapping that fails its MAC is unwrapped"
    );
}

#[test]
fn wrapping_with_other_sender_keys_rejected() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1)]);
    let mut pending = mac.start(&transport, &[]).unwrap();
    let sync_key = SyncKey::generate();
    let mut encryption = granted(&pending, vault(1), peer(1), &sync_key);
    encryption.from_encryption = PublicKey(vec![0x66; 65]);
    let mut signing = granted(&pending, vault(1), peer(1), &sync_key);
    signing.from_signing = PublicKey(vec![0x66; 65]);
    put_key_file(&transport, vault(1), peer(1), vec![encryption, signing]);
    let unwrap = FixedUnwrap::new(&sync_key);
    assert!(pending.poll(&transport, &unwrap).is_empty());

    let moved = granted(&pending, vault(1), peer(1), &sync_key);
    put_key_file(&transport, vault(1), peer(2), vec![moved]);
    assert!(
        pending.poll(&transport, &unwrap).is_empty(),
        "a wrapping moved to another replica directory fails its MAC"
    );
    assert_eq!(unwrap.calls.get(), 0);
}

#[test]
fn wrapping_to_unknown_replica_rejected() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1), vault(2)]);
    let mut pending = mac.start(&transport, &[]).unwrap();
    let request = pending.request().clone();
    let key = typed_key(&pending);
    let sync_key = SyncKey::generate();
    let mut other = wrapping(&sync_key, ReplicaId(Uuid::from_u128(0x5555)));
    key.seal_wrapping(&mut other, vault(1), peer(1), &request.keys());
    let mut of_other_vault = wrapping(&sync_key, request.replicas[&vault(2)]);
    key.seal_wrapping(&mut of_other_vault, vault(1), peer(1), &request.keys());
    put_key_file(&transport, vault(1), peer(1), vec![other, of_other_vault]);
    let unwrap = FixedUnwrap::new(&sync_key);
    assert!(pending.poll(&transport, &unwrap).is_empty());
    assert_eq!(unwrap.calls.get(), 0);
}

#[test]
fn shifted_field_boundaries_fail_hmac() {
    let key = vector_code().pair_key();
    let request = PairingRequest::new(
        RequestId(Uuid::from_u128(1)),
        BTreeMap::from([(vault(1), ReplicaId(Uuid::from_u128(2)))]),
        &ReplicaKeys {
            encryption: PublicKey(vec![0xe1, 0xe2]),
            signing: PublicKey(vec![0x51, 0x52]),
        },
        "ac".to_string(),
        &key,
    );
    let mut shifted = request.clone();
    shifted.signing = PublicKey(vec![0x51]);
    shifted.name = "Rac".to_string();
    assert_eq!(
        [shifted.signing.0.as_slice(), shifted.name.as_bytes()].concat(),
        [request.signing.0.as_slice(), request.name.as_bytes()].concat()
    );
    assert!(!shifted.verify(&key));
    let mut shifted = request.clone();
    shifted.encryption = PublicKey(vec![0xe1, 0xe2, 0x51]);
    shifted.signing = PublicKey(vec![0x52]);
    assert!(!shifted.verify(&key));

    let keys = request.keys();
    let sync_key = SyncKey::generate();
    let mut wrapping = wrapping(&sync_key, ReplicaId(Uuid::from_u128(2)));
    key.seal_wrapping(&mut wrapping, vault(1), peer(1), &keys);
    let mut shifted = wrapping.clone();
    shifted.from_signing = PublicKey(shifted.from_signing.0[..64].to_vec());
    shifted.wrapped = [&wrapping.from_signing.0[64..], wrapping.wrapped.as_slice()].concat();
    assert!(!key.verify_wrapping(&shifted, vault(1), peer(1), &keys));
    let mut shifted = wrapping.clone();
    shifted.from_encryption = PublicKey([wrapping.from_encryption.0.as_slice(), &[0xb1]].concat());
    shifted.from_signing = PublicKey(wrapping.from_signing.0[1..].to_vec());
    assert!(!key.verify_wrapping(&shifted, vault(1), peer(1), &keys));
    let shifted_keys = ReplicaKeys {
        encryption: PublicKey(vec![0xe1]),
        signing: PublicKey(vec![0xe2, 0x51, 0x52]),
    };
    assert!(!key.verify_wrapping(&wrapping, vault(1), peer(1), &shifted_keys));
    assert!(key.verify_wrapping(&wrapping, vault(1), peer(1), &keys));
}

#[test]
fn changed_key_id_or_fingerprint_fails_hmac() {
    let key = vector_code().pair_key();
    let keys = sender_keys();
    let sync_key = SyncKey::generate();
    let mut wrapping = wrapping(&sync_key, ReplicaId(Uuid::from_u128(2)));
    key.seal_wrapping(&mut wrapping, vault(1), peer(1), &keys);
    assert!(key.verify_wrapping(&wrapping, vault(1), peer(1), &keys));
    let mut key_id = wrapping.clone();
    key_id.key_id = KeyId(2);
    assert!(!key.verify_wrapping(&key_id, vault(1), peer(1), &keys));
    let mut fingerprint = wrapping.clone();
    fingerprint.key_fingerprint.0[15] ^= 1;
    assert!(!key.verify_wrapping(&fingerprint, vault(1), peer(1), &keys));
    let mut wrapped = wrapping.clone();
    wrapped.wrapped[0] ^= 1;
    assert!(!key.verify_wrapping(&wrapped, vault(1), peer(1), &keys));
    assert!(!key.verify_wrapping(&wrapping, vault(2), peer(1), &keys));
}

#[test]
fn wrong_fingerprint_wrapping_refused() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1)]);
    let mut pending = mac.start(&transport, &[]).unwrap();
    let sync_key = SyncKey::generate();
    put_key_file(
        &transport,
        vault(1),
        peer(1),
        vec![granted(&pending, vault(1), peer(1), &sync_key)],
    );
    let other = FixedUnwrap::new(&SyncKey::generate());
    assert!(pending.poll(&transport, &other).is_empty());
    assert_eq!(other.calls.get(), 1);
    let short = FixedUnwrap {
        raw: vec![1; 31],
        calls: Cell::new(0),
    };
    assert!(pending.poll(&transport, &short).is_empty());

    let paired = pending.poll(&transport, &FixedUnwrap::new(&sync_key));
    assert_eq!(
        paired.len(),
        1,
        "the vault is not accepted until a key matches"
    );
}

#[test]
fn valid_wrapping_pins_sender_keys() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1), vault(2)]);
    let mut pending = mac.start(&transport, &[]).unwrap();
    let sync_key = SyncKey::generate();
    put_key_file(
        &transport,
        vault(1),
        peer(1),
        vec![granted(&pending, vault(1), peer(1), &sync_key)],
    );
    let unwrap = FixedUnwrap::new(&sync_key);
    let paired = pending.poll(&transport, &unwrap);
    assert_eq!(paired.len(), 1);
    let paired_vault = &paired[0];
    assert_eq!(paired_vault.vault_id, vault(1));
    assert_eq!(
        paired_vault.replica_id,
        pending.request().replicas[&vault(1)]
    );
    assert_eq!(paired_vault.key_id, KeyId(1));
    assert_eq!(paired_vault.key.as_bytes(), sync_key.as_bytes());
    assert_eq!(paired_vault.peer, peer(1));
    let from = sender_keys();
    assert_eq!(
        paired_vault.pin,
        PinnedKeys {
            source: PinSource::Pairing,
            encryption: from.encryption,
            signing: from.signing,
            revoked: false,
        }
    );
}

#[test]
fn accepted_vault_skipped_in_later_polls() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1), vault(2)]);
    let mut pending = mac.start(&transport, &[]).unwrap();
    let first = SyncKey::generate();
    put_key_file(
        &transport,
        vault(1),
        peer(1),
        vec![granted(&pending, vault(1), peer(1), &first)],
    );
    let unwrap = FixedUnwrap::new(&first);
    assert_eq!(pending.poll(&transport, &unwrap).len(), 1);
    let reads = transport.reads();
    assert!(pending.poll(&transport, &unwrap).is_empty());
    assert_eq!(
        transport.reads(),
        reads,
        "no key.json of an accepted vault is read"
    );
    assert_eq!(unwrap.calls.get(), 1);

    let second = SyncKey::generate();
    put_key_file(
        &transport,
        vault(2),
        peer(2),
        vec![granted(&pending, vault(2), peer(2), &second)],
    );
    let paired = pending.poll(&transport, &FixedUnwrap::new(&second));
    assert_eq!(paired.len(), 1);
    assert_eq!(paired[0].vault_id, vault(2));
}

#[test]
fn remote_key_json_read_again_in_next_poll() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1)]);
    let mut pending = mac.start(&transport, &[]).unwrap();
    let sync_key = SyncKey::generate();
    let bytes = key_file(vec![granted(&pending, vault(1), peer(1), &sync_key)]);
    transport.put_remote_with(vault(1), peer(1), "key.json", &bytes);
    let unwrap = FixedUnwrap::new(&sync_key);
    assert!(pending.poll(&transport, &unwrap).is_empty());
    assert_eq!(transport.reads(), 0);
    assert_eq!(transport.complete_downloads(vault(1)), 1);
    let paired = pending.poll(&transport, &unwrap);
    assert_eq!(paired.len(), 1);
    assert_eq!(paired[0].vault_id, vault(1));
}

#[test]
fn invalid_key_files_and_wrappings_of_other_kinds_skipped() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1)]);
    let mut pending = mac.start(&transport, &[]).unwrap();
    let sync_key = SyncKey::generate();
    transport.put(vault(1), peer(1), "key.json", b"not json");
    transport.put(
        vault(1),
        peer(2),
        "key.json",
        br#"{"version":2,"wrappings":[]}"#,
    );
    put_key_file(
        &transport,
        vault(1),
        peer(3),
        vec![granted(&pending, vault(1), peer(3), &sync_key)],
    );
    let paired = pending.poll(&transport, &FixedUnwrap::new(&sync_key));
    assert_eq!(paired.len(), 1);
    assert_eq!(paired[0].peer, peer(3));
}

#[cfg(target_os = "macos")]
#[test]
fn key_wrapped_to_software_key_of_new_mac_unwraps_through_poll() {
    let software = ManagedKey::create_software_for_test().unwrap();
    let mac = NewMac::with_public_keys(ReplicaKeys {
        encryption: PublicKey(software.public_key_sec1().unwrap()),
        signing: PublicKey(vec![0x51; 65]),
    });
    let transport = folder(&[vault(1)]);
    let mut pending = mac.start(&transport, &[]).unwrap();
    let request = pending.request().clone();
    let sync_key = SyncKey::generate();
    let mut wrapping = DeviceWrapping::wrap(
        KeyId(1),
        &sync_key,
        request.replicas[&vault(1)],
        &request.encryption,
        &sender_keys(),
    )
    .unwrap();
    typed_key(&pending).seal_wrapping(&mut wrapping, vault(1), peer(1), &request.keys());
    put_key_file(&transport, vault(1), peer(1), vec![wrapping]);
    let paired = pending.poll(&transport, &software);
    assert_eq!(paired.len(), 1);
    assert_eq!(paired[0].key.as_bytes(), sync_key.as_bytes());
}
