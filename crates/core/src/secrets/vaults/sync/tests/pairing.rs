//! Tests of the pairing code, the pairing request, the pairing HMACs, the
//! new Mac side of pairing, and the unlocked Mac side: the prompt, the code
//! match, the dismissed requests, and the grant, and the pairing watcher.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use jiff::{SignedDuration, Timestamp};
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::load::{Fixture, GENERATION, REPLICA, body, device_key, state};
use super::manager::{Event, Managed, folder_root, set_root};
use super::reads::put_peer;
use super::state_file::key;
use super::transport::FakeTransport;
use super::txn::{synced, two_keys, under_key_2};
use crate::audit::test_support::test_dir;
use crate::core::auth::AuthContext;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::VaultHandle;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::{UnlockedKey, Vault};
use crate::secrets::vaults::storage::device_keys::{DeviceKeys, KeyProbe, KeyState, VaultFiles};
use crate::secrets::vaults::storage::test_keys::TestKeys;
use crate::secrets::vaults::storage::txn::{Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::{KeyFingerprint, SyncKey};
use crate::secrets::vaults::sync::local_state::{LocalSyncState, PinSource, PinnedKeys};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::pairing::dismissed::DismissedRequests;
use crate::secrets::vaults::sync::pairing::grant::GrantOutcome;
use crate::secrets::vaults::sync::pairing::prompt::PairingPrompt;
use crate::secrets::vaults::sync::pairing::request::PairingRequest;
use crate::secrets::vaults::sync::pairing::watcher::{PAIRING_EXPIRY, POLL_INTERVAL};
use crate::secrets::vaults::sync::pairing::{PairKey, PairingCode, PendingPairing};
use crate::secrets::vaults::sync::pins::PairedPin;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::status::BUILD_ID;
use crate::secrets::vaults::sync::transport::{
    FileName, MAX_PAIRING_SIZE, ReadResult, RequestId, SyncTransport, TransportRoot,
};
use crate::secrets::vaults::sync::wrapping::{
    DeviceUnwrap, DeviceWrapping, KeyFile, PairingMac, Wrapping,
};

/// Name of the new Mac in the tests.
const NAME: &str = "New Mac";

/// Vault `n`.
fn vault(n: u128) -> Uuid {
    Uuid::from_u128(0x7000 + n)
}

/// Replica `n` of an unlocked Mac.
fn peer(n: u128) -> ReplicaId {
    ReplicaId(Uuid::from_u128(0x9000 + n))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Keys of the unlocked Mac that writes the wrappings.
fn sender_keys() -> ReplicaKeys {
    ReplicaKeys {
        encryption: PublicKey(vec![0xa1; 65]),
        signing: PublicKey(vec![0xb1; 65]),
    }
}

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

/// App data directory of the new Mac, in a temp directory.
struct NewMac {
    dir: TempDir,
    keys: TestKeys,
}

impl NewMac {
    /// Mac with no vault file and both keys present, whose public keys are
    /// `public`.
    fn with_public_keys(public: ReplicaKeys) -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            keys: TestKeys::both().with_public_keys(public),
        }
    }

    fn new() -> Self {
        Self::with_public_keys(ReplicaKeys {
            encryption: PublicKey(vec![0xe1; 65]),
            signing: PublicKey(vec![0x51; 65]),
        })
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn files(&self) -> VaultFiles {
        VaultFiles::new(self.root().join("vaults"), self.root(), Vec::new())
    }

    fn start(&self, transport: &FakeTransport, synced: &[Uuid]) -> Result<PendingPairing, Error> {
        PendingPairing::start(
            transport,
            &synced.iter().copied().collect(),
            &self.keys,
            &self.files(),
            AuthContext::OneTime,
            NAME,
        )
    }
}

/// Folder with a directory for each vault of `vaults`.
fn folder(vaults: &[Uuid]) -> FakeTransport {
    let transport = FakeTransport::default();
    for vault_id in vaults {
        transport.put_meta(*vault_id, b"{}");
    }
    transport
}

/// Pairing key that the unlocked Mac derives from the code the user typed.
fn typed_key(pending: &PendingPairing) -> PairKey {
    PairingCode::parse(&pending.code().shown())
        .unwrap()
        .pair_key()
}

/// Wrapping of `key` under key id 1 to `to_replica`, from the keys of
/// `sender_keys`, with no MAC. The wrapped bytes are not a ciphertext, so
/// the tests unwrap with [`FixedUnwrap`].
fn wrapping(key: &SyncKey, to_replica: ReplicaId) -> DeviceWrapping {
    let from = sender_keys();
    DeviceWrapping {
        key_id: KeyId(1),
        key_fingerprint: key.fingerprint(),
        to_replica,
        from_encryption: from.encryption,
        from_signing: from.signing,
        wrapped: vec![0xc1, 0xc2, 0xc3],
        pairing_mac: None,
        signature: None,
        removed: None,
        remaining: None,
    }
}

/// Wrapping of `key` to the replica of `vault_id` in the request of
/// `pending`, sealed with the typed code, as `from_replica` writes it.
fn granted(
    pending: &PendingPairing,
    vault_id: Uuid,
    from_replica: ReplicaId,
    key: &SyncKey,
) -> DeviceWrapping {
    let request = pending.request();
    let mut wrapping = wrapping(key, request.replicas[&vault_id]);
    typed_key(pending).seal_wrapping(&mut wrapping, vault_id, from_replica, &request.keys());
    wrapping
}

/// `key.json` bytes that hold `wrappings`.
fn key_file(wrappings: Vec<DeviceWrapping>) -> Vec<u8> {
    KeyFile {
        wrappings: wrappings.into_iter().map(Wrapping::Device).collect(),
        invalid: Vec::new(),
    }
    .to_bytes()
}

/// Put a `key.json` with `wrappings` in the directory of `from_replica`.
fn put_key_file(
    transport: &FakeTransport,
    vault_id: Uuid,
    from_replica: ReplicaId,
    wrappings: Vec<DeviceWrapping>,
) {
    transport.put(vault_id, from_replica, "key.json", &key_file(wrappings));
}

/// Code of the fixed vectors, the bytes 0 to 9.
fn vector_code() -> PairingCode {
    PairingCode::from_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
}

#[test]
fn code_is_shown_in_four_groups_of_four_crockford_characters() {
    // Bits of 00 01 .. 09 in groups of 5, read by hand with `xxd -b`.
    assert_eq!(vector_code().shown().as_str(), "000G-40R4-0M30-E209");
    let first = PairingCode::generate();
    let second = PairingCode::generate();
    assert_ne!(first.shown(), second.shown());
    for shown in [first.shown(), second.shown()] {
        let groups: Vec<&str> = shown.split('-').collect();
        assert_eq!(groups.len(), 4, "{}", shown.as_str());
        for group in groups {
            assert_eq!(group.len(), 4);
            assert!(
                group
                    .chars()
                    .all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c))
            );
        }
    }
    assert_eq!(format!("{first:?}"), "PairingCode(..)");
    assert_eq!(format!("{:?}", first.pair_key()), "PairKey(..)");
}

#[test]
fn code_reads_back_from_its_shown_form_lowercase_and_with_confusable_letters() {
    let code = PairingCode::generate();
    let key = code.pair_key();
    let shown = code.shown();
    let lowercase = shown.to_lowercase();
    let confusable = shown.replace('0', "o").replace('1', "l");
    let spaced = shown.replace('-', " ");
    let bare = shown.replace('-', "");
    for text in [
        shown.as_str(),
        lowercase.as_str(),
        confusable.as_str(),
        spaced.as_str(),
        bare.as_str(),
    ] {
        let typed = PairingCode::parse(text).unwrap();
        assert_eq!(typed.pair_key().as_bytes(), key.as_bytes(), "{text}");
    }
    let vector = PairingCode::parse("ooog-4oR4-oM3o-E2o9").unwrap();
    assert_eq!(vector.shown(), vector_code().shown());
    let vector = PairingCode::parse("000g 40r4 0m30 e209").unwrap();
    assert_eq!(vector.shown(), vector_code().shown());
}

#[test]
fn code_of_other_length_or_outside_alphabet_is_refused() {
    for text in [
        "",
        "000G-40R4-0M30-E20",
        "000G-40R4-0M30-E2099",
        "000G-40R4-0M30-E20U",
        "000G-40R4-0M30-E20!",
        "000G_40R4_0M30_E209",
    ] {
        assert!(PairingCode::parse(text).is_none(), "{text}");
    }
}

#[test]
fn request_and_wrapping_hmacs_match_fixed_vectors() {
    // Vectors computed with OpenSSL, not with the code under test:
    //   openssl kdf -keylen 32 -kdfopt digest:SHA256 \
    //     -kdfopt hexkey:00010203040506070809 -kdfopt info:ap-pairing-v1 HKDF
    //   P=11e59615bf912ee3513439b91d4ecbe65406a123cea68713073cb8acba7648b3
    //   echo -n $REQUEST | xxd -r -p | openssl mac -digest SHA256 \
    //     -macopt hexkey:$P HMAC
    //   echo -n $WRAPPING | xxd -r -p | openssl mac -digest SHA256 \
    //     -macopt hexkey:$P HMAC
    // $REQUEST and $WRAPPING are the hex inputs asserted below. Each field is
    // its 4-byte big-endian length and its bytes. Ids are their 16 UUID
    // bytes, and the key id is 4 big-endian bytes.
    let key = vector_code().pair_key();
    assert_eq!(
        hex(key.as_bytes()),
        "11e59615bf912ee3513439b91d4ecbe65406a123cea68713073cb8acba7648b3"
    );

    let keys = ReplicaKeys {
        encryption: PublicKey(vec![0xe1, 0xe2]),
        signing: PublicKey(vec![0x51, 0x52]),
    };
    let replicas = BTreeMap::from([
        (Uuid::from_u128(0x11), ReplicaId(Uuid::from_u128(0x21))),
        (Uuid::from_u128(0x10), ReplicaId(Uuid::from_u128(0x20))),
    ]);
    let request = PairingRequest::new(
        RequestId(Uuid::from_u128(1)),
        replicas,
        &keys,
        "Mac".to_string(),
        &key,
    );
    let request_input = concat!(
        "00000010",
        "00000000000000000000000000000001",
        "00000002",
        "00000010",
        "00000000000000000000000000000010",
        "00000010",
        "00000000000000000000000000000020",
        "00000010",
        "00000000000000000000000000000011",
        "00000010",
        "00000000000000000000000000000021",
        "00000002e1e2",
        "000000025152",
        "000000034d6163",
    );
    assert_eq!(hex(&request.mac_input()), request_input);
    assert_eq!(
        hex(&request.mac.0),
        "872619dd18a6b24ce99fbca06f5d01c9229d0f35d6f7aa4c35b6bf0ef04bcb7c"
    );
    assert!(request.verify(&key));

    let mut wrapping = DeviceWrapping {
        key_id: KeyId(1),
        key_fingerprint: KeyFingerprint(core::array::from_fn(|i| 0xf0 + i as u8)),
        to_replica: ReplicaId(Uuid::from_u128(0x20)),
        from_encryption: PublicKey(vec![0xa1, 0xa2]),
        from_signing: PublicKey(vec![0xb1, 0xb2]),
        wrapped: vec![0xc1, 0xc2, 0xc3],
        pairing_mac: None,
        signature: None,
        removed: None,
        remaining: None,
    };
    let vault_id = Uuid::from_u128(0x10);
    let from_replica = ReplicaId(Uuid::from_u128(0x30));
    let wrapping_input = concat!(
        "00000010",
        "00000000000000000000000000000010",
        "00000010",
        "00000000000000000000000000000030",
        "00000010",
        "00000000000000000000000000000020",
        "00000004",
        "00000001",
        "00000010",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "00000002e1e2",
        "000000025152",
        "00000002a1a2",
        "00000002b1b2",
        "00000003c1c2c3",
    );
    assert_eq!(
        hex(&wrapping.pairing_input(vault_id, from_replica, &keys)),
        wrapping_input
    );
    key.seal_wrapping(&mut wrapping, vault_id, from_replica, &keys);
    assert_eq!(
        hex(&wrapping.pairing_mac.unwrap().0),
        "81a5773ca6b7042bfd79d32500bf11b4723e6b58e45cbaa8a1c4dcb6cb1e802e"
    );
    assert!(key.verify_wrapping(&wrapping, vault_id, from_replica, &keys));
}

#[test]
fn pairing_request_round_trips_and_refuses_unknown_field() {
    let key = vector_code().pair_key();
    let request = PairingRequest::new(
        RequestId(Uuid::from_u128(1)),
        BTreeMap::from([(vault(1), ReplicaId(Uuid::from_u128(2)))]),
        &sender_keys(),
        NAME.to_string(),
        &key,
    );
    let parsed = PairingRequest::parse(&request.to_bytes()).unwrap();
    assert_eq!(parsed, request);
    assert!(parsed.verify(&key));

    let mut value: serde_json::Value = serde_json::from_slice(&request.to_bytes()).unwrap();
    value["extra"] = serde_json::json!(1);
    assert!(PairingRequest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(PairingRequest::parse(b"{}").is_err());
}

#[test]
fn planted_public_key_and_device_wrapping_without_valid_hmac_are_rejected() {
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
fn pairing_wrapping_whose_sender_keys_differ_from_the_ones_the_hmac_covers_is_rejected() {
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
fn pairing_wrapping_whose_to_replica_is_not_in_the_request_map_is_rejected() {
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
fn request_or_wrapping_whose_field_boundaries_are_shifted_fails_its_hmac() {
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
fn wrapping_with_changed_key_id_or_key_fingerprint_fails_its_hmac() {
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
fn wrapping_whose_unwrapped_key_has_another_fingerprint_is_refused() {
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
fn valid_wrapping_gives_paired_vault_with_pairing_pin_of_sender_keys() {
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
fn accepted_vault_is_skipped_in_later_polls() {
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
fn remote_key_json_is_read_again_in_the_next_poll() {
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
fn invalid_key_files_and_wrappings_of_other_kinds_are_skipped() {
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

#[test]
fn start_writes_request_that_verifies_under_the_code_with_keys_and_name_of_new_mac() {
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
fn start_on_mac_with_no_keys_and_no_vault_files_creates_both_keys() {
    let mut mac = NewMac::new();
    mac.keys = TestKeys::neither();
    let transport = folder(&[vault(1)]);
    let pending = mac.start(&transport, &[]).unwrap();
    assert_eq!(mac.keys.created(), 2);
    assert_eq!(mac.keys.probe_encryption_key(), KeyProbe::Present);
    assert!(transport.pairing(pending.request().request_id).is_some());
}

#[test]
fn start_on_new_hardware_moves_files_first_and_leaves_out_no_vault() {
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
fn vault_this_mac_syncs_is_not_in_the_request_map() {
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
fn finish_deletes_the_request() {
    let mac = NewMac::new();
    let transport = folder(&[vault(1)]);
    let pending = mac.start(&transport, &[]).unwrap();
    let request_id = pending.request().request_id;
    assert!(transport.pairing(request_id).is_some());
    pending.finish(&transport).unwrap();
    assert!(transport.pairing(request_id).is_none());
    assert!(transport.list_pairings().unwrap().is_empty());
}

// Unlocked Mac side (7.9).

/// Root of the synced folder on the unlocked Mac.
fn grant_root() -> TransportRoot {
    TransportRoot::Folder {
        path: PathBuf::from("/pairing/Vaults"),
    }
}

/// Another root on the unlocked Mac.
fn other_root() -> TransportRoot {
    TransportRoot::Folder {
        path: PathBuf::from("/other/Vaults"),
    }
}

/// Time the requests of the prompt tests are written.
fn written_at() -> Timestamp {
    Timestamp::from_second(1_800_000_000).unwrap()
}

/// Write a sidecar with the root `root` for vault `vault_id` under the app
/// data directory `app_root`.
fn put_root(app_root: &Path, vault_id: Uuid, root: &TransportRoot) {
    let sidecar = Sidecar {
        transport: Some(root.clone()),
        ..Sidecar::default()
    };
    sidecar.save(app_root, vault_id).unwrap();
}

/// Request of a new Mac with the keys `keys` for `vaults`, with one new
/// replica id each, under the pairing key of `code`.
fn request_with(code: &PairingCode, vaults: &[Uuid], keys: &ReplicaKeys) -> PairingRequest {
    PairingRequest::new(
        RequestId::generate(),
        vaults.iter().map(|v| (*v, ReplicaId::generate())).collect(),
        keys,
        NAME.to_string(),
        &code.pair_key(),
    )
}

/// [`request_with`] with fixed keys that are not P-256 points, for the
/// prompt tests, which wrap no key.
fn request_of(code: &PairingCode, vaults: &[Uuid]) -> PairingRequest {
    request_with(
        code,
        vaults,
        &ReplicaKeys {
            encryption: PublicKey(vec![0xe1; 65]),
            signing: PublicKey(vec![0x51; 65]),
        },
    )
}

/// Put `request` in the pairing directory under its own id.
fn put_request(transport: &FakeTransport, request: &PairingRequest) {
    transport.put_pairing(request.request_id, &request.to_bytes());
}

/// Software encryption key of a new Mac and its public keys.
fn new_mac_keys() -> (ManagedKey, ReplicaKeys) {
    let software = ManagedKey::create_software_for_test().unwrap();
    let keys = ReplicaKeys {
        encryption: PublicKey(software.public_key_sec1().unwrap()),
        signing: PublicKey(vec![0x51; 65]),
    };
    (software, keys)
}

/// Keys of [`REPLICA`] in the sync states of the tests, as the new Mac pins
/// them.
fn unlocked_mac_keys() -> ReplicaKeys {
    ReplicaKeys {
        encryption: PublicKey(vec![4, 1]),
        signing: PublicKey(device_key()),
    }
}

/// `pairing` pin of `keys`.
fn pairing_pin(keys: &ReplicaKeys) -> PinnedKeys {
    PinnedKeys {
        source: PinSource::Pairing,
        encryption: keys.encryption.clone(),
        signing: keys.signing.clone(),
        revoked: false,
    }
}

/// Synced vault of [`REPLICA`] with a trusted sync state, synced through
/// `transport` at [`grant_root`].
fn granting(transport: &Arc<FakeTransport>) -> Fixture {
    let fx = synced(transport);
    put_root(&fx.root, fx.id(), &grant_root());
    fx
}

/// Grant `request`, matched with `code`, to the vault of `fx`.
fn grant(fx: &Fixture, request: &PairingRequest, code: &PairingCode) -> GrantOutcome {
    let key = || fx.vault.unlocked_key().unwrap();
    fx.catalog.files().grant_pairing(
        &Target::of(&fx.vault),
        Unlock::Test(&key),
        request,
        code,
        &grant_root(),
    )
}

/// Own `key.json` of `replica` in vault `vault_id`, if any.
fn own_key_file(transport: &FakeTransport, vault_id: Uuid, replica: ReplicaId) -> Option<KeyFile> {
    match transport.read(vault_id, replica, FileName::Key).unwrap() {
        ReadResult::Local(bytes) => Some(KeyFile::parse(&bytes).unwrap()),
        _ => None,
    }
}

/// Sync state of `fx` as saved.
fn saved_local(fx: &Fixture) -> LocalSyncState {
    LocalSyncState::load(&fx.root, fx.id(), &TestSigner::device()).unwrap()
}

/// Model of the app unlock of the unlocked Mac. The first key read prompts
/// and authenticates the shared context. Later reads on that context draw
/// no prompt, as `Unlock::App` reads on it.
#[derive(Default)]
struct TestAuth {
    authenticated: AtomicBool,
    prompts: AtomicUsize,
    reads: AtomicUsize,
}

impl TestAuth {
    /// File key of `vh`, read on the shared context.
    fn read(&self, vh: &VaultHandle) -> UnlockedKey {
        if !self.authenticated.swap(true, Ordering::SeqCst) {
            self.prompts.fetch_add(1, Ordering::SeqCst);
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        vh.unlocked_key().unwrap()
    }
}

/// Unlocked Mac with synced vaults in one app data directory, each synced
/// through one transport at [`grant_root`]. Vault `n` is synced as replica
/// `peer(n)`, and its directory has a `meta.json` in the folder.
struct UnlockedMac {
    _dir: TempDir,
    root: PathBuf,
    writer: VaultWriter,
    vaults: Vec<VaultHandle>,
}

impl UnlockedMac {
    fn new(transport: &Arc<FakeTransport>, count: u128) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let vaults_dir = dir.path().join("vaults");
        let writer = VaultWriter::isolated(&root).with_transport(transport.clone());
        let vaults = (1..=count)
            .map(|n| {
                let mut vault = Vault::new_for_test();
                vault.set_sync(GENERATION, Some(peer(n).0));
                let vh = VaultHandle::new_in(&vaults_dir, vault);
                writer.create(&vh).unwrap();
                let id = vh.vault_id().unwrap();
                state(id, peer(n), GENERATION)
                    .save(&root, &TestSigner::device())
                    .unwrap();
                put_root(&root, id, &grant_root());
                transport.put_meta(id, b"{}");
                vh
            })
            .collect();
        Self {
            _dir: dir,
            root,
            writer,
            vaults,
        }
    }

    /// Id of vault `n`, from 1.
    fn id(&self, n: usize) -> Uuid {
        self.vaults[n - 1].vault_id().unwrap()
    }

    fn local(&self, n: usize) -> LocalSyncState {
        LocalSyncState::load(&self.root, self.id(n), &TestSigner::device()).unwrap()
    }
}

#[test]
fn one_request_with_one_code_adds_new_mac_to_every_picked_vault_with_one_prompt() {
    let transport = Arc::new(FakeTransport::default());
    transport.set_now(written_at());
    let unlocked = UnlockedMac::new(&transport, 3);
    let (software, keys) = new_mac_keys();
    let new_mac = NewMac::with_public_keys(keys.clone());
    let mut pending = new_mac.start(&transport, &[]).unwrap();
    let request = pending.request().clone();
    let replica_ids: BTreeSet<ReplicaId> = request.replicas.values().copied().collect();
    assert_eq!(replica_ids.len(), 3, "one replica id per vault");

    // The unlocked Mac sees one request and matches the typed code.
    let now = written_at() + SignedDuration::from_mins(5);
    assert_eq!(
        PairingPrompt::pending(&*transport, &BTreeSet::new(), now).unwrap(),
        1
    );
    let typed = PairingCode::parse(&pending.code().shown()).unwrap();
    let matched = PairingPrompt::match_code(&*transport, &typed)
        .unwrap()
        .unwrap();
    assert_eq!(matched, request);
    assert_eq!(matched.name, NAME);
    let mut listed = PairingPrompt::vaults(&unlocked.root, &grant_root(), &matched);
    listed.sort();
    let mut all = vec![unlocked.id(1), unlocked.id(2), unlocked.id(3)];
    all.sort();
    assert_eq!(listed, all);

    // The user picks vaults 1 and 3. The app unlocks once.
    let auth = &TestAuth::default();
    let keys_of: Vec<Box<dyn Fn() -> UnlockedKey + Sync + '_>> = unlocked
        .vaults
        .iter()
        .map(|vh| Box::new(move || auth.read(vh)) as Box<dyn Fn() -> UnlockedKey + Sync>)
        .collect();
    let unlock = |target: &Target| {
        let n = unlocked
            .vaults
            .iter()
            .position(|vh| vh.path == target.path)
            .unwrap();
        Unlock::Test(&*keys_of[n])
    };
    let picks = vec![
        (unlocked.id(1), Target::of(&unlocked.vaults[0])),
        (unlocked.id(3), Target::of(&unlocked.vaults[2])),
    ];
    let outcomes = unlocked
        .writer
        .grant_pairings(&picks, unlock, &matched, &typed, &grant_root());

    assert_eq!(outcomes.len(), 2);
    for (vault_id, outcome) in &outcomes {
        assert!(
            matches!(outcome, GrantOutcome::Granted(PairedPin::New)),
            "{vault_id}: {outcome:?}"
        );
    }
    assert_eq!(auth.prompts.load(Ordering::SeqCst), 1);
    assert_eq!(
        auth.reads.load(Ordering::SeqCst),
        2,
        "one key read per picked vault and none for the grant"
    );

    // Each picked vault holds one wrapping in the own key.json of the
    // unlocked Mac, and pins the new Mac with `pairing`. The vault the user
    // did not pick receives no wrapping and no pin.
    for (n, replica) in [(1, peer(1)), (3, peer(3))] {
        let file = own_key_file(&transport, unlocked.id(n), replica).unwrap();
        let devices: Vec<_> = file.devices().collect();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].to_replica, request.replicas[&unlocked.id(n)]);
        let local = unlocked.local(n);
        assert_eq!(local.generation, GENERATION, "the pin keeps s");
        assert_eq!(
            local.pinned_keys[&request.replicas[&unlocked.id(n)]],
            pairing_pin(&keys)
        );
    }
    assert!(own_key_file(&transport, unlocked.id(2), peer(2)).is_none());
    assert!(
        !unlocked
            .local(2)
            .pinned_keys
            .contains_key(&request.replicas[&unlocked.id(2)])
    );

    // The new Mac receives both keys with one unwrap key, and pins the keys
    // of the unlocked Mac from each wrapping.
    let paired = pending.poll(&*transport, &software);
    let mut received: Vec<Uuid> = paired.iter().map(|vault| vault.vault_id).collect();
    received.sort();
    let mut picked = vec![unlocked.id(1), unlocked.id(3)];
    picked.sort();
    assert_eq!(received, picked);
    for vault in &paired {
        assert_eq!(vault.replica_id, request.replicas[&vault.vault_id]);
        assert_eq!(vault.key_id, KeyId(1));
        assert_eq!(vault.key.as_bytes(), key().as_bytes());
        assert_eq!(vault.pin, pairing_pin(&unlocked_mac_keys()));
    }
    assert!(pending.poll(&*transport, &software).is_empty());
}

#[test]
fn request_whose_signing_key_or_replica_map_differs_from_the_one_the_hmac_covers_is_rejected() {
    let transport = FakeTransport::default();
    let code = PairingCode::generate();
    let request = request_of(&code, &[vault(1), vault(2)]);
    let mut signing = request.clone();
    signing.signing = PublicKey(vec![0x66; 65]);
    let mut replica = request.clone();
    replica.replicas.insert(vault(1), ReplicaId::generate());
    let mut added = request.clone();
    added.replicas.insert(vault(3), ReplicaId::generate());
    let mut removed = request.clone();
    removed.replicas.remove(&vault(2));

    for planted in [signing, replica, added, removed] {
        put_request(&transport, &planted);
        assert_eq!(
            PairingPrompt::match_code(&transport, &code).unwrap(),
            None,
            "{planted:?}"
        );
    }
    put_request(&transport, &request);
    assert_eq!(
        PairingPrompt::match_code(&transport, &code).unwrap(),
        Some(request)
    );
}

#[test]
fn prompt_shows_count_and_no_name_and_name_shows_only_for_request_that_verifies_under_code() {
    let transport = FakeTransport::default();
    transport.set_now(written_at());
    let code = PairingCode::generate();
    let request = request_of(&code, &[vault(1)]);
    put_request(&transport, &request);
    put_request(
        &transport,
        &request_of(&PairingCode::generate(), &[vault(1)]),
    );

    let now = written_at() + SignedDuration::from_mins(5);
    let count = PairingPrompt::pending(&transport, &BTreeSet::new(), now).unwrap();

    assert_eq!(count, 2);
    assert_eq!(transport.pairing_reads(), 0, "the count reads no request");
    let other = PairingCode::generate();
    assert_eq!(PairingPrompt::match_code(&transport, &other).unwrap(), None);
    let matched = PairingPrompt::match_code(&transport, &code)
        .unwrap()
        .unwrap();
    assert_eq!(matched.name, NAME);
    assert_eq!(matched.request_id, request.request_id);
}

#[test]
fn real_request_matches_its_code_with_200_planted_requests_newer_than_it() {
    let transport = FakeTransport::default();
    transport.set_now(written_at());
    let code = PairingCode::generate();
    let request = request_of(&code, &[vault(1)]);
    put_request(&transport, &request);
    transport.set_now(written_at() + SignedDuration::from_hours(1));
    for n in 0..200 {
        if n % 2 == 0 {
            put_request(
                &transport,
                &request_of(&PairingCode::generate(), &[vault(1)]),
            );
        } else {
            transport.put_pairing(RequestId::generate(), b"{}");
        }
    }

    let now = written_at() + SignedDuration::from_hours(2);
    assert_eq!(
        PairingPrompt::pending(&transport, &BTreeSet::new(), now).unwrap(),
        201
    );
    assert_eq!(
        PairingPrompt::match_code(&transport, &code).unwrap(),
        Some(request)
    );
}

#[test]
fn request_that_fails_the_hmac_is_never_shown_and_is_not_deleted() {
    let transport = FakeTransport::default();
    let code = PairingCode::generate();
    let planted = request_of(&PairingCode::generate(), &[vault(1)]);
    put_request(&transport, &planted);

    assert_eq!(PairingPrompt::match_code(&transport, &code).unwrap(), None);
    assert!(transport.pairing(planted.request_id).is_some());

    // A mistyped code deletes no real request either.
    let request = request_of(&code, &[vault(1)]);
    put_request(&transport, &request);
    let mistyped = PairingCode::generate();
    assert_eq!(
        PairingPrompt::match_code(&transport, &mistyped).unwrap(),
        None
    );
    assert_eq!(transport.list_pairings().unwrap().len(), 2);
    assert_eq!(
        PairingPrompt::match_code(&transport, &code).unwrap(),
        Some(request)
    );
}

#[test]
fn dismissed_request_does_not_prompt_again_new_id_does_and_request_older_than_24_hours_does_not() {
    let app = tempfile::tempdir().unwrap();
    let transport = FakeTransport::default();
    transport.set_now(written_at());
    let first_code = PairingCode::generate();
    let first = request_of(&first_code, &[vault(1)]);
    put_request(&transport, &first);
    let now = written_at() + SignedDuration::from_hours(1);
    let pending = || {
        let dismissed = DismissedRequests::load(app.path()).of(&grant_root());
        PairingPrompt::pending(&transport, &dismissed, now).unwrap()
    };
    assert_eq!(pending(), 1);

    PairingPrompt::dismiss(&transport, &grant_root(), app.path()).unwrap();

    assert_eq!(pending(), 0);
    let second = request_of(&PairingCode::generate(), &[vault(1)]);
    put_request(&transport, &second);
    assert_eq!(pending(), 1, "a request with a new id prompts");

    let old_code = PairingCode::generate();
    let old = request_of(&old_code, &[vault(1)]);
    put_request(&transport, &old);
    transport.set_pairing_modified(
        old.request_id,
        now - SignedDuration::from_hours(24) - SignedDuration::from_secs(1),
    );
    assert_eq!(
        pending(),
        1,
        "a request older than 24 hours does not prompt"
    );
    transport.set_pairing_modified(old.request_id, now - SignedDuration::from_hours(24));
    assert_eq!(pending(), 2, "a request of exactly 24 hours prompts");

    // The code check covers dismissed and old requests.
    assert_eq!(
        PairingPrompt::match_code(&transport, &first_code).unwrap(),
        Some(first)
    );
    transport.set_pairing_modified(
        old.request_id,
        written_at() - SignedDuration::from_hours(48),
    );
    assert_eq!(
        PairingPrompt::match_code(&transport, &old_code).unwrap(),
        Some(old)
    );
}

#[test]
fn request_file_larger_than_16_kb_is_not_read() {
    let transport = FakeTransport::default();
    transport.set_now(written_at());
    let code = PairingCode::generate();
    let request = request_of(&code, &[vault(1)]);
    put_request(&transport, &request);
    let now = written_at();

    transport.set_pairing_size(request.request_id, MAX_PAIRING_SIZE + 1);

    assert_eq!(
        PairingPrompt::pending(&transport, &BTreeSet::new(), now).unwrap(),
        0
    );
    assert_eq!(PairingPrompt::match_code(&transport, &code).unwrap(), None);
    assert_eq!(transport.pairing_reads(), 0);

    transport.set_pairing_size(request.request_id, MAX_PAIRING_SIZE);
    assert_eq!(
        PairingPrompt::pending(&transport, &BTreeSet::new(), now).unwrap(),
        1
    );
    assert_eq!(
        PairingPrompt::match_code(&transport, &code).unwrap(),
        Some(request)
    );
}

#[test]
fn request_whose_request_id_differs_from_its_file_name_is_refused() {
    let transport = FakeTransport::default();
    let code = PairingCode::generate();
    let request = request_of(&code, &[vault(1)]);
    transport.put_pairing(RequestId::generate(), &request.to_bytes());

    assert_eq!(PairingPrompt::match_code(&transport, &code).unwrap(), None);

    put_request(&transport, &request);
    assert_eq!(
        PairingPrompt::match_code(&transport, &code).unwrap(),
        Some(request)
    );
}

#[test]
fn dismissed_ids_are_kept_by_root_and_unreadable_file_reads_as_empty() {
    let app = tempfile::tempdir().unwrap();
    let first = RequestId::generate();
    let second = RequestId::generate();
    let mut dismissed = DismissedRequests::default();
    dismissed.set(&grant_root(), BTreeSet::from([first]));
    dismissed.set(&other_root(), BTreeSet::from([second]));
    dismissed.save(app.path()).unwrap();

    let path = DismissedRequests::path(app.path());
    assert_eq!(path, app.path().join("sync").join("pairing.json"));
    let json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(json["roots"][0]["root"]["kind"], "Folder");
    assert_eq!(json["roots"][0]["root"]["path"], "/pairing/Vaults");
    assert_eq!(
        json["roots"][0]["requests"][0],
        first.0.hyphenated().to_string()
    );
    let loaded = DismissedRequests::load(app.path());
    assert_eq!(loaded, dismissed);
    assert_eq!(loaded.of(&grant_root()), BTreeSet::from([first]));
    assert_eq!(loaded.of(&other_root()), BTreeSet::from([second]));
    assert!(loaded.of(&TransportRoot::ICloud {}).is_empty());

    let mut cleared = loaded.clone();
    cleared.set(&grant_root(), BTreeSet::new());
    assert!(cleared.of(&grant_root()).is_empty());
    assert_eq!(cleared.of(&other_root()), BTreeSet::from([second]));

    fs::write(&path, b"{\"roots\": 1}").unwrap();
    assert_eq!(
        DismissedRequests::load(app.path()),
        DismissedRequests::default()
    );
}

#[test]
fn dismissal_file_alone_is_not_a_vault_file() {
    let app = tempfile::tempdir().unwrap();
    let mut dismissed = DismissedRequests::default();
    dismissed.set(&grant_root(), BTreeSet::from([RequestId::generate()]));
    dismissed.save(app.path()).unwrap();
    let files = VaultFiles::new(app.path().join("vaults"), app.path(), Vec::new());

    assert!(!files.present());
    assert_eq!(
        KeyState::probe(&TestKeys::neither(), &files),
        KeyState::NoVaultFiles
    );

    put_root(app.path(), vault(1), &grant_root());
    assert!(files.present(), "a sidecar is a vault file");
}

#[test]
fn vault_list_holds_synced_vaults_of_this_root_in_the_request_map() {
    let transport = Arc::new(FakeTransport::default());
    let unlocked = UnlockedMac::new(&transport, 3);
    put_root(&unlocked.root, unlocked.id(3), &other_root());
    let code = PairingCode::generate();
    let request = request_of(
        &code,
        &[unlocked.id(1), unlocked.id(2), unlocked.id(3), vault(9)],
    );
    let only_two = request_of(&code, &[unlocked.id(2)]);

    let mut listed = PairingPrompt::vaults(&unlocked.root, &grant_root(), &request);
    listed.sort();

    let mut expected = vec![unlocked.id(1), unlocked.id(2)];
    expected.sort();
    assert_eq!(listed, expected);
    assert_eq!(
        PairingPrompt::vaults(&unlocked.root, &grant_root(), &only_two),
        vec![unlocked.id(2)]
    );
    assert_eq!(
        PairingPrompt::vaults(&unlocked.root, &other_root(), &request),
        vec![unlocked.id(3)]
    );
}

#[test]
fn wrapping_is_under_current_key_id_and_other_wrappings_are_written_back_unchanged() {
    let transport = Arc::new(FakeTransport::default());
    let fx = granting(&transport);
    fx.put_text(&under_key_2(
        &fx,
        &body(REPLICA, &[device_key()]),
        &two_keys(),
    ));
    let unknown = r#"{"kind":"Passkey","key_id":1,"credential":"abc"}"#;
    let existing = format!(
        r#"{{"version":1,"wrappings":[{{"kind":"Age","key_id":1,"key_fingerprint":"EREREREREREREREREREREQ==","recipient":"age1example","wrapped":"armored"}},{unknown},{{"kind":"Device","key_id":1,"key_fingerprint":"EREREREREREREREREREREQ==","to_replica":"00000000-0000-0000-0000-00000000002a","from_encryption":"BAQE","from_signing":"BQUF","wrapped":"BwcH"}}]}}"#
    );
    transport.put(fx.id(), REPLICA, "key.json", existing.as_bytes());
    let before = KeyFile::parse(existing.as_bytes()).unwrap();
    let code = PairingCode::generate();
    let (software, keys) = new_mac_keys();
    let request = request_with(&code, &[fx.id()], &keys);

    let outcome = grant(&fx, &request, &code);

    assert!(
        matches!(outcome, GrantOutcome::Granted(PairedPin::New)),
        "{outcome:?}"
    );
    let ReadResult::Local(bytes) = transport.read(fx.id(), REPLICA, FileName::Key).unwrap() else {
        panic!("own key.json is missing");
    };
    assert!(String::from_utf8(bytes.clone()).unwrap().contains(unknown));
    let after = KeyFile::parse(&bytes).unwrap();
    assert_eq!(after.wrappings.len(), 4);
    assert_eq!(after.wrappings[..3], before.wrappings[..]);
    let Wrapping::Device(wrapping) = &after.wrappings[3] else {
        panic!("last wrapping is not a Device wrapping");
    };
    let current = SyncKey::from_bytes([3; 32]);
    assert_eq!(wrapping.key_id, KeyId(2));
    assert_eq!(wrapping.key_fingerprint, current.fingerprint());
    assert_eq!(wrapping.to_replica, request.replicas[&fx.id()]);
    assert_eq!(wrapping.from_encryption, unlocked_mac_keys().encryption);
    assert_eq!(wrapping.from_signing, unlocked_mac_keys().signing);
    assert!(
        code.pair_key()
            .verify_wrapping(wrapping, fx.id(), REPLICA, &keys)
    );
    assert_eq!(
        wrapping.unwrap(&software).unwrap().as_bytes(),
        current.as_bytes()
    );
}

#[test]
fn failed_sync_state_save_writes_no_wrapping() {
    let transport = Arc::new(FakeTransport::default());
    let fx = granting(&transport);
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    let request = request_with(&code, &[fx.id()], &keys);
    let before = fx.on_disk();
    // A directory at the temp path of the sync state makes its save fail.
    let state_path = fx.state_path();
    let name = state_path.file_name().unwrap().to_str().unwrap();
    let blocker = state_path.with_file_name(format!(".{name}.tmp"));
    fs::create_dir(&blocker).unwrap();

    let outcome = grant(&fx, &request, &code);

    assert!(
        matches!(outcome, GrantOutcome::Failed(Error::SyncStateWriteError(_))),
        "{outcome:?}"
    );
    assert!(own_key_file(&transport, fx.id(), REPLICA).is_none());
    assert_eq!(fx.on_disk(), before);
    fs::remove_dir(&blocker).unwrap();
    assert!(saved_local(&fx).pinned_keys.is_empty());
}

/// Write the sync state of a test case for the vault of a fixture.
type PutState = fn(&Fixture);

#[test]
fn vault_whose_sync_state_is_not_trusted_receives_no_wrapping() {
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    let cases: [(&str, PutState); 4] = [
        ("missing", |_| {}),
        ("other signer", |fx| {
            fx.put(&state(fx.id(), REPLICA, GENERATION), &TestSigner::random())
        }),
        ("stopped", |fx| {
            let mut local = state(fx.id(), REPLICA, GENERATION);
            local.stopped_build = Some(BUILD_ID.to_string());
            fx.put(&local, &TestSigner::device());
        }),
        ("leaving", |fx| {
            let mut local = state(fx.id(), REPLICA, GENERATION);
            local.leaving = true;
            fx.put(&local, &TestSigner::device());
        }),
    ];
    for (name, put_state) in cases {
        let transport = Arc::new(FakeTransport::default());
        let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
        put_root(&fx.root, fx.id(), &grant_root());
        put_state(&fx);
        let request = request_with(&code, &[fx.id()], &keys);
        let before = fx.on_disk();

        let outcome = grant(&fx, &request, &code);

        assert!(
            matches!(outcome, GrantOutcome::NotTrusted(_)),
            "{name}: {outcome:?}"
        );
        assert!(
            own_key_file(&transport, fx.id(), REPLICA).is_none(),
            "{name}"
        );
        assert_eq!(fx.on_disk(), before, "{name}");
    }
}

#[test]
fn request_whose_replica_id_is_pinned_with_other_keys_is_refused_for_that_vault() {
    let transport = Arc::new(FakeTransport::default());
    let fx = granting(&transport);
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    let request = request_with(&code, &[fx.id()], &keys);
    let to_replica = request.replicas[&fx.id()];
    let mut local = state(fx.id(), REPLICA, GENERATION);
    local.pinned_keys.insert(
        to_replica,
        PinnedKeys {
            source: PinSource::FirstUse,
            encryption: PublicKey(vec![0x66; 65]),
            signing: keys.signing.clone(),
            revoked: false,
        },
    );
    fx.put(&local, &TestSigner::device());
    let before = fx.on_disk();

    let outcome = grant(&fx, &request, &code);

    assert!(matches!(outcome, GrantOutcome::Conflict), "{outcome:?}");
    assert!(own_key_file(&transport, fx.id(), REPLICA).is_none());
    assert_eq!(fx.on_disk(), before);

    // A revoked pin with the same keys is refused too.
    let mut revoked = local.clone();
    revoked.pinned_keys.insert(
        to_replica,
        PinnedKeys {
            revoked: true,
            ..pairing_pin(&keys)
        },
    );
    fx.put(&revoked, &TestSigner::device());
    assert!(matches!(
        grant(&fx, &request, &code),
        GrantOutcome::Conflict
    ));
    assert!(own_key_file(&transport, fx.id(), REPLICA).is_none());
}

#[test]
fn first_use_pin_with_keys_of_request_becomes_pairing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = granting(&transport);
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    let request = request_with(&code, &[fx.id()], &keys);
    let to_replica = request.replicas[&fx.id()];
    let mut local = state(fx.id(), REPLICA, GENERATION);
    local.pinned_keys.insert(
        to_replica,
        PinnedKeys {
            source: PinSource::FirstUse,
            ..pairing_pin(&keys)
        },
    );
    fx.put(&local, &TestSigner::device());

    let outcome = grant(&fx, &request, &code);

    assert!(
        matches!(outcome, GrantOutcome::Granted(PairedPin::Upgraded)),
        "{outcome:?}"
    );
    assert_eq!(
        saved_local(&fx).pinned_keys[&to_replica],
        pairing_pin(&keys)
    );
    assert_eq!(
        own_key_file(&transport, fx.id(), REPLICA)
            .unwrap()
            .devices()
            .count(),
        1
    );
}

#[test]
fn failed_key_json_write_keeps_pin_and_later_grant_writes_one_wrapping() {
    let transport = Arc::new(FakeTransport::default());
    let fx = granting(&transport);
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    let request = request_with(&code, &[fx.id()], &keys);
    let to_replica = request.replicas[&fx.id()];
    transport.set_failing_writes(true);

    let outcome = grant(&fx, &request, &code);

    assert!(
        matches!(outcome, GrantOutcome::Failed(Error::SyncTransportError(_))),
        "{outcome:?}"
    );
    assert!(own_key_file(&transport, fx.id(), REPLICA).is_none());
    assert_eq!(
        saved_local(&fx).pinned_keys[&to_replica],
        pairing_pin(&keys)
    );

    transport.set_failing_writes(false);
    for _ in 0..2 {
        let outcome = grant(&fx, &request, &code);
        assert!(
            matches!(outcome, GrantOutcome::Granted(PairedPin::Unchanged)),
            "{outcome:?}"
        );
        let file = own_key_file(&transport, fx.id(), REPLICA).unwrap();
        let devices: Vec<_> = file.devices().collect();
        assert_eq!(
            devices.len(),
            1,
            "a wrapping to the same replica is replaced"
        );
        assert_eq!(devices[0].to_replica, to_replica);
    }
}

#[test]
fn vault_of_another_root_or_not_in_request_map_receives_no_wrapping() {
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    for (name, root, in_map) in [
        ("other root", Some(other_root()), true),
        ("no root", None, true),
        ("not in map", Some(grant_root()), false),
    ] {
        let transport = Arc::new(FakeTransport::default());
        let fx = synced(&transport);
        if let Some(root) = &root {
            put_root(&fx.root, fx.id(), root);
        }
        let vaults = if in_map {
            vec![fx.id()]
        } else {
            vec![vault(1)]
        };
        let request = request_with(&code, &vaults, &keys);
        let before = fx.on_disk();

        let outcome = grant(&fx, &request, &code);

        assert!(
            matches!(
                outcome,
                GrantOutcome::Failed(Error::PairingVaultNotOffered(_))
            ),
            "{name}: {outcome:?}"
        );
        assert!(
            own_key_file(&transport, fx.id(), REPLICA).is_none(),
            "{name}"
        );
        assert_eq!(fx.on_disk(), before, "{name}");
    }
}

// Pairing watcher of the new Mac (9.5). Each watcher runs in a manager on
// the test thread through `SyncManager::run_queued`, with watch events fired
// by `FakeTransport::fire_watch` and the clock moved by
// `SyncManager::advance_clock`.

/// Unwrap that returns fixed bytes, or fails if it has none, and counts its
/// calls through a counter the test keeps.
struct SharedUnwrap {
    raw: Option<Vec<u8>>,
    calls: Arc<AtomicUsize>,
}

impl SharedUnwrap {
    /// Unwrap that returns `key`, or fails if `None`, and its call counter.
    fn boxed(key: Option<&SyncKey>) -> (Box<dyn DeviceUnwrap + Send>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let unwrap = Self {
            raw: key.map(|key| key.as_bytes().to_vec()),
            calls: calls.clone(),
        };
        (Box::new(unwrap), calls)
    }
}

impl DeviceUnwrap for SharedUnwrap {
    fn unwrap_sync_key(&self, _wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.raw.clone().map(Zeroizing::new)
    }
}

/// Manager of a new Mac with no synced vault, with its start run. The
/// fixture holds the app data directory of the manager.
fn new_mac_manager() -> (Fixture, Managed) {
    let fx = Fixture::new(GENERATION, None);
    let managed = Managed::start(&fx, false);
    managed.run();
    (fx, managed)
}

#[test]
fn wrapping_written_after_start_is_accepted_at_next_event_with_one_unwrap_key() {
    let mac = NewMac::new();
    let transport = Arc::new(folder(&[vault(1), vault(2)]));
    let pending = mac.start(&transport, &[]).unwrap();
    let request_id = pending.request().request_id;
    let sync_key = SyncKey::generate();
    let first = granted(&pending, vault(1), peer(1), &sync_key);
    let second = granted(&pending, vault(2), peer(2), &sync_key);
    let (unwrap, calls) = SharedUnwrap::boxed(Some(&sync_key));
    let (_fx, managed) = new_mac_manager();

    managed.manager.pair(pending, transport.clone(), unwrap);
    managed.run();

    // One watch per vault of the request map. The first poll finds nothing.
    assert_eq!(transport.watch_count(), 2);
    assert!(managed.events.taken().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    put_key_file(&transport, vault(1), peer(1), vec![first]);
    assert_eq!(transport.fire_watch(vault(1)), 1);
    managed.run();

    let key = sync_key.as_bytes().to_vec();
    assert_eq!(
        managed.events.taken(),
        [Event::Paired(vault(1), key.clone())]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // With no event, the next poll is 10 seconds after the last one.
    put_key_file(&transport, vault(2), peer(2), vec![second]);
    managed.manager.advance_clock(POLL_INTERVAL.as_secs() - 1);
    managed.run();
    assert!(managed.events.taken().is_empty());
    managed.manager.advance_clock(1);
    managed.run();

    assert_eq!(managed.events.taken(), [Event::Paired(vault(2), key)]);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "one unwrap per vault");
    // The request stays until the user finishes.
    assert!(transport.pairing(request_id).is_some());
}

#[test]
fn pairing_request_is_deleted_when_app_quits_or_after_15_minutes() {
    for quit in [true, false] {
        let mac = NewMac::new();
        let transport = Arc::new(folder(&[vault(1)]));
        let pending = mac.start(&transport, &[]).unwrap();
        let request_id = pending.request().request_id;
        let (unwrap, _) = SharedUnwrap::boxed(None);
        let (_fx, managed) = new_mac_manager();
        managed.manager.pair(pending, transport.clone(), unwrap);
        managed.run();
        assert!(transport.pairing(request_id).is_some());
        assert_eq!(transport.watch_count(), 1);
        assert_eq!(transport.pairing_writes(), 1);

        if quit {
            managed.manager.shutdown();
        } else {
            managed.manager.advance_clock(PAIRING_EXPIRY.as_secs() - 1);
            managed.run();
            assert!(transport.pairing(request_id).is_some(), "quit {quit}");
            managed.manager.advance_clock(1);
            managed.run();
        }

        assert!(transport.pairing(request_id).is_none(), "quit {quit}");
        assert_eq!(transport.watch_count(), 0, "quit {quit}");
        assert_eq!(transport.pairing_writes(), 2, "quit {quit}");
        // The request is deleted once.
        managed.manager.shutdown();
        assert_eq!(transport.pairing_writes(), 2, "quit {quit}");
    }
}

#[test]
fn finished_pairing_ends_its_watches() {
    let mac = NewMac::new();
    let transport = Arc::new(folder(&[vault(1), vault(2)]));
    let pending = mac.start(&transport, &[]).unwrap();
    let request_id = pending.request().request_id;
    let (unwrap, _) = SharedUnwrap::boxed(None);
    let (_fx, managed) = new_mac_manager();
    managed.manager.pair(pending, transport.clone(), unwrap);
    managed.run();
    assert_eq!(transport.watch_count(), 2);

    managed.manager.finish_pairing();
    managed.run();

    assert_eq!(transport.watch_count(), 0);
    assert_eq!(transport.fire_watch(vault(1)), 0);
    assert!(transport.pairing(request_id).is_none());
    assert_eq!(transport.pairing_writes(), 2);

    // A second pairing finishes the one that runs.
    let first = mac.start(&transport, &[]).unwrap();
    let first_id = first.request().request_id;
    let (unwrap, _) = SharedUnwrap::boxed(None);
    managed.manager.pair(first, transport.clone(), unwrap);
    managed.run();
    let second = mac.start(&transport, &[]).unwrap();
    let second_id = second.request().request_id;
    let (unwrap, _) = SharedUnwrap::boxed(None);
    managed.manager.pair(second, transport.clone(), unwrap);
    managed.run();

    assert!(transport.pairing(first_id).is_none());
    assert!(transport.pairing(second_id).is_some());
    assert_eq!(transport.watch_count(), 2);
}

#[test]
fn only_pairing_watcher_writes_pairing_requests_and_manager_writes_none() {
    // Unlocked Mac: a synced vault whose root holds a request of another
    // Mac, with a peer change and a pairing event.
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    set_root(&fx, &folder_root());
    transport.set_now(Timestamp::now());
    put_request(
        &transport,
        &request_of(&PairingCode::generate(), &[fx.id()]),
    );
    let managed = Managed::start(&fx, true);
    managed.run();
    put_peer(&fx, &transport, peer(1), "joined");
    transport.fire_watch(fx.id());
    transport.fire_pairing_watch();
    managed.run();
    managed.manager.shutdown();

    assert_eq!(managed.unlock.transactions(), 1);
    assert_eq!(
        managed.events.taken(),
        [
            Event::Pairings(folder_root(), 1),
            Event::Synced(fx.id()),
            Event::Pairings(folder_root(), 1),
        ]
    );
    assert_eq!(transport.pairing_writes(), 0);
    assert_eq!(transport.list_pairings().unwrap().len(), 1);

    // New Mac: the request write of the start, and the one delete of the
    // watcher.
    let mac = NewMac::new();
    let new = Arc::new(folder(&[vault(1)]));
    let pending = mac.start(&new, &[]).unwrap();
    assert_eq!(new.pairing_writes(), 1);
    let (unwrap, _) = SharedUnwrap::boxed(None);
    let (_new_fx, new_managed) = new_mac_manager();
    new_managed.manager.pair(pending, new.clone(), unwrap);
    new_managed.run();
    new.fire_watch(vault(1));
    new_managed.run();
    new_managed.manager.advance_clock(POLL_INTERVAL.as_secs());
    new_managed.run();
    assert_eq!(new.pairing_writes(), 1);

    new_managed.manager.finish_pairing();
    new_managed.run();

    assert_eq!(new.pairing_writes(), 2);
    assert!(new.list_pairings().unwrap().is_empty());
}

#[test]
fn wrapping_whose_unwrap_fails_is_not_unwrapped_again_and_new_wrapping_is() {
    let mac = NewMac::new();
    let transport = Arc::new(folder(&[vault(1)]));
    let pending = mac.start(&transport, &[]).unwrap();
    let sync_key = SyncKey::generate();
    put_key_file(
        &transport,
        vault(1),
        peer(1),
        vec![granted(&pending, vault(1), peer(1), &sync_key)],
    );
    // A second wrapping with other wrapped bytes, from another replica.
    let request = pending.request().clone();
    let mut other = wrapping(&sync_key, request.replicas[&vault(1)]);
    other.wrapped = vec![0xd1, 0xd2];
    typed_key(&pending).seal_wrapping(&mut other, vault(1), peer(2), &request.keys());
    let (unwrap, calls) = SharedUnwrap::boxed(None);
    let (_fx, managed) = new_mac_manager();

    managed.manager.pair(pending, transport.clone(), unwrap);
    managed.run();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    transport.fire_watch(vault(1));
    managed.run();
    managed.manager.advance_clock(POLL_INTERVAL.as_secs());
    managed.run();

    assert_eq!(calls.load(Ordering::SeqCst), 1, "no second unwrap");
    assert!(managed.events.taken().is_empty());

    put_key_file(&transport, vault(1), peer(2), vec![other]);
    transport.fire_watch(vault(1));
    managed.run();

    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn pairing_handed_to_stopped_manager_deletes_its_request() {
    let mac = NewMac::new();
    let transport = Arc::new(folder(&[vault(1)]));
    let (_fx, managed) = new_mac_manager();
    managed.manager.shutdown();
    let pending = mac.start(&transport, &[]).unwrap();
    let request_id = pending.request().request_id;
    let (unwrap, _) = SharedUnwrap::boxed(None);

    managed.manager.pair(pending, transport.clone(), unwrap);

    assert!(transport.pairing(request_id).is_none());
    assert_eq!(transport.watch_count(), 0);
}
