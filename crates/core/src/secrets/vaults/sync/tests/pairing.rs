//! Tests of the pairing code, the pairing request, the pairing HMACs, and the
//! new Mac side of pairing.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::transport::FakeTransport;
use crate::audit::test_support::test_dir;
use crate::core::auth::AuthContext;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::device_keys::{DeviceKeys, KeyProbe, VaultFiles};
use crate::secrets::vaults::storage::test_keys::TestKeys;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::{KeyFingerprint, SyncKey};
use crate::secrets::vaults::sync::local_state::{PinSource, PinnedKeys};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::pairing::request::PairingRequest;
use crate::secrets::vaults::sync::pairing::{PairKey, PairingCode, PendingPairing};
use crate::secrets::vaults::sync::transport::{RequestId, SyncTransport};
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
