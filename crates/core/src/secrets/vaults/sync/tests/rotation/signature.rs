//! Rotation signature of `Device` wrappings, and rotations signed by a key
//! that is not pinned.

use uuid::Uuid;

use super::{Net, signing_of};
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::{KeyFingerprint, SyncKey};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::rotation::RotationPlan;
use crate::secrets::vaults::sync::tests::wrapping::SoftwareKey;
use crate::secrets::vaults::sync::wrapping::{DeviceWrapping, KeyFile, Wrapping};

const VAULT: Uuid = Uuid::from_u128(0x77);
const FROM: ReplicaId = ReplicaId(Uuid::from_u128(1));
const TO: ReplicaId = ReplicaId(Uuid::from_u128(2));

fn replica(n: u128) -> ReplicaId {
    ReplicaId(Uuid::from_u128(n))
}

/// Rotation wrapping to [`TO`] signed by `signer`, removing `removed` and
/// keeping `remaining`.
fn signed(
    signer: &TestSigner,
    removed: Vec<ReplicaId>,
    remaining: Vec<ReplicaId>,
) -> DeviceWrapping {
    let to = SoftwareKey::generate();
    let from = ReplicaKeys {
        encryption: PublicKey(SoftwareKey::generate().public_sec1()),
        signing: signing_of(signer),
    };
    let key = SyncKey::generate();
    let mut wrapping =
        DeviceWrapping::wrap(KeyId(2), &key, TO, &PublicKey(to.public_sec1()), &from).unwrap();
    wrapping
        .sign_rotation(VAULT, FROM, removed, remaining, signer)
        .unwrap();
    wrapping
}

#[test]
fn signed_wrapping_verifies_under_signer_key() {
    let signer = TestSigner::seeded(3);
    let wrapping = signed(&signer, vec![replica(3)], vec![TO]);

    wrapping
        .verify_rotation(VAULT, FROM, &signing_of(&signer))
        .unwrap();
    let other = TestSigner::seeded(4);
    assert!(
        wrapping
            .verify_rotation(VAULT, FROM, &signing_of(&other))
            .is_err()
    );
    assert!(
        wrapping
            .verify_rotation(VAULT, replica(9), &signing_of(&signer))
            .is_err(),
        "the directory of the key.json is signed"
    );
}

#[test]
fn rearranged_removed_and_remaining_fail_verification() {
    let signer = TestSigner::seeded(3);
    let mut wrapping = signed(&signer, vec![replica(3), TO], vec![replica(4)]);
    // The concatenation of the two lists is unchanged.
    wrapping.removed = Some(vec![replica(3)]);
    wrapping.remaining = Some(vec![TO, replica(4)]);

    assert!(
        wrapping
            .verify_rotation(VAULT, FROM, &signing_of(&signer))
            .is_err()
    );
}

#[test]
fn changed_key_fingerprint_fails_verification() {
    let signer = TestSigner::seeded(3);
    let mut wrapping = signed(&signer, vec![], vec![TO]);
    wrapping.key_fingerprint = KeyFingerprint([9; 16]);

    assert!(
        wrapping
            .verify_rotation(VAULT, FROM, &signing_of(&signer))
            .is_err()
    );
}

#[test]
fn rotation_field_boundaries_shifted_fail_signature() {
    let signer = TestSigner::seeded(3);
    let mut wrapping = signed(&signer, vec![], vec![TO]);
    // Move the last byte of the sender encryption key to the front of the
    // sender signing key. The concatenated bytes are unchanged.
    let byte = wrapping.from_encryption.0.pop().unwrap();
    wrapping.from_signing.0.insert(0, byte);

    let message = wrapping.rotation_message(VAULT, FROM);
    assert_ne!(
        message,
        signed(&signer, vec![], vec![TO]).rotation_message(VAULT, FROM)
    );
    assert!(
        wrapping
            .verify_rotation(VAULT, FROM, &wrapping.from_signing.clone())
            .is_err()
    );
}

#[test]
fn wrapping_without_signature_or_with_pairing_mac_fails() {
    let signer = TestSigner::seeded(3);
    let mut unsigned = signed(&signer, vec![], vec![TO]);
    unsigned.signature = None;
    assert!(
        unsigned
            .verify_rotation(VAULT, FROM, &signing_of(&signer))
            .is_err()
    );
    let mut lists_dropped = signed(&signer, vec![], vec![TO]);
    lists_dropped.remaining = None;
    assert!(
        lists_dropped
            .verify_rotation(VAULT, FROM, &signing_of(&signer))
            .is_err()
    );
}

#[test]
fn rotation_signed_by_unpinned_key_rejected() {
    let net = Net::new(2);
    net.macs[0].sync();
    net.macs[1].sync();
    // A replica that no Mac pinned writes a signed rotation to Mac 1.
    let planted = replica(0xdead);
    let signer = TestSigner::random();
    let to = &net.macs[1].keys;
    let from = ReplicaKeys {
        encryption: PublicKey(SoftwareKey::generate().public_sec1()),
        signing: signing_of(&signer),
    };
    let mut wrapping = DeviceWrapping::wrap(
        KeyId(2),
        &SyncKey::generate(),
        Net::replica(1),
        &to.encryption,
        &from,
    )
    .unwrap();
    wrapping
        .sign_rotation(
            net.vault_id(),
            planted,
            vec![Net::replica(0)],
            vec![Net::replica(1)],
            &signer,
        )
        .unwrap();
    let file = KeyFile {
        wrappings: vec![Wrapping::Device(wrapping.clone())],
        invalid: Vec::new(),
    };
    net.folder
        .put(net.vault_id(), planted, "key.json", &file.to_bytes());
    // A pinned replica's key.json holds a wrapping signed by another key.
    let mut forged = wrapping;
    forged
        .sign_rotation(
            net.vault_id(),
            Net::replica(0),
            vec![],
            vec![Net::replica(1)],
            &signer,
        )
        .unwrap();
    let file = KeyFile {
        wrappings: vec![Wrapping::Device(forged)],
        invalid: Vec::new(),
    };
    net.folder.put(
        net.vault_id(),
        Net::replica(0),
        "key.json",
        &file.to_bytes(),
    );

    net.macs[1].sync();

    assert!(net.macs[1].local().pending_rotations.is_empty());
    assert!(net.macs[1].prompts().is_empty());
}

#[test]
fn wrapping_copied_to_other_directory_rejected() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);
    net.macs[0].rotate(&RotationPlan::rotate_key());
    // The key.json of Mac 0 moved into the directory of another replica id
    // is signed for another directory.
    let bytes = net.hide_key_file(0);
    net.folder
        .put(net.vault_id(), replica(0x99), "key.json", &bytes);

    net.macs[1].sync();

    assert!(net.macs[1].prompts().is_empty());
}
