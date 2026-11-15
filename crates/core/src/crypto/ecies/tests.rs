use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;

use super::*;
use crate::crypto::ecies::vectors;

const LENGTHS: [usize; 8] = [0, 1, 15, 16, 17, 32, 1000, 4096];

fn secret_key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

fn plaintext(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 13 + 5) as u8).collect()
}

fn sample() -> (SecretKey, Vec<u8>) {
    let secret_key = secret_key();
    let ciphertext = encrypt(&secret_key.public_key(), &plaintext(48));
    (secret_key, ciphertext)
}

#[test]
fn apple_vectors_decrypt() {
    let vectors = vectors::load();
    assert!(vectors.len() >= 30, "vectors.json is generated");
    for vector in vectors {
        let secret_key = SecretKey::from_slice(&vector.private_key).unwrap();
        assert_eq!(
            secret_key.public_key().to_encoded_point(false).as_bytes(),
            vector.public_key.as_slice(),
            "{}",
            vector.name
        );
        let decrypted = decrypt_with_secret_key(&secret_key, &vector.ciphertext)
            .unwrap_or_else(|e| panic!("{}: {e}", vector.name));
        assert_eq!(decrypted.as_slice(), vector.plaintext, "{}", vector.name);
    }
}

#[test]
fn apple_vectors_cover_lengths_and_keys() {
    let vectors = vectors::load();
    let mut keys = vectors
        .iter()
        .map(|v| v.public_key.clone())
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    assert!(keys.len() >= 5);
    assert!(vectors.iter().any(|v| v.plaintext.is_empty()));
    assert!(vectors.iter().any(|v| v.plaintext.len() >= 4096));
}

#[test]
fn apple_vectors_decrypt_on_split_path() {
    for vector in vectors::load() {
        let secret_key = SecretKey::from_slice(&vector.private_key).unwrap();
        let ephemeral = shared_info_and_ephemeral_key(&vector.ciphertext).unwrap();
        let shared_secret = diffie_hellman(&secret_key, &ephemeral);
        let decrypted = decrypt_with_shared_secret(&shared_secret, &vector.ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), vector.plaintext, "{}", vector.name);
    }
}

#[test]
fn round_trip() {
    let secret_key = secret_key();
    for length in LENGTHS {
        let ciphertext = encrypt(&secret_key.public_key(), &plaintext(length));
        let decrypted = decrypt_with_secret_key(&secret_key, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext(length));
    }
}

#[test]
fn round_trip_to_sec1_key() {
    let secret_key = secret_key();
    let sec1 = secret_key.public_key().to_encoded_point(false);
    let ciphertext = encrypt_to_sec1(sec1.as_bytes(), b"sync key").unwrap();
    let decrypted = decrypt_with_secret_key(&secret_key, &ciphertext).unwrap();
    assert_eq!(decrypted.as_slice(), b"sync key");
}

#[test]
fn ciphertext_layout() {
    let secret_key = secret_key();
    for length in LENGTHS {
        let ciphertext = encrypt(&secret_key.public_key(), &plaintext(length));
        assert_eq!(ciphertext.len(), EPHEMERAL_KEY_LEN + length + TAG_LEN);
        assert_eq!(ciphertext[0], 0x04);
        assert!(shared_info_and_ephemeral_key(&ciphertext).is_ok());
    }
}

#[test]
fn encryptions_use_fresh_ephemeral_keys() {
    let secret_key = secret_key();
    let first = encrypt(&secret_key.public_key(), b"same");
    let second = encrypt(&secret_key.public_key(), b"same");
    assert_ne!(first[..EPHEMERAL_KEY_LEN], second[..EPHEMERAL_KEY_LEN]);
    assert_ne!(first, second);
}

#[test]
fn fixed_ephemeral_key_is_deterministic() {
    let peer = secret_key().public_key();
    let ephemeral = secret_key();
    let first = encrypt_with_ephemeral_key(&peer, &ephemeral, b"same");
    let second = encrypt_with_ephemeral_key(&peer, &ephemeral, b"same");
    assert_eq!(first, second);
}

#[test]
fn split_path_round_trip() {
    let (secret_key, ciphertext) = sample();
    let ephemeral = shared_info_and_ephemeral_key(&ciphertext).unwrap();
    let shared_secret = diffie_hellman(&secret_key, &ephemeral);
    let decrypted = decrypt_with_shared_secret(&shared_secret, &ciphertext).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext(48));
}

#[test]
fn flipped_tag_rejected() {
    let (secret_key, mut ciphertext) = sample();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 1;
    assert_eq!(
        decrypt_with_secret_key(&secret_key, &ciphertext).unwrap_err(),
        EciesError::Decryption
    );
}

#[test]
fn flipped_body_rejected() {
    let (secret_key, mut ciphertext) = sample();
    ciphertext[EPHEMERAL_KEY_LEN] ^= 1;
    assert_eq!(
        decrypt_with_secret_key(&secret_key, &ciphertext).unwrap_err(),
        EciesError::Decryption
    );
}

#[test]
fn flipped_ephemeral_key_byte_rejected() {
    let (secret_key, ciphertext) = sample();
    for index in 1..EPHEMERAL_KEY_LEN {
        let mut tampered = ciphertext.clone();
        tampered[index] ^= 1;
        assert!(decrypt_with_secret_key(&secret_key, &tampered).is_err());
    }
}

#[test]
fn truncated_ciphertext_rejected() {
    let (secret_key, ciphertext) = sample();
    for length in 0..MIN_CIPHERTEXT_LEN {
        assert_eq!(
            decrypt_with_secret_key(&secret_key, &ciphertext[..length]).unwrap_err(),
            EciesError::Truncated
        );
    }
    for length in MIN_CIPHERTEXT_LEN..ciphertext.len() {
        assert!(decrypt_with_secret_key(&secret_key, &ciphertext[..length]).is_err());
    }
}

#[test]
fn truncated_split_path_rejected() {
    let shared_secret = diffie_hellman(&secret_key(), &secret_key().public_key());
    assert_eq!(
        shared_info_and_ephemeral_key(&[0x04; 80]).unwrap_err(),
        EciesError::Truncated
    );
    assert_eq!(
        decrypt_with_shared_secret(&shared_secret, &[0x04; 80]).unwrap_err(),
        EciesError::Truncated
    );
}

#[test]
fn invalid_ephemeral_point_rejected() {
    let (secret_key, ciphertext) = sample();
    let mut zero_point = ciphertext.clone();
    zero_point[..EPHEMERAL_KEY_LEN].fill(0);
    let mut infinity = ciphertext.clone();
    infinity[0] = 0x00;
    let mut bad_prefix = ciphertext.clone();
    bad_prefix[0] = 0x05;
    let mut compressed = ciphertext.clone();
    compressed[0] = 0x02;
    for tampered in [zero_point, infinity, bad_prefix, compressed] {
        assert_eq!(
            decrypt_with_secret_key(&secret_key, &tampered).unwrap_err(),
            EciesError::InvalidEphemeralKey
        );
        assert_eq!(
            shared_info_and_ephemeral_key(&tampered).unwrap_err(),
            EciesError::InvalidEphemeralKey
        );
    }
}

#[test]
fn off_curve_ephemeral_point_rejected() {
    let (secret_key, mut ciphertext) = sample();
    // Change y so that (x, y) is not on the curve.
    ciphertext[EPHEMERAL_KEY_LEN - 1] ^= 1;
    assert_eq!(
        decrypt_with_secret_key(&secret_key, &ciphertext).unwrap_err(),
        EciesError::InvalidEphemeralKey
    );
    assert_eq!(
        shared_info_and_ephemeral_key(&ciphertext).unwrap_err(),
        EciesError::InvalidEphemeralKey
    );
}

#[test]
fn coordinates_over_field_size_rejected() {
    let (secret_key, mut ciphertext) = sample();
    ciphertext[1..EPHEMERAL_KEY_LEN].fill(0xff);
    assert_eq!(
        decrypt_with_secret_key(&secret_key, &ciphertext).unwrap_err(),
        EciesError::InvalidEphemeralKey
    );
}

#[test]
fn wrong_secret_key_rejected() {
    let (_, ciphertext) = sample();
    assert_eq!(
        decrypt_with_secret_key(&secret_key(), &ciphertext).unwrap_err(),
        EciesError::Decryption
    );
}

#[test]
fn wrong_shared_secret_rejected() {
    let (_, ciphertext) = sample();
    let wrong = diffie_hellman(&secret_key(), &secret_key().public_key());
    assert_eq!(
        decrypt_with_shared_secret(&wrong, &ciphertext).unwrap_err(),
        EciesError::Decryption
    );
}

#[test]
fn invalid_peer_public_key_rejected() {
    let sec1 = secret_key().public_key().to_encoded_point(false);
    let mut off_curve = sec1.as_bytes().to_vec();
    off_curve[EPHEMERAL_KEY_LEN - 1] ^= 1;
    for bytes in [
        &[][..],
        &[0x04; 65][..],
        &off_curve[..],
        &sec1.as_bytes()[..64],
    ] {
        assert_eq!(
            encrypt_to_sec1(bytes, b"x").unwrap_err(),
            EciesError::InvalidPublicKey
        );
    }
}
