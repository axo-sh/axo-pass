//! Tests against Security.framework. They run on macOS only.

use objc2_core_foundation::{CFData, CFMutableDictionary, CFString, CFType};
use objc2_security::{SecKey, kSecAttrKeyClass, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

use super::vectors::{Vector, VectorFile};
use super::{OsRng, decrypt_with_secret_key, encrypt};
use crate::secrets::keychain::errors::CFErrorOut;
use crate::secrets::keychain::managed_key::{KeyClass, ManagedKey};

const KEY_COUNT: usize = 6;
const PLAINTEXT_LENGTHS: [usize; 6] = [0, 1, 16, 32, 1000, 4096];

/// Software P-256 key of `scalar`, with no keychain item.
fn managed_key(secret: &SecretKey) -> ManagedKey {
    // Security.framework reads a private key as `04 || X || Y || K`.
    let mut external = secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    external.extend_from_slice(&secret.to_bytes());
    unsafe {
        let attrs = CFMutableDictionary::<CFString, CFType>::empty();
        attrs.add(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
        attrs.add(kSecAttrKeyClass, KeyClass::Private.as_objc());
        let mut cf_error = CFErrorOut::new();
        let sec_key = SecKey::with_data(
            &CFData::from_bytes(&external),
            attrs.as_opaque(),
            cf_error.out(),
        );
        assert!(cf_error.get().is_none(), "key import failed");
        ManagedKey::new(None, None, sec_key.expect("key imported").into())
    }
}

/// Private key `index`, derived from a fixed label so vectors are
/// reproducible.
fn fixed_secret(index: usize) -> SecretKey {
    let digest = Sha256::digest(format!("axo-pass ecies vector key {index}"));
    SecretKey::from_slice(&digest).expect("digest is a valid scalar")
}

fn pattern(index: usize, length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| (i.wrapping_mul(31).wrapping_add(index * 7) % 251) as u8)
        .collect()
}

#[test]
fn apple_decrypts_rust_ciphertext() {
    for index in 0..KEY_COUNT {
        let secret = fixed_secret(index);
        let key = managed_key(&secret);
        for length in PLAINTEXT_LENGTHS {
            let plaintext = pattern(index, length);
            let ciphertext = encrypt(&secret.public_key(), &plaintext);
            let decrypted = key
                .decrypt_bytes(&ciphertext)
                .unwrap_or_else(|| panic!("Apple rejects key {index}, length {length}"));
            assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        }
    }
}

#[test]
fn rust_decrypts_fresh_apple_ciphertext() {
    for length in PLAINTEXT_LENGTHS {
        let secret = SecretKey::random(&mut OsRng);
        let public_key = secret.public_key().to_encoded_point(false);
        let plaintext = pattern(0, length);
        let ciphertext = ManagedKey::encrypt_to(public_key.as_bytes(), &plaintext).unwrap();
        let decrypted = decrypt_with_secret_key(&secret, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }
}

#[test]
fn apple_rejects_tampered_rust_ciphertext() {
    let secret = fixed_secret(0);
    let key = managed_key(&secret);
    let mut ciphertext = encrypt(&secret.public_key(), b"sync key");
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 1;
    assert!(key.decrypt_bytes(&ciphertext).is_none());
}

/// Rewrite `vectors.json` from Security.framework output. Run with
/// `axo ecies:vectors`.
#[test]
#[ignore = "rewrites vectors.json"]
fn write_vectors() {
    let mut vectors = Vec::new();
    for index in 0..KEY_COUNT {
        let secret = fixed_secret(index);
        let public_key = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let key = managed_key(&secret);
        for length in PLAINTEXT_LENGTHS {
            let plaintext = pattern(index, length);
            let ciphertext = ManagedKey::encrypt_to(&public_key, &plaintext).unwrap();
            let decrypted = key.decrypt_bytes(&ciphertext).expect("Apple decrypts");
            assert_eq!(decrypted.as_slice(), plaintext.as_slice());
            vectors.push(Vector {
                name: format!("key{index}_len{length}"),
                private_key: secret.to_bytes().to_vec(),
                public_key: public_key.clone(),
                plaintext,
                ciphertext,
            });
        }
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/crypto/ecies/vectors.json");
    let json = serde_json::to_string_pretty(&VectorFile { vectors }).unwrap();
    std::fs::write(path, json + "\n").unwrap();
}
