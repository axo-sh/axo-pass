//! ECIES, byte compatible with Apple's
//! `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM` on
//! P-256.
//!
//! Ciphertext layout:
//! - Ephemeral public key, uncompressed SEC1 (65 bytes).
//! - AES-GCM ciphertext, as long as the plaintext.
//! - AES-GCM tag (16 bytes).
//!
//! Key derivation:
//! - ECDH between the ephemeral key and the peer key gives the shared secret,
//!   the 32-byte x coordinate of the shared point.
//! - The X9.63 KDF with SHA-256 runs over the shared secret, with the ephemeral
//!   public key (65 bytes) as shared info. It outputs 32 bytes.
//! - The first 16 bytes are the AES-128 key. The last 16 bytes are the GCM IV.
//! - GCM uses a 16-byte IV and no associated data.
//!
//! This layout was confirmed against ciphertext from Security.framework. See
//! `vectors.json`.
//!
//! The "Cofactor" variant of the algorithm uses cofactor ECDH. The cofactor of
//! P-256 is 1, so it equals plain ECDH.
//!
//! The split path serves a TPM, which computes only the ECDH point. The caller
//! reads the ephemeral key with [`shared_info_and_ephemeral_key`], has the TPM
//! compute the shared secret, and passes it to [`decrypt_with_shared_secret`].
//!
//! Known limit: the SHA-256 state of the KDF holds the shared secret and is
//! not zeroized, since `sha2` does not support it.

use aes_gcm::AesGcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::generic_array::typenum::U16;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::aes::Aes128;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(all(test, macos))]
mod apple_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vectors;

/// Length of an uncompressed SEC1 P-256 point.
pub const EPHEMERAL_KEY_LEN: usize = 65;
/// Length of the AES-GCM tag.
pub const TAG_LEN: usize = 16;
/// Length of the shortest ciphertext, which has an empty plaintext.
pub const MIN_CIPHERTEXT_LEN: usize = EPHEMERAL_KEY_LEN + TAG_LEN;

const AES_KEY_LEN: usize = 16;
const GCM_IV_LEN: usize = 16;

type Aes128Gcm16 = AesGcm<Aes128, U16>;

/// ECDH shared secret, the 32-byte x coordinate of the shared point.
pub type SharedSecret = SecretBox<[u8; 32]>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum EciesError {
    /// Public key that is not a valid P-256 point.
    #[error("public key is not a valid P-256 point")]
    InvalidPublicKey,
    /// Ciphertext shorter than the ephemeral key and the tag.
    #[error("ciphertext is too short")]
    Truncated,
    /// Ephemeral key of the ciphertext that is not a valid uncompressed P-256
    /// point.
    #[error("ephemeral key is not a valid uncompressed P-256 point")]
    InvalidEphemeralKey,
    /// Tag mismatch, from a wrong key or a modified ciphertext.
    #[error("decryption failed")]
    Decryption,
}

pub type Result<T> = std::result::Result<T, EciesError>;

/// Ciphertext of `plaintext` to `peer_public_key`, under a fresh ephemeral key.
pub fn encrypt(peer_public_key: &PublicKey, plaintext: &[u8]) -> Vec<u8> {
    encrypt_with_ephemeral_key(peer_public_key, &SecretKey::random(&mut OsRng), plaintext)
}

/// Ciphertext of `plaintext` to the uncompressed SEC1 point `peer_public_sec1`.
pub fn encrypt_to_sec1(peer_public_sec1: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let peer_public_key =
        PublicKey::from_sec1_bytes(peer_public_sec1).map_err(|_| EciesError::InvalidPublicKey)?;
    Ok(encrypt(&peer_public_key, plaintext))
}

/// Plaintext of `ciphertext`, decrypted with `secret_key`.
pub fn decrypt_with_secret_key(
    secret_key: &SecretKey,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let ephemeral_key = shared_info_and_ephemeral_key(ciphertext)?;
    let shared_secret = diffie_hellman(secret_key, &ephemeral_key);
    decrypt_with_shared_secret(&shared_secret, ciphertext)
}

/// Ephemeral public key of `ciphertext`. A TPM computes the ECDH point of this
/// key and its own private key. The point is validated to be on the curve.
pub fn shared_info_and_ephemeral_key(ciphertext: &[u8]) -> Result<PublicKey> {
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(EciesError::Truncated);
    }
    let sec1 = &ciphertext[..EPHEMERAL_KEY_LEN];
    // Apple writes the ephemeral key uncompressed. Other encodings are refused.
    if sec1[0] != 0x04 {
        return Err(EciesError::InvalidEphemeralKey);
    }
    PublicKey::from_sec1_bytes(sec1).map_err(|_| EciesError::InvalidEphemeralKey)
}

/// Plaintext of `ciphertext`, from the ECDH `shared_secret` of the private key
/// and the key from [`shared_info_and_ephemeral_key`]. Does not check the
/// ephemeral key.
pub fn decrypt_with_shared_secret(
    shared_secret: &SharedSecret,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(EciesError::Truncated);
    }
    let (ephemeral_sec1, body) = ciphertext.split_at(EPHEMERAL_KEY_LEN);
    let derived = derive(shared_secret, ephemeral_sec1);
    let (key, iv) = derived.split_at(AES_KEY_LEN);
    let cipher = Aes128Gcm16::new(GenericArray::from_slice(key));
    cipher
        .decrypt(
            GenericArray::from_slice(iv),
            Payload {
                msg: body,
                aad: &[],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| EciesError::Decryption)
}

/// Encryption with a chosen ephemeral key. Tests fix it.
fn encrypt_with_ephemeral_key(
    peer_public_key: &PublicKey,
    ephemeral_key: &SecretKey,
    plaintext: &[u8],
) -> Vec<u8> {
    let ephemeral_sec1 = ephemeral_key.public_key().to_encoded_point(false);
    let shared_secret = diffie_hellman(ephemeral_key, peer_public_key);
    let derived = derive(&shared_secret, ephemeral_sec1.as_bytes());
    let (key, iv) = derived.split_at(AES_KEY_LEN);
    let cipher = Aes128Gcm16::new(GenericArray::from_slice(key));
    let sealed = cipher
        .encrypt(
            GenericArray::from_slice(iv),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .expect("AES-GCM encryption of a short message does not fail");
    let mut out = Vec::with_capacity(EPHEMERAL_KEY_LEN + sealed.len());
    out.extend_from_slice(ephemeral_sec1.as_bytes());
    out.extend_from_slice(&sealed);
    out
}

/// ECDH. Cofactor ECDH is the same, since the cofactor of P-256 is 1.
fn diffie_hellman(secret_key: &SecretKey, public_key: &PublicKey) -> SharedSecret {
    let shared = p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    let mut bytes = Box::new([0u8; 32]);
    bytes.copy_from_slice(shared.raw_secret_bytes());
    SecretBox::new(bytes)
}

/// X9.63 KDF with SHA-256 over `shared_secret`, with `shared_info`. Outputs the
/// AES key followed by the GCM IV. The 32 output bytes are one hash block, so
/// the counter is 1.
fn derive(
    shared_secret: &SharedSecret,
    shared_info: &[u8],
) -> Zeroizing<[u8; AES_KEY_LEN + GCM_IV_LEN]> {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.expose_secret());
    hasher.update(1u32.to_be_bytes());
    hasher.update(shared_info);
    let mut derived = Zeroizing::new([0u8; AES_KEY_LEN + GCM_IV_LEN]);
    derived.copy_from_slice(&hasher.finalize());
    derived
}
