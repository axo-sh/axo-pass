use std::marker::PhantomData;

use aes_gcm::aead::{Aead, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::secrets::vaults::errors::Error;

#[derive(Zeroize)]
pub struct EncryptedBlob<T> {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> Serialize for EncryptedBlob<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // merge nonce and ciphertext into a single field for easier storage
        let mut combined = self.nonce.clone();
        combined.extend_from_slice(&self.ciphertext);
        let combined_b64 = b64.encode(&combined);
        serializer.serialize_str(&combined_b64)
    }
}

impl<'de, T> Deserialize<'de> for EncryptedBlob<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let combined_b64 = String::deserialize(deserializer)?;
        let combined = b64
            .decode(&combined_b64)
            .map_err(|_| serde::de::Error::custom("invalid base64"))?;
        if combined.len() < 12 {
            return Err(serde::de::Error::custom("invalid encrypted blob"));
        }
        let nonce = combined[..12].to_vec();
        let ciphertext = combined[12..].to_vec();
        Ok(Self {
            nonce,
            ciphertext,
            _marker: PhantomData,
        })
    }
}

impl<T> Clone for EncryptedBlob<T> {
    fn clone(&self) -> Self {
        Self {
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T: Serialize + for<'de2> Deserialize<'de2> + Zeroize> EncryptedBlob<T> {
    pub fn encrypt(value: &T, cipher: &Aes256Gcm, aad: Vec<String>) -> Result<Self, Error> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let payload = Payload {
            msg: &serde_json::to_string(&value)
                .map_err(|_| Error::VaultSecretEncryptionError)?
                .into_bytes(),
            aad: &aad.join(":").into_bytes(),
        };

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .inspect_err(|e| log::debug!("metadata encryption error: {e}"))
            .map_err(|_| Error::VaultSecretEncryptionError)?;

        Ok(Self {
            nonce: nonce.to_vec(),
            ciphertext,
            _marker: PhantomData,
        })
    }

    pub fn decrypt(&self, cipher: &Aes256Gcm, aad: Vec<String>) -> Result<SecretBox<T>, Error> {
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&self.nonce);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad.join(":").into_bytes(),
                },
            )
            .inspect_err(|e| log::debug!("metadata decryption error: {e}"))
            .map_err(|_| Error::VaultSecretDecryptionError)?;

        serde_json::from_slice(&plaintext)
            .map(SecretBox::new)
            .map_err(|_| Error::VaultSecretDecryptionError)
    }
}
