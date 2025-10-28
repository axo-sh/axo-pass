use std::fmt::Debug;
use std::ptr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use objc2::rc::Retained;
use objc2_core_foundation::{
    CFArray, CFBoolean, CFData, CFDictionary, CFError, CFMutableDictionary, CFString, CFType,
};
use objc2_security::{
    SecItemDelete, SecKey, SecKeyAlgorithm, kSecAttrApplicationLabel, kSecAttrApplicationTag,
    kSecAttrKeyClassPrivate, kSecAttrKeyClassPublic, kSecClass, kSecClassKey,
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, kSecMatchItemList,
    kSecUseDataProtectionKeychain,
};

fn alg() -> &'static SecKeyAlgorithm {
    unsafe { kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM }
}

pub enum KeyClass {
    Public,  // encryption
    Private, // decryption
}

impl KeyClass {
    pub fn as_objc(&self) -> &CFString {
        unsafe {
            match self {
                KeyClass::Public => kSecAttrKeyClassPublic,
                KeyClass::Private => kSecAttrKeyClassPrivate,
            }
        }
    }
}

pub struct ManagedKey {
    label: Option<String>,
    sec_key: Retained<SecKey>,
}

impl ManagedKey {
    pub fn new(label: Option<String>, sec_key: Retained<SecKey>) -> Self {
        ManagedKey { label, sec_key }
    }

    pub fn is_private(&self) -> bool {
        unsafe {
            self.sec_key
                .is_algorithm_supported(objc2_security::SecKeyOperationType::Decrypt, alg())
        }
    }

    pub fn app_label(&self) -> Option<String> {
        unsafe {
            let attrs = self.sec_key.attributes().unwrap();
            let attr: &CFDictionary<CFString, CFData> = attrs.cast_unchecked();
            attr.get(kSecAttrApplicationLabel)
                .map(|d| b64.encode(d.as_bytes_unchecked()))
        }
    }

    pub fn tag(&self) -> Option<String> {
        unsafe {
            let attrs = self.sec_key.attributes().unwrap();
            let attr: &CFDictionary<CFString, CFData> = attrs.cast_unchecked();
            attr.get(kSecAttrApplicationTag)
                .map(|d| String::from_utf8_lossy(d.as_bytes_unchecked()).to_string())
        }
    }

    pub fn public_key(&self) -> Option<Vec<u8>> {
        unsafe {
            let mut cf_error_ptr: *mut CFError = ptr::null_mut();
            let pub_key = self.sec_key.public_key()?;
            let pub_key_ext = pub_key.external_representation(&mut cf_error_ptr)?;
            if !cf_error_ptr.is_null() {
                log::debug!(
                    "Error getting public key external representation: {:?}",
                    cf_error_ptr
                );
                return None;
            }
            let pub_key_bytes = pub_key_ext.as_bytes_unchecked();
            Some(pub_key_bytes.to_vec())
        }
    }

    #[allow(dead_code)]
    pub fn delete(&self) -> anyhow::Result<()> {
        unsafe {
            let query = CFMutableDictionary::<CFString, CFType>::empty();
            query.add(kSecClass, kSecClassKey);
            query.add(kSecUseDataProtectionKeychain, CFBoolean::new(true));

            let key_ref = &*self.sec_key;
            query.add(kSecMatchItemList, &CFArray::from_objects(&[key_ref]));
            let status = SecItemDelete(query.as_opaque());
            log::debug!("Deleted key status: {}", status);
        }
        Ok(())
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Option<String> {
        unsafe {
            let mut cf_error_ptr: *mut CFError = ptr::null_mut();

            log::debug!(
                "Encrypting data size={} with allowed block size {}",
                plaintext.len(),
                self.sec_key.block_size()
            );

            let Some(public_key) = self.sec_key.public_key() else {
                log::debug!("No public key available for encryption");
                return None;
            };

            let res = public_key
                .encrypted_data(alg(), &CFData::from_bytes(plaintext), &mut cf_error_ptr)
                .map(|enc| b64.encode(enc.as_bytes_unchecked()));
            if !cf_error_ptr.is_null() {
                let cf_error = cf_error_ptr.as_ref().unwrap();
                log::debug!(
                    "Error encrypting data (size={}) with key {self:?}: {:?}",
                    plaintext.len(),
                    cf_error
                );
                return None;
            }
            res
        }
    }

    pub fn decrypt(&self, b64_ciphertext: &[u8]) -> Option<Vec<u8>> {
        unsafe {
            let ciphertext = b64.decode(b64_ciphertext).ok()?;
            let ciphertext = &CFData::from_bytes(&ciphertext);
            let mut cf_error_ptr: *mut CFError = ptr::null_mut();
            let res = self
                .sec_key
                .decrypted_data(alg(), ciphertext, &mut cf_error_ptr)
                .map(|data| data.as_bytes_unchecked().to_vec());
            if cf_error_ptr.is_null() {
                res
            } else {
                let cf_error = cf_error_ptr.as_ref().unwrap();
                log::debug!("Error decrypting data with key {self:?}: {:?}", cf_error);
                None
            }
        }
    }
}

impl Debug for ManagedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedKey")
            .field("label", &self.label)
            .field("app_label", &self.app_label())
            .field("tag", &self.tag())
            .field("is_private", &self.is_private())
            .finish()
    }
}
