mod query;
mod shared;

use std::fmt::Debug;
use std::ptr;

use anyhow::bail;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use objc2::rc::Retained;
use objc2_core_foundation::{
    CFArray, CFBoolean, CFData, CFDictionary, CFError, CFMutableDictionary, CFString, CFType, Type,
};
use objc2_security::{
    SecAccessControl, SecAccessControlCreateFlags, SecItemDelete, SecKey, kSecAttrAccessControl,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAttrApplicationLabel, kSecAttrApplicationTag,
    kSecAttrIsPermanent, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel,
    kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecMatchItemList,
    kSecPrivateKeyAttrs, kSecPublicKeyAttrs, kSecUseDataProtectionKeychain,
};
pub use query::ManagedKeyQuery;
pub use shared::KeyClass;

use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::shared::alg;

pub struct ManagedKey {
    pub label: Option<String>,
    sec_key: Retained<SecKey>,
}

impl ManagedKey {
    pub fn common_attrs(label: Option<String>) -> Retained<CFMutableDictionary<CFString, CFType>> {
        let query = CFMutableDictionary::<CFString, CFType>::empty();
        unsafe {
            query.add(kSecClass, kSecClassKey);
            query.add(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            // we store in the data protection keychain (secure enclave)
            query.add(kSecUseDataProtectionKeychain, CFBoolean::new(true));
            if let Some(label) = label {
                query.add(kSecAttrLabel, &CFString::from_str(&label));
            }
        }
        query.into()
    }

    pub fn new(label: Option<String>, sec_key: Retained<SecKey>) -> Self {
        ManagedKey { label, sec_key }
    }

    pub fn create(label: &str) -> Result<ManagedKey, KeychainError> {
        log::debug!("Creating new user key with label: {}", label);
        unsafe {
            let public_attrs = CFMutableDictionary::<CFString, CFType>::empty();
            public_attrs.add(kSecAttrIsPermanent, CFBoolean::new(true));

            let private_attrs = CFMutableDictionary::<CFString, CFType>::empty();
            private_attrs.add(kSecAttrIsPermanent, CFBoolean::new(true));
            private_attrs.add(kSecAttrAccessControl, &*create_access_control_flags()?);

            let query = Self::common_attrs(Some(label.to_string()));
            query.add(kSecPublicKeyAttrs, &public_attrs);
            query.add(kSecPrivateKeyAttrs, &private_attrs);
            query.add(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
            query.add(
                kSecAttrApplicationLabel,
                &CFData::from_bytes(label.as_bytes()),
            );

            let mut cf_error_ptr: *mut CFError = ptr::null_mut();
            log::debug!("Calling SecKey::new_random_key...");
            let sec_key = SecKey::new_random_key(query.as_opaque(), &mut cf_error_ptr);
            if !cf_error_ptr.is_null() {
                let cf_error = &*cf_error_ptr;
                // todo: may need to handle error codes
                log::error!(
                    "Error creating new managed key with label {}: {:?}",
                    label,
                    cf_error
                );
                return Err(KeychainError::Generic(anyhow::anyhow!(
                    cf_error.to_string()
                )));
            }
            let Some(sec_key) = sec_key else {
                return Err(KeychainError::KeyCreationFailed);
            };

            let managed_key = ManagedKey::new(Some(label.to_string()), sec_key.retain().into());
            log::debug!("Created new managed key: {:?}", managed_key);
            Ok(managed_key)
        }
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
            let query = Self::common_attrs(None);
            query.add(kSecMatchItemList, &CFArray::from_objects(&[&*self.sec_key]));
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

fn create_access_control_flags() -> anyhow::Result<Retained<SecAccessControl>> {
    unsafe {
        let mut cf_error_ptr: *mut CFError = ptr::null_mut();
        // https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/privatekeyusage?language=objc
        let access_control = SecAccessControl::with_flags(
            None,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            SecAccessControlCreateFlags::UserPresence
                | SecAccessControlCreateFlags::PrivateKeyUsage,
            &mut cf_error_ptr,
        );
        if !cf_error_ptr.is_null() {
            let cf_error = &*cf_error_ptr;
            bail!("Failed to create SecAccessControl: {cf_error:?}");
        }
        let Some(access_control) = access_control else {
            bail!("Failed to create SecAccessControl: unknown error");
        };
        Ok(access_control.into())
    }
}
