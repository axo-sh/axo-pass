//! A data-protection keychain generic-password item with no access control.
//!
//! Only code signed into this app's keychain access group can read or write
//! it, so it holds data that must not be user-editable but needs no prompt to
//! read, unlike [`super::generic_password::PasswordEntry`], which always
//! attaches a user-presence access control.

use std::ptr::{self, NonNull};

use anyhow::anyhow;
use objc2::rc::Retained;
use objc2_core_foundation::{CFBoolean, CFData, CFMutableDictionary, CFRetained, CFString, CFType};
use objc2_security::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate, errSecItemNotFound,
    errSecSuccess, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecMatchLimit,
    kSecMatchLimitOne, kSecReturnData, kSecUseDataProtectionKeychain, kSecValueData,
};

use crate::secrets::keychain::errors::KeychainError;

pub struct PlainItem {
    service: &'static str,
    account: String,
}

impl PlainItem {
    pub fn new(service: &'static str, account: &str) -> Self {
        PlainItem {
            service,
            account: account.to_string(),
        }
    }

    fn query(&self) -> Retained<CFMutableDictionary<CFString, CFType>> {
        unsafe {
            let query = CFMutableDictionary::<CFString, CFType>::empty();
            query.add(kSecClass, kSecClassGenericPassword);
            query.add(kSecAttrService, &CFString::from_str(self.service));
            query.add(kSecAttrAccount, &CFString::from_str(&self.account));
            query.add(kSecUseDataProtectionKeychain, CFBoolean::new(true));
            query.into()
        }
    }

    /// The item's value, or `None` when the item does not exist.
    pub fn read(&self) -> Result<Option<Vec<u8>>, KeychainError> {
        unsafe {
            let query = self.query();
            query.add(kSecReturnData, CFBoolean::new(true));
            query.add(kSecMatchLimit, kSecMatchLimitOne);

            let mut ret: *const CFType = ptr::null();
            let status = SecItemCopyMatching(query.as_opaque(), &mut ret);
            if status == errSecItemNotFound {
                return Ok(None);
            }
            if status != errSecSuccess {
                return Err(anyhow!("keychain read failed: {status}").into());
            }
            let Some(ret) = NonNull::new(ret.cast_mut()) else {
                return Ok(None);
            };
            // SecItemCopyMatching follows the Create Rule.
            let ret = CFRetained::from_raw(ret);
            let Some(data) = ret.downcast_ref::<CFData>() else {
                return Err(anyhow!("keychain item value is not data").into());
            };
            Ok(Some(data.to_vec()))
        }
    }

    /// Replace the item's value, creating the item if it does not exist.
    pub fn write(&self, value: &[u8]) -> Result<(), KeychainError> {
        unsafe {
            let data = CFData::from_bytes(value);

            let update = CFMutableDictionary::<CFString, CFType>::empty();
            update.add(kSecValueData, &data);
            let status = SecItemUpdate(self.query().as_opaque(), update.as_opaque());
            if status == errSecSuccess {
                return Ok(());
            }
            if status != errSecItemNotFound {
                return Err(KeychainError::AddFailed(status.to_string()));
            }

            let attrs = self.query();
            attrs.add(
                kSecAttrAccessible,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            );
            attrs.add(kSecValueData, &data);
            let mut ret: *const CFType = ptr::null();
            let status = SecItemAdd(attrs.as_opaque(), &mut ret);
            if status != errSecSuccess {
                return Err(KeychainError::AddFailed(status.to_string()));
            }
            Ok(())
        }
    }

    pub fn delete(&self) -> Result<(), KeychainError> {
        let status = unsafe { SecItemDelete(self.query().as_opaque()) };
        if status == errSecSuccess || status == errSecItemNotFound {
            Ok(())
        } else {
            Err(anyhow!("keychain delete failed: {status}").into())
        }
    }
}
