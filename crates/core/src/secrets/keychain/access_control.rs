use std::ptr;

use anyhow::bail;
use objc2::rc::Retained;
use objc2_core_foundation::CFError;
use objc2_security::{
    SecAccessControl, SecAccessControlCreateFlags, kSecAttrAccessibleWhenUnlocked,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
};

pub enum AccessControl {
    GenericPassword,
    ManagedKey,
}

impl AccessControl {
    pub fn to_sec_access_control(&self) -> anyhow::Result<Retained<SecAccessControl>> {
        let mut cf_error_ptr: *mut CFError = ptr::null_mut();
        let access_control = unsafe {
            // https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/privatekeyusage?language=objc
            match self {
                AccessControl::GenericPassword => SecAccessControl::with_flags(
                    None,
                    // not *thisDeviceOnly to allow password access across device restores
                    kSecAttrAccessibleWhenUnlocked,
                    SecAccessControlCreateFlags::UserPresence,
                    &mut cf_error_ptr,
                ),
                AccessControl::ManagedKey => SecAccessControl::with_flags(
                    None,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    SecAccessControlCreateFlags::UserPresence
                        | SecAccessControlCreateFlags::PrivateKeyUsage,
                    &mut cf_error_ptr,
                ),
            }
        };
        if !cf_error_ptr.is_null() {
            let cf_error = unsafe { &*cf_error_ptr };
            bail!("Failed to create SecAccessControl: {cf_error:?}");
        }
        let Some(access_control) = access_control else {
            bail!("Failed to create SecAccessControl: unknown error");
        };
        Ok(access_control.into())
    }
}
