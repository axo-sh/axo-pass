use anyhow::bail;
use objc2::rc::Retained;
use objc2_security::{
    SecAccessControl, SecAccessControlCreateFlags, kSecAttrAccessibleWhenUnlocked,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
};

use crate::secrets::keychain::macos::CFErrorOut;

pub enum AccessControl {
    GenericPassword,
    /// The Secure Enclave requires user presence for every use of the key.
    ManagedKey,
    /// The Secure Enclave only restricts the key to this device. The app gates
    /// each use itself, which lets it skip the prompt for a granted app.
    ManagedKeyAppEnforced,
}

impl AccessControl {
    pub fn to_sec_access_control(&self) -> anyhow::Result<Retained<SecAccessControl>> {
        let mut cf_error = CFErrorOut::new();
        let access_control = unsafe {
            // https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/privatekeyusage?language=objc
            match self {
                AccessControl::GenericPassword => SecAccessControl::with_flags(
                    None,
                    // not *thisDeviceOnly to allow password access across device restores
                    kSecAttrAccessibleWhenUnlocked,
                    SecAccessControlCreateFlags::UserPresence,
                    cf_error.out(),
                ),
                AccessControl::ManagedKey => SecAccessControl::with_flags(
                    None,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    SecAccessControlCreateFlags::UserPresence
                        | SecAccessControlCreateFlags::PrivateKeyUsage,
                    cf_error.out(),
                ),
                AccessControl::ManagedKeyAppEnforced => SecAccessControl::with_flags(
                    None,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    SecAccessControlCreateFlags::PrivateKeyUsage,
                    cf_error.out(),
                ),
            }
        };
        if let Some(cf_error) = cf_error.get() {
            bail!("Failed to create SecAccessControl: {cf_error:?}");
        }
        let Some(access_control) = access_control else {
            bail!("Failed to create SecAccessControl: unknown error");
        };
        Ok(access_control.into())
    }
}
