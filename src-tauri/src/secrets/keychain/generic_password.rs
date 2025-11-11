mod query;

use std::fmt::Debug;
use std::ptr;
use std::str::FromStr;

use anyhow::anyhow;
use objc2::rc::Retained;
use objc2_core_foundation::{CFBoolean, CFData, CFError, CFMutableDictionary, CFString, CFType};
use objc2_security::{
    SecAccessControl, SecAccessControlCreateFlags, SecItemAdd, SecItemDelete, errSecSuccess,
    kSecAttrAccessControl, kSecAttrAccessibleWhenUnlocked, kSecAttrAccount, kSecAttrService,
    kSecClass, kSecClassGenericPassword, kSecUseDataProtectionKeychain, kSecValueData,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::core::la_context::evaluate_local_la_context;
use crate::secrets::keychain::errors::KeychainError;
pub use crate::secrets::keychain::generic_password::query::GenericPasswordQuery;
use crate::secrets::keychain::keychain_query::KeyChainQuery;

static SERVICE_NAME: &str = "com.breakfastlabs.frittata";

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PasswordEntryType {
    #[serde(rename = "gpg_key")]
    GPGKey,
    #[serde(rename = "ssh_key")]
    SSHKey,
    Other,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PasswordEntry {
    pub password_type: PasswordEntryType,
    pub key_id: String, // account
}

impl PasswordEntry {
    pub fn gpg(key_id: &str) -> Self {
        PasswordEntry {
            password_type: PasswordEntryType::GPGKey,
            key_id: key_id.to_string(),
        }
    }

    pub fn ssh(key_id: &str) -> Self {
        PasswordEntry {
            password_type: PasswordEntryType::SSHKey,
            key_id: key_id.to_string(),
        }
    }

    pub fn account(&self) -> String {
        match self.password_type {
            PasswordEntryType::GPGKey => format!("gpg-key-{}", self.key_id),
            PasswordEntryType::SSHKey => format!("ssh-key-{}", self.key_id),
            PasswordEntryType::Other => self.key_id.clone(),
        }
    }

    pub fn delete(&self) -> anyhow::Result<()> {
        unsafe {
            let query = Self::common_attrs(Some(&self.account()));
            let status = SecItemDelete(query.as_opaque());
            log::debug!("Deleted key status: {}", status);
        }
        Ok(())
    }
}

impl FromStr for PasswordEntry {
    type Err = KeychainError;

    fn from_str(account: &str) -> Result<Self, Self::Err> {
        if let Some(key_id) = account.strip_prefix("gpg-key-") {
            Ok(PasswordEntry {
                password_type: PasswordEntryType::GPGKey,
                key_id: key_id.to_string(),
            })
        } else if let Some(key_id) = account.strip_prefix("ssh-key-") {
            Ok(PasswordEntry {
                password_type: PasswordEntryType::SSHKey,
                key_id: key_id.to_string(),
            })
        } else {
            Ok(PasswordEntry {
                password_type: PasswordEntryType::Other,
                key_id: account.to_string(),
            })
        }
    }
}

impl Debug for PasswordEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PasswordEntry")
            .field(&self.password_type)
            .field(&self.key_id)
            .finish()
    }
}

impl PasswordEntry {
    fn common_attrs(account: Option<&str>) -> Retained<CFMutableDictionary<CFString, CFType>> {
        unsafe {
            let query = CFMutableDictionary::<CFString, CFType>::empty();
            query.add(kSecClass, kSecClassGenericPassword);
            if let Some(account) = account {
                query.add(kSecAttrAccount, &CFString::from_str(account));
            }
            query.add(kSecAttrService, &CFString::from_str(SERVICE_NAME));
            query.add(kSecUseDataProtectionKeychain, CFBoolean::new(true));
            query.into()
        }
    }

    pub fn list() -> Result<Vec<PasswordEntry>, KeychainError> {
        evaluate_local_la_context(create_access_control_flags()?)
            .map_err(|e| KeychainError::Generic(anyhow!(e)))?;

        // need authentication: without it, we don't get all items
        let passwords = GenericPasswordQuery::build()
            .list()
            .map_err(|e| KeychainError::Generic(anyhow!(e)))?;

        let entries: Vec<PasswordEntry> = passwords
            .iter()
            .filter_map(|password| password.account.parse().ok())
            .collect();

        log::debug!("Found {} password entries", entries.len());
        Ok(entries)
    }

    pub fn exists(&self) -> Result<bool, KeychainError> {
        log::debug!("Checking if password exists for key_id: {self:?}");
        let res = GenericPasswordQuery::build()
            .with_account(&self.account())
            .without_authentication()
            .one();

        match res {
            Ok(Some(_)) => Ok(true),
            Ok(None) => {
                log::debug!("No password found for key_id: {}", &self.account());
                Ok(false)
            },
            Err(KeychainError::ItemNotAccessible) => Ok(true),
            Err(e) => {
                log::error!("Error checking password existence: {e}");
                Err(anyhow!(e).into())
            },
        }
    }

    pub fn save_password(&self, password: &str) -> Result<(), KeychainError> {
        log::debug!("Saving generic-password for key_id: {self:?}");
        let attrs = Self::common_attrs(Some(&self.account()));
        unsafe {
            attrs.add(kSecAttrAccessControl, &*create_access_control_flags()?);
            attrs.add(kSecValueData, &CFData::from_bytes(password.as_bytes()));
        }
        let res = unsafe {
            // let mut cf_error_ptr: *mut CFError = ptr::null_mut();
            let mut ret: *const CFType = ptr::null();
            SecItemAdd(attrs.as_opaque(), &mut ret)
        };
        if res != errSecSuccess {
            return Err(KeychainError::AddFailed(res.to_string()));
        }
        log::debug!("Password saved successfully to keychain!");
        Ok(())
    }

    pub fn get_password(&self) -> Result<Option<SecretString>, KeychainError> {
        log::debug!("Attempting to retrieve password for key_id: {self:?}");
        GenericPasswordQuery::build()
            .with_account(&self.account())
            .one()
            .map(|opt| opt.map(|entry| entry.password))
    }
}

fn create_access_control_flags() -> Result<Retained<SecAccessControl>, KeychainError> {
    unsafe {
        let mut cf_error_ptr: *mut CFError = ptr::null_mut();
        // https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/privatekeyusage?language=objc
        let access_control = SecAccessControl::with_flags(
            None,
            // not *thisDeviceOnly to allow password access across device restores
            kSecAttrAccessibleWhenUnlocked,
            SecAccessControlCreateFlags::UserPresence,
            &mut cf_error_ptr,
        );
        if !cf_error_ptr.is_null() {
            let cf_error = &*cf_error_ptr;
            return Err(anyhow!("Failed to create SecAccessControl: {cf_error:?}").into());
        }
        let Some(access_control) = access_control else {
            return Err(anyhow!("Failed to create SecAccessControl: unknown error").into());
        };
        Ok(access_control.into())
    }
}
