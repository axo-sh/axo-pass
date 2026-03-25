mod query;

use std::fmt::Debug;
use std::ptr;
use std::str::FromStr;

use anyhow::anyhow;
use objc2::rc::Retained;
use objc2_core_foundation::{CFBoolean, CFData, CFMutableDictionary, CFString, CFType};
use objc2_local_authentication::LAAccessControlOperation;
use objc2_security::{
    SecItemAdd, SecItemDelete, errSecSuccess, kSecAttrAccessControl, kSecAttrAccount,
    kSecAttrService, kSecClass, kSecClassGenericPassword, kSecUseDataProtectionKeychain,
    kSecValueData,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::core::auth::{AuthContext, AuthMethod, run_local_onetime, run_on_auth_thread};
use crate::secrets::keychain::access_control::AccessControl;
use crate::secrets::keychain::errors::KeychainError;
pub use crate::secrets::keychain::generic_password::query::GenericPasswordQuery;
use crate::secrets::keychain::keychain_query::KeychainQuery;

static SERVICE_NAME: &str = "com.breakfastlabs.frittata";

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PasswordEntryType {
    #[serde(rename = "gpg_key")]
    GPGKey,
    #[serde(rename = "ssh_key")]
    SSHKey,
    #[serde(rename = "age_key")]
    AgeKey,
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

    pub fn age(name: &str) -> Self {
        PasswordEntry {
            password_type: PasswordEntryType::AgeKey,
            key_id: name.to_string(),
        }
    }

    pub fn account(&self) -> String {
        match self.password_type {
            PasswordEntryType::GPGKey => format!("gpg-key-{}", self.key_id),
            PasswordEntryType::SSHKey => format!("ssh-key-{}", self.key_id),
            PasswordEntryType::AgeKey => format!("age-key-{}", self.key_id),
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
        } else if let Some(key_id) = account.strip_prefix("age-key-") {
            Ok(PasswordEntry {
                password_type: PasswordEntryType::AgeKey,
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
            .field(&format!("{}...", &self.key_id[..6])) // truncated
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
        // needs authentication: without it, we don't get all items
        run_on_auth_thread(
            AuthContext::SharedThreadLocal,
            AuthMethod::AccessControl {
                access_control: AccessControl::GenericPassword,
                operation: LAAccessControlOperation::UseItem,
                reason: "unlock to list passwords".to_string(),
            },
            |la_context| {
                let passwords = GenericPasswordQuery::build()
                    .list(la_context)
                    .map_err(|e| KeychainError::Generic(anyhow!(e)))?;
                let entries: Vec<PasswordEntry> = passwords
                    .iter()
                    .filter_map(|password| password.account.parse().ok())
                    .collect();
                log::debug!("Found {} password entries", entries.len());
                Ok(entries)
            },
        )
        .flatten()
    }

    pub fn exists(&self) -> Result<bool, KeychainError> {
        let account = self.account();
        let res = run_local_onetime(move |la_context| {
            GenericPasswordQuery::build()
                .with_account(&account)
                .without_authentication()
                .one(la_context)
        });

        // account was moved in the loop, so get a new clone
        let account = self.account();
        match res {
            Ok(Some(_)) => {
                log::debug!("{account}: Found entry");
                Ok(true)
            },
            Ok(None) => {
                log::debug!("{account}: Entry not found");
                Ok(false)
            },
            Err(KeychainError::ItemNotAccessible) => {
                // entry exists but we have not unlocked it
                log::debug!("{account}: Found entry but not accessible");
                Ok(true)
            },
            Err(e) => {
                log::error!("{account}: Entry error {e}");
                Err(anyhow!(e).into())
            },
        }
    }

    pub fn save_password(&self, password: SecretString) -> Result<(), KeychainError> {
        log::debug!(
            "Saving {:?}({}) as generic-password",
            self.password_type,
            self.key_id
        );
        let attrs = Self::common_attrs(Some(&self.account()));
        let access_control = AccessControl::GenericPassword.to_sec_access_control()?;
        unsafe {
            attrs.add(kSecAttrAccessControl, &*access_control);
            attrs.add(
                kSecValueData,
                &CFData::from_bytes(password.expose_secret().as_bytes()),
            );
        }
        let res = unsafe {
            let mut ret: *const CFType = ptr::null();
            SecItemAdd(attrs.as_opaque(), &mut ret)
        };
        if res != errSecSuccess {
            return Err(KeychainError::AddFailed(res.to_string()));
        }
        log::debug!("{:?} saved successfully to keychain", self.password_type);
        Ok(())
    }

    pub fn get_password(&self) -> Result<Option<SecretString>, KeychainError> {
        log::debug!("Attempting to retrieve password for key_id: {self:?}");
        let account = self.account();
        // todo: always prompt here? with OneTime
        run_on_auth_thread(
            AuthContext::SharedThreadLocal,
            AuthMethod::AccessControl {
                access_control: AccessControl::GenericPassword,
                operation: LAAccessControlOperation::UseItem,
                reason: format!("unlock to access password for {account}"),
            },
            move |la_context| {
                GenericPasswordQuery::build()
                    .with_account(&account)
                    .one(la_context)
                    .map(|opt| opt.map(|entry| entry.password))
            },
        )
        .flatten()
    }
}
