//! Storage of the S3 settings and key.
//!
//! The sync agent merges without decrypting, so a store must be readable
//! without a vault unlock. [`KeychainCredentialStore`] is the macOS store. A
//! Linux store sealed to the TPM is milestone M7 and is not implemented.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use super::config::S3Config;
use crate::secrets::vaults::errors::Error;

/// Store of the [`S3Config`] of each S3 location, by name.
pub trait S3CredentialStore: fmt::Debug + Send + Sync {
    /// Config saved under `name`. `None` if there is none.
    fn load(&self, name: &str) -> Result<Option<S3Config>, Error>;
    /// Save `config` under `name`, replacing an earlier one.
    fn save(&self, name: &str, config: &S3Config) -> Result<(), Error>;
    /// Delete the config under `name`. A missing config is not an error.
    fn delete(&self, name: &str) -> Result<(), Error>;
}

/// Store in memory, for tests and for a location that is not saved.
#[derive(Debug, Default)]
pub struct MemoryCredentialStore {
    configs: Mutex<BTreeMap<String, S3Config>>,
}

impl S3CredentialStore for MemoryCredentialStore {
    fn load(&self, name: &str) -> Result<Option<S3Config>, Error> {
        Ok(self.configs.lock().unwrap().get(name).cloned())
    }

    fn save(&self, name: &str, config: &S3Config) -> Result<(), Error> {
        self.configs
            .lock()
            .unwrap()
            .insert(name.to_string(), config.clone());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<(), Error> {
        self.configs.lock().unwrap().remove(name);
        Ok(())
    }
}

/// Store of this platform. `None` where none is implemented, which is every
/// platform but macOS until milestone M7.
pub fn default_credential_store() -> Option<Box<dyn S3CredentialStore>> {
    #[cfg(target_os = "macos")]
    {
        Some(Box::new(KeychainCredentialStore))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
pub use self::keychain::KeychainCredentialStore;

#[cfg(target_os = "macos")]
mod keychain {
    use zeroize::Zeroizing;

    use super::{S3Config, S3CredentialStore};
    use crate::secrets::keychain::errors::KeychainError;
    use crate::secrets::keychain::plain_item::PlainItem;
    use crate::secrets::vaults::errors::Error;

    /// Keychain service of the S3 settings.
    const SERVICE: &str = "com.breakfastlabs.frittata.s3";

    /// Store in the data protection keychain, in the keychain access group
    /// of the app. An item has no access control, so it is readable without
    /// a prompt and without a vault unlock. Only code signed into the access
    /// group can read or write it.
    #[derive(Debug, Default)]
    pub struct KeychainCredentialStore;

    impl KeychainCredentialStore {
        fn item(name: &str) -> PlainItem {
            PlainItem::new(SERVICE, name)
        }

        fn error(action: &str, e: KeychainError) -> Error {
            Error::SyncTransportError(format!("Failed to {action} S3 settings in keychain: {e}"))
        }
    }

    impl S3CredentialStore for KeychainCredentialStore {
        fn load(&self, name: &str) -> Result<Option<S3Config>, Error> {
            let bytes = Self::item(name)
                .read()
                .map_err(|e| Self::error("read", e))?
                .map(Zeroizing::new);
            bytes.map(|bytes| S3Config::from_bytes(&bytes)).transpose()
        }

        fn save(&self, name: &str, config: &S3Config) -> Result<(), Error> {
            Self::item(name)
                .write(&config.to_bytes()?)
                .map_err(|e| Self::error("write", e))
        }

        fn delete(&self, name: &str) -> Result<(), Error> {
            Self::item(name)
                .delete()
                .map_err(|e| Self::error("delete", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, SecretString};

    use super::*;

    fn config() -> S3Config {
        S3Config::new(
            "key",
            SecretString::from("secret"),
            "https://s3.example.com",
            "auto",
            "bucket",
            "ap",
        )
        .unwrap()
    }

    #[test]
    fn memory_store_saves_replaces_and_deletes() {
        let store = MemoryCredentialStore::default();
        assert!(store.load("a").unwrap().is_none());

        store.save("a", &config()).unwrap();
        let loaded = store.load("a").unwrap().unwrap();
        assert_eq!(loaded.secret_access_key.expose_secret(), "secret");
        assert!(store.load("b").unwrap().is_none());

        store.delete("a").unwrap();
        store.delete("a").unwrap();
        assert!(store.load("a").unwrap().is_none());
    }
}
