//! Linux stubs for the keychain types.
//!
//! The module paths and signatures match the macOS modules. Every operation
//! fails with [`KeychainError::Unsupported`]. The managed key types cannot be
//! constructed. The TPM and software key stores replace them.

pub mod managed_key {
    use std::convert::Infallible;
    use std::path::PathBuf;

    use ssh_agent_lib::proto;
    use ssh_key::Signature;
    use ssh_key::public::KeyData;
    use zeroize::Zeroizing;

    use crate::secrets::keychain::errors::KeychainError;

    pub use crate::secrets::keychain::sec1_utils as utils;

    /// How a managed key's use is authorized. Fixed when the key is created.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum KeyPolicy {
        Default,
        AlwaysRequireAuth,
    }

    /// A hardware key. No value of this type exists on Linux yet.
    pub struct ManagedKey {
        pub label: Option<String>,
        never: Infallible,
    }

    impl ManagedKey {
        pub fn create(_label: &str, _policy: KeyPolicy) -> Result<ManagedKey, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn create_device_key(_label: &str) -> Result<ManagedKey, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn encrypt_to(_public_sec1: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn app_label(&self) -> Option<String> {
            match self.never {}
        }

        pub fn tag(&self) -> Option<&str> {
            match self.never {}
        }

        pub fn policy(&self) -> KeyPolicy {
            match self.never {}
        }

        pub fn public_key(&self) -> Result<KeyData, KeychainError> {
            match self.never {}
        }

        pub fn public_key_sec1(&self) -> Result<Vec<u8>, KeychainError> {
            match self.never {}
        }

        pub fn delete(&self) -> anyhow::Result<()> {
            match self.never {}
        }

        pub fn encrypt(&self, _plaintext: &[u8]) -> Option<String> {
            match self.never {}
        }

        pub fn decrypt(&self, _b64_ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            match self.never {}
        }

        pub fn decrypt_bytes(&self, _ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            match self.never {}
        }

        pub fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, KeychainError> {
            match self.never {}
        }
    }

    impl std::fmt::Debug for ManagedKey {
        fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.never {}
        }
    }

    /// An SSH key held in a managed key. No value of this type exists on Linux
    /// yet.
    pub struct ManagedSshKey {
        never: Infallible,
    }

    impl ManagedSshKey {
        pub async fn create(_policy: KeyPolicy) -> Result<ManagedSshKey, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn find(_label: &str) -> Result<Option<ManagedSshKey>, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn find_by_pubkey(_pubkey: &KeyData) -> Result<Option<ManagedSshKey>, anyhow::Error> {
            Err(KeychainError::Unsupported.into())
        }

        pub fn list() -> Result<Vec<ManagedSshKey>, anyhow::Error> {
            Err(KeychainError::Unsupported.into())
        }

        pub fn name(&self) -> String {
            match self.never {}
        }

        pub fn label(&self) -> String {
            match self.never {}
        }

        pub fn pubkey_path(&self) -> Result<PathBuf, anyhow::Error> {
            match self.never {}
        }

        pub fn public_key(&self) -> &KeyData {
            match self.never {}
        }

        pub fn policy(&self) -> KeyPolicy {
            match self.never {}
        }

        pub fn public_key_openssh(&self) -> Result<String, anyhow::Error> {
            match self.never {}
        }

        pub fn write_pubkey_file(&self) -> Result<PathBuf, anyhow::Error> {
            match self.never {}
        }

        pub fn fingerprint_sha256(&self) -> String {
            match self.never {}
        }

        pub fn fingerprint_md5(&self) -> String {
            match self.never {}
        }

        pub fn sign(&self, _data: &[u8]) -> Result<Signature, anyhow::Error> {
            match self.never {}
        }

        pub fn delete(&self) -> anyhow::Result<()> {
            match self.never {}
        }

        pub fn delete_capturing(self) -> anyhow::Result<(String, String)> {
            match self.never {}
        }
    }

    impl From<ManagedSshKey> for proto::Identity {
        fn from(val: ManagedSshKey) -> Self {
            match val.never {}
        }
    }
}

pub mod generic_password {
    use std::fmt::Debug;
    use std::str::FromStr;

    use secrecy::SecretString;
    use serde::{Deserialize, Serialize};

    use crate::core::auth::AuthContext;
    use crate::secrets::keychain::errors::KeychainError;

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
        pub key_id: String,
    }

    impl PasswordEntry {
        pub fn gpg(key_id: &str) -> Self {
            Self::of(PasswordEntryType::GPGKey, key_id)
        }

        pub fn ssh(key_id: &str) -> Self {
            Self::of(PasswordEntryType::SSHKey, key_id)
        }

        pub fn age(name: &str) -> Self {
            Self::of(PasswordEntryType::AgeKey, name)
        }

        fn of(password_type: PasswordEntryType, key_id: &str) -> Self {
            PasswordEntry {
                password_type,
                key_id: key_id.to_string(),
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
            Err(KeychainError::Unsupported.into())
        }

        pub fn list() -> Result<Vec<PasswordEntry>, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn list_on(_auth_context: AuthContext) -> Result<Vec<PasswordEntry>, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn exists(&self) -> Result<bool, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn save_password(&self, _password: SecretString) -> Result<(), KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn set_password(&self, _password: SecretString) -> Result<(), KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn get_password(&self) -> Result<Option<SecretString>, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn get_password_for_caller(
            &self,
            _caller: Option<&str>,
        ) -> Result<Option<SecretString>, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn get_password_on(
            &self,
            _auth_context: AuthContext,
            _caller: Option<&str>,
        ) -> Result<Option<SecretString>, KeychainError> {
            Err(KeychainError::Unsupported)
        }
    }

    impl FromStr for PasswordEntry {
        type Err = KeychainError;

        fn from_str(account: &str) -> Result<Self, Self::Err> {
            for (prefix, password_type) in [
                ("gpg-key-", PasswordEntryType::GPGKey),
                ("ssh-key-", PasswordEntryType::SSHKey),
                ("age-key-", PasswordEntryType::AgeKey),
            ] {
                if let Some(key_id) = account.strip_prefix(prefix) {
                    return Ok(Self::of(password_type, key_id));
                }
            }
            Ok(Self::of(PasswordEntryType::Other, account))
        }
    }

    impl Debug for PasswordEntry {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("PasswordEntry")
                .field(&self.password_type)
                .field(&format!("{}...", &self.key_id[..6]))
                .finish()
        }
    }
}

pub mod plain_item {
    use crate::secrets::keychain::errors::KeychainError;

    pub struct PlainItem;

    impl PlainItem {
        pub fn new(_service: &'static str, _account: &str) -> Self {
            PlainItem
        }

        pub fn read(&self) -> Result<Option<Vec<u8>>, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn write(&self, _value: &[u8]) -> Result<(), KeychainError> {
            Err(KeychainError::Unsupported)
        }

        pub fn delete(&self) -> Result<(), KeychainError> {
            Err(KeychainError::Unsupported)
        }
    }
}
