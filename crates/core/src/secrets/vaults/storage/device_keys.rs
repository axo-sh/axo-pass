#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

use std::path::{Path, PathBuf};
use std::{fs, io};

use anyhow::anyhow;
use jiff::Zoned;
#[cfg(linux)]
use linux as platform;
#[cfg(macos)]
use macos as platform;
pub(super) use platform::probe_vault_encryption_key;

use crate::core::auth::AuthContext;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::txn::VERSIONS_DIR;
use crate::secrets::vaults::storage::unreadable::Unreadable;
use crate::secrets::vaults::sync::local_state::SYNC_DIR;
use crate::secrets::vaults::sync::model::ReplicaKeys;
use crate::secrets::vaults::sync::pairing::dismissed::DismissedRequests;

/// Name of the vaults directory under the app data directory.
pub(super) const VAULTS_DIR: &str = "vaults";

/// Keychain label of the vault encryption key.
pub(super) const VAULT_ENCRYPTION_KEY_LABEL: &str = "vault-encryption-key";

#[cfg(test)]
mod tests;

/// Result of a probe for one Secure Enclave key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KeyProbe {
    Present,
    Missing,
    /// Any keychain error other than item not found.
    Error(String),
}

impl KeyProbe {
    /// Classify the result of a keychain query made with interaction not
    /// allowed. A key gated by authentication exists, so it is `Present`.
    pub fn of<T>(result: Result<Option<T>, KeychainError>) -> Self {
        match result {
            Ok(Some(_)) | Err(KeychainError::ItemNotAccessible) => Self::Present,
            Ok(None) => Self::Missing,
            Err(e) => Self::Error(e.to_string()),
        }
    }

    /// Whether the key is missing. A probe error fails. The Linux stub does
    /// not create keys, so only the macOS key store and the test keys call it.
    #[allow(dead_code)]
    pub(super) fn is_missing(&self) -> Result<bool, Error> {
        match self {
            Self::Present => Ok(false),
            Self::Missing => Ok(true),
            Self::Error(message) => Err(Self::failure(message)),
        }
    }

    /// Keychain failure with the text of a probe error.
    pub(super) fn failure(message: &str) -> Error {
        Error::KeyRetrievalFailed(KeychainError::Generic(anyhow!("{message}")))
    }
}

/// The two Secure Enclave keys of this Mac, `vault-encryption-key` and
/// `device-signing-key`. Implemented as a trait so tests do not read the
/// keychain.
pub(crate) trait DeviceKeys: Send + Sync {
    /// Look for `vault-encryption-key` without a prompt.
    fn probe_encryption_key(&self) -> KeyProbe;

    /// Look for `device-signing-key` without a prompt.
    fn probe_signing_key(&self) -> KeyProbe;

    /// Read `vault-encryption-key` on `context`. `None` if the key does not
    /// exist. This never creates a key.
    fn read_encryption_key(&self, context: AuthContext) -> Result<Option<ManagedKey>, Error>;

    /// Create each key that is missing, on `context`. Only
    /// [`ensure_device_keys`] calls this.
    fn create_keys(&self, context: AuthContext) -> Result<(), Error>;

    /// Create `device-signing-key`, which is missing. Only the confirmed
    /// re-sign calls this.
    fn create_signing_key(&self) -> Result<(), Error>;

    /// Public keys of `vault-encryption-key` and `device-signing-key`, as
    /// uncompressed SEC1 bytes. Reads `vault-encryption-key` on `context`,
    /// which can prompt. Fails if a key is missing. This never creates a key.
    fn public_keys(&self, context: AuthContext) -> Result<ReplicaKeys, Error>;
}

/// The keys in the keychain.
pub(super) struct KeychainKeys;

/// Where vault files of this Mac are found.
#[derive(Clone, Debug)]
pub(crate) struct VaultFiles {
    /// App data directory.
    root: PathBuf,
    vaults: PathBuf,
    versions: PathBuf,
    sync: PathBuf,
    /// Paths of the external vaults that the app config lists.
    external: Vec<PathBuf>,
}

impl VaultFiles {
    /// Files in `vaults`, in `versions` and `sync` under the app data
    /// directory `root`, and the listed `external` vaults.
    pub fn new(vaults: PathBuf, root: &Path, external: Vec<PathBuf>) -> Self {
        Self {
            root: root.to_path_buf(),
            vaults,
            versions: root.join(VERSIONS_DIR),
            sync: root.join(SYNC_DIR),
            external,
        }
    }

    /// App data directory.
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    /// Directories of the vault files of this Mac, with the name of each
    /// under `unreadable/{date}/`. External vaults are not included.
    pub(super) fn dirs(&self) -> [(&'static str, &Path); 3] {
        [
            (VAULTS_DIR, &self.vaults),
            (VERSIONS_DIR, &self.versions),
            (SYNC_DIR, &self.sync),
        ]
    }

    /// Whether `vaults/`, `versions/`, or `sync/` holds a file, or a listed
    /// external vault file exists. A path that cannot be read counts as
    /// present, so no key is created for it. `sync/pairing.json`, the
    /// dismissed pairing requests, is not a vault file.
    pub fn present(&self) -> bool {
        let dismissed = DismissedRequests::path(&self.root);
        self.external.iter().any(|path| Self::exists(path))
            || self
                .dirs()
                .into_iter()
                .any(|(_, dir)| Self::holds_file(dir, &dismissed))
    }

    // MIGRATE_V1
    /// Whether `versions/` or `sync/` holds a file. A Mac that only ever ran
    /// 0.2.0 has neither, so no file on it was signed. A path that cannot be
    /// read counts as present.
    pub(super) fn holds_saved_state(&self) -> bool {
        let dismissed = DismissedRequests::path(&self.root);
        [&self.versions, &self.sync]
            .into_iter()
            .any(|dir| Self::holds_file(dir, &dismissed))
    }

    /// Whether `path` exists. Only a not found error counts as absent.
    fn exists(path: &Path) -> bool {
        match fs::metadata(path) {
            Ok(_) => true,
            Err(e) => e.kind() != io::ErrorKind::NotFound,
        }
    }

    /// Whether `dir` holds a file at any depth other than the file `ignored`.
    fn holds_file(dir: &Path, ignored: &Path) -> bool {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return false,
            Err(_) => return true,
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return true;
            };
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => {
                    if Self::holds_file(&entry.path(), ignored) {
                        return true;
                    }
                },
                _ if entry.path() == ignored => {},
                _ => return true,
            }
        }
        false
    }
}

/// Key state of this Mac, classified at launch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum KeyState {
    /// Vault files and both keys are present.
    #[default]
    Normal,
    /// No vault file exists. Creating the first vault or importing creates
    /// the missing keys.
    NoVaultFiles,
    /// Vault files and `vault-encryption-key` are present, and
    /// `device-signing-key` is missing.
    SigningKeyLost,
    /// Vault files are present and `vault-encryption-key` is missing.
    /// `Unreadable::synced_vaults` lists the synced vaults by their
    /// unverified sync states.
    NewHardware,
    /// A probe failed with a keychain error other than item not found.
    KeychainError(String),
}

impl KeyState {
    /// Classify the keys against the vault files. A probe error gives
    /// `KeychainError`, whatever the files are.
    pub(crate) fn probe(keys: &dyn DeviceKeys, files: &VaultFiles) -> Self {
        let encryption = keys.probe_encryption_key();
        let signing = keys.probe_signing_key();
        for probe in [&encryption, &signing] {
            if let KeyProbe::Error(message) = probe {
                return Self::KeychainError(message.clone());
            }
        }
        if !files.present() {
            return Self::NoVaultFiles;
        }
        match (encryption, signing) {
            (KeyProbe::Present, KeyProbe::Present) => Self::Normal,
            (KeyProbe::Present, _) => Self::SigningKeyLost,
            _ => Self::NewHardware,
        }
    }
}

/// What [`ensure_device_keys`] does on new hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OnNewHardware {
    /// Fail with `Error::NewHardware`, as an import does.
    Fail,
    /// Move the vault files to `unreadable/`, then create the missing keys,
    /// as creating a vault, pairing, and the recovery kit do.
    MoveFiles,
}

/// Create the missing keys on `context` if no vault file exists. This is the
/// only policy that creates keys. Creating the first vault and an import call
/// this.
///
/// With vault files and both keys present, nothing is created. `NewHardware`
/// fails with `Error::NewHardware` if `on_new_hardware` is `Fail`. If it is
/// `MoveFiles`, every file under `vaults/`, `versions/`, and `sync/` moves to
/// `unreadable/` first ([`Unreadable::move_all`]), and the missing keys are
/// then created. A failed move creates no key. `SigningKeyLost` fails with
/// `SigningKeyNotFound`, and the re-sign creates that key. A keychain error
/// fails with it.
pub(crate) fn ensure_device_keys(
    keys: &dyn DeviceKeys,
    files: &VaultFiles,
    context: AuthContext,
    on_new_hardware: OnNewHardware,
) -> Result<(), Error> {
    match KeyState::probe(keys, files) {
        KeyState::NoVaultFiles => keys.create_keys(context),
        KeyState::Normal => Ok(()),
        KeyState::NewHardware => match on_new_hardware {
            OnNewHardware::Fail => Err(Error::NewHardware),
            OnNewHardware::MoveFiles => {
                Unreadable::move_all(files, Zoned::now().date())?;
                keys.create_keys(context)
            },
        },
        KeyState::SigningKeyLost => Err(Error::SigningKeyNotFound),
        KeyState::KeychainError(message) => Err(KeyProbe::failure(&message)),
    }
}
