//! Confirmed re-sign after signing key loss.
//!
//! If vault files and `vault-encryption-key` are present and
//! `device-signing-key` is missing, every vault file fails verification and
//! still decrypts. Launch creates no key. After the user confirms, the
//! re-sign creates `device-signing-key` and signs every vault file and every
//! retained version again. Invalid files are not signed again.
//!
//! Local sync states are not signed again. Re-signing a sync state that
//! failed verification would accept a planted `sync_keys` entry. A synced
//! vault then loads with a failed sync state signature, sync stops, and the
//! re-link of milestone 10 takes a new replica id.
//!
//! Known limit: the re-sign accepts the `file_key` each vault holds at that
//! time, including one planted while the key was missing.

use std::collections::BTreeMap;
use std::path::PathBuf;

use uuid::Uuid;

use crate::audit::{self, Action, AuditEvent, Outcome};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::catalog::VaultCatalog;
use crate::secrets::vaults::storage::device_keys::{DeviceKeys, KeyProbe, KeyState};
use crate::secrets::vaults::storage::handle::VaultHandle;

#[cfg(test)]
mod tests;

/// Files of a re-sign.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resigned {
    /// Number of vault files and retained versions signed again.
    pub signed: usize,
    /// Files left unchanged, because they do not hold their vault or failed
    /// to be read or written.
    pub skipped: Vec<PathBuf>,
}

impl Resigned {
    fn add(&mut self, other: Resigned) {
        self.signed += other.signed;
        self.skipped.extend(other.skipped);
    }
}

/// Confirmed re-sign.
pub(super) struct Resign;

impl Resign {
    /// Check the key state again, create `device-signing-key` with `keys`,
    /// and sign again every vault file that `catalog` reads, internal and
    /// external, and every retained version that `VersionsDir::list` returns,
    /// with the signer of the catalog writer. Each vault is signed under its
    /// vault locks. Records one `vault.resigned` event.
    ///
    /// Fails with `ResignNotOffered` and changes nothing unless the state is
    /// `SigningKeyLost`. With `device-signing-key` present, a failed
    /// signature is never overridden. A keychain error fails with it. A
    /// failed key creation changes no file.
    pub(super) fn confirm(
        keys: &dyn DeviceKeys,
        catalog: &VaultCatalog,
    ) -> Result<Resigned, Error> {
        match KeyState::probe(keys, &catalog.vault_files()) {
            KeyState::SigningKeyLost => {},
            KeyState::KeychainError(message) => return Err(KeyProbe::failure(&message)),
            _ => return Err(Error::ResignNotOffered),
        }
        keys.create_signing_key()?;

        let writer = catalog.files();
        let mut vaults: BTreeMap<Uuid, Vec<PathBuf>> = BTreeMap::new();
        for (id, vh) in catalog.read_all() {
            vaults.entry(id).or_default().push(vh.path);
        }
        for id in writer.version_ids() {
            vaults.entry(id).or_default();
        }
        let mut resigned = Resigned::default();
        for (id, paths) in vaults {
            let path = paths
                .first()
                .cloned()
                .unwrap_or_else(|| VaultHandle::file_path(catalog.vaults_dir(), id));
            resigned.add(writer.resign(id, &path, &paths));
        }
        Self::record(&resigned);
        log::info!(
            "Signed {} vault files again, skipped {:?}",
            resigned.signed,
            resigned.skipped
        );
        Ok(resigned)
    }

    fn record(resigned: &Resigned) {
        audit::record(
            AuditEvent::new(
                audit::process_source(),
                Action::VaultResigned,
                Outcome::Succeeded,
            )
            .detail("file_count", resigned.signed.to_string())
            .detail("skipped_count", resigned.skipped.len().to_string()),
        );
    }
}
