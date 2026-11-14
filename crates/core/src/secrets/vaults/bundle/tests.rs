use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::ExposeSecret;
use tempfile::TempDir;
use uuid::Uuid;

use crate::secrets::vaults::bundle::export_mode::ExportMode;
use crate::secrets::vaults::bundle::exported_bundle::{
    BUNDLE_VERSION, BundledVault, ExportedBundle, RawFileKey,
};
use crate::secrets::vaults::bundle::import_identity::ImportIdentity;
use crate::secrets::vaults::bundle::{
    ImportAction, ImportSelection, ImportableBundle, PreparedVault,
};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultFileKey};
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::Vault;

mod export;
mod files;
mod format;
mod import;
mod wrapping;

/// New random bundle key.
fn bundle_key() -> aes_gcm::Key<Aes256Gcm> {
    Aes256Gcm::generate_key(aes_gcm::aead::OsRng)
}

/// Build a bundle with `count` vaults, each carrying a distinct 32-byte file
/// key, and serialize it to JSON.
fn make_bundle_json(count: usize) -> (String, Uuid, Vec<Vec<u8>>) {
    let bundle_id = Uuid::new_v4();
    let bundle_key = bundle_key();
    let bundle_cipher = Aes256Gcm::new(&bundle_key);

    let mut file_keys = Vec::new();
    let mut vaults = Vec::new();
    for i in 0..count {
        let vault_id = Uuid::new_v4();
        let file_key: Vec<u8> = (0..32).map(|b| b ^ i as u8).collect();
        file_keys.push(file_key.clone());
        let wrapped_file_key = EncryptedBlob::encrypt(
            &RawFileKey(file_key),
            &bundle_cipher,
            ExportedBundle::file_key_aad(bundle_id, vault_id),
        )
        .unwrap();
        vaults.push(BundledVault {
            id: vault_id,
            name: Some(format!("vault {i}")),
            default_key: (i > 0).then(|| format!("vault-{i}")),
            wrapped_file_key,
            metadata: None,
            items: BTreeMap::new(),
            blobs: BTreeMap::new(),
        });
    }

    let age_bundle_key = ExportMode::passphrase("pw")
        .encrypt(bundle_key.as_slice())
        .unwrap();

    let bundle = ExportedBundle {
        version: BUNDLE_VERSION,
        id: bundle_id,
        exported_at: time::OffsetDateTime::now_utc(),
        age_bundle_key,
        vaults,
    };
    (
        serde_json::to_string_pretty(&bundle).unwrap(),
        bundle_id,
        file_keys,
    )
}

/// Vault with the entries of [`Vault::fill_for_test`], saved and loaded under
/// its own file key, so its caches hold the blobs of the file.
fn filled_vault() -> Vault {
    let mut vault = Vault::new_for_test();
    vault.fill_for_test();
    let cipher = vault.unlocked_key().cipher_for_test();
    Vault::from_encrypted_with_cipher(cipher, vault.to_encrypted(true).unwrap()).unwrap()
}

/// Raw file key of `vault`.
fn file_key_of(vault: &Vault) -> Vec<u8> {
    vault.unlocked_key().cipher_for_test().key_bytes_for_test()
}

/// Bundle file of one exported vault, and the identity that opens it.
struct ExportFile {
    _dir: TempDir,
    path: PathBuf,
    identity: age::x25519::Identity,
}

impl ExportFile {
    /// Export `vault` to a bundle file in a temp directory.
    fn new(vault: &Vault, include_passkeys: bool) -> Self {
        let bundle_id = Uuid::new_v4();
        let bundle_key = bundle_key();
        let bundled = vault
            .to_bundled_vault(
                None,
                bundle_id,
                &Aes256Gcm::new(&bundle_key),
                include_passkeys,
            )
            .unwrap();
        let identity = age::x25519::Identity::generate();
        let export_mode = ExportMode::Recipient(identity.to_public().to_string());
        let bundle = ExportedBundle {
            version: BUNDLE_VERSION,
            id: bundle_id,
            exported_at: time::OffsetDateTime::now_utc(),
            age_bundle_key: export_mode.encrypt(bundle_key.as_slice()).unwrap(),
            vaults: vec![bundled],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.axovault");
        fs::write(&path, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();
        Self {
            _dir: dir,
            path,
            identity,
        }
    }

    /// Open the bundle file through [`ImportableBundle::open`].
    fn open_bundle(&self) -> ImportableBundle {
        let identity = ImportIdentity::Identity(self.identity.clone());
        ImportableBundle::open(&self.path, identity).unwrap()
    }

    /// Open the bundle file and take its one vault.
    fn open(&self) -> PreparedVault {
        self.open_bundle().vaults.into_iter().next().unwrap()
    }
}

/// Cipher of the file key an opened bundle vault holds.
fn export_cipher(prepared: &PreparedVault) -> VaultCipher {
    VaultCipher::new_with_bytes(prepared.raw_file_key.expose_secret(), prepared.id)
}

/// Check that `cipher` decrypts every live blob of a vault filled by
/// [`Vault::fill_for_test`] if `decrypts` is set, and none of them otherwise.
/// `encrypted` holds no deleted entries.
fn assert_live_blobs_decrypt(cipher: &VaultCipher, encrypted: &EncryptedVault, decrypts: bool) {
    let results = cipher.blob_results_for_test(encrypted);
    let kinds: Vec<&str> = results.keys().map(String::as_str).collect();
    assert_eq!(
        kinds,
        [
            "live: credential metadata",
            "live: history metadata",
            "live: history value",
            "live: item autofill",
            "live: item metadata",
            "live: value",
            "live: vault metadata",
        ]
    );
    for (kind, oks) in &results {
        assert!(oks.iter().all(|ok| *ok == decrypts), "{kind}: {oks:?}");
    }
}

/// Selection of a vault imported under its bundle id as `key`.
fn import_as(key: &str) -> ImportSelection {
    ImportSelection::new(key, ImportAction::Default)
}

/// File key wrapper that stores the raw key as is.
fn plain_wrap(raw: &[u8]) -> Result<VaultFileKey, Error> {
    Ok(VaultFileKey::new(raw.to_vec()))
}
