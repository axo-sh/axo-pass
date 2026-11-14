//! File credentials do not sync yet: a synced vault refuses them, sync is
//! not enabled for a vault that holds one, and the vault still syncs its
//! other changes.

use std::path::PathBuf;
use std::sync::Arc;

use secrecy::SecretString;

use super::load::{Fixture, GENERATION, sync_files};
use super::transport::FakeTransport;
use super::txn::{saved, synced};
use crate::secrets::vaults::files::{self, FileInput};
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::storage::txn::{Target, Unlock};
use crate::secrets::vaults::sync::setup::{SetupStart, SyncSetup};
use crate::secrets::vaults::sync::transport::TransportRoot;
use crate::secrets::vaults::{Error, VaultHandle};

/// Add item `item` with a file credential `doc` whose value is `value`,
/// written directly, without a blob.
fn add_file_credential(vh: &mut VaultHandle, value: &str) -> Result<(), Error> {
    vh.add_item("item", "Item")?;
    vh.add_new_secret(
        "item",
        "doc",
        "Doc",
        FieldKind::File,
        SecretString::from(value.to_string()),
    )
}

#[test]
fn synced_vault_refuses_file_credential_and_still_syncs_other_changes() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let before = fx.on_disk();

    let err = fx.write(|vh| add_file_credential(vh, "{}")).err().unwrap();

    assert!(matches!(err, Error::FileInSyncedVault), "{err}");
    assert_eq!(fx.on_disk(), before);

    fx.add_item().unwrap();
    let (local, _) = saved(&fx);
    assert_eq!(local.generation, GENERATION + 1);
}

#[test]
fn add_file_to_synced_vault_refused_before_any_blob_is_written() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    let key = || fx.vault.unlocked_key().unwrap();

    let err = files::add_file(
        fx.catalog.files(),
        &Target::of(&fx.vault),
        Unlock::Test(&key),
        "item",
        "doc",
        "Doc",
        FileInput {
            name: "doc.txt".to_string(),
            mime: None,
            contents: &b"contents"[..],
        },
    )
    .err()
    .unwrap();

    assert!(matches!(err, Error::FileInSyncedVault), "{err}");
    let store = fx.vaults_dir.read_dir().unwrap();
    let names: Vec<PathBuf> = store.map(|entry| entry.unwrap().path()).collect();
    assert_eq!(names, vec![fx.vault.path.clone()], "no store directory");
}

#[test]
fn sync_not_enabled_for_vault_that_holds_file() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(0, None, transport.clone());
    fx.write(|vh| add_file_credential(vh, "{}")).unwrap();
    // A file in the trash counts too.
    fx.write(|vh| vh.delete_item_credential("item", "doc"))
        .unwrap();
    let before = fx.on_disk();
    let root = TransportRoot::Folder {
        path: PathBuf::from("/files/Vaults"),
    };
    let setup = match SyncSetup::prepare(fx.catalog.files(), &Target::of(&fx.vault), root, "Mac")
        .unwrap()
    {
        SetupStart::Kit(setup) => setup,
        SetupStart::Join(root) => panic!("setup offered the join of {root}"),
    };
    let key = || fx.vault.unlocked_key().unwrap();

    let err = setup
        .confirm(
            fx.catalog.files(),
            &Target::of(&fx.vault),
            Unlock::Test(&key),
        )
        .err()
        .unwrap();

    assert!(matches!(err, Error::FileInSyncedVault), "{err}");
    assert_eq!(fx.on_disk(), before);
    assert_eq!(sync_files(&fx), [false; 3]);
}
