//! Local blob store through the vault transaction: write order, history,
//! trash, purge, retained versions, and garbage collection.

use std::fs::{self, File};
use std::time::{Duration, SystemTime};

use secrecy::{ExposeSecret, SecretString};

use super::{Fixture, contents, save_temp_path};
use crate::secrets::vaults::files::record::FileRecord;
use crate::secrets::vaults::files::stream::CHUNK_SIZE;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::model::fields::{FieldKind, TextField};
use crate::secrets::vaults::model::{CredentialUpdate, Vault};
use crate::secrets::vaults::{Error, files};

#[test]
fn added_file_reads_back_and_is_one_blob() {
    let fx = Fixture::new();
    let data = contents(2 * CHUNK_SIZE + 3);

    let committed = fx.add("doc", &data).unwrap();

    assert!(committed.changed);
    assert!(committed.value.credential_id.is_some());
    assert_eq!(fx.read("doc").unwrap(), data);
    let record = fx.record("doc");
    assert_eq!(fx.blobs(), vec![record.blob]);
    assert_eq!(record.name, "doc.bin");
    assert_eq!(record.size, data.len() as u64);
    let overview = fx.on_disk();
    let cred = overview
        .get_secret_overview("item", "doc")
        .unwrap()
        .unwrap();
    assert_eq!(cred.kind, FieldKind::File);
    // No temp file is left.
    assert_eq!(fx.store_entries(), vec![record.blob.to_string()]);
}

#[test]
fn failed_change_after_rename_deletes_blob() {
    let fx = Fixture::new();
    fx.add("doc", b"one").unwrap();
    let before = fx.blobs();

    // The key is taken, so the change fails after the blob is renamed.
    let err = fx.add("doc", b"two").err().unwrap();

    assert!(matches!(err, Error::DuplicateCredentialKey(_)), "{err}");
    assert_eq!(fx.blobs(), before);
    assert_eq!(fx.store_entries().len(), 1);
}

#[test]
fn crash_between_blob_write_and_vault_save_leaves_no_missing_blob() {
    let fx = Fixture::new();
    let before = fs::read_to_string(&fx.vault.path).unwrap();
    // A directory at the temp path of the save makes the vault save fail
    // after the blob is renamed into place.
    let obstacle = save_temp_path(&fx.vault.path);
    fs::create_dir(&obstacle).unwrap();

    let err = fx.add("doc", b"contents").err().unwrap();

    assert!(matches!(err, Error::VaultWriteError(_)), "{err}");
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), before);
    assert!(
        fx.on_disk()
            .get_secret_overview("item", "doc")
            .unwrap()
            .is_none()
    );
    assert_eq!(fx.blobs().len(), 1, "the blob is written before the save");
    fx.assert_no_missing_blob();

    // The next save deletes the blob that no record references.
    fs::remove_dir(&obstacle).unwrap();
    fx.touch();
    assert!(fx.blobs().is_empty());
}

#[test]
fn temp_file_of_interrupted_write_deleted_once_stale() {
    let fx = Fixture::new();
    fx.add("doc", b"contents").unwrap();
    let stale = fx.store().dir().join(".stale.tmp");
    let fresh = fx.store().dir().join(".fresh.tmp");
    fs::write(&stale, b"partial").unwrap();
    fs::write(&fresh, b"partial").unwrap();
    let day_ago = SystemTime::now() - Duration::from_secs(25 * 60 * 60);
    File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(day_ago)
        .unwrap();

    fx.touch();

    assert!(!stale.exists());
    assert!(fresh.exists(), "a temp file of a write in progress is kept");
    assert_eq!(fx.blobs().len(), 1);
}

#[test]
fn replace_moves_old_record_to_history_and_keeps_both_blobs() {
    let fx = Fixture::new();
    fx.add("doc", b"first").unwrap();
    let first = fx.record("doc");

    fx.replace("doc", b"second").unwrap();

    let second = fx.record("doc");
    assert_ne!(first.blob, second.blob);
    assert_ne!(first.key, second.key);
    assert_eq!(fx.read("doc").unwrap(), b"second");
    let vh = fx.on_disk();
    let history = vh.list_history("item", "doc").unwrap();
    assert_eq!(history.len(), 1);
    let old = vh.get_history_value("item", "doc", history[0].id).unwrap();
    assert_eq!(FileRecord::decode(old.expose_secret()).unwrap(), first);
    let mut blobs = vec![first.blob, second.blob];
    blobs.sort();
    assert_eq!(fx.blobs(), blobs);
}

#[test]
fn history_purge_deletes_blob_once_no_retained_version_references_it() {
    let fx = Fixture::new();
    fx.add("doc", b"first").unwrap();
    let first = fx.record("doc").blob;
    fx.replace("doc", b"second").unwrap();
    let second = fx.record("doc").blob;
    let history = fx.on_disk().list_history("item", "doc").unwrap();

    fx.write(|vh| vh.purge_history("item", "doc", history[0].id))
        .unwrap();
    // Retained versions from before the purge still hold the old record.
    assert!(fx.blobs().contains(&first));

    fx.erase_versions();
    fx.touch();

    assert_eq!(fx.blobs(), vec![second]);
    assert_eq!(fx.read("doc").unwrap(), b"second");
}

#[test]
fn trash_keeps_blob_and_restore_reads_it() {
    let fx = Fixture::new();
    fx.add("doc", b"contents").unwrap();
    let blob = fx.record("doc").blob;
    fx.erase_versions();

    files::delete_file(&fx.writer, &fx.target(), fx.unlock(), "item", "doc").unwrap();
    fx.erase_versions();
    fx.touch();

    assert_eq!(fx.blobs(), vec![blob]);
    let cred_id = fx.on_disk().list_all_deleted().unwrap()[0]
        .credential
        .credential
        .id;
    fx.write(|vh| vh.restore_item_credential("item", cred_id, None))
        .unwrap();
    assert_eq!(fx.read("doc").unwrap(), b"contents");
}

#[test]
fn trashed_item_keeps_blob() {
    let fx = Fixture::new();
    fx.add("doc", b"contents").unwrap();
    let blob = fx.record("doc").blob;

    fx.write(|vh| vh.delete_item("item")).unwrap();
    fx.erase_versions();
    fx.write(|vh| vh.add_item("other", "Other").map(|_| ()))
        .unwrap();

    assert_eq!(fx.blobs(), vec![blob]);
}

#[test]
fn purge_of_credential_deletes_blob() {
    let fx = Fixture::new();
    fx.add("doc", b"contents").unwrap();
    files::delete_file(&fx.writer, &fx.target(), fx.unlock(), "item", "doc").unwrap();
    let cred_id = fx.on_disk().list_all_deleted().unwrap()[0]
        .credential
        .credential
        .id;

    fx.write(|vh| vh.purge_item_credential("item", cred_id))
        .unwrap();
    fx.erase_versions();
    fx.touch();

    assert!(fx.blobs().is_empty());
}

#[test]
fn purge_of_item_deletes_its_blobs() {
    let fx = Fixture::new();
    fx.add("doc", b"one").unwrap();
    fx.add("pic", b"two").unwrap();
    files::delete_file(&fx.writer, &fx.target(), fx.unlock(), "item", "pic").unwrap();
    fx.write(|vh| vh.delete_item("item")).unwrap();
    let item_id = fx.on_disk().list_deleted_items().unwrap()[0].item.id;

    fx.write(|vh| vh.purge_item(item_id)).unwrap();
    fx.erase_versions();
    fx.write(|vh| vh.add_item("other", "Other").map(|_| ()))
        .unwrap();

    assert!(fx.blobs().is_empty());
}

#[test]
fn blob_referenced_only_by_retained_version_kept_and_version_restores() {
    let fx = Fixture::new();
    fx.add("doc", b"contents").unwrap();
    let blob = fx.record("doc").blob;
    files::delete_file(&fx.writer, &fx.target(), fx.unlock(), "item", "doc").unwrap();
    let cred_id = fx.on_disk().list_all_deleted().unwrap()[0]
        .credential
        .credential
        .id;
    fx.write(|vh| vh.purge_item_credential("item", cred_id))
        .unwrap();
    fx.touch();

    assert_eq!(fx.blobs(), vec![blob]);

    // The newest version that holds the live file is restored.
    let versions = fx.writer.list_versions(fx.id()).unwrap();
    let with_file = versions
        .iter()
        .find(|version| {
            let path = fx.versions_dir().join(&version.name);
            let contents = fs::read_to_string(path).unwrap();
            let enc = EncryptedVault::parse(&contents, fx.writer.signer().as_ref()).unwrap();
            let vault = Vault::from_unlocked_key(&fx.vault.unlocked_key().unwrap(), enc).unwrap();
            vault.get_item_credential("item", "doc").is_ok()
        })
        .unwrap();
    fx.writer
        .restore_version(&fx.target(), fx.unlock(), &with_file.name)
        .unwrap();
    assert_eq!(fx.read("doc").unwrap(), b"contents");
}

#[test]
fn unreadable_retained_version_keeps_every_blob() {
    let fx = Fixture::new();
    fx.add("doc", b"contents").unwrap();
    let blob = fx.record("doc").blob;
    files::delete_file(&fx.writer, &fx.target(), fx.unlock(), "item", "doc").unwrap();
    let cred_id = fx.on_disk().list_all_deleted().unwrap()[0]
        .credential
        .credential
        .id;
    fx.write(|vh| vh.purge_item_credential("item", cred_id))
        .unwrap();
    fx.erase_versions();
    fs::create_dir_all(fx.versions_dir()).unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    fs::write(fx.versions_dir().join(format!("{now}-9.json")), "{}").unwrap();

    fx.touch();

    assert_eq!(fx.blobs(), vec![blob]);
}

#[test]
fn corrupt_and_missing_blobs_refused_at_read() {
    let fx = Fixture::new();
    fx.add("doc", b"contents").unwrap();
    let record = fx.record("doc");
    let path = fx.store().path(&record.blob);
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(&path, &bytes).unwrap();

    let err = fx.read("doc").err().unwrap();
    assert!(matches!(err, Error::FileBlobMismatch(_)), "{err}");

    fs::remove_file(&path).unwrap();
    let err = fx.read("doc").err().unwrap();
    assert!(matches!(err, Error::FileMissing(_)), "{err}");
}

#[test]
fn read_and_replace_refuse_other_kinds() {
    let fx = Fixture::new();
    fx.write(|vh| {
        vh.add_secret(
            "item",
            "password",
            "Password",
            FieldKind::default(),
            SecretString::from("hunter2"),
        )
    })
    .unwrap();

    let err = fx.read("password").err().unwrap();
    assert!(matches!(err, Error::InvalidCredentialKey(_)), "{err}");
    let err = fx.replace("password", b"x").err().unwrap();
    assert!(matches!(err, Error::InvalidCredentialKey(_)), "{err}");
    assert!(fx.blobs().is_empty());
    assert!(
        fx.store_entries().is_empty(),
        "the staged temp file is deleted"
    );
}

#[test]
fn kind_never_changes_to_or_from_file() {
    let fx = Fixture::new();
    fx.add("doc", b"contents").unwrap();
    fx.write(|vh| {
        vh.add_secret(
            "item",
            "password",
            "Password",
            FieldKind::default(),
            SecretString::from("hunter2"),
        )
    })
    .unwrap();
    let text = FieldKind::Text(TextField::default());

    let to_text = fx.write(|vh| {
        let update = CredentialUpdate {
            kind: Some(text.clone()),
            ..CredentialUpdate::default()
        };
        vh.update_credential("item", "doc", update)
    });
    let to_file = fx.write(|vh| {
        let update = CredentialUpdate {
            kind: Some(FieldKind::File),
            ..CredentialUpdate::default()
        };
        vh.update_credential("item", "password", update)
    });
    let overwrite =
        fx.write(|vh| vh.add_secret("item", "doc", "Doc", text.clone(), SecretString::from("x")));

    for result in [to_text, to_file, overwrite] {
        let err = result.err().unwrap();
        assert!(matches!(err, Error::FileKindChange(_)), "{err}");
    }
    assert_eq!(fx.read("doc").unwrap(), b"contents");
}

#[test]
fn item_with_file_not_exported_to_another_vault() {
    let fx = Fixture::new();
    fx.add("doc", b"contents").unwrap();

    let err = fx.on_disk().export_item("item").err().unwrap();

    assert!(matches!(err, Error::FileMoveRefused(_)), "{err}");
}

#[test]
fn file_in_unknown_kind_credential_kept() {
    let fx = Fixture::new();
    fx.add("doc", b"contents").unwrap();
    let record = fx.record("doc");
    // A newer build writes the record under a kind this build does not know,
    // with a field it does not know.
    let mut json = serde_json::to_value(&record).unwrap();
    json["thumbnail"] = "x".into();
    let kind = FieldKind::Unknown(serde_json::json!({"type": "file-v2"}));
    fx.write(|vh| {
        vh.add_secret(
            "item",
            "newer",
            "Newer",
            kind,
            SecretString::from(json.to_string()),
        )?;
        vh.delete_item_credential("item", "doc")?;
        let cred_id = vh.list_all_deleted()?[0].credential.credential.id;
        vh.purge_item_credential("item", cred_id)
    })
    .unwrap();
    fx.erase_versions();

    fx.touch();

    assert_eq!(fx.blobs(), vec![record.blob]);
}
