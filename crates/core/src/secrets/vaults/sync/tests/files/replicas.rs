//! File records between two Macs that sync through one folder, and the
//! upload of the blobs of a vault that holds files at setup and join.

use super::super::join_sync::{MAC_B, Mac, enable, file_key, recovered, root};
use super::*;
use crate::secrets::vaults::sync::join_sync::JoinInto;
use crate::secrets::vaults::sync::sidecar::Sidecar;

/// Mac A with the vault of a fixture that holds item `item` and syncs
/// through `transport`, and Mac B that joined it as a new vault.
struct TwoMacs {
    a: Fixture,
    b: Mac,
    /// Vault of Mac B.
    b_vault: VaultHandle,
}

impl TwoMacs {
    fn new(transport: &Arc<FakeTransport>) -> Self {
        let a = Fixture::with_transport(0, None, transport.clone());
        a.add_item().unwrap();
        let setup = enable(&a, root());
        let b = Mac::new(transport.clone());
        let join = recovered(&setup, &**transport);
        let b_vault = b
            .join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2))
            .unwrap()
            .vault;
        Self { a, b, b_vault }
    }

    fn id(&self) -> uuid::Uuid {
        self.a.id()
    }

    /// Run a transaction with no change on Mac B, which applies the state
    /// files of Mac A, and check that sync is active. Returns the vault of
    /// Mac B as saved.
    fn sync_b(&self) -> VaultHandle {
        let committed = self.b.write(&self.b_vault, |_| Ok(())).unwrap();
        assert_eq!(committed.sync_status, Some(SyncStatus::Active));
        on_disk(&self.b_vault)
    }

    /// Contents of file credential `cred_key` on Mac B.
    fn read_b(&self, cred_key: &str) -> Result<Vec<u8>, Error> {
        read_file(self.b.catalog.files(), &self.b_vault, cred_key)
    }
}

#[test]
fn file_added_on_one_mac_read_on_other_with_fetch_into_local_store() {
    let transport = Arc::new(FakeTransport::default());
    let macs = TwoMacs::new(&transport);
    add_file(macs.a.catalog.files(), &macs.a.vault, "doc", b"contents").unwrap();

    let b_vault = macs.sync_b();

    let blob = record(&b_vault, "doc").blob;
    let b_store = store(&b_vault);
    assert!(!b_store.contains(&blob));
    assert_eq!(macs.read_b("doc").unwrap(), b"contents");
    assert_eq!(
        b_store.read_bytes(&blob).unwrap(),
        transport.blob(macs.id(), blob).unwrap()
    );
    // A second read reads the local store only.
    let reads = transport.reads();
    assert_eq!(macs.read_b("doc").unwrap(), b"contents");
    assert_eq!(transport.reads(), reads);
}

#[test]
fn blob_not_local_in_folder_requested_and_read_fails_as_pending_until_downloaded() {
    let transport = Arc::new(FakeTransport::default());
    let macs = TwoMacs::new(&transport);
    add_file(macs.a.catalog.files(), &macs.a.vault, "doc", b"contents").unwrap();
    let b_vault = macs.sync_b();
    let blob = record(&b_vault, "doc").blob;
    let bytes = transport.blob(macs.id(), blob).unwrap();
    transport.put_blob_remote(macs.id(), blob, Some(&bytes));

    let err = macs.read_b("doc").unwrap_err();

    assert!(
        matches!(err, Error::FilePending(ref name) if *name == blob.to_string()),
        "{err}"
    );
    assert_eq!(transport.blob_download_requests(), vec![(macs.id(), blob)]);
    assert!(!store(&b_vault).contains(&blob));

    assert_eq!(transport.complete_downloads(macs.id()), 1);
    assert_eq!(macs.read_b("doc").unwrap(), b"contents");
}

#[test]
fn blob_missing_from_folder_or_not_hashing_to_its_name_fails_read_and_writes_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let macs = TwoMacs::new(&transport);
    add_file(macs.a.catalog.files(), &macs.a.vault, "doc", b"contents").unwrap();
    let b_vault = macs.sync_b();
    let blob = record(&b_vault, "doc").blob;

    transport.put_blob(macs.id(), blob, b"other bytes");
    let err = macs.read_b("doc").unwrap_err();
    assert!(matches!(err, Error::FileBlobMismatch(_)), "{err}");
    assert!(store(&b_vault).list().unwrap().is_empty());

    transport.remove_blob(macs.id(), blob);
    let err = macs.read_b("doc").unwrap_err();
    assert!(matches!(err, Error::FileMissing(_)), "{err}");
    assert!(store(&b_vault).list().unwrap().is_empty());
}

#[test]
fn replace_and_trash_on_one_mac_show_on_other() {
    let transport = Arc::new(FakeTransport::default());
    let macs = TwoMacs::new(&transport);
    let (a_files, a_vault) = (macs.a.catalog.files(), &macs.a.vault);
    add_file(a_files, a_vault, "doc", b"first").unwrap();
    macs.sync_b();
    assert_eq!(macs.read_b("doc").unwrap(), b"first");
    let first = record(&on_disk(a_vault), "doc").blob;

    replace_file(a_files, a_vault, "doc", b"second").unwrap();
    let b_vault = macs.sync_b();

    let second = record(&b_vault, "doc").blob;
    assert_ne!(second, first);
    assert_eq!(macs.read_b("doc").unwrap(), b"second");
    // The replaced record is in the history on Mac B.
    let b_blobs = b_vault.get_unlocked_vault().unwrap().file_blobs().unwrap();
    assert_eq!(b_blobs, [first, second].into());

    trash_file(a_files, a_vault, "doc");
    let b_vault = macs.sync_b();

    assert!(matches!(
        files::read_record(&b_vault, "item", "doc"),
        Err(Error::InvalidCredentialKey(_))
    ));
    let b_saved = b_vault.get_unlocked_vault().unwrap();
    assert!(b_saved.holds_files());
    assert_eq!(b_saved.file_blobs().unwrap(), [first, second].into());
    // The trash holds both records, so Mac B keeps both blobs.
    let mut kept = store(&b_vault).list().unwrap();
    kept.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(kept, expected);
}

#[test]
fn mac_that_has_not_fetched_blob_reports_it_missing_and_still_syncs() {
    let transport = Arc::new(FakeTransport::default());
    let macs = TwoMacs::new(&transport);
    add_file(macs.a.catalog.files(), &macs.a.vault, "doc", b"contents").unwrap();
    macs.sync_b();

    let b_files = macs.b.catalog.files();
    assert_eq!(
        report(b_files, &macs.b_vault).blobs,
        BlobStatus {
            uploads_pending: 0,
            missing_locally: 1,
        }
    );

    // Mac B publishes an edit without the blob, and Mac A applies it.
    let committed = macs
        .b
        .write(&macs.b_vault, |vh| vh.add_item("home", "Home").map(|_| ()))
        .unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let committed = macs.a.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(saved_vault(&macs.a).get_item("home").is_ok());

    assert_eq!(macs.read_b("doc").unwrap(), b"contents");
    assert_eq!(report(b_files, &macs.b_vault).blobs, BlobStatus::default());
}

#[test]
fn setup_of_vault_that_holds_files_uploads_blobs_before_first_state_file() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(0, None, transport.clone());
    fx.add_item().unwrap();
    let files = fx.catalog.files();
    add_file(files, &fx.vault, "doc", b"contents").unwrap();
    // A file in the trash is uploaded too.
    add_file(files, &fx.vault, "old", b"old").unwrap();
    trash_file(files, &fx.vault, "old");
    let held = on_disk(&fx.vault)
        .get_unlocked_vault()
        .unwrap()
        .file_blobs()
        .unwrap();
    assert_eq!(held.len(), 2);

    enable(&fx, root());

    let hash = last_publish(&fx).unwrap();
    let held: Vec<FileHash> = held.into_iter().collect();
    assert_eq!(transport.blob_names(fx.id()), held);
    for blob in held {
        assert_uploaded_before(&transport, fx.id(), blob, hash);
    }
}

#[test]
fn join_of_existing_vault_that_holds_files_uploads_blobs_and_other_mac_reads_them() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.add_item().unwrap();
    // Mac B holds a copy of the vault from before sync, and adds a file.
    let b = Mac::new(transport.clone());
    let b_vault = b.copy_of(&a);
    add_file(b.catalog.files(), &b_vault, "doc", b"from b").unwrap();
    let blob = record(&on_disk(&b_vault), "doc").blob;
    let setup = enable(&a, root());
    let join = recovered(&setup, &*transport);
    let file_key = b_vault.unlocked_key().unwrap();

    let committed = b
        .join(
            &join,
            JoinInto::Existing(Target::of(&b_vault)),
            MAC_B,
            &file_key,
        )
        .unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let hash = Sidecar::load(&b.root, a.id()).last_publish.unwrap();
    assert_eq!(transport.blob_names(a.id()), vec![blob]);
    assert_uploaded_before(&transport, a.id(), blob, hash);

    // Mac A applies the join, and reads the file with a fetch.
    let committed = a.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(!store(&a.vault).contains(&blob));
    assert_eq!(
        read_file(a.catalog.files(), &a.vault, "doc").unwrap(),
        b"from b"
    );
}
