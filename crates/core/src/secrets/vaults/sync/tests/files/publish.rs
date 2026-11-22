//! Upload of file blobs on publish, upload of blobs the folder lost in any
//! transaction, and the blob status of the sync report.

use std::sync::Weak;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::sidecar::Sidecar;

/// Synced vault with item `item`, published through `transport`.
fn synced_with_item(transport: &Arc<FakeTransport>) -> Fixture {
    let fx = synced(transport);
    fx.add_item().unwrap();
    fx
}

/// Whether `committed` paused sync with a failed publish only.
fn publish_failed<R>(committed: &Committed<R>) -> bool {
    matches!(
        committed.sync_status,
        Some(SyncStatus::Paused(ref causes))
            if matches!(causes[..], [PausedCause::PublishFailed { .. }])
    )
}

#[test]
fn blob_uploaded_before_referencing_state_file() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced_with_item(&transport);

    let committed = add_file(fx.catalog.files(), &fx.vault, "doc", b"contents").unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let blob = record(&on_disk(&fx.vault), "doc").blob;
    let hash = last_publish(&fx).unwrap();
    assert_uploaded_before(&transport, blob, hash);
    let state = decode(&transport, &fx, hash);
    assert!(blobs::referenced(&state.store).contains(&blob));
    // The blob is copied as the local store holds it.
    assert_eq!(
        transport.blob(fx.id(), blob),
        Some(store(&fx.root, &fx.vault).read_bytes(&blob).unwrap())
    );
    assert_eq!(report(fx.catalog.files(), &fx.vault).blobs, status(0, 0));
}

#[test]
fn failed_upload_pauses_sync_until_next_transaction() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced_with_item(&transport);
    let listed = published(&transport, &fx);
    transport.set_failing_blob_writes(true);

    let committed = add_file(fx.catalog.files(), &fx.vault, "doc", b"contents").unwrap();

    assert!(committed.changed);
    assert!(publish_failed(&committed), "{:?}", committed.sync_status);
    let blob = record(&on_disk(&fx.vault), "doc").blob;
    assert!(transport.blob_names(fx.id()).is_empty());
    assert_eq!(published(&transport, &fx), listed);
    assert_eq!(saved(&fx).0.staged_blobs, vec![blob]);
    assert_eq!(report(fx.catalog.files(), &fx.vault).blobs, status(1, 0));

    // A change while the upload fails publishes nothing, and garbage
    // collection keeps the blob.
    let committed = fx
        .write(|vh| vh.add_item("other", "Other").map(|_| ()))
        .unwrap();
    assert!(publish_failed(&committed), "{:?}", committed.sync_status);
    assert!(store(&fx.root, &fx.vault).contains(&blob));
    assert_eq!(saved(&fx).0.staged_blobs, vec![blob]);
    assert_eq!(published(&transport, &fx), listed);

    transport.set_failing_blob_writes(false);
    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let hash = last_publish(&fx).unwrap();
    assert_eq!(saved(&fx).0.staged_hash, Some(hash));
    assert_eq!(published(&transport, &fx), vec![hash]);
    assert_eq!(transport.blob_names(fx.id()), vec![blob]);
    assert_uploaded_before(&transport, blob, hash);
    assert_eq!(report(fx.catalog.files(), &fx.vault).blobs, status(0, 0));
}

#[test]
fn copy_staged_uploads_blob_of_failed_publish() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced_with_item(&transport);
    let listed = published(&transport, &fx);
    transport.set_failing_blob_writes(true);
    add_file(fx.catalog.files(), &fx.vault, "doc", b"contents").unwrap();
    let blob = record(&on_disk(&fx.vault), "doc").blob;
    let staged = saved(&fx).0.staged_hash.unwrap();

    // A copy while the upload fails copies nothing.
    let files = fx.catalog.files();
    assert!(files.copy_staged(fx.id(), Some(&fx.vault.path)).is_err());
    assert_eq!(published(&transport, &fx), listed);

    transport.set_failing_blob_writes(false);
    let copy = files.copy_staged(fx.id(), Some(&fx.vault.path)).unwrap();

    assert!(matches!(copy, StagedCopy::Copied), "{copy:?}");
    assert_eq!(last_publish(&fx), Some(staged));
    assert!(published(&transport, &fx).contains(&staged));
    assert_uploaded_before(&transport, blob, staged);
}

#[test]
fn blob_listed_in_folder_not_uploaded_again() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced_with_item(&transport);
    add_file(fx.catalog.files(), &fx.vault, "doc", b"contents").unwrap();
    let blob = record(&on_disk(&fx.vault), "doc").blob;

    // A later publish of a state that references the blob lists it.
    fx.write(|vh| vh.add_item("other", "Other").map(|_| ()))
        .unwrap();

    let hash = last_publish(&fx).unwrap();
    assert!(blobs::referenced(&decode(&transport, &fx, hash).store).contains(&blob));
    // The staged blobs hold every referenced blob that the store holds,
    // listed or not. The upload skips the listed ones.
    assert_eq!(saved(&fx).0.staged_blobs, vec![blob]);
    let uploads = |transport: &FakeTransport| {
        let name = format!("blobs/{blob}");
        transport.write_log().iter().filter(|n| **n == name).count()
    };
    assert_eq!(uploads(&transport), 1);

    // A publish whose blob was uploaded before its state file copy failed
    // skips the blob at the next copy.
    let armed = Arc::new(AtomicBool::new(true));
    let hook_armed = armed.clone();
    let weak: Weak<FakeTransport> = Arc::downgrade(&transport);
    let vault_id = fx.id();
    transport.on_write(move |_| {
        let Some(transport) = weak.upgrade() else {
            return;
        };
        let second = transport.blob_names(vault_id).len() == 2;
        if second && hook_armed.swap(false, Ordering::SeqCst) {
            transport.set_failing_writes(true);
        }
    });
    let committed = add_file(fx.catalog.files(), &fx.vault, "second", b"second").unwrap();
    assert!(publish_failed(&committed), "{:?}", committed.sync_status);
    assert!(!armed.load(Ordering::SeqCst));
    let second = record(&on_disk(&fx.vault), "second").blob;
    let mut staged_blobs = vec![blob, second];
    staged_blobs.sort();
    assert_eq!(saved(&fx).0.staged_blobs, staged_blobs);
    let staged = saved(&fx).0.staged_hash.unwrap();
    transport.set_failing_writes(false);
    let log = transport.write_log();

    let copy = fx
        .catalog
        .files()
        .copy_staged(fx.id(), Some(&fx.vault.path))
        .unwrap();

    assert!(matches!(copy, StagedCopy::Copied), "{copy:?}");
    assert_eq!(
        transport.write_log()[log.len()..],
        [StateFile::name(staged)]
    );
    assert_eq!(uploads(&transport), 1);
}

/// Contents of the local sync state and the sidecar of `fx`. A save signs the
/// local sync state again, so the bytes are not compared.
fn local_files(fx: &Fixture) -> (LocalSyncState, Sidecar) {
    (saved(fx).0, Sidecar::load(&fx.root, fx.id()))
}

#[test]
fn unpublished_transaction_uploads_lost_blob() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced_with_item(&transport);
    add_file(fx.catalog.files(), &fx.vault, "doc", b"contents").unwrap();
    let blob = record(&on_disk(&fx.vault), "doc").blob;
    let bytes = transport.blob(fx.id(), blob).unwrap();
    // This transaction settles the staged file of the publish.
    fx.write(|_| Ok(())).unwrap();
    let listed = published(&transport, &fx);
    transport.remove_blob(fx.id(), blob);
    let before = local_files(&fx);

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(!committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(transport.blob(fx.id(), blob), Some(bytes));
    // Nothing was published, and no local state changed.
    assert_eq!(published(&transport, &fx), listed);
    assert_eq!(local_files(&fx), before);
}

#[test]
fn failed_heal_does_not_fail_save_or_pause_sync() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced_with_item(&transport);
    add_file(fx.catalog.files(), &fx.vault, "doc", b"contents").unwrap();
    let blob = record(&on_disk(&fx.vault), "doc").blob;
    // This transaction settles the staged file of the publish.
    fx.write(|_| Ok(())).unwrap();
    transport.remove_blob(fx.id(), blob);
    transport.set_failing_blob_writes(true);
    let before = local_files(&fx);

    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(transport.blob_names(fx.id()).is_empty());
    assert_eq!(local_files(&fx), before);

    // The next transaction uploads it.
    transport.set_failing_blob_writes(false);
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(transport.blob_names(fx.id()), vec![blob]);
}

#[test]
fn publish_uploads_lost_blob_already_referenced() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced_with_item(&transport);
    add_file(fx.catalog.files(), &fx.vault, "doc", b"contents").unwrap();
    let blob = record(&on_disk(&fx.vault), "doc").blob;
    transport.remove_blob(fx.id(), blob);

    fx.write(|vh| vh.add_item("other", "Other").map(|_| ()))
        .unwrap();

    assert_eq!(transport.blob_names(fx.id()), vec![blob]);
}

#[test]
fn report_counts_uploads_and_unreferenced_blobs() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced_with_item(&transport);
    let files = fx.catalog.files();
    let cred = add_file(files, &fx.vault, "doc", b"contents")
        .unwrap()
        .value
        .credential_id
        .unwrap();
    let blob = record(&on_disk(&fx.vault), "doc").blob;
    assert_eq!(report(files, &fx.vault).blobs, status(0, 0));

    // A blob the folder lost is waiting for upload.
    transport.remove_blob(fx.id(), blob);
    assert_eq!(report(files, &fx.vault).blobs, status(1, 0));
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(report(files, &fx.vault).blobs, status(0, 0));

    // A purge drops the reference, and the blob stays in the folder.
    trash_file(files, &fx.vault, "doc");
    fx.write(|vh| vh.purge_item_credential("item", cred))
        .unwrap();
    let size = transport.blob(fx.id(), blob).unwrap().len() as u64;
    let blobs = report(files, &fx.vault).blobs;
    assert_eq!(
        blobs.unreferenced,
        Some(UnreferencedBlobs {
            count: 1,
            bytes: size
        })
    );
    assert_eq!(transport.blob_names(fx.id()), vec![blob]);

    // Another blob adds to the count and the size.
    transport.put_blob(fx.id(), FileHash::of(b"stray"), b"stray");
    let blobs = report(files, &fx.vault).blobs;
    assert_eq!(
        blobs.unreferenced,
        Some(UnreferencedBlobs {
            count: 2,
            bytes: size + 5
        })
    );
}

#[test]
fn report_omits_unreferenced_count_if_unlistable() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced_with_item(&transport);
    let files = fx.catalog.files();
    add_file(files, &fx.vault, "doc", b"contents").unwrap();
    transport.set_unavailable(true);

    let blobs = report(files, &fx.vault).blobs;

    assert_eq!(blobs, BlobStatus::default());
}
