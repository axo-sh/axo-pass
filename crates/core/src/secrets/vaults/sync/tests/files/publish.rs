//! Upload of file blobs on publish.

use std::sync::Weak;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

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
fn blob_uploaded_as_stored_before_state_file_that_references_it() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced_with_item(&transport);

    let committed = add_file(fx.catalog.files(), &fx.vault, "doc", b"contents").unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let blob = record(&on_disk(&fx.vault), "doc").blob;
    let hash = last_publish(&fx).unwrap();
    assert_uploaded_before(&transport, fx.id(), blob, hash);
    let state = decode(&transport, &fx, hash);
    assert!(blobs::referenced(&state.store).contains(&blob));
    // The blob is copied as the local store holds it.
    assert_eq!(
        transport.blob(fx.id(), blob),
        Some(store(&fx.vault).read_bytes(&blob).unwrap())
    );
    assert_eq!(
        report(fx.catalog.files(), &fx.vault).blobs,
        BlobStatus::default()
    );
}

#[test]
fn failed_upload_copies_no_state_file_pauses_sync_and_next_transaction_completes_it() {
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
    assert_eq!(
        report(fx.catalog.files(), &fx.vault).blobs,
        BlobStatus {
            uploads_pending: 1,
            missing_locally: 0,
        }
    );

    // A change while the upload fails publishes nothing, and garbage
    // collection keeps the blob.
    let committed = fx
        .write(|vh| vh.add_item("other", "Other").map(|_| ()))
        .unwrap();
    assert!(publish_failed(&committed), "{:?}", committed.sync_status);
    assert!(store(&fx.vault).contains(&blob));
    assert_eq!(saved(&fx).0.staged_blobs, vec![blob]);
    assert_eq!(published(&transport, &fx), listed);

    transport.set_failing_blob_writes(false);
    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let hash = last_publish(&fx).unwrap();
    assert_eq!(saved(&fx).0.staged_hash, Some(hash));
    assert_eq!(published(&transport, &fx), vec![hash]);
    assert_eq!(transport.blob_names(fx.id()), vec![blob]);
    assert_uploaded_before(&transport, fx.id(), blob, hash);
    assert_eq!(
        report(fx.catalog.files(), &fx.vault).blobs,
        BlobStatus::default()
    );
}

#[test]
fn copy_staged_uploads_blob_of_failed_publish_before_staged_file() {
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
    assert_uploaded_before(&transport, fx.id(), blob, staged);
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
    assert!(saved(&fx).0.staged_blobs.is_empty());
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
    assert_eq!(saved(&fx).0.staged_blobs, vec![second]);
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
        [StateFile::name(fx.id(), staged)]
    );
    assert_eq!(uploads(&transport), 1);
}
