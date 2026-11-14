//! Export of a synced vault whose blobs are only in the synced folder.

use std::fs;

use super::replicas::TwoMacs;
use super::*;
use crate::audit::test_support::test_dir;
use crate::secrets::vaults::bundle::{ExportMode, ImportIdentity, ImportableBundle};
use crate::secrets::vaults::storage::handle::export_bundle;

/// Export the vault of Mac B as saved to a bundle file, through the writer of
/// Mac B. Returns the report and the opened bundle.
fn export_b(
    macs: &TwoMacs,
) -> (
    crate::secrets::vaults::bundle::ExportReport,
    ImportableBundle,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export.axovault");
    let identity = age::x25519::Identity::generate();
    let mode = ExportMode::Recipient(identity.to_public().to_string());
    let report = export_bundle(
        &[&on_disk(&macs.b_vault)],
        &path,
        mode,
        true,
        macs.b.catalog.files(),
        |_| {},
    )
    .unwrap();
    assert!(fs::metadata(&path).is_ok());
    let bundle = ImportableBundle::open(&path, ImportIdentity::Identity(identity)).unwrap();
    (report, bundle)
}

#[test]
fn export_fetches_blob_only_in_folder() {
    let _audit = test_dir();
    let transport = Arc::new(FakeTransport::default());
    let macs = TwoMacs::new(&transport);
    add_file(macs.a.catalog.files(), &macs.a.vault, "doc", b"contents").unwrap();
    let b_vault = macs.sync_b();
    let blob = record(&b_vault, "doc").blob;
    assert!(!store(&macs.b_vault).contains(&blob));
    let in_folder = transport.blob(macs.id(), blob).unwrap();

    let (report, bundle) = export_b(&macs);

    assert!(report.missing_blobs.is_empty(), "{report:?}");
    let info = &bundle.vaults()[0];
    assert_eq!((info.files, info.missing_files), (1, 0));
    // The blob is now in the local store, as the folder held it.
    assert_eq!(store(&macs.b_vault).read_bytes(&blob).unwrap(), in_folder);
}

#[test]
fn export_reports_blob_missing_from_folder() {
    let _audit = test_dir();
    let transport = Arc::new(FakeTransport::default());
    let macs = TwoMacs::new(&transport);
    add_file(
        macs.a.catalog.files(),
        &macs.a.vault,
        "lost",
        b"lost contents",
    )
    .unwrap();
    add_file(
        macs.a.catalog.files(),
        &macs.a.vault,
        "kept",
        b"kept contents",
    )
    .unwrap();
    let b_vault = macs.sync_b();
    let lost = record(&b_vault, "lost").blob;
    let kept = record(&b_vault, "kept").blob;
    transport.remove_blob(macs.id(), lost);

    let (report, bundle) = export_b(&macs);

    let [missing] = &report.missing_blobs[..] else {
        panic!("{report:?}");
    };
    assert_eq!((missing.vault_id, missing.blob), (macs.id(), lost));
    let info = &bundle.vaults()[0];
    assert_eq!((info.files, info.missing_files), (2, 1));
    assert!(store(&macs.b_vault).contains(&kept));
    assert!(!store(&macs.b_vault).contains(&lost));
}
