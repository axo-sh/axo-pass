//! Fault-injection tests of rotation and cleanup, moved from milestone 9.

use super::{Mac, Net};
use crate::audit::Action;
use crate::audit::test_support::test_dir;
use crate::secrets::vaults::Error;
use crate::secrets::vaults::storage::txn::Unlock;
use crate::secrets::vaults::sync::rotation::{RemovalReason, RotationPlan};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::sync::tests::audit_events::events;

/// Disable sync of vault 0 on `mac`.
fn disable(mac: &Mac) {
    let key = || mac.vault(0).unlocked_key().unwrap();
    mac.writer
        .disable_sync(&mac.target(0), Unlock::Test(&key))
        .unwrap();
}

#[test]
fn rotation_reaches_offline_mac_when_it_returns() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[0].rotate(&RotationPlan::remove([(
        Net::replica(2),
        RemovalReason::Lost,
    )]));

    // While offline, Mac 1 records its edits and sees no rotation.
    let offline = net.macs[1].sync_offline();
    assert!(matches!(
        offline.sync_status,
        Some(SyncStatus::Paused(ref causes))
            if causes.iter().any(|c| matches!(c, PausedCause::Unreachable { .. }))
    ));
    net.macs[1]
        .write_with(&net.macs[1].offline, 0, |vh| {
            vh.add_item("offline-edit", "Title").map(|_| ())
        })
        .unwrap();
    assert!(net.macs[1].prompts().is_empty());

    net.macs[1].sync_and_accept();
    net.sync_all(&[0, 1]);

    for n in [0, 1] {
        assert!(net.macs[n].items().contains("offline-edit"), "Mac {n}");
        assert_eq!(net.macs[n].local().key_id.0, 2);
    }
}

#[test]
fn cleanup_with_failed_publish_deletes_nothing() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    disable(&net.macs[2]);
    net.macs[0].sync();
    net.folder.set_failing_writes(true);

    let cleaned = net.macs[0].clean(Net::replica(2)).unwrap();

    net.folder.set_failing_writes(false);
    assert!(!cleaned.value.deleted);
    assert!(net.has_directory(2));
    // The next transaction publishes the cleanup, and the directory stays
    // until another cleanup.
    net.macs[0].sync();
    assert!(net.has_directory(2));
    let cleaned = net.macs[0].clean(Net::replica(2));
    assert!(matches!(cleaned, Err(Error::CleanupRefused(_))));
}

#[test]
fn rotation_removing_retired_mac_with_downloading_file_waits() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[2].add("in-download");
    net.make_remote(Net::replica(2));
    let plan = RotationPlan::remove([(Net::replica(2), RemovalReason::Retired)]);

    let waiting = net.macs[0].rotate_in(0, &plan);

    assert!(matches!(waiting, Err(Error::RotationWaiting(_))));
    assert_eq!(net.macs[0].local().key_id.0, 1);
    assert!(net.wrapped_to(0, 2).is_empty());
    assert!(net.folder.download_requests().contains(&net.vault_id()));

    net.folder.complete_downloads(net.vault_id());
    let rotated = net.macs[0].rotate(&plan);

    assert_eq!(rotated.deleted, vec![Net::replica(2)]);
    assert!(net.macs[0].items().contains("in-download"));
}

#[test]
fn files_of_removed_replicas_and_old_keys_ignored_and_recorded_once() {
    let _audit = test_dir();
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[0].rotate(&RotationPlan::remove([(
        Net::replica(2),
        RemovalReason::Lost,
    )]));
    net.macs[2].add("after-removal");
    net.macs[1].add("under-old-key");
    // Events of every Mac are recorded in one log. Mac 1 ignored the new
    // file of Mac 2 already.
    let before = events(Action::SyncFileIgnored).len();

    net.macs[0].sync();
    net.macs[0].sync();

    let sidecar = Sidecar::load(&net.macs[0].root, net.vault_id());
    assert!(sidecar.quarantined.is_empty());
    assert!(sidecar.ignored.contains_key(&Net::replica(2)));
    assert!(sidecar.ignored.contains_key(&Net::replica(1)));
    let all = events(Action::SyncFileIgnored);
    // Events are newest first.
    let ignored = &all[..all.len() - before];
    let reasons: Vec<String> = ignored
        .iter()
        .map(|event| event.detail["reason"].clone())
        .collect();
    assert_eq!(ignored.len(), 2, "{reasons:?}");
    assert!(reasons.contains(&"removed replica".to_string()));
    assert!(reasons.contains(&"old key id".to_string()));
    // The listing of a read does not find an ignored file as a change.
    net.macs[0].writer.advance_listing_clock(120);
    assert!(!net.macs[0].writer.read_joins(net.vault_id()));
}
