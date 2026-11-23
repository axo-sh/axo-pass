//! Remove Mac: the vaults it rotates, the preselection, flagged keys, and the
//! retired and lost reasons.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use uuid::Uuid;

use super::{Net, signing_of};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::UnlockedKey;
use crate::secrets::vaults::storage::txn::{Target, Unlock};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::model::{PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::rotation::{RemovalReason, RotationPlan};
use crate::secrets::vaults::sync::status::{BUILD_ID, SyncStatus};
use crate::secrets::vaults::sync::tests::wrapping::SoftwareKey;

/// Plan that removes the replicas of `replicas` as `reason`.
fn removing(reason: RemovalReason, replicas: &[ReplicaId]) -> RotationPlan {
    RotationPlan::remove(replicas.iter().map(|replica| (*replica, reason)))
}

/// Keys of a Mac that only exists in a planted file.
fn planted_keys() -> ReplicaKeys {
    ReplicaKeys {
        encryption: PublicKey(SoftwareKey::generate().public_sec1()),
        signing: signing_of(&TestSigner::random()),
    }
}

#[test]
fn remove_mac_rotates_every_vault_with_one_prompt() {
    // Mac 2 syncs vaults 0 and 1. Vault 2 is synced by Macs 0 and 1 only.
    let net = Net::with(3, 3, |v, n| v < 2 || n < 2);
    for v in 0..3 {
        for mac in net.macs.iter().filter(|mac| mac.vaults[v].is_some()) {
            mac.write_in(v, |_| Ok(())).unwrap();
        }
    }
    let rotating = &net.macs[0];
    // Sync of vault 1 is stopped by drift on this build, so it cannot rotate.
    let mut stopped = rotating.local_in(1);
    stopped.stopped_build = Some(BUILD_ID.to_string());
    stopped.save(&rotating.root, &rotating.signer()).unwrap();

    // Remove Mac finds Mac 2 in each vault by its signing key.
    let removed = &net.macs[2].keys.signing;
    let picks: Vec<(Uuid, Target, RotationPlan)> = (0..3)
        .filter_map(|v| {
            let report = rotating.report_in(v);
            let mac = report.mac_with_signing(removed)?;
            assert!(mac.preselected(), "a first use pin is preselected");
            let plan = removing(RemovalReason::Lost, &[mac.replica]);
            Some((net.vault_ids[v], rotating.target(v), plan))
        })
        .collect();
    assert_eq!(picks.len(), 2, "Mac 2 belongs to vaults 0 and 1");

    // The app unlocks once. Later key reads on that context draw no prompt.
    let authenticated = AtomicBool::new(false);
    let prompts = AtomicUsize::new(0);
    let read = |n: usize| -> UnlockedKey {
        if !authenticated.swap(true, Ordering::SeqCst) {
            prompts.fetch_add(1, Ordering::SeqCst);
        }
        rotating.vault(n).unlocked_key().unwrap()
    };
    let keys: Vec<Box<dyn Fn() -> UnlockedKey + Sync + '_>> = (0..2)
        .map(|v| Box::new(move || read(v)) as Box<dyn Fn() -> UnlockedKey + Sync>)
        .collect();
    let unlock = |target: &Target| {
        let v = (0..2)
            .find(|v| rotating.vault(*v).path == target.path)
            .unwrap();
        Unlock::Test(&*keys[v])
    };
    let results = rotating
        .writer
        .rotate_vaults(&picks, unlock, |_, _| panic!("no file waits"));

    assert_eq!(prompts.load(Ordering::SeqCst), 1);
    assert_eq!(results.len(), 2);
    let rotated = results[0].1.as_ref().unwrap();
    assert_eq!(results[0].0, net.vault_ids[0]);
    assert_eq!(rotated.removed, vec![Net::replica_in(0, 2)]);
    assert_eq!(rotated.remaining, vec![Net::replica_in(0, 1)]);
    assert_eq!(rotating.local_in(0).key_id.0, 2);
    assert_eq!(results[1].0, net.vault_ids[1]);
    assert!(
        matches!(results[1].1, Err(Error::RotationRefused(_))),
        "{:?}",
        results[1].1
    );
    assert_eq!(rotating.local_in(1).key_id.0, 1);
    assert_eq!(rotating.local_in(2).key_id.0, 1);
}

#[test]
fn first_use_pins_preselected_and_paired_not() {
    let net = Net::new(4);
    net.sync_all(&[0, 1, 2, 3]);
    net.pin_paired(0, 0, 1);
    // A holder of key 1 plants the keys of a Mac nobody uses.
    let planted = ReplicaId(Uuid::from_u128(0x55));
    net.plant(
        planted,
        &Net::keys_written(planted, planted, planted_keys()),
    );
    net.macs[0].sync();

    let report = net.macs[0].report_in(0);
    let preselected: BTreeSet<ReplicaId> = report
        .known_macs
        .iter()
        .filter(|mac| mac.preselected())
        .map(|mac| mac.replica)
        .collect();
    assert_eq!(
        preselected,
        BTreeSet::from([Net::replica(2), Net::replica(3)]),
        "the paired Mac and this Mac are not preselected"
    );
    assert!(net.macs[0].pin(0, planted).is_some());

    // Removing every Mac pinned at first use wraps the key to the paired Mac
    // only. The planted key is pinned too, so the user keeps it only by
    // unselecting it.
    let mut removed: Vec<ReplicaId> = preselected.into_iter().collect();
    removed.push(planted);
    let rotated = net.macs[0].rotate(&removing(RemovalReason::Lost, &removed));

    assert_eq!(rotated.remaining, vec![Net::replica(1)]);
    assert_eq!(net.wrapped_to(0, 2), BTreeSet::from([Net::replica(1)]));
}

#[test]
fn planted_key_kept_by_user_receives_wrapping() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    let planted = ReplicaId(Uuid::from_u128(0x55));
    net.plant(
        planted,
        &Net::keys_written(planted, planted, planted_keys()),
    );
    net.macs[0].sync();

    net.macs[0].rotate(&removing(RemovalReason::Lost, &[Net::replica(2)]));

    assert!(net.wrapped_to(0, 2).contains(&planted));
}

#[test]
fn second_replica_keys_value_flagged_and_superseded() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    // A holder of key 1 writes other keys into the register of Mac 1.
    let writer = ReplicaId(Uuid::from_u128(0x66));
    net.plant(
        writer,
        &Net::keys_written(writer, Net::replica(1), planted_keys()),
    );

    assert_eq!(net.macs[0].status(), Some(SyncStatus::Active));
    let flagged = |n: usize| {
        net.macs[n]
            .report_in(0)
            .known_macs
            .iter()
            .find(|mac| mac.replica == Net::replica(1))
            .unwrap()
            .keys_flagged
    };
    assert!(flagged(0));
    assert_eq!(
        net.macs[0].pin(0, Net::replica(1)).unwrap().signing,
        net.macs[1].keys.signing,
        "the pin keeps the keys of the owner"
    );

    // The owner supersedes the register in its next transaction.
    net.macs[1].sync();
    net.macs[0].sync();

    assert!(!flagged(0));
    let register = net.macs[0]
        .state()
        .store
        .replica_keys
        .get(&Net::replica(1))
        .unwrap()
        .values()
        .count();
    assert_eq!(register, 1);
}

#[test]
fn removed_replica_second_keys_value_relayed_and_cleared() {
    let net = Net::new(4);
    net.sync_all(&[0, 1, 2, 3]);
    // Mac 2 writes other keys into the register of Mac 1 before its removal,
    // and only Mac 3 joins that file before the rotation.
    net.plant(
        Net::replica(2),
        &Net::keys_written(Net::replica(2), Net::replica(1), planted_keys()),
    );
    net.macs[3].sync();
    let held = net.stash(Net::replica(3));
    let planted = net.stash(Net::replica(2));
    net.macs[0].rotate(&removing(RemovalReason::Lost, &[Net::replica(2)]));
    net.unstash(Net::replica(3), &held);
    net.unstash(Net::replica(2), &planted);

    // Mac 3 accepts and republishes the value under the new key.
    net.macs[3].sync_and_accept();
    net.macs[0].sync();

    assert_eq!(net.macs[0].status(), Some(SyncStatus::Active));
    let values = |n: usize| {
        net.macs[n]
            .state()
            .store
            .replica_keys
            .get(&Net::replica(1))
            .unwrap()
            .values()
            .count()
    };
    assert_eq!(values(0), 2);

    net.macs[1].sync_and_accept();
    net.sync_all(&[1, 3, 0]);

    assert_eq!(values(0), 1, "the owner cleared the second value");
    assert_eq!(net.macs[0].status(), Some(SyncStatus::Active));
}

#[test]
fn removed_replica_later_files_ignored_and_relayed_writes_joined() {
    let net = Net::new(4);
    net.sync_all(&[0, 1, 2, 3]);
    net.macs[2].add("early");
    net.macs[3].sync();
    // Only the file of Mac 3 holds the early write of Mac 2.
    net.stash(Net::replica(2));
    let held = net.stash(Net::replica(3));
    net.macs[0].rotate(&removing(RemovalReason::Lost, &[Net::replica(2)]));
    net.unstash(Net::replica(3), &held);
    assert!(!net.macs[0].items().contains("early"));

    net.macs[3].sync_and_accept();
    net.macs[2].add("later");
    net.macs[0].sync();

    let items = net.macs[0].items();
    assert!(items.contains("early"), "relayed write is joined");
    assert!(
        !items.contains("later"),
        "file of removed replica is ignored"
    );
    assert!(net.macs[0].local().pinned_keys[&Net::replica(2)].revoked);
}

#[test]
fn retired_waits_for_files_and_lost_does_not() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[2].add("unseen");
    net.make_remote(Net::replica(2));

    let retired = net.macs[0].rotate_in(0, &removing(RemovalReason::Retired, &[Net::replica(2)]));

    assert!(
        matches!(retired, Err(Error::RotationWaiting(ref ids)) if *ids == vec![Net::replica(2).0]),
        "{:?}",
        retired.as_ref().err()
    );
    assert_eq!(
        net.macs[0].local().key_id.0,
        1,
        "no rotation without the join"
    );

    let lost = net.macs[0].rotate(&removing(RemovalReason::Lost, &[Net::replica(2)]));

    assert_eq!(lost.key_id.0, 2);
    assert!(!net.macs[0].items().contains("unseen"));
}

#[test]
fn retired_join_keeps_write_only_its_file_holds() {
    let net = Net::new(4);
    net.sync_all(&[0, 1, 2, 3]);
    net.macs[2].add("only-in-retired-file");

    let rotated = net.macs[0].rotate(&removing(RemovalReason::Retired, &[Net::replica(2)]));

    assert_eq!(rotated.deleted, vec![Net::replica(2)]);
    assert!(!net.has_directory(2));
    net.macs[1].sync_and_accept();
    net.macs[3].sync_and_accept();
    net.sync_all(&[0, 1, 3]);
    for n in [0, 1, 3] {
        assert!(
            net.macs[n].items().contains("only-in-retired-file"),
            "Mac {n} lost the write"
        );
    }
}

#[test]
fn retired_remote_file_waits_outside_locks_and_can_be_cancelled() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[2].add("downloading");
    net.make_remote(Net::replica(2));
    let mac = &net.macs[0];
    let plan = removing(RemovalReason::Retired, &[Net::replica(2)]);
    let key = || mac.vault(0).unlocked_key().unwrap();

    let cancelled = mac.writer.rotate_waiting(
        &mac.target(0),
        || Unlock::Test(&key),
        &plan,
        |remote| {
            assert_eq!(remote, [Net::replica(2)]);
            false
        },
    );

    assert!(matches!(cancelled, Err(Error::RotationCancelled)));
    assert_eq!(mac.local().key_id.0, 1);

    let mut waits = 0;
    let rotated = mac
        .writer
        .rotate_waiting(
            &mac.target(0),
            || Unlock::Test(&key),
            &plan,
            |remote| {
                waits += 1;
                assert_eq!(remote, [Net::replica(2)], "the wait shows the retired Mac");
                // A write during the wait takes the vault locks.
                mac.add("during-wait");
                net.folder.complete_downloads(net.vault_id());
                true
            },
        )
        .unwrap();

    assert_eq!(waits, 1);
    assert_eq!(rotated.value.key_id.0, 2);
    let items = mac.items();
    assert!(items.contains("downloading"));
    assert!(items.contains("during-wait"));
}

#[test]
fn retired_directory_kept_if_publish_fails() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.folder.set_failing_writes(true);

    let rotated = net.macs[0].rotate(&removing(RemovalReason::Retired, &[Net::replica(2)]));

    net.folder.set_failing_writes(false);
    assert_eq!(rotated.kept, vec![Net::replica(2)]);
    assert!(net.has_directory(2));
    // The next transaction writes the wrappings and publishes.
    net.macs[0].sync();
    assert_eq!(net.wrapped_to(0, 2), BTreeSet::from([Net::replica(1)]));
    net.macs[1].sync_and_accept();
}

#[test]
fn retired_directory_kept_if_publish_does_not_cover_it() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    // A file of Mac 2 that fails to decode is quarantined, not joined.
    net.folder
        .put_state(net.vault_id(), Net::replica(2), b"not a state file");

    let rotated = net.macs[0].rotate(&removing(RemovalReason::Retired, &[Net::replica(2)]));

    assert_eq!(rotated.kept, vec![Net::replica(2)]);
    assert!(net.has_directory(2));
}

#[test]
fn lost_directory_deleted_after_publish() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[2].add("never-joined");
    net.make_remote(Net::replica(2));

    let rotated = net.macs[0].rotate(&removing(RemovalReason::Lost, &[Net::replica(2)]));

    assert_eq!(rotated.deleted, vec![Net::replica(2)]);
    assert!(!net.has_directory(2));
}
