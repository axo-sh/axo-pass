//! Receiving side of a rotation: the pending rotation, paused joins, files
//! under old or missing keys, the decline, and revoked signers.

use std::path::PathBuf;

use super::{Net, signing_of};
use crate::audit::Action;
use crate::audit::test_support::test_dir;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::storage::txn::Unlock;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::join_sync::{JoinFile, JoinKey};
use crate::secrets::vaults::sync::keys::{SyncKeyring, TestKeyWrapper};
use crate::secrets::vaults::sync::local_state::{PinSource, PinnedKeys};
use crate::secrets::vaults::sync::meta::MetaFile;
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::pairing::PairedVault;
use crate::secrets::vaults::sync::rotation::{RemovalReason, RotationPlan, RotationPrompt};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::sync::tests::audit_events::events;
use crate::secrets::vaults::sync::transport::TransportRoot;

/// Plan that removes Mac `n` as lost or stolen.
fn lost(n: usize) -> RotationPlan {
    RotationPlan::remove([(Net::replica(n), RemovalReason::Lost)])
}

/// Sidecar of Mac `n`.
fn sidecar(net: &Net, n: usize) -> Sidecar {
    Sidecar::load(&net.macs[n].root, net.vault_id())
}

#[test]
fn verified_rotation_pauses_joins_of_removed_replicas() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[0].rotate(&lost(2));
    net.macs[1].sync();
    let prompt = net.macs[1].prompts();
    let [RotationPrompt::Confirm { rotation, replaces }] = &prompt[..] else {
        panic!("{prompt:?}");
    };
    assert!(!replaces);
    assert_eq!(rotation.signer, Net::replica(0));
    assert_eq!(rotation.removed, vec![Net::replica(2)]);
    assert_eq!(rotation.remaining, vec![Net::replica(1)]);

    net.macs[2].add("after-rotation");
    net.macs[1].sync();

    assert!(!net.macs[1].items().contains("after-rotation"));
    assert!(sidecar(&net, 1).quarantined.is_empty());

    net.macs[1].accept(&rotation.clone());
    net.macs[2].add("after-confirmation");
    net.macs[1].sync();

    let items = net.macs[1].items();
    assert!(!items.contains("after-rotation"));
    assert!(!items.contains("after-confirmation"));
}

#[test]
fn file_under_key_not_received_waits() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);
    net.macs[0].add("under-key-1");
    net.macs[1].sync();
    net.macs[0].rotate(&RotationPlan::rotate_key());
    net.macs[0].add("under-key-2");

    net.macs[1].sync();

    assert!(!net.macs[1].items().contains("under-key-2"));
    let side = sidecar(&net, 1);
    assert!(side.quarantined.is_empty());
    assert!(
        side.ignored.is_empty(),
        "a file waiting for its key is not ignored"
    );

    net.macs[1].accept(&net.macs[1].confirm());

    assert!(net.macs[1].items().contains("under-key-2"));
}

#[test]
fn files_under_old_key_ignored_including_forged_states() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[0].rotate(&lost(2));
    net.macs[1].sync_and_accept();
    net.sync_all(&[0, 1]);
    let before = net.macs[1].state();

    // Mac 2 still holds key 1. It writes states under key 1 in the
    // directory of Mac 0 and in the own directory of Mac 1.
    let other = ReplicaKeys {
        encryption: PublicKey(vec![4, 9]),
        signing: signing_of(&TestSigner::random()),
    };
    for victim in [0, 1] {
        let replica = Net::replica(victim);
        net.plant(replica, &Net::keys_written(replica, replica, other.clone()));
    }
    for n in [0, 1] {
        net.macs[n].sync();
    }

    assert!(net.macs[1].state() == before, "Mac 1 changed");
    for n in [0, 1] {
        let side = sidecar(&net, n);
        assert!(side.quarantined.is_empty(), "Mac {n} quarantined a file");
        assert!(!side.ignored.is_empty(), "Mac {n} did not ignore a file");
    }
}

#[test]
fn late_acceptance_keeps_writes_under_old_key() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[0].rotate(&RotationPlan::rotate_key());
    net.macs[1].sync();
    net.macs[1].add("while-pending");
    net.macs[0].sync();
    assert!(!net.macs[0].items().contains("while-pending"));

    net.macs[1].accept(&net.macs[1].confirm());
    net.macs[2].sync_and_accept();
    net.sync_all(&[0, 1, 2]);

    for (n, mac) in net.macs.iter().enumerate() {
        assert!(mac.items().contains("while-pending"), "Mac {n}");
        assert_eq!(mac.local().key_id.0, 2);
    }
}

#[test]
fn every_remaining_replica_converges_under_new_key() {
    let net = Net::new(4);
    net.sync_all(&[0, 1, 2, 3]);
    net.macs[0].rotate(&lost(3));
    for n in [1, 2] {
        net.macs[n].add(&format!("item-{n}"));
        net.macs[n].sync_and_accept();
    }
    net.sync_all(&[0, 1, 2]);

    let state = net.macs[0].state();
    for n in [1, 2] {
        assert!(net.macs[n].state() == state, "Mac {n} state differs");
        assert_eq!(net.macs[n].local().key_id.0, 2);
        assert_eq!(net.macs[n].status(), Some(SyncStatus::Active));
    }
    assert!(state.store.removed.get(&Net::replica(3)).is_some());
}

#[test]
fn removed_replica_forged_states_change_no_accepting_replica() {
    let net = Net::new(4);
    net.sync_all(&[0, 1, 2, 3]);
    net.macs[0].rotate(&lost(3));
    net.macs[1].sync_and_accept();
    net.macs[2].sync_and_accept();
    net.sync_all(&[0, 1, 2]);
    let before: Vec<_> = (0..3).map(|n| net.macs[n].state()).collect();

    // Mac 3 forges a state of each remaining replica under key 1.
    let other = ReplicaKeys {
        encryption: PublicKey(vec![4, 9]),
        signing: signing_of(&TestSigner::random()),
    };
    for victim in 0..3 {
        let replica = Net::replica(victim);
        net.plant(replica, &Net::keys_written(replica, replica, other.clone()));
    }
    net.sync_all(&[0, 1, 2]);

    for n in 0..3 {
        assert!(net.macs[n].state() == before[n], "Mac {n} changed");
    }
}

#[test]
fn declined_rotation_resumes_joins_and_loses_no_write() {
    let net = Net::new(4);
    net.sync_all(&[0, 1, 2, 3]);
    // Mac 2 signs a rotation that removes Mac 3, which the user still uses.
    net.macs[2].rotate(&lost(3));
    net.macs[1].sync();
    let pending = net.macs[1].confirm();
    net.macs[3].add("from-mac-3");
    net.macs[1].sync();
    assert!(!net.macs[1].items().contains("from-mac-3"));

    net.macs[1].decline(&[pending]);

    assert!(net.macs[1].items().contains("from-mac-3"));
    assert!(net.macs[1].prompts().is_empty());
    assert_eq!(net.macs[1].local().key_id.0, 1);
}

#[test]
fn declined_rotation_pauses_sync_and_offers_relink() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[0].rotate(&RotationPlan::rotate_key());
    net.macs[1].sync();
    let pending = net.macs[1].confirm();

    let committed = net.macs[1].decline(&[pending]);

    let paused = Some(SyncStatus::Paused(vec![PausedCause::RotationDeclined {
        signer: Net::replica(0).0,
    }]));
    assert_eq!(committed.sync_status, paused);
    // Local edits are still recorded and published under key 1.
    net.macs[1].add("after-decline");
    assert_eq!(net.macs[1].status(), paused);
    net.macs[2].sync();
    assert!(net.macs[2].items().contains("after-decline"));
    net.macs[0].sync();
    assert!(!net.macs[0].items().contains("after-decline"));
}

#[test]
fn pairing_relinks_mac_that_declined_rotation_and_keeps_its_edits() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[0].rotate(&RotationPlan::rotate_key());
    net.macs[1].sync();
    let pending = net.macs[1].confirm();
    net.macs[1].decline(&[pending]);
    net.macs[1].add("after-decline");
    let old_replica = Net::replica(1);
    assert!(net.has_directory(1));

    // Mac 1 pairs with Mac 0, which sends key 2.
    let local = net.macs[0].local();
    let keyring = SyncKeyring::unwrap(&local.sync_keys, &TestKeyWrapper).unwrap();
    let key = keyring.get(KeyId(2)).unwrap().clone();
    let new_replica = ReplicaId::generate();
    let join = JoinKey::paired(PairedVault {
        vault_id: net.vault_id(),
        replica_id: new_replica,
        key_id: KeyId(2),
        key,
        peer: Net::replica(0),
        pin: PinnedKeys {
            source: PinSource::Pairing,
            encryption: net.macs[0].keys.encryption.clone(),
            signing: net.macs[0].keys.signing.clone(),
            revoked: false,
        },
    });
    net.folder
        .put_meta(net.vault_id(), &MetaFile::new(net.vault_id()).to_bytes());
    let mac = &net.macs[1];
    let target = mac.target(0);
    let unlock = || mac.vault(0).unlocked_key().unwrap();
    let root = TransportRoot::Folder {
        path: PathBuf::from("/rotation"),
    };

    let joined = mac
        .writer
        .join_sync(
            &join,
            JoinFile::Existing(&target),
            &root,
            "Mac 1",
            Unlock::Test(&unlock),
        )
        .unwrap();

    // Mac 1 syncs under key 2 with a new replica id, and its old directory
    // is deleted.
    assert_eq!(joined.sync_status, Some(SyncStatus::Active));
    let local = mac.local();
    assert_eq!(local.key_id, KeyId(2));
    assert_eq!(local.replica_id, new_replica);
    assert!(local.declined_rotations.is_empty());
    assert!(!net.has_directory(1));
    assert!(!net.folder.names(net.vault_id(), new_replica).is_empty());
    assert_ne!(old_replica, new_replica);

    // The edit made while cut off reaches Mac 0, and Mac 1 has what Mac 0
    // had.
    net.macs[0].sync();
    assert!(net.macs[0].items().contains("after-decline"));
    assert_eq!(net.macs[0].status(), Some(SyncStatus::Active));
    assert!(mac.items().contains("after-decline"));
    assert_eq!(mac.status(), Some(SyncStatus::Active));
}

#[test]
fn rotation_by_removed_signer_rejected_without_prompt() {
    let _audit = test_dir();
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    net.macs[0].rotate(&lost(2));
    net.macs[1].sync_and_accept();

    // Mac 2 signs a rotation to key 2 of its own that removes Mac 0.
    net.macs[2].rotate(&lost(0));
    net.macs[1].sync();
    net.macs[1].sync();

    assert!(net.macs[1].prompts().is_empty());
    assert!(net.macs[1].local().pending_rotations.is_empty());
    let rejected: Vec<_> = events(Action::SyncRotation)
        .into_iter()
        .filter(|event| event.detail["change"] == "rejected")
        .collect();
    assert_eq!(rejected.len(), 1, "one event for the rejected rotation");
    assert_eq!(net.macs[1].local().key_id.0, 2);
}
