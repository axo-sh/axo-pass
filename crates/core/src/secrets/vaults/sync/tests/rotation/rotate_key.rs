//! Rotate sync key, and the degraded state until a kit exists for the
//! current key.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use uuid::Uuid;

use super::{Mac, Net};
use crate::secrets::vaults::model::UnlockedKey;
use crate::secrets::vaults::storage::txn::{Target, Unlock};
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::recovery::import::{RecoveryCheck, RecoveryImport};
use crate::secrets::vaults::sync::rotation::{
    RotationPlan, RotationPrompt, RotationRecord, Rotations, Winner, winner,
};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::tests::state_file::key;
use crate::secrets::vaults::sync::transport::SyncTransport;

/// Disable sync of vault 0 on `mac`.
fn disable(mac: &Mac) {
    let key = || mac.vault(0).unlocked_key().unwrap();
    mac.writer
        .disable_sync(&mac.target(0), Unlock::Test(&key))
        .unwrap();
}

/// New kit of the current key of vault 0 on `mac`, confirmed as saved.
/// Returns whether the vault is still degraded.
fn save_kit(mac: &Mac) -> (RecoveryKit, bool) {
    let key = || mac.vault(0).unlocked_key().unwrap();
    let kit = mac
        .writer
        .create_kit(&mac.target(0), Unlock::Test(&key))
        .unwrap();
    let committed = kit
        .confirm_saved(&mac.writer, &mac.target(0), Unlock::Test(&key))
        .unwrap();
    (kit, committed.recovery_kit_missing)
}

/// Whether vault 0 of `mac` is degraded after a transaction.
fn degraded(mac: &Mac) -> bool {
    mac.sync().recovery_kit_missing
}

/// Rotate the key of Mac `first`, then of Mac `second` while the `key.json`
/// of Mac `first` is hidden. Returns the winner and the loser.
fn rotate_both(net: &Net, first: usize, second: usize) -> (usize, usize) {
    net.macs[first].rotate(&RotationPlan::rotate_key());
    let hidden = net.hide_key_file(first);
    net.macs[second].rotate(&RotationPlan::rotate_key());
    net.show_key_file(first, &hidden);
    let rotation = |n: usize| -> RotationRecord { net.macs[n].local().rotation.unwrap() };
    match winner(&rotation(first), &rotation(second)) {
        Winner::First => (first, second),
        Winner::Second => (second, first),
        Winner::UserChoice => panic!("Rotate sync key removes no signer"),
    }
}

#[test]
fn rotate_sync_key_rotates_every_vault_and_removes_nothing() {
    let net = Net::with(4, 2, |_, _| true);
    for v in 0..2 {
        for mac in &net.macs {
            mac.write_in(v, |_| Ok(())).unwrap();
        }
    }
    // Mac 3 leaves vault 0.
    disable(&net.macs[3]);
    net.macs[0].sync();

    let rotating = &net.macs[0];
    let authenticated = AtomicBool::new(false);
    let prompts = AtomicUsize::new(0);
    let read = |v: usize| -> UnlockedKey {
        if !authenticated.swap(true, Ordering::SeqCst) {
            prompts.fetch_add(1, Ordering::SeqCst);
        }
        rotating.vault(v).unlocked_key().unwrap()
    };
    let keys: Vec<Box<dyn Fn() -> UnlockedKey + Sync + '_>> = (0..2)
        .map(|v| Box::new(move || read(v)) as Box<dyn Fn() -> UnlockedKey + Sync>)
        .collect();
    let picks: Vec<(Uuid, Target, RotationPlan)> = (0..2)
        .map(|v| {
            (
                net.vault_ids[v],
                rotating.target(v),
                RotationPlan::rotate_key(),
            )
        })
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
    let rotated: Vec<_> = results
        .into_iter()
        .map(|(_, result)| result.unwrap())
        .collect();
    assert!(
        rotated
            .iter()
            .all(|r| r.removed.is_empty() && r.deleted.is_empty())
    );
    assert_eq!(
        rotated[0].remaining,
        vec![Net::replica(1), Net::replica(2)],
        "the Mac that left receives no wrapping"
    );
    assert_eq!(rotated[1].remaining.len(), 3);
    assert_eq!(
        net.wrapped_to(0, 2),
        BTreeSet::from([Net::replica(1), Net::replica(2)])
    );
    let state = rotating.state();
    assert!(state.store.removed.iter().next().is_none(), "no Removal");
    for n in 0..3 {
        assert!(net.has_directory(n), "directory of Mac {n} deleted");
    }

    net.macs[1].sync();
    let [RotationPrompt::Confirm { rotation, .. }] = &net.macs[1].prompts()[..] else {
        panic!("Mac 1 is not asked to confirm");
    };
    assert_eq!(rotation.signer, Net::replica(0));
    assert!(rotation.removed.is_empty());
    assert!(
        Rotations::paused(&net.macs[1].local()).is_empty(),
        "no joins are paused"
    );
}

#[test]
fn old_kit_opens_nothing_and_degraded_until_new_kit() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);
    let old_kit = RecoveryKit::create(net.vault_id(), KeyId(1), &key());
    let unlock_key = || net.macs[0].vault(0).unlocked_key().unwrap();
    old_kit
        .confirm_saved(
            &net.macs[0].writer,
            &net.macs[0].target(0),
            Unlock::Test(&unlock_key),
        )
        .unwrap();
    net.sync_all(&[0, 1]);
    assert!(!degraded(&net.macs[0]));
    assert!(!degraded(&net.macs[1]));

    let committed = net.macs[0]
        .rotate_in(0, &RotationPlan::rotate_key())
        .unwrap();
    assert!(committed.recovery_kit_missing);
    net.macs[1].sync_and_accept();
    assert!(degraded(&net.macs[1]));

    let folder: &dyn SyncTransport = &*net.folder;
    assert!(matches!(
        RecoveryImport::check(&old_kit, folder).unwrap(),
        RecoveryCheck::KitOutdated { .. }
    ));
    for n in 0..2 {
        assert!(
            net.key_file(n)
                .unwrap()
                .ages()
                .all(|age| age.key_id == KeyId(1)),
            "Mac {n} wrapped key 2 to the old kit"
        );
    }

    // A file under key 1 is ignored.
    let replica = Net::replica(1);
    net.plant(
        replica,
        &Net::keys_written(replica, replica, net.macs[1].keys.clone()),
    );
    net.macs[0].sync();
    assert!(
        !Sidecar::load(&net.macs[0].root, net.vault_id())
            .ignored
            .is_empty()
    );

    let (_, still_degraded) = save_kit(&net.macs[0]);
    assert!(!still_degraded);
    assert!(!degraded(&net.macs[1]));
}

#[test]
fn two_rotate_key_actions_converge_on_lower_fingerprint() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    let (won, lost) = rotate_both(&net, 0, 1);
    net.macs[lost].add("on-losing-key");
    let winning = net.macs[won].local().rotation.unwrap();

    net.macs[2].sync();
    assert_eq!(net.macs[2].confirm(), winning);
    net.macs[2].accept(&winning);
    let accepted = net.macs[lost].sync_and_accept();
    assert!(accepted.repeat.is_empty());
    net.sync_all(&[0, 1, 2]);

    let state = net.macs[0].state();
    for (n, mac) in net.macs.iter().enumerate() {
        assert_eq!(mac.local().rotation.as_ref(), Some(&winning));
        assert!(mac.state() == state, "Mac {n} state differs");
        assert!(mac.items().contains("on-losing-key"), "Mac {n}");
    }
}

#[test]
fn degraded_until_kit_for_new_key_including_losing_mac() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    let (won, lost) = rotate_both(&net, 0, 1);
    // The Mac whose rotation loses saves a kit for its own key.
    let (_, still_degraded) = save_kit(&net.macs[lost]);
    assert!(!still_degraded);
    assert!(degraded(&net.macs[won]));

    net.macs[lost].sync_and_accept();

    assert!(
        degraded(&net.macs[lost]),
        "a kit of the losing key opens nothing"
    );
    net.macs[2].sync_and_accept();
    assert!(degraded(&net.macs[2]));
    save_kit(&net.macs[won]);
    net.sync_all(&[won, lost, 2]);
    for (n, mac) in net.macs.iter().enumerate() {
        assert!(!degraded(mac), "Mac {n} is degraded");
    }
}
