//! Concurrent rotations to one key id.

use uuid::Uuid;

use super::Net;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::KeyFingerprint;
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::rotation::{
    RemovalReason, RotationPlan, RotationPrompt, RotationRecord, Winner, winner,
};
use crate::secrets::vaults::sync::sidecar::Sidecar;

/// Plan that removes the Macs of `macs` as lost or stolen.
fn lost(macs: &[usize]) -> RotationPlan {
    RotationPlan::remove(macs.iter().map(|n| (Net::replica(*n), RemovalReason::Lost)))
}

/// Rotation of the current key of Mac `n`.
fn rotation_of(net: &Net, n: usize) -> RotationRecord {
    net.macs[n].local().rotation.unwrap()
}

/// Rotate Mac `first` with `a`, then Mac `second` with `b` while the
/// `key.json` of Mac `first` is hidden, so neither sees the other first.
fn rotate_concurrently(net: &Net, first: usize, a: &RotationPlan, second: usize, b: &RotationPlan) {
    net.macs[first].rotate(a);
    let hidden = net.hide_key_file(first);
    net.macs[second].rotate(b);
    net.show_key_file(first, &hidden);
}

fn record(signer: u128, fingerprint: u8, removed: &[u128]) -> RotationRecord {
    let replica = |n: u128| ReplicaId(Uuid::from_u128(n));
    RotationRecord {
        signer: replica(signer),
        key_id: KeyId(2),
        key_fingerprint: KeyFingerprint([fingerprint; 16]),
        removed: removed.iter().map(|n| replica(*n)).collect(),
        remaining: Vec::new(),
    }
}

#[test]
fn winner_rules_in_order() {
    // Neither removes the signer of the other: the lower fingerprint wins.
    assert_eq!(
        winner(&record(1, 1, &[3]), &record(2, 2, &[4])),
        Winner::First
    );
    assert_eq!(
        winner(&record(1, 9, &[3]), &record(2, 2, &[4])),
        Winner::Second
    );
    // A rotation whose signer the other removes loses, whatever its
    // fingerprint.
    assert_eq!(
        winner(&record(1, 1, &[3]), &record(3, 9, &[4])),
        Winner::First
    );
    assert_eq!(
        winner(&record(3, 1, &[4]), &record(1, 9, &[3])),
        Winner::Second
    );
    // Each removes the signer of the other: the user chooses.
    assert_eq!(
        winner(&record(1, 1, &[2]), &record(2, 9, &[1])),
        Winner::UserChoice
    );
}

#[test]
fn concurrent_rotations_converge_on_lower_fingerprint() {
    // Keys are random, so each winner is taken in some runs.
    for _ in 0..8 {
        converge_on_lower_fingerprint();
    }
}

/// One run of [`concurrent_rotations_converge_on_lower_fingerprint`]. Mac 0
/// removes Mac 3, and Mac 1 removes Macs 3 and 4.
fn converge_on_lower_fingerprint() {
    let net = Net::new(5);
    net.sync_all(&[0, 1, 2, 3, 4]);
    rotate_concurrently(&net, 0, &lost(&[3]), 1, &lost(&[3, 4]));
    net.macs[1].add("by-signer-1");
    let (a, b) = (rotation_of(&net, 0), rotation_of(&net, 1));
    let (won, lost_by) = match winner(&a, &b) {
        Winner::First => (0, 1),
        Winner::Second => (1, 0),
        Winner::UserChoice => panic!("neither rotation removes the other signer"),
    };
    let winning = rotation_of(&net, won);

    // Mac 2 accepts the losing rotation first, then the winner.
    let hidden = net.hide_key_file(won);
    net.macs[2].sync_and_accept();
    net.macs[2].add("on-losing-key");
    net.show_key_file(won, &hidden);
    net.macs[2].sync();
    match &net.macs[2].prompts()[..] {
        [RotationPrompt::Confirm { rotation, replaces }] => {
            assert!(*replaces);
            assert_eq!(*rotation, winning);
        },
        prompts => panic!("{prompts:?}"),
    }
    net.macs[2].accept(&winning);

    // The signer of the losing rotation accepts the winner and repeats the
    // removals the winner lacks. The signer of the winner is not asked.
    let repeat = net.macs[lost_by].sync_and_accept().repeat;
    let losing = if lost_by == 0 { &a } else { &b };
    let expected: Vec<ReplicaId> = losing
        .removed
        .iter()
        .filter(|r| !winning.removed.contains(r))
        .copied()
        .collect();
    assert_eq!(repeat, expected);
    net.macs[won].sync();
    assert!(net.macs[won].prompts().is_empty());

    net.sync_all(&[0, 1, 2]);
    let state = net.macs[0].state();
    for n in [0, 1, 2] {
        let local = net.macs[n].local();
        assert_eq!(local.key_id, KeyId(2));
        assert_eq!(local.rotation.as_ref().unwrap(), &winning, "Mac {n}");
        assert!(net.macs[n].state() == state, "Mac {n} state differs");
        let items = net.macs[n].items();
        assert!(items.contains("by-signer-1"), "Mac {n}");
        assert!(items.contains("on-losing-key"), "Mac {n}");
        let sidecar = Sidecar::load(&net.macs[n].root, net.vault_id());
        assert!(sidecar.quarantined.is_empty(), "Mac {n} quarantined a file");
        // Only the removals of the winner are in the state.
        let removed: Vec<ReplicaId> = net.macs[n]
            .state()
            .store
            .removed
            .iter()
            .map(|(replica, _)| *replica)
            .collect();
        assert_eq!(removed, winning.removed, "Mac {n}");
    }
    let kept = net.macs[2].local().pinned_keys[&Net::replica(4)].clone();
    assert_eq!(kept.revoked, winning.removes(Net::replica(4)));

    if !repeat.is_empty() {
        let plan = RotationPlan::remove(repeat.iter().map(|r| (*r, RemovalReason::Lost)));
        let rotated = net.macs[lost_by].rotate(&plan);
        assert_eq!(rotated.key_id, KeyId(3));
        assert_eq!(rotated.removed, vec![Net::replica(4)]);
    }
}

#[test]
fn mutual_removals_user_chooses_and_signers_keep_own() {
    let net = Net::new(4);
    net.sync_all(&[0, 1, 2, 3]);
    rotate_concurrently(&net, 0, &lost(&[1]), 1, &lost(&[0]));
    let (a, b) = (rotation_of(&net, 0), rotation_of(&net, 1));

    net.macs[2].sync();
    let prompts = net.macs[2].prompts();
    let [
        RotationPrompt::Choose {
            first,
            second,
            current,
        },
    ] = &prompts[..]
    else {
        panic!("{prompts:?}");
    };
    assert!(!current);
    let shown = [first.clone(), second.clone()];
    assert!(shown.contains(&a) && shown.contains(&b));
    // The user picks the rotation with the higher fingerprint.
    let chosen = if a.key_fingerprint.0 > b.key_fingerprint.0 {
        &a
    } else {
        &b
    };
    net.macs[2].accept(chosen);

    assert_eq!(net.macs[2].local().rotation.as_ref(), Some(chosen));
    assert!(net.macs[2].prompts().is_empty());
    for n in [0, 1] {
        net.macs[n].sync();
        assert!(net.macs[n].prompts().is_empty(), "Mac {n} is asked");
        let own = rotation_of(&net, n);
        assert_eq!(own.signer, Net::replica(n), "Mac {n} keeps its own");
    }
}

#[test]
fn rotation_by_signer_other_removes_loses_whatever_fingerprint() {
    let net = Net::new(4);
    net.sync_all(&[0, 1, 2, 3]);
    rotate_concurrently(&net, 0, &lost(&[2]), 2, &lost(&[3]));
    let a = rotation_of(&net, 0);

    net.macs[1].sync();

    assert_eq!(net.macs[1].confirm(), a);
}
