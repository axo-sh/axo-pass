//! Simulator of a retired replica's removal after random edits and partial
//! syncs.

use std::collections::BTreeSet;

use proptest::collection::vec;
use proptest::prelude::*;

use super::Net;
use crate::secrets::vaults::sync::rotation::{RemovalReason, RotationPlan};

/// Step of a run: Mac `mac` adds an item if `edit`, or else syncs.
fn steps() -> impl Strategy<Value = Vec<(usize, bool)>> {
    vec((0..3usize, any::<bool>()), 0..12)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Every write of a replica removed as retired is kept on every remaining
    /// replica, including writes that only its own file holds when the
    /// rotation starts. Its directory is deleted only after a publish whose
    /// context covers its state.
    #[test]
    fn retired_replica_writes_all_kept(steps in steps()) {
        let net = Net::new(3);
        net.sync_all(&[0, 1, 2]);
        let mut added = BTreeSet::new();
        for (i, (mac, edit)) in steps.into_iter().enumerate() {
            if edit {
                let key = format!("item-{mac}-{i}");
                net.macs[mac].add(&key);
                added.insert(key);
            } else {
                net.macs[mac].sync();
            }
        }
        // The last write of Mac 2 is only in its own file.
        net.macs[2].add("last-of-retired");
        added.insert("last-of-retired".to_string());
        let retired = net.macs[2].state().context;

        let rotated = net.macs[0].rotate(&RotationPlan::remove([(
            Net::replica(2),
            RemovalReason::Retired,
        )]));

        prop_assert_eq!(rotated.deleted, vec![Net::replica(2)]);
        let published = net.macs[0].state().context;
        for (actor, seq) in retired.iter() {
            prop_assert!(published.get(actor) >= seq, "publish does not cover the retired state");
        }
        net.macs[1].sync_and_accept();
        net.sync_all(&[0, 1]);
        for n in [0, 1] {
            let items = net.macs[n].items();
            for key in &added {
                prop_assert!(items.contains(key), "Mac {} lost {}", n, key);
            }
        }
    }
}
