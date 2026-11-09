use proptest::prelude::*;
use uuid::Uuid;

use super::{Edit, Sim, Step};
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::view::VaultView;

/// Keys of the live items of Mac `n` that start with `mail`, sorted.
fn mail_keys(sim: &Sim, n: usize) -> Vec<String> {
    let mut keys: Vec<String> = sim.macs[n]
        .saved_vault()
        .list_items()
        .into_iter()
        .map(|item| item.key.clone())
        .filter(|key| key.starts_with("mail"))
        .collect();
    keys.sort();
    keys
}

const MAIL: Edit = Edit::Item {
    key: "mail",
    title: "Mail",
};

#[test]
fn three_macs_with_partial_views_that_create_one_key_show_same_keys_and_mint_nothing_for_it() {
    let mut sim = Sim::new(3, None);
    for n in 0..3 {
        assert!(sim.transaction(n, Some(&MAIL)));
    }

    // Each Mac joins the first file of one other Mac. Later files of Mac 0
    // would include the key that it received from Mac 1.
    for (n, from) in [(0, 1), (1, 2), (2, 0)] {
        let first = sim.files_of(from)[0];
        sim.deliver(n, first);
        assert!(sim.transaction(n, None));
        let keys = mail_keys(&sim, n);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], "mail");
        assert!(keys[1].starts_with("mail-"));
    }

    sim.converge();
    sim.check_quiet();

    let state = sim.check_converged();
    let keys = mail_keys(&sim, 0);
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0], "mail");
    assert!(keys[1..].iter().all(|key| key.starts_with("mail-")));
    // The bare key is shown for the key value with the lowest order key.
    let view = VaultView::of(&state);
    let lowest = state
        .store
        .items
        .iter()
        .min_by_key(|(_, item)| item.key.ordered()[0].0)
        .map(|(id, _)| *id)
        .unwrap();
    assert_eq!(view.items[&lowest].key, "mail");
    // Each replica minted its setup write and its creation, and nothing for
    // the duplicate.
    for n in 0..3 {
        let replica = Sim::replica(n);
        let minted: u64 = state
            .context
            .iter()
            .filter(|(actor, _)| state.actors[actor].replica == replica)
            .map(|(_, seq)| seq)
            .sum();
        assert_eq!(minted, 2, "Mac {n}");
    }
}

#[test]
fn join_that_produces_duplicate_key_writes_nothing_publishes_nothing_and_not_drift() {
    let mut sim = Sim::new(2, None);
    sim.transaction(0, Some(&MAIL));
    sim.transaction(1, Some(&MAIL));

    // Each Mac joins the other's `mail`, and one of the two is shown with a
    // suffix. The transaction checks that sync stays active.
    for (n, from) in [(0, 1), (1, 0)] {
        sim.deliver_latest(n, from);
        sim.transaction(n, None);
        let keys = mail_keys(&sim, n);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], "mail");
        assert!(keys[1].starts_with("mail-"));
    }

    // A transaction with no edit on each Mac writes and publishes nothing,
    // and sync stays active.
    sim.converge();
    sim.check_quiet();
    for mac in &sim.macs {
        let local = LocalSyncState::load(&mac.root, mac.vault_id(), &TestSigner::device()).unwrap();
        assert_eq!(local.stopped_build, None);
    }
    sim.check_converged();
}

#[test]
fn mac_whose_clock_is_behind_does_not_take_key_of_restored_item() {
    let mut sim = Sim::new(2, Some((1, -30 * 86_400)));
    // Mac 0 creates `mail`, and Mac 1 joins it and then its trash.
    sim.transaction(0, Some(&MAIL));
    let established = *sim.macs[0].saved_vault().get_item_id("mail").unwrap();
    sim.deliver_latest(1, 0);
    sim.transaction(1, None);
    sim.transaction(0, Some(&Edit::TrashItem(0)));
    sim.deliver_latest(1, 0);
    sim.transaction(1, None);
    // Mac 1 creates `mail` again while Mac 0 restores the established item.
    sim.transaction(1, Some(&MAIL));
    let later = *sim.macs[1].saved_vault().get_item_id("mail").unwrap();
    sim.transaction(0, Some(&Edit::RestoreItem(0)));

    sim.converge();
    sim.check_quiet();

    let state = sim.check_converged();
    let written_at = |id: &Uuid| {
        state.store.items.get(id).unwrap().key.ordered()[0]
            .1
            .written_at
    };
    assert!(written_at(&later) < written_at(&established));
    let view = VaultView::of(&state);
    assert_eq!(view.items[&established].key, "mail");
    assert!(view.items[&later].key.starts_with("mail-"));
    for n in 0..2 {
        let vault = sim.macs[n].saved_vault();
        assert_eq!(*vault.get_item_id("mail").unwrap(), established);
    }
    sim.check_established_keys(&state);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn concurrent_key_creation_shows_same_keys(
        steps in Step::steps(3),
    ) {
        // Each transaction checks that the vault shows the view of its state
        // and that no transaction with no edit mints.
        let mut sim = Sim::new(3, None);
        sim.apply_all(&steps);

        sim.converge();
        sim.check_quiet();

        sim.check_converged();
    }

    #[test]
    fn mac_whose_clock_is_behind_does_not_take_established_key(
        steps in Step::steps(3),
        slow in 0..3usize,
        behind in 1..=30 * 86_400i64,
    ) {
        let mut sim = Sim::new(3, Some((slow, -behind)));
        sim.apply_all(&steps);

        sim.converge();
        sim.check_quiet();

        let state = sim.check_converged();
        sim.check_established_keys(&state);
    }
}
