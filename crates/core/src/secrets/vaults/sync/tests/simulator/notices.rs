//! Notices of changes from other Macs, suffixed keys, and Keep.

use super::{Mac, Sim};
use crate::secrets::vaults::autofill::item::{ItemAutofill, MatchKind, Website};
use crate::secrets::vaults::storage::txn::{Target, Unlock};
use crate::secrets::vaults::sync::report::SyncReport;
use crate::secrets::vaults::sync::sidecar::{Notice, Sidecar};
use crate::secrets::vaults::sync::view::{Entity, VaultView};

/// Autofill that holds one website.
fn website(url: &str) -> ItemAutofill {
    ItemAutofill {
        websites: vec![Website::new(url, MatchKind::Domain)],
        ..ItemAutofill::default()
    }
}

/// Sync report of the vault of `mac`.
fn report(mac: &Mac) -> SyncReport {
    let key = || mac.vault.unlocked_key().unwrap();
    SyncReport::read(&mac.writer, &Target::of(&mac.vault), Unlock::Test(&key)).unwrap()
}

/// Notices in the sidecar of `mac`.
fn notices(mac: &Mac) -> Vec<Notice> {
    Sidecar::load(&mac.root, mac.vault_id()).notices
}

#[test]
fn website_added_by_peer_is_noticed_until_dismissed() {
    let mut sim = Sim::new(2, None);
    sim.write(0, |vh| vh.add_item("mail", "Mail").map(|_| ()));
    sim.converge();
    let item = sim.macs[1].saved_vault().get_item("mail").unwrap().id;
    assert!(notices(&sim.macs[1]).is_empty());

    sim.write(0, |vh| vh.set_item_autofill("mail", website("example.com")));
    sim.converge();

    assert_eq!(notices(&sim.macs[1]), [Notice::WebsiteAdded { item }]);
    assert_eq!(
        report(&sim.macs[1]).notices,
        [Notice::WebsiteAdded { item }]
    );
    assert!(notices(&sim.macs[0]).is_empty());

    // Dismissing writes the sidecar only.
    let mac = &sim.macs[1];
    let key = || mac.vault.unlocked_key().unwrap();
    mac.writer
        .dismiss_notices(&Target::of(&mac.vault), Unlock::Test(&key))
        .unwrap();

    assert!(notices(&sim.macs[1]).is_empty());
    assert!(report(&sim.macs[1]).notices.is_empty());
}

#[test]
fn received_time_recorded_for_peer_that_changed_state() {
    let mut sim = Sim::new(2, None);
    let writer = Sim::replica(0);
    let reader = Sim::replica(1);
    assert!(
        Sidecar::load(&sim.macs[1].root, sim.macs[1].vault_id())
            .received_at
            .is_empty()
    );

    sim.write(0, |vh| vh.add_item("mail", "Mail").map(|_| ()));
    sim.converge();

    let received = Sidecar::load(&sim.macs[1].root, sim.macs[1].vault_id()).received_at;
    assert!(received[&writer] > 0);
    assert!(!received.contains_key(&reader));
    let own = Sidecar::load(&sim.macs[0].root, sim.macs[0].vault_id()).received_at;
    assert!(!own.contains_key(&writer));
}

#[test]
fn duplicate_keys_listed_as_suffixed_and_keep_writes_shown_key() {
    let mut sim = Sim::new(2, None);
    sim.write(0, |vh| vh.add_item("mail", "From zero").map(|_| ()));
    sim.write(1, |vh| vh.add_item("mail", "From one").map(|_| ()));
    sim.converge();

    // Both Macs show one item with the bare key and one with a suffix.
    let suffixed = report(&sim.macs[0]).suffixed_keys;
    assert_eq!(suffixed.len(), 1);
    assert_eq!(report(&sim.macs[1]).suffixed_keys, suffixed);
    let Entity::Item(item) = suffixed[0] else {
        panic!("{suffixed:?}");
    };
    let shown = VaultView::of(&sim.macs[0].state()).items[&item].key.clone();
    assert_ne!(shown, "mail");

    // Keep writes the shown key into the register, on one write id.
    let published = sim
        .checked(0, 1, |mac| {
            let key = || mac.vault.unlocked_key().unwrap();
            mac.writer.keep_keys(
                &Target::of(&mac.vault),
                Unlock::Test(&key),
                suffixed.clone(),
            )
        })
        .unwrap();
    assert!(published);
    sim.converge();

    for n in 0..2 {
        assert!(report(&sim.macs[n]).suffixed_keys.is_empty(), "Mac {n}");
        let view = VaultView::of(&sim.macs[n].state());
        assert_eq!(view.items[&item].key, shown, "Mac {n}");
        assert_eq!(sim.macs[n].saved_vault().get_item(&shown).unwrap().id, item);
    }
    sim.check_converged();
}

#[test]
fn keep_skips_entry_not_shown_with_suffix() {
    let mut sim = Sim::new(2, None);
    sim.write(0, |vh| vh.add_item("mail", "Mail").map(|_| ()));
    sim.converge();
    let item = sim.macs[0].saved_vault().get_item("mail").unwrap().id;

    let published = sim
        .checked(0, 0, |mac| {
            let key = || mac.vault.unlocked_key().unwrap();
            mac.writer.keep_keys(
                &Target::of(&mac.vault),
                Unlock::Test(&key),
                vec![Entity::Item(item)],
            )
        })
        .unwrap();

    assert!(!published);
}
