//! Recovery kit entries of the sync report, and kit labels, on the Macs of
//! [`Net`].

use super::{Mac, Net};
use crate::secrets::vaults::storage::txn::Unlock;
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::recovery::{MAX_LABEL_CHARS, RecoveryKit};
use crate::secrets::vaults::sync::report::RecoveryKitEntry;
use crate::secrets::vaults::sync::rotation::RotationPlan;

/// Add the recipient of `kit` to vault 0 of `mac`.
pub(super) fn confirm(mac: &Mac, kit: &RecoveryKit) {
    let key = || mac.vault(0).unlocked_key().unwrap();
    kit.confirm_saved(&mac.writer, &mac.target(0), Unlock::Test(&key))
        .unwrap();
}

/// New kit of the current key of vault 0 on `mac` with the label `label`,
/// confirmed as saved.
pub(super) fn save_kit(mac: &Mac, label: Option<&str>) -> RecoveryKit {
    let key = || mac.vault(0).unlocked_key().unwrap();
    let kit = mac
        .writer
        .create_kit(&mac.target(0), Unlock::Test(&key))
        .unwrap()
        .labeled(label);
    confirm(mac, &kit);
    kit
}

/// Report entry of `kit` in vault 0 of `mac`.
pub(super) fn entry(mac: &Mac, kit: &RecoveryKit) -> RecoveryKitEntry {
    mac.report_in(0)
        .recovery_kits
        .into_iter()
        .find(|entry| entry.recipient == kit.recipient())
        .expect("report lists the kit")
}

#[test]
fn one_kit_listed_with_its_writer() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);

    let kit = save_kit(&net.macs[0], None);
    net.sync_all(&[0, 1]);

    let state = net.macs[0].state();
    let register = state.store.recovery.get(&kit.recipient()).unwrap();
    let written_at = register.ordered().last().unwrap().1.written_at;
    let expected = RecoveryKitEntry {
        recipient: kit.recipient(),
        key_id: KeyId(1),
        current: true,
        label: None,
        written_at,
        added_by: Some("Mac 0".to_string()),
    };
    for mac in &net.macs {
        assert_eq!(
            mac.report_in(0).recovery_kits,
            vec![expected.clone()],
            "Mac {}",
            mac.n
        );
    }
}

#[test]
fn concurrent_values_show_newest() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);
    let kit = save_kit(&net.macs[0], Some("Older"));
    // Mac 1 does not see the write of Mac 0. It writes once more first, so
    // its value of the same recipient has the higher counter.
    let hidden = net.stash(Net::replica(0));
    net.macs[1].add("item");
    let same = RecoveryKit::parse(&kit.text())
        .unwrap()
        .labeled(Some("Newer"));
    confirm(&net.macs[1], &same);
    net.unstash(Net::replica(0), &hidden);

    net.sync_all(&[0, 1]);

    let state = net.macs[0].state();
    let register = state.store.recovery.get(&kit.recipient()).unwrap();
    assert_eq!(register.values().count(), 2, "values are concurrent");
    for mac in &net.macs {
        let entry = entry(mac, &kit);
        assert_eq!(entry.label.as_deref(), Some("Newer"), "Mac {}", mac.n);
        assert_eq!(entry.added_by.as_deref(), Some("Mac 1"), "Mac {}", mac.n);
        assert!(entry.current, "Mac {}", mac.n);
    }
}

#[test]
fn kit_of_earlier_key_not_current() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);
    let old = save_kit(&net.macs[0], None);
    net.sync_all(&[0, 1]);

    net.macs[0].rotate(&RotationPlan::rotate_key());
    net.macs[1].sync_and_accept();
    net.sync_all(&[0, 1]);
    for mac in &net.macs {
        let old = entry(mac, &old);
        assert_eq!(old.key_id, KeyId(1), "Mac {}", mac.n);
        assert!(!old.current, "Mac {}", mac.n);
        assert!(mac.report_in(0).recovery_kit_missing, "Mac {}", mac.n);
    }

    // The kit for the new key replaces the kit of the earlier key.
    let new = save_kit(&net.macs[0], None);
    net.sync_all(&[0, 1]);

    for mac in &net.macs {
        assert_eq!(mac.report_in(0).recovery_kits.len(), 1, "Mac {}", mac.n);
        let new = entry(mac, &new);
        assert_eq!(new.key_id, KeyId(2), "Mac {}", mac.n);
        assert!(new.current, "Mac {}", mac.n);
        assert!(!mac.report_in(0).recovery_kit_missing, "Mac {}", mac.n);
    }
}

#[test]
fn label_round_trips_through_state_files() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);

    let kit = save_kit(&net.macs[0], Some("  Printed, home safe  "));
    net.sync_all(&[0, 1]);

    for mac in &net.macs {
        let state = mac.state();
        let register = state.store.recovery.get(&kit.recipient()).unwrap();
        let shown = &register.ordered().last().unwrap().1.value;
        assert_eq!(
            shown.label.as_deref(),
            Some("Printed, home safe"),
            "Mac {}",
            mac.n
        );
        assert_eq!(
            entry(mac, &kit).label.as_deref(),
            Some("Printed, home safe"),
            "Mac {}",
            mac.n
        );
    }
}

#[test]
fn label_trimmed_and_cut() {
    let net = Net::new(1);
    let key = || net.macs[0].vault(0).unlocked_key().unwrap();
    let kit = || {
        net.macs[0]
            .writer
            .create_kit(&net.macs[0].target(0), Unlock::Test(&key))
            .unwrap()
    };

    assert_eq!(kit().labeled(Some("   ")).label, None);
    assert_eq!(kit().labeled(None).label, None);
    let long = "a".repeat(MAX_LABEL_CHARS + 10);
    assert_eq!(
        kit()
            .labeled(Some(&long))
            .label
            .map(|label| label.chars().count()),
        Some(MAX_LABEL_CHARS)
    );
}

#[test]
fn kit_of_cleaned_writer_has_no_device() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    let kit = save_kit(&net.macs[2], None);
    net.sync_all(&[0, 1, 2]);
    let key = || net.macs[2].vault(0).unlocked_key().unwrap();
    net.macs[2]
        .writer
        .disable_sync(&net.macs[2].target(0), Unlock::Test(&key))
        .unwrap();
    net.sync_all(&[0, 1]);

    net.macs[0].clean(Net::replica(2)).unwrap();

    let entry = entry(&net.macs[0], &kit);
    assert_eq!(entry.added_by, None);
    assert!(entry.current);
}
