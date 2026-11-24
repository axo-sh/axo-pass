//! Removal of recovery kits, the `Age` wrappings dropped with them, and
//! "Revoke and replace", on the Macs of [`Net`].

use super::kits::save_kit;
use super::{Mac, Net};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::storage::txn::{Committed, Unlock};
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::recovery::import::{RecoveryCheck, RecoveryImport};
use crate::secrets::vaults::sync::rotation::RotationPlan;
use crate::secrets::vaults::sync::transport::SyncTransport;

/// Remove the recipient of `recipient` from vault 0 of `mac`.
fn remove(mac: &Mac, recipient: &str) -> Result<Committed<()>, Error> {
    let key = || mac.vault(0).unlocked_key().unwrap();
    mac.writer
        .remove_recovery(&mac.target(0), Unlock::Test(&key), recipient)
}

/// Key ids of the `Age` wrappings of `kit` in the `key.json` of Mac `n`.
fn age_keys(net: &Net, n: usize, kit: &RecoveryKit) -> Vec<KeyId> {
    net.key_file(n)
        .map(|file| {
            file.ages()
                .filter(|age| age.recipient == kit.recipient())
                .map(|age| age.key_id)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the report of vault 0 of `mac` lists `kit`.
fn lists(mac: &Mac, kit: &RecoveryKit) -> bool {
    mac.report_in(0)
        .recovery_kits
        .iter()
        .any(|entry| entry.recipient == kit.recipient())
}

#[test]
fn removal_drops_entry_and_own_wrappings() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);
    let kit = save_kit(&net.macs[0], None);
    net.sync_all(&[0, 1]);
    assert_eq!(age_keys(&net, 0, &kit), vec![KeyId(1)]);
    assert_eq!(age_keys(&net, 1, &kit), vec![KeyId(1)]);

    let committed = remove(&net.macs[0], &kit.recipient()).unwrap();

    assert!(committed.recovery_kit_missing);
    assert!(!lists(&net.macs[0], &kit));
    assert!(age_keys(&net, 0, &kit).is_empty());
    // Mac 1 joins the removal. Its `key.json` keeps the copy until it
    // removes the kit itself, rotates, or accepts a rotation.
    net.sync_all(&[0, 1]);
    assert!(
        net.macs[1]
            .state()
            .store
            .recovery
            .get(&kit.recipient())
            .is_none()
    );
    assert!(!lists(&net.macs[1], &kit));
    assert_eq!(age_keys(&net, 1, &kit), vec![KeyId(1)]);
}

#[test]
fn removal_of_unknown_kit_refused() {
    let net = Net::new(1);
    let unknown = age::x25519::Identity::generate().to_public().to_string();

    assert!(matches!(
        remove(&net.macs[0], &unknown),
        Err(Error::RecoveryKitNotRemoved(_))
    ));
    assert!(matches!(
        net.macs[0].rotate_in(0, &RotationPlan::revoke_kit(unknown)),
        Err(Error::RotationRefused(_))
    ));
}

#[test]
fn revoke_and_replace_drops_copies_on_rotation_and_acceptance() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);
    let revoked = save_kit(&net.macs[0], Some("Lost"));
    net.sync_all(&[0, 1]);
    assert_eq!(age_keys(&net, 1, &revoked), vec![KeyId(1)]);

    let rotated = net.macs[0].rotate(&RotationPlan::revoke_kit(revoked.recipient()));

    assert_eq!(rotated.key_id, KeyId(2));
    assert!(rotated.removed.is_empty());
    assert!(!lists(&net.macs[0], &revoked));
    assert!(age_keys(&net, 0, &revoked).is_empty());
    // No kit is left, so a new kit must be saved.
    assert!(net.macs[0].report_in(0).recovery_kits.is_empty());
    assert!(net.macs[0].report_in(0).recovery_kit_missing);

    net.macs[1].sync_and_accept();

    assert_eq!(net.macs[1].local().key_id, KeyId(2), "Mac 1 keeps access");
    assert!(!lists(&net.macs[1], &revoked));
    assert!(age_keys(&net, 1, &revoked).is_empty());
}

#[test]
fn revoked_kit_opens_no_new_key() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);
    let revoked = save_kit(&net.macs[0], None);
    net.sync_all(&[0, 1]);

    net.macs[0].rotate(&RotationPlan::revoke_kit(revoked.recipient()));
    net.macs[1].sync_and_accept();
    net.sync_all(&[0, 1]);

    for n in 0..2 {
        assert!(age_keys(&net, n, &revoked).is_empty(), "Mac {n}");
    }
    let folder: &dyn SyncTransport = &*net.folder;
    assert!(matches!(
        RecoveryImport::check(&revoked, folder).unwrap(),
        RecoveryCheck::KitOutdated {
            highest: KeyId(2),
            ..
        }
    ));
    // A kit saved for the new key opens it.
    let new = save_kit(&net.macs[0], None);
    net.sync_all(&[0, 1]);
    assert!(matches!(
        RecoveryImport::check(&new, folder).unwrap(),
        RecoveryCheck::Recovered(_)
    ));
}
