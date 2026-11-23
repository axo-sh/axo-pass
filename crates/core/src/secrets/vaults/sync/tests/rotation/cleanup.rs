//! Cleanup of retired and departed replicas.

use jiff::tz::TimeZone;
use secrecy::SecretString;
use uuid::Uuid;

use super::{Mac, Net};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::storage::txn::Unlock;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::model::{CredentialId, KeyId};
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::rotation::RotationPlan;
use crate::secrets::vaults::sync::tests::state_file::key;
use crate::secrets::vaults::sync::view::VaultView;

const DAY: i64 = 86_400;

/// Disable sync of vault 0 on `mac`.
fn disable(mac: &Mac) {
    let key = || mac.vault(0).unlocked_key().unwrap();
    mac.writer
        .disable_sync(&mac.target(0), Unlock::Test(&key))
        .unwrap();
}

/// Whether the state of `mac` holds a name, keys, or `left` entry of
/// `replica`.
fn knows(mac: &Mac, replica: ReplicaId) -> bool {
    let store = mac.state().store;
    store.replica_names.get(&replica).is_some()
        || store.replica_keys.get(&replica).is_some()
        || store.left.get(&replica).is_some()
}

#[test]
fn departed_replica_excluded_from_retired_wrapping_condition_and_cleaned() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    let kit = RecoveryKit::create(net.vault_id(), KeyId(1), &key());
    let unlock_key = || net.macs[0].vault(0).unlocked_key().unwrap();
    kit.confirm_saved(
        &net.macs[0].writer,
        &net.macs[0].target(0),
        Unlock::Test(&unlock_key),
    )
    .unwrap();
    net.sync_all(&[0, 1, 2]);
    disable(&net.macs[2]);
    net.macs[0].sync();
    let old_wrappings = |n: usize| {
        let file = net.key_file(n).unwrap();
        file.ages().filter(|age| age.key_id == KeyId(1)).count()
            + file.devices().filter(|d| d.key_id == KeyId(1)).count()
    };
    assert!(old_wrappings(0) > 0);

    net.macs[0].rotate(&RotationPlan::rotate_key());
    net.macs[1].sync_and_accept();
    net.macs[0].sync();

    // Mac 2 left and never published under key 2, and the wrappings of key
    // 1 are dropped.
    assert_eq!(old_wrappings(0), 0);

    let cleaned = net.macs[0].clean(Net::replica(2)).unwrap();

    assert!(cleaned.value.deleted);
    assert!(!net.has_directory(2));
    assert!(!knows(&net.macs[0], Net::replica(2)));
    net.macs[1].sync();
    assert!(!knows(&net.macs[1], Net::replica(2)));
}

#[test]
fn cleanup_keeps_shown_last_used_dates() {
    let net = Net::new(3);
    net.sync_all(&[0, 1, 2]);
    let passkey = |mac: &Mac, day: i64| {
        mac.write_in(0, |vh| {
            vh.mark_credential_used_in("site", "passkey", day * DAY, &TimeZone::UTC)
                .map(|_| ())
        })
        .unwrap();
    };
    net.macs[0]
        .write_in(0, |vh| {
            vh.add_item("site", "Site")?;
            vh.add_secret(
                "site",
                "passkey",
                "Passkey",
                FieldKind::Passkey,
                SecretString::from("{}".to_string()),
            )
        })
        .unwrap();
    net.sync_all(&[0, 1, 2]);
    passkey(&net.macs[0], 3);
    passkey(&net.macs[2], 5);
    net.sync_all(&[0, 1, 2]);
    disable(&net.macs[2]);
    net.sync_all(&[0, 1]);
    let shown = |mac: &Mac| -> Option<i64> {
        let state = mac.state();
        let view = VaultView::of(&state);
        let id: CredentialId = *state.store.credentials.iter().next().unwrap().0;
        view.credentials[&id].last_used_day_at
    };
    assert_eq!(shown(&net.macs[0]), Some(5 * DAY));

    net.macs[0].clean(Net::replica(2)).unwrap();
    net.sync_all(&[0, 1]);

    for n in [0, 1] {
        assert_eq!(shown(&net.macs[n]), Some(5 * DAY), "Mac {n}");
        assert!(!knows(&net.macs[n], Net::replica(2)));
        let state = net.macs[n].state();
        let (_, credential) = state.store.credentials.iter().next().unwrap();
        assert!(credential.last_used_day_at.get(&Net::replica(2)).is_none());
    }
}

#[test]
fn relinked_replica_cleaned() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);
    // An old replica id of Mac 1, from before a re-link, with its keys.
    let old = ReplicaId(Uuid::from_u128(0x33));
    net.plant(old, &Net::keys_written(old, old, net.macs[1].keys.clone()));
    net.macs[0].sync();
    assert!(knows(&net.macs[0], old));

    let cleaned = net.macs[0].clean(old).unwrap();

    assert!(cleaned.value.deleted);
    assert!(!knows(&net.macs[0], old));
    assert!(net.folder.names(net.vault_id(), old).is_empty());
}

#[test]
fn cleanup_of_live_replica_refused() {
    let net = Net::new(2);
    net.sync_all(&[0, 1]);

    let refused = net.macs[0].clean(Net::replica(1));

    assert!(matches!(refused, Err(Error::CleanupRefused(_))));
    assert!(net.has_directory(1));
    assert!(knows(&net.macs[0], Net::replica(1)));
}
