//! Sync report, root chosen again, and the recovery kit of a degraded vault
//! (10.6).
//!
//! The report runs on the load cases of `sync/tests/load.rs`, on a [`synced`]
//! vault, and on Macs that enable and join through one `FakeTransport`. The
//! root tests resolve each vault by the root in its sidecar through
//! `RootTransports`, so a vault with no root has no transport.

use std::collections::BTreeSet;
use std::fs;
use std::mem::discriminant;
use std::path::PathBuf;
use std::sync::Arc;

use uuid::Uuid;

use super::join::peer_state;
use super::join_sync::{Mac, enable, file_key, opened, recovered, root};
use super::load::{Fixture, GENERATION, REPLICA, cases, state};
use super::manager::{Managed, folder_root, set_root};
use super::state_file::key;
use super::transport::FakeTransport;
use super::txn::{saved, synced};
use super::view::State;
use crate::secrets::vaults::Error;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::storage::txn::{Disabled, Target, Unlock};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::join_sync::JoinInto;
use crate::secrets::vaults::sync::keys::SyncKey;
use crate::secrets::vaults::sync::load::{Mismatch, SyncLoad};
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::meta::MetaFile;
use crate::secrets::vaults::sync::model::{KeyId, SYNC_FORMAT_VERSION};
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::report::{KnownMac, SyncReport};
use crate::secrets::vaults::sync::sidecar::{Health, LoadFailure, Sidecar};
use crate::secrets::vaults::sync::state_file::padded::PaddedBody;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::status::{BUILD_ID, PausedCause, StopCause, SyncStatus};
use crate::secrets::vaults::sync::transport::{RootTransports, SyncTransport, TransportRoot};
use crate::secrets::vaults::sync::view::VaultView;

/// Display name of the Mac that enables sync, as [`enable`] names it.
const MAC_A: &str = "Work Mac";

/// Display name of the Mac that joins and edits.
const MAC_B: &str = "Home Mac";

/// Display name of the Mac that joins and then disables sync.
const MAC_C: &str = "Studio Mac";

/// Key of the fixture vaults.
const VAULT_KEY: &str = "personal";

/// Replica of a Mac that enabled sync separately.
const SEPARATE: ReplicaId = ReplicaId(Uuid::from_u128(3));

/// Root of a synced folder that holds no vault.
fn empty_root() -> TransportRoot {
    TransportRoot::Folder {
        path: PathBuf::from("/report/Empty"),
    }
}

/// Report of the vault of `fx`, unlocked with its file key.
fn read_report(fx: &Fixture) -> Result<SyncReport, Error> {
    let unlocked = || fx.vault.unlocked_key().unwrap();
    SyncReport::read(
        fx.catalog.files(),
        &Target::of(&fx.vault),
        Unlock::Test(&unlocked),
    )
}

/// New kit of the vault of `fx`, unlocked with its file key.
fn create_kit(fx: &Fixture) -> Result<RecoveryKit, Error> {
    let unlocked = || fx.vault.unlocked_key().unwrap();
    fx.catalog.create_kit(VAULT_KEY, Unlock::Test(&unlocked))
}

/// Add the recipient of `kit` to the vault of `fx`.
fn confirm(fx: &Fixture, kit: &RecoveryKit) -> Result<bool, Error> {
    let unlocked = || fx.vault.unlocked_key().unwrap();
    kit.confirm_saved(
        fx.catalog.files(),
        &Target::of(&fx.vault),
        Unlock::Test(&unlocked),
    )
    .map(|committed| committed.recovery_kit_missing)
}

/// Vault file, sync state, staged file, and sidecar of `fx` as they are on
/// disk.
fn files(fx: &Fixture) -> [Option<Vec<u8>>; 4] {
    [
        fx.vault.path.clone(),
        LocalSyncState::path(&fx.root, fx.id()),
        LocalSyncState::staged_path(&fx.root, fx.id()),
        Sidecar::path(&fx.root, fx.id()),
    ]
    .map(|path| fs::read(path).ok())
}

/// Write `meta.json` of the vault of `fx` in the folder `transport`.
fn put_meta(transport: &FakeTransport, fx: &Fixture) {
    transport.put_meta(fx.id(), &MetaFile::new(fx.id()).to_bytes());
}

#[test]
fn report_counts_conflicts_lists_quarantined_files_with_their_macs_and_known_macs_with_last_active_time_and_left()
 {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.add_item().unwrap();
    // Mac B imports one export, edits the title, and joins with the kit of
    // A.
    let b = Mac::new(transport.clone());
    let b_vault = b.copy_of(&a);
    let setup = enable(&a, root());
    let b_target = Target::of(&b_vault);
    let b_key = || b_vault.unlocked_key().unwrap();
    b.catalog
        .files()
        .write(&b_target, Unlock::Test(&b_key), |vh| {
            vh.add_item("item", "Home").map(|_| ())
        })
        .unwrap();
    let b_join = recovered(&setup, &*transport);
    b.catalog
        .join_sync(
            &b_join,
            JoinInto::Existing(b_target),
            &root(),
            MAC_B,
            Unlock::Test(&b_key),
        )
        .unwrap();
    // Mac C imports as a new vault and turns sync off.
    let c = Mac::new(transport.clone());
    let c_join = recovered(&setup, &*transport);
    let c_file_key = || file_key(a.id(), 3);
    let c_vault = c
        .catalog
        .join_sync(
            &c_join,
            JoinInto::New,
            &root(),
            MAC_C,
            Unlock::Test(&c_file_key),
        )
        .unwrap()
        .vault;
    let c_key = || c_vault.unlocked_key().unwrap();
    let disabled = c
        .catalog
        .files()
        .disable_sync(&Target::of(&c_vault), Unlock::Test(&c_key))
        .unwrap();
    assert_eq!(disabled.value, Disabled::Left);
    // A torn state file of B, whose bytes do not hash to its name.
    let b_replica = b_join.replica_id();
    let padded = PaddedBody::of(&State::default()).unwrap();
    let mut torn = StateFile::encode(&padded, a.id(), b_replica, KeyId(1), setup.key()).unwrap();
    let name = StateFile::name(StateHash::of(&torn));
    torn.truncate(torn.len() - 1);
    transport.put(a.id(), b_replica, &name, &torn);
    a.write(|_| Ok(())).unwrap();
    let before = files(&a);
    let writes = transport.writes();

    let report = read_report(&a).unwrap();

    assert_eq!(files(&a), before);
    assert_eq!(transport.writes(), writes);
    assert_eq!(report.case, SyncLoad::Current);
    assert_eq!(
        report.status,
        Some(SyncStatus::Paused(vec![PausedCause::Quarantined {
            files: 1
        }]))
    );
    assert_eq!(report.conflicts, 1);
    assert_eq!(report.quarantined.len(), 1);
    let quarantined = &report.quarantined[0];
    assert_eq!(quarantined.replica, b_replica);
    assert_eq!(quarantined.mac_name.as_deref(), Some(MAC_B));
    assert_eq!(quarantined.name, name);
    let (_, state) = opened(&a.root, a.id());
    let last_active = |replica: ReplicaId| {
        state
            .actors
            .values()
            .filter(|actor| actor.replica == replica)
            .map(|actor| actor.started_at)
            .max()
    };
    let a_replica = setup.replica_id();
    let c_replica = c_join.replica_id();
    let mut expected = [
        (a_replica, MAC_A, true, false),
        (b_replica, MAC_B, false, false),
        (c_replica, MAC_C, false, true),
    ]
    .map(|(replica, name, this_mac, left)| {
        (
            replica,
            name.to_string(),
            this_mac,
            left,
            last_active(replica),
        )
    })
    .to_vec();
    expected.sort_by_key(|mac| mac.0);
    let shown: Vec<_> = report
        .known_macs
        .iter()
        .map(|mac: &KnownMac| {
            let KnownMac {
                replica,
                name,
                this_mac,
                left,
                last_active,
                ..
            } = mac.clone();
            (replica, name, this_mac, left, last_active)
        })
        .collect();
    assert_eq!(shown, expected);
    assert!(
        report
            .known_macs
            .iter()
            .all(|mac| mac.last_active.is_some())
    );
    assert!(!report.recovery_kit_missing);
    assert_eq!(report.override_preview, None);
    assert_eq!(report.root, Some(root()));
    assert!(!report.needs_folder());
}

#[test]
fn report_of_vault_paused_by_separate_key_lists_cause() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let padded = PaddedBody::of(&peer_state(&fx, SEPARATE, "separate")).unwrap();
    let other_key = SyncKey::from_bytes([9; 32]);
    let bytes = StateFile::encode(&padded, fx.id(), SEPARATE, KeyId(1), &other_key).unwrap();
    transport.put_state(fx.id(), SEPARATE, &bytes);
    fx.add_item().unwrap();

    let report = read_report(&fx).unwrap();

    assert_eq!(
        report.status,
        Some(SyncStatus::Paused(vec![PausedCause::SeparateKey {
            replicas: 1
        }]))
    );
    assert!(report.quarantined.is_empty());
}

#[test]
fn report_uses_trusted_sync_state_only_where_transaction_builds_on_it() {
    for (name, fx, case) in cases() {
        let before = files(&fx);

        let report = read_report(&fx).unwrap();

        assert_eq!(files(&fx), before, "{name}: writes nothing");
        assert_eq!(report.case, case, "{name}");
        let expected = match &case {
            SyncLoad::Current
            | SyncLoad::OlderVault { .. }
            | SyncLoad::NewerVault { .. }
            | SyncLoad::Mismatch(Mismatch::ReplicaId(_)) => Some(SyncStatus::Active),
            SyncLoad::StoppedOlderVault { .. } => Some(SyncStatus::Stopped(StopCause::Drift {
                build: BUILD_ID.to_string(),
                override_offered: true,
            })),
            SyncLoad::StateMissing => Some(SyncStatus::Stopped(StopCause::StateMissing)),
            SyncLoad::SignatureFailed(reason) => Some(SyncStatus::Stopped(
                StopCause::SignatureFailed(reason.clone()),
            )),
            SyncLoad::KeyMissing(KeyId(key_id)) => {
                Some(SyncStatus::Paused(vec![PausedCause::KeyMissing {
                    key_id: *key_id,
                }]))
            },
            SyncLoad::NotSynced
            | SyncLoad::Mismatch(Mismatch::VaultId(_))
            | SyncLoad::VersionSkew(_)
            | SyncLoad::DisableInProgress
            | SyncLoad::Leaving => None,
        };
        assert_eq!(report.status, expected, "{name}: status");
        // Each sync state of the cases holds no recipient, so only a trusted
        // state that a transaction builds on is degraded.
        assert_eq!(
            report.recovery_kit_missing,
            case.builds_txn(),
            "{name}: degraded"
        );
        let offered = matches!(case, SyncLoad::StoppedOlderVault { .. });
        assert_eq!(
            report.override_preview.is_some(),
            offered,
            "{name}: override"
        );
        assert!(report.known_macs.is_empty(), "{name}");
        assert_eq!(report.conflicts, 0, "{name}");
        assert_eq!(report.root, None, "{name}");
    }
}

#[test]
fn report_without_sidecar_root_asks_to_choose_folder() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    assert_eq!(Sidecar::load(&fx.root, fx.id()).transport, None);

    let report = read_report(&fx).unwrap();

    assert_eq!(report.status, Some(SyncStatus::Active));
    assert_eq!(report.root, None);
    assert!(report.needs_folder());

    set_root(&fx, &folder_root());

    let report = read_report(&fx).unwrap();

    assert_eq!(report.root, Some(folder_root()));
    assert!(!report.needs_folder());

    // A vault that is not synced needs no folder.
    let fx = Fixture::new(0, None);

    let report = read_report(&fx).unwrap();

    assert_eq!(report.status, None);
    assert_eq!(report.root, None);
    assert!(!report.needs_folder());
}

#[test]
fn set_sync_root_with_folder_that_lacks_vault_refuses_and_writes_nothing_and_with_vault_next_transaction_syncs_through_it()
 {
    let folder = Arc::new(FakeTransport::default());
    let empty = Arc::new(FakeTransport::default());
    let transports: Vec<(TransportRoot, Arc<dyn SyncTransport>)> =
        vec![(root(), folder.clone()), (empty_root(), empty.clone())];
    let fx = Fixture::with_transports(0, None, Arc::new(RootTransports(transports)));
    fx.add_item().unwrap();
    let setup = enable(&fx, root());
    let replica = setup.replica_id();
    // The sidecar loses its root, as a sidecar that fails to parse and holds
    // no valid `transport` field.
    let mut sidecar = Sidecar::load(&fx.root, fx.id());
    sidecar.transport = None;
    sidecar.save(&fx.root, fx.id()).unwrap();
    // With no root, a transaction has no transport and publishes nothing.
    let published = folder.names(fx.id(), replica);
    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();
    assert_eq!(folder.names(fx.id(), replica), published);
    let staged = opened(&fx.root, fx.id()).0.staged_hash.unwrap();
    assert!(read_report(&fx).unwrap().needs_folder());
    let managed = Managed::start(&fx, false);
    managed.run();
    assert_eq!(folder.watch_count(), 0);
    let sidecar = Sidecar::load(&fx.root, fx.id());
    let before = files(&fx);

    let lacking = fx.catalog.set_sync_root(VAULT_KEY, &empty_root());

    assert!(
        matches!(lacking, Err(Error::SyncFolderLacksVault)),
        "{lacking:?}"
    );
    assert_eq!(files(&fx), before);
    assert_eq!(empty.writes(), 0);

    fx.catalog.set_sync_root(VAULT_KEY, &root()).unwrap();

    // Only the root of the sidecar changed.
    assert_eq!(
        Sidecar::load(&fx.root, fx.id()),
        Sidecar {
            transport: Some(root()),
            ..sidecar
        }
    );
    assert!(!read_report(&fx).unwrap().needs_folder());
    managed.manager.refresh();
    managed.run();
    // One watch of the vault and one of the pairing directory of its root.
    assert_eq!(folder.watch_count(), 2);
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(folder.names(fx.id(), replica).len() > published.len());
    assert_eq!(Sidecar::load(&fx.root, fx.id()).last_publish, Some(staged));
}

#[test]
fn set_sync_root_refuses_vault_not_synced_or_is_leaving_or_has_no_valid_sync_state() {
    let device = TestSigner::device();
    let mut cases = Vec::new();
    let not_set = || Error::SyncRootNotSet(String::new());

    cases.push((
        "not synced",
        Fixture::new(GENERATION, None),
        Error::SyncNotEnabled,
    ));

    let fx = Fixture::new(GENERATION, None);
    let mut leaving = state(fx.id(), REPLICA, GENERATION);
    leaving.leaving = true;
    fx.put(&leaving, &device);
    cases.push((
        "disable waits for the folder",
        fx,
        Error::SyncDisableInProgress,
    ));

    let fx = Fixture::synced();
    let mut leaving = state(fx.id(), REPLICA, GENERATION + 1);
    leaving.leaving = true;
    fx.put(&leaving, &device);
    cases.push((
        "vault saved before its leaving sync state",
        fx,
        Error::SyncDisableInProgress,
    ));

    let fx = Fixture::synced();
    let mut newer = state(fx.id(), REPLICA, GENERATION);
    newer.format_version = SYNC_FORMAT_VERSION + 1;
    fx.put(&newer, &device);
    cases.push((
        "newer format",
        fx,
        Error::SyncStateVersionSkew(String::new()),
    ));

    cases.push(("sync state missing", Fixture::synced(), not_set()));

    let fx = Fixture::synced();
    fx.put_foreign_state();
    cases.push(("signed by another key", fx, not_set()));

    let fx = Fixture::synced();
    let other = ReplicaId(Uuid::from_u128(2));
    fx.put(&state(fx.id(), other, GENERATION), &device);
    cases.push(("replica id mismatch", fx, not_set()));

    for (name, fx, expected) in cases {
        let transport = Arc::new(FakeTransport::default());
        put_meta(&transport, &fx);
        let writer = fx.catalog.files().clone().with_transport(transport);
        let before = files(&fx);

        let result = writer.set_sync_root(&Target::of(&fx.vault), &root());

        let error = result.expect_err(name);
        assert_eq!(
            discriminant(&error),
            discriminant(&expected),
            "{name}: {error:?}"
        );
        assert_eq!(files(&fx), before, "{name}: writes nothing");
    }
}

#[test]
fn set_sync_root_replaces_root_already_set_and_sidecar_that_fails_to_parse() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_meta(&transport, &fx);
    fx.add_item().unwrap();
    set_root(&fx, &folder_root());
    let sidecar = Sidecar::load(&fx.root, fx.id());
    assert!(!sidecar.joined.is_empty());

    fx.catalog.set_sync_root(VAULT_KEY, &root()).unwrap();

    assert_eq!(
        Sidecar::load(&fx.root, fx.id()),
        Sidecar {
            transport: Some(root()),
            ..sidecar
        }
    );

    // A sidecar that fails to parse is read as empty and saved with the new
    // root.
    fs::write(Sidecar::path(&fx.root, fx.id()), "not json").unwrap();

    fx.catalog.set_sync_root(VAULT_KEY, &root()).unwrap();

    assert_eq!(
        Sidecar::load(&fx.root, fx.id()),
        Sidecar {
            transport: Some(root()),
            ..Sidecar::default()
        }
    );
}

#[test]
fn new_kit_confirmation_clears_kit_missing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    assert!(read_report(&fx).unwrap().recovery_kit_missing);
    let before = files(&fx);

    let kit = create_kit(&fx).unwrap();

    assert_eq!(files(&fx), before, "a kit writes nothing");
    assert_eq!(kit.vault_id, fx.id());
    assert_eq!(kit.key_id, KeyId(1));
    assert!(kit.opens(&key()));
    assert!(!confirm(&fx, &kit).unwrap());
    assert!(!read_report(&fx).unwrap().recovery_kit_missing);

    // A vault that holds a recipient of the current key gets another kit,
    // and both recipients are kept.
    let second = create_kit(&fx).unwrap();

    assert!(!confirm(&fx, &second).unwrap());
    let (_, state) = saved(&fx);
    let recipients: BTreeSet<String> = VaultView::of(&state).recovery.into_keys().collect();
    assert_eq!(
        recipients,
        BTreeSet::from([kit.recipient(), second.recipient()])
    );
}

#[test]
fn kit_refused_where_confirm_saved_refuses_its_recipient() {
    let device = TestSigner::device();
    let mut refused = Vec::new();
    refused.push(("not synced", Fixture::new(GENERATION, None)));
    refused.push(("sync state missing", Fixture::synced()));
    let fx = Fixture::synced();
    let mut stopped = state(fx.id(), REPLICA, GENERATION);
    stopped.stopped_build = Some(BUILD_ID.to_string());
    fx.put(&stopped, &device);
    refused.push(("stopped by drift on this build", fx));
    let fx = Fixture::synced();
    let mut leaving = state(fx.id(), REPLICA, GENERATION + 1);
    leaving.leaving = true;
    fx.put(&leaving, &device);
    refused.push(("vault saved before its leaving sync state", fx));

    for (name, fx) in refused {
        let before = files(&fx);

        let result = create_kit(&fx);

        assert!(
            matches!(result, Err(Error::RecoveryKitNotAdded(_))),
            "{name}: {result:?}"
        );
        assert_eq!(files(&fx), before, "{name}: writes nothing");
        // The transaction refuses a kit for the current key too.
        let kit = RecoveryKit::create(fx.id(), KeyId(1), &key());
        assert!(
            matches!(confirm(&fx, &kit), Err(Error::RecoveryKitNotAdded(_))),
            "{name}: confirm"
        );
        // The vault, the sync state, and the staged file are unchanged. A
        // missing sync state is recorded once in the sidecar.
        let after = files(&fx);
        assert_eq!(after[..3], before[..3], "{name}: confirm writes nothing");
        if name == "sync state missing" {
            let failure = LoadFailure::StateMissing;
            assert_eq!(
                Sidecar::load(&fx.root, fx.id()).health,
                Health::Failed { failure }
            );
        } else {
            assert_eq!(after[3], before[3], "{name}: confirm writes no sidecar");
        }
    }

    // A sync stopped by drift on another build is resumed by the next
    // transaction, which adds the recipient.
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport);
    let mut stopped = state(fx.id(), REPLICA, GENERATION);
    stopped.stopped_build = Some("other-build".to_string());
    fx.put(&stopped, &device);

    let kit = create_kit(&fx).unwrap();

    assert!(!confirm(&fx, &kit).unwrap());
}
