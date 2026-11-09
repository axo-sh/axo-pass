use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use jiff::Timestamp;
use uuid::Uuid;

use super::super::load::{Fixture, GENERATION};
use super::super::state_file::VAULT;
use super::super::txn::saved;
use super::{
    FakeTransport, deletes_replica_directory_and_leaves_others,
    lists_vaults_and_reads_and_writes_meta, reads_only_exact_state_file_names,
    records_download_requests_and_makes_remote_files_local, request,
    returns_remote_for_file_not_yet_local,
    tells_local_file_from_one_not_local_or_missing_without_read,
    writes_and_deletes_own_files_and_fails_while_unavailable,
};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::storage::txn::AppTransports;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::StateHash;
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::sync::transport::{
    PairingEntry, ReadResult, RequestId, SyncTransport, SyncTransports, TransportRoot,
};

#[test]
fn fake_reads_only_exact_state_file_names() {
    reads_only_exact_state_file_names(&FakeTransport::default());
}

#[test]
fn fake_returns_remote_for_file_not_yet_local() {
    returns_remote_for_file_not_yet_local(&FakeTransport::default());
}

#[test]
fn fake_tells_local_remote_missing_without_read() {
    tells_local_file_from_one_not_local_or_missing_without_read(&FakeTransport::default());
}

#[test]
fn fake_writes_and_deletes_own_files_and_fails_while_unavailable() {
    writes_and_deletes_own_files_and_fails_while_unavailable(&FakeTransport::default());
}

#[test]
fn request_id_parse_file_name_refuses_uppercase_uuid_name_without_json_and_non_uuid() {
    let id = Uuid::from_u128(0xabcdef);
    let name = format!("{}.json", id.hyphenated());
    assert_eq!(request(0xabcdef).file_name(), name);
    assert_eq!(RequestId::parse_file_name(&name), Some(request(0xabcdef)));

    for refused in [
        format!("{}.json", id.hyphenated().to_string().to_uppercase()),
        id.hyphenated().to_string(),
        format!("{}.JSON", id.hyphenated()),
        format!("{}.json", id.simple()),
        format!("{}.json", id.braced()),
        format!("{}.json", id.urn()),
        format!("{} 2.json", id.hyphenated()),
        format!("{}.json.tmp", id.hyphenated()),
        "not-a-uuid.json".to_string(),
        ".json".to_string(),
    ] {
        assert_eq!(RequestId::parse_file_name(&refused), None, "{refused}");
    }
}

#[test]
fn fake_lists_vaults_and_reads_and_writes_meta() {
    lists_vaults_and_reads_and_writes_meta(&FakeTransport::default());
}

#[test]
fn fake_deletes_replica_directory_and_leaves_others() {
    deletes_replica_directory_and_leaves_others(&FakeTransport::default());
}

#[test]
fn fake_records_download_requests_and_makes_remote_files_local() {
    records_download_requests_and_makes_remote_files_local(&FakeTransport::default());
}

#[test]
fn fake_lists_pairing_requests_with_set_times_and_sizes() {
    let transport = FakeTransport::default();
    let written = Timestamp::from_second(1_000).unwrap();
    transport.set_now(written);
    transport.write_pairing(request(1), b"first").unwrap();
    transport.put_pairing(request(2), b"second");
    let older = Timestamp::from_second(10).unwrap();
    transport.set_pairing_modified(request(2), older);
    transport.set_pairing_size(request(2), 20_000);

    assert_eq!(
        transport.list_pairings().unwrap(),
        vec![
            PairingEntry {
                id: request(1),
                modified: written,
                size: 5,
            },
            PairingEntry {
                id: request(2),
                modified: older,
                size: 20_000,
            },
        ]
    );
    assert_eq!(transport.pairing_reads(), 0);
    assert_eq!(
        transport.read_pairing(request(1)).unwrap(),
        ReadResult::Local(b"first".to_vec())
    );
    assert_eq!(
        transport.read_pairing(request(3)).unwrap(),
        ReadResult::Missing
    );
    assert_eq!(transport.pairing_reads(), 1);

    transport.delete_pairing(request(1)).unwrap();
    assert_eq!(transport.pairing(request(1)), None);
    assert_eq!(transport.list_pairings().unwrap().len(), 1);
}

#[test]
fn fake_watch_called_when_fired_and_ends_when_handle_drops() {
    let transport = FakeTransport::default();
    let vault_calls = Arc::new(AtomicUsize::new(0));
    let pairing_calls = Arc::new(AtomicUsize::new(0));
    let counter = |calls: &Arc<AtomicUsize>| -> Box<dyn Fn() + Send> {
        let calls = calls.clone();
        Box::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
        })
    };
    let vault_watch = transport.watch(VAULT, counter(&vault_calls)).unwrap();
    let pairing_watch = transport.watch_pairings(counter(&pairing_calls)).unwrap();
    assert_eq!(transport.watch_count(), 2);

    assert_eq!(transport.fire_watch(VAULT), 1);
    assert_eq!(transport.fire_watch(Uuid::from_u128(0x200)), 0);
    assert_eq!(transport.fire_pairing_watch(), 1);
    assert_eq!(vault_calls.load(Ordering::SeqCst), 1);
    assert_eq!(pairing_calls.load(Ordering::SeqCst), 1);

    drop(vault_watch);
    assert_eq!(transport.fire_watch(VAULT), 0);
    assert_eq!(vault_calls.load(Ordering::SeqCst), 1);
    assert_eq!(transport.watch_count(), 1);
    drop(pairing_watch);
    assert_eq!(transport.watch_count(), 0);
}

#[test]
fn app_transports_give_no_transport_for_no_root_and_resolve_no_root_yet() {
    let transports = AppTransports::default();
    assert!(transports.resolve(None).unwrap().is_none());
    for root in [
        TransportRoot::ICloud {},
        TransportRoot::Folder {
            path: PathBuf::from("/tmp/Vaults"),
        },
    ] {
        assert!(matches!(
            transports.resolve(Some(&root)),
            Err(Error::SyncTransportError(_))
        ));
    }
}

#[test]
fn writer_with_app_transports_and_sidecar_with_no_root_writes_staged_file_and_copies_nothing() {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);

    let committed = fx.add_item().unwrap();

    assert!(committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let (local, _) = saved(&fx);
    let staged = fs::read(LocalSyncState::staged_path(&fx.root, fx.id())).unwrap();
    assert_eq!(local.staged_hash, Some(StateHash::of(&staged)));
    assert!(local.staged_context.is_some());
    let sidecar = Sidecar::load(&fx.root, fx.id());
    assert_eq!(sidecar.last_publish, None);
    assert_eq!(sidecar.transport, None);
    assert!(sidecar.paused.is_empty());
}

#[test]
fn root_that_fails_to_resolve_pauses_sync_with_unreachable_and_save_succeeds() {
    for root in [
        TransportRoot::ICloud {},
        TransportRoot::Folder {
            path: PathBuf::from("/tmp/Vaults"),
        },
    ] {
        let fx = Fixture::synced();
        fx.put_state(GENERATION);
        let sidecar = Sidecar {
            transport: Some(root.clone()),
            ..Sidecar::default()
        };
        sidecar.save(&fx.root, fx.id()).unwrap();

        let committed = fx.add_item().unwrap();

        assert!(committed.changed);
        let Some(SyncStatus::Paused(causes)) = committed.sync_status else {
            panic!("sync is paused");
        };
        assert!(matches!(&causes[..], [PausedCause::Unreachable { .. }]));
        // The edit is recorded and staged, and the root is kept.
        let (local, _) = saved(&fx);
        assert_eq!(local.generation, GENERATION + 1);
        assert!(local.staged_hash.is_some());
        let sidecar = Sidecar::load(&fx.root, fx.id());
        assert_eq!(sidecar.paused, causes);
        assert_eq!(sidecar.transport, Some(root));
        assert_eq!(sidecar.last_publish, None);
    }
}
