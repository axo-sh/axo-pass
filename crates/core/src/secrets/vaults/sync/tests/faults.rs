//! Fault-injection tests of milestone 9 that run on the fake transport, and
//! the download requests of the transaction (9.2).
//!
//! Apply failures, diff failures, and version skew are in
//! `sync/tests/failures.rs`. The faults that 6b to 7.10 built are in the
//! tests that "Already built" in doc 17 lists.

use std::path::PathBuf;
use std::sync::Arc;

use tempfile::TempDir;
use uuid::Uuid;

use super::guard::drift;
use super::join::{PEER, peer_state};
use super::load::{Fixture, GENERATION, REPLICA, body, device_key, state_of};
use super::publish::{last_publish, published};
use super::reads::put_peer;
use super::state_file::key;
use super::transport::FakeTransport;
use super::txn::{joined_vault, own_file, own_state, saved_vault, state_file, synced};
use super::view::State;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::{ReplicaId, Session};
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::status::SyncStatus;
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport};
use crate::secrets::vaults::sync::wrapping::KeyFile;
use crate::secrets::vaults::{Error, VaultHandle};

/// Replica of a third Mac.
const OTHER_PEER: ReplicaId = ReplicaId(Uuid::from_u128(3));

/// One Mac of [`Macs`], with its own app data directory.
struct Mac {
    _dir: TempDir,
    root: PathBuf,
    replica: ReplicaId,
    vault: VaultHandle,
    writer: VaultWriter,
}

impl Mac {
    /// Run `f` in a transaction on the vault.
    fn write(&self, f: impl FnOnce(&mut VaultHandle) -> Result<(), Error>) -> Committed<()> {
        let key = || self.vault.unlocked_key().unwrap();
        self.writer
            .write(&Target::of(&self.vault), Unlock::Test(&key), f)
            .unwrap()
    }

    /// Vault file as saved, verified.
    fn saved_vault(&self) -> Vault {
        let file = EncryptedVault::load(&self.vault.path, &TestSigner::device()).unwrap();
        Vault::from_unlocked_key(&self.vault.unlocked_key().unwrap(), file).unwrap()
    }

    fn sidecar(&self) -> Sidecar {
        Sidecar::load(&self.root, self.vault.vault_id().unwrap())
    }
}

/// Macs of one vault at [`GENERATION`] that sync through one folder. Each
/// sync state holds the `replica_keys` entry of every Mac.
struct Macs {
    vault_id: Uuid,
    transport: Arc<FakeTransport>,
    macs: Vec<Mac>,
}

impl Macs {
    /// Replica id of Mac `n`.
    fn replica(n: usize) -> ReplicaId {
        ReplicaId(Uuid::from_u128(0x10 + n as u128))
    }

    fn new(count: usize) -> Self {
        let mut initial = State::default();
        for n in 0..count {
            initial.join(body(Self::replica(n), &[device_key()]));
        }
        let file_key = Vault::new_for_test().unlocked_key();
        let vault_id = file_key.vault_id();
        let transport = Arc::new(FakeTransport::default());
        let macs = (0..count)
            .map(|n| {
                let dir = tempfile::tempdir().unwrap();
                let root = dir.path().join("data");
                let replica = Self::replica(n);
                let writer = VaultWriter::isolated(&root).with_transport(transport.clone());
                let mut vault = Vault::with_unlocked_key("personal".to_string(), &file_key);
                vault.set_sync(GENERATION, Some(replica.0));
                let vh = VaultHandle::new_in(&dir.path().join("vaults"), vault);
                writer.create(&vh).unwrap();
                state_of(vault_id, replica, GENERATION, &initial)
                    .save(&root, &TestSigner::device())
                    .unwrap();
                Mac {
                    _dir: dir,
                    root,
                    replica,
                    vault: vh,
                    writer,
                }
            })
            .collect();
        Self {
            vault_id,
            transport,
            macs,
        }
    }

    /// Hashes of the state files in the directory of Mac `n`.
    fn published(&self, n: usize) -> Vec<StateHash> {
        self.transport
            .list_states(self.vault_id, self.macs[n].replica)
            .unwrap()
    }
}

/// Own `key.json` of the vault of `fx`, if any.
fn own_key_file(transport: &FakeTransport, fx: &Fixture) -> Option<KeyFile> {
    match transport.read(fx.id(), REPLICA, FileName::Key).unwrap() {
        ReadResult::Local(bytes) => Some(KeyFile::parse(&bytes).unwrap()),
        _ => None,
    }
}

#[test]
fn unlock_with_peer_files_not_yet_downloaded_joins_local_files_completes_and_requests_download_of_rest()
 {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_peer(&fx, &transport, PEER, "local");
    let remote = peer_state(&fx, OTHER_PEER, "remote");
    let bytes = state_file(&fx, OTHER_PEER, &remote);
    let hash = StateHash::of(&bytes);
    let name = StateFile::name(hash);
    transport.put_remote_with(fx.id(), OTHER_PEER, &name, &bytes);

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let vault = saved_vault(&fx);
    assert!(vault.get_item("local").is_ok());
    assert!(vault.get_item("remote").is_err());
    assert_eq!(transport.download_requests(), [fx.id()]);
    assert!(!Sidecar::load(&fx.root, fx.id()).is_joined(OTHER_PEER, hash));

    // The file is joined by a transaction after it is local. 9.3 runs that
    // transaction when the download completes.
    assert_eq!(transport.complete_downloads(fx.id()), 1);
    fx.write(|_| Ok(())).unwrap();

    assert!(saved_vault(&fx).get_item("remote").is_ok());
    assert_eq!(transport.download_requests(), [fx.id()]);
}

#[test]
fn transaction_that_lists_remote_file_requests_one_download_and_one_with_none_requests_none() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_peer(&fx, &transport, PEER, "local");

    fx.add_item().unwrap();

    assert!(transport.download_requests().is_empty());

    // An own file and a peer file that are not local give one request.
    let own = StateFile::name(StateHash::of(b"own"));
    transport.put_remote(fx.id(), REPLICA, &own);
    let peer = StateFile::name(StateHash::of(b"peer"));
    transport.put_remote(fx.id(), OTHER_PEER, &peer);

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(transport.download_requests(), [fx.id()]);

    // A stopped transaction lists nothing and requests nothing.
    drift(&fx, "item");
    fx.write(|_| Ok(())).unwrap();
    fx.write(|_| Ok(())).unwrap();

    assert_eq!(transport.download_requests(), [fx.id()]);
}

#[test]
fn deleted_peer_dir_writes_reach_third_mac_via_second() {
    let macs = Macs::new(3);
    let [a, b, c] = &macs.macs[..] else {
        panic!("three Macs");
    };
    a.write(|vh| vh.add_item("from-a", "From A").map(|_| ()));
    assert_eq!(macs.published(0).len(), 1);

    // B joins the file of A and publishes the joined writes.
    b.write(|_| Ok(()));
    assert!(b.saved_vault().get_item("from-a").is_ok());
    let from_b = macs.published(1);
    assert_eq!(from_b.len(), 1);

    // The directory of A is deleted, as a rotation delete, a cleanup, or the
    // provider would delete it.
    macs.transport
        .delete_replica(macs.vault_id, a.replica)
        .unwrap();

    let committed = c.write(|_| Ok(()));

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(c.saved_vault().get_item("from-a").is_ok());
    let sidecar = c.sidecar();
    assert!(sidecar.is_joined(b.replica, from_b[0]));
    assert!(!sidecar.joined.contains_key(&a.replica));
}

#[test]
fn own_directory_deleted_with_delete_replica_republishes_state_file_and_writes_age_wrappings() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kit = RecoveryKit::create(fx.id(), KeyId(1), &key());
    let unlock = || fx.vault.unlocked_key().unwrap();
    kit.confirm_saved(
        fx.catalog.files(),
        &Target::of(&fx.vault),
        Unlock::Test(&unlock),
    )
    .unwrap();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(published(&transport, &fx).len(), 1);
    assert!(own_key_file(&transport, &fx).is_some());

    transport.delete_replica(fx.id(), REPLICA).unwrap();
    assert!(transport.names(fx.id(), REPLICA).is_empty());

    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let listed = published(&transport, &fx);
    assert_eq!(listed.len(), 1);
    assert_eq!(last_publish(&fx), Some(listed[0]));
    let file = own_key_file(&transport, &fx).unwrap();
    let ages: Vec<(String, KeyId)> = file
        .ages()
        .map(|age| (age.recipient.clone(), age.key_id))
        .collect();
    assert_eq!(ages, [(kit.recipient(), KeyId(1))]);
}

#[test]
fn newer_own_state_file_that_is_remote_at_publish_kept_joined_once_local_and_deleted_after_next_publish()
 {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let own = own_state(&fx, &joined_vault(), &mut Session::new(REPLICA));
    let bytes = own_file(&fx, &own);
    let remote = StateFile::name(StateHash::of(&bytes));
    transport.put_remote_with(fx.id(), REPLICA, &remote, &bytes);

    fx.add_item().unwrap();

    // The publish keeps the own file that is not local, and its download is
    // requested.
    let first = last_publish(&fx).unwrap();
    let mut names = vec![StateFile::name(first), remote.clone()];
    names.sort();
    assert_eq!(transport.names(fx.id(), REPLICA), names);
    assert_eq!(transport.download_requests(), [fx.id()]);
    assert!(saved_vault(&fx).get_item("joined").is_err());

    assert_eq!(transport.complete_downloads(fx.id()), 1);
    fx.write(|_| Ok(())).unwrap();

    // The file is joined, and the publish that covers it deletes it and the
    // first publish.
    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_ok());
    assert!(vault.get_item("item").is_ok());
    let second = last_publish(&fx).unwrap();
    assert_ne!(second, first);
    assert_eq!(transport.names(fx.id(), REPLICA), [StateFile::name(second)]);
}
