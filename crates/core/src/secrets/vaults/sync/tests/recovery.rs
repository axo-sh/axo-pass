//! Recovery kit, recipients, `Age` wrappings, the degraded state, and the age
//! import of the sync key (7.10).

mod import;
mod key_json;
mod kit;
mod trust;

use std::path::PathBuf;
use std::sync::Arc;

use tempfile::TempDir;
use uuid::Uuid;

use super::NOW;
use super::load::{Fixture, GENERATION, body, device_key, state_of};
use super::state_file::{key, keyring};
use super::transport::FakeTransport;
use super::view::State;
use crate::secrets::vaults::VaultHandle;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::{ReplicaId, Session};
use crate::secrets::vaults::sync::keys::SyncKey;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::recovery::import::RecoveryCheck;
use crate::secrets::vaults::sync::state_file::StateFile;
use crate::secrets::vaults::sync::state_file::padded::PaddedBody;
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport};
use crate::secrets::vaults::sync::wrapping::{KeyFile, Wrapping};

/// Replica `n` of the folder tests.
fn replica(n: u128) -> ReplicaId {
    ReplicaId(Uuid::from_u128(n))
}

/// Kit of the vault of `fx` for the current key, key id 1.
fn kit_of(fx: &Fixture) -> RecoveryKit {
    RecoveryKit::create(fx.id(), KeyId(1), &key())
}

/// Confirm `kit` as saved in a transaction on the vault of `fx`.
fn confirm(fx: &Fixture, kit: &RecoveryKit) -> Result<Committed<()>, Error> {
    let unlock = || fx.vault.unlocked_key().unwrap();
    kit.confirm_saved(
        fx.catalog.files(),
        &Target::of(&fx.vault),
        Unlock::Test(&unlock),
    )
}

/// Own `key.json` of `replica` in vault `vault_id`, if any.
pub(super) fn key_file(
    transport: &FakeTransport,
    vault_id: Uuid,
    replica: ReplicaId,
) -> Option<KeyFile> {
    match transport.read(vault_id, replica, FileName::Key).unwrap() {
        ReadResult::Local(bytes) => Some(KeyFile::parse(&bytes).unwrap()),
        _ => None,
    }
}

/// `Age` wrappings of the own `key.json` of `replica`, as recipient and key id.
pub(super) fn ages(
    transport: &FakeTransport,
    vault_id: Uuid,
    replica: ReplicaId,
) -> Vec<(String, KeyId)> {
    key_file(transport, vault_id, replica)
        .map(|file| {
            file.ages()
                .map(|age| (age.recipient.clone(), age.key_id))
                .collect()
        })
        .unwrap_or_default()
}

/// Put a `key.json` holding `wrappings` in the directory of `replica`.
fn put_key_file(
    transport: &FakeTransport,
    vault_id: Uuid,
    replica: ReplicaId,
    wrappings: Vec<Wrapping>,
) {
    let file = KeyFile {
        wrappings,
        invalid: Vec::new(),
    };
    transport.put(vault_id, replica, "key.json", &file.to_bytes());
}

/// State file of `state` written by `replica` in vault `vault_id`, under
/// `key` with id `key_id`.
fn state_file_under(
    vault_id: Uuid,
    replica: ReplicaId,
    state: &State,
    key_id: KeyId,
    key: &SyncKey,
) -> Vec<u8> {
    let padded = PaddedBody::of(state).unwrap();
    StateFile::encode(&padded, vault_id, replica, key_id, key).unwrap()
}

/// `state` with `name` written as the replica name of `replica`.
fn with_name(mut state: State, replica: ReplicaId, name: &str) -> State {
    let mut session = Session::new(replica);
    let m = session.mint(&mut state, NOW);
    state
        .store
        .replica_names
        .entry(replica)
        .write(&m, name.to_string());
    state
}

/// Key of a recovery check, or a panic.
fn recovered(check: RecoveryCheck) -> SyncKey {
    match check {
        RecoveryCheck::Recovered(recovered) => recovered.key,
        other => panic!("kit did not open a key: {other:?}"),
    }
}

/// One Mac of a vault synced by several Macs through one folder.
struct Mac {
    _dir: TempDir,
    root: PathBuf,
    replica: ReplicaId,
    vault: VaultHandle,
    writer: VaultWriter,
}

impl Mac {
    /// Transaction with no requested change.
    fn sync(&self) -> Committed<()> {
        let key = || self.vault.unlocked_key().unwrap();
        self.writer
            .write(&Target::of(&self.vault), Unlock::Test(&key), |_| {
                Ok::<_, Error>(())
            })
            .unwrap()
    }

    fn confirm(&self, kit: &RecoveryKit) -> Committed<()> {
        let key = || self.vault.unlocked_key().unwrap();
        kit.confirm_saved(&self.writer, &Target::of(&self.vault), Unlock::Test(&key))
            .unwrap()
    }

    /// Body of the saved sync state.
    fn state(&self) -> State {
        let id = self.vault.vault_id().unwrap();
        let local = LocalSyncState::load(&self.root, id, &TestSigner::device()).unwrap();
        local.open(&keyring()).unwrap()
    }
}

/// Macs of one vault at [`GENERATION`] that sync through one folder, each
/// with a sync state that holds the keys and the name of every Mac.
struct Macs {
    vault_id: Uuid,
    transport: Arc<FakeTransport>,
    macs: Vec<Mac>,
}

impl Macs {
    fn new(count: u128) -> Self {
        let mut initial = State::default();
        for n in 1..=count {
            initial.join(with_name(
                body(replica(n), &[device_key()]),
                replica(n),
                &format!("Mac {n}"),
            ));
        }
        let file_key = Vault::new_for_test().unlocked_key();
        let vault_id = file_key.vault_id();
        let transport = Arc::new(FakeTransport::default());
        let macs = (1..=count)
            .map(|n| {
                let dir = tempfile::tempdir().unwrap();
                let root = dir.path().join("data");
                let writer = VaultWriter::isolated(&root).with_transport(transport.clone());
                let mut vault = Vault::with_unlocked_key("personal".to_string(), &file_key);
                vault.set_sync(GENERATION, Some(replica(n).0));
                let vh = VaultHandle::new_in(&dir.path().join("vaults"), vault);
                writer.create(&vh).unwrap();
                state_of(vault_id, replica(n), GENERATION, &initial)
                    .save(&root, &TestSigner::device())
                    .unwrap();
                Mac {
                    _dir: dir,
                    root,
                    replica: replica(n),
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

    fn kit(&self) -> RecoveryKit {
        RecoveryKit::create(self.vault_id, KeyId(1), &key())
    }
}
