//! Recovery kit, recipients, `Age` wrappings, the degraded state, and the age
//! import of the sync key (7.10).

use std::path::PathBuf;
use std::sync::Arc;

use tempfile::TempDir;
use uuid::Uuid;

use super::NOW;
use super::guard::{drift, stopped};
use super::load::{Fixture, GENERATION, REPLICA, body, device_key, state_of};
use super::state_file::{key, keyring};
use super::transport::FakeTransport;
use super::txn::{saved, synced, two_keys, under_key_2};
use super::view::State;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::VaultHandle;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::{CausalStore, ReplicaId, Session};
use crate::secrets::vaults::sync::keys::SyncKey;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, RecoveryRecipient, ReplicaKeys};
use crate::secrets::vaults::sync::pairing::PairingCode;
use crate::secrets::vaults::sync::pairing::grant::GrantOutcome;
use crate::secrets::vaults::sync::pairing::request::PairingRequest;
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::recovery::import::{
    RecoveryCheck, RecoveryImport, WaitingReplica,
};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::padded::PaddedBody;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::sync::transport::{
    FileName, ReadResult, RequestId, SyncTransport, TransportRoot,
};
use crate::secrets::vaults::sync::wrapping::{AgeWrapping, DeviceWrapping, KeyFile, Wrapping};

/// Replica of a removed Mac that still holds the sync key.
const REMOVED: ReplicaId = ReplicaId(Uuid::from_u128(99));

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

/// `state` with `value` written into the `recovery` register of
/// `recipient` by a new session of `replica`.
fn with_recipient(
    mut state: State,
    replica: ReplicaId,
    recipient: &str,
    value: RecoveryRecipient,
) -> State {
    let mut session = Session::new(replica);
    let m = session.mint(&mut state, NOW);
    state
        .store
        .recovery
        .entry(recipient.to_string())
        .write(&m, value);
    state
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

#[test]
fn kit_text_reads_back_to_identity_vault_id_key_id_and_fingerprint() {
    let vault_id = Uuid::from_u128(0x6f1c);
    let kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    let text = kit.text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 5);
    assert_eq!(lines[0], "Axo Pass recovery kit");
    assert_eq!(lines[1], format!("Vault: {}", vault_id.hyphenated()));
    assert_eq!(lines[2], "Key id: 1");
    let fingerprint = lines[3].strip_prefix("Fingerprint: ").unwrap();
    let groups: Vec<usize> = fingerprint.split('-').map(str::len).collect();
    assert_eq!(groups, [4, 4, 4, 4, 4, 4, 2]);
    assert!(lines[4].starts_with("AGE-SECRET-KEY-1"));

    let parsed = RecoveryKit::parse(&text).unwrap();
    assert_eq!(parsed.vault_id, vault_id);
    assert_eq!(parsed.key_id, KeyId(1));
    assert_eq!(parsed.fingerprint, key().fingerprint());
    assert_eq!(parsed.recipient(), kit.recipient());
    assert_eq!(*parsed.text(), *text);

    // Blank lines, surrounding spaces, CRLF, and a lowercase fingerprint
    // with confusable letters read the same.
    let loose = format!(
        "\n  {}  \r\n\r\n{}\r\n{}\r\nFingerprint: {}\r\n{}\r\n\n",
        lines[0],
        lines[1],
        lines[2],
        fingerprint
            .to_lowercase()
            .replace('0', "o")
            .replace('1', "l"),
        lines[4]
    );
    let parsed = RecoveryKit::parse(&loose).unwrap();
    assert_eq!(parsed.fingerprint, key().fingerprint());
    assert_eq!(parsed.recipient(), kit.recipient());
}

#[test]
fn kit_parser_rejects_malformed_lines() {
    let kit = RecoveryKit::create(Uuid::from_u128(1), KeyId(1), &key());
    let text = kit.text();
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let with = |n: usize, line: &str| {
        let mut lines = lines.clone();
        lines[n] = line.to_string();
        lines.join("\n")
    };
    let mut reordered = lines.clone();
    reordered.swap(1, 2);
    let refused = [
        lines[..4].join("\n"),
        format!("{}\nNote: kept in the safe", lines.join("\n")),
        reordered.join("\n"),
        with(0, "Recovery kit"),
        with(1, "Vault: not-a-uuid"),
        with(1, "Vault 00000000-0000-0000-0000-000000000001"),
        with(2, "Key id: 0"),
        with(2, "Key id: +1"),
        with(2, "Key id: 4294967296"),
        with(3, "Fingerprint: 0000-0000"),
        with(3, "Fingerprint: UUUU-0000-0000-0000-0000-0000-00"),
        with(4, "AGE-SECRET-KEY-1NOTAKEY"),
    ];
    for text in refused {
        assert!(
            matches!(
                RecoveryKit::parse(&text),
                Err(Error::RecoveryKitMalformed(_))
            ),
            "kit was read: {text}"
        );
    }
}

#[test]
fn creating_kit_without_confirmation_writes_no_recipient_and_no_wrapping() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let _kit = kit_of(&fx);
    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(committed.recovery_kit_missing);
    assert!(saved(&fx).1.store.recovery.is_empty());
    assert_eq!(key_file(&transport, fx.id(), REPLICA), None);
}

#[test]
fn every_replica_writes_age_wrapping_for_each_recipient_of_current_key_and_kit_opens_after_kit_maker_directory_deleted()
 {
    let macs = Macs::new(3);
    let kit = macs.kit();
    macs.macs[0].confirm(&kit);
    for mac in &macs.macs[1..] {
        mac.sync();
    }

    for mac in &macs.macs {
        assert_eq!(
            ages(&macs.transport, macs.vault_id, mac.replica),
            [(kit.recipient(), KeyId(1))],
            "replica {} holds no age wrapping",
            mac.replica.0
        );
    }

    // Cleanup of the Mac that made the kit is milestone 13, and is a
    // deletion of its directory here.
    macs.transport
        .delete_replica(macs.vault_id, macs.macs[0].replica)
        .unwrap();
    let opened = recovered(RecoveryImport::check(&kit, &*macs.transport).unwrap());
    assert_eq!(opened.as_bytes(), key().as_bytes());
}

#[test]
fn confirmed_kit_clears_degraded_on_all_macs() {
    let macs = Macs::new(3);
    for mac in &macs.macs {
        assert!(mac.sync().recovery_kit_missing);
    }
    let kit = macs.kit();
    let committed = macs.macs[0].confirm(&kit);
    assert!(!committed.recovery_kit_missing);

    // One write id holds the recipient.
    let state = macs.macs[0].state();
    let register = state.store.recovery.get(&kit.recipient()).unwrap();
    assert_eq!(register.values().count(), 1);
    assert_eq!(register.shown(), Some(&kit.recipient_value()));

    for mac in &macs.macs[1..] {
        assert!(mac.state().store.recovery.is_empty());
        assert!(!mac.sync().recovery_kit_missing);
        assert!(mac.state().store.recovery.get(&kit.recipient()).is_some());
    }
}

#[test]
fn recipient_with_current_key_id_and_another_fingerprint_receives_no_wrapping_and_does_not_clear_degraded_state()
 {
    let macs = Macs::new(2);
    let planted = age::x25519::Identity::generate().to_public().to_string();
    let value = RecoveryRecipient {
        key_id: KeyId(1),
        key_fingerprint: SyncKey::from_bytes([9; 32]).fingerprint().0,
    };
    // A removed Mac adds the recipient for the key id it predicts.
    let state = with_recipient(macs.macs[0].state(), REMOVED, &planted, value);
    let bytes = state_file_under(macs.vault_id, REMOVED, &state, KeyId(1), &key());
    macs.transport.put_state(macs.vault_id, REMOVED, &bytes);

    for mac in &macs.macs {
        assert!(mac.sync().recovery_kit_missing);
        assert!(mac.state().store.recovery.get(&planted).is_some());
        assert_eq!(key_file(&macs.transport, macs.vault_id, mac.replica), None);
    }
}

#[test]
fn recipient_for_older_key_id_receives_no_wrapping() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    let current = two_keys().get(KeyId(2)).unwrap().clone();
    let older = age::x25519::Identity::generate().to_public().to_string();
    let newer = age::x25519::Identity::generate().to_public().to_string();
    let state = body(REPLICA, &[device_key()]);
    let state = with_recipient(
        state,
        REPLICA,
        &older,
        RecoveryRecipient {
            key_id: KeyId(1),
            key_fingerprint: key().fingerprint().0,
        },
    );
    let state = with_recipient(
        state,
        REPLICA,
        &newer,
        RecoveryRecipient {
            key_id: KeyId(2),
            key_fingerprint: current.fingerprint().0,
        },
    );
    fx.put_text(&under_key_2(&fx, &state, &two_keys()));

    let committed = fx.write(|_| Ok(())).unwrap();
    assert!(!committed.recovery_kit_missing);
    assert_eq!(ages(&transport, fx.id(), REPLICA), [(newer, KeyId(2))]);
}

#[test]
fn age_wrapping_with_planted_fingerprint_rejected() {
    let vault_id = Uuid::from_u128(0x100);
    let kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    let transport = FakeTransport::default();
    let mut planted =
        AgeWrapping::wrap(KeyId(1), &SyncKey::from_bytes([9; 32]), &kit.recipient()).unwrap();
    planted.key_fingerprint = kit.fingerprint;
    put_key_file(
        &transport,
        vault_id,
        replica(1),
        vec![Wrapping::Age(planted)],
    );

    assert!(matches!(
        RecoveryImport::check(&kit, &transport).unwrap(),
        RecoveryCheck::NoKey
    ));

    // The real wrapping in a later directory still opens.
    let real = AgeWrapping::wrap(KeyId(1), &key(), &kit.recipient()).unwrap();
    put_key_file(&transport, vault_id, replica(2), vec![Wrapping::Age(real)]);
    let opened = recovered(RecoveryImport::check(&kit, &transport).unwrap());
    assert_eq!(opened.as_bytes(), key().as_bytes());
}

#[test]
fn key_with_partial_fingerprint_match_rejected() {
    let vault_id = Uuid::from_u128(0x100);
    let mut kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    kit.fingerprint.0[15] ^= 1;
    assert_eq!(kit.fingerprint.0[..8], key().fingerprint().0[..8]);
    assert!(!kit.opens(&key()));

    let transport = FakeTransport::default();
    let wrapping = AgeWrapping::wrap(KeyId(1), &key(), &kit.recipient()).unwrap();
    put_key_file(
        &transport,
        vault_id,
        replica(1),
        vec![Wrapping::Age(wrapping)],
    );
    assert!(matches!(
        RecoveryImport::check(&kit, &transport).unwrap(),
        RecoveryCheck::NoKey
    ));
}

#[test]
fn kit_below_peer_header_key_id_refused() {
    let vault_id = Uuid::from_u128(0x100);
    let kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    let transport = FakeTransport::default();
    let wrapping = AgeWrapping::wrap(KeyId(1), &key(), &kit.recipient()).unwrap();
    put_key_file(
        &transport,
        vault_id,
        replica(1),
        vec![Wrapping::Age(wrapping)],
    );
    let state = body(replica(1), &[device_key()]);
    let old = state_file_under(vault_id, replica(1), &state, KeyId(1), &key());
    transport.put_state(vault_id, replica(1), &old);
    let rotated = state_file_under(
        vault_id,
        replica(2),
        &state,
        KeyId(2),
        &SyncKey::from_bytes([3; 32]),
    );
    transport.put_state(vault_id, replica(2), &rotated);

    match RecoveryImport::check(&kit, &transport).unwrap() {
        RecoveryCheck::KitOutdated { kit, highest } => {
            assert_eq!((kit, highest), (KeyId(1), KeyId(2)));
        },
        other => panic!("kit was not refused: {other:?}"),
    }
}

#[test]
fn import_waits_for_remote_peer_state_files() {
    let vault_id = Uuid::from_u128(0x100);
    let kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    let transport = FakeTransport::default();
    let wrapping = AgeWrapping::wrap(KeyId(1), &key(), &kit.recipient()).unwrap();
    put_key_file(
        &transport,
        vault_id,
        replica(1),
        vec![Wrapping::Age(wrapping)],
    );
    // The local file of Mac 1 names Mac 2. Mac 3 is named by no local file.
    let state = with_name(body(replica(1), &[device_key()]), replica(2), "Mac 2");
    let local = state_file_under(vault_id, replica(1), &state, KeyId(1), &key());
    transport.put_state(vault_id, replica(1), &local);
    for n in [2, 3] {
        let bytes = state_file_under(vault_id, replica(n), &state, KeyId(1), &key());
        let hash = StateHash::of(&bytes);
        transport.put_remote_with(
            vault_id,
            replica(n),
            &StateFile::name(vault_id, hash),
            &bytes,
        );
    }

    let waiting = vec![
        WaitingReplica {
            replica: replica(2),
            name: Some("Mac 2".to_string()),
        },
        WaitingReplica {
            replica: replica(3),
            name: None,
        },
    ];
    // Each check waits until the files are local. The user cancels by not
    // checking again.
    for _ in 0..2 {
        match RecoveryImport::check(&kit, &transport).unwrap() {
            RecoveryCheck::Waiting(replicas) => assert_eq!(replicas, waiting),
            other => panic!("import did not wait: {other:?}"),
        }
    }
    assert_eq!(transport.download_requests(), [vault_id, vault_id]);

    assert_eq!(transport.complete_downloads(vault_id), 2);
    let opened = recovered(RecoveryImport::check(&kit, &transport).unwrap());
    assert_eq!(opened.as_bytes(), key().as_bytes());
}

#[test]
fn remote_state_file_requested_for_download() {
    let vault_id = Uuid::from_u128(0x100);
    let kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    let transport = FakeTransport::default();
    let state = body(replica(1), &[device_key()]);
    let bytes = state_file_under(vault_id, replica(1), &state, KeyId(1), &key());
    let hash = StateHash::of(&bytes);
    transport.put_remote(vault_id, replica(1), &StateFile::name(vault_id, hash));

    assert!(matches!(
        RecoveryImport::check(&kit, &transport).unwrap(),
        RecoveryCheck::Waiting(_)
    ));
    assert_eq!(transport.download_requests(), [vault_id]);
}

#[test]
fn planted_header_with_higher_key_id_refuses_kit_and_no_state_accepted_from_it() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kit = kit_of(&fx);
    let wrapping = AgeWrapping::wrap(KeyId(1), &key(), &kit.recipient()).unwrap();
    put_key_file(&transport, fx.id(), REMOVED, vec![Wrapping::Age(wrapping)]);
    let header = br#"{"key_id":9}"#;
    let planted = [
        b"APST".as_slice(),
        &(header.len() as u32).to_be_bytes(),
        header,
        &[0xee; 64],
    ]
    .concat();
    transport.put_state(fx.id(), REMOVED, &planted);

    match RecoveryImport::check(&kit, &*transport).unwrap() {
        RecoveryCheck::KitOutdated { highest, .. } => assert_eq!(highest, KeyId(9)),
        other => panic!("kit was not refused: {other:?}"),
    }

    // A transaction quarantines the planted file and joins nothing from it.
    let before = saved(&fx).1;
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(
        committed.sync_status,
        Some(SyncStatus::Paused(vec![PausedCause::Quarantined {
            files: 1
        }]))
    );
    assert_eq!(saved(&fx).1.store, before.store);
}

#[test]
fn each_import_takes_new_replica_id() {
    let vault_id = Uuid::from_u128(0x100);
    let kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    let transport = FakeTransport::default();
    let wrapping = AgeWrapping::wrap(KeyId(1), &key(), &kit.recipient()).unwrap();
    put_key_file(
        &transport,
        vault_id,
        replica(1),
        vec![Wrapping::Age(wrapping)],
    );

    let replica_id = |check| match check {
        RecoveryCheck::Recovered(recovered) => {
            assert_eq!(recovered.vault_id, vault_id);
            assert_eq!(recovered.key_id, KeyId(1));
            recovered.replica_id
        },
        other => panic!("kit did not open a key: {other:?}"),
    };
    let first = replica_id(RecoveryImport::check(&kit, &transport).unwrap());
    let second = replica_id(RecoveryImport::check(&kit, &transport).unwrap());
    assert_ne!(first, second);
    assert_ne!(first, replica(1));
}

#[test]
fn deleted_own_key_json_written_again_with_device_wrappings_lost_and_age_wrappings_back() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kit = kit_of(&fx);
    confirm(&fx, &kit).unwrap();
    let mut file = key_file(&transport, fx.id(), REPLICA).unwrap();
    file.wrappings.push(Wrapping::Device(DeviceWrapping {
        key_id: KeyId(1),
        key_fingerprint: key().fingerprint(),
        to_replica: replica(5),
        from_encryption: PublicKey(vec![4, 1]),
        from_signing: PublicKey(device_key()),
        wrapped: vec![1, 2, 3],
        pairing_mac: None,
        signature: None,
        removed: None,
        remaining: None,
    }));
    transport.put(fx.id(), REPLICA, "key.json", &file.to_bytes());

    // An unchanged file with its wanted wrapping is not written again.
    let writes = transport.writes();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(transport.writes(), writes);

    transport.remove(fx.id(), REPLICA, "key.json");
    fx.write(|_| Ok(())).unwrap();
    let file = key_file(&transport, fx.id(), REPLICA).unwrap();
    assert_eq!(file.devices().count(), 0);
    assert_eq!(
        ages(&transport, fx.id(), REPLICA),
        [(kit.recipient(), KeyId(1))]
    );
    let opened = recovered(RecoveryImport::check(&kit, &*transport).unwrap());
    assert_eq!(opened.as_bytes(), key().as_bytes());
}

#[test]
fn pairing_grant_and_age_wrappings_written_in_one_key_json_write() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let root = TransportRoot::Folder {
        path: PathBuf::from("/recovery/Vaults"),
    };
    let sidecar = Sidecar {
        transport: Some(root.clone()),
        ..Sidecar::default()
    };
    sidecar.save(&fx.root, fx.id()).unwrap();
    let kit = kit_of(&fx);
    confirm(&fx, &kit).unwrap();
    transport.remove(fx.id(), REPLICA, "key.json");

    let software = ManagedKey::create_software_for_test().unwrap();
    let keys = ReplicaKeys {
        encryption: PublicKey(software.public_key_sec1().unwrap()),
        signing: PublicKey(vec![0x51; 65]),
    };
    let code = PairingCode::generate();
    let to_replica = ReplicaId::generate();
    let request = PairingRequest::new(
        RequestId::generate(),
        [(fx.id(), to_replica)].into_iter().collect(),
        &keys,
        "New Mac".to_string(),
        &code.pair_key(),
    );
    let unlock = || fx.vault.unlocked_key().unwrap();
    let outcome = fx.catalog.files().grant_pairing(
        &Target::of(&fx.vault),
        Unlock::Test(&unlock),
        &request,
        &code,
        &root,
    );
    assert!(matches!(outcome, GrantOutcome::Granted(_)), "{outcome:?}");

    let file = key_file(&transport, fx.id(), REPLICA).unwrap();
    let devices: Vec<ReplicaId> = file.devices().map(|device| device.to_replica).collect();
    assert_eq!(devices, [to_replica]);
    assert_eq!(
        ages(&transport, fx.id(), REPLICA),
        [(kit.recipient(), KeyId(1))]
    );
}

#[test]
fn failed_key_json_write_pauses_sync_with_publish_failed_and_next_transaction_writes_it() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kit = kit_of(&fx);
    confirm(&fx, &kit).unwrap();
    transport.remove(fx.id(), REPLICA, "key.json");

    transport.set_failing_writes(true);
    let committed = fx.write(|_| Ok(())).unwrap();
    assert!(matches!(
        committed.sync_status,
        Some(SyncStatus::Paused(ref causes))
            if matches!(causes[..], [PausedCause::PublishFailed { .. }])
    ));
    assert_eq!(key_file(&transport, fx.id(), REPLICA), None);

    transport.set_failing_writes(false);
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(
        ages(&transport, fx.id(), REPLICA),
        [(kit.recipient(), KeyId(1))]
    );
}

#[test]
fn stopped_transaction_writes_no_key_json_and_confirmation_while_stopped_writes_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kit = kit_of(&fx);
    confirm(&fx, &kit).unwrap();
    transport.remove(fx.id(), REPLICA, "key.json");
    drift(&fx, "item");

    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, stopped());
    assert_eq!(key_file(&transport, fx.id(), REPLICA), None);

    let other = kit_of(&fx);
    let on_disk = fx.on_disk();
    let writes = transport.writes();
    assert!(matches!(
        confirm(&fx, &other),
        Err(Error::RecoveryKitNotAdded(_))
    ));
    assert_eq!(fx.on_disk(), on_disk);
    assert_eq!(transport.writes(), writes);
}

#[test]
fn confirmation_of_kit_for_another_key_or_vault_writes_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kits = [
        RecoveryKit::create(fx.id(), KeyId(2), &key()),
        RecoveryKit::create(fx.id(), KeyId(1), &SyncKey::from_bytes([9; 32])),
        RecoveryKit::create(Uuid::from_u128(0x200), KeyId(1), &key()),
    ];
    for kit in &kits {
        let on_disk = fx.on_disk();
        assert!(matches!(
            confirm(&fx, kit),
            Err(Error::RecoveryKitNotAdded(_))
        ));
        assert_eq!(fx.on_disk(), on_disk);
        assert_eq!(transport.writes(), 0);
    }
}

#[test]
fn vault_with_no_sync_state_reports_no_missing_kit_and_refuses_confirmation() {
    let fx = Fixture::new(GENERATION, None);
    let committed = fx.write(|_| Ok(())).unwrap();
    assert!(!committed.recovery_kit_missing);
    assert!(matches!(
        confirm(&fx, &kit_of(&fx)),
        Err(Error::RecoveryKitNotAdded(_))
    ));
}

#[test]
fn state_file_key_id_read_from_header_without_decryption() {
    let state = body(REPLICA, &[device_key()]);
    let bytes = state_file_under(Uuid::from_u128(0x100), REPLICA, &state, KeyId(4), &key());
    assert_eq!(StateFile::peek_key_id(&bytes).unwrap(), KeyId(4));
    assert!(StateFile::peek_key_id(b"APST").is_err());
    assert!(StateFile::peek_key_id(b"NOPE\0\0\0\x02{}").is_err());
}
