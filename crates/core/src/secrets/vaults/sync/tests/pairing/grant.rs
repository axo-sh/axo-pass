use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use jiff::{SignedDuration, Timestamp};
use tempfile::TempDir;
use uuid::Uuid;

use super::{NAME, NewMac, peer, put_request, request_of, request_with, vault};
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::VaultHandle;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::{UnlockedKey, Vault};
use crate::secrets::vaults::storage::device_keys::{KeyState, VaultFiles};
use crate::secrets::vaults::storage::test_keys::TestKeys;
use crate::secrets::vaults::storage::txn::{Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::SyncKey;
use crate::secrets::vaults::sync::local_state::{LocalSyncState, PinSource, PinnedKeys};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::pairing::PairingCode;
use crate::secrets::vaults::sync::pairing::dismissed::DismissedRequests;
use crate::secrets::vaults::sync::pairing::grant::GrantOutcome;
use crate::secrets::vaults::sync::pairing::prompt::PairingPrompt;
use crate::secrets::vaults::sync::pairing::request::PairingRequest;
use crate::secrets::vaults::sync::pins::PairedPin;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::status::BUILD_ID;
use crate::secrets::vaults::sync::tests::load::{
    Fixture, GENERATION, REPLICA, body, device_key, state,
};
use crate::secrets::vaults::sync::tests::state_file::key;
use crate::secrets::vaults::sync::tests::transport::FakeTransport;
use crate::secrets::vaults::sync::tests::txn::{synced, two_keys, under_key_2};
use crate::secrets::vaults::sync::transport::{
    FileName, MAX_PAIRING_SIZE, ReadResult, RequestId, SyncTransport, TransportRoot,
};
use crate::secrets::vaults::sync::wrapping::{KeyFile, Wrapping};

// Unlocked Mac side (7.9).

/// Root of the synced folder on the unlocked Mac.
fn grant_root() -> TransportRoot {
    TransportRoot::Folder {
        path: PathBuf::from("/pairing/Vaults"),
    }
}

/// Another root on the unlocked Mac.
fn other_root() -> TransportRoot {
    TransportRoot::Folder {
        path: PathBuf::from("/other/Vaults"),
    }
}

/// Time the requests of the prompt tests are written.
fn written_at() -> Timestamp {
    Timestamp::from_second(1_800_000_000).unwrap()
}

/// Write a sidecar with the root `root` for vault `vault_id` under the app
/// data directory `app_root`.
fn put_root(app_root: &Path, vault_id: Uuid, root: &TransportRoot) {
    let sidecar = Sidecar {
        transport: Some(root.clone()),
        ..Sidecar::default()
    };
    sidecar.save(app_root, vault_id).unwrap();
}

/// Software encryption key of a new Mac and its public keys.
fn new_mac_keys() -> (ManagedKey, ReplicaKeys) {
    let software = ManagedKey::create_software_for_test().unwrap();
    let keys = ReplicaKeys {
        encryption: PublicKey(software.public_key_sec1().unwrap()),
        signing: PublicKey(vec![0x51; 65]),
    };
    (software, keys)
}

/// Keys of [`REPLICA`] in the sync states of the tests, as the new Mac pins
/// them.
fn unlocked_mac_keys() -> ReplicaKeys {
    ReplicaKeys {
        encryption: PublicKey(vec![4, 1]),
        signing: PublicKey(device_key()),
    }
}

/// `pairing` pin of `keys`.
fn pairing_pin(keys: &ReplicaKeys) -> PinnedKeys {
    PinnedKeys {
        source: PinSource::Pairing,
        encryption: keys.encryption.clone(),
        signing: keys.signing.clone(),
        revoked: false,
    }
}

/// Synced vault of [`REPLICA`] with a trusted sync state, synced through
/// `transport` at [`grant_root`].
fn granting(transport: &Arc<FakeTransport>) -> Fixture {
    let fx = synced(transport);
    put_root(&fx.root, fx.id(), &grant_root());
    fx
}

/// Grant `request`, matched with `code`, to the vault of `fx`.
fn grant(fx: &Fixture, request: &PairingRequest, code: &PairingCode) -> GrantOutcome {
    let key = || fx.vault.unlocked_key().unwrap();
    fx.catalog.files().grant_pairing(
        &Target::of(&fx.vault),
        Unlock::Test(&key),
        request,
        code,
        &grant_root(),
    )
}

/// Own `key.json` of `replica` in vault `vault_id`, if any.
fn own_key_file(transport: &FakeTransport, vault_id: Uuid, replica: ReplicaId) -> Option<KeyFile> {
    match transport.read(vault_id, replica, FileName::Key).unwrap() {
        ReadResult::Local(bytes) => Some(KeyFile::parse(&bytes).unwrap()),
        _ => None,
    }
}

/// Sync state of `fx` as saved.
fn saved_local(fx: &Fixture) -> LocalSyncState {
    LocalSyncState::load(&fx.root, fx.id(), &TestSigner::device()).unwrap()
}

/// Model of the app unlock of the unlocked Mac. The first key read prompts
/// and authenticates the shared context. Later reads on that context draw
/// no prompt, as `Unlock::App` reads on it.
#[derive(Default)]
struct TestAuth {
    authenticated: AtomicBool,
    prompts: AtomicUsize,
    reads: AtomicUsize,
}

impl TestAuth {
    /// File key of `vh`, read on the shared context.
    fn read(&self, vh: &VaultHandle) -> UnlockedKey {
        if !self.authenticated.swap(true, Ordering::SeqCst) {
            self.prompts.fetch_add(1, Ordering::SeqCst);
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        vh.unlocked_key().unwrap()
    }
}

/// Unlocked Mac with synced vaults in one app data directory, each synced
/// through one transport at [`grant_root`]. Vault `n` is synced as replica
/// `peer(n)`, and its directory has a `meta.json` in the folder.
struct UnlockedMac {
    _dir: TempDir,
    root: PathBuf,
    writer: VaultWriter,
    vaults: Vec<VaultHandle>,
}

impl UnlockedMac {
    fn new(transport: &Arc<FakeTransport>, count: u128) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let vaults_dir = dir.path().join("vaults");
        let writer = VaultWriter::isolated(&root).with_transport(transport.clone());
        let vaults = (1..=count)
            .map(|n| {
                let mut vault = Vault::new_for_test();
                vault.set_sync(GENERATION, Some(peer(n).0));
                let vh = VaultHandle::new_in(&vaults_dir, vault);
                writer.create(&vh).unwrap();
                let id = vh.vault_id().unwrap();
                state(id, peer(n), GENERATION)
                    .save(&root, &TestSigner::device())
                    .unwrap();
                put_root(&root, id, &grant_root());
                transport.put_meta(id, b"{}");
                vh
            })
            .collect();
        Self {
            _dir: dir,
            root,
            writer,
            vaults,
        }
    }

    /// Id of vault `n`, from 1.
    fn id(&self, n: usize) -> Uuid {
        self.vaults[n - 1].vault_id().unwrap()
    }

    fn local(&self, n: usize) -> LocalSyncState {
        LocalSyncState::load(&self.root, self.id(n), &TestSigner::device()).unwrap()
    }
}

#[test]
fn one_request_pairs_every_picked_vault() {
    let transport = Arc::new(FakeTransport::default());
    transport.set_now(written_at());
    let unlocked = UnlockedMac::new(&transport, 3);
    let (software, keys) = new_mac_keys();
    let new_mac = NewMac::with_public_keys(keys.clone());
    let mut pending = new_mac.start(&transport, &[]).unwrap();
    let request = pending.request().clone();
    let replica_ids: BTreeSet<ReplicaId> = request.replicas.values().copied().collect();
    assert_eq!(replica_ids.len(), 3, "one replica id per vault");

    // The unlocked Mac sees one request and matches the typed code.
    let now = written_at() + SignedDuration::from_mins(5);
    assert_eq!(
        PairingPrompt::pending(&*transport, &BTreeSet::new(), now).unwrap(),
        1
    );
    let typed = PairingCode::parse(&pending.code().shown()).unwrap();
    let matched = PairingPrompt::match_code(&*transport, &typed)
        .unwrap()
        .unwrap();
    assert_eq!(matched, request);
    assert_eq!(matched.name, NAME);
    let mut listed = PairingPrompt::vaults(&unlocked.root, &grant_root(), &matched);
    listed.sort();
    let mut all = vec![unlocked.id(1), unlocked.id(2), unlocked.id(3)];
    all.sort();
    assert_eq!(listed, all);

    // The user picks vaults 1 and 3. The app unlocks once.
    let auth = &TestAuth::default();
    let keys_of: Vec<Box<dyn Fn() -> UnlockedKey + Sync + '_>> = unlocked
        .vaults
        .iter()
        .map(|vh| Box::new(move || auth.read(vh)) as Box<dyn Fn() -> UnlockedKey + Sync>)
        .collect();
    let unlock = |target: &Target| {
        let n = unlocked
            .vaults
            .iter()
            .position(|vh| vh.path == target.path)
            .unwrap();
        Unlock::Test(&*keys_of[n])
    };
    let picks = vec![
        (unlocked.id(1), Target::of(&unlocked.vaults[0])),
        (unlocked.id(3), Target::of(&unlocked.vaults[2])),
    ];
    let outcomes = unlocked
        .writer
        .grant_pairings(&picks, unlock, &matched, &typed, &grant_root());

    assert_eq!(outcomes.len(), 2);
    for (vault_id, outcome) in &outcomes {
        assert!(
            matches!(outcome, GrantOutcome::Granted(PairedPin::New)),
            "{vault_id}: {outcome:?}"
        );
    }
    assert_eq!(auth.prompts.load(Ordering::SeqCst), 1);
    assert_eq!(
        auth.reads.load(Ordering::SeqCst),
        2,
        "one key read per picked vault and none for the grant"
    );

    // Each picked vault holds one wrapping in the own key.json of the
    // unlocked Mac, and pins the new Mac with `pairing`. The vault the user
    // did not pick receives no wrapping and no pin.
    for (n, replica) in [(1, peer(1)), (3, peer(3))] {
        let file = own_key_file(&transport, unlocked.id(n), replica).unwrap();
        let devices: Vec<_> = file.devices().collect();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].to_replica, request.replicas[&unlocked.id(n)]);
        let local = unlocked.local(n);
        assert_eq!(local.generation, GENERATION, "the pin keeps s");
        assert_eq!(
            local.pinned_keys[&request.replicas[&unlocked.id(n)]],
            pairing_pin(&keys)
        );
    }
    assert!(own_key_file(&transport, unlocked.id(2), peer(2)).is_none());
    assert!(
        !unlocked
            .local(2)
            .pinned_keys
            .contains_key(&request.replicas[&unlocked.id(2)])
    );

    // The new Mac receives both keys with one unwrap key, and pins the keys
    // of the unlocked Mac from each wrapping.
    let paired = pending.poll(&*transport, &software);
    let mut received: Vec<Uuid> = paired.iter().map(|vault| vault.vault_id).collect();
    received.sort();
    let mut picked = vec![unlocked.id(1), unlocked.id(3)];
    picked.sort();
    assert_eq!(received, picked);
    for vault in &paired {
        assert_eq!(vault.replica_id, request.replicas[&vault.vault_id]);
        assert_eq!(vault.key_id, KeyId(1));
        assert_eq!(vault.key.as_bytes(), key().as_bytes());
        assert_eq!(vault.pin, pairing_pin(&unlocked_mac_keys()));
    }
    assert!(pending.poll(&*transport, &software).is_empty());
}

#[test]
fn changed_signing_key_or_map_rejected() {
    let transport = FakeTransport::default();
    let code = PairingCode::generate();
    let request = request_of(&code, &[vault(1), vault(2)]);
    let mut signing = request.clone();
    signing.signing = PublicKey(vec![0x66; 65]);
    let mut replica = request.clone();
    replica.replicas.insert(vault(1), ReplicaId::generate());
    let mut added = request.clone();
    added.replicas.insert(vault(3), ReplicaId::generate());
    let mut removed = request.clone();
    removed.replicas.remove(&vault(2));

    for planted in [signing, replica, added, removed] {
        put_request(&transport, &planted);
        assert_eq!(
            PairingPrompt::match_code(&transport, &code).unwrap(),
            None,
            "{planted:?}"
        );
    }
    put_request(&transport, &request);
    assert_eq!(
        PairingPrompt::match_code(&transport, &code).unwrap(),
        Some(request)
    );
}

#[test]
fn prompt_shows_count_and_no_name_and_name_shows_only_for_request_that_verifies_under_code() {
    let transport = FakeTransport::default();
    transport.set_now(written_at());
    let code = PairingCode::generate();
    let request = request_of(&code, &[vault(1)]);
    put_request(&transport, &request);
    put_request(
        &transport,
        &request_of(&PairingCode::generate(), &[vault(1)]),
    );

    let now = written_at() + SignedDuration::from_mins(5);
    let count = PairingPrompt::pending(&transport, &BTreeSet::new(), now).unwrap();

    assert_eq!(count, 2);
    assert_eq!(transport.pairing_reads(), 0, "the count reads no request");
    let other = PairingCode::generate();
    assert_eq!(PairingPrompt::match_code(&transport, &other).unwrap(), None);
    let matched = PairingPrompt::match_code(&transport, &code)
        .unwrap()
        .unwrap();
    assert_eq!(matched.name, NAME);
    assert_eq!(matched.request_id, request.request_id);
}

#[test]
fn real_request_found_among_200_decoys() {
    let transport = FakeTransport::default();
    transport.set_now(written_at());
    let code = PairingCode::generate();
    let request = request_of(&code, &[vault(1)]);
    put_request(&transport, &request);
    transport.set_now(written_at() + SignedDuration::from_hours(1));
    for n in 0..200 {
        if n % 2 == 0 {
            put_request(
                &transport,
                &request_of(&PairingCode::generate(), &[vault(1)]),
            );
        } else {
            transport.put_pairing(RequestId::generate(), b"{}");
        }
    }

    let now = written_at() + SignedDuration::from_hours(2);
    assert_eq!(
        PairingPrompt::pending(&transport, &BTreeSet::new(), now).unwrap(),
        201
    );
    assert_eq!(
        PairingPrompt::match_code(&transport, &code).unwrap(),
        Some(request)
    );
}

#[test]
fn request_that_fails_hmac_is_never_shown_and_not_deleted() {
    let transport = FakeTransport::default();
    let code = PairingCode::generate();
    let planted = request_of(&PairingCode::generate(), &[vault(1)]);
    put_request(&transport, &planted);

    assert_eq!(PairingPrompt::match_code(&transport, &code).unwrap(), None);
    assert!(transport.pairing(planted.request_id).is_some());

    // A mistyped code deletes no real request either.
    let request = request_of(&code, &[vault(1)]);
    put_request(&transport, &request);
    let mistyped = PairingCode::generate();
    assert_eq!(
        PairingPrompt::match_code(&transport, &mistyped).unwrap(),
        None
    );
    assert_eq!(transport.list_pairings().unwrap().len(), 2);
    assert_eq!(
        PairingPrompt::match_code(&transport, &code).unwrap(),
        Some(request)
    );
}

#[test]
fn dismissed_request_does_not_prompt_again_new_id_does_and_request_older_than_24_hours_does_not() {
    let app = tempfile::tempdir().unwrap();
    let transport = FakeTransport::default();
    transport.set_now(written_at());
    let first_code = PairingCode::generate();
    let first = request_of(&first_code, &[vault(1)]);
    put_request(&transport, &first);
    let now = written_at() + SignedDuration::from_hours(1);
    let pending = || {
        let dismissed = DismissedRequests::load(app.path()).of(&grant_root());
        PairingPrompt::pending(&transport, &dismissed, now).unwrap()
    };
    assert_eq!(pending(), 1);

    PairingPrompt::dismiss(&transport, &grant_root(), app.path()).unwrap();

    assert_eq!(pending(), 0);
    let second = request_of(&PairingCode::generate(), &[vault(1)]);
    put_request(&transport, &second);
    assert_eq!(pending(), 1, "a request with a new id prompts");

    let old_code = PairingCode::generate();
    let old = request_of(&old_code, &[vault(1)]);
    put_request(&transport, &old);
    transport.set_pairing_modified(
        old.request_id,
        now - SignedDuration::from_hours(24) - SignedDuration::from_secs(1),
    );
    assert_eq!(
        pending(),
        1,
        "a request older than 24 hours does not prompt"
    );
    transport.set_pairing_modified(old.request_id, now - SignedDuration::from_hours(24));
    assert_eq!(pending(), 2, "a request of exactly 24 hours prompts");

    // The code check covers dismissed and old requests.
    assert_eq!(
        PairingPrompt::match_code(&transport, &first_code).unwrap(),
        Some(first)
    );
    transport.set_pairing_modified(
        old.request_id,
        written_at() - SignedDuration::from_hours(48),
    );
    assert_eq!(
        PairingPrompt::match_code(&transport, &old_code).unwrap(),
        Some(old)
    );
}

#[test]
fn request_file_larger_than_16_kb_not_read() {
    let transport = FakeTransport::default();
    transport.set_now(written_at());
    let code = PairingCode::generate();
    let request = request_of(&code, &[vault(1)]);
    put_request(&transport, &request);
    let now = written_at();

    transport.set_pairing_size(request.request_id, MAX_PAIRING_SIZE + 1);

    assert_eq!(
        PairingPrompt::pending(&transport, &BTreeSet::new(), now).unwrap(),
        0
    );
    assert_eq!(PairingPrompt::match_code(&transport, &code).unwrap(), None);
    assert_eq!(transport.pairing_reads(), 0);

    transport.set_pairing_size(request.request_id, MAX_PAIRING_SIZE);
    assert_eq!(
        PairingPrompt::pending(&transport, &BTreeSet::new(), now).unwrap(),
        1
    );
    assert_eq!(
        PairingPrompt::match_code(&transport, &code).unwrap(),
        Some(request)
    );
}

#[test]
fn mismatched_request_id_refused() {
    let transport = FakeTransport::default();
    let code = PairingCode::generate();
    let request = request_of(&code, &[vault(1)]);
    transport.put_pairing(RequestId::generate(), &request.to_bytes());

    assert_eq!(PairingPrompt::match_code(&transport, &code).unwrap(), None);

    put_request(&transport, &request);
    assert_eq!(
        PairingPrompt::match_code(&transport, &code).unwrap(),
        Some(request)
    );
}

#[test]
fn dismissed_ids_kept_by_root_and_unreadable_file_reads_as_empty() {
    let app = tempfile::tempdir().unwrap();
    let first = RequestId::generate();
    let second = RequestId::generate();
    let mut dismissed = DismissedRequests::default();
    dismissed.set(&grant_root(), BTreeSet::from([first]));
    dismissed.set(&other_root(), BTreeSet::from([second]));
    dismissed.save(app.path()).unwrap();

    let path = DismissedRequests::path(app.path());
    assert_eq!(path, app.path().join("sync").join("pairing.json"));
    let json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(json["roots"][0]["root"]["kind"], "Folder");
    assert_eq!(json["roots"][0]["root"]["path"], "/pairing/Vaults");
    assert_eq!(
        json["roots"][0]["requests"][0],
        first.0.hyphenated().to_string()
    );
    let loaded = DismissedRequests::load(app.path());
    assert_eq!(loaded, dismissed);
    assert_eq!(loaded.of(&grant_root()), BTreeSet::from([first]));
    assert_eq!(loaded.of(&other_root()), BTreeSet::from([second]));
    assert!(loaded.of(&TransportRoot::ICloud {}).is_empty());

    let mut cleared = loaded.clone();
    cleared.set(&grant_root(), BTreeSet::new());
    assert!(cleared.of(&grant_root()).is_empty());
    assert_eq!(cleared.of(&other_root()), BTreeSet::from([second]));

    fs::write(&path, b"{\"roots\": 1}").unwrap();
    assert_eq!(
        DismissedRequests::load(app.path()),
        DismissedRequests::default()
    );
}

#[test]
fn dismissal_file_alone_not_vault_file() {
    let app = tempfile::tempdir().unwrap();
    let mut dismissed = DismissedRequests::default();
    dismissed.set(&grant_root(), BTreeSet::from([RequestId::generate()]));
    dismissed.save(app.path()).unwrap();
    let files = VaultFiles::new(app.path().join("vaults"), app.path(), Vec::new());

    assert!(!files.present());
    assert_eq!(
        KeyState::probe(&TestKeys::neither(), &files),
        KeyState::NoVaultFiles
    );

    put_root(app.path(), vault(1), &grant_root());
    assert!(files.present(), "a sidecar is a vault file");
}

#[test]
fn vault_list_has_synced_vaults_in_map() {
    let transport = Arc::new(FakeTransport::default());
    let unlocked = UnlockedMac::new(&transport, 3);
    put_root(&unlocked.root, unlocked.id(3), &other_root());
    let code = PairingCode::generate();
    let request = request_of(
        &code,
        &[unlocked.id(1), unlocked.id(2), unlocked.id(3), vault(9)],
    );
    let only_two = request_of(&code, &[unlocked.id(2)]);

    let mut listed = PairingPrompt::vaults(&unlocked.root, &grant_root(), &request);
    listed.sort();

    let mut expected = vec![unlocked.id(1), unlocked.id(2)];
    expected.sort();
    assert_eq!(listed, expected);
    assert_eq!(
        PairingPrompt::vaults(&unlocked.root, &grant_root(), &only_two),
        vec![unlocked.id(2)]
    );
    assert_eq!(
        PairingPrompt::vaults(&unlocked.root, &other_root(), &request),
        vec![unlocked.id(3)]
    );
}

#[test]
fn wrapping_is_under_current_key_id_and_other_wrappings_written_back_unchanged() {
    let transport = Arc::new(FakeTransport::default());
    let fx = granting(&transport);
    fx.put_text(&under_key_2(
        &fx,
        &body(REPLICA, &[device_key()]),
        &two_keys(),
    ));
    let unknown = r#"{"kind":"Passkey","key_id":1,"credential":"abc"}"#;
    let existing = format!(
        r#"{{"version":1,"wrappings":[{{"kind":"Age","key_id":1,"key_fingerprint":"EREREREREREREREREREREQ==","recipient":"age1example","wrapped":"armored"}},{unknown},{{"kind":"Device","key_id":1,"key_fingerprint":"EREREREREREREREREREREQ==","to_replica":"00000000-0000-0000-0000-00000000002a","from_encryption":"BAQE","from_signing":"BQUF","wrapped":"BwcH"}}]}}"#
    );
    transport.put(fx.id(), REPLICA, "key.json", existing.as_bytes());
    let before = KeyFile::parse(existing.as_bytes()).unwrap();
    let code = PairingCode::generate();
    let (software, keys) = new_mac_keys();
    let request = request_with(&code, &[fx.id()], &keys);

    let outcome = grant(&fx, &request, &code);

    assert!(
        matches!(outcome, GrantOutcome::Granted(PairedPin::New)),
        "{outcome:?}"
    );
    let ReadResult::Local(bytes) = transport.read(fx.id(), REPLICA, FileName::Key).unwrap() else {
        panic!("own key.json is missing");
    };
    assert!(String::from_utf8(bytes.clone()).unwrap().contains(unknown));
    let after = KeyFile::parse(&bytes).unwrap();
    assert_eq!(after.wrappings.len(), 4);
    assert_eq!(after.wrappings[..3], before.wrappings[..]);
    let Wrapping::Device(wrapping) = &after.wrappings[3] else {
        panic!("last wrapping is not a Device wrapping");
    };
    let current = SyncKey::from_bytes([3; 32]);
    assert_eq!(wrapping.key_id, KeyId(2));
    assert_eq!(wrapping.key_fingerprint, current.fingerprint());
    assert_eq!(wrapping.to_replica, request.replicas[&fx.id()]);
    assert_eq!(wrapping.from_encryption, unlocked_mac_keys().encryption);
    assert_eq!(wrapping.from_signing, unlocked_mac_keys().signing);
    assert!(
        code.pair_key()
            .verify_wrapping(wrapping, fx.id(), REPLICA, &keys)
    );
    assert_eq!(
        wrapping.unwrap(&software).unwrap().as_bytes(),
        current.as_bytes()
    );
}

#[test]
fn failed_sync_state_save_writes_no_wrapping() {
    let transport = Arc::new(FakeTransport::default());
    let fx = granting(&transport);
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    let request = request_with(&code, &[fx.id()], &keys);
    let before = fx.on_disk();
    // A directory at the temp path of the sync state makes its save fail.
    let state_path = fx.state_path();
    let name = state_path.file_name().unwrap().to_str().unwrap();
    let blocker = state_path.with_file_name(format!(".{name}.tmp"));
    fs::create_dir(&blocker).unwrap();

    let outcome = grant(&fx, &request, &code);

    assert!(
        matches!(outcome, GrantOutcome::Failed(Error::SyncStateWriteError(_))),
        "{outcome:?}"
    );
    assert!(own_key_file(&transport, fx.id(), REPLICA).is_none());
    assert_eq!(fx.on_disk(), before);
    fs::remove_dir(&blocker).unwrap();
    assert!(saved_local(&fx).pinned_keys.is_empty());
}

/// Write the sync state of a test case for the vault of a fixture.
type PutState = fn(&Fixture);

#[test]
fn vault_whose_sync_state_not_trusted_receives_no_wrapping() {
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    let cases: [(&str, PutState); 4] = [
        ("missing", |_| {}),
        ("other signer", |fx| {
            fx.put(&state(fx.id(), REPLICA, GENERATION), &TestSigner::random())
        }),
        ("stopped", |fx| {
            let mut local = state(fx.id(), REPLICA, GENERATION);
            local.stopped_build = Some(BUILD_ID.to_string());
            fx.put(&local, &TestSigner::device());
        }),
        ("leaving", |fx| {
            let mut local = state(fx.id(), REPLICA, GENERATION);
            local.leaving = true;
            fx.put(&local, &TestSigner::device());
        }),
    ];
    for (name, put_state) in cases {
        let transport = Arc::new(FakeTransport::default());
        let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
        put_root(&fx.root, fx.id(), &grant_root());
        put_state(&fx);
        let request = request_with(&code, &[fx.id()], &keys);
        let before = fx.on_disk();

        let outcome = grant(&fx, &request, &code);

        assert!(
            matches!(outcome, GrantOutcome::NotTrusted(_)),
            "{name}: {outcome:?}"
        );
        assert!(
            own_key_file(&transport, fx.id(), REPLICA).is_none(),
            "{name}"
        );
        assert_eq!(fx.on_disk(), before, "{name}");
    }
}

#[test]
fn replica_pinned_to_other_keys_refused() {
    let transport = Arc::new(FakeTransport::default());
    let fx = granting(&transport);
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    let request = request_with(&code, &[fx.id()], &keys);
    let to_replica = request.replicas[&fx.id()];
    let mut local = state(fx.id(), REPLICA, GENERATION);
    local.pinned_keys.insert(
        to_replica,
        PinnedKeys {
            source: PinSource::FirstUse,
            encryption: PublicKey(vec![0x66; 65]),
            signing: keys.signing.clone(),
            revoked: false,
        },
    );
    fx.put(&local, &TestSigner::device());
    let before = fx.on_disk();

    let outcome = grant(&fx, &request, &code);

    assert!(matches!(outcome, GrantOutcome::Conflict), "{outcome:?}");
    assert!(own_key_file(&transport, fx.id(), REPLICA).is_none());
    assert_eq!(fx.on_disk(), before);

    // A revoked pin with the same keys is refused too.
    let mut revoked = local.clone();
    revoked.pinned_keys.insert(
        to_replica,
        PinnedKeys {
            revoked: true,
            ..pairing_pin(&keys)
        },
    );
    fx.put(&revoked, &TestSigner::device());
    assert!(matches!(
        grant(&fx, &request, &code),
        GrantOutcome::Conflict
    ));
    assert!(own_key_file(&transport, fx.id(), REPLICA).is_none());
}

#[test]
fn first_use_pin_with_keys_of_request_becomes_pairing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = granting(&transport);
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    let request = request_with(&code, &[fx.id()], &keys);
    let to_replica = request.replicas[&fx.id()];
    let mut local = state(fx.id(), REPLICA, GENERATION);
    local.pinned_keys.insert(
        to_replica,
        PinnedKeys {
            source: PinSource::FirstUse,
            ..pairing_pin(&keys)
        },
    );
    fx.put(&local, &TestSigner::device());

    let outcome = grant(&fx, &request, &code);

    assert!(
        matches!(outcome, GrantOutcome::Granted(PairedPin::Upgraded)),
        "{outcome:?}"
    );
    assert_eq!(
        saved_local(&fx).pinned_keys[&to_replica],
        pairing_pin(&keys)
    );
    assert_eq!(
        own_key_file(&transport, fx.id(), REPLICA)
            .unwrap()
            .devices()
            .count(),
        1
    );
}

#[test]
fn failed_key_json_write_keeps_pin_and_later_grant_writes_one_wrapping() {
    let transport = Arc::new(FakeTransport::default());
    let fx = granting(&transport);
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    let request = request_with(&code, &[fx.id()], &keys);
    let to_replica = request.replicas[&fx.id()];
    transport.set_failing_writes(true);

    let outcome = grant(&fx, &request, &code);

    assert!(
        matches!(outcome, GrantOutcome::Failed(Error::SyncTransportError(_))),
        "{outcome:?}"
    );
    assert!(own_key_file(&transport, fx.id(), REPLICA).is_none());
    assert_eq!(
        saved_local(&fx).pinned_keys[&to_replica],
        pairing_pin(&keys)
    );

    transport.set_failing_writes(false);
    for _ in 0..2 {
        let outcome = grant(&fx, &request, &code);
        assert!(
            matches!(outcome, GrantOutcome::Granted(PairedPin::Unchanged)),
            "{outcome:?}"
        );
        let file = own_key_file(&transport, fx.id(), REPLICA).unwrap();
        let devices: Vec<_> = file.devices().collect();
        assert_eq!(
            devices.len(),
            1,
            "a wrapping to the same replica is replaced"
        );
        assert_eq!(devices[0].to_replica, to_replica);
    }
}

#[test]
fn vault_outside_root_or_map_gets_no_wrapping() {
    let code = PairingCode::generate();
    let (_, keys) = new_mac_keys();
    for (name, root, in_map) in [
        ("other root", Some(other_root()), true),
        ("no root", None, true),
        ("not in map", Some(grant_root()), false),
    ] {
        let transport = Arc::new(FakeTransport::default());
        let fx = synced(&transport);
        if let Some(root) = &root {
            put_root(&fx.root, fx.id(), root);
        }
        let vaults = if in_map {
            vec![fx.id()]
        } else {
            vec![vault(1)]
        };
        let request = request_with(&code, &vaults, &keys);
        let before = fx.on_disk();

        let outcome = grant(&fx, &request, &code);

        assert!(
            matches!(
                outcome,
                GrantOutcome::Failed(Error::PairingVaultNotOffered(_))
            ),
            "{name}: {outcome:?}"
        );
        assert!(
            own_key_file(&transport, fx.id(), REPLICA).is_none(),
            "{name}"
        );
        assert_eq!(fx.on_disk(), before, "{name}");
    }
}
