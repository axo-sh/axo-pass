//! Rebuild of a vault from its local sync state at `v < s`, for another
//! replica id, over a refused file, and for a missing file. Restore of a
//! synced vault over a refused file.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use jiff::Zoned;
use uuid::Uuid;

use super::NOW;
use super::load::{Fixture, GENERATION, REPLICA, body, device_key, state, state_of};
use super::state_file::keyring;
use super::view::State;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultFileKey};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::{UnlockedKey, Vault};
use crate::secrets::vaults::storage::txn::{Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::{ReplicaId, Session};
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::{Error, VaultHandle};

/// Body of `replica` with its own key and the entries of a vault named `name`
/// filled by [`Vault::fill_for_test`].
fn filled(replica: ReplicaId, name: &str) -> State {
    let mut vault = Vault::new_for_test();
    vault.fill_for_test();
    vault.name = Some(name.to_string());
    let mut state = body(replica, &[device_key()]);
    let mut session = Session::new(replica);
    let edits = LocalEdits::find(&state, &vault, replica).unwrap();
    assert!(edits.record(&mut state, &mut session, NOW).is_some());
    state
}

/// File key of a vault `id` rebuilt on request, the same on each call.
fn new_key(id: Uuid) -> UnlockedKey {
    UnlockedKey::for_test(
        VaultFileKey::new(b"rebuilt file key".to_vec()),
        VaultCipher::new_with_bytes(&[7; 32], id),
    )
}

/// Vault file at `path`, verified and decrypted with `key`.
fn open(path: &Path, key: &UnlockedKey) -> Vault {
    let file = EncryptedVault::load(path, &TestSigner::device()).unwrap();
    Vault::from_unlocked_key(key, file).unwrap()
}

/// Sync state of vault `id` under `root` as saved, and its body.
fn saved_state(root: &Path, id: Uuid) -> (LocalSyncState, State) {
    let local = LocalSyncState::load(root, id, &TestSigner::device()).unwrap();
    let state = local.open(&keyring()).unwrap();
    (local, state)
}

/// Check that `vault` holds entries and has no edits of `replica` against
/// the view of `state`.
fn assert_no_edits(state: &State, vault: &Vault, replica: ReplicaId) {
    assert!(!vault.list_items().is_empty());
    let edits = LocalEdits::find(state, vault, replica).unwrap();
    assert!(edits.is_empty(), "{:?}", edits.edits());
}

/// Replace the vault file at `path` with a copy signed by another key, which
/// is refused. Returns the refused contents.
pub(super) fn refuse(path: &Path) -> String {
    let contents = fs::read_to_string(path).unwrap();
    let raw = EncryptedVault::raw_vault_json(&contents)
        .unwrap()
        .to_string();
    let forged = EncryptedVault::sign_vault_json(raw, &TestSigner::random()).unwrap();
    fs::write(path, &forged).unwrap();
    forged
}

/// Retained version or invalid file `name` of vault `id` under `root`.
fn version_file(root: &Path, id: Uuid, name: &str) -> PathBuf {
    root.join("versions")
        .join(ShortId::encode_uuid(id))
        .join(name)
}

/// Contents of the invalid files of vault `id` under `files`, newest first.
fn invalid_files(files: &VaultWriter, id: Uuid) -> Vec<String> {
    files
        .list_invalid(id)
        .iter()
        .map(|name| fs::read_to_string(version_file(files.root(), id, name)).unwrap())
        .collect()
}

fn set_mode(dir: &Path, mode: u32) {
    fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn each_row_of_generation_table_takes_stated_action() {
    let device = TestSigner::device();

    // v == s: the vault loads. A transaction records the change and saves
    // both with the next generation, the sync state first.
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    let (_, before) = saved_state(&fx.root, fx.id());
    fx.read().unwrap();
    fx.add_item().unwrap();
    let file = EncryptedVault::load(&fx.vault.path, &device).unwrap();
    assert_eq!(file.generation, GENERATION + 1);
    let (local, state) = saved_state(&fx.root, fx.id());
    assert_eq!(local.generation, GENERATION + 1);
    assert_ne!(state, before);
    assert_eq!(fx.read_case(), SyncLoad::Current);

    // v < s: the load check refuses the vault, and a read runs the rebuild
    // in its place (9.2). A transaction rebuilds the vault from the sync
    // state, retains the replaced file, and saves both with the next
    // generation.
    let fx = Fixture::synced();
    let content = filled(REPLICA, "Personal");
    fx.put(
        &state_of(fx.id(), REPLICA, GENERATION + 1, &content),
        &device,
    );
    let replaced = fs::read_to_string(&fx.vault.path).unwrap();
    let replaced_file = EncryptedVault::load(&fx.vault.path, &device).unwrap();
    assert!(matches!(
        fx.read_case().check(),
        Err(Error::SyncRepairNeeded(_))
    ));

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(committed.changed);
    let (local, state) = saved_state(&fx.root, fx.id());
    assert_eq!(local.generation, GENERATION + 2);
    assert_eq!(state, content);
    let file = EncryptedVault::load(&fx.vault.path, &device).unwrap();
    assert_eq!(file.generation, GENERATION + 2);
    assert_eq!(file.replica_id, Some(REPLICA.0));
    // The vault keeps the id, key, and file key of the file it replaced,
    // which verified.
    assert_eq!(file.id, replaced_file.id);
    assert_eq!(file.key, "personal");
    assert!(file.file_key == replaced_file.file_key);
    let vault = open(&fx.vault.path, &fx.vault.unlocked_key().unwrap());
    assert_no_edits(&state, &vault, REPLICA);
    assert_eq!(fx.read_case(), SyncLoad::Current);
    fx.read().unwrap();

    let files = fx.catalog.files();
    let versions = files.list_versions(fx.id()).unwrap();
    assert_eq!(versions.len(), 1);
    let retained = version_file(&fx.root, fx.id(), &versions[0].name);
    assert_eq!(fs::read_to_string(retained).unwrap(), replaced);
    assert!(files.list_invalid(fx.id()).is_empty());
}

#[test]
fn requested_change_applied_to_rebuilt_vault() {
    let fx = Fixture::synced();
    fx.put(
        &state_of(
            fx.id(),
            REPLICA,
            GENERATION + 1,
            &filled(REPLICA, "Personal"),
        ),
        &TestSigner::device(),
    );

    let committed = fx
        .write(|vh| {
            assert!(vh.get_item_overview("kept")?.is_some());
            vh.add_item("item", "Item").map(|_| ())
        })
        .unwrap();

    let vault = open(&fx.vault.path, &fx.vault.unlocked_key().unwrap());
    assert!(vault.get_item("kept").is_ok());
    assert!(vault.get_item("item").is_ok());
    assert_eq!(vault.generation(), GENERATION + 2);
    assert!(committed.vault.get_item_overview("item").unwrap().is_some());
}

#[test]
fn crash_between_sync_state_save_and_vault_save_loads_as_older_vault_and_rebuild_finds_no_edits() {
    let fx = Fixture::synced();
    let content = filled(REPLICA, "Personal");
    fx.put(
        &state_of(fx.id(), REPLICA, GENERATION + 1, &content),
        &TestSigner::device(),
    );
    let before = fs::read_to_string(&fx.vault.path).unwrap();

    // The vault save fails after the sync state save, as a crash between the
    // two saves leaves them.
    set_mode(&fx.vaults_dir, 0o555);
    let result = fx.write(|_| Ok(()));
    set_mode(&fx.vaults_dir, 0o755);

    assert!(matches!(result, Err(Error::VaultWriteError(_))));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), before);
    assert_eq!(saved_state(&fx.root, fx.id()).0.generation, GENERATION + 2);
    let case = SyncLoad::OlderVault {
        vault: GENERATION,
        state: GENERATION + 2,
    };
    assert_eq!(fx.read_case(), case);

    fx.write(|_| Ok(())).unwrap();

    assert_eq!(fx.read_case(), SyncLoad::Current);
    let (local, state) = saved_state(&fx.root, fx.id());
    assert_eq!(local.generation, GENERATION + 3);
    let vault = open(&fx.vault.path, &fx.vault.unlocked_key().unwrap());
    assert_no_edits(&state, &vault, REPLICA);
}

#[test]
fn vault_of_another_replica_id_is_rebuilt_and_kept_as_invalid_file() {
    let fx = Fixture::synced();
    let other = ReplicaId(Uuid::from_u128(2));
    let content = filled(other, "Personal");
    fx.put(
        &state_of(fx.id(), other, GENERATION, &content),
        &TestSigner::device(),
    );
    let replaced = fs::read_to_string(&fx.vault.path).unwrap();

    fx.write(|_| Ok(())).unwrap();

    let file = EncryptedVault::load(&fx.vault.path, &TestSigner::device()).unwrap();
    assert_eq!(file.replica_id, Some(other.0));
    assert_eq!(file.generation, GENERATION + 1);
    assert_eq!(fx.read_case(), SyncLoad::Current);
    let (_, state) = saved_state(&fx.root, fx.id());
    let vault = open(&fx.vault.path, &fx.vault.unlocked_key().unwrap());
    assert_no_edits(&state, &vault, other);

    let files = fx.catalog.files();
    assert_eq!(invalid_files(files, fx.id()), vec![replaced]);
    assert!(files.list_versions(fx.id()).unwrap().is_empty());
}

#[test]
fn signed_vault_file_copied_over_another_synced_vault_path_refused_and_rebuilt_from_sync_state() {
    let device = TestSigner::device();
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    let personal = fs::read_to_string(&fx.vault.path).unwrap();
    let work_replica = ReplicaId(Uuid::from_u128(2));
    let mut vault = Vault::new_for_test();
    vault.set_key("work".to_string());
    vault.set_sync(GENERATION, Some(work_replica.0));
    let work = VaultHandle::new_in(&fx.vaults_dir, vault);
    fx.catalog.files().create(&work).unwrap();
    let work_id = work.vault_id().unwrap();
    let work_file_key = EncryptedVault::load(&work.path, &device)
        .unwrap()
        .file_key
        .clone();
    let content = filled(work_replica, "Work");
    state_of(work_id, work_replica, GENERATION, &content)
        .save(&fx.root, &device)
        .unwrap();

    fs::copy(&fx.vault.path, &work.path).unwrap();
    let copied = fs::read_to_string(&work.path).unwrap();
    let scan = fx.catalog.scan();
    assert!(scan.vaults.is_empty());
    let missing: Vec<Uuid> = scan.missing.iter().map(|missing| missing.id).collect();
    assert_eq!(missing, vec![work_id]);

    let key = || new_key(work_id);
    let committed = fx
        .catalog
        .rebuild(work_id, None, Unlock::Test(&key))
        .unwrap();

    // The header key of the copy is claimed by the vault it was copied from,
    // so the key comes from the synced name.
    assert_eq!(committed.vault.key, "work");
    assert_eq!(committed.vault.path, work.path);
    let file = EncryptedVault::load(&work.path, &device).unwrap();
    assert_eq!(file.id, work_id);
    assert_eq!(file.replica_id, Some(work_replica.0));
    assert!(file.file_key != work_file_key);
    let (local, state) = saved_state(&fx.root, work_id);
    assert_eq!(local.generation, GENERATION + 1);
    assert_eq!(file.generation, GENERATION + 1);
    assert_no_edits(&state, &open(&work.path, &new_key(work_id)), work_replica);
    assert_eq!(invalid_files(fx.catalog.files(), work_id), vec![copied]);
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), personal);

    let scan = fx.catalog.scan();
    assert!(scan.duplicates.is_empty());
    assert!(scan.missing.is_empty());
    let keys: Vec<&str> = scan.vaults.keys().map(String::as_str).collect();
    assert_eq!(keys, vec!["personal", "work"]);
}

#[test]
fn sync_state_with_no_vault_file_can_be_rebuilt() {
    let device = TestSigner::device();
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    let lost = Uuid::from_u128(0x200);
    let content = filled(REPLICA, "Lost Vault");
    state_of(lost, REPLICA, 3, &content)
        .save(&fx.root, &device)
        .unwrap();
    let missing: Vec<Uuid> = fx.catalog.scan().missing.iter().map(|m| m.id).collect();
    assert_eq!(missing, vec![lost]);

    let key = || new_key(lost);
    let committed = fx.catalog.rebuild(lost, None, Unlock::Test(&key)).unwrap();

    let path = VaultHandle::file_path(&fx.vaults_dir, lost);
    assert_eq!(committed.vault.path, path);
    assert_eq!(committed.vault.key, "lost-vault");
    assert_eq!(committed.vault_id, lost);
    let (local, state) = saved_state(&fx.root, lost);
    assert_eq!(local.generation, 4);
    let vault = open(&path, &new_key(lost));
    assert_eq!(vault.generation(), 4);
    assert_eq!(vault.replica_id(), Some(REPLICA.0));
    assert_no_edits(&state, &vault, REPLICA);
    assert!(fx.catalog.files().list_invalid(lost).is_empty());

    let scan = fx.catalog.scan();
    assert!(scan.missing.is_empty());
    assert!(scan.vaults.contains_key("lost-vault"));
}

#[test]
fn rebuilt_vault_takes_free_header_key_or_synced_name_with_date_and_index() {
    let device = TestSigner::device();
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    let today = || Zoned::now().date().strftime("%Y%m%d").to_string();
    let rebuild = |id: Uuid, name: &str| {
        state_of(id, REPLICA, 1, &filled(REPLICA, name))
            .save(&fx.root, &device)
            .unwrap();
        let key = || new_key(id);
        let committed = fx.catalog.rebuild(id, None, Unlock::Test(&key)).unwrap();
        committed.vault.key
    };

    // A synced name whose key another vault claims takes today's date and
    // the first free index.
    let day_before = today();
    let first = rebuild(Uuid::from_u128(0x200), "Personal");
    let second = rebuild(Uuid::from_u128(0x300), "Personal");
    let keys = [day_before, today()]
        .map(|date| [format!("personal-{date}-1"), format!("personal-{date}-2")]);
    assert!(
        keys.contains(&[first.clone(), second.clone()]),
        "{first} {second}"
    );

    // A synced name that does not give a valid key gives `vault`.
    assert_eq!(rebuild(Uuid::from_u128(0x400), "?"), "vault");

    // A refused file whose header key is valid and free keeps it.
    let id = Uuid::from_u128(0x500);
    let mut vault = Vault::new_for_test();
    vault.set_key("kept-key".to_string());
    let path = VaultHandle::file_path(&fx.vaults_dir, id);
    let other_mac = VaultWriter::isolated_with_signer(fx.root.join("other"), TestSigner::random());
    other_mac
        .create(&VaultHandle::unlocked(path, vault))
        .unwrap();
    assert_eq!(rebuild(id, "Personal"), "kept-key");
    assert_eq!(fx.catalog.files().list_invalid(id).len(), 1);
}

#[test]
fn rebuild_over_refused_file_takes_new_file_key_and_keeps_refused_file() {
    let device = TestSigner::device();
    let fx = Fixture::synced();
    let content = filled(REPLICA, "Personal");
    fx.put(&state_of(fx.id(), REPLICA, GENERATION, &content), &device);
    let refused = refuse(&fx.vault.path);
    assert!(matches!(fx.read(), Err(Error::VaultSignatureInvalid)));

    let key = || new_key(fx.id());
    let committed = fx
        .catalog
        .rebuild(fx.id(), Some(&fx.vault.path), Unlock::Test(&key))
        .unwrap();

    // The unverified header key is valid and free.
    assert_eq!(committed.vault.key, "personal");
    let file = EncryptedVault::load(&fx.vault.path, &device).unwrap();
    assert_eq!(file.generation, GENERATION + 1);
    // The refused file key does not open the rebuilt vault.
    assert!(matches!(
        Vault::from_unlocked_key(&fx.vault.unlocked_key().unwrap(), file),
        Err(Error::VaultFileKeyChanged)
    ));
    let (_, state) = saved_state(&fx.root, fx.id());
    assert_no_edits(&state, &open(&fx.vault.path, &new_key(fx.id())), REPLICA);
    assert_eq!(invalid_files(fx.catalog.files(), fx.id()), vec![refused]);
}

#[test]
fn rebuild_on_request_refuses_file_that_verifies_and_sync_state_not_trusted_or_leaving() {
    let device = TestSigner::device();
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    let key = || new_key(fx.id());
    let before = fx.on_disk();

    let verifies = fx
        .catalog
        .rebuild(fx.id(), Some(&fx.vault.path), Unlock::Test(&key));
    assert!(matches!(verifies, Err(Error::VaultNotRefused(_))));
    let unlocked = fx
        .catalog
        .rebuild(fx.id(), Some(&fx.vault.path), Unlock::Unlocked(&fx.vault));
    assert!(matches!(unlocked, Err(Error::VaultLocked)));
    assert_eq!(fx.on_disk(), before);

    for name in ["signed by another key", "missing", "leaving"] {
        let fx = Fixture::synced();
        match name {
            "signed by another key" => {
                fx.put_foreign_state();
            },
            "leaving" => {
                let mut local = state(fx.id(), REPLICA, GENERATION);
                local.leaving = true;
                fx.put(&local, &device);
            },
            _ => {},
        }
        refuse(&fx.vault.path);
        let before = fx.on_disk();

        let key = || new_key(fx.id());
        let result = fx
            .catalog
            .rebuild(fx.id(), Some(&fx.vault.path), Unlock::Test(&key));

        assert!(
            matches!(result, Err(Error::SyncRepairNeeded(_))),
            "{name}: {:?}",
            result.err()
        );
        assert_eq!(fx.on_disk(), before, "{name}");
        assert!(
            fx.catalog.files().list_invalid(fx.id()).is_empty(),
            "{name}"
        );
    }
}

#[test]
fn restore_over_refused_file_takes_state_generation() {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    fx.add_item().unwrap();
    fx.put_state(GENERATION + 1);
    let refused = refuse(&fx.vault.path);
    let versions = fx.catalog.files().list_versions(fx.id()).unwrap();
    assert_eq!(versions.len(), 1);

    let key = || fx.vault.unlocked_key().unwrap();
    fx.catalog
        .files()
        .restore_refused(
            &Target::of(&fx.vault),
            Unlock::Test(&key),
            &versions[0].name,
        )
        .unwrap();

    let file = EncryptedVault::load(&fx.vault.path, &TestSigner::device()).unwrap();
    assert_eq!(file.generation, GENERATION + 1);
    assert_eq!(file.replica_id, Some(REPLICA.0));
    assert!(file.items.is_empty());
    assert_eq!(fx.read_case(), SyncLoad::Current);
    assert_eq!(invalid_files(fx.catalog.files(), fx.id()), vec![refused]);
}
