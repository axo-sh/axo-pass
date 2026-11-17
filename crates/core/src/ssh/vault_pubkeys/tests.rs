use std::os::unix::fs::PermissionsExt;

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

use super::*;
use crate::ssh::ssh_keys::SystemSshKey;

const LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl work";

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

#[test]
fn path_uses_short_credential_id() {
    let path = path_for(Path::new("/home/u/.ssh"), id(1));

    assert_eq!(
        path,
        Path::new("/home/u/.ssh/id_vault_1111111111111111111112.pub")
    );
}

#[test]
fn key_name_matches_file_stem() {
    assert_eq!(key_name(id(1)), "id_vault_1111111111111111111112");
}

#[test]
fn write_creates_public_file_and_directory() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join(".ssh");

    let path = write(&dir, id(1), LINE).unwrap();

    assert_eq!(path, path_for(&dir, id(1)));
    assert_eq!(fs::read_to_string(&path).unwrap(), format!("{LINE}\n"));
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o644);
    assert_eq!(mode(&dir), 0o700);
}

#[test]
fn write_replaces_file_and_restores_deleted_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), id(1), "old").unwrap();

    write(dir.path(), id(1), LINE).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), format!("{LINE}\n"));

    fs::remove_file(&path).unwrap();
    write(dir.path(), id(1), LINE).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), format!("{LINE}\n"));
}

#[test]
fn write_leaves_existing_directory_mode() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();

    write(dir.path(), id(1), LINE).unwrap();

    let mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755);
}

#[test]
fn remove_deletes_file_and_tolerates_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), id(1), LINE).unwrap();
    let other = write(dir.path(), id(2), LINE).unwrap();

    remove(dir.path(), id(1)).unwrap();
    remove(dir.path(), id(1)).unwrap();

    assert!(!path.exists());
    assert!(other.exists());
}

#[test]
fn sweep_deletes_only_files_of_removed_keys() {
    let dir = tempfile::tempdir().unwrap();
    let kept = write(dir.path(), id(1), LINE).unwrap();
    let gone = write(dir.path(), id(2), LINE).unwrap();
    let unrelated = [
        "id_se_abc.pub",
        "id_ed25519.pub",
        "id_vault_notauuid.pub",
        "id_vault_00000000-0000-0000-0000-000000000003",
        "config",
    ];
    for name in unrelated {
        fs::write(dir.path().join(name), "x").unwrap();
    }

    let removed = sweep(dir.path(), &HashSet::from([id(1)])).unwrap();

    assert_eq!(removed, vec![gone.clone()]);
    assert!(kept.exists());
    assert!(!gone.exists());
    for name in unrelated {
        assert!(dir.path().join(name).exists(), "{name}");
    }
}

#[test]
fn sweep_of_missing_directory_removes_nothing() {
    let dir = tempfile::tempdir().unwrap();

    let removed = sweep(&dir.path().join("none"), &HashSet::new()).unwrap();

    assert!(removed.is_empty());
}

#[test]
fn system_key_listing_skips_vault_public_files() {
    let dir = tempfile::tempdir().unwrap();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    key.write_openssh_file(&dir.path().join("id_ed25519"), LineEnding::LF)
        .unwrap();
    let line = key.public_key().to_openssh().unwrap();
    write(dir.path(), id(1), &line).unwrap();

    let keys = SystemSshKey::load_from_dir(dir.path()).unwrap();

    let names: Vec<_> = keys.iter().map(|key| key.name.as_str()).collect();
    assert_eq!(names, ["id_ed25519"]);
}
