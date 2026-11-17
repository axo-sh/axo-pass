use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::{fs, io};

/// Write a file by way of a temp file in the same directory. The data is
/// synced before the temp file is renamed over `path`, so `path` holds either
/// the old or the new contents after a crash.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    write_atomic_with_mode(path, data, None)
}

/// Like [`write_atomic`], with the file readable and writable by the owner
/// only (mode `0600`).
pub fn write_atomic_private(path: &Path, data: &[u8]) -> io::Result<()> {
    write_atomic_with_mode(path, data, Some(0o600))
}

fn write_atomic_with_mode(path: &Path, data: &[u8], mode: Option<u32>) -> io::Result<()> {
    let (dir, tmp_path) = tmp_path(path, "tmp")?;
    let result = write_synced(&tmp_path, data, mode).and_then(|()| fs::rename(&tmp_path, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
        return result;
    }

    // Sync the directory so the rename itself is durable.
    fs::File::open(dir)?.sync_all()
}

/// Write a file that must not exist yet, by way of a temp file in the same
/// directory. The temp file is linked to `path`, which fails if `path` exists,
/// so an existing file is never replaced and `path` never holds partial data.
pub fn write_atomic_new(path: &Path, data: &[u8]) -> io::Result<()> {
    let (dir, tmp_path) = tmp_path(path, "new.tmp")?;
    let result = write_synced(&tmp_path, data, None).and_then(|()| fs::hard_link(&tmp_path, path));
    let _ = fs::remove_file(&tmp_path);
    result?;
    fs::File::open(dir)?.sync_all()
}

/// Directory of `path`, and the hidden temp file `.{file name}.{suffix}` in
/// it.
fn tmp_path<'a>(path: &'a Path, suffix: &str) -> io::Result<(&'a Path, PathBuf)> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Path has no parent directory"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Path has no file name"))?
        .to_string_lossy();
    Ok((dir, dir.join(format!(".{file_name}.{suffix}"))))
}

/// Write a new file and sync it. Fails if `path` already exists.
pub fn write_new_synced(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

fn write_synced(path: &Path, data: &[u8], mode: Option<u32>) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    if let Some(mode) = mode {
        options.mode(mode);
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn write_atomic_replaces_contents_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        fs::write(&path, "old contents that are longer").unwrap();

        write_atomic(&path, b"new").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![OsString::from("vault.json")]);
    }

    #[test]
    fn write_atomic_private_sets_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_atomic_private(&path, b"new").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn write_atomic_keeps_old_file_if_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        fs::write(&path, "old").unwrap();
        // A directory at the temp path makes creating the temp file fail.
        fs::create_dir(dir.path().join(".vault.json.tmp")).unwrap();

        assert!(write_atomic(&path, b"new").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "old");
    }

    #[test]
    fn write_atomic_new_refuses_existing_file_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_atomic_new(&path, b"first").unwrap();

        let err = write_atomic_new(&path, b"second").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![OsString::from("vault.json")]);
    }

    #[test]
    fn write_new_synced_refuses_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("version.json");
        write_new_synced(&path, b"first").unwrap();

        assert!(write_new_synced(&path, b"second").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
    }
}
