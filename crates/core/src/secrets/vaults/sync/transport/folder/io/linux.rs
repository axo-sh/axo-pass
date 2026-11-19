//! Plain file access for Linux.

use std::ffi::{CStr, CString};
use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::{
    FileStatus, FolderIo, WriteMode, delete_path, metadata_status, move_into_place, read_limited,
    write_temp,
};

/// Error codes of `renameat2` for a file system without `RENAME_NOREPLACE`.
/// Linux reports a filesystem without the flag as `EINVAL`, and a kernel
/// without `renameat2` as `ENOSYS`.
pub(super) const RENAME_UNSUPPORTED: &[i32] = &[libc::ENOTSUP, libc::EINVAL, libc::ENOSYS];

/// Linux files are always local.
pub(super) fn is_dataless(_meta: &Metadata) -> bool {
    false
}

/// Rename `from` to `to` with `RENAME_NOREPLACE`. Returns the C result.
pub(super) fn rename_noreplace(from: &CStr, to: &CStr) -> i32 {
    // SAFETY: both paths are NUL-terminated strings that outlive the call.
    unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    }
}

/// File access through `std::fs` on Linux. Nothing coordinates the access,
/// since the folders of Linux sync tools (Syncthing, Nextcloud, rclone) are
/// plain directories. A file is always local.
///
/// A write puts the temp file outside the synced folder, in
/// `$XDG_CACHE_HOME/axo-pass/tmp`, if that directory is on the file system of
/// the target. Otherwise the temp file is an unnamed `O_TMPFILE` file of the
/// target's directory, which no listing shows until it is linked in. If the
/// file system has no `O_TMPFILE`, the write fails.
#[derive(Debug, Default)]
pub struct CoordinatedIo;

/// Where a write puts its temp file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TempPlace {
    /// A file in the cache temp directory, moved into place by rename.
    CacheDir,
    /// An unnamed file of the target's directory, linked into place.
    Tmpfile,
}

impl TempPlace {
    /// Place for a write of a file in a directory on device `target_dev`,
    /// with the cache temp directory on device `cache_dev`. A rename works
    /// within one device only.
    fn choose(cache_dev: u64, target_dev: u64) -> Self {
        if cache_dev == target_dev {
            Self::CacheDir
        } else {
            Self::Tmpfile
        }
    }
}

impl CoordinatedIo {
    /// Directory of the temp files that are renamed into place.
    #[cfg(not(test))]
    fn cache_temp_dir() -> PathBuf {
        crate::core::dirs::cache_dir().join("tmp")
    }

    /// Directory of the temp files in a test, a temp directory of the
    /// running thread that is deleted when the thread ends, so no test
    /// writes under the real cache directory.
    #[cfg(test)]
    fn cache_temp_dir() -> PathBuf {
        thread_local! {
            static DIR: tempfile::TempDir = tempfile::tempdir().unwrap();
        }
        DIR.with(|dir| dir.path().join("tmp"))
    }

    /// Create `dir` with mode 0700, and the missing directories above it.
    fn create_private_dir(dir: &Path) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }

    /// Write `data` to `path`. The temp file is in `cache_temp` if that
    /// directory is on the device of the target directory, and an `O_TMPFILE`
    /// file otherwise, or if the rename from `cache_temp` fails with `EXDEV`.
    /// `force` replaces the choice by device, for tests.
    fn write_at(
        path: &Path,
        data: &[u8],
        mode: WriteMode,
        cache_temp: &Path,
        force: Option<TempPlace>,
    ) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let dir = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        let target_dev = fs::metadata(dir)?.dev();
        let cache_dev = Self::create_private_dir(cache_temp)
            .and_then(|()| fs::metadata(cache_temp))
            .map(|meta| meta.dev());
        let place = match (force, cache_dev) {
            (Some(place), _) => place,
            (None, Ok(cache_dev)) => TempPlace::choose(cache_dev, target_dev),
            (None, Err(e)) => {
                log::debug!(
                    "Cache temp directory {} unusable: {e}",
                    cache_temp.display()
                );
                TempPlace::Tmpfile
            },
        };
        if place == TempPlace::CacheDir {
            match Self::write_via_cache(path, data, mode, cache_temp) {
                Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
                    log::debug!(
                        "Cannot move {} from {} (cross-device), using O_TMPFILE",
                        path.display(),
                        cache_temp.display()
                    );
                },
                result => {
                    log::debug!("Wrote {} through {}", path.display(), cache_temp.display());
                    return result;
                },
            }
        }
        let result = Self::write_via_tmpfile(path, dir, data, mode, cache_temp);
        log::debug!(
            "Wrote {} through O_TMPFILE: {:?}",
            path.display(),
            result.is_ok()
        );
        result
    }

    /// Write `data` to a new temp file in `cache_temp` and move it to
    /// `path`. The temp file is removed on failure.
    fn write_via_cache(
        path: &Path,
        data: &[u8],
        mode: WriteMode,
        cache_temp: &Path,
    ) -> io::Result<()> {
        let temp = cache_temp.join(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = write_temp(&temp, data).and_then(|()| move_into_place(&temp, path, mode));
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    /// Write `data` to an `O_TMPFILE` file in `dir`, sync it, and link it to
    /// `path` (`New`), or to a hidden sibling that replaces `path`
    /// (`Replace`).
    fn write_via_tmpfile(
        path: &Path,
        dir: &Path,
        data: &[u8],
        mode: WriteMode,
        cache_temp: &Path,
    ) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let mut file = match OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
            .mode(0o600)
            .open(dir)
        {
            Ok(file) => file,
            // Kernels and file systems without `O_TMPFILE`: EOPNOTSUPP, or
            // EISDIR and EINVAL from older kernels that ignore the flag.
            Err(e)
                if e.raw_os_error().is_some_and(|code| {
                    [libc::EOPNOTSUPP, libc::EISDIR, libc::EINVAL].contains(&code)
                }) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "cannot write {}: it is on a different file system than the temp \
                         directory {}, and its file system has no O_TMPFILE ({e})",
                        path.display(),
                        cache_temp.display()
                    ),
                ));
            },
            Err(e) => return Err(e),
        };
        file.write_all(data)?;
        file.sync_all()?;
        let source = format!("/proc/self/fd/{}", file.as_raw_fd());
        match mode {
            WriteMode::New => link_fd(&source, path),
            WriteMode::Replace => {
                let name = path.file_name().unwrap_or("file".as_ref());
                let mut sibling_name = std::ffi::OsString::from(".");
                sibling_name.push(name);
                sibling_name.push(format!(".{}.axo-tmp", uuid::Uuid::new_v4()));
                let sibling = dir.join(sibling_name);
                link_fd(&source, &sibling)?;
                let result = fs::rename(&sibling, path);
                if result.is_err() {
                    let _ = fs::remove_file(&sibling);
                }
                result
            },
        }
    }
}

/// Give the unnamed file at `/proc/self/fd/<fd>` the name `to`. Fails with
/// `AlreadyExists` if `to` exists. `AT_EMPTY_PATH` would need
/// `CAP_DAC_READ_SEARCH`.
fn link_fd(source: &str, to: &Path) -> io::Result<()> {
    let source = CString::new(source)?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    // SAFETY: both paths are NUL-terminated strings that outlive the call.
    let result = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

impl FolderIo for CoordinatedIo {
    fn status(&self, path: &Path) -> io::Result<FileStatus> {
        metadata_status(path)
    }

    fn read(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        read_limited(path, limit)
    }

    fn write(&self, path: &Path, data: &[u8], mode: WriteMode) -> io::Result<()> {
        Self::write_at(path, data, mode, &Self::cache_temp_dir(), None)
    }

    fn delete(&self, path: &Path) -> io::Result<()> {
        delete_path(path)
    }

    fn download(&self, _paths: Vec<PathBuf>) {}
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use tempfile::TempDir;

    use super::*;

    /// Synced folder and cache temp directory, both on the temp file system.
    struct Dirs {
        _root: TempDir,
        folder: PathBuf,
        cache: PathBuf,
    }

    fn dirs() -> Dirs {
        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join("folder");
        let cache = root.path().join("cache/tmp");
        fs::create_dir(&folder).unwrap();
        Dirs {
            _root: root,
            folder,
            cache,
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn write(
        dirs: &Dirs,
        name: &str,
        data: &[u8],
        mode: WriteMode,
        place: Option<TempPlace>,
    ) -> io::Result<()> {
        CoordinatedIo::write_at(&dirs.folder.join(name), data, mode, &dirs.cache, place)
    }

    const PLACES: [TempPlace; 2] = [TempPlace::CacheDir, TempPlace::Tmpfile];

    #[test]
    fn temp_place_is_cache_dir_only_on_same_device() {
        assert_eq!(TempPlace::choose(7, 7), TempPlace::CacheDir);
        assert_eq!(TempPlace::choose(7, 8), TempPlace::Tmpfile);
    }

    #[test]
    fn new_and_replace_write_the_target_on_both_paths_and_leave_nothing_else() {
        for place in PLACES {
            let dirs = dirs();
            fs::create_dir_all(&dirs.cache).unwrap();
            write(&dirs, "a.json", b"one", WriteMode::New, Some(place)).unwrap();
            assert_eq!(fs::read(dirs.folder.join("a.json")).unwrap(), b"one");
            write(&dirs, "a.json", b"two", WriteMode::Replace, Some(place)).unwrap();
            assert_eq!(fs::read(dirs.folder.join("a.json")).unwrap(), b"two");
            write(&dirs, "b.json", b"new", WriteMode::Replace, Some(place)).unwrap();

            assert_eq!(names(&dirs.folder), ["a.json", "b.json"], "{place:?}");
            assert!(names(&dirs.cache).is_empty(), "{place:?}");
            // `write_temp` creates with the default mode, `O_TMPFILE` with 0600.
            if place == TempPlace::Tmpfile {
                let mode = fs::metadata(dirs.folder.join("a.json")).unwrap().mode();
                assert_eq!(mode & 0o777, 0o600 & !current_umask());
            }
        }
    }

    fn current_umask() -> u32 {
        // SAFETY: `umask` only swaps the process mask. The value is restored.
        unsafe {
            let mask = libc::umask(0o077);
            libc::umask(mask);
            mask
        }
    }

    #[test]
    fn new_on_existing_target_fails_with_already_exists_on_both_paths_and_keeps_it() {
        for place in PLACES {
            let dirs = dirs();
            write(&dirs, "a.json", b"one", WriteMode::New, Some(place)).unwrap();
            let err = write(&dirs, "a.json", b"two", WriteMode::New, Some(place)).unwrap_err();

            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{place:?}: {err}");
            assert_eq!(fs::read(dirs.folder.join("a.json")).unwrap(), b"one");
            assert_eq!(names(&dirs.folder), ["a.json"], "{place:?}");
            assert!(names(&dirs.cache).is_empty(), "{place:?}");
        }
    }

    #[test]
    fn failed_write_leaves_no_temp_file_on_both_paths() {
        for place in PLACES {
            for mode in [WriteMode::New, WriteMode::Replace] {
                let dirs = dirs();
                fs::create_dir_all(&dirs.cache).unwrap();
                // The target is a directory, so a replace fails at the
                // rename, and a new file fails with EEXIST.
                fs::create_dir(dirs.folder.join("a.json")).unwrap();
                fs::write(dirs.folder.join("a.json/x"), b"x").unwrap();

                assert!(write(&dirs, "a.json", b"data", mode, Some(place)).is_err());

                assert_eq!(names(&dirs.folder), ["a.json"], "{place:?} {mode:?}");
                assert!(names(&dirs.cache).is_empty(), "{place:?} {mode:?}");
            }
        }
    }

    #[test]
    fn write_to_read_only_folder_fails_and_leaves_no_temp_file_on_both_paths() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        for place in PLACES {
            let dirs = dirs();
            fs::create_dir_all(&dirs.cache).unwrap();
            fs::set_permissions(&dirs.folder, fs::Permissions::from_mode(0o555)).unwrap();
            let result = write(&dirs, "a.json", b"data", WriteMode::Replace, Some(place));
            fs::set_permissions(&dirs.folder, fs::Permissions::from_mode(0o755)).unwrap();

            assert!(result.is_err(), "{place:?}");
            assert!(names(&dirs.folder).is_empty(), "{place:?}");
            assert!(names(&dirs.cache).is_empty(), "{place:?}");
        }
    }

    #[test]
    fn tmpfile_write_into_missing_folder_fails_not_found() {
        let dirs = dirs();
        let path = dirs.folder.join("missing/a.json");
        let err = CoordinatedIo::write_at(
            &path,
            b"data",
            WriteMode::New,
            &dirs.cache,
            Some(TempPlace::Tmpfile),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn unforced_write_creates_private_cache_dir_and_uses_it_on_same_device() {
        let dirs = dirs();
        assert!(!dirs.cache.exists());
        write(&dirs, "a.json", b"data", WriteMode::New, None).unwrap();

        let meta = fs::metadata(&dirs.cache).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert_eq!(meta.dev(), fs::metadata(&dirs.folder).unwrap().dev());
        assert_eq!(names(&dirs.folder), ["a.json"]);
        assert!(names(&dirs.cache).is_empty());
    }

    #[test]
    fn unusable_cache_dir_falls_back_to_tmpfile() {
        let dirs = dirs();
        // A file in the place of the cache directory.
        fs::create_dir_all(dirs.cache.parent().unwrap()).unwrap();
        fs::write(&dirs.cache, b"file").unwrap();
        write(&dirs, "a.json", b"data", WriteMode::New, None).unwrap();
        assert_eq!(fs::read(dirs.folder.join("a.json")).unwrap(), b"data");
        assert_eq!(names(&dirs.folder), ["a.json"]);
    }

    #[test]
    fn coordinated_io_trait_methods_read_status_write_delete() {
        let dirs = dirs();
        let io = CoordinatedIo;
        let path = dirs.folder.join("a.json");
        assert_eq!(io.status(&path).unwrap(), FileStatus::Missing);
        io.write(&path, b"data", WriteMode::New).unwrap();
        assert_eq!(io.status(&path).unwrap(), FileStatus::Local);
        assert_eq!(io.read(&path, 10).unwrap(), b"data");
        assert!(io.read(&path, 3).is_err());
        io.download(vec![path.clone()]);
        io.delete(&path).unwrap();
        io.delete(&path).unwrap();
        assert_eq!(io.status(&path).unwrap(), FileStatus::Missing);
    }
}
