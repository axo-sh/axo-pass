//! File access of the folder transport.
//!
//! [`CoordinatedIo`] reads, writes, and deletes through `NSFileCoordinator`
//! on macOS, so iCloud and File Provider folders see each change. On Linux it
//! uses `std::fs`. [`PlainIo`] uses `std::fs` only, for tests. All of them
//! write each file to a temp file outside the synced folder, sync it, and move
//! it into place, so the provider never uploads a partial file.

#[cfg(apple)]
mod apple;
#[cfg(ios)]
mod ios;
#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

#[cfg(test)]
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex;

#[cfg(ios)]
use ios as platform;
#[cfg(linux)]
use linux as platform;
#[cfg(macos)]
use macos as platform;
pub use platform::CoordinatedIo;
#[cfg(test)]
use uuid::Uuid;

/// Local state of a file in the synced folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileStatus {
    /// No regular file at the path. A directory or a symlink is not a file.
    Missing,
    /// File exists and is not local.
    Remote,
    Local,
}

/// How a write treats a file that exists at its path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteMode {
    /// Fail the write.
    New,
    /// Replace the file.
    Replace,
}

/// File access of a folder transport.
pub trait FolderIo: fmt::Debug + Send + Sync {
    /// Status of the file at `path`. The file is not read.
    fn status(&self, path: &Path) -> io::Result<FileStatus>;
    /// Bytes of the local file at `path`. A file longer than `limit` bytes
    /// fails.
    fn read(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>>;
    /// Write `data` to a temp file outside the synced folder, sync it, and
    /// move it to `path`.
    fn write(&self, path: &Path, data: &[u8], mode: WriteMode) -> io::Result<()>;
    /// Delete the file or the directory at `path`, with its contents. A
    /// missing path is not an error. A symlink is deleted, not its target.
    fn delete(&self, path: &Path) -> io::Result<()>;
    /// Start a download of each file of `paths`. Does not wait. `done` runs
    /// once, on any thread, when the download ends, with whether it
    /// succeeded.
    fn download(&self, paths: Vec<PathBuf>, done: DownloadDone);
}

/// Callback of the end of a download, with whether it succeeded.
pub type DownloadDone = Box<dyn FnOnce(bool) + Send>;

/// Status of the file at `path` from its metadata. A dataless file is
/// `Remote`.
fn metadata_status(path: &Path) -> io::Result<FileStatus> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(status_of(&meta)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(FileStatus::Missing),
        Err(e) => Err(e),
    }
}

fn status_of(meta: &Metadata) -> FileStatus {
    if !meta.is_file() {
        FileStatus::Missing
    } else if platform::is_dataless(meta) {
        FileStatus::Remote
    } else {
        FileStatus::Local
    }
}

/// Bytes of the file at `path`, at most `limit`. A symlink is not followed.
fn read_limited(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file is larger than {limit} bytes"),
        ));
    }
    Ok(bytes)
}

/// Write `data` to the new file `temp` and sync it.
fn write_temp(temp: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = File::create_new(temp)?;
    file.write_all(data)?;
    file.sync_all()
}

/// Move `temp` to `path`.
fn move_into_place(temp: &Path, path: &Path, mode: WriteMode) -> io::Result<()> {
    match mode {
        WriteMode::Replace => fs::rename(temp, path),
        WriteMode::New => rename_exclusive(temp, path),
    }
}

/// Rename `from` to `to` with an atomic no-replace rename, which fails if `to`
/// exists. Known limit: on a volume without the flag, `to` is checked before
/// the rename, and a file that another writer creates between the two is
/// replaced.
fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let from_c = CString::new(from.as_os_str().as_bytes())?;
    let to_c = CString::new(to.as_os_str().as_bytes())?;
    if platform::rename_noreplace(&from_c, &to_c) == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if !e
        .raw_os_error()
        .is_some_and(|code| platform::RENAME_UNSUPPORTED.contains(&code))
    {
        return Err(e);
    }
    if fs::symlink_metadata(to).is_ok() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    fs::rename(from, to)
}

/// Delete the file, symlink, or directory at `path`. A missing path is not
/// an error.
fn delete_path(path: &Path) -> io::Result<()> {
    let result = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) => Err(e),
    };
    match result {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// File access through `std::fs`, for tests. Temp files are written in a
/// directory outside the synced folder on the same volume. A test marks
/// files as not local.
#[cfg(test)]
#[derive(Debug)]
pub struct PlainIo {
    temp: PathBuf,
    hooks: Mutex<PlainHooks>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct PlainHooks {
    /// Files marked as not local.
    remote: BTreeSet<PathBuf>,
    /// Count of reads of local files.
    reads: usize,
    /// Paths of the download calls, in call order.
    downloads: Vec<Vec<PathBuf>>,
    /// Callbacks of the downloads that did not end yet.
    done: DoneCallbacks,
}

#[cfg(test)]
#[derive(Default)]
struct DoneCallbacks(Vec<DownloadDone>);

#[cfg(test)]
impl fmt::Debug for DoneCallbacks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} callbacks", self.0.len())
    }
}

#[cfg(test)]
impl PlainIo {
    /// File access with temp files in `temp`.
    pub fn new(temp: impl Into<PathBuf>) -> Self {
        Self {
            temp: temp.into(),
            hooks: Mutex::default(),
        }
    }

    fn hooks(&self) -> std::sync::MutexGuard<'_, PlainHooks> {
        self.hooks.lock().unwrap()
    }

    /// Mark the file at `path` as not local, or as local again.
    pub fn set_remote(&self, path: &Path, remote: bool) {
        let mut hooks = self.hooks();
        if remote {
            hooks.remote.insert(path.to_path_buf());
        } else {
            hooks.remote.remove(path);
        }
    }

    /// Count of reads of local files.
    pub fn reads(&self) -> usize {
        self.hooks().reads
    }

    /// Paths of the download calls, in call order.
    pub fn downloads(&self) -> Vec<Vec<PathBuf>> {
        self.hooks().downloads.clone()
    }

    /// End each download that did not end, as a provider does. Returns the
    /// count.
    pub fn finish_downloads(&self) -> usize {
        self.end_downloads(true)
    }

    /// Fail each download that did not end, as a provider that cannot reach
    /// the files. Returns the count.
    pub fn fail_downloads(&self) -> usize {
        self.end_downloads(false)
    }

    fn end_downloads(&self, succeeded: bool) -> usize {
        let done = std::mem::take(&mut self.hooks().done).0;
        let count = done.len();
        for done in done {
            done(succeeded);
        }
        count
    }
}

#[cfg(test)]
impl FolderIo for PlainIo {
    fn status(&self, path: &Path) -> io::Result<FileStatus> {
        let status = metadata_status(path)?;
        if status == FileStatus::Local && self.hooks().remote.contains(path) {
            return Ok(FileStatus::Remote);
        }
        Ok(status)
    }

    fn read(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        let bytes = read_limited(path, limit)?;
        self.hooks().reads += 1;
        Ok(bytes)
    }

    fn write(&self, path: &Path, data: &[u8], mode: WriteMode) -> io::Result<()> {
        let temp = self.temp.join(format!("{}.tmp", Uuid::new_v4()));
        let result = write_temp(&temp, data).and_then(|()| move_into_place(&temp, path, mode));
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn delete(&self, path: &Path) -> io::Result<()> {
        delete_path(path)
    }

    fn download(&self, paths: Vec<PathBuf>, done: DownloadDone) {
        let mut hooks = self.hooks();
        hooks.downloads.push(paths);
        hooks.done.0.push(done);
    }
}
