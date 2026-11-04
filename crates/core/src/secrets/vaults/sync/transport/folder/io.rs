//! File access of the folder transport.
//!
//! [`CoordinatedIo`] reads, writes, and deletes through `NSFileCoordinator`,
//! so iCloud and File Provider folders see each change. [`PlainIo`] uses
//! `std::fs` only, for tests. Both write each file to a temp file outside the
//! synced folder, sync it, and move it into place, so the provider never
//! uploads a partial file.

use std::cell::{Cell, RefCell};
#[cfg(test)]
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::macos::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
#[cfg(test)]
use std::sync::Mutex;

use block2::{RcBlock, StackBlock};
use objc2::AllocAnyThread;
use objc2::rc::{Retained, autoreleasepool};
use objc2::runtime::AnyObject;
use objc2_foundation::{
    NSArray, NSError, NSFileAccessIntent, NSFileCoordinator, NSFileCoordinatorReadingOptions,
    NSFileCoordinatorWritingOptions, NSFileManager, NSOperationQueue, NSSearchPathDirectory,
    NSSearchPathDomainMask, NSString, NSURL, NSURLUbiquitousItemDownloadingStatusCurrent,
    NSURLUbiquitousItemDownloadingStatusKey,
};
#[cfg(test)]
use uuid::Uuid;

/// `st_flags` bit of a dataless file, whose contents are not local. The
/// value of `SF_DATALESS` in `sys/stat.h`.
const SF_DATALESS: u32 = 0x4000_0000;

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
    /// Start a download of each file of `paths`. Does not wait.
    fn download(&self, paths: Vec<PathBuf>);
}

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
    } else if meta.st_flags() & SF_DATALESS != 0 {
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

/// Rename `from` to `to` with `RENAME_EXCL`, which fails if `to` exists.
/// Known limit: on a volume without `RENAME_EXCL`, `to` is checked before
/// the rename, and a file that another writer creates between the two is
/// replaced.
fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let from_c = CString::new(from.as_os_str().as_bytes())?;
    let to_c = CString::new(to.as_os_str().as_bytes())?;
    // SAFETY: both paths are NUL-terminated strings that outlive the call.
    let result = unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() != Some(libc::ENOTSUP) {
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

/// File access through `NSFileCoordinator` and `NSFileManager`. A file whose
/// ubiquitous download status is not current is `Remote`, as is a dataless
/// file.
#[derive(Debug, Default)]
pub struct CoordinatedIo;

impl CoordinatedIo {
    fn url(path: &Path) -> Retained<NSURL> {
        NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()))
    }

    fn path(url: &NSURL) -> Option<PathBuf> {
        url.path().map(|path| PathBuf::from(path.to_string()))
    }

    fn error(error: &NSError) -> io::Error {
        io::Error::other(error.localizedDescription().to_string())
    }

    fn coordinator() -> Retained<NSFileCoordinator> {
        NSFileCoordinator::initWithFilePresenter(NSFileCoordinator::alloc(), None)
    }

    /// Whether the ubiquitous download status of the file at `path` is
    /// current. A file with no download status, outside iCloud and File
    /// Provider folders, is current.
    fn is_current(path: &Path) -> io::Result<bool> {
        autoreleasepool(|_| {
            let url = Self::url(path);
            let mut value: Option<Retained<AnyObject>> = None;
            // SAFETY: the key is a constant of Foundation, and its value is a
            // string.
            unsafe {
                url.getResourceValue_forKey_error(
                    &mut value,
                    NSURLUbiquitousItemDownloadingStatusKey,
                )
            }
            .map_err(|e| Self::error(&e))?;
            let Some(status) = value.and_then(|value| value.downcast::<NSString>().ok()) else {
                return Ok(true);
            };
            // SAFETY: the status is a constant of Foundation.
            Ok(status.isEqualToString(unsafe { NSURLUbiquitousItemDownloadingStatusCurrent }))
        })
    }

    /// Run `access` on the path that a coordinated read of `path` gives.
    fn coordinate_read<T>(
        path: &Path,
        access: impl FnOnce(&Path) -> io::Result<T>,
    ) -> io::Result<T> {
        autoreleasepool(|_| {
            let url = Self::url(path);
            let access = Cell::new(Some(access));
            let result = RefCell::new(None);
            let accessor = StackBlock::new(|granted: NonNull<NSURL>| {
                // SAFETY: the coordinator passes a valid URL for the call.
                let granted = Self::path(unsafe { granted.as_ref() });
                if let Some(access) = access.take() {
                    let target = granted.as_deref().unwrap_or(path);
                    *result.borrow_mut() = Some(access(target));
                }
            });
            let mut error = None;
            Self::coordinator().coordinateReadingItemAtURL_options_error_byAccessor(
                &url,
                NSFileCoordinatorReadingOptions(0),
                Some(&mut error),
                &accessor,
            );
            if let Some(error) = error {
                return Err(Self::error(&error));
            }
            result
                .into_inner()
                .unwrap_or_else(|| Err(io::Error::other("coordinated read did not run")))
        })
    }

    /// Run `access` on the path that a coordinated write of `path` with
    /// `options` gives.
    fn coordinate_write(
        path: &Path,
        options: NSFileCoordinatorWritingOptions,
        access: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        autoreleasepool(|_| {
            let url = Self::url(path);
            let access = Cell::new(Some(access));
            let result = RefCell::new(None);
            let accessor = StackBlock::new(|granted: NonNull<NSURL>| {
                // SAFETY: the coordinator passes a valid URL for the call.
                let granted = Self::path(unsafe { granted.as_ref() });
                if let Some(access) = access.take() {
                    let target = granted.as_deref().unwrap_or(path);
                    *result.borrow_mut() = Some(access(target));
                }
            });
            let mut error = None;
            Self::coordinator().coordinateWritingItemAtURL_options_error_byAccessor(
                &url,
                options,
                Some(&mut error),
                &accessor,
            );
            if let Some(error) = error {
                return Err(Self::error(&error));
            }
            result
                .into_inner()
                .unwrap_or_else(|| Err(io::Error::other("coordinated write did not run")))
        })
    }

    /// New temp directory on the volume of `path` and outside the synced
    /// folder, from `NSItemReplacementDirectory`.
    fn replacement_dir(path: &Path) -> io::Result<PathBuf> {
        let dir = path.parent().unwrap_or(path);
        autoreleasepool(|_| {
            let manager = NSFileManager::defaultManager();
            let url = manager
                .URLForDirectory_inDomain_appropriateForURL_create_error(
                    NSSearchPathDirectory::ItemReplacementDirectory,
                    NSSearchPathDomainMask::UserDomainMask,
                    Some(&Self::url(dir)),
                    true,
                )
                .map_err(|e| Self::error(&e))?;
            Self::path(&url).ok_or_else(|| io::Error::other("temp directory has no path"))
        })
    }
}

impl FolderIo for CoordinatedIo {
    fn status(&self, path: &Path) -> io::Result<FileStatus> {
        let status = metadata_status(path)?;
        if status != FileStatus::Local || Self::is_current(path)? {
            return Ok(status);
        }
        Ok(FileStatus::Remote)
    }

    fn read(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        Self::coordinate_read(path, |target| read_limited(target, limit))
    }

    fn write(&self, path: &Path, data: &[u8], mode: WriteMode) -> io::Result<()> {
        let temp_dir = Self::replacement_dir(path)?;
        let temp = temp_dir.join(path.file_name().unwrap_or("file".as_ref()));
        let result = write_temp(&temp, data).and_then(|()| {
            Self::coordinate_write(
                path,
                NSFileCoordinatorWritingOptions::ForReplacing,
                |target| move_into_place(&temp, target, mode),
            )
        });
        if let Err(e) = fs::remove_dir_all(&temp_dir) {
            log::debug!("Failed to delete {}: {e}", temp_dir.display());
        }
        result
    }

    fn delete(&self, path: &Path) -> io::Result<()> {
        Self::coordinate_write(
            path,
            NSFileCoordinatorWritingOptions::ForDeleting,
            delete_path,
        )
    }

    fn download(&self, paths: Vec<PathBuf>) {
        autoreleasepool(|_| {
            let intents: Vec<Retained<NSFileAccessIntent>> = paths
                .iter()
                .map(|path| {
                    NSFileAccessIntent::readingIntentWithURL_options(
                        &Self::url(path),
                        NSFileCoordinatorReadingOptions(0),
                    )
                })
                .collect();
            let intents = NSArray::from_retained_slice(&intents);
            let coordinator = Self::coordinator();
            let queue = NSOperationQueue::new();
            // The accessor holds the coordinator and the queue until it runs.
            let held = (coordinator.clone(), queue.clone());
            let count = paths.len();
            let accessor = RcBlock::new(move |error: *mut NSError| {
                let _ = &held;
                // SAFETY: the error is null or valid for the call.
                match unsafe { error.as_ref() } {
                    Some(error) => log::warn!(
                        "Failed to download {count} files: {}",
                        error.localizedDescription()
                    ),
                    None => log::debug!("Downloaded {count} files"),
                }
            });
            // SAFETY: the accessor is a heap block that holds what it uses.
            unsafe {
                coordinator
                    .coordinateAccessWithIntents_queue_byAccessor(&intents, &queue, &accessor);
            }
        });
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

    fn download(&self, paths: Vec<PathBuf>) {
        self.hooks().downloads.push(paths);
    }
}
