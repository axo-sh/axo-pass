//! `NSFileCoordinator` file access for macOS.

use std::cell::{Cell, RefCell};
use std::ffi::CStr;
use std::fs::{self, Metadata};
use std::io;
use std::os::macos::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

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

use super::{
    FileStatus, FolderIo, WriteMode, delete_path, metadata_status, move_into_place, read_limited,
    write_temp,
};

/// `st_flags` bit of a dataless file, whose contents are not local. The
/// value of `SF_DATALESS` in `sys/stat.h`.
const SF_DATALESS: u32 = 0x4000_0000;

/// Error codes of `renamex_np` for a volume without `RENAME_EXCL`.
pub(super) const RENAME_UNSUPPORTED: &[i32] = &[libc::ENOTSUP];

/// Whether the contents of the file are not local.
pub(super) fn is_dataless(meta: &Metadata) -> bool {
    meta.st_flags() & SF_DATALESS != 0
}

/// Rename `from` to `to` with `RENAME_EXCL`. Returns the C result.
pub(super) fn rename_noreplace(from: &CStr, to: &CStr) -> i32 {
    // SAFETY: both paths are NUL-terminated strings that outlive the call.
    unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) }
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
