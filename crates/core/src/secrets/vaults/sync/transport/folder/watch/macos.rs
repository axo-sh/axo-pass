//! FSEvents watch of the folder transport.
//!
//! A [`FolderWatch`] streams the file events of the root and calls `notify`
//! with the changed paths of each batch. The whole root is watched, so a
//! directory created later is covered. FSEvents reports writes of every
//! process, including writes that use no coordination, such as Syncthing
//! writes.
//!
//! FSEvents reports real paths, so the caller passes the real path of the
//! root. A root reached through a symlink, or a temp directory under `/var`,
//! which is a symlink to `/private/var`, then matches its events.

use std::ffi::{CStr, OsStr, c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::slice;

use dispatch2::{DispatchQueue, DispatchRetained};
use objc2_core_foundation::{CFArray, CFString};
use objc2_core_services::{
    ConstFSEventStreamRef, FSEventStreamContext, FSEventStreamCreate, FSEventStreamEventFlags,
    FSEventStreamEventId, FSEventStreamInvalidate, FSEventStreamRef, FSEventStreamRelease,
    FSEventStreamSetDispatchQueue, FSEventStreamStart, FSEventStreamStop,
    kFSEventStreamCreateFlagFileEvents, kFSEventStreamCreateFlagWatchRoot,
    kFSEventStreamEventFlagKernelDropped, kFSEventStreamEventFlagMustScanSubDirs,
    kFSEventStreamEventFlagRootChanged, kFSEventStreamEventFlagUserDropped,
    kFSEventStreamEventIdSinceNow,
};

use super::Changes;
use crate::secrets::vaults::sync::sync_log::{self, Level};

/// Time in seconds that FSEvents gathers events before it delivers them.
const LATENCY: f64 = 1.0;

/// Root and callback of one stream. Only the serial queue of the stream
/// reads it, so calls of `notify` never overlap.
struct WatchContext {
    /// Real path of the root.
    root: PathBuf,
    notify: Box<dyn Fn(Changes) + Send>,
}

/// FSEvents stream on a root, scheduled on its own serial dispatch queue.
/// Drop stops the stream, waits for a callback in flight, and frees the
/// callback, so no call of `notify` follows the drop.
pub struct FolderWatch {
    stream: FSEventStreamRef,
    queue: DispatchRetained<DispatchQueue>,
    context: NonNull<WatchContext>,
}

// SAFETY: FSEvents functions of a stream scheduled on a dispatch queue may be
// called from any thread. The context is read only on the queue, and drop
// frees it after the queue has finished every callback.
unsafe impl Send for FolderWatch {}

impl FolderWatch {
    /// Watch of the real root `root` that calls `notify` with the paths of
    /// each batch of events, or with [`Changes::Unknown`] if FSEvents could
    /// not report them by path. `None` if the stream fails to start.
    ///
    /// The watch must not drop inside `notify`, since drop waits for the
    /// callback.
    pub fn start(root: &Path, notify: Box<dyn Fn(Changes) + Send>) -> Option<Self> {
        let context = Box::new(WatchContext {
            root: root.to_path_buf(),
            notify,
        });
        let context = NonNull::from(Box::leak(context));
        let mut stream_context = FSEventStreamContext {
            version: 0,
            info: context.as_ptr().cast(),
            retain: None,
            release: None,
            copyDescription: None,
        };
        let path = CFString::from_str(&root.to_string_lossy());
        let paths = CFArray::from_objects(&[&*path]);
        // SAFETY: the callback matches `FSEventStreamCallback`, the stream
        // context is copied by the call, and its info pointer is valid
        // until drop. The array holds strings, as the call requires.
        let stream = unsafe {
            FSEventStreamCreate(
                None,
                Some(Self::callback),
                &mut stream_context,
                paths.as_opaque(),
                kFSEventStreamEventIdSinceNow,
                LATENCY,
                kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot,
            )
        };
        if stream.is_null() {
            // SAFETY: no stream holds the context.
            drop(unsafe { Box::from_raw(context.as_ptr()) });
            return None;
        }
        let queue = DispatchQueue::new("com.breakfastlabs.frittata.folder-watch", None);
        // SAFETY: the stream is valid and not yet started.
        unsafe { FSEventStreamSetDispatchQueue(stream, Some(&queue)) };
        let watch = Self {
            stream,
            queue,
            context,
        };
        // SAFETY: the stream is valid and scheduled on a queue.
        if !unsafe { FSEventStreamStart(watch.stream) } {
            log::warn!("Failed to start the FSEvents stream of {}", root.display());
            return None;
        }
        Some(watch)
    }

    /// Whether the flags of an event report that events were lost or that the
    /// root moved. FSEvents then does not report the changed paths, so every
    /// watch of the stream must scan.
    pub fn lost_events(flags: FSEventStreamEventFlags) -> bool {
        const LOST: FSEventStreamEventFlags = kFSEventStreamEventFlagMustScanSubDirs
            | kFSEventStreamEventFlagUserDropped
            | kFSEventStreamEventFlagKernelDropped
            | kFSEventStreamEventFlagRootChanged;
        flags & LOST != 0
    }

    /// Stream callback. Calls `notify` once with the paths of the batch.
    unsafe extern "C-unwind" fn callback(
        _stream: ConstFSEventStreamRef,
        info: *mut c_void,
        count: usize,
        paths: NonNull<c_void>,
        flags: NonNull<FSEventStreamEventFlags>,
        _ids: NonNull<FSEventStreamEventId>,
    ) {
        // SAFETY: `info` is the context of `start`, valid until drop, which
        // waits for this callback. Without `kFSEventStreamCreateFlagUseCFTypes`,
        // `paths` is an array of `count` C strings, and `flags` is an array of
        // `count` flag sets.
        let (context, paths, flags) = unsafe {
            (
                &*info.cast::<WatchContext>(),
                slice::from_raw_parts(paths.as_ptr().cast::<*const c_char>(), count),
                slice::from_raw_parts(flags.as_ptr(), count),
            )
        };
        let changes = if flags.iter().any(|&flags| Self::lost_events(flags)) {
            sync_log::record(
                Level::Warn,
                None,
                "File events were dropped or the root changed, scanning again",
                Some(context.root.display().to_string()),
            );
            Changes::Unknown
        } else {
            let paths = paths
                .iter()
                .map(|&path| {
                    // SAFETY: each path is a NUL-terminated string that
                    // FSEvents holds for the call.
                    let path = unsafe { CStr::from_ptr(path) };
                    Path::new(OsStr::from_bytes(path.to_bytes())).to_path_buf()
                })
                .collect();
            Changes::Paths(paths)
        };
        if catch_unwind(AssertUnwindSafe(|| (context.notify)(changes))).is_err() {
            log::error!("Watch callback of {} panicked", context.root.display());
        }
    }
}

impl Drop for FolderWatch {
    fn drop(&mut self) {
        // SAFETY: the stream is valid. Stop and invalidate unschedule it, so
        // the queue gets no further callback. The empty block runs after any
        // callback already on the serial queue, so none is in flight when
        // the stream is released and the context freed.
        unsafe {
            FSEventStreamStop(self.stream);
            FSEventStreamInvalidate(self.stream);
            self.queue.exec_sync(|| {});
            FSEventStreamRelease(self.stream);
            drop(Box::from_raw(self.context.as_ptr()));
        }
    }
}
