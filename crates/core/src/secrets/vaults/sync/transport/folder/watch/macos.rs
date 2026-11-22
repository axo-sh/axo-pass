//! FSEvents watch of the folder transport.
//!
//! A [`FolderWatch`] streams the file events of the root and calls `notify`
//! for events under one directory of it. The root is watched, not the
//! directory, so a directory created later is covered. FSEvents reports
//! writes of every process, including writes that use no coordination, such
//! as Syncthing writes.
//!
//! FSEvents reports real paths, so the root is resolved before the stream
//! starts. A root reached through a symlink, or a temp directory under
//! `/var`, which is a symlink to `/private/var`, matches its events.

use std::ffi::{CStr, OsStr, c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::{fs, slice};

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

use crate::secrets::vaults::sync::sync_log::{self, Level};
use crate::secrets::vaults::sync::transport::WatchHandle;

/// Time in seconds that FSEvents gathers events before it delivers them.
const LATENCY: f64 = 1.0;

/// Directory and callback of one stream. Only the serial queue of the stream
/// reads it, so calls of `notify` never overlap.
struct WatchContext {
    /// Real path of the watched directory.
    dir: PathBuf,
    notify: Box<dyn Fn() + Send>,
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
    /// Watch of `root` that calls `notify` for each batch of events under
    /// `{root}/{dir}`, or under an ancestor of it, such as a change of the
    /// root itself or a batch that FSEvents could not report by path. `None`
    /// if the root is missing or is not a folder, or the stream fails to
    /// start.
    ///
    /// The handle must not drop inside `notify`, since drop waits for the
    /// callback.
    pub fn start(root: &Path, dir: &Path, notify: Box<dyn Fn() + Send>) -> Option<WatchHandle> {
        let root = fs::canonicalize(root).ok()?;
        if !root.is_dir() {
            return None;
        }
        let context = Box::new(WatchContext {
            dir: root.join(dir),
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
        Some(WatchHandle::new(move || drop(watch)))
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

    /// Whether an event at `path` reports a change under `dir`: the path is
    /// `dir`, a path under it, or an ancestor of it.
    pub fn matches(dir: &Path, path: &Path) -> bool {
        path.starts_with(dir) || dir.starts_with(path)
    }

    /// Stream callback. Calls `notify` once if any event path matches.
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
        let lost = flags.iter().any(|&flags| Self::lost_events(flags));
        if lost {
            sync_log::record(
                Level::Warn,
                None,
                "File events were dropped or the root changed, scanning again",
                Some(context.dir.display().to_string()),
            );
        }
        let matched = lost
            || paths.iter().any(|&path| {
                // SAFETY: each path is a NUL-terminated string that FSEvents
                // holds for the call.
                let path = unsafe { CStr::from_ptr(path) };
                let path = Path::new(OsStr::from_bytes(path.to_bytes()));
                Self::matches(&context.dir, path)
            });
        if matched && catch_unwind(AssertUnwindSafe(|| (context.notify)())).is_err() {
            log::error!("Watch callback of {} panicked", context.dir.display());
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
