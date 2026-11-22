//! Metadata query watch of the folder transport on macOS.
//!
//! A [`MetadataWatch`] runs an `NSMetadataQuery` over the root, limited by
//! predicate to paths under one directory of it. The query reports a change
//! of a file, including the download status of an iCloud file, so it reports
//! a download that no file event reports.
//!
//! The query needs a run loop. The watch runs it on its own thread. Drop stops
//! the run loop and waits for the thread.
//!
//! The query is served by the Spotlight index. A folder that Spotlight does
//! not index gives no update, so the query adds to the file events and the
//! rescan of the manager and does not replace them.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use block2::RcBlock;
use objc2::Message;
use objc2::rc::{Retained, autoreleasepool};
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2_core_foundation::{CFRetained, CFRunLoop, kCFRunLoopDefaultMode};
use objc2_foundation::{
    NSArray, NSMetadataItemPathKey, NSMetadataQuery, NSMetadataQueryDidFinishGatheringNotification,
    NSMetadataQueryDidUpdateNotification, NSNotification, NSNotificationCenter, NSPredicate,
    NSString, NSTimer, NSURL,
};
use uuid::Uuid;

use crate::secrets::vaults::sync::sync_log::{self, Level};
use crate::secrets::vaults::sync::transport::WatchHandle;

/// Time in seconds that the query gathers updates before it posts them.
const BATCH_INTERVAL: f64 = 1.0;

/// Time in seconds of the timer that keeps the run loop alive. The run loop
/// returns from it at most this long after a stop that came early.
const KEEP_ALIVE: f64 = 5.0;

/// Run loop of the thread of a watch, to stop from another thread.
struct RunLoop(CFRetained<CFRunLoop>);

// SAFETY: `CFRunLoopStop` may be called from any thread.
unsafe impl Send for RunLoop {}

/// Metadata query on a thread with a run loop. Drop stops the query, ends the
/// thread, and waits for a call in flight, so no call of `notify` follows the
/// drop.
pub struct MetadataWatch {
    stop: Arc<AtomicBool>,
    run_loop: Option<RunLoop>,
    thread: Option<JoinHandle<()>>,
}

impl MetadataWatch {
    /// Query of `root` that calls `notify` when the gather ends and for each
    /// batch of updates of a path under `{root}/{dir}`. `vault_id` is the
    /// vault of the sync log entries. `None` if the root is missing or is not
    /// a folder, or the thread fails to start.
    ///
    /// The handle must not drop inside `notify`, since drop waits for the
    /// thread that makes the call.
    pub fn start(
        root: &Path,
        dir: &Path,
        vault_id: Option<Uuid>,
        notify: Box<dyn Fn() + Send>,
    ) -> Option<WatchHandle> {
        let root = fs::canonicalize(root).ok()?;
        if !root.is_dir() {
            return None;
        }
        let dir = root.join(dir);
        let stop = Arc::new(AtomicBool::new(false));
        let (ready, started) = mpsc::channel();
        let thread = {
            let stop = stop.clone();
            thread::Builder::new()
                .name("folder-metadata-query".into())
                .spawn(move || Self::run(&root, &dir, vault_id, notify, &stop, &ready))
        };
        let thread = match thread {
            Ok(thread) => thread,
            Err(e) => {
                sync_log::record(
                    Level::Warn,
                    vault_id,
                    "Failed to start the metadata query thread",
                    Some(e.to_string()),
                );
                return None;
            },
        };
        // The thread sends its run loop once the query started, or `None` if
        // it did not.
        let run_loop = started.recv().ok().flatten();
        let watch = Self {
            stop,
            run_loop,
            thread: Some(thread),
        };
        Some(WatchHandle::new(move || drop(watch)))
    }

    /// Thread body. Starts the query, sends the run loop to `ready`, and runs
    /// the run loop until `stop`.
    fn run(
        root: &Path,
        dir: &Path,
        vault_id: Option<Uuid>,
        notify: Box<dyn Fn() + Send>,
        stop: &AtomicBool,
        ready: &Sender<Option<RunLoop>>,
    ) {
        autoreleasepool(|_| {
            let Some(run_loop) = CFRunLoop::current() else {
                let _ = ready.send(None);
                return;
            };
            let query = NSMetadataQuery::new();
            let root_url = NSURL::fileURLWithPath(&NSString::from_str(&root.to_string_lossy()));
            let scopes: Retained<NSArray<AnyObject>> =
                NSArray::from_retained_slice(&[Retained::into_super(Retained::into_super(
                    root_url,
                ))]);
            // SAFETY: the scopes are URLs, which the query accepts.
            unsafe { query.setSearchScopes(&scopes) };
            // SAFETY: the key is a constant of Foundation.
            let key = unsafe { NSMetadataItemPathKey };
            let format = NSString::from_str("%K BEGINSWITH %@");
            let path = NSString::from_str(&dir.to_string_lossy());
            let args: Retained<NSArray<AnyObject>> = NSArray::from_retained_slice(&[
                Retained::into_super(Retained::into_super(key.retain())),
                Retained::into_super(Retained::into_super(path)),
            ]);
            // SAFETY: the format takes a key and a string, as the arguments
            // are.
            let predicate =
                unsafe { NSPredicate::predicateWithFormat_argumentArray(&format, Some(&args)) };
            query.setPredicate(Some(&predicate));
            query.setNotificationBatchingInterval(BATCH_INTERVAL);

            let notify = Arc::new(notify);
            let center = NSNotificationCenter::defaultCenter();
            let observe = |name: &NSString, message: &'static str| {
                let notify = notify.clone();
                let block = RcBlock::new(move |_: std::ptr::NonNull<NSNotification>| {
                    sync_log::record(Level::Info, vault_id, message, None);
                    notify();
                });
                // SAFETY: the block holds what it uses. The observer is
                // removed before the thread ends.
                unsafe {
                    center.addObserverForName_object_queue_usingBlock(
                        Some(name),
                        Some(&query),
                        None,
                        &block,
                    )
                }
            };
            // SAFETY: the names are constants of Foundation.
            let observers = unsafe {
                [
                    observe(
                        NSMetadataQueryDidFinishGatheringNotification,
                        "Metadata query finished gathering",
                    ),
                    observe(
                        NSMetadataQueryDidUpdateNotification,
                        "Metadata query reported an update",
                    ),
                ]
            };

            // The timer keeps the run loop from returning at once for lack of
            // a source.
            let keep_alive = RcBlock::new(|_: std::ptr::NonNull<NSTimer>| {});
            // SAFETY: the block holds nothing.
            let _timer = unsafe {
                NSTimer::scheduledTimerWithTimeInterval_repeats_block(KEEP_ALIVE, true, &keep_alive)
            };

            if !query.startQuery() {
                sync_log::record(
                    Level::Warn,
                    vault_id,
                    "Failed to start the metadata query",
                    None,
                );
                let _ = ready.send(None);
            } else {
                sync_log::record(Level::Info, vault_id, "Metadata query started", None);
                let _ = ready.send(Some(RunLoop(run_loop.clone())));
                while !stop.load(Ordering::SeqCst) {
                    // SAFETY: the mode is a constant of Core Foundation.
                    let result =
                        unsafe { CFRunLoop::run_in_mode(kCFRunLoopDefaultMode, 60.0, false) };
                    log::trace!("Metadata query run loop returned {result:?}");
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    // A run loop with nothing to run returns at once.
                    thread::sleep(Duration::from_millis(250));
                }
                query.stopQuery();
            }
            for observer in observers {
                // SAFETY: each observer came from `observe`.
                unsafe { center.removeObserver(ProtocolObject::as_ref(&observer)) };
            }
        });
    }
}

impl Drop for MetadataWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(run_loop) = &self.run_loop {
            run_loop.0.stop();
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            log::error!("The metadata query thread panicked");
        }
    }
}
