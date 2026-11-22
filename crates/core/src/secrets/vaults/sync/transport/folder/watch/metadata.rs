//! Metadata query watch of the folder transport on macOS.
//!
//! A [`MetadataWatch`] runs an `NSMetadataQuery` over the root. The query
//! reports a change of a file, including the download status of an iCloud
//! file, so it reports a download that no file event reports. Each update
//! calls `notify` with the paths of the added, changed, and removed items.
//!
//! The query needs a run loop. The watch runs it on its own thread. Drop stops
//! the run loop and waits for the thread.
//!
//! The query is served by the Spotlight index. A folder that Spotlight does
//! not index gives no update, so the query adds to the file events and the
//! rescan of the manager and does not replace them.

use std::path::{Path, PathBuf};
use std::ptr::NonNull;
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
    NSArray, NSMetadataItem, NSMetadataItemPathKey, NSMetadataQuery,
    NSMetadataQueryDidFinishGatheringNotification, NSMetadataQueryDidUpdateNotification,
    NSMetadataQueryUpdateAddedItemsKey, NSMetadataQueryUpdateChangedItemsKey,
    NSMetadataQueryUpdateRemovedItemsKey, NSNotification, NSNotificationCenter, NSPredicate,
    NSString, NSTimer, NSURL,
};

use super::Changes;
use crate::secrets::vaults::sync::sync_log::{self, Level};

/// Time in seconds that the query gathers updates before it posts them.
const BATCH_INTERVAL: f64 = 1.0;

/// Time in seconds of the timer that keeps the run loop alive, and timeout of
/// each run of the run loop. A stop sent before a run starts is lost, so the
/// thread ends at most this long after the stop.
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
    /// Query of the real root `root` that calls `notify` for each batch of
    /// updates under it. The end of the first gather is only logged, since
    /// each watch scans when it starts. `None` if the thread fails to start.
    ///
    /// The watch must not drop inside `notify`, since drop waits for the
    /// thread that makes the call.
    pub fn start(root: &Path, notify: Box<dyn Fn(Changes) + Send>) -> Option<Self> {
        let root = root.to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let (ready, started) = mpsc::channel();
        let thread = {
            let stop = stop.clone();
            thread::Builder::new()
                .name("folder-metadata-query".into())
                .spawn(move || Self::run(&root, notify, &stop, &ready))
        };
        let thread = match thread {
            Ok(thread) => thread,
            Err(e) => {
                sync_log::record(
                    Level::Warn,
                    None,
                    "Failed to start the metadata query thread",
                    Some(e.to_string()),
                );
                return None;
            },
        };
        // The thread sends its run loop once the query started, or `None` if
        // it did not.
        let run_loop = started.recv().ok().flatten();
        Some(Self {
            stop,
            run_loop,
            thread: Some(thread),
        })
    }

    /// Paths of the items of an update notification. `Unknown` if the
    /// notification holds no item or an item has no path.
    fn changes(notification: &NSNotification) -> Changes {
        let Some(info) = notification.userInfo() else {
            return Changes::Unknown;
        };
        // SAFETY: the keys are constants of Foundation.
        let keys = unsafe {
            [
                NSMetadataQueryUpdateAddedItemsKey,
                NSMetadataQueryUpdateChangedItemsKey,
                NSMetadataQueryUpdateRemovedItemsKey,
            ]
        };
        // SAFETY: the key is a constant of Foundation.
        let path_key = unsafe { NSMetadataItemPathKey };
        let mut paths = Vec::new();
        for key in keys {
            let Some(items) = info.objectForKey(key) else {
                continue;
            };
            let Ok(items) = items.downcast::<NSArray>() else {
                return Changes::Unknown;
            };
            for item in items.iter() {
                let Ok(item) = item.downcast::<NSMetadataItem>() else {
                    return Changes::Unknown;
                };
                let path = item
                    .valueForAttribute(path_key)
                    .and_then(|path| path.downcast::<NSString>().ok());
                let Some(path) = path else {
                    return Changes::Unknown;
                };
                paths.push(PathBuf::from(path.to_string()));
            }
        }
        if paths.is_empty() {
            return Changes::Unknown;
        }
        Changes::Paths(paths)
    }

    /// Thread body. Starts the query, sends the run loop to `ready`, and runs
    /// the run loop until `stop`.
    fn run(
        root: &Path,
        notify: Box<dyn Fn(Changes) + Send>,
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
            // A query needs a predicate. This one matches every item under
            // the root.
            // SAFETY: the key is a constant of Foundation.
            let key = unsafe { NSMetadataItemPathKey };
            let format = NSString::from_str("%K BEGINSWITH %@");
            let path = NSString::from_str(&root.to_string_lossy());
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

            let center = NSNotificationCenter::defaultCenter();
            let gathered = RcBlock::new(|_: NonNull<NSNotification>| {
                sync_log::record(Level::Info, None, "Metadata query finished gathering", None);
            });
            let updated = RcBlock::new(move |notification: NonNull<NSNotification>| {
                // SAFETY: the notification is valid for the call.
                let changes = Self::changes(unsafe { notification.as_ref() });
                notify(changes);
            });
            // SAFETY: the names are constants of Foundation. Each block holds
            // what it uses. The observers are removed before the thread ends.
            let observers = unsafe {
                [
                    center.addObserverForName_object_queue_usingBlock(
                        Some(NSMetadataQueryDidFinishGatheringNotification),
                        Some(&query),
                        None,
                        &gathered,
                    ),
                    center.addObserverForName_object_queue_usingBlock(
                        Some(NSMetadataQueryDidUpdateNotification),
                        Some(&query),
                        None,
                        &updated,
                    ),
                ]
            };

            // The timer keeps the run loop from returning immediately for
            // lack of a source.
            let keep_alive = RcBlock::new(|_: NonNull<NSTimer>| {});
            // SAFETY: the block holds nothing.
            let _timer = unsafe {
                NSTimer::scheduledTimerWithTimeInterval_repeats_block(KEEP_ALIVE, true, &keep_alive)
            };

            if !query.startQuery() {
                sync_log::record(
                    Level::Warn,
                    None,
                    "Failed to start the metadata query",
                    None,
                );
                let _ = ready.send(None);
            } else {
                sync_log::record(Level::Info, None, "Metadata query started", None);
                let _ = ready.send(Some(RunLoop(run_loop.clone())));
                while !stop.load(Ordering::SeqCst) {
                    // SAFETY: the mode is a constant of Core Foundation.
                    let result =
                        unsafe { CFRunLoop::run_in_mode(kCFRunLoopDefaultMode, KEEP_ALIVE, false) };
                    log::trace!("Metadata query run loop returned {result:?}");
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    // A run loop with nothing to run returns immediately.
                    thread::sleep(Duration::from_millis(250));
                }
                query.stopQuery();
            }
            for observer in observers {
                // SAFETY: each observer came from the center.
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
