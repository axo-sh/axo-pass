//! Polling watch of the S3 transport.
//!
//! S3 has no change feed that a client can use, so a watch lists the watched
//! objects at an interval and calls `notify` if the listing differs from the
//! last one. The first listing that succeeds always notifies, since a change
//! between the start of the watch and that listing cannot be told from none.
//! This is also the poll at unlock, since a watch starts at unlock. A listing
//! that fails is logged and retried at the next interval.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use super::client::ObjectInfo;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::sync::transport::WatchHandle;

/// Poll thread that stops when its handle drops.
pub struct PollWatch;

impl PollWatch {
    /// Start a thread that calls `snapshot` every `interval` and `notify` if
    /// the result changes, and after the first result. `None` if the thread
    /// does not start.
    ///
    /// Drop of the handle waits for a `notify` call in flight and does not
    /// wait for a listing. The handle must not drop inside `notify`.
    pub fn start(
        interval: Duration,
        snapshot: impl Fn() -> Result<Vec<ObjectInfo>, Error> + Send + 'static,
        notify: Box<dyn Fn() + Send>,
    ) -> Option<WatchHandle> {
        let stopped = Arc::new(Mutex::new(false));
        let (wake, sleep) = mpsc::channel::<()>();
        let thread_stopped = stopped.clone();
        thread::Builder::new()
            .name("s3-poll".to_string())
            .spawn(move || {
                let mut last: Option<Vec<ObjectInfo>> = None;
                loop {
                    match snapshot() {
                        Ok(current) => {
                            if last.as_ref() != Some(&current) {
                                let stopped = thread_stopped.lock().unwrap();
                                if *stopped {
                                    return;
                                }
                                notify();
                            }
                            last = Some(current);
                        },
                        Err(e) => log::warn!("S3 poll failed: {e}"),
                    }
                    if !matches!(sleep.recv_timeout(interval), Err(RecvTimeoutError::Timeout)) {
                        return;
                    }
                }
            })
            .ok()?;
        Some(WatchHandle::new(move || {
            *stopped.lock().unwrap() = true;
            let _ = wake.send(());
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::Receiver;

    use jiff::Timestamp;

    use super::*;

    const INTERVAL: Duration = Duration::from_millis(10);
    const WAIT: Duration = Duration::from_secs(5);

    fn object(key: &str) -> ObjectInfo {
        ObjectInfo {
            key: key.to_string(),
            size: 1,
            modified: Timestamp::UNIX_EPOCH,
            etag: String::new(),
        }
    }

    /// Watch of a shared listing, and the channel of its notifications.
    fn watch(listing: &Arc<Mutex<Result<Vec<ObjectInfo>, String>>>) -> (WatchHandle, Receiver<()>) {
        let (sender, receiver) = mpsc::channel();
        let listing = listing.clone();
        let handle = PollWatch::start(
            INTERVAL,
            move || {
                listing
                    .lock()
                    .unwrap()
                    .clone()
                    .map_err(Error::SyncTransportError)
            },
            Box::new(move || {
                let _ = sender.send(());
            }),
        )
        .unwrap();
        (handle, receiver)
    }

    #[test]
    fn notifies_for_first_listing_and_change_and_not_for_same_listing() {
        let listing = Arc::new(Mutex::new(Ok(vec![object("a")])));
        let (_handle, receiver) = watch(&listing);
        receiver.recv_timeout(WAIT).unwrap();
        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());

        *listing.lock().unwrap() = Ok(vec![object("a"), object("b")]);

        receiver.recv_timeout(WAIT).unwrap();
        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
    }

    #[test]
    fn first_notification_waits_for_listing_to_succeed() {
        let listing = Arc::new(Mutex::new(Err("down".to_string())));
        let (_handle, receiver) = watch(&listing);
        assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());

        *listing.lock().unwrap() = Ok(vec![object("a")]);

        receiver.recv_timeout(WAIT).unwrap();
    }

    #[test]
    fn no_notification_after_handle_drops() {
        let listing = Arc::new(Mutex::new(Ok(vec![])));
        let (handle, receiver) = watch(&listing);
        receiver.recv_timeout(WAIT).unwrap();

        drop(handle);
        *listing.lock().unwrap() = Ok(vec![object("a")]);

        assert!(receiver.recv_timeout(Duration::from_millis(200)).is_err());
    }
}
