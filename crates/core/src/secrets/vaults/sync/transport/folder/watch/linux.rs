//! inotify watch of the folder transport.
//!
//! A [`FolderWatch`] watches the root recursively through the `notify` crate
//! and calls `notify` with the changed paths of each batch. The whole root is
//! watched, so a directory created later is covered. inotify reports writes
//! of every process, including writes that use no coordination, such as
//! Syncthing writes.
//!
//! inotify reports paths below the path it was given, so the caller passes
//! the real path of the root. A root reached through a symlink then matches
//! its events.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use notify::event::{AccessKind, AccessMode};
use notify::{Event, EventKind, RecursiveMode, Watcher};

use super::Changes;

/// Time that events are gathered before `notify` is called, as the latency
/// of the FSEvents stream on macOS.
const LATENCY: Duration = Duration::from_secs(1);

/// Message to the thread of a watch.
enum Message {
    Event(notify::Result<Event>),
    Stop,
}

/// Recursive inotify watch of a root, with a thread that batches events and
/// calls `notify`. Drop stops the watcher, ends the thread, and waits for a
/// call in flight, so no call of `notify` follows the drop.
pub struct FolderWatch {
    /// Dropped last, which ends the inotify watch.
    watcher: Option<notify::RecommendedWatcher>,
    stop: Sender<Message>,
    thread: Option<JoinHandle<()>>,
}

impl FolderWatch {
    /// Watch of the real root `root` that calls `notify` with the paths of
    /// each batch of events, or with [`Changes::Unknown`] if inotify could
    /// not report them by path, such as after an overflow of its queue.
    /// `None` if the watch fails to start.
    ///
    /// At most one call is made per second. Calls never overlap.
    ///
    /// The watch must not drop inside `notify`, since drop waits for the
    /// thread that makes the call.
    pub fn start(root: &Path, notify: Box<dyn Fn(Changes) + Send>) -> Option<Self> {
        let (sender, receiver) = mpsc::channel();
        let events = sender.clone();
        let mut watcher = match notify::recommended_watcher(move |event| {
            // The thread has ended if the send fails.
            let _ = events.send(Message::Event(event));
        }) {
            Ok(watcher) => watcher,
            Err(e) => {
                log::warn!(
                    "Failed to create the inotify watch of {}: {e}",
                    root.display()
                );
                return None;
            },
        };
        if let Err(e) = watcher.watch(root, RecursiveMode::Recursive) {
            log::warn!("Failed to watch {}: {e}", root.display());
            return None;
        }
        let name = root.to_path_buf();
        let thread = thread::Builder::new()
            .name("folder-watch".into())
            .spawn(move || Self::run(&name, &receiver, &notify));
        let thread = match thread {
            Ok(thread) => thread,
            Err(e) => {
                log::warn!(
                    "Failed to start the thread of the watch of {}: {e}",
                    root.display()
                );
                return None;
            },
        };
        Some(Self {
            watcher: Some(watcher),
            stop: sender,
            thread: Some(thread),
        })
    }

    /// Changes that `event` reports. `None` for a read, which is not a
    /// change. An error and an event with no path report changes that are
    /// not known by path, such as an overflow of the inotify queue.
    fn changes(event: &notify::Result<Event>) -> Option<Changes> {
        let Ok(event) = event else {
            return Some(Changes::Unknown);
        };
        // Our own reads open and close files, and would call `notify` again.
        let reads = match event.kind {
            EventKind::Access(AccessKind::Close(AccessMode::Write)) => false,
            EventKind::Access(_) => true,
            _ => false,
        };
        if reads {
            return None;
        }
        if event.need_rescan() || event.paths.is_empty() {
            return Some(Changes::Unknown);
        }
        Some(Changes::Paths(event.paths.clone()))
    }

    /// Add the changes of `event` to `batch`. Unknown changes absorb any
    /// paths.
    fn gather(batch: &mut Option<Changes>, event: &notify::Result<Event>) {
        let Some(changes) = Self::changes(event) else {
            return;
        };
        if let Err(e) = event {
            log::warn!("Folder watch reported an error: {e}");
        }
        *batch = match (batch.take(), changes) {
            (Some(Changes::Paths(mut paths)), Changes::Paths(more)) => {
                paths.extend(more);
                Some(Changes::Paths(paths))
            },
            (None, changes) => Some(changes),
            _ => Some(Changes::Unknown),
        };
    }

    /// Body of the thread. Waits for an event that reports a change, gathers
    /// events for [`LATENCY`], and calls `notify` once. Ends on `Stop`, or
    /// when the channel closes.
    fn run(root: &Path, receiver: &Receiver<Message>, notify: &dyn Fn(Changes)) {
        loop {
            let mut batch = None;
            while batch.is_none() {
                match receiver.recv() {
                    Ok(Message::Event(event)) => Self::gather(&mut batch, &event),
                    Ok(Message::Stop) | Err(_) => return,
                }
            }
            let deadline = Instant::now() + LATENCY;
            loop {
                let wait = deadline.saturating_duration_since(Instant::now());
                match receiver.recv_timeout(wait) {
                    Ok(Message::Event(event)) => Self::gather(&mut batch, &event),
                    Ok(Message::Stop) | Err(RecvTimeoutError::Disconnected) => return,
                    Err(RecvTimeoutError::Timeout) => break,
                }
            }
            let Some(changes) = batch else {
                continue;
            };
            if catch_unwind(AssertUnwindSafe(|| notify(changes))).is_err() {
                log::error!("Watch callback of {} panicked", root.display());
            }
        }
    }
}

impl Drop for FolderWatch {
    fn drop(&mut self) {
        // Stop the thread first, so it makes no call after the drop. The join
        // waits for a call in flight. Then end the inotify watch.
        let _ = self.stop.send(Message::Stop);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            log::error!("Thread of a folder watch panicked");
        }
        drop(self.watcher.take());
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use notify::event::{CreateKind, ModifyKind};

    use super::*;

    fn event(kind: EventKind, paths: &[&str]) -> notify::Result<Event> {
        let mut event = Event::new(kind);
        for path in paths {
            event = event.add_path(PathBuf::from(path));
        }
        Ok(event)
    }

    fn paths(paths: &[&str]) -> Option<Changes> {
        Some(Changes::Paths(paths.iter().map(PathBuf::from).collect()))
    }

    #[test]
    fn events_report_paths_or_unknown_and_reads_report_nothing() {
        let create = EventKind::Create(CreateKind::File);
        assert_eq!(
            FolderWatch::changes(&event(create, &["/root/vault/a/key.json"])),
            paths(&["/root/vault/a/key.json"])
        );
        // A rename reports both paths.
        let rename = EventKind::Modify(ModifyKind::Name(notify::event::RenameMode::Both));
        assert_eq!(
            FolderWatch::changes(&event(rename, &["/root/pairing/a", "/root/vault/b"])),
            paths(&["/root/pairing/a", "/root/vault/b"])
        );
        // No path, or an overflow.
        assert_eq!(
            FolderWatch::changes(&event(create, &[])),
            Some(Changes::Unknown)
        );
        let overflow = Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan);
        assert_eq!(
            FolderWatch::changes(&Ok(overflow.add_path("/elsewhere".into()))),
            Some(Changes::Unknown)
        );
        assert_eq!(
            FolderWatch::changes(&Err(notify::Error::generic("overflow"))),
            Some(Changes::Unknown)
        );
        // Opening and reading a file is not a change. Closing a written one is.
        let open = EventKind::Access(AccessKind::Open(AccessMode::Any));
        let read = EventKind::Access(AccessKind::Close(AccessMode::Read));
        let written = EventKind::Access(AccessKind::Close(AccessMode::Write));
        assert_eq!(FolderWatch::changes(&event(open, &["/root/vault/a"])), None);
        assert_eq!(FolderWatch::changes(&event(read, &["/root/vault/a"])), None);
        assert_eq!(
            FolderWatch::changes(&event(written, &["/root/vault/a"])),
            paths(&["/root/vault/a"])
        );
    }

    #[test]
    fn batch_joins_paths_and_unknown_absorbs_them() {
        let create = EventKind::Create(CreateKind::File);
        let mut batch = None;
        FolderWatch::gather(&mut batch, &event(create, &["/root/a"]));
        FolderWatch::gather(&mut batch, &event(create, &["/root/b"]));
        assert_eq!(batch, paths(&["/root/a", "/root/b"]));

        FolderWatch::gather(&mut batch, &event(create, &[]));
        FolderWatch::gather(&mut batch, &event(create, &["/root/c"]));
        assert_eq!(batch, Some(Changes::Unknown));
    }
}
