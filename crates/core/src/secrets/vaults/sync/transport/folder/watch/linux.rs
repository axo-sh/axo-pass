//! inotify watch of the folder transport.
//!
//! A [`FolderWatch`] watches the root recursively through the `notify` crate
//! and calls `notify` for events under one directory of it. The root is
//! watched, not the directory, so a directory created later is covered.
//! inotify reports writes of every process, including writes that use no
//! coordination, such as Syncthing writes.
//!
//! inotify reports paths below the path it was given, so the root is
//! resolved before the watch starts. A root reached through a symlink
//! matches its events.

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use notify::event::{AccessKind, AccessMode};
use notify::{Event, EventKind, RecursiveMode, Watcher};

use crate::secrets::vaults::sync::transport::WatchHandle;

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
    /// Watch of `root` that calls `notify` for each batch of events under
    /// `{root}/{dir}`, or under an ancestor of it, such as a change of the
    /// root itself, or a batch that inotify could not report by path, such
    /// as an overflow of its queue. `None` if the root is missing or is not
    /// a folder, or the watch fails to start.
    ///
    /// At most one call is made per second. Calls never overlap.
    ///
    /// The handle must not drop inside `notify`, since drop waits for the
    /// thread that makes the call.
    pub fn start(root: &Path, dir: &Path, notify: Box<dyn Fn() + Send>) -> Option<WatchHandle> {
        let root = fs::canonicalize(root).ok()?;
        if !root.is_dir() {
            return None;
        }
        let dir = root.join(dir);
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
        if let Err(e) = watcher.watch(&root, RecursiveMode::Recursive) {
            log::warn!("Failed to watch {}: {e}", root.display());
            return None;
        }
        let thread = thread::Builder::new()
            .name("folder-watch".into())
            .spawn(move || Self::run(&dir, &receiver, &notify));
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
        let watch = Self {
            watcher: Some(watcher),
            stop: sender,
            thread: Some(thread),
        };
        Some(WatchHandle::new(move || drop(watch)))
    }

    /// Whether an event at `path` reports a change under `dir`: the path is
    /// `dir`, a path under it, or an ancestor of it.
    pub fn matches(dir: &Path, path: &Path) -> bool {
        path.starts_with(dir) || dir.starts_with(path)
    }

    /// Whether `event` reports a change under `dir`. An error and an event
    /// with no path report a change that is not known by path, such as an
    /// overflow of the inotify queue.
    fn relevant(dir: &Path, event: &notify::Result<Event>) -> bool {
        let Ok(event) = event else {
            return true;
        };
        // Our own reads open and close files, and would call `notify` again.
        let reads = match event.kind {
            EventKind::Access(AccessKind::Close(AccessMode::Write)) => false,
            EventKind::Access(_) => true,
            _ => false,
        };
        if reads {
            return false;
        }
        event.need_rescan()
            || event.paths.is_empty()
            || event.paths.iter().any(|path| Self::matches(dir, path))
    }

    /// Body of the thread. Waits for a relevant event, gathers events for
    /// [`LATENCY`], and calls `notify` once. Ends on `Stop`, or when the
    /// channel closes.
    fn run(dir: &Path, receiver: &Receiver<Message>, notify: &dyn Fn()) {
        loop {
            match receiver.recv() {
                Ok(Message::Event(event)) if Self::relevant(dir, &event) => {
                    if let Err(e) = &event {
                        log::warn!("Watch of {} reported an error: {e}", dir.display());
                    }
                },
                Ok(Message::Event(_)) => continue,
                Ok(Message::Stop) | Err(_) => return,
            }
            let deadline = Instant::now() + LATENCY;
            loop {
                let wait = deadline.saturating_duration_since(Instant::now());
                match receiver.recv_timeout(wait) {
                    Ok(Message::Event(_)) => {},
                    Ok(Message::Stop) | Err(RecvTimeoutError::Disconnected) => return,
                    Err(RecvTimeoutError::Timeout) => break,
                }
            }
            if catch_unwind(AssertUnwindSafe(notify)).is_err() {
                log::error!("Watch callback of {} panicked", dir.display());
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

    #[test]
    fn events_with_paths_outside_dir_or_without_paths_or_that_read_are_filtered() {
        let dir = Path::new("/root/vault");
        let create = EventKind::Create(CreateKind::File);
        assert!(FolderWatch::relevant(
            dir,
            &event(create, &["/root/vault/a/key.json"])
        ));
        assert!(FolderWatch::relevant(dir, &event(create, &["/root/vault"])));
        assert!(FolderWatch::relevant(dir, &event(create, &["/root"])));
        assert!(!FolderWatch::relevant(
            dir,
            &event(create, &["/root/pairing/a.json"])
        ));
        // A rename reports both paths.
        let rename = EventKind::Modify(ModifyKind::Name(notify::event::RenameMode::Both));
        assert!(FolderWatch::relevant(
            dir,
            &event(rename, &["/root/pairing/a", "/root/vault/b"])
        ));
        // No path, or an overflow.
        assert!(FolderWatch::relevant(dir, &event(create, &[])));
        let overflow = Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan);
        assert!(FolderWatch::relevant(
            dir,
            &Ok(overflow.add_path("/elsewhere".into()))
        ));
        assert!(FolderWatch::relevant(
            dir,
            &Err(notify::Error::generic("overflow"))
        ));
        // Opening and reading a file is not a change. Closing a written one is.
        let open = EventKind::Access(AccessKind::Open(AccessMode::Any));
        let read = EventKind::Access(AccessKind::Close(AccessMode::Read));
        let written = EventKind::Access(AccessKind::Close(AccessMode::Write));
        assert!(!FolderWatch::relevant(
            dir,
            &event(open, &["/root/vault/a"])
        ));
        assert!(!FolderWatch::relevant(
            dir,
            &event(read, &["/root/vault/a"])
        ));
        assert!(FolderWatch::relevant(
            dir,
            &event(written, &["/root/vault/a"])
        ));
    }
}
