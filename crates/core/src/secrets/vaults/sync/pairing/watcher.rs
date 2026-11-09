//! Pairing watcher on the new Mac ("Pairing wait", 9.5).
//!
//! The watcher holds a [`PendingPairing`] until the user finishes, the
//! request expires, or the app quits. It watches the directory of each vault
//! in the request map and polls the `key.json` files on each event and every
//! [`POLL_INTERVAL`], so a transport with no watch is still polled. Each
//! accepted vault is returned to the `SyncManager`, which reports it and
//! starts its import (D6 of doc 18).
//!
//! The `SyncManager` thread runs the watcher, so `SyncManager::shutdown`
//! finishes it with the watches of the synced vaults. The watcher holds no
//! lock and writes no vault file. Its only write is the delete of its own
//! request under `{root}/pairing/`, which happens once, at the finish or
//! the drop.
//!
//! The unwrap holds `vault-encryption-key`, read once by the caller on the
//! context of `PendingPairing::start` (D16). The MAC of a wrapping is checked
//! before the unwrap, so only an accepted wrapping uses the key. If the
//! context lapsed, that unwrap prompts on the `SyncManager` thread.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::{PairedVault, PendingPairing};
use crate::secrets::vaults::sync::transport::{SyncTransport, WatchHandle};
use crate::secrets::vaults::sync::wrapping::DeviceUnwrap;

/// Time between two polls with no watch event.
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Time from the start after which the request is deleted.
pub const PAIRING_EXPIRY: Duration = Duration::from_secs(15 * 60);

/// Pairing of the new Mac, with its watches, run by the `SyncManager`.
pub struct PairingWatcher {
    /// `None` once the pairing finished.
    pending: Option<PendingPairing>,
    transport: Arc<dyn SyncTransport>,
    unwrap: WatcherUnwrap,
    watches: Vec<WatchHandle>,
    expires_at: Instant,
    next_poll: Instant,
}

impl PairingWatcher {
    /// Watch the directory of each vault in the request map of `pending`
    /// through `transport`, calling `notify` on each change, and expire
    /// [`PAIRING_EXPIRY`] after `now`. The first poll is due at `now`.
    /// `unwrap` holds `vault-encryption-key`, read once on one context.
    pub fn start(
        pending: PendingPairing,
        transport: Arc<dyn SyncTransport>,
        unwrap: Box<dyn DeviceUnwrap + Send>,
        notify: impl Fn() + Clone + Send + 'static,
        now: Instant,
    ) -> Self {
        let watches = pending
            .request()
            .replicas
            .keys()
            .filter_map(|vault_id| transport.watch(*vault_id, Box::new(notify.clone())))
            .collect();
        log::info!(
            "Pairing request {} is watched",
            pending.request().request_id
        );
        Self {
            pending: Some(pending),
            transport,
            unwrap: WatcherUnwrap::new(unwrap),
            watches,
            expires_at: now + PAIRING_EXPIRY,
            next_poll: now,
        }
    }

    /// Earliest time the watcher needs to run: the next poll or the expiry.
    pub fn next_wake(&self) -> Instant {
        self.next_poll.min(self.expires_at)
    }

    /// Whether the request expired at `now`.
    pub fn expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Whether a poll with no watch event is due at `now`.
    pub fn poll_due(&self, now: Instant) -> bool {
        now >= self.next_poll
    }

    /// Poll the `key.json` files. Returns the vaults accepted by this poll.
    /// The next poll is due [`POLL_INTERVAL`] after `now`.
    pub fn poll(&mut self, now: Instant) -> Vec<PairedVault> {
        self.next_poll = now + POLL_INTERVAL;
        let Some(pending) = &mut self.pending else {
            return Vec::new();
        };
        pending.poll(&*self.transport, &self.unwrap)
    }

    /// End the watches, delete the request, and drop the code.
    pub fn finish(mut self) {
        self.end();
    }

    /// End the watches and delete the request, once. A delete that fails is
    /// logged, and the request stops prompting after 24 hours.
    fn end(&mut self) {
        self.watches.clear();
        let Some(pending) = self.pending.take() else {
            return;
        };
        let request_id = pending.request().request_id;
        match pending.finish(&*self.transport) {
            Ok(()) => log::info!("Pairing request {request_id} deleted"),
            Err(e) => log::warn!("Failed to delete pairing request {request_id}: {e}"),
        }
    }
}

impl Drop for PairingWatcher {
    fn drop(&mut self) {
        self.end();
    }
}

/// Unwrap of the watcher. A ciphertext whose unwrap failed is not unwrapped
/// again, so a prompt that the user cancelled is not drawn again at each
/// poll. A new wrapping is unwrapped once.
struct WatcherUnwrap {
    key: Box<dyn DeviceUnwrap + Send>,
    failed: RefCell<BTreeSet<Vec<u8>>>,
}

impl WatcherUnwrap {
    fn new(key: Box<dyn DeviceUnwrap + Send>) -> Self {
        Self {
            key,
            failed: RefCell::new(BTreeSet::new()),
        }
    }
}

impl DeviceUnwrap for WatcherUnwrap {
    fn unwrap_sync_key(&self, wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if self.failed.borrow().contains(wrapped) {
            return None;
        }
        let raw = self.key.unwrap_sync_key(wrapped);
        if raw.is_none() {
            self.failed.borrow_mut().insert(wrapped.to_vec());
        }
        raw
    }
}
