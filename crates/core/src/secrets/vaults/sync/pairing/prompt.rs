//! Pairing prompt on the unlocked Mac (Device pairing steps 4 to 6,
//! "Pairing prompts").
//!
//! The unlocked Mac cannot tell a real request from a planted one before the
//! user types the code, so the prompt shows the number of pending requests
//! and no computer name. The count reads no request. The code check reads
//! every listed request of at most [`MAX_PAIRING_SIZE`], whatever its
//! modification time or dismissal, so newer planted requests cannot push the
//! real one out of view. A request that fails is never shown and is not
//! deleted, since only the new Mac deletes its own request.

use std::collections::BTreeSet;
use std::path::Path;

use jiff::{SignedDuration, Timestamp};
use uuid::Uuid;

use super::PairingCode;
use super::dismissed::DismissedRequests;
use super::request::PairingRequest;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::transport::{
    MAX_PAIRING_SIZE, PairingEntry, ReadResult, RequestId, SyncTransport, TransportRoot,
};

/// Age of a request past which it does not prompt. The modification time is
/// untrusted and decides only the prompt.
pub const PROMPT_WINDOW: SignedDuration = SignedDuration::from_hours(24);

/// Pairing prompt of one transport root.
pub struct PairingPrompt;

impl PairingPrompt {
    /// Number of requests listed by `transport` that prompt at `now`: a size
    /// of at most [`MAX_PAIRING_SIZE`], a modification time at most
    /// [`PROMPT_WINDOW`] before `now`, and an id not in `dismissed`. Only
    /// valid file names are listed. No request is read, so the count names
    /// no computer.
    pub fn pending(
        transport: &dyn SyncTransport,
        dismissed: &BTreeSet<RequestId>,
        now: Timestamp,
    ) -> Result<usize, Error> {
        Ok(Self::prompting(transport, dismissed, now)?.len())
    }

    /// Ids of the requests that [`Self::pending`] counts.
    pub fn prompting(
        transport: &dyn SyncTransport,
        dismissed: &BTreeSet<RequestId>,
        now: Timestamp,
    ) -> Result<Vec<RequestId>, Error> {
        Ok(transport
            .list_pairings()?
            .iter()
            .filter(|entry| Self::prompts(entry, dismissed, now))
            .map(|entry| entry.id)
            .collect())
    }

    /// Whether `entry` prompts at `now`.
    fn prompts(entry: &PairingEntry, dismissed: &BTreeSet<RequestId>, now: Timestamp) -> bool {
        entry.size <= MAX_PAIRING_SIZE
            && now.duration_since(entry.modified) <= PROMPT_WINDOW
            && !dismissed.contains(&entry.id)
    }

    /// Dismiss the current requests of `transport`, whose root is `root`.
    /// Every listed id is stored in `sync/pairing.json` under the app data
    /// directory `app_root`, in place of the ids stored for `root`, so only
    /// a request with a new id prompts again.
    pub fn dismiss(
        transport: &dyn SyncTransport,
        root: &TransportRoot,
        app_root: &Path,
    ) -> Result<(), Error> {
        let current: BTreeSet<RequestId> = transport
            .list_pairings()?
            .into_iter()
            .map(|entry| entry.id)
            .collect();
        let mut dismissed = DismissedRequests::load(app_root);
        dismissed.set(root, current);
        dismissed.save(app_root)
    }

    /// Every request listed by `transport`, with its age now, oldest first.
    /// Reads no request. Lists requests that are dismissed, too old to
    /// prompt, or too large to read, so the user can delete them.
    pub fn list(transport: &dyn SyncTransport) -> Result<Vec<(RequestId, SignedDuration)>, Error> {
        let now = Timestamp::now();
        let mut requests: Vec<(RequestId, SignedDuration)> = transport
            .list_pairings()?
            .into_iter()
            .map(|entry| {
                let age = now.duration_since(entry.modified);
                (entry.id, age.max(SignedDuration::ZERO))
            })
            .collect();
        requests.sort_by_key(|(id, age)| (std::cmp::Reverse(*age), *id));
        Ok(requests)
    }

    /// Dismiss the request `id` under `root`, in addition to the ids already
    /// dismissed. Used after a grant, so the answered request does not prompt
    /// again.
    pub fn dismiss_request(
        root: &TransportRoot,
        app_root: &Path,
        id: RequestId,
    ) -> Result<(), Error> {
        let mut dismissed = DismissedRequests::load(app_root);
        let mut requests = dismissed.of(root);
        requests.insert(id);
        dismissed.set(root, requests);
        dismissed.save(app_root)
    }

    /// Request listed by `transport` whose MAC verifies under the pairing
    /// key of `code`, with its computer name.
    ///
    /// Reads every listed request of at most [`MAX_PAIRING_SIZE`], whatever
    /// its modification time or dismissal. A request whose `request_id`
    /// differs from the id of its file name fails, since the MAC covers the
    /// id of the field. A request that fails to read or to parse, or fails
    /// its MAC, is skipped and logged without its name. A request that is
    /// `Remote` is skipped and its download is requested. `None` if no
    /// request verifies. If none verifies and a request was `Remote`, fails
    /// so the caller can ask the user to try again.
    pub fn match_code(
        transport: &dyn SyncTransport,
        code: &PairingCode,
    ) -> Result<Option<PairingRequest>, Error> {
        let key = code.pair_key();
        let mut downloading = false;
        for entry in transport.list_pairings()? {
            if entry.size > MAX_PAIRING_SIZE {
                continue;
            }
            let id = entry.id;
            let bytes = match transport.read_pairing(id) {
                Ok(ReadResult::Local(bytes)) => bytes,
                Ok(ReadResult::Remote) => {
                    downloading = true;
                    if let Err(e) = transport.request_pairing_download(id) {
                        log::warn!("Failed to request the download of pairing request {id}: {e}");
                    }
                    continue;
                },
                Ok(ReadResult::Missing) => continue,
                Err(e) => {
                    log::warn!("Failed to read pairing request {id}: {e}");
                    continue;
                },
            };
            let request = match PairingRequest::parse(&bytes) {
                Ok(request) => request,
                Err(e) => {
                    log::debug!("Pairing request {id} is skipped: {e}");
                    continue;
                },
            };
            if request.request_id != id {
                log::debug!("Pairing request {id} holds another request id");
                continue;
            }
            if request.verify(&key) {
                log::info!("Pairing request {id} matches the code");
                return Ok(Some(request));
            }
        }
        if downloading {
            return Err(Error::SyncTransportError(
                "A pairing request is still downloading. Try again in a moment.".to_string(),
            ));
        }
        Ok(None)
    }

    /// Synced vaults of this Mac that `request` can be paired with: each
    /// vault with a local sync state under the app data directory `app_root`
    /// whose sidecar root is `root` and that is in the request map, in vault
    /// id order.
    ///
    /// The sync states and sidecars are not verified here. They only build
    /// the list the user picks from, and the grant checks each picked vault
    /// again under its locks.
    pub fn vaults(app_root: &Path, root: &TransportRoot, request: &PairingRequest) -> Vec<Uuid> {
        let mut vaults: Vec<Uuid> = LocalSyncState::list(app_root)
            .into_iter()
            .map(|(vault_id, _)| vault_id)
            .filter(|vault_id| request.replicas.contains_key(vault_id))
            .filter(|vault_id| {
                Sidecar::read(app_root, *vault_id)
                    .is_ok_and(|sidecar| sidecar.transport.as_ref() == Some(root))
            })
            .collect();
        vaults.sort();
        vaults.dedup();
        vaults
    }
}
