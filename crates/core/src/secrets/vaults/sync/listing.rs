//! Listing of the peer state files of a vault, for change detection (D3).
//!
//! The listed hashes of each peer directory are compared with the hashes the
//! sidecar records as joined or quarantined. No state file is read, and no
//! time or size is recorded. The transport has no call that tells a file
//! that is not local from a local one without a read, so a listed file that
//! is not local is found as a change too.

use uuid::Uuid;

use super::crdt::ReplicaId;
use super::sidecar::Sidecar;
use super::state_file::StateHash;
use super::transport::{FileName, SyncTransport};
use crate::secrets::vaults::errors::Error;

/// Listing of the peer state files of one vault.
pub(crate) struct PeerListing;

impl PeerListing {
    /// Peer state files of vault `vault_id` listed by `transport` that
    /// `sidecar` neither records as joined nor quarantines, by replica.
    /// `own` is this replica, whose directory is not listed. Fails if the
    /// replica directories cannot be listed. A peer directory that cannot be
    /// listed is logged and skipped.
    pub(crate) fn changed(
        transport: &dyn SyncTransport,
        sidecar: &Sidecar,
        vault_id: Uuid,
        own: ReplicaId,
    ) -> Result<Vec<(ReplicaId, StateHash)>, Error> {
        let mut changed = Vec::new();
        for replica in transport.list_replicas(vault_id)? {
            if replica == own {
                continue;
            }
            let listed = match transport.list_states(vault_id, replica) {
                Ok(listed) => listed,
                Err(e) => {
                    let replica = replica.0;
                    log::warn!(
                        "Failed to list state files of replica {replica} of vault {vault_id}: {e}"
                    );
                    continue;
                },
            };
            changed.extend(
                listed
                    .into_iter()
                    .filter(|hash| {
                        let name = FileName::State(*hash).file_name(vault_id);
                        !sidecar.is_joined(replica, *hash)
                            && !sidecar.is_quarantined(replica, &name, *hash)
                    })
                    .map(|hash| (replica, hash)),
            );
        }
        Ok(changed)
    }
}
