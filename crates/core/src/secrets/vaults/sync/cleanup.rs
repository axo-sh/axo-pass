//! Cleanup of retired and departed replicas (`05-transaction.md`, "Retired
//! and departed replicas").
//!
//! A replica can be cleaned up if it has left, is removed by a rotation, has
//! a revoked pin, or has the keys of another replica id, as a Mac that
//! re-linked. The downloads of its state files are requested and waited for
//! outside the vault locks. A transaction then joins them and checks that
//! each one was joined. If a file is still remote, it ends with
//! `RotationWaiting` and writes nothing.
//!
//! The transaction folds a later `last_used_day_at` time of the replica into
//! the own register, removes its `replica_names`, `replica_keys`, and `left`
//! entries and its `last_used_day_at` registers under one write id, and
//! publishes. The `removed` entry, the pins, and the revocations are kept.
//! The directory of the replica is deleted only after that publish
//! succeeds, and only if every listed file of it was joined. The transaction
//! records `sync.replica_cleaned`.

use super::crdt::ReplicaId;
use super::rotation::{Cleaned, RotationStep};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};

impl VaultWriter {
    /// Clean up `replica` of the vault `target` in one transaction (see the
    /// module comment). Fails with `RotationWaiting` and writes nothing if a
    /// file of `replica` is still remote. [`Self::clean_waiting`] waits for
    /// those files first.
    pub fn clean_replica(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        replica: ReplicaId,
    ) -> Result<Committed<Cleaned>, Error> {
        let mut step = RotationStep::Clean {
            replica,
            cleaned: None,
        };
        let committed = self.write_rotating(target, unlock, &mut step)?;
        let RotationStep::Clean { cleaned, .. } = step else {
            unreachable!("step is a cleanup");
        };
        Ok(committed.with_value(cleaned.unwrap_or_default()))
    }

    /// [`Self::clean_replica`] after the files of `replica` are local, with
    /// `wait` called outside the vault locks while they download, as
    /// `rotate_waiting` calls it. Fails with `RotationCancelled` if `wait`
    /// returns false.
    pub fn clean_waiting<'u>(
        &self,
        target: &Target,
        unlock: impl Fn() -> Unlock<'u>,
        replica: ReplicaId,
        wait: impl FnMut(&[ReplicaId]) -> bool,
    ) -> Result<Committed<Cleaned>, Error> {
        self.waiting(target, &[replica], wait, || {
            self.clean_replica(target, unlock(), replica)
        })
    }
}
