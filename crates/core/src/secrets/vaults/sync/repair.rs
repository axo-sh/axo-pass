//! Recovery merge, the `v > s` repair, and the user override.
//!
//! A repair runs in a transaction in place of the no-edit guard. It joins this
//! replica's own state files, adds each difference of the vault against the
//! view as a concurrent value under one write id
//! ([`LocalEdits::find_repair`]), and then joins the peer files. The vault is
//! then saved from the view. The requested change of the transaction is
//! recorded after the repair as an ordinary edit, under its own write id.
//!
//! The `v > s` repair runs at each load of a vault newer than its sync state.
//! The recovery merge resumes a sync stopped by drift. It runs automatically
//! on a build other than the one that stopped sync, and on that build only
//! after the user override, which is offered once per build.
//!
//! [`LocalEdits::find_repair`]: super::diff::LocalEdits::find_repair

use super::local_state::LocalSyncState;
use super::recovery::RecoveryAdd;
use super::status::BUILD_ID;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};

/// Repair a transaction runs in place of the no-edit guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Repair {
    /// `v > s`. A sync state restored from a backup.
    NewerVault,
    /// Recovery merge of a sync stopped by drift on another build.
    NewBuild,
    /// Recovery merge on the build that stopped sync, after the user
    /// override.
    Override,
}

/// What a transaction asks of the sync state besides its change.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SyncRequest {
    /// Record the change as local edits.
    Change,
    /// Record a restored retained version. An entry the version lacks is
    /// moved to the trash.
    Restore,
    /// Run the recovery merge on this build. Fails with
    /// `SyncOverrideNotOffered` if the override is not offered.
    Override,
    /// Write the recipient of a saved recovery kit into `recovery`, under
    /// the write id of the change (D18). Fails with `RecoveryKitNotAdded`
    /// and writes nothing if sync does not run or the kit is not for the
    /// current key.
    AddRecovery(RecoveryAdd),
}

impl Repair {
    /// Repair of a transaction on the sync state `local`. `newer` is set for
    /// a vault newer than the sync state, and `confirmed` for the user
    /// override. `None` if the transaction runs the guard.
    ///
    /// A sync stopped by drift on another build runs the recovery merge. One
    /// stopped on this build runs it only if `confirmed`, and otherwise stays
    /// stopped, at `v > s` too.
    pub(crate) fn of(local: &LocalSyncState, newer: bool, confirmed: bool) -> Option<Self> {
        match local.stopped_build.as_deref() {
            Some(build) if build != BUILD_ID => Some(Self::NewBuild),
            Some(_) if confirmed => Some(Self::Override),
            Some(_) => None,
            None if newer => Some(Self::NewerVault),
            None => None,
        }
    }

    /// Whether the user override is offered for the sync state `local`: sync
    /// is stopped by drift on this build, and the last override was not on
    /// this build.
    pub(crate) fn override_offered(local: &LocalSyncState) -> bool {
        local.stopped_build.as_deref() == Some(BUILD_ID)
            && local.override_build.as_deref() != Some(BUILD_ID)
    }

    /// Set the header of `local` for this repair. A recovery merge resumes
    /// sync, and the override records this build in `override_build`.
    pub(crate) fn start(self, local: &mut LocalSyncState) {
        match self {
            Self::NewerVault => {},
            Self::NewBuild => local.stopped_build = None,
            Self::Override => {
                local.stopped_build = None;
                local.override_build = Some(BUILD_ID.to_string());
            },
        }
    }
}

/// User override of a sync stopped by drift on this build: "Resume and show
/// differences as conflicts". The confirmation UI is milestone 10.
pub struct SyncOverride<'a> {
    writer: &'a VaultWriter,
    target: &'a Target,
}

impl<'a> SyncOverride<'a> {
    /// Override for the vault `target`, written by `writer`.
    pub fn new(writer: &'a VaultWriter, target: &'a Target) -> Self {
        Self { writer, target }
    }

    /// Number of differences the recovery merge would add, against the sync
    /// state as loaded, for the confirmation. Writes nothing. Fails with
    /// `SyncOverrideNotOffered` if the override is not offered.
    pub fn preview(&self, unlock: Unlock<'_>) -> Result<usize, Error> {
        self.writer.override_preview(self.target, unlock)
    }

    /// Run the recovery merge on this build after the confirmation, and
    /// resume sync. The sync state records this build in `override_build`.
    /// Fails with `SyncOverrideNotOffered` and writes nothing if the override
    /// is not offered.
    pub fn confirm(&self, unlock: Unlock<'_>) -> Result<Committed<()>, Error> {
        self.writer
            .write_as(self.target, unlock, SyncRequest::Override, |_| Ok(()))
    }
}
