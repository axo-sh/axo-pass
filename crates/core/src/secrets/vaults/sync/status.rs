//! Sync status of one vault: active, paused, or stopped.
//!
//! A paused sync records local edits and skips only the files and the publish
//! that its causes block. Paused causes are recorded in the sidecar, and each
//! transaction that syncs finds them again, so a cause clears in the first
//! transaction that no longer finds it. A stopped sync records no edit,
//! mints no write id, and publishes nothing. A stop for drift is
//! `stopped_build` in the signed header of the sync state. A stop for a
//! failed signature or a missing sync state is found again at each load.
//!
//! A stop for drift ends with the recovery merge (`sync/repair.rs`), which
//! runs in the next transaction on another build, or on this build after the
//! user override.

use serde::{Deserialize, Serialize};

use super::load::{SignatureFailure, SyncLoad};
use super::model::KeyId;

/// Build id of this build: the crate version and the git commit hash, with
/// `-dirty` for a tree with changes. A release build and a development build
/// of one commit compare equal.
pub const BUILD_ID: &str = env!("AXO_BUILD_ID");

/// Sync status of a synced vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncStatus {
    Active,
    /// Local edits are recorded, and the causes block some files or the
    /// publish.
    Paused(Vec<PausedCause>),
    Stopped(StopCause),
}

/// Cause of a paused sync.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cause", rename_all = "snake_case", deny_unknown_fields)]
pub enum PausedCause {
    /// The synced folder, or a replica directory in it, cannot be listed.
    Unreachable { error: String },
    /// The staged file failed to copy to the synced folder.
    PublishFailed { error: String },
    /// Listed state files are quarantined.
    Quarantined { files: usize },
    /// The sync state is under a key id the unlock did not unwrap, after a
    /// second unlock. Found again at each load, and not recorded in the
    /// sidecar.
    KeyMissing { key_id: u32 },
}

/// Cause of a stopped sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopCause {
    /// The no-edit guard found edits on build `build`. Another build runs
    /// the recovery merge in its next transaction.
    Drift {
        build: String,
        /// Whether the user override is offered. It is not offered again on
        /// the build that recorded the last override.
        override_offered: bool,
    },
    SignatureFailed(SignatureFailure),
    StateMissing,
}

/// Paused causes found by one transaction. The first error of each kind is
/// kept.
#[derive(Debug, Default)]
pub(crate) struct FoundCauses {
    pub(crate) unreachable: Option<String>,
    pub(crate) publish_failed: Option<String>,
    /// Number of listed state files found quarantined.
    pub(crate) quarantined: usize,
}

impl FoundCauses {
    /// Record that a listing failed with `error`.
    pub(crate) fn unreachable(&mut self, error: impl ToString) {
        self.unreachable.get_or_insert_with(|| error.to_string());
    }

    /// Causes in the order of [`PausedCause`].
    pub(crate) fn causes(&self) -> Vec<PausedCause> {
        let mut causes = Vec::new();
        if let Some(error) = &self.unreachable {
            causes.push(PausedCause::Unreachable {
                error: error.clone(),
            });
        }
        if let Some(error) = &self.publish_failed {
            causes.push(PausedCause::PublishFailed {
                error: error.clone(),
            });
        }
        if self.quarantined > 0 {
            causes.push(PausedCause::Quarantined {
                files: self.quarantined,
            });
        }
        causes
    }
}

impl SyncStatus {
    /// Status of a vault whose transaction found `case` and ran no sync
    /// steps. `None` if the case has no sync status, such as a vault that is
    /// not synced.
    pub(crate) fn of_case(case: &SyncLoad) -> Option<Self> {
        match case {
            SyncLoad::StateMissing => Some(Self::Stopped(StopCause::StateMissing)),
            SyncLoad::SignatureFailed(reason) => {
                Some(Self::Stopped(StopCause::SignatureFailed(reason.clone())))
            },
            SyncLoad::KeyMissing(KeyId(key_id)) => {
                Some(Self::Paused(vec![PausedCause::KeyMissing {
                    key_id: *key_id,
                }]))
            },
            _ => None,
        }
    }

    /// Status of a vault with a trusted sync state, stopped by drift on
    /// `stopped_build` if set, or else paused by `paused` if not empty. The
    /// override is offered unless `override_build` is this build.
    pub(crate) fn of_trusted(
        stopped_build: Option<&str>,
        override_build: Option<&str>,
        paused: &[PausedCause],
    ) -> Self {
        match stopped_build {
            Some(build) => Self::Stopped(StopCause::Drift {
                build: build.to_string(),
                override_offered: override_build != Some(BUILD_ID),
            }),
            None if paused.is_empty() => Self::Active,
            None => Self::Paused(paused.to_vec()),
        }
    }
}
