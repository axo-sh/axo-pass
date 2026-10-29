//! Publish condition and the delete rule for own state files.

use super::context::CausalContext;

/// State of an own state file as seen by a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnFileState {
    /// Decrypted and joined into the local state, by this transaction or an
    /// earlier one.
    Joined,
    /// Listed but not downloaded. Counts as present.
    Remote,
    /// Local but not joined. It failed to decrypt, was quarantined, or was
    /// refused.
    NotJoined,
}

/// State file in the directory of this replica. `H` is the content hash in
/// the file name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnFile<H> {
    pub hash: H,
    pub state: OwnFileState,
}

impl<H: PartialEq> OwnFile<H> {
    /// Whether to delete this file after a successful publish of the file
    /// named `published`.
    ///
    /// Only a joined file is deleted, since the new file covers it. A file
    /// that is `Remote` or not joined is left in place until a later
    /// transaction joins it.
    pub fn should_delete(&self, published: &H) -> bool {
        self.state == OwnFileState::Joined && self.hash != *published
    }
}

impl CausalContext {
    /// Whether a transaction with this local context should publish.
    ///
    /// It publishes if this context is ahead of `published_context`, or if
    /// `own_files` has no file named `last_published`, the hash of the last
    /// successful publish. A `Remote` file counts as present. With no
    /// recorded publish, only the context decides.
    pub fn should_publish<H: PartialEq>(
        &self,
        published_context: &Self,
        last_published: Option<&H>,
        own_files: &[OwnFile<H>],
    ) -> bool {
        let missing =
            last_published.is_some_and(|hash| !own_files.iter().any(|file| file.hash == *hash));
        self.is_ahead_of(published_context) || missing
    }
}
