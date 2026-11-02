//! Ids of replicas, actors, and writes.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Id of a replica. The serde form is the `Uuid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReplicaId(pub Uuid);

/// Id of an actor, the writer of one session of one replica. The serde form
/// is the `Uuid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActorId(pub Uuid);

/// Id of one write.
///
/// Sequence numbers of an actor start at 1 and increase by 1. Write ids are
/// ordered by actor, then sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WriteId {
    pub actor: ActorId,
    pub seq: u64,
}
