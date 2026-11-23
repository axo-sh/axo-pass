//! Pinned public keys of the peers of one vault (decision 11).
//!
//! A peer is pinned at pairing, or at the first join that names it. A
//! first-use pin takes the one value of the peer `replica_keys` register
//! written by an actor of that peer. Any holder of the sync key can write the
//! register of another replica, so a value written by another replica's
//! actor is never pinned. A register with no such value, or with more than
//! one, pins nothing, and a later join pins it. A pin is never replaced by a
//! later join. This replica is never pinned.
//!
//! A key rotation wraps the new key only to pinned encryption keys and
//! verifies only against pinned signing keys (`sync/rotation.rs`). Accepting
//! or signing a rotation revokes the pins of the replicas it removes. The
//! sync report flags a `replica_keys` register that differs from its pin.
//! `VaultView::replica_keys` shows the register values and does not read the
//! pins.

use super::crdt::{CausalState, ReplicaId};
use super::local_state::{LocalSyncState, PinSource, PinnedKeys};
use super::model::{ReplicaKeys, SyncState};

/// Pins of the local sync state.
pub struct Pins;

/// Result of a pairing pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairedPin {
    /// No pin existed. A `pairing` pin was added.
    New,
    /// A `first_use` pin with the same keys became a `pairing` pin.
    Upgraded,
    /// A `pairing` pin with the same keys existed. Nothing changed.
    Unchanged,
    /// A pin with other keys, or a revoked pin, exists. Nothing changed.
    Conflict,
}

impl PairedPin {
    /// Whether the local sync state changed.
    pub fn changed(self) -> bool {
        matches!(self, Self::New | Self::Upgraded)
    }
}

impl Pins {
    /// Pin with `first_use` each replica of `replica_keys` in `state` that is
    /// not the replica of `local` and has no pin in `local`. Returns whether
    /// a pin was added.
    pub fn pin_first_use(local: &mut LocalSyncState, state: &CausalState<SyncState>) -> bool {
        let mut pinned = false;
        for (replica, _) in state.store.replica_keys.iter() {
            let replica = *replica;
            if replica == local.replica_id || local.pinned_keys.contains_key(&replica) {
                continue;
            }
            let Some(keys) = Self::own_value(state, replica) else {
                continue;
            };
            let vault_id = local.vault_id;
            let peer = replica.0;
            log::info!("Vault {vault_id} pins the keys of replica {peer} at first use");
            local
                .pinned_keys
                .insert(replica, Self::pin(PinSource::FirstUse, keys));
            pinned = true;
        }
        pinned
    }

    /// Pin `keys` for `replica` with `pairing` in `local`. A `first_use` pin
    /// with the same keys becomes a `pairing` pin. A pin with other keys, or
    /// a revoked pin, refuses the pairing and changes nothing.
    pub fn pin_paired(
        local: &mut LocalSyncState,
        replica: ReplicaId,
        keys: &ReplicaKeys,
    ) -> PairedPin {
        let Some(pin) = local.pinned_keys.get_mut(&replica) else {
            local
                .pinned_keys
                .insert(replica, Self::pin(PinSource::Pairing, keys));
            return PairedPin::New;
        };
        if pin.revoked || pin.encryption != keys.encryption || pin.signing != keys.signing {
            return PairedPin::Conflict;
        }
        match pin.source {
            PinSource::Pairing => PairedPin::Unchanged,
            PinSource::FirstUse => {
                pin.source = PinSource::Pairing;
                PairedPin::Upgraded
            },
        }
    }

    /// The one value of the `replica_keys` register of `replica` in `state`
    /// written by an actor of `replica`. `None` if there is none or more than
    /// one.
    fn own_value(state: &CausalState<SyncState>, replica: ReplicaId) -> Option<&ReplicaKeys> {
        let register = state.store.replica_keys.get(&replica)?;
        let mut own = register.values().filter(|(id, _)| {
            state
                .actors
                .get(&id.actor)
                .is_some_and(|info| info.replica == replica)
        });
        let (_, value) = own.next()?;
        own.next().is_none().then_some(&value.value)
    }

    /// Unrevoked pin of `keys` with `source`.
    fn pin(source: PinSource, keys: &ReplicaKeys) -> PinnedKeys {
        PinnedKeys {
            source,
            encryption: keys.encryption.clone(),
            signing: keys.signing.clone(),
            revoked: false,
        }
    }
}
