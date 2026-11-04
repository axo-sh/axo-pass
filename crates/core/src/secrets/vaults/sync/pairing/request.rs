//! Pairing request, the file `{root}/pairing/{request_id}.json` that a new
//! Mac writes (Device pairing step 3).
//!
//! Every field is untrusted until `mac` verifies under the pairing key of
//! the code the user typed. The MAC covers `request_id`, `replicas` as a
//! counted list of vault id and replica id pairs in vault id order,
//! `encryption`, `signing`, and `name`, in the canonical encoding.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use super::PairKey;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::model::{PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::transport::RequestId;
use crate::secrets::vaults::sync::wrapping::PairingMac;
use crate::secrets::vaults::sync::wrapping::encoding::Canonical;

/// Failure to read a pairing request.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PairingRequestError {
    #[error("pairing request is malformed: {0}")]
    Malformed(String),
}

/// Pairing request of a new Mac.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRequest {
    pub request_id: RequestId,
    /// Replica id of the new Mac in each vault, by vault id.
    pub replicas: BTreeMap<Uuid, ReplicaId>,
    /// Public key of `vault-encryption-key` of the new Mac.
    pub encryption: PublicKey,
    /// Public key of `device-signing-key` of the new Mac.
    pub signing: PublicKey,
    /// Computer name of the new Mac. Shown only if `mac` verifies.
    pub name: String,
    pub mac: PairingMac,
}

impl PairingRequest {
    /// Request of the new Mac with the public keys `keys`, with its MAC
    /// under `key`.
    pub fn new(
        request_id: RequestId,
        replicas: BTreeMap<Uuid, ReplicaId>,
        keys: &ReplicaKeys,
        name: String,
        key: &PairKey,
    ) -> Self {
        let mut request = Self {
            request_id,
            replicas,
            encryption: keys.encryption.clone(),
            signing: keys.signing.clone(),
            name,
            mac: PairingMac([0; 32]),
        };
        request.mac = key.mac(&request.mac_input());
        request
    }

    /// Request of the JSON `bytes`. The MAC is not checked.
    pub fn parse(bytes: &[u8]) -> Result<Self, PairingRequestError> {
        serde_json::from_slice(bytes).map_err(|e| PairingRequestError::Malformed(e.to_string()))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("pairing request has only string map keys")
    }

    /// Public keys of the new Mac.
    pub fn keys(&self) -> ReplicaKeys {
        ReplicaKeys {
            encryption: self.encryption.clone(),
            signing: self.signing.clone(),
        }
    }

    /// Canonical bytes that `mac` covers.
    pub fn mac_input(&self) -> Vec<u8> {
        Canonical::new()
            .id(self.request_id.0)
            .list(self.replicas.iter(), |canonical, (vault_id, replica)| {
                canonical.id(*vault_id).id(replica.0)
            })
            .field(&self.encryption.0)
            .field(&self.signing.0)
            .field(self.name.as_bytes())
            .into_bytes()
    }

    /// Whether `mac` verifies under `key`.
    pub fn verify(&self, key: &PairKey) -> bool {
        key.verify(&self.mac_input(), &self.mac)
    }
}
