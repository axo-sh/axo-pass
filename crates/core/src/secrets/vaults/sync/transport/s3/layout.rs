//! Object keys of the S3 transport.
//!
//! ```text
//! {prefix}/vaults/{vault}/meta.json
//! {prefix}/vaults/{vault}/{replica}/key.json
//! {prefix}/vaults/{vault}/{replica}/{vault}.{hash}.apstate
//! {prefix}/vaults/{vault}/blobs/{blob}
//! {prefix}/pairing/{request}.json
//! ```
//!
//! Vault and replica directories are named by short id, as in the folder
//! transport. A key of a directory ends in `/`. With an empty prefix, the
//! keys start at `vaults/` and `pairing/`.

use uuid::Uuid;

use crate::secrets::vaults::files::FileHash;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::transport::{FileName, RequestId};

/// Name of the file of the vault format in each vault directory.
const META_FILE: &str = "meta.json";

/// Directory of the vaults under the prefix.
const VAULTS_DIR: &str = "vaults";

/// Directory of the pairing requests under the prefix.
const PAIRING_DIR: &str = "pairing";

/// Directory of the file blobs in each vault directory.
const BLOB_DIR: &str = "blobs";

/// Directory of the connection test objects under the prefix.
const PROBE_DIR: &str = "probe";

/// Keys of one transport, under a prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLayout {
    /// Prefix with no leading or trailing slash.
    prefix: String,
}

impl KeyLayout {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.trim_matches('/').to_string(),
        }
    }

    fn join(&self, rest: &str) -> String {
        if self.prefix.is_empty() {
            rest.to_string()
        } else {
            format!("{}/{rest}", self.prefix)
        }
    }

    /// Directory of the vault directories.
    pub fn vaults_dir(&self) -> String {
        self.join(&format!("{VAULTS_DIR}/"))
    }

    pub fn vault_dir(&self, vault_id: Uuid) -> String {
        self.join(&format!("{VAULTS_DIR}/{}/", ShortId::encode_uuid(vault_id)))
    }

    pub fn meta(&self, vault_id: Uuid) -> String {
        format!("{}{META_FILE}", self.vault_dir(vault_id))
    }

    pub fn replica_dir(&self, vault_id: Uuid, replica: ReplicaId) -> String {
        format!(
            "{}{}/",
            self.vault_dir(vault_id),
            ShortId::encode_uuid(replica.0)
        )
    }

    pub fn file(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> String {
        format!(
            "{}{}",
            self.replica_dir(vault_id, replica),
            name.file_name(vault_id)
        )
    }

    pub fn blob_dir(&self, vault_id: Uuid) -> String {
        format!("{}{BLOB_DIR}/", self.vault_dir(vault_id))
    }

    pub fn blob(&self, vault_id: Uuid, blob: FileHash) -> String {
        format!("{}{blob}", self.blob_dir(vault_id))
    }

    pub fn pairing_dir(&self) -> String {
        self.join(&format!("{PAIRING_DIR}/"))
    }

    pub fn pairing(&self, request: RequestId) -> String {
        format!("{}{}", self.pairing_dir(), request.file_name())
    }

    /// Directory of the objects that a connection test writes.
    pub fn probe_dir(&self) -> String {
        self.join(&format!("{PROBE_DIR}/"))
    }

    /// Id named by `name`, the exact short form of a UUID. The hex forms that
    /// `ShortId::decode` also reads are refused.
    pub fn parse_short_id(name: &str) -> Option<Uuid> {
        let id = ShortId::parse_uuid(name).ok()?;
        (ShortId::encode_uuid(id) == name).then_some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::vaults::sync::state_file::StateHash;

    const VAULT: Uuid = Uuid::from_u128(0x100);
    const REPLICA: ReplicaId = ReplicaId(Uuid::from_u128(1));

    fn short(id: Uuid) -> String {
        ShortId::encode_uuid(id)
    }

    #[test]
    fn keys_under_prefix() {
        let layout = KeyLayout::new("team/ap");
        let vault = short(VAULT);
        let replica = short(REPLICA.0);
        let hash = StateHash::of(b"state");
        let request = RequestId(Uuid::from_u128(7));

        assert_eq!(layout.vaults_dir(), "team/ap/vaults/");
        assert_eq!(layout.vault_dir(VAULT), format!("team/ap/vaults/{vault}/"));
        assert_eq!(
            layout.meta(VAULT),
            format!("team/ap/vaults/{vault}/meta.json")
        );
        assert_eq!(
            layout.file(VAULT, REPLICA, FileName::Key),
            format!("team/ap/vaults/{vault}/{replica}/key.json")
        );
        assert_eq!(
            layout.file(VAULT, REPLICA, FileName::State(hash)),
            format!(
                "team/ap/vaults/{vault}/{replica}/{}",
                FileName::State(hash).file_name(VAULT)
            )
        );
        assert_eq!(
            layout.pairing(request),
            format!("team/ap/pairing/{}", request.file_name())
        );
        assert_eq!(layout.pairing_dir(), "team/ap/pairing/");
    }

    #[test]
    fn empty_prefix_has_no_leading_slash() {
        for prefix in ["", "/"] {
            let layout = KeyLayout::new(prefix);
            assert_eq!(layout.vaults_dir(), "vaults/");
            assert_eq!(layout.pairing_dir(), "pairing/");
            assert_eq!(layout.probe_dir(), "probe/");
        }
    }

    #[test]
    fn blob_keys_in_blobs_directory_of_vault() {
        let layout = KeyLayout::new("p");
        let blob = FileHash::of(b"blob");
        let dir = layout.blob_dir(VAULT);
        assert_eq!(dir, format!("p/vaults/{}/blobs/", short(VAULT)));
        assert_eq!(layout.blob(VAULT, blob), format!("{dir}{blob}"));
    }

    #[test]
    fn blobs_directory_is_not_replica_and_hex_id_refused() {
        assert_eq!(KeyLayout::parse_short_id("blobs"), None);
        assert_eq!(KeyLayout::parse_short_id("pairing"), None);
        assert_eq!(
            KeyLayout::parse_short_id(&short(REPLICA.0)),
            Some(REPLICA.0)
        );
        assert_eq!(
            KeyLayout::parse_short_id(&REPLICA.0.simple().to_string()),
            None
        );
    }
}
