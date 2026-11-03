//! Local sync state: this Mac's signed record of the sync state of one vault.
//!
//! The file is a JSON envelope of `signature` and `state`. The signature is
//! made by `device-signing-key` over `ap-local-state-v1:` and the raw bytes
//! of `state`, and is checked before `state` is parsed. `state` holds the
//! header fields, a nonce, and the body. The body is the padded body of a
//! state file, encrypted under the local AAD, whose prefix differs from the
//! state file AAD. The file is at `sync/{short_vault_id}.state.json`.
//!
//! The staged file is the state file of the same padded body under the state
//! file AAD with a fresh nonce, at `sync/{short_vault_id}.staged.apstate`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_with::base64::Base64;
use serde_with::serde_as;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::crdt::{CausalContext, CausalState, ReplicaId};
use super::keys::{SyncKey, SyncKeyring, WrappedSyncKey};
use super::model::{ByteString, KeyId, PublicKey, SYNC_FORMAT_VERSION, SyncState};
use super::state_file::body::{BodyError, StateBody};
use super::state_file::padded::{PaddedBody, PaddingError};
use super::state_file::{FormatVersion, StateFile, StateHash};
use super::view::VIEW_VERSION;
use crate::core::files::write_atomic;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::{self, VaultSigner};

/// Prefix of the signed message.
const SIGNATURE_PREFIX: &[u8] = b"ap-local-state-v1:";

/// Prefix of the body AAD.
const AAD_PREFIX: &str = "ap-local-body-v1";

/// Directory of the local sync files under the app data directory.
const SYNC_DIR: &str = "sync";

/// Outer object of a local sync state file.
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalStateEnvelope<'a> {
    /// DER signature by `device-signing-key` over
    /// [`LocalSyncState::signed_message`], written as base64.
    #[serde_as(as = "Base64")]
    signature: Vec<u8>,
    #[serde(borrow)]
    state: &'a RawValue,
}

/// Signed contents of a local sync state file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSyncState {
    pub format_version: u32,
    pub vault_id: Uuid,
    pub replica_id: ReplicaId,
    /// Key id of the key that encrypts the body.
    pub key_id: KeyId,
    /// Generation `s`. Plaintext, so the vault can be classified before the
    /// body is decrypted.
    pub generation: u64,
    /// View rules version the vault was last saved with.
    pub view_version: u32,
    /// Causal context of this replica's last successful publish.
    pub published_context: CausalContext,
    /// Causal context of the staged file if it was not yet published.
    pub staged_context: Option<CausalContext>,
    /// Content hash of the staged file if it was not yet published.
    pub staged_hash: Option<StateHash>,
    /// Build that stopped sync for the vault.
    pub stopped_build: Option<String>,
    /// Build on which the user last used the drift override.
    pub override_build: Option<String>,
    /// Whether the user disabled sync and the final state file is not yet
    /// copied to the synced folder.
    pub leaving: bool,
    /// This Mac's keyring, each key wrapped to `vault-encryption-key`.
    pub sync_keys: Vec<WrappedSyncKey>,
    /// Public keys of each peer, pinned when first learned.
    pub pinned_keys: BTreeMap<ReplicaId, PinnedKeys>,
    #[serde(with = "ByteString")]
    nonce: [u8; 12],
    /// Ciphertext of the padded body.
    #[serde(with = "ByteString")]
    body: Vec<u8>,
}

/// Pinned public keys of one peer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedKeys {
    pub source: PinSource,
    /// Vault encryption key.
    pub encryption: PublicKey,
    /// Device signing key.
    pub signing: PublicKey,
}

/// How a peer's keys were first learned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinSource {
    Pairing,
    FirstUse,
}

/// Failure to read a local sync state.
#[derive(Debug, Error)]
pub enum LocalStateError {
    #[error("sync state file is missing")]
    Missing,
    #[error("failed to read sync state: {0}")]
    Read(#[source] io::Error),
    #[error("sync state envelope is malformed: {0}")]
    Envelope(String),
    #[error("sync state signature is invalid")]
    SignatureInvalid,
    #[error("sync state signature cannot be checked: {0}")]
    SigningKey(#[source] Error),
    /// Newer format version, or a body field this build does not know.
    #[error("sync state is from a newer format: {0}")]
    VersionSkew(String),
    /// Signed state whose fields do not parse.
    #[error("sync state is malformed: {0}")]
    Malformed(String),
    #[error("sync state body is under key {}, which the keyring lacks", .0.0)]
    KeyMissing(KeyId),
    #[error("sync state body fails to decrypt")]
    Decryption,
    #[error(transparent)]
    Padding(PaddingError),
    #[error(transparent)]
    Body(BodyError),
}

impl LocalSyncState {
    /// Local sync state of a vault with no published context, no staged
    /// file, no stop, an empty keyring, no pins, and no body.
    pub fn new(vault_id: Uuid, replica_id: ReplicaId, key_id: KeyId) -> Self {
        Self {
            format_version: SYNC_FORMAT_VERSION,
            vault_id,
            replica_id,
            key_id,
            generation: 0,
            view_version: VIEW_VERSION,
            published_context: CausalContext::default(),
            staged_context: None,
            staged_hash: None,
            stopped_build: None,
            override_build: None,
            leaving: false,
            sync_keys: Vec::new(),
            pinned_keys: BTreeMap::new(),
            nonce: [0; 12],
            body: Vec::new(),
        }
    }

    /// Local sync state file of vault `vault_id` under the app data directory
    /// `root`.
    pub fn path(root: &Path, vault_id: Uuid) -> PathBuf {
        let vault_id = ShortId::encode_uuid(vault_id);
        root.join(SYNC_DIR).join(format!("{vault_id}.state.json"))
    }

    /// Vault ids and paths of the local sync state files under the app data
    /// directory `root`, ordered by path. Only names of the form of
    /// [`Self::path`] are listed. The files are not read.
    pub fn list(root: &Path) -> Vec<(Uuid, PathBuf)> {
        let mut found: Vec<(Uuid, PathBuf)> = fs::read_dir(root.join(SYNC_DIR))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name();
                let short_id = name.to_str()?.strip_suffix(".state.json")?;
                let vault_id = ShortId::decode(short_id).ok()?.uuid();
                (ShortId::encode_uuid(vault_id) == short_id).then(|| (vault_id, entry.path()))
            })
            .collect();
        found.sort_by(|(_, a), (_, b)| a.cmp(b));
        found
    }

    /// Staged file of vault `vault_id` under the app data directory `root`.
    pub fn staged_path(root: &Path, vault_id: Uuid) -> PathBuf {
        let vault_id = ShortId::encode_uuid(vault_id);
        root.join(SYNC_DIR)
            .join(format!("{vault_id}.staged.apstate"))
    }

    /// Body AAD:
    /// `ap-local-body-v1:{format_version}:{vault_id}:{replica_id}:{key_id}:
    /// {generation}`, in the forms of the state file AAD.
    pub fn aad(&self) -> String {
        let format_version = self.format_version;
        let vault_id = self.vault_id;
        let replica_id = self.replica_id.0;
        let key_id = self.key_id.0;
        let generation = self.generation;
        format!("{AAD_PREFIX}:{format_version}:{vault_id}:{replica_id}:{key_id}:{generation}")
    }

    /// Encrypt the padded body `padded` as the body, with a fresh nonce,
    /// under the key of `keyring` with this state's key id. The AAD holds
    /// `generation` and `key_id`, so seal after the last change to either.
    pub fn seal(&mut self, padded: &[u8], keyring: &SyncKeyring) -> Result<(), Error> {
        let (nonce, body) = self
            .key(keyring)?
            .state_key(self.vault_id)
            .encrypt(self.aad().as_bytes(), padded)
            .ok_or_else(|| Error::SyncStateEncodeError("body fails to encrypt".to_string()))?;
        self.nonce = nonce;
        self.body = body;
        Ok(())
    }

    /// Staged file of the padded body `padded`: the state file of this
    /// replica under the key of `keyring` with this state's key id.
    pub fn staged_file(&self, padded: &[u8], keyring: &SyncKeyring) -> Result<Vec<u8>, Error> {
        StateFile::encode(
            padded,
            self.vault_id,
            self.replica_id,
            self.key_id,
            self.key(keyring)?,
        )
    }

    /// Key with this state's key id.
    fn key<'k>(&self, keyring: &'k SyncKeyring) -> Result<&'k SyncKey, Error> {
        keyring.get(self.key_id).ok_or_else(|| {
            let key_id = self.key_id.0;
            Error::SyncStateEncodeError(format!("keyring lacks key {key_id}"))
        })
    }

    /// Sync state of the body, decrypted with the key of `keyring` with this
    /// state's key id. A body field this build does not know is version
    /// skew.
    pub fn open(&self, keyring: &SyncKeyring) -> Result<CausalState<SyncState>, LocalStateError> {
        let padded = self.open_padded(keyring)?;
        let body = PaddedBody::unpad(&padded).map_err(LocalStateError::Padding)?;
        StateBody::decode(&body).map_err(|e| match e {
            BodyError::VersionSkew(message) => LocalStateError::VersionSkew(message),
            e => LocalStateError::Body(e),
        })
    }

    /// Padded body, decrypted with the key of `keyring` with this state's key
    /// id.
    pub(crate) fn open_padded(
        &self,
        keyring: &SyncKeyring,
    ) -> Result<Zeroizing<Vec<u8>>, LocalStateError> {
        keyring
            .get(self.key_id)
            .ok_or(LocalStateError::KeyMissing(self.key_id))?
            .state_key(self.vault_id)
            .decrypt(&self.nonce, self.aad().as_bytes(), &self.body)
            .ok_or(LocalStateError::Decryption)
    }

    /// Message signed for the raw state bytes `state_json`.
    fn signed_message(state_json: &str) -> Vec<u8> {
        [SIGNATURE_PREFIX, state_json.as_bytes()].concat()
    }

    /// Contents of a local sync state file holding this state, signed by
    /// `signer`.
    pub fn to_file_contents(&self, signer: &dyn VaultSigner) -> Result<String, Error> {
        // Indent the state JSON to its depth in the envelope. JSON strings
        // hold no raw newlines, so only line breaks between tokens change.
        let state_json = serde_json::to_string_pretty(self)
            .map_err(|e| Error::SyncStateEncodeError(e.to_string()))?
            .replace('\n', "\n  ");
        let signature = signer.sign(&Self::signed_message(&state_json))?;
        let state = RawValue::from_string(state_json)
            .map_err(|e| Error::SyncStateEncodeError(e.to_string()))?;
        let envelope = LocalStateEnvelope {
            signature,
            state: &state,
        };
        serde_json::to_string_pretty(&envelope)
            .map_err(|e| Error::SyncStateEncodeError(e.to_string()))
    }

    /// Local sync state of the file contents `contents`, verified under the
    /// key of `signer` before the state is parsed. A newer format version is
    /// version skew, checked before the other fields.
    pub fn parse(contents: &str, signer: &dyn VaultSigner) -> Result<Self, LocalStateError> {
        let envelope: LocalStateEnvelope =
            serde_json::from_str(contents).map_err(|e| LocalStateError::Envelope(e.to_string()))?;
        let state_json = envelope.state.get();
        let key = signer
            .verifying_key()
            .map_err(LocalStateError::SigningKey)?;
        signing::verify(&key, &Self::signed_message(state_json), &envelope.signature)
            .map_err(|_| LocalStateError::SignatureInvalid)?;
        match FormatVersion::of(state_json.as_bytes()).map_err(LocalStateError::Malformed)? {
            SYNC_FORMAT_VERSION => {},
            newer if newer > SYNC_FORMAT_VERSION => {
                return Err(LocalStateError::VersionSkew(format!(
                    "format version {newer}"
                )));
            },
            older => {
                return Err(LocalStateError::Malformed(format!(
                    "format version {older}"
                )));
            },
        }
        serde_json::from_str(state_json).map_err(|e| LocalStateError::Malformed(e.to_string()))
    }

    /// Local sync state of vault `vault_id` under the app data directory
    /// `root`, verified under the key of `signer`.
    pub fn load(
        root: &Path,
        vault_id: Uuid,
        signer: &dyn VaultSigner,
    ) -> Result<Self, LocalStateError> {
        let contents = fs::read_to_string(Self::path(root, vault_id)).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                LocalStateError::Missing
            } else {
                LocalStateError::Read(e)
            }
        })?;
        Self::parse(&contents, signer)
    }

    /// Write this state, signed by `signer`, to its file under the app data
    /// directory `root`, replacing the file in one rename.
    pub fn save(&self, root: &Path, signer: &dyn VaultSigner) -> Result<(), Error> {
        let contents = self.to_file_contents(signer)?;
        let path = Self::path(root, self.vault_id);
        fs::create_dir_all(root.join(SYNC_DIR)).map_err(Error::SyncStateWriteError)?;
        write_atomic(&path, contents.as_bytes()).map_err(Error::SyncStateWriteError)
    }
}
