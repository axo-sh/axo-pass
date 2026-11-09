//! Tests of the pairing code, the pairing request, the pairing HMACs, the
//! new Mac side of pairing, and the unlocked Mac side: the prompt, the code
//! match, the dismissed requests, and the grant, and the pairing watcher.

mod code;
mod grant;
mod manager;
mod start;
mod verify;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::transport::FakeTransport;
use crate::core::auth::AuthContext;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::model::UnlockedKey;
use crate::secrets::vaults::storage::device_keys::VaultFiles;
use crate::secrets::vaults::storage::test_keys::TestKeys;
use crate::secrets::vaults::storage::txn::Unlock;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::{SyncKey, SyncKeyWrapper, TestKeyWrapper};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::pairing::request::PairingRequest;
use crate::secrets::vaults::sync::pairing::{PairKey, PairingCode, PendingPairing};
use crate::secrets::vaults::sync::transport::RequestId;
use crate::secrets::vaults::sync::wrapping::{
    DeviceUnwrap, DeviceWrapping, KeyFile, PairingKeys, Wrapping,
};

/// Name of the new Mac in the tests.
const NAME: &str = "New Mac";

/// Vault `n`.
fn vault(n: u128) -> Uuid {
    Uuid::from_u128(0x7000 + n)
}

/// Replica `n` of an unlocked Mac.
fn peer(n: u128) -> ReplicaId {
    ReplicaId(Uuid::from_u128(0x9000 + n))
}

/// Keys of the unlocked Mac that writes the wrappings.
fn sender_keys() -> ReplicaKeys {
    ReplicaKeys {
        encryption: PublicKey(vec![0xa1; 65]),
        signing: PublicKey(vec![0xb1; 65]),
    }
}

/// App data directory of the new Mac, in a temp directory.
struct NewMac {
    dir: TempDir,
    keys: TestKeys,
}

impl NewMac {
    /// Mac with no vault file and both keys present, whose public keys are
    /// `public`.
    fn with_public_keys(public: ReplicaKeys) -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            keys: TestKeys::both().with_public_keys(public),
        }
    }

    fn new() -> Self {
        Self::with_public_keys(ReplicaKeys {
            encryption: PublicKey(vec![0xe1; 65]),
            signing: PublicKey(vec![0x51; 65]),
        })
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn files(&self) -> VaultFiles {
        VaultFiles::new(self.root().join("vaults"), self.root(), Vec::new())
    }

    fn start(&self, transport: &FakeTransport, synced: &[Uuid]) -> Result<PendingPairing, Error> {
        PendingPairing::start(
            transport,
            &synced.iter().copied().collect(),
            &self.keys,
            &self.files(),
            AuthContext::OneTime,
            NAME,
        )
    }
}

/// Folder with a directory for each vault of `vaults`.
fn folder(vaults: &[Uuid]) -> FakeTransport {
    let transport = FakeTransport::default();
    for vault_id in vaults {
        transport.put_meta(*vault_id, b"{}");
    }
    transport
}

/// Pairing key that the unlocked Mac derives from the code the user typed.
pub(super) fn typed_key(pending: &PendingPairing) -> PairKey {
    PairingCode::parse(&pending.code().shown())
        .unwrap()
        .pair_key()
}

/// Wrapping of `key` under key id 1 to `to_replica`, from the keys of
/// `sender_keys`, with no MAC. The wrapped bytes are not a ciphertext, so
/// the tests unwrap with [`FixedUnwrap`].
fn wrapping(key: &SyncKey, to_replica: ReplicaId) -> DeviceWrapping {
    let from = sender_keys();
    DeviceWrapping {
        key_id: KeyId(1),
        key_fingerprint: key.fingerprint(),
        to_replica,
        from_encryption: from.encryption,
        from_signing: from.signing,
        wrapped: vec![0xc1, 0xc2, 0xc3],
        pairing_mac: None,
        signature: None,
        removed: None,
        remaining: None,
    }
}

/// Wrapping of `key` to the replica of `vault_id` in the request of
/// `pending`, sealed with the typed code, as `from_replica` writes it.
fn granted(
    pending: &PendingPairing,
    vault_id: Uuid,
    from_replica: ReplicaId,
    key: &SyncKey,
) -> DeviceWrapping {
    let request = pending.request();
    let mut wrapping = wrapping(key, request.replicas[&vault_id]);
    typed_key(pending).seal_wrapping(&mut wrapping, vault_id, from_replica, &request.keys());
    wrapping
}

/// `key.json` bytes that hold `wrappings`.
fn key_file(wrappings: Vec<DeviceWrapping>) -> Vec<u8> {
    KeyFile {
        wrappings: wrappings.into_iter().map(Wrapping::Device).collect(),
        invalid: Vec::new(),
    }
    .to_bytes()
}

/// Put a `key.json` with `wrappings` in the directory of `from_replica`.
fn put_key_file(
    transport: &FakeTransport,
    vault_id: Uuid,
    from_replica: ReplicaId,
    wrappings: Vec<DeviceWrapping>,
) {
    transport.put(vault_id, from_replica, "key.json", &key_file(wrappings));
}

/// Code of the fixed vectors, the bytes 0 to 9.
fn vector_code() -> PairingCode {
    PairingCode::from_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
}

/// Request of a new Mac with the keys `keys` for `vaults`, with one new
/// replica id each, under the pairing key of `code`.
fn request_with(code: &PairingCode, vaults: &[Uuid], keys: &ReplicaKeys) -> PairingRequest {
    PairingRequest::new(
        RequestId::generate(),
        vaults.iter().map(|v| (*v, ReplicaId::generate())).collect(),
        keys,
        NAME.to_string(),
        &code.pair_key(),
    )
}

/// [`request_with`] with fixed keys that are not P-256 points, for the
/// prompt tests, which wrap no key.
fn request_of(code: &PairingCode, vaults: &[Uuid]) -> PairingRequest {
    request_with(
        code,
        vaults,
        &ReplicaKeys {
            encryption: PublicKey(vec![0xe1; 65]),
            signing: PublicKey(vec![0x51; 65]),
        },
    )
}

/// Put `request` in the pairing directory under its own id.
fn put_request(transport: &FakeTransport, request: &PairingRequest) {
    transport.put_pairing(request.request_id, &request.to_bytes());
}

/// Pairing keys whose unwrap returns fixed bytes, or fails if it has none,
/// and counts its calls through a counter the test keeps. The keyring is
/// wrapped with [`TestKeyWrapper`], and the join of an import takes the file
/// key of `file_key`.
pub(super) struct SharedUnwrap {
    raw: Option<Vec<u8>>,
    calls: Arc<AtomicUsize>,
    file_key: Box<dyn Fn() -> UnlockedKey + Send + Sync>,
}

impl SharedUnwrap {
    /// Keys whose unwrap returns `key`, or fails if `None`, and whose join
    /// takes the file key of `file_key`.
    pub(super) fn new(
        key: Option<&SyncKey>,
        file_key: impl Fn() -> UnlockedKey + Send + Sync + 'static,
    ) -> Self {
        Self {
            raw: key.map(|key| key.as_bytes().to_vec()),
            calls: Arc::new(AtomicUsize::new(0)),
            file_key: Box::new(file_key),
        }
    }

    /// Keys that return `key`, or fail if `None`, and their call counter.
    /// The tests run no join with them.
    fn boxed(key: Option<&SyncKey>) -> (Box<dyn PairingKeys + Send>, Arc<AtomicUsize>) {
        let keys = Self::new(key, || panic!("the test runs no join"));
        let calls = keys.calls.clone();
        (Box::new(keys), calls)
    }
}

impl DeviceUnwrap for SharedUnwrap {
    fn unwrap_sync_key(&self, _wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.raw.clone().map(Zeroizing::new)
    }
}

impl SyncKeyWrapper for SharedUnwrap {
    fn wrap(&self, raw: &[u8]) -> Option<String> {
        TestKeyWrapper.wrap(raw)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        TestKeyWrapper.unwrap(wrapped)
    }
}

impl PairingKeys for SharedUnwrap {
    fn unlock(&self) -> Unlock<'_> {
        Unlock::Test(&*self.file_key)
    }
}
