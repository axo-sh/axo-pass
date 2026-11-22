//! S3 transport.
//!
//! The synced folder is a prefix of an S3-compatible bucket, such as AWS S3,
//! Cloudflare R2, Backblaze B2, or MinIO. The layout is in [`layout`].
//!
//! Every object is untrusted. Only the exact names of [`FileName`],
//! `meta.json`, [`FileHash`], and [`RequestId`] are listed or read. Only
//! directories with the exact short id of a UUID are listed as vaults and
//! replicas. A read returns the object or `Missing`, never `Remote`. Therefore
//! `request_download` and `request_blob_download` do nothing.
//!
//! Each write is a whole-object `PutObject`. The design needs no conditional
//! writes, locking, or ordering. A state file is named by its content hash,
//! so a second write of a name has the same bytes.
//!
//! List-after-write consistency is not assumed. AWS S3 is strongly
//! consistent. R2, B2, and MinIO are unverified. No call depends on a listing
//! that follows a write in the same process. A watch lists again at each
//! interval, so a late entry delays sync and does not omit it.

pub mod client;
pub mod config;
pub mod credentials;
pub mod layout;
pub mod poll;
pub mod probe;

use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use self::client::{HttpS3Client, ListRequest, ObjectInfo, S3Client};
pub use self::config::S3Config;
use self::layout::KeyLayout;
use self::poll::PollWatch;
pub use self::probe::{ConnectionReport, test_connection, test_connection_with};
use super::{
    FileName, MAX_PAIRING_SIZE, PairingEntry, ReadResult, RequestId, SyncTransport, WatchHandle,
};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::FileHash;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::state_file::StateHash;

/// Interval of a vault watch if none is set. Each poll is one LIST request
/// per page on every device. The user cannot change it yet. Watches poll
/// at the same interval while the app is in the background, where a slower
/// interval would cost less.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Interval of the pairing watch if none is set. It is shorter than the
/// vault interval, so the unlocked device sees a pairing request quickly.
pub const DEFAULT_PAIRING_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Shortest interval of a watch.
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Object of a directory listing, with its name in the directory.
type NamedObject = (String, ObjectInfo);

/// Entries of a directory listing. Contains the objects and the directory
/// names.
struct DirEntries {
    objects: Vec<ObjectInfo>,
    dirs: Vec<String>,
}

/// Transport of a prefix in an S3 bucket. Objects are read and written
/// through an [`S3Client`].
#[derive(Debug)]
pub struct S3Transport {
    client: Arc<dyn S3Client>,
    layout: KeyLayout,
    poll_interval: Duration,
    pairing_poll_interval: Duration,
}

impl S3Transport {
    /// Transport of the bucket in `config`, over HTTP.
    pub fn connect(config: &S3Config) -> Result<Self, Error> {
        let client = HttpS3Client::new(config)?;
        Ok(Self::new(Arc::new(client), &config.prefix))
    }

    /// Transport of `prefix`, with object access `client`.
    pub fn new(client: Arc<dyn S3Client>, prefix: &str) -> Self {
        Self {
            client,
            layout: KeyLayout::new(prefix),
            poll_interval: DEFAULT_POLL_INTERVAL,
            pairing_poll_interval: DEFAULT_PAIRING_POLL_INTERVAL,
        }
    }

    /// Set the interval of the vault and pairing watches started later. At
    /// least one second.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval.max(MIN_POLL_INTERVAL);
        self.pairing_poll_interval = self.poll_interval;
        self
    }

    /// Interval of the vault watches.
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Interval of the pairing watch.
    pub fn pairing_poll_interval(&self) -> Duration {
        self.pairing_poll_interval
    }

    /// Every page of a listing, in key order. A page that repeats its own
    /// token ends the listing.
    fn list_all(client: &dyn S3Client, prefix: &str, delimiter: bool) -> Result<DirEntries, Error> {
        let mut entries = DirEntries {
            objects: Vec::new(),
            dirs: Vec::new(),
        };
        let mut request = ListRequest {
            prefix: prefix.to_string(),
            delimiter,
            continuation: None,
        };
        loop {
            let page = client.list_page(&request)?;
            entries.objects.extend(page.objects);
            entries.dirs.extend(page.prefixes);
            match page.next {
                Some(token) if request.continuation.as_ref() != Some(&token) => {
                    request.continuation = Some(token);
                },
                _ => break,
            }
        }
        Ok(entries)
    }

    /// Entries directly under the directory key `dir`, which ends in `/`.
    /// Object names and directory names are relative to `dir`. An entry that
    /// is not under `dir`, or whose name is empty, is left out.
    fn list_dir(&self, dir: &str) -> Result<(Vec<NamedObject>, Vec<String>), Error> {
        let entries = Self::list_all(self.client.as_ref(), dir, true)?;
        let objects = entries
            .objects
            .into_iter()
            .filter_map(|object| {
                let name = object.key.strip_prefix(dir)?.to_string();
                (!name.is_empty() && !name.contains('/')).then_some((name, object))
            })
            .collect();
        let dirs = entries
            .dirs
            .iter()
            .filter_map(|prefix| prefix.strip_prefix(dir)?.strip_suffix('/'))
            .map(str::to_string)
            .collect();
        Ok((objects, dirs))
    }

    /// Ids of the directories under `dir` named by a short id, in order.
    fn short_id_dirs(&self, dir: &str) -> Result<Vec<Uuid>, Error> {
        let (_, dirs) = self.list_dir(dir)?;
        let mut ids: Vec<Uuid> = dirs
            .iter()
            .filter_map(|name| KeyLayout::parse_short_id(name))
            .collect();
        ids.sort();
        Ok(ids)
    }

    fn read_object(&self, key: &str, limit: u64) -> Result<ReadResult, Error> {
        Ok(match self.client.get(key, limit)? {
            Some(bytes) => ReadResult::Local(bytes),
            None => ReadResult::Missing,
        })
    }

    fn exists(&self, key: &str) -> Result<bool, Error> {
        Ok(self.client.head(key)?.is_some())
    }

    /// Watch of the objects under `dir`, listed every `interval`. The listing
    /// of each interval is compared with the last one.
    fn watch_dir(
        &self,
        vault_id: Option<Uuid>,
        dir: String,
        interval: Duration,
        notify: Box<dyn Fn() + Send>,
    ) -> Option<WatchHandle> {
        let client = self.client.clone();
        PollWatch::start(
            vault_id,
            interval,
            move || Ok(Self::list_all(client.as_ref(), &dir, false)?.objects),
            notify,
        )
    }
}

impl SyncTransport for S3Transport {
    fn list_replicas(&self, vault_id: Uuid) -> Result<Vec<ReplicaId>, Error> {
        let ids = self.short_id_dirs(&self.layout.vault_dir(vault_id))?;
        Ok(ids.into_iter().map(ReplicaId).collect())
    }

    fn list_vaults(&self) -> Result<Vec<Uuid>, Error> {
        self.short_id_dirs(&self.layout.vaults_dir())
    }

    fn list_states(&self, vault_id: Uuid, replica: ReplicaId) -> Result<Vec<StateHash>, Error> {
        let (objects, _) = self.list_dir(&self.layout.replica_dir(vault_id, replica))?;
        let mut hashes: Vec<StateHash> = objects
            .iter()
            .filter_map(|(name, _)| FileName::parse_state(name))
            .collect();
        hashes.sort();
        Ok(hashes)
    }

    fn read(
        &self,
        vault_id: Uuid,
        replica: ReplicaId,
        name: FileName,
    ) -> Result<ReadResult, Error> {
        self.read_object(&self.layout.file(vault_id, replica, name), u64::MAX)
    }

    fn is_local(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> Result<bool, Error> {
        self.exists(&self.layout.file(vault_id, replica, name))
    }

    fn read_meta(&self, vault_id: Uuid) -> Result<ReadResult, Error> {
        self.read_object(&self.layout.meta(vault_id), u64::MAX)
    }

    fn write_meta(&self, vault_id: Uuid, data: &[u8]) -> Result<(), Error> {
        self.client.put(&self.layout.meta(vault_id), data)
    }

    fn write_own(
        &self,
        vault_id: Uuid,
        replica: ReplicaId,
        name: FileName,
        data: &[u8],
    ) -> Result<(), Error> {
        self.client
            .put(&self.layout.file(vault_id, replica, name), data)
    }

    fn delete_own(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> Result<(), Error> {
        self.client
            .delete(&self.layout.file(vault_id, replica, name))
    }

    /// Delete every object under the replica directory. The keys are listed
    /// first and then deleted.
    fn delete_replica(&self, vault_id: Uuid, replica: ReplicaId) -> Result<(), Error> {
        let dir = self.layout.replica_dir(vault_id, replica);
        let entries = Self::list_all(self.client.as_ref(), &dir, false)?;
        for object in entries.objects {
            self.client.delete(&object.key)?;
        }
        Ok(())
    }

    /// Does nothing, since no object is ever not local.
    fn request_download(&self, _vault_id: Uuid) -> Result<(), Error> {
        Ok(())
    }

    /// Poll the vault directory at the vault poll interval and call `notify`
    /// if its listing changes. `notify` is also called after the first
    /// listing, so a watch started at unlock polls at unlock.
    ///
    /// The listing is recursive, so it includes the blobs under `blobs/` of
    /// the vault. The watch does not need them, since a blob is read by its
    /// key only when a state file references it. A vault with more than 1,000
    /// objects costs one LIST request per page at each poll. A layout with the
    /// blobs outside the vault prefix would limit each poll to one request.
    fn watch(&self, vault_id: Uuid, notify: Box<dyn Fn() + Send>) -> Option<WatchHandle> {
        self.watch_dir(
            Some(vault_id),
            self.layout.vault_dir(vault_id),
            self.poll_interval,
            notify,
        )
    }

    fn list_pairings(&self) -> Result<Vec<PairingEntry>, Error> {
        let (objects, _) = self.list_dir(&self.layout.pairing_dir())?;
        let mut entries: Vec<PairingEntry> = objects
            .into_iter()
            .filter_map(|(name, object)| {
                Some(PairingEntry {
                    id: RequestId::parse_file_name(&name)?,
                    modified: object.modified,
                    size: object.size,
                })
            })
            .collect();
        entries.sort_by_key(|entry| entry.id);
        Ok(entries)
    }

    /// Read a pairing request. A request larger than [`MAX_PAIRING_SIZE`]
    /// fails.
    fn read_pairing(&self, request: RequestId) -> Result<ReadResult, Error> {
        self.read_object(&self.layout.pairing(request), MAX_PAIRING_SIZE)
    }

    fn write_pairing(&self, request: RequestId, data: &[u8]) -> Result<(), Error> {
        self.client.put(&self.layout.pairing(request), data)
    }

    fn delete_pairing(&self, request: RequestId) -> Result<(), Error> {
        self.client.delete(&self.layout.pairing(request))
    }

    /// Poll `pairing/` at the pairing poll interval and call `notify` if its
    /// listing changes.
    fn watch_pairings(&self, notify: Box<dyn Fn() + Send>) -> Option<WatchHandle> {
        self.watch_dir(
            None,
            self.layout.pairing_dir(),
            self.pairing_poll_interval,
            notify,
        )
    }

    fn list_blobs(&self, vault_id: Uuid) -> Result<Vec<FileHash>, Error> {
        Ok(self
            .list_blob_sizes(vault_id)?
            .into_iter()
            .map(|(blob, _)| blob)
            .collect())
    }

    fn list_blob_sizes(&self, vault_id: Uuid) -> Result<Vec<(FileHash, u64)>, Error> {
        let (objects, _) = self.list_dir(&self.layout.blob_dir(vault_id))?;
        let mut blobs: Vec<(FileHash, u64)> = objects
            .into_iter()
            .filter_map(|(name, object)| Some((FileHash::parse(&name)?, object.size)))
            .collect();
        blobs.sort();
        Ok(blobs)
    }

    fn read_blob(&self, vault_id: Uuid, blob: FileHash) -> Result<ReadResult, Error> {
        self.read_object(&self.layout.blob(vault_id, blob), u64::MAX)
    }

    /// Write a blob with a new name. A blob that exists under the name is
    /// not overwritten. The check and the write are not atomic, and a second
    /// writer of the name writes the same bytes.
    fn write_blob(&self, vault_id: Uuid, blob: FileHash, data: &[u8]) -> Result<(), Error> {
        let key = self.layout.blob(vault_id, blob);
        if self.exists(&key)? {
            return Ok(());
        }
        self.client.put(&key, data)
    }

    fn is_blob_local(&self, vault_id: Uuid, blob: FileHash) -> Result<bool, Error> {
        self.exists(&self.layout.blob(vault_id, blob))
    }

    fn delete_blob(&self, vault_id: Uuid, blob: FileHash) -> Result<(), Error> {
        self.client.delete(&self.layout.blob(vault_id, blob))
    }

    /// Does nothing, since no object is ever not local.
    fn request_blob_download(&self, _vault_id: Uuid, _blob: FileHash) -> Result<(), Error> {
        Ok(())
    }
}
