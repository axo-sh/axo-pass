//! Fake S3 client that holds a bucket in memory.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use jiff::Timestamp;

use crate::secrets::vaults::Error;
use crate::secrets::vaults::sync::transport::s3::client::{
    ListPage, ListRequest, ObjectInfo, S3Client,
};

/// Bucket in memory. A listing has pages of `page_size` entries, where an
/// object and a common prefix are each one entry, as in S3. The bucket can
/// be made unavailable, writes can be made to fail, and a key can be hidden
/// from listings, as on a provider that lists late.
#[derive(Debug)]
pub(super) struct FakeS3 {
    inner: Mutex<Bucket>,
}

#[derive(Debug)]
struct Bucket {
    objects: BTreeMap<String, Vec<u8>>,
    modified: Timestamp,
    page_size: usize,
    unavailable: bool,
    failing_writes: bool,
    hidden: BTreeSet<String>,
    /// Count of next listings that show nothing.
    blind_lists: usize,
    /// Keys of the successful puts, in order.
    puts: Vec<String>,
    /// Count of calls of `list_page`.
    list_calls: usize,
    /// Count of reads that returned an object.
    reads: usize,
}

/// Entry of a listing, ordered by its key or common prefix.
#[derive(Debug)]
enum Entry {
    Object(String),
    Prefix(String),
}

impl Entry {
    fn sort_key(&self) -> &str {
        match self {
            Self::Object(key) | Self::Prefix(key) => key,
        }
    }
}

impl Default for FakeS3 {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Bucket {
                objects: BTreeMap::new(),
                modified: Timestamp::UNIX_EPOCH,
                page_size: 1000,
                unavailable: false,
                failing_writes: false,
                hidden: BTreeSet::new(),
                blind_lists: 0,
                puts: Vec::new(),
                list_calls: 0,
                reads: 0,
            }),
        }
    }
}

impl FakeS3 {
    /// Set the entries of a listing page.
    pub(super) fn set_page_size(&self, size: usize) {
        self.inner.lock().unwrap().page_size = size;
    }

    pub(super) fn set_unavailable(&self, unavailable: bool) {
        self.inner.lock().unwrap().unavailable = unavailable;
    }

    /// Make every put and delete fail.
    pub(super) fn set_failing_writes(&self, failing: bool) {
        self.inner.lock().unwrap().failing_writes = failing;
    }

    /// Set the modification time of the objects put next.
    pub(super) fn set_now(&self, now: Timestamp) {
        self.inner.lock().unwrap().modified = now;
    }

    /// Leave `key` out of listings. Reads still find it.
    pub(super) fn hide(&self, key: &str) {
        self.inner.lock().unwrap().hidden.insert(key.to_string());
    }

    /// Make the next `count` listings show nothing.
    pub(super) fn blind_lists(&self, count: usize) {
        self.inner.lock().unwrap().blind_lists = count;
    }

    pub(super) fn show_all(&self) {
        self.inner.lock().unwrap().hidden.clear();
    }

    /// Put `bytes` at `key`, as another writer.
    pub(super) fn insert(&self, key: &str, bytes: &[u8]) {
        self.inner
            .lock()
            .unwrap()
            .objects
            .insert(key.to_string(), bytes.to_vec());
    }

    pub(super) fn bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().objects.get(key).cloned()
    }

    /// Keys that start with `prefix`, in order.
    pub(super) fn keys(&self, prefix: &str) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .objects
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect()
    }

    pub(super) fn puts(&self) -> Vec<String> {
        self.inner.lock().unwrap().puts.clone()
    }

    pub(super) fn list_calls(&self) -> usize {
        self.inner.lock().unwrap().list_calls
    }

    pub(super) fn reads(&self) -> usize {
        self.inner.lock().unwrap().reads
    }

    fn down() -> Error {
        Error::SyncTransportError("bucket unavailable".to_string())
    }

    fn info(key: &str, bytes: &[u8], modified: Timestamp) -> ObjectInfo {
        ObjectInfo {
            key: key.to_string(),
            size: bytes.len() as u64,
            modified,
            etag: String::new(),
        }
    }
}

impl S3Client for FakeS3 {
    fn get(&self, key: &str, limit: u64) -> Result<Option<Vec<u8>>, Error> {
        let mut bucket = self.inner.lock().unwrap();
        if bucket.unavailable {
            return Err(Self::down());
        }
        let Some(bytes) = bucket.objects.get(key).cloned() else {
            return Ok(None);
        };
        if bytes.len() as u64 > limit {
            return Err(Error::SyncTransportError(format!(
                "Failed to read {key}: larger than {limit} bytes"
            )));
        }
        bucket.reads += 1;
        Ok(Some(bytes))
    }

    fn head(&self, key: &str) -> Result<Option<ObjectInfo>, Error> {
        let bucket = self.inner.lock().unwrap();
        if bucket.unavailable {
            return Err(Self::down());
        }
        Ok(bucket
            .objects
            .get(key)
            .map(|bytes| Self::info(key, bytes, bucket.modified)))
    }

    fn put(&self, key: &str, data: &[u8]) -> Result<(), Error> {
        let mut bucket = self.inner.lock().unwrap();
        if bucket.unavailable || bucket.failing_writes {
            return Err(Self::down());
        }
        bucket.objects.insert(key.to_string(), data.to_vec());
        bucket.puts.push(key.to_string());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        let mut bucket = self.inner.lock().unwrap();
        if bucket.unavailable || bucket.failing_writes {
            return Err(Self::down());
        }
        bucket.objects.remove(key);
        Ok(())
    }

    fn list_page(&self, request: &ListRequest) -> Result<ListPage, Error> {
        let mut bucket = self.inner.lock().unwrap();
        bucket.list_calls += 1;
        if bucket.unavailable {
            return Err(Self::down());
        }
        if bucket.blind_lists > 0 {
            bucket.blind_lists -= 1;
            return Ok(ListPage::default());
        }
        let mut entries: Vec<Entry> = Vec::new();
        for key in bucket.objects.keys() {
            let Some(rest) = key.strip_prefix(&request.prefix) else {
                continue;
            };
            if bucket.hidden.contains(key) {
                continue;
            }
            match rest.find('/').filter(|_| request.delimiter) {
                Some(slash) => {
                    let prefix = format!("{}{}", request.prefix, &rest[..=slash]);
                    if !matches!(entries.last(), Some(Entry::Prefix(last)) if *last == prefix) {
                        entries.push(Entry::Prefix(prefix));
                    }
                },
                None => entries.push(Entry::Object(key.clone())),
            }
        }
        let after = request.continuation.as_deref().unwrap_or("");
        let mut rest = entries
            .into_iter()
            .filter(|entry| request.continuation.is_none() || entry.sort_key() > after);
        let page: Vec<Entry> = rest.by_ref().take(bucket.page_size).collect();
        let next = (rest.next().is_some())
            .then(|| page.last().map(|entry| entry.sort_key().to_string()))
            .flatten();
        let mut listed = ListPage {
            next,
            ..ListPage::default()
        };
        for entry in page {
            match entry {
                Entry::Object(key) => {
                    let bytes = &bucket.objects[&key];
                    listed
                        .objects
                        .push(Self::info(&key, bytes, bucket.modified));
                },
                Entry::Prefix(prefix) => listed.prefixes.push(prefix),
            }
        }
        Ok(listed)
    }
}
