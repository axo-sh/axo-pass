//! S3 transport against a fake client.

mod fake;

use std::sync::{Arc, mpsc};
use std::time::Duration;

use jiff::Timestamp;
use uuid::Uuid;

use self::fake::FakeS3;
use super::state_file::{VAULT, WRITER};
use super::transport::{
    SyncedFolder, deletes_replica_directory_and_leaves_others,
    lists_vaults_and_reads_and_writes_meta, reads_only_exact_state_file_names, request,
    writes_and_deletes_own_files_and_fails_while_unavailable,
};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::files::FileHash;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::transport::s3::client::{
    ListPage, ListRequest, ObjectInfo, S3Client,
};
use crate::secrets::vaults::sync::transport::s3::layout::KeyLayout;
use crate::secrets::vaults::sync::transport::s3::{
    DEFAULT_POLL_INTERVAL, S3Transport, test_connection_with,
};
use crate::secrets::vaults::sync::transport::{
    FileName, MAX_PAIRING_SIZE, ReadResult, SyncTransport, TransportRoot,
};

const PREFIX: &str = "team/ap";

/// Bucket in memory, read through an [`S3Transport`].
struct Bucket {
    fake: Arc<FakeS3>,
    layout: KeyLayout,
    transport: S3Transport,
}

impl Bucket {
    fn new() -> Self {
        let fake = Arc::new(FakeS3::default());
        Self {
            transport: S3Transport::new(fake.clone(), PREFIX),
            layout: KeyLayout::new(PREFIX),
            fake,
        }
    }

    /// Bucket whose transport polls at the shortest interval.
    fn polled() -> Self {
        let mut bucket = Self::new();
        bucket.transport = S3Transport::new(bucket.fake.clone(), PREFIX)
            .with_poll_interval(Duration::from_millis(1));
        bucket
    }

    /// Replica `n`.
    fn replica(n: u128) -> ReplicaId {
        ReplicaId(Uuid::from_u128(n))
    }

    /// Put the state file of `bytes` of `replica`. Returns its hash.
    fn state(&self, replica: ReplicaId, bytes: &[u8]) -> StateHash {
        let hash = StateHash::of(bytes);
        self.transport
            .write_own(VAULT, replica, FileName::State(hash), bytes)
            .unwrap();
        hash
    }
}

impl SyncedFolder for Bucket {
    fn transport(&self) -> &dyn SyncTransport {
        &self.transport
    }

    fn put(&self, vault_id: Uuid, replica: ReplicaId, name: &str, bytes: &[u8]) {
        let key = format!("{}{name}", self.layout.replica_dir(vault_id, replica));
        self.fake.insert(&key, bytes);
    }

    fn put_not_local(&self, _: Uuid, _: ReplicaId, _: &str, _: Option<&[u8]>) {
        unreachable!("an S3 object is never not local");
    }

    fn complete_downloads(&self, _: Uuid) -> usize {
        unreachable!("an S3 object is never not local");
    }

    fn download_requests(&self) -> Vec<Uuid> {
        unreachable!("an S3 object is never not local");
    }

    fn reads(&self) -> usize {
        self.fake.reads()
    }

    fn set_unavailable(&self, unavailable: bool) {
        self.fake.set_unavailable(unavailable);
    }

    fn set_failing_writes(&self, failing: bool) {
        self.fake.set_failing_writes(failing);
    }

    fn names(&self, vault_id: Uuid, replica: ReplicaId) -> Vec<String> {
        let dir = self.layout.replica_dir(vault_id, replica);
        self.fake
            .keys(&dir)
            .into_iter()
            .map(|key| key[dir.len()..].to_string())
            .collect()
    }

    fn meta(&self, vault_id: Uuid) -> Option<Vec<u8>> {
        self.fake.bytes(&self.layout.meta(vault_id))
    }
}

#[test]
fn exact_state_file_names_read() {
    reads_only_exact_state_file_names(&Bucket::new());
}

#[test]
fn own_files_written_deleted_and_failures_reported() {
    writes_and_deletes_own_files_and_fails_while_unavailable(&Bucket::new());
}

#[test]
fn vaults_listed_and_meta_read_and_written() {
    lists_vaults_and_reads_and_writes_meta(&Bucket::new());
}

#[test]
fn replica_directory_deleted_and_others_left() {
    deletes_replica_directory_and_leaves_others(&Bucket::new());
}

#[test]
fn objects_written_under_layout_keys() {
    let bucket = Bucket::new();
    let transport = &bucket.transport;
    let hash = StateHash::of(b"state");
    let blob = FileHash::of(b"blob");
    transport.write_meta(VAULT, b"{}").unwrap();
    transport
        .write_own(VAULT, WRITER, FileName::Key, b"key")
        .unwrap();
    transport
        .write_own(VAULT, WRITER, FileName::State(hash), b"state")
        .unwrap();
    transport.write_blob(VAULT, blob, b"blob").unwrap();
    transport.write_pairing(request(7), b"{}").unwrap();

    let vault = ShortId::encode_uuid(VAULT);
    let replica = ShortId::encode_uuid(WRITER.0);
    let mut expected = vec![
        format!("{PREFIX}/pairing/{}", request(7).file_name()),
        format!("{PREFIX}/vaults/{vault}/blobs/{blob}"),
        format!("{PREFIX}/vaults/{vault}/meta.json"),
        format!("{PREFIX}/vaults/{vault}/{replica}/key.json"),
        format!(
            "{PREFIX}/vaults/{vault}/{replica}/{}",
            StateFile::name(VAULT, hash)
        ),
    ];
    expected.sort();
    assert_eq!(bucket.fake.keys(""), expected);
}

#[test]
fn listings_follow_every_page() {
    let bucket = Bucket::new();
    bucket.fake.set_page_size(2);
    let transport = &bucket.transport;
    let replicas: Vec<ReplicaId> = (1..=7).map(Bucket::replica).collect();
    for replica in &replicas {
        bucket.state(*replica, replica.0.as_bytes());
    }
    for n in 0..5u128 {
        bucket.state(Bucket::replica(1), format!("extra {n}").as_bytes());
    }
    for n in 1..=5 {
        transport.write_pairing(request(n), b"{}").unwrap();
        transport
            .write_blob(VAULT, FileHash::of(&[n as u8]), &[n as u8; 3])
            .unwrap();
        transport
            .write_own(Uuid::from_u128(0x200 + n), WRITER, FileName::Key, b"key")
            .unwrap();
    }

    assert_eq!(transport.list_replicas(VAULT).unwrap(), replicas);
    assert_eq!(
        transport
            .list_states(VAULT, Bucket::replica(1))
            .unwrap()
            .len(),
        6
    );
    assert_eq!(transport.list_pairings().unwrap().len(), 5);
    let blobs = transport.list_blob_sizes(VAULT).unwrap();
    assert_eq!(blobs.len(), 5);
    assert!(blobs.iter().all(|(_, size)| *size == 3));
    assert_eq!(transport.list_blobs(VAULT).unwrap().len(), 5);
    assert_eq!(transport.list_vaults().unwrap().len(), 6);

    let before = bucket.fake.list_calls();
    transport.delete_replica(VAULT, Bucket::replica(1)).unwrap();
    assert!(bucket.fake.list_calls() - before >= 3);
    assert!(
        bucket
            .fake
            .keys(&bucket.layout.replica_dir(VAULT, Bucket::replica(1)))
            .is_empty()
    );
    assert_eq!(transport.list_replicas(VAULT).unwrap().len(), 6);
}

/// Client whose listing never ends: every page holds the same token.
#[derive(Debug)]
struct EndlessListing;

impl S3Client for EndlessListing {
    fn get(&self, _: &str, _: u64) -> Result<Option<Vec<u8>>, Error> {
        unreachable!()
    }

    fn head(&self, _: &str) -> Result<Option<ObjectInfo>, Error> {
        unreachable!()
    }

    fn put(&self, _: &str, _: &[u8]) -> Result<(), Error> {
        unreachable!()
    }

    fn delete(&self, _: &str) -> Result<(), Error> {
        unreachable!()
    }

    fn list_page(&self, _: &ListRequest) -> Result<ListPage, Error> {
        Ok(ListPage {
            next: Some("same".to_string()),
            ..ListPage::default()
        })
    }
}

#[test]
fn listing_that_repeats_its_token_ends() {
    let transport = S3Transport::new(Arc::new(EndlessListing), "");
    assert!(transport.list_vaults().unwrap().is_empty());
}

#[test]
fn read_finds_object_or_missing_and_never_remote() {
    let bucket = Bucket::new();
    let transport = &bucket.transport;
    let hash = bucket.state(WRITER, b"state");
    let name = FileName::State(hash);

    assert_eq!(
        transport.read(VAULT, WRITER, name).unwrap(),
        ReadResult::Local(b"state".to_vec())
    );
    assert_eq!(
        transport.read(VAULT, WRITER, FileName::Key).unwrap(),
        ReadResult::Missing
    );
    assert_eq!(transport.read_meta(VAULT).unwrap(), ReadResult::Missing);
    assert_eq!(
        transport.read_blob(VAULT, FileHash::of(b"x")).unwrap(),
        ReadResult::Missing
    );
    assert_eq!(
        transport.read_pairing(request(1)).unwrap(),
        ReadResult::Missing
    );
    assert!(transport.is_local(VAULT, WRITER, name).unwrap());
    assert!(!transport.is_local(VAULT, WRITER, FileName::Key).unwrap());
}

#[test]
fn download_requests_do_nothing() {
    let bucket = Bucket::new();
    bucket.state(WRITER, b"state");
    let blob = FileHash::of(b"blob");
    let calls = (
        bucket.fake.list_calls(),
        bucket.fake.reads(),
        bucket.fake.puts(),
    );

    bucket.transport.request_download(VAULT).unwrap();
    bucket.transport.request_blob_download(VAULT, blob).unwrap();

    assert_eq!(
        calls,
        (
            bucket.fake.list_calls(),
            bucket.fake.reads(),
            bucket.fake.puts()
        )
    );
}

#[test]
fn read_does_not_need_listing() {
    let bucket = Bucket::new();
    let key = bucket
        .layout
        .file(VAULT, WRITER, FileName::State(StateHash::of(b"state")));
    bucket.state(WRITER, b"state");
    bucket.fake.hide(&key);
    let hash = StateHash::of(b"state");

    assert!(
        bucket
            .transport
            .list_states(VAULT, WRITER)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        bucket
            .transport
            .read(VAULT, WRITER, FileName::State(hash))
            .unwrap(),
        ReadResult::Local(b"state".to_vec())
    );

    bucket.fake.show_all();
    assert_eq!(
        bucket.transport.list_states(VAULT, WRITER).unwrap(),
        vec![hash]
    );
}

#[test]
fn pairing_requests_listed_with_time_and_size_and_oversize_not_read() {
    let bucket = Bucket::new();
    let now: Timestamp = "2026-11-15T10:00:00Z".parse().unwrap();
    bucket.fake.set_now(now);
    let transport = &bucket.transport;
    transport.write_pairing(request(2), b"two").unwrap();
    transport.write_pairing(request(1), b"1").unwrap();
    let big = vec![0u8; MAX_PAIRING_SIZE as usize + 1];
    transport.write_pairing(request(3), &big).unwrap();
    let dir = bucket.layout.pairing_dir();
    for planted in ["x.json", "readme.txt", &format!("{}.JSON", request(4).0)] {
        bucket.fake.insert(&format!("{dir}{planted}"), b"planted");
    }

    let entries = transport.list_pairings().unwrap();

    let listed: Vec<_> = entries
        .iter()
        .map(|entry| (entry.id, entry.size, entry.modified))
        .collect();
    assert_eq!(
        listed,
        vec![
            (request(1), 1, now),
            (request(2), 3, now),
            (request(3), MAX_PAIRING_SIZE + 1, now)
        ]
    );
    assert_eq!(
        transport.read_pairing(request(2)).unwrap(),
        ReadResult::Local(b"two".to_vec())
    );
    assert!(transport.read_pairing(request(3)).is_err());

    transport.delete_pairing(request(2)).unwrap();
    transport.delete_pairing(request(2)).unwrap();
    assert_eq!(transport.list_pairings().unwrap().len(), 2);
}

#[test]
fn blob_write_keeps_existing_blob_and_delete_ignores_missing() {
    let bucket = Bucket::new();
    let transport = &bucket.transport;
    let blob = FileHash::of(b"blob");
    transport.write_blob(VAULT, blob, b"first").unwrap();
    transport.write_blob(VAULT, blob, b"second").unwrap();

    assert_eq!(
        transport.read_blob(VAULT, blob).unwrap(),
        ReadResult::Local(b"first".to_vec())
    );
    assert!(transport.is_blob_local(VAULT, blob).unwrap());
    assert_eq!(bucket.fake.puts().len(), 1);
    let dir = bucket.layout.blob_dir(VAULT);
    bucket.fake.insert(&format!("{dir}not-a-hash"), b"planted");
    assert_eq!(transport.list_blobs(VAULT).unwrap(), vec![blob]);

    transport.delete_blob(VAULT, blob).unwrap();
    transport.delete_blob(VAULT, blob).unwrap();
    assert!(!transport.is_blob_local(VAULT, blob).unwrap());
}

#[test]
fn blobs_directory_not_listed_as_replica() {
    let bucket = Bucket::new();
    bucket
        .transport
        .write_blob(VAULT, FileHash::of(b"blob"), b"blob")
        .unwrap();
    bucket.state(WRITER, b"state");

    assert_eq!(bucket.transport.list_replicas(VAULT).unwrap(), vec![WRITER]);
}

#[test]
fn poll_interval_defaults_to_60_seconds_and_is_set_with_minimum() {
    let transport = S3Transport::new(Arc::new(FakeS3::default()), "");
    assert_eq!(DEFAULT_POLL_INTERVAL, Duration::from_secs(60));
    assert_eq!(transport.poll_interval(), DEFAULT_POLL_INTERVAL);

    let transport = transport.with_poll_interval(Duration::from_secs(5));
    assert_eq!(transport.poll_interval(), Duration::from_secs(5));
    let transport = transport.with_poll_interval(Duration::ZERO);
    assert_eq!(transport.poll_interval(), Duration::from_secs(1));
}

/// Time that covers more than two polls at the shortest interval.
const QUIET: Duration = Duration::from_millis(2500);

/// Wait for a notification. Fails after ten seconds.
fn notified(receiver: &mpsc::Receiver<()>) {
    receiver.recv_timeout(Duration::from_secs(10)).unwrap();
}

#[test]
fn watch_notifies_for_own_vault_only_and_ends_on_drop() {
    let bucket = Bucket::polled();
    let (sender, receiver) = mpsc::channel();
    let handle = bucket
        .transport
        .watch(
            VAULT,
            Box::new(move || {
                let _ = sender.send(());
            }),
        )
        .unwrap();
    // The first listing notifies.
    notified(&receiver);

    bucket
        .transport
        .write_own(Uuid::from_u128(0x200), WRITER, FileName::Key, b"key")
        .unwrap();
    assert!(receiver.recv_timeout(QUIET).is_err());

    bucket
        .transport
        .write_own(VAULT, WRITER, FileName::Key, b"key")
        .unwrap();
    notified(&receiver);

    drop(handle);
    bucket
        .transport
        .write_own(VAULT, WRITER, FileName::Key, b"changed")
        .unwrap();
    assert!(receiver.recv_timeout(QUIET).is_err());
}

#[test]
fn watch_pairings_notifies_for_new_request() {
    let bucket = Bucket::polled();
    let (sender, receiver) = mpsc::channel();
    let _handle = bucket
        .transport
        .watch_pairings(Box::new(move || {
            let _ = sender.send(());
        }))
        .unwrap();
    notified(&receiver);

    bucket.transport.write_pairing(request(1), b"{}").unwrap();

    notified(&receiver);
}

#[test]
fn s3_root_serializes_with_name_only() {
    let root = TransportRoot::S3 {
        name: "work".to_string(),
    };

    let json = serde_json::to_string(&root).unwrap();

    assert_eq!(json, r#"{"kind":"S3","name":"work"}"#);
    assert_eq!(serde_json::from_str::<TransportRoot>(&json).unwrap(), root);
    assert_eq!(root.to_string(), "S3 location work");
}

#[test]
fn connection_test_leaves_no_probe_and_reports_attempts() {
    let fake = FakeS3::default();

    let report = test_connection_with(&fake, PREFIX, Duration::ZERO).unwrap();

    assert_eq!(report.list_attempts, 1);
    let puts = fake.puts();
    assert_eq!(puts.len(), 1);
    assert!(puts[0].starts_with(&format!("{PREFIX}/probe/")));
    assert!(fake.keys("").is_empty());
}

#[test]
fn connection_test_waits_for_late_listing() {
    let fake = FakeS3::default();
    fake.blind_lists(3);

    let report = test_connection_with(&fake, PREFIX, Duration::ZERO).unwrap();

    assert_eq!(report.list_attempts, 4);
    assert!(fake.keys("").is_empty());
}

#[test]
fn connection_test_fails_if_object_never_listed_and_deletes_probe() {
    let fake = FakeS3::default();
    fake.blind_lists(usize::MAX);

    let error = test_connection_with(&fake, PREFIX, Duration::ZERO).unwrap_err();

    assert!(matches!(error, Error::SyncTransportError(_)));
    assert!(fake.keys("").is_empty());
}

#[test]
fn connection_test_fails_if_writes_fail_or_bucket_unavailable() {
    let fake = FakeS3::default();
    fake.set_failing_writes(true);
    assert!(test_connection_with(&fake, PREFIX, Duration::ZERO).is_err());

    fake.set_failing_writes(false);
    fake.set_unavailable(true);
    assert!(test_connection_with(&fake, PREFIX, Duration::ZERO).is_err());
}
