//! Streaming blob encryption: chunking, nonces, AAD, and hash checks.

use std::io::Cursor;

use uuid::Uuid;

use super::contents;
use crate::secrets::vaults::Error;
use crate::secrets::vaults::files::record::{FileHash, FileKey, FileRecord};
use crate::secrets::vaults::files::stream::{self, CHUNK_SIZE};

/// Sealed bytes of a full chunk.
const SEALED: usize = CHUNK_SIZE + 16;

fn vault_id() -> Uuid {
    Uuid::from_u128(1)
}

/// Blob of `plaintext` under a new key, and its record.
fn sealed(plaintext: &[u8]) -> (Vec<u8>, FileRecord) {
    let key = FileKey::generate();
    let mut blob = Vec::new();
    let sealed = stream::encrypt(&key, vault_id(), plaintext, &mut blob).unwrap();
    let record = FileRecord {
        blob: sealed.blob,
        key,
        sha256: sealed.sha256,
        size: sealed.size,
        name: "file".to_string(),
        mime: None,
    };
    (blob, record)
}

fn open(record: &FileRecord, blob: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    stream::decrypt(record, vault_id(), Cursor::new(blob), &mut out)?;
    Ok(out)
}

/// `record` with its blob name set to the hash of `blob`, so a changed blob
/// passes the hash check and reaches the decryption.
fn renamed(record: &FileRecord, blob: &[u8]) -> FileRecord {
    FileRecord {
        blob: FileHash::of(blob),
        ..record.clone()
    }
}

#[test]
fn round_trip_at_chunk_boundaries() {
    for len in [
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        3 * CHUNK_SIZE + 17,
    ] {
        let plaintext = contents(len);
        let (blob, record) = sealed(&plaintext);
        assert_eq!(record.size, len as u64);
        assert_eq!(record.sha256, FileHash::of(&plaintext));
        assert_eq!(record.blob, FileHash::of(&blob));
        assert_eq!(open(&record, &blob).unwrap(), plaintext, "{len}");
    }
}

#[test]
fn empty_file_is_one_empty_final_chunk() {
    let (blob, record) = sealed(&[]);
    assert_eq!(blob.len(), 16);
    assert_eq!(record.size, 0);
    assert_eq!(open(&record, &blob).unwrap(), Vec::<u8>::new());
}

#[test]
fn exact_multiple_of_chunk_size_ends_on_full_final_chunk() {
    let plaintext = contents(2 * CHUNK_SIZE);
    let (blob, record) = sealed(&plaintext);
    assert_eq!(blob.len(), 2 * SEALED);
    assert_eq!(open(&record, &blob).unwrap(), plaintext);

    // An empty final chunk appended after full chunks is refused.
    let mut padded = blob.clone();
    let key = record.key.clone();
    let mut tail = Vec::new();
    stream::encrypt(&key, vault_id(), &[][..], &mut tail).unwrap();
    padded.extend_from_slice(&tail);
    let err = open(&renamed(&record, &padded), &padded).unwrap_err();
    assert!(matches!(err, Error::FileDecryptionError), "{err}");
}

#[test]
fn truncated_stream_refused() {
    let plaintext = contents(3 * CHUNK_SIZE);
    let (blob, record) = sealed(&plaintext);

    for cut in [2 * SEALED, SEALED, SEALED + 100, blob.len() - 1, 10] {
        let truncated = &blob[..cut];
        let err = open(&record, truncated).unwrap_err();
        assert!(matches!(err, Error::FileBlobMismatch(_)), "{cut}: {err}");
        let err = open(&renamed(&record, truncated), truncated).unwrap_err();
        assert!(matches!(err, Error::FileDecryptionError), "{cut}: {err}");
    }
    let err = open(&renamed(&record, &[]), &[]).unwrap_err();
    assert!(matches!(err, Error::FileDecryptionError), "{err}");
}

#[test]
fn reordered_chunks_refused() {
    let plaintext = contents(3 * CHUNK_SIZE);
    let (blob, record) = sealed(&plaintext);
    let mut swapped = blob[SEALED..2 * SEALED].to_vec();
    swapped.extend_from_slice(&blob[..SEALED]);
    swapped.extend_from_slice(&blob[2 * SEALED..]);

    let err = open(&record, &swapped).unwrap_err();
    assert!(matches!(err, Error::FileBlobMismatch(_)), "{err}");
    let err = open(&renamed(&record, &swapped), &swapped).unwrap_err();
    assert!(matches!(err, Error::FileDecryptionError), "{err}");
}

#[test]
fn flipped_byte_refused() {
    let plaintext = contents(2 * CHUNK_SIZE + 5);
    let (blob, record) = sealed(&plaintext);
    for at in [0, SEALED - 1, SEALED + 3, blob.len() - 1] {
        let mut flipped = blob.clone();
        flipped[at] ^= 1;
        let err = open(&record, &flipped).unwrap_err();
        assert!(matches!(err, Error::FileBlobMismatch(_)), "{at}: {err}");
        let err = open(&renamed(&record, &flipped), &flipped).unwrap_err();
        assert!(matches!(err, Error::FileDecryptionError), "{at}: {err}");
    }
}

#[test]
fn wrong_vault_id_refused() {
    let (blob, record) = sealed(&contents(100));
    let mut out = Vec::new();
    let err =
        stream::decrypt(&record, Uuid::from_u128(2), Cursor::new(&blob), &mut out).unwrap_err();
    assert!(matches!(err, Error::FileDecryptionError), "{err}");
    assert!(out.is_empty());
}

#[test]
fn wrong_key_refused() {
    let (blob, record) = sealed(&contents(100));
    let other = FileRecord {
        key: FileKey::generate(),
        ..record
    };
    let err = open(&other, &blob).unwrap_err();
    assert!(matches!(err, Error::FileDecryptionError), "{err}");
}

#[test]
fn blob_hash_mismatch_refused_before_decrypting() {
    let (blob, record) = sealed(&contents(100));
    let other = FileRecord {
        blob: FileHash([0; 32]),
        ..record
    };
    let mut out = Vec::new();
    let err = stream::decrypt(&other, vault_id(), Cursor::new(&blob), &mut out).unwrap_err();
    assert!(matches!(err, Error::FileBlobMismatch(_)), "{err}");
    assert!(out.is_empty(), "nothing is decrypted before the hash check");
}

#[test]
fn plaintext_hash_or_size_mismatch_refused_after_decrypting() {
    let plaintext = contents(CHUNK_SIZE + 9);
    let (blob, record) = sealed(&plaintext);
    let other_hash = FileRecord {
        sha256: FileHash([0; 32]),
        ..record.clone()
    };
    let err = open(&other_hash, &blob).unwrap_err();
    assert!(matches!(err, Error::FileContentMismatch(_)), "{err}");

    let other_size = FileRecord {
        size: record.size + 1,
        ..record
    };
    let err = open(&other_size, &blob).unwrap_err();
    assert!(matches!(err, Error::FileContentMismatch(_)), "{err}");
}

#[test]
fn same_plaintext_under_new_keys_gives_different_blobs() {
    let plaintext = contents(10);
    let (first, a) = sealed(&plaintext);
    let (second, b) = sealed(&plaintext);
    assert_ne!(first, second);
    assert_ne!(a.blob, b.blob);
    assert_eq!(a.sha256, b.sha256);
}
