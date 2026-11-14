//! Streaming encryption of file contents.
//!
//! AES-GCM verifies its tag only after the whole message. A file sealed as
//! one message would have to be held in memory until the tag verifies, or
//! written out unverified. A file is therefore sealed in chunks. Encryption
//! and decryption hold two chunks at a time, whatever the file size. Each
//! chunk is verified before its plaintext is written. Per-chunk messages
//! also stay far below the AES-GCM limit of about 64 GiB per message.
//!
//! Contents are split into chunks of [`CHUNK_SIZE`] bytes and each chunk is
//! sealed with AES-256-GCM under the per-file key. The 12-byte nonce of a
//! chunk is its index as 11 bytes big endian, then 1 for the final chunk and
//! 0 for any other. Only the final chunk may be shorter than [`CHUNK_SIZE`].
//! It is empty only if the file is empty. The AAD of every chunk is
//! `ap-file-v1:{vault id}`, with the vault id in the hyphenated form. A blob
//! is the sealed chunks in order, with no header.
//!
//! A reordered chunk fails its tag under the nonce of its position. A stream
//! cut at a chunk boundary ends on a chunk sealed as not final, which fails
//! its tag when opened as final.

use std::io::{self, Read, Seek, SeekFrom, Write};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::record::{FileHash, FileKey, FileRecord};
use crate::secrets::vaults::errors::Error;

/// Plaintext bytes per chunk. The chunk size of age's STREAM construction,
/// which this format follows. The tag adds 0.02% per full chunk, and most
/// small files fit in one chunk.
pub(crate) const CHUNK_SIZE: usize = 64 * 1024;

/// AES-GCM tag bytes per chunk.
const TAG_SIZE: usize = 16;

/// Sealed bytes of a full chunk.
const SEALED_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

/// Prefix of the AAD of every chunk.
const AAD_PREFIX: &str = "ap-file-v1";

/// Bytes of the chunk index in the nonce.
const INDEX_BYTES: usize = 11;

/// Hashes and plaintext size of an encrypted stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sealed {
    /// SHA-256 of the ciphertext, the blob name.
    pub(crate) blob: FileHash,
    /// SHA-256 of the plaintext.
    pub(crate) sha256: FileHash,
    /// Plaintext size in bytes.
    pub(crate) size: u64,
}

fn aad(vault_id: Uuid) -> Vec<u8> {
    format!("{AAD_PREFIX}:{vault_id}").into_bytes()
}

/// Nonce of chunk `index`. Fails if the index does not fit in 11 bytes.
fn nonce(index: u128, last: bool) -> Result<[u8; 12], Error> {
    if index >> (INDEX_BYTES * 8) != 0 {
        return Err(Error::FileTooLarge);
    }
    let mut nonce = [0u8; 12];
    nonce[..INDEX_BYTES].copy_from_slice(&index.to_be_bytes()[16 - INDEX_BYTES..]);
    nonce[INDEX_BYTES] = u8::from(last);
    Ok(nonce)
}

/// Fill `buf` from `input` until it is full or `input` ends. Returns the
/// bytes read.
fn read_full(input: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {},
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Encrypt `input` under `key` for vault `vault_id` and write the blob to
/// `output`. Returns the ciphertext hash, the plaintext hash, and the size.
pub(crate) fn encrypt(
    key: &FileKey,
    vault_id: Uuid,
    mut input: impl Read,
    mut output: impl Write,
) -> Result<Sealed, Error> {
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let aad = aad(vault_id);
    let mut blob_hash = Sha256::new();
    let mut plain_hash = Sha256::new();
    let mut size = 0u64;
    let mut current = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut next = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut len = read_full(&mut input, &mut current).map_err(Error::FileReadError)?;
    let mut index = 0u128;
    loop {
        // A full chunk is final only if no byte follows it.
        let next_len = if len == CHUNK_SIZE {
            read_full(&mut input, &mut next).map_err(Error::FileReadError)?
        } else {
            0
        };
        let last = next_len == 0;
        let chunk = &current[..len];
        plain_hash.update(chunk);
        size += len as u64;
        let nonce = nonce(index, last)?;
        let sealed = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::FileEncryptionError)?;
        blob_hash.update(&sealed);
        output.write_all(&sealed).map_err(Error::FileWriteError)?;
        if last {
            break;
        }
        std::mem::swap(&mut current, &mut next);
        len = next_len;
        index += 1;
    }
    output.flush().map_err(Error::FileWriteError)?;
    Ok(Sealed {
        blob: FileHash(blob_hash.finalize().into()),
        sha256: FileHash(plain_hash.finalize().into()),
        size,
    })
}

/// Fail with `FileBlobMismatch` unless the bytes of `input` hash to `blob`.
pub(crate) fn check_blob(mut input: impl Read, blob: &FileHash) -> Result<(), Error> {
    let mut hash = Sha256::new();
    io::copy(&mut input, &mut hash).map_err(Error::FileReadError)?;
    let actual = FileHash(hash.finalize().into());
    if actual != *blob {
        return Err(Error::FileBlobMismatch(blob.to_string()));
    }
    Ok(())
}

/// Decrypt the blob `input` of `record` for vault `vault_id` to `output`.
///
/// The ciphertext hash is checked against `record.blob` before any chunk is
/// decrypted. The plaintext hash and size are checked against the record
/// after the last chunk. Every chunk is authenticated before it is written,
/// but `output` holds a prefix of the file if a later check fails, so the
/// caller discards it on any error.
pub(crate) fn decrypt(
    record: &FileRecord,
    vault_id: Uuid,
    mut input: impl Read + Seek,
    mut output: impl Write,
) -> Result<(), Error> {
    check_blob(&mut input, &record.blob)?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(Error::FileReadError)?;

    let cipher = Aes256Gcm::new(record.key.as_bytes().into());
    let aad = aad(vault_id);
    let mut plain_hash = Sha256::new();
    let mut size = 0u64;
    let mut current = vec![0u8; SEALED_SIZE];
    let mut next = vec![0u8; SEALED_SIZE];
    let mut len = read_full(&mut input, &mut current).map_err(Error::FileReadError)?;
    let mut index = 0u128;
    loop {
        if len < TAG_SIZE {
            return Err(Error::FileDecryptionError);
        }
        // A full chunk is final only if no byte follows it.
        let next_len = if len == SEALED_SIZE {
            read_full(&mut input, &mut next).map_err(Error::FileReadError)?
        } else {
            0
        };
        let last = next_len == 0;
        let nonce = nonce(index, last)?;
        let chunk = Zeroizing::new(
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &current[..len],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::FileDecryptionError)?,
        );
        // An empty final chunk after other chunks is not the encoding of any
        // file.
        if last && chunk.is_empty() && index > 0 {
            return Err(Error::FileDecryptionError);
        }
        plain_hash.update(&chunk[..]);
        size += chunk.len() as u64;
        output.write_all(&chunk).map_err(Error::FileWriteError)?;
        if last {
            break;
        }
        std::mem::swap(&mut current, &mut next);
        len = next_len;
        index += 1;
    }
    output.flush().map_err(Error::FileWriteError)?;
    let sha256 = FileHash(plain_hash.finalize().into());
    if sha256 != record.sha256 || size != record.size {
        return Err(Error::FileContentMismatch(record.blob.to_string()));
    }
    Ok(())
}
