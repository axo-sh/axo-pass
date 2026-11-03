//! Padded body: the plaintext that state files and the local sync state
//! encrypt.
//!
//! The padded body is the length of the compressed body as a big-endian
//! `u32`, the compressed body as a raw DEFLATE stream at level 6, and zero
//! bytes up to the size bucket. Buckets are `round(2^(i/4) * 1024)` bytes for
//! whole `i` from 24, so the smallest bucket is 64 KiB and each bucket is at
//! most 19% larger than the one below it.

use std::io::Write;

use flate2::write::DeflateEncoder;
use flate2::{Compression, Decompress, FlushDecompress, Status};
use thiserror::Error;
use zeroize::Zeroizing;

use super::body::StateBody;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::sync::crdt::CausalState;
use crate::secrets::vaults::sync::model::SyncState;

/// Largest inflated body a reader accepts: 64 MiB.
pub const MAX_BODY_LEN: usize = 64 * 1024 * 1024;

/// Exponent of the smallest bucket, 2^(24/4) KiB = 64 KiB.
const FIRST_BUCKET: i32 = 24;

/// DEFLATE compression level.
const LEVEL: u32 = 6;

/// Length of the length prefix.
const PREFIX_LEN: usize = 4;

/// Bytes added to the inflate buffer at a time.
const INFLATE_CHUNK: usize = 64 * 1024;

/// Failure to read a padded body.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PaddingError {
    #[error("padded body length prefix is past the end of the plaintext")]
    LengthPrefix,
    #[error("padded body holds a nonzero padding byte")]
    NonzeroPadding,
    #[error("state body inflates past {MAX_BODY_LEN} bytes")]
    TooLarge,
    #[error("compressed state body is not a valid DEFLATE stream: {0}")]
    Inflate(String),
}

/// Compression and padding of a CBOR body.
pub struct PaddedBody;

impl PaddedBody {
    /// Padded body of `state`.
    pub fn of(state: &CausalState<SyncState>) -> Result<Zeroizing<Vec<u8>>, Error> {
        let body = StateBody::encode(state)
            .map(Zeroizing::new)
            .map_err(|e| Error::SyncStateEncodeError(e.to_string()))?;
        Self::pad(&body)
    }

    /// Padded body of the CBOR body `body`. Fails for a body above
    /// [`MAX_BODY_LEN`], which no reader accepts.
    pub fn pad(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if body.len() > MAX_BODY_LEN {
            let len = body.len();
            return Err(Error::SyncStateEncodeError(format!(
                "state body of {len} bytes is above {MAX_BODY_LEN} bytes"
            )));
        }
        let compressed = Self::deflate(body)?;
        let prefix = u32::try_from(compressed.len())
            .expect("DEFLATE of at most 64 MiB is below 4 GiB")
            .to_be_bytes();
        let size = Self::bucket(PREFIX_LEN + compressed.len());
        let mut padded = Zeroizing::new(Vec::with_capacity(size));
        padded.extend_from_slice(&prefix);
        padded.extend_from_slice(&compressed);
        padded.resize(size, 0);
        Ok(padded)
    }

    /// CBOR body of the padded body `padded`. Fails if the length prefix is
    /// past the end, a padding byte is not zero, the stream is not one
    /// complete DEFLATE stream, or it inflates past [`MAX_BODY_LEN`].
    pub fn unpad(padded: &[u8]) -> Result<Zeroizing<Vec<u8>>, PaddingError> {
        let (prefix, rest) = padded
            .split_first_chunk::<PREFIX_LEN>()
            .ok_or(PaddingError::LengthPrefix)?;
        let len =
            usize::try_from(u32::from_be_bytes(*prefix)).map_err(|_| PaddingError::LengthPrefix)?;
        if len > rest.len() {
            return Err(PaddingError::LengthPrefix);
        }
        let (compressed, padding) = rest.split_at(len);
        if padding.iter().any(|byte| *byte != 0) {
            return Err(PaddingError::NonzeroPadding);
        }
        Self::inflate(compressed)
    }

    /// Smallest bucket that holds `len` bytes.
    pub fn bucket(len: usize) -> usize {
        (FIRST_BUCKET..)
            .map(|i| (2f64.powf(f64::from(i) / 4.0) * 1024.0).round() as usize)
            .find(|size| *size >= len)
            .expect("buckets grow past any length")
    }

    /// Raw DEFLATE stream of `body` at [`LEVEL`].
    fn deflate(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let encode_error = |e: std::io::Error| Error::SyncStateEncodeError(e.to_string());
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(LEVEL));
        encoder.write_all(body).map_err(encode_error)?;
        encoder.finish().map(Zeroizing::new).map_err(encode_error)
    }

    /// Inflated bytes of the raw DEFLATE stream `compressed`. The stream must
    /// end exactly at the end of `compressed`.
    fn inflate(compressed: &[u8]) -> Result<Zeroizing<Vec<u8>>, PaddingError> {
        let mut inflater = Decompress::new(false);
        let mut body = Zeroizing::new(Vec::new());
        loop {
            if body.len() > MAX_BODY_LEN {
                return Err(PaddingError::TooLarge);
            }
            if body.len() == body.capacity() {
                body.reserve(INFLATE_CHUNK);
            }
            let consumed = inflater.total_in() as usize;
            let produced = inflater.total_out();
            let status = inflater
                .decompress_vec(&compressed[consumed..], &mut body, FlushDecompress::None)
                .map_err(|e| PaddingError::Inflate(e.to_string()))?;
            match status {
                Status::StreamEnd => break,
                Status::Ok | Status::BufError => {
                    let progress = inflater.total_in() as usize != consumed
                        || inflater.total_out() != produced;
                    if !progress {
                        return Err(PaddingError::Inflate("stream ends early".to_string()));
                    }
                },
            }
        }
        if body.len() > MAX_BODY_LEN {
            return Err(PaddingError::TooLarge);
        }
        let trailing = compressed.len() - inflater.total_in() as usize;
        if trailing > 0 {
            return Err(PaddingError::Inflate(format!(
                "{trailing} bytes after the stream"
            )));
        }
        Ok(body)
    }
}
