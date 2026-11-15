//! Connection test of an S3 location.
//!
//! The test writes a probe object under `{prefix}/probe/`, lists the
//! directory until the object appears, reads it back, and deletes it. The
//! probe object is deleted on every exit path that wrote it.

use std::thread;
use std::time::Duration;

use uuid::Uuid;

use super::client::{HttpS3Client, ListRequest, S3Client};
use super::config::S3Config;
use super::layout::KeyLayout;
use crate::secrets::vaults::errors::Error;

/// Times the listing is read for the probe object.
const LIST_ATTEMPTS: u32 = 10;

/// Wait between two reads of the listing.
const LIST_RETRY_DELAY: Duration = Duration::from_millis(300);

/// Outcome of a passed connection test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionReport {
    /// Reads of the listing until it showed the probe object. One means the
    /// listing was consistent with the write.
    pub list_attempts: u32,
}

/// Test the connection to the bucket in `config`. Writes, lists, reads, and
/// deletes a probe object.
pub fn test_connection(config: &S3Config) -> Result<ConnectionReport, Error> {
    let client = HttpS3Client::new(config)?;
    test_connection_with(&client, &config.prefix, LIST_RETRY_DELAY)
}

/// Run the test against `client`, waiting `retry_delay` between reads of the
/// listing.
pub fn test_connection_with(
    client: &dyn S3Client,
    prefix: &str,
    retry_delay: Duration,
) -> Result<ConnectionReport, Error> {
    let layout = KeyLayout::new(prefix);
    let dir = layout.probe_dir();
    let key = format!("{dir}{}", Uuid::new_v4().hyphenated());
    let body = key.as_bytes();

    client.put(&key, body)?;
    let result = check(client, &dir, &key, body, retry_delay);
    let deleted = client.delete(&key);
    let report = result?;
    deleted?;
    Ok(report)
}

/// Steps after the write: list until the object appears, then read it.
fn check(
    client: &dyn S3Client,
    dir: &str,
    key: &str,
    body: &[u8],
    retry_delay: Duration,
) -> Result<ConnectionReport, Error> {
    // List-after-write consistency is an open question for R2, B2, and
    // MinIO. The listing is read again for a bounded time, and a listing
    // that never shows the object fails the test.
    let mut attempts = 0;
    loop {
        attempts += 1;
        let page = client.list_page(&ListRequest {
            prefix: dir.to_string(),
            delimiter: true,
            continuation: None,
        })?;
        if page.objects.iter().any(|object| object.key == key) {
            break;
        }
        if attempts == LIST_ATTEMPTS {
            return Err(Error::SyncTransportError(format!(
                "The probe object was not listed after {LIST_ATTEMPTS} tries"
            )));
        }
        thread::sleep(retry_delay);
    }
    match client.get(key, body.len() as u64)? {
        Some(read) if read == body => Ok(ConnectionReport {
            list_attempts: attempts,
        }),
        Some(_) => Err(Error::SyncTransportError(
            "The probe object read back with other bytes".to_string(),
        )),
        None => Err(Error::SyncTransportError(
            "The probe object was listed and could not be read".to_string(),
        )),
    }
}
