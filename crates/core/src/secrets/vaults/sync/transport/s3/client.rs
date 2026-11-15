//! Object operations of the S3 transport.
//!
//! [`S3Client`] is the interface the transport needs: get, head, put, delete,
//! and one page of a listing. [`HttpS3Client`] implements it over HTTP with
//! `rusty-s3` request signing and a blocking `ureq` agent on rustls. Tests
//! use a fake client.
//!
//! Error text holds the operation, the key, the status, and the S3 error
//! code. It never holds a request URL, since a signed URL is a bearer token
//! until it expires.

use std::fmt;
use std::time::Duration;

use jiff::Timestamp;
use rusty_s3::actions::{ListObjectsV2, S3Action};
use rusty_s3::{Bucket, Credentials, UrlStyle};
use secrecy::ExposeSecret;
use ureq::Agent;

use super::config::S3Config;
use crate::secrets::vaults::errors::Error;

/// Time a signed URL is valid.
const SIGN_DURATION: Duration = Duration::from_secs(60);

/// Time limit of one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Bytes of an S3 error body that are read to find its code.
const ERROR_BODY_LIMIT: u64 = 4096;

/// Object of a listing or a head request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectInfo {
    /// Full key, with the prefix of the transport.
    pub key: String,
    /// Size in bytes.
    pub size: u64,
    pub modified: Timestamp,
    /// Entity tag, empty if the service sends none.
    pub etag: String,
}

/// One request of a listing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListRequest {
    pub prefix: String,
    /// Group keys by the next `/` after the prefix, so that each group is
    /// one entry of [`ListPage::prefixes`].
    pub delimiter: bool,
    /// Token of the previous page.
    pub continuation: Option<String>,
}

/// One page of a listing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListPage {
    pub objects: Vec<ObjectInfo>,
    /// Common prefixes, each ending in `/`.
    pub prefixes: Vec<String>,
    /// Token of the next page. `None` on the last page.
    pub next: Option<String>,
}

/// Operations on the objects of one bucket.
pub trait S3Client: fmt::Debug + Send + Sync {
    /// Object `key`, or `None` if it does not exist. Fails if the object is
    /// larger than `limit` bytes.
    fn get(&self, key: &str, limit: u64) -> Result<Option<Vec<u8>>, Error>;
    /// Metadata of object `key`, or `None` if it does not exist.
    fn head(&self, key: &str) -> Result<Option<ObjectInfo>, Error>;
    /// Write object `key` whole. An existing object is replaced.
    fn put(&self, key: &str, data: &[u8]) -> Result<(), Error>;
    /// Delete object `key`. A missing object is not an error.
    fn delete(&self, key: &str) -> Result<(), Error>;
    /// One page of the keys under a prefix, in key order.
    fn list_page(&self, request: &ListRequest) -> Result<ListPage, Error>;
}

/// Client of an S3-compatible service over HTTP.
pub struct HttpS3Client {
    bucket: Bucket,
    credentials: Credentials,
    agent: Agent,
}

impl HttpS3Client {
    /// Client of the bucket in `config`. Requests use path-style URLs, which
    /// MinIO, R2, B2, and AWS accept.
    pub fn new(config: &S3Config) -> Result<Self, Error> {
        let bucket = Bucket::new(
            config.endpoint.clone(),
            UrlStyle::Path,
            config.bucket.clone(),
            config.region.clone(),
        )
        .map_err(|e| Error::SyncTransportError(format!("Invalid S3 endpoint: {e}")))?;
        let credentials = Credentials::new(
            config.access_key_id.clone(),
            config.secret_access_key.expose_secret().to_string(),
        );
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Ok(Self {
            bucket,
            credentials,
            agent,
        })
    }

    fn error(action: &str, key: &str, detail: impl fmt::Display) -> Error {
        Error::SyncTransportError(format!("Failed to {action} {key}: {detail}"))
    }

    /// Detail of a failed response: the status and the S3 error code.
    fn status_detail(response: ureq::http::Response<ureq::Body>) -> String {
        let status = response.status().as_u16();
        let body = response
            .into_body()
            .with_config()
            .limit(ERROR_BODY_LIMIT)
            .read_to_string()
            .unwrap_or_default();
        match Self::error_code(&body) {
            Some(code) => format!("HTTP {status} {code}"),
            None => format!("HTTP {status}"),
        }
    }

    /// Text of `<Code>` in an S3 error body.
    fn error_code(body: &str) -> Option<&str> {
        let rest = body.split_once("<Code>")?.1;
        let code = rest.split_once("</Code>")?.0;
        (code.len() <= 64 && code.chars().all(|c| c.is_ascii_alphanumeric())).then_some(code)
    }

    fn transport_error(action: &str, key: &str, e: ureq::Error) -> Error {
        Self::error(action, key, e)
    }
}

impl fmt::Debug for HttpS3Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpS3Client")
            .field("endpoint", &self.bucket.base_url().as_str())
            .field("bucket", &self.bucket.name())
            .finish_non_exhaustive()
    }
}

impl S3Client for HttpS3Client {
    fn get(&self, key: &str, limit: u64) -> Result<Option<Vec<u8>>, Error> {
        let url = self
            .bucket
            .get_object(Some(&self.credentials), key)
            .sign(SIGN_DURATION);
        let response = self
            .agent
            .get(url.as_str())
            .call()
            .map_err(|e| Self::transport_error("read", key, e))?;
        match response.status().as_u16() {
            200..=299 => {
                let bytes = response
                    .into_body()
                    .with_config()
                    .limit(limit.saturating_add(1))
                    .read_to_vec()
                    .map_err(|e| Self::transport_error("read", key, e))?;
                if bytes.len() as u64 > limit {
                    return Err(Self::error(
                        "read",
                        key,
                        format!("larger than {limit} bytes"),
                    ));
                }
                Ok(Some(bytes))
            },
            404 => {
                // A missing bucket is also a 404, and it is not a missing
                // object.
                let detail = Self::status_detail(response);
                if detail.ends_with("NoSuchKey") {
                    Ok(None)
                } else {
                    Err(Self::error("read", key, detail))
                }
            },
            _ => Err(Self::error("read", key, Self::status_detail(response))),
        }
    }

    /// A head response has no body, so a 404 for a missing bucket looks like
    /// a missing object. A later write or listing reports the bucket.
    fn head(&self, key: &str) -> Result<Option<ObjectInfo>, Error> {
        let url = self
            .bucket
            .head_object(Some(&self.credentials), key)
            .sign(SIGN_DURATION);
        let response = self
            .agent
            .head(url.as_str())
            .call()
            .map_err(|e| Self::transport_error("read", key, e))?;
        let status = response.status().as_u16();
        match status {
            200..=299 => {
                let header = |name: &str| {
                    response
                        .headers()
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                };
                let size = header("content-length")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let modified = header("last-modified")
                    .and_then(|value| jiff::fmt::rfc2822::parse(value).ok())
                    .map_or(Timestamp::UNIX_EPOCH, |zoned| zoned.timestamp());
                Ok(Some(ObjectInfo {
                    key: key.to_string(),
                    size,
                    modified,
                    etag: header("etag")
                        .unwrap_or_default()
                        .trim_matches('"')
                        .to_string(),
                }))
            },
            404 => Ok(None),
            _ => Err(Self::error("read", key, format!("HTTP {status}"))),
        }
    }

    fn put(&self, key: &str, data: &[u8]) -> Result<(), Error> {
        let url = self
            .bucket
            .put_object(Some(&self.credentials), key)
            .sign(SIGN_DURATION);
        let response = self
            .agent
            .put(url.as_str())
            .send(data)
            .map_err(|e| Self::transport_error("write", key, e))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Self::error("write", key, Self::status_detail(response)))
        }
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        let url = self
            .bucket
            .delete_object(Some(&self.credentials), key)
            .sign(SIGN_DURATION);
        let response = self
            .agent
            .delete(url.as_str())
            .call()
            .map_err(|e| Self::transport_error("delete", key, e))?;
        // S3 answers 204 for a missing key, and some services answer 404.
        if response.status().is_success() || response.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(Self::error("delete", key, Self::status_detail(response)))
        }
    }

    fn list_page(&self, request: &ListRequest) -> Result<ListPage, Error> {
        let mut action = ListObjectsV2::new(&self.bucket, Some(&self.credentials));
        action.with_prefix(request.prefix.as_str());
        if request.delimiter {
            action.with_delimiter("/");
        }
        if let Some(token) = &request.continuation {
            action.with_continuation_token(token.as_str());
        }
        let url = action.sign(SIGN_DURATION);
        let key = request.prefix.as_str();
        let response = self
            .agent
            .get(url.as_str())
            .call()
            .map_err(|e| Self::transport_error("list", key, e))?;
        if !response.status().is_success() {
            return Err(Self::error("list", key, Self::status_detail(response)));
        }
        let body = response
            .into_body()
            .read_to_string()
            .map_err(|e| Self::transport_error("list", key, e))?;
        let parsed = ListObjectsV2::parse_response(&body)
            .map_err(|e| Self::error("list", key, format!("bad response: {e}")))?;
        let objects = parsed
            .contents
            .into_iter()
            .map(|content| {
                let modified = content.last_modified.parse::<Timestamp>().map_err(|e| {
                    Self::error("list", &content.key, format!("bad modification time: {e}"))
                })?;
                Ok(ObjectInfo {
                    key: content.key,
                    size: content.size,
                    modified,
                    etag: content.etag.trim_matches('"').to_string(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(ListPage {
            objects,
            prefixes: parsed
                .common_prefixes
                .into_iter()
                .map(|prefix| prefix.prefix)
                .collect(),
            next: parsed.next_continuation_token,
        })
    }
}
