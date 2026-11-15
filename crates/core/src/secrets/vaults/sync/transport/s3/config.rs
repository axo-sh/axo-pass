//! Settings and credentials of an S3 location.
//!
//! The secret access key is a [`SecretString`]. It is never in `Debug`
//! output, an error, or a log line. [`S3Config::to_bytes`] is the only place
//! that exposes it.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::secrets::vaults::errors::Error;

/// Settings of an S3-compatible bucket, with the key that reaches it.
#[derive(Clone, Debug)]
pub struct S3Config {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    /// Endpoint of the service, such as `https://s3.us-east-1.amazonaws.com`.
    pub endpoint: Url,
    pub region: String,
    pub bucket: String,
    /// Key prefix of every object, with no leading or trailing slash. Empty
    /// for the root of the bucket.
    pub prefix: String,
}

/// Stored form of [`S3Config`]. Fields are checked by [`S3Config::new`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredConfig {
    access_key_id: String,
    secret_access_key: SecretString,
    endpoint: String,
    region: String,
    bucket: String,
    prefix: String,
}

/// Borrowed stored form, for writing.
#[derive(Serialize)]
struct StoredConfigRef<'a> {
    access_key_id: &'a str,
    secret_access_key: &'a str,
    endpoint: &'a str,
    region: &'a str,
    bucket: &'a str,
    prefix: &'a str,
}

impl S3Config {
    /// Checked config. Fails on an empty field, an endpoint that is not
    /// HTTPS, or a plain HTTP endpoint whose host is not `localhost`.
    pub fn new(
        access_key_id: &str,
        secret_access_key: SecretString,
        endpoint: &str,
        region: &str,
        bucket: &str,
        prefix: &str,
    ) -> Result<Self, Error> {
        for (name, value) in [
            ("access key id", access_key_id),
            ("region", region),
            ("bucket", bucket),
        ] {
            if value.trim().is_empty() {
                return Err(Self::invalid(format!("The {name} is empty")));
            }
        }
        if secret_access_key.expose_secret().is_empty() {
            return Err(Self::invalid("The secret access key is empty".to_string()));
        }
        Ok(Self {
            access_key_id: access_key_id.trim().to_string(),
            secret_access_key,
            endpoint: Self::parse_endpoint(endpoint)?,
            region: region.trim().to_string(),
            bucket: bucket.trim().to_string(),
            prefix: Self::parse_prefix(prefix)?,
        })
    }

    /// Endpoint URL. HTTPS, or HTTP for `localhost` only. The URL has a host,
    /// no user info, no query, and no fragment.
    fn parse_endpoint(endpoint: &str) -> Result<Url, Error> {
        let url = Url::parse(endpoint.trim())
            .map_err(|e| Self::invalid(format!("The endpoint is not a URL: {e}")))?;
        match url.scheme() {
            "https" => {},
            "http" if matches!(url.host(), Some(Host::Domain("localhost"))) => {},
            "http" => {
                return Err(Self::invalid(
                    "The endpoint must use HTTPS. Plain HTTP is allowed only for localhost"
                        .to_string(),
                ));
            },
            scheme => {
                return Err(Self::invalid(format!(
                    "The endpoint scheme {scheme} is not supported"
                )));
            },
        }
        if url.host().is_none() {
            return Err(Self::invalid("The endpoint has no host".to_string()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Self::invalid(
                "The endpoint must not hold a user name or password".to_string(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(Self::invalid(
                "The endpoint must not hold a query or fragment".to_string(),
            ));
        }
        Ok(url)
    }

    /// Prefix without leading and trailing slashes. Fails on an empty
    /// segment in the middle.
    fn parse_prefix(prefix: &str) -> Result<String, Error> {
        let prefix = prefix.trim().trim_matches('/');
        if prefix.is_empty() {
            return Ok(String::new());
        }
        if prefix.split('/').any(str::is_empty) || prefix.chars().any(char::is_control) {
            return Err(Self::invalid(
                "The prefix has an empty segment or a control character".to_string(),
            ));
        }
        Ok(prefix.to_string())
    }

    fn invalid(message: String) -> Error {
        Error::SyncTransportError(format!("Invalid S3 settings: {message}"))
    }

    /// JSON of the config, for a credential store. The bytes hold the secret
    /// and are zeroed on drop.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let stored = StoredConfigRef {
            access_key_id: &self.access_key_id,
            secret_access_key: self.secret_access_key.expose_secret(),
            endpoint: self.endpoint.as_str(),
            region: &self.region,
            bucket: &self.bucket,
            prefix: &self.prefix,
        };
        serde_json::to_vec(&stored)
            .map(Zeroizing::new)
            .map_err(|e| Error::SyncTransportError(format!("Failed to encode S3 settings: {e}")))
    }

    /// Config read from the bytes of [`Self::to_bytes`]. The fields are
    /// checked again.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let stored: StoredConfig = serde_json::from_slice(bytes)
            .map_err(|e| Error::SyncTransportError(format!("Failed to read S3 settings: {e}")))?;
        Self::new(
            &stored.access_key_id,
            stored.secret_access_key,
            &stored.endpoint,
            &stored.region,
            &stored.bucket,
            &stored.prefix,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(endpoint: &str, prefix: &str) -> Result<S3Config, Error> {
        S3Config::new(
            "key",
            SecretString::from("hunter2-secret"),
            endpoint,
            "us-east-1",
            "bucket",
            prefix,
        )
    }

    #[test]
    fn https_endpoint_accepted() {
        let config = config("https://s3.example.com", "").unwrap();
        assert_eq!(config.endpoint.host_str(), Some("s3.example.com"));
    }

    #[test]
    fn http_accepted_only_for_localhost() {
        assert!(config("http://localhost:9000", "").is_ok());
        for refused in [
            "http://example.com",
            "http://127.0.0.1:9000",
            "http://localhost.example.com",
            "http://[::1]:9000",
            "ftp://example.com",
            "https://user:pass@example.com",
            "https://example.com?x=1",
            "example.com",
        ] {
            assert!(config(refused, "").is_err(), "{refused}");
        }
    }

    #[test]
    fn prefix_trimmed_and_empty_segments_refused() {
        assert_eq!(config("https://e.com", "/a/b/").unwrap().prefix, "a/b");
        assert_eq!(config("https://e.com", "/").unwrap().prefix, "");
        assert!(config("https://e.com", "a//b").is_err());
    }

    #[test]
    fn empty_fields_refused() {
        let secret = || SecretString::from("s");
        let e = "https://e.com";
        assert!(S3Config::new("", secret(), e, "r", "b", "").is_err());
        assert!(S3Config::new("k", secret(), e, "", "b", "").is_err());
        assert!(S3Config::new("k", secret(), e, "r", " ", "").is_err());
        assert!(S3Config::new("k", SecretString::from(""), e, "r", "b", "").is_err());
    }

    #[test]
    fn secret_not_in_debug_or_errors() {
        let config = config("https://s3.example.com", "p").unwrap();
        assert!(!format!("{config:?}").contains("hunter2-secret"));
        let error = S3Config::new(
            "k",
            SecretString::from("hunter2-secret"),
            "http://example.com",
            "r",
            "b",
            "",
        )
        .unwrap_err();
        assert!(!error.to_string().contains("hunter2-secret"));
    }

    #[test]
    fn bytes_round_trip() {
        let config = config("https://s3.example.com", "p/q").unwrap();
        let read = S3Config::from_bytes(&config.to_bytes().unwrap()).unwrap();
        assert_eq!(read.endpoint, config.endpoint);
        assert_eq!(read.prefix, "p/q");
        assert_eq!(read.secret_access_key.expose_secret(), "hunter2-secret");
        assert!(S3Config::from_bytes(b"{}").is_err());
    }
}
