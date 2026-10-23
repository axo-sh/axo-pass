//! Retained versions of vault files and their retention.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, io};

use crate::core::files::write_new_synced;
use crate::secrets::vaults::errors::Error;

pub(super) const HOUR_MS: u64 = 60 * 60 * 1000;
pub(super) const DAY_MS: u64 = 24 * HOUR_MS;
/// Versions from the last hour that retention keeps.
const RECENT_VERSIONS: usize = 100;
/// Days for which retention keeps the last version of each day.
const RETAINED_DAYS: u64 = 30;

/// A retained version of a vault: the vault file as it was before a save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedVersion {
    /// File name, `{unix_ms}-{n}.json`.
    pub name: String,
    /// Time of the save that replaced this version, in milliseconds since the
    /// Unix epoch.
    pub saved_at_ms: u64,
    /// Counter that orders versions saved in the same millisecond.
    pub(super) seq: u64,
}

impl RetainedVersion {
    pub(super) fn parse(name: &str) -> Option<Self> {
        let stem = name.strip_suffix(".json")?;
        let (ms, seq) = stem.split_once('-')?;
        Some(Self {
            name: name.to_string(),
            saved_at_ms: ms.parse().ok()?,
            seq: seq.parse().ok()?,
        })
    }
}

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Directory of the retained versions of one vault.
pub(super) struct VersionsDir {
    pub(super) path: PathBuf,
}

impl VersionsDir {
    pub(super) fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Path of version `name`.
    pub(super) fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Write `contents` as a new version. The counter in the name makes it
    /// unique if another version has the same millisecond. The directory is
    /// created again if [`super::VaultWriter::prune_all`] removed it in the
    /// meantime.
    pub(super) fn add(&self, now: u64, contents: &str) -> io::Result<PathBuf> {
        fs::create_dir_all(&self.path)?;
        let mut recreated = false;
        let mut n = 0u64;
        loop {
            let path = self.file(&format!("{now}-{n}.json"));
            match write_new_synced(&path, contents.as_bytes()) {
                Ok(()) => return Ok(path),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => n += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound && !recreated => {
                    fs::create_dir_all(&self.path)?;
                    recreated = true;
                },
                Err(e) => return Err(e),
            }
        }
    }

    /// Versions, newest first. A missing directory has none. Files with other
    /// names are ignored.
    pub(super) fn list(&self) -> io::Result<Vec<RetainedVersion>> {
        let entries = match fs::read_dir(&self.path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut versions = Vec::new();
        for entry in entries {
            let name = entry?.file_name();
            if let Some(version) = name.to_str().and_then(RetainedVersion::parse) {
                versions.push(version);
            }
        }
        versions.sort_by_key(|v| std::cmp::Reverse((v.saved_at_ms, v.seq)));
        Ok(versions)
    }

    /// Delete the versions that retention does not keep. Returns the versions
    /// kept, newest first. A version that another prune deleted first is
    /// skipped.
    pub(super) fn prune(&self, now: u64) -> io::Result<Vec<RetainedVersion>> {
        let versions = self.list()?;
        let keep = kept_versions(&versions, now);
        let (kept, expired): (Vec<_>, Vec<_>) =
            versions.into_iter().partition(|v| keep.contains(&v.name));
        for v in expired {
            match fs::remove_file(self.file(&v.name)) {
                Ok(()) => {},
                Err(e) if e.kind() == io::ErrorKind::NotFound => {},
                Err(e) => return Err(e),
            }
        }
        Ok(kept)
    }

    /// Delete every version and the directory. Returns the number of versions
    /// deleted.
    pub(super) fn erase(&self) -> Result<usize, Error> {
        let count = self.list().map_err(Error::VaultReadError)?.len();
        match fs::remove_dir_all(&self.path) {
            Ok(()) => Ok(count),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(count),
            Err(e) => Err(Error::VaultDeleteError(e)),
        }
    }
}

/// Names of the versions retention keeps: up to 100 from the last hour, and
/// the last version of each UTC day for 30 days. `versions` is newest first.
pub(super) fn kept_versions(versions: &[RetainedVersion], now: u64) -> HashSet<String> {
    let age = |v: &RetainedVersion| now.saturating_sub(v.saved_at_ms);
    let mut keep: HashSet<String> = versions
        .iter()
        .filter(|v| age(v) < HOUR_MS)
        .take(RECENT_VERSIONS)
        .map(|v| v.name.clone())
        .collect();
    let mut days = HashSet::new();
    for v in versions {
        if age(v) < RETAINED_DAYS * DAY_MS && days.insert(v.saved_at_ms / DAY_MS) {
            keep.insert(v.name.clone());
        }
    }
    keep
}
