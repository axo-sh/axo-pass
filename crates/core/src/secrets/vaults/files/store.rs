//! Local blob store of a vault.
//!
//! Blobs of a vault are in the directory `{vault short id}.files` beside the
//! vault file, one file per blob, named by the blob hash. A blob is first
//! written to a hidden temp file in that directory. The temp file is renamed
//! to the blob name under the vault locks, before the transaction that
//! references the blob saves (`files/mod.rs`). Garbage collection ignores
//! temp files unless they are older than [`STALE_TEMP`].

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use uuid::Uuid;

use super::record::{FileHash, FileKey, FileRecord};
use super::stream::{self, Sealed};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::short_id::ShortId;

/// Suffix of the store directory name.
const STORE_SUFFIX: &str = "files";

/// Suffix of a temp file name.
const TEMP_SUFFIX: &str = ".tmp";

/// Age after which a temp file left by an interrupted write is deleted.
const STALE_TEMP: Duration = Duration::from_secs(24 * 60 * 60);

/// Blob store of one vault.
#[derive(Clone, Debug)]
pub(crate) struct BlobStore {
    dir: PathBuf,
}

impl BlobStore {
    /// Store of vault `id` whose vault file is at `vault_path`.
    pub(crate) fn of(vault_path: &Path, id: Uuid) -> Self {
        let parent = vault_path.parent().unwrap_or(Path::new(""));
        let name = format!("{}.{STORE_SUFFIX}", ShortId::encode_uuid(id));
        Self {
            dir: parent.join(name),
        }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path of blob `blob`.
    pub(crate) fn path(&self, blob: &FileHash) -> PathBuf {
        self.dir.join(blob.to_string())
    }

    /// Encrypt `input` under a new key for vault `vault_id` to a temp file in
    /// the store. The temp file is deleted if the result is dropped before
    /// [`StagedBlob::commit`].
    pub(crate) fn stage(&self, vault_id: Uuid, input: impl io::Read) -> Result<StagedBlob, Error> {
        fs::create_dir_all(&self.dir).map_err(Error::FileWriteError)?;
        let temp = self.temp_path();
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(Error::FileWriteError)?;
        // From here on the temp file is deleted on any failure.
        let mut staged = StagedBlob {
            temp: Some(temp),
            key: FileKey::generate(),
            sealed: None,
        };
        let mut writer = BufWriter::new(file);
        let sealed = stream::encrypt(&staged.key, vault_id, input, &mut writer)?;
        let file = writer
            .into_inner()
            .map_err(|e| Error::FileWriteError(e.into_error()))?;
        file.sync_all().map_err(Error::FileWriteError)?;
        staged.sealed = Some(sealed);
        Ok(staged)
    }

    /// Decrypt the blob of `record` for vault `vault_id` to `output`. The
    /// blob is verified against the record first (`files/stream.rs`). A
    /// missing blob fails with `FileMissing`.
    pub(crate) fn read(
        &self,
        record: &FileRecord,
        vault_id: Uuid,
        output: impl Write,
    ) -> Result<(), Error> {
        let file = self.open(&record.blob)?;
        stream::decrypt(record, vault_id, io::BufReader::new(file), output)
    }

    /// Ciphertext of blob `blob`, checked against its name. A missing blob
    /// fails with `FileMissing`, and one whose bytes do not hash to its name
    /// fails with `FileBlobMismatch`.
    pub(crate) fn read_bytes(&self, blob: &FileHash) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut self.open(blob)?, &mut bytes).map_err(Error::FileReadError)?;
        if FileHash::of(&bytes) != *blob {
            return Err(Error::FileBlobMismatch(blob.to_string()));
        }
        Ok(bytes)
    }

    /// Write `bytes` as blob `blob`, through a temp file renamed to the blob
    /// name, and sync the directory. Fails with `FileBlobMismatch` and writes
    /// nothing if `bytes` do not hash to `blob`. An existing blob is
    /// replaced by the same bytes.
    pub(crate) fn put(&self, blob: &FileHash, bytes: &[u8]) -> Result<(), Error> {
        if FileHash::of(bytes) != *blob {
            return Err(Error::FileBlobMismatch(blob.to_string()));
        }
        fs::create_dir_all(&self.dir).map_err(Error::FileWriteError)?;
        let temp = self.temp_path();
        let write = || -> io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temp, self.path(blob))?;
            File::open(&self.dir)?.sync_all()
        };
        write().map_err(|e| {
            let _ = fs::remove_file(&temp);
            Error::FileWriteError(e)
        })
    }

    /// Whether blob `blob` is in the store.
    pub(crate) fn contains(&self, blob: &FileHash) -> bool {
        self.path(blob).is_file()
    }

    /// Path of a new hidden temp file in the store.
    fn temp_path(&self) -> PathBuf {
        self.dir
            .join(format!(".{}{TEMP_SUFFIX}", Uuid::new_v4().simple()))
    }

    fn open(&self, blob: &FileHash) -> Result<File, Error> {
        File::open(self.path(blob)).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::FileMissing(blob.to_string())
            } else {
                Error::FileReadError(e)
            }
        })
    }

    /// Delete blob `blob`. A missing blob is skipped. Returns whether a file
    /// was deleted.
    pub(crate) fn delete(&self, blob: &FileHash) -> Result<bool, Error> {
        match fs::remove_file(self.path(blob)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::FileDeleteError(e)),
        }
    }

    /// Blobs in the store, ordered by name. A missing directory has none.
    /// Files with other names are ignored.
    pub(crate) fn list(&self) -> Result<Vec<FileHash>, Error> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::FileReadError(e)),
        };
        let mut blobs = Vec::new();
        for entry in entries {
            let name = entry.map_err(Error::FileReadError)?.file_name();
            if let Some(blob) = name.to_str().and_then(FileHash::parse) {
                blobs.push(blob);
            }
        }
        blobs.sort();
        Ok(blobs)
    }

    /// Delete temp files last modified before `now` less [`STALE_TEMP`].
    /// Failures are logged. Returns the number deleted.
    pub(crate) fn delete_stale_temps(&self, now: SystemTime) -> usize {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return 0;
        };
        let mut deleted = 0;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let is_temp = name
                .to_str()
                .is_some_and(|name| name.starts_with('.') && name.ends_with(TEMP_SUFFIX));
            if !is_temp {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|modified| modified + STALE_TEMP < now);
            if !stale {
                continue;
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => deleted += 1,
                Err(e) => log::warn!("Failed to delete {}: {e}", entry.path().display()),
            }
        }
        deleted
    }
}

/// Blob encrypted to a temp file, not yet under its blob name.
pub(crate) struct StagedBlob {
    /// Temp file. `None` once committed.
    temp: Option<PathBuf>,
    key: FileKey,
    /// Hashes and size. Set once the temp file is written.
    sealed: Option<Sealed>,
}

impl StagedBlob {
    fn sealed(&self) -> Sealed {
        self.sealed.expect("a staged blob is returned once written")
    }

    /// Record of this blob, for a file named `name` of MIME type `mime`.
    pub(crate) fn record(&self, name: String, mime: Option<String>) -> FileRecord {
        let sealed = self.sealed();
        FileRecord {
            blob: sealed.blob,
            key: self.key.clone(),
            sha256: sealed.sha256,
            size: sealed.size,
            name,
            mime,
        }
    }

    /// Rename the temp file to its blob name in `store` and sync the
    /// directory. Returns the blob.
    pub(crate) fn commit(mut self, store: &BlobStore) -> Result<FileHash, Error> {
        let blob = self.sealed().blob;
        let Some(temp) = self.temp.as_ref() else {
            return Ok(blob);
        };
        fs::create_dir_all(store.dir()).map_err(Error::FileWriteError)?;
        fs::rename(temp, store.path(&blob)).map_err(Error::FileWriteError)?;
        self.temp = None;
        File::open(store.dir())
            .and_then(|dir| dir.sync_all())
            .map_err(Error::FileWriteError)?;
        Ok(blob)
    }
}

impl Drop for StagedBlob {
    fn drop(&mut self) {
        if let Some(temp) = self.temp.take()
            && let Err(e) = fs::remove_file(&temp)
            && e.kind() != io::ErrorKind::NotFound
        {
            log::warn!("Failed to delete {}: {e}", temp.display());
        }
    }
}
