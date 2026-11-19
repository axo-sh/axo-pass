//! Plain file access for iOS.

use std::fs::Metadata;
use std::io;
use std::os::ios::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(super) use super::apple::{RENAME_UNSUPPORTED, rename_noreplace};
use super::{
    FileStatus, FolderIo, WriteMode, delete_path, metadata_status, move_into_place, read_limited,
    write_temp,
};

/// Whether the contents of the file are not local.
pub(super) fn is_dataless(meta: &Metadata) -> bool {
    super::apple::is_dataless_flags(meta.st_flags())
}

/// File access through `std::fs` on iOS. Nothing coordinates the access. The
/// folder transport is not used on iOS, so this only has to build and behave
/// like the plain access of the other platforms.
///
/// A write puts the temp file in the cache directory, which must be on the
/// volume of the target.
#[derive(Debug, Default)]
pub struct CoordinatedIo;

impl FolderIo for CoordinatedIo {
    fn status(&self, path: &Path) -> io::Result<FileStatus> {
        metadata_status(path)
    }

    fn read(&self, path: &Path, limit: u64) -> io::Result<Vec<u8>> {
        read_limited(path, limit)
    }

    fn write(&self, path: &Path, data: &[u8], mode: WriteMode) -> io::Result<()> {
        let dir = crate::core::dirs::try_cache_dir()
            .map_err(io::Error::other)?
            .join("tmp");
        std::fs::create_dir_all(&dir)?;
        let temp = dir.join(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = write_temp(&temp, data).and_then(|()| move_into_place(&temp, path, mode));
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }

    fn delete(&self, path: &Path) -> io::Result<()> {
        delete_path(path)
    }

    fn download(&self, _paths: Vec<PathBuf>) {}
}
