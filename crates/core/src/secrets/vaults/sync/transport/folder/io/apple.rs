//! File calls of macOS and iOS that use no coordination.

use std::ffi::CStr;

/// `st_flags` bit of a dataless file, whose contents are not local. The
/// value of `SF_DATALESS` in `sys/stat.h`.
const SF_DATALESS: u32 = 0x4000_0000;

/// Error codes of `renamex_np` for a volume without `RENAME_EXCL`.
pub(super) const RENAME_UNSUPPORTED: &[i32] = &[libc::ENOTSUP];

/// Whether `st_flags` mark a file whose contents are not local.
pub(super) fn is_dataless_flags(st_flags: u32) -> bool {
    st_flags & SF_DATALESS != 0
}

/// Rename `from` to `to` with `RENAME_EXCL`. Returns the C result.
pub(super) fn rename_noreplace(from: &CStr, to: &CStr) -> i32 {
    // SAFETY: both paths are NUL-terminated strings that outlive the call.
    unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) }
}
