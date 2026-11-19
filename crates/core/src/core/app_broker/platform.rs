//! Parts of the broker that differ by platform. Each platform module
//! implements the same functions.

#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

pub(crate) use imp::app_bundle_path;
pub use imp::serve;
pub(super) use imp::{disable_sigpipe, launch_app, support_dirs};
#[cfg(linux)]
use linux as imp;
#[cfg(macos)]
use macos as imp;
