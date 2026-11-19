pub mod errors;

#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

#[cfg(linux)]
pub use linux::{generic_password, managed_key, plain_item};
#[cfg(macos)]
pub use macos::{
    AccessControl, generic_password, keychain_query, managed_key, plain_item,
};

/// SEC1 key conversion, which has no platform dependency. The Linux stubs
/// re-export it as `managed_key::utils`.
#[cfg(linux)]
#[path = "macos/managed_key/utils.rs"]
pub mod sec1_utils;
