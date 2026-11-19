pub mod errors;

#[cfg(not(target_os = "macos"))]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(not(target_os = "macos"))]
pub use linux::{generic_password, managed_key, plain_item};
#[cfg(target_os = "macos")]
pub use macos::{
    AccessControl, generic_password, keychain_query, managed_key, plain_item,
};

/// SEC1 key conversion, which has no platform dependency. The Linux stubs
/// re-export it as `managed_key::utils`.
#[cfg(not(target_os = "macos"))]
#[path = "macos/managed_key/utils.rs"]
pub mod sec1_utils;
