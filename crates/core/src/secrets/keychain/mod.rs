pub mod errors;
pub mod sec1_utils;

#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

#[cfg(linux)]
pub use linux::{generic_password, managed_key, plain_item};
#[cfg(macos)]
pub use macos::{
    AccessControl, CFErrorOut, generic_password, keychain_query, managed_key, plain_item,
};
