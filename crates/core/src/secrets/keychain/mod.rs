pub mod errors;
pub mod sec1_utils;

#[cfg(apple)]
mod apple;
#[cfg(linux)]
mod linux;
#[cfg(sim_keys)]
pub mod software_keys;

#[cfg(apple)]
pub use apple::{
    AccessControl, CFErrorOut, generic_password, keychain_query, managed_key, plain_item,
};
#[cfg(linux)]
pub use linux::{generic_password, managed_key, plain_item};
