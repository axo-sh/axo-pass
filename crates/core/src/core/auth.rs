#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

#[cfg(linux)]
pub use linux::*;
#[cfg(macos)]
pub use macos::*;
