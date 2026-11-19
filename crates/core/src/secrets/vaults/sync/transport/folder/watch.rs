#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

#[cfg(linux)]
pub use linux::FolderWatch;
#[cfg(macos)]
pub use macos::FolderWatch;
