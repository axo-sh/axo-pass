#[cfg(not(target_os = "macos"))]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(not(target_os = "macos"))]
pub use linux::FolderWatch;
#[cfg(target_os = "macos")]
pub use macos::FolderWatch;
