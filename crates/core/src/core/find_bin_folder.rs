use std::path::PathBuf;
use std::process::Command;

// Running as a MacOS app means zshrc etc won't be sourced, and so PATH may not
// be configured with the necessary binary location eg if gpg was installed with
// Homebrew.
pub fn find_bin_folder(bin_name: &str) -> Option<PathBuf> {
    let bin_path_output = Command::new("which").arg(bin_name).output().ok()?;
    if bin_path_output.status.success() {
        let bin_path = String::from_utf8_lossy(&bin_path_output.stdout)
            .trim()
            .to_string();
        let bin_path = PathBuf::from(bin_path);
        return bin_path.parent().map(|p| p.to_path_buf());
    }

    // check homebrew location as well
    let brew_path = PathBuf::from("/opt/homebrew/bin");
    if brew_path.join(bin_name).exists() {
        return Some(brew_path);
    }
    None
}
