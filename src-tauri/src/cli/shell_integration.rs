use std::io::Write;
use std::path::PathBuf;

use indoc::formatdoc;
use tauri_utils::platform::current_exe;

pub const SENTINEL_START: &str = "# BEGIN axo-pass";
pub const SENTINEL_END: &str = "# END axo-pass";

// use to detect if the shell integration block is already present in the zshrc
// file
pub const SHELLENV_MARKER: &str = "ap shellenv zsh";

pub fn zshrc_path() -> PathBuf {
    if let Ok(zdotdir) = std::env::var("ZDOTDIR") {
        PathBuf::from(zdotdir).join(".zshrc")
    } else {
        dirs::home_dir().unwrap().join(".zshrc")
    }
}

pub fn ap_bin_path() -> Option<String> {
    current_exe()
        .inspect_err(|e| log::debug!("Failed to get app directory: {e}"))
        .ok()
        .and_then(|p| {
            p.parent()
                .and_then(|p| p.parent())
                .map(|parent| parent.join("bin/ap").to_string_lossy().to_string())
        })
}

/// Returns `(configured, zshrc_path)`.
pub fn check_status() -> (bool, PathBuf) {
    let path = zshrc_path();
    let configured = std::fs::read_to_string(&path)
        .map(|content| content.contains(SHELLENV_MARKER))
        .unwrap_or(false);
    (configured, path)
}

/// Writes the shell integration block to `.zshrc` if not already present.
/// Returns `Err` with a message on failure.
pub fn write_integration() -> Result<PathBuf, String> {
    let path = zshrc_path();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing.contains(SHELLENV_MARKER) {
        return Ok(path);
    }

    let ap_path = ap_bin_path().ok_or("Could not determine ap binary path")?;

    // we need to escape spaces in the path
    let escaped_ap_path = shlex::try_quote(&ap_path).unwrap();

    let block = formatdoc! {r#"
        {SENTINEL_START}
        alias ap="{escaped_ap_path}"
        source <(ap shellenv zsh)
        {SENTINEL_END}
    "#};

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("Failed to open {}: {e}", path.display()))?;

    file.write_all(block.as_bytes())
        .map_err(|e| format!("Failed to write to {}: {e}", path.display()))?;

    log::debug!("Wrote shell integration block to {}", path.display());

    Ok(path)
}
