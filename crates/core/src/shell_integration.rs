use std::io::Write;
use std::path::{Path, PathBuf};

use indoc::formatdoc;

use crate::ssh::askpass;

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
    // Inside the bundle `ap` sits next to the main executable in
    // Contents/MacOS/ (strudel.toml copies + signs it there). Standalone, this
    // resolves to the running `ap` binary itself, which is fine for the alias.
    std::env::current_exe()
        .inspect_err(|e| log::debug!("Failed to get exe path: {e}"))
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|dir| dir.join("ap").to_string_lossy().into_owned())
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

/// Builds the current shell integration block, sentinels included, with a
/// trailing newline.
fn build_block() -> Result<String, String> {
    let ap_path = ap_bin_path().ok_or("Could not determine ap binary path")?;

    // we need to escape spaces in the path
    let escaped_ap_path = shlex::try_quote(&ap_path).unwrap();

    let mut block = formatdoc! {r#"
        {SENTINEL_START}
        alias ap={escaped_ap_path}
        source <(ap shellenv zsh)
    "#};

    // SSH_ASKPASS routes ssh/ssh-add's passphrase and password prompts into
    // the app when they have no terminal to prompt on. Only available when
    // running from the installed app bundle, same as the pinentry wrapper.
    if let Some(askpass_path) = askpass::wrapper_path() {
        let askpass_path = askpass_path.to_string_lossy();
        let escaped_askpass_path = shlex::try_quote(&askpass_path).unwrap();
        block.push_str(&formatdoc! {r#"
            export SSH_ASKPASS={escaped_askpass_path}
            export SSH_ASKPASS_REQUIRE=force
        "#});
    }

    block.push_str(SENTINEL_END);
    block.push('\n');
    Ok(block)
}

/// Finds the byte range of an existing sentinel-delimited block, if any,
/// including the trailing newline after `SENTINEL_END`.
fn find_existing_block(content: &str) -> Option<std::ops::Range<usize>> {
    let start = content.find(SENTINEL_START)?;
    let end_marker = content[start..].find(SENTINEL_END)? + start;
    let after_end = end_marker + SENTINEL_END.len();
    let end = match content[after_end..].find('\n') {
        Some(offset) => after_end + offset + 1,
        None => content.len(),
    };
    Some(start..end)
}

/// Writes the shell integration block to `.zshrc`, replacing an existing
/// sentinel-delimited block if its content is out of date, or appending one
/// if none is present yet. No-ops if an up-to-date block is already there.
pub fn write_integration() -> Result<PathBuf, String> {
    let path = zshrc_path();
    write_integration_to(&path)?;
    Ok(path)
}

fn write_integration_to(path: &Path) -> Result<(), String> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let block = build_block()?;

    match find_existing_block(&existing) {
        Some(range) if existing[range.clone()] == block => return Ok(()),
        Some(range) => {
            let mut updated = existing[..range.start].to_string();
            updated.push_str(&block);
            updated.push_str(&existing[range.end..]);
            std::fs::write(path, updated)
                .map_err(|e| format!("Failed to write to {}: {e}", path.display()))?;
            log::debug!("Updated shell integration block in {}", path.display());
        }
        None => {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("Failed to open {}: {e}", path.display()))?;

            // Start the block on its own line when the file does not already
            // end with one.
            if !existing.is_empty() && !existing.ends_with('\n') {
                file.write_all(b"\n")
                    .map_err(|e| format!("Failed to write to {}: {e}", path.display()))?;
            }

            file.write_all(block.as_bytes())
                .map_err(|e| format!("Failed to write to {}: {e}", path.display()))?;

            log::debug!("Wrote shell integration block to {}", path.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn appends_block_to_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".zshrc");

        write_integration_to(&path).unwrap();

        let content = read(&path);
        assert!(content.contains(SENTINEL_START));
        assert!(content.contains(SENTINEL_END));
        assert!(content.contains(SHELLENV_MARKER));
    }

    #[test]
    fn preserves_content_around_the_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".zshrc");
        std::fs::write(&path, "export PATH=/usr/local/bin:$PATH\n").unwrap();

        write_integration_to(&path).unwrap();

        let content = read(&path);
        assert!(content.starts_with("export PATH=/usr/local/bin:$PATH\n"));
        assert!(content.contains(SENTINEL_START));
    }

    #[test]
    fn is_idempotent_once_up_to_date() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".zshrc");

        write_integration_to(&path).unwrap();
        let first = read(&path);
        write_integration_to(&path).unwrap();
        let second = read(&path);

        assert_eq!(first, second);
    }

    #[test]
    fn replaces_an_outdated_block_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".zshrc");
        std::fs::write(
            &path,
            format!(
                "# before\n{SENTINEL_START}\nalias ap=\"/old/path/ap\"\n{SENTINEL_END}\n# after\n"
            ),
        )
        .unwrap();

        write_integration_to(&path).unwrap();

        let content = read(&path);
        assert!(content.starts_with("# before\n"));
        assert!(content.ends_with("# after\n"));
        assert!(!content.contains("/old/path/ap"));
        assert!(content.contains(SHELLENV_MARKER));
        // Exactly one sentinel pair, not two.
        assert_eq!(content.matches(SENTINEL_START).count(), 1);
    }

    #[test]
    fn separates_the_block_when_the_file_has_no_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".zshrc");
        std::fs::write(&path, "export PATH=/usr/local/bin:$PATH").unwrap();

        write_integration_to(&path).unwrap();

        let content = read(&path);
        assert!(content.starts_with("export PATH=/usr/local/bin:$PATH\n"));
        assert!(content.contains(&format!("\n{SENTINEL_START}")));
    }
}
