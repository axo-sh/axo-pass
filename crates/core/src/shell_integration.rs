use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use indoc::formatdoc;

use crate::ssh::askpass;

pub const SENTINEL_START: &str = "# BEGIN axo-pass";
pub const SENTINEL_END: &str = "# END axo-pass";

// use to detect if the shell integration block is already present in the zshrc
// file
pub const SHELLENV_MARKER: &str = "ap shellenv zsh";

/// Variable `ap shellenv zsh` exports. A new zsh that has it set loaded the
/// shell integration, wherever the user added it.
pub const HOOK_ENV_VAR: &str = "AXO_PASS_SHELLENV";

/// Longest wait for the probe shell to start.
const HOOK_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of the last `verify_shell_hook` call.
static HOOK_VERIFIED: AtomicBool = AtomicBool::new(false);

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
    // resolves to the running `ap` binary itself.
    std::env::current_exe()
        .inspect_err(|e| log::debug!("Failed to get exe path: {e}"))
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|dir| dir.join("ap").to_string_lossy().into_owned())
        })
}

/// The user-writable directory the `ap` symlink is installed into. No sudo and
/// no sandbox prompt, unlike `/usr/local/bin`.
pub fn local_bin_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".local").join("bin"))
}

/// Path to the `ap` symlink in `~/.local/bin`.
pub fn ap_symlink_path() -> Option<PathBuf> {
    local_bin_dir().map(|dir| dir.join("ap"))
}

/// Creates or refreshes `~/.local/bin/ap` so `ap` resolves for scripts and
/// non-zsh tools, not just interactive zsh. A pre-existing regular file at that
/// path is the user's own binary and is left untouched.
pub fn install_symlink() -> Result<(), String> {
    let target = ap_bin_path().ok_or("Could not determine ap binary path")?;
    let dir = local_bin_dir().ok_or("Could not determine home directory")?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create {}: {e}", dir.display()))?;
    let link = dir.join("ap");

    match std::fs::symlink_metadata(&link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if std::fs::read_link(&link).ok().as_deref() == Some(Path::new(&target)) {
                return Ok(());
            }
            std::fs::remove_file(&link)
                .map_err(|e| format!("Failed to replace {}: {e}", link.display()))?;
        },
        Ok(_) => {
            return Err(format!(
                "{} already exists and is not our symlink; remove it and retry",
                link.display()
            ));
        },
        Err(_) => {},
    }

    std::os::unix::fs::symlink(&target, &link)
        .map_err(|e| format!("Failed to create {}: {e}", link.display()))?;
    log::debug!("Linked {} -> {target}", link.display());
    Ok(())
}

/// State of the `.zshrc` block and the `~/.local/bin/ap` symlink.
pub struct Status {
    /// The `.zshrc` block is present.
    pub zshrc_configured: bool,
    /// The last `verify_shell_hook` call found the hook in a new zsh.
    pub hook_verified: bool,
    /// `~/.local/bin/ap` is a symlink to the current `ap` binary.
    pub symlink_ok: bool,
    pub zshrc_path: PathBuf,
    pub symlink_path: Option<PathBuf>,
}

impl Status {
    /// The shell hook is in `.zshrc` or was found in a new zsh.
    pub fn hook_configured(&self) -> bool {
        self.zshrc_configured || self.hook_verified
    }

    /// Both the shell hook and the symlink are in place.
    pub fn configured(&self) -> bool {
        self.hook_configured() && self.symlink_ok
    }
}

/// Whether `content` has an uncommented line that sources the shell hook.
fn has_active_hook(content: &str) -> bool {
    content.lines().any(|line| {
        let line = line.trim_start();
        !line.starts_with('#') && line.contains(SHELLENV_MARKER)
    })
}

/// Start an interactive zsh and report whether the shell hook ran in it.
///
/// Covers setups that `.zshrc` detection misses, such as `.zshenv`, a
/// dotfiles repo, or a sourced file. Runs the user's startup files, so call
/// it only on request. The result is kept for `check_status`.
pub fn verify_shell_hook() -> bool {
    let found = probe_zsh_for_hook();
    HOOK_VERIFIED.store(found, Ordering::Relaxed);
    found
}

fn probe_zsh_for_hook() -> bool {
    let mut child = match Command::new("zsh")
        .arg("-ic")
        .arg(format!("print -r -- ${HOOK_ENV_VAR}"))
        .env_remove(HOOK_ENV_VAR)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            log::debug!("Failed to start zsh: {e}");
            return false;
        },
    };

    let deadline = Instant::now() + HOOK_PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            },
            _ => {
                log::debug!("Shell hook probe did not finish");
                let _ = child.kill();
                let _ = child.wait();
                return false;
            },
        }
    }

    child
        .wait_with_output()
        .ok()
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .last()
                .map(|line| line.trim() == "1")
        })
        .unwrap_or(false)
}

/// Whether `link` is a symlink that points at `target`, which must exist.
fn symlink_points_to(link: &Path, target: &Path) -> bool {
    std::fs::read_link(link).ok().as_deref() == Some(target) && target.exists()
}

pub fn check_status() -> Status {
    let zshrc_path = zshrc_path();
    let zshrc_configured = std::fs::read_to_string(&zshrc_path)
        .map(|content| has_active_hook(&content))
        .unwrap_or(false);
    let symlink_path = ap_symlink_path();
    let symlink_ok = match (&symlink_path, ap_bin_path()) {
        (Some(link), Some(target)) => symlink_points_to(link, Path::new(&target)),
        _ => false,
    };
    Status {
        zshrc_configured,
        hook_verified: HOOK_VERIFIED.load(Ordering::Relaxed),
        symlink_ok,
        zshrc_path,
        symlink_path,
    }
}

/// Quotes a path for a zshrc assignment such as `export NAME=<value>`.
fn shell_quote(value: &str) -> String {
    shlex::try_quote(value).unwrap().into_owned()
}

/// Builds the current shell integration block, sentinels included, with a
/// trailing newline.
fn build_block() -> Result<String, String> {
    Ok(format!(
        "{SENTINEL_START}\n{}{SENTINEL_END}\n",
        block_body()
    ))
}

/// Lines of the shell integration block between the sentinels, with a
/// trailing newline.
pub fn block_body() -> String {
    formatdoc! {r#"
        if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
          export PATH="$HOME/.local/bin:$PATH"
        fi
        source <(ap shellenv zsh)
    "#}
}

/// Export lines that point `SSH_ASKPASS` at the bundled helper, with a
/// trailing newline.
///
/// `SSH_ASKPASS` routes ssh and ssh-add passphrase and password prompts into
/// the app if they have no terminal to prompt on. Empty outside the installed
/// app bundle, same as the pinentry wrapper.
pub fn askpass_exports() -> String {
    let Some(askpass_path) = askpass::wrapper_path() else {
        return String::new();
    };
    let escaped_askpass_path = shell_quote(&askpass_path.to_string_lossy());
    formatdoc! {r#"
        export SSH_ASKPASS={escaped_askpass_path}
        export SSH_ASKPASS_REQUIRE=force
    "#}
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
    install_symlink()?;
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
        },
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
        },
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
    fn block_puts_local_bin_on_path_without_alias() {
        let block = build_block().unwrap();
        assert!(!block.contains("alias ap="));
        assert!(block.contains("$HOME/.local/bin"));
        assert!(block.contains(SHELLENV_MARKER));
    }

    #[test]
    fn path_guard_is_valid_zsh_and_prepends_once() {
        // The sentinel-to-source lines are the PATH guard.
        let block = build_block().unwrap();
        let guard: String = block
            .lines()
            .skip(1)
            .take_while(|l| !l.starts_with("source "))
            .collect::<Vec<_>>()
            .join("\n");

        // Run the guard twice in one shell; the directory is prepended once.
        let script = format!("PATH=/usr/bin\n{guard}\n{guard}\necho \"$PATH\"\n");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.zsh");
        std::fs::write(&path, &script).unwrap();
        let out = match std::process::Command::new("zsh")
            .arg("-f")
            .arg(&path)
            .env("HOME", "/home/tester")
            .output()
        {
            Ok(out) => out,
            // macOS ships zsh. Linux machines may not have it.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipped: zsh is not installed");
                return;
            },
            Err(e) => panic!("Failed to run zsh: {e}"),
        };
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "/home/tester/.local/bin:/usr/bin"
        );
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
    fn preserves_content_around_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".zshrc");
        std::fs::write(&path, "export PATH=/usr/local/bin:$PATH\n").unwrap();

        write_integration_to(&path).unwrap();

        let content = read(&path);
        assert!(content.starts_with("export PATH=/usr/local/bin:$PATH\n"));
        assert!(content.contains(SENTINEL_START));
    }

    #[test]
    fn active_hook_line_detected() {
        assert!(has_active_hook("export A=1\nsource <(ap shellenv zsh)\n"));
        assert!(has_active_hook("  eval \"$(ap shellenv zsh)\"\n"));
    }

    #[test]
    fn commented_hook_line_ignored() {
        assert!(!has_active_hook("# source <(ap shellenv zsh)\n"));
        assert!(!has_active_hook("  # source <(ap shellenv zsh)\n"));
        assert!(!has_active_hook(""));
    }

    #[test]
    fn symlink_to_existing_target_matches() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ap");
        let link = dir.path().join("link");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(symlink_points_to(&link, &target));
    }

    #[test]
    fn missing_symlink_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ap");
        std::fs::write(&target, "").unwrap();

        assert!(!symlink_points_to(&dir.path().join("link"), &target));
    }

    #[test]
    fn symlink_to_other_target_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ap");
        let other = dir.path().join("other");
        let link = dir.path().join("link");
        std::fs::write(&target, "").unwrap();
        std::fs::write(&other, "").unwrap();
        std::os::unix::fs::symlink(&other, &link).unwrap();

        assert!(!symlink_points_to(&link, &target));
    }

    #[test]
    fn dangling_symlink_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ap");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(!symlink_points_to(&link, &target));
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
    fn replaces_outdated_block_in_place() {
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
    fn separates_block_when_file_has_no_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".zshrc");
        std::fs::write(&path, "export PATH=/usr/local/bin:$PATH").unwrap();

        write_integration_to(&path).unwrap();

        let content = read(&path);
        assert!(content.starts_with("export PATH=/usr/local/bin:$PATH\n"));
        assert!(content.contains(&format!("\n{SENTINEL_START}")));
    }
}
