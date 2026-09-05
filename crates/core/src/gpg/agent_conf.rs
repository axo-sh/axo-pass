//! Reads and writes the `pinentry-program` line in `~/.gnupg/gpg-agent.conf`.
//!
//! gpg-agent runs whatever `pinentry-program` names when it needs a passphrase,
//! so pointing it at the bundled `ap-pinentry` wrapper is what routes GPG
//! prompts into this app. See `crates/core/src/gpg/pinentry/mod.rs`.

use std::io::Write;
use std::path::{Path, PathBuf};

const OPTION: &str = "pinentry-program";
const BACKUP_SUFFIX: &str = "bak";

/// Comment added above a `pinentry-program` line this app disabled.
const DISABLED_NOTE: &str = "# disabled by Axo Pass:";

/// Whether gpg-agent is pointed at this app's pinentry helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// `pinentry-program` names this app's helper.
    Configured,
    /// No active `pinentry-program` line is present.
    NotConfigured,
    /// `pinentry-program` names some other program.
    OtherProgram,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub state: State,
    /// The `gpg-agent.conf` that was read, whether or not it exists.
    pub conf_path: PathBuf,
    /// The line this app writes. `None` when the bundled helper cannot be
    /// located, which means configuring is not possible.
    pub expected_line: Option<String>,
    /// The currently configured program, when it is not this app's helper.
    pub current_program: Option<String>,
}

/// The GnuPG home directory, honouring `GNUPGHOME`.
pub fn gnupg_home() -> PathBuf {
    if let Ok(home) = std::env::var("GNUPGHOME")
        && !home.is_empty()
    {
        return PathBuf::from(home);
    }
    dirs::home_dir().unwrap_or_default().join(".gnupg")
}

pub fn conf_path() -> PathBuf {
    gnupg_home().join("gpg-agent.conf")
}

/// Absolute path to the bundled `ap-pinentry` wrapper.
///
/// Inside the bundle the main executable sits in `Contents/MacOS/` and the
/// wrapper in `Contents/Resources/` (see `strudel.toml`). Outside a bundle
/// there is no wrapper to point at.
pub fn pinentry_path() -> Option<PathBuf> {
    let exe = std::env::current_exe()
        .inspect_err(|e| log::debug!("Failed to get exe path: {e}"))
        .ok()?;
    let candidate = exe.parent()?.parent()?.join("Resources/ap-pinentry");
    candidate.exists().then_some(candidate)
}

fn expected_line(pinentry: &Path) -> String {
    // gpg's option parser takes the rest of the line as the value, so a path
    // containing spaces needs no quoting.
    format!("{OPTION} {}", pinentry.display())
}

/// The value of an active `pinentry-program` line, if this is one.
fn parse_option(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix(OPTION)?;
    // Guard against matching an option that merely starts with the same text.
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    Some(rest.trim())
}

pub fn check_status() -> Status {
    let conf_path = conf_path();
    let pinentry = pinentry_path();
    let expected_line = pinentry.as_deref().map(expected_line);
    let content = std::fs::read_to_string(&conf_path).unwrap_or_default();
    let current = content.lines().filter_map(parse_option).next_back();

    let state = match (&current, &pinentry) {
        (None, _) => State::NotConfigured,
        (Some(program), Some(expected)) if Path::new(program) == expected => State::Configured,
        _ => State::OtherProgram,
    };

    Status {
        state,
        conf_path,
        expected_line,
        current_program: match state {
            State::Configured => None,
            _ => current.map(str::to_string),
        },
    }
}

/// Points `pinentry-program` at this app's helper, commenting out any line that
/// names another program. Backs the file up to `gpg-agent.conf.bak` first.
///
/// gpg-agent keeps using the old program until it is reloaded; that happens in
/// [`super::test_integration`].
pub fn configure() -> Result<Status, String> {
    let pinentry = pinentry_path().ok_or(
        "Could not find ap-pinentry. This only works when running from the installed app bundle.",
    )?;
    let conf_path = conf_path();
    let dir = conf_path.parent().ok_or("Invalid gpg-agent.conf path")?;

    // gpg refuses to use a GnuPG home that others can read.
    std::fs::create_dir_all(dir).map_err(|e| format!("Failed to create {}: {e}", dir.display()))?;
    set_owner_only(dir, 0o700);

    let existing = std::fs::read_to_string(&conf_path).unwrap_or_default();
    if !existing.is_empty() {
        let backup = conf_path.with_extension(BACKUP_SUFFIX);
        std::fs::write(&backup, &existing)
            .map_err(|e| format!("Failed to write {}: {e}", backup.display()))?;
    }

    let mut out = String::new();
    for line in existing.lines() {
        match parse_option(line) {
            Some(_) => {
                out.push_str(DISABLED_NOTE);
                out.push('\n');
                out.push_str("# ");
                out.push_str(line);
            },
            None => out.push_str(line),
        }
        out.push('\n');
    }
    out.push_str(&expected_line(&pinentry));
    out.push('\n');

    let mut file = std::fs::File::create(&conf_path)
        .map_err(|e| format!("Failed to open {}: {e}", conf_path.display()))?;
    file.write_all(out.as_bytes())
        .map_err(|e| format!("Failed to write to {}: {e}", conf_path.display()))?;
    drop(file);
    set_owner_only(&conf_path, 0o600);

    log::debug!("Configured pinentry-program in {}", conf_path.display());

    Ok(check_status())
}

/// Best effort: a failure here leaves a working config with loose permissions,
/// which gpg complains about but still honours.
fn set_owner_only(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        log::debug!("Failed to set permissions on {}: {e}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_the_pinentry_option() {
        assert_eq!(
            parse_option("pinentry-program /usr/bin/pe"),
            Some("/usr/bin/pe")
        );
        assert_eq!(
            parse_option("  pinentry-program\t/usr/bin/pe  "),
            Some("/usr/bin/pe")
        );
        assert_eq!(
            parse_option("pinentry-program /with space/pe"),
            Some("/with space/pe")
        );
        assert_eq!(parse_option("# pinentry-program /usr/bin/pe"), None);
        assert_eq!(parse_option("pinentry-programme /usr/bin/pe"), None);
        assert_eq!(parse_option("default-cache-ttl 600"), None);
    }
}
