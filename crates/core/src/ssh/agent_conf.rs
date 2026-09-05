//! Reads and writes the `IdentityAgent` directive in `~/.ssh/config`.
//!
//! Pointing `IdentityAgent` at this app's agent socket routes ssh's agent
//! requests (signing, listing identities) through Axo Pass instead of the
//! system ssh-agent. See `crates/core/src/ssh/agent_client.rs`.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use indoc::formatdoc;

use super::agent_client::default_socket_path;
use super::utils::get_ssh_dir;

const OPTION: &str = "IdentityAgent";
const BACKUP_SUFFIX: &str = "bak";

/// Comment added above an `IdentityAgent` line this app disabled.
const DISABLED_NOTE: &str = "# disabled by Axo Pass:";

/// Sentinels around the block `configure` appends. A prior block is stripped
/// before a new one is written, so running `configure` repeatedly leaves a
/// single block rather than stacking them.
const BLOCK_START: &str = "# BEGIN axo-pass IdentityAgent";
const BLOCK_END: &str = "# END axo-pass IdentityAgent";

/// Whether ssh is pointed at this app's agent socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// `IdentityAgent` resolves to this app's socket.
    Configured,
    /// No active `IdentityAgent` is in effect.
    NotConfigured,
    /// `IdentityAgent` resolves to some other agent.
    OtherAgent,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub state: State,
    /// The `~/.ssh/config` that setup writes to, whether or not it exists.
    pub config_path: PathBuf,
    /// The socket path this app writes.
    pub expected_agent: String,
    /// The currently effective `IdentityAgent`, when it is not this app's socket.
    pub current_agent: Option<String>,
}

pub fn config_path() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".ssh").join("config")
}

fn expected_agent() -> String {
    default_socket_path().to_string_lossy().to_string()
}

fn unquote(value: &str) -> &str {
    value.trim_matches('"')
}

/// The `IdentityAgent` ssh would actually use, found by asking `ssh -G` to
/// resolve the config the way ssh itself does (includes, Match blocks, and
/// so on) rather than reimplementing that parser here.
fn effective_agent() -> Option<String> {
    // The hostname is never contacted; `-G` only resolves and prints config.
    let output = Command::new("ssh")
        .arg("-G")
        .arg("axo-pass-agent-conf-check")
        .output()
        .inspect_err(|e| log::debug!("Failed to run ssh -G: {e}"))
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().find_map(|line| {
        let rest = line.strip_prefix("identityagent")?;
        if !rest.starts_with(char::is_whitespace) {
            return None;
        }
        let value = unquote(rest.trim());
        (!value.is_empty() && value != "none").then(|| value.to_string())
    })
}

/// The value of an active `IdentityAgent` line, if this is one. Matches the
/// directive name case-insensitively, as ssh_config does.
fn parse_option(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.len() < OPTION.len() || !trimmed.is_char_boundary(OPTION.len()) {
        return None;
    }
    let (name, rest) = trimmed.split_at(OPTION.len());
    if !name.eq_ignore_ascii_case(OPTION) || !rest.starts_with(char::is_whitespace) {
        return None;
    }
    Some(rest.trim())
}

pub fn check_status() -> Status {
    let expected = expected_agent();
    let current = effective_agent();
    let state = match &current {
        Some(agent) if *agent == expected => State::Configured,
        Some(_) => State::OtherAgent,
        None => State::NotConfigured,
    };

    Status {
        state,
        config_path: config_path(),
        expected_agent: expected,
        current_agent: match state {
            State::Configured => None,
            _ => current,
        },
    }
}

/// Points `IdentityAgent` at this app's agent socket for all hosts, commenting
/// out any active `IdentityAgent` line. Backs the file up to `config.bak`
/// first. Idempotent: a block from a previous run is replaced, not stacked.
pub fn configure() -> Result<Status, String> {
    let ssh_dir = get_ssh_dir().map_err(|e| e.to_string())?;
    let config_path = ssh_dir.join("config");

    let existing = std::fs::read_to_string(&config_path).unwrap_or_default();
    if !existing.is_empty() {
        let backup = config_path.with_extension(BACKUP_SUFFIX);
        std::fs::write(&backup, &existing)
            .map_err(|e| format!("Failed to write {}: {e}", backup.display()))?;
    }

    let out = rewrite_config(&existing, &expected_agent());

    let mut file = std::fs::File::create(&config_path)
        .map_err(|e| format!("Failed to open {}: {e}", config_path.display()))?;
    file.write_all(out.as_bytes())
        .map_err(|e| format!("Failed to write to {}: {e}", config_path.display()))?;
    drop(file);
    set_owner_only(&config_path, 0o600);

    log::debug!("Configured IdentityAgent in {}", config_path.display());

    Ok(check_status())
}

/// Strips any previously appended app block, comments out active
/// `IdentityAgent` lines, and appends a fresh sentinel-wrapped block pointing
/// at `agent`.
fn rewrite_config(existing: &str, agent: &str) -> String {
    let stripped = strip_app_block(existing);

    let mut out = String::new();
    for line in stripped.lines() {
        match parse_option(line) {
            Some(_) => out.push_str(&formatdoc! {"
                {DISABLED_NOTE}
                # {line}
            "}),
            None => {
                out.push_str(line);
                out.push('\n');
            },
        }
    }

    out.push_str(&formatdoc! {r#"
        {BLOCK_START}
        Host *
          {OPTION} "{agent}"
        {BLOCK_END}
    "#});
    out
}

/// Removes the sentinel-delimited block a previous `configure` appended,
/// including the trailing newline after `BLOCK_END`. Returns the input
/// unchanged when no complete block is present.
fn strip_app_block(content: &str) -> String {
    let Some(start) = content.find(BLOCK_START) else {
        return content.to_string();
    };
    let Some(end_marker) = content[start..].find(BLOCK_END).map(|o| o + start) else {
        return content.to_string();
    };
    let after_end = end_marker + BLOCK_END.len();
    let end = match content[after_end..].find('\n') {
        Some(offset) => after_end + offset + 1,
        None => content.len(),
    };
    let mut out = content[..start].to_string();
    out.push_str(&content[end..]);
    out
}

fn set_owner_only(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        log::debug!("Failed to set permissions on {}: {e}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_the_identity_agent_option_case_insensitively() {
        assert_eq!(
            parse_option("IdentityAgent /path/to/agent.sock"),
            Some("/path/to/agent.sock")
        );
        assert_eq!(
            parse_option("  identityagent\t\"/with space/agent.sock\"  "),
            Some("\"/with space/agent.sock\"")
        );
        assert_eq!(parse_option("# IdentityAgent /path/to/agent.sock"), None);
        assert_eq!(parse_option("IdentityAgentX /path/to/agent.sock"), None);
        assert_eq!(parse_option("Host *"), None);
    }

    #[test]
    fn rewrite_is_idempotent() {
        let sock = "/tmp/axo/agent.sock";
        let once = rewrite_config("Host example\n  User me\n", sock);
        let twice = rewrite_config(&once, sock);
        assert_eq!(once, twice);
        assert_eq!(once.matches(BLOCK_START).count(), 1);
        assert!(once.contains("Host example\n  User me\n"));
    }

    #[test]
    fn rewrite_comments_out_an_existing_identity_agent() {
        let out = rewrite_config("IdentityAgent /other/agent.sock\n", "/tmp/axo/agent.sock");
        assert!(out.contains(&format!("{DISABLED_NOTE}\n# IdentityAgent /other/agent.sock")));
        assert!(out.contains("IdentityAgent \"/tmp/axo/agent.sock\""));
        assert_eq!(out.matches("\nIdentityAgent ").count(), 0);
    }

    #[test]
    fn strip_app_block_removes_only_the_block() {
        let content = format!("# keep\n{BLOCK_START}\nHost *\n  IdentityAgent \"x\"\n{BLOCK_END}\n# tail\n");
        assert_eq!(strip_app_block(&content), "# keep\n# tail\n");
        assert_eq!(strip_app_block("# no block here\n"), "# no block here\n");
    }
}
