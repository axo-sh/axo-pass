//! Parses `ssh`/`ssh-add`'s askpass prompt text to find the key it names, so
//! `ap ssh-askpass` can look up (or save) that key's passphrase in the
//! keychain instead of asking every time.

use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;

use super::utils::get_ssh_key_fingerprint;

/// Absolute path to the bundled `ap-ssh-askpass` wrapper.
///
/// Inside the bundle the main executable sits in `Contents/MacOS/` and the
/// wrapper in `Contents/Resources/` (see `strudel.toml`). Outside a bundle
/// there is no wrapper to point at.
pub fn wrapper_path() -> Option<PathBuf> {
    let exe = std::env::current_exe()
        .inspect_err(|e| log::debug!("Failed to get exe path: {e}"))
        .ok()?;
    let candidate = exe.parent()?.parent()?.join("Resources/ap-ssh-askpass");
    candidate.exists().then_some(candidate)
}

static PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    let valid_path_char = r#"[^:!$`&*()'"+/\\]"#;
    let path_re_raw = format!("(/{valid_path_char}+)+/?");
    Regex::new(&path_re_raw).unwrap()
});

/// The key path named in an "Enter passphrase for ..." prompt, if this is
/// one. Other prompts (e.g. a password prompt for `user@host's password:`)
/// don't identify a key.
pub fn extract_key_path(prompt: &str) -> Option<String> {
    let prompt = prompt.trim();
    if !prompt.to_lowercase().contains("enter passphrase") {
        return None;
    }
    PATH_REGEX.find(prompt).map(|m| m.as_str().trim().to_string())
}

/// The keychain fingerprint for the key an askpass prompt names, if any.
pub fn key_id_from_prompt(prompt: &str) -> Option<String> {
    extract_key_path(prompt).and_then(|path| get_ssh_key_fingerprint(&path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_key_path_from_common_prompt_shapes() {
        let test_keys = [
            "/Users/example/.ssh/id_ed25519",
            r#"/Users/foo bar/.ssh/id ed25519"#,
        ];

        for key in test_keys {
            let test_cases = [
                r#"Enter passphrase for {}:"#,
                r#"Enter passphrase for {} (will confirm each use):"#,
                r#"Enter passphrase for "{}":"#,
                r#"Enter passphrase for key '{}':"#,
                r#"Enter passphrase for {}"#,
                r#"Enter passphrase for "{}" (will confirm each use)"#,
            ];
            for prompt_template in test_cases {
                let prompt = prompt_template.replace("{}", key);
                assert_eq!(extract_key_path(&prompt).as_deref(), Some(key));
            }
        }
    }

    #[test]
    fn does_not_mistake_a_password_prompt_for_a_key() {
        assert_eq!(extract_key_path("user@host's password:"), None);
    }
}
