use std::io::Write;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use tokio::sync::oneshot;

use crate::app::password_request::{PasswordRequest, PasswordRequestHandler, RequestState};
use crate::secrets::keychain::generic_password::PasswordEntry;
use crate::ssh::utils::get_ssh_key_fingerprint;

static PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    let valid_path_char = r#"[^:!$`&*()'"+/\\]"#;
    let path_re_raw = format!("(/{valid_path_char}+)+/?");
    Regex::new(&path_re_raw).unwrap()
});

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SshAskPassRequest {
    pub key_path: Option<String>, // ssh key path
    pub prompt: String,           // original askpass prompt message

    /* common fields that we populate for the frontend */
    pub key_id: Option<String>,          // ssh fingerprint
    pub has_saved_password: bool,        // whether a password is already saved for this key
    pub attempting_saved_password: bool, // whether we're prompting for saved password
}

// Implement PasswordRequest trait for SshAskPassRequest
impl PasswordRequest for SshAskPassRequest {
    fn entry(&self) -> Option<PasswordEntry> {
        self.key_id
            .as_ref()
            .map(|key_id| PasswordEntry::ssh(key_id))
    }

    fn has_saved_password(&self) -> bool {
        self.has_saved_password
    }

    fn is_attempting_saved_password(&self) -> bool {
        self.attempting_saved_password
    }

    fn set_attempting_saved_password(&mut self, attempting: bool) {
        self.attempting_saved_password = attempting;
    }

    fn set_has_saved_password(&mut self, has_saved: bool) {
        self.has_saved_password = has_saved;
    }
}

// Type alias for the SSH askpass-specific state
pub type AskPassState = RequestState<SshAskPassRequest>;

/// SSH askpass handler that integrates with Tauri
pub struct SshAskpassHandler {
    password_handler: PasswordRequestHandler<SshAskPassRequest>,
    exit_sender: Option<oneshot::Sender<()>>,
}

impl SshAskpassHandler {
    pub fn new(state: AskPassState, exit_sender: oneshot::Sender<()>) -> Self {
        let password_handler = PasswordRequestHandler::new(state.clone(), "askpass-request");
        Self {
            password_handler,
            exit_sender: Some(exit_sender),
        }
    }

    /// Run the SSH askpass handler
    pub async fn run(mut self, prompt: String) -> anyhow::Result<()> {
        log::debug!("ssh-askpass: {}", prompt.trim());

        let mut request = SshAskPassRequest {
            key_path: None,
            prompt: prompt.trim().to_string(),
            key_id: None,
            has_saved_password: false,
            attempting_saved_password: false,
        };

        // Parse the prompt to extract key path if available, otherwise we
        // show the original prompt to the user
        if let Some(key_path) = Self::extract_key_path(&prompt) {
            request.key_path = Some(key_path.clone());
            request.key_id = get_ssh_key_fingerprint(&key_path);
            log::debug!(
                "ssh-askpass: identified key {key_path} [{:?}]",
                request.key_id.clone().map(|k| k.as_str()[0..6].to_string())
            );
        }

        if request
            .key_id
            .as_ref()
            .and_then(|key_id| PasswordEntry::ssh(key_id).exists().ok())
            .unwrap_or(false)
        {
            request.set_has_saved_password(true);
            request.set_attempting_saved_password(true);
        }

        // Use the shared password handler to get the password
        match self.password_handler.handle_request(request).await? {
            Some(password) => {
                // Write password to stdout (SSH reads from here)
                let mut stdout = std::io::stdout();
                stdout.write_all(password.as_bytes())?;
                stdout.flush()?;

                // Signal exit
                if let Some(tx) = self.exit_sender.take() {
                    let _ = tx.send(());
                }

                Ok(())
            },
            None => {
                // User cancelled
                if let Some(tx) = self.exit_sender.take() {
                    let _ = tx.send(());
                }

                Err(anyhow::anyhow!("User cancelled password entry"))
            },
        }
    }

    /// Extract key path from SSH askpass prompt
    fn extract_key_path(prompt: &str) -> Option<String> {
        let prompt = prompt.trim();

        // if prompt has "enter passphrase", search for key path patterns
        if prompt.to_lowercase().contains("enter passphrase") {
            PATH_REGEX
                .find(prompt)
                .map(|m| m.as_str().trim().to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_regex() {
        let test_keys = vec![
            "/Users/example/.ssh/id_ed25519",
            r#"/Users/foo bar/.ssh/id ed25519"#,
        ];

        for key in test_keys {
            let test_cases = vec![
                // ssh-add <key>
                r#"Enter passphrase for {}:"#,
                // ssh-add -c <key>
                r#"Enter passphrase for {} (will confirm each use):"#,
                // ssh-keygen -y -f <key> (has quotes)
                r#"Enter passphrase for "{}":"#,
                // ssh -T git@github.com
                r#"Enter passphrase for key '{}':"#,
                // some other variants
                r#"Enter passphrase for {}"#,
                r#"Enter passphrase for "{}" (will confirm each use)"#,
            ];
            for prompt_template in test_cases {
                let prompt = prompt_template.replace("{}", key);
                let extracted_path = SshAskpassHandler::extract_key_path(&prompt);
                assert_eq!(extracted_path.as_deref(), Some(key));
            }
        }
    }
}
