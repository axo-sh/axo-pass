use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;
use tokio::sync::oneshot;

use crate::password_request::{PasswordRequest, PasswordRequestHandler, RequestState};
use crate::secrets::keychain::generic_password::PasswordEntry;

#[derive(Clone, Debug, Serialize)]
pub struct AskPasswordRequest {
    pub key_path: Option<String>,
    pub key_id: Option<String>,
    pub has_saved_password: bool,
    pub attempting_saved_password: bool,
}

// Implement PasswordRequest trait for AskPasswordRequest
impl PasswordRequest for AskPasswordRequest {
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
pub type AskPassState = RequestState<AskPasswordRequest>;

/// SSH askpass handler that integrates with Tauri
pub struct SshAskpassHandler {
    password_handler: PasswordRequestHandler<AskPasswordRequest>,
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
        // Parse the prompt to extract key path if available
        log::debug!("ssh-askpass: {}", prompt.trim());
        // Create a password request
        let mut request = AskPasswordRequest {
            key_path: None,
            key_id: None,
            has_saved_password: false,
            attempting_saved_password: false,
        };

        if let Some(key_path) = Self::extract_key_path(&prompt) {
            request.key_path = Some(key_path.clone());
            request.key_id = get_ssh_key_fingerprint(&key_path);
            log::debug!(
                "ssh-askpass: identified key {key_path} [{:?}]",
                request.key_id
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
        let passphrase_re = regex::Regex::new(
            r"^Enter passphrase for (?P<key_path>[^\s]+)(?: \(will confirm each use\))?:$",
        )
        .ok()?;

        passphrase_re
            .captures(prompt)
            .and_then(|caps| caps.name("key_path"))
            .map(|m| m.as_str().to_string())
    }
}

fn get_ssh_key_fingerprint(key_path: &str) -> Option<String> {
    if !PathBuf::from(&key_path).exists() {
        return None;
    }

    match std::process::Command::new("ssh-keygen")
        .arg("-l")
        .arg("-E")
        .arg("sha256")
        .arg("-f")
        .arg(key_path)
        .output()
    {
        Ok(output) => {
            if output.status.success()
                && let Ok(stdout) = String::from_utf8(output.stdout)
                && let Some(fingerprint) = stdout.split_whitespace().nth(1)
            {
                Some(
                    fingerprint
                        .split_once(':')
                        .map(|(_, fp)| fp.to_string())
                        .unwrap_or_else(|| fingerprint.to_owned()),
                )
            } else {
                log::error!(
                    "ssh-keygen failed or produced invalid output: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                None
            }
        },
        Err(err) => {
            log::error!("Failed to get key ID from ssh-keygen: {err}");
            None
        },
    }
}
