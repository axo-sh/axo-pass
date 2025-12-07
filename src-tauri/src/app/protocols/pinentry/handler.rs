use serde::Serialize;
use tokio::sync::oneshot;

use crate::app::password_request::{PasswordRequest, PasswordRequestHandler, RequestState};
use crate::app::protocols::pinentry::server::PinentryServerHandler;
use crate::secrets::keychain::generic_password::PasswordEntry;

#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct GetPinRequest {
    description: Option<String>,
    prompt: Option<String>,

    /* additional fields that we populate for the frontend */
    key_id: Option<String>,          // extracted GPG key ID
    has_saved_password: bool,        // whether a password is already saved for this key
    attempting_saved_password: bool, // whether we're prompting for saved password
    error_message: Option<String>,
}

// Implement PasswordRequest trait for GetPinRequest
impl PasswordRequest for GetPinRequest {
    fn entry(&self) -> Option<PasswordEntry> {
        self.key_id
            .as_ref()
            .map(|key_id| PasswordEntry::gpg(key_id))
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

pub type PinentryState = RequestState<GetPinRequest>;

pub struct PinentryHandler {
    password_handler: PasswordRequestHandler<GetPinRequest>,
    exit_sender: Option<oneshot::Sender<()>>,
}

impl PinentryHandler {
    pub fn new(state: PinentryState, exit_sender: oneshot::Sender<()>) -> Self {
        let password_handler = PasswordRequestHandler::new(state.clone(), "pinentry-request");
        Self {
            password_handler,
            exit_sender: Some(exit_sender),
        }
    }
}

#[async_trait::async_trait]
impl PinentryServerHandler for PinentryHandler {
    fn signal_exit(&mut self) {
        if let Some(sender) = self.exit_sender.take() {
            let _ = sender.send(());
        }
    }

    async fn get_pin(
        &mut self,
        desc: Option<&str>,
        prompt: Option<&str>,
        keyinfo: Option<&str>,
        error_message: Option<&str>,
    ) -> std::io::Result<String> {
        // use keyinfo (GPG key grip from SETKEYINFO), or else try to extract key ID
        // from desc
        /*
        ... It currently has the form
        'X/HEXSTRING' where 'X' is either 'n', 's', or 'u'.  In the former
        two cases, the HEXSTRING corresponds to the key grip.  The key grip
        is not the OpenPGP Key ID, but it can be mapped to the key using
        the following: gpg --with-keygrip --list-secret-keys
        */
        let key_id = keyinfo.and_then(|k| k.rsplit('/').next()).map(String::from);

        let has_saved_password = key_id
            .as_ref()
            .and_then(|key_id| PasswordEntry::gpg(key_id).exists().ok())
            .unwrap_or(false);

        // Skip saved password if there's an error message (e.g., bad passphrase)
        let skip_saved_password = error_message.is_some();

        let request = GetPinRequest {
            description: desc.map(String::from),
            prompt: prompt.map(String::from),
            error_message: error_message.map(String::from),
            key_id: key_id.clone(),
            has_saved_password,
            attempting_saved_password: has_saved_password && !skip_saved_password,
        };

        self.password_handler
            .handle_request(request)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .ok_or_else(|| std::io::Error::other("User cancelled"))
    }

    async fn confirm(&mut self, desc: Option<&str>) -> std::io::Result<bool> {
        self.password_handler
            .handle_confirm(desc.map(String::from))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    async fn message(&mut self, desc: Option<&str>) -> std::io::Result<()> {
        self.password_handler
            .handle_message(desc.map(String::from))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}
