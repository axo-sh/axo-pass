use std::sync::{Arc, Mutex};

use secrecy::ExposeSecret;
use tauri::{AppHandle, Emitter};
use tokio::sync::oneshot;

use crate::pinentry;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::generic_password::PasswordEntry;

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GetPinRequest {
    description: Option<String>,
    prompt: Option<String>,

    /* additional fields that we populate for the frontend */
    key_id: Option<String>,          // extracted GPG key ID
    has_saved_password: bool,        // whether a password is already saved for this key
    attempting_saved_password: bool, // whether we're prompting for saved password
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinentryRequest {
    GetPin(GetPinRequest),
    GetPinSuccess(String), // internal only: indicates saved password retrieval success
    Confirm { description: Option<String> },
    Message { description: Option<String> },
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserPinentryResponse {
    UseSavedPassword,
    Confirmed,
    Cancelled,
    Password {
        value: String,
        save_to_keychain: bool,
    },
}

// Shared state for pinentry requests
#[derive(Default, Clone)]
pub struct PinentryState {
    // pending_request is initially created from the pinentry request
    // but also tracks intermediate states like GetPinSuccess
    pub pending_request: Arc<Mutex<Option<PinentryRequest>>>,
    pub response_sender: Arc<Mutex<Option<oneshot::Sender<UserPinentryResponse>>>>,
    pub app_handle: Arc<Mutex<Option<AppHandle>>>,
}

impl PinentryState {
    pub fn set_app_handle(&self, handle: AppHandle) {
        *self.app_handle.lock().unwrap() = Some(handle);
    }
}

// Pinentry handler that integrates with Tauri
pub struct TauriPinentryHandler {
    state: PinentryState,
    exit_sender: Option<oneshot::Sender<()>>,
}

impl TauriPinentryHandler {
    pub fn new(state: PinentryState, exit_sender: oneshot::Sender<()>) -> Self {
        Self {
            state,
            exit_sender: Some(exit_sender),
        }
    }

    fn set_pending_request(&mut self, request: PinentryRequest) {
        // Set the pending request
        *self.state.pending_request.lock().unwrap() = Some(request.clone());

        // Emit event to the frontend
        if let Some(app_handle) = self.state.app_handle.lock().unwrap().as_ref()
            && let Err(e) = app_handle.emit("pinentry-request", &request)
        {
            log::error!("Failed to emit pinentry-request event: {e}");
        }
    }

    fn clear_pending_request(&mut self) {
        *self.state.pending_request.lock().unwrap() = None;
    }

    async fn wait_for_response(&mut self) -> std::io::Result<UserPinentryResponse> {
        // Create a oneshot channel for receiving the response
        let (tx, rx) = oneshot::channel();
        *self.state.response_sender.lock().unwrap() = Some(tx);
        rx.await
            .map_err(|_| std::io::Error::other("Failed to receive response from user"))
    }

    async fn handle_request(&mut self, state: PinentryRequest) -> anyhow::Result<Option<String>> {
        let mut state = state.clone();
        loop {
            self.set_pending_request(state.clone());
            state = match state {
                // try to get saved password with keychain
                PinentryRequest::GetPin(ref get_pin) if get_pin.attempting_saved_password => {
                    let mut get_pin_prompt = get_pin.clone();
                    // so subsequent attempts don't attempt the saved password again
                    get_pin_prompt.attempting_saved_password = false;

                    if !get_pin_prompt.has_saved_password {
                        // if no saved password, this will loop to prompt the user
                        PinentryRequest::GetPin(get_pin_prompt)
                    } else if let Some(ref key_id) = get_pin.key_id {
                        match PasswordEntry::gpg(key_id).get_password() {
                            Ok(Some(password)) => {
                                PinentryRequest::GetPinSuccess(password.expose_secret().to_owned())
                            },
                            Ok(None) => {
                                // no saved password
                                get_pin_prompt.has_saved_password = false;
                                PinentryRequest::GetPin(get_pin_prompt)
                            },
                            Err(KeychainError::UserCancelled) => {
                                PinentryRequest::GetPin(get_pin_prompt)
                            },
                            Err(err) => {
                                // unknown error
                                log::error!(
                                    "Error retrieving saved password for key_id {:?}: {err}",
                                    get_pin.key_id
                                );
                                get_pin_prompt.has_saved_password = false;
                                PinentryRequest::GetPin(get_pin_prompt)
                            },
                        }
                    } else {
                        // no key id
                        get_pin_prompt.has_saved_password = false;
                        PinentryRequest::GetPin(get_pin_prompt)
                    }
                },

                // wait for user to provide password or request saved password
                PinentryRequest::GetPin(ref get_pin) => match self.wait_for_response().await? {
                    UserPinentryResponse::Password {
                        value,
                        save_to_keychain,
                    } => {
                        if save_to_keychain && let Some(ref kid) = get_pin.key_id {
                            log::debug!("Calling save_password_with_touchid for key: {kid}");
                            match PasswordEntry::gpg(&kid).save_password(&value) {
                                Ok(()) => {
                                    log::debug!("Successfully saved password to keychain");
                                },
                                Err(e) => {
                                    log::error!("Failed to save password to keychain: {e}");
                                },
                            }
                        }
                        PinentryRequest::GetPinSuccess(value)
                    },
                    UserPinentryResponse::UseSavedPassword => {
                        let mut get_pin = get_pin.clone();
                        get_pin.attempting_saved_password = true;
                        PinentryRequest::GetPin(get_pin)
                    },
                    UserPinentryResponse::Cancelled => return Ok(None), // user cancelled

                    UserPinentryResponse::Confirmed => {
                        anyhow::bail!("invalid confirmed user response in get_pin loop")
                    },
                },

                // internal state: success, return password
                PinentryRequest::GetPinSuccess(password) => {
                    self.clear_pending_request();
                    if let Some(app_handle) = self.state.app_handle.lock().unwrap().as_ref()
                        && let Err(e) = app_handle.emit(
                            "pinentry-request",
                            PinentryRequest::GetPinSuccess("".to_string()),
                        )
                    {
                        log::error!("Failed to emit pinentry-request event: {e}");
                    }
                    log::debug!("Retrieved password successfully");
                    return Ok(Some(password));
                },

                PinentryRequest::Confirm { .. } => {
                    anyhow::bail!("cannot handle pinentry CONFIRM in get_pin loop");
                },

                PinentryRequest::Message { .. } => {
                    anyhow::bail!("cannot handle pinentry MESSAGE in get_pin loop");
                },
            }
        }
    }
}

#[async_trait::async_trait]
impl pinentry::PinentryHandler for TauriPinentryHandler {
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
            .and_then(|kid| PasswordEntry::gpg(&kid).exists().ok())
            .unwrap_or(false);

        let state = PinentryRequest::GetPin(GetPinRequest {
            description: desc.map(String::from),
            prompt: prompt.map(String::from),
            key_id: key_id.clone(),
            has_saved_password,
            attempting_saved_password: has_saved_password,
        });

        self.handle_request(state)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .ok_or_else(|| std::io::Error::other("User cancelled"))
    }

    async fn confirm(&mut self, desc: Option<&str>) -> std::io::Result<bool> {
        self.set_pending_request(PinentryRequest::Confirm {
            description: desc.map(String::from),
        });
        match self.wait_for_response().await? {
            UserPinentryResponse::Confirmed => Ok(true),
            UserPinentryResponse::Cancelled => Ok(false),
            _ => Err(std::io::Error::other("Unexpected response for confirm")),
        }
    }

    async fn message(&mut self, desc: Option<&str>) -> std::io::Result<()> {
        self.set_pending_request(PinentryRequest::Message {
            description: desc.map(String::from),
        });
        match self.wait_for_response().await? {
            UserPinentryResponse::Confirmed => Ok(()),
            _ => Err(std::io::Error::other("Unexpected response for message")),
        }
    }
}
