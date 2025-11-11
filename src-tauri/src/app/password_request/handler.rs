use secrecy::ExposeSecret;
use serde::Serialize;
use tauri::Emitter;
use tokio::sync::oneshot;

use crate::app::password_request::{PasswordRequest, PasswordResponse, RequestEvent, RequestState};
use crate::secrets::keychain::errors::KeychainError;

/// Generic password request handler, contains state machine logic for
/// requesting passwords from user in the app
pub struct PasswordRequestHandler<Req>
where
    Req: PasswordRequest + Serialize,
{
    state: RequestState<Req>,
    event_name: String,
}

impl<Req> PasswordRequestHandler<Req>
where
    Req: PasswordRequest + Serialize,
{
    pub fn new(state: RequestState<Req>, event_name: impl Into<String>) -> Self {
        Self {
            state,
            event_name: event_name.into(),
        }
    }

    /// Emit an event to the frontend
    fn emit_event<T: Serialize + Clone>(&self, event: &T) {
        if let Some(app_handle) = self.state.get_app_handle()
            && let Err(e) = app_handle.emit(&self.event_name, event)
        {
            log::error!("Failed to emit {} event: {e}", self.event_name);
        }
    }

    /// Set the pending request and emit event to frontend
    fn set_pending_event(&self, event: RequestEvent<Req>) {
        self.state.set_pending_event(event.clone());
        self.emit_event(&event);
    }

    /// Clear the pending request
    fn clear_pending_event(&self) {
        self.state.clear_pending_event();
    }

    /// Wait for user response
    async fn wait_for_response(&self) -> std::io::Result<PasswordResponse> {
        let (tx, rx) = oneshot::channel();
        self.state.set_response_sender(tx);
        rx.await
            .map_err(|_| std::io::Error::other("Failed to receive response from user"))
    }

    /// Handle a password request as a state machine.
    pub async fn handle_request(&self, request: Req) -> anyhow::Result<Option<String>> {
        let mut event = RequestEvent::GetPassword(request.clone());

        loop {
            self.set_pending_event(event.clone());

            event = match event {
                // Try to get saved password from keychain
                RequestEvent::GetPassword(ref req) if req.is_attempting_saved_password() => {
                    let mut updated_req = req.clone();
                    // So subsequent attempts don't attempt the saved password again
                    updated_req.set_attempting_saved_password(false);

                    if !req.has_saved_password() {
                        // If no saved password, loop to prompt the user to enter password
                        RequestEvent::GetPassword(updated_req)
                    } else if let Some(entry) = req.entry()
                        && let Some(password) = entry.get_password().transpose()
                    {
                        // attempt to get the saved password: get_password above asks the user to
                        // authenticate with touch id/password
                        match password {
                            Ok(password) => {
                                RequestEvent::Success(password.expose_secret().to_owned())
                            },
                            Err(KeychainError::UserCancelled) => {
                                log::debug!("User cancelled keychain access for {entry:?}");
                                RequestEvent::GetPassword(updated_req)
                            },
                            Err(err) => {
                                log::error!("Error retrieving saved password for {entry:?}: {err}",);
                                updated_req.set_has_saved_password(false);
                                RequestEvent::GetPassword(updated_req)
                            },
                        }
                    } else {
                        // No key id or no saved password
                        updated_req.set_has_saved_password(false);
                        RequestEvent::GetPassword(updated_req)
                    }
                },

                // Wait for user to provide password or request saved password
                RequestEvent::GetPassword(ref req) => {
                    match self.wait_for_response().await? {
                        response if response.is_password() => {
                            if let Some((value, save_to_keychain)) = response.into_password() {
                                if save_to_keychain && let Some(entry) = req.entry() {
                                    log::debug!("Saving password to keychain for {entry:?}");
                                    match entry.save_password(&value) {
                                        Ok(()) => {
                                            log::debug!("Successfully saved password to keychain");
                                        },
                                        Err(e) => {
                                            log::error!("Failed to save password to keychain: {e}");
                                        },
                                    }
                                }
                                RequestEvent::Success(value)
                            } else {
                                anyhow::bail!("Password response did not contain value")
                            }
                        },
                        response if response.is_use_saved_password() => {
                            let mut updated_req = req.clone();
                            updated_req.set_attempting_saved_password(true);
                            RequestEvent::GetPassword(updated_req)
                        },
                        response if response.is_cancelled() => {
                            // User cancelled in our UI (not keychain prompt)
                            return Ok(None);
                        },
                        _ => {
                            anyhow::bail!("Unexpected response type for password request")
                        },
                    }
                },

                // Internal state: success, return password
                RequestEvent::Success(password) => {
                    self.clear_pending_event();
                    // Emit success event with empty password for security (maybe make a different
                    // event?)
                    self.emit_event(&RequestEvent::<Req>::Success("".to_string()));
                    log::debug!("Retrieved password successfully");
                    return Ok(Some(password));
                },

                // Handle confirmation requests
                RequestEvent::Confirm { .. } => {
                    anyhow::bail!("Confirm events should be handled via handle_confirm method")
                },

                // Handle message requests
                RequestEvent::Message { .. } => {
                    anyhow::bail!("Message events should be handled via handle_message method")
                },
            }
        }
    }

    /// Handle a confirmation request
    pub async fn handle_confirm(&self, description: Option<String>) -> anyhow::Result<bool> {
        let event = RequestEvent::<Req>::Confirm { description };
        self.set_pending_event(event);

        match self.wait_for_response().await? {
            response if response.is_confirmed() => Ok(true),
            response if response.is_cancelled() => Ok(false),
            _ => anyhow::bail!("Unexpected response type for confirm request"),
        }
    }

    /// Handle a message request
    pub async fn handle_message(&self, description: Option<String>) -> anyhow::Result<()> {
        let event = RequestEvent::<Req>::Message { description };
        self.set_pending_event(event);

        match self.wait_for_response().await? {
            response if response.is_confirmed() => Ok(()),
            _ => anyhow::bail!("Unexpected response type for message request"),
        }
    }
}
