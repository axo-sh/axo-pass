use crate::password_request::PasswordResponse;
use crate::pinentry_handler::PinentryState;
use crate::ssh_askpass_handler::AskPassState;

#[tauri::command]
pub async fn send_pinentry_response(
    response: PasswordResponse,
    state: tauri::State<'_, PinentryState>,
) -> Result<(), String> {
    if let Some(sender) = state.take_response_sender() {
        sender
            .send(response)
            .map_err(|_| "Failed to send response".to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn send_askpass_response(
    response: PasswordResponse,
    state: tauri::State<'_, AskPassState>,
) -> Result<(), String> {
    if let Some(sender) = state.take_response_sender() {
        sender
            .send(response)
            .map_err(|_| "Failed to send response".to_string())?;
    }
    Ok(())
}
