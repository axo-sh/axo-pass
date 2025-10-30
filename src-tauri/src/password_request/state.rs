use std::sync::{Arc, Mutex};

use tauri::AppHandle;
use tokio::sync::oneshot;

use super::types::{PasswordRequest, PasswordResponse, RequestEvent};

/// Shared state for password requests
#[derive(Clone)]
pub struct RequestState<Req>
where
    Req: PasswordRequest,
{
    /// The current pending request event (GetPassword or Success). We generally
    /// emit this directly to the frontend, but we store it so if the frontend
    /// page gets reloaded, we can bootstrap it with the pending event.
    pub pending_event: Arc<Mutex<Option<RequestEvent<Req>>>>,

    /// Channel sender for receiving user responses
    pub response_sender: Arc<Mutex<Option<oneshot::Sender<PasswordResponse>>>>,

    /// Reference to the Tauri app handle for emitting events
    pub app_handle: Arc<Mutex<Option<AppHandle>>>,
}

impl<Req> Default for RequestState<Req>
where
    Req: PasswordRequest,
{
    fn default() -> Self {
        Self {
            pending_event: Arc::new(Mutex::new(None)),
            response_sender: Arc::new(Mutex::new(None)),
            app_handle: Arc::new(Mutex::new(None)),
        }
    }
}

impl<Req> RequestState<Req>
where
    Req: PasswordRequest,
{
    pub fn set_app_handle(&self, handle: AppHandle) {
        *self.app_handle.lock().unwrap() = Some(handle);
    }

    pub fn get_app_handle(&self) -> Option<AppHandle> {
        self.app_handle.lock().unwrap().as_ref().cloned()
    }

    pub fn set_pending_event(&self, event: RequestEvent<Req>) {
        *self.pending_event.lock().unwrap() = Some(event);
    }

    pub fn get_pending_event(&self) -> Option<RequestEvent<Req>> {
        self.pending_event.lock().unwrap().clone()
    }

    pub fn clear_pending_event(&self) {
        *self.pending_event.lock().unwrap() = None;
    }

    pub fn set_response_sender(&self, sender: oneshot::Sender<PasswordResponse>) {
        *self.response_sender.lock().unwrap() = Some(sender);
    }

    pub fn take_response_sender(&self) -> Option<oneshot::Sender<PasswordResponse>> {
        self.response_sender.lock().unwrap().take()
    }
}
