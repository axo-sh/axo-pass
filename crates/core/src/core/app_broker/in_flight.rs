//! Tracks a request while the app serves it, so a client that disconnects ends
//! its prompt.

use tokio::io::AsyncReadExt;

use crate::core::auth::ForeignContext;

/// The request being served. It is abandoned when the client that sent it
/// disconnects, which ends its prompt. The broker serves one connection at a
/// time, and an abandoned prompt would otherwise block the requests behind it.
pub(super) struct InFlightRequest {
    context: std::sync::Mutex<Option<ForeignContext>>,
    abandoned: tokio::sync::watch::Sender<bool>,
}

impl Default for InFlightRequest {
    fn default() -> Self {
        Self {
            context: std::sync::Mutex::new(None),
            abandoned: tokio::sync::watch::Sender::new(false),
        }
    }
}

impl InFlightRequest {
    /// Attach the context the request's prompt evaluates on. Abandoning the
    /// request invalidates it, which fails the evaluation and so ends the
    /// prompt through the usual path. Invalidates it at once if the request is
    /// already abandoned.
    pub(super) fn attach(&self, context: &ForeignContext) {
        let mut slot = self.context.lock().unwrap_or_else(|e| e.into_inner());
        if *self.abandoned.borrow() {
            context.invalidate();
        } else {
            *slot = Some(context.clone());
        }
    }

    /// Run `prompt` unless the request is abandoned first, in which case
    /// `None`. For prompts with no context to invalidate: dropping a call into
    /// the app cancels its task, and the app dismisses a cancelled prompt.
    pub(super) async fn unless_abandoned<T>(&self, prompt: impl Future<Output = T>) -> Option<T> {
        let mut abandoned = self.abandoned.subscribe();
        // Checked first, so a request already abandoned never starts its
        // prompt.
        tokio::select! {
            biased; // poll in order
            _ = abandoned.wait_for(|abandoned| *abandoned) => None,
            value = prompt => Some(value),
        }
    }

    /// Run `prompt` to completion. If the request is abandoned first, `abandon`
    /// runs while it waits and should make `prompt` finish early. For a prompt
    /// that must not be dropped partway, because the app would carry on with it
    /// alongside the next request.
    pub(super) async fn abandoning<T>(
        &self,
        prompt: impl Future<Output = T>,
        abandon: impl Future<Output = ()>,
    ) -> T {
        tokio::pin!(prompt);
        let mut abandoned = self.abandoned.subscribe();
        tokio::select! {
            value = &mut prompt => return value,
            _ = abandoned.wait_for(|abandoned| *abandoned) => {},
        }
        abandon.await;
        prompt.await
    }

    pub(super) fn is_abandoned(&self) -> bool {
        *self.abandoned.borrow()
    }

    pub(super) fn abandon(&self) {
        let mut slot = self.context.lock().unwrap_or_else(|e| e.into_inner());
        self.abandoned.send_replace(true);
        if let Some(context) = slot.take() {
            context.invalidate();
        }
    }
}

/// Resolves once the client closes its end. A client sends one request line
/// and then only waits for the response, so any read returning means it has
/// disconnected.
pub(super) async fn client_disconnected(reader: &mut (impl tokio::io::AsyncRead + Unpin)) {
    let mut buf = [0u8; 64];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {},
        }
    }
}
