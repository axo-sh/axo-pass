use std::sync::{Arc, Mutex, Once, OnceLock};

use axo_pass_core::audit;
use axo_pass_core::core::app_broker;
use axo_pass_core::core::auth::{
    AuthContext, AuthMethod, adopt_shared_context, external_auth_lock, invalidate_auth,
    run_on_auth_thread,
};
use axo_pass_core::secrets::vaults::storage::txn::VaultWriter;
use axo_pass_core::secrets::vaults::sync::manager::{AppUnlock, LogEvents, SyncManager};
use axo_pass_core::secrets::vaults::{VaultCatalog, VaultsManager};

use crate::*;

/// Sync manager of the process, started by the first [`AxoPass`].
static SYNC_MANAGER: OnceLock<SyncManager> = OnceLock::new();

#[derive(uniffi::Object)]
pub struct AxoPass {
    pub(crate) manager: Arc<Mutex<VaultsManager>>,
    /// Held between `begin_embedded_auth` and `end_embedded_auth` so a
    /// UI-driven prompt still serializes against other processes.
    pub(crate) embedded_auth_lock: Mutex<Option<std::fs::File>>,
    /// Shuts the app broker down; `Some` while it is serving.
    pub(crate) app_broker: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// The logins indexed at the last unlock. The broker lists from it for the
    /// clients that may list without a prompt.
    pub(crate) login_index: Arc<app_broker::LoginIndex>,
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        axo_pass_core::logging::init("app.log");
        audit::set_process_source(audit::Source::App);
        // Retention also runs on each save. This covers vaults that are not
        // saved again. The app creates several instances, so it runs once per
        // process.
        static PRUNE: Once = Once::new();
        PRUNE.call_once(|| {
            std::thread::spawn(|| VaultWriter::app().prune_all());
        });
        // One sync manager per process, for the same reason. It runs on its
        // own thread and logs its events until the app registers its own.
        SYNC_MANAGER.get_or_init(|| {
            SyncManager::start(
                VaultCatalog::app(),
                Arc::new(LogEvents),
                Arc::new(AppUnlock),
            )
        });
        let manager = VaultsManager::new();
        log::info!("Key state at launch: {:?}", manager.key_state());
        Arc::new(Self {
            manager: Arc::new(Mutex::new(manager)),
            embedded_auth_lock: Mutex::new(None),
            app_broker: Mutex::new(None),
            login_index: Arc::new(app_broker::LoginIndex::default()),
        })
    }

    /// Take the cross-process auth lock ahead of a UI-driven prompt (see
    /// `adopt_auth_context`). Blocks until no other process is prompting. Pair
    /// every call with `end_embedded_auth`.
    pub async fn begin_embedded_auth(&self) -> Result<(), FfiError> {
        let file = tokio::task::spawn_blocking(external_auth_lock)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?;
        *self
            .embedded_auth_lock
            .lock()
            .map_err(|_| FfiError::Poisoned)? = Some(file);
        Ok(())
    }

    /// Release the lock taken by `begin_embedded_auth`.
    pub fn end_embedded_auth(&self) -> Result<(), FfiError> {
        self.embedded_auth_lock
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .take();
        Ok(())
    }

    /// Adopt an `LAContext` the UI created and authenticated, making it the
    /// shared context for subsequent vault operations.
    ///
    /// The UI owns the context so it can attach an `LAAuthenticationView` and
    /// draw the biometric prompt inline. `context_ptr` is the address of a live
    /// `LAContext`; the caller keeps its own reference across the call.
    pub fn adopt_auth_context(&self, context_ptr: u64) -> Result<(), FfiError> {
        if context_ptr == 0 {
            return Err(FfiError::InvalidInput(
                "the app did not return an authentication session".into(),
            ));
        }
        unsafe { adopt_shared_context(context_ptr as *mut std::ffi::c_void) }
            .map_err(FfiError::from)
    }

    /// Authenticate globally via Touch ID / password, showing the system
    /// dialog. One prompt covers all subsequent vault operations for the
    /// lifetime of the LAContext. Mirrors `unlock_axo` in the Tauri app.
    ///
    /// The macOS app unlocks through `adopt_auth_context` instead so it can
    /// draw the prompt inline. This remains for callers with no UI, such as the
    /// `ap` CLI.
    pub async fn unlock(&self) -> Result<(), FfiError> {
        let result: Result<(), FfiError> = tokio::task::spawn_blocking(|| {
            run_on_auth_thread(
                AuthContext::SharedThreadLocal,
                AuthMethod::Policy {
                    reason: "unlock Axo Pass".to_string(),
                },
                |_| {},
            )
            .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?;

        let (outcome, message) = match &result {
            Ok(()) => (audit::Outcome::Succeeded, None),
            Err(FfiError::AuthCancelled) => (audit::Outcome::Cancelled, None),
            Err(e) => (audit::Outcome::Failed, Some(e.to_string())),
        };
        let mut event =
            audit::AuditEvent::new(audit::process_source(), audit::Action::VaultUnlock, outcome);
        if let Some(message) = message {
            event = event.message(message);
        }
        audit::record_async(event).await;
        result
    }

    /// Drop every decrypted vault from memory and invalidate the shared
    /// LAContext. Reading items again costs a decryption and a fresh prompt.
    /// Mirrors `lock_axo` in the Tauri app.
    pub fn lock(&self) -> Result<(), FfiError> {
        self.manager
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .lock_all();
        invalidate_auth();
        audit::record(audit::AuditEvent::new(
            audit::process_source(),
            audit::Action::VaultLock,
            audit::Outcome::Succeeded,
        ));
        Ok(())
    }
}
