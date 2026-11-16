use std::sync::{Arc, Mutex, Once, OnceLock};

use axo_pass_core::audit;
use axo_pass_core::core::app_broker;
use axo_pass_core::core::auth::{adopt_shared_context, external_auth_lock, invalidate_auth};
use axo_pass_core::secrets::vaults::storage::txn::VaultWriter;
use axo_pass_core::secrets::vaults::sync::manager::{AppUnlock, SyncManager};
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
        // own thread. Its events are logged, and forwarded to the delegate
        // once `set_sync_events` sets it (D12).
        SYNC_MANAGER.get_or_init(|| {
            SyncManager::start(
                VaultCatalog::app(),
                ForwardEvents::shared(),
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

    /// Drop every decrypted vault from memory and invalidate the shared
    /// LAContext. Reading items again costs a decryption and a new unlock by
    /// the app.
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

impl AxoPass {
    /// Sync manager of the process. Every `AxoPass` starts it in `new`.
    pub(crate) fn sync_manager() -> Result<&'static SyncManager, FfiError> {
        SYNC_MANAGER
            .get()
            .ok_or_else(|| FfiError::Internal("sync manager did not start".into()))
    }

    /// Find the synced vaults again, after an enable, a join, a disable, a
    /// delete, a rebuild, or a root change. Does nothing if no manager
    /// started.
    pub(crate) fn refresh_sync() {
        if let Some(manager) = SYNC_MANAGER.get() {
            manager.refresh();
        }
    }
}

/// Stop the sync manager of the process at quit (D17). Ends every watch and
/// deletes the pairing request of the new Mac, if one is pending. Waits for
/// a scan, a poll, or a transaction that runs. Does nothing if no manager
/// started or it already stopped.
#[uniffi::export]
pub fn sync_shutdown() {
    if let Some(manager) = SYNC_MANAGER.get() {
        manager.shutdown();
    }
}
