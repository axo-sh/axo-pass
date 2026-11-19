use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::audit;
use crate::core::app_broker::{
    BrokerPasswordEntry, ClientIdentity, CollectedPassphrase, ConfirmPrompt, KeychainLister,
    PassphraseAuthorizer, PassphraseKind, PassphrasePrompt, PromptOutcome, SignAuthorizer,
    SignPrompt, vault,
};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::generic_password::PasswordEntryType;
use crate::ssh::app_grants::GrantApp;

/// The passphrase the stub hands back when asked to collect one.
pub(super) const STUB_PASSPHRASE: &str = "hunter2";

/// Stands in for the app. It cannot produce a real `LAContext`, so both
/// `begin` methods decline. A request that reaches it has still been
/// accepted, framed, parsed and routed, which is what these tests cover.
#[derive(Default)]
pub(in crate::core::app_broker) struct StubAuthorizer {
    pub(super) prompts: Mutex<Vec<SignPrompt>>,
    pub(super) passphrase_prompts: Mutex<Vec<PassphrasePrompt>>,
    /// Kinds of the passphrase prompts passed to `begin`.
    pub(super) passphrase_kinds: Mutex<Vec<PassphraseKind>>,
    /// Whether the keychain listing fails on the shared context, as it does
    /// in a locked app.
    pub(super) locked: AtomicBool,
    pub(super) vault_prompts: Mutex<Vec<vault::VaultAccessPrompt>>,
    pub(super) peers: Mutex<Vec<audit::Actor>>,
    pub(super) ended: AtomicUsize,
    pub(super) prompts_hung: AtomicUsize,
    pub(super) prompts_dropped: AtomicUsize,
    /// Signalled when the broker abandons a vault request, as the app's
    /// prompt does when its client disconnects.
    abandoned: tokio::sync::Notify,
}

impl StubAuthorizer {
    /// Wait for a user who never answers, until the request is abandoned.
    /// Starting and ending the wait are both counted.
    async fn hang(&self) {
        self.prompts_hung.fetch_add(1, Ordering::SeqCst);
        struct Dropped<'a>(&'a AtomicUsize);
        impl Drop for Dropped<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let _dropped = Dropped(&self.prompts_dropped);
        self.abandoned.notified().await;
    }
}

/// Answers with a fixed entry instead of reading the login keychain, which
/// would raise an authorization prompt and stall the suite. If `locked` is
/// set, the shared context fails as it does in a locked app.
impl KeychainLister for StubAuthorizer {
    fn list_passwords(
        &self,
        context: AuthContext,
    ) -> Result<Vec<BrokerPasswordEntry>, KeychainError> {
        if self.locked.load(Ordering::SeqCst) && matches!(context, AuthContext::SharedThreadLocal) {
            return Err(KeychainError::AuthenticationExpired);
        }
        Ok(vec![BrokerPasswordEntry {
            password_type: PasswordEntryType::SSHKey,
            key_id: "stub".to_string(),
        }])
    }
}

#[async_trait]
impl SignAuthorizer for StubAuthorizer {
    async fn begin(
        &self,
        prompt: SignPrompt,
        peer: audit::Actor,
    ) -> Result<ForeignContext, String> {
        self.prompts.lock().unwrap().push(prompt);
        self.peers.lock().unwrap().push(peer);
        Err("stub authorizer".to_string())
    }

    async fn end(&self, _prompt: SignPrompt, _outcome: PromptOutcome) {
        self.ended.fetch_add(1, Ordering::SeqCst);
    }

    async fn notify_preapproved(&self, _prompt: SignPrompt, _app: GrantApp) {}
}

#[async_trait]
impl PassphraseAuthorizer for StubAuthorizer {
    async fn begin(
        &self,
        prompt: PassphrasePrompt,
        peer: audit::Actor,
    ) -> Result<ForeignContext, String> {
        self.passphrase_kinds.lock().unwrap().push(prompt.kind);
        self.peers.lock().unwrap().push(peer);
        Err("stub authorizer".to_string())
    }

    async fn collect(
        &self,
        prompt: PassphrasePrompt,
        _can_use_saved: bool,
    ) -> Result<Option<CollectedPassphrase>, String> {
        self.passphrase_prompts.lock().unwrap().push(prompt);
        Ok(Some(CollectedPassphrase {
            value: secrecy::SecretString::from(STUB_PASSPHRASE),
            // Nothing may touch the real keychain from a test.
            save_to_keychain: false,
            use_saved: false,
        }))
    }

    async fn end(&self, _prompt: PassphrasePrompt, _outcome: PromptOutcome) {
        self.ended.fetch_add(1, Ordering::SeqCst);
    }

    /// `"hang"` stands for a user who never answers. Its prompt is only
    /// ever dropped. Starting and dropping it are both counted.
    async fn confirm(&self, prompt: ConfirmPrompt) -> bool {
        if prompt.description.as_deref() == Some("hang") {
            self.hang().await;
        }
        true
    }

    async fn message(&self, _description: Option<String>) {}
}

#[async_trait]
impl vault::VaultAuthorizer for StubAuthorizer {
    async fn begin(
        &self,
        prompt: vault::VaultAccessPrompt,
        peer: audit::Actor,
    ) -> Result<vault::VaultAuthorization, String> {
        if matches!(
            &prompt.client,
            ClientIdentity::Browser { extension: Some(extension), .. } if extension == "hang"
        ) {
            self.hang().await;
            return Err("abandoned".to_string());
        }
        self.vault_prompts.lock().unwrap().push(prompt);
        self.peers.lock().unwrap().push(peer);
        Err("stub authorizer".to_string())
    }

    async fn abandon(&self) {
        self.abandoned.notify_one();
    }

    async fn end(&self, _prompt: vault::VaultAccessPrompt, _outcome: PromptOutcome) {
        self.ended.fetch_add(1, Ordering::SeqCst);
    }
}

pub(super) const PAGE: &str =
    r#""url":"https://example.com","frame_url":"https://example.com/login""#;

/// A vault store with no vaults, so no test reads the developer's own vaults.
pub(in crate::core::app_broker) fn empty_vaults() -> crate::secrets::vaults::VaultCatalog {
    crate::secrets::vaults::VaultCatalog::with_unlocker(
        PathBuf::from("/nonexistent/vaults"),
        crate::secrets::vaults::storage::txn::VaultWriter::isolated("/nonexistent/data"),
        Default::default(),
        Arc::new(crate::secrets::vaults::storage::test_unlocker::KeyUnlocker::default()),
    )
}
