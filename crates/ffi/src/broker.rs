use std::sync::Arc;

use axo_pass_core::audit;
use axo_pass_core::core::auth::ForeignContext;
use axo_pass_core::core::{app_broker, provenance};
use axo_pass_core::ssh::app_grants;
use secrecy::SecretString;

use crate::*;

/// How a prompt ended, as the app sees it.
#[derive(uniffi::Enum, Clone)]
pub enum PromptOutcome {
    /// The user approved, or a still-valid approval was reused.
    Succeeded,
    /// The user dismissed the prompt. Nothing was authorized.
    Cancelled,
    Failed {
        message: String,
    },
}

impl From<app_broker::PromptOutcome> for PromptOutcome {
    fn from(outcome: app_broker::PromptOutcome) -> Self {
        match outcome {
            app_broker::PromptOutcome::Succeeded => Self::Succeeded,
            app_broker::PromptOutcome::Cancelled => Self::Cancelled,
            app_broker::PromptOutcome::Failed(message) => Self::Failed { message },
        }
    }
}

/// Implemented by the app. `begin_authorization` prepares an `LAContext` with
/// an `LAAuthenticationView` attached and puts the prompt on screen;
/// `end_authorization` takes it down again.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait SignPromptDelegate: Send + Sync {
    /// Return the address of a live `LAContext` to sign on. The app must keep
    /// its own reference to that context until `end_authorization`.
    #[allow(clippy::too_many_arguments)]
    async fn begin_authorization(
        &self,
        key_label: String,
        fingerprint: Option<String>,
        comment: Option<String>,
        caller: Option<String>,
        // The full requesting process chain, innermost first. Shown when the
        // user expands the prompt.
        caller_chain: Vec<ProcessNode>,
        // A verified identity for `caller_chain`, for keying reused approvals.
        // `None` when any process in the chain could not be verified, in which
        // case no approval may be reused.
        caller_identity: Option<String>,
        // True for a managed Secure Enclave key. False for a confirm-on-use
        // gate on a key the agent holds directly, which the app words
        // differently and never reuses across requests.
        managed: bool,
        // The process the broker verified, for the grant events the app
        // records. Not shown to the user: `caller` is what the prompt says.
        peer: RequestActor,
        // The managed key's policy. `None` for a confirm-on-use gate.
        policy: Option<SshKeyPolicy>,
        // The app the prompt may offer lasting access to. Set only for a
        // default-policy key requested through a verified chain with a signed
        // app in it.
        grant_candidate: Option<SshGrantApp>,
        // The purpose of the signature, parsed by the agent from the request.
        // The requesting process chooses the data, so this value is not
        // authenticated.
        purpose: Option<SshSignPurpose>,
    ) -> Result<u64, FfiError>;

    /// The attempt finished. Called once for every `begin_authorization`.
    async fn end_authorization(&self, key_label: String, outcome: PromptOutcome);

    /// The broker signed without a prompt because `app` holds a grant for the
    /// key. No `begin_authorization` or `end_authorization` is made for it.
    async fn notify_preapproved(
        &self,
        key_label: String,
        fingerprint: Option<String>,
        comment: Option<String>,
        caller: Option<String>,
        app: SshGrantApp,
    );
}

struct DelegatingAuthorizer {
    delegate: Arc<dyn SignPromptDelegate>,
}

#[async_trait::async_trait]
impl app_broker::SignAuthorizer for DelegatingAuthorizer {
    async fn begin(
        &self,
        prompt: app_broker::SignPrompt,
        peer: audit::Actor,
    ) -> Result<ForeignContext, String> {
        let caller_identity = provenance::chain_identity(&prompt.caller_chain);
        let context_ptr = self
            .delegate
            .begin_authorization(
                prompt.key_label,
                prompt.fingerprint,
                prompt.comment,
                prompt.caller,
                prompt.caller_chain.into_iter().map(Into::into).collect(),
                caller_identity,
                prompt.managed,
                peer.into(),
                prompt.policy.map(SshKeyPolicy::from),
                prompt.grant_candidate.map(SshGrantApp::from),
                prompt.purpose.map(SshSignPurpose::from),
            )
            .await
            .map_err(|e| e.to_string())?;
        if context_ptr == 0 {
            return Err("the app did not return an authentication session for signing".to_string());
        }
        // SAFETY: the app holds a reference to the context until
        // `end_authorization`, which the broker calls after signing.
        unsafe { ForeignContext::from_ptr(context_ptr as *mut std::ffi::c_void) }
            .map_err(|e| e.to_string())
    }

    async fn end(&self, prompt: app_broker::SignPrompt, outcome: app_broker::PromptOutcome) {
        self.delegate
            .end_authorization(prompt.key_label, outcome.into())
            .await;
    }

    async fn notify_preapproved(&self, prompt: app_broker::SignPrompt, app: app_grants::GrantApp) {
        self.delegate
            .notify_preapproved(
                prompt.key_label,
                prompt.fingerprint,
                prompt.comment,
                prompt.caller,
                app.into(),
            )
            .await;
    }
}

/// One process in a caller chain, shown when the user expands a prompt. Mirrors
/// [`provenance::ProcessNode`].
#[derive(uniffi::Record, Clone)]
pub struct ProcessNode {
    pub command: String,
    pub executable: Option<String>,
    pub pid: u32,
    pub bundle_id: Option<String>,
    pub team_id: Option<String>,
    /// False when `command`, `bundle_id`, and `team_id` were reported by the
    /// binary itself and could not be verified.
    pub verified: bool,
}

impl From<provenance::ProcessNode> for ProcessNode {
    fn from(node: provenance::ProcessNode) -> Self {
        Self {
            command: node.command,
            executable: node.executable,
            pid: node.pid,
            bundle_id: node.bundle_id,
            team_id: node.team_id,
            verified: node.verified,
        }
    }
}

/// The process a broker request came from, as the broker verified it. Mirrors
/// [`audit::Actor`].
///
/// `caller` is who that process says asked it, falling back to the root of its
/// own chain. The rest describes the process on the other end of the socket,
/// read from its audit token and code signature rather than from anything it
/// sent us.
#[derive(uniffi::Record, Clone, Default)]
pub struct RequestActor {
    pub caller: Option<String>,
    pub pid: Option<u32>,
    pub executable: Option<String>,
    pub bundle_id: Option<String>,
    pub team_id: Option<String>,
    pub chain: Vec<String>,
}

impl From<audit::Actor> for RequestActor {
    fn from(actor: audit::Actor) -> Self {
        Self {
            caller: actor.caller,
            pid: actor.pid,
            executable: actor.executable,
            bundle_id: actor.bundle_id,
            team_id: actor.team_id,
            chain: actor.chain,
        }
    }
}

impl From<RequestActor> for audit::Actor {
    fn from(actor: RequestActor) -> Self {
        Self {
            caller: actor.caller,
            pid: actor.pid,
            executable: actor.executable,
            bundle_id: actor.bundle_id,
            team_id: actor.team_id,
            chain: actor.chain,
            // Detail is carried on the prompt itself, not through the actor.
            chain_detail: Vec::new(),
        }
    }
}

/// Which agent a [`PassphrasePrompt`] is on behalf of. Mirrors
/// [`app_broker::PassphraseKind`].
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseKind {
    Gpg,
    Ssh,
    Age,
}

impl From<app_broker::PassphraseKind> for PassphraseKind {
    fn from(kind: app_broker::PassphraseKind) -> Self {
        match kind {
            app_broker::PassphraseKind::Gpg => Self::Gpg,
            app_broker::PassphraseKind::Ssh => Self::Ssh,
            app_broker::PassphraseKind::Age => Self::Age,
        }
    }
}

/// A passphrase prompt, as the app sees it. Mirrors
/// [`app_broker::PassphrasePrompt`]; for GPG the strings are gpg's own
/// wording, for SSH they are ssh/ssh-add's.
#[derive(uniffi::Record, Clone)]
pub struct PassphrasePrompt {
    pub kind: PassphraseKind,
    /// The key grip (GPG) or key fingerprint (SSH) naming the keychain entry.
    /// Absent when nothing identifies a key, in which case nothing can be
    /// saved or read back.
    pub key_id: Option<String>,
    pub description: Option<String>,
    pub prompt: Option<String>,
    /// gpg's report of the previous attempt. Set means the saved passphrase is
    /// wrong, so the app asks for a new one rather than unlocking. Always
    /// `None` for SSH.
    pub error_message: Option<String>,
    pub caller: Option<String>,
    /// The full requesting process chain, innermost first. Shown when the user
    /// expands the prompt.
    pub caller_chain: Vec<ProcessNode>,
    /// A verified identity for `caller_chain`, for keying reused approvals.
    /// `None` when any process in the chain could not be verified, in which
    /// case no approval may be reused.
    pub caller_identity: Option<String>,
}

impl From<app_broker::PassphrasePrompt> for PassphrasePrompt {
    fn from(prompt: app_broker::PassphrasePrompt) -> Self {
        Self {
            kind: prompt.kind.into(),
            key_id: prompt.key_id,
            description: prompt.description,
            prompt: prompt.prompt,
            error_message: prompt.error_message,
            caller: prompt.caller,
            caller_identity: provenance::chain_identity(&prompt.caller_chain),
            caller_chain: prompt.caller_chain.into_iter().map(Into::into).collect(),
        }
    }
}

/// A passphrase the user typed. The value crosses as bytes, never a `String`,
/// so the app can zero the buffer it came from.
#[derive(uniffi::Record)]
pub struct CollectedPassphrase {
    pub value: Vec<u8>,
    pub save_to_keychain: bool,
}

/// gpg's `CONFIRM` question. Mirrors [`app_broker::ConfirmPrompt`]: `None`
/// labels mean the defaults, OK and Cancel.
#[derive(uniffi::Record, Clone)]
pub struct ConfirmPrompt {
    pub description: Option<String>,
    pub ok_label: Option<String>,
    pub cancel_label: Option<String>,
}

impl From<app_broker::ConfirmPrompt> for ConfirmPrompt {
    fn from(prompt: app_broker::ConfirmPrompt) -> Self {
        Self {
            description: prompt.description,
            ok_label: prompt.ok_label,
            cancel_label: prompt.cancel_label,
        }
    }
}

/// Implemented by the app. `begin_authorization` prepares an `LAContext` with
/// an `LAAuthenticationView` attached so the saved passphrase can be unlocked
/// inline; `collect_passphrase` asks the user to type one.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait PassphrasePromptDelegate: Send + Sync {
    /// Return the address of a live `LAContext` to read the keychain on. The
    /// app must keep its own reference to that context until
    /// `end_authorization`. `peer` is the process the broker verified, for the
    /// grant events the app records.
    async fn begin_authorization(
        &self,
        prompt: PassphrasePrompt,
        peer: RequestActor,
    ) -> Result<u64, FfiError>;

    /// Ask the user for the passphrase. `None` means they dismissed the prompt.
    async fn collect_passphrase(
        &self,
        prompt: PassphrasePrompt,
    ) -> Result<Option<CollectedPassphrase>, FfiError>;

    /// The attempt finished. Called once for every `begin_authorization`.
    async fn end_authorization(&self, prompt: PassphrasePrompt, outcome: PromptOutcome);

    /// Put gpg's `CONFIRM` question to the user.
    async fn confirm(&self, prompt: ConfirmPrompt) -> bool;

    /// Show gpg's `MESSAGE` and wait for the user to dismiss it.
    async fn message(&self, description: Option<String>);
}

struct DelegatingPassphraseAuthorizer {
    delegate: Arc<dyn PassphrasePromptDelegate>,
}

#[async_trait::async_trait]
impl app_broker::PassphraseAuthorizer for DelegatingPassphraseAuthorizer {
    async fn begin(
        &self,
        prompt: app_broker::PassphrasePrompt,
        peer: audit::Actor,
    ) -> Result<ForeignContext, String> {
        let context_ptr = self
            .delegate
            .begin_authorization(prompt.into(), peer.into())
            .await
            .map_err(|e| e.to_string())?;
        if context_ptr == 0 {
            return Err(
                "the app did not return an authentication session for the request".to_string(),
            );
        }
        // SAFETY: the app holds a reference to the context until
        // `end_authorization`, which the broker calls after the read.
        unsafe { ForeignContext::from_ptr(context_ptr as *mut std::ffi::c_void) }
            .map_err(|e| e.to_string())
    }

    async fn collect(
        &self,
        prompt: app_broker::PassphrasePrompt,
    ) -> Result<Option<app_broker::CollectedPassphrase>, String> {
        let collected = self
            .delegate
            .collect_passphrase(prompt.into())
            .await
            .map_err(|e| e.to_string())?;
        collected
            .map(|collected| {
                let value = String::from_utf8(collected.value)
                    .map_err(|_| "Passphrase is not valid UTF-8".to_string())?;
                Ok(app_broker::CollectedPassphrase {
                    value: SecretString::from(value),
                    save_to_keychain: collected.save_to_keychain,
                })
            })
            .transpose()
    }

    async fn end(&self, prompt: app_broker::PassphrasePrompt, outcome: app_broker::PromptOutcome) {
        self.delegate
            .end_authorization(prompt.into(), outcome.into())
            .await;
    }

    async fn confirm(&self, prompt: app_broker::ConfirmPrompt) -> bool {
        self.delegate.confirm(prompt.into()).await
    }

    async fn message(&self, description: Option<String>) {
        self.delegate.message(description).await
    }
}

/// What the app is being asked to do with a vault. Mirrors
/// [`app_broker::VaultAction`].

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Serve the CLI's requests: SSH signatures for the agent, and GPG
    /// passphrases for `ap pinentry`. Each prompts through its delegate, so the
    /// app draws the prompt instead of a headless process raising the system
    /// dialog. Returns once the socket is bound; serving continues in the
    /// background until [`Self::stop_app_broker`] or app exit.
    pub async fn start_app_broker(
        &self,
        sign_delegate: Arc<dyn SignPromptDelegate>,
        passphrase_delegate: Arc<dyn PassphrasePromptDelegate>,
        vault_delegate: Arc<dyn VaultPromptDelegate>,
    ) -> Result<(), FfiError> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        {
            let mut slot = self.app_broker.lock().map_err(|_| FfiError::Poisoned)?;
            if slot.is_some() {
                return Err(FfiError::InvalidInput(
                    "App broker is already running".to_string(),
                ));
            }
            *slot = Some(shutdown_tx);
        }

        let authorizers = app_broker::Authorizers {
            sign: Arc::new(DelegatingAuthorizer {
                delegate: sign_delegate,
            }),
            passphrase: Arc::new(DelegatingPassphraseAuthorizer {
                delegate: passphrase_delegate,
            }),
            keychain: Arc::new(app_broker::SystemKeychain),
            vault: Arc::new(DelegatingVaultAuthorizer {
                delegate: vault_delegate,
                manager: Arc::clone(&self.manager),
            }),
            logins: Arc::clone(&self.login_index),
        };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            // `serve` binds before it accepts and only returns at shutdown, so
            // readiness is reported before awaiting it. Bind failures surface
            // in the log.
            let _ = ready_tx.send(());
            if let Err(e) = app_broker::serve(authorizers, shutdown_rx).await {
                log::error!("App broker stopped: {e}");
            }
        });
        let _ = ready_rx.await;
        Ok(())
    }

    /// Stop serving and remove the socket, so the agent and pinentry report an
    /// error rather than hanging.
    pub fn stop_app_broker(&self) -> Result<(), FfiError> {
        if let Some(shutdown) = self
            .app_broker
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .take()
        {
            let _ = shutdown.send(());
        }
        Ok(())
    }

    /// Whether the broker started this app to serve a request, rather than a
    /// person opening it. Reads the flag off this process's own arguments, so
    /// it holds for the life of the process.
    pub fn is_broker_launch(&self) -> bool {
        std::env::args().any(|arg| arg == app_broker::LAUNCH_FLAG)
    }
}
