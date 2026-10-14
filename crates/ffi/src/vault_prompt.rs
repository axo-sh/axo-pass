use std::sync::{Arc, Mutex};

use axo_pass_core::audit;
use axo_pass_core::core::auth::ForeignContext;
use axo_pass_core::core::{app_broker, provenance};
use axo_pass_core::secrets::vaults::VaultsManager;

use crate::*;

#[derive(uniffi::Enum, Clone)]
pub enum VaultAction {
    ListItems,
    ReadSecret {
        item_key: String,
        credential_key: String,
    },
    /// The AutoFill extension is listing the logins that match `page`, without
    /// their passwords.
    ListLogins {
        page: LoginPage,
        /// The request also lists the logins that do not match the page.
        all: bool,
    },
    /// The AutoFill extension is filling the username and password of one
    /// login on `page`. `account` is the client's own label for the login. It
    /// is not verified, so the prompt may show it but nothing may rely on it.
    FillLogin {
        page: LoginPage,
        record_id: String,
        account: Option<String>,
        /// The login is one that does not match the page, picked from the full
        /// list. The broker asks the user to confirm it.
        unmatched: bool,
    },
    /// The AutoFill extension is asking for the one-time code of one login on
    /// `page`.
    GenerateTotp {
        page: LoginPage,
        record_id: String,
    },
    /// A browser captured a login from a form on `page` and is asking to save
    /// it as a new item. The password is not carried to the app.
    SaveLogin {
        page: LoginPage,
        username: Option<String>,
    },
    /// A browser captured a new password for one login from a form on `page`.
    /// `account` is the client's own label for the login, like `FillLogin`'s.
    /// The password is not carried to the app.
    UpdateLoginPassword {
        page: LoginPage,
        record_id: String,
        account: Option<String>,
    },
    /// `ap exec` / `ap inject`: resolve `refs` behind one prompt. The refs may
    /// span several vaults.
    ResolveSecrets {
        purpose: ResolvePurpose,
        refs: Vec<VaultSecretRef>,
    },
    /// `ap item set`: write one credential's secret value. The value is not
    /// carried to the app.
    WriteSecret {
        item_key: String,
        credential_key: String,
    },
    /// `ap vault export`: unlock `count` vaults and write an encrypted bundle.
    ExportVaults {
        count: u32,
    },
    /// `ap vault import`: import `count` vaults from a bundle.
    ImportVaults {
        count: u32,
    },
    /// `ap vault add`: validate and register the vault at `path`.
    AddVault {
        path: String,
    },
    /// The AutoFill extension is registering a passkey for `rp_id`. The prompt
    /// offers where to store it.
    CreatePasskey {
        rp_id: String,
        user_name: String,
        choices: PasskeyChoicesInfo,
    },
    /// The AutoFill extension is asserting a passkey for `rp_id`.
    AssertPasskey {
        rp_id: String,
    },
}

/// The vaults and logins a new passkey may be stored in. Mirrors
/// [`app_broker::PasskeyChoices`].
#[derive(uniffi::Record, Clone)]
pub struct PasskeyChoicesInfo {
    /// Every vault.
    pub vaults: Vec<VaultInfo>,
    /// The matching logins in every vault.
    pub logins: Vec<PasskeyLoginChoice>,
    /// The vault selected when the prompt opens.
    pub default_vault: String,
    /// The login selected when the prompt opens, as an index into `logins`.
    /// `None` selects "New login".
    pub suggested: Option<u32>,
}

/// A login item that matches the relying party.
#[derive(uniffi::Record, Clone)]
pub struct PasskeyLoginChoice {
    pub vault_key: String,
    pub item_key: String,
    pub title: String,
    pub username: Option<String>,
}

impl From<app_broker::PasskeyChoices> for PasskeyChoicesInfo {
    fn from(choices: app_broker::PasskeyChoices) -> Self {
        Self {
            vaults: choices
                .vaults
                .into_iter()
                .map(|v| VaultInfo {
                    key: v.key,
                    name: v.name,
                })
                .collect(),
            logins: choices
                .logins
                .into_iter()
                .map(|l| PasskeyLoginChoice {
                    vault_key: l.vault_key,
                    item_key: l.item_key,
                    title: l.title,
                    username: l.username,
                })
                .collect(),
            default_vault: choices.default_vault,
            suggested: choices.suggested.map(|index| index as u32),
        }
    }
}

/// Where the user chose to store a passkey: a vault, and an item in it or a new
/// login when `item_key` is `None`. Mirrors [`app_broker::PasskeyPlacement`].
#[derive(uniffi::Record, Clone)]
pub struct PasskeyPlacementInfo {
    pub vault_key: String,
    pub item_key: Option<String>,
}

/// The page a login request is for. Mirrors [`app_broker::LoginPage`], less the
/// URL.
#[derive(uniffi::Record, Clone)]
pub struct LoginPage {
    /// The frame's host, with one leading `www.` removed.
    pub host: String,
    /// The frame's registrable domain. Grants are keyed on it.
    pub domain: String,
    /// The top-level host, when the form is in a frame of another host.
    pub top_host: Option<String>,
    /// False when the frame is on `http:`.
    pub secure: bool,
    /// The name of the app that asked. `None` means a browser.
    pub requester: Option<String>,
}

impl From<app_broker::LoginPage> for LoginPage {
    fn from(page: app_broker::LoginPage) -> Self {
        Self {
            host: page.host,
            domain: page.domain,
            top_host: page.top_host,
            secure: page.secure,
            requester: page.requester,
        }
    }
}

/// Mirrors [`app_broker::ResolvePurpose`].
#[derive(uniffi::Enum, Clone, Copy)]
pub enum ResolvePurpose {
    Exec,
    Inject,
    Read,
}

impl From<app_broker::ResolvePurpose> for ResolvePurpose {
    fn from(purpose: app_broker::ResolvePurpose) -> Self {
        match purpose {
            app_broker::ResolvePurpose::Exec => Self::Exec,
            app_broker::ResolvePurpose::Inject => Self::Inject,
            app_broker::ResolvePurpose::Read => Self::Read,
        }
    }
}

/// A secret requested by a resolve. The prompt lists it when the user expands
/// the card. Mirrors [`app_broker::VaultRef`].
#[derive(uniffi::Record, Clone)]
pub struct VaultSecretRef {
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
}

impl From<app_broker::VaultRef> for VaultSecretRef {
    fn from(r: app_broker::VaultRef) -> Self {
        Self {
            vault_key: r.vault_key,
            item_key: r.item_key,
            credential_key: r.credential_key,
        }
    }
}

impl From<app_broker::VaultAction> for VaultAction {
    fn from(action: app_broker::VaultAction) -> Self {
        match action {
            app_broker::VaultAction::ListItems => Self::ListItems,
            app_broker::VaultAction::ReadSecret {
                item_key,
                credential_key,
            } => Self::ReadSecret {
                item_key,
                credential_key,
            },
            app_broker::VaultAction::ListLogins { page, all } => Self::ListLogins {
                page: page.into(),
                all,
            },
            app_broker::VaultAction::FillLogin {
                page,
                record_id,
                account,
                unmatched,
            } => Self::FillLogin {
                page: page.into(),
                record_id,
                account,
                unmatched,
            },
            app_broker::VaultAction::GenerateTotp { page, record_id } => Self::GenerateTotp {
                page: page.into(),
                record_id,
            },
            app_broker::VaultAction::SaveLogin { page, username } => Self::SaveLogin {
                page: page.into(),
                username,
            },
            app_broker::VaultAction::UpdateLoginPassword {
                page,
                record_id,
                account,
            } => Self::UpdateLoginPassword {
                page: page.into(),
                record_id,
                account,
            },
            app_broker::VaultAction::ResolveSecrets { purpose, refs } => Self::ResolveSecrets {
                purpose: purpose.into(),
                refs: refs.into_iter().map(Into::into).collect(),
            },
            app_broker::VaultAction::WriteSecret {
                item_key,
                credential_key,
            } => Self::WriteSecret {
                item_key,
                credential_key,
            },
            app_broker::VaultAction::ExportVaults { vault_keys } => Self::ExportVaults {
                count: vault_keys.len() as u32,
            },
            app_broker::VaultAction::ImportVaults { count } => Self::ImportVaults {
                count: count as u32,
            },
            app_broker::VaultAction::AddVault { path } => Self::AddVault { path },
            app_broker::VaultAction::CreatePasskey {
                rp_id,
                user_name,
                choices,
            } => Self::CreatePasskey {
                rp_id,
                user_name,
                choices: choices.into(),
            },
            app_broker::VaultAction::AssertPasskey { rp_id } => Self::AssertPasskey { rp_id },
        }
    }
}

/// A vault access prompt, as the app sees it. Mirrors
/// [`app_broker::VaultAccessPrompt`].
#[derive(uniffi::Record, Clone)]
pub struct VaultAccessPrompt {
    pub vault_key: String,
    pub caller: Option<String>,
    /// The full requesting process chain, innermost first. Shown when the user
    /// expands the prompt.
    pub caller_chain: Vec<ProcessNode>,
    /// A verified identity for `caller_chain`, for keying reused approvals.
    /// `None` when any process in the chain could not be verified, in which
    /// case no approval may be reused.
    pub caller_identity: Option<String>,
    pub action: VaultAction,
}

impl From<app_broker::VaultAccessPrompt> for VaultAccessPrompt {
    fn from(prompt: app_broker::VaultAccessPrompt) -> Self {
        // A browser is identified by its signing identity, not by the host's
        // process chain, and an unverified browser host is never identified.
        let caller_identity = match &prompt.client {
            app_broker::ClientIdentity::Process => provenance::chain_identity(&prompt.caller_chain),
            app_broker::ClientIdentity::Browser { name, team_id, .. } => {
                Some(format!("browser:{team_id}:{name}"))
            },
            app_broker::ClientIdentity::Unverified { .. } => None,
        };
        Self {
            vault_key: prompt.vault_key,
            caller: prompt.caller,
            caller_identity,
            caller_chain: prompt.caller_chain.into_iter().map(Into::into).collect(),
            action: prompt.action.into(),
        }
    }
}

/// Implemented by the app. `begin_authorization` prepares an `LAContext` with
/// an `LAAuthenticationView` attached so a lapsed authentication can be
/// re-evaluated inline; `end_authorization` takes the prompt down again.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait VaultPromptDelegate: Send + Sync {
    /// Return the address of a live `LAContext` to unlock the vault on. The app
    /// must keep its own reference to that context until `end_authorization`.
    /// `peer` is the process the broker verified, for the grant events the app
    /// records.
    async fn begin_authorization(
        &self,
        prompt: VaultAccessPrompt,
        peer: RequestActor,
    ) -> Result<u64, FfiError>;

    /// The client disconnected while `begin_authorization` was waiting on the
    /// user. Dismiss the prompt so it returns. `end_authorization` follows as
    /// usual.
    async fn abandon_authorization(&self);

    /// Where the user chose to store the passkey a `CreatePasskey` prompt is
    /// for. Called after `begin_authorization` returns a context. `None` means
    /// the user made no choice, and the prompt's default applies.
    async fn passkey_placement(&self, prompt: VaultAccessPrompt) -> Option<PasskeyPlacementInfo>;

    /// The attempt finished. Called once for every `begin_authorization`.
    async fn end_authorization(&self, prompt: VaultAccessPrompt, outcome: PromptOutcome);

    /// A broker request wrote to one or more vaults on disk. The app drops its
    /// cached copy of each named vault and re-indexes AutoFill. An empty list
    /// means the written vault could not be named, so treat every vault as
    /// possibly changed.
    async fn vaults_changed(&self, vault_keys: Vec<String>);
}

pub(crate) struct DelegatingVaultAuthorizer {
    pub(crate) delegate: Arc<dyn VaultPromptDelegate>,
    /// The app's long-lived manager. A broker write goes to disk through its
    /// own `VaultWrapper`, so this copy is relocked afterwards to force a
    /// reload on the next read.
    pub(crate) manager: Arc<Mutex<VaultsManager>>,
}

/// Whether a completed vault action changed the vault on disk.
fn vault_action_mutates(action: &app_broker::VaultAction) -> bool {
    matches!(
        action,
        app_broker::VaultAction::WriteSecret { .. }
            | app_broker::VaultAction::SaveLogin { .. }
            | app_broker::VaultAction::UpdateLoginPassword { .. }
            | app_broker::VaultAction::CreatePasskey { .. }
            | app_broker::VaultAction::AssertPasskey { .. }
            | app_broker::VaultAction::ImportVaults { .. }
            | app_broker::VaultAction::AddVault { .. }
    )
}

/// The vault keys a mutating action wrote to, when the prompt names them.
/// `WriteSecret`, `SaveLogin`, and `CreatePasskey` carry the real key, which
/// for a registration is the vault the user chose. A passkey sign-in records
/// its use in the vault that signed, which the broker fills in once it is
/// known. The password update, import and add actions do not, so they return
/// an empty list and every vault is relocked.
fn changed_vault_keys(prompt: &app_broker::VaultAccessPrompt) -> Vec<String> {
    match &prompt.action {
        app_broker::VaultAction::WriteSecret { .. }
        | app_broker::VaultAction::SaveLogin { .. }
        | app_broker::VaultAction::CreatePasskey { .. } => {
            vec![prompt.vault_key.clone()]
        },
        app_broker::VaultAction::AssertPasskey { .. } if !prompt.vault_key.is_empty() => {
            vec![prompt.vault_key.clone()]
        },
        _ => Vec::new(),
    }
}

#[async_trait::async_trait]
impl app_broker::VaultAuthorizer for DelegatingVaultAuthorizer {
    async fn begin(
        &self,
        prompt: app_broker::VaultAccessPrompt,
        peer: audit::Actor,
    ) -> Result<ForeignContext, String> {
        let context_ptr = self
            .delegate
            .begin_authorization(prompt.into(), peer.into())
            .await
            .map_err(|e| e.to_string())?;
        if context_ptr == 0 {
            return Err(
                "the app did not return an authentication session for unlocking".to_string(),
            );
        }
        // SAFETY: the app holds a reference to the context until
        // `end_authorization`, which the broker calls after the unlock.
        unsafe { ForeignContext::from_ptr(context_ptr as *mut std::ffi::c_void) }
            .map_err(|e| e.to_string())
    }

    async fn abandon(&self) {
        self.delegate.abandon_authorization().await;
    }

    async fn passkey_placement(
        &self,
        prompt: &app_broker::VaultAccessPrompt,
    ) -> Option<app_broker::PasskeyPlacement> {
        let placement = self
            .delegate
            .passkey_placement(prompt.clone().into())
            .await?;
        Some(app_broker::PasskeyPlacement {
            vault_key: placement.vault_key,
            item_key: placement.item_key,
        })
    }

    async fn end(&self, prompt: app_broker::VaultAccessPrompt, outcome: app_broker::PromptOutcome) {
        let changed = matches!(outcome, app_broker::PromptOutcome::Succeeded)
            && vault_action_mutates(&prompt.action);
        let changed_keys = changed_vault_keys(&prompt);

        self.delegate
            .end_authorization(prompt.into(), outcome.into())
            .await;

        if changed {
            if let Ok(mut manager) = self.manager.lock() {
                if changed_keys.is_empty() {
                    manager.lock_all();
                } else {
                    for key in &changed_keys {
                        manager.relock(key);
                    }
                }
            }
            self.delegate.vaults_changed(changed_keys).await;
        }
    }

    /// The vaults are unchanged, so nothing is relocked. The empty list makes
    /// the app reload what it shows and re-register AutoFill identities.
    async fn passkey_reports_changed(&self) {
        self.delegate.vaults_changed(Vec::new()).await;
    }
}
