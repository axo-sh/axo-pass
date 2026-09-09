//! The vault side of the broker: every `ap` command that needs the vault
//! encryption key runs through here. Reads (`ap item list`, `ap item get`, `ap
//! read`, `ap exec`, `ap inject`), the single write (`ap item set`), and vault
//! management (`ap vault export`, `ap vault import`, `ap vault add`).
//!
//! `ap` holds no keychain entitlements, so it cannot read or create the vault
//! encryption key itself. It hands the request to the app, which unlocks the
//! vault on a context it owns and returns the result. A read or a write prompts
//! every time; a listing may reuse a recent approval.
//!
//! The app verifies the peer before it serves a request, so it holds the full
//! provenance for the process that asked. It is therefore the process that
//! records the `secret.read`, `vault.items_listed`, `vault.exported`,
//! `vault.imported` and `vault.linked` events, the same way the SSH agent
//! records `ssh.sign`. Export and import also emit the per-vault events that
//! the core records internally, sourced to the app.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{BrokerError, PromptOutcome, WireRequest, WireResponse, send_request};
use crate::audit::{self, Action, Actor, AuditEvent, Outcome, Subject, SubjectKind};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::core::config::APP_CONFIG;
use crate::core::dirs::vaults_dir;
use crate::secrets::vaults::vault_export::{ExportMode, ImportIdentity, WorkFactor};
use crate::secrets::vaults::{FieldKind, VaultWrapper, VaultsManager};

/// One `axo://` reference to resolve, as it crosses the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRef {
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
}

/// Which command asked for a batch resolve, so the app records the matching
/// audit action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvePurpose {
    /// `ap exec`.
    Exec,
    /// `ap inject`.
    Inject,
    /// `ap read` with more than one reference. One prompt covers the batch.
    Read,
}

/// What the app is being asked to do with the vault. Grants are keyed on the
/// action as well as the vault, so authorizing a listing does not also
/// authorize a read of the same vault.
#[derive(Debug, Clone)]
pub enum VaultAction {
    /// `ap item list`: return the item overview, never a secret.
    ListItems,

    /// `ap read`: return one credential's secret value.
    ReadSecret {
        item_key: String,
        credential_key: String,
    },

    /// `ap exec` / `ap inject`: resolve many `axo://` references at once,
    /// possibly across several vaults, behind one prompt.
    ResolveSecrets {
        purpose: ResolvePurpose,
        refs: Vec<VaultRef>,
    },

    /// `ap item set`: write one credential's secret value, creating the item
    /// or credential if it does not exist. The value itself is not carried
    /// here; it travels in [`WriteSecretPayload`] so it never reaches the
    /// app's prompt delegate.
    WriteSecret {
        item_key: String,
        credential_key: String,
    },

    /// `ap vault export`: unlock every named vault and write an encrypted
    /// bundle. Reads all secrets, so it prompts every time. The destination
    /// path and the export passphrase travel in [`ExportPayload`].
    ExportVaults { vault_keys: Vec<String> },

    /// `ap vault import`: re-wrap the selected vaults from a bundle with the
    /// local encryption key and write them to the vaults directory. The bundle
    /// path, decryption identity and selection travel in [`ImportPayload`].
    ImportVaults { count: usize },

    /// `ap vault add`: unlock the vault at `path` to validate it, then register
    /// it as an external vault in the app config.
    AddVault { path: String },
}

/// The secret an [`VaultAction::WriteSecret`] writes, kept out of
/// [`VaultAccessPrompt`] so it is not handed to the app for the prompt.
#[derive(Clone)]
pub struct WriteSecretPayload {
    pub title: String,
    pub value: SecretString,
}

/// Where an [`VaultAction::ExportVaults`] writes and how the bundle key is
/// protected. Kept out of [`VaultAccessPrompt`], like [`WriteSecretPayload`].
#[derive(Clone)]
pub struct ExportPayload {
    pub dest_path: PathBuf,
    pub mode: ExportMode,
}

/// The bundle an [`VaultAction::ImportVaults`] reads, its decryption identity
/// and the id-to-key selection. Kept out of [`VaultAccessPrompt`].
#[derive(Clone)]
pub struct ImportPayload {
    pub import_path: PathBuf,
    pub identity: WireImportIdentity,
    /// `(bundle vault id, target key)` pairs.
    pub selection: Vec<(String, String)>,
}

/// A payload that does not belong in [`VaultAccessPrompt`] because it carries a
/// secret or would clutter the prompt.
#[derive(Clone)]
pub(super) enum VaultPayload {
    Write(WriteSecretPayload),
    Export(ExportPayload),
    Import(ImportPayload),
}

/// How the export bundle key is protected, as it crosses the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireExportMode {
    /// A passphrase and the resolved scrypt `log_n`.
    Passphrase { passphrase: String, work_factor: u8 },
    /// An age recipient (`age1...`).
    Recipient { recipient: String },
}

impl From<WireExportMode> for ExportMode {
    fn from(mode: WireExportMode) -> Self {
        match mode {
            WireExportMode::Passphrase {
                passphrase,
                work_factor,
            } => ExportMode::Passphrase {
                passphrase: passphrase.into(),
                work_factor: WorkFactor::Custom(work_factor),
            },
            WireExportMode::Recipient { recipient } => ExportMode::Recipient(recipient),
        }
    }
}

/// How the import bundle is decrypted, as it crosses the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireImportIdentity {
    Passphrase {
        passphrase: String,
    },
    /// An age secret key (`AGE-SECRET-KEY-1...`).
    Identity {
        identity: String,
    },
}

impl TryFrom<WireImportIdentity> for ImportIdentity {
    type Error = String;

    fn try_from(identity: WireImportIdentity) -> Result<Self, Self::Error> {
        match identity {
            WireImportIdentity::Passphrase { passphrase } => {
                Ok(ImportIdentity::Passphrase(passphrase.into()))
            },
            WireImportIdentity::Identity { identity } => age::x25519::Identity::from_str(&identity)
                .map(ImportIdentity::Identity)
                .map_err(|e| format!("Invalid age identity: {e}")),
        }
    }
}

/// What the app needs to describe the prompt for a vault access.
#[derive(Debug, Clone)]
pub struct VaultAccessPrompt {
    /// The vault a single-vault access names. For
    /// [`VaultAction::ResolveSecrets`], the distinct vault keys joined with
    /// `, `, since one resolve can span several vaults.
    pub vault_key: String,

    /// Who asked, as `ap` resolved it. Carries the same delegated trust as
    /// [`WireRequest::Sign`]'s caller.
    pub caller: Option<String>,

    /// The full requesting process chain. For a vault access `ap` is the
    /// broker's own peer, so this is the peer's resolved chain rather than a
    /// delegated one. Shown when the user expands the prompt.
    pub caller_chain: Vec<crate::core::provenance::ProcessNode>,

    pub action: VaultAction,
}

/// One vault item as it crosses the socket: the overview only, never a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerVaultItem {
    pub key: String,
    pub title: String,
    pub credentials: Vec<BrokerCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerCredential {
    pub key: String,
    pub title: String,
}

/// Supplies an `LAContext` to unlock the vault on, and learns how the attempt
/// ended so it can take its prompt down.
#[async_trait]
pub trait VaultAuthorizer: Send + Sync + 'static {
    /// Prepare a context for `prompt` and put the prompt on screen. The broker
    /// unlocks on the returned context, which is what makes the attached
    /// `LAAuthenticationView` draw. `peer` is the process the broker verified.
    async fn begin(&self, prompt: VaultAccessPrompt, peer: Actor)
    -> Result<ForeignContext, String>;

    /// The attempt finished. Always called once `begin` has been called, so the
    /// app can take the prompt down and settle the authorization it handed out.
    async fn end(&self, prompt: VaultAccessPrompt, outcome: PromptOutcome);
}

/// Ask the app to unlock a vault and return its item overview. Blocking: it may
/// wait for the user to answer a prompt, so call it from a thread that can
/// block. Starts the app if it is not already running.
pub fn request_vault_items(
    vault_key: &str,
    caller: Option<&str>,
) -> Result<Vec<BrokerVaultItem>, BrokerError> {
    let request = WireRequest::ListVaultItems {
        vault_key: vault_key.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultItems { items } => Ok(items),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault listing".to_string(),
        )),
    }
}

/// Ask the app to unlock a vault and return one credential's secret. `None`
/// means the credential does not exist. Blocking, same as
/// [`request_vault_items`].
pub fn request_vault_secret(
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    caller: Option<&str>,
) -> Result<Option<SecretString>, BrokerError> {
    let request = WireRequest::ReadVaultSecret {
        vault_key: vault_key.to_string(),
        item_key: item_key.to_string(),
        credential_key: credential_key.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultSecret { value } => Ok(value.map(SecretString::from)),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault secret read".to_string(),
        )),
    }
}

/// Ask the app to resolve many `axo://` references at once, behind one prompt.
/// The returned vector is positionally matched to `refs`; `None` means that
/// reference does not resolve. Blocking, same as [`request_vault_items`].
pub fn request_resolve_secrets(
    refs: &[VaultRef],
    purpose: ResolvePurpose,
    caller: Option<&str>,
) -> Result<Vec<Option<SecretString>>, BrokerError> {
    let request = WireRequest::ResolveSecrets {
        refs: refs.to_vec(),
        purpose,
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::ResolvedSecrets { values } => Ok(values
            .into_iter()
            .map(|v| v.map(SecretString::from))
            .collect()),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to secret resolution".to_string(),
        )),
    }
}

/// Ask the app to unlock a vault and write one credential's secret value,
/// creating the item or credential if needed. Returns whether the item was
/// newly created. Blocking, same as [`request_vault_items`].
pub fn request_write_vault_secret(
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    title: &str,
    value: &SecretString,
    caller: Option<&str>,
) -> Result<bool, BrokerError> {
    let request = WireRequest::WriteVaultSecret {
        vault_key: vault_key.to_string(),
        item_key: item_key.to_string(),
        credential_key: credential_key.to_string(),
        title: title.to_string(),
        value: value.expose_secret().to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultWritten { created } => Ok(created),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault secret write".to_string(),
        )),
    }
}

/// Ask the app to unlock every named vault and write an encrypted bundle to
/// `dest_path`. Blocking, same as [`request_vault_items`].
pub fn request_export_vaults(
    vault_keys: &[String],
    dest_path: &str,
    mode: WireExportMode,
    caller: Option<&str>,
) -> Result<u32, BrokerError> {
    let request = WireRequest::ExportVaults {
        vault_keys: vault_keys.to_vec(),
        dest_path: dest_path.to_string(),
        mode,
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultsExported { count } => Ok(count),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault export".to_string(),
        )),
    }
}

/// Ask the app to import the selected vaults from a bundle, re-wrapping each
/// file key with the local encryption key. `selection` is `(bundle vault id,
/// target key)` pairs. Returns the keys of the imported vaults. Blocking, same
/// as [`request_vault_items`].
pub fn request_import_vaults(
    import_path: &str,
    identity: WireImportIdentity,
    selection: &[(String, String)],
    caller: Option<&str>,
) -> Result<Vec<String>, BrokerError> {
    let request = WireRequest::ImportVaults {
        import_path: import_path.to_string(),
        identity,
        selection: selection.to_vec(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultsImported { keys } => Ok(keys),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault import".to_string(),
        )),
    }
}

/// Ask the app to unlock the vault at `path` to validate it, then register it
/// as an external vault. Returns the vault key and name. Blocking, same as
/// [`request_vault_items`].
pub fn request_add_external_vault(
    path: &str,
    caller: Option<&str>,
) -> Result<(String, Option<String>), BrokerError> {
    let request = WireRequest::AddExternalVault {
        path: path.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultLinked { vault_key, name } => Ok((vault_key, name)),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault add".to_string(),
        )),
    }
}

pub(super) async fn authorize_and_serve(
    authorizer: &dyn VaultAuthorizer,
    prompt: VaultAccessPrompt,
    actor: Actor,
    payload: Option<VaultPayload>,
) -> WireResponse {
    let context = match authorizer.begin(prompt.clone(), actor.clone()).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!("App broker vault authorization declined: {message}");
            record_access(&prompt, &actor, Outcome::Denied, None, Some(&message));
            authorizer
                .end(prompt, PromptOutcome::Failed(message.clone()))
                .await;
            return WireResponse::Failed { message };
        },
    };

    let job = prompt.clone();
    let result = tokio::task::spawn_blocking(move || serve_on_context(job, context, payload))
        .await
        .unwrap_or_else(|e| Err(format!("Vault task failed: {e}")));

    let (response, outcome) = match result {
        Ok(response) => {
            record_access(&prompt, &actor, Outcome::Succeeded, Some(&response), None);
            (response, PromptOutcome::Succeeded)
        },
        Err(message) => {
            record_access(&prompt, &actor, Outcome::Failed, None, Some(&message));
            (
                WireResponse::Failed {
                    message: message.clone(),
                },
                PromptOutcome::Failed(message),
            )
        },
    };
    authorizer.end(prompt, outcome).await;
    response
}

/// Record one vault access. Values never appear: a read is named by its
/// `vault/item/credential` path, and a listing by its item count.
fn record_access(
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    outcome: Outcome,
    response: Option<&WireResponse>,
    message: Option<&str>,
) {
    let vault_key = &prompt.vault_key;
    let (action, subject) = match &prompt.action {
        VaultAction::ListItems => (
            Action::VaultItemsListed,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::ReadSecret {
            item_key,
            credential_key,
        } => (
            Action::SecretRead,
            Subject::new(
                SubjectKind::Credential,
                format!("{vault_key}/{item_key}/{credential_key}"),
            ),
        ),
        VaultAction::ResolveSecrets { purpose, .. } => {
            let action = match purpose {
                ResolvePurpose::Exec => Action::SecretExec,
                ResolvePurpose::Inject => Action::SecretInject,
                ResolvePurpose::Read => Action::SecretRead,
            };
            (action, Subject::new(SubjectKind::Vault, vault_key.clone()))
        },
        VaultAction::WriteSecret {
            item_key,
            credential_key,
        } => (
            Action::VaultItemUpdated,
            Subject::new(
                SubjectKind::Credential,
                format!("{vault_key}/{item_key}/{credential_key}"),
            ),
        ),
        VaultAction::ExportVaults { .. } => (
            Action::VaultExported,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::ImportVaults { .. } => (
            Action::VaultImported,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::AddVault { path } => (
            Action::VaultLinked,
            Subject::new(SubjectKind::Vault, path.clone()),
        ),
    };

    // A write that created the item records `vault.item_created` instead. The
    // serve step reports which through the response.
    let action = match (&prompt.action, response) {
        (VaultAction::WriteSecret { .. }, Some(WireResponse::VaultWritten { created: true })) => {
            Action::VaultItemCreated
        },
        _ => action,
    };

    let mut event = AuditEvent::new(audit::process_source(), action, outcome)
        .subject(subject)
        .actor(actor.clone())
        .detail("vault", vault_key.clone())
        .detail("via", "broker");
    if let VaultAction::ResolveSecrets { refs, .. } = &prompt.action {
        event = event.detail("secret_count", refs.len().to_string());
    }
    match response {
        Some(WireResponse::VaultItems { items }) => {
            event = event.detail("item_count", items.len().to_string());
        },
        Some(WireResponse::VaultSecret { value }) => {
            event = event.detail("found", value.is_some().to_string());
        },
        Some(WireResponse::ResolvedSecrets { values }) => {
            let resolved = values.iter().filter(|v| v.is_some()).count();
            event = event.detail("resolved_count", resolved.to_string());
        },
        Some(WireResponse::VaultWritten { created }) => {
            event = event.detail("created", created.to_string());
        },
        Some(WireResponse::VaultsExported { count }) => {
            event = event.detail("vault_count", count.to_string());
        },
        Some(WireResponse::VaultsImported { keys }) => {
            event = event.detail("vault_count", keys.len().to_string());
        },
        _ => {},
    }
    if let Some(message) = message {
        event = event.message(message.to_string());
    }
    audit::record(event);
}

/// Load the vault from disk and serve the request on the app's context.
///
/// The vault is loaded fresh from disk and, for a write, saved straight back,
/// so this does not touch the app's in-memory vault state. The app's own CRUD
/// re-reads the file before every mutation (`with_unlocked_vault` calls
/// `unlock` each time), so a later UI edit does not clobber a write made here.
fn serve_on_context(
    prompt: VaultAccessPrompt,
    context: ForeignContext,
    payload: Option<VaultPayload>,
) -> Result<WireResponse, String> {
    match &prompt.action {
        VaultAction::ResolveSecrets { refs, .. } => return resolve_secrets(refs, context),
        VaultAction::ExportVaults { vault_keys } => {
            let Some(VaultPayload::Export(export)) = payload else {
                return Err("Missing export payload".to_string());
            };
            return export_vaults(vault_keys, export, context);
        },
        VaultAction::ImportVaults { .. } => {
            let Some(VaultPayload::Import(import)) = payload else {
                return Err("Missing import payload".to_string());
            };
            return import_vaults(import, context);
        },
        VaultAction::AddVault { path } => return add_external_vault(path, context),
        _ => {},
    }

    let write = match payload {
        Some(VaultPayload::Write(write)) => Some(write),
        None => None,
        Some(_) => return Err("Wrong payload for this vault action".to_string()),
    };

    let mut vw = VaultWrapper::load(&vaults_dir(), Some(prompt.vault_key.clone()))
        .map_err(|e| format!("Failed to load vault: {e}"))?;
    vw.unlock_on(AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to unlock vault: {e}"))?;

    match prompt.action {
        VaultAction::ListItems => Ok(WireResponse::VaultItems {
            items: collect_items(&vw)?,
        }),
        VaultAction::ReadSecret {
            item_key,
            credential_key,
        } => {
            let value = vw
                .get_secret(&item_key, &credential_key)
                .map_err(|e| format!("Failed to get secret: {e}"))?
                .map(|secret| secret.expose_secret().to_string());
            Ok(WireResponse::VaultSecret { value })
        },
        VaultAction::WriteSecret {
            item_key,
            credential_key,
        } => {
            let payload = write.ok_or("Missing write payload")?;
            // Keep an existing credential's kind so a value-only update does
            // not reset it; a new credential falls back to the default.
            let existing = vw
                .get_secret_overview(&item_key, &credential_key)
                .ok()
                .flatten();
            let created =
                existing.is_none() && vw.get_item_overview(&item_key).ok().flatten().is_none();
            let kind = existing
                .map(|o| o.kind.clone())
                .unwrap_or_else(FieldKind::default);
            vw.add_secret(
                &item_key,
                &credential_key,
                &payload.title,
                kind,
                payload.value,
            )
            .map_err(|e| format!("Failed to add secret: {e}"))?;
            vw.save()
                .map_err(|e| format!("Failed to save vault: {e}"))?;
            Ok(WireResponse::VaultWritten { created })
        },
        VaultAction::ResolveSecrets { .. }
        | VaultAction::ExportVaults { .. }
        | VaultAction::ImportVaults { .. }
        | VaultAction::AddVault { .. } => unreachable!("handled above"),
    }
}

/// Unlock every named vault on the app's context and write the export bundle.
fn export_vaults(
    vault_keys: &[String],
    export: ExportPayload,
    context: ForeignContext,
) -> Result<WireResponse, String> {
    let mut vm = VaultsManager::new();
    vm.export_bundle_on(
        vault_keys,
        &export.dest_path,
        export.mode,
        AuthContext::Foreign(context),
        |_| {},
    )
    .map_err(|e| format!("Failed to export vaults: {e}"))?;
    Ok(WireResponse::VaultsExported {
        count: vault_keys.len() as u32,
    })
}

/// Re-open the bundle and import the selected vaults, re-wrapping each file key
/// with the local encryption key on the app's context.
fn import_vaults(import: ImportPayload, context: ForeignContext) -> Result<WireResponse, String> {
    let identity =
        ImportIdentity::try_from(import.identity).map_err(|e| format!("Invalid identity: {e}"))?;

    let mut selection: std::collections::BTreeMap<uuid::Uuid, String> =
        std::collections::BTreeMap::new();
    for (id, key) in import.selection {
        let id = uuid::Uuid::parse_str(&id).map_err(|e| format!("Invalid vault id {id}: {e}"))?;
        selection.insert(id, key);
    }

    let mut vm = VaultsManager::new();
    let bundle = vm
        .open_bundle(&import.import_path, identity)
        .map_err(|e| format!("Failed to open bundle: {e}"))?;
    let keys = vm
        .import_bundle_on(bundle, &selection, AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to import bundle: {e}"))?;
    Ok(WireResponse::VaultsImported { keys })
}

/// Unlock the vault at `path` to validate it, then register it as an external
/// vault in the app config.
fn add_external_vault(path: &str, context: ForeignContext) -> Result<WireResponse, String> {
    let path = Path::new(path)
        .canonicalize()
        .map_err(|e| format!("Could not resolve path {path}: {e}"))?;

    let mut vw = VaultWrapper::load_from_path(None, &path)
        .map_err(|e| format!("Not a valid vault file: {e}"))?;
    vw.unlock_on(AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to unlock vault: {e}"))?;

    let name = vw.vault_name().map(str::to_string);
    APP_CONFIG
        .lock()
        .map_err(|e| format!("Failed to lock config: {e}"))?
        .add_external_vault(&vw.key, path)
        .map_err(|e| format!("Failed to add vault: {e}"))?;

    Ok(WireResponse::VaultLinked {
        vault_key: vw.key.clone(),
        name,
    })
}

/// Resolve every reference, unlocking each distinct vault once on the app's
/// context. The result is positionally matched to `refs`. A reference whose
/// vault fails to load or unlock resolves to `None` rather than failing the
/// whole batch.
fn resolve_secrets(refs: &[VaultRef], context: ForeignContext) -> Result<WireResponse, String> {
    use std::collections::HashMap;

    let vaults_dir = vaults_dir();
    let mut vaults: HashMap<String, Option<VaultWrapper>> = HashMap::new();
    let mut values = Vec::with_capacity(refs.len());

    for r in refs {
        let vw = vaults.entry(r.vault_key.clone()).or_insert_with(|| {
            match VaultWrapper::load(&vaults_dir, Some(r.vault_key.clone())) {
                Ok(mut vw) => match vw.unlock_on(AuthContext::Foreign(context.clone())) {
                    Ok(()) => Some(vw),
                    Err(e) => {
                        log::error!("Failed to unlock vault {}: {e}", r.vault_key);
                        None
                    },
                },
                Err(e) => {
                    log::error!("Failed to load vault {}: {e}", r.vault_key);
                    None
                },
            }
        });

        let value = match vw {
            Some(vw) => match vw.get_secret(&r.item_key, &r.credential_key) {
                Ok(secret) => secret.map(|s| s.expose_secret().to_string()),
                Err(e) => {
                    log::error!(
                        "Failed to get secret {}/{}/{}: {e}",
                        r.vault_key,
                        r.item_key,
                        r.credential_key
                    );
                    None
                },
            },
            None => None,
        };
        values.push(value);
    }

    Ok(WireResponse::ResolvedSecrets { values })
}

fn collect_items(vw: &VaultWrapper) -> Result<Vec<BrokerVaultItem>, String> {
    let mut items: Vec<BrokerVaultItem> = vw
        .list_items()
        .map_err(|e| format!("Failed to list items: {e}"))?
        .into_iter()
        .map(|item| BrokerVaultItem {
            key: item.key.clone(),
            title: item.title.clone(),
            credentials: item
                .credentials
                .values()
                .map(|c| BrokerCredential {
                    key: c.key.clone(),
                    title: c.title.clone(),
                })
                .collect(),
        })
        .collect();
    items.sort_by_key(|a| a.title.to_lowercase());
    Ok(items)
}
