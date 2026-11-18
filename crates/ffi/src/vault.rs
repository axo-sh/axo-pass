use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axo_pass_core::audit;
use axo_pass_core::core::app_broker::IndexedPasskey;
use axo_pass_core::core::app_broker::ssh::{vault_keys as ssh_vault_keys, vault_keys_path};
use axo_pass_core::core::config::{APP_CONFIG, autofill_excluded_vaults};
use axo_pass_core::secrets::password::PasswordPolicy;
use axo_pass_core::secrets::vaults::model::history::HistoryKind;
use axo_pass_core::secrets::vaults::model::{ItemChange, ItemHistoryEvent, totp};
use axo_pass_core::secrets::vaults::passkey::PasskeyTarget;
use axo_pass_core::secrets::vaults::passkey::signals::{self, SignalStore};
use axo_pass_core::secrets::vaults::storage::txn::VaultWriter;
use axo_pass_core::secrets::vaults::{
    CredentialPlacement, CredentialUpdate, Error as VaultError, FieldKind, MatchKind, ShortId,
    Site, TextField, VaultCatalog, VaultFolder, VaultHandle, VaultItemCredentialOverview,
    VaultItemOverview, VaultItemSection, VaultsManager, Website, autofill, display_order, passkey,
};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::files::{FileInfo, refuse_file};
use crate::ssh_vault_keys::{sweep_ssh_pubkey_files, sync_ssh_key_listing};
use crate::*;

#[derive(uniffi::Record, Clone)]
pub struct VaultInfo {
    pub key: String,
    pub name: Option<String>,
    /// Vault id as a short id, read from the file header without verifying
    /// it. Sync events name vaults by id. `None` if the header fails to
    /// read.
    pub id: Option<String>,
}

/// Vault id held by more than one file, with the path of each file.
#[derive(uniffi::Record, Clone)]
pub struct DuplicateVaultInfo {
    pub vault_id: String,
    pub paths: Vec<String>,
}

/// Vault key claimed by more than one file, with the path of each file.
#[derive(uniffi::Record, Clone)]
pub struct DuplicateVaultKeyInfo {
    pub key: String,
    pub paths: Vec<String>,
}

/// A retained version of a vault: the vault file as it was before a save.
#[derive(uniffi::Record)]
pub struct RetainedVersionInfo {
    /// Identifies the version for a restore.
    pub name: String,
    /// Time of the save that replaced this version, as a Unix timestamp in
    /// seconds.
    pub saved_at: i64,
}

#[derive(uniffi::Record)]
pub struct CredentialInfo {
    /// Credential id as a short id. It does not change when the key does.
    pub id: String,
    pub key: String,
    pub title: String,
    pub kind: FieldKindInfo,
    /// User-defined order within the credential's section. `None` for
    /// credentials that have never been reordered; the list is already
    /// returned in display order.
    pub position: Option<u32>,
    /// `id` of the item section the credential is in. `None` for a credential
    /// outside any section.
    pub section_id: Option<String>,
    /// The part the credential plays in autofill: "username", "password",
    /// "totp", or none. The password role decides the credential is concealed,
    /// whatever its kind.
    pub role: Option<String>,
    /// Unix seconds of the first use on the most recent day of use. Only
    /// passkey sign-ins set it. It names the day of last use, not the time.
    pub last_used_day_at: Option<i64>,
    /// Unix seconds of creation.
    pub created_at: i64,
    /// Only present for passkeys; contains passkey credential details for
    /// display.
    pub passkey: Option<PasskeyInfo>,
    /// Only present for file credentials whose record reads; details of the
    /// file for display. Carries no key.
    pub file: Option<FileInfo>,
}

/// The displayable fields of a passkey. Carries no key material, so the UI
/// can show a passkey without revealing its record.
#[derive(uniffi::Record)]
pub struct PasskeyInfo {
    pub rp_id: String,
    /// base64url, no padding.
    pub credential_id: String,
    pub username: Option<String>,
    pub user_display_name: Option<String>,
    /// Unix seconds when the passkey was registered, when recorded.
    pub created_at: Option<i64>,
    /// The passkey supports the WebAuthn PRF extension.
    pub prf: bool,
    /// The site reported that it no longer accepts this passkey. It is not
    /// offered in AutoFill.
    pub site_rejected: bool,
    /// A new account name the site reported, when it differs from the stored
    /// one.
    pub suggested_name: Option<String>,
}

/// What the user dismissed about a passkey site report.
#[derive(uniffi::Enum, Clone, Copy)]
pub enum PasskeyReportKind {
    /// Keep a passkey the site no longer accepts.
    Rejection,
    /// Ignore a reported account name.
    Rename,
}

impl From<PasskeyReportKind> for signals::DismissKind {
    fn from(kind: PasskeyReportKind) -> Self {
        match kind {
            PasskeyReportKind::Rejection => signals::DismissKind::Rejection,
            PasskeyReportKind::Rename => signals::DismissKind::Rename,
        }
    }
}

/// Passkey details for display, with what site reports say about it.
fn passkey_info(summary: passkey::PasskeySummary, signals: &SignalStore) -> PasskeyInfo {
    let status = signals.status(passkey_ref(&summary));
    PasskeyInfo {
        rp_id: summary.rp_id,
        credential_id: summary.credential_id,
        username: summary.username,
        user_display_name: summary.user_display_name,
        created_at: summary.created_at,
        prf: summary.prf,
        site_rejected: status.rejected,
        suggested_name: status.suggested_name,
    }
}

fn passkey_ref(summary: &passkey::PasskeySummary) -> signals::PasskeyRef<'_> {
    signals::PasskeyRef {
        rp_id: &summary.rp_id,
        credential_id: &summary.credential_id,
        user_handle: summary.user_handle.as_deref(),
        current_name: summary
            .user_display_name
            .as_deref()
            .or(summary.username.as_deref()),
    }
}

/// A previous value of a credential. The value is not included. Read it with
/// `get_credential_history_value`.
#[derive(uniffi::Record)]
pub struct HistoryEntryInfo {
    /// Entry id as a short id.
    pub id: String,
    /// Time the value was replaced, as a Unix timestamp in seconds.
    pub replaced_at: i64,
}

/// Change an item history event records. See `model::ItemChange`.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum ItemHistoryKind {
    ItemCreated,
    ValueCreated,
    ValueUpdated,
    CredentialDeleted,
    /// History entry of a kind this build does not know.
    Other,
}

/// One event of the history of an item. Values are not included.
#[derive(uniffi::Record)]
pub struct ItemHistoryEventInfo {
    /// Time of the event, as a Unix timestamp in seconds.
    pub at: i64,
    pub kind: ItemHistoryKind,
    /// Credential id as a short id. `None` for an event of the item.
    pub credential_id: Option<String>,
    pub credential_key: Option<String>,
    pub credential_title: Option<String>,
    /// Whether the credential is deleted.
    pub credential_deleted: bool,
    /// History entry id as a short id, for an event from a credential history.
    pub history_id: Option<String>,
}

impl From<ItemHistoryEvent<'_>> for ItemHistoryEventInfo {
    fn from(event: ItemHistoryEvent<'_>) -> Self {
        let (kind, history_id) = match event.change {
            ItemChange::ItemCreated => (ItemHistoryKind::ItemCreated, None),
            ItemChange::CredentialDeleted => (ItemHistoryKind::CredentialDeleted, None),
            ItemChange::History { id, kind } => {
                let kind = match kind {
                    HistoryKind::ValueCreated => ItemHistoryKind::ValueCreated,
                    HistoryKind::ValueUpdated => ItemHistoryKind::ValueUpdated,
                    HistoryKind::Unknown(_) => ItemHistoryKind::Other,
                };
                (kind, Some(ShortId::encode_uuid(id)))
            },
        };
        Self {
            at: event.at,
            kind,
            credential_id: event.credential.map(|c| ShortId::encode_uuid(c.id)),
            credential_key: event.credential.map(|c| c.key.clone()),
            credential_title: event.credential.map(|c| c.title.clone()),
            credential_deleted: event.credential_deleted,
            history_id,
        }
    }
}

/// A deleted item that can still be restored. Credential values are not
/// included.
#[derive(uniffi::Record)]
pub struct DeletedItemInfo {
    /// Item id as a short id. Pass back to `restore_item` or `purge_item`.
    pub id: String,
    pub key: String,
    pub title: String,
    /// Credentials the item had, in display order, including those deleted
    /// before the item at their former positions. All are restored with the
    /// item.
    pub credentials: Vec<DeletedItemCredentialInfo>,
    /// Deletion time as a Unix timestamp in seconds.
    pub deleted_at: i64,
}

/// A credential of a deleted item. Read its value with
/// `get_deleted_credential_secret`.
#[derive(uniffi::Record)]
pub struct DeletedItemCredentialInfo {
    /// Credential id as a short id.
    pub id: String,
    pub key: String,
    pub title: String,
    pub kind: FieldKindInfo,
    /// True if the credential was deleted before the item.
    pub deleted_before_item: bool,
    /// Details of a deleted file credential. `None` for any other kind.
    pub file: Option<FileInfo>,
}

/// A deleted credential of a live item that can still be restored. The value
/// is not included. Read it with `get_deleted_credential_secret`.
#[derive(uniffi::Record)]
pub struct DeletedCredentialInfo {
    /// Credential id as a short id. Pass back to `restore_credential` or
    /// `purge_credential`.
    pub id: String,
    pub key: String,
    pub title: String,
    pub kind: FieldKindInfo,
    /// Id of the item the credential was deleted from.
    pub item_id: String,
    pub item_key: String,
    pub item_title: String,
    /// Deletion time as a Unix timestamp in seconds.
    pub deleted_at: i64,
    /// Details of a deleted file credential. `None` for any other kind.
    pub file: Option<FileInfo>,
}

/// A vault folder. Folders are listed in display order.
#[derive(uniffi::Record)]
pub struct FolderInfo {
    /// Folder id as a short id.
    pub id: String,
    pub title: String,
}

impl From<&VaultFolder> for FolderInfo {
    fn from(f: &VaultFolder) -> Self {
        Self {
            id: ShortId::encode_uuid(f.id),
            title: f.title.clone(),
        }
    }
}

/// A section of an item. Sections are listed in display order.
#[derive(uniffi::Record)]
pub struct SectionInfo {
    /// Section id as a short id.
    pub id: String,
    pub title: String,
}

impl From<&VaultItemSection> for SectionInfo {
    fn from(s: &VaultItemSection) -> Self {
        Self {
            id: ShortId::encode_uuid(s.id),
            title: s.title.clone(),
        }
    }
}

/// Where a credential goes in `arrange_credentials`.
#[derive(uniffi::Record)]
pub struct CredentialPlacementInfo {
    pub key: String,
    /// `id` of a section of the same item, or `None` for no section.
    pub section_id: Option<String>,
}

/// Flattened view of `FieldKind` for the UI. `kind` is the discriminator:
/// "text", "email", "url", "phone", "date", "totp", "passkey", "file", or
/// "unknown". `multiline` applies only to "text"; it is false for every other
/// kind, and `concealed` is true for "text" that conceals its value, for
/// "passkey", and for "file".
///
/// The write path (`add_or_update_credential`) accepts every discriminator
/// except "unknown", which cannot be reconstructed, and "passkey" and "file",
/// whose values are structured records written only by their own code paths.
/// When the caller wants to leave an existing credential's kind untouched it
/// passes `None`.
#[derive(uniffi::Record, Clone)]
pub struct FieldKindInfo {
    pub kind: String,
    pub concealed: bool,
    pub multiline: bool,
}

impl From<&FieldKind> for FieldKindInfo {
    fn from(k: &FieldKind) -> Self {
        let (kind, concealed, multiline) = match k {
            FieldKind::Text(t) => ("text", false, t.multiline.unwrap_or(false)),
            FieldKind::Confidential(t) => ("text", true, t.multiline.unwrap_or(false)),
            FieldKind::Email => ("email", false, false),
            FieldKind::Url => ("url", false, false),
            FieldKind::Phone => ("phone", false, false),
            FieldKind::Date => ("date", false, false),
            FieldKind::Totp => ("totp", false, false),
            FieldKind::Passkey => ("passkey", true, false),
            FieldKind::File => ("file", true, false),
            FieldKind::SshKey => ("ssh-key", true, false),
            FieldKind::Unknown(_) => ("unknown", false, false),
        };
        Self {
            kind: kind.to_string(),
            concealed,
            multiline,
        }
    }
}

impl TryFrom<FieldKindInfo> for FieldKind {
    type Error = FfiError;

    fn try_from(i: FieldKindInfo) -> Result<Self, Self::Error> {
        Ok(match i.kind.as_str() {
            "text" => {
                let field = TextField {
                    multiline: Some(i.multiline),
                };
                if i.concealed {
                    FieldKind::Confidential(field)
                } else {
                    FieldKind::Text(field)
                }
            },
            "email" => FieldKind::Email,
            "url" => FieldKind::Url,
            "phone" => FieldKind::Phone,
            "date" => FieldKind::Date,
            "totp" => FieldKind::Totp,
            // "passkey" is deliberately absent: a passkey's value is a
            // structured record the CTAP2 authenticator owns, so it is never
            // written through the generic credential path. "file" and
            // "ssh-key" are absent for the same reason.
            other => {
                return Err(FfiError::InvalidInput(format!(
                    "cannot set field kind {other:?}"
                )));
            },
        })
    }
}

/// A website a login applies to. `match_kind` is "domain", "host",
/// "starts-with", or "never".
#[derive(uniffi::Record, Clone)]
pub struct WebsiteInfo {
    pub url: String,
    pub match_kind: String,
}

impl From<&Website> for WebsiteInfo {
    fn from(website: &Website) -> Self {
        let match_kind = match website.match_kind {
            MatchKind::Domain => "domain",
            MatchKind::Host => "host",
            MatchKind::StartsWith => "starts-with",
            MatchKind::Never => "never",
        };
        Self {
            url: website.url.clone(),
            match_kind: match_kind.to_string(),
        }
    }
}

impl TryFrom<WebsiteInfo> for Website {
    type Error = FfiError;

    fn try_from(info: WebsiteInfo) -> Result<Self, Self::Error> {
        let match_kind = match info.match_kind.as_str() {
            "domain" => MatchKind::Domain,
            "host" => MatchKind::Host,
            "starts-with" => MatchKind::StartsWith,
            "never" => MatchKind::Never,
            other => {
                return Err(FfiError::InvalidInput(format!(
                    "unknown match kind {other:?}"
                )));
            },
        };
        Ok(Website::new(info.url, match_kind))
    }
}

/// What a website matches, for display. See [`autofill::match_scope`]. `None`
/// if the URL or match kind is invalid.
#[uniffi::export]
pub fn website_match_scope(website: WebsiteInfo) -> Option<String> {
    autofill::match_scope(&Website::try_from(website).ok()?)
}

/// A credential's part in autofill: "username", "password", or "totp".
fn parse_role(role: &str) -> Result<autofill::Role, FfiError> {
    match role {
        "username" => Ok(autofill::Role::Username),
        "password" => Ok(autofill::Role::Password),
        "totp" => Ok(autofill::Role::Totp),
        other => Err(FfiError::InvalidInput(format!("unknown role {other:?}"))),
    }
}

#[derive(uniffi::Record)]
pub struct ItemInfo {
    /// Item id as a short id. It does not change when the key does.
    pub id: String,
    pub key: String,
    pub title: String,
    /// `id` of the folder the item is in. `None` for an unfiled item.
    pub folder_id: Option<String>,
    pub sections: Vec<SectionInfo>,
    /// Credentials outside any section first, then each section's
    /// credentials in section order.
    pub credentials: Vec<CredentialInfo>,
    /// The item's display category, such as "login".
    pub category: Option<String>,
    /// The value of the username credential, when the item has one.
    pub username: Option<String>,
    /// The websites the item applies to.
    pub websites: Vec<WebsiteInfo>,
    /// The item has no autofill data but its credentials look like a login, so
    /// the app can offer to convert it.
    pub can_convert_to_login: bool,
    /// The item names a password credential that is missing or cannot be one.
    pub password_role_broken: bool,
}

/// A one-time code and how long it stays valid.
#[derive(uniffi::Record)]
pub struct TotpCodeInfo {
    pub code: String,
    pub seconds_remaining: u64,
}

/// One fillable item, as the AutoFill identity store needs it. Mirrors
/// [`autofill::AutofillItem`].
#[derive(uniffi::Record)]
pub struct AutofillItemInfo {
    pub vault_key: String,
    pub item_key: String,
    /// `<vault id>/<item id>/<password credential id>`, as short ids. The
    /// identifier the AutoFill index stores, and the broker's login requests
    /// take.
    pub record_id: String,
    pub title: String,
    pub username: Option<String>,
    /// The credential key holding the password to fill.
    pub password_key: String,
    /// The hosts to register with the system, one identity each. A `domain`
    /// website contributes its registrable domain as well as its host, since
    /// the system's subdomain matching for a domain identifier is unconfirmed.
    /// A website that never matches contributes none.
    pub hosts: Vec<String>,
    /// The item has a one-time code, so it also gets a code identity.
    pub has_totp: bool,
}

/// One stored passkey, as the AutoFill identity store needs it. The system
/// matches on the relying party; the record identifier points the assertion
/// back at the vault credential.
#[derive(uniffi::Record)]
pub struct PasskeyIdentityInfo {
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
    /// `<vault id>/<item id>/<credential id>`, as short ids.
    pub record_id: String,
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    pub user_name: String,
    /// Empty when the record carries no user handle.
    pub user_handle: Vec<u8>,
}

impl From<autofill::AutofillItem> for AutofillItemInfo {
    fn from(item: autofill::AutofillItem) -> Self {
        Self {
            vault_key: item.vault_key,
            item_key: item.item_key,
            record_id: item.record_id,
            title: item.title,
            username: item.username,
            password_key: item.password_key,
            hosts: autofill::identity_hosts(&item.websites),
            has_totp: item.has_totp,
        }
    }
}

impl AxoPass {
    /// Run `f` on a vault in one transaction on a blocking thread. The manager
    /// mutex is not held while the transaction waits for the vault locks.
    async fn edit_vault<R: Send + 'static>(
        &self,
        vault_key: String,
        f: impl FnOnce(&mut VaultHandle) -> Result<R, FfiError> + Send + 'static,
    ) -> Result<R, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || VaultsManager::write_vault(&manager, &vault_key, f))
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// The vault files on disk, for an operation that keeps no copy in the
    /// manager.
    pub(crate) fn store(&self) -> Result<VaultCatalog, FfiError> {
        Ok(self
            .manager
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .store()
            .clone())
    }
}

/// Decrypt vault `vault_key` from disk if it is not already in memory. Uses
/// the shared LAContext the app adopted at unlock, so this never prompts. Fails
/// with `AuthExpired` if the app is locked. The manager mutex is released while
/// the vault unlocks, since the read can run a transaction
/// ([`VaultsManager::unlock_vault`]).
pub(crate) fn ensure_unlocked(
    manager: &Mutex<VaultsManager>,
    vault_key: &str,
) -> Result<(), FfiError> {
    let locked = {
        let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
        let vault = m.get_or_create_vault_mut(vault_key)?;
        matches!(vault.list_items(), Err(VaultError::VaultLocked))
    };
    if locked {
        VaultsManager::unlock_vault(manager, vault_key)?;
    }
    Ok(())
}

/// Unlock every vault of the manager, with the manager mutex released while
/// each vault unlocks ([`VaultsManager::unlock_vault`]). A vault that fails to
/// unlock is logged with `purpose` and skipped. Returns the keys of the vaults
/// that unlocked.
fn unlock_every_vault(
    manager: &Mutex<VaultsManager>,
    purpose: &str,
) -> Result<Vec<String>, FfiError> {
    let vault_keys: Vec<String> = manager
        .lock()
        .map_err(|_| FfiError::Poisoned)?
        .iter_vault_keys()
        .collect();
    Ok(vault_keys
        .into_iter()
        .filter(
            |vault_key| match VaultsManager::unlock_vault(manager, vault_key) {
                Ok(()) => true,
                Err(e) => {
                    log::error!("Failed to unlock vault {vault_key} for {purpose}: {e}");
                    false
                },
            },
        )
        .collect())
}

/// Item sections in display order, and a comparator that orders item
/// credentials for display. Credentials outside any section come first, then
/// each section by its display order.
fn item_display_order(
    item: &VaultItemOverview,
) -> (
    Vec<&VaultItemSection>,
    impl Fn(&VaultItemCredentialOverview, &VaultItemCredentialOverview) -> std::cmp::Ordering,
) {
    let mut sections: Vec<&VaultItemSection> = item.sections.values().collect();
    sections.sort_by(|a, b| {
        display_order(a.position, &a.title).cmp(&display_order(b.position, &b.title))
    });

    let section_rank: HashMap<Uuid, usize> = sections
        .iter()
        .enumerate()
        .map(|(idx, s)| (s.id, idx + 1))
        .collect();
    let rank = move |section: Option<Uuid>| {
        section
            .and_then(|s| section_rank.get(&s).copied())
            .unwrap_or(0)
    };
    let credential_order = move |a: &VaultItemCredentialOverview,
                                 b: &VaultItemCredentialOverview| {
        (rank(a.section), display_order(a.position, &a.title))
            .cmp(&(rank(b.section), display_order(b.position, &b.title)))
    };
    (sections, credential_order)
}

/// Details of the deleted credential `cred_id` of item `item_id`, if `kind`
/// is the file kind and its record reads.
fn deleted_file_info(
    writer: &VaultWriter,
    vault: &VaultHandle,
    item_id: Uuid,
    cred_id: Uuid,
    kind: &FieldKind,
) -> Option<FileInfo> {
    if !matches!(kind, FieldKind::File) {
        return None;
    }
    let value = vault.get_deleted_secret(item_id, cred_id).ok()?;
    FileInfo::of_value(writer, vault, value.expose_secret())
}

/// Fail with `InvalidInput` if the deleted credential `cred_id` of item
/// `item_id` is a file credential. Its value is a record with the file key.
fn refuse_deleted_file(vault: &VaultHandle, item_id: Uuid, cred_id: Uuid) -> Result<(), FfiError> {
    let in_live_items = vault
        .list_all_deleted()?
        .into_iter()
        .filter(|d| d.item.id == item_id && d.credential.credential.id == cred_id)
        .map(|d| matches!(d.credential.credential.kind, FieldKind::File));
    let in_deleted_items = vault
        .list_deleted_items()?
        .into_iter()
        .filter(|d| d.item.id == item_id)
        .flat_map(|d| {
            d.item
                .credentials
                .values()
                .chain(d.deleted_credentials.iter().copied())
                .filter(|c| c.id == cred_id)
                .map(|c| matches!(c.kind, FieldKind::File))
                .collect::<Vec<_>>()
        });
    if in_live_items.chain(in_deleted_items).any(|is_file| is_file) {
        return Err(FfiError::InvalidInput(
            "A file credential has no text value".to_string(),
        ));
    }
    Ok(())
}

/// Read an id passed from Swift. The short form and the hex forms are
/// accepted.
pub(crate) fn parse_id(id: &str) -> Result<Uuid, FfiError> {
    ShortId::parse_uuid(id).map_err(|_| FfiError::InvalidInput(format!("Invalid id: {id}")))
}

/// Short form of an id given in the short or a hex form. `None` if `id` is not
/// an id. For ids that Swift stored before ids were short.
#[uniffi::export]
pub fn short_id(id: String) -> Option<String> {
    ShortId::decode(&id).ok().map(ShortId::encode)
}

fn parse_optional_id(id: Option<String>) -> Result<Option<Uuid>, FfiError> {
    id.as_deref().map(parse_id).transpose()
}

fn parse_ids(ids: &[String]) -> Result<Vec<Uuid>, FfiError> {
    ids.iter().map(|id| parse_id(id)).collect()
}

/// Audit subject for a vault.
fn vault_subject(vault_key: &str) -> audit::Subject {
    audit::Subject::new(audit::SubjectKind::Vault, vault_key)
}

/// Audit subject for an item, named `vault/item`.
pub(crate) fn item_subject(vault_key: &str, item_key: &str) -> audit::Subject {
    audit::Subject::new(audit::SubjectKind::Item, format!("{vault_key}/{item_key}"))
}

/// Audit subject for a credential, named `vault/item/credential`.
pub(crate) fn credential_subject(
    vault_key: &str,
    item_key: &str,
    cred_key: &str,
) -> audit::Subject {
    audit::Subject::new(
        audit::SubjectKind::Credential,
        format!("{vault_key}/{item_key}/{cred_key}"),
    )
}

/// Audit subject for an item looked up by id. `found` is the item key and
/// title. The id stands in for the key if the item was not found.
fn item_subject_by_id(
    vault_key: &str,
    item_id: &str,
    found: Option<(String, String)>,
) -> audit::Subject {
    match found {
        Some((item_key, title)) => item_subject(vault_key, &item_key).label(title),
        None => item_subject(vault_key, item_id),
    }
}

/// Audit subject for a credential looked up by id. `found` is the credential
/// key and title. The id stands in for the key if the credential was not
/// found.
fn credential_subject_by_id(
    vault_key: &str,
    item_key: &str,
    cred_id: &str,
    found: Option<(String, String)>,
) -> audit::Subject {
    match found {
        Some((cred_key, title)) => credential_subject(vault_key, item_key, &cred_key).label(title),
        None => credential_subject(vault_key, item_key, cred_id),
    }
}

/// Website origin for an audit detail, as `scheme://host`. The path and query
/// are dropped because they can carry tokens. The host is normalized as in
/// autofill matching, without a leading `www.`. A URL that does not parse is
/// recorded as `invalid`.
fn website_origin(url: &str) -> String {
    match Site::parse(url) {
        Some(site) => {
            let scheme = if site.secure { "https" } else { "http" };
            format!("{scheme}://{}", site.host)
        },
        None => "invalid".to_string(),
    }
}

/// Record in the vault of the passkey that the user dismissed what reports so
/// far say about it. The caller saves the vault.
fn dismiss_report(
    vw: &mut VaultHandle,
    summary: &passkey::PasskeySummary,
    kind: signals::DismissKind,
) -> Result<(), FfiError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| FfiError::Internal(e.to_string()))?;
    let at = i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX);
    vw.update_passkey_signals(|store| {
        store.dismiss(&summary.rp_id, &summary.credential_id, kind, at)
    })?;
    Ok(())
}

/// Audit event for a successful vault change made in the app. Failed changes
/// and reads in the app are not recorded. A passkey move that leaves the
/// passkey in both vaults is the one exception. Details carry keys, titles,
/// and counts, never values. `ids` are the ids of the subject.
pub(crate) fn change_event(
    action: audit::Action,
    vault_key: &str,
    subject: audit::Subject,
    ids: audit::SubjectIds,
) -> audit::AuditEvent {
    audit::AuditEvent::new(audit::process_source(), action, audit::Outcome::Succeeded)
        .subject(subject)
        .subject_ids(ids)
        .detail("vault", vault_key)
        .detail("via", "app")
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Scan the vault files again, for vault files added or moved since this
    /// object was created, such as by a pairing import or the move to
    /// `unreadable/` on new hardware. Reads only the file headers. Does not
    /// require authentication.
    pub fn rescan_vaults(&self) -> Result<(), FfiError> {
        self.manager
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .rescan();
        Ok(())
    }

    /// List all known vaults. Does not require authentication.
    pub fn list_vaults(&self) -> Result<Vec<VaultInfo>, FfiError> {
        let manager = self.manager.lock().map_err(|_| FfiError::Poisoned)?;
        let mut vaults: Vec<VaultInfo> = manager
            .iter_vaults()
            .map(|(key, vw)| VaultInfo {
                key: key.clone(),
                name: vw.vault_name().map(|s| s.to_string()),
                id: vw.peek_vault_id().ok().map(ShortId::encode_uuid),
            })
            .collect();
        vaults.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(vaults)
    }

    /// Keys of the vaults left out of AutoFill suggestions on this device.
    /// Their logins are still listed for manual selection. Does not require
    /// authentication.
    pub fn list_autofill_excluded_vaults(&self) -> Vec<String> {
        autofill_excluded_vaults().into_iter().collect()
    }

    /// Leave the vault `vault_key` out of AutoFill suggestions on this device,
    /// or include it again. The system AutoFill index changes on the next
    /// `list_autofill_items` and `list_passkey_identities`.
    pub fn set_vault_autofill_excluded(
        &self,
        vault_key: String,
        excluded: bool,
    ) -> Result<(), FfiError> {
        APP_CONFIG
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .set_autofill_excluded(&vault_key, excluded)
            .map_err(|e| FfiError::Internal(e.to_string()))
    }

    /// List vault ids held by more than one file. None of these files is in
    /// `list_vaults`. Does not require authentication.
    pub fn list_duplicate_vaults(&self) -> Result<Vec<DuplicateVaultInfo>, FfiError> {
        let manager = self.manager.lock().map_err(|_| FfiError::Poisoned)?;
        Ok(manager
            .duplicates()
            .iter()
            .map(|duplicate| DuplicateVaultInfo {
                vault_id: ShortId::encode_uuid(duplicate.id),
                paths: duplicate
                    .paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            })
            .collect())
    }

    /// List vault keys claimed by more than one file. None of these files is
    /// in `list_vaults`. A file can also be in `list_duplicate_vaults`. Does
    /// not require authentication.
    pub fn list_duplicate_vault_keys(&self) -> Result<Vec<DuplicateVaultKeyInfo>, FfiError> {
        let manager = self.manager.lock().map_err(|_| FfiError::Poisoned)?;
        Ok(manager
            .duplicate_keys()
            .iter()
            .map(|duplicate| DuplicateVaultKeyInfo {
                key: duplicate.key.clone(),
                paths: duplicate
                    .paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
            })
            .collect())
    }

    /// List items for a vault. Decrypts the vault from disk using the shared
    /// LAContext, without prompting. Fails with `AuthExpired` if the app is
    /// locked.
    pub async fn list_items(&self, vault_key: String) -> Result<Vec<ItemInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let catalog = m.store().clone();
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;

            let signals = vault.passkey_signals().map_err(FfiError::from)?;
            let items = vault.list_items().map_err(FfiError::from)?;
            let mut result: Vec<ItemInfo> = items
                .into_iter()
                .map(|item| {
                    let (sections, credential_order) = item_display_order(item);
                    let mut credentials: Vec<_> = item.credentials.values().collect();
                    credentials.sort_by(|a, b| credential_order(a, b));

                    let roles = &item.autofill;
                    let role_of = |id| {
                        if roles.password_credential(item).map(|c| c.id) == Some(id) {
                            Some("password")
                        } else if roles.username_credential(item).map(|c| c.id) == Some(id) {
                            Some("username")
                        } else if roles.totp_credential(item).map(|c| c.id) == Some(id) {
                            Some("totp")
                        } else {
                            None
                        }
                    };
                    let credentials: Vec<CredentialInfo> = credentials
                        .into_iter()
                        .map(|c| {
                            let role = role_of(c.id);
                            let mut kind = FieldKindInfo::from(&c.kind);
                            if role == Some("password") {
                                kind.concealed = true;
                            }
                            let passkey = matches!(c.kind, FieldKind::Passkey)
                                .then(|| vault.get_secret(&item.key, &c.key).ok().flatten())
                                .flatten()
                                .and_then(|value| passkey::summary(value.expose_secret()))
                                .map(|s| passkey_info(s, &signals));
                            let file = matches!(c.kind, FieldKind::File)
                                .then(|| vault.get_secret(&item.key, &c.key).ok().flatten())
                                .flatten()
                                .and_then(|value| {
                                    FileInfo::of_value(
                                        catalog.files(),
                                        vault,
                                        value.expose_secret(),
                                    )
                                });
                            CredentialInfo {
                                id: ShortId::encode_uuid(c.id),
                                key: c.key.clone(),
                                title: c.title.clone(),
                                kind,
                                position: c.position,
                                section_id: c.section.map(ShortId::encode_uuid),
                                role: role.map(str::to_string),
                                last_used_day_at: c.last_used_day_at,
                                created_at: c.created_at,
                                passkey,
                                file,
                            }
                        })
                        .collect();
                    let username = roles
                        .username_credential(item)
                        .and_then(|cred| vault.get_secret(&item.key, &cred.key).ok().flatten())
                        .map(|secret| secret.expose_secret().clone())
                        .filter(|value| !value.trim().is_empty());
                    let can_convert_to_login = autofill::suggest_conversion(vault, item)
                        .ok()
                        .flatten()
                        .is_some();
                    ItemInfo {
                        id: ShortId::encode_uuid(item.id),
                        key: item.key.clone(),
                        title: item.title.clone(),
                        folder_id: item.folder.map(ShortId::encode_uuid),
                        sections: sections.into_iter().map(SectionInfo::from).collect(),
                        credentials,
                        category: item.category.clone(),
                        username,
                        websites: roles.websites.iter().map(WebsiteInfo::from).collect(),
                        can_convert_to_login,
                        password_role_broken: roles.password.is_some()
                            && roles.password_credential(item).is_none(),
                    }
                })
                .collect();
            result.sort_by(|a, b| a.title.cmp(&b.title));
            Ok(result)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// List a vault's folders in display order. Unlocks the vault the same
    /// way as `list_items`.
    pub async fn list_folders(&self, vault_key: String) -> Result<Vec<FolderInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;

            let mut folders = vault.list_folders().map_err(FfiError::from)?;
            folders.sort_by(|a, b| {
                display_order(a.position, &a.title).cmp(&display_order(b.position, &b.title))
            });
            Ok(folders.into_iter().map(FolderInfo::from).collect())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// List every fillable item across every vault, for registering AutoFill
    /// identities with the system. Requires the app to be unlocked; a vault
    /// that fails to unlock is skipped rather than failing the listing.
    ///
    /// Only the username and URLs are read. The password stays in the vault
    /// until the extension asks for it by name.
    ///
    /// The result also replaces the broker's login index, which answers the
    /// listings that need no prompt.
    pub async fn list_autofill_items(&self) -> Result<Vec<AutofillItemInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        let index = Arc::clone(&self.login_index);
        tokio::task::spawn_blocking(move || {
            let vault_keys = unlock_every_vault(&manager, "autofill")?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let mut found_items = Vec::new();
            let mut places = Vec::new();
            let mut ssh_keys = Vec::new();
            for vault_key in vault_keys {
                let Some(vault) = m.get_vault_mut(&vault_key) else {
                    continue;
                };
                ssh_keys.push((
                    vault_key.clone(),
                    ssh_vault_keys::collect(&vault_key, vault),
                ));
                match autofill::collect_items(vault, None) {
                    Ok(found) => found_items.extend(found),
                    Err(e) => log::error!("Failed to collect autofill items in {vault_key}: {e}"),
                }
                match autofill::collect_places(vault) {
                    Ok(found) => places.extend(found),
                    Err(e) => log::error!("Failed to collect login items in {vault_key}: {e}"),
                }
            }
            index.replace(found_items.clone());
            index.replace_places(places);
            let excluded = autofill_excluded_vaults();
            found_items.retain(|item| !excluded.contains(&item.vault_key));
            let known: Vec<String> = m.iter_vault_keys().collect();
            match ssh_vault_keys::refresh(&vault_keys_path(), &known, ssh_keys) {
                Ok(entries) => sweep_ssh_pubkey_files(&entries),
                Err(e) => log::error!("Failed to write the vault SSH key listing: {e}"),
            }
            Ok(found_items
                .into_iter()
                .map(AutofillItemInfo::from)
                .collect())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// List every stored passkey across every vault, for registering
    /// `ASPasskeyCredentialIdentity` entries with the system. Requires the app
    /// to be unlocked; a vault that fails to unlock is skipped. Passkeys a
    /// site reported it no longer accepts are left out.
    ///
    /// Only the metadata the identity store needs is read. The private key
    /// stays in the vault until the extension asks for an assertion.
    ///
    /// The result also replaces the passkeys of the broker's login index, which
    /// answers the extension's account list.
    pub async fn list_passkey_identities(&self) -> Result<Vec<PasskeyIdentityInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        let index = Arc::clone(&self.login_index);
        tokio::task::spawn_blocking(move || {
            let vault_keys = unlock_every_vault(&manager, "passkeys")?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let mut identities = Vec::new();
            let excluded = autofill_excluded_vaults();
            for vault_key in vault_keys {
                if excluded.contains(&vault_key) {
                    continue;
                }
                let Some(vault) = m.get_vault_mut(&vault_key) else {
                    continue;
                };
                let signals = vault.passkey_signals().unwrap_or_default();
                match passkey::list(vault) {
                    Ok(found) => identities.extend(
                        found.into_iter().filter(|s| !signals.rejects(s)).map(|s| {
                            PasskeyIdentityInfo {
                                vault_key: vault_key.clone(),
                                record_id: s.record_id(),
                                item_key: s.item_key,
                                credential_key: s.credential_key,
                                rp_id: s.passkey.rp_id,
                                credential_id: s.passkey.credential_id.as_slice().to_vec(),
                                user_name: s.passkey.username.unwrap_or_default(),
                                user_handle: s
                                    .passkey
                                    .user_handle
                                    .map(|h| h.as_slice().to_vec())
                                    .unwrap_or_default(),
                            }
                        }),
                    ),
                    Err(e) => log::error!("Failed to list passkeys in {vault_key}: {e}"),
                }
            }
            index.replace_passkeys(
                identities
                    .iter()
                    .map(|i| IndexedPasskey {
                        rp_id: i.rp_id.clone(),
                        credential_id: i.credential_id.clone(),
                        user_name: i.user_name.clone(),
                    })
                    .collect(),
            );
            Ok(identities)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Retrieve a credential secret as raw bytes.
    ///
    /// Swift callers should immediately wrap the returned `Data` in a
    /// `CryptoKit.SymmetricKey` and zero the `Data` buffer:
    ///
    ///   var raw = try await axoPass.getCredentialSecret(...)
    ///   let key = SymmetricKey(data: raw)
    ///   raw.resetBytes(in: raw.indices)
    pub async fn get_credential_secret(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<Vec<u8>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            refuse_file(vault, &item_key, &cred_key)?;
            match vault
                .get_secret(&item_key, &cred_key)
                .map_err(FfiError::from)?
            {
                Some(secret) => Ok(secret.expose_secret().as_bytes().to_vec()),
                None => Err(FfiError::NotFound(format!(
                    "{vault_key}/{item_key}/{cred_key}"
                ))),
            }
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// List the previous values of a credential, most recently replaced first.
    pub async fn list_credential_history(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<Vec<HistoryEntryInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;

            let history = vault
                .list_history(&item_key, &cred_key)
                .map_err(FfiError::from)?;
            Ok(history
                .into_iter()
                .map(|h| HistoryEntryInfo {
                    id: ShortId::encode_uuid(h.id),
                    replaced_at: h.at,
                })
                .collect())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// List the history of an item, newest first.
    pub async fn list_item_history(
        &self,
        vault_key: String,
        item_key: String,
    ) -> Result<Vec<ItemHistoryEventInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;

            let events = vault.item_history(&item_key).map_err(FfiError::from)?;
            Ok(events.into_iter().map(ItemHistoryEventInfo::from).collect())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Retrieve a previous value of a credential as raw bytes (same zeroing
    /// convention as `get_credential_secret`).
    pub async fn get_credential_history_value(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        history_id: String,
    ) -> Result<Vec<u8>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            refuse_file(vault, &item_key, &cred_key)?;
            let secret = vault
                .get_history_value(&item_key, &cred_key, parse_id(&history_id)?)
                .map_err(FfiError::from)?;
            Ok(secret.expose_secret().as_bytes().to_vec())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Make a previous value the current value. The value it replaces is added
    /// to the history.
    pub async fn restore_credential_history_value(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        history_id: String,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let id = history_id.clone();
        let ids = self
            .edit_vault(vault_key.clone(), move |vw| {
                vw.restore_history_value(&item_key, &cred_key, parse_id(&history_id)?)?;
                Ok(vw.credential_ids(&item_key, &cred_key)?)
            })
            .await?;
        change_event(
            audit::Action::CredentialHistoryRestored,
            &vault_key,
            subject,
            ids,
        )
        .detail("history_id", id)
        .record_async()
        .await;
        Ok(())
    }

    /// Delete a previous value of a credential permanently.
    pub async fn purge_credential_history(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        history_id: String,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let id = history_id.clone();
        let ids = self
            .edit_vault(vault_key.clone(), move |vw| {
                vw.purge_history(&item_key, &cred_key, parse_id(&history_id)?)?;
                Ok(vw.credential_ids(&item_key, &cred_key)?)
            })
            .await?;
        change_event(
            audit::Action::CredentialHistoryPurged,
            &vault_key,
            subject,
            ids,
        )
        .detail("history_id", id)
        .record_async()
        .await;
        Ok(())
    }

    /// Retrieve a credential secret's decrypted title as raw bytes (same
    /// zeroing convention as `get_credential_secret`). `None` if not found.
    pub async fn get_decrypted_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<Option<Vec<u8>>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            refuse_file(vault, &item_key, &cred_key)?;
            match vault
                .get_secret(&item_key, &cred_key)
                .map_err(FfiError::from)?
            {
                Some(secret) => Ok(Some(secret.expose_secret().as_bytes().to_vec())),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Create a new vault. Mirrors `add_vault` in the Tauri app.
    pub async fn add_vault(
        &self,
        name: Option<String>,
        vault_key: String,
    ) -> Result<VaultInfo, FfiError> {
        let manager = Arc::clone(&self.manager);
        let info = tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vw = m.add_vault(name, &vault_key).map_err(FfiError::from)?;
            let vault_id = vw.vault_id()?;
            let info = VaultInfo {
                key: vw.key.clone(),
                name: vw.vault_name().map(|s| s.to_string()),
                id: Some(ShortId::encode_uuid(vault_id)),
            };
            Ok::<_, FfiError>((info, audit::SubjectIds::vault(vault_id)))
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        let (info, ids) = info;
        change_event(
            audit::Action::VaultCreated,
            &info.key,
            vault_subject(&info.key).maybe_label(info.name.clone()),
            ids,
        )
        .record_async()
        .await;
        Ok(info)
    }

    /// Rename a vault and/or change its key, in one transaction that saves
    /// once. Mirrors `update_vault` in the Tauri app. The new key is
    /// normalized, and refused if another vault file claims it. The file name
    /// is unchanged.
    pub async fn update_vault(
        &self,
        vault_key: String,
        new_vault_key: Option<String>,
        new_name: Option<String>,
    ) -> Result<(), FfiError> {
        let store = self.store()?;
        let (renamed, rekeyed, ids) = self
            .edit_vault(vault_key.clone(), move |vw| {
                let mut renamed = None;
                if new_name.as_deref() != vw.vault_name()
                    && let Some(new_name) = new_name
                {
                    vw.set_vault_name(new_name.clone())?;
                    renamed = Some(new_name);
                }

                let mut rekeyed = None;
                if let Some(new_vault_key) = new_vault_key {
                    let new_vault_key = store.unclaimed_key(&new_vault_key, Some(&vw.path))?;
                    if new_vault_key != vw.key {
                        vw.set_vault_key(new_vault_key.clone())?;
                        rekeyed = Some(new_vault_key);
                    }
                }

                Ok((renamed, rekeyed, audit::SubjectIds::vault(vw.vault_id()?)))
            })
            .await?;

        if renamed.is_some() || rekeyed.is_some() {
            change_event(
                audit::Action::VaultUpdated,
                &vault_key,
                vault_subject(&vault_key),
                ids,
            )
            .maybe_detail("new_name", renamed)
            .maybe_detail("new_key", rekeyed)
            .record_async()
            .await;
        }
        Ok(())
    }

    /// Retained versions of a vault, newest first.
    pub async fn list_vault_versions(
        &self,
        vault_key: String,
    ) -> Result<Vec<RetainedVersionInfo>, FfiError> {
        let store = self.store()?;
        let versions = tokio::task::spawn_blocking(move || store.list_versions(&vault_key))
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))??;
        Ok(versions
            .into_iter()
            .map(|v| RetainedVersionInfo {
                saved_at: i64::try_from(v.saved_at_ms / 1000).unwrap_or(i64::MAX),
                name: v.name,
            })
            .collect())
    }

    /// Replace a vault with its retained version `name`. The replaced vault is
    /// retained in turn, so the restore can be undone. Records
    /// `vault.version_restored`.
    pub async fn restore_vault_version(
        &self,
        vault_key: String,
        name: String,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        let version = name.clone();
        let (key, vault_name, vault_id) = tokio::task::spawn_blocking(move || {
            VaultsManager::restore_version(&manager, &vault_key, &version)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        change_event(
            audit::Action::VaultVersionRestored,
            &key,
            vault_subject(&key).maybe_label(vault_name),
            audit::SubjectIds::vault(vault_id),
        )
        .detail("version", name)
        .record_async()
        .await;
        Ok(())
    }

    /// Replace a vault file that fails to load with its retained version
    /// `name`, as `restore_vault_version` does for a vault that loads. A
    /// synced vault records the differences as edits on every Mac (D16).
    /// Needs the app unlocked. Records `vault.version_restored`.
    pub async fn restore_refused_vault_version(
        &self,
        vault_key: String,
        name: String,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        let version = name.clone();
        let (key, vault_name, vault_id) = tokio::task::spawn_blocking(move || {
            VaultsManager::restore_refused(&manager, &vault_key, &version)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        change_event(
            audit::Action::VaultVersionRestored,
            &key,
            vault_subject(&key).maybe_label(vault_name),
            audit::SubjectIds::vault(vault_id),
        )
        .detail("version", name)
        .detail("refused", "true")
        .record_async()
        .await;
        Ok(())
    }

    /// Delete every retained version of a vault. The vault itself is
    /// unchanged. Records `vault.versions_erased`. Returns the number of
    /// versions deleted.
    pub async fn erase_vault_versions(&self, vault_key: String) -> Result<u32, FfiError> {
        let store = self.store()?;
        let key = vault_key.clone();
        let (vault_id, count) = tokio::task::spawn_blocking(move || store.erase_versions(&key))
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))??;
        change_event(
            audit::Action::VaultVersionsErased,
            &vault_key,
            vault_subject(&vault_key),
            audit::SubjectIds::vault(vault_id),
        )
        .detail("version_count", count.to_string())
        .record_async()
        .await;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// Delete a vault (moved to Trash, not permanently deleted). Mirrors
    /// `delete_vault` in the Tauri app.
    ///
    /// A synced vault is disabled first, which needs the app unlocked, and
    /// is deleted on this Mac only. A final file that waits for the synced
    /// folder is copied by the sync manager.
    pub async fn delete_vault(&self, vault_key: String) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        let key = vault_key.clone();
        let (name, vault_id) = tokio::task::spawn_blocking(move || {
            let (name, vault_id) = {
                let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
                let vw = m.get_or_create_vault_mut(&vault_key)?;
                (vw.vault_name().map(str::to_string), vw.peek_vault_id()?)
            };
            VaultsManager::delete_vault(&manager, &vault_key)?;
            Ok::<_, FfiError>((name, vault_id))
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        AxoPass::refresh_sync();
        change_event(
            audit::Action::VaultDeleted,
            &key,
            vault_subject(&key).maybe_label(name),
            audit::SubjectIds::vault(vault_id),
        )
        .record_async()
        .await;
        Ok(())
    }

    /// Create or rename an item within a vault.
    pub async fn add_or_update_item(
        &self,
        vault_key: String,
        item_key: String,
        item_title: String,
    ) -> Result<(), FfiError> {
        let subject = item_subject(&vault_key, &item_key).label(item_title.clone());
        let (key, title) = (vault_key.clone(), item_title.clone());
        let (previous_title, ids) = self
            .edit_vault(vault_key, move |vw| {
                let previous_title = vw.get_item_overview(&item_key)?.map(|i| i.title.clone());
                vw.add_item(&item_key, &item_title)?;
                Ok((previous_title, vw.item_ids(&item_key)?))
            })
            .await?;
        let event = match previous_title {
            None => change_event(audit::Action::ItemCreated, &key, subject, ids),
            Some(previous) if previous != title => {
                change_event(audit::Action::ItemUpdated, &key, subject, ids)
                    .detail("changed", "title")
            },
            Some(_) => return Ok(()),
        };
        event.record_async().await;
        Ok(())
    }

    /// Move an item to another vault with its credentials and previous values.
    /// The item keeps its key unless `dest_item_key` is given. It is unfiled in
    /// the destination. The item is purged from the source, not left in its
    /// deleted items. The destination is written first and then the source in
    /// separate transactions, so a failure between the two leaves the item in
    /// both vaults. Fails if the destination has an item with the key.
    pub async fn move_item_to_vault(
        &self,
        vault_key: String,
        item_key: String,
        dest_vault_key: String,
        dest_item_key: Option<String>,
    ) -> Result<(), FfiError> {
        if vault_key == dest_vault_key {
            return Err(FfiError::Internal(
                "the item is already in this vault".to_string(),
            ));
        }
        let manager = Arc::clone(&self.manager);
        let (source_key, source_item) = (vault_key.clone(), item_key.clone());
        let dest_key = dest_vault_key.clone();
        let (title, source_ids, dest_ids, dest_final_key, removed) =
            tokio::task::spawn_blocking(move || {
                // Plaintext values are held only between the two transactions.
                let (transfer, title, source_ids) =
                    VaultsManager::write_vault(&manager, &vault_key, |vw| {
                        let title = vw.get_item_overview(&item_key)?.map(|i| i.title.clone());
                        let ids = vw.item_ids(&item_key)?;
                        Ok::<_, FfiError>((vw.export_item(&item_key)?, title, ids))
                    })?;
                let item_id = transfer.item_id();
                let (final_key, dest_ids) =
                    VaultsManager::write_vault(&manager, &dest_vault_key, |vw| {
                        let key = vw
                            .import_item(transfer, dest_item_key.as_deref())?
                            .key
                            .clone();
                        let ids = vw.item_ids(&key)?;
                        Ok::<_, FfiError>((key, ids))
                    })?;
                let removed = VaultsManager::write_vault(&manager, &vault_key, |vw| {
                    vw.delete_item(&item_key)?;
                    vw.purge_item(item_id)?;
                    Ok::<_, FfiError>(())
                });
                Ok::<_, FfiError>((title, source_ids, dest_ids, final_key, removed))
            })
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))??;
        let mut event = change_event(
            audit::Action::ItemMoved,
            &source_key,
            item_subject(&source_key, &source_item).maybe_label(title),
            source_ids,
        )
        .detail("dest_vault", dest_key)
        .detail("dest_item", dest_final_key)
        .maybe_detail("dest_vault_id", dest_ids.vault_id.map(ShortId::encode_uuid));
        // The destination holds the item even if removing the source failed,
        // so that is recorded as a failed move.
        if let Err(e) = &removed {
            event.outcome = audit::Outcome::Failed;
            event = event
                .detail("source_removed", "false")
                .message(e.to_string());
        }
        event.record_async().await;
        removed
    }

    /// Change the key of an item. Fails if another item has the key.
    pub async fn change_item_key(
        &self,
        vault_key: String,
        item_key: String,
        new_key: String,
    ) -> Result<(), FfiError> {
        let key = vault_key.clone();
        let (title, new_key, ids) = self
            .edit_vault(vault_key, move |vw| {
                let item = vw.change_item_key(&item_key, &new_key)?;
                let (title, new_key) = (item.title.clone(), item.key.clone());
                Ok((title, new_key.clone(), vw.item_ids(&new_key)?))
            })
            .await?;
        change_event(
            audit::Action::ItemUpdated,
            &key,
            item_subject(&key, &new_key).label(title),
            ids,
        )
        .detail("changed", "key")
        .record_async()
        .await;
        Ok(())
    }

    /// List a vault's deleted items, most recently deleted first.
    pub async fn list_deleted_items(
        &self,
        vault_key: String,
    ) -> Result<Vec<DeletedItemInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let catalog = m.store().clone();
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;

            let deleted = vault.list_deleted_items().map_err(FfiError::from)?;
            Ok(deleted
                .into_iter()
                .map(|d| {
                    let (_, credential_order) = item_display_order(d.item);
                    let mut credentials: Vec<_> = d
                        .item
                        .credentials
                        .values()
                        .map(|c| (c, false))
                        .chain(d.deleted_credentials.iter().map(|c| (*c, true)))
                        .collect();
                    credentials.sort_by(|(a, _), (b, _)| credential_order(a, b));
                    let credentials = credentials
                        .into_iter()
                        .map(|(c, deleted_before_item)| DeletedItemCredentialInfo {
                            id: ShortId::encode_uuid(c.id),
                            key: c.key.clone(),
                            title: c.title.clone(),
                            kind: FieldKindInfo::from(&c.kind),
                            deleted_before_item,
                            file: deleted_file_info(
                                catalog.files(),
                                vault,
                                d.item.id,
                                c.id,
                                &c.kind,
                            ),
                        })
                        .collect();
                    DeletedItemInfo {
                        id: ShortId::encode_uuid(d.item.id),
                        key: d.item.key.clone(),
                        title: d.item.title.clone(),
                        credentials,
                        deleted_at: d.deleted_at,
                    }
                })
                .collect())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Restore a deleted item with its credentials, deleted credentials,
    /// sections, and folder. A folder that no longer exists is dropped. The
    /// item gets `new_key` if given. Fails with `InvalidInput` if the
    /// resulting key is taken.
    pub async fn restore_item(
        &self,
        vault_key: String,
        item_id: String,
        new_key: Option<String>,
    ) -> Result<(), FfiError> {
        let id = item_id.clone();
        let (restored, ids) = self
            .edit_vault(vault_key.clone(), move |vw| {
                let id = parse_id(&item_id)?;
                vw.restore_item(id, new_key)?;
                let restored = vw
                    .get_item_overview_by_id(id)?
                    .map(|i| (i.key.clone(), i.title.clone()));
                Ok((restored, audit::SubjectIds::item(vw.vault_id()?, id)))
            })
            .await?;
        change_event(
            audit::Action::ItemRestored,
            &vault_key,
            item_subject_by_id(&vault_key, &id, restored),
            ids,
        )
        .record_async()
        .await;
        Ok(())
    }

    /// Delete a deleted item permanently, with its credentials.
    pub async fn purge_item(&self, vault_key: String, item_id: String) -> Result<(), FfiError> {
        let id = item_id.clone();
        let (purged, ids) = self
            .edit_vault(vault_key.clone(), move |vw| {
                let id = parse_id(&item_id)?;
                let purged = vw
                    .list_deleted_items()?
                    .into_iter()
                    .find(|d| d.item.id == id)
                    .map(|d| (d.item.key.clone(), d.item.title.clone()));
                vw.purge_item(id)?;
                Ok((purged, audit::SubjectIds::item(vw.vault_id()?, id)))
            })
            .await?;
        change_event(
            audit::Action::ItemPurged,
            &vault_key,
            item_subject_by_id(&vault_key, &id, purged),
            ids,
        )
        .record_async()
        .await;
        Ok(())
    }

    /// Delete an item (and all its credentials) from a vault. It stays
    /// recoverable with `restore_item` until purged.
    pub async fn delete_item(&self, vault_key: String, item_key: String) -> Result<(), FfiError> {
        let subject = item_subject(&vault_key, &item_key);
        let (title, ids) = self
            .edit_vault(vault_key.clone(), move |vw| {
                let title = vw.get_item_overview(&item_key)?.map(|i| i.title.clone());
                let ids = vw.item_ids(&item_key)?;
                vw.delete_item(&item_key)?;
                Ok((title, ids))
            })
            .await?;
        change_event(
            audit::Action::ItemDeleted,
            &vault_key,
            subject.maybe_label(title),
            ids,
        )
        .record_async()
        .await;
        sync_ssh_key_listing(Arc::clone(&self.manager), vault_key).await;
        Ok(())
    }

    /// Create a credential within an item. Fails if the key is already taken.
    pub async fn add_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        title: String,
        value: String,
        kind: Option<FieldKindInfo>,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key).label(title.clone());
        let key = vault_key.clone();
        let ids = self
            .edit_vault(vault_key, move |vw| {
                let kind = match kind {
                    Some(info) => FieldKind::try_from(info)?,
                    None => FieldKind::default(),
                };
                vw.add_new_secret(
                    &item_key,
                    &cred_key,
                    &title,
                    kind,
                    SecretString::from(value),
                )?;
                Ok(vw.credential_ids(&item_key, &cred_key)?)
            })
            .await?;
        change_event(audit::Action::CredentialCreated, &key, subject, ids)
            .record_async()
            .await;
        Ok(())
    }

    /// Create or update a credential's title/value within an item.
    pub async fn add_or_update_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        title: String,
        value: String,
        kind: Option<FieldKindInfo>,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key).label(title.clone());
        let key = vault_key.clone();
        let (changed, ids) = self
            .edit_vault(vault_key, move |vw| {
                refuse_file(vw, &item_key, &cred_key)?;
                let previous = vw
                    .get_secret_overview(&item_key, &cred_key)?
                    .map(|o| (o.title.clone(), o.kind.clone()));
                // `None` keeps an existing credential's kind, so an edit that
                // only touches the title or value does not reset it. A new
                // credential with no kind given falls back to the default.
                let kind = match kind {
                    Some(info) => FieldKind::try_from(info)?,
                    None => previous
                        .as_ref()
                        .map(|(_, kind)| kind.clone())
                        .unwrap_or_default(),
                };
                // Changed fields of an existing credential. The value is
                // always written, so it is always listed.
                let changed = previous.map(|(previous_title, previous_kind)| {
                    let mut changed = vec!["value"];
                    if previous_title != title {
                        changed.push("title");
                    }
                    if previous_kind != kind {
                        changed.push("kind");
                    }
                    changed.join(",")
                });
                vw.add_secret(
                    &item_key,
                    &cred_key,
                    &title,
                    kind,
                    SecretString::from(value),
                )?;
                Ok((changed, vw.credential_ids(&item_key, &cred_key)?))
            })
            .await?;
        let event = match changed {
            None => change_event(audit::Action::CredentialCreated, &key, subject, ids),
            Some(changed) => change_event(audit::Action::CredentialUpdated, &key, subject, ids)
                .detail("changed", changed),
        };
        event.record_async().await;
        Ok(())
    }

    /// Change the key, title, or kind of a credential without resubmitting its
    /// value. `None` arguments are left unchanged.
    pub async fn update_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        new_key: Option<String>,
        title: Option<String>,
        kind: Option<FieldKindInfo>,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let changed = [
            new_key.as_ref().map(|_| "key"),
            title.as_ref().map(|_| "title"),
            kind.as_ref().map(|_| "kind"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(",");
        let renamed_to = new_key.clone();
        let ids = self
            .edit_vault(vault_key.clone(), move |vw| {
                let ids = vw.credential_ids(&item_key, &cred_key)?;
                let update = CredentialUpdate {
                    key: new_key,
                    title,
                    kind: kind.map(FieldKind::try_from).transpose()?,
                };
                vw.update_credential(&item_key, &cred_key, update)?;
                Ok(ids)
            })
            .await?;
        if !changed.is_empty() {
            change_event(audit::Action::CredentialUpdated, &vault_key, subject, ids)
                .detail("changed", changed)
                .maybe_detail("new_key", renamed_to)
                .record_async()
                .await;
        }
        Ok(())
    }

    /// List the deleted credentials of a vault's live items, most recently
    /// deleted first. Credentials of deleted items are listed with the item
    /// by `list_deleted_items`.
    pub async fn list_deleted_credentials(
        &self,
        vault_key: String,
    ) -> Result<Vec<DeletedCredentialInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let catalog = m.store().clone();
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;

            let deleted = vault.list_all_deleted().map_err(FfiError::from)?;
            Ok(deleted
                .into_iter()
                .map(|d| DeletedCredentialInfo {
                    id: ShortId::encode_uuid(d.credential.credential.id),
                    key: d.credential.credential.key.clone(),
                    title: d.credential.credential.title.clone(),
                    kind: FieldKindInfo::from(&d.credential.credential.kind),
                    item_id: ShortId::encode_uuid(d.item.id),
                    item_key: d.item.key.clone(),
                    item_title: d.item.title.clone(),
                    deleted_at: d.credential.deleted_at,
                    file: deleted_file_info(
                        catalog.files(),
                        vault,
                        d.item.id,
                        d.credential.credential.id,
                        &d.credential.credential.kind,
                    ),
                })
                .collect())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Retrieve the secret of a deleted credential, or of a credential in a
    /// deleted item, as raw bytes (same zeroing convention as
    /// `get_credential_secret`).
    pub async fn get_deleted_credential_secret(
        &self,
        vault_key: String,
        item_id: String,
        cred_id: String,
    ) -> Result<Vec<u8>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            let (item_id, cred_id) = (parse_id(&item_id)?, parse_id(&cred_id)?);
            refuse_deleted_file(vault, item_id, cred_id)?;
            let secret = vault
                .get_deleted_secret(item_id, cred_id)
                .map_err(FfiError::from)?;
            Ok(secret.expose_secret().as_bytes().to_vec())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Restore a deleted credential with its value, position, and section. A
    /// section that no longer exists is dropped. The credential gets `new_key`
    /// if given. Fails with `InvalidInput` if the resulting key is taken.
    pub async fn restore_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_id: String,
        new_key: Option<String>,
    ) -> Result<(), FfiError> {
        let (item, id) = (item_key.clone(), cred_id.clone());
        let (restored, ids) = self
            .edit_vault(vault_key.clone(), move |vw| {
                let id = parse_id(&cred_id)?;
                vw.restore_item_credential(&item_key, id, new_key)?;
                let restored = vw.get_item_overview(&item_key)?.and_then(|i| {
                    i.credentials
                        .values()
                        .find(|c| c.id == id)
                        .map(|c| (c.key.clone(), c.title.clone()))
                });
                let ids = audit::SubjectIds {
                    credential_id: Some(id),
                    ..vw.item_ids(&item_key)?
                };
                Ok((restored, ids))
            })
            .await?;
        change_event(
            audit::Action::CredentialRestored,
            &vault_key,
            credential_subject_by_id(&vault_key, &item, &id, restored),
            ids,
        )
        .record_async()
        .await;
        Ok(())
    }

    /// Delete a deleted credential permanently.
    pub async fn purge_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_id: String,
    ) -> Result<(), FfiError> {
        let (item, id) = (item_key.clone(), cred_id.clone());
        let (purged, ids) = self
            .edit_vault(vault_key.clone(), move |vw| {
                let id = parse_id(&cred_id)?;
                let purged = vw
                    .list_all_deleted()?
                    .into_iter()
                    .find(|d| d.item.key == item_key && d.credential.credential.id == id)
                    .map(|d| {
                        (
                            d.credential.credential.key.clone(),
                            d.credential.credential.title.clone(),
                        )
                    });
                vw.purge_item_credential(&item_key, id)?;
                let ids = audit::SubjectIds {
                    credential_id: Some(id),
                    ..vw.item_ids(&item_key)?
                };
                Ok((purged, ids))
            })
            .await?;
        change_event(
            audit::Action::CredentialPurged,
            &vault_key,
            credential_subject_by_id(&vault_key, &item, &id, purged),
            ids,
        )
        .record_async()
        .await;
        Ok(())
    }

    /// Delete a single credential from an item. It stays recoverable with
    /// `restore_credential` until purged.
    pub async fn delete_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let key = vault_key.clone();
        let (title, ids) = self
            .edit_vault(vault_key, move |vw| {
                let title = vw
                    .get_secret_overview(&item_key, &cred_key)?
                    .map(|o| o.title.clone());
                let ids = vw.credential_ids(&item_key, &cred_key)?;
                vw.delete_item_credential(&item_key, &cred_key)?;
                Ok((title, ids))
            })
            .await?;
        change_event(
            audit::Action::CredentialDeleted,
            &key,
            subject.maybe_label(title),
            ids,
        )
        .record_async()
        .await;
        sync_ssh_key_listing(Arc::clone(&self.manager), key).await;
        Ok(())
    }

    /// Create a login from a website, an optional username, and a password.
    /// The item key and title come from the website unless given, and a taken
    /// key gets a numeric suffix. Returns the item's key.
    pub async fn create_login(
        &self,
        vault_key: String,
        website: String,
        username: Option<String>,
        password: String,
        item_key: Option<String>,
        title: Option<String>,
    ) -> Result<String, FfiError> {
        let key = vault_key.clone();
        let (created_key, ids) = self
            .edit_vault(vault_key, move |vw| {
                let created_key = autofill::create_login(
                    vw,
                    &website,
                    username.as_deref(),
                    SecretString::from(password),
                    item_key.as_deref(),
                    title.as_deref(),
                )?;
                let ids = vw.item_ids(&created_key)?;
                Ok((created_key, ids))
            })
            .await?;
        change_event(
            audit::Action::ItemCreated,
            &key,
            item_subject(&key, &created_key),
            ids,
        )
        .detail("login", "true")
        .record_async()
        .await;
        Ok(created_key)
    }

    /// The current one-time code of a `totp` credential.
    pub async fn current_totp_code(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<TotpCodeInfo, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            let secret = vault
                .get_secret(&item_key, &cred_key)
                .map_err(FfiError::from)?
                .ok_or_else(|| FfiError::NotFound(format!("{vault_key}/{item_key}/{cred_key}")))?;
            let code =
                totp::current_code(secret.expose_secret()).map_err(FfiError::InvalidInput)?;
            Ok(TotpCodeInfo {
                code: code.code,
                seconds_remaining: code.seconds_remaining,
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Generate a random password.
    pub fn generate_password(&self, length: u32, symbols: bool) -> Result<String, FfiError> {
        let policy = PasswordPolicy {
            length: length as usize,
            symbols,
            ..PasswordPolicy::default()
        };
        policy
            .generate()
            .map(|password| password.expose_secret().to_string())
            .map_err(|e| FfiError::InvalidInput(e.to_string()))
    }

    /// Assign a role ("username", "password", or "totp") to a credential, or
    /// clear the role when `cred_key` is `None`. A credential has one role.
    pub async fn set_credential_role(
        &self,
        vault_key: String,
        item_key: String,
        role: String,
        cred_key: Option<String>,
    ) -> Result<(), FfiError> {
        let role_name = role.clone();
        let role = parse_role(&role)?;
        // A cleared role names the item. A set role names the credential.
        let subject = match &cred_key {
            Some(cred_key) => credential_subject(&vault_key, &item_key, cred_key),
            None => item_subject(&vault_key, &item_key),
        };
        let cleared = cred_key.is_none();
        let key = vault_key.clone();
        let ids = self
            .edit_vault(vault_key, move |vw| {
                autofill::set_role(vw, &item_key, role, cred_key.as_deref())?;
                Ok(match &cred_key {
                    Some(cred_key) => vw.credential_ids(&item_key, cred_key)?,
                    None => vw.item_ids(&item_key)?,
                })
            })
            .await?;
        let mut event = change_event(audit::Action::CredentialRoleChanged, &key, subject, ids)
            .detail("role", role_name);
        if cleared {
            event = event.detail("cleared", "true");
        }
        event.record_async().await;
        Ok(())
    }

    /// Replace the websites an item applies to.
    pub async fn set_item_websites(
        &self,
        vault_key: String,
        item_key: String,
        websites: Vec<WebsiteInfo>,
    ) -> Result<(), FfiError> {
        let websites = websites
            .into_iter()
            .map(Website::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let origins = websites
            .iter()
            .map(|w| website_origin(&w.url))
            .collect::<Vec<_>>()
            .join(",");
        let website_count = websites.len().to_string();
        let subject = item_subject(&vault_key, &item_key);
        let key = vault_key.clone();
        let ids = self
            .edit_vault(vault_key, move |vw| {
                autofill::set_websites(vw, &item_key, websites)?;
                Ok(vw.item_ids(&item_key)?)
            })
            .await?;
        change_event(audit::Action::ItemWebsitesChanged, &key, subject, ids)
            .detail("origins", origins)
            .detail("website_count", website_count)
            .record_async()
            .await;
        Ok(())
    }

    /// Give an item with no autofill data the roles and websites its
    /// credentials suggest. Returns false when there was nothing to convert.
    pub async fn convert_item_to_login(
        &self,
        vault_key: String,
        item_key: String,
    ) -> Result<bool, FfiError> {
        let subject = item_subject(&vault_key, &item_key);
        let key = vault_key.clone();
        let (converted, ids) = self
            .edit_vault(vault_key, move |vw| {
                let converted = autofill::convert_to_login(vw, &item_key)?;
                Ok((converted, vw.item_ids(&item_key)?))
            })
            .await?;
        if converted {
            change_event(audit::Action::ItemConverted, &key, subject, ids)
                .record_async()
                .await;
        }
        Ok(converted)
    }

    /// Move a passkey to another item, which may be in another vault. With no
    /// `dest_item_key` it moves into a new login item for its relying party.
    ///
    /// A move within one vault keeps the credential and its id. A move to
    /// another vault copies the passkey. The destination is written and saved
    /// before the source is removed, so a failure partway leaves the passkey in
    /// both places rather than in neither. The source is purged, not kept in
    /// the deleted credentials.
    pub async fn move_passkey(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        dest_vault_key: String,
        dest_item_key: Option<String>,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let key = vault_key.clone();
        let dest_vault = dest_vault_key.clone();
        let dest_item = dest_item_key
            .clone()
            .unwrap_or_else(|| "new_login".to_string());
        // `None` if there was nothing to move. Otherwise the ids of the source,
        // the WebAuthn credential id, the ids of the stored passkey, and the
        // result of removing the source, after the destination was written.
        let moved = tokio::task::spawn_blocking(move || {
            let target = match dest_item_key {
                Some(key) => PasskeyTarget::Item(key),
                None => PasskeyTarget::NewLogin,
            };
            if vault_key == dest_vault_key {
                if target == PasskeyTarget::Item(item_key.clone()) {
                    return Ok(None);
                }
                return VaultsManager::write_vault(&manager, &vault_key, |vw| {
                    let source = vw.credential_ids(&item_key, &cred_key)?;
                    let webauthn_id = passkey::webauthn_credential_id(vw, &item_key, &cred_key)?;
                    let dest = passkey::move_within_vault(vw, &item_key, &cred_key, &target)?;
                    Ok::<_, FfiError>(Some((source, webauthn_id, dest, Ok(()))))
                });
            }
            // An add in a transaction on the destination, then a remove in a
            // transaction on the source, so no transaction holds two vaults'
            // locks. A failure between the two leaves the passkey in both.
            let (record, source, webauthn_id) =
                VaultsManager::write_vault(&manager, &vault_key, |vw| {
                    let record = passkey::read_record(vw, &item_key, &cred_key)?;
                    let source = vw.credential_ids(&item_key, &cred_key)?;
                    let webauthn_id = passkey::webauthn_credential_id(vw, &item_key, &cred_key)?;
                    Ok::<_, FfiError>((record, source, webauthn_id))
                })?;
            let dest = VaultsManager::write_vault(&manager, &dest_vault_key, |vw| {
                passkey::write_record(vw, &record, &target).map_err(FfiError::from)
            })?;
            let removed = VaultsManager::write_vault(&manager, &vault_key, |vw| {
                passkey::remove_record(vw, &item_key, &cred_key).map_err(FfiError::from)
            });
            Ok(Some((source, webauthn_id, dest, removed)))
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        let Some((source, webauthn_id, dest, removed)) = moved else {
            return Ok(());
        };
        let mut event = change_event(audit::Action::PasskeyMoved, &key, subject, source)
            .passkey_credential_id(&webauthn_id)
            .detail("dest_vault", dest_vault)
            .detail("dest_item", dest_item)
            .maybe_detail("dest_vault_id", dest.vault_id.map(ShortId::encode_uuid))
            .maybe_detail("dest_item_id", dest.item_id.map(ShortId::encode_uuid))
            .maybe_detail(
                "dest_credential_id",
                dest.credential_id.map(ShortId::encode_uuid),
            );
        // The destination holds the passkey even if removing the source failed,
        // so that is recorded as a failed move.
        if let Err(e) = &removed {
            event.outcome = audit::Outcome::Failed;
            event = event
                .detail("source_removed", "false")
                .message(e.to_string());
        }
        event.record_async().await;
        removed
    }

    /// Set the account name of a passkey to `name`, as its site reported. The
    /// report is then settled, so the suggestion is no longer shown.
    pub async fn apply_passkey_name(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        name: String,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let key = vault_key.clone();
        let (item, cred) = (item_key.clone(), cred_key.clone());
        let (ids, webauthn_id) = self
            .edit_vault(vault_key, move |vw| {
                passkey::rename_account(vw, &item, &cred, &name)?;
                let value = vw.get_secret(&item, &cred)?;
                if let Some(summary) = value.and_then(|v| passkey::summary(v.expose_secret())) {
                    dismiss_report(vw, &summary, signals::DismissKind::Rename)?;
                }
                // An id that does not decode leaves the event without one and
                // does not fail the rename.
                let webauthn_id = passkey::webauthn_credential_id(vw, &item, &cred).ok();
                Ok((vw.credential_ids(&item, &cred)?, webauthn_id))
            })
            .await?;
        let mut event = change_event(audit::Action::PasskeyRenamed, &key, subject, ids);
        if let Some(id) = &webauthn_id {
            event = event.passkey_credential_id(id);
        }
        event.record_async().await;
        Ok(())
    }

    /// Dismiss what site reports say about a passkey: keep a passkey the site
    /// no longer accepts, or ignore a reported name. A later report marks it
    /// again. The dismissal is stored in the vault. The passkey is unchanged.
    pub async fn dismiss_passkey_report(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        kind: PasskeyReportKind,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            let value = vw.get_secret(&item_key, &cred_key)?;
            let summary = value
                .and_then(|v| passkey::summary(v.expose_secret()))
                .ok_or_else(|| FfiError::InvalidInput("Not a passkey".to_string()))?;
            dismiss_report(vw, &summary, kind.into())
        })
        .await
    }

    /// Write the site reports held in memory into the vaults. Each vault takes
    /// the reports for the relying parties of its passkeys. Reports stay in
    /// memory if any vault fails to unlock or save. A vault is saved only if
    /// its reports changed. Requires the app to be unlocked.
    pub async fn apply_passkey_reports(&self) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let reports = signals::pending();
            if reports.is_empty() {
                return Ok(());
            }

            let vault_keys: Vec<String> = manager
                .lock()
                .map_err(|_| FfiError::Poisoned)?
                .iter_vault_keys()
                .collect();
            let mut complete = true;
            for vault_key in vault_keys {
                // A vault that already holds every report is not changed, so
                // the transaction writes nothing.
                let applied = VaultsManager::write_vault(&manager, &vault_key, |vault| {
                    let rp_ids: std::collections::HashSet<String> = passkey::list(vault)?
                        .into_iter()
                        .map(|s| s.passkey.rp_id)
                        .collect();
                    let mut relevant = reports.clone();
                    relevant.retain_rp(|rp_id| rp_ids.contains(rp_id));
                    if !relevant.is_empty() {
                        vault.update_passkey_signals(|store| store.merge(&relevant))?;
                    }
                    Ok::<_, VaultError>(())
                });
                if let Err(e) = applied {
                    log::error!("Failed to apply passkey reports in {vault_key}: {e}");
                    complete = false;
                }
            }
            if complete {
                signals::clear_pending(&reports);
            }
            Ok(())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Move every credential of `source_item_key` into `dest_item_key` and
    /// delete the source item. Both items are in `vault_key`.
    pub async fn merge_items(
        &self,
        vault_key: String,
        source_item_key: String,
        dest_item_key: String,
    ) -> Result<(), FfiError> {
        let subject = item_subject(&vault_key, &dest_item_key);
        let key = vault_key.clone();
        let source_item = source_item_key.clone();
        let (ids, source) = self
            .edit_vault(vault_key, move |vw| {
                let source = vw.item_ids(&source_item_key)?;
                autofill::merge_items(vw, &source_item_key, &dest_item_key)?;
                Ok((vw.item_ids(&dest_item_key)?, source))
            })
            .await?;
        change_event(audit::Action::ItemMerged, &key, subject, ids)
            .detail("source_item", source_item)
            .maybe_detail("source_item_id", source.item_id.map(ShortId::encode_uuid))
            .record_async()
            .await;
        Ok(())
    }

    /// Set the display order of an item's credentials, keeping each in its
    /// current section. `ordered_cred_keys` must list exactly the item's
    /// credential keys, once each.
    pub async fn reorder_credentials(
        &self,
        vault_key: String,
        item_key: String,
        ordered_cred_keys: Vec<String>,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            vw.reorder_credentials(&item_key, &ordered_cred_keys)
                .map_err(FfiError::from)
        })
        .await
    }

    /// Set the display order and section of an item's credentials in one
    /// save. `placements` must list exactly the item's credential keys, once
    /// each, in display order.
    pub async fn arrange_credentials(
        &self,
        vault_key: String,
        item_key: String,
        placements: Vec<CredentialPlacementInfo>,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            let placements = placements
                .into_iter()
                .map(|p| {
                    Ok(CredentialPlacement {
                        key: p.key,
                        section: parse_optional_id(p.section_id)?,
                    })
                })
                .collect::<Result<Vec<_>, FfiError>>()?;
            Ok(vw.arrange_credentials(&item_key, &placements)?)
        })
        .await
    }

    /// Move a credential into a section of its item, or out of any section
    /// when `section_id` is `None`.
    pub async fn move_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        section_id: Option<String>,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            let section_id = parse_optional_id(section_id)?;
            Ok(vw.move_credential(&item_key, &cred_key, section_id)?)
        })
        .await
    }

    // -----------------------------------------------------------------------
    // Folders and sections
    // -----------------------------------------------------------------------

    pub async fn create_folder(
        &self,
        vault_key: String,
        title: String,
    ) -> Result<FolderInfo, FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(FolderInfo::from(vw.create_folder(&title)?))
        })
        .await
    }

    pub async fn rename_folder(
        &self,
        vault_key: String,
        folder_id: String,
        title: String,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.rename_folder(parse_id(&folder_id)?, &title)?)
        })
        .await
    }

    /// Delete a folder. Its items become unfiled.
    pub async fn delete_folder(
        &self,
        vault_key: String,
        folder_id: String,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.delete_folder(parse_id(&folder_id)?)?)
        })
        .await
    }

    /// Set the display order of folders. `ordered_folder_ids` must list every
    /// folder exactly once.
    pub async fn reorder_folders(
        &self,
        vault_key: String,
        ordered_folder_ids: Vec<String>,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.reorder_folders(&parse_ids(&ordered_folder_ids)?)?)
        })
        .await
    }

    /// Move an item into a folder, or out of any folder when `folder_id` is
    /// `None`.
    pub async fn move_item(
        &self,
        vault_key: String,
        item_key: String,
        folder_id: Option<String>,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.move_item(&item_key, parse_optional_id(folder_id)?)?)
        })
        .await
    }

    pub async fn create_section(
        &self,
        vault_key: String,
        item_key: String,
        title: String,
    ) -> Result<SectionInfo, FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(SectionInfo::from(
                vw.create_item_section(&item_key, &title)?,
            ))
        })
        .await
    }

    pub async fn rename_section(
        &self,
        vault_key: String,
        item_key: String,
        section_id: String,
        title: String,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.rename_item_section(&item_key, parse_id(&section_id)?, &title)?)
        })
        .await
    }

    /// Delete a section. Its credentials move out of any section.
    pub async fn delete_section(
        &self,
        vault_key: String,
        item_key: String,
        section_id: String,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.delete_item_section(&item_key, parse_id(&section_id)?)?)
        })
        .await
    }

    /// Set the display order of an item's sections. `ordered_section_ids` must
    /// list every section of the item exactly once.
    pub async fn reorder_sections(
        &self,
        vault_key: String,
        item_key: String,
        ordered_section_ids: Vec<String>,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.reorder_item_sections(&item_key, &parse_ids(&ordered_section_ids)?)?)
        })
        .await
    }
}
