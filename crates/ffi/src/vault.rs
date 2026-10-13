use std::collections::HashMap;
use std::sync::Arc;

use axo_pass_core::secrets::password::PasswordPolicy;
use axo_pass_core::secrets::vaults::passkey::PasskeyTarget;
use axo_pass_core::secrets::vaults::{
    CredentialPlacement, CredentialUpdate, Error as VaultError, FieldKind, MatchKind, TextField,
    VaultFolder, VaultItemCredentialOverview, VaultItemOverview, VaultItemSection, VaultWrapper,
    Website, autofill, display_order, passkey, totp,
};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::*;

#[derive(uniffi::Record, Clone)]
pub struct VaultInfo {
    pub key: String,
    pub name: Option<String>,
}

#[derive(uniffi::Record)]
pub struct CredentialInfo {
    /// Credential id as a UUID string. It does not change when the key does.
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
    /// Only present for passkeys; contains passkey credential details for
    /// display.
    pub passkey: Option<PasskeyInfo>,
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
}

/// A previous value of a credential. The value is not included. Read it with
/// `get_credential_history_value`.
#[derive(uniffi::Record)]
pub struct HistoryEntryInfo {
    /// Entry id as a UUID string.
    pub id: String,
    /// Time the value was replaced, as a Unix timestamp in seconds.
    pub replaced_at: i64,
}

/// A deleted item that can still be restored. Credential values are not
/// included.
#[derive(uniffi::Record)]
pub struct DeletedItemInfo {
    /// Item id as a UUID string. Pass back to `restore_item` or `purge_item`.
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
    /// Credential id as a UUID string.
    pub id: String,
    pub key: String,
    pub title: String,
    pub kind: FieldKindInfo,
    /// True if the credential was deleted before the item.
    pub deleted_before_item: bool,
}

/// A deleted credential of a live item that can still be restored. The value
/// is not included. Read it with `get_deleted_credential_secret`.
#[derive(uniffi::Record)]
pub struct DeletedCredentialInfo {
    /// Credential id as a UUID string. Pass back to `restore_credential` or
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
}

/// A vault folder. Folders are listed in display order.
#[derive(uniffi::Record)]
pub struct FolderInfo {
    /// Folder id as a UUID string.
    pub id: String,
    pub title: String,
}

impl From<&VaultFolder> for FolderInfo {
    fn from(f: &VaultFolder) -> Self {
        Self {
            id: f.id.to_string(),
            title: f.title.clone(),
        }
    }
}

/// A section of an item. Sections are listed in display order.
#[derive(uniffi::Record)]
pub struct SectionInfo {
    /// Section id as a UUID string.
    pub id: String,
    pub title: String,
}

impl From<&VaultItemSection> for SectionInfo {
    fn from(s: &VaultItemSection) -> Self {
        Self {
            id: s.id.to_string(),
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
/// "text", "email", "url", "phone", "date", "totp", "passkey", or "unknown".
/// `multiline` applies only to "text"; it is false for every other kind, and
/// `concealed` is true for "text" that conceals its value and for "passkey".
///
/// The write path (`add_or_update_credential`) accepts every discriminator
/// except "unknown", which cannot be reconstructed, and "passkey", whose value
/// is a structured record only the authenticator may write. When the caller
/// wants to leave an existing credential's kind untouched it passes `None`.
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
            // written through the generic credential path.
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
    /// Item id as a UUID string. It does not change when the key does.
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
    /// `<vault uuid>/<item uuid>/<password credential uuid>`. The identifier
    /// the AutoFill index stores, and the broker's login requests take.
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
    /// `<vault uuid>/<item uuid>/<credential uuid>`.
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
    /// Run `f` on an unlocked vault on a blocking thread, then save the vault.
    async fn edit_vault<R: Send + 'static>(
        &self,
        vault_key: String,
        f: impl FnOnce(&mut VaultWrapper) -> Result<R, FfiError> + Send + 'static,
    ) -> Result<R, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, f)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }
}

/// Decrypt a vault from disk if it is not already in memory. Uses the shared
/// LAContext, so there is no re-prompt after a successful `unlock`.
fn ensure_unlocked(vault: &mut VaultWrapper) -> Result<(), FfiError> {
    if matches!(vault.list_items(), Err(VaultError::VaultLocked)) {
        vault.unlock()?;
    }
    Ok(())
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

fn parse_id(id: &str) -> Result<Uuid, FfiError> {
    Uuid::parse_str(id).map_err(|_| FfiError::InvalidInput(format!("Invalid id: {id}")))
}

fn parse_optional_id(id: Option<String>) -> Result<Option<Uuid>, FfiError> {
    id.as_deref().map(parse_id).transpose()
}

fn parse_ids(ids: &[String]) -> Result<Vec<Uuid>, FfiError> {
    ids.iter().map(|id| parse_id(id)).collect()
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// List all known vaults. Does not require authentication.
    pub fn list_vaults(&self) -> Result<Vec<VaultInfo>, FfiError> {
        let manager = self.manager.lock().map_err(|_| FfiError::Poisoned)?;
        let mut vaults: Vec<VaultInfo> = manager
            .iter_vaults()
            .map(|(key, vw)| VaultInfo {
                key: key.clone(),
                name: vw.vault_name().map(|s| s.to_string()),
            })
            .collect();
        vaults.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(vaults)
    }

    /// List items for a vault. Decrypts the vault from disk using the
    /// shared LAContext — no additional Touch ID prompt if `unlock` has
    /// already been called. Triggers auth if called before `unlock`.
    pub async fn list_items(&self, vault_key: String) -> Result<Vec<ItemInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;

            ensure_unlocked(vault)?;

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
                                .map(|s| PasskeyInfo {
                                    rp_id: s.rp_id,
                                    credential_id: s.credential_id,
                                    username: s.username,
                                    user_display_name: s.user_display_name,
                                    created_at: s.created_at,
                                });
                            CredentialInfo {
                                id: c.id.to_string(),
                                key: c.key.clone(),
                                title: c.title.clone(),
                                kind,
                                position: c.position,
                                section_id: c.section.map(|id| id.to_string()),
                                role: role.map(str::to_string),
                                passkey,
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
                        id: item.id.to_string(),
                        key: item.key.clone(),
                        title: item.title.clone(),
                        folder_id: item.folder.map(|id| id.to_string()),
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
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            ensure_unlocked(vault)?;

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
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault_keys: Vec<String> = m.iter_vault_keys().collect();
            let mut found_items = Vec::new();
            let mut places = Vec::new();
            for vault_key in vault_keys {
                let Some(vault) = m.get_vault_mut(&vault_key) else {
                    continue;
                };
                if let Err(e) = vault.unlock() {
                    log::error!("Failed to unlock vault {vault_key} for autofill: {e}");
                    continue;
                }
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
    /// to be unlocked; a vault that fails to unlock is skipped.
    ///
    /// Only the metadata the identity store needs is read. The private key
    /// stays in the vault until the extension asks for an assertion.
    pub async fn list_passkey_identities(&self) -> Result<Vec<PasskeyIdentityInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault_keys: Vec<String> = m.iter_vault_keys().collect();
            let mut identities = Vec::new();
            for vault_key in vault_keys {
                let Some(vault) = m.get_vault_mut(&vault_key) else {
                    continue;
                };
                if let Err(e) = vault.unlock() {
                    log::error!("Failed to unlock vault {vault_key} for passkeys: {e}");
                    continue;
                }
                match passkey::list(vault) {
                    Ok(found) => identities.extend(found.into_iter().map(|s| {
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
                    })),
                    Err(e) => log::error!("Failed to list passkeys in {vault_key}: {e}"),
                }
            }
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
            let m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_vault(&vault_key)
                .ok_or_else(|| FfiError::NotFound(vault_key.clone()))?;
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
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            ensure_unlocked(vault)?;

            let history = vault
                .list_history(&item_key, &cred_key)
                .map_err(FfiError::from)?;
            Ok(history
                .into_iter()
                .map(|h| HistoryEntryInfo {
                    id: h.id.to_string(),
                    replaced_at: h.replaced_at,
                })
                .collect())
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
            let m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_vault(&vault_key)
                .ok_or_else(|| FfiError::NotFound(vault_key.clone()))?;
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
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.restore_history_value(&item_key, &cred_key, parse_id(&history_id)?)?)
        })
        .await
    }

    /// Delete a previous value of a credential permanently.
    pub async fn purge_credential_history(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        history_id: String,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.purge_history(&item_key, &cred_key, parse_id(&history_id)?)?)
        })
        .await
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
            let m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_vault(&vault_key)
                .ok_or_else(|| FfiError::NotFound(vault_key.clone()))?;
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
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vw = m.add_vault(name, &vault_key).map_err(FfiError::from)?;
            Ok(VaultInfo {
                key: vw.key.clone(),
                name: vw.vault_name().map(|s| s.to_string()),
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Rename a vault and/or change its key. Does not require the vault to be
    /// unlocked. Mirrors `update_vault` in the Tauri app.
    pub async fn update_vault(
        &self,
        vault_key: String,
        new_vault_key: Option<String>,
        new_name: Option<String>,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vw = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;

            if new_name.as_deref() != vw.vault_name()
                && let Some(new_name) = new_name
            {
                vw.set_vault_name(new_name).map_err(FfiError::from)?;
                vw.save().map_err(FfiError::from)?;
            }

            if new_vault_key.as_deref() != Some(vault_key.as_str())
                && let Some(new_vault_key) = new_vault_key
            {
                m.update_vault_key(&vault_key, &new_vault_key)
                    .map_err(FfiError::from)?;
            }

            Ok(())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Delete a vault (moved to Trash, not permanently deleted). Mirrors
    /// `delete_vault` in the Tauri app.
    pub async fn delete_vault(&self, vault_key: String) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.delete_vault(&vault_key).map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Create or rename an item within a vault.
    pub async fn add_or_update_item(
        &self,
        vault_key: String,
        item_key: String,
        item_title: String,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                vw.add_item(&item_key, &item_title)
                    .map_err(FfiError::from)?;
                Ok(())
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// List a vault's deleted items, most recently deleted first.
    pub async fn list_deleted_items(
        &self,
        vault_key: String,
    ) -> Result<Vec<DeletedItemInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            ensure_unlocked(vault)?;

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
                            id: c.id.to_string(),
                            key: c.key.clone(),
                            title: c.title.clone(),
                            kind: FieldKindInfo::from(&c.kind),
                            deleted_before_item,
                        })
                        .collect();
                    DeletedItemInfo {
                        id: d.item.id.to_string(),
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
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.restore_item(parse_id(&item_id)?, new_key)?)
        })
        .await
    }

    /// Delete a deleted item permanently, with its credentials.
    pub async fn purge_item(&self, vault_key: String, item_id: String) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| Ok(vw.purge_item(parse_id(&item_id)?)?))
            .await
    }

    /// Delete an item (and all its credentials) from a vault. It stays
    /// recoverable with `restore_item` until purged.
    pub async fn delete_item(&self, vault_key: String, item_key: String) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                vw.delete_item(&item_key).map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
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
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
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
                )
                .map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
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
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                // `None` keeps an existing credential's kind, so an edit that
                // only touches the title or value does not reset it. A new
                // credential with no kind given falls back to the default.
                let kind = match kind {
                    Some(info) => FieldKind::try_from(info)?,
                    None => vw
                        .get_secret_overview(&item_key, &cred_key)
                        .ok()
                        .flatten()
                        .map(|o| o.kind.clone())
                        .unwrap_or_default(),
                };
                vw.add_secret(
                    &item_key,
                    &cred_key,
                    &title,
                    kind,
                    SecretString::from(value),
                )
                .map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
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
        self.edit_vault(vault_key, move |vw| {
            let update = CredentialUpdate {
                key: new_key,
                title,
                kind: kind.map(FieldKind::try_from).transpose()?,
            };
            Ok(vw.update_credential(&item_key, &cred_key, update)?)
        })
        .await
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
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            ensure_unlocked(vault)?;

            let deleted = vault.list_all_deleted().map_err(FfiError::from)?;
            Ok(deleted
                .into_iter()
                .map(|d| DeletedCredentialInfo {
                    id: d.credential.credential.id.to_string(),
                    key: d.credential.credential.key.clone(),
                    title: d.credential.credential.title.clone(),
                    kind: FieldKindInfo::from(&d.credential.credential.kind),
                    item_id: d.item.id.to_string(),
                    item_key: d.item.key.clone(),
                    item_title: d.item.title.clone(),
                    deleted_at: d.credential.deleted_at,
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
            let m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_vault(&vault_key)
                .ok_or_else(|| FfiError::NotFound(vault_key.clone()))?;
            let secret = vault
                .get_deleted_secret(parse_id(&item_id)?, parse_id(&cred_id)?)
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
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.restore_item_credential(&item_key, parse_id(&cred_id)?, new_key)?)
        })
        .await
    }

    /// Delete a deleted credential permanently.
    pub async fn purge_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_id: String,
    ) -> Result<(), FfiError> {
        self.edit_vault(vault_key, move |vw| {
            Ok(vw.purge_item_credential(&item_key, parse_id(&cred_id)?)?)
        })
        .await
    }

    /// Delete a single credential from an item. It stays recoverable with
    /// `restore_credential` until purged.
    pub async fn delete_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                vw.delete_item_credential(&item_key, &cred_key)
                    .map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
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
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                autofill::create_login(
                    vw,
                    &website,
                    username.as_deref(),
                    SecretString::from(password),
                    item_key.as_deref(),
                    title.as_deref(),
                )
                .map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
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
            let m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_vault(&vault_key)
                .ok_or_else(|| FfiError::NotFound(vault_key.clone()))?;
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
        let role = parse_role(&role)?;
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                autofill::set_role(vw, &item_key, role, cred_key.as_deref()).map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
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
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                autofill::set_websites(vw, &item_key, websites).map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Give an item with no autofill data the roles and websites its
    /// credentials suggest. Returns false when there was nothing to convert.
    pub async fn convert_item_to_login(
        &self,
        vault_key: String,
        item_key: String,
    ) -> Result<bool, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                autofill::convert_to_login(vw, &item_key).map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Move a passkey to another item, which may be in another vault. With no
    /// `dest_item_key` it moves into a new login item for its relying party.
    ///
    /// The destination is written and saved before the source is removed, so a
    /// failure partway leaves the passkey in both places rather than in
    /// neither. The source is purged, not kept in the deleted credentials.
    pub async fn move_passkey(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        dest_vault_key: String,
        dest_item_key: Option<String>,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let target = match dest_item_key {
                Some(key) => PasskeyTarget::Item(key),
                None => PasskeyTarget::NewLogin,
            };
            if vault_key == dest_vault_key {
                if target == PasskeyTarget::Item(item_key.clone()) {
                    return Ok(());
                }
                return m.with_unlocked_vault(&vault_key, |vw| {
                    let record = passkey::read_record(vw, &item_key, &cred_key)?;
                    passkey::write_record(vw, &record, &target)?;
                    passkey::remove_record(vw, &item_key, &cred_key)?;
                    Ok::<_, FfiError>(())
                });
            }
            let record = m.with_unlocked_vault(&vault_key, |vw| {
                passkey::read_record(vw, &item_key, &cred_key).map_err(FfiError::from)
            })?;
            m.with_unlocked_vault(&dest_vault_key, |vw| {
                passkey::write_record(vw, &record, &target).map_err(FfiError::from)
            })?;
            m.with_unlocked_vault(&vault_key, |vw| {
                passkey::remove_record(vw, &item_key, &cred_key).map_err(FfiError::from)
            })
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
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                autofill::merge_items(vw, &source_item_key, &dest_item_key).map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
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
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                vw.reorder_credentials(&item_key, &ordered_cred_keys)
                    .map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
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
