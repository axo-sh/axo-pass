use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::secrets::vaults::FieldKind;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::model::{VaultItemCredentialOverview, VaultItemOverview};

/// The `category` value for items created as logins.
pub const CATEGORY_LOGIN: &str = "login";

/// The `category` value for items that hold an SSH key.
pub const CATEGORY_SSH_KEY: &str = "ssh-key";

/// A credential's part in autofill.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Username,
    Password,
    /// The credential the one-time code comes from.
    Totp,
}

/// Role slots and websites for autofill. Stored in its own encrypted blob so
/// that edits here do not conflict with item renames.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ItemAutofill {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub websites: Vec<Website>,
    /// Credential filled as the account name.
    #[serde_as(as = "Option<ShortId>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<Uuid>,
    /// Credential filled as the password.
    #[serde_as(as = "Option<ShortId>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Uuid>,
    /// Credential the one-time code is generated from.
    #[serde_as(as = "Option<ShortId>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<Uuid>,
}

impl Zeroize for ItemAutofill {
    fn zeroize(&mut self) {
        self.websites.clear();
        self.username = None;
        self.password = None;
        self.totp = None;
    }
}

impl ItemAutofill {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The credential filled as the username. A slot that points at a missing
    /// credential, or at a passkey, one-time code, or unknown kind, reads as
    /// empty.
    pub fn username_credential<'a>(
        &self,
        item: &'a VaultItemOverview,
    ) -> Option<&'a VaultItemCredentialOverview> {
        self.resolve(self.username, item)
    }

    /// The credential filled as the password, with the same rules as
    /// [`Self::username_credential`].
    pub fn password_credential<'a>(
        &self,
        item: &'a VaultItemOverview,
    ) -> Option<&'a VaultItemCredentialOverview> {
        self.resolve(self.password, item)
    }

    /// The credential the one-time code comes from. A slot that points at a
    /// missing credential, or at one that is not a one-time code, reads as
    /// empty.
    pub fn totp_credential<'a>(
        &self,
        item: &'a VaultItemOverview,
    ) -> Option<&'a VaultItemCredentialOverview> {
        let cred = item.credentials.get(&self.totp?)?;
        matches!(cred.kind, FieldKind::Totp).then_some(cred)
    }

    fn resolve<'a>(
        &self,
        slot: Option<Uuid>,
        item: &'a VaultItemOverview,
    ) -> Option<&'a VaultItemCredentialOverview> {
        let cred = item.credentials.get(&slot?)?;
        match cred.kind {
            FieldKind::Passkey
            | FieldKind::File
            | FieldKind::SshKey
            | FieldKind::Totp
            | FieldKind::Unknown(_) => None,
            _ => Some(cred),
        }
    }

    /// Whether one credential fills both roles.
    pub fn has_shared_slot(&self) -> bool {
        self.username.is_some() && self.username == self.password
    }

    /// Remove each later website with the URL of an earlier one. The first
    /// website of each URL by order stays. Returns whether a website was
    /// removed.
    pub fn remove_duplicate_websites(&mut self) -> bool {
        let before = self.websites.len();
        let mut urls = BTreeSet::new();
        self.websites
            .retain(|website| urls.insert(website.url.clone()));
        self.websites.len() != before
    }

    /// Role slot of `role`.
    fn slot_mut(&mut self, role: Role) -> &mut Option<Uuid> {
        match role {
            Role::Username => &mut self.username,
            Role::Password => &mut self.password,
            Role::Totp => &mut self.totp,
        }
    }

    /// Role whose slot points at `cred_id`. A credential has at most one.
    pub fn role_of(&self, cred_id: Uuid) -> Option<Role> {
        [
            (Role::Username, self.username),
            (Role::Password, self.password),
            (Role::Totp, self.totp),
        ]
        .into_iter()
        .find(|(_, slot)| *slot == Some(cred_id))
        .map(|(role, _)| role)
    }

    /// Point the `role` slot at `cred_id` if the slot is empty. Returns whether
    /// the slot was set.
    pub fn fill_empty_slot(&mut self, role: Role, cred_id: Uuid) -> bool {
        let slot = self.slot_mut(role);
        if slot.is_some() {
            return false;
        }
        *slot = Some(cred_id);
        true
    }

    /// Clear any slot that points at `cred_id`.
    pub fn clear_credential(&mut self, cred_id: Uuid) {
        if self.username == Some(cred_id) {
            self.username = None;
        }
        if self.password == Some(cred_id) {
            self.password = None;
        }
        if self.totp == Some(cred_id) {
            self.totp = None;
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Website {
    pub url: String,
    #[serde(
        default,
        skip_serializing_if = "MatchKind::is_default",
        rename = "match"
    )]
    pub match_kind: MatchKind,
}

impl Website {
    pub fn new(url: impl Into<String>, match_kind: MatchKind) -> Self {
        Self {
            url: url.into(),
            match_kind,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MatchKind {
    /// Same registrable domain.
    #[default]
    Domain,
    /// Same host.
    Host,
    /// The page URL starts with the stored URL.
    StartsWith,
    /// This website never matches. Other websites on the item still do.
    Never,
}

impl MatchKind {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item_with(kinds: &[(&str, FieldKind)]) -> (VaultItemOverview, Vec<Uuid>) {
        let mut item = VaultItemOverview::try_new("Item", "item").unwrap();
        let mut ids = Vec::new();
        for (key, kind) in kinds {
            let cred = VaultItemCredentialOverview::try_new(key, key, kind.clone()).unwrap();
            ids.push(cred.id);
            item.credentials.insert(cred.id, cred);
        }
        (item, ids)
    }

    #[test]
    fn default_serializes_to_empty_object() {
        let json = serde_json::to_string(&ItemAutofill::default()).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn default_match_kind_omitted() {
        let site = Website::new("github.com", MatchKind::Domain);
        assert_eq!(
            serde_json::to_value(&site).unwrap(),
            serde_json::json!({"url": "github.com"})
        );
        let site = Website::new("github.com", MatchKind::StartsWith);
        assert_eq!(
            serde_json::to_value(&site).unwrap(),
            serde_json::json!({"url": "github.com", "match": "starts-with"})
        );
        let site = Website::new("github.com", MatchKind::Never);
        assert_eq!(
            serde_json::to_value(&site).unwrap(),
            serde_json::json!({"url": "github.com", "match": "never"})
        );
    }

    #[test]
    fn website_with_unknown_field_refused() {
        let autofill = serde_json::json!({"websites": [{"url": "github.com"}]});
        assert!(serde_json::from_value::<ItemAutofill>(autofill).is_ok());

        let autofill = serde_json::json!({"websites": [{"url": "github.com", "x": 1}]});
        assert!(serde_json::from_value::<ItemAutofill>(autofill).is_err());
        let autofill = serde_json::json!({"websites": [], "x": 1});
        assert!(serde_json::from_value::<ItemAutofill>(autofill).is_err());
    }

    #[test]
    fn roles_resolve_to_credentials() {
        let (item, ids) = item_with(&[
            ("username", FieldKind::Email),
            ("password", FieldKind::default()),
        ]);
        let autofill = ItemAutofill {
            username: Some(ids[0]),
            password: Some(ids[1]),
            ..Default::default()
        };
        assert_eq!(autofill.username_credential(&item).unwrap().key, "username");
        assert_eq!(autofill.password_credential(&item).unwrap().key, "password");
    }

    #[test]
    fn missing_or_wrong_kind_credential_reads_as_empty() {
        let (item, ids) = item_with(&[("code", FieldKind::Totp), ("key", FieldKind::Passkey)]);
        let autofill = ItemAutofill {
            username: Some(ids[0]),
            password: Some(ids[1]),
            ..Default::default()
        };
        assert!(autofill.username_credential(&item).is_none());
        assert!(autofill.password_credential(&item).is_none());

        let dangling = ItemAutofill {
            password: Some(Uuid::new_v4()),
            ..Default::default()
        };
        assert!(dangling.password_credential(&item).is_none());
    }

    #[test]
    fn clear_credential_clears_matching_slots() {
        let id = Uuid::new_v4();
        let mut autofill = ItemAutofill {
            username: Some(Uuid::new_v4()),
            password: Some(id),
            ..Default::default()
        };
        autofill.clear_credential(id);
        assert!(autofill.password.is_none());
        assert!(autofill.username.is_some());
    }
}
