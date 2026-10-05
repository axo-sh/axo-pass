use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use super::FieldKind;
use super::vault::{VaultItemCredentialOverview, VaultItemOverview};

/// The `category` value for items created as logins.
pub const CATEGORY_LOGIN: &str = "login";

/// Role slots and websites for autofill. Stored in its own encrypted blob so
/// that edits here do not conflict with item renames.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ItemAutofill {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub websites: Vec<Website>,
    /// Credential filled as the account name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<Uuid>,
    /// Credential filled as the password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Uuid>,
}

impl Zeroize for ItemAutofill {
    fn zeroize(&mut self) {
        self.websites.clear();
        self.username = None;
        self.password = None;
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

    fn resolve<'a>(
        &self,
        slot: Option<Uuid>,
        item: &'a VaultItemOverview,
    ) -> Option<&'a VaultItemCredentialOverview> {
        let cred = item.credentials.get(&slot?)?;
        match cred.kind {
            FieldKind::Passkey | FieldKind::Totp | FieldKind::Unknown(_) => None,
            _ => Some(cred),
        }
    }

    /// Whether one credential fills both roles.
    pub fn has_shared_slot(&self) -> bool {
        self.username.is_some() && self.username == self.password
    }

    /// Clear any slot that points at `cred_id`.
    pub fn clear_credential(&mut self, cred_id: Uuid) {
        if self.username == Some(cred_id) {
            self.username = None;
        }
        if self.password == Some(cred_id) {
            self.password = None;
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
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
    fn default_serializes_to_an_empty_object() {
        let json = serde_json::to_string(&ItemAutofill::default()).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn default_match_kind_is_omitted() {
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
    fn a_missing_or_wrong_kind_credential_reads_as_empty() {
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
