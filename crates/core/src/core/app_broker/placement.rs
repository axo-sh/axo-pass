//! Where a new passkey is stored, and the choices the registration prompt
//! offers.
//!
//! The broker builds the choices from its login index before it raises the
//! prompt, so the user sees the vault and the login with the approval. The
//! answer comes back from the app and is checked against the same choices, so a
//! client or a compromised app delegate cannot name a vault or an item the
//! prompt did not offer.

use crate::secrets::vaults::autofill::{LoginPlace, places_for_rp};
use crate::secrets::vaults::passkey::PasskeyTarget;

/// A vault the passkey may be stored in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementVault {
    pub key: String,
    pub name: Option<String>,
}

/// A login item whose websites match the relying party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementLogin {
    pub vault_key: String,
    pub item_key: String,
    pub title: String,
    pub username: Option<String>,
}

/// What the registration prompt offers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PasskeyChoices {
    /// Every vault.
    pub vaults: Vec<PlacementVault>,
    /// The matching logins in every vault. The prompt shows the ones in the
    /// chosen vault, and "New login".
    pub logins: Vec<PlacementLogin>,
    /// The vault used when the user does not choose: the suggested login's
    /// vault, otherwise the default vault.
    pub default_vault: String,
    /// The login preselected in the prompt, as an index into `logins`.
    pub suggested: Option<usize>,
}

/// The user's answer: a vault, and an item in it or a new login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyPlacement {
    pub vault_key: String,
    pub item_key: Option<String>,
}

impl PasskeyPlacement {
    pub fn target(&self) -> PasskeyTarget {
        match &self.item_key {
            Some(key) => PasskeyTarget::Item(key.clone()),
            None => PasskeyTarget::NewLogin,
        }
    }
}

impl PasskeyChoices {
    /// Build the choices for registering `user_name` at `rp_id`.
    ///
    /// The suggested login is the one matching login whose username equals
    /// `user_name`. With none, or with several, nothing is suggested and "New
    /// login" in the default vault is preselected.
    pub fn build(
        rp_id: &str,
        user_name: &str,
        places: &[LoginPlace],
        vaults: Vec<PlacementVault>,
        write_vault: String,
    ) -> Self {
        let logins: Vec<PlacementLogin> = places_for_rp(places, rp_id)
            .into_iter()
            .map(|place| PlacementLogin {
                vault_key: place.vault_key.clone(),
                item_key: place.item_key.clone(),
                title: place.title.clone(),
                username: place.username.clone(),
            })
            .collect();

        let mut same_user = logins.iter().enumerate().filter(|(_, login)| {
            !user_name.is_empty() && login.username.as_deref() == Some(user_name)
        });
        let suggested = match (same_user.next(), same_user.next()) {
            (Some((index, _)), None) => Some(index),
            _ => None,
        };
        let default_vault = suggested
            .map(|index| logins[index].vault_key.clone())
            .unwrap_or(write_vault);
        Self {
            vaults,
            logins,
            default_vault,
            suggested,
        }
    }

    /// The placement when the user does not choose.
    pub fn default_placement(&self) -> PasskeyPlacement {
        match self.suggested {
            Some(index) => PasskeyPlacement {
                vault_key: self.logins[index].vault_key.clone(),
                item_key: Some(self.logins[index].item_key.clone()),
            },
            None => PasskeyPlacement {
                vault_key: self.default_vault.clone(),
                item_key: None,
            },
        }
    }

    /// Accept `placement` only when the prompt offered it. With no vaults yet
    /// the default vault is the one a write creates, so it is accepted.
    pub fn validate(&self, placement: PasskeyPlacement) -> Result<PasskeyPlacement, String> {
        let vault_offered = placement.vault_key == self.default_vault
            || self.vaults.iter().any(|v| v.key == placement.vault_key);
        if !vault_offered {
            return Err(format!(
                "Vault {} was not offered for the passkey",
                placement.vault_key
            ));
        }
        if let Some(item_key) = &placement.item_key {
            let offered = self
                .logins
                .iter()
                .any(|l| l.vault_key == placement.vault_key && &l.item_key == item_key);
            if !offered {
                return Err(format!("Item {item_key} was not offered for the passkey"));
            }
        }
        Ok(placement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::vaults::{MatchKind, Website};

    fn place(vault: &str, item: &str, user: Option<&str>, site: &str) -> LoginPlace {
        LoginPlace {
            vault_key: vault.to_string(),
            item_key: item.to_string(),
            title: item.to_string(),
            username: user.map(String::from),
            websites: vec![Website::new(site, MatchKind::Domain)],
        }
    }

    fn vaults() -> Vec<PlacementVault> {
        ["personal", "work"]
            .into_iter()
            .map(|key| PlacementVault {
                key: key.to_string(),
                name: None,
            })
            .collect()
    }

    fn build(user: &str, places: &[LoginPlace]) -> PasskeyChoices {
        PasskeyChoices::build(
            "example.com",
            user,
            places,
            vaults(),
            "personal".to_string(),
        )
    }

    #[test]
    fn suggests_the_one_login_with_the_same_username() {
        let places = [
            place("personal", "a", Some("ada"), "example.com"),
            place("work", "b", Some("grace"), "login.example.com"),
            place("work", "c", Some("ada"), "other.com"),
        ];
        let choices = build("grace", &places);
        assert_eq!(choices.logins.len(), 2);
        assert_eq!(choices.suggested, Some(1));
        assert_eq!(choices.default_vault, "work");
        assert_eq!(
            choices.default_placement(),
            PasskeyPlacement {
                vault_key: "work".to_string(),
                item_key: Some("b".to_string()),
            }
        );
    }

    #[test]
    fn suggests_nothing_for_several_matches_or_none() {
        let places = [
            place("personal", "a", Some("ada"), "example.com"),
            place("work", "b", Some("ada"), "example.com"),
        ];
        let several = build("ada", &places);
        assert_eq!(several.suggested, None);
        assert_eq!(several.default_vault, "personal");
        assert_eq!(several.default_placement().item_key, None);

        let none = build("grace", &places);
        assert_eq!(none.suggested, None);
    }

    #[test]
    fn a_login_for_another_site_is_not_offered() {
        let places = [place("personal", "a", Some("ada"), "evil.com")];
        assert!(build("ada", &places).logins.is_empty());
    }

    #[test]
    fn validation_accepts_only_offered_choices() {
        let places = [place("personal", "a", Some("ada"), "example.com")];
        let choices = build("ada", &places);
        let choice = |vault: &str, item: Option<&str>| PasskeyPlacement {
            vault_key: vault.to_string(),
            item_key: item.map(String::from),
        };

        assert!(choices.validate(choice("work", None)).is_ok());
        assert!(choices.validate(choice("personal", Some("a"))).is_ok());
        assert!(choices.validate(choice("elsewhere", None)).is_err());
        // The item exists in another vault, but was not offered in this one.
        assert!(choices.validate(choice("work", Some("a"))).is_err());
        assert!(choices.validate(choice("personal", Some("zzz"))).is_err());
    }
}
