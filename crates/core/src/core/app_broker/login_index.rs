//! The logins the app indexed at its last unlock, kept in memory so a client
//! can list the accounts for a page without raising a prompt.
//!
//! The index holds what the AutoFill identity store already holds: record ids,
//! titles, account names, websites, and passkey relying parties, credential
//! ids, and account names. It never holds a password or a key. It lives
//! only in this process, so after a cold start nothing is indexed until the app
//! unlocks, and [`LoginIndex::lookup`] says so rather than answering with an
//! empty list.

use std::sync::Mutex;

use crate::secrets::vaults::autofill::{self, AutofillItem, LoginPlace, LoginSummary};

#[derive(Default)]
pub struct LoginIndex {
    /// `None` until the first [`LoginIndex::replace`].
    items: Mutex<Option<Vec<AutofillItem>>>,
    /// The login items a passkey may be stored in. `None` until the first
    /// [`LoginIndex::replace_places`].
    places: Mutex<Option<Vec<LoginPlace>>>,
    /// The passkeys the AutoFill extension may offer. `None` until the first
    /// [`LoginIndex::replace_passkeys`].
    passkeys: Mutex<Option<Vec<IndexedPasskey>>>,
}

/// One passkey in the index. Rejected passkeys are left out by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedPasskey {
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    pub user_name: String,
}

impl LoginIndex {
    /// Replace the whole index with the logins of every vault.
    pub fn replace(&self, items: Vec<AutofillItem>) {
        *self.lock() = Some(items);
    }

    /// Add `item`, or replace the indexed login with the same record id. Does
    /// nothing before the first [`LoginIndex::replace`], since a one-item index
    /// would pass for a complete one.
    pub fn upsert(&self, item: AutofillItem) {
        if let Some(items) = self.lock().as_mut() {
            match items.iter_mut().find(|i| i.record_id == item.record_id) {
                Some(existing) => *existing = item,
                None => items.push(item),
            }
        }
    }

    /// The indexed logins that match `frame_url`, best match first. `None` when
    /// nothing has been indexed yet.
    pub fn lookup(&self, frame_url: &str) -> Option<Vec<LoginSummary>> {
        let guard = self.lock();
        let items = guard.as_ref()?;
        let mut found: Vec<AutofillItem> = items
            .iter()
            .filter_map(|item| {
                let matched = autofill::match_service(&item.websites, frame_url)?;
                Some(AutofillItem {
                    matched: Some(matched),
                    ..item.clone()
                })
            })
            .collect();
        found.sort_by_key(AutofillItem::sort_key);
        Some(found.iter().filter_map(AutofillItem::summary).collect())
    }

    /// Replace the login items a passkey may be stored in.
    pub fn replace_places(&self, places: Vec<LoginPlace>) {
        *self.places.lock().unwrap_or_else(|e| e.into_inner()) = Some(places);
    }

    /// The indexed login items, or none before the first
    /// [`LoginIndex::replace_places`].
    pub fn places(&self) -> Vec<LoginPlace> {
        self.places
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_default()
    }

    /// Replace the indexed passkeys with the passkeys of every vault.
    pub fn replace_passkeys(&self, passkeys: Vec<IndexedPasskey>) {
        *self.passkeys.lock().unwrap_or_else(|e| e.into_inner()) = Some(passkeys);
    }

    /// The indexed passkeys of `rp_id`, sorted by account name. `None` when
    /// nothing has been indexed yet.
    pub fn passkeys_for(&self, rp_id: &str) -> Option<Vec<IndexedPasskey>> {
        let guard = self.passkeys.lock().unwrap_or_else(|e| e.into_inner());
        let mut found: Vec<IndexedPasskey> = guard
            .as_ref()?
            .iter()
            .filter(|p| p.rp_id == rp_id)
            .cloned()
            .collect();
        found.sort_by_key(|a| a.user_name.to_lowercase());
        found.dedup_by(|a, b| a.credential_id == b.credential_id);
        Some(found)
    }

    /// Account name of the one indexed passkey of `rp_id` that `allowed`
    /// permits. An empty `allowed` permits every passkey of the relying party.
    /// `None` if no passkey or several match, or the account name is empty.
    pub fn passkey_user_name(&self, rp_id: &str, allowed: &[Vec<u8>]) -> Option<String> {
        let mut found = self
            .passkeys_for(rp_id)?
            .into_iter()
            .filter(|p| allowed.is_empty() || allowed.contains(&p.credential_id));
        let only = found.next()?;
        if found.next().is_some() || only.user_name.is_empty() {
            return None;
        }
        Some(only.user_name)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Vec<AutofillItem>>> {
        self.items.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::vaults::{MatchKind, Website};

    fn login(record_id: &str, title: &str, site: &str) -> AutofillItem {
        AutofillItem {
            vault_key: "personal".to_string(),
            item_key: title.to_lowercase(),
            record_id: record_id.to_string(),
            title: title.to_string(),
            username: Some("tp".to_string()),
            password_key: "password".to_string(),
            websites: vec![Website::new(site, MatchKind::Domain)],
            has_totp: false,
            matched: None,
        }
    }

    #[test]
    fn nothing_indexed_before_first_replace() {
        let index = LoginIndex::default();
        assert!(index.lookup("https://github.com").is_none());

        index.upsert(login("a", "GitHub", "github.com"));
        assert!(index.lookup("https://github.com").is_none());
    }

    #[test]
    fn lookup_returns_only_logins_for_page() {
        let index = LoginIndex::default();
        index.replace(vec![
            login("a", "GitHub", "github.com"),
            login("b", "Example", "example.com"),
        ]);

        let found = index.lookup("https://gist.github.com/new").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].record_id, "a");
        assert_eq!(found[0].matched.host, "github.com");

        assert!(index.lookup("https://github.io").unwrap().is_empty());
    }

    #[test]
    fn upsert_replaces_login_with_same_record_id() {
        let index = LoginIndex::default();
        index.replace(vec![login("a", "GitHub", "github.com")]);

        index.upsert(login("a", "GitHub 2", "github.com"));
        index.upsert(login("b", "Gist", "github.com"));

        let found = index.lookup("https://github.com").unwrap();
        let titles: Vec<_> = found.iter().map(|l| l.title.as_str()).collect();
        assert_eq!(titles, ["Gist", "GitHub 2"]);
    }

    fn passkey(rp_id: &str, id: u8, user_name: &str) -> IndexedPasskey {
        IndexedPasskey {
            rp_id: rp_id.to_string(),
            credential_id: vec![id],
            user_name: user_name.to_string(),
        }
    }

    #[test]
    fn passkeys_for_returns_relying_party_passkeys_by_name() {
        let index = LoginIndex::default();
        assert!(index.passkeys_for("example.com").is_none());

        index.replace_passkeys(vec![
            passkey("example.com", 1, "wobby"),
            passkey("other.com", 2, "ada"),
            passkey("example.com", 3, "Webby"),
        ]);

        let found = index.passkeys_for("example.com").unwrap();
        let names: Vec<_> = found.iter().map(|p| p.user_name.as_str()).collect();
        assert_eq!(names, ["Webby", "wobby"]);
        assert!(index.passkeys_for("sub.example.com").unwrap().is_empty());
    }

    #[test]
    fn passkey_user_name_names_only_single_match() {
        let index = LoginIndex::default();
        assert_eq!(index.passkey_user_name("example.com", &[]), None);

        index.replace_passkeys(vec![
            passkey("example.com", 1, "wobby"),
            passkey("example.com", 2, "Webby"),
            passkey("example.com", 3, ""),
            passkey("other.com", 4, "ada"),
        ]);

        assert_eq!(
            index.passkey_user_name("example.com", &[vec![1]]),
            Some("wobby".to_string())
        );
        assert_eq!(
            index.passkey_user_name("example.com", &[vec![1], vec![2]]),
            None
        );
        assert_eq!(index.passkey_user_name("example.com", &[]), None);
        assert_eq!(index.passkey_user_name("example.com", &[vec![3]]), None);
        assert_eq!(index.passkey_user_name("example.com", &[vec![4]]), None);
        assert_eq!(
            index.passkey_user_name("other.com", &[]),
            Some("ada".to_string())
        );
    }
}
