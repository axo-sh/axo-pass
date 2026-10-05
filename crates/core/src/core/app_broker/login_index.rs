//! The logins the app indexed at its last unlock, kept in memory so a client
//! can list the accounts for a page without raising a prompt.
//!
//! The index holds what the AutoFill identity store already holds: record ids,
//! titles, account names, and websites. It never holds a password. It lives
//! only in this process, so after a cold start nothing is indexed until the app
//! unlocks, and [`LoginIndex::lookup`] says so rather than answering with an
//! empty list.

use std::sync::Mutex;

use crate::secrets::vaults::autofill::{self, AutofillItem, LoginSummary};

#[derive(Default)]
pub struct LoginIndex {
    /// `None` until the first [`LoginIndex::replace`].
    items: Mutex<Option<Vec<AutofillItem>>>,
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
            websites_from_url_fields: false,
            matched: None,
        }
    }

    #[test]
    fn nothing_is_indexed_before_the_first_replace() {
        let index = LoginIndex::default();
        assert!(index.lookup("https://github.com").is_none());

        index.upsert(login("a", "GitHub", "github.com"));
        assert!(index.lookup("https://github.com").is_none());
    }

    #[test]
    fn lookup_returns_only_the_logins_for_the_page() {
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
    fn upsert_replaces_a_login_with_the_same_record_id() {
        let index = LoginIndex::default();
        index.replace(vec![login("a", "GitHub", "github.com")]);

        index.upsert(login("a", "GitHub 2", "github.com"));
        index.upsert(login("b", "Gist", "github.com"));

        let found = index.lookup("https://github.com").unwrap();
        let titles: Vec<_> = found.iter().map(|l| l.title.as_str()).collect();
        assert_eq!(titles, ["Gist", "GitHub 2"]);
    }
}
