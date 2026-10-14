//! Site reports about stored passkeys, from the WebAuthn Signal API.
//!
//! A site can report that a passkey is unknown to it, list the passkeys it
//! still accepts for an account, or report a new account name. The AutoFill
//! extension receives these in the background, with the vault locked, so they
//! are kept outside the vault in `<app data>/passkey-signals.json`.
//!
//! The file holds relying party ids, credential ids, user handles, and account
//! names. The AutoFill identity store already holds the same values. It never
//! holds key material.
//!
//! Reports only mark passkeys. A rejected passkey is hidden from AutoFill and
//! shown with a notice, and a reported name is offered as a suggestion. Nothing
//! is deleted or renamed until the user acts. Credential ids and user handles
//! are base64url without padding, as in the passkey record.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};

use crate::core::dirs::app_data_dir;
use crate::secrets::vaults::passkey::StoredPasskey;
use crate::secrets::vaults::vault_wrapper::write_atomic;

/// Most entries kept in each report list. The oldest are dropped first.
const MAX_ENTRIES: usize = 500;

/// One report from a site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// The site does not know this credential.
    Unknown {
        rp_id: String,
        credential_id: Vec<u8>,
    },
    /// The credentials the site accepts for one account. Others for the same
    /// account are rejected.
    AllAccepted {
        rp_id: String,
        user_handle: Vec<u8>,
        credential_ids: Vec<Vec<u8>>,
    },
    /// The account has a new name.
    Renamed {
        rp_id: String,
        user_handle: Vec<u8>,
        name: String,
    },
}

/// What site reports say about one passkey.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasskeyStatus {
    /// The site no longer accepts the passkey.
    pub rejected: bool,
    /// A new account name the site reported, when it differs from the stored
    /// one.
    pub suggested_name: Option<String>,
}

/// The identifying fields of a stored passkey, as in its summary.
#[derive(Debug, Clone, Copy)]
pub struct PasskeyRef<'a> {
    pub rp_id: &'a str,
    pub credential_id: &'a str,
    pub user_handle: Option<&'a str>,
    pub current_name: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UnknownEntry {
    rp_id: String,
    credential_id: String,
    at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AcceptedEntry {
    rp_id: String,
    user_handle: String,
    credential_ids: Vec<String>,
    at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RenameEntry {
    rp_id: String,
    user_handle: String,
    name: String,
    at: i64,
}

/// What the user dismissed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DismissKind {
    /// Keep a passkey the site rejected.
    Rejection,
    /// Ignore a reported name.
    Rename,
}

/// A dismissal applies to reports made at or before `at`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DismissEntry {
    rp_id: String,
    credential_id: String,
    kind: DismissKind,
    at: i64,
}

/// All recorded reports and dismissals.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignalStore {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unknown: Vec<UnknownEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    accepted: Vec<AcceptedEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    renames: Vec<RenameEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    dismissed: Vec<DismissEntry>,
}

/// Location of the store. `AXO_PASS_SIGNALS_PATH` overrides it, for tests.
pub fn signals_path() -> PathBuf {
    if let Some(path) = std::env::var_os("AXO_PASS_SIGNALS_PATH") {
        return PathBuf::from(path);
    }
    app_data_dir().join("passkey-signals.json")
}

/// Serializes changes to the store file within this process. Only the app
/// writes it.
static UPDATE_LOCK: Mutex<()> = Mutex::new(());

impl SignalStore {
    /// Load the store. A missing or unreadable file gives an empty store, and
    /// an unreadable one is logged.
    pub fn load() -> Self {
        Self::load_from(&signals_path())
    }

    /// Load the store, apply `change`, and save it.
    pub fn update<R>(change: impl FnOnce(&mut SignalStore) -> R) -> std::io::Result<R> {
        let _guard = UPDATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = signals_path();
        let mut store = Self::load_from(&path);
        let result = change(&mut store);
        store.save_to(&path)?;
        Ok(result)
    }

    pub fn load_from(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                log::error!("Ignoring unreadable passkey signals file: {e}");
                Self::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                log::error!("Failed to read the passkey signals file: {e}");
                Self::default()
            },
        }
    }

    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_atomic(path, text.as_bytes())?;
        set_owner_only(path)
    }

    /// Record a report made at `at`. A newer report replaces an older one
    /// about the same credential or account.
    pub fn record(&mut self, report: Report, at: i64) {
        match report {
            Report::Unknown {
                rp_id,
                credential_id,
            } => {
                let credential_id = B64URL.encode(credential_id);
                self.unknown
                    .retain(|e| !(e.rp_id == rp_id && e.credential_id == credential_id));
                self.unknown.push(UnknownEntry {
                    rp_id,
                    credential_id,
                    at,
                });
                trim(&mut self.unknown);
            },
            Report::AllAccepted {
                rp_id,
                user_handle,
                credential_ids,
            } => {
                let user_handle = B64URL.encode(user_handle);
                self.accepted
                    .retain(|e| !(e.rp_id == rp_id && e.user_handle == user_handle));
                self.accepted.push(AcceptedEntry {
                    rp_id,
                    user_handle,
                    credential_ids: credential_ids.iter().map(|id| B64URL.encode(id)).collect(),
                    at,
                });
                trim(&mut self.accepted);
            },
            Report::Renamed {
                rp_id,
                user_handle,
                name,
            } => {
                let user_handle = B64URL.encode(user_handle);
                let name = name.trim().to_string();
                self.renames
                    .retain(|e| !(e.rp_id == rp_id && e.user_handle == user_handle));
                if !name.is_empty() {
                    self.renames.push(RenameEntry {
                        rp_id,
                        user_handle,
                        name,
                        at,
                    });
                    trim(&mut self.renames);
                }
            },
        }
    }

    /// Dismiss what the reports so far say about one passkey. A later report
    /// marks it again.
    pub fn dismiss(&mut self, rp_id: &str, credential_id: &str, kind: DismissKind, at: i64) {
        self.dismissed
            .retain(|e| !(e.rp_id == rp_id && e.credential_id == credential_id && e.kind == kind));
        self.dismissed.push(DismissEntry {
            rp_id: rp_id.to_string(),
            credential_id: credential_id.to_string(),
            kind,
            at,
        });
        trim(&mut self.dismissed);
    }

    /// What the reports say about one passkey.
    pub fn status(&self, passkey: PasskeyRef<'_>) -> PasskeyStatus {
        PasskeyStatus {
            rejected: self
                .rejected_at(passkey)
                .is_some_and(|at| !self.is_dismissed(passkey, DismissKind::Rejection, at)),
            suggested_name: self.suggested_name(passkey),
        }
    }

    /// Whether the site no longer accepts a stored passkey.
    pub fn rejects(&self, stored: &StoredPasskey) -> bool {
        let credential_id = B64URL.encode(stored.passkey.credential_id.as_slice());
        let user_handle = stored
            .passkey
            .user_handle
            .as_ref()
            .map(|h| B64URL.encode(h.as_slice()));
        self.status(PasskeyRef {
            rp_id: &stored.passkey.rp_id,
            credential_id: &credential_id,
            user_handle: user_handle.as_deref(),
            current_name: None,
        })
        .rejected
    }

    /// Latest account listing for the passkey's account.
    fn account_listing(&self, passkey: PasskeyRef<'_>) -> Option<&AcceptedEntry> {
        let user_handle = passkey.user_handle?;
        self.accepted
            .iter()
            .filter(|e| e.rp_id == passkey.rp_id && e.user_handle == user_handle)
            .max_by_key(|e| e.at)
    }

    /// When the site last rejected the passkey, or `None` if it has not, or a
    /// later account listing includes it.
    fn rejected_at(&self, passkey: PasskeyRef<'_>) -> Option<i64> {
        let listing = self.account_listing(passkey);
        let listed = listing.map(|e| {
            (
                e.at,
                e.credential_ids
                    .iter()
                    .any(|id| id == passkey.credential_id),
            )
        });
        let unknown_at = self
            .unknown
            .iter()
            .filter(|e| e.rp_id == passkey.rp_id && e.credential_id == passkey.credential_id)
            .map(|e| e.at)
            .max();

        let from_unknown = match (unknown_at, listed) {
            (Some(at), Some((listed_at, true))) if listed_at >= at => None,
            (at, _) => at,
        };
        let from_listing = match listed {
            Some((at, false)) => Some(at),
            _ => None,
        };
        from_unknown.max(from_listing)
    }

    fn suggested_name(&self, passkey: PasskeyRef<'_>) -> Option<String> {
        let user_handle = passkey.user_handle?;
        let rename = self
            .renames
            .iter()
            .filter(|e| e.rp_id == passkey.rp_id && e.user_handle == user_handle)
            .max_by_key(|e| e.at)?;
        if Some(rename.name.as_str()) == passkey.current_name
            || self.is_dismissed(passkey, DismissKind::Rename, rename.at)
        {
            return None;
        }
        Some(rename.name.clone())
    }

    fn is_dismissed(&self, passkey: PasskeyRef<'_>, kind: DismissKind, reported_at: i64) -> bool {
        self.dismissed.iter().any(|e| {
            e.rp_id == passkey.rp_id
                && e.credential_id == passkey.credential_id
                && e.kind == kind
                && e.at >= reported_at
        })
    }
}

/// Drop the oldest entries past [`MAX_ENTRIES`]. Entries are appended in
/// report order.
fn trim<T>(entries: &mut Vec<T>) {
    if entries.len() > MAX_ENTRIES {
        let excess = entries.len() - MAX_ENTRIES;
        entries.drain(..excess);
    }
}

fn set_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RP: &str = "example.com";

    fn id(bytes: &[u8]) -> String {
        B64URL.encode(bytes)
    }

    fn passkey<'a>(credential_id: &'a str, user_handle: &'a str) -> PasskeyRef<'a> {
        PasskeyRef {
            rp_id: RP,
            credential_id,
            user_handle: Some(user_handle),
            current_name: Some("ada"),
        }
    }

    #[test]
    fn an_unknown_report_rejects_only_that_passkey() {
        let mut store = SignalStore::default();
        store.record(
            Report::Unknown {
                rp_id: RP.into(),
                credential_id: vec![1],
            },
            10,
        );
        let (a, b, user) = (id(&[1]), id(&[2]), id(&[9]));
        assert!(store.status(passkey(&a, &user)).rejected);
        assert!(!store.status(passkey(&b, &user)).rejected);
        let other_site = PasskeyRef {
            rp_id: "other.com",
            ..passkey(&a, &user)
        };
        assert!(!store.status(other_site).rejected);
    }

    #[test]
    fn an_account_listing_rejects_unlisted_passkeys_of_that_account() {
        let mut store = SignalStore::default();
        store.record(
            Report::AllAccepted {
                rp_id: RP.into(),
                user_handle: vec![9],
                credential_ids: vec![vec![1]],
            },
            10,
        );
        let (a, b, user, other_user) = (id(&[1]), id(&[2]), id(&[9]), id(&[8]));
        assert!(!store.status(passkey(&a, &user)).rejected);
        assert!(store.status(passkey(&b, &user)).rejected);
        assert!(!store.status(passkey(&b, &other_user)).rejected);
    }

    #[test]
    fn a_later_listing_that_includes_the_passkey_clears_an_unknown_report() {
        let mut store = SignalStore::default();
        let (a, user) = (id(&[1]), id(&[9]));
        store.record(
            Report::Unknown {
                rp_id: RP.into(),
                credential_id: vec![1],
            },
            10,
        );
        store.record(
            Report::AllAccepted {
                rp_id: RP.into(),
                user_handle: vec![9],
                credential_ids: vec![vec![1]],
            },
            20,
        );
        assert!(!store.status(passkey(&a, &user)).rejected);

        store.record(
            Report::Unknown {
                rp_id: RP.into(),
                credential_id: vec![1],
            },
            30,
        );
        assert!(store.status(passkey(&a, &user)).rejected);
    }

    #[test]
    fn a_dismissal_lasts_until_the_next_report() {
        let mut store = SignalStore::default();
        let (a, user) = (id(&[1]), id(&[9]));
        store.record(
            Report::Unknown {
                rp_id: RP.into(),
                credential_id: vec![1],
            },
            10,
        );
        store.dismiss(RP, &a, DismissKind::Rejection, 15);
        assert!(!store.status(passkey(&a, &user)).rejected);

        store.record(
            Report::Unknown {
                rp_id: RP.into(),
                credential_id: vec![1],
            },
            20,
        );
        assert!(store.status(passkey(&a, &user)).rejected);
    }

    #[test]
    fn a_rename_is_suggested_until_applied_or_dismissed() {
        let mut store = SignalStore::default();
        let (a, user) = (id(&[1]), id(&[9]));
        store.record(
            Report::Renamed {
                rp_id: RP.into(),
                user_handle: vec![9],
                name: " lovelace ".into(),
            },
            10,
        );
        assert_eq!(
            store.status(passkey(&a, &user)).suggested_name.as_deref(),
            Some("lovelace")
        );

        let applied = PasskeyRef {
            current_name: Some("lovelace"),
            ..passkey(&a, &user)
        };
        assert_eq!(store.status(applied).suggested_name, None);

        store.dismiss(RP, &a, DismissKind::Rename, 10);
        assert_eq!(store.status(passkey(&a, &user)).suggested_name, None);
    }

    #[test]
    fn the_store_round_trips_through_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signals.json");
        let mut store = SignalStore::default();
        store.record(
            Report::Unknown {
                rp_id: RP.into(),
                credential_id: vec![1],
            },
            10,
        );
        store.save_to(&path).unwrap();

        assert_eq!(SignalStore::load_from(&path), store);
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            SignalStore::load_from(&dir.path().join("missing.json")),
            SignalStore::default()
        );
    }

    #[test]
    fn report_lists_are_bounded() {
        let mut store = SignalStore::default();
        for n in 0..(MAX_ENTRIES + 10) {
            store.record(
                Report::Unknown {
                    rp_id: RP.into(),
                    credential_id: (n as u32).to_be_bytes().to_vec(),
                },
                n as i64,
            );
        }
        assert_eq!(store.unknown.len(), MAX_ENTRIES);
        assert_eq!(store.unknown[0].at, 10);
    }
}
