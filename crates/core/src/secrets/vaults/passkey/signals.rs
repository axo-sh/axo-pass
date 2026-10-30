//! Site reports about stored passkeys, from the WebAuthn Signal API.
//!
//! A site can report that a passkey is unknown to it, list the passkeys it
//! still accepts for an account, or report a new account name. The AutoFill
//! extension receives these in the background, with the vault locked.
//!
//! Each vault stores the reports about its own passkeys in its encrypted
//! metadata. A report that arrives while the vault is locked is held in memory
//! until the app next unlocks, then written into the vaults with passkeys for
//! that relying party. A report held in memory is lost if the app quits first.
//! Readers combine the vault store with the reports held in memory.
//!
//! Reports only mark passkeys. A rejected passkey is hidden from AutoFill and
//! shown with a notice, and a reported name is offered as a suggestion. Nothing
//! is deleted or renamed until the user acts. Credential ids and user handles
//! are base64url without padding, as in the passkey record.

use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};

use crate::secrets::vaults::passkey::StoredPasskey;

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
#[serde(deny_unknown_fields)]
pub(crate) struct UnknownEntry {
    pub(crate) rp_id: String,
    pub(crate) credential_id: String,
    pub(crate) at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptedEntry {
    pub(crate) rp_id: String,
    pub(crate) user_handle: String,
    pub(crate) credential_ids: Vec<String>,
    pub(crate) at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenameEntry {
    pub(crate) rp_id: String,
    pub(crate) user_handle: String,
    pub(crate) name: String,
    pub(crate) at: i64,
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
#[serde(deny_unknown_fields)]
pub(crate) struct DismissEntry {
    pub(crate) rp_id: String,
    pub(crate) credential_id: String,
    pub(crate) kind: DismissKind,
    pub(crate) at: i64,
}

/// Entry of one report list, as the sync model stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignalEntry {
    Unknown(UnknownEntry),
    Accepted(AcceptedEntry),
    Rename(RenameEntry),
    Dismissed(DismissEntry),
}

impl SignalEntry {
    /// Map key of the entry in the sync model. Report list name, then the
    /// fields that identify the report, joined by `:`. Two entries have one
    /// key if `SignalStore::merge` treats them as the same report.
    pub(crate) fn key(&self) -> String {
        match self {
            Self::Unknown(e) => e.key(),
            Self::Accepted(e) => e.key(),
            Self::Rename(e) => e.key(),
            Self::Dismissed(e) => e.key(),
        }
    }
}

/// All recorded reports and dismissals.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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

/// Reports received since they were last written into the vaults.
static PENDING: Mutex<SignalStore> = Mutex::new(SignalStore::new());

/// Hold a report made at `at` until the next unlock.
pub fn record_pending(report: Report, at: i64) {
    lock_pending().record(report, at);
}

/// Reports not yet written into the vaults.
pub fn pending() -> SignalStore {
    lock_pending().clone()
}

/// Drop the pending entries that `applied` holds, after they were written into
/// the vaults. Entries recorded since then stay pending.
pub fn clear_pending(applied: &SignalStore) {
    lock_pending().remove(applied);
}

/// `vault` combined with the reports held in memory.
pub fn effective(vault: &SignalStore) -> SignalStore {
    let mut store = vault.clone();
    store.merge(&lock_pending());
    store
}

fn lock_pending() -> std::sync::MutexGuard<'static, SignalStore> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

impl SignalStore {
    pub const fn new() -> Self {
        Self {
            unknown: Vec::new(),
            accepted: Vec::new(),
            renames: Vec::new(),
            dismissed: Vec::new(),
        }
    }

    /// Store with an entry in every list and a dismissal of every kind, for
    /// the vault schema snapshot. Built from struct literals, so a new field
    /// or kind fails to compile here until the sample sets it.
    #[cfg(test)]
    pub(crate) fn schema_sample_for_test() -> Self {
        // A new kind fails to compile here until it is added to `kinds`.
        let _ = |kind: DismissKind| match kind {
            DismissKind::Rejection | DismissKind::Rename => {},
        };
        let kinds = [DismissKind::Rejection, DismissKind::Rename];
        Self {
            unknown: vec![UnknownEntry {
                rp_id: "example.com".to_string(),
                credential_id: "AQID".to_string(),
                at: 1_700_000_001,
            }],
            accepted: vec![AcceptedEntry {
                rp_id: "example.com".to_string(),
                user_handle: "CQ".to_string(),
                credential_ids: vec!["AQID".to_string(), "BAUG".to_string()],
                at: 1_700_000_002,
            }],
            renames: vec![RenameEntry {
                rp_id: "example.com".to_string(),
                user_handle: "CQ".to_string(),
                name: "ada".to_string(),
                at: 1_700_000_003,
            }],
            dismissed: kinds
                .into_iter()
                .map(|kind| DismissEntry {
                    rp_id: "example.com".to_string(),
                    credential_id: "AQID".to_string(),
                    kind,
                    at: 1_700_000_004,
                })
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.unknown.is_empty()
            && self.accepted.is_empty()
            && self.renames.is_empty()
            && self.dismissed.is_empty()
    }

    /// Add the entries of `other`. An entry about the same credential or
    /// account replaces this one if it is at least as new. Returns whether the
    /// store changed.
    pub fn merge(&mut self, other: &SignalStore) -> bool {
        let unknown = merge_entries(&mut self.unknown, &other.unknown);
        let accepted = merge_entries(&mut self.accepted, &other.accepted);
        let renames = merge_entries(&mut self.renames, &other.renames);
        let dismissed = merge_entries(&mut self.dismissed, &other.dismissed);
        unknown || accepted || renames || dismissed
    }

    /// Add `entry` with the entry rule of [`Self::merge`], without the trim.
    pub(crate) fn add_untrimmed(&mut self, entry: &SignalEntry) {
        match entry {
            SignalEntry::Unknown(e) => merge_entry(&mut self.unknown, e),
            SignalEntry::Accepted(e) => merge_entry(&mut self.accepted, e),
            SignalEntry::Rename(e) => merge_entry(&mut self.renames, e),
            SignalEntry::Dismissed(e) => merge_entry(&mut self.dismissed, e),
        };
    }

    /// Order each list by report time, then by [`SignalEntry::key`].
    pub(crate) fn sort_lists(&mut self) {
        sort_entries(&mut self.unknown);
        sort_entries(&mut self.accepted);
        sort_entries(&mut self.renames);
        sort_entries(&mut self.dismissed);
    }

    /// Entries of every list, in list order. Lists are in field order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = SignalEntry> + '_ {
        let unknown = self.unknown.iter().cloned().map(SignalEntry::Unknown);
        let accepted = self.accepted.iter().cloned().map(SignalEntry::Accepted);
        let renames = self.renames.iter().cloned().map(SignalEntry::Rename);
        let dismissed = self.dismissed.iter().cloned().map(SignalEntry::Dismissed);
        unknown.chain(accepted).chain(renames).chain(dismissed)
    }

    /// Remove the entries equal to one in `other`.
    pub fn remove(&mut self, other: &SignalStore) {
        self.unknown.retain(|e| !other.unknown.contains(e));
        self.accepted.retain(|e| !other.accepted.contains(e));
        self.renames.retain(|e| !other.renames.contains(e));
        self.dismissed.retain(|e| !other.dismissed.contains(e));
    }

    /// Keep only the entries whose relying party passes `keep`.
    pub fn retain_rp(&mut self, keep: impl Fn(&str) -> bool) {
        self.unknown.retain(|e| keep(&e.rp_id));
        self.accepted.retain(|e| keep(&e.rp_id));
        self.renames.retain(|e| keep(&e.rp_id));
        self.dismissed.retain(|e| keep(&e.rp_id));
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

/// Entry of one report list.
trait ListEntry: Clone + PartialEq {
    /// Report time.
    fn at(&self) -> i64;

    /// Whether `other` is about the same credential or account.
    fn same_report(&self, other: &Self) -> bool;

    /// Map key of the entry in the sync model. See [`SignalEntry::key`].
    fn key(&self) -> String;
}

impl ListEntry for UnknownEntry {
    fn at(&self) -> i64 {
        self.at
    }

    fn same_report(&self, other: &Self) -> bool {
        self.rp_id == other.rp_id && self.credential_id == other.credential_id
    }

    fn key(&self) -> String {
        format!("unknown:{}:{}", self.rp_id, self.credential_id)
    }
}

impl ListEntry for AcceptedEntry {
    fn at(&self) -> i64 {
        self.at
    }

    fn same_report(&self, other: &Self) -> bool {
        self.rp_id == other.rp_id && self.user_handle == other.user_handle
    }

    fn key(&self) -> String {
        format!("accepted:{}:{}", self.rp_id, self.user_handle)
    }
}

impl ListEntry for RenameEntry {
    fn at(&self) -> i64 {
        self.at
    }

    fn same_report(&self, other: &Self) -> bool {
        self.rp_id == other.rp_id && self.user_handle == other.user_handle
    }

    fn key(&self) -> String {
        format!("renames:{}:{}", self.rp_id, self.user_handle)
    }
}

impl ListEntry for DismissEntry {
    fn at(&self) -> i64 {
        self.at
    }

    fn same_report(&self, other: &Self) -> bool {
        self.rp_id == other.rp_id
            && self.credential_id == other.credential_id
            && self.kind == other.kind
    }

    fn key(&self) -> String {
        let kind = match self.kind {
            DismissKind::Rejection => "rejection",
            DismissKind::Rename => "rename",
        };
        format!("dismissed:{kind}:{}:{}", self.rp_id, self.credential_id)
    }
}

/// Add `from` to `into` with [`merge_entry`], then trim. Returns whether
/// `into` changed.
fn merge_entries<T: ListEntry>(into: &mut Vec<T>, from: &[T]) -> bool {
    let mut changed = false;
    for entry in from {
        changed |= merge_entry(into, entry);
    }
    trim(into);
    changed
}

/// Add `entry` to `into`. An entry about the same report is replaced if the
/// new one is at least as new and differs. Returns whether `into` changed.
fn merge_entry<T: ListEntry>(into: &mut Vec<T>, entry: &T) -> bool {
    match into.iter().position(|existing| existing.same_report(entry)) {
        Some(index) if entry.at() >= into[index].at() && into[index] != *entry => {
            into.remove(index);
            into.push(entry.clone());
            true
        },
        Some(_) => false,
        None => {
            into.push(entry.clone());
            true
        },
    }
}

/// Order `entries` by report time, then by key.
fn sort_entries<T: ListEntry>(entries: &mut [T]) {
    entries.sort_by_cached_key(|e| (e.at(), e.key()));
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
    fn report_entries_with_unknown_field_are_refused() {
        let entries = [
            (
                "unknown",
                serde_json::json!({"rp_id": RP, "credential_id": "AQ", "at": 1}),
            ),
            (
                "accepted",
                serde_json::json!({
                    "rp_id": RP, "user_handle": "CQ", "credential_ids": ["AQ"], "at": 1
                }),
            ),
            (
                "renames",
                serde_json::json!({"rp_id": RP, "user_handle": "CQ", "name": "ada", "at": 1}),
            ),
            (
                "dismissed",
                serde_json::json!({
                    "rp_id": RP, "credential_id": "AQ", "kind": "rejection", "at": 1
                }),
            ),
        ];
        for (list, entry) in entries {
            let store = serde_json::json!({ list: [entry.clone()] });
            assert!(
                serde_json::from_value::<SignalStore>(store).is_ok(),
                "{list}"
            );

            let mut extra = entry;
            extra["x"] = serde_json::json!(1);
            let store = serde_json::json!({ list: [extra] });
            assert!(
                serde_json::from_value::<SignalStore>(store).is_err(),
                "{list}"
            );
        }
        let store = serde_json::json!({"x": []});
        assert!(serde_json::from_value::<SignalStore>(store).is_err());
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
    fn merge_keeps_the_newer_entry() {
        let unknown = |at| {
            let mut store = SignalStore::default();
            store.record(
                Report::Unknown {
                    rp_id: RP.into(),
                    credential_id: vec![1],
                },
                at,
            );
            store
        };
        let mut store = unknown(10);
        assert!(store.merge(&unknown(20)));
        assert_eq!(store.unknown.len(), 1);
        assert_eq!(store.unknown[0].at, 20);

        assert!(!store.merge(&unknown(5)));
        assert!(!store.merge(&unknown(20)));
        assert_eq!(store.unknown.len(), 1);
        assert_eq!(store.unknown[0].at, 20);

        let mut other = SignalStore::default();
        other.dismiss(RP, &id(&[1]), DismissKind::Rejection, 25);
        assert!(store.merge(&other));
        let (a, user) = (id(&[1]), id(&[9]));
        assert!(!store.status(passkey(&a, &user)).rejected);
    }

    #[test]
    fn remove_drops_only_equal_entries() {
        let mut store = SignalStore::default();
        store.record(
            Report::Unknown {
                rp_id: RP.into(),
                credential_id: vec![1],
            },
            10,
        );
        let applied = store.clone();
        store.record(
            Report::Unknown {
                rp_id: RP.into(),
                credential_id: vec![2],
            },
            20,
        );
        store.remove(&applied);
        assert_eq!(store.unknown.len(), 1);
        assert_eq!(store.unknown[0].credential_id, id(&[2]));
    }

    #[test]
    fn retain_rp_keeps_only_the_named_sites() {
        let mut store = SignalStore::default();
        for rp_id in [RP, "other.com"] {
            store.record(
                Report::Unknown {
                    rp_id: rp_id.into(),
                    credential_id: vec![1],
                },
                10,
            );
        }
        store.retain_rp(|rp_id| rp_id == RP);
        assert_eq!(store.unknown.len(), 1);
        assert_eq!(store.unknown[0].rp_id, RP);
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
