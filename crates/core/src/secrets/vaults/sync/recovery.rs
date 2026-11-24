//! Age recovery kit, recovery recipients, and their `Age` wrappings.
//!
//! A kit holds an age identity, the vault id, the key id, and the fingerprint
//! of the sync key it was made for. Creating a kit writes nothing. After the
//! user confirms that the kit is saved, [`RecoveryKit::confirm_saved`] writes
//! the recipient into the `recovery` map of the sync state (D18). The value
//! holds the key id, the fingerprint, and the label of
//! [`RecoveryKit::labeled`], if any.
//!
//! Each transaction that syncs and has a transport adds to the own `key.json`
//! an `Age` wrapping of the current key for each recipient that the file lacks
//! (decision 13). A recipient counts if any value of its register holds the
//! current key id and the fingerprint of the current key in all 16 bytes. The
//! same rule decides the degraded state, `Committed::recovery_kit_missing`.
//!
//! The `recovery` map holds one kit. Adding a kit removes the other entries
//! in the same write, so the new kit replaces the earlier one. Kits added
//! concurrently on two Macs can both remain until one is replaced.
//!
//! A kit is revoked by removing its entry from the map, with
//! `SyncRequest::RemoveRecovery` or with a rotation whose plan revokes it
//! (`sync/rotation.rs`). The transaction drops from the own `key.json` the
//! `Age` wrappings of each recipient the map no longer holds. A removal
//! without a rotation leaves the kit able to open the current key, since a
//! copy can remain in the `key.json` of another replica, in a sync service,
//! or in a backup. After a rotation the kit does not open the new key.
//!
//! The kit text (D19) is five lines, in this order:
//!
//! ```text
//! Axo Pass recovery kit
//! Vault: 6f1c2b9e-0d4a-4c1e-9b7a-3e2f1d0c9b8a
//! Key id: 1
//! Fingerprint: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX
//! AGE-SECRET-KEY-1...
//! ```
//!
//! The fingerprint is the 16 bytes in Crockford base32, in groups of 4. The
//! parser trims each line and skips blank lines. It refuses any other title,
//! a label that is missing, repeated, or out of order, any other line, a
//! vault id that is not a UUID, a key id that is not a decimal number above
//! 0, a fingerprint that does not decode to 16 bytes, and an identity that
//! age refuses. Core does not write the kit to disk.

pub mod import;

use std::fmt;
use std::str::FromStr;

use secrecy::ExposeSecret;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::keys::{KeyFingerprint, SyncKey, SyncKeyring};
use super::model::{KeyId, RecoveryRecipient, SyncState};
use super::repair::SyncRequest;
use super::wrapping::base32::Crockford;
use super::wrapping::{AgeWrapping, KeyFile, Wrapping};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};

/// Title line of the kit text.
const TITLE: &str = "Axo Pass recovery kit";
const VAULT_LABEL: &str = "Vault: ";
const KEY_ID_LABEL: &str = "Key id: ";
const FINGERPRINT_LABEL: &str = "Fingerprint: ";

/// Age recovery kit of one vault and one sync key.
pub struct RecoveryKit {
    identity: age::x25519::Identity,
    pub vault_id: Uuid,
    pub key_id: KeyId,
    /// Fingerprint of the key, as printed in the kit.
    pub fingerprint: KeyFingerprint,
    /// Label written with the recipient. Not part of the kit text, so a
    /// parsed kit has none.
    pub label: Option<String>,
}

/// Most characters of a kit label. A longer label is cut.
pub const MAX_LABEL_CHARS: usize = 100;

/// Label of the kit saved when sync is turned on. The setup does not ask
/// for one.
pub const SETUP_KIT_LABEL: &str = "Saved when sync was turned on";

impl RecoveryKit {
    /// New kit for `key` under `key_id` of vault `vault_id`, with a new age
    /// identity. Writes nothing.
    pub fn create(vault_id: Uuid, key_id: KeyId, key: &SyncKey) -> Self {
        Self {
            identity: age::x25519::Identity::generate(),
            vault_id,
            key_id,
            fingerprint: key.fingerprint(),
            label: None,
        }
    }

    /// Kit with the label `label`, trimmed and cut to [`MAX_LABEL_CHARS`]. An
    /// empty label is none.
    pub fn labeled(mut self, label: Option<&str>) -> Self {
        self.label = label
            .map(|label| {
                label
                    .trim()
                    .chars()
                    .take(MAX_LABEL_CHARS)
                    .collect::<String>()
            })
            .map(|label| label.trim_end().to_string())
            .filter(|label| !label.is_empty());
        self
    }

    /// Kit text of D19. Holds the age identity.
    pub fn text(&self) -> Zeroizing<String> {
        let vault_id = self.vault_id.hyphenated();
        let key_id = self.key_id.0;
        let fingerprint = Crockford::encode_grouped(&self.fingerprint.0, 4);
        let identity = self.identity.to_string();
        let identity = identity.expose_secret();
        Zeroizing::new(format!(
            "{TITLE}\n{VAULT_LABEL}{vault_id}\n{KEY_ID_LABEL}{key_id}\n\
             {FINGERPRINT_LABEL}{fingerprint}\n{identity}\n"
        ))
    }

    /// Kit of the kit text `text`. See the module comment for what is
    /// refused.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let malformed = |message: &str| Error::RecoveryKitMalformed(message.to_string());
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        let [title, vault_id, key_id, fingerprint, identity] = lines[..] else {
            return Err(malformed("kit does not hold five lines"));
        };
        if title != TITLE {
            return Err(malformed("first line is not the kit title"));
        }
        let field = Self::field;
        let vault_id = Uuid::try_parse(field(vault_id, VAULT_LABEL)?)
            .map_err(|_| malformed("vault id is not a UUID"))?;
        let key_id = field(key_id, KEY_ID_LABEL)?;
        let key_id = key_id
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| key_id.parse::<u32>().ok())
            .flatten()
            .filter(|key_id| *key_id > 0)
            .ok_or_else(|| malformed("key id is not a number above 0"))?;
        let fingerprint = Crockford::decode(field(fingerprint, FINGERPRINT_LABEL)?)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .ok_or_else(|| malformed("fingerprint is not 16 bytes of Crockford base32"))?;
        let identity = age::x25519::Identity::from_str(identity)
            .map_err(|_| malformed("last line is not an age identity"))?;
        Ok(Self {
            identity,
            vault_id,
            key_id: KeyId(key_id),
            fingerprint: KeyFingerprint(fingerprint),
            label: None,
        })
    }

    /// Value of the kit line `line` after its label `label`, trimmed.
    fn field<'a>(line: &'a str, label: &str) -> Result<&'a str, Error> {
        line.strip_prefix(label).map(str::trim).ok_or_else(|| {
            let label = label.trim();
            Error::RecoveryKitMalformed(format!("line does not start with {label}"))
        })
    }

    /// Age recipient of the kit, `age1...`.
    pub fn recipient(&self) -> String {
        self.identity.to_public().to_string()
    }

    pub(crate) fn identity(&self) -> &age::x25519::Identity {
        &self.identity
    }

    /// Value of the `recovery` register of the kit recipient, with the kit
    /// label.
    pub fn recipient_value(&self) -> RecoveryRecipient {
        RecoveryRecipient {
            key_id: self.key_id,
            key_fingerprint: self.fingerprint.0,
            label: self.label.clone(),
        }
    }

    /// Whether `key` is the key of the kit: its fingerprint equals the kit
    /// fingerprint in all 16 bytes.
    pub fn opens(&self, key: &SyncKey) -> bool {
        key.fingerprint() == self.fingerprint
    }

    /// Add the kit recipient to the `recovery` map of the vault `target`,
    /// after the user confirms that the kit is saved. Runs one transaction
    /// with [`SyncRequest::AddRecovery`], which mints one write id. Fails with
    /// `RecoveryKitNotAdded` and writes nothing if the vault has no trusted
    /// sync state, if sync does not run, if the kit is for another vault, or
    /// if the kit is not for the current key.
    pub fn confirm_saved(
        &self,
        writer: &VaultWriter,
        target: &Target,
        unlock: Unlock<'_>,
    ) -> Result<Committed<()>, Error> {
        let add = self.recovery_add();
        writer.write_as(target, unlock, SyncRequest::AddRecovery(add), |_| Ok(()))
    }

    /// Recipient of the kit, as a transaction writes it.
    pub(crate) fn recovery_add(&self) -> RecoveryAdd {
        RecoveryAdd {
            vault_id: self.vault_id,
            recipient: self.recipient(),
            value: self.recipient_value(),
        }
    }
}

/// `Debug` shows no identity.
impl fmt::Debug for RecoveryKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryKit")
            .field("vault_id", &self.vault_id)
            .field("key_id", &self.key_id)
            .field("fingerprint", &self.fingerprint)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// Recipient of a saved kit, as [`SyncRequest::AddRecovery`] writes it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RecoveryAdd {
    /// Vault of the kit.
    pub(crate) vault_id: Uuid,
    /// Age recipient, the key of the `recovery` map.
    pub(crate) recipient: String,
    pub(crate) value: RecoveryRecipient,
}

/// Recovery recipients of a sync state and their `Age` wrappings.
pub(crate) struct RecoveryRecipients;

impl RecoveryRecipients {
    /// Recipients of `state` that receive an `Age` wrapping of the key with
    /// id `key_id` and fingerprint `fingerprint`. A recipient counts if any
    /// value of its register holds that key id and fingerprint, so a
    /// concurrent value cannot hide a valid one. The fingerprint is compared
    /// in all 16 bytes.
    pub(crate) fn current(
        state: &SyncState,
        key_id: KeyId,
        fingerprint: &KeyFingerprint,
    ) -> Vec<String> {
        state
            .recovery
            .iter()
            .filter(|(_, register)| {
                register.values().any(|(_, v)| {
                    v.value.key_id == key_id && v.value.key_fingerprint == fingerprint.0
                })
            })
            .map(|(recipient, _)| recipient.clone())
            .collect()
    }

    /// [`Self::current`] for the key with id `key_id` in `keyring`, the key
    /// of the body of a sync state. Empty if `keyring` lacks the key.
    pub(crate) fn of_key(state: &SyncState, key_id: KeyId, keyring: &SyncKeyring) -> Vec<String> {
        match keyring.get(key_id) {
            Some(key) => Self::current(state, key_id, &key.fingerprint()),
            None => Vec::new(),
        }
    }

    /// Add to `file` an `Age` wrapping of `key` under `key_id` for each of
    /// `recipients` that it lacks. A wrapping with the recipient, the key id,
    /// and the fingerprint of `key` counts as present. A recipient that age
    /// refuses is skipped and logged. Returns the number of wrappings added.
    pub(crate) fn add_missing(
        file: &mut KeyFile,
        key_id: KeyId,
        key: &SyncKey,
        recipients: &[String],
    ) -> usize {
        let fingerprint = key.fingerprint();
        let mut added = 0;
        for recipient in recipients {
            let present = file.ages().any(|age| {
                age.recipient == *recipient
                    && age.key_id == key_id
                    && age.key_fingerprint == fingerprint
            });
            if present {
                continue;
            }
            match AgeWrapping::wrap(key_id, key, recipient) {
                Ok(wrapping) => {
                    file.wrappings.push(Wrapping::Age(wrapping));
                    added += 1;
                },
                Err(e) => log::warn!("Skipped the age wrapping of recipient {recipient}: {e}"),
            }
        }
        added
    }
}
