mod keys;
mod round_trip;
mod trash;

use secrecy::SecretString;
use uuid::Uuid;

use super::view::State;
use super::{NOW, session};
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::passkey::signals::Report;
use crate::secrets::vaults::sync::apply::ApplyReport;
use crate::secrets::vaults::sync::crdt::Session;
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::view::VaultView;

/// Vault, sync state, and session of one Mac.
pub(super) struct Mac {
    pub(super) vault: Vault,
    pub(super) state: State,
    pub(super) session: Session,
}

impl Mac {
    /// Mac of replica 1 whose state is recorded from `vault`.
    pub(super) fn first(vault: Vault) -> Self {
        let mut mac = Self {
            vault,
            state: State::default(),
            session: session(1),
        };
        let edits = mac.find();
        edits.record(&mut mac.state, &mut mac.session, NOW);
        mac
    }

    /// Mac of replica `n` with an empty vault and state.
    pub(super) fn empty(n: u128) -> Self {
        Self {
            vault: Vault::new_for_test(),
            state: State::default(),
            session: session(n),
        }
    }

    /// Mac of replica `n` with an empty vault, joined with `other`.
    pub(super) fn joined(other: &Mac, n: u128) -> Self {
        let mut mac = Self::empty(n);
        mac.join(other);
        mac
    }

    pub(super) fn find(&self) -> LocalEdits {
        LocalEdits::find(&self.state, &self.vault, self.session.replica).unwrap()
    }

    pub(super) fn assert_no_edits(&self, vault: &Vault) {
        let edits = LocalEdits::find(&self.state, vault, self.session.replica).unwrap();
        assert!(edits.is_empty(), "{:?}", edits.edits());
    }

    /// Apply a local change to the vault and record its edits, which must
    /// not be empty.
    pub(super) fn edit(&mut self, change: impl FnOnce(&mut Vault)) {
        change(&mut self.vault);
        let edits = self.find();
        assert!(!edits.is_empty());
        edits.record(&mut self.state, &mut self.session, NOW);
    }

    /// Join the state of `other` and apply the view.
    pub(super) fn join(&mut self, other: &Mac) -> ApplyReport {
        self.state.join(other.state.clone());
        self.apply()
    }

    /// Apply the view of the state, and check that the vault then has no
    /// edits, also after a save and reload.
    pub(super) fn apply(&mut self) -> ApplyReport {
        let report = VaultView::of(&self.state).apply(&mut self.vault).unwrap();
        self.assert_no_edits(&self.vault);
        self.assert_no_edits(&reload(&self.vault));
        report
    }

    pub(super) fn view(&self) -> VaultView {
        VaultView::of(&self.state)
    }
}

/// Save and load a vault under its own key.
pub(super) fn reload(vault: &Vault) -> Vault {
    let cipher = vault.unlocked_key().cipher_for_test();
    Vault::from_encrypted_with_cipher(cipher, vault.to_encrypted(true).unwrap()).unwrap()
}

/// Join each Mac with the other, and check that both show the same view and
/// that each vault holds it.
pub(super) fn sync(a: &mut Mac, b: &mut Mac) -> (ApplyReport, ApplyReport) {
    let report_a = a.join(b);
    let report_b = b.join(a);
    assert_eq!(a.view(), b.view());
    a.assert_no_edits(&b.vault);
    b.assert_no_edits(&a.vault);
    (report_a, report_b)
}

pub(super) fn filled() -> Vault {
    let mut vault = Vault::new_for_test();
    vault.fill_for_test();
    vault
}

fn add_item(vault: &mut Vault, key: &str) -> Uuid {
    vault.add_or_update_item(key, "Item").unwrap().id
}

pub(super) fn add_credential(vault: &mut Vault, item: &str, key: &str, value: &str) -> Uuid {
    vault
        .add_or_update_item_credential(
            item,
            key,
            &key.to_uppercase(),
            FieldKind::default(),
            SecretString::from(value.to_string()),
        )
        .unwrap()
        .id
}

fn report(n: u32) -> Report {
    Report::Unknown {
        rp_id: "example.com".to_string(),
        credential_id: n.to_be_bytes().to_vec(),
    }
}
