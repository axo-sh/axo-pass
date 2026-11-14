use uuid::Uuid;

use super::{NOW, id, session};
use crate::secrets::vaults::autofill::item::{MatchKind, Role};
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::model::history::HistoryKind;
use crate::secrets::vaults::passkey::signals::{RenameEntry, Report, SignalEntry, SignalStore};
use crate::secrets::vaults::sync::crdt::{CausalState, Mint, MvRegister, Policy, ReplicaId};
use crate::secrets::vaults::sync::model::{
    FolderValue, HistoryValue, KeyId, Placement, PublicKey, RecoveryRecipient, Removal,
    ReplicaKeys, SecretText, SectionValue, SyncState, TrashValue, WebsiteValue,
};
use crate::secrets::vaults::sync::view::keys::{CREDENTIAL_KEY_PREFIX, ITEM_KEY_PREFIX, Suffix};
use crate::secrets::vaults::sync::view::{
    AskRegister, Conflict, Entity, RECOVERED_CREDENTIAL_TITLE, RECOVERED_ITEM_TITLE, VaultView,
};

mod conflicts;
mod merged;

pub(super) type State = CausalState<SyncState>;

/// State written by one mint of replica 1.
pub(super) fn base(edit: impl FnOnce(&mut SyncState, &Mint)) -> State {
    edited(&State::default(), 1, edit)
}

/// `state` after one mint of replica `n` that applies `edit`.
pub(super) fn edited(state: &State, n: u128, edit: impl FnOnce(&mut SyncState, &Mint)) -> State {
    let mut state = state.clone();
    let m = session(n).mint(&mut state, NOW);
    edit(&mut state.store, &m);
    state
}

/// Join of `a` and `b`, in both orders.
pub(super) fn join(a: &State, b: &State) -> (State, State) {
    let mut ab = a.clone();
    ab.join(b.clone());
    let mut ba = b.clone();
    ba.join(a.clone());
    (ab, ba)
}

/// View of `base` edited concurrently by replica 2 with `a` and by replica 3
/// with `b`. The view of the join is the same in both orders. Values of
/// replica 3 have the higher order key.
pub(super) fn concurrent(
    base: &State,
    a: impl FnOnce(&mut SyncState, &Mint),
    b: impl FnOnce(&mut SyncState, &Mint),
) -> (State, VaultView) {
    let (ab, ba) = join(&edited(base, 2, a), &edited(base, 3, b));
    let view = VaultView::of(&ab);
    assert_eq!(view, VaultView::of(&ba));
    (ab, view)
}

fn add_item(s: &mut SyncState, m: &Mint, item: Uuid) {
    let entry = s.items.entry(item);
    entry.title.write(m, "Item".to_string());
    entry.key.write(m, "item".to_string());
}

fn add_credential(s: &mut SyncState, m: &Mint, credential: Uuid, item: Uuid, title: &str) {
    let entry = s.credentials.entry(credential);
    entry.item.write(m, item);
    entry.title.write(m, title.to_string());
    entry.key.write(m, title.to_lowercase());
}

pub(super) fn trash(deleted_at: i64, role: Option<Role>) -> Option<TrashValue> {
    Some(TrashValue { deleted_at, role })
}

fn count<T, P: Policy>(register: &MvRegister<T, P>) -> usize {
    register.values().count()
}

fn rename(name: &str, at: i64) -> SignalEntry {
    SignalEntry::Rename(RenameEntry {
        rp_id: "example.com".to_string(),
        user_handle: "CQ".to_string(),
        name: name.to_string(),
        at,
    })
}
