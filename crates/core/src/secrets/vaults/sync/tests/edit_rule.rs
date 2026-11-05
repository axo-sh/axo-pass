//! MVP edit rule (milestone 8). Every write to an Ask register supersedes
//! every value of the register, from the UI and from every writer outside it.
//! Each credential value not chosen is written to `history` under its derived
//! id. The tests run each writer as a transaction of the 6b simulator.
//!
//! History id rewrite (9.1). The entry that a change adds for the replaced
//! shown value takes the id derived from the write id of that value.

use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::simulator::Sim;
use super::view::State;
use crate::secrets::vaults::autofill::{self, LoginWrite};
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::passkey::rename_account;
use crate::secrets::vaults::sync::crdt::WriteId;
use crate::secrets::vaults::sync::resolve::HistoryIds;
use crate::secrets::vaults::sync::view::{AskRegister, Conflict, Entity, VaultView};
use crate::secrets::vaults::{Error, MatchKind, VaultHandle};

const ITEM: &str = "mail";
const FIELD: &str = "password";

/// Passkey record with the account name `name`, in the field order that
/// `rename_account` writes. `rename_account` reads only its JSON fields, so
/// the key is not a valid COSE key.
fn passkey(name: &str) -> String {
    format!(
        r#"{{"rp_id":"example.com","credential_id":"AQID","username":"{name}","user_display_name":"{name}","key":"AAAA"}}"#
    )
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_string())
}

/// Id of the folder titled `title` in `vh`.
fn folder(vh: &VaultHandle, title: &str) -> Result<Uuid, Error> {
    let folders = vh.list_folders()?;
    let folder = folders.iter().find(|f| f.title == title);
    Ok(folder.expect("folder exists").id)
}

/// Item and credential ids of `mail/password` in `vault`.
fn ids(vault: &Vault) -> (Uuid, Uuid) {
    let item = *vault.get_item_id(ITEM).unwrap();
    let credential = vault.get_item_credential(ITEM, FIELD).unwrap().id;
    (item, credential)
}

/// Three Macs of one vault that holds `mail` with a credential `password` of
/// `kind`. Macs 0 and 1 write `values`, the item title, and the item folder
/// concurrently. Every Mac then holds the joined state, so the value and title
/// registers hold a conflict and the folder register holds two values.
fn conflicted(kind: FieldKind, first: &str, values: [&str; 2]) -> Sim {
    let mut sim = Sim::new(3, None);
    sim.write(0, |vh| {
        vh.add_item(ITEM, "Mail")?;
        vh.create_folder("A")?;
        vh.create_folder("B")?;
        vh.add_secret(ITEM, FIELD, "Password", kind.clone(), secret(first))
    });
    sim.converge();
    for (n, (title, folder_title)) in [("Zero", "A"), ("One", "B")].into_iter().enumerate() {
        let kind = kind.clone();
        sim.write(n, |vh| {
            let field_title = vh.get_secret_overview(ITEM, FIELD)?.unwrap().title.clone();
            vh.add_secret(ITEM, FIELD, &field_title, kind, secret(values[n]))?;
            let folder = folder(vh, folder_title)?;
            vh.move_item(ITEM, Some(folder))?;
            vh.add_item(ITEM, title).map(|_| ())
        });
    }
    sim.converge();

    let state = sim.check_converged();
    let (item, credential) = ids(&sim.macs[0].saved_vault());
    let conflicts = VaultView::of(&state).conflicts().to_vec();
    assert!(conflicts.contains(&value_conflict(credential)));
    assert!(conflicts.contains(&Conflict {
        entity: Entity::Item(item),
        register: AskRegister::Title,
    }));
    assert_eq!(
        state
            .store
            .items
            .get(&item)
            .unwrap()
            .folder
            .values()
            .count(),
        2
    );
    sim
}

fn value_conflict(credential: Uuid) -> Conflict {
    Conflict {
        entity: Entity::Credential(credential),
        register: AskRegister::Value,
    }
}

/// Values of the value register of `credential`, lowest order key first.
fn values(state: &State, credential: Uuid) -> Vec<(WriteId, String)> {
    let register = &state.store.credentials.get(&credential).unwrap().value;
    register
        .ordered()
        .into_iter()
        .map(|(key, v)| (key.write_id, v.value.0.as_str().to_string()))
        .collect()
}

/// History entries of `mail/password` in the saved vault of Mac `n`, by id.
fn history(sim: &Sim, n: usize) -> BTreeMap<Uuid, String> {
    let vault = sim.macs[n].saved_vault();
    vault
        .list_history(ITEM, FIELD)
        .unwrap()
        .into_iter()
        .map(|entry| {
            let value = vault.get_history_value(ITEM, FIELD, entry.id).unwrap();
            (entry.id, value.expose_secret().clone())
        })
        .collect()
}

/// Run `write` on Mac `n` of a [`conflicted`] simulator and check the edit
/// rule. The write sets the value to `written`. The value register then holds
/// only `written`, and each value not chosen is in `history` under its derived
/// id on every Mac. The shown value is added to history if `keeps_shown`, by
/// the vault mutation, and is the only other new entry. After the exchange,
/// no Mac shows a conflict on the value. Returns the converged state.
fn check_write(
    sim: &mut Sim,
    n: usize,
    written: &str,
    keeps_shown: bool,
    write: impl FnOnce(&mut VaultHandle) -> Result<(), Error>,
) -> State {
    let (_, credential) = ids(&sim.macs[n].saved_vault());
    let mut before = values(&sim.macs[n].state(), credential);
    let (_, shown) = before.pop().unwrap();
    let not_chosen: Vec<(Uuid, String)> = before
        .into_iter()
        .filter(|(_, value)| value != written && *value != shown)
        .map(|(write_id, value)| (HistoryIds::derive(credential, write_id), value))
        .collect();
    assert!(!not_chosen.is_empty());
    let history_before = history(sim, n);

    sim.write(n, write);

    let after = values(&sim.macs[n].state(), credential);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].1, written);
    let added: BTreeMap<Uuid, String> = history(sim, n)
        .into_iter()
        .filter(|(id, _)| !history_before.contains_key(id))
        .collect();
    for (id, value) in &not_chosen {
        assert_eq!(added.get(id), Some(value), "value not chosen is in history");
    }
    let others: Vec<&String> = added
        .iter()
        .filter(|(id, _)| !not_chosen.iter().any(|(derived, _)| derived == *id))
        .map(|(_, value)| value)
        .collect();
    if keeps_shown {
        assert_eq!(others, [&shown]);
    } else {
        assert!(others.is_empty(), "added {others:?}");
    }

    sim.converge();
    sim.check_quiet();
    let state = sim.check_converged();
    assert!(
        !VaultView::of(&state)
            .conflicts()
            .contains(&value_conflict(credential))
    );
    for m in 0..sim.macs.len() {
        let history = history(sim, m);
        for (id, value) in &not_chosen {
            assert_eq!(history.get(id), Some(value), "Mac {m}");
        }
    }
    state
}

#[test]
fn edit_from_ui_to_ask_register_with_conflict_supersedes_every_value_and_clears_conflict_on_every_mac()
 {
    let mut sim = conflicted(FieldKind::default(), "first", ["zero", "one"]);

    // Mac 2 saw both values and wrote neither. The edit view writes the title
    // and the value of the shown credential.
    let state = check_write(&mut sim, 2, "two", true, |vh| {
        vh.add_item(ITEM, "Two")?;
        vh.add_secret(ITEM, FIELD, "Password", FieldKind::default(), secret("two"))
    });

    assert!(VaultView::of(&state).conflicts().is_empty());
    let (item, _) = ids(&sim.macs[0].saved_vault());
    assert_eq!(
        state.store.items.get(&item).unwrap().title.values().count(),
        1
    );
}

#[test]
fn writer_outside_ui_to_ask_register_with_conflict_supersedes_every_value_and_order_write_succeeds()
{
    type Write = Box<dyn FnOnce(&mut VaultHandle) -> Result<(), Error>>;
    let broker: Write = Box::new(|vh| {
        // `ap` and the broker `WriteSecret` request keep the kind.
        let kind = vh.get_secret_overview(ITEM, FIELD)?.unwrap().kind.clone();
        vh.add_secret(ITEM, FIELD, "Password", kind, secret("two"))
    });
    let autofill: Write = Box::new(|vh| {
        let login = LoginWrite {
            item_key: ITEM,
            title: "Mail",
            password_key: FIELD,
            password: secret("two"),
            username: None,
            websites: &[],
            match_kind: MatchKind::Domain,
        };
        autofill::write_login(vh, login)
    });
    let passkey_rename: Write = Box::new(|vh| rename_account(vh, ITEM, FIELD, "two"));
    let cases = [
        (
            "broker and ap",
            FieldKind::default(),
            ["first", "zero", "one", "two"],
            true,
            broker,
        ),
        (
            "autofill",
            FieldKind::default(),
            ["first", "zero", "one", "two"],
            true,
            autofill,
        ),
        (
            "passkey",
            FieldKind::Passkey,
            ["ada", "zero", "one", "two"],
            false,
            passkey_rename,
        ),
    ];

    for (writer, kind, names, keeps_shown, write) in cases {
        let value = |name: &str| match kind {
            FieldKind::Passkey => passkey(name),
            _ => name.to_string(),
        };
        let mut sim = conflicted(
            kind.clone(),
            &value(names[0]),
            [&value(names[1]), &value(names[2])],
        );

        // A write to the item folder, an Order register with two values.
        sim.write(2, |vh| vh.move_item(ITEM, None));
        let (item, _) = ids(&sim.macs[2].saved_vault());
        let state = sim.macs[2].state();
        let folder = &state.store.items.get(&item).unwrap().folder;
        assert_eq!(folder.values().count(), 1, "{writer}");

        check_write(&mut sim, 2, &value(names[3]), keeps_shown, write);
    }
}

#[test]
fn edit_made_on_stale_read_replaces_newer_value_from_other_mac_and_replaced_value_is_in_history() {
    let mut sim = Sim::new(2, None);
    sim.write(0, |vh| {
        vh.add_item(ITEM, "Mail")?;
        vh.add_secret(
            ITEM,
            FIELD,
            "Password",
            FieldKind::default(),
            secret("first"),
        )
    });
    sim.converge();
    // Mac 0 reads the value. Mac 1 then replaces it, and its file reaches Mac 0
    // before Mac 0 saves an edit made on the value it read.
    let read = sim.macs[0]
        .saved_vault()
        .get_item_credential_secret(ITEM, FIELD)
        .unwrap()
        .unwrap()
        .expose_secret()
        .clone();
    assert_eq!(read, "first");
    sim.write(1, |vh| {
        vh.add_secret(
            ITEM,
            FIELD,
            "Password",
            FieldKind::default(),
            secret("newer"),
        )
    });
    sim.deliver_latest(0, 1);
    let edited = format!("{read} edited");
    sim.write(0, |vh| {
        vh.add_secret(
            ITEM,
            FIELD,
            "Password",
            FieldKind::default(),
            secret(&edited),
        )
    });

    let (_, credential) = ids(&sim.macs[0].saved_vault());
    let after = values(&sim.macs[0].state(), credential);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].1, edited);
    sim.converge();
    sim.check_quiet();
    let state = sim.check_converged();
    assert_eq!(values(&state, credential)[0].1, edited);
    for n in 0..2 {
        let history: Vec<String> = history(&sim, n).into_values().collect();
        assert!(
            history.contains(&"newer".to_string()),
            "Mac {n}: {history:?}"
        );
    }
}

#[test]
fn rename_account_on_passkey_with_value_conflict_keeps_values_not_chosen_and_adds_no_entry_for_rename()
 {
    let mut sim = conflicted(
        FieldKind::Passkey,
        &passkey("ada"),
        [&passkey("zero"), &passkey("one")],
    );

    // A rename with no conflict adds no history entry.
    let mut single = Sim::new(1, None);
    single.write(0, |vh| {
        vh.add_item(ITEM, "Mail")?;
        vh.add_secret(
            ITEM,
            FIELD,
            "ada",
            FieldKind::Passkey,
            secret(&passkey("ada")),
        )
    });
    single.write(0, |vh| rename_account(vh, ITEM, FIELD, "lovelace"));
    assert!(history(&single, 0).is_empty());

    // With a conflict, the value not chosen is in history on every Mac, and
    // the shown value that the rename replaced is not.
    let (_, credential) = ids(&sim.macs[0].saved_vault());
    let shown = values(&sim.macs[0].state(), credential).pop().unwrap().1;
    check_write(&mut sim, 0, &passkey("two"), false, |vh| {
        rename_account(vh, ITEM, FIELD, "two")
    });
    for n in 0..3 {
        let history: Vec<String> = history(&sim, n).into_values().collect();
        assert!(!history.contains(&shown), "Mac {n}");
    }
}

/// Simulator of `macs` Macs whose vault holds `mail/password` set to `first`
/// on Mac 0, joined by every Mac. Returns the credential id and the write id
/// of `first`.
fn set_first(macs: usize) -> (Sim, Uuid, WriteId) {
    let mut sim = Sim::new(macs, None);
    sim.write(0, |vh| {
        vh.add_item(ITEM, "Mail")?;
        vh.add_secret(
            ITEM,
            FIELD,
            "Password",
            FieldKind::default(),
            secret("first"),
        )
    });
    sim.converge();
    let (_, credential) = ids(&sim.macs[0].saved_vault());
    let shown = values(&sim.macs[0].state(), credential);
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].1, "first");
    (sim, credential, shown[0].0)
}

#[test]
fn two_macs_that_replace_one_shown_value_concurrently_write_one_entry_under_derived_id() {
    let (mut sim, credential, first) = set_first(3);
    let derived = HistoryIds::derive(credential, first);

    // Macs 0 and 1 replace `first` before either joins the other.
    for (n, value) in ["zero", "one"].into_iter().enumerate() {
        sim.write(n, |vh| {
            vh.add_secret(ITEM, FIELD, "Password", FieldKind::default(), secret(value))
        });
        let history = history(&sim, n);
        assert_eq!(
            history,
            BTreeMap::from([(derived, "first".to_string())]),
            "Mac {n}"
        );
    }

    sim.converge();
    sim.check_quiet();
    let state = sim.check_converged();
    let shown = &VaultView::of(&state).credentials[&credential].history;
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].id, derived);
    for n in 0..sim.macs.len() {
        let history = history(&sim, n);
        assert_eq!(
            history,
            BTreeMap::from([(derived, "first".to_string())]),
            "Mac {n}"
        );
    }
}

#[test]
fn entry_added_by_change_for_value_other_than_shown_value_keeps_random_id() {
    let (mut sim, credential, first) = set_first(2);

    // One change replaces `first` with `two`, then `two` with `three`. The
    // vault mutation adds an entry for each replaced value.
    let mut random = None;
    sim.write(0, |vh| {
        for value in ["two", "three"] {
            vh.add_secret(ITEM, FIELD, "Password", FieldKind::default(), secret(value))?;
        }
        for entry in vh.list_history(ITEM, FIELD)? {
            if vh.get_history_value(ITEM, FIELD, entry.id)?.expose_secret() == "two" {
                random = Some(entry.id);
            }
        }
        Ok(())
    });

    let random = random.expect("change added entry for two");
    let expected = BTreeMap::from([
        (HistoryIds::derive(credential, first), "first".to_string()),
        (random, "two".to_string()),
    ]);
    assert_eq!(history(&sim, 0), expected);
    sim.converge();
    sim.check_quiet();
    sim.check_converged();
    assert_eq!(history(&sim, 1), expected);
}
