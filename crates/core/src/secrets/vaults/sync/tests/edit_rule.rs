//! Edit rule. Milestone 8 made every write to an Ask register supersede every
//! value of the register. Each credential value not chosen is written to
//! `history` under its derived id. Milestone 12 keeps that rule for writers
//! outside the UI, which declare themselves and are never refused. An edit
//! from the UI carries the write ids it read and is refused if a register it
//! writes changed, holds a conflict, or was not read. The tests run each
//! writer as a transaction of the 6b simulator.
//!
//! History id rewrite (9.1). The entry that a change adds for the replaced
//! shown value takes the id derived from the write id of that value.

use std::collections::{BTreeMap, BTreeSet};

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::audit_events::events;
use super::simulator::Sim;
use super::view::State;
use crate::audit::Action;
use crate::audit::test_support::test_dir;
use crate::secrets::vaults::autofill::item::Role;
use crate::secrets::vaults::autofill::{self, LoginWrite};
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::model::history::HistoryKind;
use crate::secrets::vaults::passkey::rename_account;
use crate::secrets::vaults::sync::crdt::WriteId;
use crate::secrets::vaults::sync::edit_check::{
    ConflictDetail, EditRefusal, ReadSet, RefusalReason, ResolvePick, write_ids,
};
use crate::secrets::vaults::sync::model::SecretText;
use crate::secrets::vaults::sync::resolve::{Choice, HistoryIds};
use crate::secrets::vaults::sync::view::{AskRegister, Conflict, Entity, VaultView};
use crate::secrets::vaults::{Error, MatchKind, VaultHandle, Website};

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
    assert!(conflicts.contains(&value_register(credential)));
    assert!(conflicts.contains(&title_register(item)));
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

fn value_register(credential: Uuid) -> Conflict {
    Conflict {
        entity: Entity::Credential(credential),
        register: AskRegister::Value,
    }
}

fn title_register(item: Uuid) -> Conflict {
    Conflict {
        entity: Entity::Item(item),
        register: AskRegister::Title,
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

/// Values of the value register of `credential`, as text.
fn value_texts(state: &State, credential: Uuid) -> Vec<String> {
    values(state, credential)
        .into_iter()
        .map(|(_, value)| value)
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

/// Value of `mail/password` in the saved vault of Mac `n`.
fn shown_value(sim: &Sim, n: usize) -> String {
    let vault = sim.macs[n].saved_vault();
    let value = vault.get_item_credential_secret(ITEM, FIELD).unwrap();
    value.unwrap().expose_secret().clone()
}

/// Edit from the UI that carries `reads` and sets `mail/password` to `value`.
fn ui_edit(reads: ReadSet, value: &str) -> impl FnOnce(&mut VaultHandle) -> Result<(), Error> + '_ {
    move |vh| {
        vh.carry_reads(reads);
        vh.add_secret(ITEM, FIELD, "Password", FieldKind::default(), secret(value))
    }
}

/// Refusal of a transaction that must be refused.
fn refusal(result: Result<bool, Error>) -> EditRefusal {
    match result {
        Err(Error::EditRefused(refusal)) => refusal,
        other => panic!("edit not refused: {other:?}"),
    }
}

/// Number of `sync.conflict_resolved` events for the register `register`.
fn resolved_events(register: AskRegister) -> usize {
    events(Action::SyncConflictResolved)
        .iter()
        .filter(|event| event.detail["register"] == register.name())
        .count()
}

/// Run `write` on Mac `n` of a [`conflicted`] simulator and check the edit
/// rule. The write runs with the edit check it declares, and sets the value to
/// `written`. The value register then holds only `written`, and each value
/// not chosen is in `history` under its derived id on every Mac. The shown
/// value is added to history if `keeps_shown`, by the vault mutation, and is
/// the only other new entry. After the exchange, no Mac shows a conflict on
/// the value. Returns the converged state.
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

    sim.write_ui(n, write).unwrap();

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
            .contains(&value_register(credential))
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
fn ui_edit_to_conflicted_register_refused_until_resolved() {
    let mut sim = conflicted(FieldKind::default(), "first", ["zero", "one"]);
    let (item, credential) = ids(&sim.macs[2].saved_vault());
    let before = sim.macs[2].state();
    let reads = sim.macs[2].reads();
    assert!(reads.conflicts.contains(&value_register(credential)));
    let refused = EditRefusal {
        register: value_register(credential),
        reason: RefusalReason::Conflicted,
    };

    // Mac 2 read both values. An edit of the value is refused, and so is a
    // write of the shown value.
    let result = sim.write_ui(2, ui_edit(reads.reads.clone(), "two"));
    assert_eq!(refusal(result), refused);
    let shown = shown_value(&sim, 2);
    let result = sim.write_ui(2, ui_edit(reads.reads.clone(), &shown));
    assert_eq!(refusal(result), refused);
    assert!(sim.macs[2].state() == before);

    // The user keeps `zero`.
    let detail = ConflictDetail::of(&before)
        .into_iter()
        .find(|d| d.register == value_register(credential))
        .unwrap();
    assert_eq!(detail.values.len(), 2);
    let zero = Choice::Value(credential, SecretText::new("zero"));
    let chosen = detail.values.iter().find(|v| v.value == zero).unwrap();
    let pick = ResolvePick {
        register: value_register(credential),
        read: detail.read.clone(),
        chosen: chosen.write_id,
    };
    sim.resolve(2, pick).unwrap();
    assert_eq!(value_texts(&sim.macs[2].state(), credential), ["zero"]);

    // With the reads taken after the resolve, the edit is saved.
    let reads = sim.macs[2].reads();
    assert!(!reads.conflicts.contains(&value_register(credential)));
    sim.write_ui(2, ui_edit(reads.reads, "two")).unwrap();
    assert_eq!(value_texts(&sim.macs[2].state(), credential), ["two"]);

    sim.converge();
    sim.check_quiet();
    let state = sim.check_converged();
    let conflicts = VaultView::of(&state).conflicts().to_vec();
    assert!(!conflicts.contains(&value_register(credential)));
    // No request wrote the title, so its conflict is left.
    assert!(conflicts.contains(&title_register(item)));
}

#[test]
fn ui_edit_on_changed_read_refused_and_join_saved() {
    let (mut sim, credential, _) = set_first(2);
    // Mac 0 reads the value. Mac 1 then replaces it, and its file reaches Mac 0
    // before Mac 0 saves an edit made on the value it read.
    let reads = sim.macs[0].reads().reads;
    assert_eq!(shown_value(&sim, 0), "first");
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

    let result = sim.write_ui(0, ui_edit(reads, "first edited"));

    let refused = refusal(result);
    assert_eq!(
        refused,
        EditRefusal {
            register: value_register(credential),
            reason: RefusalReason::Changed,
        }
    );
    // The join was saved, so the vault shows the current value.
    assert_eq!(shown_value(&sim, 0), "newer");
    assert_eq!(value_texts(&sim.macs[0].state(), credential), ["newer"]);

    // The draft reapplied to the current values is saved, and the replaced
    // value is in history.
    let reads = sim.macs[0].reads().reads;
    sim.write_ui(0, ui_edit(reads, "first edited")).unwrap();
    sim.converge();
    sim.check_quiet();
    let state = sim.check_converged();
    assert_eq!(value_texts(&state, credential), ["first edited"]);
    for n in 0..2 {
        let history: Vec<String> = history(&sim, n).into_values().collect();
        assert!(
            history.contains(&"newer".to_string()),
            "Mac {n}: {history:?}"
        );
    }
}

#[test]
fn change_not_carrying_reads_refused_with_register() {
    let (mut sim, credential, _) = set_first(2);
    let item = ids(&sim.macs[0].saved_vault()).0;
    let not_carried = EditRefusal {
        register: value_register(credential),
        reason: RefusalReason::NotCarried,
    };

    // A change that declares no edit check.
    let result = sim.write_ui(0, |vh| {
        vh.add_secret(
            ITEM,
            FIELD,
            "Password",
            FieldKind::default(),
            secret("second"),
        )
    });
    let refused = refusal(result);
    assert_eq!(refused, not_carried);
    let message = Error::EditRefused(refused).to_string();
    assert!(message.contains("value of field"), "{message}");

    // An edit from the UI that read only the item title.
    let mut reads = ReadSet::default();
    let title = title_register(item);
    reads.insert(title, write_ids(&sim.macs[0].state(), title).unwrap());
    let result = sim.write_ui(0, ui_edit(reads, "second"));
    assert_eq!(refusal(result), not_carried);
    assert_eq!(shown_value(&sim, 0), "first");

    // A new entry carries no write ids.
    sim.write_ui(0, |vh| {
        vh.add_item("bank", "Bank")?;
        vh.add_new_secret(ITEM, "pin", "PIN", FieldKind::default(), secret("1234"))
    })
    .unwrap();
    let vault = sim.macs[0].saved_vault();
    assert!(vault.get_item("bank").is_ok());
    assert!(vault.get_item_credential(ITEM, "pin").is_ok());
}

#[test]
fn writer_outside_ui_to_ask_register_with_conflict_supersedes_every_value_and_order_write_succeeds()
{
    let _audit = test_dir();
    type Write = Box<dyn FnOnce(&mut VaultHandle) -> Result<(), Error>>;
    let broker: Write = Box::new(|vh| {
        // `ap` and the broker `WriteSecret` request declare a writer outside
        // the UI and keep the kind.
        vh.write_outside_ui();
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

        let resolved = resolved_events(AskRegister::Value);
        check_write(&mut sim, 2, &value(names[3]), keeps_shown, write);
        assert_eq!(
            resolved_events(AskRegister::Value),
            resolved + 1,
            "{writer}"
        );
    }
}

#[test]
fn writer_write_equal_to_shown_value_resolves_conflict() {
    let _audit = test_dir();
    type Write = fn(&mut VaultHandle, &str) -> Result<(), Error>;
    let broker: Write = |vh, value| {
        vh.write_outside_ui();
        let kind = vh.get_secret_overview(ITEM, FIELD)?.unwrap().kind.clone();
        vh.add_secret(ITEM, FIELD, "Password", kind, secret(value))
    };
    let autofill: Write = |vh, value| {
        let login = LoginWrite {
            item_key: ITEM,
            title: "Mail",
            password_key: FIELD,
            password: secret(value),
            username: None,
            websites: &[],
            match_kind: MatchKind::Domain,
        };
        autofill::write_login(vh, login)
    };

    for (writer, write) in [("broker and ap", broker), ("autofill", autofill)] {
        let mut sim = conflicted(FieldKind::default(), "first", ["zero", "one"]);
        let (_, credential) = ids(&sim.macs[2].saved_vault());

        // A request that writes nothing to the value register leaves the
        // conflict in place.
        sim.write(2, |vh| vh.move_item(ITEM, None));
        let state = sim.macs[2].state();
        assert!(
            VaultView::of(&state)
                .conflicts()
                .contains(&value_register(credential)),
            "{writer}"
        );

        // The writer writes the shown value. The vault is unchanged, and the
        // write still supersedes the other value.
        let shown = shown_value(&sim, 2);
        let other: Vec<(WriteId, String)> = values(&state, credential)
            .into_iter()
            .filter(|(_, value)| *value != shown)
            .collect();
        let resolved = resolved_events(AskRegister::Value);
        sim.write_ui(2, |vh| write(vh, &shown)).unwrap();

        assert_eq!(
            value_texts(&sim.macs[2].state(), credential),
            [shown.clone()],
            "{writer}"
        );
        assert_eq!(
            resolved_events(AskRegister::Value),
            resolved + 1,
            "{writer}"
        );
        sim.converge();
        sim.check_quiet();
        let state = sim.check_converged();
        assert!(
            !VaultView::of(&state)
                .conflicts()
                .contains(&value_register(credential)),
            "{writer}"
        );
        for m in 0..sim.macs.len() {
            let history = history(&sim, m);
            for (write_id, value) in &other {
                let id = HistoryIds::derive(credential, *write_id);
                assert_eq!(history.get(&id), Some(value), "{writer}, Mac {m}");
            }
        }
    }
}

#[test]
fn slot_credential_trash_move_restore_need_no_slot_reads() {
    let mut sim = Sim::new(2, None);
    sim.write(0, |vh| {
        let login = LoginWrite {
            item_key: ITEM,
            title: "Mail",
            password_key: FIELD,
            password: secret("first"),
            username: Some("ada"),
            websites: &[],
            match_kind: MatchKind::Domain,
        };
        autofill::write_login(vh, login)?;
        vh.add_item("bank", "Bank").map(|_| ())
    });
    sim.converge();
    let (item, credential) = ids(&sim.macs[0].saved_vault());
    let slots = |sim: &Sim| -> Vec<BTreeSet<WriteId>> {
        let state = sim.macs[0].state();
        [AskRegister::Username, AskRegister::Password]
            .into_iter()
            .map(|register| {
                let slot = Conflict {
                    entity: Entity::Item(item),
                    register,
                };
                write_ids(&state, slot).unwrap()
            })
            .collect()
    };
    let password_slot = |sim: &Sim| {
        sim.macs[0]
            .saved_vault()
            .get_item(ITEM)
            .unwrap()
            .autofill
            .password
    };
    let before = slots(&sim);
    assert_eq!(password_slot(&sim), Some(credential));

    // Each change below declares no edit check, so a write to a slot would be
    // refused.
    sim.write_ui(0, |vh| vh.delete_item_credential(ITEM, FIELD))
        .unwrap();
    assert_eq!(slots(&sim), before, "trash");
    assert_eq!(password_slot(&sim), None);

    // An autofill write of the item, with the slot cleared for the trashed
    // credential.
    sim.write_ui(0, |vh| {
        let website = Website::new("https://mail.example.com", MatchKind::Domain);
        autofill::set_websites(vh, ITEM, vec![website])?;
        autofill::set_role(vh, ITEM, Role::Password, None)
    })
    .unwrap();
    assert_eq!(slots(&sim), before, "autofill cleanup");

    sim.write_ui(0, |vh| vh.restore_item_credential(ITEM, credential, None))
        .unwrap();
    assert_eq!(slots(&sim), before, "restore");
    assert_eq!(password_slot(&sim), Some(credential));

    sim.write_ui(0, |vh| {
        vh.transfer_credential(ITEM, FIELD, "bank", FIELD, None)
    })
    .unwrap();
    assert_eq!(slots(&sim), before, "move");
    assert_eq!(password_slot(&sim), None);

    sim.converge();
    sim.check_quiet();
    sim.check_converged();
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
fn concurrent_replace_writes_one_derived_id_entry() {
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
    let shown: Vec<_> = VaultView::of(&state).credentials[&credential]
        .history
        .iter()
        .filter(|h| h.kind == HistoryKind::ValueUpdated)
        .map(|h| h.id)
        .collect();
    assert_eq!(shown, [derived]);
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
fn entry_for_unshown_value_keeps_random_id() {
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
