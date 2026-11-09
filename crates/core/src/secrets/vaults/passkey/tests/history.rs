use super::*;
use crate::audit::test_support::test_dir;
use crate::audit::{self, AuditEvent};
use crate::secrets::vaults::CredentialUpdate;

/// Sign-ins the passkey detail view lists for `passkey_credential_id`.
/// The app builds the same filter in `VaultsModel.recentSignIns`.
fn sign_ins(passkey_credential_id: &str) -> Vec<Uuid> {
    audit::read(&audit::AuditFilter {
        actions: vec![audit::Action::PasskeyAsserted],
        outcomes: vec![audit::Outcome::Succeeded],
        detail_id: Some(audit::DetailId::new(
            audit::PASSKEY_CREDENTIAL_ID,
            passkey_credential_id,
        )),
        ..Default::default()
    })
    .events
    .into_iter()
    .map(|event| event.id)
    .collect()
}

/// Record a sign-in of the passkey at `item_key`/`credential_key` with
/// the ids the broker records. Returns the event id.
fn record_sign_in(vw: &VaultHandle, item_key: &str, credential_key: &str) -> Uuid {
    let id = webauthn_credential_id(vw, item_key, credential_key).unwrap();
    let event = AuditEvent::new(
        audit::process_source(),
        audit::Action::PasskeyAsserted,
        audit::Outcome::Succeeded,
    )
    .passkey_credential_id(&id)
    .detail("credential", format!("{item_key}/{credential_key}"));
    let event_id = event.id;
    audit::record(event);
    event_id
}

#[tokio::test]
async fn sign_ins_are_assertions_of_one_passkey_newest_first() {
    let _audit = test_dir();
    let mut vw = registered_vault("ada").await;
    register(&mut vw, PasskeyTarget::NewLogin, "bob").await;
    let ada = passkey_of(&vw, "ada");
    let bob = passkey_of(&vw, "bob");
    let ada_id = encode_credential_id(ada.passkey.credential_id.as_slice());
    let ada_path = format!("{}/{}", ada.item_key, ada.credential_key);

    let first = record_sign_in(&vw, &ada.item_key, &ada.credential_key);
    record_sign_in(&vw, &bob.item_key, &bob.credential_key);
    // A failed assertion and an older event name the passkey by path only.
    audit::record(
        AuditEvent::new(
            audit::process_source(),
            audit::Action::PasskeyAsserted,
            audit::Outcome::Failed,
        )
        .detail("credential", ada_path.clone()),
    );
    audit::record(
        AuditEvent::new(
            audit::process_source(),
            audit::Action::PasskeyAsserted,
            audit::Outcome::Succeeded,
        )
        .detail("credential", ada_path),
    );
    // A site report lists the passkey but is not a sign-in.
    audit::record(
        AuditEvent::new(
            audit::process_source(),
            audit::Action::PasskeyReported,
            audit::Outcome::Succeeded,
        )
        .passkey_credential_ids([ada.passkey.credential_id.as_slice()]),
    );
    let second = record_sign_in(&vw, &ada.item_key, &ada.credential_key);

    assert_eq!(sign_ins(&ada_id), [second, first]);
}

/// The detail view reads the id from the passkey where it is now, so its
/// history survives renames and moves.
#[tokio::test]
async fn sign_in_history_unchanged_after_rename_and_moves() {
    let _audit = test_dir();
    let mut source = registered_vault("ada").await;
    source.add_item("other", "Other").unwrap();
    let stored = list(&source).unwrap().remove(0);
    let item_key = stored.item_key.clone();
    let before = record_sign_in(&source, &item_key, &stored.credential_key);

    rename_account(&mut source, &item_key, &stored.credential_key, "Ada L").unwrap();
    source
        .update_credential(
            &item_key,
            &stored.credential_key,
            CredentialUpdate {
                key: Some("work".into()),
                title: Some("Work".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let renamed = record_sign_in(&source, &item_key, "work");
    let ids = SubjectIds::credential(stored.vault_id, stored.item_id, stored.credential_id);
    assert_eq!(sign_ins(&stored_id(&source, ids)), [renamed, before]);

    let moved = move_within_vault(
        &mut source,
        &item_key,
        "work",
        &PasskeyTarget::Item("other".into()),
    )
    .unwrap();
    let moved_key = passkey_of(&source, "Ada L").credential_key;
    let within = record_sign_in(&source, "other", &moved_key);
    assert_eq!(
        sign_ins(&stored_id(&source, moved)),
        [within, renamed, before]
    );

    let record = read_record(&source, "other", &moved_key).unwrap();
    let mut dest = VaultHandle::new_for_test("work");
    let copied = write_record(&mut dest, &record, &PasskeyTarget::NewLogin).unwrap();
    remove_record(&mut source, "other", &moved_key).unwrap();
    assert_eq!(
        sign_ins(&stored_id(&dest, copied)),
        [within, renamed, before]
    );
}

#[tokio::test]
async fn renaming_account_keeps_key_and_adds_no_history() {
    let mut vw = registered_vault("ada").await;
    let stored = list(&vw).unwrap().remove(0);

    rename_account(
        &mut vw,
        &stored.item_key,
        &stored.credential_key,
        " lovelace ",
    )
    .unwrap();

    let renamed = list(&vw).unwrap().remove(0);
    assert_eq!(renamed.passkey.username.as_deref(), Some("lovelace"));
    assert_eq!(
        renamed.passkey.user_display_name.as_deref(),
        Some("lovelace")
    );
    assert_eq!(renamed.passkey.credential_id, stored.passkey.credential_id);
    assert_eq!(
        renamed.passkey.key.clone().to_vec().unwrap(),
        stored.passkey.key.clone().to_vec().unwrap()
    );
    let overview = vw
        .get_secret_overview(&stored.item_key, &stored.credential_key)
        .unwrap()
        .unwrap();
    assert_eq!(overview.title, "lovelace");
    assert!(
        vw.list_history(&stored.item_key, &stored.credential_key)
            .unwrap()
            .is_empty()
    );
    assert!(rename_account(&mut vw, &stored.item_key, &stored.credential_key, " ").is_err());
}
