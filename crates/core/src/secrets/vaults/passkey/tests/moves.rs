use super::*;
use crate::secrets::vaults::{CredentialUpdate, VaultItemOverview};

#[tokio::test]
async fn passkey_moves_to_another_vault_with_its_record_intact() {
    let mut source = registered_vault("ada").await;
    let stored = list(&source).unwrap().remove(0);
    source
        .mark_credential_used(&stored.item_key, &stored.credential_key, 1_750_000_000)
        .unwrap();
    let record = read_record(&source, &stored.item_key, &stored.credential_key).unwrap();

    let mut dest = VaultHandle::new_for_test("work");
    write_record(&mut dest, &record, &PasskeyTarget::NewLogin).unwrap();

    let moved = list(&dest).unwrap().remove(0);
    let last_used = |vw: &VaultHandle| {
        vw.get_secret_overview(&moved.item_key, &moved.credential_key)
            .unwrap()
            .unwrap()
            .last_used_day_at
    };
    assert_eq!(last_used(&dest), Some(1_750_000_000));
    assert_eq!(moved.credential_key, stored.credential_key);
    assert_eq!(moved.passkey.credential_id, stored.passkey.credential_id);
    assert_eq!(
        moved.passkey.key.clone().to_vec().unwrap(),
        stored.passkey.key.clone().to_vec().unwrap()
    );
    assert_eq!(dest.list_items().unwrap().len(), 1);
}

#[tokio::test]
async fn moved_passkey_leaves_no_source_tombstone() {
    let mut source = registered_vault("ada").await;
    let stored = list(&source).unwrap().remove(0);
    let record = read_record(&source, &stored.item_key, &stored.credential_key).unwrap();
    let mut dest = VaultHandle::new_for_test("work");
    write_record(&mut dest, &record, &PasskeyTarget::NewLogin).unwrap();

    remove_record(&mut source, &stored.item_key, &stored.credential_key).unwrap();

    assert!(list(&source).unwrap().is_empty());
    assert!(source.list_all_deleted().unwrap().is_empty());
}

#[tokio::test]
async fn move_within_vault_keeps_credential() {
    let mut vw = registered_vault("ada").await;
    let stored = list(&vw).unwrap().remove(0);
    vw.mark_credential_used(&stored.item_key, &stored.credential_key, 1_750_000_000)
        .unwrap();
    let before = vw
        .get_secret_overview(&stored.item_key, &stored.credential_key)
        .unwrap()
        .unwrap()
        .clone();
    vw.add_item("other", "Other").unwrap();

    let ids = move_within_vault(
        &mut vw,
        &stored.item_key,
        &stored.credential_key,
        &PasskeyTarget::Item("other".into()),
    )
    .unwrap();

    let after = vw
        .get_secret_overview("other", &stored.credential_key)
        .unwrap()
        .unwrap();
    assert_eq!(ids.credential_id, Some(before.id));
    assert_eq!(after.id, before.id);
    assert_eq!(after.title, before.title);
    assert_eq!(after.last_used_day_at, Some(1_750_000_000));
    let passkeys = list(&vw).unwrap();
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].item_key, "other");
    assert!(
        vw.get_secret_overview(&stored.item_key, &stored.credential_key)
            .unwrap()
            .is_none()
    );
    assert!(vw.list_all_deleted().unwrap().is_empty());
}

#[tokio::test]
async fn move_in_vault_to_new_login_matches_copy() {
    let mut vw = registered_vault("ada@example.com").await;
    let stored = list(&vw).unwrap().remove(0);
    let record = read_record(&vw, &stored.item_key, &stored.credential_key).unwrap();
    let mut copy = VaultHandle::new_for_test("work");
    let copied = write_record(&mut copy, &record, &PasskeyTarget::NewLogin).unwrap();
    let source_id = vw
        .credential_ids(&stored.item_key, &stored.credential_key)
        .unwrap()
        .credential_id;

    let ids = move_within_vault(
        &mut vw,
        &stored.item_key,
        &stored.credential_key,
        &PasskeyTarget::NewLogin,
    )
    .unwrap();

    assert_eq!(ids.credential_id, source_id);
    let moved = vw
        .get_item_overview_by_id(ids.item_id.unwrap())
        .unwrap()
        .unwrap();
    let expected = copy
        .get_item_overview_by_id(copied.item_id.unwrap())
        .unwrap()
        .unwrap();
    assert_ne!(moved.key, stored.item_key);
    assert_eq!(moved.title, expected.title);
    assert_eq!(moved.category, expected.category);
    assert_eq!(moved.autofill.websites, expected.autofill.websites);
    assert!(moved.autofill.password.is_none());
    let username = |vw: &VaultHandle, item: &VaultItemOverview| {
        let cred = item.autofill.username_credential(item).unwrap();
        let value = vw.get_secret(&item.key, &cred.key).unwrap().unwrap();
        (cred.key.clone(), value.expose_secret().clone())
    };
    assert_eq!(username(&vw, moved), username(&copy, expected));
    assert_eq!(list(&vw).unwrap()[0].item_key, moved.key);
}

/// A passkey key comes from the WebAuthn credential id, so a destination
/// credential with the same key is the same passkey. It takes the source
/// record and keeps its own id.
#[tokio::test]
async fn move_within_vault_onto_same_passkey_replaces_it() {
    let mut vw = registered_vault("ada").await;
    let stored = list(&vw).unwrap().remove(0);
    vw.mark_credential_used(&stored.item_key, &stored.credential_key, 1_750_000_000)
        .unwrap();
    let record = read_record(&vw, &stored.item_key, &stored.credential_key).unwrap();
    vw.add_item("other", "Other").unwrap();
    let existing = write_record(&mut vw, &record, &PasskeyTarget::Item("other".into()))
        .unwrap()
        .credential_id;
    vw.update_credential(
        "other",
        &stored.credential_key,
        CredentialUpdate {
            title: Some("Old title".into()),
            ..Default::default()
        },
    )
    .unwrap();

    let ids = move_within_vault(
        &mut vw,
        &stored.item_key,
        &stored.credential_key,
        &PasskeyTarget::Item("other".into()),
    )
    .unwrap();

    assert_eq!(ids.credential_id, existing);
    let after = vw
        .get_secret_overview("other", &stored.credential_key)
        .unwrap()
        .unwrap();
    assert_eq!(after.title, record.title);
    assert_eq!(after.last_used_day_at, Some(1_750_000_000));
    let passkeys = list(&vw).unwrap();
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].item_key, "other");
    assert!(vw.list_all_deleted().unwrap().is_empty());
}

#[tokio::test]
async fn move_within_vault_to_source_item_changes_nothing() {
    let mut vw = registered_vault("ada").await;
    let stored = list(&vw).unwrap().remove(0);
    let before = vw
        .credential_ids(&stored.item_key, &stored.credential_key)
        .unwrap();

    let ids = move_within_vault(
        &mut vw,
        &stored.item_key,
        &stored.credential_key,
        &PasskeyTarget::Item(stored.item_key.clone()),
    )
    .unwrap();

    assert_eq!(ids.credential_id, before.credential_id);
    assert_eq!(list(&vw).unwrap().len(), 1);
    assert!(vw.list_all_deleted().unwrap().is_empty());
}

#[tokio::test]
async fn move_onto_same_passkey_keeps_later_last_used_time() {
    for (source_at, dest_at) in [(EARLIER_USE, LATER_USE), (LATER_USE, EARLIER_USE)] {
        let mut vw = registered_vault("ada").await;
        let stored = list(&vw).unwrap().remove(0);
        let key = &stored.credential_key;
        vw.add_item("other", "Other").unwrap();
        let record = read_record(&vw, &stored.item_key, key).unwrap();
        write_record(&mut vw, &record, &PasskeyTarget::Item("other".into())).unwrap();
        vw.mark_credential_used(&stored.item_key, key, source_at)
            .unwrap();
        vw.mark_credential_used("other", key, dest_at).unwrap();

        move_within_vault(
            &mut vw,
            &stored.item_key,
            key,
            &PasskeyTarget::Item("other".into()),
        )
        .unwrap();

        assert_eq!(last_used_at(&vw, "other", key), Some(LATER_USE));
    }
}

#[tokio::test]
async fn copy_across_vaults_keeps_later_last_used() {
    for (source_at, dest_at) in [(EARLIER_USE, LATER_USE), (LATER_USE, EARLIER_USE)] {
        let source = registered_vault("ada").await;
        let stored = list(&source).unwrap().remove(0);
        let key = &stored.credential_key;
        let mut dest = VaultHandle::new_for_test("work");
        let record = read_record(&source, &stored.item_key, key).unwrap();
        let ids = write_record(&mut dest, &record, &PasskeyTarget::NewLogin).unwrap();
        let dest_item = dest
            .get_item_overview_by_id(ids.item_id.unwrap())
            .unwrap()
            .unwrap()
            .key
            .clone();
        dest.mark_credential_used(&dest_item, key, dest_at).unwrap();
        let record = PasskeyRecord {
            last_used_day_at: Some(source_at),
            ..record
        };

        write_record(&mut dest, &record, &PasskeyTarget::Item(dest_item.clone())).unwrap();

        assert_eq!(last_used_at(&dest, &dest_item, key), Some(LATER_USE));
    }
}

#[tokio::test]
async fn move_in_vault_keeps_credential_id() {
    let mut vw = registered_vault("ada").await;
    let stored = list(&vw).unwrap().remove(0);
    vw.add_item("other", "Other").unwrap();
    let recorded = recorded_id(&vw, &stored);

    let moved = move_within_vault(
        &mut vw,
        &stored.item_key,
        &stored.credential_key,
        &PasskeyTarget::Item("other".into()),
    )
    .unwrap();

    assert_eq!(stored_id(&vw, moved), recorded);
    assert_eq!(
        recorded,
        encode_credential_id(stored.passkey.credential_id.as_slice())
    );
}

#[tokio::test]
async fn move_across_vaults_keeps_credential_id() {
    let source = registered_vault("ada").await;
    let stored = list(&source).unwrap().remove(0);
    let recorded = recorded_id(&source, &stored);
    let record = read_record(&source, &stored.item_key, &stored.credential_key).unwrap();
    let mut dest = VaultHandle::new_for_test("work");

    let moved = write_record(&mut dest, &record, &PasskeyTarget::NewLogin).unwrap();

    assert_eq!(stored_id(&dest, moved), recorded);
    assert_ne!(moved.credential_id, Some(stored.credential_id));
}
