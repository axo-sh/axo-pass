use super::*;

#[test]
fn every_id_in_vault_file_is_short() {
    let mut vault = filled_vault();
    vault.replica_id = Some(Uuid::new_v4());
    let contents = contents_of(&vault);

    // Vault id, replica id, and the ids of the item, its credential, its
    // history entry, its deleted credential, the deleted item, and the
    // credential and deleted credential of the deleted item.
    assert!(EncryptedVault::assert_short_ids_for_test(&contents) >= 9);
    let file: Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(file["vault"]["id"], json!(ShortId::encode_uuid(vault.id)));
    assert!(!contents.contains(&vault.id.hyphenated().to_string()));
}

#[test]
fn vault_file_with_hyphenated_ids_loads_and_saves_short_ids() {
    let mut vault = filled_vault();
    vault.replica_id = Some(Uuid::new_v4());
    let short = contents_of(&vault);
    let hyphenated = EncryptedVault::hyphenate_ids_for_test(&short, &signer());
    assert!(hyphenated.contains(&format!("\"{}\"", vault.id.hyphenated())));

    let back = parse(&hyphenated).unwrap();
    assert_eq!(back.id, vault.id);
    assert_eq!(back.replica_id, vault.replica_id);
    assert_eq!(VaultHeader::parse(&hyphenated).unwrap().id, vault.id);
    assert_eq!(back.to_vault_json().unwrap(), raw(&short));
}

#[test]
fn blob_plaintext_with_hyphenated_ids_loads_and_saves_short_ids() {
    let folder = Uuid::new_v4();
    let section = Uuid::new_v4();
    let cred = Uuid::new_v4();
    let short = |id: Uuid| json!(ShortId::encode_uuid(id));

    let item: VaultItemMetadata = serde_json::from_value(json!({
        "title": "Item",
        "key": "item",
        "folder": folder,
        "sections": [{ "id": section, "title": "Section" }],
    }))
    .unwrap();
    assert_eq!(item.folder, Some(folder));
    let item = serde_json::to_value(&item).unwrap();
    assert_eq!(item["folder"], short(folder));
    assert_eq!(item["sections"][0]["id"], short(section));

    let credential: VaultCredentialMetadata = serde_json::from_value(json!({
        "title": "Password",
        "key": "password",
        "section": section,
    }))
    .unwrap();
    assert_eq!(credential.section, Some(section));
    let credential = serde_json::to_value(&credential).unwrap();
    assert_eq!(credential["section"], short(section));

    let autofill: ItemAutofill = serde_json::from_value(json!({
        "username": cred,
        "password": cred,
        "totp": cred,
    }))
    .unwrap();
    assert_eq!(autofill.password, Some(cred));
    let autofill = serde_json::to_value(&autofill).unwrap();
    for slot in ["username", "password", "totp"] {
        assert_eq!(autofill[slot], short(cred), "{slot}");
    }

    let metadata: VaultMetadata = serde_json::from_value(json!({
        "folders": [{ "id": folder, "title": "Work" }],
    }))
    .unwrap();
    assert_eq!(metadata.folders[0].id, folder);
    let metadata = serde_json::to_value(&metadata).unwrap();
    assert_eq!(metadata["folders"][0]["id"], short(folder));
}
