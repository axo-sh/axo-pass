use super::*;

fn make_vault() -> EncryptedVault {
    EncryptedVault {
        id: Uuid::new_v4(),
        key: "test-vault".to_string(),
        name: Some("test vault".to_string()),
        generation: 0,
        replica_id: None,
        file_key: VaultFileKey::new(vec![0u8; 32]),
        metadata: None,
        items: BTreeMap::new(),
        deleted: BTreeMap::new(),
    }
}

#[test]
fn add_multiple_items() {
    let mut vault = make_vault();
    let cipher = VaultCipher::new(vault.id);
    let item_a = VaultItemOverview::try_new("Item A", "item-a").unwrap();
    let item_b = VaultItemOverview::try_new("Item B", "item-b").unwrap();
    vault.add_item(&cipher, None, None, &item_a).unwrap();
    vault.add_item(&cipher, None, None, &item_b).unwrap();

    assert_eq!(vault.items.len(), 2);
    assert!(vault.items.contains_key(&item_a.id));
    assert!(vault.items.contains_key(&item_b.id));

    // Each item should have encrypted metadata and no credentials yet
    let enc_a = vault.items.get(&item_a.id).unwrap();
    assert!(enc_a.credentials.is_empty());
    let enc_b = vault.items.get(&item_b.id).unwrap();
    assert!(enc_b.credentials.is_empty());

    // Verify the metadata decrypts to the expected values
    let meta_a = cipher
        .decrypt_item_metadata(item_a.id, &enc_a.metadata)
        .unwrap();
    let meta_a = meta_a.expose_secret();
    assert_eq!(meta_a.title, "Item A");
    assert_eq!(meta_a.key, "item-a");

    let meta_b = cipher
        .decrypt_item_metadata(item_b.id, &enc_b.metadata)
        .unwrap();
    let meta_b = meta_b.expose_secret();
    assert_eq!(meta_b.title, "Item B");
    assert_eq!(meta_b.key, "item-b");
}

#[test]
fn added_credential_decrypts() {
    let mut vault = make_vault();
    let cipher = VaultCipher::new(vault.id);
    let item = VaultItemOverview::try_new("My Item", "my-item").unwrap();
    vault.add_item(&cipher, None, None, &item).unwrap();

    let cred =
        VaultItemCredentialOverview::try_new("Password", "password", FieldKind::default()).unwrap();
    let secret = cipher
        .encrypt_cred_value(item.id, cred.id, "secret123")
        .unwrap();

    vault
        .add_credential(&cipher, None, item.id, &cred, secret, Vec::new())
        .unwrap();

    // Verify the vault has exactly one item with exactly one credential
    assert_eq!(vault.items.len(), 1);
    let enc_item = vault.items.get(&item.id).unwrap();
    assert_eq!(enc_item.credentials.len(), 1);

    let enc_cred = enc_item.credentials.get(&cred.id).unwrap();

    // Verify credential metadata decrypts to the expected values
    let meta = cipher
        .decrypt_cred_metadata(item.id, cred.id, &enc_cred.metadata)
        .unwrap();
    let meta = meta.expose_secret();
    assert_eq!(meta.title, "Password");
    assert_eq!(meta.key, "password");

    // Verify the secret value decrypts correctly
    let secret_value = cipher
        .decrypt_cred_value(item.id, cred.id, &enc_cred.value)
        .unwrap();
    assert_eq!(secret_value.expose_secret(), "secret123");
}

#[test]
fn credential_position_persisted_in_metadata() {
    let mut vault = make_vault();
    let cipher = VaultCipher::new(vault.id);
    let item = VaultItemOverview::try_new("My Item", "my-item").unwrap();
    vault.add_item(&cipher, None, None, &item).unwrap();

    let mut cred =
        VaultItemCredentialOverview::try_new("Password", "password", FieldKind::default()).unwrap();
    cred.position = Some(3);
    let secret = cipher
        .encrypt_cred_value(item.id, cred.id, "secret123")
        .unwrap();
    vault
        .add_credential(&cipher, None, item.id, &cred, secret, Vec::new())
        .unwrap();

    let enc_cred = vault
        .items
        .get(&item.id)
        .unwrap()
        .credentials
        .get(&cred.id)
        .unwrap();
    let meta = cipher
        .decrypt_cred_metadata(item.id, cred.id, &enc_cred.metadata)
        .unwrap();
    assert_eq!(meta.expose_secret().position, Some(3));
}

#[test]
fn vault_metadata_encrypted_and_bound_to_its_vault() {
    let mut vault = make_vault();
    let cipher = VaultCipher::new(vault.id);
    let metadata = VaultMetadata {
        folders: vec![VaultFolder::new("Work").to_metadata()],
        ..Default::default()
    };
    vault.set_metadata(&cipher, None, &metadata).unwrap();

    let blob = vault.metadata.as_ref().unwrap();
    let back = cipher.decrypt_vault_metadata(blob).unwrap();
    assert_eq!(back.expose_secret().folders[0].title, "Work");

    // The AAD binds the blob to its vault id.
    let other = VaultCipher::new(Uuid::new_v4());
    assert!(other.decrypt_vault_metadata(blob).is_err());
}

#[test]
fn vault_without_metadata_omits_field() {
    let mut vault = make_vault();
    let cipher = VaultCipher::new(vault.id);
    vault
        .set_metadata(&cipher, None, &VaultMetadata::default())
        .unwrap();
    let json = serde_json::to_value(&vault).unwrap();
    assert!(json.get("metadata").is_none());

    let back: EncryptedVault = serde_json::from_value(json).unwrap();
    assert!(back.metadata.is_none());
}

#[test]
fn credential_for_missing_item_refused() {
    let mut vault = make_vault();
    let cipher = VaultCipher::new(vault.id);
    let cred =
        VaultItemCredentialOverview::try_new("Token", "token", FieldKind::default()).unwrap();
    let secret = cipher
        .encrypt_cred_value(Uuid::new_v4(), Uuid::new_v4(), "tok")
        .unwrap();

    let result = vault.add_credential(&cipher, None, Uuid::new_v4(), &cred, secret, Vec::new());
    assert!(matches!(result, Err(Error::InvalidItemKey(_))));
}
