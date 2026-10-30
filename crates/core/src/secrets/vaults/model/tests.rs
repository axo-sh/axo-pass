use super::*;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::model::fields::TextField;

const TEST_FILE_KEY: [u8; 32] = [7u8; 32];

fn test_vault() -> Vault {
    let id = Uuid::new_v4();
    Vault::empty(
        id,
        "test-vault".to_string(),
        Some("test vault".to_string()),
        VaultFileKey::new(vec![0u8; 32]),
        VaultCipher::new_with_bytes(&TEST_FILE_KEY, id),
    )
}

/// Save and load the vault, as a restart would.
fn reload(vault: &Vault) -> Vault {
    let encrypted = vault.to_encrypted(true).unwrap();
    let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
    Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap()
}

/// A vault with one item holding the given credential keys, plus a second
/// item with a single credential to test cross-item rejection.
fn vault_with_credentials(item_key: &str, cred_keys: &[&str]) -> Vault {
    let mut vault = test_vault();
    vault.add_or_update_item(item_key, "Item").unwrap();
    for cred_key in cred_keys {
        vault
            .add_or_update_item_credential(
                item_key,
                cred_key,
                cred_key,
                FieldKind::default(),
                SecretString::from("secret"),
            )
            .unwrap();
    }

    vault.add_or_update_item("other-item", "Other").unwrap();
    vault
        .add_or_update_item_credential(
            "other-item",
            "elsewhere",
            "Elsewhere",
            FieldKind::default(),
            SecretString::from("secret"),
        )
        .unwrap();
    vault
}

fn unsectioned(cred_keys: &[&str]) -> Vec<CredentialPlacement> {
    cred_keys
        .iter()
        .map(|k| CredentialPlacement {
            key: k.to_string(),
            section: None,
        })
        .collect()
}

#[test]
fn export_leaves_out_passkeys_unless_asked() {
    let mut vault = vault_with_credentials("site", &["password"]);
    vault
        .add_or_update_item_credential(
            "site",
            "passkey-1",
            "Passkey",
            FieldKind::Passkey,
            SecretString::from("{}"),
        )
        .unwrap();
    let cipher = Aes256Gcm::new(&Aes256Gcm::generate_key(OsRng));
    let item_id = *vault.get_item_id("site").unwrap();
    let count = |include_passkeys| {
        vault
            .to_bundled_vault(None, Uuid::new_v4(), &cipher, include_passkeys)
            .unwrap()
            .items[&item_id]
            .credentials
            .len()
    };

    assert_eq!(count(true), 2);
    assert_eq!(count(false), 1);
    // The vault itself keeps the passkey.
    assert_eq!(vault.get_item("site").unwrap().credentials.len(), 2);
}

fn positions(vault: &Vault, item_key: &str, cred_keys: &[&str]) -> Vec<Option<u32>> {
    cred_keys
        .iter()
        .map(|k| vault.get_item_credential(item_key, k).unwrap().position)
        .collect()
}

fn cred_metadata(title: &str, key: &str, kind: FieldKind) -> VaultCredentialMetadata {
    VaultCredentialMetadata {
        title: title.to_string(),
        key: key.to_string(),
        kind,
        position: None,
        section: None,
        last_used_day_at: None,
    }
}

/// Populate the metadata caches the way a load/save cycle would, so a
/// change has to invalidate them to take effect.
fn populate_caches(vault: &mut Vault) {
    let encrypted = vault.to_encrypted(true).unwrap();
    vault.metadata_blob = encrypted.metadata;
    for (item_id, item) in encrypted.items {
        vault.item_blobs.insert(item_id, item.metadata);
        for (cred_id, cred) in item.credentials {
            vault.cred_blobs.insert(cred_id, cred.metadata);
        }
    }
}

#[test]
fn reorder_assigns_positions_in_the_given_order() {
    let keys = ["alpha", "beta", "gamma"];
    let mut vault = vault_with_credentials("item", &keys);
    assert_eq!(positions(&vault, "item", &keys), vec![None, None, None]);

    vault
        .reorder_item_credentials("item", &unsectioned(&["gamma", "alpha", "beta"]))
        .unwrap();

    assert_eq!(
        positions(&vault, "item", &keys),
        vec![Some(1), Some(2), Some(0)]
    );
}

#[test]
fn reorder_invalidates_cached_metadata_so_positions_are_persisted() {
    let keys = ["alpha", "beta"];
    let mut vault = vault_with_credentials("item", &keys);
    populate_caches(&mut vault);

    vault
        .reorder_item_credentials("item", &unsectioned(&["beta", "alpha"]))
        .unwrap();

    let vault = reload(&vault);
    assert_eq!(positions(&vault, "item", &keys), vec![Some(1), Some(0)]);
}

#[test]
fn reorder_rejects_a_partial_list() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta", "gamma"]);
    let err = vault
        .reorder_item_credentials("item", &unsectioned(&["beta", "alpha"]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialOrder(_)));
    assert_eq!(
        positions(&vault, "item", &["alpha", "beta", "gamma"]),
        vec![None, None, None]
    );
}

#[test]
fn reorder_rejects_a_duplicated_key() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let err = vault
        .reorder_item_credentials("item", &unsectioned(&["alpha", "alpha"]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialOrder(_)));
}

#[test]
fn reorder_rejects_an_unknown_key() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let err = vault
        .reorder_item_credentials("item", &unsectioned(&["alpha", "nope"]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialKey(_)));
}

#[test]
fn reorder_rejects_a_key_from_another_item() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let err = vault
        .reorder_item_credentials("item", &unsectioned(&["alpha", "elsewhere"]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialKey(_)));
}

#[test]
fn reorder_rejects_an_unknown_item() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let err = vault
        .reorder_item_credentials("nope", &unsectioned(&["alpha"]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidItemKey(_)));
}

#[test]
fn reordered_positions_survive_a_save_and_load() {
    let keys = ["alpha", "beta", "gamma"];
    let mut vault = vault_with_credentials("item", &keys);
    vault
        .reorder_item_credentials("item", &unsectioned(&["gamma", "beta", "alpha"]))
        .unwrap();

    let vault = reload(&vault);
    assert_eq!(
        positions(&vault, "item", &keys),
        vec![Some(2), Some(1), Some(0)]
    );
}

#[test]
fn updating_a_credential_kind_persists_through_a_save() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().kind,
        FieldKind::default()
    );
    populate_caches(&mut vault);

    let new_kind = FieldKind::Text(TextField {
        multiline: Some(true),
    });
    vault
        .add_or_update_item_credential(
            "item",
            "alpha",
            "alpha",
            new_kind.clone(),
            SecretString::from("secret"),
        )
        .unwrap();
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().kind,
        new_kind
    );

    let vault = reload(&vault);
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().kind,
        new_kind
    );
}

fn cred_id(vault: &Vault, item_key: &str, cred_key: &str) -> Uuid {
    vault.get_item_credential(item_key, cred_key).unwrap().id
}

#[test]
fn autofill_survives_a_save_and_decrypts_with_its_own_aad() {
    use crate::secrets::vaults::autofill::item::{MatchKind, Website};

    let mut vault = vault_with_credentials("item", &["username", "password", "totp"]);
    let autofill = ItemAutofill {
        websites: vec![Website::new("github.com", MatchKind::Host)],
        username: Some(cred_id(&vault, "item", "username")),
        password: Some(cred_id(&vault, "item", "password")),
        totp: Some(cred_id(&vault, "item", "totp")),
    };
    vault.set_item_autofill("item", autofill.clone()).unwrap();
    vault
        .set_item_category("item", Some("login".to_string()))
        .unwrap();

    let encrypted = vault.to_encrypted(true).unwrap();
    let item_id = *vault.get_item_id("item").unwrap();
    let enc_item = encrypted.items.get(&item_id).unwrap();
    let blob = enc_item.autofill.as_ref().unwrap();

    let decrypted = vault.cipher.decrypt_item_autofill(item_id, blob).unwrap();
    assert_eq!(*decrypted.expose_secret(), autofill);

    // The blob is bound to its item and role.
    assert!(
        vault
            .cipher
            .decrypt_item_autofill(Uuid::new_v4(), blob)
            .is_err()
    );
    let meta = vault
        .cipher
        .decrypt_item_metadata(item_id, &enc_item.metadata)
        .unwrap();
    assert_eq!(meta.expose_secret().category.as_deref(), Some("login"));
}

#[test]
fn items_without_autofill_store_no_blob() {
    let vault = vault_with_credentials("item", &["password"]);
    let encrypted = vault.to_encrypted(true).unwrap();
    assert!(encrypted.items.values().all(|item| item.autofill.is_none()));
}

#[test]
fn autofill_and_category_survive_delete_and_restore() {
    let mut vault = vault_with_credentials("item", &["username", "password"]);
    let autofill = ItemAutofill {
        username: Some(cred_id(&vault, "item", "username")),
        password: Some(cred_id(&vault, "item", "password")),
        ..Default::default()
    };
    vault.set_item_autofill("item", autofill.clone()).unwrap();
    vault
        .set_item_category("item", Some("login".to_string()))
        .unwrap();
    let item_id = *vault.get_item_id("item").unwrap();

    vault.delete_item("item").unwrap();
    let mut vault = reload(&vault);
    vault.restore_item(item_id, None).unwrap();
    let vault = reload(&vault);

    let item = vault.get_item("item").unwrap();
    assert_eq!(item.autofill, autofill);
    assert_eq!(item.category.as_deref(), Some("login"));
}

#[test]
fn deleting_a_credential_clears_its_role_slot() {
    let mut vault = vault_with_credentials("item", &["username", "password"]);
    vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                username: Some(cred_id(&vault, "item", "username")),
                password: Some(cred_id(&vault, "item", "password")),
                ..Default::default()
            },
        )
        .unwrap();

    vault.delete_item_credential("item", "password").unwrap();

    let item = vault.get_item("item").unwrap();
    assert!(item.autofill.password.is_none());
    assert!(item.autofill.username.is_some());
}

#[test]
fn transferring_a_credential_keeps_its_value_history_and_id() {
    let mut vault = vault_with_credentials("item", &["password"]);
    vault
        .add_or_update_item_credential(
            "item",
            "password",
            "password",
            FieldKind::default(),
            SecretString::from("new"),
        )
        .unwrap();
    let id = cred_id(&vault, "item", "password");
    let section = vault.create_item_section("other-item", "Old").unwrap().id;

    vault
        .transfer_item_credential(
            "item",
            "password",
            "other-item",
            "old-password",
            Some(section),
        )
        .unwrap();
    // The blobs are re-encrypted for the destination, so they decrypt there
    // after a save.
    let vault = reload(&vault);

    assert!(vault.get_item_credential("item", "password").is_err());
    let moved = vault
        .get_item_credential("other-item", "old-password")
        .unwrap();
    assert_eq!(moved.id, id);
    assert_eq!(moved.section, Some(section));
    let value = vault
        .get_item_credential_secret("other-item", "old-password")
        .unwrap()
        .unwrap();
    assert_eq!(value.expose_secret(), "new");
    let history = vault.list_history("other-item", "old-password").unwrap();
    assert_eq!(history.len(), 1);
    let previous = vault
        .get_history_value("other-item", "old-password", history[0].id)
        .unwrap();
    assert_eq!(previous.expose_secret(), "secret");
}

#[test]
fn transferring_a_credential_rejects_a_taken_key() {
    let mut vault = vault_with_credentials("item", &["password"]);
    let err = vault
        .transfer_item_credential("item", "password", "other-item", "elsewhere", None)
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateCredentialKey(_)));
    assert!(vault.get_item_credential("item", "password").is_ok());
}

#[test]
fn restoring_a_credential_gives_back_its_role() {
    let mut vault = vault_with_credentials("item", &["username", "password"]);
    let password = cred_id(&vault, "item", "password");
    vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                username: Some(cred_id(&vault, "item", "username")),
                password: Some(password),
                ..Default::default()
            },
        )
        .unwrap();

    vault.delete_item_credential("item", "password").unwrap();
    // The role survives a save while the credential is deleted.
    let mut vault = reload(&vault);
    vault
        .restore_item_credential("item", password, None)
        .unwrap();
    let vault = reload(&vault);

    let item = vault.get_item("item").unwrap();
    assert_eq!(item.autofill.password, Some(password));
}

#[test]
fn restoring_a_credential_leaves_a_role_another_credential_took() {
    let mut vault = vault_with_credentials("item", &["password", "new-password"]);
    let old = cred_id(&vault, "item", "password");
    let new = cred_id(&vault, "item", "new-password");
    vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                password: Some(old),
                ..Default::default()
            },
        )
        .unwrap();

    vault.delete_item_credential("item", "password").unwrap();
    vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                password: Some(new),
                ..Default::default()
            },
        )
        .unwrap();
    vault.restore_item_credential("item", old, None).unwrap();

    let item = vault.get_item("item").unwrap();
    assert_eq!(item.autofill.password, Some(new));
    assert_eq!(item.autofill.role_of(old), None);
}

#[test]
fn one_credential_cannot_fill_both_roles() {
    let mut vault = vault_with_credentials("item", &["password"]);
    let id = cred_id(&vault, "item", "password");
    let err = vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                username: Some(id),
                password: Some(id),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(matches!(err, Error::InvalidAutofill(_)));
}

#[test]
fn two_websites_with_one_url_are_refused() {
    use crate::secrets::vaults::autofill::item::{MatchKind, Website};

    let mut vault = vault_with_credentials("item", &["password"]);
    let autofill = ItemAutofill {
        websites: vec![
            Website::new("github.com", MatchKind::Domain),
            Website::new("github.com", MatchKind::Host),
        ],
        ..Default::default()
    };
    let err = vault.set_item_autofill("item", autofill).unwrap_err();
    assert!(matches!(err, Error::InvalidAutofill(_)));
    assert!(vault.get_item("item").unwrap().autofill.websites.is_empty());
}

#[test]
fn a_role_slot_must_point_into_the_item() {
    let mut vault = vault_with_credentials("item", &["password"]);
    let elsewhere = cred_id(&vault, "other-item", "elsewhere");
    let err = vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                password: Some(elsewhere),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(matches!(err, Error::InvalidAutofill(_)));
}

#[test]
fn records_resolve_by_id_after_a_credential_is_renamed() {
    let mut vault = vault_with_credentials("item", &["password"]);
    let item_id = *vault.get_item_id("item").unwrap();
    let id = cred_id(&vault, "item", "password");

    vault
        .add_or_update_item_credential(
            "item",
            "password",
            "Renamed",
            FieldKind::default(),
            SecretString::from("new-secret"),
        )
        .unwrap();

    let secret = vault
        .get_item_credential_secret_by_id(item_id, id)
        .unwrap()
        .unwrap();
    assert_eq!(secret.expose_secret(), "new-secret");
    assert_eq!(
        vault.get_item_credential_by_id(item_id, id).unwrap().title,
        "Renamed"
    );
    assert!(vault.get_item_by_id(Uuid::new_v4()).is_err());
    assert!(
        vault
            .get_item_credential_by_id(item_id, Uuid::new_v4())
            .is_err()
    );
}

#[test]
fn legacy_item_metadata_without_category_loads() {
    let meta: VaultItemMetadata = serde_json::from_str(r#"{"title":"Item","key":"item"}"#).unwrap();
    assert_eq!(meta.category, None);
    let json = serde_json::to_value(&meta).unwrap();
    assert!(json.get("category").is_none());
}

#[test]
fn default_kind_is_omitted_from_json() {
    let meta = cred_metadata("Password", "password", FieldKind::default());
    let json = serde_json::to_value(&meta).unwrap();
    assert!(json.get("kind").is_none());
}

#[test]
fn legacy_metadata_without_kind_loads_as_default() {
    let meta: VaultCredentialMetadata =
        serde_json::from_str(r#"{"title":"Password","key":"password"}"#).unwrap();
    assert_eq!(meta.kind, FieldKind::default());
}

#[test]
fn position_is_omitted_when_unset_and_roundtrips_when_set() {
    let meta = cred_metadata("Password", "password", FieldKind::default());
    let json = serde_json::to_value(&meta).unwrap();
    assert!(json.get("position").is_none());

    let mut meta = meta;
    meta.position = Some(2);
    let json = serde_json::to_value(&meta).unwrap();
    assert_eq!(json.get("position").and_then(|v| v.as_u64()), Some(2));
    let back: VaultCredentialMetadata = serde_json::from_value(json).unwrap();
    assert_eq!(back.position, Some(2));
}

#[test]
fn legacy_metadata_without_position_loads_as_none() {
    let meta: VaultCredentialMetadata =
        serde_json::from_str(r#"{"title":"Password","key":"password"}"#).unwrap();
    assert_eq!(meta.position, None);
    assert_eq!(meta.section, None);
}

#[test]
fn non_default_kind_roundtrips_through_metadata() {
    let meta = cred_metadata(
        "Notes",
        "notes",
        FieldKind::Text(TextField {
            multiline: Some(true),
        }),
    );
    let json = serde_json::to_value(&meta).unwrap();
    let back: VaultCredentialMetadata = serde_json::from_value(json).unwrap();
    assert_eq!(back.kind, meta.kind);
}

#[test]
fn legacy_item_metadata_loads_unfiled_without_sections() {
    let meta: VaultItemMetadata = serde_json::from_str(r#"{"title":"Item","key":"item"}"#).unwrap();
    assert_eq!(meta.folder, None);
    assert!(meta.sections.is_empty());

    let json = serde_json::to_value(&meta).unwrap();
    assert!(json.get("folder").is_none());
    assert!(json.get("sections").is_none());
}

#[test]
fn folders_and_filing_survive_a_save_and_load() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let folder_id = vault.create_folder(" Work ").id;
    vault.move_item("item", Some(folder_id)).unwrap();

    let vault = reload(&vault);
    assert_eq!(vault.get_folder(folder_id).unwrap().title, "Work");
    assert_eq!(vault.get_item("item").unwrap().folder, Some(folder_id));
    assert_eq!(vault.get_item("other-item").unwrap().folder, None);
}

#[test]
fn moving_an_item_invalidates_its_cached_metadata() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let folder_id = vault.create_folder("Work").id;
    populate_caches(&mut vault);

    vault.move_item("item", Some(folder_id)).unwrap();
    let vault = reload(&vault);
    assert_eq!(vault.get_item("item").unwrap().folder, Some(folder_id));
}

#[test]
fn moving_an_item_to_an_unknown_folder_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let err = vault.move_item("item", Some(Uuid::new_v4())).unwrap_err();
    assert!(matches!(err, Error::InvalidFolder(_)));
    assert_eq!(vault.get_item("item").unwrap().folder, None);
}

#[test]
fn renaming_a_folder_persists() {
    let mut vault = test_vault();
    let folder_id = vault.create_folder("Work").id;
    populate_caches(&mut vault);

    vault.rename_folder(folder_id, "Personal").unwrap();
    let vault = reload(&vault);
    assert_eq!(vault.get_folder(folder_id).unwrap().title, "Personal");
}

#[test]
fn deleting_a_folder_unfiles_its_items() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let folder_id = vault.create_folder("Work").id;
    vault.move_item("item", Some(folder_id)).unwrap();
    populate_caches(&mut vault);

    vault.delete_folder(folder_id).unwrap();
    assert_eq!(vault.get_item("item").unwrap().folder, None);

    let vault = reload(&vault);
    assert!(vault.list_folders().is_empty());
    assert_eq!(vault.get_item("item").unwrap().folder, None);
    assert!(vault.get_item_credential("item", "alpha").is_ok());
}

#[test]
fn passkey_reports_persist_in_the_vault_metadata() {
    use crate::secrets::vaults::passkey::signals::Report;

    let mut vault = test_vault();
    let folder_id = vault.create_folder("Work").id;
    populate_caches(&mut vault);

    let mut reports = SignalStore::new();
    reports.record(
        Report::Unknown {
            rp_id: "example.com".into(),
            credential_id: vec![1],
        },
        10,
    );
    vault.update_passkey_signals(|store| store.merge(&reports));
    let vault = reload(&vault);
    assert_eq!(vault.passkey_signals(), &reports);
    assert_eq!(vault.get_folder(folder_id).unwrap().title, "Work");
}

#[test]
fn an_item_in_a_missing_folder_loads_unfiled() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let folder_id = vault.create_folder("Work").id;
    vault.move_item("item", Some(folder_id)).unwrap();

    let mut encrypted = vault.to_encrypted(true).unwrap();
    encrypted.metadata = None;
    let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
    let vault = Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap();

    assert_eq!(vault.get_item("item").unwrap().folder, None);
    // The stale blob is not cached, so the next save writes the fix.
    assert!(
        !vault
            .item_blobs
            .contains_key(&vault.get_item("item").unwrap().id)
    );
}

#[test]
fn reorder_folders_requires_every_folder_once() {
    let mut vault = test_vault();
    let a = vault.create_folder("A").id;
    let b = vault.create_folder("B").id;

    assert!(matches!(
        vault.reorder_folders(&[a]),
        Err(Error::InvalidFolderOrder)
    ));
    assert!(matches!(
        vault.reorder_folders(&[a, a]),
        Err(Error::InvalidFolderOrder)
    ));
    assert!(matches!(
        vault.reorder_folders(&[a, Uuid::new_v4()]),
        Err(Error::InvalidFolderOrder)
    ));

    vault.reorder_folders(&[b, a]).unwrap();
    let vault = reload(&vault);
    assert_eq!(vault.get_folder(b).unwrap().position, Some(0));
    assert_eq!(vault.get_folder(a).unwrap().position, Some(1));
}

#[test]
fn sections_and_placement_survive_a_save_and_load() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    vault
        .move_item_credential("item", "beta", Some(section_id))
        .unwrap();

    let vault = reload(&vault);
    let item = vault.get_item("item").unwrap();
    assert_eq!(item.sections.get(&section_id).unwrap().title, "Login");
    assert_eq!(
        vault.get_item_credential("item", "beta").unwrap().section,
        Some(section_id)
    );
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().section,
        None
    );
}

#[test]
fn moving_a_credential_to_another_items_section_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let other_section = vault.create_item_section("other-item", "S").unwrap().id;
    let err = vault
        .move_item_credential("item", "alpha", Some(other_section))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidSection(_)));
}

#[test]
fn deleting_a_section_keeps_its_credentials() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    vault
        .move_item_credential("item", "alpha", Some(section_id))
        .unwrap();
    populate_caches(&mut vault);

    vault.delete_item_section("item", section_id).unwrap();

    let vault = reload(&vault);
    assert!(vault.get_item("item").unwrap().sections.is_empty());
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().section,
        None
    );
}

#[test]
fn updating_a_credential_keeps_its_value_and_persists() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    populate_caches(&mut vault);

    let new_kind = FieldKind::Text(TextField {
        multiline: Some(true),
    });
    vault
        .update_item_credential(
            "item",
            "alpha",
            CredentialUpdate {
                key: Some("renamed".to_string()),
                title: Some(" Renamed ".to_string()),
                kind: Some(new_kind.clone()),
            },
        )
        .unwrap();

    let vault = reload(&vault);
    assert!(matches!(
        vault.get_item_credential("item", "alpha"),
        Err(Error::InvalidCredentialKey(_))
    ));
    let cred = vault.get_item_credential("item", "renamed").unwrap();
    assert_eq!(cred.title, "Renamed");
    assert_eq!(cred.kind, new_kind);
    let secret = vault
        .get_item_credential_secret("item", "renamed")
        .unwrap()
        .unwrap();
    assert_eq!(secret.expose_secret(), "secret");
}

#[test]
fn marking_a_credential_used_persists_without_history() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    populate_caches(&mut vault);
    let marked = vault
        .mark_credential_used("item", "alpha", 1_750_000_000, &TimeZone::UTC)
        .unwrap();
    assert!(marked);

    let vault = reload(&vault);
    let cred = vault.get_item_credential("item", "alpha").unwrap();
    assert_eq!(cred.last_used_day_at, Some(1_750_000_000));
    assert!(vault.list_history("item", "alpha").unwrap().is_empty());
    let secret = vault
        .get_item_credential_secret("item", "alpha")
        .unwrap()
        .unwrap();
    assert_eq!(secret.expose_secret(), "secret");
}

#[test]
fn a_use_on_the_same_local_day_is_not_written() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let zone = TimeZone::fixed(jiff::tz::Offset::from_seconds(-7 * 3600).unwrap());
    // 2026-10-22 08:00 at UTC-7.
    let first = 1_792_713_600 - 9 * 3600;
    assert!(
        vault
            .mark_credential_used("item", "alpha", first, &zone)
            .unwrap()
    );
    populate_caches(&mut vault);
    let (_, cred_id) = vault.get_credential_ids("item", "alpha").unwrap();
    let cached = |vault: &Vault| {
        vault
            .cred_blobs
            .get(&cred_id)
            .map(|blob| serde_json::to_string(blob).unwrap())
    };
    let before = cached(&vault);
    assert!(before.is_some());

    // 23:59 the same day at UTC-7, and on the next day in UTC.
    let marked = vault
        .mark_credential_used("item", "alpha", first + 15 * 3600 + 59 * 60, &zone)
        .unwrap();

    assert!(!marked);
    assert_eq!(cached(&vault), before);
    let cred = vault.get_item_credential("item", "alpha").unwrap();
    assert_eq!(cred.last_used_day_at, Some(first));
}

#[test]
fn adding_a_credential_with_a_taken_key_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let err = vault
        .add_item_credential(
            "item",
            "alpha",
            "Title",
            FieldKind::default(),
            SecretString::from("other".to_string()),
        )
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateCredentialKey(_)));
    let secret = vault
        .get_item_credential_secret("item", "alpha")
        .unwrap()
        .unwrap();
    assert_ne!(secret.expose_secret(), "other");
    vault
        .add_item_credential(
            "item",
            "gamma",
            "Title",
            FieldKind::default(),
            SecretString::from("new".to_string()),
        )
        .unwrap();
}

#[test]
fn updating_a_credential_to_a_taken_key_fails() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let err = vault
        .update_item_credential(
            "item",
            "alpha",
            CredentialUpdate {
                key: Some("beta".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateCredentialKey(_)));
    // The same key is not a conflict with itself.
    vault
        .update_item_credential(
            "item",
            "alpha",
            CredentialUpdate {
                key: Some("alpha".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
}

#[test]
fn renaming_and_reordering_sections_persists() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let a = vault.create_item_section("item", "A").unwrap().id;
    let b = vault.create_item_section("item", "B").unwrap().id;
    populate_caches(&mut vault);

    vault.rename_item_section("item", a, "Renamed").unwrap();
    assert!(matches!(
        vault.reorder_item_sections("item", &[b]),
        Err(Error::InvalidSectionOrder(_))
    ));
    vault.reorder_item_sections("item", &[b, a]).unwrap();

    let vault = reload(&vault);
    let sections = &vault.get_item("item").unwrap().sections;
    assert_eq!(sections.get(&a).unwrap().title, "Renamed");
    assert_eq!(sections.get(&a).unwrap().position, Some(1));
    assert_eq!(sections.get(&b).unwrap().position, Some(0));
}

#[test]
fn new_sections_go_last_regardless_of_title() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let a = vault.create_item_section("item", "zeta").unwrap().id;
    let b = vault.create_item_section("item", "Alpha").unwrap().id;
    // Without a position this section would sort first by title.
    let mut legacy = VaultItemSection::new("beta");
    legacy.position = None;
    let legacy_id = legacy.id;
    vault
        .edit_item("item", |item| {
            item.sections.insert(legacy_id, legacy);
            Ok(())
        })
        .unwrap();
    let c = vault.create_item_section("item", "Another").unwrap().id;

    let sections = &vault.get_item("item").unwrap().sections;
    let position = |id: Uuid| sections.get(&id).unwrap().position;
    assert_eq!(
        [position(a), position(b), position(legacy_id), position(c)],
        [Some(0), Some(1), Some(2), Some(3)]
    );
}

#[test]
fn reorder_sets_sections_and_positions() {
    let keys = ["alpha", "beta", "gamma"];
    let mut vault = vault_with_credentials("item", &keys);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;

    let placements = vec![
        CredentialPlacement {
            key: "gamma".to_string(),
            section: None,
        },
        CredentialPlacement {
            key: "alpha".to_string(),
            section: Some(section_id),
        },
        CredentialPlacement {
            key: "beta".to_string(),
            section: Some(section_id),
        },
    ];
    vault.reorder_item_credentials("item", &placements).unwrap();

    let vault = reload(&vault);
    assert_eq!(
        positions(&vault, "item", &keys),
        vec![Some(1), Some(2), Some(0)]
    );
    let sections: Vec<Option<Uuid>> = keys
        .iter()
        .map(|k| vault.get_item_credential("item", k).unwrap().section)
        .collect();
    assert_eq!(sections, vec![Some(section_id), Some(section_id), None]);
}

#[test]
fn reorder_rejects_an_unknown_section_without_changes() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let placements = vec![CredentialPlacement {
        key: "alpha".to_string(),
        section: Some(Uuid::new_v4()),
    }];
    let err = vault
        .reorder_item_credentials("item", &placements)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidSection(_)));
    assert_eq!(positions(&vault, "item", &["alpha"]), vec![None]);
}

#[test]
fn a_credential_in_a_missing_section_loads_unsectioned() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    vault
        .move_item_credential("item", "alpha", Some(section_id))
        .unwrap();
    // Drop the section from the item without touching the credential, as
    // a stale or hand-edited file could.
    vault
        .items
        .values_mut()
        .for_each(|item| item.sections.clear());

    let vault = reload(&vault);
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().section,
        None
    );
}

#[test]
fn deleting_an_item_drops_its_cached_credential_metadata() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    populate_caches(&mut vault);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

    vault.delete_item("item").unwrap();
    assert!(!vault.cred_blobs.contains_key(&cred_id));
}

fn deleted_ids(vault: &Vault, item_key: &str) -> Vec<Uuid> {
    vault
        .list_deleted(item_key)
        .unwrap()
        .iter()
        .map(|t| t.credential.id)
        .collect()
}

fn secret_of(vault: &Vault, item_key: &str, cred_key: &str) -> String {
    vault
        .get_item_credential_secret(item_key, cred_key)
        .unwrap()
        .unwrap()
        .expose_secret()
        .clone()
}

#[test]
fn deleted_credentials_survive_a_save_and_load_as_deleted() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    populate_caches(&mut vault);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

    vault.delete_item_credential("item", "alpha").unwrap();
    assert!(vault.get_item_credential("item", "alpha").is_err());
    assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);

    let vault = reload(&vault);
    assert!(vault.get_item_credential("item", "alpha").is_err());
    assert!(vault.get_item_credential("item", "beta").is_ok());
    let deleted = vault.list_deleted("item").unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].credential.id, cred_id);
    assert_eq!(deleted[0].credential.key, "alpha");
    assert!(deleted[0].deleted_at > 0);
    assert!(vault.list_deleted("other-item").unwrap().is_empty());
}

#[test]
fn deleting_a_credential_frees_its_key() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    vault
        .add_item_credential(
            "item",
            "alpha",
            "New",
            FieldKind::default(),
            SecretString::from("new".to_string()),
        )
        .unwrap();
    assert_eq!(secret_of(&vault, "item", "alpha"), "new");
    assert_eq!(deleted_ids(&vault, "item").len(), 1);
}

#[test]
fn restoring_keeps_id_value_position_and_section() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    let placements = vec![
        CredentialPlacement {
            key: "beta".to_string(),
            section: None,
        },
        CredentialPlacement {
            key: "alpha".to_string(),
            section: Some(section_id),
        },
    ];
    vault.reorder_item_credentials("item", &placements).unwrap();
    populate_caches(&mut vault);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

    vault.delete_item_credential("item", "alpha").unwrap();
    let mut vault = reload(&vault);
    vault
        .restore_item_credential("item", cred_id, None)
        .unwrap();
    assert!(deleted_ids(&vault, "item").is_empty());

    let vault = reload(&vault);
    let cred = vault.get_item_credential("item", "alpha").unwrap();
    assert_eq!(cred.id, cred_id);
    assert_eq!(cred.position, Some(1));
    assert_eq!(cred.section, Some(section_id));
    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
}

#[test]
fn restoring_into_a_deleted_section_drops_the_section() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    vault
        .move_item_credential("item", "alpha", Some(section_id))
        .unwrap();
    populate_caches(&mut vault);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

    vault.delete_item_credential("item", "alpha").unwrap();
    vault.delete_item_section("item", section_id).unwrap();
    vault
        .restore_item_credential("item", cred_id, None)
        .unwrap();

    let vault = reload(&vault);
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().section,
        None
    );
}

#[test]
fn restoring_with_a_taken_key_fails_unless_a_new_key_is_given() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    populate_caches(&mut vault);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;
    vault.delete_item_credential("item", "alpha").unwrap();
    vault
        .add_item_credential(
            "item",
            "alpha",
            "New",
            FieldKind::default(),
            SecretString::from("new".to_string()),
        )
        .unwrap();

    let err = vault
        .restore_item_credential("item", cred_id, None)
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateCredentialKey(_)));
    let err = vault
        .restore_item_credential("item", cred_id, Some("alpha".to_string()))
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateCredentialKey(_)));
    // A failed restore leaves the credential deleted.
    assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);

    vault
        .restore_item_credential("item", cred_id, Some("alpha-old".to_string()))
        .unwrap();
    let vault = reload(&vault);
    assert_eq!(secret_of(&vault, "item", "alpha-old"), "secret");
    assert_eq!(secret_of(&vault, "item", "alpha"), "new");
    assert_eq!(
        vault.get_item_credential("item", "alpha-old").unwrap().id,
        cred_id
    );
}

#[test]
fn restoring_with_an_invalid_new_key_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;
    vault.delete_item_credential("item", "alpha").unwrap();
    let err = vault
        .restore_item_credential("item", cred_id, Some("  ".to_string()))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialKey(_)));
    assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);
}

#[test]
fn restoring_through_another_item_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;
    vault.delete_item_credential("item", "alpha").unwrap();
    let err = vault
        .restore_item_credential("other-item", cred_id, None)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialKey(_)));
    let err = vault
        .purge_item_credential("other-item", cred_id)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialKey(_)));
    assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);
}

#[test]
fn purging_removes_a_deleted_credential_for_good() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let alpha = vault.get_item_credential("item", "alpha").unwrap().id;
    vault.delete_item_credential("item", "alpha").unwrap();
    vault.delete_item_credential("item", "beta").unwrap();

    vault.purge_item_credential("item", alpha).unwrap();
    assert!(matches!(
        vault.restore_item_credential("item", alpha, None),
        Err(Error::InvalidCredentialKey(_))
    ));

    let vault = reload(&vault);
    assert_eq!(vault.list_deleted("item").unwrap().len(), 1);
    assert_eq!(
        vault.list_deleted("item").unwrap()[0].credential.key,
        "beta"
    );
}

#[test]
fn purge_deleted_removes_entries_older_than_the_cutoff() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    vault.delete_item_credential("item", "beta").unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    assert_eq!(vault.purge_deleted(0), 0);
    assert_eq!(vault.list_deleted("item").unwrap().len(), 2);
    assert_eq!(vault.purge_deleted(now + 10), 2);
    assert!(vault.list_deleted("item").unwrap().is_empty());
}

fn item_id_of(vault: &Vault, item_key: &str) -> Uuid {
    *vault.get_item_id(item_key).unwrap()
}

#[test]
fn a_deleted_item_survives_a_save_and_load_and_frees_its_key() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    populate_caches(&mut vault);
    let item_id = item_id_of(&vault, "item");

    vault.delete_item("item").unwrap();
    assert!(vault.get_item("item").is_err());
    assert!(vault.get_item_credential("item", "alpha").is_err());
    assert!(vault.get_item("other-item").is_ok());

    let mut vault = reload(&vault);
    assert!(vault.get_item("item").is_err());
    let deleted = vault.list_deleted_items();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].item.id, item_id);
    assert_eq!(deleted[0].item.key, "item");
    assert_eq!(deleted[0].item.credentials.len(), 2);
    assert!(deleted[0].deleted_at > 0);

    // The key can be used by a new item.
    vault.add_or_update_item("item", "New").unwrap();
    assert_ne!(item_id_of(&vault, "item"), item_id);
}

#[test]
fn restoring_an_item_brings_back_credentials_values_and_layout() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let folder_id = vault.create_folder("Work").id;
    vault.move_item("item", Some(folder_id)).unwrap();
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    vault
        .move_item_credential("item", "beta", Some(section_id))
        .unwrap();
    let alpha_id = vault.get_item_credential("item", "alpha").unwrap().id;
    populate_caches(&mut vault);
    let item_id = item_id_of(&vault, "item");

    vault.delete_item("item").unwrap();
    let mut vault = reload(&vault);
    vault.restore_item(item_id, None).unwrap();
    assert!(vault.list_deleted_items().is_empty());

    let vault = reload(&vault);
    let item = vault.get_item("item").unwrap();
    assert_eq!(item.id, item_id);
    assert_eq!(item.folder, Some(folder_id));
    assert_eq!(item.sections.get(&section_id).unwrap().title, "Login");
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().id,
        alpha_id
    );
    assert_eq!(
        vault.get_item_credential("item", "beta").unwrap().section,
        Some(section_id)
    );
    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    assert_eq!(secret_of(&vault, "item", "beta"), "secret");
}

#[test]
fn a_deleted_item_keeps_its_own_deleted_credentials() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    populate_caches(&mut vault);
    let alpha_id = vault.get_item_credential("item", "alpha").unwrap().id;
    let item_id = item_id_of(&vault, "item");
    vault.delete_item_credential("item", "alpha").unwrap();

    vault.delete_item("item").unwrap();
    assert!(vault.deleted.is_empty());
    assert_eq!(vault.list_deleted_items()[0].deleted_credentials.len(), 1);

    let mut vault = reload(&vault);
    vault.restore_item(item_id, None).unwrap();
    assert_eq!(deleted_ids(&vault, "item"), vec![alpha_id]);
    assert!(vault.get_item_credential("item", "beta").is_ok());

    vault
        .restore_item_credential("item", alpha_id, None)
        .unwrap();
    let vault = reload(&vault);
    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
}

#[test]
fn restoring_an_item_with_a_taken_key_fails_unless_a_new_key_is_given() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let item_id = item_id_of(&vault, "item");
    vault.delete_item("item").unwrap();
    vault.add_or_update_item("item", "New").unwrap();

    let err = vault.restore_item(item_id, None).unwrap_err();
    assert!(matches!(err, Error::DuplicateItemKey(_)));
    let err = vault
        .restore_item(item_id, Some("item".to_string()))
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateItemKey(_)));
    let err = vault
        .restore_item(item_id, Some("  ".to_string()))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidItemKey(_)));
    // A failed restore leaves the item deleted.
    assert_eq!(vault.list_deleted_items().len(), 1);

    vault
        .restore_item(item_id, Some("item-old".to_string()))
        .unwrap();
    let vault = reload(&vault);
    assert_eq!(vault.get_item("item-old").unwrap().id, item_id);
    assert_eq!(secret_of(&vault, "item-old", "alpha"), "secret");
    assert_ne!(item_id_of(&vault, "item"), item_id);
}

#[test]
fn restoring_an_item_into_a_deleted_folder_unfiles_it() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let folder_id = vault.create_folder("Work").id;
    vault.move_item("item", Some(folder_id)).unwrap();
    populate_caches(&mut vault);
    let item_id = item_id_of(&vault, "item");

    vault.delete_item("item").unwrap();
    vault.delete_folder(folder_id).unwrap();
    vault.restore_item(item_id, None).unwrap();

    let vault = reload(&vault);
    assert_eq!(vault.get_item("item").unwrap().folder, None);
}

fn deleted_secret_of(vault: &Vault, item_id: Uuid, cred_id: Uuid) -> String {
    vault
        .get_deleted_credential_secret(item_id, cred_id)
        .unwrap()
        .expose_secret()
        .clone()
}

#[test]
fn list_all_deleted_lists_credentials_of_live_items_with_their_item() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let alpha_id = vault.get_item_credential("item", "alpha").unwrap().id;
    let elsewhere_id = vault
        .get_item_credential("other-item", "elsewhere")
        .unwrap()
        .id;
    vault.delete_item_credential("item", "alpha").unwrap();
    vault
        .delete_item_credential("other-item", "elsewhere")
        .unwrap();

    let vault = reload(&vault);
    let all = vault.list_all_deleted();
    let mut found: Vec<(Uuid, &str)> = all
        .iter()
        .map(|e| (e.credential.credential.id, e.item.key.as_str()))
        .collect();
    found.sort();
    let mut expected = vec![(alpha_id, "item"), (elsewhere_id, "other-item")];
    expected.sort();
    assert_eq!(found, expected);
}

#[test]
fn list_all_deleted_leaves_out_credentials_of_deleted_items() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    vault.delete_item("item").unwrap();
    assert!(vault.list_all_deleted().is_empty());
}

#[test]
fn deleted_secrets_can_be_read_in_every_deleted_location() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let item_id = item_id_of(&vault, "item");
    let alpha_id = vault.get_item_credential("item", "alpha").unwrap().id;
    let beta_id = vault.get_item_credential("item", "beta").unwrap().id;
    let other_item_id = item_id_of(&vault, "other-item");

    // Deleted from a live item.
    vault.delete_item_credential("item", "alpha").unwrap();
    let vault = reload(&vault);
    assert_eq!(deleted_secret_of(&vault, item_id, alpha_id), "secret");

    // In a deleted item, and deleted before the item.
    let mut vault = vault;
    vault.delete_item("item").unwrap();
    let vault = reload(&vault);
    assert_eq!(deleted_secret_of(&vault, item_id, alpha_id), "secret");
    assert_eq!(deleted_secret_of(&vault, item_id, beta_id), "secret");

    // A credential id is only valid with its own item.
    assert!(matches!(
        vault.get_deleted_credential_secret(other_item_id, alpha_id),
        Err(Error::InvalidCredentialKey(_))
    ));
    assert!(matches!(
        vault.get_deleted_credential_secret(item_id, Uuid::new_v4()),
        Err(Error::InvalidCredentialKey(_))
    ));
}

#[test]
fn a_live_credential_has_no_deleted_secret() {
    let vault = vault_with_credentials("item", &["alpha"]);
    let item_id = item_id_of(&vault, "item");
    let alpha_id = vault.get_item_credential("item", "alpha").unwrap().id;
    assert!(matches!(
        vault.get_deleted_credential_secret(item_id, alpha_id),
        Err(Error::InvalidCredentialKey(_))
    ));
}

fn set_value(vault: &mut Vault, item_key: &str, cred_key: &str, value: &str) {
    vault
        .add_or_update_item_credential(
            item_key,
            cred_key,
            cred_key,
            FieldKind::default(),
            SecretString::from(value.to_string()),
        )
        .unwrap();
}

fn history_values(vault: &Vault, item_key: &str, cred_key: &str) -> Vec<String> {
    vault
        .list_history(item_key, cred_key)
        .unwrap()
        .iter()
        .map(|h| {
            vault
                .get_history_value(item_key, cred_key, h.id)
                .unwrap()
                .expose_secret()
                .clone()
        })
        .collect()
}

#[test]
fn changing_a_value_keeps_the_old_value_in_the_history() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    assert!(vault.list_history("item", "alpha").unwrap().is_empty());

    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");

    assert_eq!(secret_of(&vault, "item", "alpha"), "third");
    // Most recently replaced first.
    assert_eq!(
        history_values(&vault, "item", "alpha"),
        vec!["second", "secret"]
    );
    assert!(
        vault
            .list_history("item", "alpha")
            .unwrap()
            .iter()
            .all(|h| h.replaced_at > 0)
    );
}

#[test]
fn saving_the_same_or_a_first_or_an_empty_value_adds_no_history() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "secret");
    assert!(vault.list_history("item", "alpha").unwrap().is_empty());

    // A credential created with no value yet, then given one.
    vault
        .add_item_credential(
            "item",
            "empty",
            "Empty",
            FieldKind::default(),
            SecretString::from(String::new()),
        )
        .unwrap();
    set_value(&mut vault, "item", "empty", "first");
    assert!(vault.list_history("item", "empty").unwrap().is_empty());
    set_value(&mut vault, "item", "empty", "second");
    assert_eq!(history_values(&vault, "item", "empty"), vec!["first"]);
}

#[test]
fn history_survives_a_save_and_load() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");

    let vault = reload(&vault);
    assert_eq!(secret_of(&vault, "item", "alpha"), "third");
    assert_eq!(
        history_values(&vault, "item", "alpha"),
        vec!["second", "secret"]
    );
}

#[test]
fn restoring_a_previous_value_swaps_it_with_the_current_value() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    let first = vault.list_history("item", "alpha").unwrap()[0].id;

    vault.restore_history_value("item", "alpha", first).unwrap();

    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["second"]);
    let vault = reload(&vault);
    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["second"]);
}

#[test]
fn restoring_the_only_previous_value_over_an_empty_value_clears_the_history() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "");
    let first = vault.list_history("item", "alpha").unwrap()[0].id;

    vault.restore_history_value("item", "alpha", first).unwrap();

    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    assert!(vault.history.is_empty());
}

#[test]
fn history_info_that_fails_to_decrypt_fails_the_load() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");
    let item_id = item_id_of(&vault, "item");
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

    let mut encrypted = vault.to_encrypted(true).unwrap();
    let cred = encrypted
        .items
        .get_mut(&item_id)
        .unwrap()
        .credentials
        .get_mut(&cred_id)
        .unwrap();
    let first_info = cred.history[0].info.clone();
    cred.history[1].info = first_info;
    let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);

    let result = Vault::from_encrypted_with_cipher(cipher, encrypted);
    assert!(matches!(result, Err(Error::VaultSecretDecryptionError)));
}

#[test]
fn restoring_an_unknown_previous_value_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    assert!(matches!(
        vault.restore_history_value("item", "alpha", Uuid::new_v4()),
        Err(Error::InvalidHistoryEntry(_))
    ));
    assert!(matches!(
        vault.get_history_value("item", "alpha", Uuid::new_v4()),
        Err(Error::InvalidHistoryEntry(_))
    ));
    assert!(matches!(
        vault.purge_history("item", "alpha", Uuid::new_v4()),
        Err(Error::InvalidHistoryEntry(_))
    ));
    assert_eq!(secret_of(&vault, "item", "alpha"), "second");
}

#[test]
fn purging_a_previous_value_removes_it_for_good() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");
    let newest = vault.list_history("item", "alpha").unwrap()[0].id;

    vault.purge_history("item", "alpha", newest).unwrap();
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);

    let vault = reload(&vault);
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
    assert_eq!(secret_of(&vault, "item", "alpha"), "third");
}

#[test]
fn history_follows_a_credential_through_delete_and_restore() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

    vault.delete_item_credential("item", "alpha").unwrap();
    assert!(vault.history.is_empty());

    let mut vault = reload(&vault);
    vault
        .restore_item_credential("item", cred_id, None)
        .unwrap();
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
    assert_eq!(secret_of(&vault, "item", "alpha"), "second");
}

#[test]
fn history_follows_a_credential_through_item_delete_and_restore() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    let item_id = item_id_of(&vault, "item");

    vault.delete_item("item").unwrap();
    assert!(vault.history.is_empty());

    let mut vault = reload(&vault);
    vault.restore_item(item_id, None).unwrap();
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);

    let vault = reload(&vault);
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
    assert_eq!(secret_of(&vault, "item", "alpha"), "second");
}

#[test]
fn history_is_exported_and_omitted_from_the_file_when_empty() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    set_value(&mut vault, "item", "alpha", "second");

    let json = serde_json::to_value(vault.to_encrypted(false).unwrap()).unwrap();
    let creds = json["items"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|item| item["credentials"].as_object().unwrap().values())
        .collect::<Vec<_>>();
    assert_eq!(
        creds.iter().filter(|c| c.get("history").is_some()).count(),
        1
    );
}

#[test]
fn a_previous_value_cannot_be_swapped_into_another_place() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");
    let item_id = item_id_of(&vault, "item");
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

    let load = |encrypted: EncryptedVault| {
        let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
        Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap()
    };

    // A history value in the live value's place.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let cred = encrypted
        .items
        .get_mut(&item_id)
        .unwrap()
        .credentials
        .get_mut(&cred_id)
        .unwrap();
    cred.value = cred.history[0].value.clone();
    let swapped = load(encrypted);
    assert!(swapped.get_item_credential_secret("item", "alpha").is_err());

    // A history value in another history entry's place.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let cred = encrypted
        .items
        .get_mut(&item_id)
        .unwrap()
        .credentials
        .get_mut(&cred_id)
        .unwrap();
    let first_value = cred.history[0].value.clone();
    cred.history[1].value = first_value;
    let swapped = load(encrypted);
    let ids: Vec<Uuid> = swapped
        .list_history("item", "alpha")
        .unwrap()
        .iter()
        .map(|h| h.id)
        .collect();
    let decrypted: Vec<bool> = ids
        .iter()
        .map(|id| swapped.get_history_value("item", "alpha", *id).is_ok())
        .collect();
    // Only the entry that kept its own value decrypts.
    assert_eq!(decrypted.iter().filter(|ok| **ok).count(), 1);
}

#[test]
fn purging_an_item_removes_it_and_its_deleted_credentials() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    let item_id = item_id_of(&vault, "item");
    vault.delete_item("item").unwrap();

    vault.purge_item(item_id).unwrap();
    assert!(matches!(
        vault.restore_item(item_id, None),
        Err(Error::DeletedItemNotFound(_))
    ));
    assert!(matches!(
        vault.purge_item(item_id),
        Err(Error::DeletedItemNotFound(_))
    ));

    let encrypted = vault.to_encrypted(true).unwrap();
    assert!(encrypted.deleted.is_empty());
    assert!(vault.deleted.is_empty());
}

#[test]
fn purge_deleted_includes_deleted_credentials_of_deleted_items() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    vault
        .delete_item_credential("other-item", "elsewhere")
        .unwrap();
    let item_id = item_id_of(&vault, "item");
    vault.delete_item("item").unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    assert_eq!(vault.purge_deleted(now + 10), 2);
    assert!(vault.deleted.is_empty());
    assert_eq!(vault.list_deleted_items()[0].deleted_credentials.len(), 0);

    // The deleted item itself is kept.
    vault.restore_item(item_id, None).unwrap();
    assert!(vault.list_deleted("item").unwrap().is_empty());
    assert!(vault.get_item_credential("item", "beta").is_ok());
}

#[test]
fn purge_deleted_items_removes_entries_older_than_the_cutoff() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item("item").unwrap();
    vault.delete_item("other-item").unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    assert_eq!(vault.purge_deleted_items(0), 0);
    assert_eq!(vault.list_deleted_items().len(), 2);
    assert_eq!(vault.purge_deleted_items(now + 10), 2);
    assert!(vault.list_deleted_items().is_empty());
}

#[test]
fn bundled_export_leaves_out_deleted_items() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item("item").unwrap();

    assert_eq!(vault.to_encrypted(true).unwrap().deleted.len(), 1);
    let without = vault.to_encrypted(false).unwrap();
    assert!(without.deleted.is_empty());
    assert_eq!(without.items.len(), 1);
}

#[test]
fn vault_file_without_deleted_field_loads_with_no_deleted_items() {
    let vault = vault_with_credentials("item", &["alpha"]);
    let json = serde_json::to_value(vault.to_encrypted(true).unwrap()).unwrap();
    assert!(json.get("deleted").is_none());

    let encrypted: EncryptedVault = serde_json::from_value(json).unwrap();
    let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
    let vault = Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap();
    assert!(vault.list_deleted_items().is_empty());
}

#[test]
fn deleted_item_info_is_bound_to_its_item() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item("item").unwrap();
    vault.delete_item("other-item").unwrap();

    // Swap the info blobs of the two deleted items.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let mut entries = encrypted.deleted.values_mut();
    let (first, second) = (entries.next().unwrap(), entries.next().unwrap());
    std::mem::swap(&mut first.info, &mut second.info);

    let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
    assert!(Vault::from_encrypted_with_cipher(cipher, encrypted).is_err());
}

#[test]
fn bundled_export_leaves_out_the_deleted() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item_credential("item", "alpha").unwrap();

    let with_deleted = vault.to_encrypted(true).unwrap();
    assert!(
        with_deleted
            .items
            .values()
            .any(|item| !item.deleted.is_empty())
    );
    let without_deleted = vault.to_encrypted(false).unwrap();
    assert!(
        without_deleted
            .items
            .values()
            .all(|item| item.deleted.is_empty())
    );
}

#[test]
fn vault_file_without_item_deleted_field_loads_with_empty_deleted() {
    let vault = vault_with_credentials("item", &["alpha"]);
    let json = serde_json::to_value(vault.to_encrypted(true).unwrap()).unwrap();
    for item in json["items"].as_object().unwrap().values() {
        assert!(item.get("deleted").is_none());
    }

    let encrypted: EncryptedVault = serde_json::from_value(json).unwrap();
    let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
    let vault = Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap();
    assert!(vault.deleted.is_empty());
    assert!(vault.get_item_credential("item", "alpha").is_ok());
}

#[test]
fn deleted_info_is_bound_to_its_credential() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    vault.delete_item_credential("item", "beta").unwrap();

    // Swap the info blobs of the two deleted entries.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let item = encrypted
        .items
        .values_mut()
        .find(|item| item.deleted.len() == 2)
        .unwrap();
    let mut entries = item.deleted.values_mut();
    let (first, second) = (entries.next().unwrap(), entries.next().unwrap());
    std::mem::swap(&mut first.info, &mut second.info);

    let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
    assert!(Vault::from_encrypted_with_cipher(cipher, encrypted).is_err());
}

/// File key wrapper that stores the raw key as is.
fn plain_wrap(raw: &[u8]) -> Result<VaultFileKey, Error> {
    Ok(VaultFileKey::new(raw.to_vec()))
}

/// Vault with the entries of [`Vault::fill_for_test`], saved and loaded, so
/// its caches hold the blobs of the file.
fn filled_test_vault() -> Vault {
    let mut vault = test_vault();
    vault.fill_for_test();
    reload(&vault)
}

/// Save and load a vault under its own file key.
fn reload_own_key(vault: &Vault) -> Vault {
    let encrypted = vault.to_encrypted(true).unwrap();
    Vault::from_encrypted_with_cipher(vault.cipher.duplicate(), encrypted).unwrap()
}

/// Place and kind of every blob in a vault filled by [`Vault::fill_for_test`],
/// as [`VaultCipher::blob_results_for_test`] names them.
const FILLED_BLOB_KINDS: [&str; 24] = [
    "deleted item deleted credential: credential metadata",
    "deleted item deleted credential: deleted info",
    "deleted item deleted credential: history info",
    "deleted item deleted credential: history value",
    "deleted item deleted credential: value",
    "deleted item: credential metadata",
    "deleted item: deleted item info",
    "deleted item: history info",
    "deleted item: history value",
    "deleted item: item autofill",
    "deleted item: item metadata",
    "deleted item: value",
    "live deleted credential: credential metadata",
    "live deleted credential: deleted info",
    "live deleted credential: history info",
    "live deleted credential: history value",
    "live deleted credential: value",
    "live: credential metadata",
    "live: history info",
    "live: history value",
    "live: item autofill",
    "live: item metadata",
    "live: value",
    "live: vault metadata",
];

/// Check that `cipher` decrypts every blob of the filled vault `encrypted` if
/// `decrypts` is set, and none of them otherwise.
fn assert_blobs_decrypt(cipher: &VaultCipher, encrypted: &EncryptedVault, decrypts: bool) {
    let results = cipher.blob_results_for_test(encrypted);
    let kinds: Vec<&str> = results.keys().map(String::as_str).collect();
    assert_eq!(kinds, FILLED_BLOB_KINDS);
    for (kind, oks) in &results {
        assert!(oks.iter().all(|ok| *ok == decrypts), "{kind}: {oks:?}");
    }
}

/// Credential metadata plaintext read as a JSON object.
#[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize)]
struct LooseMetadata {
    #[serde(flatten)]
    #[zeroize(skip)]
    fields: BTreeMap<String, serde_json::Value>,
}

/// Credential metadata plaintext of `item_id/cred_id` as `vault` writes it.
fn stored_cred_metadata(
    vault: &Vault,
    item_id: Uuid,
    cred_id: Uuid,
) -> BTreeMap<String, serde_json::Value> {
    let encrypted = vault.to_encrypted(true).unwrap();
    let blob = &encrypted.items[&item_id].credentials[&cred_id].metadata;
    let metadata: SecretBox<LooseMetadata> = vault
        .cipher
        .decrypt_cred_metadata_as_for_test(item_id, cred_id, blob);
    metadata.expose_secret().fields.clone()
}

#[test]
fn every_blob_kind_decrypts_under_new_key_and_fails_under_old_key() {
    let source = filled_test_vault();
    assert_blobs_decrypt(&source.cipher, &source.to_encrypted(true).unwrap(), true);

    let rekeyed = source.rekeyed(None, plain_wrap).unwrap();
    let encrypted = rekeyed.to_encrypted(true).unwrap();

    assert_eq!(encrypted.id, source.id());
    assert_blobs_decrypt(&rekeyed.cipher, &encrypted, true);
    assert_blobs_decrypt(&source.cipher, &encrypted, false);
}

#[test]
fn copy_decrypts_under_new_vault_id_and_fails_under_old_vault_id() {
    let source = filled_test_vault();
    let new_id = Uuid::new_v4();

    let copy = source.rekeyed(Some(new_id), plain_wrap).unwrap();
    let encrypted = copy.to_encrypted(true).unwrap();

    assert_eq!(copy.id(), new_id);
    assert_eq!(encrypted.id, new_id);
    assert_blobs_decrypt(&copy.cipher, &encrypted, true);
    let old_id = copy.cipher.with_vault_id_for_test(source.id());
    assert_blobs_decrypt(&old_id, &encrypted, false);
    assert_blobs_decrypt(&source.cipher, &encrypted, false);
}

#[test]
fn rekeyed_vault_holds_every_entry_of_source() {
    let source = filled_test_vault();
    for new_id in [None, Some(Uuid::new_v4())] {
        let rekeyed = source.rekeyed(new_id, plain_wrap).unwrap();
        rekeyed.assert_filled_for_test();
        assert_eq!(rekeyed.entry_ids_for_test(), source.entry_ids_for_test());

        let reloaded = reload_own_key(&rekeyed);
        reloaded.assert_filled_for_test();
        assert_eq!(reloaded.entry_ids_for_test(), source.entry_ids_for_test());
    }
}

#[test]
fn copy_keeps_key_and_name_and_is_not_synced() {
    let mut source = filled_test_vault();
    source.generation = 5;
    source.replica_id = Some(Uuid::new_v4());

    let rekeyed = source.rekeyed(None, plain_wrap).unwrap();
    assert_eq!(rekeyed.id(), source.id());
    assert_eq!(rekeyed.generation, 5);
    assert_eq!(rekeyed.replica_id, source.replica_id);

    let new_id = Uuid::new_v4();
    let copy = source.rekeyed(Some(new_id), plain_wrap).unwrap();
    assert_eq!(copy.id(), new_id);
    assert_eq!(copy.generation, 0);
    assert_eq!(copy.replica_id, None);
    for vault in [&rekeyed, &copy] {
        assert_eq!(vault.key(), source.key());
        assert_eq!(vault.name, source.name);
    }
}

#[test]
fn source_is_unchanged_and_its_file_key_still_decrypts_it() {
    let source = filled_test_vault();
    let before = source.to_encrypted(true).unwrap().to_vault_json().unwrap();

    source.rekeyed(None, plain_wrap).unwrap();
    source.rekeyed(Some(Uuid::new_v4()), plain_wrap).unwrap();

    let after = source.to_encrypted(true).unwrap();
    assert_eq!(after.to_vault_json().unwrap(), before);
    assert_eq!(source.cipher.key_bytes_for_test(), TEST_FILE_KEY);
    let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, source.id());
    assert_blobs_decrypt(&cipher, &after, true);
    reload(&source).assert_filled_for_test();
}

#[test]
fn two_rekeys_of_one_vault_have_different_file_keys() {
    let source = filled_test_vault();

    let first = source.rekeyed(None, plain_wrap).unwrap();
    let second = source.rekeyed(None, plain_wrap).unwrap();

    let first_key = first.cipher.key_bytes_for_test();
    let second_key = second.cipher.key_bytes_for_test();
    assert_ne!(first_key, second_key);
    assert_ne!(first_key, TEST_FILE_KEY);
    assert_ne!(second_key, TEST_FILE_KEY);
    assert!(first.file_key != second.file_key);
}

#[test]
fn wrapper_receives_raw_key_of_rekeyed_vault() {
    let source = filled_test_vault();
    let mut seen = Vec::new();

    let rekeyed = source
        .rekeyed(None, |raw| {
            seen = raw.to_vec();
            Ok(VaultFileKey::new(vec![9u8; 4]))
        })
        .unwrap();

    assert_eq!(seen, rekeyed.cipher.key_bytes_for_test());
    let wrapped = VaultFileKey::new(vec![9u8; 4]);
    assert!(rekeyed.file_key == wrapped);
    assert!(rekeyed.to_encrypted(true).unwrap().file_key == wrapped);
}

#[test]
fn failed_wrap_fails_rekey() {
    let source = filled_test_vault();
    let result = source.rekeyed(None, |_| Err(Error::VaultFileKeyEncryptionError));
    assert!(matches!(result, Err(Error::VaultFileKeyEncryptionError)));
}

#[test]
fn folder_and_section_metadata_refuse_unknown_fields() {
    let id = ShortId::encode_uuid(Uuid::new_v4());
    let folder = serde_json::json!({"id": id, "title": "Folder"});
    let section = serde_json::json!({"id": id, "title": "Section"});
    let metadata = |folder: &serde_json::Value| serde_json::json!({"folders": [folder]});
    let item = |section: &serde_json::Value| serde_json::json!({"title": "Item", "key": "item", "sections": [section]});
    assert!(serde_json::from_value::<VaultMetadata>(metadata(&folder)).is_ok());
    assert!(serde_json::from_value::<VaultItemMetadata>(item(&section)).is_ok());

    let mut folder = folder;
    folder["x"] = serde_json::json!(1);
    let mut section = section;
    section["x"] = serde_json::json!(1);
    assert!(serde_json::from_value::<VaultMetadata>(metadata(&folder)).is_err());
    assert!(serde_json::from_value::<VaultItemMetadata>(item(&section)).is_err());
}

#[test]
fn blob_with_unknown_field_fails_the_load() {
    let source = filled_test_vault();
    let mut edited = BTreeSet::new();
    for n in 0.. {
        let mut encrypted = source.to_encrypted(true).unwrap();
        let Some(kind) = source.cipher.add_unknown_field_for_test(&mut encrypted, n) else {
            break;
        };

        let result = Vault::from_encrypted_with_cipher(source.cipher.duplicate(), encrypted);

        assert!(
            matches!(result, Err(Error::VaultSecretDecryptionError)),
            "{kind}"
        );
        edited.insert(kind);
    }
    // Every blob kind but values and previous values holds a struct.
    let expected: BTreeSet<String> = FILLED_BLOB_KINDS
        .iter()
        .filter(|kind| !kind.ends_with(": value") && !kind.ends_with(": history value"))
        .map(|kind| kind.to_string())
        .collect();
    assert_eq!(edited, expected);
}

#[test]
fn credential_with_unknown_field_kind_loads_and_saves_kind_unchanged() {
    let kind = serde_json::json!({"band": 5, "ssid": "home", "type": "wifi"});
    let vault = vault_with_credentials("net", &["wifi"]);
    let (item_id, cred_id) = vault.get_credential_ids("net", "wifi").unwrap();
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let newer = LooseMetadata {
        fields: BTreeMap::from([
            ("title".to_string(), serde_json::json!("Wifi")),
            ("key".to_string(), serde_json::json!("wifi")),
            ("kind".to_string(), kind.clone()),
        ]),
    };
    let blob = vault
        .cipher
        .encrypt_cred_metadata_as_for_test(item_id, cred_id, &newer);
    let credentials = &mut encrypted.items.get_mut(&item_id).unwrap().credentials;
    credentials.get_mut(&cred_id).unwrap().metadata = blob;

    let mut loaded =
        Vault::from_encrypted_with_cipher(vault.cipher.duplicate(), encrypted).unwrap();

    let cred = loaded.get_item_credential("net", "wifi").unwrap();
    assert_eq!(cred.kind, FieldKind::Unknown(kind.clone()));
    // Moving the credential writes its metadata again from the parsed kind.
    let section_id = loaded.create_item_section("net", "Section").unwrap().id;
    loaded
        .move_item_credential("net", "wifi", Some(section_id))
        .unwrap();
    let fields = stored_cred_metadata(&loaded, item_id, cred_id);
    assert_eq!(fields["kind"], kind);
    assert_eq!(fields["section"], ShortId::encode_uuid(section_id));
    let reloaded = reload_own_key(&loaded);
    let cred = reloaded.get_item_credential("net", "wifi").unwrap();
    assert_eq!(cred.kind, FieldKind::Unknown(kind));
}

#[test]
fn stale_credential_metadata_field_fails_the_load() {
    let vault = vault_with_credentials("site", &["password"]);
    let (item_id, cred_id) = vault.get_credential_ids("site", "password").unwrap();
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let stale = LooseMetadata {
        fields: BTreeMap::from([
            ("title".to_string(), serde_json::json!("Password")),
            ("key".to_string(), serde_json::json!("password")),
            ("last_used_at".to_string(), serde_json::json!(1_700_000_000)),
        ]),
    };
    let blob = vault
        .cipher
        .encrypt_cred_metadata_as_for_test(item_id, cred_id, &stale);
    let credentials = &mut encrypted.items.get_mut(&item_id).unwrap().credentials;
    credentials.get_mut(&cred_id).unwrap().metadata = blob;

    let result = Vault::from_encrypted_with_cipher(vault.cipher.duplicate(), encrypted);
    assert!(matches!(result, Err(Error::VaultSecretDecryptionError)));
}

/// Filled vault in which `breaks` replaces value blobs of item `kept` with the
/// value blob of `alpha`. `breaks` receives the source vault, the encrypted
/// item, and that blob. A replaced blob fails to decrypt, since its AAD names
/// another credential.
fn filled_vault_with_broken_values(
    breaks: impl FnOnce(&Vault, &mut EncryptedVaultItem, &EncryptedBlob<String>),
) -> Vault {
    let source = filled_test_vault();
    let (item_id, alpha_id) = source.get_credential_ids("kept", "alpha").unwrap();
    let mut encrypted = source.to_encrypted(true).unwrap();
    let item = encrypted.items.get_mut(&item_id).unwrap();
    let alpha_value = item.credentials[&alpha_id].value.clone();
    breaks(&source, item, &alpha_value);
    Vault::from_encrypted_with_cipher(source.cipher.duplicate(), encrypted).unwrap()
}

#[test]
fn deleted_entry_that_fails_to_decrypt_does_not_fail_export() {
    let vault = filled_vault_with_broken_values(|_, item, value| {
        for entry in item.deleted.values_mut() {
            entry.credential.value = value.clone();
        }
    });
    let cipher = Aes256Gcm::new(&Aes256Gcm::generate_key(OsRng));

    assert!(vault.rekeyed(None, plain_wrap).is_err());
    for include_passkeys in [true, false] {
        let bundled = vault.to_bundled_vault(None, Uuid::new_v4(), &cipher, include_passkeys);
        assert!(bundled.is_ok());
    }
}

#[test]
fn left_out_passkey_that_fails_to_decrypt_does_not_fail_export() {
    let vault = filled_vault_with_broken_values(|source, item, value| {
        let (_, passkey_id) = source.get_credential_ids("kept", "passkey").unwrap();
        item.credentials.get_mut(&passkey_id).unwrap().value = value.clone();
    });
    let cipher = Aes256Gcm::new(&Aes256Gcm::generate_key(OsRng));

    assert!(
        vault
            .to_bundled_vault(None, Uuid::new_v4(), &cipher, false)
            .is_ok()
    );
    assert!(
        vault
            .to_bundled_vault(None, Uuid::new_v4(), &cipher, true)
            .is_err()
    );
}

#[test]
fn unknown_field_kind_is_kept_by_rekey() {
    let kind = serde_json::json!({"type": "wifi", "ssid": "home", "band": 5});
    let mut vault = test_vault();
    vault.add_or_update_item("net", "Net").unwrap();
    vault
        .add_or_update_item_credential(
            "net",
            "wifi",
            "Wifi",
            FieldKind::Unknown(kind.clone()),
            SecretString::from("hunter2"),
        )
        .unwrap();
    let vault = reload(&vault);
    let (item_id, cred_id) = vault.get_credential_ids("net", "wifi").unwrap();

    let rekeyed = vault.rekeyed(None, plain_wrap).unwrap();

    assert_eq!(
        stored_cred_metadata(&rekeyed, item_id, cred_id)["kind"],
        kind
    );
    let reloaded = reload_own_key(&rekeyed);
    let cred = reloaded.get_item_credential("net", "wifi").unwrap();
    assert_eq!(cred.kind, FieldKind::Unknown(kind));
}
