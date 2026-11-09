use std::collections::BTreeMap;

use secrecy::ExposeSecret;

use super::{
    ExportFile, assert_live_blobs_decrypt, export_cipher, file_key_of, filled_vault, plain_wrap,
};
use crate::secrets::vaults::bundle::PreparedVault;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultFileKey};
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;

/// Export `vault` to a bundle file and open the file again.
fn export_and_open(vault: &Vault, include_passkeys: bool) -> PreparedVault {
    ExportFile::new(vault, include_passkeys).open()
}

#[test]
fn export_file_key_differs_from_source_and_source_unchanged() {
    let vault = filled_vault();
    let source_key = file_key_of(&vault);
    let before = vault.to_encrypted(true).unwrap().to_vault_json().unwrap();

    let prepared = export_and_open(&vault, true);

    assert_ne!(*prepared.raw_file_key.expose_secret(), source_key);
    assert_eq!(file_key_of(&vault), source_key);
    let after = vault.to_encrypted(true).unwrap().to_vault_json().unwrap();
    assert_eq!(after, before);
    vault.assert_filled_for_test();
}

#[test]
fn two_exports_of_one_vault_have_different_file_keys() {
    let vault = filled_vault();

    let first = export_and_open(&vault, true);
    let second = export_and_open(&vault, true);

    assert_ne!(
        first.raw_file_key.expose_secret(),
        second.raw_file_key.expose_secret()
    );
}

#[test]
fn bundle_blobs_fail_to_decrypt_under_source_file_key() {
    let vault = filled_vault();
    let prepared = export_and_open(&vault, true);
    let cipher = export_cipher(&prepared);
    let exported = EncryptedVault {
        id: prepared.id,
        key: "exported".to_string(),
        name: None,
        generation: 0,
        replica_id: None,
        file_key: VaultFileKey::new(Vec::new()),
        metadata: prepared.metadata,
        items: prepared.items,
        deleted: BTreeMap::new(),
    };

    assert_live_blobs_decrypt(&cipher, &exported, true);
    let source_cipher = vault.unlocked_key().cipher_for_test();
    assert_live_blobs_decrypt(&source_cipher, &exported, false);
}

#[test]
fn export_without_passkeys_holds_no_passkey_credential() {
    let vault = filled_vault();
    let kept_id = vault.get_item("kept").unwrap().id;
    let passkey_id = vault.get_item_credential("kept", "passkey").unwrap().id;

    let prepared = export_and_open(&vault, false);

    let cipher = export_cipher(&prepared);
    assert!(
        !prepared.items[&kept_id]
            .credentials
            .contains_key(&passkey_id)
    );
    for (item_id, item) in &prepared.items {
        for (cred_id, cred) in &item.credentials {
            let metadata = cipher
                .decrypt_cred_metadata(*item_id, *cred_id, &cred.metadata)
                .unwrap();
            assert_ne!(metadata.expose_secret().kind, FieldKind::Passkey);
            let value = cipher
                .decrypt_cred_value(*item_id, *cred_id, &cred.value)
                .unwrap();
            assert_ne!(value.expose_secret(), Vault::PASSKEY_VALUE_FOR_TEST);
        }
    }
    let imported = prepared
        .into_vault("imported".to_string(), None, plain_wrap)
        .unwrap();
    assert!(imported.get_item_credential("kept", "passkey").is_err());
    let alpha = imported
        .get_item_credential_secret("kept", "alpha")
        .unwrap();
    assert_eq!(alpha.unwrap().expose_secret(), "two");
}

#[test]
fn export_with_passkeys_holds_passkey_record_unchanged() {
    let vault = filled_vault();
    let kept_id = vault.get_item("kept").unwrap().id;
    let passkey_id = vault.get_item_credential("kept", "passkey").unwrap().id;

    let prepared = export_and_open(&vault, true);

    let cipher = export_cipher(&prepared);
    let passkey = &prepared.items[&kept_id].credentials[&passkey_id];
    let metadata = cipher
        .decrypt_cred_metadata(kept_id, passkey_id, &passkey.metadata)
        .unwrap();
    assert_eq!(metadata.expose_secret().kind, FieldKind::Passkey);
    let value = cipher
        .decrypt_cred_value(kept_id, passkey_id, &passkey.value)
        .unwrap();
    assert_eq!(value.expose_secret(), Vault::PASSKEY_VALUE_FOR_TEST);
}
