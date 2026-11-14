use super::*;
use crate::secrets::vaults::storage::handle::normalized_key;

#[tokio::test]
async fn record_survives_round_trip() {
    let passkey = sample_passkey().await;

    let encoded = encode(&passkey, None).unwrap();
    let decoded = decode(&encoded).unwrap();

    assert_eq!(decoded.rp_id, passkey.rp_id);
    assert_eq!(decoded.credential_id, passkey.credential_id);
    assert_eq!(decoded.user_handle, passkey.user_handle);
    assert_eq!(decoded.username, passkey.username);
    assert_eq!(decoded.user_display_name, passkey.user_display_name);
    assert_eq!(decoded.counter, passkey.counter);
    // The private key is what makes the credential usable, so it has to
    // come back byte-identical.
    assert_eq!(
        decoded.key.clone().to_vec().unwrap(),
        passkey.key.clone().to_vec().unwrap()
    );
}

#[tokio::test]
async fn record_is_plain_json_with_base64url_ids() {
    let passkey = sample_passkey().await;
    let value: serde_json::Value = serde_json::from_str(&encode(&passkey, None).unwrap()).unwrap();

    assert_eq!(value["rp_id"], "example.com");
    assert_eq!(value["username"], "ada");
    assert_eq!(
        value["credential_id"].as_str().unwrap(),
        B64URL.encode(passkey.credential_id.as_slice())
    );
    // base64url ids must never carry the characters that would need
    // escaping in a URL.
    let id = value["credential_id"].as_str().unwrap();
    assert!(
        !id.contains('+') && !id.contains('/') && !id.contains('='),
        "{id}"
    );
}

/// Credential ids are random bytes. Every one must give a key the vault
/// accepts unchanged, including ids whose base64url form starts with a
/// digit or ends with `-`.
#[test]
fn credential_keys_are_valid_vault_keys() {
    let ids: [&[u8]; 4] = [
        &[0x00; 16],
        &[0xff; 16],
        &[0xd3, 0x4f, 0xb9, 0x01, 0x22, 0x7e, 0x80, 0x11, 0x5a],
        &[0x01, 0x02],
    ];
    for id in ids {
        let key = PasskeyCredentialStore::credential_key(id);
        assert_eq!(
            normalized_key(&key).as_deref(),
            Some(key.as_str()),
            "{id:?}"
        );
    }
    assert_eq!(
        PasskeyCredentialStore::credential_key(&[
            0xd3, 0x4f, 0xb9, 0x01, 0x22, 0x7e, 0x80, 0x11, 0x5a
        ]),
        "passkey-d34fb901227e8011"
    );
}

#[tokio::test]
async fn registration_records_when_it_was_created() {
    let vw = registered_vault("ada").await;
    let stored = list(&vw).unwrap().remove(0);
    let value = vw
        .get_secret(&stored.item_key, &stored.credential_key)
        .unwrap()
        .unwrap();

    let summary = summary(value.expose_secret()).unwrap();
    assert_eq!(summary.rp_id, "example.com");
    assert_eq!(summary.username.as_deref(), Some("ada"));
    assert!(summary.created_at.is_some_and(|t| t > 1_700_000_000));
}

#[test]
fn record_without_creation_time_still_summarizes() {
    let summary = summary(r#"{"rp_id":"example.com","credential_id":"AA","key":"x"}"#).unwrap();
    assert_eq!(summary.created_at, None);
    assert!(super::summary("not json").is_none());
}

/// A field that a newer build adds to the record is kept by a rename.
#[tokio::test]
async fn rename_keeps_fields_this_build_does_not_know() {
    let mut vw = registered_vault("ada").await;
    let stored = list(&vw).unwrap().remove(0);
    let value = vw
        .get_secret(&stored.item_key, &stored.credential_key)
        .unwrap()
        .unwrap();
    let mut record: serde_json::Value = serde_json::from_str(value.expose_secret()).unwrap();
    record["backup_state"] = serde_json::json!({"eligible": true});
    let title = read_record(&vw, &stored.item_key, &stored.credential_key)
        .unwrap()
        .title;
    vw.replace_secret(
        &stored.item_key,
        &stored.credential_key,
        &title,
        FieldKind::Passkey,
        SecretString::from(record.to_string()),
    )
    .unwrap();

    rename_account(
        &mut vw,
        &stored.item_key,
        &stored.credential_key,
        "lovelace",
    )
    .unwrap();

    let value = vw
        .get_secret(&stored.item_key, &stored.credential_key)
        .unwrap()
        .unwrap();
    let record: serde_json::Value = serde_json::from_str(value.expose_secret()).unwrap();
    assert_eq!(record["username"], "lovelace");
    assert_eq!(
        record["backup_state"],
        serde_json::json!({"eligible": true})
    );
}

#[test]
fn unreadable_records_rejected_not_panicked_on() {
    assert!(decode("not json").is_err());
    assert!(decode(r#"{"rp_id":"example.com"}"#).is_err());
}
