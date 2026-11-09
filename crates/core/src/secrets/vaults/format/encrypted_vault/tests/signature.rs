use super::*;

/// Format 2 file contents of a filled vault that is synced.
fn synced_contents() -> String {
    let mut vault = filled_vault();
    vault.generation = 7;
    vault.replica_id = Some(Uuid::new_v4());
    contents_of(&vault)
}

/// Replace the text `from` with `to` in `contents`, once, and keep the
/// signature.
fn edit_raw(contents: &str, from: &str, to: &str) -> String {
    assert_eq!(contents.matches(from).count(), 1, "{from}");
    contents.replacen(from, to, 1)
}

/// `contents` with the top-level field `field` set to the JSON text
/// `json`. Every other field is kept byte for byte.
fn with_field(contents: &str, field: &str, json: String) -> String {
    let mut fields: BTreeMap<String, Box<RawValue>> = serde_json::from_str(contents).unwrap();
    fields.insert(field.to_string(), RawValue::from_string(json).unwrap());
    serde_json::to_string_pretty(&fields).unwrap()
}

/// `contents` with `signature` written as its signature.
fn with_signature(contents: &str, signature: &[u8]) -> String {
    with_field(
        contents,
        "signature",
        json!(B64.encode(signature)).to_string(),
    )
}

fn assert_signature_invalid(result: Result<EncryptedVault, Error>, what: &str) {
    assert!(
        matches!(result, Err(Error::VaultSignatureInvalid)),
        "{what} was not refused for its signature"
    );
}

#[test]
fn format2_file_round_trips() {
    let vault = filled_vault();
    let contents = contents_of(&vault);
    let back = parse(&contents).unwrap();
    assert_eq!(back.to_vault_json().unwrap(), raw(&contents));

    let file: Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(file["format"], json!(VAULT_FORMAT));
    assert!(file["signature"].is_string());
    assert!(file["vault"].get("generation").is_none());
    assert!(file["vault"].get("replica_id").is_none());
}

#[test]
fn signature_covers_exact_raw_vault_bytes() {
    let vault = filled_vault();
    let contents = contents_of(&vault);
    let file: Value = serde_json::from_str(&contents).unwrap();
    let signature = B64.decode(file["signature"].as_str().unwrap()).unwrap();
    assert_eq!(with_signature(&contents, &signature), contents);

    let message = format!("ap-vault-v2:{}", raw(&contents));
    let key = signer().verifying_key().unwrap();
    signing::verify(&key, message.as_bytes(), &signature).unwrap();
    // The file holds the vault object as it was signed.
    assert_eq!(raw(&contents), vault.to_vault_json().unwrap());
}

#[test]
fn generation_and_replica_id_written_if_set() {
    let mut vault = filled_vault();
    let replica_id = Uuid::new_v4();
    vault.generation = 7;
    vault.replica_id = Some(replica_id);
    let contents = contents_of(&vault);

    let file: Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(file["vault"]["generation"], json!(7));
    assert_eq!(
        file["vault"]["replica_id"],
        json!(ShortId::encode_uuid(replica_id))
    );
    let back = parse(&contents).unwrap();
    assert_eq!(back.generation, 7);
    assert_eq!(back.replica_id, Some(replica_id));
}

#[test]
fn replaced_file_key_fails_verification() {
    let contents = contents_of(&filled_vault());
    let file: Value = serde_json::from_str(&contents).unwrap();
    let file_key = file["vault"]["file_key"].as_str().unwrap();
    let planted = VaultFileKey::new(vec![9u8; 32]);
    let planted = serde_json::to_value(&planted).unwrap();
    let edited = edit_raw(&contents, &format!("\"{file_key}\""), &planted.to_string());
    assert_signature_invalid(parse(&edited), "replaced file_key");
}

#[test]
fn spliced_blob_fails_verification() {
    // A blob from an older copy of the same vault, under the same file
    // key, decrypts. Only the signature refuses it.
    let mut vault = Vault::new_for_test();
    vault.fill_for_test();
    let older = vault.to_encrypted(true).unwrap();
    vault
        .add_or_update_item_credential(
            "kept",
            "alpha",
            "alpha",
            FieldKind::default(),
            SecretString::from("three".to_string()),
        )
        .unwrap();
    let newer = vault.to_encrypted(true).unwrap();
    let contents = contents_of(&newer);

    // The newer vault with one item replaced by its older copy.
    let item = *older.items.keys().next().unwrap();
    let mut spliced = parse(&contents).unwrap();
    let old_item = serde_json::to_value(&older.items[&item]).unwrap();
    spliced
        .items
        .insert(item, serde_json::from_value(old_item).unwrap());
    let spliced_json = spliced.to_vault_json().unwrap();
    assert_ne!(spliced_json, raw(&contents));

    // Signed again, the splice decrypts to the older value, so only the
    // signature refuses it.
    let resigned = EncryptedVault::parse(&contents_of(&spliced), &signer()).unwrap();
    let back = Vault::from_unlocked_key(&vault.unlocked_key(), resigned).unwrap();
    let value = back.get_item_credential_secret("kept", "alpha").unwrap();
    assert_eq!(value.unwrap().expose_secret(), "two");
    let spliced = with_field(&contents, "vault", spliced_json);
    assert_signature_invalid(parse(&spliced), "spliced blob");
}

#[test]
fn changed_format_fails_verification() {
    let contents = contents_of(&filled_vault());
    // A file of another format is refused before its signature is read.
    let edited = edit_raw(&contents, "\"format\": 2", "\"format\": 3");
    assert!(matches!(
        parse(&edited),
        Err(Error::UnsupportedVaultFormat(3))
    ));

    // The signed prefix names the format, so a signature of the same raw
    // vault bytes for another format does not verify as format 2.
    let message = VaultEnvelope::signed_message(3, &raw(&contents));
    let signature = signer().sign(&message).unwrap();
    let edited = with_signature(&contents, &signature);
    assert_signature_invalid(parse(&edited), "signature for format 3");
}

#[test]
fn edited_generation_fails_verification() {
    let contents = synced_contents();
    let edited = edit_raw(&contents, "\"generation\": 7", "\"generation\": 8");
    assert_signature_invalid(parse(&edited), "edited generation");
}

#[test]
fn edited_replica_id_fails_verification() {
    let contents = synced_contents();
    let file: Value = serde_json::from_str(&contents).unwrap();
    let replica_id = file["vault"]["replica_id"].as_str().unwrap();
    let other = ShortId::encode_uuid(Uuid::new_v4());
    let edited = edit_raw(&contents, replica_id, &other);
    assert_signature_invalid(parse(&edited), "edited replica_id");

    // Removing the replica id turns the file into a vault that is not
    // synced, and fails too.
    let line = format!("\n    \"replica_id\": \"{replica_id}\",");
    let edited = edit_raw(&contents, &line, "");
    assert_signature_invalid(parse(&edited), "removed replica_id");
}

#[test]
fn edited_key_fails_verification() {
    let contents = contents_of(&filled_vault());
    let edited = edit_raw(&contents, "\"key\": \"personal\"", "\"key\": \"other\"");
    assert_signature_invalid(parse(&edited), "edited key");
    // The header is not verified and reads the edited key.
    assert_eq!(VaultHeader::parse(&edited).unwrap().key, "other");
}

#[test]
fn reformatted_file_fails_verification() {
    let contents = contents_of(&filled_vault());
    let file: Value = serde_json::from_str(&contents).unwrap();
    let compact = serde_json::to_string(&file).unwrap();
    assert_signature_invalid(parse(&compact), "compact file");

    let indented = contents.replace("\n  ", "\n    ");
    assert_ne!(indented, contents);
    assert_signature_invalid(parse(&indented), "indented file");
}

#[test]
fn unsigned_format2_file_refused() {
    let mut file = filled_file();
    file.as_object_mut().unwrap().remove("signature");
    let contents = file.to_string();
    assert!(matches!(
        parse(&contents),
        Err(Error::VaultSignatureMissing)
    ));
    // The header of an unsigned file is still read, unverified.
    assert_eq!(VaultHeader::parse(&contents).unwrap().key, "personal");
}

#[test]
fn file_signed_by_another_key_fails_verification() {
    let contents = filled_vault()
        .to_file_contents(&TestSigner::random())
        .unwrap();
    assert_signature_invalid(parse(&contents), "file signed by another key");
}

#[test]
fn signature_not_der_fails_verification() {
    let contents = with_signature(&contents_of(&filled_vault()), b"sig");
    assert_signature_invalid(parse(&contents), "signature that is not DER");
}
