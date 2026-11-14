use super::*;

/// Pointer to the one entry of the map at `pointer` in `file`.
fn only_entry(file: &Value, pointer: &str) -> String {
    let map = file.pointer(pointer).unwrap().as_object().unwrap();
    assert_eq!(map.len(), 1, "{pointer}");
    let key = map.keys().next().unwrap();
    format!("{pointer}/{key}")
}

/// Pointer to the one entry of the map at `pointer` in `file` that has a
/// previous value, which is a history entry with a value.
fn only_entry_with_history(file: &Value, pointer: &str) -> String {
    let map = file.pointer(pointer).unwrap().as_object().unwrap();
    let mut keys = map
        .iter()
        .filter(|(_, entry)| {
            entry["history"]
                .as_array()
                .is_some_and(|h| h.iter().any(|e| e.get("value").is_some()))
        })
        .map(|(key, _)| key);
    let key = keys.next().unwrap();
    assert!(keys.next().is_none(), "{pointer}");
    format!("{pointer}/{key}")
}

/// Parse `file` after adding an unknown field to the object at `pointer`.
fn parse_with_unknown_field(file: &Value, pointer: &str) -> Result<EncryptedVault, Error> {
    let mut file = file.clone();
    let object = file.pointer_mut(pointer).unwrap().as_object_mut().unwrap();
    object.insert("unknown".to_string(), json!(1));
    parse(&signed(&file))
}

fn assert_refused(result: Result<EncryptedVault, Error>, pointer: &str) {
    assert!(
        matches!(result, Err(Error::VaultDeserializationError(_))),
        "unknown field at {pointer:?} was not refused"
    );
}

/// Assert that `parse` of `contents` and `VaultHeader::parse` of
/// `header_contents` both fail with an error that `refused` accepts. `context`
/// labels a failure.
fn assert_both_refused(
    contents: &str,
    header_contents: &str,
    refused: impl Fn(&Error) -> bool,
    context: &str,
) {
    let error = parse(contents).err();
    assert!(error.as_ref().is_some_and(&refused), "{context}");
    let error = VaultHeader::parse(header_contents).err();
    assert!(error.as_ref().is_some_and(&refused), "{context}");
}

#[test]
fn unknown_format_fails_closed() {
    for format in [0, 1, 3, 1000] {
        let mut file = filled_file();
        file["format"] = json!(format);
        // A later format can add envelope fields. The format is checked
        // first.
        file["signature"] = json!("c2ln");
        let contents = file.to_string();

        assert_both_refused(
            &contents,
            &contents,
            |e| matches!(e, Error::UnsupportedVaultFormat(f) if *f == format),
            &format!("format {format}"),
        );
    }
}

#[test]
fn format2_file_key_with_members_shape_refused() {
    let shapes = [
        json!([{ "public_key": "key", "wrapped_key": [1, 2, 3] }]),
        json!({ "path": "/tmp/members.json" }),
    ];
    for shape in shapes {
        let mut file = filled_file();
        file["vault"]["file_key"] = shape.clone();
        let result = parse(&signed(&file));
        assert!(
            matches!(result, Err(Error::VaultDeserializationError(_))),
            "{shape}"
        );
    }
}

#[test]
fn file_without_envelope_refused_as_format_1() {
    // A format 1 file is the vault object without an envelope.
    let contents = serde_json::to_string_pretty(&filled_vault()).unwrap();
    assert_both_refused(
        &contents,
        &contents,
        |e| matches!(e, Error::UnsupportedVaultFormat(1)),
        "format 1",
    );
}

#[test]
fn unknown_field_in_any_outer_struct_refused() {
    let file = filled_file();
    parse(&signed(&file)).unwrap();

    let item = only_entry(&file, "/vault/items");
    let credential = only_entry_with_history(&file, &format!("{item}/credentials"));
    let deleted_credential = only_entry(&file, &format!("{item}/deleted"));
    let deleted_item = only_entry(&file, "/vault/deleted");
    let deleted_item_credential = only_entry(&file, &format!("{deleted_item}/item/deleted"));
    let pointers = [
        String::new(),
        "/vault".to_string(),
        item,
        credential.clone(),
        format!("{credential}/history/0"),
        deleted_credential.clone(),
        format!("{deleted_credential}/credential"),
        deleted_item.clone(),
        format!("{deleted_item}/item"),
        deleted_item_credential.clone(),
        format!("{deleted_item_credential}/credential"),
    ];
    for pointer in pointers {
        assert_refused(parse_with_unknown_field(&file, &pointer), &pointer);
    }
}

#[test]
fn header_read_from_vault_file() {
    let dir = tempfile::tempdir().unwrap();
    let vault = filled_vault();
    let path = dir.path().join("filled.json");
    fs::write(&path, contents_of(&vault)).unwrap();

    let header = VaultHeader::peek(&path).unwrap();
    assert_eq!(header.id, vault.id);
    assert_eq!(header.name.as_deref(), Some("Filled"));
}

#[test]
fn header_holds_vault_key() {
    let vault = filled_vault();
    let contents = contents_of(&vault);

    let file: Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(file["vault"]["key"], json!("personal"));
    assert_eq!(VaultHeader::parse(&contents).unwrap().key, "personal");
    assert_eq!(parse(&contents).unwrap().key, "personal");
}

#[test]
fn file_without_key_refused() {
    let mut file = filled_file();
    file["vault"].as_object_mut().unwrap().remove("key");
    let contents = file.to_string();

    assert_both_refused(
        &signed(&file),
        &contents,
        |e| matches!(e, Error::VaultDeserializationError(_)),
        "file without key",
    );
}

#[test]
fn file_with_key_not_normalized_refused() {
    for key in ["Personal", "my vault", "", "1password"] {
        let mut file = filled_file();
        file["vault"]["key"] = json!(key);
        let contents = file.to_string();

        assert_both_refused(
            &signed(&file),
            &contents,
            |e| matches!(e, Error::InvalidVaultKey(_)),
            &format!("{key:?}"),
        );
    }
}
