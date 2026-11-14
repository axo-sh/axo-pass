use super::*;
use crate::secrets::vaults::files::{self, FileInput};
use crate::secrets::vaults::storage::txn::{Target, Unlock};

/// Add file credential `item/doc` to vault `personal` as an app edit.
fn add_file(fx: &Fixture) {
    fx.app_write("personal", |vw| vw.add_item("item", "Item").map(|_| ()));
    let original = &fx.originals["personal"];
    files::add_file(
        fx.vaults.files(),
        &Target::of(original),
        Unlock::Unlocked(original),
        "item",
        "doc",
        "Doc",
        FileInput {
            name: "doc.txt".to_string(),
            mime: None,
            contents: &b"contents"[..],
        },
    )
    .unwrap();
}

fn read_doc() -> VaultAction {
    VaultAction::ReadSecret {
        item_key: "item".to_string(),
        credential_key: "doc".to_string(),
    }
}

#[test]
fn broker_read_of_file_credential_refused() {
    let fx = Fixture::new();
    add_file(&fx);

    let result = fx.serve("personal", read_doc(), None);

    assert!(matches!(&result, Err(e) if e.contains("file credential")));
}

#[test]
fn broker_resolve_of_file_credential_gives_no_value() {
    let fx = Fixture::new();
    add_file(&fx);

    let resolved = fx
        .serve(
            "personal",
            VaultAction::ResolveSecrets {
                purpose: ResolvePurpose::Read,
                refs: vec![token_ref("personal", "doc")],
            },
            None,
        )
        .unwrap()
        .response;

    assert!(matches!(
        resolved,
        WireResponse::ResolvedSecrets { ref values } if values == &[None]
    ));
}

#[test]
fn broker_write_over_file_credential_refused() {
    let fx = Fixture::new();
    add_file(&fx);
    let before = fx.read("personal");
    let record = before.get_secret("item", "doc").unwrap().unwrap();

    let result = fx.serve(
        "personal",
        VaultAction::WriteSecret {
            item_key: "item".to_string(),
            credential_key: "doc".to_string(),
        },
        Some(VaultPayload::Write(WriteSecretPayload {
            title: "Doc".to_string(),
            value: SecretString::from("text".to_string()),
            login: None,
        })),
    );

    assert!(matches!(&result, Err(e) if e.contains("file credential")));
    assert_eq!(
        fx.value("personal", "doc").as_deref(),
        Some(record.expose_secret().as_str())
    );
}

fn read_doc_file(dest: &std::path::Path) -> VaultAction {
    VaultAction::ReadFile {
        item_key: "item".to_string(),
        credential_key: "doc".to_string(),
        dest_path: dest.to_string_lossy().to_string(),
    }
}

#[test]
fn file_read_writes_contents_to_destination() {
    let fx = Fixture::new();
    add_file(&fx);
    let dest = tempfile::tempdir().unwrap();
    let path = dest.path().join("out.txt");

    let served = fx.serve("personal", read_doc_file(&path), None).unwrap();

    assert!(matches!(
        served.response,
        WireResponse::VaultFileRead { ref name, size: 8, .. } if name == "doc.txt"
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"contents");
}

#[test]
fn file_read_refuses_existing_destination() {
    let fx = Fixture::new();
    add_file(&fx);
    let dest = tempfile::tempdir().unwrap();
    let path = dest.path().join("out.txt");
    std::fs::write(&path, b"keep").unwrap();

    let result = fx.serve("personal", read_doc_file(&path), None);

    assert!(result.is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"keep");
}

#[test]
fn file_read_refuses_relative_destination() {
    let fx = Fixture::new();
    add_file(&fx);

    let result = fx.serve(
        "personal",
        read_doc_file(std::path::Path::new("out.txt")),
        None,
    );

    assert!(matches!(&result, Err(e) if e.contains("absolute")));
}

#[test]
fn file_read_refuses_text_credential() {
    let fx = Fixture::new();
    add_file(&fx);
    fx.app_write("personal", |vw| {
        vw.add_secret(
            "item",
            "token",
            "Token",
            FieldKind::default(),
            "secret".into(),
        )
        .map(|_| ())
    });
    let dest = tempfile::tempdir().unwrap();
    let path = dest.path().join("out.txt");
    let action = VaultAction::ReadFile {
        item_key: "item".to_string(),
        credential_key: "token".to_string(),
        dest_path: path.to_string_lossy().to_string(),
    };

    let result = fx.serve("personal", action, None);

    assert!(matches!(&result, Err(e) if e.contains("not a file")));
    assert!(!path.exists());
}
