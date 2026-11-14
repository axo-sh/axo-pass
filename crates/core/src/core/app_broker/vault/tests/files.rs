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
