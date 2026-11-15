use std::os::unix::fs::PermissionsExt;

use indoc::indoc;

use super::super::manage::import_plan;
use super::*;
use crate::secrets::vaults::vault_import::{ImportPlan, MapOptions, map_items, parse_1pif};

const NOTE_UUID: &str = "ABC123ABC123ABC123ABC123ABC123AB";

const EXPORT: &str = indoc! {r#"
    {"uuid":"5930154CFAB244FB920D5189DA0FAB9C","typeName":"webforms.WebForm","title":"GitHub","createdAt":1400000000,"openContents":{"tags":["work"]},"secureContents":{"URLs":[{"label":"website","url":"https://github.com"}],"fields":[{"name":"login","designation":"username","value":"me","type":"T"},{"name":"pass","designation":"password","value":"hunter2","type":"P"}]}}
    {"uuid":"ABC123ABC123ABC123ABC123ABC123AB","typeName":"securenotes.SecureNote","title":"Note","createdAt":1400000000,"secureContents":{}}
"#};

/// Export folder in `dir` with the records of [`EXPORT`] and two attachments
/// on the note.
fn write_export(dir: &Path) -> PathBuf {
    let export = dir.join("export.1pif");
    let attachments = export.join("attachments").join(NOTE_UUID);
    fs::create_dir_all(&attachments).unwrap();
    fs::write(export.join("data.1pif"), EXPORT).unwrap();
    fs::write(attachments.join("a.pdf"), "alpha").unwrap();
    fs::write(attachments.join("b.png"), "bravo").unwrap();
    export
}

fn new_vault(name: &str) -> WireImportTarget {
    WireImportTarget::New {
        name: name.to_string(),
    }
}

fn existing(vault_key: &str) -> WireImportTarget {
    WireImportTarget::Existing {
        vault_key: vault_key.to_string(),
    }
}

fn import(
    fx: &Fixture,
    export: &Path,
    target: WireImportTarget,
) -> Result<(String, WireImportSummary), String> {
    let new_vault = matches!(target, WireImportTarget::New { .. });
    let key = match &target {
        WireImportTarget::New { name } => name.clone(),
        WireImportTarget::Existing { vault_key } => vault_key.clone(),
    };
    let served = fx.serve(
        &key,
        VaultAction::ImportItems { new_vault },
        Some(VaultPayload::ImportItems(ImportItemsPayload {
            import_path: export.to_path_buf(),
            include_trashed: false,
            target,
        })),
    )?;
    match served.response {
        WireResponse::ItemsImported { vault_key, summary } => Ok((vault_key, summary)),
        _ => panic!("unexpected response"),
    }
}

/// Keys of the vault files in the vaults directory.
fn vault_files(fx: &Fixture) -> Vec<String> {
    let mut keys: Vec<String> = fx.vaults.list().into_keys().collect();
    keys.sort();
    keys
}

fn plan_of(export: &Path) -> ImportPlan {
    map_items(&parse_1pif(export).unwrap(), MapOptions::default())
}

#[test]
fn new_vault_created_with_items() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_export(dir.path());
    let fx = Fixture::new();

    let (key, summary) = import(&fx, &export, new_vault("Work Stuff")).unwrap();

    assert_eq!(key, "work-stuff");
    assert_eq!(summary.added, 2);
    assert_eq!(summary.files_added, 2);
    assert_eq!(summary.skipped_existing, 0);
    let vault = fx.read("work-stuff");
    assert_eq!(vault.vault_name(), Some("Work Stuff"));
    let github = vault.get_item_overview("github").unwrap().unwrap();
    assert_eq!(github.title, "GitHub");
    assert_eq!(
        vault
            .get_secret("github", "password")
            .unwrap()
            .unwrap()
            .expose_secret(),
        "hunter2"
    );
    assert!(vault.get_item_overview("note").unwrap().is_some());
}

#[test]
fn new_vault_key_gets_suffix_if_taken() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_export(dir.path());
    let fx = Fixture::new();

    let (key, _) = import(&fx, &export, new_vault("Personal")).unwrap();

    assert_eq!(key, "personal-2");
    assert_eq!(vault_files(&fx), ["personal", "personal-2", "shared"]);
}

#[test]
fn existing_vault_keeps_items_and_gains_imported() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_export(dir.path());
    let fx = Fixture::new();
    fx.app_add("personal", "token", "secret");

    let (key, summary) = import(&fx, &export, existing("personal")).unwrap();

    assert_eq!(key, "personal");
    assert_eq!(summary.added, 2);
    assert_eq!(fx.value("personal", "token").as_deref(), Some("secret"));
    let vault = fx.read("personal");
    assert!(vault.get_item_overview("github").unwrap().is_some());
    assert_eq!(vault_files(&fx), ["personal", "shared"]);
}

#[test]
fn reimport_skips_items_already_in_vault() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_export(dir.path());
    let fx = Fixture::new();
    import(&fx, &export, new_vault("Work")).unwrap();
    let before = fx.read("work").list_items().unwrap().len();

    let (_, summary) = import(&fx, &export, existing("work")).unwrap();

    assert_eq!(summary.added, 0);
    assert_eq!(summary.skipped_existing, 2);
    assert_eq!(summary.files_added, 0);
    assert_eq!(fx.read("work").list_items().unwrap().len(), before);
}

#[test]
fn failed_import_into_new_vault_leaves_no_vault() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_export(dir.path());
    let fx = Fixture::new();
    let mut plan = plan_of(&export);
    let repeat = plan.items[0].clone();
    plan.items.push(repeat);

    let result = import_plan(
        &fx.vaults,
        &new_vault("Doomed"),
        &plan,
        ForeignContext::for_test(),
    );

    assert!(matches!(&result, Err(e) if e.contains("Failed to import items")));
    assert_eq!(vault_files(&fx), ["personal", "shared"]);
    let files: Vec<_> = fs::read_dir(fx.vaults.vaults_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(files.len(), 1);
}

#[test]
fn failed_import_into_existing_vault_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_export(dir.path());
    let fx = Fixture::new();
    fx.app_add("personal", "token", "secret");
    let mut plan = plan_of(&export);
    let repeat = plan.items[0].clone();
    plan.items.push(repeat);

    let result = import_plan(
        &fx.vaults,
        &existing("personal"),
        &plan,
        ForeignContext::for_test(),
    );

    assert!(result.is_err());
    let vault = fx.read("personal");
    assert_eq!(vault.list_items().unwrap().len(), 1);
    assert_eq!(fx.value("personal", "token").as_deref(), Some("secret"));
}

#[test]
fn unreadable_attachment_reported_and_import_continues() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_export(dir.path());
    let locked = export.join("attachments").join(NOTE_UUID).join("a.pdf");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&locked).is_ok() {
        // Permissions do not apply, such as for root.
        return;
    }
    let fx = Fixture::new();

    let served = fx
        .serve(
            "personal",
            VaultAction::ImportItems { new_vault: false },
            Some(VaultPayload::ImportItems(ImportItemsPayload {
                import_path: export,
                include_trashed: false,
                target: existing("personal"),
            })),
        )
        .unwrap();

    let WireResponse::ItemsImported { summary, .. } = served.response else {
        panic!("unexpected response");
    };
    assert_eq!(summary.added, 2);
    assert_eq!(summary.files_added, 1);
    assert_eq!(summary.files_skipped, 1);
    assert_eq!(summary.file_failures.len(), 1);
    assert_eq!(summary.file_failures[0].item, "Note");
    assert!(summary.file_failures[0].path.ends_with("a.pdf"));
    let vault = fx.read("personal");
    let note = vault.get_item_overview("note").unwrap().unwrap();
    assert!(note.credentials.values().any(|c| c.key == "b-png"));
    assert!(note.credentials.values().all(|c| c.key != "a-pdf"));
}

#[test]
fn summary_reports_dropped_data_without_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_export(dir.path());
    let fx = Fixture::new();

    let (_, summary) = import(&fx, &export, new_vault("Work")).unwrap();

    assert!(
        summary
            .dropped
            .iter()
            .any(|d| d.item == "GitHub" && d.kind == "tags" && d.detail.contains("work"))
    );
    let json = serde_json::to_string(&summary).unwrap();
    assert!(!json.contains("hunter2"));
}

const HISTORY_EXPORT: &str = indoc! {r#"
    {"uuid":"5930154CFAB244FB920D5189DA0FAB9C","typeName":"webforms.WebForm","title":"GitHub","secureContents":{"fields":[{"name":"login","designation":"username","value":"me","type":"T"},{"name":"pass","designation":"password","value":"hunter2","type":"P"}],"passwordHistory":[{"value":"old-one","time":1634666640},{"value":"bad-entry"},{"value":"old-two","time":1634666650}]}}
"#};

/// Export folder in `dir` with the record of [`HISTORY_EXPORT`].
fn write_history_export(dir: &Path) -> PathBuf {
    let export = dir.join("history.1pif");
    fs::create_dir_all(&export).unwrap();
    fs::write(export.join("data.1pif"), HISTORY_EXPORT).unwrap();
    export
}

/// Previous values of a credential as `(value, time)`, oldest first.
fn history(vault: &VaultHandle, item: &str, credential: &str) -> Vec<(String, i64)> {
    let mut entries: Vec<(String, i64)> = vault
        .list_history(item, credential)
        .unwrap()
        .iter()
        .map(|entry| {
            let value = vault.get_history_value(item, credential, entry.id).unwrap();
            (value.expose_secret().clone(), entry.at)
        })
        .collect();
    entries.reverse();
    entries
}

#[test]
fn login_history_imported_and_kept_out_of_summary() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_history_export(dir.path());
    let fx = Fixture::new();

    let (key, summary) = import(&fx, &export, new_vault("Work")).unwrap();

    assert_eq!(summary.added, 1);
    let vault = fx.read(&key);
    assert_eq!(
        history(&vault, "github", "password"),
        [
            ("old-one".to_string(), 1_634_666_640),
            ("old-two".to_string(), 1_634_666_650),
        ]
    );
    assert!(
        summary
            .dropped
            .iter()
            .any(|d| d.item == "GitHub" && d.kind == "parse note" && d.detail.contains("entry 2"))
    );
    let json = serde_json::to_string(&summary).unwrap();
    for secret in ["old-one", "old-two", "bad-entry", "hunter2"] {
        assert!(!json.contains(secret), "{secret} in summary");
    }
}

#[test]
fn failed_import_writes_no_history() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_history_export(dir.path());
    let fx = Fixture::new();
    fx.app_add("personal", "token", "secret");
    let mut plan = plan_of(&export);
    let repeat = plan.items[0].clone();
    plan.items.push(repeat);

    let result = import_plan(
        &fx.vaults,
        &existing("personal"),
        &plan,
        ForeignContext::for_test(),
    );

    assert!(result.is_err());
    let vault = fx.read("personal");
    assert!(vault.get_item_overview("github").unwrap().is_none());
    assert_eq!(vault.list_items().unwrap().len(), 1);
}

#[test]
fn import_audited_as_items_imported_with_vault_ids() {
    let _audit = test_dir();
    let dir = tempfile::tempdir().unwrap();
    let export = write_export(dir.path());
    let fx = Fixture::new();

    let event = fx.serve_recorded(
        true,
        "personal",
        VaultAction::ImportItems { new_vault: false },
        Some(VaultPayload::ImportItems(ImportItemsPayload {
            import_path: export,
            include_trashed: false,
            target: existing("personal"),
        })),
    );

    assert_eq!(event.action, Action::VaultItemsImported);
    assert_eq!(event.outcome, Outcome::Succeeded);
    assert_eq!(
        event.detail.get("item_count").map(String::as_str),
        Some("2")
    );
    let personal = fx.read("personal").vault_id().unwrap();
    assert_eq!(recorded_ids(&event).vault_id, Some(personal));
}
