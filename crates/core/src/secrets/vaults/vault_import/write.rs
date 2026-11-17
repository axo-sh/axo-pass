use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::map::{ImportPlan, PlannedCredential, PlannedItem};
use crate::secrets::vaults::files::{FileInput, StagedFile, stage_file};
use crate::secrets::vaults::storage::txn::{Target, VaultWriter};
use crate::secrets::vaults::{Error, FieldKind, ItemAutofill, VaultHandle};

/// File credential values by export path, for the files that were staged.
pub type FileValues = HashMap<PathBuf, SecretString>;

/// Counts of what [`write_plan`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportSummary {
    /// Items written, including trashed items.
    pub added: usize,
    /// File credentials written.
    pub files_added: usize,
    /// Planned files that were not staged, so no credential was written.
    pub files_skipped: usize,
    /// Items left out because the vault already holds an item with their id.
    pub skipped_existing: usize,
    /// Written items that were then deleted.
    pub trashed: usize,
    /// Folders created. A folder with the title of an existing folder is
    /// reused.
    pub folders_created: usize,
}

/// Ids of the items in the vault, including items in Recently Deleted. An
/// imported item has the 1Password record uuid as its id, so a planned item
/// whose id is in this set was imported before.
pub fn existing_item_ids(handle: &VaultHandle) -> Result<HashSet<Uuid>, Error> {
    let mut ids: HashSet<Uuid> = handle.list_items()?.iter().map(|item| item.id).collect();
    ids.extend(handle.list_deleted_items()?.iter().map(|d| d.item.id));
    Ok(ids)
}

/// Whether `item` has an id that is in `existing`.
fn already_imported(item: &PlannedItem, existing: &HashSet<Uuid>) -> bool {
    item.id.is_some_and(|id| existing.contains(&id))
}

/// A planned file that could not be staged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFailure {
    /// Title of the item that holds the file.
    pub item: String,
    pub path: PathBuf,
    pub reason: String,
}

/// Result of [`stage_plan_files`].
pub struct StagedFiles {
    /// Staged files, for `write_with_files`.
    pub files: Vec<StagedFile>,
    /// Credential values of the staged files, for [`write_plan`].
    pub values: FileValues,
    /// Files that were left out. The import continues without them.
    pub failures: Vec<FileFailure>,
}

/// Stage every planned file of the items whose id is not in `skip`, which is
/// from [`existing_item_ids`]. A file that cannot be read or staged is
/// recorded as a failure.
pub fn stage_plan_files(
    writer: &VaultWriter,
    target: &Target,
    plan: &ImportPlan,
    skip: &HashSet<Uuid>,
) -> StagedFiles {
    let mut staged = StagedFiles {
        files: Vec::new(),
        values: FileValues::new(),
        failures: Vec::new(),
    };
    for item in plan.items.iter().filter(|i| !already_imported(i, skip)) {
        for planned in &item.files {
            let result = File::open(&planned.path)
                .map_err(|e| e.to_string())
                .and_then(|contents| {
                    let input = FileInput {
                        name: planned.name.clone(),
                        mime: None,
                        contents,
                    };
                    stage_file(writer, target, input).map_err(|e| e.to_string())
                });
            match result {
                Ok(file) => {
                    let value = SecretString::from(file.value().expose_secret().to_string());
                    staged.values.insert(planned.path.clone(), value);
                    staged.files.push(file);
                },
                Err(reason) => staged.failures.push(FileFailure {
                    item: item.title.clone(),
                    path: planned.path.clone(),
                    reason,
                }),
            }
        }
    }
    staged
}

/// Write a plan to a vault. Items whose id is already in the vault are
/// skipped. A planned item keeps its id, so an item without one gets a new id.
/// An item key that is taken gets a numeric suffix. A file credential
/// is written for each planned file that has a value in `files`. The caller
/// runs this in one vault transaction and saves. An error leaves the handle
/// partly written, so the caller must discard it.
pub fn write_plan(
    handle: &mut VaultHandle,
    plan: &ImportPlan,
    files: &FileValues,
) -> Result<ImportSummary, Error> {
    let mut summary = ImportSummary::default();
    let existing = existing_item_ids(handle)?;
    let mut taken: HashSet<String> = handle
        .list_items()?
        .iter()
        .map(|item| item.key.clone())
        .collect();

    let mut folders: HashMap<String, Uuid> = handle
        .list_folders()?
        .iter()
        .map(|folder| (folder.title.clone(), folder.id))
        .collect();
    let mut folder_ids: HashMap<&str, Uuid> = HashMap::new();
    for planned in &plan.folders {
        let id = match folders.get(&planned.title) {
            Some(id) => *id,
            None => {
                let id = handle.create_folder(&planned.title)?.id;
                folders.insert(planned.title.clone(), id);
                summary.folders_created += 1;
                id
            },
        };
        folder_ids.insert(planned.uuid.as_str(), id);
    }

    for item in &plan.items {
        if already_imported(item, &existing) {
            summary.skipped_existing += 1;
            continue;
        }
        let key = free_key(&item.key, &taken);
        taken.insert(key.clone());
        let folder = item
            .folder_uuid
            .as_deref()
            .and_then(|uuid| folder_ids.get(uuid).copied());
        let (written, left_out) = write_item(handle, item, &key, folder, files)?;
        summary.added += 1;
        summary.files_added += written;
        summary.files_skipped += left_out;
        if item.trashed {
            handle.delete_item(&key)?;
            summary.trashed += 1;
        }
    }
    Ok(summary)
}

/// Write one item. Returns the counts of file credentials written and left
/// out.
fn write_item(
    handle: &mut VaultHandle,
    item: &PlannedItem,
    key: &str,
    folder: Option<Uuid>,
    files: &FileValues,
) -> Result<(usize, usize), Error> {
    match item.id {
        Some(id) => handle.add_item_with_id(id, key, &item.title)?,
        None => handle.add_item(key, &item.title)?,
    };
    if let Some(at) = item.created_at {
        handle.set_item_created_at(key, at)?;
    }

    let mut ids: HashMap<&str, Uuid> = HashMap::new();
    for credential in &item.credentials {
        write_credential(handle, item, key, credential, None, &mut ids)?;
    }
    for section in &item.sections {
        let section_id = handle.create_item_section(key, &section.title)?.id;
        for credential in &section.credentials {
            write_credential(handle, item, key, credential, Some(section_id), &mut ids)?;
        }
    }

    let (mut written, mut left_out) = (0, 0);
    for file in &item.files {
        let Some(value) = files.get(&file.path) else {
            left_out += 1;
            continue;
        };
        handle.add_new_secret(
            key,
            &file.key,
            &file.title,
            FieldKind::File,
            SecretString::from(value.expose_secret().to_string()),
        )?;
        if let Some(at) = item.created_at {
            handle.set_credential_created_at(key, &file.key, at)?;
        }
        written += 1;
    }

    let slot = |slot: &Option<String>| slot.as_deref().and_then(|k| ids.get(k).copied());
    let autofill = ItemAutofill {
        websites: item.autofill.websites.clone(),
        username: slot(&item.autofill.username),
        password: slot(&item.autofill.password),
        totp: slot(&item.autofill.totp),
    };
    if !autofill.is_empty() {
        handle.set_item_autofill(key, autofill)?;
    }
    if let Some(category) = item.category {
        handle.set_item_category(key, Some(category.to_string()))?;
    }
    if folder.is_some() {
        handle.move_item(key, folder)?;
    }
    Ok((written, left_out))
}

fn write_credential<'a>(
    handle: &mut VaultHandle,
    item: &PlannedItem,
    item_key: &str,
    credential: &'a PlannedCredential,
    section: Option<Uuid>,
    ids: &mut HashMap<&'a str, Uuid>,
) -> Result<(), Error> {
    handle.add_secret(
        item_key,
        &credential.key,
        &credential.title,
        credential.kind.clone(),
        SecretString::from(credential.value.clone()),
    )?;
    if section.is_some() {
        handle.move_credential(item_key, &credential.key, section)?;
    }
    if let Some(at) = item.created_at {
        handle.set_credential_created_at(item_key, &credential.key, at)?;
    }
    if !credential.history.is_empty() {
        let entries: Vec<(i64, SecretString)> = credential
            .history
            .iter()
            .map(|entry| (entry.time, SecretString::from(entry.value.clone())))
            .collect();
        handle.add_history_values(item_key, &credential.key, &entries)?;
    }
    let overview = handle
        .get_secret_overview(item_key, &credential.key)?
        .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{}", credential.key)))?;
    ids.insert(credential.key.as_str(), overview.id);
    Ok(())
}

/// `key`, or `key` with the first numeric suffix that is not in `taken`.
fn free_key(key: &str, taken: &HashSet<String>) -> String {
    let mut candidate = key.to_string();
    let mut n = 2;
    while taken.contains(&candidate) {
        candidate = format!("{key}-{n}");
        n += 1;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use std::fs;

    use indoc::indoc;

    use super::*;
    use crate::secrets::vaults::files::{read_file, write_with_files};
    use crate::secrets::vaults::storage::txn::{Committed, Unlock};
    use crate::secrets::vaults::vault_import::map::{IMPORT_SECTION, MapOptions, map_items};
    use crate::secrets::vaults::vault_import::parse_1pif;
    use crate::secrets::vaults::{CATEGORY_LOGIN, FieldKind};

    fn plan_of(records: &str) -> ImportPlan {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.1pif"), records).unwrap();
        let options = MapOptions {
            include_trashed: true,
        };
        map_items(&parse_1pif(dir.path()).unwrap(), options)
    }

    fn handle() -> VaultHandle {
        VaultHandle::new_for_test("personal")
    }

    /// Write a plan that has no files.
    fn apply(vault: &mut VaultHandle, plan: &ImportPlan) -> Result<ImportSummary, Error> {
        write_plan(vault, plan, &FileValues::new())
    }

    /// Vault `personal` on disk, with its store under a temp directory.
    struct Fixture {
        dir: tempfile::TempDir,
        writer: VaultWriter,
        vault: VaultHandle,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let writer = VaultWriter::isolated(dir.path().join("data"));
            let vault =
                VaultHandle::new_for_test_at(dir.path().join("vaults").join("personal.json"));
            writer.create(&vault).unwrap();
            Self { dir, writer, vault }
        }

        /// Export folder with a note that has attachments `a.pdf` and `b.png`.
        fn export_with_attachments(&self) -> std::path::PathBuf {
            let export = self.dir.path().join("export.1pif");
            let uuid = "ABC123ABC123ABC123ABC123ABC123AB";
            fs::create_dir_all(export.join("attachments").join(uuid)).unwrap();
            let record = format!(
                r#"{{"uuid":"{uuid}","typeName":"securenotes.SecureNote","title":"Note","createdAt":1400000000,"secureContents":{{}}}}"#
            );
            fs::write(export.join("data.1pif"), record).unwrap();
            fs::write(export.join("attachments").join(uuid).join("a.pdf"), "alpha").unwrap();
            fs::write(export.join("attachments").join(uuid).join("b.png"), "bravo").unwrap();
            export
        }

        fn plan(&self, export: &std::path::Path) -> ImportPlan {
            map_items(&parse_1pif(export).unwrap(), MapOptions::default())
        }

        /// Stage the files of `plan`, then write it in one transaction.
        fn import(&self, plan: &ImportPlan) -> (Vec<FileFailure>, Committed<ImportSummary>) {
            let target = Target::of(&self.vault);
            let staged = stage_plan_files(&self.writer, &target, plan, &HashSet::new());
            let values = staged.values;
            let committed = write_with_files(
                &self.writer,
                &target,
                Unlock::Unlocked(&self.vault),
                staged.files,
                |vh| write_plan(vh, plan, &values),
            )
            .unwrap();
            (staged.failures, committed)
        }
    }

    fn secret(handle: &VaultHandle, item: &str, credential: &str) -> String {
        handle
            .get_secret(item, credential)
            .unwrap()
            .unwrap()
            .expose_secret()
            .clone()
    }

    const LOGIN_UUID: &str = "5930154CFAB244FB920D5189DA0FAB9C";

    const LOGIN: &str = indoc! {r#"
        {"uuid":"5930154CFAB244FB920D5189DA0FAB9C","typeName":"webforms.WebForm","title":"GitHub","location":"https://github.com","createdAt":1400000000,"folderUuid":"F1","secureContents":{"URLs":[{"label":"website","url":"https://github.com"}],"fields":[{"name":"login","designation":"username","value":"me","type":"T"},{"name":"pass","designation":"password","value":"hunter2","type":"P"}],"sections":[{"title":"Security","fields":[{"k":"concealed","t":"otp","v":"otpauth://totp/x?secret=abc"}]}],"notesPlain":"hello"}}
        {"uuid":"F1","typeName":"system.folder.Regular","title":"Work","secureContents":{}}
    "#};

    #[test]
    fn login_written_with_slots_sections_and_times() {
        let mut vault = handle();
        let summary = apply(&mut vault, &plan_of(LOGIN)).unwrap();

        assert_eq!(summary.added, 1);
        assert_eq!(summary.folders_created, 1);
        let item = vault.get_item_overview("github").unwrap().unwrap();
        assert_eq!(item.title, "GitHub");
        assert_eq!(item.created_at, 1_400_000_000);
        assert_eq!(item.category.as_deref(), Some(CATEGORY_LOGIN));
        assert_eq!(item.autofill.websites.len(), 1);
        let autofill = &item.autofill;
        assert_eq!(autofill.username_credential(item).unwrap().key, "username");
        assert_eq!(autofill.password_credential(item).unwrap().key, "password");
        assert_eq!(autofill.totp_credential(item).unwrap().key, "otp");
        assert!(
            item.credentials
                .values()
                .all(|c| c.created_at == 1_400_000_000)
        );
        assert_eq!(secret(&vault, "github", "password"), "hunter2");
        assert_eq!(secret(&vault, "github", "notes"), "hello");
        assert_eq!(
            secret(&vault, "github", "onepassword-type"),
            "webforms.WebForm"
        );
    }

    #[test]
    fn item_written_with_record_uuid_as_id() {
        let mut vault = handle();
        apply(&mut vault, &plan_of(LOGIN)).unwrap();

        let item = vault.get_item_overview("github").unwrap().unwrap();
        assert_eq!(item.id, Uuid::parse_str(LOGIN_UUID).unwrap());
    }

    #[test]
    fn item_without_usable_uuid_gets_new_id_and_imports_again() {
        let mut vault = handle();
        let plan = plan_of(indoc! {r#"
            {"uuid":"not-a-uuid","typeName":"securenotes.SecureNote","title":"Note","secureContents":{}}
        "#});

        apply(&mut vault, &plan).unwrap();
        let second = apply(&mut vault, &plan).unwrap();

        assert_eq!(second.added, 1);
        assert_eq!(second.skipped_existing, 0);
        assert_eq!(vault.list_items().unwrap().len(), 2);
    }

    #[test]
    fn add_item_with_id_refuses_taken_id_key_and_deleted_id() {
        let mut vault = handle();
        let id = Uuid::new_v4();
        vault.add_item_with_id(id, "one", "One").unwrap();

        let same_id = vault.add_item_with_id(id, "two", "Two");
        assert!(matches!(same_id, Err(Error::InvalidItemKey(_))));

        let same_key = vault.add_item_with_id(Uuid::new_v4(), "one", "Again");
        assert!(matches!(same_key, Err(Error::DuplicateItemKey(_))));

        vault.delete_item("one").unwrap();
        let deleted_id = vault.add_item_with_id(id, "three", "Three");
        assert!(matches!(deleted_id, Err(Error::InvalidItemKey(_))));
    }

    #[test]
    fn credentials_placed_in_sections() {
        let mut vault = handle();
        apply(&mut vault, &plan_of(LOGIN)).unwrap();

        let item = vault.get_item_overview("github").unwrap().unwrap();
        let section_of = |key: &str| {
            let credential = item.credentials.values().find(|c| c.key == key).unwrap();
            credential
                .section
                .map(|id| item.sections[&id].title.clone())
        };
        assert_eq!(section_of("otp").as_deref(), Some("Security"));
        assert_eq!(
            section_of("onepassword-type").as_deref(),
            Some(IMPORT_SECTION)
        );
        assert_eq!(section_of("password"), None);
        let otp = item.credentials.values().find(|c| c.key == "otp").unwrap();
        assert_eq!(otp.kind, FieldKind::Totp);
    }

    #[test]
    fn item_filed_in_folder() {
        let mut vault = handle();
        apply(&mut vault, &plan_of(LOGIN)).unwrap();

        let item = vault.get_item_overview("github").unwrap().unwrap();
        let folders = vault.list_folders().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].title, "Work");
        assert_eq!(item.folder, Some(folders[0].id));
    }

    #[test]
    fn reimport_skips_existing_items_and_reuses_folders() {
        let mut vault = handle();
        let plan = plan_of(LOGIN);
        apply(&mut vault, &plan).unwrap();

        let summary = apply(&mut vault, &plan).unwrap();

        assert_eq!(
            summary,
            ImportSummary {
                skipped_existing: 1,
                ..ImportSummary::default()
            }
        );
        assert_eq!(vault.list_items().unwrap().len(), 1);
        assert_eq!(vault.list_folders().unwrap().len(), 1);
    }

    #[test]
    fn reimport_skips_item_in_recently_deleted() {
        let mut vault = handle();
        let plan = plan_of(LOGIN);
        apply(&mut vault, &plan).unwrap();
        vault.delete_item("github").unwrap();

        let summary = apply(&mut vault, &plan).unwrap();

        assert_eq!(summary.added, 0);
        assert_eq!(summary.skipped_existing, 1);
        assert!(vault.list_items().unwrap().is_empty());
    }

    #[test]
    fn taken_item_key_gets_suffix() {
        let mut vault = handle();
        vault.add_item("github", "Mine").unwrap();

        apply(&mut vault, &plan_of(LOGIN)).unwrap();

        assert_eq!(
            vault.get_item_overview("github").unwrap().unwrap().title,
            "Mine"
        );
        let imported = vault.get_item_overview("github-2").unwrap().unwrap();
        assert_eq!(imported.title, "GitHub");
    }

    #[test]
    fn trashed_item_written_then_deleted() {
        let mut vault = handle();
        let plan = plan_of(indoc! {r#"
            {"uuid":"T1","typeName":"securenotes.SecureNote","title":"Old","trashed":true,"secureContents":{"notesPlain":"gone"}}
        "#});

        let summary = apply(&mut vault, &plan).unwrap();

        assert_eq!(summary.added, 1);
        assert_eq!(summary.trashed, 1);
        assert!(vault.list_items().unwrap().is_empty());
        let deleted = vault.list_deleted_items().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].item.title, "Old");
    }

    #[test]
    fn attachments_written_as_file_credentials() {
        let fx = Fixture::new();
        let plan = fx.plan(&fx.export_with_attachments());

        let (failures, committed) = fx.import(&plan);

        assert!(failures.is_empty());
        assert_eq!(committed.value.added, 1);
        assert_eq!(committed.value.files_added, 2);
        assert_eq!(committed.value.files_skipped, 0);
        let vault = &committed.vault;
        let item = vault.get_item_overview("note").unwrap().unwrap();
        let file = item
            .credentials
            .values()
            .find(|c| c.key == "a-pdf")
            .unwrap();
        assert_eq!(file.kind, FieldKind::File);
        assert_eq!(file.title, "a.pdf");
        assert_eq!(file.created_at, 1_400_000_000);
        let mut contents = Vec::new();
        let summary = read_file(&fx.writer, vault, "note", "b-png", &mut contents).unwrap();
        assert_eq!(contents, b"bravo");
        assert_eq!(summary.name, "b.png");
        assert_eq!(summary.mime, None);
    }

    #[test]
    fn unreadable_attachment_reported_and_import_continues() {
        let fx = Fixture::new();
        let export = fx.export_with_attachments();
        let plan = fx.plan(&export);
        let missing = plan.items[0].files[0].path.clone();
        fs::remove_file(&missing).unwrap();

        let (failures, committed) = fx.import(&plan);

        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].item, "Note");
        assert_eq!(failures[0].path, missing);
        assert_eq!(committed.value.added, 1);
        assert_eq!(committed.value.files_added, 1);
        assert_eq!(committed.value.files_skipped, 1);
        let item = committed.vault.get_item_overview("note").unwrap().unwrap();
        assert!(item.credentials.values().all(|c| c.key != "a-pdf"));
    }

    #[test]
    fn failed_write_leaves_no_blobs() {
        let fx = Fixture::new();
        let plan = fx.plan(&fx.export_with_attachments());
        let target = Target::of(&fx.vault);
        let staged = stage_plan_files(&fx.writer, &target, &plan, &HashSet::new());

        let result = write_with_files(
            &fx.writer,
            &target,
            Unlock::Unlocked(&fx.vault),
            staged.files,
            |_| Err::<(), _>(Error::InvalidItemKey("forced".to_string())),
        );

        assert!(result.is_err());
        let blobs = fx.writer.blob_store(fx.vault.vault_id().unwrap()).list();
        assert!(blobs.unwrap().is_empty());
    }

    const LOGIN_WITH_HISTORY: &str = indoc! {r#"
        {"uuid":"5930154CFAB244FB920D5189DA0FAB9C","typeName":"webforms.WebForm","title":"GitHub","createdAt":1400000000,"secureContents":{"fields":[{"name":"login","designation":"username","value":"me","type":"T"},{"name":"pass","designation":"password","value":"current","type":"P"}],"passwordHistory":[{"value":"first","time":1634666640},{"value":"second","time":1634666650}]}}
    "#};

    /// Previous values of a credential as `(value, time)`, oldest first.
    fn history(handle: &VaultHandle, item: &str, credential: &str) -> Vec<(String, i64)> {
        let mut entries: Vec<(String, i64)> = handle
            .list_history(item, credential)
            .unwrap()
            .iter()
            .map(|entry| {
                let value = handle
                    .get_history_value(item, credential, entry.id)
                    .unwrap();
                (value.expose_secret().clone(), entry.at)
            })
            .collect();
        entries.reverse();
        entries
    }

    #[test]
    fn history_written_oldest_first_at_original_times() {
        let mut vault = handle();

        apply(&mut vault, &plan_of(LOGIN_WITH_HISTORY)).unwrap();

        assert_eq!(secret(&vault, "github", "password"), "current");
        assert_eq!(
            history(&vault, "github", "password"),
            [
                ("first".to_string(), 1_634_666_640),
                ("second".to_string(), 1_634_666_650),
            ]
        );
        assert!(history(&vault, "github", "username").is_empty());
    }

    #[test]
    fn reimport_adds_no_history() {
        let mut vault = handle();
        let plan = plan_of(LOGIN_WITH_HISTORY);
        apply(&mut vault, &plan).unwrap();

        let summary = apply(&mut vault, &plan).unwrap();

        assert_eq!(summary.skipped_existing, 1);
        assert_eq!(history(&vault, "github", "password").len(), 2);
    }

    #[test]
    fn history_entry_equal_to_current_not_written() {
        let mut vault = handle();
        let plan = plan_of(indoc! {r#"
            {"uuid":"5930154CFAB244FB920D5189DA0FAB9C","typeName":"webforms.WebForm","title":"GitHub","secureContents":{"fields":[{"name":"pass","designation":"password","value":"current","type":"P"}],"passwordHistory":[{"value":"old","time":10},{"value":"current","time":20}]}}
        "#});

        apply(&mut vault, &plan).unwrap();

        assert_eq!(
            history(&vault, "github", "password"),
            [("old".to_string(), 10)]
        );
    }

    #[test]
    fn malformed_history_entry_skipped_import_continues() {
        let mut vault = handle();
        let plan = plan_of(indoc! {r#"
            {"uuid":"5930154CFAB244FB920D5189DA0FAB9C","typeName":"webforms.WebForm","title":"GitHub","secureContents":{"fields":[{"name":"pass","designation":"password","value":"current","type":"P"}],"passwordHistory":[{"value":"bad"},{"value":"good","time":10}]}}
            {"uuid":"N1","typeName":"securenotes.SecureNote","title":"Note","secureContents":{}}
        "#});

        let summary = apply(&mut vault, &plan).unwrap();

        assert_eq!(summary.added, 2);
        assert_eq!(
            history(&vault, "github", "password"),
            [("good".to_string(), 10)]
        );
    }

    #[test]
    fn note_without_time_keeps_current_time() {
        let mut vault = handle();
        let plan = plan_of(indoc! {r#"
            {"uuid":"N1","typeName":"securenotes.SecureNote","title":"Note","secureContents":{"notesPlain":"x"}}
        "#});

        apply(&mut vault, &plan).unwrap();

        let item = vault.get_item_overview("note").unwrap().unwrap();
        assert!(item.created_at > 1_700_000_000);
        assert_eq!(item.category, None);
    }
}
