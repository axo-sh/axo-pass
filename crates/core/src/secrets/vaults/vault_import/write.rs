use std::collections::{HashMap, HashSet};

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::map::{ImportPlan, PlannedCredential, PlannedItem, UUID_KEY};
use crate::secrets::vaults::{Error, ItemAutofill, VaultHandle};

/// Counts of what [`write_plan`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportSummary {
    /// Items written, including trashed items.
    pub added: usize,
    /// Items left out because the vault already holds their 1Password uuid.
    pub skipped_existing: usize,
    /// Written items that were then deleted.
    pub trashed: usize,
    /// Folders created. A folder with the title of an existing folder is
    /// reused.
    pub folders_created: usize,
}

/// 1Password uuids of items that an earlier import wrote to the vault. This
/// includes items in Recently Deleted.
pub fn existing_import_uuids(handle: &VaultHandle) -> Result<HashSet<String>, Error> {
    let mut uuids = HashSet::new();
    for item in handle.list_items()? {
        if let Some(secret) = handle.get_secret(&item.key, UUID_KEY)? {
            uuids.insert(secret.expose_secret().clone());
        }
    }
    for deleted in handle.list_deleted_items()? {
        let uuid_credential = deleted
            .item
            .credentials
            .values()
            .find(|c| c.key == UUID_KEY);
        if let Some(credential) = uuid_credential {
            let secret = handle.get_deleted_secret(deleted.item.id, credential.id)?;
            uuids.insert(secret.expose_secret().clone());
        }
    }
    Ok(uuids)
}

/// Write a plan to a vault. Items whose uuid is already in the vault are
/// skipped. An item key that is taken gets a numeric suffix. The caller runs
/// this in one vault transaction and saves. An error leaves the handle
/// partly written, so the caller must discard it.
pub fn write_plan(handle: &mut VaultHandle, plan: &ImportPlan) -> Result<ImportSummary, Error> {
    let mut summary = ImportSummary::default();
    let existing = existing_import_uuids(handle)?;
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
        if existing.contains(&item.uuid) {
            summary.skipped_existing += 1;
            continue;
        }
        let key = free_key(&item.key, &taken);
        taken.insert(key.clone());
        let folder = item
            .folder_uuid
            .as_deref()
            .and_then(|uuid| folder_ids.get(uuid).copied());
        write_item(handle, item, &key, folder)?;
        summary.added += 1;
        if item.trashed {
            handle.delete_item(&key)?;
            summary.trashed += 1;
        }
    }
    Ok(summary)
}

fn write_item(
    handle: &mut VaultHandle,
    item: &PlannedItem,
    key: &str,
    folder: Option<Uuid>,
) -> Result<(), Error> {
    handle.add_item(key, &item.title)?;
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
    Ok(())
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

    fn secret(handle: &VaultHandle, item: &str, credential: &str) -> String {
        handle
            .get_secret(item, credential)
            .unwrap()
            .unwrap()
            .expose_secret()
            .clone()
    }

    const LOGIN: &str = indoc! {r#"
        {"uuid":"L1","typeName":"webforms.WebForm","title":"GitHub","createdAt":1400000000,"folderUuid":"F1","secureContents":{"URLs":[{"label":"website","url":"https://github.com"}],"fields":[{"name":"login","designation":"username","value":"me","type":"T"},{"name":"pass","designation":"password","value":"hunter2","type":"P"}],"sections":[{"title":"Security","fields":[{"k":"concealed","t":"otp","v":"otpauth://totp/x?secret=abc"}]}],"notesPlain":"hello"}}
        {"uuid":"F1","typeName":"system.folder.Regular","title":"Work","secureContents":{}}
    "#};

    #[test]
    fn login_written_with_slots_sections_and_times() {
        let mut vault = handle();
        let summary = write_plan(&mut vault, &plan_of(LOGIN)).unwrap();

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
        assert_eq!(secret(&vault, "github", "onepassword-uuid"), "L1");
    }

    #[test]
    fn credentials_placed_in_sections() {
        let mut vault = handle();
        write_plan(&mut vault, &plan_of(LOGIN)).unwrap();

        let item = vault.get_item_overview("github").unwrap().unwrap();
        let section_of = |key: &str| {
            let credential = item.credentials.values().find(|c| c.key == key).unwrap();
            credential
                .section
                .map(|id| item.sections[&id].title.clone())
        };
        assert_eq!(section_of("otp").as_deref(), Some("Security"));
        assert_eq!(
            section_of("onepassword-uuid").as_deref(),
            Some(IMPORT_SECTION)
        );
        assert_eq!(section_of("password"), None);
        let otp = item.credentials.values().find(|c| c.key == "otp").unwrap();
        assert_eq!(otp.kind, FieldKind::Totp);
    }

    #[test]
    fn item_filed_in_folder() {
        let mut vault = handle();
        write_plan(&mut vault, &plan_of(LOGIN)).unwrap();

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
        write_plan(&mut vault, &plan).unwrap();

        let summary = write_plan(&mut vault, &plan).unwrap();

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
        write_plan(&mut vault, &plan).unwrap();
        vault.delete_item("github").unwrap();

        let summary = write_plan(&mut vault, &plan).unwrap();

        assert_eq!(summary.added, 0);
        assert_eq!(summary.skipped_existing, 1);
        assert!(vault.list_items().unwrap().is_empty());
    }

    #[test]
    fn taken_item_key_gets_suffix() {
        let mut vault = handle();
        vault.add_item("github", "Mine").unwrap();

        write_plan(&mut vault, &plan_of(LOGIN)).unwrap();

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

        let summary = write_plan(&mut vault, &plan).unwrap();

        assert_eq!(summary.added, 1);
        assert_eq!(summary.trashed, 1);
        assert!(vault.list_items().unwrap().is_empty());
        let deleted = vault.list_deleted_items().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].item.title, "Old");
    }

    #[test]
    fn note_without_time_keeps_current_time() {
        let mut vault = handle();
        let plan = plan_of(indoc! {r#"
            {"uuid":"N1","typeName":"securenotes.SecureNote","title":"Note","secureContents":{"notesPlain":"x"}}
        "#});

        write_plan(&mut vault, &plan).unwrap();

        let item = vault.get_item_overview("note").unwrap().unwrap();
        assert!(item.created_at > 1_700_000_000);
        assert_eq!(item.category, None);
    }
}
