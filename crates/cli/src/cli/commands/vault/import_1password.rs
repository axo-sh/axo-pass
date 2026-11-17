use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};

use axo_pass_core::core::app_broker::{
    self, WireDropped, WireFileFailure, WireImportSummary, WireImportTarget,
};
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::secrets::vaults::vault_import::{
    MapOptions, dropped_data, is_apple_csv, map_items, parse_export,
};
use inquire::Confirm;

const REIMPORT_NOTICE: &str = "A re-import only adds new items and does not update old ones.";

const APPLE_REIMPORT_NOTICE: &str =
    "An Apple Passwords export has no item ids, so a re-import adds every item again.";

const PLAINTEXT_NOTICE: &str =
    "The export file holds passwords in plain text. Delete it after checking the import.";

const TRASHED_NOTICE: &str = "Purging an imported trashed item makes the next import add it again.";

/// Whether `path` is a 1Password `.1pif` export. That is a file with the
/// extension or a directory that holds `data.1pif` or `1PIF.txt`.
pub(super) fn is_1pif(path: &Path) -> bool {
    if path.is_dir() {
        return ["data.1pif", "1PIF.txt"]
            .iter()
            .any(|name| path.join(name).is_file());
    }
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("1pif"))
}

/// Whether `path` is an item export that this import reads, a 1Password
/// `.1pif` export or an Apple Passwords `.csv` file.
pub(super) fn is_item_export(path: &Path) -> bool {
    is_1pif(path) || is_apple_csv(path)
}

/// Application that wrote an item export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    OnePassword,
    ApplePasswords,
}

impl Source {
    fn of(path: &Path) -> Self {
        if is_apple_csv(path) {
            Self::ApplePasswords
        } else {
            Self::OnePassword
        }
    }

    /// Name of a new vault if `--name` is not given.
    fn vault_name(self) -> &'static str {
        match self {
            Self::OnePassword => "1Password",
            Self::ApplePasswords => "Apple Passwords",
        }
    }

    fn reimport_notice(self) -> &'static str {
        match self {
            Self::OnePassword => REIMPORT_NOTICE,
            Self::ApplePasswords => APPLE_REIMPORT_NOTICE,
        }
    }
}

/// Import of a `.1pif` or Apple Passwords `.csv` export, from the options of
/// `ap vault import`.
#[derive(Debug)]
pub(super) struct OnePasswordImport {
    /// `.1pif` export directory or its data file.
    pub(super) path: PathBuf,
    /// Name of a new vault. Unused if `vault` is set.
    pub(super) name: Option<String>,
    /// Key of an existing vault to import into.
    pub(super) vault: Option<String>,
    pub(super) include_trashed: bool,
    pub(super) dry_run: bool,
    /// Import without asking for confirmation.
    pub(super) yes: bool,
    /// Show the full report before asking for confirmation.
    pub(super) verbose: bool,
}

impl OnePasswordImport {
    pub fn execute(&self) -> Result<(), String> {
        if !self.confirm()? {
            println!("Import cancelled.");
            return Ok(());
        }

        let caller = Provenance::resolve_current_parent().and_then(|p| p.caller());
        // The app serves the request from its own working directory, so it
        // needs an absolute path to the export.
        let import_path = self
            .path
            .canonicalize()
            .unwrap_or_else(|_| self.path.clone())
            .to_string_lossy()
            .to_string();

        let (vault_key, summary) = app_broker::request_import_items(
            &import_path,
            self.include_trashed,
            self.target(),
            caller.as_deref(),
        )
        .map_err(|e| format!("Failed to import items: {e}"))?;

        let outcome = Outcome::Imported {
            vault_key,
            new_vault: self.vault.is_none(),
            include_trashed: self.include_trashed,
        };
        print!(
            "{}",
            render_report(Source::of(&self.path), &outcome, &summary, None)
        );
        Ok(())
    }

    /// Whether to go ahead with the import. Always true with `--yes`. Always
    /// false with `--dry-run`, as if the question were answered no. Otherwise
    /// prints the preview and asks.
    fn confirm(&self) -> Result<bool, String> {
        if self.yes && !self.dry_run {
            return Ok(true);
        }
        let summary = self.preview()?;
        if self.dry_run {
            return Ok(false);
        }
        let target = match self.target() {
            WireImportTarget::Existing { vault_key } => format!("vault {vault_key}"),
            WireImportTarget::New { name } => format!("a new vault named {name}"),
        };
        let prompt = format!(
            "Import {} items from {} into {target}?",
            summary.added,
            self.path.display()
        );
        Confirm::new(&prompt)
            .with_default(true)
            .prompt()
            .map_err(|e| format!("Import not confirmed ({e}). Use --yes to skip the question."))
    }

    /// Vault that receives the items. A new vault unless `--into` is given.
    fn target(&self) -> WireImportTarget {
        match &self.vault {
            Some(vault_key) => WireImportTarget::Existing {
                vault_key: vault_key.clone(),
            },
            None => WireImportTarget::New {
                name: self
                    .name
                    .clone()
                    .unwrap_or_else(|| Source::of(&self.path).vault_name().to_string()),
            },
        }
    }

    /// Print what the import would do, as a brief summary or as the full
    /// report with `--verbose`. Parses the export in this process.
    fn preview(&self) -> Result<WireImportSummary, String> {
        let (summary, without_id) = self.dry_run_summary()?;
        let source = Source::of(&self.path);
        if self.verbose {
            let outcome = Outcome::Preview {
                include_trashed: self.include_trashed,
            };
            println!(
                "{}",
                render_report(source, &outcome, &summary, Some(without_id))
            );
        } else {
            println!("{}", brief_summary(source, &summary));
        }
        Ok(summary)
    }

    /// Summary of what an import would do, from parsing and mapping in this
    /// process. Items already in the target vault are not known, so none are
    /// counted as skipped. Also returns the number of items with no usable
    /// uuid.
    fn dry_run_summary(&self) -> Result<(WireImportSummary, usize), String> {
        let parsed =
            parse_export(&self.path).map_err(|e| format!("Failed to parse export: {e}"))?;
        let plan = map_items(
            &parsed,
            MapOptions {
                include_trashed: self.include_trashed,
            },
        );

        let dropped = parsed
            .iter()
            .filter(|item| self.include_trashed || !item.trashed)
            .flat_map(|item| {
                dropped_data(item).into_iter().map(|d| WireDropped {
                    item: item.title.clone(),
                    kind: d.kind.to_string(),
                    detail: d.detail,
                })
            })
            .collect();

        let summary = WireImportSummary {
            added: plan.items.len() as u32,
            files_added: plan.items.iter().map(|i| i.files.len()).sum::<usize>() as u32,
            trashed: plan.items.iter().filter(|i| i.trashed).count() as u32,
            folders_created: plan.folders.len() as u32,
            skipped_trashed: plan.skipped_trashed as u32,
            repeated_uuids: plan.repeated_uuids.clone(),
            dropped,
            ..WireImportSummary::default()
        };
        let without_id = plan.items.iter().filter(|i| i.id.is_none()).count();
        Ok((summary, without_id))
    }
}

/// What the report describes.
enum Outcome {
    /// Report shown before the confirmation question, or for a dry run.
    Preview { include_trashed: bool },
    Imported {
        vault_key: String,
        new_vault: bool,
        include_trashed: bool,
    },
}

/// Short summary of an import to confirm. Lines for zero counts are left out.
/// Dropped data is counted, and `--verbose` lists it.
fn brief_summary(source: Source, summary: &WireImportSummary) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Items to import: {}.", summary.added);
    if source == Source::OnePassword {
        let counts = [
            ("Trashed items written", summary.trashed),
            ("Trashed items skipped", summary.skipped_trashed),
            ("Folders to create", summary.folders_created),
            ("Files to add", summary.files_added),
        ];
        for (label, count) in counts {
            if count > 0 {
                let _ = writeln!(out, "{label}: {count}.");
            }
        }
    }
    if !summary.dropped.is_empty() {
        let _ = writeln!(
            out,
            "Data not imported: {} entries. Use --verbose to list them.",
            summary.dropped.len()
        );
    }
    out
}

/// Report text for a preview or a finished import. Concealed values are not
/// part of the summary, so none appear. `without_id` is the number of items
/// with no usable uuid, known only to a preview. An Apple Passwords export has
/// no trashed items, folders, files, or uuids, so the report leaves those out.
fn render_report(
    source: Source,
    outcome: &Outcome,
    summary: &WireImportSummary,
    without_id: Option<usize>,
) -> String {
    let mut out = String::new();
    let (dry_run, include_trashed) = match outcome {
        Outcome::Preview { include_trashed } => (true, *include_trashed),
        Outcome::Imported {
            include_trashed, ..
        } => (false, *include_trashed),
    };

    if let Outcome::Imported {
        vault_key,
        new_vault: true,
        ..
    } = outcome
    {
        let _ = writeln!(out, "Created vault {vault_key}.");
        let _ = writeln!(
            out,
            "A re-import needs --into {vault_key}. Without --into, each run creates another vault."
        );
    }

    let verb = if dry_run { "Would add" } else { "Added" };
    let _ = writeln!(out, "{verb} {} items.", summary.added);
    if !dry_run {
        let _ = writeln!(
            out,
            "Skipped {} items that were already imported.",
            summary.skipped_existing
        );
    }
    if source == Source::OnePassword {
        let _ = writeln!(out, "Trashed items written: {}.", summary.trashed);
        let _ = writeln!(out, "Trashed items skipped: {}.", summary.skipped_trashed);
        let _ = writeln!(out, "Folders created: {}.", summary.folders_created);
        let _ = writeln!(
            out,
            "Files added: {}. Files skipped: {}.",
            summary.files_added, summary.files_skipped
        );
    }

    if source == Source::OnePassword
        && let Some(count) = without_id.filter(|c| *c > 0)
    {
        let _ = writeln!(
            out,
            "{count} items have no usable uuid. A re-import does not recognize them."
        );
    }
    if !summary.repeated_uuids.is_empty() {
        let _ = writeln!(
            out,
            "Record uuids that repeat an earlier record. A re-import does not recognize these items:"
        );
        for uuid in &summary.repeated_uuids {
            let _ = writeln!(out, "  {uuid}");
        }
    }

    render_file_failures(&mut out, &summary.file_failures);
    render_dropped(&mut out, &summary.dropped);

    let _ = writeln!(out, "\n{}", source.reimport_notice());
    if include_trashed && source == Source::OnePassword {
        let _ = writeln!(out, "{TRASHED_NOTICE}");
    }
    if !dry_run {
        let _ = writeln!(out, "{PLAINTEXT_NOTICE}");
    }
    out
}

fn render_file_failures(out: &mut String, failures: &[WireFileFailure]) {
    if failures.is_empty() {
        return;
    }
    let _ = writeln!(out, "Files that could not be read ({}):", failures.len());
    for failure in failures {
        let WireFileFailure { item, path, reason } = failure;
        let _ = writeln!(out, "  {item}: {path}: {reason}");
    }
}

/// Dropped data grouped by kind, with the number of entries and the titles of
/// the items that have them.
fn render_dropped(out: &mut String, dropped: &[WireDropped]) {
    if dropped.is_empty() {
        return;
    }
    let mut by_kind: BTreeMap<&str, Vec<&WireDropped>> = BTreeMap::new();
    for entry in dropped {
        by_kind.entry(entry.kind.as_str()).or_default().push(entry);
    }
    let _ = writeln!(out, "Not imported:");
    for (kind, entries) in &by_kind {
        let _ = writeln!(out, "  {kind}: {}", entries.len());
        for entry in entries {
            if entry.detail.is_empty() {
                let _ = writeln!(out, "    {}", entry.item);
            } else {
                let _ = writeln!(out, "    {}: {}", entry.item, entry.detail);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use clap::Parser;

    use super::super::import::VaultImportCommand;
    use super::*;

    fn parse(args: &[&str]) -> Result<VaultImportCommand, clap::Error> {
        let mut argv = vec!["import"];
        argv.extend_from_slice(args);
        VaultImportCommand::try_parse_from(argv)
    }

    fn import(args: &[&str]) -> OnePasswordImport {
        parse(args).unwrap().one_password().unwrap().unwrap()
    }

    fn sample_summary() -> WireImportSummary {
        WireImportSummary {
            added: 3,
            files_added: 2,
            files_skipped: 1,
            skipped_existing: 4,
            trashed: 1,
            folders_created: 2,
            skipped_trashed: 5,
            repeated_uuids: vec!["AAA1".to_string()],
            file_failures: vec![WireFileFailure {
                item: "GitHub".to_string(),
                path: "attachments/AAA1/key.pem".to_string(),
                reason: "permission denied".to_string(),
            }],
            dropped: vec![
                WireDropped {
                    item: "GitHub".to_string(),
                    kind: "tags".to_string(),
                    detail: "work".to_string(),
                },
                WireDropped {
                    item: "WiFi".to_string(),
                    kind: "tags".to_string(),
                    detail: String::new(),
                },
                WireDropped {
                    item: "WiFi".to_string(),
                    kind: "favorite".to_string(),
                    detail: String::new(),
                },
            ],
        }
    }

    #[test]
    fn name_conflicts_with_into() {
        let err = parse(&["x.1pif", "--name", "A", "--into", "b"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn default_target_is_new_vault_named_1password() {
        assert_eq!(
            import(&["x.1pif"]).target(),
            WireImportTarget::New {
                name: "1Password".to_string()
            }
        );
    }

    #[test]
    fn name_sets_new_vault_name() {
        assert_eq!(
            import(&["x.1pif", "--name", "Old logins"]).target(),
            WireImportTarget::New {
                name: "Old logins".to_string()
            }
        );
    }

    #[test]
    fn into_selects_existing_target() {
        assert_eq!(
            import(&["x.1pif", "--into", "work"]).target(),
            WireImportTarget::Existing {
                vault_key: "work".to_string()
            }
        );
    }

    #[test]
    fn vault_selector_refused_for_1pif() {
        let cmd = parse(&["x.1pif", "--vault", "a"]).unwrap();
        assert!(cmd.one_password().is_err());
    }

    #[test]
    fn into_refused_for_bundle() {
        let cmd = parse(&["x.axo", "--into", "a"]).unwrap();
        assert!(cmd.one_password().is_err());
    }

    #[test]
    fn bundle_flags_refused_for_1pif() {
        for extra in [
            &["--existing", "skip"][..],
            &["--key", "a=b"],
            &["--passphrase", "x"],
        ] {
            let mut args = vec!["x.1pif"];
            args.extend_from_slice(extra);
            assert!(parse(&args).unwrap().one_password().is_err(), "{extra:?}");
        }
    }

    #[test]
    fn export_flags_refused_for_bundle() {
        for flag in ["--include-trashed", "--dry-run"] {
            let cmd = parse(&["x.axo", flag]).unwrap();
            assert!(cmd.one_password().is_err(), "{flag}");
        }
        assert!(parse(&["x.axo"]).unwrap().one_password().unwrap().is_none());
    }

    #[test]
    fn detects_1pif_directory() {
        let dir = std::env::temp_dir().join(format!("ap-detect-1pif-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert!(!is_1pif(&dir));
        fs::write(dir.join("data.1pif"), "").unwrap();
        assert!(is_1pif(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_lists_skips_failures_and_dropped_data() {
        let outcome = Outcome::Imported {
            vault_key: "vault-1password".to_string(),
            new_vault: true,
            include_trashed: false,
        };
        let text = render_report(Source::OnePassword, &outcome, &sample_summary(), None);

        assert!(text.contains("Created vault vault-1password."));
        assert!(text.contains("--into vault-1password"));
        assert!(text.contains("Added 3 items."));
        assert!(text.contains("Skipped 4 items that were already imported."));
        assert!(text.contains("Trashed items skipped: 5."));
        assert!(text.contains("Files added: 2. Files skipped: 1."));
        assert!(text.contains("  AAA1"));
        assert!(text.contains("GitHub: attachments/AAA1/key.pem: permission denied"));
        assert!(text.contains("  tags: 2\n    GitHub: work\n    WiFi\n"));
        assert!(text.contains("  favorite: 1\n    WiFi\n"));
        assert!(text.contains(REIMPORT_NOTICE));
        assert!(!text.contains(TRASHED_NOTICE));
    }

    #[test]
    fn existing_vault_report_omits_new_vault_text() {
        let outcome = Outcome::Imported {
            vault_key: "work".to_string(),
            new_vault: false,
            include_trashed: true,
        };
        let text = render_report(
            Source::OnePassword,
            &outcome,
            &WireImportSummary::default(),
            None,
        );

        assert!(!text.contains("Created vault"));
        assert!(text.contains(REIMPORT_NOTICE));
        assert!(text.contains(TRASHED_NOTICE));
    }

    #[test]
    fn import_report_reminds_to_delete_export() {
        for source in [Source::OnePassword, Source::ApplePasswords] {
            let outcome = Outcome::Imported {
                vault_key: "work".to_string(),
                new_vault: false,
                include_trashed: false,
            };
            let text = render_report(source, &outcome, &WireImportSummary::default(), None);
            assert!(text.contains(PLAINTEXT_NOTICE));
        }
    }

    #[test]
    fn preview_report_omits_delete_reminder() {
        let outcome = Outcome::Preview {
            include_trashed: false,
        };
        let text = render_report(
            Source::OnePassword,
            &outcome,
            &WireImportSummary::default(),
            None,
        );
        assert!(!text.contains(PLAINTEXT_NOTICE));
    }

    #[test]
    fn apple_report_omits_1password_lines() {
        let outcome = Outcome::Preview {
            include_trashed: true,
        };
        let text = render_report(
            Source::ApplePasswords,
            &outcome,
            &WireImportSummary::default(),
            Some(2),
        );

        assert!(text.contains("Would add 0 items."));
        assert!(text.contains(APPLE_REIMPORT_NOTICE));
        for absent in ["Trashed", "Folders", "Files", "uuid", REIMPORT_NOTICE] {
            assert!(!text.contains(absent), "{absent}");
        }
    }

    #[test]
    fn csv_path_defaults_to_apple_vault_name() {
        let dir = std::env::temp_dir().join(format!("ap-default-name-csv-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("Passwords.csv");
        fs::write(&csv, "Title,Password\n").unwrap();
        let args = [csv.to_str().unwrap()];
        assert_eq!(
            import(&args).target(),
            WireImportTarget::New {
                name: "Apple Passwords".to_string()
            }
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_report_counts_items_without_uuid() {
        let outcome = Outcome::Preview {
            include_trashed: true,
        };
        let text = render_report(
            Source::OnePassword,
            &outcome,
            &WireImportSummary::default(),
            Some(2),
        );

        assert!(text.contains("2 items have no usable uuid."));
        assert!(text.contains(REIMPORT_NOTICE));
        assert!(text.contains(TRASHED_NOTICE));
    }

    #[test]
    fn confirmation_skipped_only_with_yes() {
        assert!(!import(&["x.1pif"]).yes);
        assert!(import(&["x.1pif", "--yes"]).yes);
        assert!(import(&["x.1pif", "-y"]).yes);
    }

    #[test]
    fn yes_and_verbose_refused_for_bundle() {
        for flag in ["--yes", "--verbose"] {
            let cmd = parse(&["x.axo", flag]).unwrap();
            assert!(cmd.one_password().is_err(), "{flag}");
        }
    }

    #[test]
    fn verbose_flag_read() {
        assert!(!import(&["x.1pif"]).verbose);
        assert!(import(&["x.1pif", "--verbose"]).verbose);
    }

    #[test]
    fn brief_summary_counts_and_points_to_verbose() {
        let text = brief_summary(Source::OnePassword, &sample_summary());
        assert!(text.contains("Items to import: 3."));
        assert!(text.contains("Trashed items skipped: 5."));
        assert!(text.contains("Folders to create: 2."));
        assert!(text.contains("Data not imported: 3 entries. Use --verbose"));
        assert!(!text.contains("GitHub"));
    }

    #[test]
    fn brief_summary_omits_zero_counts_and_apple_extras() {
        let text = brief_summary(Source::OnePassword, &WireImportSummary::default());
        assert_eq!(text, "Items to import: 0.\n");

        let apple = brief_summary(Source::ApplePasswords, &sample_summary());
        assert!(!apple.contains("Trashed"));
        assert!(!apple.contains("Folders"));
    }

    #[test]
    fn dry_run_declines_without_asking() {
        let dir = std::env::temp_dir().join(format!("ap-dry-run-declines-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let data = r#"{"uuid":"AAA1","typeName":"passwords.Password","title":"WiFi","secureContents":{"password":"pw"}}"#;
        fs::write(dir.join("data.1pif"), data).unwrap();

        // `--yes` does not turn a dry run into an import. There is no
        // terminal in a test, so asking would fail.
        let cmd = import(&[dir.to_str().unwrap(), "--dry-run", "--yes"]);
        let confirmed = cmd.confirm();
        let _ = fs::remove_dir_all(&dir);

        assert!(!confirmed.unwrap());
    }

    #[test]
    fn dry_run_needs_no_broker() {
        let dir = std::env::temp_dir().join(format!("ap-import-1password-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let data = concat!(
            r#"{"uuid":"AAA1","typeName":"passwords.Password","title":"WiFi","secureContents":{"password":"correcthorse"}}"#,
            "\n***5642bee8-a5ff-11dc-8314-0800200c9a66***\n",
            r#"{"uuid":"CCC3","typeName":"securenotes.SecureNote","title":"Old","trashed":true,"secureContents":{"notesPlain":"gone"}}"#,
        );
        fs::write(dir.join("data.1pif"), data).unwrap();

        let cmd = import(&[dir.to_str().unwrap(), "--dry-run"]);
        let (summary, without_id) = cmd.dry_run_summary().unwrap();
        // No app is running in a test, so a broker call would fail.
        cmd.execute().unwrap();
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(summary.added, 1);
        assert_eq!(summary.skipped_trashed, 1);
        assert_eq!(summary.skipped_existing, 0);
        // The uuid "AAA1" is not a uuid.
        assert_eq!(without_id, 1);
        assert!(!format!("{summary:?}").contains("correcthorse"));
    }
}
