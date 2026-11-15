use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};

use axo_pass_core::core::app_broker::{
    self, WireDropped, WireFileFailure, WireImportSummary, WireImportTarget,
};
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::secrets::vaults::vault_import::{
    MapOptions, dropped_data, map_items, parse_1pif,
};

const DEFAULT_VAULT_NAME: &str = "1Password";

const REIMPORT_NOTICE: &str = "A re-import only adds new items and does not update old ones.";

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

/// Import of a `.1pif` export, from the options of `ap vault import`.
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
}

impl OnePasswordImport {
    pub fn execute(&self) -> Result<(), String> {
        if self.dry_run {
            let (summary, without_id) = self.dry_run_summary()?;
            print!(
                "{}",
                render_report(&self.outcome_dry_run(), &summary, Some(without_id))
            );
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
        print!("{}", render_report(&outcome, &summary, None));
        Ok(())
    }

    /// Vault that receives the items. A new vault unless `--vault` is given.
    fn target(&self) -> WireImportTarget {
        match &self.vault {
            Some(vault_key) => WireImportTarget::Existing {
                vault_key: vault_key.clone(),
            },
            None => WireImportTarget::New {
                name: self
                    .name
                    .clone()
                    .unwrap_or_else(|| DEFAULT_VAULT_NAME.to_string()),
            },
        }
    }

    fn outcome_dry_run(&self) -> Outcome {
        Outcome::DryRun {
            include_trashed: self.include_trashed,
        }
    }

    /// Summary of what an import would do, from parsing and mapping in this
    /// process. Items already in the target vault are not known, so none are
    /// counted as skipped. Also returns the number of items with no usable
    /// uuid.
    fn dry_run_summary(&self) -> Result<(WireImportSummary, usize), String> {
        let parsed = parse_1pif(&self.path).map_err(|e| format!("Failed to parse 1pif: {e}"))?;
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
    DryRun {
        include_trashed: bool,
    },
    Imported {
        vault_key: String,
        new_vault: bool,
        include_trashed: bool,
    },
}

/// Report text for a dry run or a finished import. Concealed values are not
/// part of the summary, so none appear. `without_id` is the number of items
/// with no usable uuid, known only to a dry run.
fn render_report(
    outcome: &Outcome,
    summary: &WireImportSummary,
    without_id: Option<usize>,
) -> String {
    let mut out = String::new();
    let (dry_run, include_trashed) = match outcome {
        Outcome::DryRun { include_trashed } => (true, *include_trashed),
        Outcome::Imported {
            include_trashed, ..
        } => (false, *include_trashed),
    };

    if dry_run {
        let _ = writeln!(out, "Dry run. Nothing was written.");
    }
    if let Outcome::Imported {
        vault_key,
        new_vault: true,
        ..
    } = outcome
    {
        let _ = writeln!(out, "Created vault {vault_key}.");
        let _ = writeln!(
            out,
            "A re-import needs --vault {vault_key}. Without --vault, each run creates another vault."
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
    let _ = writeln!(out, "Trashed items written: {}.", summary.trashed);
    let _ = writeln!(out, "Trashed items skipped: {}.", summary.skipped_trashed);
    let _ = writeln!(out, "Folders created: {}.", summary.folders_created);
    let _ = writeln!(
        out,
        "Files added: {}. Files skipped: {}.",
        summary.files_added, summary.files_skipped
    );

    if let Some(count) = without_id.filter(|c| *c > 0) {
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

    let _ = writeln!(out, "\n{REIMPORT_NOTICE}");
    if include_trashed {
        let _ = writeln!(out, "{TRASHED_NOTICE}");
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
    fn name_conflicts_with_vault() {
        let err = parse(&["x.1pif", "--name", "A", "--vault", "b"]).unwrap_err();
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
    fn vault_selects_existing_target() {
        assert_eq!(
            import(&["x.1pif", "--vault", "work"]).target(),
            WireImportTarget::Existing {
                vault_key: "work".to_string()
            }
        );
    }

    #[test]
    fn repeated_vault_refused() {
        let cmd = parse(&["x.1pif", "--vault", "a", "--vault", "b"]).unwrap();
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
        let text = render_report(&outcome, &sample_summary(), None);

        assert!(text.contains("Created vault vault-1password."));
        assert!(text.contains("--vault vault-1password"));
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
        let text = render_report(&outcome, &WireImportSummary::default(), None);

        assert!(!text.contains("Created vault"));
        assert!(text.contains(REIMPORT_NOTICE));
        assert!(text.contains(TRASHED_NOTICE));
    }

    #[test]
    fn dry_run_report_counts_items_without_uuid() {
        let outcome = Outcome::DryRun {
            include_trashed: true,
        };
        let text = render_report(&outcome, &WireImportSummary::default(), Some(2));

        assert!(text.contains("Dry run. Nothing was written."));
        assert!(text.contains("2 items have no usable uuid."));
        assert!(text.contains(REIMPORT_NOTICE));
        assert!(text.contains(TRASHED_NOTICE));
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
