//! Checked-in samples of a serialized schema, one directory per schema
//! version.
//!
//! A schema test builds a sample of every serialized struct from fixed values
//! and compares the samples with the files in `snapshots/{name}-{version}/`
//! of this crate. A directory is written only if it is missing, and is never
//! replaced. A changed sample therefore fails the test until the version is
//! bumped, which writes a new directory beside the older ones.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Field added to each object of a sample to check that it is refused.
const UNKNOWN_FIELD: &str = "unknown_field";

/// Samples of one schema version, by file name.
pub(crate) struct SchemaSnapshot {
    dir: PathBuf,
    samples: BTreeMap<String, String>,
}

impl SchemaSnapshot {
    /// Snapshot of schema `name` at `version`, in `snapshots/` of this crate.
    pub(crate) fn new(name: &str, version: u32) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots");
        Self::in_dir(&root, name, version)
    }

    /// Snapshot of schema `name` at `version`, in `root`.
    pub(crate) fn in_dir(root: &Path, name: &str, version: u32) -> Self {
        Self {
            dir: root.join(format!("{name}-{version}")),
            samples: BTreeMap::new(),
        }
    }

    /// Add `value` as the sample `name`, pretty-printed. The sample must parse
    /// back as `T` and serialize to the same text. It must fail to parse with
    /// an unknown field added to any of its objects. Objects at a key in
    /// `open_keys`, and the objects inside them, are not checked.
    pub(crate) fn add<T>(&mut self, name: &str, value: &T, open_keys: &[&str])
    where
        T: Serialize + DeserializeOwned,
    {
        let text = serde_json::to_string_pretty(value).unwrap();
        self.add_text(name, text, open_keys, |text| {
            let value: T = serde_json::from_str(text).map_err(|e| e.to_string())?;
            serde_json::to_string_pretty(&value).map_err(|e| e.to_string())
        });
    }

    /// Add `text` as the sample `name`. `parse` reads a text and returns it
    /// serialized again. The checks of [`Self::add`] apply through `parse`.
    pub(crate) fn add_text(
        &mut self,
        name: &str,
        text: String,
        open_keys: &[&str],
        parse: impl Fn(&str) -> Result<String, String>,
    ) {
        let again = parse(&text).unwrap_or_else(|e| panic!("{name} does not parse: {e}"));
        assert_eq!(again, text, "{name} serializes to other text after a parse");
        let json: Value = serde_json::from_str(&text).unwrap();
        for pointer in Self::object_pointers(&json, open_keys) {
            let mut edited = json.clone();
            let object = edited.pointer_mut(&pointer).unwrap();
            object
                .as_object_mut()
                .unwrap()
                .insert(UNKNOWN_FIELD.to_string(), Value::from(1));
            let edited = serde_json::to_string_pretty(&edited).unwrap();
            assert!(
                parse(&edited).is_err(),
                "{name} parses with an unknown field at \"{pointer}\""
            );
        }
        assert!(
            self.samples.insert(name.to_string(), text).is_none(),
            "{name} is added twice"
        );
    }

    /// JSON pointers of every object in `json`, `json` included, except
    /// objects at a key in `open_keys` and the objects inside them.
    fn object_pointers(json: &Value, open_keys: &[&str]) -> Vec<String> {
        fn walk(value: &Value, pointer: String, open_keys: &[&str], pointers: &mut Vec<String>) {
            match value {
                Value::Object(map) => {
                    pointers.push(pointer.clone());
                    for (key, child) in map {
                        if child.is_object() && open_keys.contains(&key.as_str()) {
                            continue;
                        }
                        let escaped = key.replace('~', "~0").replace('/', "~1");
                        walk(child, format!("{pointer}/{escaped}"), open_keys, pointers);
                    }
                },
                Value::Array(values) => {
                    for (index, child) in values.iter().enumerate() {
                        walk(child, format!("{pointer}/{index}"), open_keys, pointers);
                    }
                },
                _ => {},
            }
        }

        let mut pointers = Vec::new();
        walk(json, String::new(), open_keys, &mut pointers);
        pointers
    }

    /// Replace the text of the sample `name` with `edit` of it, without the
    /// checks of [`Self::add`]. For tests of a changed schema.
    pub(crate) fn edit(&mut self, name: &str, edit: impl FnOnce(&str) -> String) {
        let text = self.samples.get_mut(name).unwrap();
        *text = edit(text);
    }

    /// Write the snapshot directory with the samples if it is missing. Returns
    /// whether it was written. An existing directory is never changed.
    pub(crate) fn write_if_missing(&self) -> Result<bool, String> {
        let dir = self.dir.display();
        if self.dir.exists() {
            return Ok(false);
        }
        fs::create_dir_all(&self.dir).map_err(|e| format!("Cannot create {dir}: {e}"))?;
        for (name, text) in &self.samples {
            let path = self.dir.join(format!("{name}.json"));
            fs::write(&path, format!("{text}\n"))
                .map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
        }
        Ok(true)
    }

    /// Compare the samples with the files of the snapshot directory. A missing
    /// directory fails.
    pub(crate) fn compare(&self) -> Result<(), String> {
        let dir = self.dir.display();
        let mut files = BTreeMap::new();
        let entries = fs::read_dir(&self.dir).map_err(|e| format!("Cannot read {dir}: {e}"))?;
        for entry in entries {
            let path = entry.map_err(|e| format!("Cannot read {dir}: {e}"))?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(name) = name.strip_suffix(".json") else {
                continue;
            };
            let text = fs::read_to_string(&path)
                .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
            files.insert(name.to_string(), text);
        }

        let mut errors = Vec::new();
        let names: BTreeSet<&String> = self.samples.keys().chain(files.keys()).collect();
        for name in names {
            match (self.samples.get(name), files.get(name)) {
                (Some(_), None) => errors.push(format!("Sample {name} has no file.")),
                (None, Some(_)) => errors.push(format!("File {name}.json has no sample.")),
                (Some(text), Some(file)) if file != &format!("{text}\n") => errors.push(format!(
                    "Sample {name} differs from {name}.json.\nFile:\n{file}\nSample:\n{text}"
                )),
                _ => {},
            }
        }
        if errors.is_empty() {
            return Ok(());
        }
        Err(format!(
            "The schema changed without a version bump. Snapshot {dir} is never \
             replaced. Bump the schema version to write a new snapshot.\n\n{}",
            errors.join("\n\n")
        ))
    }

    /// Fail the test unless the samples equal the files. A missing directory
    /// is written first and the test still fails, so a new snapshot is
    /// checked before it is committed.
    pub(crate) fn check(&self) {
        match self.write_if_missing() {
            Ok(true) => panic!(
                "Wrote the new schema snapshot {}. Check the files and commit them.",
                self.dir.display()
            ),
            Ok(false) => {},
            Err(e) => panic!("{e}"),
        }
        if let Err(e) = self.compare() {
            panic!("{e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use tempfile::TempDir;

    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Strict {
        name: String,
        inner: Vec<Inner>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Inner {
        size: u32,
    }

    #[derive(Serialize, Deserialize)]
    struct Loose {
        name: String,
    }

    fn sample(name: &str) -> Strict {
        Strict {
            name: name.to_string(),
            inner: vec![Inner { size: 1 }],
        }
    }

    fn snapshot(root: &Path, version: u32, name: &str) -> SchemaSnapshot {
        let mut snapshot = SchemaSnapshot::in_dir(root, "test", version);
        snapshot.add("strict", &sample(name), &[]);
        snapshot
    }

    #[test]
    fn missing_snapshot_fails_and_written_once() {
        let root = TempDir::new().unwrap();
        assert!(snapshot(root.path(), 1, "a").compare().is_err());

        assert!(snapshot(root.path(), 1, "a").write_if_missing().unwrap());

        let file = fs::read_to_string(root.path().join("test-1/strict.json")).unwrap();
        let text = serde_json::to_string_pretty(&sample("a")).unwrap();
        assert_eq!(file, format!("{text}\n"));
        assert!(snapshot(root.path(), 1, "a").compare().is_ok());
        assert!(!snapshot(root.path(), 1, "b").write_if_missing().unwrap());
    }

    #[test]
    #[should_panic(expected = "Wrote the new schema snapshot")]
    fn check_of_missing_snapshot_fails() {
        let root = TempDir::new().unwrap();
        snapshot(root.path(), 1, "a").check();
    }

    #[test]
    fn changed_sample_without_version_bump_fails_and_file_kept() {
        let root = TempDir::new().unwrap();
        snapshot(root.path(), 1, "a").write_if_missing().unwrap();
        let path = root.path().join("test-1/strict.json");
        let before = fs::read_to_string(&path).unwrap();

        let changed = snapshot(root.path(), 1, "b");
        assert!(!changed.write_if_missing().unwrap());
        let error = changed.compare().unwrap_err();

        assert!(error.contains("without a version bump"), "{error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn version_bump_writes_new_snapshot_beside_older_one() {
        let root = TempDir::new().unwrap();
        snapshot(root.path(), 1, "a").write_if_missing().unwrap();

        assert!(snapshot(root.path(), 2, "b").write_if_missing().unwrap());

        assert!(snapshot(root.path(), 1, "a").compare().is_ok());
        assert!(snapshot(root.path(), 2, "b").compare().is_ok());
    }

    #[test]
    fn missing_and_extra_files_fail() {
        let root = TempDir::new().unwrap();
        snapshot(root.path(), 1, "a").write_if_missing().unwrap();

        let mut more = snapshot(root.path(), 1, "a");
        more.add("other", &sample("c"), &[]);
        let error = more.compare().unwrap_err();
        assert!(error.contains("Sample other has no file"), "{error}");

        let fewer = SchemaSnapshot::in_dir(root.path(), "test", 1);
        let error = fewer.compare().unwrap_err();
        assert!(error.contains("File strict.json has no sample"), "{error}");
    }

    #[test]
    #[should_panic(expected = "parses with an unknown field at \"\"")]
    fn struct_that_accepts_unknown_fields_refused() {
        let root = TempDir::new().unwrap();
        let mut snapshot = SchemaSnapshot::in_dir(root.path(), "test", 1);
        let loose = Loose {
            name: "a".to_string(),
        };
        snapshot.add("loose", &loose, &[]);
    }

    #[test]
    fn unknown_field_checked_in_nested_objects_except_open_keys() {
        let json = serde_json::json!({
            "a": {"b": [{"c": 1}]},
            "kind": {"d": {}},
        });
        let pointers = SchemaSnapshot::object_pointers(&json, &["kind"]);
        assert_eq!(pointers, ["", "/a", "/a/b/0"]);
    }
}
