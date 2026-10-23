use std::collections::{BTreeMap, HashMap};
use std::thread;

use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

use super::*;
use crate::secrets::vaults::FieldKind;
use crate::secrets::vaults::test_unlocker::KeyUnlocker;
use crate::secrets::vaults::vault_txn::VaultWriter;

/// Vault `personal` in the vaults directory and external vault `shared` in
/// another directory, served through a [`VaultCatalog`] that unlocks with the
/// file keys instead of the keychain.
struct Fixture {
    _dir: TempDir,
    vaults: VaultCatalog,
    /// Vaults as created, unlocked, by key. Their file keys open the files.
    originals: HashMap<String, VaultHandle>,
    rt: tokio::runtime::Runtime,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vaults_dir = dir.path().join("vaults");
        let files = VaultWriter::isolated(dir.path().join("data"));
        let personal = VaultHandle::new_for_test_at(vaults_dir.join("personal.json"));
        let shared_path = dir.path().join("elsewhere").join("shared.json");
        let shared = VaultHandle::new_for_test_at(shared_path.clone());

        let mut keys = HashMap::new();
        for vw in [&personal, &shared] {
            files.create(vw).unwrap();
            keys.insert(vw.vault_id().unwrap(), vw.unlocked_key().unwrap());
        }
        let external = BTreeMap::from([("shared".to_string(), shared_path)]);
        Self {
            _dir: dir,
            vaults: VaultCatalog::with_unlocker(
                vaults_dir,
                files,
                external,
                Arc::new(KeyUnlocker(keys)),
            ),
            originals: HashMap::from([
                ("personal".to_string(), personal),
                ("shared".to_string(), shared),
            ]),
            rt: tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
        }
    }

    /// Serve `action` on `vault_key` as the broker does once the user has
    /// approved the prompt.
    fn serve(
        &self,
        vault_key: &str,
        action: VaultAction,
        payload: Option<VaultPayload>,
    ) -> Result<WireResponse, String> {
        serve_on_context(
            &self.vaults,
            prompt(vault_key, action),
            ForeignContext::for_test(),
            payload,
            self.rt.handle().clone(),
            &mut None,
        )
    }

    /// Write `item/cred` through the broker.
    fn broker_write(&self, vault_key: &str, cred: &str, value: &str) {
        let response = self
            .serve(
                vault_key,
                VaultAction::WriteSecret {
                    item_key: "item".to_string(),
                    credential_key: cred.to_string(),
                },
                Some(VaultPayload::Write(WriteSecretPayload {
                    title: cred.to_string(),
                    value: SecretString::from(value.to_string()),
                    login: None,
                })),
            )
            .unwrap();
        assert!(matches!(response, WireResponse::VaultWritten { .. }));
    }

    /// Run `f` in a transaction on `vault_key`, as an app edit does.
    fn app_write<R>(
        &self,
        vault_key: &str,
        f: impl FnOnce(&mut VaultHandle) -> Result<R, crate::secrets::vaults::Error>,
    ) -> R {
        self.vaults
            .files()
            .write_unlocked(&self.originals[vault_key], f)
            .unwrap()
            .value
    }

    /// Write `item/cred` as an app edit.
    fn app_add(&self, vault_key: &str, cred: &str, value: &str) {
        self.app_write(vault_key, |vw| {
            vw.add_item("item", "Item")?;
            vw.add_secret(
                "item",
                cred,
                cred,
                FieldKind::default(),
                SecretString::from(value.to_string()),
            )
        });
    }

    /// The vault as it is on disk now, unlocked.
    fn read(&self, vault_key: &str) -> VaultHandle {
        let mut vw = self.vaults.load(vault_key).unwrap();
        self.vaults.unlock(&mut vw, AuthContext::OneTime).unwrap();
        vw
    }

    fn value(&self, vault_key: &str, cred: &str) -> Option<String> {
        self.read(vault_key)
            .get_secret("item", cred)
            .unwrap()
            .map(|s| s.expose_secret().to_string())
    }
}

fn prompt(vault_key: &str, action: VaultAction) -> VaultAccessPrompt {
    VaultAccessPrompt {
        vault_key: vault_key.to_string(),
        caller: None,
        caller_chain: Vec::new(),
        client: ClientIdentity::Process,
        action,
    }
}

#[test]
fn a_broker_write_and_an_app_write_to_one_vault_both_land() {
    let fx = Fixture::new();
    thread::scope(|s| {
        for i in 0..4 {
            let fx = &fx;
            s.spawn(move || fx.broker_write("personal", &format!("broker-{i}"), "b"));
            s.spawn(move || fx.app_add("personal", &format!("app-{i}"), "a"));
        }
    });
    for i in 0..4 {
        assert_eq!(
            fx.value("personal", &format!("broker-{i}")).as_deref(),
            Some("b")
        );
        assert_eq!(
            fx.value("personal", &format!("app-{i}")).as_deref(),
            Some("a")
        );
    }
}

#[test]
fn a_broker_read_and_write_reach_an_external_vault() {
    let fx = Fixture::new();
    fx.broker_write("shared", "token", "secret");

    let read = fx
        .serve(
            "shared",
            VaultAction::ReadSecret {
                item_key: "item".to_string(),
                credential_key: "token".to_string(),
            },
            None,
        )
        .unwrap();
    assert!(matches!(
        read,
        WireResponse::VaultSecret { value: Some(ref v) } if v == "secret"
    ));

    let resolved = fx
        .serve(
            "shared",
            VaultAction::ResolveSecrets {
                purpose: ResolvePurpose::Read,
                refs: vec![VaultRef {
                    vault_key: "shared".to_string(),
                    item_key: "item".to_string(),
                    credential_key: "token".to_string(),
                }],
            },
            None,
        )
        .unwrap();
    assert!(matches!(
        resolved,
        WireResponse::ResolvedSecrets { ref values } if values == &[Some("secret".to_string())]
    ));

    // The write landed in the external file, not in the vaults directory.
    assert_eq!(fx.value("shared", "token").as_deref(), Some("secret"));
    assert!(!fx.vaults.vaults_dir().join("shared.json").exists());
}

#[test]
fn an_app_edit_made_during_an_update_confirmation_is_kept() {
    let fx = Fixture::new();
    let page = LoginPage::parse(
        "https://example.com/login",
        "https://example.com/login",
        None,
    )
    .unwrap();
    let item = fx.app_write("personal", |vw| {
        autofill::save_login(
            vw,
            &page.frame_origin,
            Some("tp"),
            SecretString::from("old"),
        )
    });

    let served = update_login_password(
        &fx.vaults,
        &page,
        &item.record_id,
        UpdateLoginPayload {
            password: SecretString::from("new"),
        },
        ForeignContext::for_test(),
    )
    .unwrap();
    // The app saves an edit while the confirmation is shown.
    fx.app_add("personal", "note", "kept");
    let commit = served
        .commit
        .expect("an update commits after the confirmation");
    commit().unwrap();

    assert_eq!(fx.value("personal", "note").as_deref(), Some("kept"));
    let vw = fx.read("personal");
    let found = autofill::find_login_record(&vw, &item.record_id)
        .unwrap()
        .unwrap();
    let secrets = autofill::read_login(&vw, &found).unwrap().unwrap();
    assert_eq!(secrets.password.expose_secret(), "new");
}
