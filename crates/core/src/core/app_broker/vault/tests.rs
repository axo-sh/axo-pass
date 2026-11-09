use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, thread};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

use super::super::PromptOutcome;
use super::super::in_flight::InFlightRequest;
use super::super::login_index::LoginIndex;
use super::super::placement::PasskeyChoices;
use super::super::wire::{WireImportIdentity, WireImportSelection, WireResponse};
use super::audit::access_event;
use super::logins::{save_login, serve_logins, update_login_password};
use super::passkeys::record_passkey_report;
use super::serve::{AccessIds, Served, authorize_and_serve, serve_on_context};
use super::{
    AssertPasskeyPayload, ClientIdentity, CreatePasskeyPayload, ExportPayload, ImportPayload,
    LoginPage, ResolvePurpose, SaveLoginPayload, UpdateLoginPayload, VaultAccessPrompt,
    VaultAction, VaultAuthorizer, VaultPayload, VaultRef, WriteSecretPayload,
};
use crate::audit::test_support::test_dir;
use crate::audit::{self, Action, Actor, AuditEvent, Outcome, PASSKEY_CREDENTIAL_ID, SubjectIds};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::secrets::vaults::bundle::{ExportMode, ImportAction};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::passkey::signals::Report;
use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;
use crate::secrets::vaults::storage::txn::VaultWriter;
use crate::secrets::vaults::{FieldKind, MatchKind, VaultCatalog, VaultHandle, autofill, passkey};

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
        let external = vec![shared_path];
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
    ) -> Result<Served, String> {
        serve_on_context(
            &self.vaults,
            prompt(vault_key, action),
            ForeignContext::for_test(),
            payload,
            self.rt.handle().clone(),
            &mut None,
        )
    }

    /// Serve `action` on `vault_key` and return the event the broker records
    /// for it.
    fn serve_event(
        &self,
        vault_key: &str,
        action: VaultAction,
        payload: Option<VaultPayload>,
    ) -> AuditEvent {
        let served = self.serve(vault_key, action.clone(), payload).unwrap();
        access_event(
            &prompt(vault_key, action),
            &Actor::default(),
            Outcome::Succeeded,
            Some(&served.response),
            &served.ids,
            None,
        )
    }

    /// Run `action` through the prompt and the serve step, as the broker does
    /// for a request, and return the event it recorded. The prompt is
    /// approved if `approve` is set. The caller holds an audit test dir.
    fn serve_recorded(
        &self,
        approve: bool,
        vault_key: &str,
        action: VaultAction,
        payload: Option<VaultPayload>,
    ) -> AuditEvent {
        self.rt.block_on(authorize_and_serve(
            &Approver { approve },
            &self.vaults,
            prompt(vault_key, action),
            Actor::default(),
            payload,
            &InFlightRequest::default(),
        ));
        audit::read(&audit::AuditFilter {
            limit: Some(1),
            ..Default::default()
        })
        .events
        .remove(0)
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
            .unwrap()
            .response;
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

/// Approves every prompt if `approve` is set, and declines it otherwise.
struct Approver {
    approve: bool,
}

#[async_trait]
impl VaultAuthorizer for Approver {
    async fn begin(
        &self,
        _prompt: VaultAccessPrompt,
        _peer: Actor,
    ) -> Result<ForeignContext, String> {
        if self.approve {
            Ok(ForeignContext::for_test())
        } else {
            Err("Declined".to_string())
        }
    }

    async fn abandon(&self) {}

    async fn end(&self, _prompt: VaultAccessPrompt, _outcome: PromptOutcome) {}
}

/// Ids an event records under `vault_id`, `item_id`, and `credential_id`.
fn recorded_ids(event: &AuditEvent) -> SubjectIds {
    let id = |key: &str| {
        event
            .detail
            .get(key)
            .map(|value| ShortId::parse_uuid(value).unwrap())
    };
    SubjectIds {
        vault_id: id("vault_id"),
        item_id: id("item_id"),
        credential_id: id("credential_id"),
    }
}

fn read_token() -> VaultAction {
    VaultAction::ReadSecret {
        item_key: "item".to_string(),
        credential_key: "token".to_string(),
    }
}

fn token_ref(vault_key: &str, cred: &str) -> VaultRef {
    VaultRef {
        vault_key: vault_key.to_string(),
        item_key: "item".to_string(),
        credential_key: cred.to_string(),
    }
}

fn example_page() -> LoginPage {
    LoginPage::parse(
        "https://example.com/login",
        "https://example.com/login",
        None,
    )
    .unwrap()
}

/// Request data of a passkey sign-in on `example.com`.
fn assertion() -> (VaultAction, VaultPayload) {
    let action = VaultAction::AssertPasskey {
        rp_id: "example.com".to_string(),
        user_name: None,
    };
    let payload = VaultPayload::AssertPasskey(AssertPasskeyPayload {
        request: passkey::AssertPasskeyRequest {
            rp_id: "example.com".to_string(),
            client_data_hash: vec![0; 32],
            allowed_credentials: Vec::new(),
            prf: None,
        },
        choose_account: false,
        vault_key: None,
    });
    (action, payload)
}

#[test]
fn broker_write_and_app_write_to_one_vault_both_land() {
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
fn broker_read_and_write_reach_external_vault() {
    let fx = Fixture::new();
    fx.broker_write("shared", "token", "secret");

    let read = fx.serve("shared", read_token(), None).unwrap().response;
    assert!(matches!(
        read,
        WireResponse::VaultSecret { value: Some(ref v) } if v == "secret"
    ));

    let resolved = fx
        .serve(
            "shared",
            VaultAction::ResolveSecrets {
                purpose: ResolvePurpose::Read,
                refs: vec![token_ref("shared", "token")],
            },
            None,
        )
        .unwrap()
        .response;
    assert!(matches!(
        resolved,
        WireResponse::ResolvedSecrets { ref values } if values == &[Some("secret".to_string())]
    ));

    // The write landed in the external file, not in the vaults directory.
    assert_eq!(fx.value("shared", "token").as_deref(), Some("secret"));
    assert!(!fx.vaults.vaults_dir().join("shared.json").exists());
}

#[test]
fn app_edit_made_during_update_confirmation_kept() {
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

#[test]
fn denied_prompt_records_no_ids_and_approved_read_records_its_credential() {
    let _audit = test_dir();
    let fx = Fixture::new();
    fx.broker_write("personal", "token", "secret");

    let denied = fx.serve_recorded(false, "personal", read_token(), None);
    assert_eq!(denied.action, Action::CredentialRead);
    assert_eq!(denied.outcome, Outcome::Denied);
    assert_eq!(recorded_ids(&denied), SubjectIds::default());

    let read = fx.serve_recorded(true, "personal", read_token(), None);
    assert_eq!(read.outcome, Outcome::Succeeded);
    let token = fx.read("personal").credential_ids("item", "token").unwrap();
    assert!(token.credential_id.is_some());
    assert_eq!(recorded_ids(&read), token);
}

#[test]
fn listing_and_write_record_ids_of_their_subject() {
    let fx = Fixture::new();
    let created = fx.serve_event(
        "personal",
        VaultAction::WriteSecret {
            item_key: "item".to_string(),
            credential_key: "token".to_string(),
        },
        Some(VaultPayload::Write(WriteSecretPayload {
            title: "Token".to_string(),
            value: SecretString::from("secret"),
            login: None,
        })),
    );
    assert_eq!(created.action, Action::ItemCreated);
    let vw = fx.read("personal");
    assert_eq!(
        recorded_ids(&created),
        vw.credential_ids("item", "token").unwrap()
    );

    let listed = fx.serve_event("personal", VaultAction::ListItems, None);
    assert_eq!(
        recorded_ids(&listed),
        SubjectIds::vault(vw.vault_id().unwrap())
    );
}

#[test]
fn resolve_across_vaults_lists_credentials_it_resolved() {
    let fx = Fixture::new();
    fx.broker_write("personal", "token", "a");
    fx.broker_write("shared", "token", "b");

    let event = fx.serve_event(
        "personal, shared",
        VaultAction::ResolveSecrets {
            purpose: ResolvePurpose::Exec,
            refs: vec![
                token_ref("personal", "token"),
                token_ref("shared", "token"),
                token_ref("personal", "missing"),
                token_ref("personal", "token"),
            ],
        },
        None,
    );
    let personal = fx.read("personal").credential_ids("item", "token").unwrap();
    let shared = fx.read("shared").credential_ids("item", "token").unwrap();
    let list =
        |ids: [Option<uuid::Uuid>; 2]| ids.map(|id| ShortId::encode_uuid(id.unwrap())).join(",");
    assert_eq!(
        event.detail["vault_ids"],
        list([personal.vault_id, shared.vault_id])
    );
    assert_eq!(
        event.detail["item_ids"],
        list([personal.item_id, shared.item_id])
    );
    assert_eq!(
        event.detail["credential_ids"],
        list([personal.credential_id, shared.credential_id])
    );
    assert_eq!(recorded_ids(&event), SubjectIds::default());
}

#[test]
fn export_lists_vaults_it_exported() {
    let fx = Fixture::new();
    let dest = fx._dir.path().join("export.axovault");
    let recipient = age::x25519::Identity::generate().to_public().to_string();
    let event = fx.serve_event(
        "personal, shared",
        VaultAction::ExportVaults {
            vault_keys: vec!["personal".to_string(), "shared".to_string()],
        },
        Some(VaultPayload::Export(ExportPayload {
            dest_path: dest,
            mode: ExportMode::Recipient(recipient),
            include_passkeys: false,
        })),
    );
    let id = |key: &str| ShortId::encode_uuid(fx.originals[key].vault_id().unwrap());
    assert_eq!(
        event.detail["vault_ids"],
        format!("{},{}", id("personal"), id("shared"))
    );
}

/// Export `personal` and `shared` through the broker, then remove the
/// `shared` file, so the bundle holds one id that exists on this Mac and one
/// that does not. Returns the bundle path and the identity that opens it.
fn export_then_remove_shared(fx: &Fixture) -> (PathBuf, WireImportIdentity) {
    let path = fx._dir.path().join("export.axovault");
    let identity = age::x25519::Identity::generate();
    fx.serve(
        "personal, shared",
        VaultAction::ExportVaults {
            vault_keys: vec!["personal".to_string(), "shared".to_string()],
        },
        Some(VaultPayload::Export(ExportPayload {
            dest_path: path.clone(),
            mode: ExportMode::Recipient(identity.to_public().to_string()),
            include_passkeys: true,
        })),
    )
    .unwrap();
    fs::remove_file(&fx.originals["shared"].path).unwrap();
    let identity = WireImportIdentity::Identity {
        identity: identity.to_string().expose_secret().to_string(),
    };
    (path, identity)
}

/// Wire selection of bundle vault `id` as `key` with `action`.
fn selected(id: &str, key: &str, action: ImportAction) -> WireImportSelection {
    WireImportSelection {
        id: id.to_string(),
        key: key.to_string(),
        action,
    }
}

/// Serve an import of `selection` from the bundle at `path`.
fn serve_import(
    fx: &Fixture,
    path: &Path,
    identity: WireImportIdentity,
    selection: Vec<WireImportSelection>,
) -> Result<Served, String> {
    fx.serve(
        "export.axovault",
        VaultAction::ImportVaults {
            count: selection.len(),
        },
        Some(VaultPayload::Import(ImportPayload {
            import_path: path.to_path_buf(),
            identity,
            selection,
        })),
    )
}

#[test]
fn default_import_of_existing_id_writes_nothing_and_names_id() {
    let _audit = test_dir();
    let fx = Fixture::new();
    fx.broker_write("personal", "token", "secret");
    let (path, identity) = export_then_remove_shared(&fx);
    let personal_id = fx.originals["personal"].vault_id().unwrap();
    let shared_id = fx.originals["shared"].vault_id().unwrap();
    let before = fs::read_dir(fx.vaults.vaults_dir()).unwrap().count();

    let error = serve_import(
        &fx,
        &path,
        identity,
        vec![
            selected(
                &ShortId::encode_uuid(personal_id),
                "restored",
                ImportAction::Default,
            ),
            selected(
                &ShortId::encode_uuid(shared_id),
                "shared",
                ImportAction::Default,
            ),
        ],
    )
    .err()
    .expect("import is refused");

    assert!(
        error.contains(&ShortId::encode_uuid(personal_id)),
        "{error}"
    );
    assert!(!error.contains(&ShortId::encode_uuid(shared_id)), "{error}");
    assert_eq!(
        fs::read_dir(fx.vaults.vaults_dir()).unwrap().count(),
        before
    );
}

#[test]
fn broker_import_applies_action_to_existing_id_only() {
    let _audit = test_dir();
    let fx = Fixture::new();
    fx.broker_write("personal", "token", "a");
    fx.broker_write("shared", "token", "b");
    let (path, identity) = export_then_remove_shared(&fx);
    let personal_id = fx.originals["personal"].vault_id().unwrap();
    let shared_id = fx.originals["shared"].vault_id().unwrap();

    // Ids are read in every form.
    let served = serve_import(
        &fx,
        &path,
        identity,
        vec![
            selected(
                &personal_id.hyphenated().to_string().to_uppercase(),
                "personal-copy",
                ImportAction::Copy,
            ),
            selected(
                &shared_id.simple().to_string(),
                "shared",
                ImportAction::Default,
            ),
        ],
    )
    .unwrap();

    let WireResponse::VaultsImported { mut keys } = served.response else {
        panic!("unexpected response");
    };
    keys.sort();
    assert_eq!(keys, ["personal-copy", "shared"]);
    let copy = fx.read("personal-copy");
    assert_ne!(copy.vault_id().unwrap(), personal_id);
    assert_eq!(
        copy.get_secret("item", "token")
            .unwrap()
            .map(|s| s.expose_secret().to_string())
            .as_deref(),
        Some("a")
    );
    assert_eq!(fx.read("shared").vault_id().unwrap(), shared_id);
    assert_eq!(fx.value("shared", "token").as_deref(), Some("b"));
    assert_eq!(fx.read("personal").vault_id().unwrap(), personal_id);
    assert_eq!(fx.value("personal", "token").as_deref(), Some("a"));
}

#[test]
fn login_listing_records_no_ids_and_fill_and_code_record_login() {
    let fx = Fixture::new();
    // The login is in the second vault, so the request unlocks both.
    fx.app_write("shared", |vw| {
        autofill::write_login(
            vw,
            autofill::LoginWrite {
                item_key: "example",
                title: "Example",
                password_key: "password",
                password: SecretString::from("pw"),
                username: Some("ada"),
                websites: &["example.com".to_string()],
                match_kind: MatchKind::Domain,
            },
        )?;
        vw.add_secret(
            "example",
            "code",
            "Code",
            FieldKind::Totp,
            SecretString::from("JBSWY3DPEHPK3PXP"),
        )?;
        autofill::set_role(vw, "example", autofill::Role::Totp, Some("code"))
    });
    let vw = fx.read("shared");
    let password = vw.credential_ids("example", "password").unwrap();
    let code = vw.credential_ids("example", "code").unwrap();
    let record_id = autofill::collect_items(&vw, None).unwrap()[0]
        .record_id
        .clone();

    let ids = |action: VaultAction| {
        serve_logins(
            &fx.vaults,
            &prompt("", action),
            ForeignContext::for_test(),
            None,
            &LoginIndex::default(),
        )
        .unwrap()
        .ids
    };
    assert_eq!(
        ids(VaultAction::ListLogins {
            page: example_page(),
            all: true,
        }),
        AccessIds::None
    );
    assert_eq!(
        ids(VaultAction::FillLogin {
            page: example_page(),
            record_id: record_id.clone(),
            account: None,
            unmatched: false,
        }),
        AccessIds::One(password)
    );
    assert_eq!(
        ids(VaultAction::GenerateTotp {
            page: example_page(),
            record_id,
        }),
        AccessIds::One(code)
    );
}

#[test]
fn saved_login_and_password_update_record_ids_of_login() {
    let fx = Fixture::new();
    let page = example_page();
    let saved = save_login(
        &fx.vaults,
        &prompt(
            "personal",
            VaultAction::SaveLogin {
                page: page.clone(),
                username: Some("ada".to_string()),
            },
        ),
        &page,
        Some("ada"),
        SaveLoginPayload {
            password: SecretString::from("old"),
        },
        ForeignContext::for_test(),
        &LoginIndex::default(),
    )
    .unwrap();
    let vw = fx.read("personal");
    let item = autofill::collect_items(&vw, None).unwrap().remove(0);
    assert_eq!(
        saved.ids,
        AccessIds::One(vw.item_ids(&item.item_key).unwrap())
    );

    let updated = update_login_password(
        &fx.vaults,
        &page,
        &item.record_id,
        UpdateLoginPayload {
            password: SecretString::from("new"),
        },
        ForeignContext::for_test(),
    )
    .unwrap();
    assert_eq!(
        updated.ids,
        AccessIds::One(
            vw.credential_ids(&item.item_key, &item.password_key)
                .unwrap()
        )
    );
}

#[test]
fn assertion_records_signing_passkey() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let (action, payload) = assertion();
    let failed = fx.serve_recorded(true, "", action, Some(payload));
    assert_eq!(failed.outcome, Outcome::Failed);
    assert_eq!(recorded_ids(&failed), SubjectIds::default());

    let created = fx.serve_event(
        "shared",
        VaultAction::CreatePasskey {
            rp_id: "example.com".to_string(),
            user_name: "ada".to_string(),
            choices: PasskeyChoices::default(),
        },
        Some(VaultPayload::CreatePasskey(CreatePasskeyPayload {
            request: passkey::CreatePasskeyRequest {
                rp_id: "example.com".to_string(),
                rp_name: Some("Example".to_string()),
                user_handle: vec![1, 2, 3, 4],
                user_name: "ada".to_string(),
                user_display_name: "Ada".to_string(),
                client_data_hash: vec![0; 32],
                algorithms: Vec::new(),
                excluded_credentials: Vec::new(),
                prf: None,
                target: passkey::PasskeyTarget::NewLogin,
            },
        })),
    );
    let stored = passkey::list(&fx.read("shared")).unwrap().remove(0);
    let ids = SubjectIds::credential(stored.vault_id, stored.item_id, stored.credential_id);
    assert_eq!(recorded_ids(&created), ids);

    // The prompt names no vault. Personal is unlocked first and holds no
    // passkey.
    let (action, payload) = assertion();
    let asserted = fx.serve_recorded(true, "", action, Some(payload));
    assert_eq!(asserted.action, Action::PasskeyAsserted);
    assert_eq!(asserted.outcome, Outcome::Succeeded);
    assert_eq!(recorded_ids(&asserted), ids);
    assert_eq!(asserted.detail["vault"], "shared");
}

#[test]
fn register_and_assert_share_credential_id() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let (action, payload) = assertion();
    let failed = fx.serve_recorded(true, "", action, Some(payload));
    assert_eq!(failed.outcome, Outcome::Failed);
    assert!(!failed.detail.contains_key(PASSKEY_CREDENTIAL_ID));

    let registered = fx.serve_recorded(
        true,
        "shared",
        VaultAction::CreatePasskey {
            rp_id: "example.com".to_string(),
            user_name: "ada".to_string(),
            choices: PasskeyChoices {
                default_vault: "shared".to_string(),
                ..Default::default()
            },
        },
        Some(VaultPayload::CreatePasskey(CreatePasskeyPayload {
            request: passkey::CreatePasskeyRequest {
                rp_id: "example.com".to_string(),
                rp_name: Some("Example".to_string()),
                user_handle: vec![1, 2, 3, 4],
                user_name: "ada".to_string(),
                user_display_name: "Ada".to_string(),
                client_data_hash: vec![0; 32],
                algorithms: Vec::new(),
                excluded_credentials: Vec::new(),
                prf: None,
                target: passkey::PasskeyTarget::NewLogin,
            },
        })),
    );
    assert_eq!(registered.action, Action::PasskeyRegistered);
    assert_eq!(registered.outcome, Outcome::Succeeded);
    let vw = fx.read("shared");
    let stored = passkey::list(&vw).unwrap().remove(0);
    let value = vw
        .get_secret(&stored.item_key, &stored.credential_key)
        .unwrap()
        .unwrap();
    let summary = passkey::summary(value.expose_secret()).unwrap();
    assert_eq!(
        registered.detail[PASSKEY_CREDENTIAL_ID],
        summary.credential_id
    );

    let (action, payload) = assertion();
    let asserted = fx.serve_recorded(true, "", action, Some(payload));
    assert_eq!(asserted.action, Action::PasskeyAsserted);
    assert_eq!(asserted.outcome, Outcome::Succeeded);
    assert_eq!(
        asserted.detail[PASSKEY_CREDENTIAL_ID],
        summary.credential_id
    );
}

#[test]
fn passkey_report_records_passkey_credential_ids_it_names() {
    let _audit = test_dir();
    let fx = Fixture::new();
    // A relying party no other test uses, since pending reports are shared by
    // the process.
    let rp_id = "reports.example".to_string();
    let report = |report: Report| {
        fx.rt.block_on(record_passkey_report(
            &Approver { approve: true },
            report,
            Actor::default(),
        ));
        audit::read(&audit::AuditFilter {
            limit: Some(1),
            ..Default::default()
        })
        .events
        .remove(0)
    };

    let unknown = report(Report::Unknown {
        rp_id: rp_id.clone(),
        credential_id: vec![0xfb, 0xff, 0x01],
    });
    assert_eq!(unknown.action, Action::PasskeyReported);
    assert_eq!(unknown.detail[PASSKEY_CREDENTIAL_ID], "-_8B");

    let accepted = report(Report::AllAccepted {
        rp_id: rp_id.clone(),
        user_handle: vec![1, 2, 3, 4],
        credential_ids: vec![vec![0xfb, 0xff, 0x01], vec![1, 2, 3]],
    });
    assert_eq!(
        accepted.detail[&format!("{PASSKEY_CREDENTIAL_ID}s")],
        "-_8B,AQID"
    );
    assert!(!accepted.detail.contains_key(PASSKEY_CREDENTIAL_ID));

    // A rename names an account, not a passkey.
    let renamed = report(Report::Renamed {
        rp_id,
        user_handle: vec![1, 2, 3, 4],
        name: "ada".to_string(),
    });
    assert!(!renamed.detail.contains_key(PASSKEY_CREDENTIAL_ID));
    assert!(
        !renamed
            .detail
            .contains_key(&format!("{PASSKEY_CREDENTIAL_ID}s"))
    );
}
