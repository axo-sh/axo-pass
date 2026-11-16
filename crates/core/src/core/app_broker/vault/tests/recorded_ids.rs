use super::*;

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
            details: None,
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
                choices: Default::default(),
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
            &Approver {
                approve: true,
                save_vault: None,
            },
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
