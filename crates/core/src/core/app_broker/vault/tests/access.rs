use super::*;

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
