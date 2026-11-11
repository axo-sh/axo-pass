use super::super::logins::vault_choices;
use super::super::serve::authorize_and_serve_logins;
use super::*;
use crate::core::app_broker::Authorizers;
use crate::core::app_broker::tests::support::StubAuthorizer;

/// Save a login for example.com through the prompt, answered with `answer`.
/// Returns the response, the event the broker recorded, and the login index.
/// The caller holds an audit test dir.
fn save(fx: &Fixture, answer: Option<&str>) -> (WireResponse, AuditEvent, Arc<LoginIndex>) {
    let stub = Arc::new(StubAuthorizer::default());
    let logins = Arc::new(LoginIndex::default());
    logins.replace(Vec::new());
    let authorizers = Authorizers {
        sign: stub.clone(),
        passphrase: stub.clone(),
        keychain: stub,
        vault: Arc::new(Approver {
            approve: true,
            save_vault: answer.map(String::from),
        }),
        logins: logins.clone(),
        vaults: fx.vaults.clone(),
    };
    let choices = vault_choices(&fx.vaults);
    let page = LoginPage::parse(
        "https://example.com/login",
        "https://example.com/login",
        None,
    )
    .unwrap();
    let prompt = prompt(
        &choices.default_vault.clone(),
        VaultAction::SaveLogin {
            page,
            username: Some("ada".to_string()),
            choices,
        },
    );
    let response = fx.rt.block_on(authorize_and_serve_logins(
        &authorizers,
        prompt,
        Actor::default(),
        Some(VaultPayload::SaveLogin(SaveLoginPayload {
            password: SecretString::from("pw"),
        })),
        &InFlightRequest::default(),
    ));
    let event = audit::read(&audit::AuditFilter {
        limit: Some(1),
        ..Default::default()
    })
    .events
    .remove(0);
    (response, event, logins)
}

/// Fail with the broker's message if `response` is not a saved login.
fn assert_saved(response: &WireResponse) {
    match response {
        WireResponse::LoginSaved { .. } => {},
        WireResponse::Failed { message } => panic!("the save failed: {message}"),
        _ => panic!("unexpected response to a save"),
    }
}

/// Logins in `vault_key` on disk.
fn saved_logins(fx: &Fixture, vault_key: &str) -> Vec<autofill::AutofillItem> {
    autofill::collect_items(&fx.read(vault_key), None).unwrap()
}

/// Vault id in the record id of each login indexed for example.com.
fn indexed_vault_ids(index: &LoginIndex) -> Vec<uuid::Uuid> {
    index
        .lookup("https://example.com/login")
        .unwrap()
        .iter()
        .map(|login| autofill::parse_record_id(&login.record_id).unwrap().0)
        .collect()
}

#[test]
fn choices_offer_every_vault_with_write_vault_as_default() {
    let fx = Fixture::new();
    let choices = vault_choices(&fx.vaults);
    let keys: Vec<&str> = choices.vaults.iter().map(|v| v.key.as_str()).collect();
    assert_eq!(keys, ["personal", "shared"]);
    // There is no `default` vault, so the first vault is the default.
    assert_eq!(choices.default_vault, "personal");
}

#[test]
fn save_writes_to_chosen_vault() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let (response, event, index) = save(&fx, Some("shared"));
    assert_saved(&response);

    assert!(saved_logins(&fx, "personal").is_empty());
    let saved = saved_logins(&fx, "shared");
    assert_eq!(saved.len(), 1);

    let shared_id = fx.read("shared").vault_id().unwrap();
    assert_eq!(event.action, Action::ItemCreated);
    assert_eq!(event.outcome, Outcome::Succeeded);
    assert_eq!(event.detail["vault"], "shared");
    assert_eq!(recorded_ids(&event).vault_id, Some(shared_id));
    assert_eq!(indexed_vault_ids(&index), [shared_id]);
}

#[test]
fn save_refuses_vault_not_offered() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let (response, event, index) = save(&fx, Some("elsewhere"));
    let WireResponse::Failed { message } = &response else {
        panic!("the save was not refused");
    };
    assert!(message.contains("not offered"), "{message}");

    assert!(saved_logins(&fx, "personal").is_empty());
    assert!(saved_logins(&fx, "shared").is_empty());
    assert_eq!(event.outcome, Outcome::Failed);
    assert!(indexed_vault_ids(&index).is_empty());
}

#[test]
fn save_with_no_answer_goes_to_default_vault() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let (response, event, index) = save(&fx, None);
    assert_saved(&response);

    assert_eq!(saved_logins(&fx, "personal").len(), 1);
    assert!(saved_logins(&fx, "shared").is_empty());

    let personal_id = fx.read("personal").vault_id().unwrap();
    assert_eq!(event.detail["vault"], "personal");
    assert_eq!(recorded_ids(&event).vault_id, Some(personal_id));
    assert_eq!(indexed_vault_ids(&index), [personal_id]);
}
