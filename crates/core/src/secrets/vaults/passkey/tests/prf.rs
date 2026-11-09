use super::*;

#[tokio::test]
async fn assertion_leaves_stored_record_unchanged() {
    let mut vw = VaultHandle::new_for_test("personal");
    register(&mut vw, PasskeyTarget::NewLogin, "ada").await;
    let before = list(&vw).unwrap();
    let item_key = before[0].item_key.clone();
    let credential_key = before[0].credential_key.clone();
    let stored = |vw: &VaultHandle| {
        vw.get_secret(&item_key, &credential_key)
            .unwrap()
            .unwrap()
            .expose_secret()
            .clone()
    };
    let record = stored(&vw);

    for _ in 0..2 {
        let response = assert(
            &mut vw,
            get_assertion::Request {
                rp_id: "example.com".into(),
                client_data_hash: vec![7u8; 32].into(),
                allow_list: None,
                extensions: None,
                options: get_assertion::Options {
                    rk: true,
                    up: true,
                    uv: true,
                },
                pin_auth: None,
                pin_protocol: None,
            },
        )
        .await
        .unwrap();
        // The counter is the four bytes after the 32 byte rp id hash and the
        // flags byte.
        assert_eq!(&response.auth_data.to_vec()[33..37], &[0, 0, 0, 0]);
    }
    assert_eq!(stored(&vw), record);
}

/// Flags the app shows in the passkey details. Sites see every passkey as
/// user present, user verified, backup eligible, and backed up.
#[tokio::test]
async fn registrations_and_assertions_report_synced_verified_flags() {
    use passkey_types::ctap2::Flags;

    let mut vw = VaultHandle::new_for_test("personal");
    let mut authenticator = Authenticator::new(
        AAGUID,
        PasskeyCredentialStore::new(&mut vw, PasskeyTarget::NewLogin),
        PromptedUser,
    );
    let created = authenticator
        .make_credential(registration("example.com", "ada"))
        .await
        .unwrap();
    assert_eq!(created.fmt, "none");
    assert_eq!(
        created.auth_data.flags,
        Flags::UP | Flags::UV | Flags::BE | Flags::BS | Flags::AT
    );

    let asserted = assert(
        &mut vw,
        get_assertion::Request {
            rp_id: "example.com".into(),
            client_data_hash: vec![7u8; 32].into(),
            allow_list: None,
            extensions: None,
            options: get_assertion::Options {
                rk: true,
                up: true,
                uv: true,
            },
            pin_auth: None,
            pin_protocol: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        asserted.auth_data.flags,
        Flags::UP | Flags::UV | Flags::BE | Flags::BS
    );
}

fn prf_assertion(prf: Option<PrfAssertionInput>) -> get_assertion::Request {
    get_assertion::Request {
        rp_id: "example.com".into(),
        client_data_hash: vec![7u8; 32].into(),
        allow_list: None,
        extensions: prf.as_ref().map(PrfAssertionInput::to_ctap),
        options: get_assertion::Options {
            rk: true,
            up: true,
            uv: true,
        },
        pin_auth: None,
        pin_protocol: None,
    }
}

fn prf_output(response: get_assertion::Response) -> Option<PrfValues> {
    response
        .unsigned_extension_outputs
        .and_then(|o| o.prf)
        .map(|o| prf_results(o.results))
}

#[test]
fn prf_salts_hashed_with_webauthn_context() {
    let mut data = b"WebAuthn PRF\0".to_vec();
    data.extend_from_slice(b"hello");
    assert_eq!(prf_salt(b"hello"), passkey_types::crypto::sha256(&data));
}

#[tokio::test]
async fn prf_results_are_stable_and_match_registration() {
    let mut vw = VaultHandle::new_for_test("personal");
    let eval = PrfValues {
        first: b"first input".to_vec(),
        second: Some(b"second input".to_vec()),
    };
    let mut request = registration("example.com", "ada");
    request.extensions = Some(
        PrfRegistrationInput {
            eval: Some(eval.clone()),
        }
        .to_ctap(),
    );
    let created = authenticator(PasskeyCredentialStore::new(
        &mut vw,
        PasskeyTarget::NewLogin,
    ))
    .make_credential(request)
    .await
    .unwrap();
    let made = created
        .unsigned_extension_outputs
        .and_then(|o| o.prf)
        .unwrap();
    assert!(made.enabled);
    let at_registration = prf_results(made.results.unwrap());
    assert_eq!(at_registration.first.len(), 32);

    let input = PrfAssertionInput {
        eval: Some(eval),
        eval_by_credential: Vec::new(),
    };
    let first = prf_output(
        assert(&mut vw, prf_assertion(Some(input.clone())))
            .await
            .unwrap(),
    );
    let second = prf_output(assert(&mut vw, prf_assertion(Some(input))).await.unwrap());
    assert_eq!(first.as_ref(), Some(&at_registration));
    assert_eq!(first, second);

    let other = prf_output(
        assert(
            &mut vw,
            prf_assertion(Some(PrfAssertionInput {
                eval: Some(PrfValues {
                    first: b"other".to_vec(),
                    second: None,
                }),
                eval_by_credential: Vec::new(),
            })),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_ne!(other.first, at_registration.first);
    assert_eq!(other.second, None);

    // The secret is in the stored record, so it survives a reload.
    let stored = list(&vw).unwrap().remove(0);
    let value = vw
        .get_secret(&stored.item_key, &stored.credential_key)
        .unwrap()
        .unwrap();
    assert!(summary(value.expose_secret()).unwrap().prf);
}

#[tokio::test]
async fn per_credential_prf_input_takes_precedence() {
    let mut vw = VaultHandle::new_for_test("personal");
    let mut request = registration("example.com", "ada");
    request.extensions = Some(make_credential::ExtensionInputs {
        hmac_secret: Some(true),
        ..Default::default()
    });
    authenticator(PasskeyCredentialStore::new(
        &mut vw,
        PasskeyTarget::NewLogin,
    ))
    .make_credential(request)
    .await
    .unwrap();
    let credential_id = list(&vw).unwrap()[0].passkey.credential_id.to_vec();

    let specific = PrfValues {
        first: b"specific".to_vec(),
        second: None,
    };
    let by_credential = prf_output(
        assert(
            &mut vw,
            prf_assertion(Some(PrfAssertionInput {
                eval: Some(PrfValues {
                    first: b"general".to_vec(),
                    second: None,
                }),
                eval_by_credential: vec![(credential_id, specific.clone())],
            })),
        )
        .await
        .unwrap(),
    );
    let direct = prf_output(
        assert(
            &mut vw,
            prf_assertion(Some(PrfAssertionInput {
                eval: Some(specific),
                eval_by_credential: Vec::new(),
            })),
        )
        .await
        .unwrap(),
    );
    assert!(by_credential.is_some());
    assert_eq!(by_credential, direct);
}

#[tokio::test]
async fn passkey_without_prf_secret_returns_no_prf_results() {
    let mut vw = VaultHandle::new_for_test("personal");
    // Registered without PRF, as passkeys were before PRF support.
    register(&mut vw, PasskeyTarget::NewLogin, "ada").await;
    let stored = list(&vw).unwrap().remove(0);
    let value = vw
        .get_secret(&stored.item_key, &stored.credential_key)
        .unwrap()
        .unwrap();
    assert!(!summary(value.expose_secret()).unwrap().prf);

    let response = assert(
        &mut vw,
        prf_assertion(Some(PrfAssertionInput {
            eval: Some(PrfValues {
                first: b"input".to_vec(),
                second: None,
            }),
            eval_by_credential: Vec::new(),
        })),
    )
    .await
    .unwrap();
    assert_eq!(prf_output(response), None);
}
