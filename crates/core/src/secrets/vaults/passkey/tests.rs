use std::sync::{Arc, Mutex};

use super::*;
use crate::audit::{self, AuditEvent};

mod history;
mod last_used;
mod moves;
mod prf;
mod record;
mod targets;

/// Keeps whatever the authenticator saves, so a test can inspect a real
/// credential without needing a vault on disk.
#[derive(Clone, Default)]
struct CapturingStore(Arc<Mutex<Option<Passkey>>>);

#[async_trait]
impl CredentialStore for CapturingStore {
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        _ids: Option<&[PublicKeyCredentialDescriptor]>,
        _rp_id: &str,
        _user_handle: Option<&[u8]>,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        match self.0.lock().unwrap().clone() {
            Some(passkey) => Ok(vec![passkey]),
            None => Err(Ctap2Error::NoCredentials.into()),
        }
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        _user: PublicKeyCredentialUserEntity,
        _rp: PublicKeyCredentialRpEntity,
        _options: passkey_types::ctap2::get_assertion::Options,
    ) -> Result<(), StatusCode> {
        *self.0.lock().unwrap() = Some(cred);
        Ok(())
    }

    async fn update_credential(&mut self, cred: &Self::PasskeyItem) -> Result<(), StatusCode> {
        *self.0.lock().unwrap() = Some(cred.clone());
        Ok(())
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::Full,
        }
    }
}

/// Build a real passkey by running a registration, so the record under test
/// carries a genuine COSE key rather than a hand-made one.
async fn sample_passkey() -> Passkey {
    let store = CapturingStore::default();
    let mut authenticator = Authenticator::new(AAGUID, store.clone(), PromptedUser);
    let request = make_credential::Request {
        client_data_hash: vec![0u8; 32].into(),
        rp: PublicKeyCredentialRpEntity {
            id: "example.com".into(),
            name: Some("Example".into()),
        },
        user: passkey_types::webauthn::PublicKeyCredentialUserEntity {
            id: vec![1, 2, 3, 4].into(),
            name: "ada".into(),
            display_name: "Ada Lovelace".into(),
        },
        pub_key_cred_params: vec![passkey_types::webauthn::PublicKeyCredentialParameters {
            ty: passkey_types::webauthn::PublicKeyCredentialType::PublicKey,
            alg: coset::iana::Algorithm::ES256,
        }],
        exclude_list: None,
        extensions: None,
        options: passkey_types::ctap2::get_assertion::Options {
            rk: true,
            up: true,
            uv: true,
        },
        pin_auth: None,
        pin_protocol: None,
    };
    authenticator.make_credential(request).await.unwrap();
    let passkey = store.0.lock().unwrap().clone();
    passkey.expect("registration should have saved a credential")
}

fn registration(rp_id: &str, user: &str) -> make_credential::Request {
    make_credential::Request {
        client_data_hash: vec![0u8; 32].into(),
        rp: PublicKeyCredentialRpEntity {
            id: rp_id.into(),
            name: Some("Example".into()),
        },
        user: WebauthnUserEntity {
            id: vec![1, 2, 3, 4].into(),
            name: user.into(),
            display_name: user.into(),
        },
        pub_key_cred_params: vec![PublicKeyCredentialParameters {
            ty: PublicKeyCredentialType::PublicKey,
            alg: coset::iana::Algorithm::ES256,
        }],
        exclude_list: None,
        extensions: None,
        options: get_assertion::Options {
            rk: true,
            up: true,
            uv: true,
        },
        pin_auth: None,
        pin_protocol: None,
    }
}

/// Register without saving, since a test vault has no path to write to.
async fn register(vw: &mut VaultHandle, target: PasskeyTarget, user: &str) {
    let mut authenticator = Authenticator::new(
        AAGUID,
        PasskeyCredentialStore::new(vw, target),
        PromptedUser,
    );
    authenticator
        .make_credential(registration("example.com", user))
        .await
        .unwrap();
}

/// Vault `personal` with a passkey of `user` registered in a new login.
async fn registered_vault(user: &str) -> VaultHandle {
    let mut vw = VaultHandle::new_for_test("personal");
    register(&mut vw, PasskeyTarget::NewLogin, user).await;
    vw
}

/// Last used times ten days apart, so they fall on different dates in
/// every zone.
const EARLIER_USE: i64 = 1_750_000_000;
const LATER_USE: i64 = EARLIER_USE + 10 * 86_400;

fn last_used_at(vw: &VaultHandle, item_key: &str, credential_key: &str) -> Option<i64> {
    vw.get_secret_overview(item_key, credential_key)
        .unwrap()
        .unwrap()
        .last_used_day_at
}

/// `passkey_credential_id` that a move of `stored` records.
fn recorded_id(vw: &VaultHandle, stored: &PasskeyCredential) -> String {
    let id = webauthn_credential_id(vw, &stored.item_key, &stored.credential_key).unwrap();
    AuditEvent::new(
        audit::process_source(),
        audit::Action::PasskeyMoved,
        audit::Outcome::Succeeded,
    )
    .passkey_credential_id(&id)
    .detail
    .remove(audit::PASSKEY_CREDENTIAL_ID)
    .unwrap()
}

/// WebAuthn credential id in the stored record of the passkey `ids` name.
fn stored_id(vw: &VaultHandle, ids: SubjectIds) -> String {
    let stored = list(vw)
        .unwrap()
        .into_iter()
        .find(|s| Some(s.credential_id) == ids.credential_id)
        .unwrap();
    let value = vw
        .get_secret(&stored.item_key, &stored.credential_key)
        .unwrap()
        .unwrap();
    summary(value.expose_secret()).unwrap().credential_id
}

/// Passkey of `vw` whose account is `username`.
fn passkey_of(vw: &VaultHandle, username: &str) -> PasskeyCredential {
    list(vw)
        .unwrap()
        .into_iter()
        .find(|s| s.passkey.username.as_deref() == Some(username))
        .unwrap()
}
