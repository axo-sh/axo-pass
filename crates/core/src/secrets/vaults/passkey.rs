//! WebAuthn passkeys stored as vault credentials.
//!
//! The CTAP2 authenticator itself comes from `passkey-authenticator`; this
//! module supplies the two traits it needs. [`VaultStore`] is the
//! `CredentialStore`, backed by an unlocked vault, and [`PromptedUser`] is the
//! `UserValidationMethod`.
//!
//! One passkey is one credential of kind [`FieldKind::Passkey`], whose value is
//! a JSON [`StoredRecord`]: the private key, the credential id, the relying
//! party, and the user handle. It is a secret like any other, so it is
//! encrypted with the rest of the vault and travels in export bundles.
//!
//! The on-disk shape is ours rather than `passkey-types`' own, which is not
//! serde-serializable. Owning it also keeps a version bump in that crate from
//! changing what is already written in people's vaults.
//!
//! User presence and verification are settled before the authenticator runs.
//! The app raises its own Touch ID prompt to unlock the vault for the request,
//! so by the time this code has a decrypted vault the user has already
//! approved; [`PromptedUser`] reports that rather than asking twice.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use coset::{CborSerializable, CoseKey};
use passkey_authenticator::{
    Authenticator, CredentialStore, DiscoverabilitySupport, StoreInfo, UiHint, UserCheck,
    UserValidationMethod,
};
use passkey_types::ctap2::make_credential::{
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
};
use passkey_types::ctap2::{Aaguid, Ctap2Error, StatusCode, get_assertion, make_credential};
use passkey_types::webauthn::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity as WebauthnUserEntity,
};
use passkey_types::{Passkey, Bytes};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{Error, FieldKind, VaultWrapper};

/// Identifies Axo Pass as the authenticator model in attestation data. A fixed
/// random constant, per the WebAuthn spec: it names the model, never the
/// instance, so it carries nothing about the user or this install.
const AAGUID: Aaguid = Aaguid([
    0x9a, 0x0c, 0x4e, 0x7b, 0x2d, 0x51, 0x4f, 0x86, 0xb1, 0x63, 0x5c, 0x8d, 0x74, 0x2e, 0x9f, 0x30,
]);

/// Prefix of the item every passkey is written under. One item per relying
/// party keeps the vault list readable.
const ITEM_KEY_PREFIX: &str = "passkey";

/// Create a passkey in an unlocked vault and return the CTAP2 response. The
/// caller turns `as_webauthn_bytes()` into the attestation object the browser
/// wants.
///
/// The vault is saved before returning, so the credential is durable by the
/// time the relying party sees the attestation.
pub async fn create(
    vw: &mut VaultWrapper,
    request: make_credential::Request,
) -> Result<make_credential::Response, Error> {
    let mut authenticator = Authenticator::new(AAGUID, VaultStore::new(vw), PromptedUser);
    let response = authenticator
        .make_credential(request)
        .await
        .map_err(status_error)?;
    // `save_credential` staged the credential in the in-memory vault; persist
    // it now that the authenticator has finished.
    vw.save()?;
    Ok(response)
}

/// Assert an existing passkey in an unlocked vault.
pub async fn assert(
    vw: &mut VaultWrapper,
    request: get_assertion::Request,
) -> Result<get_assertion::Response, Error> {
    let mut authenticator = Authenticator::new(AAGUID, VaultStore::new(vw), PromptedUser);
    let response = authenticator
        .get_assertion(request)
        .await
        .map_err(status_error)?;
    // An assertion bumps the signature counter, which `update_credential` wrote
    // back into the vault.
    vw.save()?;
    Ok(response)
}

/// A passkey with the vault coordinates it was read from.
#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub item_key: String,
    pub credential_key: String,
    pub passkey: Passkey,
}

/// List the passkeys in an unlocked vault, for the UI and for registering
/// AutoFill identities. A record this build cannot read is logged and skipped
/// rather than failing the listing.
pub fn list(vw: &VaultWrapper) -> Result<Vec<StoredPasskey>, Error> {
    let mut out = Vec::new();
    for item in vw.list_items()? {
        for cred in item.credentials.values() {
            if !matches!(cred.kind, FieldKind::Passkey) {
                continue;
            }
            let Some(secret) = vw.get_secret(&item.key, &cred.key)? else {
                continue;
            };
            match decode(secret.expose_secret()) {
                Ok(passkey) => out.push(StoredPasskey {
                    item_key: item.key.clone(),
                    credential_key: cred.key.clone(),
                    passkey,
                }),
                Err(e) => {
                    log::error!("Skipping unreadable passkey {}/{}: {e}", item.key, cred.key)
                },
            }
        }
    }
    Ok(out)
}

// MARK: - Broker wire types

/// A WebAuthn registration request, as it crosses the broker socket. The
/// AutoFill extension fills this from an `ASPasskeyCredentialRequest`; the app
/// runs the authenticator against an unlocked vault.
#[derive(Debug, Clone)]
pub struct CreatePasskeyRequest {
    pub rp_id: String,
    pub rp_name: Option<String>,
    /// The relying party's opaque user id.
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    /// SHA-256 of the client data, signed over by the attestation.
    pub client_data_hash: Vec<u8>,
    /// COSE algorithm identifiers the client accepts, most preferred first. An
    /// empty list means ES256.
    pub algorithms: Vec<i64>,
    /// Credential ids the relying party already holds for this user. A match
    /// makes the authenticator refuse, so the browser does not double-register.
    pub excluded_credentials: Vec<Vec<u8>>,
}

/// The result of a registration, ready for `ASPasskeyRegistrationCredential`.
#[derive(Debug, Clone)]
pub struct CreatePasskeyResponse {
    pub credential_id: Vec<u8>,
    /// CBOR-encoded WebAuthn attestation object.
    pub attestation_object: Vec<u8>,
}

/// A WebAuthn assertion request, as it crosses the broker socket.
#[derive(Debug, Clone)]
pub struct AssertPasskeyRequest {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    /// Credential ids the relying party will accept. Empty means any passkey
    /// for the relying party.
    pub allowed_credentials: Vec<Vec<u8>>,
}

/// The result of an assertion, ready for `ASPasskeyAssertionCredential`.
#[derive(Debug, Clone)]
pub struct AssertPasskeyResponse {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    /// Serialized authenticator data.
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Map a COSE algorithm identifier to the `coset` enum. Only the algorithms the
/// authenticator can actually produce are listed; anything else is dropped from
/// the parameter list.
fn cose_algorithm(id: i64) -> Option<coset::iana::Algorithm> {
    use coset::iana::Algorithm;
    Some(match id {
        -7 => Algorithm::ES256,
        -8 => Algorithm::EdDSA,
        -35 => Algorithm::ES384,
        -36 => Algorithm::ES512,
        -257 => Algorithm::RS256,
        _ => return None,
    })
}

fn descriptors(ids: Vec<Vec<u8>>) -> Option<Vec<PublicKeyCredentialDescriptor>> {
    if ids.is_empty() {
        return None;
    }
    Some(
        ids.into_iter()
            .map(|id| PublicKeyCredentialDescriptor {
                ty: PublicKeyCredentialType::PublicKey,
                id: Bytes::from(id),
                transports: None,
            })
            .collect(),
    )
}

/// Register a passkey in an unlocked vault from a broker request.
pub async fn create_from_wire(
    vw: &mut VaultWrapper,
    req: CreatePasskeyRequest,
) -> Result<CreatePasskeyResponse, Error> {
    let mut params: Vec<PublicKeyCredentialParameters> = req
        .algorithms
        .iter()
        .filter_map(|id| cose_algorithm(*id))
        .map(|alg| PublicKeyCredentialParameters {
            ty: PublicKeyCredentialType::PublicKey,
            alg,
        })
        .collect();
    if params.is_empty() {
        params.push(PublicKeyCredentialParameters {
            ty: PublicKeyCredentialType::PublicKey,
            alg: coset::iana::Algorithm::ES256,
        });
    }

    let request = make_credential::Request {
        client_data_hash: req.client_data_hash.into(),
        rp: PublicKeyCredentialRpEntity {
            id: req.rp_id,
            name: req.rp_name,
        },
        user: WebauthnUserEntity {
            id: req.user_handle.into(),
            name: req.user_name,
            display_name: req.user_display_name,
        },
        pub_key_cred_params: params,
        exclude_list: descriptors(req.excluded_credentials),
        extensions: None,
        options: get_assertion::Options {
            rk: true,
            up: true,
            uv: true,
        },
        pin_auth: None,
        pin_protocol: None,
    };

    let response = create(vw, request).await?;
    let credential_id = response
        .auth_data
        .attested_credential_data
        .as_ref()
        .map(|acd| acd.credential_id().to_vec())
        .ok_or_else(|| {
            Error::Passkey("Registration response carries no attested credential data".to_string())
        })?;
    Ok(CreatePasskeyResponse {
        credential_id,
        attestation_object: response.as_webauthn_bytes().to_vec(),
    })
}

/// Assert an existing passkey in an unlocked vault from a broker request. The
/// user handle is read back from the stored record rather than the CTAP2
/// response, which omits it for a non-discoverable assertion.
pub async fn assert_from_wire(
    vw: &mut VaultWrapper,
    req: AssertPasskeyRequest,
) -> Result<AssertPasskeyResponse, Error> {
    let request = get_assertion::Request {
        rp_id: req.rp_id.clone(),
        client_data_hash: req.client_data_hash.into(),
        allow_list: descriptors(req.allowed_credentials),
        extensions: None,
        options: get_assertion::Options {
            rk: true,
            up: true,
            uv: true,
        },
        pin_auth: None,
        pin_protocol: None,
    };

    let response = assert(vw, request).await?;
    let credential_id = response
        .credential
        .map(|d| d.id.as_slice().to_vec())
        .ok_or_else(|| Error::Passkey("Assertion response names no credential".to_string()))?;

    let user_handle = list(vw)?
        .into_iter()
        .find(|s| s.passkey.credential_id.as_slice() == credential_id.as_slice())
        .and_then(|s| s.passkey.user_handle.map(|h| h.as_slice().to_vec()))
        .unwrap_or_default();

    Ok(AssertPasskeyResponse {
        credential_id,
        user_handle,
        authenticator_data: response.auth_data.to_vec(),
        signature: response.signature.as_slice().to_vec(),
    })
}

// MARK: - On-disk record

/// How a passkey is written into a credential's value. Byte fields are base64
/// so the record stays plain JSON.
#[derive(Serialize, Deserialize)]
struct StoredRecord {
    rp_id: String,
    /// base64url, no padding: the same encoding WebAuthn uses for credential
    /// ids on the wire.
    credential_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    counter: Option<u32>,
    /// Standard base64 of the CBOR-encoded COSE key, private half included.
    key: String,
}

fn encode(passkey: &Passkey) -> Result<String, Error> {
    let key = passkey
        .key
        .clone()
        .to_vec()
        .map_err(|e| Error::Passkey(format!("Failed to encode the COSE key: {e}")))?;
    let record = StoredRecord {
        rp_id: passkey.rp_id.clone(),
        credential_id: B64URL.encode(passkey.credential_id.as_slice()),
        user_handle: passkey
            .user_handle
            .as_ref()
            .map(|h| B64URL.encode(h.as_slice())),
        username: passkey.username.clone(),
        user_display_name: passkey.user_display_name.clone(),
        counter: passkey.counter,
        key: B64.encode(key),
    };
    serde_json::to_string(&record)
        .map_err(|e| Error::Passkey(format!("Failed to encode the passkey: {e}")))
}

fn decode(value: &str) -> Result<Passkey, Error> {
    let record: StoredRecord = serde_json::from_str(value)
        .map_err(|e| Error::Passkey(format!("Failed to parse the passkey: {e}")))?;
    let key = B64
        .decode(&record.key)
        .map_err(|e| Error::Passkey(format!("Failed to decode the COSE key: {e}")))?;
    let key = CoseKey::from_slice(&key)
        .map_err(|e| Error::Passkey(format!("Failed to parse the COSE key: {e}")))?;
    let credential_id = B64URL
        .decode(&record.credential_id)
        .map_err(|e| Error::Passkey(format!("Failed to decode the credential id: {e}")))?;
    let user_handle = match &record.user_handle {
        Some(handle) => Some(
            B64URL
                .decode(handle)
                .map_err(|e| Error::Passkey(format!("Failed to decode the user handle: {e}")))?,
        ),
        None => None,
    };

    Ok(Passkey {
        key,
        credential_id: Bytes::from(credential_id),
        rp_id: record.rp_id,
        user_handle: user_handle.map(Bytes::from),
        username: record.username,
        user_display_name: record.user_display_name,
        counter: record.counter,
        extensions: Default::default(),
    })
}

// MARK: - Credential store

/// The `CredentialStore` the authenticator reads and writes through.
///
/// Holds the unlocked vault for the length of one request. Writes are staged
/// into the in-memory vault and flushed by [`create`] / [`assert`], so a failed
/// request leaves nothing behind on disk.
struct VaultStore<'a> {
    vw: &'a mut VaultWrapper,
}

impl<'a> VaultStore<'a> {
    fn new(vw: &'a mut VaultWrapper) -> Self {
        Self { vw }
    }

    /// Where a passkey for `rp_id` lives. One item per relying party, with the
    /// credential id distinguishing several accounts on the same site.
    fn item_key(rp_id: &str) -> String {
        let slug: String = rp_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        format!("{ITEM_KEY_PREFIX}-{}", slug.trim_matches('-').to_lowercase())
    }

    /// The vault credential key for a passkey: `passkey-` and the lowercase hex
    /// of the first 8 bytes of the credential id. Vault keys are lowercased and
    /// must match `normalized_key`, so the id's base64url form cannot be used
    /// directly. The full id is in the stored record, which is what lookups
    /// match on.
    fn credential_key(credential_id: &[u8]) -> String {
        let prefix: String = credential_id
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("passkey-{prefix}")
    }

    /// Write `cred` into the vault, replacing whatever is under the same keys.
    /// Used for both a new credential and a counter update.
    fn put(&mut self, cred: &Passkey, item_title: &str, credential_title: &str) -> Result<(), Error> {
        let item_key = Self::item_key(&cred.rp_id);
        let credential_key = Self::credential_key(&cred.credential_id);
        let value = encode(cred)?;
        self.vw.add_item(&item_key, item_title)?;
        self.vw.add_secret(
            &item_key,
            &credential_key,
            credential_title,
            FieldKind::Passkey,
            SecretString::from(value),
        )?;
        Ok(())
    }
}

#[async_trait]
impl CredentialStore for VaultStore<'_> {
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
        user_handle: Option<&[u8]>,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        let stored = list(self.vw).map_err(internal)?;

        let matches: Vec<Passkey> = stored
            .into_iter()
            .map(|s| s.passkey)
            .filter(|p| p.rp_id == rp_id)
            .filter(|p| match ids {
                // An allow list names the acceptable credentials. An empty one
                // is not the same as absent: it must match nothing.
                Some(ids) => ids.iter().any(|id| id.id.as_slice() == p.credential_id.as_slice()),
                None => true,
            })
            .filter(|p| match user_handle {
                Some(handle) => p.user_handle.as_ref().map(|h| h.as_slice()) == Some(handle),
                None => true,
            })
            .collect();

        if matches.is_empty() {
            return Err(Ctap2Error::NoCredentials.into());
        }
        Ok(matches)
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: PublicKeyCredentialUserEntity,
        rp: PublicKeyCredentialRpEntity,
        _options: passkey_types::ctap2::get_assertion::Options,
    ) -> Result<(), StatusCode> {
        let item_title = rp
            .name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| cred.rp_id.clone());
        let credential_title = user
            .display_name
            .clone()
            .filter(|n| !n.is_empty())
            .or_else(|| user.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Passkey".to_string());

        self.put(&cred, &item_title, &credential_title)
            .map_err(internal)
    }

    async fn update_credential(&mut self, cred: &Self::PasskeyItem) -> Result<(), StatusCode> {
        // The titles are already on the stored credential; re-deriving them
        // from the record keeps an update from renaming anything.
        let item_title = cred.rp_id.clone();
        let credential_title = cred
            .user_display_name
            .clone()
            .or_else(|| cred.username.clone())
            .unwrap_or_else(|| "Passkey".to_string());
        self.put(cred, &item_title, &credential_title)
            .map_err(internal)
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::Full,
        }
    }
}

/// Reports the approval the app already collected.
///
/// The vault cannot be decrypted without the user answering the app's Touch ID
/// prompt, so reaching this code at all means presence and verification are
/// established. Prompting here would ask the same question twice.
struct PromptedUser;

#[async_trait]
impl UserValidationMethod for PromptedUser {
    type PasskeyItem = Passkey;

    async fn check_user<'a>(
        &self,
        _hint: UiHint<'a, Self::PasskeyItem>,
        presence: bool,
        verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        Ok(UserCheck {
            presence,
            verification,
        })
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

/// A vault failure the CTAP2 layer has no specific code for.
fn internal(e: Error) -> StatusCode {
    log::error!("Passkey store failure: {e}");
    Ctap2Error::Processing.into()
}

fn status_error(status: StatusCode) -> Error {
    Error::Passkey(format!("{status:?}"))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

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

    #[tokio::test]
    async fn record_survives_a_round_trip() {
        let passkey = sample_passkey().await;

        let encoded = encode(&passkey).unwrap();
        let decoded = decode(&encoded).unwrap();

        assert_eq!(decoded.rp_id, passkey.rp_id);
        assert_eq!(decoded.credential_id, passkey.credential_id);
        assert_eq!(decoded.user_handle, passkey.user_handle);
        assert_eq!(decoded.username, passkey.username);
        assert_eq!(decoded.user_display_name, passkey.user_display_name);
        assert_eq!(decoded.counter, passkey.counter);
        // The private key is what makes the credential usable, so it has to
        // come back byte-identical.
        assert_eq!(
            decoded.key.clone().to_vec().unwrap(),
            passkey.key.clone().to_vec().unwrap()
        );
    }

    #[tokio::test]
    async fn record_is_plain_json_with_base64url_ids() {
        let passkey = sample_passkey().await;
        let value: serde_json::Value = serde_json::from_str(&encode(&passkey).unwrap()).unwrap();

        assert_eq!(value["rp_id"], "example.com");
        assert_eq!(value["username"], "ada");
        assert_eq!(
            value["credential_id"].as_str().unwrap(),
            B64URL.encode(passkey.credential_id.as_slice())
        );
        // base64url ids must never carry the characters that would need
        // escaping in a URL.
        let id = value["credential_id"].as_str().unwrap();
        assert!(!id.contains('+') && !id.contains('/') && !id.contains('='), "{id}");
    }

    #[test]
    fn item_keys_are_normalized_per_relying_party() {
        assert_eq!(VaultStore::item_key("example.com"), "passkey-example-com");
        assert_eq!(
            VaultStore::item_key("login.EXAMPLE.co.uk"),
            "passkey-login-example-co-uk"
        );
    }

    /// Credential ids are random bytes. Every one must give a key the vault
    /// accepts unchanged, including ids whose base64url form starts with a
    /// digit or ends with `-`.
    #[test]
    fn credential_keys_are_valid_vault_keys() {
        let ids: [&[u8]; 4] = [
            &[0x00; 16],
            &[0xff; 16],
            &[0xd3, 0x4f, 0xb9, 0x01, 0x22, 0x7e, 0x80, 0x11, 0x5a],
            &[0x01, 0x02],
        ];
        for id in ids {
            let key = VaultStore::credential_key(id);
            assert_eq!(
                crate::secrets::vaults::vault_wrapper::normalized_key(&key).as_deref(),
                Some(key.as_str()),
                "{id:?}"
            );
        }
        assert_eq!(
            VaultStore::credential_key(&[0xd3, 0x4f, 0xb9, 0x01, 0x22, 0x7e, 0x80, 0x11, 0x5a]),
            "passkey-d34fb901227e8011"
        );
    }

    #[test]
    fn unreadable_records_are_rejected_not_panicked_on() {
        assert!(decode("not json").is_err());
        assert!(decode(r#"{"rp_id":"example.com"}"#).is_err());
    }
}
