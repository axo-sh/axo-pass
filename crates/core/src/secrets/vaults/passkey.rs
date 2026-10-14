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
//!
//! Every passkey created here supports the WebAuthn PRF extension. A random
//! secret is stored in the record at registration, and PRF results are
//! HMAC-SHA-256 of that secret over the hashed page input.

use std::collections::HashMap;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use coset::{CborSerializable, CoseKey};
use passkey_authenticator::extensions::HmacSecretConfig;
use passkey_authenticator::{
    Authenticator, CredentialStore, DiscoverabilitySupport, StoreInfo, UiHint, UserCheck,
    UserValidationMethod,
};
use passkey_types::ctap2::extensions::{AuthenticatorPrfInputs, AuthenticatorPrfValues};
use passkey_types::ctap2::make_credential::{
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
};
use passkey_types::ctap2::{Aaguid, Ctap2Error, StatusCode, get_assertion, make_credential};
use passkey_types::webauthn::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity as WebauthnUserEntity,
};
use passkey_types::{Bytes, CredentialExtensions, Passkey, StoredHmacSecret};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Error, FieldKind, VaultWrapper, autofill};

/// Identifies Axo Pass as the authenticator model in attestation data. A fixed
/// random constant, per the WebAuthn spec: it names the model, never the
/// instance, so it carries nothing about the user or this install.
const AAGUID: Aaguid = Aaguid([
    0x9a, 0x0c, 0x4e, 0x7b, 0x2d, 0x51, 0x4f, 0x86, 0xb1, 0x63, 0x5c, 0x8d, 0x74, 0x2e, 0x9f, 0x30,
]);

/// Where a new passkey is stored in the chosen vault.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PasskeyTarget {
    /// A new login item for the relying party.
    #[default]
    NewLogin,
    /// An existing item, by key.
    Item(String),
}

/// Create a passkey in an unlocked vault and return the CTAP2 response. The
/// caller turns `as_webauthn_bytes()` into the attestation object the browser
/// wants.
///
/// The vault is saved before returning, so the credential is durable by the
/// time the relying party sees the attestation.
pub async fn create(
    vw: &mut VaultWrapper,
    request: make_credential::Request,
    target: PasskeyTarget,
) -> Result<make_credential::Response, Error> {
    let mut authenticator = authenticator(VaultStore::new(vw, target));
    let response = authenticator
        .make_credential(request)
        .await
        .map_err(status_error)?;
    // `save_credential` staged the credential in the in-memory vault; persist
    // it now that the authenticator has finished.
    vw.save()?;
    Ok(response)
}

/// Assert an existing passkey in an unlocked vault. Passkeys are synced, so
/// their signature counter stays 0 and the stored record is never changed.
pub async fn assert(
    vw: &mut VaultWrapper,
    request: get_assertion::Request,
) -> Result<get_assertion::Response, Error> {
    let mut authenticator = authenticator(VaultStore::new(vw, PasskeyTarget::NewLogin));
    authenticator
        .get_assertion(request)
        .await
        .map_err(status_error)
}

/// The authenticator with PRF enabled. PRF secrets are only used after user
/// verification, which every request here performs.
fn authenticator(store: VaultStore<'_>) -> Authenticator<VaultStore<'_>, PromptedUser> {
    Authenticator::new(AAGUID, store, PromptedUser)
        .hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential())
}

/// A passkey with the vault coordinates it was read from.
#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub vault_id: Uuid,
    pub item_id: Uuid,
    pub credential_id: Uuid,
    pub item_key: String,
    pub credential_key: String,
    pub passkey: Passkey,
}

impl StoredPasskey {
    /// `<vault uuid>/<item uuid>/<credential uuid>`, the record identifier the
    /// AutoFill index stores for the passkey.
    pub fn record_id(&self) -> String {
        format!("{}/{}/{}", self.vault_id, self.item_id, self.credential_id)
    }
}

/// List the passkeys in an unlocked vault, for the UI and for registering
/// AutoFill identities. A record this build cannot read is logged and skipped
/// rather than failing the listing.
pub fn list(vw: &VaultWrapper) -> Result<Vec<StoredPasskey>, Error> {
    let mut out = Vec::new();
    let vault_id = vw.vault_id()?;
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
                    vault_id,
                    item_id: item.id,
                    credential_id: cred.id,
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
    /// PRF extension input. `None` when the page did not use the extension.
    pub prf: Option<PrfRegistrationInput>,
    /// Where in the vault the passkey is stored.
    pub target: PasskeyTarget,
}

/// The result of a registration, ready for `ASPasskeyRegistrationCredential`.
#[derive(Debug, Clone)]
pub struct CreatePasskeyResponse {
    pub credential_id: Vec<u8>,
    /// CBOR-encoded WebAuthn attestation object.
    pub attestation_object: Vec<u8>,
    /// PRF extension output. `None` when the request carried no PRF input.
    pub prf: Option<PrfRegistrationOutput>,
}

/// A WebAuthn assertion request, as it crosses the broker socket.
#[derive(Debug, Clone)]
pub struct AssertPasskeyRequest {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    /// Credential ids the relying party will accept. Empty means any passkey
    /// for the relying party.
    pub allowed_credentials: Vec<Vec<u8>>,
    /// PRF extension input. `None` when the page did not use the extension.
    pub prf: Option<PrfAssertionInput>,
}

/// The result of an assertion, ready for `ASPasskeyAssertionCredential`.
#[derive(Debug, Clone)]
pub struct AssertPasskeyResponse {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    /// Serialized authenticator data.
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    /// PRF results. `None` when the request carried no PRF input or the
    /// passkey has no PRF secret.
    pub prf: Option<PrfValues>,
    /// Where the passkey that signed is stored.
    pub item_key: String,
    pub credential_key: String,
}

// MARK: - PRF

/// One or two PRF values. As input these are the page values before hashing.
/// As output they are the 32-byte PRF results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfValues {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

/// PRF input of a registration. Its presence asks whether PRF is supported.
/// `eval` also asks for results immediately.
#[derive(Debug, Clone, Default)]
pub struct PrfRegistrationInput {
    pub eval: Option<PrfValues>,
}

/// PRF output of a registration.
#[derive(Debug, Clone)]
pub struct PrfRegistrationOutput {
    pub enabled: bool,
    pub results: Option<PrfValues>,
}

/// PRF input of an assertion. A per-credential entry for the signing
/// credential takes precedence over `eval`.
#[derive(Debug, Clone, Default)]
pub struct PrfAssertionInput {
    pub eval: Option<PrfValues>,
    pub eval_by_credential: Vec<(Vec<u8>, PrfValues)>,
}

/// Salt for one PRF input, as WebAuthn defines it:
/// SHA-256("WebAuthn PRF" || 0x00 || input). The page input arrives
/// unhashed, so the hash is applied here.
fn prf_salt(input: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(13 + input.len());
    data.extend_from_slice(b"WebAuthn PRF");
    data.push(0);
    data.extend_from_slice(input);
    passkey_types::crypto::sha256(&data)
}

fn prf_salts(values: &PrfValues) -> AuthenticatorPrfValues {
    AuthenticatorPrfValues {
        first: prf_salt(&values.first),
        second: values.second.as_deref().map(prf_salt),
    }
}

fn prf_results(values: AuthenticatorPrfValues) -> PrfValues {
    PrfValues {
        first: values.first.to_vec(),
        second: values.second.map(|b| b.to_vec()),
    }
}

impl PrfRegistrationInput {
    fn to_ctap(&self) -> make_credential::ExtensionInputs {
        make_credential::ExtensionInputs {
            hmac_secret: Some(true),
            hmac_secret_mc: None,
            prf: Some(AuthenticatorPrfInputs {
                eval: self.eval.as_ref().map(prf_salts),
                eval_by_credential: None,
            }),
        }
    }
}

impl PrfAssertionInput {
    fn to_ctap(&self) -> get_assertion::ExtensionInputs {
        let by_credential: HashMap<Bytes, AuthenticatorPrfValues> = self
            .eval_by_credential
            .iter()
            .map(|(id, values)| (Bytes::from(id.clone()), prf_salts(values)))
            .collect();
        get_assertion::ExtensionInputs {
            hmac_secret: None,
            prf: Some(AuthenticatorPrfInputs {
                eval: self.eval.as_ref().map(prf_salts),
                eval_by_credential: (!by_credential.is_empty()).then_some(by_credential),
            }),
        }
    }
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
        // A PRF secret is created for every passkey, so a page can use PRF at
        // sign-in even if it did not ask at registration.
        extensions: Some(match &req.prf {
            Some(prf) => prf.to_ctap(),
            None => make_credential::ExtensionInputs {
                hmac_secret: Some(true),
                ..Default::default()
            },
        }),
        options: get_assertion::Options {
            rk: true,
            up: true,
            uv: true,
        },
        pin_auth: None,
        pin_protocol: None,
    };

    let response = create(vw, request, req.target).await?;
    let credential_id = response
        .auth_data
        .attested_credential_data
        .as_ref()
        .map(|acd| acd.credential_id().to_vec())
        .ok_or_else(|| {
            Error::Passkey("Registration response carries no attested credential data".to_string())
        })?;
    let prf = req.prf.as_ref().map(|_| {
        let output = response
            .unsigned_extension_outputs
            .as_ref()
            .and_then(|outputs| outputs.prf.clone());
        PrfRegistrationOutput {
            enabled: output.as_ref().is_some_and(|o| o.enabled),
            results: output.and_then(|o| o.results).map(prf_results),
        }
    });
    Ok(CreatePasskeyResponse {
        credential_id,
        attestation_object: response.as_webauthn_bytes().to_vec(),
        prf,
    })
}

/// Assert an existing passkey in an unlocked vault from a broker request. The
/// user handle is read back from the stored record rather than the CTAP2
/// response, which omits it for a non-discoverable assertion.
///
/// The passkey's last use is recorded in its credential metadata, and the
/// vault is saved. A failure to save is logged and does not fail the
/// sign-in.
pub async fn assert_from_wire(
    vw: &mut VaultWrapper,
    req: AssertPasskeyRequest,
) -> Result<AssertPasskeyResponse, Error> {
    let request = get_assertion::Request {
        rp_id: req.rp_id.clone(),
        client_data_hash: req.client_data_hash.into(),
        allow_list: descriptors(req.allowed_credentials),
        extensions: req.prf.as_ref().map(PrfAssertionInput::to_ctap),
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

    let stored = list(vw)?
        .into_iter()
        .find(|s| s.passkey.credential_id.as_slice() == credential_id.as_slice())
        .ok_or_else(|| Error::Passkey("The signing passkey is not in the vault".to_string()))?;
    let user_handle = stored
        .passkey
        .user_handle
        .as_ref()
        .map(|h| h.as_slice().to_vec())
        .unwrap_or_default();

    if let Some(now) = now_unix() {
        let marked = vw
            .mark_credential_used(&stored.item_key, &stored.credential_key, now)
            .and_then(|()| vw.save());
        if let Err(e) = marked {
            log::error!(
                "Failed to record the use of passkey {}/{}: {e}",
                stored.item_key,
                stored.credential_key
            );
        }
    }

    let prf = response
        .unsigned_extension_outputs
        .and_then(|outputs| outputs.prf)
        .map(|output| prf_results(output.results));

    Ok(AssertPasskeyResponse {
        credential_id,
        user_handle,
        authenticator_data: response.auth_data.to_vec(),
        signature: response.signature.as_slice().to_vec(),
        prf,
        item_key: stored.item_key,
        credential_key: stored.credential_key,
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
    /// Unix seconds when the passkey was registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<i64>,
    /// Standard base64 of the CBOR-encoded COSE key, private half included.
    key: String,
    /// Standard base64 of the PRF secret, used only after user verification.
    /// Absent for passkeys created before PRF support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prf_secret: Option<String>,
}

/// Passkey details to display. Excludes key and the user handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeySummary {
    pub rp_id: String,
    /// base64url, no padding.
    pub credential_id: String,
    pub username: Option<String>,
    pub user_display_name: Option<String>,
    /// Unix seconds when the passkey was registered, when recorded.
    pub created_at: Option<i64>,
    /// The passkey has a PRF secret.
    pub prf: bool,
    /// base64url of the user handle, no padding. Used to match site reports,
    /// not shown.
    pub user_handle: Option<String>,
}

/// Read the displayable fields of a stored passkey record. `None` when the
/// value is not a passkey record.
pub fn summary(value: &str) -> Option<PasskeySummary> {
    let record: StoredRecord = serde_json::from_str(value).ok()?;
    Some(PasskeySummary {
        rp_id: record.rp_id,
        credential_id: record.credential_id,
        username: record.username,
        user_display_name: record.user_display_name,
        created_at: record.created_at,
        prf: record.prf_secret.is_some(),
        user_handle: record.user_handle,
    })
}

fn now_unix() -> Option<i64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    i64::try_from(elapsed.as_secs()).ok()
}

fn encode(passkey: &Passkey, created_at: Option<i64>) -> Result<String, Error> {
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
        created_at,
        key: B64.encode(key),
        prf_secret: passkey
            .extensions
            .hmac_secret
            .as_ref()
            .map(|secret| B64.encode(&secret.cred_with_uv)),
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
    let hmac_secret = match &record.prf_secret {
        Some(secret) => Some(StoredHmacSecret {
            cred_with_uv: B64
                .decode(secret)
                .map_err(|e| Error::Passkey(format!("Failed to decode the PRF secret: {e}")))?,
            cred_without_uv: None,
        }),
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
        extensions: CredentialExtensions { hmac_secret },
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
    /// Where a new passkey goes. Read by `save_credential` only.
    target: PasskeyTarget,
}

impl<'a> VaultStore<'a> {
    fn new(vw: &'a mut VaultWrapper, target: PasskeyTarget) -> Self {
        Self { vw, target }
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

    /// Write a new passkey into the target item, creating a login item for the
    /// relying party when the target is a new login.
    fn put(
        &mut self,
        cred: &Passkey,
        item_title: Option<&str>,
        credential_title: &str,
    ) -> Result<(), Error> {
        let value = encode(cred, now_unix())?;
        store_passkey(
            self.vw,
            cred,
            value,
            item_title,
            credential_title,
            &self.target,
        )
    }
}

/// Write a passkey record into `target` in an unlocked vault, creating a login
/// item for the relying party when the target is a new login. The caller saves
/// the vault.
fn store_passkey(
    vw: &mut VaultWrapper,
    cred: &Passkey,
    value: String,
    item_title: Option<&str>,
    credential_title: &str,
    target: &PasskeyTarget,
) -> Result<(), Error> {
    let item_key = match target {
        PasskeyTarget::Item(key) => {
            if vw.get_item_overview(key)?.is_none() {
                return Err(Error::InvalidItemKey(key.clone()));
            }
            key.clone()
        },
        PasskeyTarget::NewLogin => {
            autofill::add_passkey_login(vw, &cred.rp_id, item_title, cred.username.as_deref())?
        },
    };
    let credential_key = VaultStore::credential_key(&cred.credential_id);
    vw.add_secret(
        &item_key,
        &credential_key,
        credential_title,
        FieldKind::Passkey,
        SecretString::from(value),
    )
}

/// A stored passkey's raw record and credential title, read so it can move to
/// another item or vault.
pub struct PasskeyRecord {
    pub value: SecretString,
    pub title: String,
}

/// Read the passkey at `item_key`/`credential_key`. Fails when the credential
/// is not a passkey.
pub fn read_record(
    vw: &VaultWrapper,
    item_key: &str,
    credential_key: &str,
) -> Result<PasskeyRecord, Error> {
    let overview = vw
        .get_secret_overview(item_key, credential_key)?
        .filter(|cred| matches!(cred.kind, FieldKind::Passkey))
        .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{credential_key}")))?;
    let title = overview.title.clone();
    let value = vw
        .get_secret(item_key, credential_key)?
        .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{credential_key}")))?;
    Ok(PasskeyRecord {
        value: SecretString::from(value.expose_secret().clone()),
        title,
    })
}

/// Store a record read by [`read_record`] in `target`. The record must decode,
/// so a damaged value is refused rather than copied. The caller saves the
/// vault.
pub fn write_record(
    vw: &mut VaultWrapper,
    record: &PasskeyRecord,
    target: &PasskeyTarget,
) -> Result<(), Error> {
    let value = record.value.expose_secret().to_string();
    let cred = decode(&value)?;
    store_passkey(vw, &cred, value, None, &record.title, target)
}

/// Remove the passkey at `item_key`/`credential_key` after it was copied by
/// [`write_record`]. The passkey is deleted and purged immediately rather than
/// kept in the deleted credentials. A copy left there would keep the private
/// key in this vault, and restoring it would give two passkeys with one
/// credential id. Fails when the credential is not a passkey. The caller saves
/// the vault.
pub fn remove_record(
    vw: &mut VaultWrapper,
    item_key: &str,
    credential_key: &str,
) -> Result<(), Error> {
    let cred_id = vw
        .get_secret_overview(item_key, credential_key)?
        .filter(|cred| matches!(cred.kind, FieldKind::Passkey))
        .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{credential_key}")))?
        .id;
    vw.delete_item_credential(item_key, credential_key)?;
    vw.purge_item_credential(item_key, cred_id)
}

/// Set the account name of the passkey at `item_key`/`credential_key`, as a
/// site reported it. The record username, display name, and credential title
/// all take the new name. The replaced record is not kept as a previous value,
/// since it differs only in the name. The caller saves the vault.
pub fn rename_account(
    vw: &mut VaultWrapper,
    item_key: &str,
    credential_key: &str,
    name: &str,
) -> Result<(), Error> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::Passkey("The new account name is empty".to_string()));
    }
    let record = read_record(vw, item_key, credential_key)?;
    let mut stored: StoredRecord = serde_json::from_str(record.value.expose_secret())
        .map_err(|e| Error::Passkey(format!("Failed to parse the passkey: {e}")))?;
    stored.username = Some(name.to_string());
    stored.user_display_name = Some(name.to_string());
    let value = serde_json::to_string(&stored)
        .map_err(|e| Error::Passkey(format!("Failed to encode the passkey: {e}")))?;

    let before: Vec<Uuid> = vw
        .list_history(item_key, credential_key)?
        .into_iter()
        .map(|entry| entry.id)
        .collect();
    vw.add_secret(
        item_key,
        credential_key,
        name,
        FieldKind::Passkey,
        SecretString::from(value),
    )?;
    for entry in vw.list_history(item_key, credential_key)? {
        if !before.contains(&entry.id) {
            vw.purge_history(item_key, credential_key, entry.id)?;
        }
    }
    Ok(())
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
                Some(ids) => ids
                    .iter()
                    .any(|id| id.id.as_slice() == p.credential_id.as_slice()),
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
        let item_title = rp.name.clone().filter(|n| !n.is_empty());
        let credential_title = user
            .display_name
            .clone()
            .filter(|n| !n.is_empty())
            .or_else(|| user.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "Passkey".to_string());

        self.put(&cred, item_title.as_deref(), &credential_title)
            .map_err(internal)
    }

    async fn update_credential(&mut self, _cred: &Self::PasskeyItem) -> Result<(), StatusCode> {
        // Passkeys are synced, so the signature counter is never advanced and a
        // stored record never changes after registration. An assertion writes
        // nothing.
        Ok(())
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
    use crate::secrets::vaults::MatchKind;
    use crate::secrets::vaults::vault_wrapper::normalized_key;

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

        let encoded = encode(&passkey, None).unwrap();
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
        let value: serde_json::Value =
            serde_json::from_str(&encode(&passkey, None).unwrap()).unwrap();

        assert_eq!(value["rp_id"], "example.com");
        assert_eq!(value["username"], "ada");
        assert_eq!(
            value["credential_id"].as_str().unwrap(),
            B64URL.encode(passkey.credential_id.as_slice())
        );
        // base64url ids must never carry the characters that would need
        // escaping in a URL.
        let id = value["credential_id"].as_str().unwrap();
        assert!(
            !id.contains('+') && !id.contains('/') && !id.contains('='),
            "{id}"
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
                normalized_key(&key).as_deref(),
                Some(key.as_str()),
                "{id:?}"
            );
        }
        assert_eq!(
            VaultStore::credential_key(&[0xd3, 0x4f, 0xb9, 0x01, 0x22, 0x7e, 0x80, 0x11, 0x5a]),
            "passkey-d34fb901227e8011"
        );
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
    async fn register(vw: &mut VaultWrapper, target: PasskeyTarget, user: &str) {
        let mut authenticator =
            Authenticator::new(AAGUID, VaultStore::new(vw, target), PromptedUser);
        authenticator
            .make_credential(registration("example.com", user))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_new_login_target_creates_a_login_item() {
        let mut vw = VaultWrapper::new_for_test("personal");
        register(&mut vw, PasskeyTarget::NewLogin, "ada@example.com").await;

        let passkeys = list(&vw).unwrap();
        assert_eq!(passkeys.len(), 1);
        let item = vw
            .get_item_overview(&passkeys[0].item_key)
            .unwrap()
            .unwrap();
        assert_eq!(item.title, "Example");
        assert_eq!(item.category.as_deref(), Some("login"));
        assert_eq!(item.autofill.websites.len(), 1);
        assert_eq!(item.autofill.websites[0].url, "example.com");
        assert!(item.autofill.password.is_none());
        let username = item.autofill.username_credential(item).unwrap();
        assert_eq!(username.key, "username");
        assert_eq!(passkeys[0].record_id().split('/').count(), 3);
    }

    #[tokio::test]
    async fn an_item_target_stores_the_passkey_beside_the_login() {
        let mut vw = VaultWrapper::new_for_test("personal");
        autofill::write_login(
            &mut vw,
            autofill::LoginWrite {
                item_key: "example",
                title: "Example",
                password_key: "password",
                password: SecretString::from("pw"),
                username: Some("ada"),
                websites: &["example.com".to_string()],
                match_kind: MatchKind::Domain,
            },
        )
        .unwrap();
        register(&mut vw, PasskeyTarget::Item("example".into()), "ada").await;

        let passkeys = list(&vw).unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0].item_key, "example");
        assert_eq!(vw.list_items().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_passkey_moves_to_another_vault_with_its_record_intact() {
        let mut source = VaultWrapper::new_for_test("personal");
        register(&mut source, PasskeyTarget::NewLogin, "ada").await;
        let stored = list(&source).unwrap().remove(0);
        let record = read_record(&source, &stored.item_key, &stored.credential_key).unwrap();

        let mut dest = VaultWrapper::new_for_test("work");
        write_record(&mut dest, &record, &PasskeyTarget::NewLogin).unwrap();

        let moved = list(&dest).unwrap().remove(0);
        assert_eq!(moved.credential_key, stored.credential_key);
        assert_eq!(moved.passkey.credential_id, stored.passkey.credential_id);
        assert_eq!(
            moved.passkey.key.clone().to_vec().unwrap(),
            stored.passkey.key.clone().to_vec().unwrap()
        );
        assert_eq!(dest.list_items().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_moved_passkey_is_not_kept_in_the_source_deleted_credentials() {
        let mut source = VaultWrapper::new_for_test("personal");
        register(&mut source, PasskeyTarget::NewLogin, "ada").await;
        let stored = list(&source).unwrap().remove(0);
        let record = read_record(&source, &stored.item_key, &stored.credential_key).unwrap();
        let mut dest = VaultWrapper::new_for_test("work");
        write_record(&mut dest, &record, &PasskeyTarget::NewLogin).unwrap();

        remove_record(&mut source, &stored.item_key, &stored.credential_key).unwrap();

        assert!(list(&source).unwrap().is_empty());
        assert!(source.list_all_deleted().unwrap().is_empty());
    }

    #[test]
    fn only_passkeys_can_be_removed_after_a_move() {
        let mut vw = VaultWrapper::new_for_test("personal");
        vw.add_item("site", "Site").unwrap();
        vw.add_secret(
            "site",
            "password",
            "Password",
            FieldKind::default(),
            SecretString::from("pw"),
        )
        .unwrap();
        assert!(remove_record(&mut vw, "site", "password").is_err());
        assert!(vw.get_secret("site", "password").unwrap().is_some());
    }

    #[test]
    fn only_passkeys_can_be_read_for_a_move() {
        let mut vw = VaultWrapper::new_for_test("personal");
        vw.add_item("site", "Site").unwrap();
        vw.add_secret(
            "site",
            "password",
            "Password",
            FieldKind::default(),
            SecretString::from("pw"),
        )
        .unwrap();
        assert!(read_record(&vw, "site", "password").is_err());
    }

    #[tokio::test]
    async fn a_missing_item_target_is_an_error() {
        let mut vw = VaultWrapper::new_for_test("personal");
        let mut authenticator = Authenticator::new(
            AAGUID,
            VaultStore::new(&mut vw, PasskeyTarget::Item("gone".into())),
            PromptedUser,
        );
        assert!(
            authenticator
                .make_credential(registration("example.com", "ada"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_assertion_leaves_the_stored_record_unchanged() {
        let mut vw = VaultWrapper::new_for_test("personal");
        register(&mut vw, PasskeyTarget::NewLogin, "ada").await;
        let before = list(&vw).unwrap();
        let item_key = before[0].item_key.clone();
        let credential_key = before[0].credential_key.clone();
        let stored = |vw: &VaultWrapper| {
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

        let mut vw = VaultWrapper::new_for_test("personal");
        let mut authenticator = Authenticator::new(
            AAGUID,
            VaultStore::new(&mut vw, PasskeyTarget::NewLogin),
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
    fn prf_salts_are_hashed_with_the_webauthn_context() {
        let mut data = b"WebAuthn PRF\0".to_vec();
        data.extend_from_slice(b"hello");
        assert_eq!(prf_salt(b"hello"), passkey_types::crypto::sha256(&data));
    }

    #[tokio::test]
    async fn prf_results_are_stable_and_match_registration() {
        let mut vw = VaultWrapper::new_for_test("personal");
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
        let created = authenticator(VaultStore::new(&mut vw, PasskeyTarget::NewLogin))
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
        let mut vw = VaultWrapper::new_for_test("personal");
        let mut request = registration("example.com", "ada");
        request.extensions = Some(make_credential::ExtensionInputs {
            hmac_secret: Some(true),
            ..Default::default()
        });
        authenticator(VaultStore::new(&mut vw, PasskeyTarget::NewLogin))
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
    async fn a_passkey_without_a_prf_secret_returns_no_prf_results() {
        let mut vw = VaultWrapper::new_for_test("personal");
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

    #[tokio::test]
    async fn renaming_an_account_keeps_the_key_and_adds_no_history() {
        let mut vw = VaultWrapper::new_for_test("personal");
        register(&mut vw, PasskeyTarget::NewLogin, "ada").await;
        let stored = list(&vw).unwrap().remove(0);

        rename_account(
            &mut vw,
            &stored.item_key,
            &stored.credential_key,
            " lovelace ",
        )
        .unwrap();

        let renamed = list(&vw).unwrap().remove(0);
        assert_eq!(renamed.passkey.username.as_deref(), Some("lovelace"));
        assert_eq!(
            renamed.passkey.user_display_name.as_deref(),
            Some("lovelace")
        );
        assert_eq!(renamed.passkey.credential_id, stored.passkey.credential_id);
        assert_eq!(
            renamed.passkey.key.clone().to_vec().unwrap(),
            stored.passkey.key.clone().to_vec().unwrap()
        );
        let overview = vw
            .get_secret_overview(&stored.item_key, &stored.credential_key)
            .unwrap()
            .unwrap();
        assert_eq!(overview.title, "lovelace");
        assert!(
            vw.list_history(&stored.item_key, &stored.credential_key)
                .unwrap()
                .is_empty()
        );
        assert!(rename_account(&mut vw, &stored.item_key, &stored.credential_key, " ").is_err());
    }

    #[tokio::test]
    async fn a_registration_records_when_it_was_created() {
        let mut vw = VaultWrapper::new_for_test("personal");
        register(&mut vw, PasskeyTarget::NewLogin, "ada").await;
        let stored = list(&vw).unwrap().remove(0);
        let value = vw
            .get_secret(&stored.item_key, &stored.credential_key)
            .unwrap()
            .unwrap();

        let summary = summary(value.expose_secret()).unwrap();
        assert_eq!(summary.rp_id, "example.com");
        assert_eq!(summary.username.as_deref(), Some("ada"));
        assert!(summary.created_at.is_some_and(|t| t > 1_700_000_000));
    }

    #[test]
    fn a_record_without_a_creation_time_still_summarizes() {
        let summary = summary(r#"{"rp_id":"example.com","credential_id":"AA","key":"x"}"#).unwrap();
        assert_eq!(summary.created_at, None);
        assert!(super::summary("not json").is_none());
    }

    #[test]
    fn unreadable_records_are_rejected_not_panicked_on() {
        assert!(decode("not json").is_err());
        assert!(decode(r#"{"rp_id":"example.com"}"#).is_err());
    }
}
