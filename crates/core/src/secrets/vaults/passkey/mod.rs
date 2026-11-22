//! WebAuthn passkeys stored as vault credentials.
//!
//! The CTAP2 authenticator itself comes from `passkey-authenticator`; this
//! module supplies the two traits it needs. [`PasskeyCredentialStore`] is the
//! `CredentialStore`, backed by an unlocked vault, and [`PromptedUser`] is the
//! `UserValidationMethod`.
//!
//! One passkey is one credential of kind [`FieldKind::Passkey`], whose value is
//! a JSON [`StoredPasskey`]: the private key, the credential id, the relying
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

pub mod signals;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use coset::{CborSerializable, CoseKey};
use jiff::tz::TimeZone;
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

use super::model::last_used;
use super::storage::txn::VaultWriter;
use super::{Error, FieldKind, ShortId, VaultHandle, autofill};
use crate::audit::SubjectIds;

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

/// Create a passkey in an unlocked vault and return the CTAP2 response and the
/// audit ids of the stored passkey. The caller turns `as_webauthn_bytes()` into
/// the attestation object the browser wants.
///
/// The authenticator works on `vw`. The new passkey is then written into a
/// fresh copy of the vault in its own transaction, so an edit saved since
/// `vw` was loaded is kept. It is saved before this returns, so the
/// credential is durable by the time the relying party sees the attestation.
pub async fn create(
    files: &VaultWriter,
    vw: &mut VaultHandle,
    request: make_credential::Request,
    target: PasskeyTarget,
) -> Result<(make_credential::Response, SubjectIds), Error> {
    let staged = Arc::new(Mutex::new(None));
    let response = {
        let store = PasskeyCredentialStore {
            vw: &mut *vw,
            target: target.clone(),
            staged: Arc::clone(&staged),
        };
        authenticator(store)
            .make_credential(request)
            .await
            .map_err(status_error)?
    };
    let staged = staged
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .ok_or_else(|| Error::Passkey("The authenticator saved no passkey".to_string()))?;
    let credential_key = PasskeyCredentialStore::credential_key(&staged.cred.credential_id);
    let ids = files
        .write_unlocked::<_, Error>(vw, |fresh| {
            let item_key = staged.write(fresh, &target)?;
            fresh.credential_ids(&item_key, &credential_key)
        })?
        .value;
    Ok((response, ids))
}

/// Assert an existing passkey in an unlocked vault. Passkeys are synced, so
/// their signature counter stays 0 and the stored record is never changed.
pub async fn assert(
    vw: &mut VaultHandle,
    request: get_assertion::Request,
) -> Result<get_assertion::Response, Error> {
    let mut authenticator = authenticator(PasskeyCredentialStore::new(vw, PasskeyTarget::NewLogin));
    authenticator
        .get_assertion(request)
        .await
        .map_err(status_error)
}

/// The authenticator with PRF enabled. PRF secrets are only used after user
/// verification, which every request here performs.
fn authenticator(
    store: PasskeyCredentialStore<'_>,
) -> Authenticator<PasskeyCredentialStore<'_>, PromptedUser> {
    Authenticator::new(AAGUID, store, PromptedUser)
        .hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential())
}

/// A passkey with the vault coordinates it was read from.
#[derive(Debug, Clone)]
pub struct PasskeyCredential {
    pub vault_id: Uuid,
    pub item_id: Uuid,
    pub credential_id: Uuid,
    pub item_key: String,
    pub credential_key: String,
    pub passkey: Passkey,
}

impl PasskeyCredential {
    /// `<vault id>/<item id>/<credential id>` as short ids, the record
    /// identifier the AutoFill index stores for the passkey.
    pub fn record_id(&self) -> String {
        format!(
            "{}/{}/{}",
            ShortId::new(self.vault_id),
            ShortId::new(self.item_id),
            ShortId::new(self.credential_id)
        )
    }
}

/// List the passkeys in an unlocked vault, for the UI and for registering
/// AutoFill identities. A record this build cannot read is logged and skipped
/// rather than failing the listing.
pub fn list(vw: &VaultHandle) -> Result<Vec<PasskeyCredential>, Error> {
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
                Ok(passkey) => out.push(PasskeyCredential {
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
    /// Audit ids of the stored passkey.
    pub ids: SubjectIds,
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
    files: &VaultWriter,
    vw: &mut VaultHandle,
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

    let (response, ids) = create(files, vw, request, req.target).await?;
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
        ids,
    })
}

/// Assert an existing passkey in an unlocked vault from a broker request. The
/// user handle is read back from the stored record rather than the CTAP2
/// response, which omits it for a non-discoverable assertion.
///
/// The passkey's last use is recorded in its credential metadata by
/// [`record_use`], at most once a day. A failure to save is logged and does
/// not fail the sign-in.
pub async fn assert_from_wire(
    files: &VaultWriter,
    vw: &mut VaultHandle,
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
        let marked = record_use(files, vw, &stored, now, &TimeZone::system());
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

/// Record a use of `stored` at `now`. Runs a transaction only if the use
/// stored in `vw` falls on an earlier date in `zone` than `now`, so a later
/// sign-in that day writes nothing. The transaction reloads the vault, so an
/// edit saved since `vw` was loaded is kept. It saves only if the reloaded
/// vault also holds an earlier use. Returns whether the vault was saved.
fn record_use(
    files: &VaultWriter,
    vw: &VaultHandle,
    stored: &PasskeyCredential,
    now: i64,
    zone: &TimeZone,
) -> Result<bool, Error> {
    let last_used = vw
        .get_secret_overview(&stored.item_key, &stored.credential_key)?
        .and_then(|cred| cred.last_used_day_at);
    if !last_used::is_later_day(last_used, now, zone) {
        return Ok(false);
    }
    let committed = files.write_unlocked::<_, Error>(vw, |fresh| {
        fresh.mark_credential_used_in(&stored.item_key, &stored.credential_key, now, zone)
    })?;
    Ok(committed.changed)
}

// MARK: - On-disk record

/// How a passkey is written into a credential's value. Byte fields are base64
/// so the record stays plain JSON.
#[derive(Serialize, Deserialize)]
struct StoredPasskey {
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
    /// Fields this build does not know, written back unchanged on a rewrite.
    /// A field that a newer build adds is not dropped by a rename here.
    #[serde(flatten)]
    unknown: serde_json::Map<String, serde_json::Value>,
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
    let record: StoredPasskey = serde_json::from_str(value).ok()?;
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

/// WebAuthn credential id in base64url without padding, as the stored record
/// holds it.
pub fn encode_credential_id(id: &[u8]) -> String {
    B64URL.encode(id)
}

fn encode(passkey: &Passkey, created_at: Option<i64>) -> Result<String, Error> {
    let key = passkey
        .key
        .clone()
        .to_vec()
        .map_err(|e| Error::Passkey(format!("Failed to encode the COSE key: {e}")))?;
    let record = StoredPasskey {
        rp_id: passkey.rp_id.clone(),
        credential_id: encode_credential_id(passkey.credential_id.as_slice()),
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
        unknown: serde_json::Map::new(),
    };
    serde_json::to_string(&record)
        .map_err(|e| Error::Passkey(format!("Failed to encode the passkey: {e}")))
}

fn decode(value: &str) -> Result<Passkey, Error> {
    let record: StoredPasskey = serde_json::from_str(value)
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
/// Holds the unlocked vault for the length of one request. A new passkey is
/// written into the in-memory vault and kept in `staged`, and [`create`]
/// writes it to disk in a transaction. A failed request leaves nothing behind
/// on disk.
struct PasskeyCredentialStore<'a> {
    vw: &'a mut VaultHandle,
    /// Where a new passkey goes. Read by `save_credential` only.
    target: PasskeyTarget,
    /// The passkey `save_credential` wrote, if any.
    staged: Arc<Mutex<Option<StagedPasskey>>>,
}

/// A passkey the authenticator saved, kept so it can be written again into a
/// fresh copy of the vault.
struct StagedPasskey {
    cred: Passkey,
    /// Encoded record, with the creation time of the registration.
    value: String,
    item_title: Option<String>,
    credential_title: String,
}

impl StagedPasskey {
    /// Write the passkey into `vw` at `target`. Returns the item key.
    fn write(&self, vw: &mut VaultHandle, target: &PasskeyTarget) -> Result<String, Error> {
        store_passkey(
            vw,
            &self.cred,
            self.value.clone(),
            self.item_title.as_deref(),
            &self.credential_title,
            target,
        )
    }
}

impl<'a> PasskeyCredentialStore<'a> {
    fn new(vw: &'a mut VaultHandle, target: PasskeyTarget) -> Self {
        Self {
            vw,
            target,
            staged: Arc::new(Mutex::new(None)),
        }
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
        let staged = StagedPasskey {
            cred: cred.clone(),
            value: encode(cred, now_unix())?,
            item_title: item_title.map(str::to_string),
            credential_title: credential_title.to_string(),
        };
        staged.write(self.vw, &self.target)?;
        *self.staged.lock().unwrap_or_else(|e| e.into_inner()) = Some(staged);
        Ok(())
    }
}

/// Write a passkey record into `target` in an unlocked vault, creating a login
/// item for the relying party when the target is a new login. Returns the item
/// key. The caller saves the vault. A writer outside the UI
/// ([`VaultHandle::write_outside_ui`]), which requests a write to the passkey
/// value.
fn store_passkey(
    vw: &mut VaultHandle,
    cred: &Passkey,
    value: String,
    item_title: Option<&str>,
    credential_title: &str,
    target: &PasskeyTarget,
) -> Result<String, Error> {
    vw.write_outside_ui();
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
    let credential_key = PasskeyCredentialStore::credential_key(&cred.credential_id);
    vw.add_secret(
        &item_key,
        &credential_key,
        credential_title,
        FieldKind::Passkey,
        SecretString::from(value),
    )?;
    Ok(item_key)
}

/// Raw record, credential title, and last used day of a stored passkey, read
/// so it can move to another item or vault.
pub struct PasskeyRecord {
    pub value: SecretString,
    pub title: String,
    pub last_used_day_at: Option<i64>,
}

/// Read the passkey at `item_key`/`credential_key`. Fails when the credential
/// is not a passkey.
pub fn read_record(
    vw: &VaultHandle,
    item_key: &str,
    credential_key: &str,
) -> Result<PasskeyRecord, Error> {
    let overview = vw
        .get_secret_overview(item_key, credential_key)?
        .filter(|cred| matches!(cred.kind, FieldKind::Passkey))
        .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{credential_key}")))?;
    let title = overview.title.clone();
    let last_used_day_at = overview.last_used_day_at;
    let value = vw
        .get_secret(item_key, credential_key)?
        .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{credential_key}")))?;
    Ok(PasskeyRecord {
        value: SecretString::from(value.expose_secret().clone()),
        title,
        last_used_day_at,
    })
}

/// WebAuthn credential id of the passkey at `item_key`/`credential_key`. Fails
/// when the credential is not a passkey or its record does not decode.
pub fn webauthn_credential_id(
    vw: &VaultHandle,
    item_key: &str,
    credential_key: &str,
) -> Result<Vec<u8>, Error> {
    let record = read_record(vw, item_key, credential_key)?;
    Ok(decode(record.value.expose_secret())?
        .credential_id
        .as_slice()
        .to_vec())
}

/// Store a record read by [`read_record`] in `target`, with its last used
/// day. If the target credential already holds the passkey with a use on the
/// same date or later, its own time is kept. The record must decode, so a
/// damaged value is refused rather than copied. The caller saves the vault.
/// Returns the audit ids of the stored passkey.
pub fn write_record(
    vw: &mut VaultHandle,
    record: &PasskeyRecord,
    target: &PasskeyTarget,
) -> Result<SubjectIds, Error> {
    let value = record.value.expose_secret().to_string();
    let cred = decode(&value)?;
    let item_key = store_passkey(vw, &cred, value, None, &record.title, target)?;
    let credential_key = PasskeyCredentialStore::credential_key(&cred.credential_id);
    if let Some(at) = record.last_used_day_at {
        vw.mark_credential_used(&item_key, &credential_key, at)?;
    }
    vw.credential_ids(&item_key, &credential_key)
}

/// Move the passkey at `item_key`/`credential_key` to `target` in the same
/// vault. The credential keeps its id, title, metadata, last used day, and
/// previous values. A new login is created as [`store_passkey`] creates it. If
/// the target item already holds the passkey key, that credential is the same
/// passkey. It then takes the record through [`write_record`], and the source
/// is removed. A move to the source item changes nothing. The caller saves the
/// vault. Returns the audit ids of the moved passkey. A writer outside the UI.
pub fn move_within_vault(
    vw: &mut VaultHandle,
    item_key: &str,
    credential_key: &str,
    target: &PasskeyTarget,
) -> Result<SubjectIds, Error> {
    vw.write_outside_ui();
    let record = read_record(vw, item_key, credential_key)?;
    let cred = decode(record.value.expose_secret())?;
    let new_key = PasskeyCredentialStore::credential_key(&cred.credential_id);
    let dest_item_key = match target {
        PasskeyTarget::Item(key) if key == item_key => {
            return vw.credential_ids(item_key, credential_key);
        },
        PasskeyTarget::Item(key) => {
            if vw.get_item_overview(key)?.is_none() {
                return Err(Error::InvalidItemKey(key.clone()));
            }
            if vw.get_secret_overview(key, &new_key)?.is_some() {
                let ids = write_record(vw, &record, target)?;
                remove_record(vw, item_key, credential_key)?;
                return Ok(ids);
            }
            key.clone()
        },
        PasskeyTarget::NewLogin => {
            autofill::add_passkey_login(vw, &cred.rp_id, None, cred.username.as_deref())?
        },
    };
    vw.transfer_credential(item_key, credential_key, &dest_item_key, &new_key, None)?;
    vw.credential_ids(&dest_item_key, &new_key)
}

/// Remove the passkey at `item_key`/`credential_key` after it was copied by
/// [`write_record`]. The passkey is deleted and purged immediately rather than
/// kept in the deleted credentials. A copy left there would keep the private
/// key in this vault, and restoring it would give two passkeys with one
/// credential id. Fails when the credential is not a passkey. The caller saves
/// the vault. A writer outside the UI.
pub fn remove_record(
    vw: &mut VaultHandle,
    item_key: &str,
    credential_key: &str,
) -> Result<(), Error> {
    vw.write_outside_ui();
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
/// since it differs only in the name, and no history entry is added or purged.
/// The caller saves the vault. A writer outside the UI, which requests a
/// write to the passkey value.
pub fn rename_account(
    vw: &mut VaultHandle,
    item_key: &str,
    credential_key: &str,
    name: &str,
) -> Result<(), Error> {
    vw.write_outside_ui();
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::Passkey("The new account name is empty".to_string()));
    }
    let record = read_record(vw, item_key, credential_key)?;
    let mut stored: StoredPasskey = serde_json::from_str(record.value.expose_secret())
        .map_err(|e| Error::Passkey(format!("Failed to parse the passkey: {e}")))?;
    stored.username = Some(name.to_string());
    stored.user_display_name = Some(name.to_string());
    let value = serde_json::to_string(&stored)
        .map_err(|e| Error::Passkey(format!("Failed to encode the passkey: {e}")))?;

    vw.replace_secret(
        item_key,
        credential_key,
        name,
        FieldKind::Passkey,
        SecretString::from(value),
    )
}

#[async_trait]
impl CredentialStore for PasskeyCredentialStore<'_> {
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
mod tests;
