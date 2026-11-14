use secrecy::{ExposeSecret, SecretString};

use super::super::BrokerError;
use super::super::client::send_request;
use super::super::wire::{
    WireExportMode, WireImportIdentity, WireImportSelection, WirePrfAssertion,
    WirePrfCredentialValues, WirePrfRegistration, WirePrfValues, WireRequest, WireResponse,
    b64_decode, b64_encode, decode_prf_values,
};
use super::{BrokerVaultItem, ResolvePurpose, VaultRef, WireLogin};
use crate::audit::SubjectIds;
use crate::secrets::vaults::passkey;

/// Send `request` and read the response with `accept`. `accept` returns
/// `Ok(None)` for a response it does not expect, which becomes a failure naming
/// `what`. A cancelled or failed response maps to the matching error without
/// `accept`.
fn exchange<T>(
    request: &WireRequest,
    what: &str,
    accept: impl FnOnce(WireResponse) -> Result<Option<T>, BrokerError>,
) -> Result<T, BrokerError> {
    match send_request(request)? {
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        response => accept(response)?
            .ok_or_else(|| BrokerError::Failed(format!("Unexpected response to {what}"))),
    }
}

/// Ask the app to unlock a vault and return its item overview. Blocking: it may
/// wait for the user to answer a prompt, so call it from a thread that can
/// block. Starts the app if it is not already running.
pub fn request_vault_items(
    vault_key: &str,
    caller: Option<&str>,
) -> Result<Vec<BrokerVaultItem>, BrokerError> {
    let request = WireRequest::ListVaultItems {
        vault_key: vault_key.to_string(),
        caller: caller.map(String::from),
    };
    exchange(&request, "vault listing", |response| match response {
        WireResponse::VaultItems { items } => Ok(Some(items)),
        _ => Ok(None),
    })
}

/// Ask the app to unlock a vault and return one credential's secret. `None`
/// means the credential does not exist. Blocking, same as
/// [`request_vault_items`].
pub fn request_vault_secret(
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    caller: Option<&str>,
) -> Result<Option<SecretString>, BrokerError> {
    let request = WireRequest::ReadVaultSecret {
        vault_key: vault_key.to_string(),
        item_key: item_key.to_string(),
        credential_key: credential_key.to_string(),
        caller: caller.map(String::from),
    };
    exchange(&request, "vault secret read", |response| match response {
        WireResponse::VaultSecret { value } => Ok(Some(value.map(SecretString::from))),
        _ => Ok(None),
    })
}

/// Details of a file the app decrypted to the requested path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileReadSummary {
    pub name: String,
    pub mime: Option<String>,
    /// Plaintext size in bytes.
    pub size: u64,
}

/// Ask the app to decrypt one file credential to `dest_path`, which must be
/// absolute and must not exist. Blocking, same as [`request_vault_items`].
pub fn request_read_vault_file(
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    dest_path: &str,
    caller: Option<&str>,
) -> Result<FileReadSummary, BrokerError> {
    let request = WireRequest::ReadVaultFile {
        vault_key: vault_key.to_string(),
        item_key: item_key.to_string(),
        credential_key: credential_key.to_string(),
        dest_path: dest_path.to_string(),
        caller: caller.map(String::from),
    };
    exchange(&request, "vault file read", |response| match response {
        WireResponse::VaultFileRead { name, mime, size } => {
            Ok(Some(FileReadSummary { name, mime, size }))
        },
        _ => Ok(None),
    })
}

/// Ask the app to resolve many `axo://` references at once, behind one prompt.
/// The returned vector is positionally matched to `refs`; `None` means that
/// reference does not resolve. Blocking, same as [`request_vault_items`].
pub fn request_resolve_secrets(
    refs: &[VaultRef],
    purpose: ResolvePurpose,
    caller: Option<&str>,
) -> Result<Vec<Option<SecretString>>, BrokerError> {
    let request = WireRequest::ResolveSecrets {
        refs: refs.to_vec(),
        purpose,
        caller: caller.map(String::from),
    };
    exchange(&request, "secret resolution", |response| match response {
        WireResponse::ResolvedSecrets { values } => Ok(Some(
            values
                .into_iter()
                .map(|v| v.map(SecretString::from))
                .collect(),
        )),
        _ => Ok(None),
    })
}

/// Ask the app to unlock a vault and write one credential's secret value,
/// creating the item or credential if needed. Returns whether the item was
/// newly created. Blocking, same as [`request_vault_items`].
pub fn request_write_vault_secret(
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    title: &str,
    value: &SecretString,
    login: Option<WireLogin>,
    caller: Option<&str>,
) -> Result<bool, BrokerError> {
    let request = WireRequest::WriteVaultSecret {
        vault_key: vault_key.to_string(),
        item_key: item_key.to_string(),
        credential_key: credential_key.to_string(),
        title: title.to_string(),
        value: value.expose_secret().to_string(),
        login,
        caller: caller.map(String::from),
    };
    exchange(&request, "vault secret write", |response| match response {
        WireResponse::VaultWritten { created } => Ok(Some(created)),
        _ => Ok(None),
    })
}

/// Outcome of an export the app served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportSummary {
    /// Vaults written into the bundle.
    pub vaults: u32,
    /// File blobs that the bundle lacks. Their files are in the bundle as
    /// records only.
    pub missing_blobs: u32,
}

/// Ask the app to unlock every named vault and write an encrypted bundle to
/// `dest_path`. Blocking, same as [`request_vault_items`].
pub fn request_export_vaults(
    vault_keys: &[String],
    dest_path: &str,
    mode: WireExportMode,
    include_passkeys: bool,
    caller: Option<&str>,
) -> Result<ExportSummary, BrokerError> {
    let request = WireRequest::ExportVaults {
        vault_keys: vault_keys.to_vec(),
        dest_path: dest_path.to_string(),
        mode,
        exclude_passkeys: !include_passkeys,
        caller: caller.map(String::from),
    };
    exchange(&request, "vault export", |response| match response {
        WireResponse::VaultsExported {
            count,
            missing_blobs,
        } => Ok(Some(ExportSummary {
            vaults: count,
            missing_blobs,
        })),
        _ => Ok(None),
    })
}

/// Ask the app to import the selected vaults from a bundle, re-wrapping each
/// file key with the local encryption key. Returns the keys of the imported
/// vaults. Blocking, same as [`request_vault_items`].
pub fn request_import_vaults(
    import_path: &str,
    identity: WireImportIdentity,
    selection: Vec<WireImportSelection>,
    caller: Option<&str>,
) -> Result<Vec<String>, BrokerError> {
    let request = WireRequest::ImportVaults {
        import_path: import_path.to_string(),
        identity,
        selection,
        caller: caller.map(String::from),
    };
    exchange(&request, "vault import", |response| match response {
        WireResponse::VaultsImported { keys } => Ok(Some(keys)),
        _ => Ok(None),
    })
}

/// Ask the app to unlock the vault at `path` to validate it, then register it
/// as an external vault. Returns the vault key and name. Blocking, same as
/// [`request_vault_items`].
pub fn request_add_external_vault(
    path: &str,
    caller: Option<&str>,
) -> Result<(String, Option<String>), BrokerError> {
    let request = WireRequest::AddExternalVault {
        path: path.to_string(),
        caller: caller.map(String::from),
    };
    exchange(&request, "vault add", |response| match response {
        WireResponse::VaultLinked { vault_key, name } => Ok(Some((vault_key, name))),
        _ => Ok(None),
    })
}

/// Ask the app to register a passkey against an unlocked vault and return the
/// attestation. Blocking, same as [`request_vault_items`].
pub fn request_create_passkey(
    request: passkey::CreatePasskeyRequest,
    caller: Option<&str>,
) -> Result<passkey::CreatePasskeyResponse, BrokerError> {
    let wire = WireRequest::CreatePasskey {
        rp_id: request.rp_id.clone(),
        rp_name: request.rp_name.clone(),
        user_handle: b64_encode(&request.user_handle),
        user_name: request.user_name.clone(),
        user_display_name: request.user_display_name.clone(),
        client_data_hash: b64_encode(&request.client_data_hash),
        algorithms: request.algorithms.clone(),
        excluded_credentials: request
            .excluded_credentials
            .iter()
            .map(|c| b64_encode(c))
            .collect(),
        prf: request.prf.as_ref().map(|p| WirePrfRegistration {
            eval: p.eval.as_ref().map(WirePrfValues::encode),
        }),
        origin: None,
        caller: caller.map(String::from),
    };
    exchange(&wire, "passkey registration", |response| match response {
        WireResponse::PasskeyRegistered {
            credential_id,
            attestation_object,
            prf,
        } => Ok(Some(passkey::CreatePasskeyResponse {
            credential_id: b64_decode(&credential_id)?,
            attestation_object: b64_decode(&attestation_object)?,
            prf: prf
                .map(|p| -> Result<_, BrokerError> {
                    Ok(passkey::PrfRegistrationOutput {
                        enabled: p.enabled,
                        results: p.results.as_ref().map(decode_prf_values).transpose()?,
                    })
                })
                .transpose()?,
            // The wire does not carry where the passkey is stored.
            ids: SubjectIds::default(),
        })),
        _ => Ok(None),
    })
}

/// Ask the app to sign an assertion challenge with a stored passkey. Blocking,
/// same as [`request_vault_items`].
pub fn request_assert_passkey(
    request: passkey::AssertPasskeyRequest,
    caller: Option<&str>,
) -> Result<passkey::AssertPasskeyResponse, BrokerError> {
    let wire = WireRequest::AssertPasskey {
        rp_id: request.rp_id.clone(),
        client_data_hash: b64_encode(&request.client_data_hash),
        allowed_credentials: request
            .allowed_credentials
            .iter()
            .map(|c| b64_encode(c))
            .collect(),
        choose_account: false,
        prf: request.prf.as_ref().map(|p| WirePrfAssertion {
            eval: p.eval.as_ref().map(WirePrfValues::encode),
            eval_by_credential: p
                .eval_by_credential
                .iter()
                .map(|(id, values)| WirePrfCredentialValues {
                    credential_id: b64_encode(id),
                    first: b64_encode(&values.first),
                    second: values.second.as_deref().map(b64_encode),
                })
                .collect(),
        }),
        origin: None,
        caller: caller.map(String::from),
    };
    exchange(&wire, "passkey assertion", |response| match response {
        WireResponse::PasskeyAsserted {
            credential_id,
            user_handle,
            authenticator_data,
            signature,
            prf,
        } => Ok(Some(passkey::AssertPasskeyResponse {
            credential_id: b64_decode(&credential_id)?,
            user_handle: b64_decode(&user_handle)?,
            authenticator_data: b64_decode(&authenticator_data)?,
            signature: b64_decode(&signature)?,
            prf: prf.as_ref().map(decode_prf_values).transpose()?,
            // The wire does not carry where the passkey is stored.
            item_key: String::new(),
            credential_key: String::new(),
        })),
        _ => Ok(None),
    })
}
