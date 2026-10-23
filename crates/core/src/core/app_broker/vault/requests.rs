use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use secrecy::{ExposeSecret, SecretString};

use super::super::BrokerError;
use super::super::client::send_request;
use super::super::wire::{
    BrowserClient, WirePrfAssertion, WirePrfCredentialValues, WirePrfRegistration, WirePrfValues,
    WireRequest, WireResponse,
};
use super::{
    BrokerVaultItem, ResolvePurpose, VaultRef, WireExportMode, WireImportIdentity, WireLogin,
};
use crate::audit::SubjectIds;
use crate::secrets::vaults::passkey;

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
    match send_request(&request)? {
        WireResponse::VaultItems { items } => Ok(items),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault listing".to_string(),
        )),
    }
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
    match send_request(&request)? {
        WireResponse::VaultSecret { value } => Ok(value.map(SecretString::from)),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault secret read".to_string(),
        )),
    }
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
    match send_request(&request)? {
        WireResponse::ResolvedSecrets { values } => Ok(values
            .into_iter()
            .map(|v| v.map(SecretString::from))
            .collect()),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to secret resolution".to_string(),
        )),
    }
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
    match send_request(&request)? {
        WireResponse::VaultWritten { created } => Ok(created),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault secret write".to_string(),
        )),
    }
}

/// Ask the app to unlock every named vault and write an encrypted bundle to
/// `dest_path`. Blocking, same as [`request_vault_items`].
pub fn request_export_vaults(
    vault_keys: &[String],
    dest_path: &str,
    mode: WireExportMode,
    include_passkeys: bool,
    caller: Option<&str>,
) -> Result<u32, BrokerError> {
    let request = WireRequest::ExportVaults {
        vault_keys: vault_keys.to_vec(),
        dest_path: dest_path.to_string(),
        mode,
        exclude_passkeys: !include_passkeys,
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultsExported { count } => Ok(count),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault export".to_string(),
        )),
    }
}

/// Ask the app to import the selected vaults from a bundle, re-wrapping each
/// file key with the local encryption key. `selection` is `(bundle vault id,
/// target key)` pairs. Returns the keys of the imported vaults. Blocking, same
/// as [`request_vault_items`].
pub fn request_import_vaults(
    import_path: &str,
    identity: WireImportIdentity,
    selection: &[(String, String)],
    caller: Option<&str>,
) -> Result<Vec<String>, BrokerError> {
    let request = WireRequest::ImportVaults {
        import_path: import_path.to_string(),
        identity,
        selection: selection.to_vec(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultsImported { keys } => Ok(keys),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault import".to_string(),
        )),
    }
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
    match send_request(&request)? {
        WireResponse::VaultLinked { vault_key, name } => Ok((vault_key, name)),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault add".to_string(),
        )),
    }
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
        client: BrowserClient::default(),
    };
    match send_request(&wire)? {
        WireResponse::PasskeyRegistered {
            credential_id,
            attestation_object,
            prf,
        } => Ok(passkey::CreatePasskeyResponse {
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
        }),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to passkey registration".to_string(),
        )),
    }
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
        client: BrowserClient::default(),
    };
    match send_request(&wire)? {
        WireResponse::PasskeyAsserted {
            credential_id,
            user_handle,
            authenticator_data,
            signature,
            prf,
        } => Ok(passkey::AssertPasskeyResponse {
            credential_id: b64_decode(&credential_id)?,
            user_handle: b64_decode(&user_handle)?,
            authenticator_data: b64_decode(&authenticator_data)?,
            signature: b64_decode(&signature)?,
            prf: prf.as_ref().map(decode_prf_values).transpose()?,
            // The wire does not carry where the passkey is stored.
            item_key: String::new(),
            credential_key: String::new(),
        }),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to passkey assertion".to_string(),
        )),
    }
}

pub(super) fn b64_encode(bytes: &[u8]) -> String {
    b64.encode(bytes)
}

pub(super) fn decode_prf_values(values: &WirePrfValues) -> Result<passkey::PrfValues, BrokerError> {
    Ok(passkey::PrfValues {
        first: b64_decode(&values.first)?,
        second: values.second.as_deref().map(b64_decode).transpose()?,
    })
}

pub(super) fn b64_decode(value: &str) -> Result<Vec<u8>, BrokerError> {
    b64.decode(value)
        .map_err(|e| BrokerError::Failed(format!("Malformed base64 in passkey response: {e}")))
}
