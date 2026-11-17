use secrecy::ExposeSecret;
use ssh_key::Signature;

use super::super::ssh::vault_keys;
use super::super::wire::{WireResponse, b64_encode};
use super::VaultPayload;
use super::serve::{AccessIds, Served, open_vault};
use crate::core::auth::ForeignContext;
use crate::secrets::vaults::ssh_keys::SshKeyRecord;
use crate::secrets::vaults::{FieldKind, VaultCatalog, VaultHandle};
use crate::ssh::rsa_signing::sign_with_flags;

/// Serve a [`VaultAction::SignSshKey`](super::VaultAction): sign with one
/// credential's key. Only the vault of the credential is unlocked.
///
/// The cache entry that led here is not trusted. If the credential does not
/// hold a key with the requested fingerprint, the request is refused and the
/// listing cache entries of this vault are rewritten from the unlocked vault.
pub(super) fn sign_ssh_key(
    vaults: &VaultCatalog,
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    fingerprint: &str,
    payload: Option<VaultPayload>,
    context: ForeignContext,
) -> Result<Served, String> {
    let Some(VaultPayload::SignSshKey(payload)) = payload else {
        return Err("Missing SSH signing payload".to_string());
    };
    let vh = open_vault(vaults, vault_key, context)?;
    let signed = sign_with_stored_key(
        &vh,
        item_key,
        credential_key,
        fingerprint,
        &payload.data,
        payload.flags,
    );
    let signature = match signed {
        Ok(signature) => signature,
        Err(message) => {
            let entries = vault_keys::collect(vault_key, &vh);
            if let Err(e) = vault_keys::replace_vault(&payload.cache_path, vault_key, entries) {
                log::error!("Failed to rewrite the vault SSH key listing: {e}");
            }
            return Err(message);
        },
    };
    Ok(Served::new(
        WireResponse::Signed {
            algorithm: signature.algorithm().to_string(),
            signature: b64_encode(signature.as_bytes()),
        },
        AccessIds::One(vh.credential_ids(item_key, credential_key)?),
    ))
}

/// Sign `data` with the key of credential `credential_key`, after checking that
/// the credential is an SSH key with fingerprint `fingerprint`. `flags` select
/// the hash of an RSA key. The key is dropped before returning.
pub(super) fn sign_with_stored_key(
    vh: &VaultHandle,
    item_key: &str,
    credential_key: &str,
    fingerprint: &str,
    data: &[u8],
    flags: u32,
) -> Result<Signature, String> {
    let overview = vh
        .get_secret_overview(item_key, credential_key)
        .map_err(|e| format!("Failed to read the credential: {e}"))?
        .ok_or("The credential does not exist")?;
    if overview.kind != FieldKind::SshKey {
        return Err("The credential is not an SSH key".to_string());
    }
    let value = vh
        .get_secret(item_key, credential_key)
        .map_err(|e| format!("Failed to read the key: {e}"))?
        .ok_or("The credential has no value")?;
    let record = SshKeyRecord::from_value(value.expose_secret()).map_err(|e| e.to_string())?;
    if !record.ssh_use {
        return Err("SSH use is not allowed for this key".to_string());
    }
    let key = record
        .private_key_for(fingerprint)
        .map_err(|e| e.to_string())?;
    sign_with_flags(key.key_data(), data, flags).map_err(|e| format!("Failed to sign: {e}"))
}

#[cfg(test)]
mod tests;
