use std::path::Path;

use secrecy::ExposeSecret;
use ssh_key::{PrivateKey, Signature};
use zeroize::Zeroizing;

use super::super::ssh::vault_keys;
use super::super::wire::{WireResponse, b64_encode};
use super::audit::access_event;
use super::serve::{AccessIds, Served, open_vault};
use super::{SignSshKeyPayload, VaultAccessPrompt, VaultAction, VaultAuthorizer, VaultPayload};
use crate::audit::{self, Actor, Outcome};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::secrets::keychain::managed_key::KeyPolicy;
use crate::secrets::vaults::ssh_keys::SshKeyRecord;
use crate::secrets::vaults::{FieldKind, VaultCatalog, VaultHandle};
use crate::ssh::app_grants;
use crate::ssh::rsa_signing::sign_with_flags;

/// Sign without a prompt for an app that holds a grant on the key. The vault is
/// opened on the app's shared context, which is authenticated only while the
/// app is unlocked. Returns `None` if no grant covers the request, the app is
/// locked, or the signature could not be made. The request prompts instead.
pub(in super::super) async fn serve_granted_sign(
    authorizer: &dyn VaultAuthorizer,
    vaults: &VaultCatalog,
    prompt: &VaultAccessPrompt,
    payload: &SignSshKeyPayload,
    actor: &Actor,
) -> Option<WireResponse> {
    let VaultAction::SignSshKey {
        item_key,
        credential_key,
        fingerprint,
        ..
    } = &prompt.action
    else {
        return None;
    };
    let (vaults, vault_key) = (vaults.clone(), prompt.vault_key.clone());
    let (item_key, credential_key) = (item_key.clone(), credential_key.clone());
    let fingerprint = fingerprint.clone();
    let chain = prompt.caller_chain.clone();
    let (data, flags) = (payload.data.clone(), payload.flags);

    let (signature, ids, grant) = tokio::task::spawn_blocking(move || {
        let grants = app_grants::load()
            .inspect_err(|e| log::warn!("Could not read SSH app grants: {e}"))
            .ok()?;
        let grant = app_grants::find_match(
            &grants,
            &fingerprint,
            KeyPolicy::Default,
            &chain,
            time::OffsetDateTime::now_utc(),
        )?
        .clone();
        let vh = vaults
            .open(&vault_key, AuthContext::SharedThreadLocal)
            .inspect_err(|e| log::debug!("Granted SSH sign needs a prompt: {e}"))
            .ok()?;
        let signature =
            sign_with_stored_key(&vh, &item_key, &credential_key, &fingerprint, &data, flags)
                .inspect_err(|e| {
                    log::warn!(
                        "Signing for granted app {} failed: {e}",
                        grant.app.bundle_id
                    )
                })
                .ok()?;
        let ids = vh.credential_ids(&item_key, &credential_key).ok()?;
        Some((signature, ids, grant))
    })
    .await
    .inspect_err(|e| log::warn!("Granted SSH sign task failed: {e}"))
    .ok()
    .flatten()?;

    let response = WireResponse::Signed {
        algorithm: signature.algorithm().to_string(),
        signature: b64_encode(signature.as_bytes()),
    };
    let event = access_event(
        prompt,
        actor,
        Outcome::Succeeded,
        Some(&response),
        &AccessIds::One(ids),
        None,
    );
    audit::record(event.detail("grant", format!("app:{}", grant.app.bundle_id)));
    authorizer.notify_preapproved(prompt.clone(), None).await;
    Some(response)
}

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
            rewrite_listing(&vh, vault_key, &payload.cache_path);
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

/// Serve a [`VaultAction::LoadSshKey`](super::VaultAction): return the private
/// key of one credential for the agent to hold. Only the vault of the
/// credential is unlocked.
///
/// The cache entry that led here is not trusted, as for [`sign_ssh_key`]. The
/// credential must also have auto-load on.
pub(super) fn load_ssh_key(
    vaults: &VaultCatalog,
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    fingerprint: &str,
    payload: Option<VaultPayload>,
    context: ForeignContext,
) -> Result<Served, String> {
    let Some(VaultPayload::LoadSshKey(payload)) = payload else {
        return Err("Missing SSH key load payload".to_string());
    };
    let vh = open_vault(vaults, vault_key, context)?;
    let key = match read_stored_key(&vh, item_key, credential_key, fingerprint, true) {
        Ok(key) => key,
        Err(message) => {
            rewrite_listing(&vh, vault_key, &payload.cache_path);
            return Err(message);
        },
    };
    let text = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| format!("Failed to encode the key: {e}"))?;
    Ok(Served::new(
        WireResponse::VaultKey {
            private_key: Zeroizing::new(b64_encode(text.as_bytes())),
        },
        AccessIds::One(vh.credential_ids(item_key, credential_key)?),
    ))
}

/// Rewrite the listing cache entries of vault `vault_key` from the unlocked
/// vault `vh`.
fn rewrite_listing(vh: &VaultHandle, vault_key: &str, cache_path: &Path) {
    let entries = vault_keys::collect(vault_key, vh);
    if let Err(e) = vault_keys::replace_vault(cache_path, vault_key, entries) {
        log::error!("Failed to rewrite the vault SSH key listing: {e}");
    }
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
    let key = read_stored_key(vh, item_key, credential_key, fingerprint, false)?;
    sign_with_flags(key.key_data(), data, flags).map_err(|e| format!("Failed to sign: {e}"))
}

/// The private key of credential `credential_key`, after checking that the
/// credential is an SSH key with fingerprint `fingerprint` and SSH use on. With
/// `require_auto_load`, auto-load must be on as well.
fn read_stored_key(
    vh: &VaultHandle,
    item_key: &str,
    credential_key: &str,
    fingerprint: &str,
    require_auto_load: bool,
) -> Result<PrivateKey, String> {
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
    if require_auto_load && !record.auto_load {
        return Err("Auto-load is not allowed for this key".to_string());
    }
    record
        .private_key_for(fingerprint)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests;
