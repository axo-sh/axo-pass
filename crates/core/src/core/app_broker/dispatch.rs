//! Routes one request from a verified peer to the authorizer that serves it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;

use super::access::{RequestScope, client_identity, request_actor, requester_for, vouched_caller};
use super::in_flight::InFlightRequest;
use super::wire::{WireRequest, WireResponse, decode_b64};
use super::{
    Authorizers, ConfirmPrompt, PassphraseKind, PassphrasePrompt, SignPrompt, age, gpg, keychain,
    ssh, vault,
};
use crate::core::provenance::PeerIdentity;
use crate::secrets::vaults::autofill::check_rp_id;
use crate::secrets::vaults::passkey::{AssertPasskeyRequest, CreatePasskeyRequest, PasskeyTarget};

/// Serve one request from a verified peer, whichever transport carried it.
///
/// `disconnected` resolves when the client goes away. The request is then
/// abandoned, which ends its prompt, and still runs to completion so the app's
/// `end` is called. Nobody is left to read the response, so `None` is returned.
pub(super) async fn serve_request(
    request: WireRequest,
    peer: &PeerIdentity,
    scope: RequestScope,
    authorizers: Authorizers,
    disconnected: impl Future<Output = ()>,
) -> std::io::Result<Option<WireResponse>> {
    if !scope.allows(&request) {
        log::warn!("App broker refused a request outside the {scope:?} scope");
        return Ok(Some(WireResponse::Failed {
            message: "This client may not send that request".to_string(),
        }));
    }

    // Resolved once per connection and handed to whichever authorizer serves
    // the request, so the grant the app hands out is attributed to the process
    // we verified rather than to a caller string alone.
    let client_id = client_identity(scope, request.client());
    let actor = request_actor(
        peer,
        vouched_caller(scope, &client_id, request.caller().map(String::from)).as_deref(),
        request.caller_chain(),
    );
    let caller_chain = actor.chain_detail.clone();

    let in_flight = InFlightRequest::default();
    let serve = async {
        Ok::<_, std::io::Error>(match request {
            WireRequest::ListIdentities => {
                log::debug!("App broker request: list identities");
                tokio::task::spawn_blocking(ssh::list_identities_locally)
                    .await
                    .unwrap_or_else(|e| Err(format!("Failed to list managed keys: {e}")))
                    .map_or_else(
                        |message| WireResponse::Failed { message },
                        |keys| WireResponse::Identities { keys },
                    )
            },
            WireRequest::Sign {
                key_label,
                fingerprint,
                comment,
                caller,
                caller_chain: _,
                purpose,
                data,
                // Secure Enclave keys are ECDSA P-256 and have no flag-selected
                // hash.
                flags: _,
            } => {
                let data = b64
                    .decode(&data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let prompt = SignPrompt {
                    key_label,
                    fingerprint,
                    comment,
                    caller,
                    caller_chain: caller_chain.clone(),
                    managed: true,
                    policy: None,
                    grant_candidate: None,
                    purpose,
                };
                log::debug!("App broker request: {prompt:?}");
                ssh::sign_managed(&*authorizers.sign, prompt, actor, data, &in_flight).await
            },
            WireRequest::AuthorizeKeyUse {
                fingerprint,
                comment,
                caller,
                caller_chain: _,
                purpose,
                allow_grants,
            } => {
                let prompt = SignPrompt {
                    key_label: String::new(),
                    fingerprint,
                    comment,
                    caller,
                    caller_chain: caller_chain.clone(),
                    managed: false,
                    policy: None,
                    grant_candidate: None,
                    purpose,
                };
                log::debug!(
                    "App broker request: authorize key use {prompt:?}, allow grants {allow_grants}"
                );
                ssh::authorize_key_use(&*authorizers.sign, prompt, actor, allow_grants, &in_flight)
                    .await
            },
            WireRequest::GetPassphrase {
                key_id,
                description,
                prompt,
                error_message,
                caller,
                caller_chain: _,
            } => {
                let prompt = PassphrasePrompt {
                    kind: PassphraseKind::Gpg,
                    key_id,
                    description,
                    prompt,
                    error_message,
                    caller,
                    caller_chain: caller_chain.clone(),
                };
                log::debug!("App broker request: {prompt:?}");
                gpg::get_passphrase(&*authorizers.passphrase, prompt, actor, &in_flight).await
            },
            WireRequest::GetSshPassphrase {
                key_id,
                prompt,
                caller,
                caller_chain: _,
            } => {
                let prompt = PassphrasePrompt {
                    kind: PassphraseKind::Ssh,
                    key_id,
                    description: None,
                    prompt: Some(prompt),
                    error_message: None,
                    caller,
                    caller_chain: caller_chain.clone(),
                };
                log::debug!("App broker request: {prompt:?}");
                ssh::get_passphrase(&*authorizers.passphrase, prompt, actor, &in_flight).await
            },
            WireRequest::ListVaultItems { vault_key, caller } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key,
                    caller,
                    caller_chain: caller_chain.clone(),
                    client: client_id.clone(),
                    action: vault::VaultAction::ListItems,
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(&*authorizers.vault, prompt, actor, None, &in_flight)
                    .await
            },
            WireRequest::ListLogins {
                url,
                frame_url,
                all,
                requester,
                caller,
                client: _,
            } => match vault::LoginPage::parse(&url, &frame_url, requester_for(scope, requester)) {
                Ok(page) => {
                    let prompt = vault::VaultAccessPrompt {
                        // The listing spans every vault, so there is no single
                        // key to name. The prompt describes the site instead.
                        vault_key: String::new(),
                        caller: vouched_caller(scope, &client_id, caller),
                        caller_chain: caller_chain.clone(),
                        client: client_id.clone(),
                        action: vault::VaultAction::ListLogins { page, all },
                    };
                    log::debug!("App broker request: {prompt:?}");
                    vault::authorize_and_serve_logins(&authorizers, prompt, actor, None, &in_flight)
                        .await
                },
                Err(message) => WireResponse::Failed { message },
            },
            WireRequest::ListLoginsLocked {
                url,
                frame_url,
                requester,
                caller,
                client: _,
            } => {
                if !scope.may_list_locked(&client_id) {
                    log::warn!("App broker refused a locked listing from {scope:?}");
                    return Ok(WireResponse::Failed {
                        message: "This client may not list logins without a prompt".to_string(),
                    });
                }
                match vault::LoginPage::parse(&url, &frame_url, requester_for(scope, requester)) {
                    Ok(page) => {
                        let prompt = vault::VaultAccessPrompt {
                            vault_key: String::new(),
                            caller: vouched_caller(scope, &client_id, caller),
                            caller_chain: caller_chain.clone(),
                            client: client_id.clone(),
                            action: vault::VaultAction::ListLogins { page, all: false },
                        };
                        log::debug!("App broker request: locked listing {prompt:?}");
                        vault::list_logins_locked(&prompt, &actor, &authorizers.logins)
                    },
                    Err(message) => WireResponse::Failed { message },
                }
            },
            WireRequest::FillLogin {
                url,
                frame_url,
                record_id,
                account,
                unmatched,
                requester,
                caller,
                client: _,
            } => match vault::LoginPage::parse(&url, &frame_url, requester_for(scope, requester))
                .and_then(vault::LoginPage::require_same_site)
            {
                Ok(page) => {
                    let prompt = vault::VaultAccessPrompt {
                        vault_key: String::new(),
                        caller: vouched_caller(scope, &client_id, caller),
                        caller_chain: caller_chain.clone(),
                        client: client_id.clone(),
                        action: vault::VaultAction::FillLogin {
                            page,
                            record_id,
                            account: account.filter(|a| !a.trim().is_empty()),
                            unmatched,
                        },
                    };
                    log::debug!("App broker request: {prompt:?}");
                    vault::authorize_and_serve_logins(&authorizers, prompt, actor, None, &in_flight)
                        .await
                },
                Err(message) => WireResponse::Failed { message },
            },
            WireRequest::GenerateTotp {
                url,
                frame_url,
                record_id,
                requester,
                caller,
                client: _,
            } => match vault::LoginPage::parse(&url, &frame_url, requester_for(scope, requester))
                .and_then(vault::LoginPage::require_same_site)
            {
                Ok(page) => {
                    let prompt = vault::VaultAccessPrompt {
                        vault_key: String::new(),
                        caller: vouched_caller(scope, &client_id, caller),
                        caller_chain: caller_chain.clone(),
                        client: client_id.clone(),
                        action: vault::VaultAction::GenerateTotp { page, record_id },
                    };
                    log::debug!("App broker request: {prompt:?}");
                    vault::authorize_and_serve_logins(&authorizers, prompt, actor, None, &in_flight)
                        .await
                },
                Err(message) => WireResponse::Failed { message },
            },
            WireRequest::GeneratePassword { policy, .. } => {
                log::debug!("App broker request: generate password");
                match policy.unwrap_or_default().generate() {
                    Ok(password) => WireResponse::GeneratedPassword {
                        password: secrecy::ExposeSecret::expose_secret(&password).to_string(),
                    },
                    Err(e) => WireResponse::Failed {
                        message: format!("Failed to generate a password: {e}"),
                    },
                }
            },
            WireRequest::SaveLogin {
                url,
                frame_url,
                username,
                password,
                caller,
                client: _,
            } => {
                if password.is_empty() {
                    return Ok(WireResponse::Failed {
                        message: "There is no password to save".to_string(),
                    });
                }
                match vault::LoginPage::parse(&url, &frame_url, None) {
                    Ok(page) => {
                        let username = username.filter(|name| !name.trim().is_empty());
                        let prompt = vault::VaultAccessPrompt {
                            vault_key: vault::write_vault_key(),
                            caller: vouched_caller(scope, &client_id, caller),
                            caller_chain: caller_chain.clone(),
                            client: client_id.clone(),
                            action: vault::VaultAction::SaveLogin { page, username },
                        };
                        log::debug!("App broker request: {prompt:?}");
                        let payload = vault::VaultPayload::SaveLogin(vault::SaveLoginPayload {
                            password: secrecy::SecretString::from(password),
                        });
                        vault::authorize_and_serve_logins(
                            &authorizers,
                            prompt,
                            actor,
                            Some(payload),
                            &in_flight,
                        )
                        .await
                    },
                    Err(message) => WireResponse::Failed { message },
                }
            },
            WireRequest::UpdateLoginPassword {
                url,
                frame_url,
                record_id,
                password,
                account,
                caller,
                client: _,
            } => {
                if password.is_empty() {
                    return Ok(WireResponse::Failed {
                        message: "There is no password to save".to_string(),
                    });
                }
                match vault::LoginPage::parse(&url, &frame_url, None) {
                    Ok(page) => {
                        let prompt = vault::VaultAccessPrompt {
                            // The login's vault is found by its record id once
                            // the vault is open.
                            vault_key: String::new(),
                            caller: vouched_caller(scope, &client_id, caller),
                            caller_chain: caller_chain.clone(),
                            client: client_id.clone(),
                            action: vault::VaultAction::UpdateLoginPassword {
                                page,
                                record_id,
                                account: account.filter(|a| !a.trim().is_empty()),
                            },
                        };
                        log::debug!("App broker request: {prompt:?}");
                        let payload = vault::VaultPayload::UpdateLogin(vault::UpdateLoginPayload {
                            password: secrecy::SecretString::from(password),
                        });
                        vault::authorize_and_serve_logins(
                            &authorizers,
                            prompt,
                            actor,
                            Some(payload),
                            &in_flight,
                        )
                        .await
                    },
                    Err(message) => WireResponse::Failed { message },
                }
            },
            WireRequest::ReadVaultSecret {
                vault_key,
                item_key,
                credential_key,
                caller,
            } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key,
                    caller,
                    caller_chain: caller_chain.clone(),
                    client: client_id.clone(),
                    action: vault::VaultAction::ReadSecret {
                        item_key,
                        credential_key,
                    },
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(&*authorizers.vault, prompt, actor, None, &in_flight)
                    .await
            },
            WireRequest::ResolveSecrets {
                refs,
                purpose,
                caller,
            } => {
                let mut vault_keys: Vec<String> =
                    refs.iter().map(|r| r.vault_key.clone()).collect();
                vault_keys.sort();
                vault_keys.dedup();
                let prompt = vault::VaultAccessPrompt {
                    vault_key: vault_keys.join(", "),
                    caller,
                    caller_chain: caller_chain.clone(),
                    client: client_id.clone(),
                    action: vault::VaultAction::ResolveSecrets { purpose, refs },
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(&*authorizers.vault, prompt, actor, None, &in_flight)
                    .await
            },
            WireRequest::WriteVaultSecret {
                vault_key,
                item_key,
                credential_key,
                title,
                value,
                login,
                caller,
            } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key,
                    caller,
                    caller_chain: caller_chain.clone(),
                    client: client_id.clone(),
                    action: vault::VaultAction::WriteSecret {
                        item_key,
                        credential_key,
                    },
                };
                let payload = vault::WriteSecretPayload {
                    title,
                    value: secrecy::SecretString::from(value),
                    login,
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(
                    &*authorizers.vault,
                    prompt,
                    actor,
                    Some(vault::VaultPayload::Write(payload)),
                    &in_flight,
                )
                .await
            },
            WireRequest::ExportVaults {
                vault_keys,
                dest_path,
                mode,
                exclude_passkeys,
                caller,
            } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key: vault_keys.join(", "),
                    caller,
                    caller_chain: caller_chain.clone(),
                    client: client_id.clone(),
                    action: vault::VaultAction::ExportVaults {
                        vault_keys: vault_keys.clone(),
                    },
                };
                let payload = vault::ExportPayload {
                    dest_path: std::path::PathBuf::from(dest_path),
                    mode: mode.into(),
                    include_passkeys: !exclude_passkeys,
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(
                    &*authorizers.vault,
                    prompt,
                    actor,
                    Some(vault::VaultPayload::Export(payload)),
                    &in_flight,
                )
                .await
            },
            WireRequest::ImportVaults {
                import_path,
                identity,
                selection,
                caller,
            } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key: std::path::Path::new(&import_path)
                        .file_name()
                        .map_or_else(|| import_path.clone(), |n| n.to_string_lossy().into_owned()),
                    caller,
                    caller_chain: caller_chain.clone(),
                    client: client_id.clone(),
                    action: vault::VaultAction::ImportVaults {
                        count: selection.len(),
                    },
                };
                let payload = vault::ImportPayload {
                    import_path: std::path::PathBuf::from(import_path),
                    identity,
                    selection,
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(
                    &*authorizers.vault,
                    prompt,
                    actor,
                    Some(vault::VaultPayload::Import(payload)),
                    &in_flight,
                )
                .await
            },
            WireRequest::AddExternalVault { path, caller } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key: path.clone(),
                    caller,
                    caller_chain: caller_chain.clone(),
                    client: client_id.clone(),
                    action: vault::VaultAction::AddVault { path },
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(&*authorizers.vault, prompt, actor, None, &in_flight)
                    .await
            },
            WireRequest::CreatePasskey {
                rp_id,
                rp_name,
                user_handle,
                user_name,
                user_display_name,
                client_data_hash,
                algorithms,
                excluded_credentials,
                origin,
                caller,
                client: _,
            } => {
                if let Err(message) = check_rp_id(&rp_id, origin.as_deref()) {
                    log::warn!("App broker refused a passkey registration: {message}");
                    return Ok(WireResponse::Failed { message });
                }
                let mut excluded = Vec::with_capacity(excluded_credentials.len());
                for c in &excluded_credentials {
                    excluded.push(decode_b64(c)?);
                }
                let choices = vault::passkey_choices(&rp_id, &user_name, &authorizers.logins);
                let request = CreatePasskeyRequest {
                    rp_id: rp_id.clone(),
                    rp_name,
                    user_handle: decode_b64(&user_handle)?,
                    user_name: user_name.clone(),
                    user_display_name,
                    client_data_hash: decode_b64(&client_data_hash)?,
                    algorithms,
                    excluded_credentials: excluded,
                    // Replaced with the user's choice once the prompt is
                    // answered.
                    target: PasskeyTarget::NewLogin,
                };
                let prompt = vault::VaultAccessPrompt {
                    vault_key: choices.default_vault.clone(),
                    caller: vouched_caller(scope, &client_id, caller),
                    caller_chain: caller_chain.clone(),
                    client: client_id.clone(),
                    action: vault::VaultAction::CreatePasskey {
                        rp_id,
                        user_name,
                        choices,
                    },
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(
                    &*authorizers.vault,
                    prompt,
                    actor,
                    Some(vault::VaultPayload::CreatePasskey(
                        vault::CreatePasskeyPayload { request },
                    )),
                    &in_flight,
                )
                .await
            },
            WireRequest::AssertPasskey {
                rp_id,
                client_data_hash,
                allowed_credentials,
                origin,
                caller,
                client: _,
            } => {
                if let Err(message) = check_rp_id(&rp_id, origin.as_deref()) {
                    log::warn!("App broker refused a passkey assertion: {message}");
                    return Ok(WireResponse::Failed { message });
                }
                let mut allowed = Vec::with_capacity(allowed_credentials.len());
                for c in &allowed_credentials {
                    allowed.push(decode_b64(c)?);
                }
                let request = AssertPasskeyRequest {
                    rp_id: rp_id.clone(),
                    client_data_hash: decode_b64(&client_data_hash)?,
                    allowed_credentials: allowed,
                };
                let prompt = vault::VaultAccessPrompt {
                    vault_key: String::new(),
                    caller: vouched_caller(scope, &client_id, caller),
                    caller_chain: caller_chain.clone(),
                    client: client_id.clone(),
                    action: vault::VaultAction::AssertPasskey { rp_id },
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(
                    &*authorizers.vault,
                    prompt,
                    actor,
                    Some(vault::VaultPayload::AssertPasskey(
                        vault::AssertPasskeyPayload { request },
                    )),
                    &in_flight,
                )
                .await
            },
            WireRequest::ListAgeKeys { .. } => {
                log::debug!("App broker request: list age keys");
                age::list_keys().await
            },
            WireRequest::GetAgeIdentity { key_id, caller } => {
                log::debug!("App broker request: get age identity {key_id}");
                age::get_identity(&*authorizers.passphrase, key_id, caller, actor, &in_flight).await
            },
            WireRequest::CreateAgeKey { key_id, .. } => {
                log::debug!("App broker request: create age key {key_id}");
                age::create_key(key_id, actor).await
            },
            WireRequest::DeleteAgeKey { key_id, .. } => {
                log::debug!("App broker request: delete age key {key_id}");
                age::delete_key(key_id, actor).await
            },
            WireRequest::ListKeychainPasswords { .. } => {
                log::debug!("App broker request: list keychain passwords");
                keychain::list_passwords(&*authorizers.keychain).await
            },
            WireRequest::DeleteManagedKey { label, .. } => {
                log::debug!("App broker request: delete managed key {label}");
                keychain::delete_managed_key(label, actor).await
            },
            WireRequest::Confirm {
                description,
                ok_label,
                cancel_label,
            } => {
                log::debug!("App broker request: confirm");
                let prompt = ConfirmPrompt {
                    description,
                    ok_label,
                    cancel_label,
                };
                let ok = in_flight
                    .unless_abandoned(authorizers.passphrase.confirm(prompt))
                    .await;
                WireResponse::Confirmed {
                    ok: ok.unwrap_or(false),
                }
            },
            WireRequest::Message { description } => {
                log::debug!("App broker request: message");
                in_flight
                    .unless_abandoned(authorizers.passphrase.message(description))
                    .await;
                WireResponse::Acknowledged
            },
        })
    };
    tokio::pin!(serve);
    tokio::pin!(disconnected);

    tokio::select! {
        biased; // poll in order
        () = &mut disconnected => {
            log::debug!("App broker client disconnected mid-request, ending its prompt");
            in_flight.abandon();
            serve.await?;
            Ok(None)
        },
        response = &mut serve => Ok(Some(response?)),
    }
}
