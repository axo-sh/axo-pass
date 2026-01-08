use std::num::NonZero;
use std::sync::{LazyLock, Mutex, mpsc};
use std::thread;

use lru::LruCache;
use objc2::rc::Retained;
use objc2_local_authentication::{LAAccessControlOperation, LAContext};
use ssh_key::Signature;

use crate::cli::commands::ssh_agent::credential::CredentialError;
use crate::core::la_context::evaluate_la_context_with;
use crate::secrets::keychain::AccessControl;
use crate::secrets::keychain::managed_key::ManagedSshKey;

struct SignatureRequest {
    label: String,
    data: Vec<u8>,
}

type SignMessage = (
    SignatureRequest,
    mpsc::Sender<Result<Signature, CredentialError>>,
);

// Store up to 16 LAContext instances for reuse.
static LA_CONTEXT_CACHE_SIZE: usize = 16;

/// Single dedicated thread for all LAContext signing operations. This ensures
/// the LAContext cache is always accessed from the same thread. Another nice
/// property is that only one authentication prompt can be active at a time.
static SIGN_THREAD: LazyLock<Mutex<mpsc::Sender<SignMessage>>> = LazyLock::new(|| {
    let (tx, rx) = mpsc::channel::<SignMessage>();
    log::debug!("Spawning ssh-signer thread...");
    thread::Builder::new()
        .name("ssh-signer".into())
        .spawn(move || {
            log::debug!("Started ssh-signer thread.");
            let mut la_cache: LruCache<String, Retained<LAContext>> =
                LruCache::new(NonZero::new(LA_CONTEXT_CACHE_SIZE).unwrap());
            for (request, reply_tx) in rx {
                log::debug!("Signing with key {}", request.label);
                let la_context = la_cache
                    .get_or_insert(request.label.clone(), || unsafe { LAContext::new() })
                    .clone();
                let result = sign_with_managed_key_context(la_context, &request);
                log::debug!("Completed signing with key {}", request.label);
                let _ = reply_tx.send(result);
            }
        })
        .expect("Failed to spawn ssh-signer thread");
    Mutex::new(tx)
});

pub fn sign_with_managed_key(
    managed_key_label: &str,
    data: &[u8],
) -> Result<Signature, CredentialError> {
    let (reply_tx, reply_rx) = mpsc::channel();
    log::debug!("Request signing with key {managed_key_label}");
    SIGN_THREAD
        .lock()
        .unwrap()
        .send((
            SignatureRequest {
                label: managed_key_label.to_string(),
                data: data.to_vec(),
            },
            reply_tx,
        ))
        .map_err(|_| CredentialError::SigningFailed)?;

    log::debug!("Waiting for signature reply for key {managed_key_label}");
    reply_rx
        .recv()
        .inspect_err(|e| log::error!("Failed to receive sign reply: {e}"))
        .map_err(|_| CredentialError::SigningFailed)?
}

fn sign_with_managed_key_context(
    la_context: Retained<LAContext>,
    sign_data: &SignatureRequest,
) -> Result<Signature, CredentialError> {
    let managed_key_label = &sign_data.label;
    let access_control = AccessControl::ManagedKey
        .to_sec_access_control()
        .map_err(|e| {
            log::debug!("Failed to create access control flags: {e}");
            CredentialError::SigningFailed
        })?;

    // todo: simplify and improve the prompt message
    evaluate_la_context_with(
        &la_context,
        LAAccessControlOperation::UseKeySign,
        access_control,
        &format!("sign with SSH key {managed_key_label}"),
    )
    .map_err(|e| {
        log::debug!("Failed to evaluate LAContext for key {managed_key_label}: {e}");
        CredentialError::SigningFailed
    })?;

    let managed_key =
        ManagedSshKey::find_with_la_context(managed_key_label, Some(la_context.clone()))
            .map_err(|e| {
                log::debug!("Failed to find managed key {managed_key_label}: {e}");
                CredentialError::SigningFailed
            })?
            .ok_or_else(|| {
                log::debug!("Managed key {managed_key_label} not found");
                CredentialError::SigningFailed
            })?;

    managed_key.sign(&sign_data.data).map_err(|e| {
        log::debug!("Failed to sign with managed credential: {e}");
        CredentialError::SigningFailed
    })
}
