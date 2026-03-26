mod la_context;
use std::num::NonZero;
use std::sync::{LazyLock, Mutex, mpsc};
use std::thread;

use anyhow::anyhow;
use lru::LruCache;
use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_local_authentication::{LAAccessControlOperation, LAContext, LAPolicy};
use ssh_key::Signature;

use crate::core::auth::la_context::create_la_auth_callback;
use crate::secrets::keychain::AccessControl;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::ManagedSshKey;

// const TOUCH_ID_REUSE_DURATION_SECS: f64 = 300.0; // 5 minutes
const TOUCH_ID_REUSE_DURATION_SECS: f64 = 5.0; // 5 seconds for testing

enum AuthMessage {
    Work(AuthWork),
    Invalidate(mpsc::Sender<()>),
}

struct AuthWork {
    context: AuthContext,
    auth: AuthMethod,
    auth_reply: mpsc::Sender<Result<(), KeychainError>>,
    work: Box<dyn FnOnce(Retained<LAContext>) + Send + 'static>,
}

#[derive(Debug)]
pub enum AuthContext {
    SharedThreadLocal,
    WithContext(String),
    OneTime,
}

pub enum AuthMethod {
    // maps to evaluatePolicy_localizedReason_reply
    Policy {
        reason: String,
    },
    // maps to evaluateAccessControl_operation_localizedReason_reply
    AccessControl {
        access_control: AccessControl,
        operation: LAAccessControlOperation,
        reason: String,
    },
    /// Skip authentication
    None,
}

// Store up to 16 LAContext instances for reuse.
static LA_CONTEXT_CACHE_SIZE: usize = 16;

/// Dedicated thread that owns a single LAContext with Touch ID reuse duration
/// enabled. All auth-requiring keychain operations run on this thread so they
/// share the same LAContext and a single Touch ID prompt covers them all.
static AUTH_THREAD: LazyLock<Mutex<mpsc::Sender<AuthMessage>>> = LazyLock::new(|| {
    let (tx, rx) = mpsc::channel::<AuthMessage>();
    thread::Builder::new()
        .name("shared-auth".into())
        .spawn(move || {
            // Shared LAContext for the thread; allows reuse.
            let mut thread_la_context = unsafe {
                let ctx = LAContext::new();
                ctx.setTouchIDAuthenticationAllowableReuseDuration(TOUCH_ID_REUSE_DURATION_SECS);
                ctx
            };

            // Cache of keyed contexts
            let mut la_cache: LruCache<String, Retained<LAContext>> =
                LruCache::new(NonZero::new(LA_CONTEXT_CACHE_SIZE).unwrap());

            for msg in rx {
                match msg {
                    AuthMessage::Invalidate(reply) => {
                        log::debug!("Invalidating all LAContext instances");
                        thread_la_context = unsafe {
                            let ctx = LAContext::new();
                            ctx.setTouchIDAuthenticationAllowableReuseDuration(
                                TOUCH_ID_REUSE_DURATION_SECS,
                            );
                            ctx
                        };
                        la_cache.clear();
                        let _ = reply.send(());
                    },
                    AuthMessage::Work(work) => {
                        let selected_la_ctx = match work.context {
                            AuthContext::WithContext(ref key) => {
                                log::debug!("Running auth work with context {key}");
                                la_cache
                                    .get_or_insert(key.clone(), || unsafe { LAContext::new() })
                                    .clone()
                            },
                            AuthContext::SharedThreadLocal => thread_la_context.clone(),
                            AuthContext::OneTime => unsafe { LAContext::new() },
                        };
                        match authenticate(selected_la_ctx.clone(), work.auth) {
                            Ok(_) => {
                                log::debug!(
                                    "Authentication successful for context {:?}",
                                    work.context
                                );
                                let _ = work.auth_reply.send(Ok(()));
                                (work.work)(selected_la_ctx);
                            },
                            Err(e) => {
                                log::error!(
                                    "Authentication failed for context {:?}: {e}",
                                    work.context
                                );
                                let _ = work.auth_reply.send(Err(e));
                                continue;
                            },
                        }
                    },
                }
            }
        })
        .expect("Failed to spawn shared-auth thread");
    Mutex::new(tx)
});

// Authenticate the LAContext using the specified method
fn authenticate(la_context: Retained<LAContext>, method: AuthMethod) -> Result<(), KeychainError> {
    let (callback, rx) = create_la_auth_callback();
    match method {
        AuthMethod::Policy { reason } => unsafe {
            la_context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &NSString::from_str(&reason),
                &callback,
            );
        },
        AuthMethod::AccessControl {
            access_control,
            operation,
            reason,
        } => unsafe {
            let sec_access_control = access_control.to_sec_access_control()?;
            la_context.evaluateAccessControl_operation_localizedReason_reply(
                &sec_access_control,
                operation,
                &NSString::from_str(&reason),
                &callback,
            );
        },
        AuthMethod::None => {
            unsafe { la_context.setInteractionNotAllowed(true) };
            return Ok(());
        },
    }

    match rx.recv() {
        Ok(result) => result,
        Err(e) => Err(anyhow!("error evaluating la_context: {e}").into()),
    }
}

pub fn run_on_auth_thread<F, R>(
    auth_context: AuthContext,
    auth_method: AuthMethod,
    work_fn: F,
) -> Result<R, KeychainError>
where
    F: FnOnce(Retained<LAContext>) -> R + Send + 'static,
    R: Send + 'static,
{
    let (reply_tx, reply_rx) = mpsc::channel::<R>();
    let (auth_tx, auth_rx) = mpsc::channel::<Result<(), KeychainError>>();
    let work = AuthWork {
        context: auth_context,
        auth: auth_method,
        auth_reply: auth_tx,
        work: Box::new(move |la_context| {
            let result = work_fn(la_context);
            let _ = reply_tx.send(result);
        }),
    };
    AUTH_THREAD
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .send(AuthMessage::Work(work))
        .expect("shared-auth thread stopped");

    auth_rx.recv().expect("shared-auth thread stopped")?;
    Ok(reply_rx.recv().expect("shared-auth thread stopped"))
}

pub fn run_local_onetime<F, R>(work_fn: F) -> R
where
    F: FnOnce(Retained<LAContext>) -> R + Send + 'static,
    R: Send + 'static,
{
    // alternative to running on shared thread with AuthContext::OneTime,
    // AuthMethod::None
    unsafe {
        let la_context = LAContext::new();
        la_context.setInteractionNotAllowed(true);
        work_fn(la_context)
    }
}

/// Verify that the user is still authenticated. Returns Ok(()) if auth is
/// still valid, or Err if it has expired (which also invalidates cached
/// contexts).
pub fn check_auth() -> Result<(), KeychainError> {
    // todo: handle the case where we call this as the initial auth check -
    // we shouldn't prompt for auth, we should only be checking if an existing auth
    // is still valid
    run_on_auth_thread(
        AuthContext::SharedThreadLocal,
        AuthMethod::Policy {
            reason: "verify authentication".to_string(),
        },
        |_| {},
    )
}

/// Invalidate all cached LAContext instances, requiring re-authentication.
pub fn invalidate_auth() {
    let (tx, rx) = mpsc::channel();
    AUTH_THREAD
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .send(AuthMessage::Invalidate(tx))
        .expect("shared-auth thread stopped");
    rx.recv().expect("shared-auth thread stopped");
}

pub fn sign_with_managed_key(managed_key_label: &str, data: &[u8]) -> Result<Signature, String> {
    let managed_key_label = managed_key_label.to_string();
    let data = data.to_vec();

    run_on_auth_thread(
        AuthContext::WithContext(managed_key_label.clone()),
        AuthMethod::AccessControl {
            access_control: AccessControl::ManagedKey,
            operation: LAAccessControlOperation::UseKeySign,
            reason: format!("sign with SSH key {}", managed_key_label),
        },
        move |la_context| match ManagedSshKey::find_with_la_context(&managed_key_label, la_context)
        {
            Ok(Some(managed_key)) => managed_key
                .sign(&data)
                .inspect(|_| log::debug!("Completed signing with key {managed_key_label}"))
                .map_err(|e| e.to_string()),
            Ok(None) => Err(format!("{managed_key_label} not found")),
            Err(e) => Err(format!("{managed_key_label} error: {e}")),
        },
    )
    .map_err(|e| e.to_string())?
}
