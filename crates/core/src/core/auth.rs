mod la_context;
use std::ffi::c_void;
use std::num::NonZero;
use std::sync::{LazyLock, Mutex, mpsc};
use std::thread;

use anyhow::anyhow;
use lru::LruCache;
use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_local_authentication::{
    LAAccessControlOperation, LAContext, LAPolicy,
    LATouchIDAuthenticationMaximumAllowableReuseDuration,
};
use ssh_key::Signature;

use crate::core::auth::la_context::create_la_auth_callback;
use crate::secrets::keychain::AccessControl;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::ManagedSshKey;

// How long a Touch ID match can be reused, capped by the system at
// LATouchIDAuthenticationMaximumAllowableReuseDuration (300s as of macOS 15).
//
// This does not bound how long the app stays unlocked. It governs reuse of a
// match across evaluations, but re-evaluating the same live LAContext returns
// success from the context's own state without consulting it. Measured with
// this set to 5s: a re-evaluation 25s later succeeded in 5ms with no prompt.
// An unlock therefore lasts as long as the LAContext object, and only
// invalidate_auth() ends it. An idle timeout would have to be enforced by the
// caller.
const TOUCH_ID_REUSE_DURATION_SECS: f64 = 300.0; // 5 minutes

enum AuthMessage {
    Work(AuthWork),
    Invalidate(mpsc::Sender<()>),
    AdoptContext(ForeignContext, mpsc::Sender<()>),
}

/// An `LAContext` created outside this crate and handed to the shared auth
/// thread. The UI owns the context it authenticates with so it can attach an
/// `LAAuthenticationView` and draw the biometric prompt inline rather than in
/// the system dialog.
#[derive(Clone)]
pub struct ForeignContext(Retained<LAContext>);

impl ForeignContext {
    /// # Safety
    /// `context_ptr` must point to a live `LAContext`. The caller keeps its own
    /// reference; this takes an additional one.
    pub unsafe fn from_ptr(context_ptr: *mut c_void) -> Result<Self, KeychainError> {
        let context = unsafe { Retained::retain(context_ptr.cast::<LAContext>()) }
            .ok_or_else(|| KeychainError::from(anyhow!("null LAContext pointer")))?;
        Ok(Self(context))
    }
}

impl std::fmt::Debug for ForeignContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ForeignContext")
    }
}

// SAFETY: LAContext supports use from any thread, and every other context in
// this module already moves onto the shared-auth thread the same way.
unsafe impl Send for ForeignContext {}

struct AuthWork {
    context: AuthContext,
    auth: AuthMethod,
    auth_reply: mpsc::Sender<Result<(), KeychainError>>,
    work: Box<dyn FnOnce(Retained<LAContext>) + Send + 'static>,
}

#[derive(Debug, Clone)]
pub enum AuthContext {
    SharedThreadLocal,
    WithContext(String),
    OneTime,
    /// A context the caller owns, so it can attach an `LAAuthenticationView`
    /// and draw the prompt itself. Used by the app broker, where the app
    /// supplies the context and the requesting process does the signing.
    Foreign(ForeignContext),
}

pub enum AuthMethod {
    /// Run the work with the context as it stands, evaluating nothing. For
    /// probes that must not raise a prompt; the work is responsible for coping
    /// with a context that is not authenticated.
    None,
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
            let mut thread_la_context = init_shared_la_context();

            // Cache of keyed contexts
            let mut la_cache: LruCache<String, Retained<LAContext>> =
                LruCache::new(NonZero::new(LA_CONTEXT_CACHE_SIZE).unwrap());

            for msg in rx {
                match msg {
                    AuthMessage::Invalidate(reply) => {
                        log::debug!("Invalidating all LAContext instances");
                        thread_la_context = init_shared_la_context();
                        la_cache.clear();
                        let _ = reply.send(());
                    },
                    AuthMessage::AdoptContext(context, reply) => {
                        log::debug!("Adopting externally created LAContext as the shared context");
                        thread_la_context = context.0;
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
                            AuthContext::Foreign(ref context) => context.0.clone(),
                        };
                        match authenticate(selected_la_ctx.clone(), work.auth) {
                            Ok(_) => {
                                log::debug!("Authentication successful ({:?})", work.context);
                                let _ = work.auth_reply.send(Ok(()));
                                (work.work)(selected_la_ctx);
                            },
                            Err(KeychainError::AuthenticationExpired) => {
                                log::warn!(
                                    "{:?} expired, invalidating all LAContext instances",
                                    work.context
                                );
                                // Replace shared thread-local la context
                                thread_la_context = init_shared_la_context();
                                la_cache.clear();
                                let _ = work
                                    .auth_reply
                                    .send(Err(KeychainError::AuthenticationExpired));
                                continue;
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

fn init_shared_la_context() -> Retained<LAContext> {
    let ctx = unsafe { LAContext::new() };
    set_reuse_duration(&ctx);
    ctx
}

fn set_reuse_duration(ctx: &LAContext) {
    unsafe {
        if TOUCH_ID_REUSE_DURATION_SECS > LATouchIDAuthenticationMaximumAllowableReuseDuration {
            log::warn!(
                "Requested Touch ID reuse duration of {TOUCH_ID_REUSE_DURATION_SECS}s exceeds the system maximum of {LATouchIDAuthenticationMaximumAllowableReuseDuration}s. Capping to the maximum."
            );
            ctx.setTouchIDAuthenticationAllowableReuseDuration(
                LATouchIDAuthenticationMaximumAllowableReuseDuration,
            );
        } else {
            // this takes an NSTimeInterval, which is a c_double
            // which is "almost always f64" per the std::os::raw docs
            ctx.setTouchIDAuthenticationAllowableReuseDuration(TOUCH_ID_REUSE_DURATION_SECS);
        }
    }
}

/// Adopt an `LAContext` created outside this crate as the shared context, so
/// later keychain operations reuse the authentication already performed on it.
///
/// The macOS UI creates its own context to drive `LAAuthenticationView`, calls
/// `evaluatePolicy` on it, then hands it over here.
///
/// # Safety
/// `context_ptr` must point to a live `LAContext`. The caller keeps its own
/// reference; this takes an additional one.
pub unsafe fn adopt_shared_context(context_ptr: *mut c_void) -> Result<(), KeychainError> {
    let context = unsafe { ForeignContext::from_ptr(context_ptr) }?;
    // The reuse duration is deliberately not set here: it only affects
    // evaluations that follow it, and the caller has already evaluated. See the
    // note on TOUCH_ID_REUSE_DURATION_SECS for why it would not matter anyway.

    let (tx, rx) = mpsc::channel();
    AUTH_THREAD
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .send(AuthMessage::AdoptContext(context, tx))
        .expect("shared-auth thread stopped");
    rx.recv().expect("shared-auth thread stopped");
    Ok(())
}

/// Serialize an authentication prompt driven from outside this crate. The UI
/// calls `evaluatePolicy` for the embedded prompt, bypassing [`authenticate`]
/// and the lock it takes. Hold the returned file while the prompt is on screen.
pub fn external_auth_lock() -> std::fs::File {
    acquire_auth_lock()
}

// evaluatePolicy shows OS authentication UI; if a second process calls it while
// another process's prompt is up, the system cancels the first request
// (LAError::SystemCancel / KeychainError::AuthenticationInProgress) instead of
// queuing it. We serialize calls across processes with a blocking file lock so
// concurrent invocations (e.g. `ap inject` run back-to-back) waits their turn
// instead of repeatedly triggering.
fn acquire_auth_lock() -> std::fs::File {
    let path = crate::core::dirs::app_data_dir().join("auth.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("failed to open auth lock file {path:?}: {e}"));
    file.lock().expect("failed to acquire auth lock");
    file
}

// Kept as a defense-in-depth fallback for races with authentication requests
// outside our control (e.g. another app), which the file lock above can't
// serialize against.
const AUTH_RETRY_ATTEMPTS: u32 = 50;
const AUTH_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

// Authenticate the LAContext using the specified method
fn authenticate(la_context: Retained<LAContext>, method: AuthMethod) -> Result<(), KeychainError> {
    // Nothing to evaluate and no prompt to serialize against, so skip the lock.
    if matches!(method, AuthMethod::None) {
        return Ok(());
    }

    let _lock = acquire_auth_lock();
    let mut attempts_left = AUTH_RETRY_ATTEMPTS;
    loop {
        let (callback, rx) = create_la_auth_callback();
        match &method {
            // Returned above, before the lock.
            AuthMethod::None => return Ok(()),
            AuthMethod::Policy { reason } => unsafe {
                la_context.evaluatePolicy_localizedReason_reply(
                    LAPolicy::DeviceOwnerAuthentication,
                    &NSString::from_str(reason),
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
                    *operation,
                    &NSString::from_str(reason),
                    &callback,
                );
            },
        }

        let result = match rx.recv() {
            Ok(result) => result,
            Err(e) => Err(anyhow!("error evaluating la_context: {e}").into()),
        };

        match result {
            Err(KeychainError::AuthenticationInProgress) if attempts_left > 0 => {
                attempts_left -= 1;
                thread::sleep(AUTH_RETRY_DELAY);
            },
            other => return other,
        }
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
    // alternative to running on shared thread with AuthContext::OneTime and
    // AuthMethod::None, on a context of its own rather than the shared one
    unsafe {
        let la_context = LAContext::new();
        la_context.setInteractionNotAllowed(true);
        work_fn(la_context)
    }
}

/// Run `probe_fn` against the shared context with interaction disallowed, so a
/// keychain read reports that authentication is needed rather than prompting
/// for it. The flag is restored afterwards.
///
/// The shared context is only touched on the auth thread, so the window where
/// interaction is disallowed cannot overlap other work.
pub fn probe_shared_context<F, R>(probe_fn: F) -> Result<R, KeychainError>
where
    F: FnOnce(Retained<LAContext>) -> R + Send + 'static,
    R: Send + 'static,
{
    run_on_auth_thread(
        AuthContext::SharedThreadLocal,
        AuthMethod::None,
        move |la_context| unsafe {
            la_context.setInteractionNotAllowed(true);
            let result = probe_fn(la_context.clone());
            la_context.setInteractionNotAllowed(false);
            result
        },
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

/// Reason string shown in the authentication prompt for an SSH signature.
pub fn signing_reason(managed_key_label: &str, caller: Option<&str>) -> String {
    match caller {
        Some(c) => format!("sign with SSH key {managed_key_label} for {c}"),
        None => format!("sign with SSH key {managed_key_label}"),
    }
}

pub fn sign_with_managed_key(
    managed_key_label: &str,
    data: &[u8],
    caller: Option<&str>,
) -> Result<Signature, String> {
    sign_with_managed_key_on(
        AuthContext::WithContext(managed_key_label.to_string()),
        managed_key_label,
        data,
        caller,
    )
    .map_err(|e| e.to_string())
}

/// Sign on a specific [`AuthContext`]. The app broker passes
/// [`AuthContext::Foreign`] so the app that owns the context draws the prompt.
/// Unlike [`sign_with_managed_key`] this keeps the error typed, so a caller can
/// tell a cancelled prompt from a failure.
pub fn sign_with_managed_key_on(
    auth_context: AuthContext,
    managed_key_label: &str,
    data: &[u8],
    caller: Option<&str>,
) -> Result<Signature, KeychainError> {
    let managed_key_label = managed_key_label.to_string();
    let data = data.to_vec();
    let reason = signing_reason(&managed_key_label, caller);

    run_on_auth_thread(
        auth_context,
        AuthMethod::AccessControl {
            access_control: AccessControl::ManagedKey,
            operation: LAAccessControlOperation::UseKeySign,
            reason,
        },
        move |la_context| match ManagedSshKey::find_with_la_context(&managed_key_label, la_context)
        {
            Ok(Some(managed_key)) => managed_key
                .sign(&data)
                .inspect(|_| log::debug!("Completed signing with key {managed_key_label}"))
                .map_err(|e| KeychainError::SigningFailed(e.to_string())),
            Ok(None) => Err(KeychainError::SigningFailed(format!(
                "{managed_key_label} not found"
            ))),
            Err(e) => Err(e),
        },
    )?
}
