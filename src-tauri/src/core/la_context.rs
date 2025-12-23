use std::sync::{LazyLock, mpsc};

use anyhow::anyhow;
use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAAccessControlOperation, LAContext, LAError, LAPolicy};
use objc2_security::SecAccessControl;

use crate::secrets::keychain::errors::KeychainError;

thread_local! {
    pub static THREAD_LA_CONTEXT: LazyLock<Retained<LAContext>> = LazyLock::new(|| {
        unsafe {
            // five minutes
            // la_ctx.setTouchIDAuthenticationAllowableReuseDuration(600.0);
            LAContext::new()
        }
    });
}

fn create_la_callback() -> (
    RcBlock<dyn Fn(Bool, *mut NSError)>,
    mpsc::Receiver<Result<(), KeychainError>>,
) {
    let (tx, rx) = mpsc::channel();
    let callback = RcBlock::new(move |success: Bool, error: *mut NSError| {
        if success.as_bool() {
            let _ = tx.send(Ok(()));
        } else if error.is_null() {
            let _ = tx.send(Err(anyhow!(
                "Failed to authenticate with LAContext: unknown error"
            )
            .into()));
        } else {
            let err: &NSError = unsafe { &*error };
            log::debug!(
                "LAContext authentication failed: success={success:?}, error={}, code={}, domain={}",
                err,
                err.code(),
                err.domain(),
            );
            let err = match LAError(err.code()) {
                LAError::UserCancel => KeychainError::UserCancelled,
                _ => anyhow!("Failed to authenticate with LAContext: {err:?}").into(),
            };
            let _ = tx.send(Err(err));
        };
    });
    (callback, rx)
}

// use this to create a one time authentication prompt
pub fn evaluate_la_context(reason: &str) -> Result<(), KeychainError> {
    // "Axo Pass is trying to {reason}."
    let displayed_reason = NSString::from_str(reason);
    let policy = LAPolicy::DeviceOwnerAuthentication; // biometrics or password
    let (evaluate_callback, rx) = create_la_callback();
    unsafe {
        let la_context = LAContext::new();
        la_context.evaluatePolicy_localizedReason_reply(
            policy,
            &displayed_reason,
            &evaluate_callback,
        );
    }
    match rx.recv() {
        Ok(callback_result) => callback_result,
        Err(e) => Err(anyhow!("error evaluating la_context: {e}").into()),
    }
}

// use this to evaluate access control for an item, using the thread global
// LAContext (which means authentication will be reused within an allowable
// duration)
pub fn evaluate_local_la_context(
    access_control: Retained<SecAccessControl>,
) -> Result<(), KeychainError> {
    let (evaluate_callback, rx) = create_la_callback();
    let displayed_reason = NSString::from_str("use secure item");
    THREAD_LA_CONTEXT.with(|ctx| unsafe {
        (**ctx).evaluateAccessControl_operation_localizedReason_reply(
            &access_control,
            LAAccessControlOperation::UseItem,
            &displayed_reason,
            &evaluate_callback,
        );
    });

    match rx.recv() {
        Ok(callback_result) => callback_result,
        Err(e) => Err(anyhow!("error evaluating la_context: {e}").into()),
    }
}
