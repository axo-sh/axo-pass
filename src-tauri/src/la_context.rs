use std::cell::Cell;
use std::sync::{LazyLock, mpsc};

use anyhow::anyhow;
use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAAccessControlOperation, LAContext, LAError};
use objc2_security::SecAccessControl;

use crate::secrets::keychain::errors::KeychainError;

thread_local! {
    pub static THREAD_LA_CONTEXT: LazyLock<Retained<LAContext>> = LazyLock::new(|| {
        unsafe {
            let la_ctx = LAContext::new();
            // five minutes
            // la_ctx.setTouchIDAuthenticationAllowableReuseDuration(600.0);
            la_ctx
        }
    });
}

pub fn evaluate_local_la_context(
    access_control: Retained<SecAccessControl>,
) -> Result<(), KeychainError> {
    let (tx, rx) = mpsc::channel();

    unsafe {
        let reason = NSString::from_str("use secure item");

        // Wrap the mpsc sender in a Cell to convert FnOnce to Fn
        let tx_cell = Cell::new(Some(tx));
        let block = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let tx = tx_cell.take().expect("block called more than once");
            if success.as_bool() {
                let _ = tx.send(Ok(()));
            } else {
                let error_msg = if error.is_null() {
                    "unknown error".to_string()
                } else {
                    format!("{:?}", &*error)
                };

                let err: &NSError = &*error;
                log::debug!(
                    "LAContext authentication failed: success={success:?}, error={}, code={}, domain={}",
                    err,
                    err.code(),
                    err.domain(),
                );
                let err = match LAError(err.code()) {
                    LAError::UserCancel => KeychainError::UserCancelled,
                    _ => anyhow!("Failed to authenticate with LAContext: {}", error_msg).into(),
                };
                let _ = tx.send(Err(err));
            };
        });

        THREAD_LA_CONTEXT.with(|ctx| {
            // context.setTouchIDAuthenticationAllowableReuseDuration(5.0 * 60.0);
            (**ctx).evaluateAccessControl_operation_localizedReason_reply(
                &access_control,
                LAAccessControlOperation::UseItem,
                &reason,
                &block,
            );
        });

        let _ = rx
            .recv()
            .map_err(|e| anyhow!("Blocking task panicked: {}", e))??;

        Ok(())
    }
}
