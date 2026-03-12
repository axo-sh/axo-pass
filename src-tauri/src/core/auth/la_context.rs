use std::sync::mpsc;

use anyhow::anyhow;
use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::NSError;
use objc2_local_authentication::LAError;

use crate::secrets::keychain::errors::KeychainError;

pub fn create_la_auth_callback() -> (
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
