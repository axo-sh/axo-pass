use std::ptr::NonNull;
use std::time::Duration;
use std::{ptr, thread};

use anyhow::anyhow;
use objc2::rc::Retained;
use objc2_core_foundation::{CFArray, CFMutableDictionary, CFRetained, CFString, CFType};
use objc2_local_authentication::LAContext;
use objc2_security::{
    SecItemCopyMatching, errSecInteractionNotAllowed, errSecItemNotFound, errSecSuccess,
    errSecUserCanceled, kSecMatchLimit, kSecMatchLimitAll, kSecUseAuthenticationContext,
};

use crate::secrets::keychain::errors::KeychainError;

/// When another process is already showing a Touch ID / passcode prompt for
/// the same keychain item, `SecItemCopyMatching` fails immediately with
/// `errSecInteractionNotAllowed` instead of waiting. Retry for a while so
/// concurrent invocations (e.g. `ap inject` run back-to-back) queue behind
/// the in-progress prompt rather than failing outright.
const INTERACTION_RETRY_ATTEMPTS: u32 = 50;
const INTERACTION_RETRY_DELAY: Duration = Duration::from_millis(200);

pub trait KeychainQuery {
    type Item;

    fn parse_result(&self, result: &CFType) -> Result<Self::Item, KeychainError>;
    fn build_query(&self) -> Retained<CFMutableDictionary<CFString, CFType>>;

    fn one(&self, la_context: Retained<LAContext>) -> Result<Option<Self::Item>, KeychainError> {
        self.one_with_retry(la_context, true)
    }

    /// Like `one`, but `retry_on_blocked` controls whether
    /// `errSecInteractionNotAllowed` is retried. Callers that intentionally
    /// disallow interaction on the `LAContext` (e.g. a fast non-prompting
    /// `exists()` probe) will always hit this error and should pass `false`
    /// to avoid burning the full retry budget on every call.
    fn one_with_retry(
        &self,
        la_context: Retained<LAContext>,
        retry_on_blocked: bool,
    ) -> Result<Option<Self::Item>, KeychainError> {
        unsafe {
            let query = self.build_query();

            // attach auth context
            let la_context = Retained::as_ptr(&la_context) as *const CFType;
            query.add(kSecUseAuthenticationContext, &*la_context);

            let mut attempts_left = if retry_on_blocked {
                INTERACTION_RETRY_ATTEMPTS
            } else {
                0
            };
            loop {
                let mut ret: *const CFType = ptr::null();
                let res = SecItemCopyMatching(query.as_opaque(), &mut ret);
                #[allow(non_upper_case_globals)]
                match res {
                    errSecSuccess if ret.is_null() => return Ok(None),
                    errSecSuccess => {
                        // SecItemCopyMatching follows the Create Rule, so the
                        // result is owned here. See the note in `list`.
                        let ret = CFRetained::from_raw(NonNull::new_unchecked(ret.cast_mut()));
                        return self.parse_result(&ret).map(Some);
                    },
                    errSecItemNotFound => return Ok(None),
                    errSecUserCanceled => return Err(KeychainError::UserCancelled),
                    errSecInteractionNotAllowed if attempts_left > 0 => {
                        attempts_left -= 1;
                        thread::sleep(INTERACTION_RETRY_DELAY);
                    },
                    errSecInteractionNotAllowed => return Err(KeychainError::ItemNotAccessible),
                    _ => return Err(anyhow!("got error code: {res}").into()),
                }
            }
        }
    }

    fn list(&self, la_context: Retained<LAContext>) -> Result<Vec<Self::Item>, KeychainError> {
        unsafe {
            let query = self.build_query();
            query.add(kSecMatchLimit, kSecMatchLimitAll);

            // attach auth context
            let la_context = Retained::as_ptr(&la_context) as *const CFType;
            query.add(kSecUseAuthenticationContext, &*la_context);

            let mut ret: *const CFType = ptr::null(); // CFTypeRef
            let res = SecItemCopyMatching(query.as_opaque(), &mut ret);

            let Some(ret) = NonNull::new(ret.cast_mut()) else {
                log::debug!("ret is null");
                return Ok(vec![]);
            };
            // SecItemCopyMatching follows the Create Rule, so the result is
            // owned here and must be released. CFRetained releases it on drop.
            // Leaking it pins an LAContext for the life of the process: the
            // array retains every SecKey in it, and a Secure Enclave SecKey
            // retains the LAContext it was fetched with. Once enough
            // contexts accumulate the system invalidates them and evaluations
            // fail with LAError::InvalidContext.
            let ret = CFRetained::from_raw(ret);

            if res != errSecSuccess {
                log::debug!("got error code: {res}");
                return Err(anyhow!("got error code: {res}").into());
            }

            let Some(cf_array) = ret.downcast_ref::<CFArray>() else {
                return Err(anyhow!("expected CFArray result").into());
            };

            let mut items = Vec::new();
            for i in 0..cf_array.len() {
                let el: *const CFType = cf_array.value_at_index(i.try_into().unwrap()).cast();
                let managed_key = self.parse_result(&*el)?;
                items.push(managed_key);
            }
            Ok(items)
        }
    }
}
