use std::ptr::{self, NonNull};

use objc2_core_foundation::{CFError, CFRetained};

/// Receives the `CFError` a Security call reports through its out-parameter,
/// and releases it on drop.
pub struct CFErrorOut(*mut CFError);

impl Default for CFErrorOut {
    fn default() -> Self {
        Self::new()
    }
}

impl CFErrorOut {
    pub fn new() -> Self {
        Self(ptr::null_mut())
    }

    /// The out-parameter to pass to the Security call.
    pub fn out(&mut self) -> &mut *mut CFError {
        &mut self.0
    }

    /// The error the call reported, if any.
    pub fn get(&self) -> Option<&CFError> {
        unsafe { self.0.as_ref() }
    }
}

impl Drop for CFErrorOut {
    fn drop(&mut self) {
        if let Some(error) = NonNull::new(self.0) {
            drop(unsafe { CFRetained::from_raw(error) });
        }
    }
}
