use std::os::raw::c_void;

use anyhow::anyhow;
use objc2::rc::Retained;
use objc2_core_foundation::{CFBoolean, CFDictionary, CFMutableDictionary, CFString, CFType, Type};
use objc2_local_authentication::LAContext;
use objc2_security::{
    SecKey, kSecAttrKeyClass, kSecAttrLabel, kSecReturnAttributes, kSecReturnRef,
    kSecUseAuthenticationContext, kSecValueRef,
};

use crate::core::la_context::THREAD_LA_CONTEXT;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::keychain_query::KeyChainQuery;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::keychain::managed_key::shared::KeyClass;

pub struct ManagedKeyQuery {
    label: Option<String>,
    key_class: Option<KeyClass>,
}

impl ManagedKeyQuery {
    pub fn build() -> Self {
        ManagedKeyQuery {
            label: None,
            key_class: None,
        }
    }

    pub fn with_label(mut self, label: &str) -> Self {
        self.label = Some(label.to_string());
        self
    }

    pub fn with_key_class(mut self, key_class: KeyClass) -> Self {
        self.key_class = Some(key_class);
        self
    }
}

impl KeyChainQuery for ManagedKeyQuery {
    type Item = ManagedKey;

    fn parse_result(&self, cf_type: &CFType) -> Result<Self::Item, KeychainError> {
        unsafe {
            let Some(cf_dict_ref) = cf_type.downcast_ref::<CFDictionary>() else {
                return Err(anyhow!("expected dict").into());
            };
            // we do the pointer dance because the CFDictionary is opaque and
            // contains varying types.
            let label_ptr =
                cf_dict_ref.value(kSecAttrLabel as *const _ as *const c_void) as *const CFString;
            let label = label_ptr.as_ref();

            let seckey_ptr =
                cf_dict_ref.value(kSecValueRef as *const _ as *const c_void) as *const SecKey;
            let Some(sec_key) = seckey_ptr.as_ref() else {
                return Err(anyhow!("no SecKey found").into());
            };
            Ok(ManagedKey::new(
                label.as_ref().map(|l| l.to_string()),
                sec_key.retain().into(),
            ))
        }
    }

    fn build_query(&self) -> Retained<CFMutableDictionary<CFString, CFType>> {
        unsafe {
            let query = ManagedKey::common_attrs(self.label.clone());

            // if only kSecReturnRef is specified, a SecKeyRef is returned
            // otherwise a dict with attributes and including SecKeyRef is returned
            // where SecKeyRef is under the kSecValueRef key
            // https://developer.apple.com/documentation/security/item-return-result-keys
            // we request both because the user label is only present in the return
            // attributes
            query.add(kSecReturnRef, CFBoolean::new(true));
            query.add(kSecReturnAttributes, CFBoolean::new(true));
            if let Some(key_class) = &self.key_class {
                query.add(kSecAttrKeyClass, key_class.as_objc());
            }

            // reuse our LAContext
            THREAD_LA_CONTEXT.with(|thread_la_context| {
                let la_context = thread_la_context.as_ref() as *const LAContext as *const CFType;
                query.add(kSecUseAuthenticationContext, &*la_context);
            });
            query
        }
    }
}
