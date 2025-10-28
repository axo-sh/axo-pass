use std::os::raw::c_void;
use std::ptr;

use anyhow::bail;
use objc2::rc::Retained;
use objc2_core_foundation::{
    CFArray, CFBoolean, CFData, CFDictionary, CFError, CFMutableDictionary, CFString, CFType, Type,
};
use objc2_security::{
    SecAccessControl, SecAccessControlCreateFlags, SecItemCopyMatching, SecKey, errSecSuccess,
    kSecAttrAccessControl, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAttrApplicationLabel,
    kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrLabel, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey,
    kSecMatchLimit, kSecMatchLimitAll, kSecPrivateKeyAttrs, kSecPublicKeyAttrs,
    kSecReturnAttributes, kSecReturnRef, kSecUseDataProtectionKeychain, kSecValueRef,
};

use crate::secrets::managed_key::{KeyClass, ManagedKey};

pub struct KeyChainQuery {
    label: Option<String>,
    key_class: Option<KeyClass>,
}

impl KeyChainQuery {
    pub fn build() -> Self {
        KeyChainQuery {
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

    pub fn one(&self) -> anyhow::Result<Option<ManagedKey>> {
        unsafe {
            let query = self.build_query();
            let mut ret: *const CFType = ptr::null();
            let res = SecItemCopyMatching(query.as_opaque(), &mut ret);
            if ret.is_null() {
                log::debug!("ret is null");
                return Ok(None);
            }
            if res != errSecSuccess {
                log::debug!("got error code: {res}");
                bail!("got error code: {res}");
            }
            get_managed_key_from_result(ret).map(Some)
        }
    }

    pub fn list(&self) -> anyhow::Result<Vec<ManagedKey>> {
        unsafe {
            let query = self.build_query();
            query.add(kSecMatchLimit, kSecMatchLimitAll);
            let mut ret: *const CFType = ptr::null(); // CFTypeRef
            let res = SecItemCopyMatching(query.as_opaque(), &mut ret);

            if ret.is_null() {
                log::debug!("ret is null");
                return Ok(vec![]);
            }
            if res != errSecSuccess {
                log::debug!("got error code: {res}");
                bail!("got error code: {res}");
            }

            let cf_type_ret = &*ret;
            let Some(cf_array) = cf_type_ret.downcast_ref::<CFArray>() else {
                bail!("expected CFArray result");
            };

            let mut managed_keys = Vec::new();
            for i in 0..cf_array.len() {
                let el: *const CFType = cf_array.value_at_index(i.try_into().unwrap()).cast();
                let managed_key = get_managed_key_from_result(el)?;
                managed_keys.push(managed_key);
            }
            Ok(managed_keys)
        }
    }

    fn build_query(&self) -> Retained<CFMutableDictionary<CFString, CFType>> {
        unsafe {
            let query = CFMutableDictionary::<CFString, CFType>::empty();

            query.add(kSecClass, kSecClassKey);
            query.add(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);

            // we store in the data protection keychain (secure enclave)
            query.add(kSecUseDataProtectionKeychain, CFBoolean::new(true));

            // if only kSecReturnRef is specified, a SecKeyRef is returned
            // otherwise a dict with attributes and including SecKeyRef is returned
            // where SecKeyRef is under the kSecValueRef key
            // https://developer.apple.com/documentation/security/item-return-result-keys
            // we request both because the user label is only present in the return
            // attributes
            query.add(kSecReturnRef, CFBoolean::new(true));
            query.add(kSecReturnAttributes, CFBoolean::new(true));

            // if let Some(app_label) = &self.app_label {
            //     query.add(
            //         kSecAttrApplicationLabel,
            //         &CFData::from_bytes(&b64.decode(app_label).unwrap()),
            //     );
            // }
            if let Some(label) = &self.label {
                query.add(kSecAttrLabel, &CFString::from_str(label));
            }
            if let Some(key_class) = &self.key_class {
                query.add(kSecAttrKeyClass, key_class.as_objc());
            }
            query.into()
        }
    }
}

fn get_managed_key_from_result(el: *const CFType) -> anyhow::Result<ManagedKey> {
    unsafe {
        let cf_type = &*el;
        let Some(cf_dict_ref) = cf_type.downcast_ref::<CFDictionary>() else {
            bail!("unexpected type in returned array");
        };
        // we do the pointer dance because the CFDictionary is opaque and
        // contains varying types.
        let label_ptr =
            cf_dict_ref.value(kSecAttrLabel as *const _ as *const c_void) as *const CFString;
        let label = label_ptr.as_ref();

        let seckey_ptr =
            cf_dict_ref.value(kSecValueRef as *const _ as *const c_void) as *const SecKey;
        let Some(sec_key) = seckey_ptr.as_ref() else {
            bail!("no SecKey ref found in dict");
        };
        Ok(ManagedKey::new(
            label.as_ref().map(|l| l.to_string()),
            sec_key.retain().into(),
        ))
    }
}

fn create_access_control_flags() -> anyhow::Result<Retained<SecAccessControl>> {
    unsafe {
        let mut cf_error_ptr: *mut CFError = ptr::null_mut();
        // https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/privatekeyusage?language=objc
        let access_control = SecAccessControl::with_flags(
            None,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            SecAccessControlCreateFlags::UserPresence
                | SecAccessControlCreateFlags::PrivateKeyUsage,
            &mut cf_error_ptr,
        );
        if !cf_error_ptr.is_null() {
            let cf_error = &*cf_error_ptr;
            bail!("Failed to create SecAccessControl: {cf_error:?}");
        }
        let Some(access_control) = access_control else {
            bail!("Failed to create SecAccessControl: unknown error");
        };
        Ok(access_control.into())
    }
}

pub fn new_user_key(label: &str) -> anyhow::Result<ManagedKey> {
    log::debug!("Creating new user key with label: {}", label);
    unsafe {
        let public_attrs = CFMutableDictionary::<CFString, CFType>::empty();
        public_attrs.add(kSecAttrIsPermanent, CFBoolean::new(true));

        let private_attrs = CFMutableDictionary::<CFString, CFType>::empty();
        private_attrs.add(kSecAttrIsPermanent, CFBoolean::new(true));
        private_attrs.add(kSecAttrAccessControl, &*create_access_control_flags()?);

        let query = CFMutableDictionary::<CFString, CFType>::empty();

        // key type
        query.add(kSecClass, kSecClassKey);
        query.add(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
        query.add(kSecPublicKeyAttrs, &public_attrs);
        query.add(kSecPrivateKeyAttrs, &private_attrs);

        // we store in the data protection keychain (secure enclave)
        query.add(kSecUseDataProtectionKeychain, CFBoolean::new(true));
        query.add(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);

        query.add(kSecAttrLabel, &CFString::from_str(label));
        query.add(
            kSecAttrApplicationLabel,
            &CFData::from_bytes(label.as_bytes()),
        );

        let mut cf_error_ptr: *mut CFError = ptr::null_mut();
        log::debug!("Calling SecKey::new_random_key...");
        let sec_key = SecKey::new_random_key(query.as_opaque(), &mut cf_error_ptr);
        if !cf_error_ptr.is_null() {
            let cf_error = &*cf_error_ptr;
            bail!("Failed to create SecKey: {cf_error:?}");
        }
        let Some(sec_key) = sec_key else {
            bail!("Failed to create SecKey: unknown error");
        };

        let managed_key = ManagedKey::new(Some(label.to_string()), sec_key.retain().into());
        log::debug!("Created new managed key: {:?}", managed_key);
        Ok(managed_key)
    }
}
