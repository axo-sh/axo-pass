use std::os::raw::c_void;

use anyhow::anyhow;
use objc2::rc::Retained;
use objc2_core_foundation::{
    CFBoolean, CFData, CFDictionary, CFMutableDictionary, CFString, CFType,
};
use objc2_local_authentication::LAContext;
use objc2_security::{
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecReturnAttributes,
    kSecReturnData, kSecUseAuthenticationContext, kSecUseAuthenticationUI,
    kSecUseDataProtectionKeychain, kSecValueData,
};
use secrecy::SecretString;

use crate::la_context::THREAD_LA_CONTEXT;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::keychain_query::KeyChainQuery;

pub struct GenericPassword {
    pub account: String,
    pub password: SecretString,
}
pub struct GenericPasswordQuery {
    account: Option<String>,
    authenticate: bool,
}

impl GenericPasswordQuery {
    pub fn build() -> Self {
        GenericPasswordQuery {
            account: None,
            authenticate: true,
        }
    }

    pub fn with_account(mut self, account: &str) -> Self {
        self.account = Some(account.to_string());
        self
    }

    pub fn without_authentication(mut self) -> Self {
        self.authenticate = false;
        self
    }
}

static SERVICE_NAME: &str = "com.breakfastlabs.frittata";

impl GenericPasswordQuery {
    fn common_attrs(account: Option<&str>) -> Retained<CFMutableDictionary<CFString, CFType>> {
        unsafe {
            let query = CFMutableDictionary::<CFString, CFType>::empty();
            query.add(kSecClass, kSecClassGenericPassword);
            if let Some(account) = account {
                query.add(kSecAttrAccount, &CFString::from_str(account));
            }
            query.add(kSecAttrService, &CFString::from_str(SERVICE_NAME));
            query.add(kSecUseDataProtectionKeychain, CFBoolean::new(true));
            query.into()
        }
    }
}
impl KeyChainQuery for GenericPasswordQuery {
    type Item = GenericPassword;

    fn parse_result(&self, cf_type: &CFType) -> Result<Self::Item, KeychainError> {
        unsafe {
            let Some(cf_dict_ref) = cf_type.downcast_ref::<CFDictionary>() else {
                return Err(anyhow!("expected_dict").into());
            };

            let account = {
                let k_sec_attr_account = kSecAttrAccount as *const _ as *const c_void;
                let account_ptr = cf_dict_ref.value(k_sec_attr_account) as *const CFString;
                let Some(account_cfstr) = account_ptr.as_ref() else {
                    return Err(anyhow!("no account found").into());
                };
                account_cfstr.to_string()
            };

            let k_sec_value_data = kSecValueData as *const _ as *const c_void;
            let data_ptr = cf_dict_ref.value(k_sec_value_data) as *const CFData;
            let Some(Ok(passwd)) = data_ptr.as_ref().map(CFData::to_vec).map(String::from_utf8)
            else {
                return Err(anyhow!("no password found").into());
            };

            Ok(GenericPassword {
                account,
                password: passwd.into(),
            })
        }
    }

    fn build_query(&self) -> Retained<CFMutableDictionary<CFString, CFType>> {
        unsafe {
            let query = Self::common_attrs(self.account.as_deref());
            query.add(kSecReturnData, CFBoolean::new(true));
            query.add(kSecReturnAttributes, CFBoolean::new(true));
            if self.authenticate {
                query.add(kSecUseAuthenticationUI, CFBoolean::new(true));
                THREAD_LA_CONTEXT.with(|thread_la_context| {
                    let la_context =
                        thread_la_context.as_ref() as *const LAContext as *const CFType;
                    query.add(kSecUseAuthenticationContext, &*la_context);
                });
            } else {
                let la_context = LAContext::new();
                la_context.setInteractionNotAllowed(true);
                let la_context = la_context.as_ref() as *const LAContext as *const CFType;
                query.add(kSecUseAuthenticationContext, &*la_context);
            }
            query
        }
    }
}
