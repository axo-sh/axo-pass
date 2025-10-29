use std::ptr;

use anyhow::{anyhow, bail};
use objc2::rc::Retained;
use objc2_core_foundation::{CFArray, CFMutableDictionary, CFString, CFType};
use objc2_security::{
    SecItemCopyMatching, errSecInteractionNotAllowed, errSecSuccess, errSecUserCanceled,
    kSecMatchLimit, kSecMatchLimitAll,
};

use crate::secrets::keychain::errors::KeychainError;

pub trait KeyChainQuery {
    type Item;

    fn parse_result(&self, result: &CFType) -> Result<Self::Item, KeychainError>;
    fn build_query(&self) -> Retained<CFMutableDictionary<CFString, CFType>>;

    fn one(&self) -> Result<Option<Self::Item>, KeychainError> {
        unsafe {
            let query = self.build_query();
            let mut ret: *const CFType = ptr::null();
            let res = SecItemCopyMatching(query.as_opaque(), &mut ret);
            #[allow(non_upper_case_globals)]
            match res {
                errSecSuccess if ret.is_null() => Ok(None),
                errSecSuccess => self.parse_result(&*ret).map(Some),
                errSecUserCanceled => Err(KeychainError::UserCancelled),
                errSecInteractionNotAllowed => Err(KeychainError::ItemNotAccessible),
                _ => Err(anyhow!("got error code: {res}").into()),
            }
        }
    }

    fn list(&self) -> anyhow::Result<Vec<Self::Item>> {
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
