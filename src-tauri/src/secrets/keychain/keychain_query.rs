use std::ptr;

use anyhow::bail;
use objc2::rc::Retained;
use objc2_core_foundation::{CFArray, CFMutableDictionary, CFString, CFType};
use objc2_security::{SecItemCopyMatching, errSecSuccess, kSecMatchLimit, kSecMatchLimitAll};

pub trait KeyChainQuery {
    type Item;

    fn parse_result(&self, result: &CFType) -> anyhow::Result<Self::Item>;
    fn build_query(&self) -> Retained<CFMutableDictionary<CFString, CFType>>;

    fn one(&self) -> anyhow::Result<Option<Self::Item>> {
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
            self.parse_result(&*ret).map(Some)
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
