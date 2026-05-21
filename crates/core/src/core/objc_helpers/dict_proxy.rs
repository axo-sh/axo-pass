use core::ptr::NonNull;
use std::os::raw::c_void;

use objc2::rc::Retained;
use objc2_core_foundation::{
    CFDictionary, CFNumber, CFRetained, CFString, CFType, CFURL, ConcreteType,
};
use url::Url;

#[derive(Debug)]
pub struct CFDictionaryProxy {
    dict: Retained<CFDictionary>,
}

impl CFDictionaryProxy {
    pub unsafe fn from_raw(raw: *const CFDictionary) -> Option<Self> {
        let dict = unsafe { Retained::from_raw(raw as *mut CFDictionary)? };
        Some(CFDictionaryProxy { dict })
    }

    /// Looks up `key` and downcasts the value to `V`, returning an owned
    /// `CFRetained<V>`.
    pub fn get<V: ConcreteType>(&self, key: &str) -> Option<CFRetained<V>> {
        unsafe {
            let k = CFString::from_str(key);
            let ptr = self.dict.value(&*k as *const CFString as *const c_void);
            if ptr.is_null() {
                return None;
            }
            let cf_type = &*(ptr as *const CFType);
            let v = cf_type.downcast_ref::<V>()?;
            Some(CFRetained::retain(NonNull::new_unchecked(
                v as *const V as *mut V,
            )))
        }
    }

    /// Looks up `key` and returns the value as a `String` (if it is a
    /// `CFString`).
    pub fn get_string<K: AsRef<str>>(&self, key: K) -> Option<String> {
        self.get::<CFString>(key.as_ref()).map(|s| s.to_string())
    }

    pub fn get_url<K: AsRef<str>>(&self, key: K) -> Option<Url> {
        self.get::<CFURL>(key.as_ref())
            .and_then(|url| CFURL::string(&url).to_string().parse().ok())
    }

    /// Looks up `key` and returns the value as a `u32` (if it is a `CFNumber`).
    pub fn get_u32(&self, key: &str) -> Option<u32> {
        self.get::<CFNumber>(key)?.as_i32().map(|v| v as u32)
    }

    /// Looks up `key` and returns the value as a nested `CFDictionaryProxy`.
    pub fn get_dict(&self, key: &str) -> Option<CFDictionaryProxy> {
        self.get::<CFDictionary>(key)
            .map(|dict| CFDictionaryProxy { dict: dict.into() })
    }
}
