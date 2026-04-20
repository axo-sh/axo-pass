use core::ptr::{self, NonNull};

use anyhow::bail;
use objc2::Message;
use objc2::rc::Retained;
use objc2_core_foundation::{CFMutableDictionary, CFNumber, CFString, CFType};
use objc2_security::{SecCSFlags, SecCode, SecStaticCode, kSecGuestAttributePid};

// use SecCodeCopyGuestWithAttributes to look up SecCode for a given pid, which
// can be used to get the SecStaticCode representing the on-disk executable and
// its signing information. https://docs.rs/objc2-security/latest/objc2_security/fn.SecCodeCopyGuestWithAttributes.html
// https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys
pub fn get_sec_code_for_pid(pid: u32) -> anyhow::Result<Retained<SecCode>> {
    let mut code_ptr: *mut SecCode = ptr::null_mut();

    let attrs = CFMutableDictionary::<CFString, CFType>::empty();
    let pid_num = CFNumber::new_i32(pid as i32);

    unsafe {
        attrs.add(kSecGuestAttributePid, &pid_num);

        // 1. look up the SecCode for the given pid
        let status = SecCode::copy_guest_with_attributes(
            None,
            Some(attrs.as_opaque()),
            SecCSFlags(0),
            NonNull::new_unchecked(&mut code_ptr),
        );
        if status != 0 || code_ptr.is_null() {
            bail!("SecCodeCopyGuestWithAttributes failed for pid {pid}: {status}");
        }
        Ok(SecCode::retain(&*code_ptr))
    }
}

// convert a SecCode to SecStaticCode to get signing information and path
pub fn get_static_code_for_sec_code(code: &SecCode) -> anyhow::Result<Retained<SecStaticCode>> {
    let mut static_code_ptr: *const SecStaticCode = ptr::null();
    unsafe {
        let status =
            code.copy_static_code(SecCSFlags(0), NonNull::new_unchecked(&mut static_code_ptr));
        if status != 0 || static_code_ptr.is_null() {
            bail!("SecCodeCopyStaticCode failed: {status}");
        }
        Ok(SecStaticCode::retain(&*static_code_ptr))
    }
}

// Host is typically mach_kernel, need to investigate if there are other
// possible values
pub fn get_host_for_sec_code(code: &SecCode) -> anyhow::Result<Retained<SecStaticCode>> {
    let mut host_ptr: *mut SecCode = ptr::null_mut();
    unsafe {
        let status = SecCode::copy_host(code, SecCSFlags(0), NonNull::new_unchecked(&mut host_ptr));
        if status != 0 || host_ptr.is_null() {
            bail!("SecCodeCopyHost failed: {status}");
        }
        let host_code = Retained::from_raw(host_ptr).unwrap();
        get_static_code_for_sec_code(&host_code)
    }
}
