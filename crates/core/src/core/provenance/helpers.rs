use core::ptr::{self, NonNull};

use anyhow::{Context, bail};
use objc2::Message;
use objc2::rc::Retained;
use objc2_core_foundation::{CFData, CFMutableDictionary, CFNumber, CFString, CFType};
use objc2_security::{
    SecCSFlags, SecCode, SecRequirement, SecStaticCode, kSecGuestAttributeAudit,
    kSecGuestAttributePid,
};

// use SecCodeCopyGuestWithAttributes to look up SecCode for a given pid, which
// can be used to get the SecStaticCode representing the on-disk executable and
// its signing information. https://docs.rs/objc2-security/latest/objc2_security/fn.SecCodeCopyGuestWithAttributes.html
// https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys
pub fn get_sec_code_for_pid(pid: u32) -> anyhow::Result<Retained<SecCode>> {
    let attrs = CFMutableDictionary::<CFString, CFType>::empty();
    let pid_num = CFNumber::new_i32(pid as i32);
    unsafe {
        attrs.add(kSecGuestAttributePid, &pid_num);
        copy_guest(&attrs).with_context(|| format!("for pid {pid}"))
    }
}

/// Look up the SecCode for an audit token.
///
/// The token names one specific process instance, so unlike a pid it cannot be
/// recycled onto a different process between the lookup and any later use.
pub fn get_sec_code_for_audit_token(token: &[u8]) -> anyhow::Result<Retained<SecCode>> {
    let attrs = CFMutableDictionary::<CFString, CFType>::empty();
    unsafe {
        let data = CFData::new(None, token.as_ptr(), token.len() as isize)
            .context("Could not wrap the audit token")?;
        attrs.add(kSecGuestAttributeAudit, &data);
        copy_guest(&attrs).context("for an audit token")
    }
}

/// SecCode for the calling process.
pub fn get_sec_code_for_self() -> anyhow::Result<Retained<SecCode>> {
    let mut code_ptr: *mut SecCode = ptr::null_mut();
    unsafe {
        let status = SecCode::copy_self(SecCSFlags(0), NonNull::new_unchecked(&mut code_ptr));
        if status != 0 || code_ptr.is_null() {
            bail!("SecCodeCopySelf failed: {status}");
        }
        Retained::from_raw(code_ptr).context("SecCodeCopySelf returned nothing")
    }
}

/// # Safety
///
/// `attrs` values must be of the type the matching guest attribute key expects.
unsafe fn copy_guest(
    attrs: &CFMutableDictionary<CFString, CFType>,
) -> anyhow::Result<Retained<SecCode>> {
    let mut code_ptr: *mut SecCode = ptr::null_mut();
    unsafe {
        let status = SecCode::copy_guest_with_attributes(
            None,
            Some(attrs.as_opaque()),
            SecCSFlags(0),
            NonNull::new_unchecked(&mut code_ptr),
        );
        if status != 0 || code_ptr.is_null() {
            bail!("SecCodeCopyGuestWithAttributes failed: {status}");
        }
        Retained::from_raw(code_ptr).context("SecCodeCopyGuestWithAttributes returned nothing")
    }
}

/// Check `code` against a code requirement in text form, e.g.
/// `anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`.
///
/// This validates the running code, not just the file on disk, so it is not
/// defeated by replacing the executable after the process started.
pub fn check_requirement(code: &SecCode, requirement: &str) -> anyhow::Result<()> {
    let mut req_ptr: *mut SecRequirement = ptr::null_mut();
    unsafe {
        let text = CFString::from_str(requirement);
        let status = SecRequirement::create_with_string(
            &text,
            SecCSFlags(0),
            NonNull::new_unchecked(&mut req_ptr),
        );
        if status != 0 || req_ptr.is_null() {
            bail!("Could not compile the code requirement {requirement:?}: {status}");
        }
        let req = Retained::from_raw(req_ptr)
            .context("SecRequirementCreateWithString returned nothing")?;

        let status = code.check_validity(SecCSFlags(0), Some(&req));
        if status != 0 {
            bail!("Code requirement {requirement:?} not satisfied: {status}");
        }
    }
    Ok(())
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

pub use crate::core::provenance::kinfo::get_parent_pid;

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
