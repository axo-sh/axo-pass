use core::ptr::{self, NonNull};
use std::fmt;

use objc2_core_foundation::CFDictionary;
use objc2_security::{
    SecCSFlags, SecCode, SecCodeSignatureFlags, SecStaticCode, kSecCodeInfoMainExecutable,
};
use url::Url;

use crate::core::objc_helpers::dict_proxy::CFDictionaryProxy;

pub struct SigningInfo {
    // also see SecCode::copy_path
    pub main_executable: Url,

    pub display_name: String,

    // e.g. "com.apple.ssh-add"
    pub identifier: String,

    // entitlements-dict["com.apple.developer.team-identifier"]
    pub team_identifier: String,

    // binary format, e.g. Mach-O thin (arm64e)
    pub format: String,

    /// Code-signing flags bitmask. See SecCodeSignatureFlags
    pub flags: u32,
}

impl SigningInfo {
    // this gets signing information for a given SecStaticCode, which can be used to
    // determine the code signature and entitlements of a process. This is useful
    // for determining if a process is part of axo/axo-pass or not.
    pub fn from_sec_code(static_code: &SecStaticCode) -> Option<SigningInfo> {
        unsafe {
            let mut raw: *const CFDictionary = ptr::null();
            let status = SecCode::copy_signing_information(
                static_code,
                SecCSFlags(0),
                NonNull::new_unchecked(&mut raw),
            );
            if status != 0 || raw.is_null() {
                return None;
            }
            let dict = CFDictionaryProxy::from_raw(raw)?;
            // uncomment to show extra debug of the raw signing info dict
            // log::debug!("SigningInfo: {dict:?}");

            let identifier = dict.get_string("identifier").unwrap_or_default();
            let main_executable = dict.get_url(kSecCodeInfoMainExecutable.to_string());
            let format = dict.get_string("format").unwrap_or_default();
            let flags = dict.get_u32("flags").unwrap_or(0);

            let display_name = dict
                .get_dict("info-plist")
                .and_then(|info| {
                    info.get_string("CFBundleDisplayName")
                        .or_else(|| info.get_string("CFBundleName"))
                })
                .or_else(|| {
                    main_executable
                        .as_ref()
                        .and_then(|url| url.path_segments())
                        .and_then(|mut segments| segments.next_back())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default();

            let team_identifier = dict
                .get_dict("entitlements-dict")
                .and_then(|e| e.get_string("com.apple.developer.team-identifier"))
                .unwrap_or_default();

            Some(SigningInfo {
                identifier,
                main_executable: main_executable.unwrap_or(Url::parse("file:///unknown").unwrap()),
                display_name,
                team_identifier,
                format,
                flags,
            })
        }
    }

    /// Returns the best human-readable label for user display.
    /// Prefers display_name (e.g. "Axo Pass"), falls back to identifier
    /// (e.g. "com.apple.ssh-add"), then the executable path.
    pub fn display_label(&self) -> String {
        if !self.display_name.is_empty() {
            self.display_name.clone()
        } else if !self.identifier.is_empty() {
            self.identifier.clone()
        } else {
            self.main_executable
                .path_segments()
                .and_then(|mut segments| segments.next_back())
                .unwrap_or("?")
                .to_string()
        }
    }

    #[allow(dead_code)]
    /// Returns true if the hardened runtime flag is set (flags & 0x10000).
    pub fn is_hardened_runtime(&self) -> bool {
        self.flags & SecCodeSignatureFlags::Runtime.bits() != 0
    }
}

impl fmt::Debug for SigningInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningInfo")
            .field("main_executable", &self.main_executable.to_string())
            .field("identifier", &self.identifier)
            .field("display_name", &self.display_name)
            .field("team_identifier", &self.team_identifier)
            .field("format", &self.format)
            .field("flags", &format!("0x{:x}", self.flags))
            .finish()
    }
}
