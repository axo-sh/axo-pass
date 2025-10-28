use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use apple_native_keyring_store::protected::Store;
use core_foundation::base::{CFType, CFTypeRef, TCFType};
use keyring_core::api::CredentialStoreApi;
use objc2_local_authentication::LAContext;
use security_framework::item;
use serde::Serialize;

static SERVICE_NAME: &str = "com.breakfastlabs.frittata";
static REQUIRE_USER_PRESENCE: &str = "RequireUserPresence"; // see also: WhenUnlockedThisDeviceOnly

#[derive(Clone, Serialize)]
pub struct PasswordEntry {
    pub key_id: String,
}

fn get_store() -> Result<Arc<Store>, keyring_core::Error> {
    Store::new().inspect_err(|e| {
        log::debug!("Failed to create store: {e}");
    })
}

pub fn has_password(key_id: &str) -> io::Result<bool> {
    log::debug!("Checking if password exists for key_id: {key_id}");
    let account = format!("gpg-key-{key_id}");

    // create an LAContext with objc2 and convert it to a core-foundation
    // CFTypeRef for security-framework
    // 1. LAContext::new() and setInteractionNotAllowed() are standard objc2 API
    //    calls
    // 2. LAContext is toll-free bridged with CFType
    // 3. We use wrap_under_get_rule which doesn't take ownership (uses "get rule"
    //    semantics)
    // 4. _context lives for the entire function scope, so the pointer remains valid
    let (_context, cf_context) = unsafe {
        let context = LAContext::new();
        context.setInteractionNotAllowed(true);
        let cf_context_ref = context.as_ref() as *const LAContext as CFTypeRef;
        let cf_context = CFType::wrap_under_get_rule(cf_context_ref);
        (context, cf_context)
    };

    let mut options = item::ItemSearchOptions::new();
    options
        .service(SERVICE_NAME)
        .account(account.as_str())
        .ignore_legacy_keychains()
        .class(item::ItemClass::generic_password())
        .load_attributes(false)
        .limit(item::Limit::All)
        .skip_authenticated_items(false)
        .local_authentication_context(Some(cf_context));

    let results = options.search();

    Ok(results.map(|r| !r.is_empty()).unwrap_or_else(|err| {
        if err.code() == -25308 {
            true
        } else {
            log::error!("Error searching for password: {err:#?}");
            false
        }
    }))
}

pub fn save_password(key_id: &str, password: &str) -> Result<(), keyring_core::Error> {
    log::debug!("Attempting to save password for key_id: {key_id}");
    let account = format!("gpg-key-{}", key_id);

    let mut modifiers = HashMap::new();
    modifiers.insert("access-policy", REQUIRE_USER_PRESENCE);

    let entry = get_store()?.build(SERVICE_NAME, &account, Some(&modifiers))?;

    log::debug!("Setting password for account: {account}");
    entry.set_password(password).inspect_err(|e| {
        log::error!("Failed to set password: {e}");
    })?;
    log::debug!("Password saved successfully to keychain!");
    Ok(())
}

pub fn get_password(key_id: &str) -> Result<Option<String>, keyring_core::Error> {
    log::debug!("Attempting to retrieve password for key_id: {key_id}");
    let account = format!("gpg-key-{key_id}");
    let entry = get_store()?
        .build(SERVICE_NAME, &account, None)
        .inspect_err(|e| {
            log::error!("Failed to build entry {e}");
        })?;

    log::debug!("Retrieving password for account: {account}");
    match entry.get_password() {
        Ok(password) => {
            log::debug!("Password retrieved successfully from keychain");
            Ok(Some(password))
        },
        Err(e) => {
            // If the error is "not found", return None
            // Otherwise return the error
            let err_str = e.to_string();
            log::error!("Error retrieving password: {err_str}");
            if err_str.contains("not found") || err_str.contains("errSecItemNotFound") {
                log::error!("Password not found in keychain");
                Ok(None)
            } else {
                Err(e)
            }
        },
    }
}
