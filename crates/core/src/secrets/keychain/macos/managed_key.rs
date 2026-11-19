mod managed_ssh_key;
mod query;
mod shared;
mod utils;

use std::fmt::Debug;

use anyhow::bail;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
pub use managed_ssh_key::ManagedSshKey;
use objc2::rc::Retained;
use objc2_core_foundation::{
    CFArray, CFBoolean, CFData, CFDictionary, CFMutableDictionary, CFString, CFType,
};
use objc2_local_authentication::LAContext;
use objc2_security::{
    SecItemDelete, SecKey, kSecAttrAccessControl, kSecAttrApplicationLabel, kSecAttrApplicationTag,
    kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrLabel, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey,
    kSecMatchItemList, kSecPrivateKeyAttrs, kSecPublicKeyAttrs, kSecUseAuthenticationContext,
    kSecUseDataProtectionKeychain,
};
pub use query::ManagedKeyQuery;
pub use shared::KeyClass;
use ssh_key::public::KeyData;
use zeroize::Zeroizing;

use crate::secrets::keychain::macos::AccessControl;
use crate::secrets::keychain::errors::{CFErrorOut, KeychainError};
use crate::secrets::keychain::managed_key::shared::{alg, sign_alg};
use crate::secrets::keychain::managed_key::utils::sec1_to_ssh_ecdsa;

/// `kSecAttrApplicationTag` written on keys created with
/// [`KeyPolicy::Default`]. Keys without it were created before the policy
/// existed and carry the hardware access control.
const APP_ENFORCED_TAG: &str = "axo.ssh.app-enforced";

/// How a managed key's use is authorized. Fixed when the key is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPolicy {
    /// The Secure Enclave allows use without a prompt and the app evaluates a
    /// policy before each use. The app may skip the prompt for a granted app.
    Default,
    /// The Secure Enclave requires user presence for every use.
    AlwaysRequireAuth,
}

impl KeyPolicy {
    fn access_control(self) -> AccessControl {
        match self {
            KeyPolicy::Default => AccessControl::ManagedKeyAppEnforced,
            KeyPolicy::AlwaysRequireAuth => AccessControl::ManagedKey,
        }
    }

    fn tag(self) -> Option<&'static str> {
        match self {
            KeyPolicy::Default => Some(APP_ENFORCED_TAG),
            KeyPolicy::AlwaysRequireAuth => None,
        }
    }
}

pub struct ManagedKey {
    pub label: Option<String>,
    /// `kSecAttrApplicationTag`, read from the keychain item's attributes.
    /// `SecKeyCopyAttributes` on the key ref does not return it.
    tag: Option<String>,
    sec_key: Retained<SecKey>,
}

// to confirm: SecKey is safe to send between threads
// https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Multithreading/ThreadSafetySummary/ThreadSafetySummary.html
unsafe impl Send for ManagedKey {}

impl ManagedKey {
    pub fn common_attrs(label: Option<String>) -> Retained<CFMutableDictionary<CFString, CFType>> {
        let query = CFMutableDictionary::<CFString, CFType>::empty();
        unsafe {
            query.add(kSecClass, kSecClassKey);
            query.add(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            // we store in the data protection keychain (secure enclave)
            query.add(kSecUseDataProtectionKeychain, CFBoolean::new(true));
            if let Some(label) = label {
                query.add(kSecAttrLabel, &CFString::from_str(&label));
            }
        }
        query.into()
    }

    pub fn new(label: Option<String>, tag: Option<String>, sec_key: Retained<SecKey>) -> Self {
        ManagedKey {
            label,
            tag,
            sec_key,
        }
    }

    pub fn create(label: &str, policy: KeyPolicy) -> Result<ManagedKey, KeychainError> {
        Self::create_with_context(label, policy, None)
    }

    /// Create a managed key, optionally on a caller-owned `LAContext`. Secure
    /// Enclave key generation with a `UserPresence` access control prompts for
    /// biometrics, so the app broker passes its own context to draw that prompt
    /// in the app panel rather than the system dialog.
    pub fn create_with_context(
        label: &str,
        policy: KeyPolicy,
        la_context: Option<Retained<LAContext>>,
    ) -> Result<ManagedKey, KeychainError> {
        Self::create_secure_enclave(label, policy.access_control(), policy.tag(), la_context)
    }

    /// Create a key the app uses itself, such as `device-signing-key`. The
    /// Secure Enclave restricts it to this device and never prompts. It has no
    /// application tag, so it is not a [`KeyPolicy::Default`] SSH key.
    pub fn create_device_key(label: &str) -> Result<ManagedKey, KeychainError> {
        Self::create_secure_enclave(label, AccessControl::ManagedKeyAppEnforced, None, None)
    }

    fn create_secure_enclave(
        label: &str,
        access_control: AccessControl,
        tag: Option<&str>,
        la_context: Option<Retained<LAContext>>,
    ) -> Result<ManagedKey, KeychainError> {
        log::debug!("Creating new user key with label: {label}");
        unsafe {
            let public_attrs = CFMutableDictionary::<CFString, CFType>::empty();
            public_attrs.add(kSecAttrIsPermanent, CFBoolean::new(true));

            let private_attrs = CFMutableDictionary::<CFString, CFType>::empty();
            private_attrs.add(kSecAttrIsPermanent, CFBoolean::new(true));

            let access_control = access_control.to_sec_access_control()?;
            private_attrs.add(kSecAttrAccessControl, &*access_control);
            if let Some(tag) = tag {
                private_attrs.add(kSecAttrApplicationTag, &CFData::from_bytes(tag.as_bytes()));
            }

            if let Some(la_context) = &la_context {
                let la_context = Retained::as_ptr(la_context) as *const CFType;
                private_attrs.add(kSecUseAuthenticationContext, &*la_context);
            }

            let query = Self::common_attrs(Some(label.to_string()));
            query.add(kSecPublicKeyAttrs, &public_attrs);
            query.add(kSecPrivateKeyAttrs, &private_attrs);
            query.add(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
            query.add(
                kSecAttrApplicationLabel,
                &CFData::from_bytes(label.as_bytes()),
            );

            let mut cf_error = CFErrorOut::new();
            log::debug!("Calling SecKey::new_random_key...");
            let sec_key = SecKey::new_random_key(query.as_opaque(), cf_error.out());
            if let Some(cf_error) = cf_error.get() {
                // todo: may need to handle error codes
                log::error!("Error creating new managed key with label {label}: {cf_error:?}");
                return Err(KeychainError::Generic(anyhow::anyhow!(
                    cf_error.to_string()
                )));
            }
            let Some(sec_key) = sec_key else {
                return Err(KeychainError::KeyCreationFailed);
            };

            // SecKey::new_random_key follows the Create Rule and hands back an
            // owned CFRetained, so this takes it as-is. Retaining again would
            // leak the key, and with it the LAContext the key was created on.
            let managed_key = ManagedKey::new(
                Some(label.to_string()),
                tag.map(String::from),
                sec_key.into(),
            );
            log::debug!("Created new managed key: {managed_key:?}");
            Ok(managed_key)
        }
    }

    /// In-memory software P-256 key with no keychain item, for tests.
    #[cfg(test)]
    pub(crate) fn create_software_for_test() -> Result<ManagedKey, KeychainError> {
        use objc2_core_foundation::CFNumber;
        use objc2_security::kSecAttrKeySizeInBits;

        unsafe {
            let private_attrs = CFMutableDictionary::<CFString, CFType>::empty();
            private_attrs.add(kSecAttrIsPermanent, CFBoolean::new(false));

            // A key with no token needs its size. The Secure Enclave token
            // sets it for the keys of `create_secure_enclave`.
            let query = CFMutableDictionary::<CFString, CFType>::empty();
            query.add(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            query.add(kSecAttrKeySizeInBits, &CFNumber::new_i32(256));
            query.add(kSecPrivateKeyAttrs, &private_attrs);

            let mut cf_error = CFErrorOut::new();
            let sec_key = SecKey::new_random_key(query.as_opaque(), cf_error.out());
            if let Some(cf_error) = cf_error.get() {
                return Err(KeychainError::Generic(anyhow::anyhow!(
                    cf_error.to_string()
                )));
            }
            let Some(sec_key) = sec_key else {
                return Err(KeychainError::KeyCreationFailed);
            };
            Ok(ManagedKey::new(None, None, sec_key.into()))
        }
    }

    pub fn is_private(&self) -> bool {
        unsafe {
            self.sec_key
                .is_algorithm_supported(objc2_security::SecKeyOperationType::Decrypt, alg())
        }
    }

    pub fn app_label(&self) -> Option<String> {
        unsafe {
            let attrs = self.sec_key.attributes().unwrap();
            let attr: &CFDictionary<CFString, CFData> = attrs.cast_unchecked();
            attr.get(kSecAttrApplicationLabel)
                .map(|d| b64.encode(d.as_bytes_unchecked()))
        }
    }

    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// The policy the key was created with. Untagged keys predate the policy
    /// and carry the hardware access control.
    pub fn policy(&self) -> KeyPolicy {
        match self.tag() {
            Some(APP_ENFORCED_TAG) => KeyPolicy::Default,
            _ => KeyPolicy::AlwaysRequireAuth,
        }
    }

    pub fn public_key(&self) -> Result<KeyData, KeychainError> {
        let pub_key_bytes = self.public_key_sec1()?;
        sec1_to_ssh_ecdsa(&pub_key_bytes).map_err(|err| {
            KeychainError::PublicKeyUnavailable(format!(
                "Failed to convert public key to SSH format: {err}"
            ))
        })
    }

    /// Public key as an uncompressed SEC1 point.
    pub fn public_key_sec1(&self) -> Result<Vec<u8>, KeychainError> {
        // note SecKeyCopyExternalRepresentation returns public key in
        // ANSI X9.63 format (04 || X || Y [ || K])
        unsafe {
            let mut cf_error = CFErrorOut::new();
            let Some(pub_key) = self.sec_key.public_key() else {
                return Err(KeychainError::PublicKeyUnavailable(
                    "No public key".to_string(),
                ));
            };
            let pub_key_ext = pub_key.external_representation(cf_error.out());
            if let Some(cf_error) = cf_error.get() {
                return Err(KeychainError::PublicKeyUnavailable(format!(
                    "Error getting public key: {cf_error:?}"
                )));
            }
            let Some(pub_key_ext) = pub_key_ext else {
                return Err(KeychainError::PublicKeyUnavailable(
                    "No public key representation".to_string(),
                ));
            };
            Ok(pub_key_ext.as_bytes_unchecked().to_vec())
        }
    }

    pub fn delete(&self) -> anyhow::Result<()> {
        if self.label.is_none() {
            bail!("Cannot delete managed key without label.");
        }
        unsafe {
            let query = Self::common_attrs(self.label.clone());
            query.add(kSecMatchItemList, &CFArray::from_objects(&[&*self.sec_key]));

            // TODO: query to ensure we only delete the desired item.
            let status = SecItemDelete(query.as_opaque());
            log::debug!("Deleted key status: {}", status);
        }
        Ok(())
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Option<String> {
        unsafe {
            let mut cf_error = CFErrorOut::new();

            log::debug!(
                "Encrypting data size={} with allowed block size {}",
                plaintext.len(),
                self.sec_key.block_size()
            );

            let Some(public_key) = self.sec_key.public_key() else {
                log::debug!("No public key available for encryption");
                return None;
            };

            let res = public_key
                .encrypted_data(alg(), &CFData::from_bytes(plaintext), cf_error.out())
                .map(|enc| b64.encode(enc.as_bytes_unchecked()));
            if let Some(cf_error) = cf_error.get() {
                log::debug!(
                    "Error encrypting data (size={}) with key {self:?}: {:?}",
                    plaintext.len(),
                    cf_error
                );
                return None;
            }
            res
        }
    }

    /// ECIES ciphertext of `plaintext` to the P-256 public key `public_sec1`,
    /// with the algorithm of [`Self::encrypt`]. `public_sec1` is an
    /// uncompressed SEC1 point. Makes no keychain call. The ciphertext is raw
    /// bytes, not base64.
    pub fn encrypt_to(public_sec1: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, KeychainError> {
        unsafe {
            let attrs = CFMutableDictionary::<CFString, CFType>::empty();
            attrs.add(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            attrs.add(kSecAttrKeyClass, KeyClass::Public.as_objc());

            let mut cf_error = CFErrorOut::new();
            let public_key = SecKey::with_data(
                &CFData::from_bytes(public_sec1),
                attrs.as_opaque(),
                cf_error.out(),
            );
            if let Some(cf_error) = cf_error.get() {
                return Err(KeychainError::PublicKeyCreationFailed(anyhow::anyhow!(
                    cf_error.to_string()
                )));
            }
            let Some(public_key) = public_key else {
                return Err(KeychainError::PublicKeyCreationFailed(anyhow::anyhow!(
                    "No public key from SEC1 bytes"
                )));
            };

            let mut cf_error = CFErrorOut::new();
            let ciphertext = public_key
                .encrypted_data(alg(), &CFData::from_bytes(plaintext), cf_error.out())
                .map(|data| data.as_bytes_unchecked().to_vec());
            if let Some(cf_error) = cf_error.get() {
                return Err(KeychainError::Generic(anyhow::anyhow!(
                    "Encryption to public key failed: {cf_error}"
                )));
            }
            ciphertext.ok_or(KeychainError::Generic(anyhow::anyhow!(
                "No ciphertext returned"
            )))
        }
    }

    pub fn decrypt(&self, b64_ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let ciphertext = b64.decode(b64_ciphertext).ok()?;
        self.decrypt_bytes(&ciphertext)
    }

    /// Plaintext of the raw ECIES ciphertext `ciphertext`. Can prompt.
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        unsafe {
            let ciphertext = &CFData::from_bytes(ciphertext);
            let mut cf_error = CFErrorOut::new();
            let res = self
                .sec_key
                .decrypted_data(alg(), ciphertext, cf_error.out())
                .map(|data| Zeroizing::new(data.as_bytes_unchecked().to_vec()));
            match cf_error.get() {
                None => res,
                Some(cf_error) => {
                    log::debug!("Error decrypting data with key {self:?}: {:?}", cf_error);
                    None
                },
            }
        }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeychainError> {
        unsafe {
            let mut cf_error = CFErrorOut::new();
            let res = self
                .sec_key
                .signature(sign_alg(), &CFData::from_bytes(data), cf_error.out())
                .map(|sig| sig.as_bytes_unchecked().to_vec());
            if let Some(cf_error) = cf_error.get() {
                return Err(KeychainError::SigningFailed(cf_error.to_string()));
            }
            res.ok_or(KeychainError::SigningFailed(
                "No signature returned".to_string(),
            ))
        }
    }
}

impl Debug for ManagedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedKey")
            .field("label", &self.label)
            .field("app_label", &self.app_label())
            .field("tag", &self.tag())
            .field("policy", &self.policy())
            .field("is_private", &self.is_private())
            .finish()
    }
}
