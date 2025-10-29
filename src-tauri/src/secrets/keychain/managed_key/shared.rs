use objc2_core_foundation::CFString;
use objc2_security::{
    SecKeyAlgorithm, kSecAttrKeyClassPrivate, kSecAttrKeyClassPublic,
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
};

pub fn alg() -> &'static SecKeyAlgorithm {
    unsafe { kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM }
}

pub enum KeyClass {
    Public,  // encryption
    Private, // decryption
}

impl KeyClass {
    pub fn as_objc(&self) -> &CFString {
        unsafe {
            match self {
                KeyClass::Public => kSecAttrKeyClassPublic,
                KeyClass::Private => kSecAttrKeyClassPrivate,
            }
        }
    }
}
