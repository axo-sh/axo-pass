use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

use super::*;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::model::{Vault, VaultFolder};

mod envelope;
mod ids;
mod items;
mod signature;

/// Vault named "Filled" with entries of every kind the vault file holds.
fn filled_vault() -> EncryptedVault {
    let mut vault = Vault::new_for_test();
    vault.name = Some("Filled".to_string());
    vault.fill_for_test();
    vault.to_encrypted(true).unwrap()
}

/// Signer of the test files, the test device key.
fn signer() -> TestSigner {
    TestSigner::device()
}

/// Format 2 file contents of `vault`, signed by [`signer`].
fn contents_of(vault: &EncryptedVault) -> String {
    vault.to_file_contents(&signer()).unwrap()
}

/// Verify and parse `contents` under [`signer`].
fn parse(contents: &str) -> Result<EncryptedVault, Error> {
    EncryptedVault::parse(contents, &signer()).map(VerifiedVault::into_inner)
}

/// Raw vault bytes of `contents`.
fn raw(contents: &str) -> String {
    EncryptedVault::raw_vault_json(contents)
        .unwrap()
        .to_string()
}

/// Format 2 file of [`filled_vault`], as JSON.
fn filled_file() -> Value {
    serde_json::from_str(&contents_of(&filled_vault())).unwrap()
}

/// `file`, edited as JSON, signed again by [`signer`].
fn signed(file: &Value) -> String {
    EncryptedVault::sign_file_for_test(file, &signer())
}
