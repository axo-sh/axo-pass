//! Resolves `axo://` references for `ap exec` and `ap inject` through the app
//! broker.
//!
//! `ap` holds no keychain entitlements, so it cannot unlock a vault itself. One
//! invocation may pull many secrets across several vaults, so the references
//! are gathered up front and resolved in a single broker request that raises
//! one prompt. A build that is not staged in an app bundle has no broker to
//! reach and resolves locally through a [`VaultsManager`].

use std::collections::HashMap;

use axo_pass_core::core::app_broker::{self, BrokerError, ResolvePurpose, VaultRef};
use axo_pass_core::core::interpolate::{ResolvedSecret, SecretRef, SecretResolver};
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::secrets::vaults::VaultsManager;
use secrecy::ExposeSecret;

/// A `(vault, item, credential)` triple, the key a resolved value is cached
/// under. References that repeat resolve once.
type RefKey = (String, String, String);

fn key_of(r: &SecretRef) -> RefKey {
    (
        r.vault_key.clone(),
        r.item_key.clone(),
        r.credential_key.clone(),
    )
}

/// Resolves references from a map filled by [`BrokerSecretResolver::prepare`].
pub struct BrokerSecretResolver {
    purpose: ResolvePurpose,
    resolved: HashMap<RefKey, ResolvedSecret>,
}

impl BrokerSecretResolver {
    pub fn new(purpose: ResolvePurpose) -> Self {
        Self {
            purpose,
            resolved: HashMap::new(),
        }
    }

    /// Resolve every distinct reference in `refs` once, so the later
    /// per-string interpolation is offline. Raises one broker prompt.
    pub fn prepare(&mut self, refs: &[SecretRef]) -> Result<(), String> {
        let mut distinct: Vec<&SecretRef> = Vec::new();
        for r in refs {
            let key = key_of(r);
            if !self.resolved.contains_key(&key) && !distinct.iter().any(|d| key_of(d) == key) {
                distinct.push(r);
            }
        }
        if distinct.is_empty() {
            return Ok(());
        }

        let caller = Provenance::resolve_current_parent()
            .inspect(|provenance| log::debug!("interpolate caller: {provenance:#?}"))
            .and_then(|provenance| provenance.caller());

        let wire: Vec<VaultRef> = distinct
            .iter()
            .map(|r| VaultRef {
                vault_key: r.vault_key.clone(),
                item_key: r.item_key.clone(),
                credential_key: r.credential_key.clone(),
            })
            .collect();

        let values =
            match app_broker::request_resolve_secrets(&wire, self.purpose, caller.as_deref()) {
                Ok(values) => values,
                Err(BrokerError::Unavailable) => return self.prepare_locally(&distinct),
                Err(e) => return Err(format!("Failed to resolve secrets: {e}")),
            };

        for (r, value) in distinct.iter().zip(values) {
            let resolved = match value {
                Some(secret) => ResolvedSecret::Found(secret.expose_secret().to_string()),
                None => ResolvedSecret::NotFound,
            };
            self.resolved.insert(key_of(r), resolved);
        }
        Ok(())
    }

    fn prepare_locally(&mut self, distinct: &[&SecretRef]) -> Result<(), String> {
        let mut vaults = VaultsManager::new();
        let owned: Vec<SecretRef> = distinct.iter().map(|r| (*r).clone()).collect();
        let resolved = vaults.resolve_all(&owned)?;
        for (r, value) in owned.iter().zip(resolved) {
            self.resolved.insert(key_of(r), value);
        }
        Ok(())
    }
}

impl SecretResolver for BrokerSecretResolver {
    fn resolve_all(&mut self, refs: &[SecretRef]) -> Result<Vec<ResolvedSecret>, String> {
        Ok(refs
            .iter()
            .map(|r| {
                self.resolved
                    .get(&key_of(r))
                    .cloned()
                    .unwrap_or(ResolvedSecret::Error)
            })
            .collect())
    }
}
