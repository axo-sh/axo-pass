use crate::secrets::vaults::VaultCatalog;

/// Key for a new vault named `name`. A key that another vault holds gets a
/// numeric suffix.
pub fn free_vault_key(vaults: &VaultCatalog, name: &str) -> Result<String, String> {
    let base = vault_key_for(name);
    (1..100)
        .map(|n| match n {
            1 => base.clone(),
            n => format!("{base}-{n}"),
        })
        .find(|key| vaults.unclaimed_key(key, None).is_ok())
        .ok_or_else(|| format!("No free vault key for the name {name}"))
}

/// Vault key made from a name. Lower-case ASCII letters and digits are kept,
/// and each run of other characters becomes `-`. The result is a valid key.
pub fn vault_key_for(name: &str) -> String {
    let mut key = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            key.push(c.to_ascii_lowercase());
        } else if !key.is_empty() && !key.ends_with('-') {
            key.push('-');
        }
    }
    let mut key = key.trim_end_matches('-').to_string();
    if !key.starts_with(|c: char| c.is_ascii_lowercase()) {
        key = format!("vault-{key}").trim_end_matches('-').to_string();
    }
    if key.len() < 3 {
        key.push_str("-vault");
    }
    key
}
