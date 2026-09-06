use regex::Regex;

use crate::secrets::vaults::VaultsManager;

/// One `axo://vault/item/credential` reference found in the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    /// The full matched text, e.g. `axo://v/i/c`.
    pub url: String,
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
}

/// The outcome of resolving one [`SecretRef`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedSecret {
    Found(String),
    NotFound,
    Error,
}

/// Resolves the `axo://` references in one `interpolate_secrets` call.
///
/// The whole batch is resolved at once so a broker-backed resolver can raise a
/// single prompt for an invocation that pulls many secrets. A local resolver
/// ([`VaultsManager`]) just walks the list.
pub trait SecretResolver {
    /// Resolve every reference, positionally. The returned vector has the same
    /// length and order as `refs`. `Err` is a hard failure of the resolver
    /// itself (a dismissed prompt, a broken transport); a reference that simply
    /// does not resolve is [`ResolvedSecret::NotFound`] or
    /// [`ResolvedSecret::Error`].
    fn resolve_all(&mut self, refs: &[SecretRef]) -> Result<Vec<ResolvedSecret>, String>;
}

impl SecretResolver for VaultsManager {
    fn resolve_all(&mut self, refs: &[SecretRef]) -> Result<Vec<ResolvedSecret>, String> {
        Ok(refs
            .iter()
            .map(|r| match self.get_secret_by_url(&r.url) {
                Ok(Some(secret)) => ResolvedSecret::Found(secret),
                Ok(None) => {
                    log::warn!("Secret not found for reference: {}", r.url);
                    ResolvedSecret::NotFound
                },
                Err(e) => {
                    log::error!("Error fetching secret for reference {}: {e:?}", r.url);
                    ResolvedSecret::Error
                },
            })
            .collect())
    }
}

fn axo_url_re() -> Regex {
    Regex::new(r"\baxo://(?P<vault>[a-zA-Z0-9-_]+)/(?P<item>[a-zA-Z0-9-_]+)/(?P<credential>[a-zA-Z0-9-_]+\b)").unwrap()
}

/// Every `axo://` reference in `input`, in the order it appears. Duplicates are
/// kept: `interpolate_secrets` substitutes positionally.
pub fn find_refs(input: &str) -> Vec<SecretRef> {
    axo_url_re()
        .captures_iter(input)
        .map(|caps| SecretRef {
            url: caps[0].to_string(),
            vault_key: caps["vault"].to_string(),
            item_key: caps["item"].to_string(),
            credential_key: caps["credential"].to_string(),
        })
        .collect()
}

/// Replace every `axo://vault/item/credential` reference in `input` with its
/// secret value. An unresolved reference becomes `NOT_FOUND`; a resolver error
/// on one reference becomes `ERROR`. `Err` is returned only when the resolver
/// fails as a whole.
pub fn interpolate_secrets(
    input: &str,
    resolver: &mut dyn SecretResolver,
) -> Result<String, String> {
    let refs = find_refs(input);
    if refs.is_empty() {
        return Ok(input.to_string());
    }

    let resolved = resolver.resolve_all(&refs)?;
    if resolved.len() != refs.len() {
        return Err(format!(
            "resolver returned {} values for {} references",
            resolved.len(),
            refs.len()
        ));
    }

    let mut values = resolved.into_iter();
    let result = axo_url_re().replace_all(input, |caps: &regex::Captures| {
        log::debug!("Found reference {}", &caps[0]);
        match values.next() {
            Some(ResolvedSecret::Found(secret)) => secret,
            Some(ResolvedSecret::NotFound) => "NOT_FOUND".to_string(),
            Some(ResolvedSecret::Error) | None => "ERROR".to_string(),
        }
    });
    Ok(result.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpolate_secrets() {
        let cases: &[(&str, &str)] = &[
            ("hello world", "hello world"),
            ("", ""),
            // non-axo URLs are not replaced
            (
                "https://example.com/vault/item/cred",
                "https://example.com/vault/item/cred",
            ),
            // missing credential segment — regex requires all three path components
            ("axo://vault/item", "axo://vault/item"),
            // replace url with ERROR (vault doesn't exist)
            ("axo://nonexistent-vault/my-item/my-cred", "ERROR"),
            // only url is replaced
            (
                "prefix axo://no-vault/item/cred suffix",
                "prefix ERROR suffix",
            ),
            // multiple references are all replaced
            ("a=axo://v1/i1/c1 b=axo://v2/i2/c2", "a=ERROR b=ERROR"),
            // "xaxo" has no \b before `axo` — not matched
            ("xaxo://vault/item/cred", "xaxo://vault/item/cred"),
            // trailing non-word char: URL replaced, dot kept
            ("axo://vault/item/cred.", "ERROR."),
        ];

        // todo: have a way to create a test vault
        let mut vaults = VaultsManager::default();
        for (input, expected) in cases {
            assert_eq!(
                interpolate_secrets(input, &mut vaults).unwrap(),
                *expected,
                "input: {input:?}",
            );
        }
    }

    #[test]
    fn find_refs_parses_each_component_in_order() {
        let refs = find_refs("a=axo://v1/i1/c1 b=axo://v2/i2/c2 a=axo://v1/i1/c1");
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].vault_key, "v1");
        assert_eq!(refs[1].vault_key, "v2");
        assert_eq!(refs[1].item_key, "i2");
        assert_eq!(refs[1].credential_key, "c2");
        assert_eq!(refs[2], refs[0]);
    }

    #[test]
    fn interpolate_substitutes_positionally() {
        struct Fixed;
        impl SecretResolver for Fixed {
            fn resolve_all(&mut self, refs: &[SecretRef]) -> Result<Vec<ResolvedSecret>, String> {
                Ok(refs
                    .iter()
                    .map(|r| ResolvedSecret::Found(format!("<{}>", r.credential_key)))
                    .collect())
            }
        }
        assert_eq!(
            interpolate_secrets("a=axo://v/i/c1 b=axo://v/i/c2", &mut Fixed).unwrap(),
            "a=<c1> b=<c2>",
        );
    }

    #[test]
    fn interpolate_propagates_resolver_failure() {
        struct Broken;
        impl SecretResolver for Broken {
            fn resolve_all(&mut self, _refs: &[SecretRef]) -> Result<Vec<ResolvedSecret>, String> {
                Err("prompt dismissed".to_string())
            }
        }
        assert_eq!(
            interpolate_secrets("axo://v/i/c", &mut Broken),
            Err("prompt dismissed".to_string()),
        );
    }
}
