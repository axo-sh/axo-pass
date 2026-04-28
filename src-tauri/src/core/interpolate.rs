use regex::Regex;

use crate::secrets::vaults::VaultsManager;

pub fn interpolate_secrets(input: &str, vaults: &mut VaultsManager) -> String {
    let axo_url_re =
        Regex::new(r"\baxo://(?P<vault>[a-zA-Z0-9-_]+)/(?P<item>[a-zA-Z0-9-_]+)/(?P<credential>[a-zA-Z0-9-_]+\b)").unwrap();
    let result = axo_url_re.replace_all(input, |caps: &regex::Captures| {
        let item_url = &caps[0];
        log::debug!("Found reference {item_url}");
        match vaults.get_secret_by_url(item_url) {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                log::warn!("Secret not found for reference: {}", item_url);
                "NOT_FOUND".to_string()
            },
            Err(e) => {
                log::error!("Error fetching secret for reference {}: {:?}", item_url, e);
                "ERROR".to_string()
            },
        }
    });
    result.to_string()
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
                interpolate_secrets(input, &mut vaults),
                *expected,
                "input: {input:?}",
            );
        }
    }
}
