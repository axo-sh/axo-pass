//! One-time codes from a `Totp` credential's stored value.
//!
//! The value is an `otpauth://totp/...` URI, or a bare base32 secret, which
//! takes SHA-1, 6 digits, and a 30 second period.

use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

/// A one-time code and how long it stays valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
}

/// The code for the current time. Errors name what is wrong with the stored
/// value and never include it.
pub fn current_code(value: &str) -> Result<TotpCode, String> {
    let totp = parse(value)?;
    let code = totp
        .generate_current()
        .map_err(|e| format!("The system clock is unusable: {e}"))?;
    let seconds_remaining = totp
        .ttl()
        .map_err(|e| format!("The system clock is unusable: {e}"))?;
    Ok(TotpCode {
        code,
        seconds_remaining,
    })
}

fn parse(value: &str) -> Result<TOTP, String> {
    let value = value.trim();
    if value.starts_with("otpauth://") {
        return TOTP::from_url_unchecked(uppercase_secret_param(value))
            .map_err(|_| "The one-time code URI is not valid".to_string());
    }
    // Secrets are often copied with spaces between groups.
    let compact: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();
    let secret = Secret::Encoded(compact)
        .to_bytes()
        .map_err(|_| "The one-time code secret is not valid base32".to_string())?;
    if secret.is_empty() {
        return Err("The one-time code secret is empty".to_string());
    }
    Ok(TOTP::new_unchecked(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        None,
        String::new(),
    ))
}

/// Uppercases the `secret` query parameter, since the base32 decoder only
/// accepts uppercase and many services emit lowercase secrets.
fn uppercase_secret_param(uri: &str) -> String {
    let Some((head, query)) = uri.split_once('?') else {
        return uri.to_string();
    };
    let query: Vec<String> = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, val)) if key.eq_ignore_ascii_case("secret") => {
                format!("{key}={}", val.to_uppercase())
            },
            _ => pair.to_string(),
        })
        .collect();
    format!("{head}?{}", query.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238's SHA-1 test secret, "12345678901234567890" in base32.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn bare_secret_gives_six_digits() {
        let code = current_code(RFC_SECRET).unwrap();
        assert_eq!(code.code.len(), 6);
        assert!(code.code.chars().all(|c| c.is_ascii_digit()));
        assert!((1..=30).contains(&code.seconds_remaining));
    }

    #[test]
    fn grouped_lowercase_secrets_match_compact_form() {
        let totp = parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        let compact = parse(RFC_SECRET).unwrap();
        assert_eq!(totp.generate(59), compact.generate(59));
    }

    #[test]
    fn matches_rfc_6238_vector() {
        // RFC 6238 appendix B, SHA-1 at T=59 is 94287082 with 8 digits, so the
        // 6 digit code is its last six digits.
        let totp = parse(RFC_SECRET).unwrap();
        assert_eq!(totp.generate(59), "287082");
    }

    #[test]
    fn otpauth_uri_sets_its_own_parameters() {
        let uri = format!("otpauth://totp/Example:tp?secret={RFC_SECRET}&digits=8&period=60");
        let totp = parse(&uri).unwrap();
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.step, 60);
        // A 60 second period puts T=59 in counter 0, and RFC 4226's counter 0
        // code is 755224. With 8 digits the value is 84755224.
        assert_eq!(totp.generate(59), "84755224");
    }

    #[test]
    fn otpauth_uri_with_lowercase_secret_parses() {
        let uri = "otpauth://totp/octavore?issuer=GitHub&secret=abcd";
        assert!(parse(uri).is_ok());
    }

    #[test]
    fn otpauth_uri_with_slash_in_its_label_parses() {
        let uri = "otpauth://totp/github.com/octavore?issuer=GitHub&secret=ABCD";
        assert!(parse(uri).is_ok());
    }

    #[test]
    fn rejects_values_not_secrets() {
        assert!(current_code("").is_err());
        assert!(current_code("not base32 !!").is_err());
        assert!(current_code("otpauth://totp/x").is_err());
    }
}
