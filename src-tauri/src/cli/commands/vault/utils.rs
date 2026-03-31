use std::fs;
use std::io::{IsTerminal, Read};

use inquire::Password;
use secrecy::SecretString;

pub fn prompt_passphrase(prompt: &str) -> Result<SecretString, String> {
    if std::io::stdin().is_terminal() {
        Password::new(prompt)
            .prompt()
            .map(|s| SecretString::from(s))
            .map_err(|e| format!("Failed to read passphrase: {e}"))
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("Failed to read passphrase from stdin: {e}"))?;
        Ok(SecretString::from(buf.trim().to_string()))
    }
}

pub fn read_age_identity_file(path: &str) -> Result<age::x25519::Identity, String> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read identity file '{path}': {e}"))?;

    let key_line = contents
        .lines()
        .filter(|l| l.starts_with("AGE-SECRET-KEY-1"))
        .collect::<Vec<_>>();

    if key_line.len() != 1 {
        return Err(format!(
            "Identity file '{path}' should contain exactly one secret key found {}",
            key_line.len()
        ));
    }
    let identity_str = key_line.first().unwrap().trim();

    identity_str
        .parse::<age::x25519::Identity>()
        .map_err(|e| format!("Invalid age identity in '{path}': {e}"))
}
