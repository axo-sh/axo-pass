use std::collections::BTreeMap;

use anyhow::{anyhow, bail};
use axo_pass_core::core::app_broker::ResolvePurpose;
use axo_pass_core::core::interpolate::{find_refs, interpolate_secrets};
use clap::Parser;

use super::exec::load_env_files;
use super::secret_resolver::BrokerSecretResolver;

#[derive(Parser, Debug)]
pub struct EnvCommand {
    /// dotenv-style file(s) to load with interpolation.
    /// Glob patterns are supported and matches are loaded in sorted order.
    /// Repeat the flag for multiple paths/patterns.
    #[arg(long = "env-file", short = 'e', required = true)]
    pub env_files: Vec<String>,
}

impl EnvCommand {
    // ways to test this:
    // eval "$(ap env -e /tmp/test.env)" && printenv FOO
    pub async fn execute(&self) {
        match self.try_render() {
            Ok(script) => print!("{script}"),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            },
        }
    }

    /// POSIX shell script that exports the variables from the env files.
    fn try_render(&self) -> Result<String, anyhow::Error> {
        // Later definitions override earlier ones. A sorted map gives stable output.
        let vars: BTreeMap<String, String> = load_env_files(&self.env_files)?.into_iter().collect();
        for key in vars.keys() {
            if !is_shell_identifier(key) {
                bail!("Cannot export '{key}': not a valid shell variable name");
            }
        }

        // Resolve every axo:// reference in one broker request so a
        // multi-secret invocation raises one prompt.
        let refs: Vec<_> = vars.values().flat_map(|v| find_refs(v)).collect();
        let mut resolver = BrokerSecretResolver::new(ResolvePurpose::Env);
        resolver.prepare(&refs).map_err(|e| anyhow!("{e}"))?;

        let mut script = String::new();
        for (key, value) in &vars {
            let value = interpolate_secrets(value, &mut resolver).map_err(|e| anyhow!("{e}"))?;
            script.push_str(&format!("export {key}={}\n", shell_quote(&value)));
        }
        Ok(script)
    }
}

fn is_shell_identifier(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Single-quote `value` for a POSIX shell. Embedded single quotes are escaped.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_wraps_plain_value() {
        assert_eq!(shell_quote("abc"), "'abc'");
    }

    #[test]
    fn quote_escapes_single_quote() {
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
    }

    #[test]
    fn quote_keeps_metacharacters_literal() {
        assert_eq!(shell_quote("$HOME \"x\" `y`\n"), "'$HOME \"x\" `y`\n'");
    }

    #[test]
    fn identifier_accepts_valid_names() {
        assert!(is_shell_identifier("FOO_1"));
        assert!(is_shell_identifier("_x"));
    }

    #[test]
    fn identifier_rejects_invalid_names() {
        assert!(!is_shell_identifier(""));
        assert!(!is_shell_identifier("1A"));
        assert!(!is_shell_identifier("A-B"));
        assert!(!is_shell_identifier("A;rm"));
    }
}
