use std::collections::BTreeMap;
use std::fs;

use ssh_key::Fingerprint;
use ssh_key::known_hosts::{Entry, HostPatterns, KnownHosts as SshKeyKnownHosts};
use ssh_key::public::KeyData;

use crate::ssh::utils::{compute_sha256_fingerprint, ssh_dir_path};

#[derive(Debug, Default)]
pub struct KnownHosts {
    keyed_entries: BTreeMap<Fingerprint, Vec<HostPatterns>>,
}

impl KnownHosts {
    fn load_from_str(data: &str) -> anyhow::Result<Self> {
        let entries = SshKeyKnownHosts::new(data)
            .filter_map(|result| result.ok())
            .collect();
        let mut parser = Self::default();
        parser.index_entries(entries);
        Ok(parser)
    }

    pub fn load_from_user_ssh_dir() -> anyhow::Result<Self> {
        let ssh_dir = ssh_dir_path()
            .inspect_err(|e| log::error!("Failed to get SSH directory: {e}"))
            .unwrap_or_default();

        let path = ssh_dir.join("known_hosts");
        let data = fs::read_to_string(&path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read known_hosts file from {}: {e}",
                path.display()
            )
        })?;

        Self::load_from_str(&data)
    }

    fn index_entries(&mut self, entries: Vec<Entry>) {
        for entry in entries {
            let key = entry
                .public_key()
                .key_data()
                .fingerprint(ssh_key::HashAlg::Sha256);
            self.keyed_entries
                .entry(key)
                .or_default()
                .push(entry.host_patterns().clone());
        }
    }

    pub fn find_host_by_key(&self, key_data: &KeyData) -> Vec<String> {
        let key = key_data.fingerprint(ssh_key::HashAlg::Sha256);
        self.keyed_entries
            .get(&key)
            .into_iter() // handle the Option, get iter over &Vec<HostPatterns>
            .flatten() // flatten the iterator to HostPatterns
            .flat_map(|patterns| match patterns {
                HostPatterns::Patterns(hosts) => hosts.clone(),
                HostPatterns::HashedName { .. } => Vec::new(), // hashed names are ignored
            })
            .collect()
    }

    // formats a keydata into either a hostname if known, or else its sha256
    // fingerprint
    pub fn format_keydata(&self, key_data: Option<KeyData>) -> String {
        let Some(key_data) = key_data else {
            return "<none>".to_string();
        };
        if let Some(hostname) = self.find_host_by_key(&key_data).first() {
            hostname.clone()
        } else {
            compute_sha256_fingerprint(&key_data)
        }
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::PublicKey;

    use super::*;

    #[test]
    fn test_parse_known_hosts() {
        let parser = KnownHosts::load_from_str(
            r#"
# Comment line
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
192.168.1.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkpKl0rYnX6kLpmHGKbtJpTQAqYz7wJsQrNcZMqgweY
example.com,192.168.1.100 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHczLoR+B0P7qCYfFuYJCqvnE1xXJxMPmQK3KSs7vEUk
"#,
        ).expect("Failed to parse known_hosts");

        let test_cases = &vec![
            (
                // Test find_host_by_key, single hostname
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
                vec!["github.com"],
            ),
            (
                // Test find_host_by_key, single hostname with comment
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl hello",
                vec!["github.com"],
            ),
            (
                // Test find_host_by_key, entry with multiple hostnames
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHczLoR+B0P7qCYfFuYJCqvnE1xXJxMPmQK3KSs7vEUk",
                vec!["example.com", "192.168.1.100"],
            ),
        ];

        for (public_key_str, expected_hostnames) in test_cases {
            let public_key: PublicKey = public_key_str.parse().unwrap();
            let hostnames = parser.find_host_by_key(public_key.key_data());
            assert_eq!(hostnames, *expected_hostnames);
        }
    }
}
