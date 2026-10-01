//! Hosts an SSH key signed in to, from successful `ssh.sign` audit events.

use ssh_key::Fingerprint;
use time::OffsetDateTime;

use crate::audit::{self, Action, AuditEvent, AuditFilter, Outcome};
use crate::ssh::known_hosts::KnownHosts;

/// The most recent `ssh.sign` events read for one key.
const USAGE_EVENT_LIMIT: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelatedHost {
    /// The `host` recorded at sign time, else a `known_hosts` lookup. `None`
    /// when neither names the host key, for example a hashed entry.
    pub host: Option<String>,
    /// The server's host key, `SHA256:...`.
    pub hostkey_fingerprint: String,
    pub user: Option<String>,
    pub last_used: OffsetDateTime,
    /// The oldest signature counted in `use_count`.
    pub first_used: OffsetDateTime,
    pub use_count: u32,
}

/// Hosts the key with this `SHA256:...` fingerprint signed in to, most
/// recently used first.
pub fn related_hosts(fingerprint: &str) -> anyhow::Result<Vec<RelatedHost>> {
    let fingerprint: Fingerprint = fingerprint
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid fingerprint {fingerprint}: {e}"))?;
    let fingerprint = fingerprint.to_string();
    let page = audit::read(&AuditFilter {
        actions: vec![Action::SshSign],
        outcomes: vec![Outcome::Succeeded],
        query: Some(fingerprint.clone()),
        limit: Some(USAGE_EVENT_LIMIT),
        ..Default::default()
    });
    let known_hosts = KnownHosts::load_from_user_ssh_dir()
        .inspect_err(|e| log::debug!("{e}"))
        .unwrap_or_default();
    Ok(connected_hosts(&page.events, &fingerprint, &known_hosts))
}

/// Group successful signatures by host key and user. `events` are newest
/// first, so the first event of a group gives its last use and the last event
/// its first use.
fn connected_hosts(
    events: &[AuditEvent],
    fingerprint: &str,
    known_hosts: &KnownHosts,
) -> Vec<RelatedHost> {
    let mut hosts: Vec<RelatedHost> = Vec::new();
    for event in events {
        // The reader's query is a substring match on several fields.
        let subject_fingerprint = event
            .subject
            .as_ref()
            .and_then(|s| s.fingerprint.as_deref());
        if subject_fingerprint != Some(fingerprint) {
            continue;
        }
        // Signatures that are not for a user authentication, such as git
        // commit signing, have no host key.
        let Some(hostkey) = event.detail.get("hostkey_fingerprint") else {
            continue;
        };
        let user = event.detail.get("user");
        let recorded_host = event.detail.get("host");

        let existing = hosts
            .iter_mut()
            .find(|h| h.hostkey_fingerprint == *hostkey && h.user.as_ref() == user);
        match existing {
            Some(host) => {
                host.use_count += 1;
                host.first_used = event.at;
                if host.host.is_none() {
                    host.host = recorded_host.cloned();
                }
            },
            None => hosts.push(RelatedHost {
                host: recorded_host.cloned(),
                hostkey_fingerprint: hostkey.clone(),
                user: user.cloned(),
                last_used: event.at,
                first_used: event.at,
                use_count: 1,
            }),
        }
    }

    // Events recorded before the agent wrote `host` fall back to known_hosts.
    for host in &mut hosts {
        if host.host.is_none()
            && let Ok(hostkey) = host.hostkey_fingerprint.parse::<Fingerprint>()
        {
            host.host = known_hosts
                .find_host_by_fingerprint(&hostkey)
                .into_iter()
                .next();
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use ssh_key::{HashAlg, PublicKey};
    use time::Duration;

    use super::*;
    use crate::audit::{Source, Subject, SubjectKind};

    const KEY_FP: &str = "SHA256:keykeykey";
    const GITHUB_HOSTKEY_FP: &str = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU";
    const OTHER_HOSTKEY_FP: &str = "SHA256:otherhostkey";

    fn sign_event(
        minutes_ago: i64,
        fingerprint: &str,
        hostkey: Option<&str>,
        user: Option<&str>,
        host: Option<&str>,
    ) -> AuditEvent {
        let mut event = AuditEvent::new(Source::Agent, Action::SshSign, Outcome::Succeeded)
            .subject(Subject::new(SubjectKind::SshKey, fingerprint).fingerprint(fingerprint))
            .maybe_detail("hostkey_fingerprint", hostkey)
            .maybe_detail("user", user)
            .maybe_detail("host", host);
        event.at =
            OffsetDateTime::UNIX_EPOCH + Duration::days(365 * 50) - Duration::minutes(minutes_ago);
        event
    }

    fn known_hosts() -> KnownHosts {
        KnownHosts::load_from_str(
            "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        )
        .unwrap()
    }

    #[test]
    fn known_hosts_fixture_has_the_expected_fingerprint() {
        let key: PublicKey =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
                .parse()
                .unwrap();
        assert_eq!(
            key.fingerprint(HashAlg::Sha256).to_string(),
            GITHUB_HOSTKEY_FP
        );
    }

    #[test]
    fn groups_signatures_by_host_key_and_user() {
        let events = vec![
            sign_event(1, KEY_FP, Some(GITHUB_HOSTKEY_FP), Some("git"), None),
            sign_event(
                2,
                KEY_FP,
                Some(OTHER_HOSTKEY_FP),
                Some("me"),
                Some("box.local"),
            ),
            sign_event(3, KEY_FP, Some(GITHUB_HOSTKEY_FP), Some("git"), None),
            sign_event(4, KEY_FP, Some(GITHUB_HOSTKEY_FP), Some("other"), None),
            // Another key, and a signature with no host key.
            sign_event(
                5,
                "SHA256:another",
                Some(GITHUB_HOSTKEY_FP),
                Some("git"),
                None,
            ),
            sign_event(6, KEY_FP, None, None, None),
        ];
        let hosts = connected_hosts(&events, KEY_FP, &known_hosts());

        assert_eq!(hosts.len(), 3);
        assert_eq!(hosts[0].host.as_deref(), Some("github.com"));
        assert_eq!(hosts[0].user.as_deref(), Some("git"));
        assert_eq!(hosts[0].use_count, 2);
        assert_eq!(hosts[0].last_used, events[0].at);
        assert_eq!(hosts[0].first_used, events[2].at);
        assert_eq!(hosts[1].host.as_deref(), Some("box.local"));
        assert_eq!(hosts[2].user.as_deref(), Some("other"));
        assert_eq!(hosts[2].use_count, 1);
    }

    #[test]
    fn prefers_the_recorded_host_and_leaves_unknown_hosts_empty() {
        let events = vec![
            sign_event(1, KEY_FP, Some(GITHUB_HOSTKEY_FP), Some("git"), None),
            sign_event(
                2,
                KEY_FP,
                Some(GITHUB_HOSTKEY_FP),
                Some("git"),
                Some("gh.example"),
            ),
            sign_event(3, KEY_FP, Some(OTHER_HOSTKEY_FP), None, None),
        ];
        let hosts = connected_hosts(&events, KEY_FP, &known_hosts());
        assert_eq!(hosts[0].host.as_deref(), Some("gh.example"));
        assert_eq!(hosts[1].host, None);
        assert_eq!(hosts[1].hostkey_fingerprint, OTHER_HOSTKEY_FP);
    }
}
