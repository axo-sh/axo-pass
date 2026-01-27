use std::fmt::Display;

use anyhow::bail;
use ssh_agent_lib::proto::extension::DestinationConstraint;
use ssh_agent_lib::proto::{self};
use ssh_key::public::KeyData;

use crate::cli::commands::ssh_agent::credential::Credential;
use crate::cli::commands::ssh_agent::session::SshAgentSession;
use crate::ssh::known_hosts::KnownHosts;
use crate::ssh::utils::compute_sha256_fingerprint;

impl SshAgentSession {
    pub fn identity_permitted(
        &self,
        cred: &dyn Credential,
        user: Option<&str>,
    ) -> anyhow::Result<()> {
        // todo: add display or something for creds
        log::debug!(
            "Checking identity permitted for {}",
            compute_sha256_fingerprint(&cred.public_key_data())
        );
        let dest_constraints = cred.dest_constraints();
        if dest_constraints.is_empty() {
            // No constraints, always permitted
            return Ok(());
        }

        if self.sessions.is_empty() {
            if self.session_bind_attempted {
                bail!("Previous session bind failed on socket")
            }
            // No session bind, local use
            return Ok(());
        }

        let mut prev_host: Option<&KeyData> = None;

        // required: an identity must permit the full chain of hops
        for (i, session) in self.sessions.iter().enumerate() {
            let destination = &session.inner.host_key;
            let is_final_hop = i == self.sessions.len() - 1;
            let session_hop = match prev_host {
                None => SessionHop::FirstHop(destination, is_final_hop),
                Some(origin) => SessionHop::IntermediateHop {
                    origin,
                    destination,
                    final_hop: is_final_hop,
                },
            };

            validate_session_hop(
                session_hop,
                session.inner.is_forwarding,
                user,
                &dest_constraints,
            )?;
            prev_host = Some(&session.inner.host_key);
        }

        // special case: if the last bound session ID was for
        // forwarding, and this function is not being called to check a sign
        // request (i.e. no 'user' supplied), then only permit the key if
        // there is a permission that would allow it to be used at another
        // destination.
        // This hides keys that are allowed for authenticating *to* a host
        // but not permitted for *use* beyond it.
        if let Some(last_session) = self.sessions.last()
            && last_session.inner.is_forwarding
            // not being used for signing (no user)
            && user.is_none()
            // check if the key is allowed to be used at another destination
            && let Err(err) = permitted_by_dest_constraints(
                SessionHop::OriginOnly(&last_session.inner.host_key),
                &dest_constraints,
                None,
            )
        {
            bail!("Key permitted at host but not after: {err}");
        }

        Ok(())
    }
}

fn validate_session_hop(
    session_hop: SessionHop,
    is_forwarding: bool,
    user: Option<&str>,
    constraints: &[proto::extension::DestinationConstraint],
) -> anyhow::Result<String> {
    let hop = format!("{session_hop}"); // for debugging
    log::debug!("Validating {hop} (forwarding={is_forwarding})");

    let checked_user = if session_hop.is_final() {
        // For a signature request (user is some), the final hop must not be forwarding
        if user.is_some() && is_forwarding {
            bail!("Tried to sign on forwarding hop")
        }
        // Final hop checks user if provided (i.e. for sign requests)
        user
    } else {
        // Intermediate hops must be forwarding
        if !is_forwarding {
            bail!("Intermediate session hop is not marked as forwarding");
        }
        // Intermediate hop does not check user
        None
    };

    permitted_by_dest_constraints(session_hop, constraints, checked_user)
        .inspect(|_| log::debug!("Validating {hop}: permitted"))
        .inspect_err(|err| log::debug!("Validating {hop}: failed: {err}"))
}

// Represents a session hop in the chain, for clarity
enum SessionHop<'a> {
    // none -> A (destination only, no origin on first hop)
    FirstHop(&'a KeyData, bool),
    // A -> B
    IntermediateHop {
        origin: &'a KeyData,
        destination: &'a KeyData,
        final_hop: bool,
    },
    // B -> none (origin only, for forwarding non-signing final hop checks)
    OriginOnly(&'a KeyData),
}

impl SessionHop<'_> {
    fn get_origin_and_destination(&self) -> (Option<&KeyData>, Option<&KeyData>) {
        match self {
            SessionHop::FirstHop(destination, _) => (None, Some(destination)),
            SessionHop::IntermediateHop {
                origin,
                destination,
                ..
            } => (Some(origin), Some(destination)),
            SessionHop::OriginOnly(origin) => (Some(origin), None),
        }
    }

    fn is_final(&self) -> bool {
        match self {
            SessionHop::FirstHop(_, final_hop) => *final_hop,
            SessionHop::IntermediateHop { final_hop, .. } => *final_hop,
            SessionHop::OriginOnly(_) => true,
        }
    }
}

impl Display for SessionHop<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (origin, destination) = self.get_origin_and_destination();
        let known_hosts = KnownHosts::load_from_user_ssh_dir().unwrap_or_default();
        write!(
            f,
            "{} -> {}",
            origin
                .map(|k| known_hosts.format_keydata(Some(k.clone())))
                .unwrap_or("(ORIGIN)".into()),
            known_hosts.format_keydata(destination.cloned()),
        )?;
        if !self.is_final() {
            write!(f, " [intermediate]")?
        }
        Ok(())
    }
}

/// Check destination constraints on an identity against the hostkey/user.
fn permitted_by_dest_constraints(
    session_hop: SessionHop,
    constraints: &[proto::extension::DestinationConstraint],
    user: Option<&str>,
) -> anyhow::Result<String> {
    let (origin, destination) = session_hop.get_origin_and_destination();

    for DestinationConstraint { from, to } in constraints.iter() {
        let from_matches = match origin {
            // if origin is None, that means we are matching the first hop:
            // expect no hostname and no keys
            None => from.hostname.is_empty() && from.keys.is_empty(),
            // for subsequent hops, expect *explicit* allowed origin key
            // this means that if from keys are empty, it cannot be used on subsequent hops
            Some(origin) => from.keys.iter().any(|k| k.keyblob == *origin),
        };
        if !from_matches {
            continue;
        }

        // Check destination key if specified
        let to_matches = destination
            .map(|d| to.keys.iter().any(|k| k.keyblob == *d))
            .unwrap_or(true);
        if !to_matches {
            continue;
        }

        // Check username if specified
        if !to.username.is_empty()
            && let Some(user) = user
            && to.username != user
        {
            // NOTE: openssh supports * and ? wildcards, but we don't currently
            continue;
        }

        // Successfully matched this constraint
        let hostname = if to.hostname.is_empty() {
            "*".to_string()
        } else {
            to.hostname.clone()
        };
        return Ok(hostname);
    }

    // No matches found
    bail!("Identity not permitted for this destination");
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
    use ssh_agent_lib::proto::extension::{DestinationConstraint, HostTuple, KeySpec};
    use ssh_key::PrivateKey;

    use super::*;

    static TEST_RSA_KEY: LazyLock<KeyData> = LazyLock::new(|| {
        let data = include_str!("./fixtures/b64_rsa");
        let privkey = PrivateKey::from_bytes(b64.decode(data).unwrap().as_slice()).unwrap();
        privkey.public_key().key_data().clone()
    });

    static TEST_ED25519_KEY: LazyLock<KeyData> = LazyLock::new(|| {
        let data = include_str!("./fixtures/b64_ed25519");
        let privkey = PrivateKey::from_bytes(b64.decode(data).unwrap().as_slice()).unwrap();
        privkey.public_key().key_data().clone()
    });

    fn empty_host_tuple() -> HostTuple {
        HostTuple {
            username: "".to_string(),
            hostname: "".to_string(),
            keys: vec![],
        }
    }

    fn host_tuple(hostname: &str, key_data: &KeyData) -> HostTuple {
        HostTuple {
            username: "".to_string(),
            hostname: hostname.to_string(),
            keys: vec![KeySpec {
                keyblob: key_data.clone(),
                is_ca: false,
            }],
        }
    }

    mod test_permitted_by_dest_constraints {
        use super::*;

        #[test]
        fn test_empty_constraints_rejects() {
            // note: identity_permitted() allows empty constraints to always pass
            let result = permitted_by_dest_constraints(
                SessionHop::IntermediateHop {
                    origin: &TEST_RSA_KEY,
                    destination: &TEST_ED25519_KEY,
                    final_hop: false,
                },
                &vec![],
                None,
            );
            assert!(result.is_err(), "Empty constraints should fail");
        }

        #[test]
        fn test_first_hop_with_empty_from() {
            let dest_key = &TEST_ED25519_KEY;
            // First hop (origin is None) with destination key matching constraint (to)
            let result = permitted_by_dest_constraints(
                SessionHop::FirstHop(&dest_key, false),
                &vec![DestinationConstraint {
                    from: empty_host_tuple(),
                    to: host_tuple("server1.example.com", &dest_key),
                }],
                None,
            );
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "server1.example.com");
        }

        #[test]
        fn test_subsequent_hop_rejects_with_origin_constraint() {
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;

            // Should fail because we have an origin but constraint only valid for first hop
            // note: this isn't really possible, since openssh doesn't allow this syntax
            let result = permitted_by_dest_constraints(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                &vec![DestinationConstraint {
                    from: empty_host_tuple(),
                    to: host_tuple("server1.example.com", &dest_key),
                }],
                None,
            );
            assert!(result.is_err());
        }

        #[test]
        fn test_valid_subsequent_hop() {
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;
            let result = permitted_by_dest_constraints(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: host_tuple("server2.example.com", &dest_key),
                }],
                None,
            );
            assert!(result.is_ok(), "Valid constraint should succeed");
            assert_eq!(result.unwrap(), "server2.example.com");
        }

        #[test]
        fn test_destination_key_mismatch() {
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;
            let wrong_dest_key = &TEST_RSA_KEY;
            let result = permitted_by_dest_constraints(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: host_tuple("server2.example.com", &wrong_dest_key),
                }],
                None,
            );
            assert!(result.is_err(), "Mismatching destination key should fail");
        }

        #[test]
        fn test_username_match() {
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;

            let result = permitted_by_dest_constraints(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: HostTuple {
                        username: "alice".to_string(),
                        hostname: "server2.example.com".to_string(),
                        keys: vec![KeySpec {
                            keyblob: (*dest_key).clone(),
                            is_ca: false,
                        }],
                    },
                }],
                Some("alice"),
            );
            assert!(result.is_ok(), "Matching username should succeed");
            assert_eq!(result.unwrap(), "server2.example.com");
        }

        #[test]
        fn test_username_mismatch() {
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;

            let result = permitted_by_dest_constraints(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: HostTuple {
                        username: "alice".to_string(),
                        hostname: "server2.example.com".to_string(),
                        keys: vec![KeySpec {
                            keyblob: (*dest_key).clone(),
                            is_ca: false,
                        }],
                    },
                }],
                Some("bob"),
            );
            assert!(result.is_err(), "Mismatching username should fail");
        }

        #[test]
        fn test_username_ignored_when_empty() {
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;

            let result = permitted_by_dest_constraints(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: HostTuple {
                        username: "".to_string(), // empty username matches any
                        hostname: "server2.example.com".to_string(),
                        keys: vec![KeySpec {
                            keyblob: (*dest_key).clone(),
                            is_ca: false,
                        }],
                    },
                }],
                Some("anyone"),
            );
            assert!(result.is_ok());
        }

        #[test]
        fn test_empty_hostname_returns_wildcard() {
            // not sure how this would happen with ssh-add, but test the wildcard behavior
            // anyway
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;
            let result = permitted_by_dest_constraints(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: host_tuple("", &dest_key),
                }],
                None,
            );
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "*");
        }

        #[test]
        fn test_multiple_constraints_first_match_wins() {
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;
            let wrong_dest_key = &TEST_RSA_KEY;
            let result = permitted_by_dest_constraints(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                &vec![
                    DestinationConstraint {
                        from: host_tuple("server1.example.com", &origin_key),
                        to: host_tuple("should-not-match.example.com", &wrong_dest_key),
                    },
                    DestinationConstraint {
                        from: host_tuple("server1.example.com", &origin_key),
                        to: host_tuple("correct.example.com", &dest_key),
                    },
                ],
                None,
            );
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "correct.example.com");
        }

        #[test]
        fn test_origin_only_matches_any_destination() {
            // origin-only is mainly for non-signing use case
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;

            let result = permitted_by_dest_constraints(
                SessionHop::OriginOnly(&origin_key),
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: host_tuple("server2.example.com", &dest_key),
                }],
                None,
            );
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "server2.example.com");
        }

        #[test]
        fn test_origin_only_matches_no_destination() {
            // origin-only is mainly for non-signing use case
            let origin_key = &TEST_RSA_KEY;
            let result = permitted_by_dest_constraints(
                SessionHop::OriginOnly(&origin_key),
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: empty_host_tuple(),
                }],
                None,
            );
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "*");
        }

        #[test]
        fn test_origin_only_rejects_invalid_origin() {
            // origin-only is mainly for non-signing use case
            let origin_key = &TEST_RSA_KEY;
            let wrong_origin_key = &TEST_ED25519_KEY;
            let result = permitted_by_dest_constraints(
                SessionHop::OriginOnly(&origin_key),
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &wrong_origin_key),
                    to: empty_host_tuple(),
                }],
                None,
            );
            assert!(result.is_err(), "Mismatching origin key should fail");
        }
    }

    mod test_validate_session_hop {
        use super::*;

        #[test]
        fn test_validate_session_hop_valid_single_hop_no_origin() {
            // single hop has no origin (being the first hop)
            let dest_key = &TEST_ED25519_KEY;
            let result = validate_session_hop(
                SessionHop::FirstHop(&dest_key, true), // final hop
                false,                                 // not forwarding
                Some("alice"),
                &vec![DestinationConstraint {
                    from: empty_host_tuple(),
                    to: host_tuple("server1.example.com", &dest_key),
                }],
            );
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "server1.example.com");
        }

        #[test]
        fn test_validate_session_hop_single_hop_signing_on_forwarding_fails() {
            // single hop has no origin (being the first hop)
            let dest_key = &TEST_ED25519_KEY;
            let result = validate_session_hop(
                SessionHop::FirstHop(&dest_key, true), // final hop
                true,                                  // forwarding
                Some("alice"),                         // signing request
                &vec![DestinationConstraint {
                    from: empty_host_tuple(),
                    to: host_tuple("server1.example.com", &dest_key),
                }],
            );
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Tried to sign on forwarding hop"),
                "Should fail when trying to sign on forwarding hop"
            );
        }

        #[test]
        fn test_validate_session_hop_valid_intermediate_hop() {
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;
            let result = validate_session_hop(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                true, // forwarding
                None,
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: host_tuple("server2.example.com", &dest_key),
                }],
            );
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "server2.example.com");
        }

        #[test]
        fn test_validate_session_hop_intermediate_hop_not_forwarding_fails() {
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;

            let result = validate_session_hop(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                false, // not forwarding
                None,
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: host_tuple("server2.example.com", &dest_key),
                }],
            );
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Intermediate session hop is not marked as forwarding"),
                "Intermediate hop must be forwarding"
            );
        }

        #[test]
        fn test_validate_session_hop_constraint_not_matched() {
            let origin_key = &TEST_RSA_KEY;
            let dest_key = &TEST_ED25519_KEY;
            let wrong_dest_key = &TEST_RSA_KEY;

            let result = validate_session_hop(
                SessionHop::IntermediateHop {
                    origin: &origin_key,
                    destination: &dest_key,
                    final_hop: false,
                },
                true, // forwarding
                None,
                &vec![DestinationConstraint {
                    from: host_tuple("server1.example.com", &origin_key),
                    to: host_tuple("server2.example.com", &wrong_dest_key), // wrong key
                }],
            );
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("not permitted for this destination")
            );
        }
    }
}
