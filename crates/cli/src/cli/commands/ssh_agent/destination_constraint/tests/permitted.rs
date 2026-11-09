use ssh_agent_lib::proto::extension::{DestinationConstraint, HostTuple, KeySpec};

use super::super::{SessionHop, permitted_by_dest_constraints};
use super::{TEST_ED25519_KEY, TEST_RSA_KEY, empty_host_tuple, host_tuple};

#[test]
fn empty_constraints_rejects() {
    // note: identity_permitted() allows empty constraints to always pass
    let result = permitted_by_dest_constraints(
        SessionHop::IntermediateHop {
            origin: &TEST_RSA_KEY,
            destination: &TEST_ED25519_KEY,
            final_hop: false,
        },
        &[],
        None,
    );
    assert!(result.is_err(), "Empty constraints should fail");
}

#[test]
fn first_hop_with_empty_from() {
    let dest_key = &TEST_ED25519_KEY;
    // First hop (origin is None) with destination key matching constraint (to)
    let result = permitted_by_dest_constraints(
        SessionHop::FirstHop(dest_key, false),
        &[DestinationConstraint {
            from: empty_host_tuple(),
            to: host_tuple("server1.example.com", dest_key),
        }],
        None,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "server1.example.com");
}

#[test]
fn subsequent_hop_rejects_with_origin_constraint() {
    let origin_key = &TEST_RSA_KEY;
    let dest_key = &TEST_ED25519_KEY;

    // Should fail because we have an origin but constraint only valid for first hop
    // note: this isn't really possible, since openssh doesn't allow this syntax
    let result = permitted_by_dest_constraints(
        SessionHop::IntermediateHop {
            origin: origin_key,
            destination: dest_key,
            final_hop: false,
        },
        &[DestinationConstraint {
            from: empty_host_tuple(),
            to: host_tuple("server1.example.com", dest_key),
        }],
        None,
    );
    assert!(result.is_err());
}

#[test]
fn valid_subsequent_hop() {
    let origin_key = &TEST_RSA_KEY;
    let dest_key = &TEST_ED25519_KEY;
    let result = permitted_by_dest_constraints(
        SessionHop::IntermediateHop {
            origin: origin_key,
            destination: dest_key,
            final_hop: false,
        },
        &[DestinationConstraint {
            from: host_tuple("server1.example.com", origin_key),
            to: host_tuple("server2.example.com", dest_key),
        }],
        None,
    );
    assert!(result.is_ok(), "Valid constraint should succeed");
    assert_eq!(result.unwrap(), "server2.example.com");
}

#[test]
fn destination_key_mismatch() {
    let origin_key = &TEST_RSA_KEY;
    let dest_key = &TEST_ED25519_KEY;
    let wrong_dest_key = &TEST_RSA_KEY;
    let result = permitted_by_dest_constraints(
        SessionHop::IntermediateHop {
            origin: origin_key,
            destination: dest_key,
            final_hop: false,
        },
        &[DestinationConstraint {
            from: host_tuple("server1.example.com", origin_key),
            to: host_tuple("server2.example.com", wrong_dest_key),
        }],
        None,
    );
    assert!(result.is_err(), "Mismatching destination key should fail");
}

#[test]
fn username_checked_against_constraint() {
    let origin_key = &TEST_RSA_KEY;
    let dest_key = &TEST_ED25519_KEY;
    // Label, username of the constraint, requested username, and the
    // permitted hostname if the hop is permitted. An empty constraint
    // username matches any requested username.
    let rows = [
        ("match", "alice", "alice", Some("server2.example.com")),
        ("mismatch", "alice", "bob", None),
        (
            "empty constraint username",
            "",
            "anyone",
            Some("server2.example.com"),
        ),
    ];
    for (label, constraint_username, requested, expected) in rows {
        let result = permitted_by_dest_constraints(
            SessionHop::IntermediateHop {
                origin: origin_key,
                destination: dest_key,
                final_hop: false,
            },
            &[DestinationConstraint {
                from: host_tuple("server1.example.com", origin_key),
                to: HostTuple {
                    username: constraint_username.to_string(),
                    hostname: "server2.example.com".to_string(),
                    keys: vec![KeySpec {
                        keyblob: (*dest_key).clone(),
                        is_ca: false,
                    }],
                },
            }],
            Some(requested),
        );
        assert_eq!(result.ok().as_deref(), expected, "{label}");
    }
}

#[test]
fn empty_hostname_returns_wildcard() {
    // not sure how this would happen with ssh-add, but test the wildcard behavior
    // anyway
    let origin_key = &TEST_RSA_KEY;
    let dest_key = &TEST_ED25519_KEY;
    let result = permitted_by_dest_constraints(
        SessionHop::IntermediateHop {
            origin: origin_key,
            destination: dest_key,
            final_hop: false,
        },
        &[DestinationConstraint {
            from: host_tuple("server1.example.com", origin_key),
            to: host_tuple("", dest_key),
        }],
        None,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "*");
}

#[test]
fn multiple_constraints_first_match_wins() {
    let origin_key = &TEST_RSA_KEY;
    let dest_key = &TEST_ED25519_KEY;
    let wrong_dest_key = &TEST_RSA_KEY;
    let result = permitted_by_dest_constraints(
        SessionHop::IntermediateHop {
            origin: origin_key,
            destination: dest_key,
            final_hop: false,
        },
        &[
            DestinationConstraint {
                from: host_tuple("server1.example.com", origin_key),
                to: host_tuple("should-not-match.example.com", wrong_dest_key),
            },
            DestinationConstraint {
                from: host_tuple("server1.example.com", origin_key),
                to: host_tuple("correct.example.com", dest_key),
            },
        ],
        None,
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "correct.example.com");
}

#[test]
fn origin_only_checks_origin_and_ignores_destination() {
    // Origin-only is mainly for the non-signing use case.
    let origin_key = &TEST_RSA_KEY;
    let dest_key = &TEST_ED25519_KEY;
    let wrong_origin_key = &TEST_ED25519_KEY;
    // Label, constraint, and the permitted hostname if the hop is permitted.
    let rows = [
        (
            "any destination",
            DestinationConstraint {
                from: host_tuple("server1.example.com", origin_key),
                to: host_tuple("server2.example.com", dest_key),
            },
            Some("server2.example.com"),
        ),
        (
            "no destination",
            DestinationConstraint {
                from: host_tuple("server1.example.com", origin_key),
                to: empty_host_tuple(),
            },
            Some("*"),
        ),
        (
            "invalid origin",
            DestinationConstraint {
                from: host_tuple("server1.example.com", wrong_origin_key),
                to: empty_host_tuple(),
            },
            None,
        ),
    ];
    for (label, constraint, expected) in rows {
        let result =
            permitted_by_dest_constraints(SessionHop::OriginOnly(origin_key), &[constraint], None);
        assert_eq!(result.ok().as_deref(), expected, "{label}");
    }
}
