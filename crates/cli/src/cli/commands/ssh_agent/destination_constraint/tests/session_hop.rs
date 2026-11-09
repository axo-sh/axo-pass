use ssh_agent_lib::proto::extension::DestinationConstraint;

use super::super::{SessionHop, validate_session_hop};
use super::{TEST_ED25519_KEY, TEST_RSA_KEY, empty_host_tuple, host_tuple};

#[test]
fn valid_single_hop_no_origin() {
    // single hop has no origin (being the first hop)
    let dest_key = &TEST_ED25519_KEY;
    let result = validate_session_hop(
        SessionHop::FirstHop(dest_key, true), // final hop
        false,                                // not forwarding
        Some("alice"),
        &[DestinationConstraint {
            from: empty_host_tuple(),
            to: host_tuple("server1.example.com", dest_key),
        }],
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "server1.example.com");
}

#[test]
fn single_hop_signing_on_forwarding_fails() {
    // single hop has no origin (being the first hop)
    let dest_key = &TEST_ED25519_KEY;
    let result = validate_session_hop(
        SessionHop::FirstHop(dest_key, true), // final hop
        true,                                 // forwarding
        Some("alice"),                        // signing request
        &[DestinationConstraint {
            from: empty_host_tuple(),
            to: host_tuple("server1.example.com", dest_key),
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
fn valid_intermediate_hop() {
    let origin_key = &TEST_RSA_KEY;
    let dest_key = &TEST_ED25519_KEY;
    let result = validate_session_hop(
        SessionHop::IntermediateHop {
            origin: origin_key,
            destination: dest_key,
            final_hop: false,
        },
        true, // forwarding
        None,
        &[DestinationConstraint {
            from: host_tuple("server1.example.com", origin_key),
            to: host_tuple("server2.example.com", dest_key),
        }],
    );
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "server2.example.com");
}

#[test]
fn intermediate_hop_not_forwarding_fails() {
    let origin_key = &TEST_RSA_KEY;
    let dest_key = &TEST_ED25519_KEY;

    let result = validate_session_hop(
        SessionHop::IntermediateHop {
            origin: origin_key,
            destination: dest_key,
            final_hop: false,
        },
        false, // not forwarding
        None,
        &[DestinationConstraint {
            from: host_tuple("server1.example.com", origin_key),
            to: host_tuple("server2.example.com", dest_key),
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
fn constraint_not_matched() {
    let origin_key = &TEST_RSA_KEY;
    let dest_key = &TEST_ED25519_KEY;
    let wrong_dest_key = &TEST_RSA_KEY;

    let result = validate_session_hop(
        SessionHop::IntermediateHop {
            origin: origin_key,
            destination: dest_key,
            final_hop: false,
        },
        true, // forwarding
        None,
        &[DestinationConstraint {
            from: host_tuple("server1.example.com", origin_key),
            to: host_tuple("server2.example.com", wrong_dest_key), // wrong key
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
