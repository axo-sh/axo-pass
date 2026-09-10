use axo_pass_core::core::app_broker::{self, BrokerError};
use axo_pass_core::core::provenance::Provenance;
use clml::cprintln;
use ssh_key::HashAlg;

/// Who asked, resolved from this process's parent chain and delegated to the
/// broker the same way `ap age` does it.
fn caller() -> Option<String> {
    Provenance::resolve_current_parent().and_then(|provenance| provenance.caller())
}

fn exit_on_broker_err(e: BrokerError) -> ! {
    match e {
        BrokerError::Cancelled => log::error!("Cancelled"),
        e => log::error!("{e}"),
    }
    std::process::exit(1);
}

pub async fn cmd_list_managed_keys() {
    let identities = match app_broker::list_identities() {
        Ok(identities) => identities,
        Err(e) => exit_on_broker_err(e),
    };

    if identities.is_empty() {
        println!("No managed keys found");
        return;
    }

    for (i, identity) in identities.iter().enumerate() {
        cprintln!("<green>Label:</green> {}", identity.key_label);
        match ssh_key::PublicKey::from_openssh(&identity.public_key) {
            Ok(public_key) => cprintln!(
                "<green>Public Key:</green> {}",
                public_key.fingerprint(HashAlg::Sha256)
            ),
            Err(e) => cprintln!("<red>Failed to parse public key:</red> {e}"),
        }
        if i < identities.len() - 1 {
            println!();
        }
    }
}

pub async fn cmd_delete_managed_key(label: &str) {
    match app_broker::request_delete_managed_key(label, caller().as_deref()) {
        Ok(()) => cprintln!("<green>Deleted managed key:</green> {label}"),
        Err(e) => exit_on_broker_err(e),
    }
}
