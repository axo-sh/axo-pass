use axo_pass_core::core::app_broker::{self, BrokerError};
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::secrets::keychain::generic_password::PasswordEntry;
use clml::cprintln;

/// Who asked, resolved from this process's parent chain and delegated to the
/// broker the same way `ap age` does it.
fn caller() -> Option<String> {
    Provenance::resolve_current_parent().and_then(|provenance| provenance.caller())
}

pub async fn cmd_list_generic_passwords() {
    let entries = match app_broker::request_keychain_passwords(caller().as_deref()) {
        Ok(entries) => entries,
        Err(e) => {
            match e {
                BrokerError::Cancelled => log::error!("Cancelled"),
                e => log::error!("{e}"),
            }
            std::process::exit(1);
        },
    };
    for entry in entries {
        let account = PasswordEntry {
            password_type: entry.password_type.clone(),
            key_id: entry.key_id,
        }
        .account();
        cprintln!(
            "<green>{:6}</green> {}",
            format!("{:?}", entry.password_type),
            account
        );
    }
}
