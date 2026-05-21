use color_print::cprintln;

use axo_pass_core::secrets::keychain::generic_password::PasswordEntry;

pub async fn cmd_list_generic_passwords() {
    let passwords = PasswordEntry::list().unwrap();
    for password in passwords {
        cprintln!(
            "<green>{:6}</green> {}",
            format!("{:?}", password.password_type),
            password.account()
        );
    }
}
