use color_print::cprintln;

use crate::secrets::keychain::generic_password::PasswordEntry;

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
