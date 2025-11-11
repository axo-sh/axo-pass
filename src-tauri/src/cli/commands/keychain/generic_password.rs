use crate::secrets::keychain::generic_password::PasswordEntry;

pub async fn cmd_list_generic_passwords() {
    let passwords = PasswordEntry::list().unwrap();
    for password in passwords {
        println!("{:?} {}", password.password_type, password.account());
    }
}
