use super::*;

mod conversion;
mod login_write;
mod lookup;
mod matching;
mod merge;

fn site(url: &str, kind: MatchKind) -> Website {
    Website::new(url, kind)
}

fn domain(url: &str) -> Vec<Website> {
    vec![site(url, MatchKind::Domain)]
}

fn matches(websites: &[Website], service: &str) -> bool {
    match_service(websites, service).is_some()
}

fn login<'a>(websites: &'a [String], username: Option<&'a str>) -> LoginWrite<'a> {
    LoginWrite {
        item_key: "github",
        title: "GitHub",
        password_key: "password",
        password: SecretString::from("hunter2"),
        username,
        websites,
        match_kind: MatchKind::Domain,
    }
}

fn names(url: &str) -> (String, String) {
    names_for_site(&Site::parse(url).unwrap())
}

/// An item the way an older build stored it: credentials only, with no
/// roles or websites.
fn legacy_item(vw: &mut VaultHandle, key: &str, creds: &[(&str, FieldKind, &str)]) {
    vw.add_item(key, key).unwrap();
    for (cred_key, kind, value) in creds {
        vw.add_secret(
            key,
            cred_key,
            cred_key,
            kind.clone(),
            SecretString::from(*value),
        )
        .unwrap();
    }
}

fn overview(creds: &[(&str, FieldKind)]) -> VaultItemOverview {
    let mut item = VaultItemOverview::try_new("Item", "item").unwrap();
    for (key, kind) in creds {
        let cred = VaultItemCredentialOverview::try_new(key, key, kind.clone()).unwrap();
        item.credentials.insert(cred.id, cred);
    }
    item
}

fn key_of(item: &VaultItemOverview, key: &str) -> uuid::Uuid {
    item.credentials.values().find(|c| c.key == key).unwrap().id
}

fn github_login(vw: &mut VaultHandle) -> String {
    let websites = vec!["github.com".to_string()];
    write_login(vw, login(&websites, Some("tp"))).unwrap();
    collect_items(vw, Some("github.com")).unwrap()[0]
        .record_id
        .clone()
}
