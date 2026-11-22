//! Picks the vault items an AutoFill credential provider can offer, and matches
//! them against the service identifier the system supplies.
//!
//! An item is a login when its autofill data names a password credential, and
//! it applies to the websites in its autofill data. The username is a
//! credential value, so collecting it needs an unlocked vault; the password is
//! never collected here, it is read separately once the user picks an account.
//!
//! Items that predate autofill data have no roles or websites. They are not
//! offered until the user converts them: [`suggest_conversion`] proposes roles
//! and websites from the item's credentials, and [`convert_to_login`] applies
//! them.
//!
//! Websites match through the Public Suffix List, including its private
//! section, so `a.github.io` and `b.github.io` are different sites.

pub(super) mod item;

use std::collections::HashMap;

pub use item::Role;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::{Host, Url};
use uuid::Uuid;

use super::model::totp::{self, TotpCode};
use super::storage::handle::validate_key;
use super::sync::view::{AskRegister, Conflict, Entity};
use super::{
    CATEGORY_LOGIN, Error, FieldKind, ItemAutofill, MatchKind, ShortId, VaultHandle,
    VaultItemCredentialOverview, VaultItemOverview, VaultItemSection, Website,
};

/// Credential keys treated as the account name when a conversion finds no
/// `Email` field, in preference order. The first is also the key new logins
/// write.
const USERNAME_KEYS: &[&str] = &["username", "user", "login", "email", "account"];

/// How closely a stored website matched. Lower sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchRank {
    /// The stored host equals the requested host.
    Host,
    /// Only the registrable domain is shared.
    Domain,
}

/// The stored website that made an item match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedWebsite {
    /// The stored host, lowercased, with one leading `www.` removed.
    pub host: String,
    pub kind: MatchKind,
    pub rank: MatchRank,
}

/// One vault item as an AutoFill candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillItem {
    pub vault_key: String,
    /// Display name of the vault. `None` if the vault has no name.
    #[serde(default)]
    pub vault_name: Option<String>,
    pub item_key: String,
    /// `<vault uuid>/<item uuid>/<password credential uuid>`. Survives renames
    /// of the item and its credentials.
    pub record_id: String,
    pub title: String,
    /// The account name shown beside the item. `None` when the item has no
    /// field that reads as one.
    pub username: Option<String>,
    /// The credential key holding the password to fill.
    pub password_key: String,
    /// The websites the item applies to.
    pub websites: Vec<Website>,
    /// Whether the item has a `Totp` credential to produce a one-time code
    /// from.
    pub has_totp: bool,
    /// The website that matched the requested service. `None` when collected
    /// without a service.
    pub matched: Option<MatchedWebsite>,
}

impl AutofillItem {
    /// How this item ranks among matches, best first. Ties break on title.
    pub fn sort_key(&self) -> (Option<MatchRank>, String) {
        (
            self.matched.as_ref().map(|m| m.rank),
            self.title.to_lowercase(),
        )
    }

    /// What a client may learn about a match: enough to show the account and
    /// say why it matched. `None` when the item was collected without a
    /// service.
    pub fn summary(&self, show_vault: bool) -> Option<LoginSummary> {
        Some(LoginSummary {
            record_id: self.record_id.clone(),
            title: self.title.clone(),
            username: self.username.clone(),
            vault_name: self.shown_vault_name(show_vault),
            matched: self.matched.clone()?,
            has_totp: self.has_totp,
        })
    }

    /// What a client may learn about a login that does not match the page.
    pub fn other(&self, show_vault: bool) -> OtherLogin {
        OtherLogin {
            record_id: self.record_id.clone(),
            title: self.title.clone(),
            username: self.username.clone(),
            vault_name: self.shown_vault_name(show_vault),
            has_totp: self.has_totp,
        }
    }

    /// Hosts of the item's websites, without duplicates.
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = Vec::new();
        for website in &self.websites {
            let host = Site::parse(&website.url).map_or(website.url.clone(), |s| s.host);
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        hosts
    }

    /// Vault name for a client list. Left out if the user has one vault.
    fn shown_vault_name(&self, show_vault: bool) -> Option<String> {
        self.vault_name.clone().filter(|_| show_vault)
    }
}

/// A login that does not match the page, listed so the user can still choose
/// it. Filling one needs the user's confirmation. It carries no website.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtherLogin {
    pub record_id: String,
    pub title: String,
    pub username: Option<String>,
    /// Name of the vault holding the login. Set only if the user has more than
    /// one vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_name: Option<String>,
    pub has_totp: bool,
}

/// One login offered for a page, as a client sees it. It carries no password,
/// no credential keys, and no website other than the one that matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginSummary {
    pub record_id: String,
    pub title: String,
    pub username: Option<String>,
    /// Name of the vault holding the login. Set only if the user has more than
    /// one vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_name: Option<String>,
    /// The stored website that matched, and how.
    pub matched: MatchedWebsite,
    /// Whether the login has a one-time code.
    pub has_totp: bool,
}

/// Collect every AutoFill candidate in an unlocked vault. `service`, when
/// given, keeps only the items matching it, best match first.
pub fn collect_items(vw: &VaultHandle, service: Option<&str>) -> Result<Vec<AutofillItem>, Error> {
    let target = match service {
        Some(service) => match ParsedUrl::parse(service) {
            Some(target) => Some(target),
            // A service that is not an http(s) site matches nothing.
            None => return Ok(Vec::new()),
        },
        None => None,
    };
    let vault_id = vw.vault_id()?;

    let mut items = Vec::new();
    for overview in vw.list_items()? {
        if let Some(item) = candidate(vw, vault_id, overview, target.as_ref())? {
            items.push(item);
        }
    }
    items.sort_by_key(AutofillItem::sort_key);
    Ok(items)
}

/// One item as an AutoFill candidate. `None` when the item is not a login, or
/// when `target` is given and no website of the item matches it.
fn candidate(
    vw: &VaultHandle,
    vault_id: Uuid,
    overview: &VaultItemOverview,
    target: Option<&ParsedUrl>,
) -> Result<Option<AutofillItem>, Error> {
    let Some(password) = overview.autofill.password_credential(overview) else {
        return Ok(None);
    };
    let websites = overview.autofill.websites.clone();

    let matched = match target {
        Some(target) => match best_match(&websites, target) {
            Some(matched) => Some(matched),
            None => return Ok(None),
        },
        None => None,
    };

    let username = match overview.autofill.username_credential(overview) {
        Some(cred) => read(vw, &overview.key, &cred.key)?,
        None => None,
    };

    Ok(Some(AutofillItem {
        vault_key: vw.key.clone(),
        vault_name: vw.vault_name().map(str::to_string),
        item_key: overview.key.clone(),
        record_id: format!(
            "{}/{}/{}",
            ShortId::new(vault_id),
            ShortId::new(overview.id),
            ShortId::new(password.id)
        ),
        title: overview.title.clone(),
        username,
        password_key: password.key.clone(),
        websites,
        has_totp: overview.autofill.totp_credential(overview).is_some(),
        matched,
    }))
}

/// The hosts to register with the system's credential identity store for an
/// item's websites, without duplicates. A `domain` website registers its
/// registrable domain as well as its host, and the other kinds register the
/// host. A website that never matches registers nothing.
pub fn identity_hosts(websites: &[Website]) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    let mut add = |host: String| {
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    };
    for website in websites {
        let Some(site) = Site::parse(&website.url) else {
            continue;
        };
        match website.match_kind {
            MatchKind::Never => {},
            MatchKind::Domain => {
                add(site.domain);
                add(site.host);
            },
            MatchKind::Host | MatchKind::StartsWith => add(site.host),
        }
    }
    hosts
}

/// A login item that a new passkey may be stored in.
#[derive(Debug, Clone, PartialEq)]
pub struct LoginPlace {
    pub vault_key: String,
    pub item_key: String,
    pub title: String,
    pub username: Option<String>,
    pub websites: Vec<Website>,
}

/// Collect the login items of an unlocked vault that list at least one website.
/// A login is an item with a password role, a passkey, or the `login` category.
/// Unlike [`collect_items`] this includes logins with no password, such as the
/// ones created for a passkey.
pub fn collect_places(vw: &VaultHandle) -> Result<Vec<LoginPlace>, Error> {
    let mut places = Vec::new();
    for overview in vw.list_items()? {
        let has_passkey = overview
            .credentials
            .values()
            .any(|c| matches!(c.kind, FieldKind::Passkey));
        let is_login = overview.autofill.password_credential(overview).is_some()
            || has_passkey
            || overview.category.as_deref() == Some(CATEGORY_LOGIN);
        if !is_login || overview.autofill.websites.is_empty() {
            continue;
        }
        let username = match overview.autofill.username_credential(overview) {
            Some(cred) => read(vw, &overview.key, &cred.key)?,
            None => None,
        };
        places.push(LoginPlace {
            vault_key: vw.key.clone(),
            item_key: overview.key.clone(),
            title: overview.title.clone(),
            username,
            websites: overview.autofill.websites.clone(),
        });
    }
    Ok(places)
}

/// The places with a website that matches the relying party `rp_id`. A relying
/// party matches under `domain` rules, since an rp id is valid for its
/// registrable domain.
pub fn places_for_rp<'a>(places: &'a [LoginPlace], rp_id: &str) -> Vec<&'a LoginPlace> {
    places
        .iter()
        .filter(|place| match_service(&place.websites, rp_id).is_some())
        .collect()
}

/// The three ids of a record identifier: vault, item, and password credential.
/// Record identifiers are written with short ids. The hex forms are also read,
/// since the AutoFill index can hold identifiers registered before.
pub fn parse_record_id(record_id: &str) -> Option<(Uuid, Uuid, Uuid)> {
    let mut parts = record_id.split('/');
    let vault = ShortId::parse_uuid(parts.next()?).ok()?;
    let item = ShortId::parse_uuid(parts.next()?).ok()?;
    let credential = ShortId::parse_uuid(parts.next()?).ok()?;
    parts.next().is_none().then_some((vault, item, credential))
}

/// The login a record identifier names, when it still matches `frame_url`.
///
/// This is the broker's own check before a fill or a code is produced, so it
/// does not trust the client's claim that the record belongs on the page. The
/// record must be a login in this vault, its password credential must be the
/// one the identifier names, and one of its websites must match `frame_url`
/// under that website's match kind.
pub fn find_login(
    vw: &VaultHandle,
    record_id: &str,
    frame_url: &str,
) -> Result<Option<AutofillItem>, Error> {
    let Some(ids @ (vault_id, item_id, _)) = parse_record_id(record_id) else {
        return Ok(None);
    };
    if vw.vault_id()? != vault_id {
        return Ok(None);
    }
    let Some(target) = ParsedUrl::parse(frame_url) else {
        return Ok(None);
    };
    let Some(overview) = vw.get_item_overview_by_id(item_id)? else {
        return Ok(None);
    };
    Ok(candidate(vw, vault_id, overview, Some(&target))?
        .filter(|item| parse_record_id(&item.record_id) == Some(ids)))
}

/// What a fill returns: the username and password roles and nothing else on the
/// item.
pub struct LoginSecrets {
    pub username: Option<String>,
    pub password: SecretString,
}

/// Read the role credentials of a login found by [`find_login`].
pub fn read_login(vw: &VaultHandle, item: &AutofillItem) -> Result<Option<LoginSecrets>, Error> {
    use secrecy::ExposeSecret;

    let Some(password) = vw.get_secret(&item.item_key, &item.password_key)? else {
        return Ok(None);
    };
    Ok(Some(LoginSecrets {
        username: item.username.clone(),
        password: SecretString::from(password.expose_secret().clone()),
    }))
}

/// The current one-time code of a login found by [`find_login`], from the
/// item's `Totp` credential with the lowest position. `None` when the item has
/// no such credential or it is empty.
pub fn login_totp(vw: &VaultHandle, item: &AutofillItem) -> Result<Option<TotpCode>, Error> {
    use secrecy::ExposeSecret;

    let Some(overview) = vw.get_item_overview(&item.item_key)? else {
        return Ok(None);
    };
    let Some(cred) = overview.autofill.totp_credential(overview) else {
        return Ok(None);
    };
    let Some(value) = vw.get_secret(&item.item_key, &cred.key)? else {
        return Ok(None);
    };
    totp::current_code(value.expose_secret())
        .map(Some)
        .map_err(Error::InvalidOneTimeCode)
}

/// A page's site, reduced to what a prompt shows and a grant is keyed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// Lowercase ASCII host, with one leading `www.` removed.
    pub host: String,
    /// The registrable domain.
    pub domain: String,
    /// False for `http:`.
    pub secure: bool,
}

impl Site {
    /// Parse an http(s) URL or a bare domain. A bare domain counts as secure.
    pub fn parse(value: &str) -> Option<Self> {
        let parsed = ParsedUrl::parse(value)?;
        Some(Self {
            host: parsed.host,
            domain: parsed.domain,
            secure: parsed.secure,
        })
    }
}

/// Check a WebAuthn relying party id.
///
/// The id must be a domain that is not a public suffix. When `origin` is given
/// it must be the origin's host or a suffix of it on a label boundary
/// (WebAuthn section 5.1.4.1). Safari supplies no origin: the system has
/// already bound the relying party id to the page.
pub fn check_rp_id(rp_id: &str, origin: Option<&str>) -> Result<(), String> {
    let invalid = || format!("{rp_id:?} is not a valid relying party id");
    if rp_id.is_empty()
        || rp_id != rp_id.to_ascii_lowercase()
        || rp_id.contains(['/', ':', '@', ' ', '?', '#'])
        || rp_id.starts_with('.')
        || rp_id.ends_with('.')
    {
        return Err(invalid());
    }
    if rp_id.parse::<std::net::IpAddr>().is_ok() {
        return Err(invalid());
    }
    // The registrable domain is `None` for a public suffix and for a host with
    // no known suffix.
    if psl::domain(rp_id.as_bytes()).is_none() {
        return Err(format!("{rp_id:?} is a public suffix"));
    }

    let Some(origin) = origin else {
        return Ok(());
    };
    let host = Url::parse(origin)
        .ok()
        .and_then(|url| match url.host()? {
            Host::Domain(domain) => Some(domain.trim_end_matches('.').to_string()),
            Host::Ipv4(_) | Host::Ipv6(_) => None,
        })
        .ok_or_else(|| format!("{origin:?} has no domain"))?;
    let is_suffix = host == rp_id || host.ends_with(&format!(".{rp_id}"));
    if is_suffix {
        Ok(())
    } else {
        Err(format!("{rp_id:?} is not a domain of {host:?}"))
    }
}

/// A login to write: the item, its password, and the optional username and
/// websites.
pub struct LoginWrite<'a> {
    pub item_key: &'a str,
    /// Used only when the item does not exist yet.
    pub title: &'a str,
    /// The credential key for the password. Conventionally `password`.
    pub password_key: &'a str,
    pub password: SecretString,
    pub username: Option<&'a str>,
    /// URLs or bare domains, added with `match_kind` unless the item already
    /// lists them.
    pub websites: &'a [String],
    pub match_kind: MatchKind,
}

/// Write a login into an unlocked vault: the item when it is missing, the
/// password credential, the username credential keyed `username`, the role
/// slots, the websites, and `category: login`. The caller saves the vault.
///
/// A writer outside the UI ([`VaultHandle::write_outside_ui`]). It requests
/// writes to the password value and slot, and to the username value and slot
/// if a username is given, so each supersedes a conflict even if the value is
/// unchanged.
pub fn write_login(vw: &mut VaultHandle, login: LoginWrite) -> Result<(), Error> {
    vw.write_outside_ui();
    if vw.get_item_overview(login.item_key)?.is_none() {
        vw.add_item(login.item_key, login.title)?;
    }
    let item_id = item_id(vw, login.item_key)?;
    vw.request_write(slot(item_id, AskRegister::Password));
    if login.username.is_some() {
        vw.request_write(slot(item_id, AskRegister::Username));
    }

    vw.add_secret(
        login.item_key,
        login.password_key,
        "Password",
        FieldKind::default(),
        login.password,
    )?;
    let password_id = credential_id(vw, login.item_key, login.password_key)?;

    let mut autofill = vw
        .get_item_overview(login.item_key)?
        .map(|item| item.autofill.clone())
        .unwrap_or_default();
    autofill.password = Some(password_id);

    if let Some(username) = login.username {
        let kind = if looks_like_email(username) {
            FieldKind::Email
        } else {
            FieldKind::Text(Default::default())
        };
        vw.add_secret(
            login.item_key,
            USERNAME_KEYS[0],
            "Username",
            kind,
            SecretString::from(username.to_string()),
        )?;
        autofill.username = Some(credential_id(vw, login.item_key, USERNAME_KEYS[0])?);
    }

    for url in login.websites {
        let url = url.trim();
        if !url.is_empty() && !autofill.websites.iter().any(|w| w.url == url) {
            autofill.websites.push(Website::new(url, login.match_kind));
        }
    }

    vw.set_item_autofill(login.item_key, autofill)?;
    let has_category = vw
        .get_item_overview(login.item_key)?
        .is_some_and(|item| item.category.is_some());
    if !has_category {
        vw.set_item_category(login.item_key, Some(CATEGORY_LOGIN.to_string()))?;
    }
    Ok(())
}

/// The item key and title for a login saved from `site`. The key is the
/// registrable domain's first label, or the whole domain with dashes when that
/// label is not a valid key. The title is the domain with its first letter
/// capitalized.
pub fn names_for_site(site: &Site) -> (String, String) {
    let label = site.domain.split('.').next().unwrap_or_default();
    let key = [label.to_string(), site.domain.replace('.', "-")]
        .into_iter()
        .find(|candidate| validate_key(candidate))
        .unwrap_or_else(|| "login".to_string());

    let mut chars = site.domain.chars();
    let title = match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Login".to_string(),
    };
    (key, title)
}

/// `base`, or `base-2`, `base-3`, and so on, whichever is the first key no item
/// in `vw` uses.
pub(super) fn unused_item_key(vw: &VaultHandle, base: &str) -> Result<String, Error> {
    let mut key = base.to_string();
    let mut n = 2;
    while vw.get_item_overview(&key)?.is_some() {
        key = format!("{base}-{n}");
        n += 1;
    }
    Ok(key)
}

/// Save a login captured from a form on `site_origin` as a new item, with the
/// conventional `username` and `password` keys. The website is stored with
/// `host` matching, so a capture on one page of a shared host does not offer
/// the login across its whole registrable domain. The caller saves the vault.
pub fn save_login(
    vw: &mut VaultHandle,
    site_origin: &str,
    username: Option<&str>,
    password: SecretString,
) -> Result<AutofillItem, Error> {
    let site = Site::parse(site_origin)
        .ok_or_else(|| Error::InvalidItemKey(format!("{site_origin} is not an http(s) site")))?;
    let (base_key, title) = names_for_site(&site);
    let item_key = unused_item_key(vw, &base_key)?;

    write_login(
        vw,
        LoginWrite {
            item_key: &item_key,
            title: &title,
            password_key: "password",
            password,
            username: username.filter(|name| !name.trim().is_empty()),
            websites: &[site_origin.to_string()],
            match_kind: MatchKind::Host,
        },
    )?;

    let vault_id = vw.vault_id()?;
    let overview = vw
        .get_item_overview(&item_key)?
        .ok_or_else(|| Error::InvalidItemKey(item_key.clone()))?;
    candidate(vw, vault_id, overview, None)?.ok_or_else(|| Error::InvalidItemKey(item_key))
}

/// Create a login from a website, an optional username, and a password, the way
/// the New Login sheet does. The item key and title come from the website's
/// registrable domain unless given. A key that is already taken gets a numeric
/// suffix. The website matches by `domain`. The caller saves the vault. Returns
/// the item's key.
pub fn create_login(
    vw: &mut VaultHandle,
    website: &str,
    username: Option<&str>,
    password: SecretString,
    item_key: Option<&str>,
    title: Option<&str>,
) -> Result<String, Error> {
    let website = website.trim();
    let site = Site::parse(website)
        .ok_or_else(|| Error::InvalidItemKey(format!("{website} is not an http(s) site")))?;
    let (derived_key, derived_title) = names_for_site(&site);

    let base_key = non_empty(item_key).unwrap_or(&derived_key);
    if !validate_key(base_key) {
        return Err(Error::InvalidItemKey(base_key.to_string()));
    }
    let item_key = unused_item_key(vw, base_key)?;

    write_login(
        vw,
        LoginWrite {
            item_key: &item_key,
            title: non_empty(title).unwrap_or(&derived_title),
            password_key: "password",
            password,
            username: non_empty(username),
            websites: &[website.to_string()],
            match_kind: MatchKind::Domain,
        },
    )?;
    Ok(item_key)
}

/// Create a login with an empty password credential and an empty username
/// credential, the way the New Login sheet does. A key that is already taken
/// gets a numeric suffix. The caller saves the vault. Returns the item's key.
pub fn create_blank_login(
    vw: &mut VaultHandle,
    item_key: &str,
    title: &str,
) -> Result<String, Error> {
    if !validate_key(item_key) {
        return Err(Error::InvalidItemKey(item_key.to_string()));
    }
    let item_key = unused_item_key(vw, item_key)?;

    write_login(
        vw,
        LoginWrite {
            item_key: &item_key,
            title,
            password_key: "password",
            password: SecretString::from(String::new()),
            username: Some(""),
            websites: &[],
            match_kind: MatchKind::Domain,
        },
    )?;
    Ok(item_key)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// Assign `role` to the credential `cred_key`, or clear the role with `None`. A
/// credential has one role, so it leaves any it had before. Assigning the
/// password role to an item with no category makes it a login. The caller saves
/// the vault.
pub fn set_role(
    vw: &mut VaultHandle,
    item_key: &str,
    role: Role,
    cred_key: Option<&str>,
) -> Result<(), Error> {
    let overview = vw
        .get_item_overview(item_key)?
        .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
    let mut autofill = overview.autofill.clone();
    let has_category = overview.category.is_some();

    let cred_id = match cred_key {
        Some(cred_key) => {
            let cred = vw
                .get_secret_overview(item_key, cred_key)?
                .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))?;
            let usable = match role {
                Role::Totp => matches!(cred.kind, FieldKind::Totp),
                Role::Username | Role::Password => !matches!(
                    cred.kind,
                    FieldKind::Passkey
                        | FieldKind::File
                        | FieldKind::SshKey
                        | FieldKind::Totp
                        | FieldKind::Unknown(_)
                ),
            };
            if !usable {
                return Err(Error::InvalidAutofill(format!(
                    "{cred_key} cannot be used as the {role:?} credential"
                )));
            }
            autofill.clear_credential(cred.id);
            Some(cred.id)
        },
        None => None,
    };
    match role {
        Role::Username => autofill.username = cred_id,
        Role::Password => autofill.password = cred_id,
        Role::Totp => autofill.totp = cred_id,
    }

    vw.set_item_autofill(item_key, autofill)?;
    if role == Role::Password && cred_id.is_some() && !has_category {
        vw.set_item_category(item_key, Some(CATEGORY_LOGIN.to_string()))?;
    }
    Ok(())
}

/// Replace the websites an item applies to. Every URL must be an `http` or
/// `https` site or a bare domain. The caller saves the vault.
pub fn set_websites(
    vw: &mut VaultHandle,
    item_key: &str,
    websites: Vec<Website>,
) -> Result<(), Error> {
    let overview = vw
        .get_item_overview(item_key)?
        .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
    let mut autofill = overview.autofill.clone();
    autofill.websites = websites
        .into_iter()
        .map(|website| {
            let url = website.url.trim();
            if Site::parse(url).is_none() {
                return Err(Error::InvalidAutofill(format!(
                    "{url:?} is not an http(s) site"
                )));
            }
            Ok(Website::new(url, website.match_kind))
        })
        .collect::<Result<_, _>>()?;
    vw.set_item_autofill(item_key, autofill)
}

/// Create the login item a new passkey is stored in: titled `title`, with a
/// website for `rp_id` under `domain` matching and, when `username` is given, a
/// username credential assigned the username role. It has no password role. The
/// caller saves the vault. Returns the new item's key.
pub fn add_passkey_login(
    vw: &mut VaultHandle,
    rp_id: &str,
    title: Option<&str>,
    username: Option<&str>,
) -> Result<String, Error> {
    let site = Site::parse(rp_id)
        .ok_or_else(|| Error::InvalidItemKey(format!("{rp_id} is not a relying party domain")))?;
    let (base_key, derived_title) = names_for_site(&site);
    let item_key = unused_item_key(vw, &base_key)?;
    let title = title
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .unwrap_or(&derived_title);
    vw.add_item(&item_key, title)?;

    let mut autofill = ItemAutofill::default();
    if let Some(username) = username.map(str::trim).filter(|name| !name.is_empty()) {
        let kind = if looks_like_email(username) {
            FieldKind::Email
        } else {
            FieldKind::Text(Default::default())
        };
        vw.add_secret(
            &item_key,
            USERNAME_KEYS[0],
            "Username",
            kind,
            SecretString::from(username.to_string()),
        )?;
        autofill.username = Some(credential_id(vw, &item_key, USERNAME_KEYS[0])?);
    }
    autofill
        .websites
        .push(Website::new(rp_id, MatchKind::Domain));
    vw.set_item_autofill(&item_key, autofill)?;
    vw.set_item_category(&item_key, Some(CATEGORY_LOGIN.to_string()))?;
    Ok(item_key)
}

/// Move credentials from `source_key` item into `dest_key` and delete the
/// source item.
///
/// - credentials move with their values and previous values, and keep their
///   ids.
/// - credentials whose key and value equal one already in the destination stay
///   in the source and are not moved, so merging two logins for the same
///   account does not leave two usernames.
/// - keys already present in the destination are given a numeric suffix.
/// - a credential in a source section goes in the destination section with the
///   same title, which is created if missing.
/// - source's roles are only added to the destination unless already present
/// - websites are added unless already present
/// - uncategorized destinations take the source's category.
/// - source passkeys that stay in the source are purged, so a restored source
///   does not give a second copy of a passkey.
/// - the source goes to the deleted items with the credentials that stayed and
///   its own deleted credentials. With neither, it is purged.
/// - caller is responsible for saving the vault.
///
/// A writer outside the UI ([`VaultHandle::write_outside_ui`]), so it is never
/// refused, and each Ask register it writes supersedes a conflict.
pub fn merge_items(vw: &mut VaultHandle, source_key: &str, dest_key: &str) -> Result<(), Error> {
    use secrecy::ExposeSecret;

    vw.write_outside_ui();
    if source_key == dest_key {
        return Err(Error::InvalidItemKey(format!(
            "cannot merge {source_key} into itself"
        )));
    }
    let source = vw
        .get_item_overview(source_key)?
        .ok_or_else(|| Error::InvalidItemKey(source_key.to_string()))?
        .clone();
    let dest = vw
        .get_item_overview(dest_key)?
        .ok_or_else(|| Error::InvalidItemKey(dest_key.to_string()))?
        .clone();

    // Source credential id to the destination credential that now holds it.
    let mut moved: Vec<(Uuid, Uuid)> = Vec::new();
    // Source section id to the destination section with the same title.
    let mut sections: HashMap<Uuid, Uuid> = HashMap::new();
    let mut stayed = 0;
    for cred in sorted_credentials(&source) {
        if let Some(existing) = dest.credentials.values().find(|c| c.key == cred.key) {
            let value = vw.get_secret(source_key, &cred.key)?;
            let same = existing.kind == cred.kind
                && value.is_some_and(|value| {
                    vw.get_secret(dest_key, &existing.key)
                        .ok()
                        .flatten()
                        .is_some_and(|v| v.expose_secret() == value.expose_secret())
                });
            if same {
                moved.push((cred.id, existing.id));
                if matches!(cred.kind, FieldKind::Passkey) {
                    super::passkey::remove_record(vw, source_key, &cred.key)?;
                } else {
                    stayed += 1;
                }
                continue;
            }
        }
        let section = match cred.section.and_then(|id| source.sections.get(&id)) {
            Some(section) => Some(dest_section(vw, dest_key, section, &mut sections)?),
            None => None,
        };
        let key = unused_credential_key(vw, dest_key, &cred.key)?;
        vw.transfer_credential(source_key, &cred.key, dest_key, &key, section)?;
        moved.push((cred.id, cred.id));
    }
    let carried = |slot: Option<Uuid>| {
        slot.and_then(|id| {
            moved
                .iter()
                .find(|(from, _)| *from == id)
                .map(|(_, to)| *to)
        })
    };

    let mut autofill = dest.autofill.clone();
    autofill.username = autofill.username.or(carried(source.autofill.username));
    autofill.password = autofill.password.or(carried(source.autofill.password));
    autofill.totp = autofill.totp.or(carried(source.autofill.totp));
    for website in &source.autofill.websites {
        if !autofill.websites.iter().any(|w| w.url == website.url) {
            autofill.websites.push(website.clone());
        }
    }
    vw.set_item_autofill(dest_key, autofill)?;
    if dest.category.is_none() && source.category.is_some() {
        vw.set_item_category(dest_key, source.category.clone())?;
    }
    let has_deleted = vw
        .list_all_deleted()?
        .iter()
        .any(|entry| entry.item.id == source.id);
    vw.delete_item(source_key)?;
    if stayed == 0 && !has_deleted {
        vw.purge_item(source.id)?;
    }
    Ok(())
}

/// Destination section for credentials from `section` of the source item: the
/// destination section with the same title, created if there is none.
/// `sections` caches the choice per source section.
fn dest_section(
    vw: &mut VaultHandle,
    dest_key: &str,
    section: &VaultItemSection,
    sections: &mut HashMap<Uuid, Uuid>,
) -> Result<Uuid, Error> {
    if let Some(id) = sections.get(&section.id) {
        return Ok(*id);
    }
    let existing = vw
        .get_item_overview(dest_key)?
        .and_then(|dest| dest.sections.values().find(|s| s.title == section.title))
        .map(|s| s.id);
    let id = match existing {
        Some(id) => id,
        None => vw.create_item_section(dest_key, &section.title)?.id,
    };
    sections.insert(section.id, id);
    Ok(id)
}

/// `base`, or `base-2`, `base-3`, and so on, whichever is the first credential
/// key the item does not use.
fn unused_credential_key(vw: &VaultHandle, item_key: &str, base: &str) -> Result<String, Error> {
    let mut key = base.to_string();
    let mut n = 2;
    while vw.get_secret_overview(item_key, &key)?.is_some() {
        key = format!("{base}-{n}");
        n += 1;
    }
    Ok(key)
}

/// The login a record identifier names, wherever it applies. Unlike
/// [`find_login`] this does not check a page, so the caller decides what an
/// unmatched page means.
pub fn find_login_record(vw: &VaultHandle, record_id: &str) -> Result<Option<AutofillItem>, Error> {
    let Some(ids @ (vault_id, item_id, _)) = parse_record_id(record_id) else {
        return Ok(None);
    };
    if vw.vault_id()? != vault_id {
        return Ok(None);
    }
    let Some(overview) = vw.get_item_overview_by_id(item_id)? else {
        return Ok(None);
    };
    Ok(candidate(vw, vault_id, overview, None)?
        .filter(|item| parse_record_id(&item.record_id) == Some(ids)))
}

/// Whether `frame_url` is a page the login is stored for.
pub fn is_stored_for(item: &AutofillItem, frame_url: &str) -> bool {
    match_service(&item.websites, frame_url).is_some()
}

/// Replace the password of a login found by [`find_login_record`], keeping the
/// credential's title and kind. The caller saves the vault. A writer outside
/// the UI, which requests a write to the password value.
pub fn update_login_password(
    vw: &mut VaultHandle,
    item: &AutofillItem,
    password: SecretString,
) -> Result<(), Error> {
    vw.write_outside_ui();
    let (title, kind) = vw
        .get_secret_overview(&item.item_key, &item.password_key)?
        .map(|credential| (credential.title.clone(), credential.kind.clone()))
        .ok_or_else(|| {
            Error::InvalidCredentialKey(format!("{}/{}", item.item_key, item.password_key))
        })?;
    vw.add_secret(&item.item_key, &item.password_key, &title, kind, password)
}

fn item_id(vw: &VaultHandle, item_key: &str) -> Result<Uuid, Error> {
    vw.get_item_overview(item_key)?
        .map(|item| item.id)
        .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))
}

/// Role slot register `register` of item `item_id`.
fn slot(item_id: Uuid, register: AskRegister) -> Conflict {
    Conflict {
        entity: Entity::Item(item_id),
        register,
    }
}

fn credential_id(vw: &VaultHandle, item_key: &str, cred_key: &str) -> Result<uuid::Uuid, Error> {
    vw.get_secret_overview(item_key, cred_key)?
        .map(|cred| cred.id)
        .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))
}

fn looks_like_email(value: &str) -> bool {
    match value.split_once('@') {
        Some((local, host)) => {
            !local.is_empty() && host.contains('.') && !value.chars().any(char::is_whitespace)
        },
        None => false,
    }
}

/// The first website of `websites` that matches `service`, preferring an exact
/// host match over a domain match. `service` is a bare domain or a full URL.
pub fn match_service(websites: &[Website], service: &str) -> Option<MatchedWebsite> {
    best_match(websites, &ParsedUrl::parse(service)?)
}

fn best_match(websites: &[Website], target: &ParsedUrl) -> Option<MatchedWebsite> {
    websites
        .iter()
        .filter_map(|website| match_website(website, target))
        .min_by_key(|matched| matched.rank)
}

fn match_website(website: &Website, target: &ParsedUrl) -> Option<MatchedWebsite> {
    let stored = ParsedUrl::parse(&website.url)?;
    // A login stored with an https URL never fills an http page.
    if stored.https_only && !target.secure {
        return None;
    }
    let same_host = stored.host == target.host;
    // Host and path matching also compare ports. Domain matching does not.
    let same_origin_host = same_host && ports_agree(stored.port, target.port);
    let matches = match website.match_kind {
        MatchKind::Never => false,
        MatchKind::Domain => stored.domain == target.domain,
        MatchKind::Host => same_origin_host,
        MatchKind::StartsWith => {
            // A bare domain has no page to compare, so it matches by host.
            same_origin_host
                && match &target.path {
                    None => true,
                    Some(path) => path_within(stored.path.as_deref().unwrap_or("/"), path),
                }
        },
    };
    matches.then_some(MatchedWebsite {
        host: stored.host,
        kind: website.match_kind,
        rank: if same_host {
            MatchRank::Host
        } else {
            MatchRank::Domain
        },
    })
}

/// What a website matches, for display. A `domain` website gives its
/// registrable domain, a `host` or `never` website gives its host, and a
/// `starts-with` website gives its host and path. A port other than 80 or 443
/// is kept. `None` if the URL does not parse.
pub fn match_scope(website: &Website) -> Option<String> {
    let parsed = ParsedUrl::parse(&website.url)?;
    let host = match parsed.port {
        Some(port) if port != 80 && port != 443 => format!("{}:{port}", parsed.host),
        _ => parsed.host,
    };
    Some(match website.match_kind {
        MatchKind::Domain => parsed.domain,
        MatchKind::Host | MatchKind::Never => host,
        MatchKind::StartsWith => match parsed.path.as_deref() {
            None | Some("/") => host,
            Some(path) => format!("{host}{path}"),
        },
    })
}

/// Two ports agree when they are equal, or when either side names none. A bare
/// domain names none.
fn ports_agree(stored: Option<u16>, target: Option<u16>) -> bool {
    match (stored, target) {
        (Some(stored), Some(target)) => stored == target,
        _ => true,
    }
}

/// Whether `target` is `stored` or a page under it. Both are a path with an
/// optional `?query`. Paths compare by segment, so `/app` covers `/app/login`
/// but not `/application`, and a trailing slash is ignored. A stored query must
/// equal the target's.
fn path_within(stored: &str, target: &str) -> bool {
    let (stored_path, stored_query) = match stored.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (stored, None),
    };
    let (target_path, target_query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    let stored_path = stored_path.trim_end_matches('/');
    let target_path = target_path.trim_end_matches('/');
    let under = target_path == stored_path
        || target_path
            .strip_prefix(stored_path)
            .is_some_and(|rest| rest.starts_with('/'));
    under && stored_query.is_none_or(|query| target_query == Some(query))
}

/// A service identifier or stored URL reduced to what matching compares.
#[derive(Debug, PartialEq, Eq)]
struct ParsedUrl {
    /// Lowercase ASCII host, with one leading `www.` removed.
    host: String,
    /// The registrable domain. The host itself for IP addresses, single-label
    /// hosts, and hosts that are public suffixes.
    domain: String,
    /// False for `http:`. A bare domain counts as secure.
    secure: bool,
    /// True when the value names `https:` explicitly. A bare domain does not.
    https_only: bool,
    /// The port, with the scheme's default filled in, so `https://example.com`
    /// and `https://example.com:443` agree. `None` for a bare domain with no
    /// port.
    port: Option<u16>,
    /// Path and query. `None` for a bare domain.
    path: Option<String>,
}

impl ParsedUrl {
    /// Parse a bare domain or an http(s) URL. Any other scheme gives `None`.
    /// Domain matching ignores ports.
    fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        let has_scheme = value.contains("://");
        // A bare domain has no scheme, which `Url` rejects, so add one.
        let candidate = if has_scheme {
            value.to_string()
        } else {
            format!("https://{value}")
        };
        let url = Url::parse(&candidate).ok()?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }

        let (host, is_ip) = match url.host()? {
            // `Url` has already lowercased the host and converted it to ASCII.
            Host::Domain(domain) => (domain.trim_end_matches('.').to_string(), false),
            Host::Ipv4(ip) => (ip.to_string(), true),
            Host::Ipv6(ip) => (ip.to_string(), true),
        };
        let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
        if host.is_empty() {
            return None;
        }

        let domain = if is_ip {
            host.clone()
        } else {
            psl::domain(host.as_bytes())
                .and_then(|domain| std::str::from_utf8(domain.as_bytes()).ok())
                .unwrap_or(&host)
                .to_string()
        };

        let has_path = url.path() != "/" || url.query().is_some();
        let path = (has_scheme || has_path).then(|| match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        });

        let secure = url.scheme() != "http";
        let https_only = has_scheme && url.scheme() == "https";
        let port = url
            .port()
            .or_else(|| has_scheme.then(|| url.port_or_known_default()).flatten());

        Some(Self {
            host,
            domain,
            secure,
            https_only,
            port,
            path,
        })
    }
}

fn read(vw: &VaultHandle, item_key: &str, cred_key: &str) -> Result<Option<String>, Error> {
    use secrecy::ExposeSecret;
    let value = vw
        .get_secret(item_key, cred_key)?
        .map(|secret| secret.expose_secret().to_string())
        .filter(|value| !value.trim().is_empty());
    Ok(value)
}

/// An item's credentials in display order. Reordered credentials lead, so the
/// first confidential field is the one the user put at the top.
fn sorted_credentials(overview: &VaultItemOverview) -> Vec<&VaultItemCredentialOverview> {
    let mut credentials: Vec<_> = overview.credentials.values().collect();
    credentials.sort_by(|a, b| {
        (a.position.unwrap_or(u32::MAX), &a.title).cmp(&(b.position.unwrap_or(u32::MAX), &b.title))
    });
    credentials
}

/// The roles and websites that would turn an item with no autofill data into a
/// login.
#[derive(Debug, Clone, PartialEq)]
pub struct LoginConversion {
    pub password: Uuid,
    pub username: Option<Uuid>,
    pub totp: Option<Uuid>,
    pub websites: Vec<Website>,
}

/// What converting `overview` to a login would assign, or `None` when the item
/// already has roles or websites, or lacks a confidential credential or an
/// `http` or `https` `Url` credential.
///
/// The password is the first confidential credential, preferring one whose key
/// or title contains "password". The username is the first `Email` credential,
/// else the first credential keyed `username`, `user`, `login`, `email`, or
/// `account`. The websites are the item's `Url` credentials with an `http` or
/// `https` scheme, matched by `domain`; other schemes would turn database and
/// API items into logins. The one-time code is the first `Totp` credential.
pub fn suggest_conversion(
    vw: &VaultHandle,
    overview: &VaultItemOverview,
) -> Result<Option<LoginConversion>, Error> {
    let autofill = &overview.autofill;
    if autofill.password.is_some() || autofill.username.is_some() || !autofill.websites.is_empty() {
        return Ok(None);
    }
    let credentials = sorted_credentials(overview);
    let Some(password) = pick_password(&credentials) else {
        return Ok(None);
    };

    let mut websites: Vec<Website> = Vec::new();
    for cred in credentials
        .iter()
        .filter(|c| matches!(c.kind, FieldKind::Url))
    {
        let Some(value) = read(vw, &overview.key, &cred.key)? else {
            continue;
        };
        let value = value.trim();
        if ParsedUrl::parse(value).is_some() && !websites.iter().any(|w| w.url == value) {
            websites.push(Website::new(value, MatchKind::Domain));
        }
    }
    if websites.is_empty() {
        return Ok(None);
    }

    Ok(Some(LoginConversion {
        password: password.id,
        username: pick_username(&credentials).map(|cred| cred.id),
        totp: credentials
            .iter()
            .find(|c| matches!(c.kind, FieldKind::Totp))
            .map(|cred| cred.id),
        websites,
    }))
}

/// Apply [`suggest_conversion`] to an item and mark it as a login. Credential
/// keys are not renamed. Returns false when there was nothing to convert. The
/// caller saves the vault.
pub fn convert_to_login(vw: &mut VaultHandle, item_key: &str) -> Result<bool, Error> {
    let Some(overview) = vw.get_item_overview(item_key)? else {
        return Err(Error::InvalidItemKey(item_key.to_string()));
    };
    let Some(conversion) = suggest_conversion(vw, overview)? else {
        return Ok(false);
    };
    let mut autofill = overview.autofill.clone();
    autofill.password = Some(conversion.password);
    autofill.username = conversion.username;
    autofill.totp = autofill.totp.or(conversion.totp);
    autofill.websites = conversion.websites;
    let has_category = overview.category.is_some();
    vw.set_item_autofill(item_key, autofill)?;
    if !has_category {
        vw.set_item_category(item_key, Some(CATEGORY_LOGIN.to_string()))?;
    }
    Ok(true)
}

/// The credential to fill: a confidential field, preferring one named
/// "password" when the item has several.
fn pick_password<'a>(
    credentials: &[&'a VaultItemCredentialOverview],
) -> Option<&'a VaultItemCredentialOverview> {
    let confidential: Vec<_> = credentials
        .iter()
        .copied()
        .filter(|c| matches!(c.kind, FieldKind::Confidential(_)))
        .collect();
    confidential
        .iter()
        .copied()
        .find(|c| c.key.contains("password") || c.title.to_lowercase().contains("password"))
        .or_else(|| confidential.first().copied())
}

/// The credential that names the account: an `Email` field, else the first
/// credential whose key is a conventional username key.
fn pick_username<'a>(
    credentials: &[&'a VaultItemCredentialOverview],
) -> Option<&'a VaultItemCredentialOverview> {
    if let Some(email) = credentials
        .iter()
        .copied()
        .find(|c| matches!(c.kind, FieldKind::Email))
    {
        return Some(email);
    }
    USERNAME_KEYS.iter().find_map(|wanted| {
        credentials
            .iter()
            .copied()
            .find(|c| c.key == *wanted && !matches!(c.kind, FieldKind::Confidential(_)))
    })
}

#[cfg(test)]
mod tests;
