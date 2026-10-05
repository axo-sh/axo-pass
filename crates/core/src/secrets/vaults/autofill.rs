//! Picks the vault items an AutoFill credential provider can offer, and matches
//! them against the service identifier the system supplies.
//!
//! An item is a login when its autofill data names a password credential.
//! Items with no role slots fall back to a heuristic: the first confidential
//! credential is the password, and their `Url` credentials are the websites.
//! The username and the fallback URLs are credential values, so collecting
//! them needs an unlocked vault; the password is never collected here, it is
//! read separately once the user picks an account.
//!
//! Websites match through the Public Suffix List, including its private
//! section, so `a.github.io` and `b.github.io` are different sites.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::{Host, Url};
use uuid::Uuid;

use super::totp::{self, TotpCode};
use super::vault_wrapper::validate_key;
use super::{
    CATEGORY_LOGIN, Error, FieldKind, ItemAutofill, MatchKind, VaultItemCredentialOverview,
    VaultItemOverview, VaultWrapper, Website,
};

/// Credential keys treated as the account name when no `Email` field is
/// present, in preference order.
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
    /// True when `websites` came from the item's `Url` credentials because it
    /// has none of its own.
    pub websites_from_url_fields: bool,
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
    pub fn summary(&self) -> Option<LoginSummary> {
        Some(LoginSummary {
            record_id: self.record_id.clone(),
            title: self.title.clone(),
            username: self.username.clone(),
            matched: self.matched.clone()?,
            url_fallback: self.websites_from_url_fields,
        })
    }

    /// What a client may learn about a login that does not match the page.
    pub fn other(&self) -> OtherLogin {
        OtherLogin {
            record_id: self.record_id.clone(),
            title: self.title.clone(),
            username: self.username.clone(),
        }
    }
}

/// A login that does not match the page, listed so the user can still choose
/// it. Filling one needs the user's confirmation. It carries no website.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtherLogin {
    pub record_id: String,
    pub title: String,
    pub username: Option<String>,
}

/// One login offered for a page, as a client sees it. It carries no password,
/// no credential keys, and no website other than the one that matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginSummary {
    pub record_id: String,
    pub title: String,
    pub username: Option<String>,
    /// The stored website that matched, and how.
    pub matched: MatchedWebsite,
    /// True when the item matched through its `Url` field because it lists no
    /// websites. A fill of such a login needs the user's confirmation.
    pub url_fallback: bool,
}

/// Collect every AutoFill candidate in an unlocked vault. `service`, when
/// given, keeps only the items matching it, best match first.
pub fn collect_items(vw: &VaultWrapper, service: Option<&str>) -> Result<Vec<AutofillItem>, Error> {
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
    vw: &VaultWrapper,
    vault_id: Uuid,
    overview: &VaultItemOverview,
    target: Option<&ParsedUrl>,
) -> Result<Option<AutofillItem>, Error> {
    let credentials = sorted_credentials(overview);
    let Roles { password, username } = pick_roles(overview, &credentials);
    let Some(password) = password else {
        return Ok(None);
    };

    let mut websites = overview.autofill.websites.clone();
    let mut from_url_fields = false;
    if websites.is_empty() {
        from_url_fields = true;
        for cred in credentials
            .iter()
            .filter(|c| matches!(c.kind, FieldKind::Url))
        {
            if let Some(value) = read(vw, &overview.key, &cred.key)? {
                // Only http and https sites are logins. Other schemes would
                // offer database and API items as logins.
                if ParsedUrl::parse(&value).is_some() {
                    websites.push(Website::new(value, MatchKind::Domain));
                }
            }
        }
    }

    let matched = match target {
        Some(target) => match best_match(&websites, target) {
            Some(matched) => Some(matched),
            None => return Ok(None),
        },
        None => None,
    };

    let username = match username {
        Some(cred) => read(vw, &overview.key, &cred.key)?,
        None => None,
    };

    Ok(Some(AutofillItem {
        vault_key: vw.key.clone(),
        item_key: overview.key.clone(),
        record_id: format!("{vault_id}/{}/{}", overview.id, password.id),
        title: overview.title.clone(),
        username,
        password_key: password.key.clone(),
        websites,
        websites_from_url_fields: from_url_fields,
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
pub fn collect_places(vw: &VaultWrapper) -> Result<Vec<LoginPlace>, Error> {
    let mut places = Vec::new();
    for overview in vw.list_items()? {
        let credentials = sorted_credentials(overview);
        let Roles { password, username } = pick_roles(overview, &credentials);
        let has_passkey = credentials
            .iter()
            .any(|c| matches!(c.kind, FieldKind::Passkey));
        let is_login = password.is_some()
            || has_passkey
            || overview.category.as_deref() == Some(CATEGORY_LOGIN);
        if !is_login || overview.autofill.websites.is_empty() {
            continue;
        }
        let username = match username {
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
pub fn parse_record_id(record_id: &str) -> Option<(Uuid, Uuid, Uuid)> {
    let mut parts = record_id.split('/');
    let vault = Uuid::parse_str(parts.next()?).ok()?;
    let item = Uuid::parse_str(parts.next()?).ok()?;
    let credential = Uuid::parse_str(parts.next()?).ok()?;
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
    vw: &VaultWrapper,
    record_id: &str,
    frame_url: &str,
) -> Result<Option<AutofillItem>, Error> {
    let Some((vault_id, item_id, _)) = parse_record_id(record_id) else {
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
    Ok(
        candidate(vw, vault_id, overview, Some(&target))?
            .filter(|item| item.record_id == record_id),
    )
}

/// What a fill returns: the username and password roles and nothing else on the
/// item.
pub struct LoginSecrets {
    pub username: Option<String>,
    pub password: SecretString,
}

/// Read the role credentials of a login found by [`find_login`].
pub fn read_login(vw: &VaultWrapper, item: &AutofillItem) -> Result<Option<LoginSecrets>, Error> {
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
pub fn login_totp(vw: &VaultWrapper, item: &AutofillItem) -> Result<Option<TotpCode>, Error> {
    use secrecy::ExposeSecret;

    let Some(overview) = vw.get_item_overview(&item.item_key)? else {
        return Ok(None);
    };
    let Some(cred) = sorted_credentials(overview)
        .into_iter()
        .find(|c| matches!(c.kind, FieldKind::Totp))
    else {
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
pub fn write_login(vw: &mut VaultWrapper, login: LoginWrite) -> Result<(), Error> {
    if vw.get_item_overview(login.item_key)?.is_none() {
        vw.add_item(login.item_key, login.title)?;
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
pub(super) fn unused_item_key(vw: &VaultWrapper, base: &str) -> Result<String, Error> {
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
    vw: &mut VaultWrapper,
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

/// Create the login item a new passkey is stored in: titled `title`, with a
/// website for `rp_id` under `domain` matching and, when `username` is given, a
/// username credential assigned the username role. It has no password role. The
/// caller saves the vault. Returns the new item's key.
pub fn add_passkey_login(
    vw: &mut VaultWrapper,
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

/// The login a record identifier names, wherever it applies. Unlike
/// [`find_login`] this does not check a page, so the caller decides what an
/// unmatched page means.
pub fn find_login_record(
    vw: &VaultWrapper,
    record_id: &str,
) -> Result<Option<AutofillItem>, Error> {
    let Some((vault_id, item_id, _)) = parse_record_id(record_id) else {
        return Ok(None);
    };
    if vw.vault_id()? != vault_id {
        return Ok(None);
    }
    let Some(overview) = vw.get_item_overview_by_id(item_id)? else {
        return Ok(None);
    };
    Ok(candidate(vw, vault_id, overview, None)?.filter(|item| item.record_id == record_id))
}

/// Whether `frame_url` is a page the login is stored for. A login that is
/// offered only through its `Url` fields does not count: it lists no website.
pub fn is_stored_for(item: &AutofillItem, frame_url: &str) -> bool {
    !item.websites_from_url_fields && match_service(&item.websites, frame_url).is_some()
}

/// Replace the password of a login found by [`find_login_record`], keeping the
/// credential's title and kind. The caller saves the vault.
pub fn update_login_password(
    vw: &mut VaultWrapper,
    item: &AutofillItem,
    password: SecretString,
) -> Result<(), Error> {
    let (title, kind) = vw
        .get_secret_overview(&item.item_key, &item.password_key)?
        .map(|credential| (credential.title.clone(), credential.kind.clone()))
        .ok_or_else(|| {
            Error::InvalidCredentialKey(format!("{}/{}", item.item_key, item.password_key))
        })?;
    vw.add_secret(&item.item_key, &item.password_key, &title, kind, password)
}

fn credential_id(vw: &VaultWrapper, item_key: &str, cred_key: &str) -> Result<uuid::Uuid, Error> {
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

fn read(vw: &VaultWrapper, item_key: &str, cred_key: &str) -> Result<Option<String>, Error> {
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

struct Roles<'a> {
    password: Option<&'a VaultItemCredentialOverview>,
    username: Option<&'a VaultItemCredentialOverview>,
}

/// The credentials to fill. Role slots decide when the item has any; an item
/// with none uses the heuristic.
fn pick_roles<'a>(
    overview: &'a VaultItemOverview,
    credentials: &[&'a VaultItemCredentialOverview],
) -> Roles<'a> {
    let autofill: &ItemAutofill = &overview.autofill;
    if autofill.password.is_some() || autofill.username.is_some() {
        return Roles {
            password: autofill.password_credential(overview),
            username: autofill.username_credential(overview),
        };
    }
    Roles {
        password: pick_password(credentials),
        username: pick_username(credentials),
    }
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
mod tests {
    use super::*;

    fn site(url: &str, kind: MatchKind) -> Website {
        Website::new(url, kind)
    }

    fn domain(url: &str) -> Vec<Website> {
        vec![site(url, MatchKind::Domain)]
    }

    fn matches(websites: &[Website], service: &str) -> bool {
        match_service(websites, service).is_some()
    }

    #[test]
    fn identity_hosts_follow_the_match_kind() {
        let websites = [
            site("https://login.example.com/x", MatchKind::Domain),
            site("https://www.other.org/app", MatchKind::Host),
            site("https://pages.test/a", MatchKind::StartsWith),
            site("https://never.test", MatchKind::Never),
            site("example.com", MatchKind::Domain),
        ];
        assert_eq!(
            identity_hosts(&websites),
            [
                "example.com",
                "login.example.com",
                "other.org",
                "pages.test"
            ]
        );
    }

    #[test]
    fn domain_matches_the_same_host() {
        assert!(matches(&domain("https://example.com/login"), "example.com"));
        assert!(matches(
            &domain("example.com"),
            "https://example.com/anything"
        ));
    }

    #[test]
    fn domain_matches_across_subdomains_of_a_registrable_domain() {
        assert!(matches(
            &domain("https://accounts.example.com"),
            "example.com"
        ));
        assert!(matches(&domain("https://example.com"), "login.example.com"));
        assert!(matches(
            &domain("https://a.example.co.uk"),
            "b.example.co.uk"
        ));
    }

    #[test]
    fn private_suffixes_isolate_sites() {
        assert!(!matches(&domain("a.github.io"), "b.github.io"));
        assert!(!matches(&domain("github.io"), "a.github.io"));
        assert!(!matches(&domain("a.github.io"), "github.io"));
        assert!(matches(&domain("a.github.io"), "a.github.io"));
        assert!(!matches(&domain("one.vercel.app"), "two.vercel.app"));
    }

    #[test]
    fn domain_does_not_cross_registrable_domains() {
        assert!(!matches(&domain("https://example.com"), "example.org"));
        assert!(!matches(&domain("https://example.com"), "notexample.com"));
        assert!(!matches(
            &domain("https://example.com"),
            "example.com.evil.com"
        ));
        assert!(!matches(&domain("https://co.uk"), "example.co.uk"));
        assert!(!matches(&[], "example.com"));
    }

    #[test]
    fn www_is_ignored() {
        assert!(matches(&domain("https://www.example.com"), "example.com"));
        assert!(matches(
            &[site("www.example.com", MatchKind::Host)],
            "example.com"
        ));
    }

    #[test]
    fn host_requires_equal_hosts() {
        let websites = [site("https://login.example.com", MatchKind::Host)];
        assert!(matches(&websites, "login.example.com"));
        assert!(matches(&websites, "https://login.example.com/path?q=1"));
        assert!(!matches(&websites, "example.com"));
        assert!(!matches(&websites, "other.example.com"));
    }

    #[test]
    fn domain_matching_ignores_ports() {
        assert!(matches(
            &domain("http://example.com:8080"),
            "https://example.com:9000/x"
        ));
        assert!(matches(&domain("localhost:3000"), "http://localhost:8080"));
    }

    #[test]
    fn host_matching_compares_ports() {
        let websites = [site("http://localhost:3000", MatchKind::Host)];
        assert!(matches(&websites, "http://localhost:3000/login"));
        assert!(!matches(&websites, "http://localhost:8080"));
        assert!(!matches(&websites, "http://localhost"));
    }

    #[test]
    fn default_ports_agree_with_no_port() {
        let websites = [site("https://example.com", MatchKind::Host)];
        assert!(matches(&websites, "https://example.com:443/x"));
        assert!(!matches(&websites, "https://example.com:8443"));
        let websites = [site("https://example.com:443", MatchKind::Host)];
        assert!(matches(&websites, "https://example.com"));
    }

    #[test]
    fn a_bare_domain_names_no_port() {
        assert!(matches(
            &[site("https://example.com:8443", MatchKind::Host)],
            "example.com"
        ));
        assert!(matches(
            &[site("example.com", MatchKind::Host)],
            "https://example.com:8443"
        ));
    }

    #[test]
    fn starts_with_compares_ports() {
        let websites = [site("https://example.com:8443/app", MatchKind::StartsWith)];
        assert!(matches(&websites, "https://example.com:8443/app/x"));
        assert!(!matches(&websites, "https://example.com/app/x"));
    }

    #[test]
    fn never_matches_nothing() {
        let websites = [site("https://example.com", MatchKind::Never)];
        assert!(!matches(&websites, "https://example.com"));
        assert!(!matches(&websites, "example.com"));
        assert!(!matches(&websites, "https://sub.example.com"));
    }

    #[test]
    fn never_does_not_block_another_website_on_the_same_login() {
        let websites = [
            site("https://example.com/admin", MatchKind::Never),
            site("https://example.com", MatchKind::Domain),
        ];
        assert!(matches(&websites, "https://example.com/admin"));
    }

    #[test]
    fn an_https_login_does_not_match_an_http_page() {
        for kind in [MatchKind::Domain, MatchKind::Host, MatchKind::StartsWith] {
            let websites = [site("https://example.com", kind)];
            assert!(matches(&websites, "https://example.com"));
            assert!(!matches(&websites, "http://example.com"));
            assert!(!matches(&websites, "HTTP://example.com/login"));
        }
    }

    #[test]
    fn an_http_or_bare_login_matches_an_http_page() {
        assert!(matches(&domain("http://example.com"), "http://example.com"));
        assert!(matches(&domain("example.com"), "http://example.com"));
    }

    #[test]
    fn starts_with_compares_pages_on_the_same_host() {
        let websites = [site("https://example.com/app", MatchKind::StartsWith)];
        assert!(matches(&websites, "https://example.com/app/login"));
        assert!(matches(&websites, "https://example.com/app"));
        assert!(!matches(&websites, "https://example.com/other"));
        assert!(!matches(&websites, "https://sub.example.com/app"));
    }

    #[test]
    fn starts_with_compares_whole_path_segments() {
        let websites = [site("https://example.com/app", MatchKind::StartsWith)];
        assert!(!matches(&websites, "https://example.com/application"));
        assert!(!matches(&websites, "https://example.com/app-evil/login"));
        assert!(matches(&websites, "https://example.com/app/"));
        assert!(matches(&websites, "https://example.com/app/a/b?x=1"));
        let websites = [site("https://example.com/app/", MatchKind::StartsWith)];
        assert!(matches(&websites, "https://example.com/app"));
        assert!(matches(&websites, "https://example.com/app/login"));
        assert!(!matches(&websites, "https://example.com/application"));
    }

    #[test]
    fn starts_with_normalizes_dot_segments() {
        let websites = [site("https://example.com/app", MatchKind::StartsWith)];
        assert!(!matches(&websites, "https://example.com/app/../admin"));
        assert!(matches(&websites, "https://example.com/other/../app/login"));
    }

    #[test]
    fn starts_with_requires_an_equal_stored_query() {
        let websites = [site(
            "https://example.com/app?tenant=a",
            MatchKind::StartsWith,
        )];
        assert!(matches(&websites, "https://example.com/app?tenant=a"));
        assert!(!matches(&websites, "https://example.com/app?tenant=ab"));
        assert!(!matches(&websites, "https://example.com/app"));
    }

    #[test]
    fn starts_with_does_not_match_a_longer_host() {
        let websites = [site("https://example.com", MatchKind::StartsWith)];
        assert!(!matches(&websites, "https://example.com.evil.com/login"));
        assert!(matches(&websites, "https://example.com/login"));
    }

    #[test]
    fn starts_with_treats_a_bare_domain_as_a_host_match() {
        let websites = [site("https://example.com/app", MatchKind::StartsWith)];
        assert!(matches(&websites, "example.com"));
        assert!(!matches(&websites, "other.com"));
    }

    #[test]
    fn idn_hosts_compare_in_ascii() {
        assert!(matches(
            &domain("https://bücher.example"),
            "xn--bcher-kva.example"
        ));
        assert!(matches(&domain("xn--bcher-kva.example"), "BÜCHER.example"));
    }

    #[test]
    fn ip_addresses_and_single_label_hosts_match_exactly() {
        assert!(matches(&domain("http://192.168.0.1"), "192.168.0.1"));
        assert!(!matches(&domain("http://192.168.0.1"), "10.168.0.1"));
        assert!(!matches(&domain("http://192.168.0.1"), "192.168.0.2"));
        assert!(matches(&domain("localhost"), "http://localhost:3000"));
        assert!(!matches(&domain("localhost"), "other"));
    }

    #[test]
    fn other_schemes_never_match() {
        assert!(!matches(
            &domain("postgres://example.com/db"),
            "example.com"
        ));
        assert!(!matches(
            &domain("example.com"),
            "postgres://example.com/db"
        ));
        assert!(!matches(&domain("example.com"), ""));
    }

    #[test]
    fn reports_the_stored_host_that_matched() {
        let websites = vec![
            site("https://www.other.com", MatchKind::Domain),
            site("https://accounts.example.com", MatchKind::Domain),
        ];
        let matched = match_service(&websites, "https://example.com/login").unwrap();
        assert_eq!(matched.host, "accounts.example.com");
        assert_eq!(matched.kind, MatchKind::Domain);
        assert_eq!(matched.rank, MatchRank::Domain);
    }

    #[test]
    fn an_exact_host_match_beats_a_domain_match() {
        let websites = vec![
            site("https://accounts.example.com", MatchKind::Domain),
            site("https://example.com", MatchKind::Domain),
        ];
        let matched = match_service(&websites, "example.com").unwrap();
        assert_eq!(matched.host, "example.com");
        assert_eq!(matched.rank, MatchRank::Host);
    }

    #[test]
    fn matches_sort_by_rank_then_title() {
        let item = |title: &str, rank: Option<MatchRank>| AutofillItem {
            vault_key: "personal".to_string(),
            item_key: title.to_lowercase(),
            record_id: String::new(),
            title: title.to_string(),
            username: None,
            password_key: "password".to_string(),
            websites: Vec::new(),
            websites_from_url_fields: false,
            matched: rank.map(|rank| MatchedWebsite {
                host: "example.com".to_string(),
                kind: MatchKind::Domain,
                rank,
            }),
        };
        let mut items = [
            item("Zed", Some(MatchRank::Host)),
            item("Alpha", Some(MatchRank::Domain)),
            item("Beta", Some(MatchRank::Host)),
        ];
        items.sort_by_key(AutofillItem::sort_key);
        let titles: Vec<_> = items.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(titles, ["Beta", "Zed", "Alpha"]);
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

    #[test]
    fn write_login_creates_the_item_credentials_roles_and_websites() {
        use secrecy::ExposeSecret;

        let mut vw = VaultWrapper::new_for_test("personal");
        let websites = vec!["github.com".to_string()];
        write_login(&mut vw, login(&websites, Some("tp"))).unwrap();

        let item = vw.get_item_overview("github").unwrap().unwrap();
        assert_eq!(item.title, "GitHub");
        assert_eq!(item.category.as_deref(), Some(CATEGORY_LOGIN));
        assert_eq!(
            item.autofill.websites,
            vec![Website::new("github.com", MatchKind::Domain)]
        );
        assert_eq!(
            item.autofill.password_credential(item).unwrap().key,
            "password"
        );
        let username = item.autofill.username_credential(item).unwrap();
        assert_eq!(username.key, "username");
        assert!(matches!(username.kind, FieldKind::Text(_)));

        let password = vw.get_secret("github", "password").unwrap().unwrap();
        assert_eq!(password.expose_secret(), "hunter2");
        let username = vw.get_secret("github", "username").unwrap().unwrap();
        assert_eq!(username.expose_secret(), "tp");

        let found = collect_items(&vw, Some("gist.github.com")).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].username.as_deref(), Some("tp"));
        assert_eq!(found[0].matched.as_ref().unwrap().host, "github.com");
        assert!(!found[0].websites_from_url_fields);
        assert!(collect_items(&vw, Some("github.io")).unwrap().is_empty());
    }

    #[test]
    fn write_login_stores_an_email_username_as_email() {
        let mut vw = VaultWrapper::new_for_test("personal");
        write_login(&mut vw, login(&[], Some("tp@example.com"))).unwrap();
        let cred = vw
            .get_secret_overview("github", "username")
            .unwrap()
            .unwrap();
        assert_eq!(cred.kind, FieldKind::Email);
    }

    #[test]
    fn write_login_does_not_duplicate_websites_on_update() {
        let mut vw = VaultWrapper::new_for_test("personal");
        let websites = vec!["github.com".to_string()];
        write_login(&mut vw, login(&websites, None)).unwrap();
        write_login(&mut vw, login(&websites, None)).unwrap();
        let item = vw.get_item_overview("github").unwrap().unwrap();
        assert_eq!(item.autofill.websites.len(), 1);
        assert!(item.autofill.username.is_none());
    }

    fn names(url: &str) -> (String, String) {
        names_for_site(&Site::parse(url).unwrap())
    }

    #[test]
    fn names_come_from_the_registrable_domain() {
        let pair = |key: &str, title: &str| (key.to_string(), title.to_string());
        assert_eq!(
            names("https://accounts.github.com/login"),
            pair("github", "Github.com")
        );
        assert_eq!(
            names("https://www.example.co.uk"),
            pair("example", "Example.co.uk")
        );
    }

    #[test]
    fn names_fall_back_when_the_first_label_is_not_a_key() {
        let pair = |key: &str, title: &str| (key.to_string(), title.to_string());
        // Keys start with a letter and have at least three characters.
        assert_eq!(names("https://x.com"), pair("x-com", "X.com"));
        assert_eq!(names("https://t.co"), pair("t-co", "T.co"));
        assert_eq!(names("https://123.com"), pair("login", "123.com"));
    }

    #[test]
    fn save_login_stores_a_host_website_and_the_conventional_keys() {
        use secrecy::ExposeSecret;

        let mut vw = VaultWrapper::new_for_test("personal");
        let item = save_login(
            &mut vw,
            "https://login.example.com",
            Some("tp"),
            SecretString::from("pw"),
        )
        .unwrap();

        assert_eq!(item.item_key, "example");
        assert_eq!(item.title, "Example.com");
        assert_eq!(item.username.as_deref(), Some("tp"));
        assert_eq!(item.password_key, "password");

        let overview = vw.get_item_overview("example").unwrap().unwrap();
        assert_eq!(overview.category.as_deref(), Some(CATEGORY_LOGIN));
        assert_eq!(
            overview.autofill.websites,
            vec![Website::new("https://login.example.com", MatchKind::Host)]
        );
        let password = vw.get_secret("example", "password").unwrap().unwrap();
        assert_eq!(password.expose_secret(), "pw");

        // `host` matching offers the login on its own host and nowhere else
        // under the registrable domain.
        let id = &item.record_id;
        assert!(
            find_login(&vw, id, "https://login.example.com/x")
                .unwrap()
                .is_some()
        );
        assert!(
            find_login(&vw, id, "https://www.example.com")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn save_login_leaves_an_existing_item_alone() {
        use secrecy::ExposeSecret;

        let mut vw = VaultWrapper::new_for_test("personal");
        let save = |vw: &mut VaultWrapper, password: &str| {
            save_login(
                vw,
                "https://example.com",
                Some("tp"),
                SecretString::from(password),
            )
            .unwrap()
        };
        let first = save(&mut vw, "one");
        let second = save(&mut vw, "two");

        assert_eq!(first.item_key, "example");
        assert_eq!(second.item_key, "example-2");
        assert_ne!(first.record_id, second.record_id);
        let password = vw.get_secret("example", "password").unwrap().unwrap();
        assert_eq!(password.expose_secret(), "one");
    }

    #[test]
    fn save_login_without_a_username_has_no_username_role() {
        let mut vw = VaultWrapper::new_for_test("personal");
        let item = save_login(
            &mut vw,
            "https://example.com",
            Some("  "),
            SecretString::from("pw"),
        )
        .unwrap();
        assert!(item.username.is_none());
        let overview = vw.get_item_overview("example").unwrap().unwrap();
        assert!(overview.autofill.username.is_none());
    }

    #[test]
    fn save_login_refuses_a_page_that_is_not_http() {
        let mut vw = VaultWrapper::new_for_test("personal");
        assert!(save_login(&mut vw, "ftp://example.com", None, SecretString::from("pw")).is_err());
    }

    #[test]
    fn update_login_password_changes_only_the_value() {
        use secrecy::ExposeSecret;

        let mut vw = VaultWrapper::new_for_test("personal");
        let websites = vec!["github.com".to_string()];
        write_login(&mut vw, login(&websites, Some("tp"))).unwrap();
        let before = vw
            .get_secret_overview("github", "password")
            .unwrap()
            .unwrap()
            .clone();
        let item = collect_items(&vw, None).unwrap().remove(0);

        update_login_password(&mut vw, &item, SecretString::from("new")).unwrap();

        let password = vw.get_secret("github", "password").unwrap().unwrap();
        assert_eq!(password.expose_secret(), "new");
        let after = vw
            .get_secret_overview("github", "password")
            .unwrap()
            .unwrap();
        assert_eq!(after.id, before.id);
        assert_eq!(after.title, before.title);
        assert_eq!(after.kind, before.kind);
    }

    #[test]
    fn find_login_record_ignores_the_page_but_not_the_id() {
        let mut vw = VaultWrapper::new_for_test("personal");
        let websites = vec!["github.com".to_string()];
        write_login(&mut vw, login(&websites, Some("tp"))).unwrap();
        let item = collect_items(&vw, None).unwrap().remove(0);

        let found = find_login_record(&vw, &item.record_id).unwrap().unwrap();
        assert_eq!(found.record_id, item.record_id);

        let (vault, item_id, _) = parse_record_id(&item.record_id).unwrap();
        let wrong_credential = format!("{vault}/{item_id}/{}", Uuid::new_v4());
        assert!(find_login_record(&vw, &wrong_credential).unwrap().is_none());
        assert!(find_login_record(&vw, "not-a-record").unwrap().is_none());
    }

    #[test]
    fn a_login_is_stored_for_a_page_only_through_a_listed_website() {
        let mut vw = VaultWrapper::new_for_test("personal");
        let websites = vec!["github.com".to_string()];
        write_login(&mut vw, login(&websites, Some("tp"))).unwrap();
        let item = find_login_record(&vw, &collect_items(&vw, None).unwrap()[0].record_id)
            .unwrap()
            .unwrap();

        assert!(is_stored_for(&item, "https://gist.github.com/new"));
        assert!(!is_stored_for(&item, "https://evil.com"));

        let from_url_field = AutofillItem {
            websites_from_url_fields: true,
            ..item
        };
        assert!(!is_stored_for(&from_url_field, "https://github.com"));
    }

    #[test]
    fn url_field_fallback_is_limited_to_http_sites() {
        let mut vw = VaultWrapper::new_for_test("personal");
        vw.add_item("database", "Database").unwrap();
        for (key, value) in [("password", "pw"), ("url", "postgres://example.com/db")] {
            let kind = if key == "url" {
                FieldKind::Url
            } else {
                FieldKind::default()
            };
            vw.add_secret("database", key, key, kind, SecretString::from(value))
                .unwrap();
        }
        assert!(collect_items(&vw, Some("example.com")).unwrap().is_empty());

        vw.add_item("blog", "Blog").unwrap();
        vw.add_secret(
            "blog",
            "password",
            "Password",
            FieldKind::default(),
            SecretString::from("pw"),
        )
        .unwrap();
        vw.add_secret(
            "blog",
            "site",
            "Site",
            FieldKind::Url,
            SecretString::from("https://blog.example.com/login"),
        )
        .unwrap();
        let found = collect_items(&vw, Some("example.com")).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].item_key, "blog");
        assert!(found[0].websites_from_url_fields);
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

    #[test]
    fn roles_take_precedence_over_the_heuristic() {
        let mut item = overview(&[
            ("password", FieldKind::default()),
            ("pin", FieldKind::default()),
            ("handle", FieldKind::Text(Default::default())),
        ]);
        item.autofill.password = Some(key_of(&item, "pin"));
        item.autofill.username = Some(key_of(&item, "handle"));
        let credentials = sorted_credentials(&item);
        let roles = pick_roles(&item, &credentials);
        assert_eq!(roles.password.unwrap().key, "pin");
        assert_eq!(roles.username.unwrap().key, "handle");
    }

    #[test]
    fn a_dangling_password_role_is_not_a_login() {
        let mut item = overview(&[("password", FieldKind::default())]);
        item.autofill.password = Some(uuid::Uuid::new_v4());
        let credentials = sorted_credentials(&item);
        assert!(pick_roles(&item, &credentials).password.is_none());
    }

    fn github_login(vw: &mut VaultWrapper) -> String {
        let websites = vec!["github.com".to_string()];
        write_login(vw, login(&websites, Some("tp"))).unwrap();
        collect_items(vw, Some("github.com")).unwrap()[0]
            .record_id
            .clone()
    }

    #[test]
    fn find_login_requires_a_website_that_matches_the_frame() {
        let mut vw = VaultWrapper::new_for_test("personal");
        let record_id = github_login(&mut vw);

        let found = find_login(&vw, &record_id, "https://gist.github.com/new")
            .unwrap()
            .unwrap();
        assert_eq!(found.record_id, record_id);
        assert_eq!(found.username.as_deref(), Some("tp"));

        assert!(
            find_login(&vw, &record_id, "https://github.io")
                .unwrap()
                .is_none()
        );
        assert!(
            find_login(&vw, &record_id, "https://evil.com")
                .unwrap()
                .is_none()
        );
        assert!(find_login(&vw, &record_id, "").unwrap().is_none());
        assert!(
            find_login(&vw, &record_id, "ftp://github.com")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn find_login_refuses_ids_that_do_not_name_this_login() {
        let mut vw = VaultWrapper::new_for_test("personal");
        let record_id = github_login(&mut vw);
        let (vault, item, credential) = parse_record_id(&record_id).unwrap();
        let new = Uuid::new_v4;

        for wrong in [
            format!("{}/{item}/{credential}", new()),
            format!("{vault}/{}/{credential}", new()),
            format!("{vault}/{item}/{}", new()),
            format!("{vault}/{item}"),
            format!("{record_id}/extra"),
            "github/github/password".to_string(),
            String::new(),
        ] {
            assert!(
                find_login(&vw, &wrong, "https://github.com")
                    .unwrap()
                    .is_none(),
                "{wrong}"
            );
        }
    }

    #[test]
    fn read_login_returns_only_the_role_credentials() {
        use secrecy::ExposeSecret;

        let mut vw = VaultWrapper::new_for_test("personal");
        let record_id = github_login(&mut vw);
        vw.add_secret(
            "github",
            "recovery",
            "Recovery code",
            FieldKind::default(),
            SecretString::from("do-not-return"),
        )
        .unwrap();

        let item = find_login(&vw, &record_id, "github.com").unwrap().unwrap();
        let secrets = read_login(&vw, &item).unwrap().unwrap();
        assert_eq!(secrets.username.as_deref(), Some("tp"));
        assert_eq!(secrets.password.expose_secret(), "hunter2");
    }

    #[test]
    fn a_login_listing_summary_carries_no_secret_or_key() {
        let mut vw = VaultWrapper::new_for_test("personal");
        github_login(&mut vw);
        let found = collect_items(&vw, Some("github.com")).unwrap();
        let summary = found[0].summary().unwrap();
        assert_eq!(summary.title, "GitHub");
        assert_eq!(summary.username.as_deref(), Some("tp"));
        assert_eq!(summary.matched.host, "github.com");
        assert!(!summary.url_fallback);
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("password"));
        assert!(collect_items(&vw, None).unwrap()[0].summary().is_none());
    }

    #[test]
    fn a_login_matched_through_a_url_field_is_flagged() {
        let mut vw = VaultWrapper::new_for_test("personal");
        vw.add_item("blog", "Blog").unwrap();
        vw.add_secret(
            "blog",
            "password",
            "Password",
            FieldKind::default(),
            SecretString::from("pw"),
        )
        .unwrap();
        vw.add_secret(
            "blog",
            "site",
            "Site",
            FieldKind::Url,
            SecretString::from("https://blog.example.com"),
        )
        .unwrap();
        let record_id = collect_items(&vw, Some("example.com")).unwrap()[0]
            .record_id
            .clone();
        let found = find_login(&vw, &record_id, "https://example.com")
            .unwrap()
            .unwrap();
        assert!(found.websites_from_url_fields);
        assert!(found.summary().unwrap().url_fallback);
    }

    #[test]
    fn login_totp_uses_the_first_totp_credential() {
        let mut vw = VaultWrapper::new_for_test("personal");
        let record_id = github_login(&mut vw);
        let item = find_login(&vw, &record_id, "github.com").unwrap().unwrap();
        assert!(login_totp(&vw, &item).unwrap().is_none());

        vw.add_secret(
            "github",
            "otp",
            "Code",
            FieldKind::Totp,
            SecretString::from("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        )
        .unwrap();
        let code = login_totp(&vw, &item).unwrap().unwrap();
        assert_eq!(code.code.len(), 6);

        vw.add_secret(
            "github",
            "broken",
            "Broken",
            FieldKind::Totp,
            SecretString::from("!!"),
        )
        .unwrap();
        vw.reorder_credentials(
            "github",
            &["broken", "otp", "password", "username"].map(String::from),
        )
        .unwrap();
        assert!(matches!(
            login_totp(&vw, &item),
            Err(Error::InvalidOneTimeCode(_))
        ));
    }

    #[test]
    fn site_reports_the_host_domain_and_scheme() {
        let site = Site::parse("http://www.accounts.example.co.uk:8080/x").unwrap();
        assert_eq!(site.host, "accounts.example.co.uk");
        assert_eq!(site.domain, "example.co.uk");
        assert!(!site.secure);
        assert!(Site::parse("https://example.com").unwrap().secure);
        assert!(Site::parse("example.com").unwrap().secure);
        assert!(!Site::parse("HTTP://example.com").unwrap().secure);
        assert!(!Site::parse(" http://example.com").unwrap().secure);
        assert!(Site::parse("ftp://example.com").is_none());
    }

    #[test]
    fn rp_ids_must_be_valid_for_the_origin() {
        let ok = |rp: &str, origin: &str| check_rp_id(rp, Some(origin)).is_ok();
        assert!(ok("example.com", "https://login.example.com"));
        assert!(ok("example.com", "https://example.com"));
        assert!(ok("login.example.com", "https://login.example.com"));
        assert!(ok("example.com", "https://a.b.example.com:8443/path"));

        assert!(!ok("login.example.com", "https://example.com"));
        assert!(!ok("github.io", "https://example.github.io"));
        assert!(!ok("github.io", "https://github.io"));
        assert!(!ok("evil.com", "https://example.com"));
        assert!(!ok("example.com", "https://notexample.com"));
        assert!(!ok("example.com", "https://example.com.evil.com"));
        assert!(!ok("com", "https://example.com"));
        assert!(!ok("co.uk", "https://example.co.uk"));
        assert!(!ok("example.com", "https://192.168.0.1"));
    }

    #[test]
    fn rp_ids_are_checked_without_an_origin() {
        assert!(check_rp_id("example.com", None).is_ok());
        assert!(check_rp_id("login.example.co.uk", None).is_ok());
        for invalid in [
            "",
            "github.io",
            "co.uk",
            "localhost",
            "192.168.0.1",
            "Example.com",
            "https://example.com",
            "example.com:8080",
            "example.com/path",
            ".example.com",
            "example.com.",
        ] {
            assert!(check_rp_id(invalid, None).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn items_without_roles_use_the_heuristic() {
        let item = overview(&[
            ("api-token", FieldKind::default()),
            ("password", FieldKind::default()),
            ("email", FieldKind::Email),
        ]);
        let credentials = sorted_credentials(&item);
        let roles = pick_roles(&item, &credentials);
        assert_eq!(roles.password.unwrap().key, "password");
        assert_eq!(roles.username.unwrap().key, "email");
    }
}
